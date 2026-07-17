//! `relativelylight::auth` — authentication (users, sessions, login, argon2id) + authorization
//! (a small [`Authz`] gate trait + presets). Usable on its own (feature `auth`, no `crud`): it gates
//! any axum app. See `docs/AUTH.md` for the full design.
//!
//! There is **no middleware and no injected request context**. Authn is a handful of on-demand
//! lookups on [`Auth`]: given a request's headers, [`Auth::identify`] resolves the session cookie →
//! user → groups in one query and returns an [`Identity`] (or `None` for anonymous). The
//! authorization gate itself lives in [`crate::authz`]; the presets here ([`ValidUsers`],
//! [`UsersReadGroupWrite`]) implement it by resolving the identity with an `Auth` handle and
//! returning a [`Decision`](crate::authz::Decision) the caller renders.
//!
//! Implemented: the `user`/`session`/`group`/`user_group` SeaORM models, argon2id hashing, a
//! login/logout flow with an opaque server-side session cookie (via `axum-extra`'s `CookieJar`),
//! **TOTP two-factor authentication** (a second-factor step at login, plus self-service enrolment /
//! disable on the profile page and a manager disable for other users), on-demand [`Auth::identify`],
//! the gate presets ([`ValidUsers`], [`UsersReadGroupWrite`], [`AdminOnly`]), a self-service
//! **profile / password-change** page plus a manager reset (`GET/POST /profile`,
//! `GET/POST /profile/{id}` — see [`Auth::routes`]), admin helpers (`make_admin`, `set_password`,
//! `add_to_group`, …), and per-model enforcement in the `crud` HTTP handlers via
//! `crud::seaorm::Crud::register`. Not yet: the CSRF/CORS/real-ip/logging middleware and OIDC.
//!
//! The session cookie (name configurable, default `rl_session`) carries only an **opaque token** —
//! the id of a row in the session table; the identity is rebuilt server-side from the DB on each
//! lookup, and deleting the row revokes it.

pub mod group;
pub mod session;
mod totp;
pub mod user;
pub mod user_group;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use async_trait::async_trait;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use crate::authz::{Authz, Decision, Operation};
use rand_core::{OsRng, RngCore};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait,
    IntoActiveModel, QueryFilter, Schema, Set,
};

const DEFAULT_COOKIE: &str = "rl_session";

// ===================== Identity + gate presets =====================

/// A logged-in identity, resolved on demand by [`Auth::identify`] from the session cookie. It is a
/// plain return value — nothing injects it into the request.
#[derive(Clone, Debug)]
pub struct Identity {
    pub id: String,
    pub username: String,
    pub groups: Vec<String>,
}

impl Identity {
    /// Whether this identity belongs to the named group.
    pub fn in_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }

    /// Whether this identity belongs to any of the given groups.
    pub fn in_any_group(&self, groups: &[String]) -> bool {
        self.groups.iter().any(|g| groups.contains(g))
    }
}

/// Gate: any authenticated user may do anything; anonymous → `NeedsLogin`. Holds an [`Auth`] handle
/// to resolve the caller; construct with `ValidUsers::new(&auth)`.
pub struct ValidUsers(Auth);

impl ValidUsers {
    pub fn new(auth: &Auth) -> Self {
        Self(auth.clone())
    }
}

#[async_trait]
impl Authz for ValidUsers {
    async fn authorize(&self, _: Operation, headers: &HeaderMap) -> Decision {
        match self.0.identify(headers).await {
            Some(_) => Decision::Allow,
            None => Decision::NeedsLogin,
        }
    }
}

/// Gate: any authenticated user may list/read; a write requires membership in one of `write_groups`
/// (else `Denied`); anonymous → `NeedsLogin`. Construct with
/// `UsersReadGroupWrite::new(&auth, ["admin"])`.
pub struct UsersReadGroupWrite {
    auth: Auth,
    write_groups: Vec<String>,
}

impl UsersReadGroupWrite {
    pub fn new<I, S>(auth: &Auth, write_groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            auth: auth.clone(),
            write_groups: write_groups.into_iter().map(Into::into).collect(),
        }
    }
}

#[async_trait]
impl Authz for UsersReadGroupWrite {
    async fn authorize(&self, op: Operation, headers: &HeaderMap) -> Decision {
        match self.auth.identify(headers).await {
            None => Decision::NeedsLogin,
            Some(_) if !op.is_write() => Decision::Allow,
            Some(who) => {
                if who.groups.iter().any(|g| self.write_groups.contains(g)) {
                    Decision::Allow
                } else {
                    Decision::Denied
                }
            }
        }
    }
}

/// Gate: only members of one of `admin_groups` may do anything (read *or* write); anonymous →
/// `NeedsLogin`, any other logged-in user → `Denied`. Construct with `AdminOnly::new(&auth,
/// ["admin"])` — the stricter sibling of [`UsersReadGroupWrite`] (which lets any logged-in user read).
/// Use it to keep whole models (e.g. the user/group tables) admin-only, and its [`admits`](AdminOnly::admits)
/// helper to decide admin-only UI from an already-resolved [`Identity`].
pub struct AdminOnly {
    auth: Auth,
    admin_groups: Vec<String>,
}

impl AdminOnly {
    pub fn new<I, S>(auth: &Auth, admin_groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            auth: auth.clone(),
            admin_groups: admin_groups.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether an already-resolved identity is in one of the admin groups (a header-free check, e.g.
    /// for hiding admin-only links without a second session lookup).
    pub fn admits(&self, who: &Identity) -> bool {
        who.in_any_group(&self.admin_groups)
    }
}

#[async_trait]
impl Authz for AdminOnly {
    async fn authorize(&self, _: Operation, headers: &HeaderMap) -> Decision {
        match self.auth.identify(headers).await {
            None => Decision::NeedsLogin,
            Some(who) if self.admits(&who) => Decision::Allow,
            Some(_) => Decision::Denied,
        }
    }
}

// ===================== Passwords (argon2id) =====================

/// Hash a password with argon2id, returning a PHC string suitable for storage.
pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hashing failed")
        .to_string()
}

/// Verify a password against a stored PHC hash (constant-time; `false` on any error).
pub fn verify_password(hash: &str, password: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

// ===================== Setup helpers =====================

/// Create the auth tables — `rl_user`, `rl_session`, `rl_group`, `rl_user_group` (use on a fresh DB
/// or with your own migrations). The app owns the database.
pub async fn migrate(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let schema = Schema::new(backend);
    db.execute(backend.build(&schema.create_table_from_entity(user::Entity))).await?;
    db.execute(backend.build(&schema.create_table_from_entity(session::Entity))).await?;
    db.execute(backend.build(&schema.create_table_from_entity(group::Entity))).await?;
    db.execute(backend.build(&schema.create_table_from_entity(user_group::Entity))).await?;
    Ok(())
}

/// Insert an active user with the given password (hashed with argon2id).
pub async fn create_user(db: &DatabaseConnection, username: &str, password: &str) -> Result<(), DbErr> {
    user::ActiveModel {
        username: Set(username.to_string()),
        password_hash: Set(hash_password(password)),
        is_active: Set(true),
        ..Default::default()
    }
    .insert(db)
    .await?;
    Ok(())
}

/// Set (or reset) a user's password — updates the hash and re-activates if the user exists, else
/// creates them. Convenient for an app CLI flag, e.g. `--set-admin-pw`:
///
/// ```ignore
/// if let Some(pw) = admin_pw_flag { auth::set_password(&db, "admin", &pw).await?; return Ok(()); }
/// ```
pub async fn set_password(db: &DatabaseConnection, username: &str, password: &str) -> Result<(), DbErr> {
    match user::Entity::find().filter(user::Column::Username.eq(username)).one(db).await? {
        Some(existing) => {
            let mut am = existing.into_active_model();
            am.password_hash = Set(hash_password(password));
            am.is_active = Set(true);
            am.update(db).await?;
            Ok(())
        }
        None => create_user(db, username, password).await,
    }
}

/// Ensure a group exists (create if missing); return its id. The group name is the app's choice
/// (e.g. a hard-coded constant or a config value — the admin/superadmin group).
pub async fn ensure_group(db: &DatabaseConnection, name: &str) -> Result<i32, DbErr> {
    if let Some(g) = group::Entity::find().filter(group::Column::Name.eq(name)).one(db).await? {
        return Ok(g.id);
    }
    let g = group::ActiveModel { name: Set(name.to_string()), ..Default::default() }.insert(db).await?;
    Ok(g.id)
}

/// Add a user (by username) to a group, creating the group if needed. Idempotent.
pub async fn add_to_group(db: &DatabaseConnection, username: &str, group_name: &str) -> Result<(), DbErr> {
    let user = user::Entity::find()
        .filter(user::Column::Username.eq(username))
        .one(db)
        .await?
        .ok_or_else(|| DbErr::Custom(format!("no such user: {username}")))?;
    let group_id = ensure_group(db, group_name).await?;
    if user_group::Entity::find_by_id((user.id, group_id)).one(db).await?.is_none() {
        user_group::ActiveModel { user_id: Set(user.id), group_id: Set(group_id) }.insert(db).await?;
    }
    Ok(())
}

/// Make a user an admin: (re-)set their password *and* ensure they're a member of the (configurable)
/// admin group, creating both as needed. Handy for an app's `--set-admin-pw` startup path.
pub async fn make_admin(
    db: &DatabaseConnection,
    admin_group: &str,
    username: &str,
    password: &str,
) -> Result<(), DbErr> {
    set_password(db, username, password).await?;
    add_to_group(db, username, admin_group).await
}

/// The group names a user belongs to.
async fn groups_of(db: &DatabaseConnection, user_id: i32) -> Vec<String> {
    let memberships = user_group::Entity::find()
        .filter(user_group::Column::UserId.eq(user_id))
        .all(db)
        .await
        .unwrap_or_default();
    let ids: Vec<i32> = memberships.into_iter().map(|m| m.group_id).collect();
    if ids.is_empty() {
        return Vec::new();
    }
    group::Entity::find()
        .filter(group::Column::Id.is_in(ids))
        .all(db)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|g| g.name)
        .collect()
}

// ===================== The Auth builder =====================

type LoginShell = Arc<dyn Fn(&str) -> String + Send + Sync>;
/// Wraps the profile/password fragment into a full page. Also handed the resolved [`Identity`] so the
/// app can render its chrome (e.g. the signed-in username in the navbar).
type ProfileShell = Arc<dyn Fn(&str, &Identity) -> String + Send + Sync>;

struct Inner {
    db: DatabaseConnection,
    admin_group: String,
    cookie_name: String,
    login_path: String,
    profile_path: String,
    secure_cookies: bool,
    ttl_secs: i64,
    /// Wraps the login-form fragment into a full page. Default: a minimal unstyled document; set
    /// [`Auth::login_shell`] to embed it in your Bootstrap (or other) shell so the app styles it.
    login_shell: LoginShell,
    /// Wraps the profile/password fragment into a full page (see [`Auth::profile_shell`]).
    profile_shell: ProfileShell,
    /// Groups whose members may reset *other* users' passwords. `None` → fall back to `[admin_group]`.
    profile_managers: Option<Vec<String>>,
    /// Issuer label shown in authenticator apps for TOTP enrolment (the `otpauth://` URL / QR).
    totp_issuer: String,
}

impl Inner {
    /// The groups that may reset *other* users' passwords: the configured manager groups, defaulting
    /// to the admin group.
    fn manager_groups(&self) -> Vec<String> {
        self.profile_managers.clone().unwrap_or_else(|| vec![self.admin_group.clone()])
    }

    /// Whether `who` may manage *someone else's* profile (i.e. is in a manager group).
    fn can_manage_others(&self, who: &Identity) -> bool {
        who.in_any_group(&self.manager_groups())
    }
}

/// Wires authn into an app: login/logout routes ([`routes`](Auth::routes)) and on-demand session
/// lookups ([`identify`](Auth::identify)). The app owns the router and merges the routes where it
/// likes; gates and page handlers call `identify` themselves — there is no middleware. Cheap to
/// clone (an `Arc` inside), so gates hold their own handle.
#[derive(Clone)]
pub struct Auth {
    inner: Arc<Inner>,
}

impl Auth {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                admin_group: "admin".into(),
                cookie_name: DEFAULT_COOKIE.into(),
                login_path: "/login".into(),
                profile_path: "/profile".into(),
                secure_cookies: true,
                ttl_secs: 7 * 24 * 3600,
                login_shell: Arc::new(default_login_shell),
                profile_shell: Arc::new(default_profile_shell),
                profile_managers: None,
                totp_issuer: "relativelylight".into(),
            }),
        }
    }

    /// Wrap the login-form fragment into a full page — embed it in your app's shell so *you* style it
    /// (e.g. a Bootstrap page). The closure receives the `<form>…</form>` fragment (which carries
    /// Bootstrap-friendly classes) and returns the full HTML document.
    pub fn login_shell(mut self, shell: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().login_shell = Arc::new(shell);
        self
    }

    /// Wrap the profile/password fragment into a full page — as [`login_shell`](Auth::login_shell),
    /// but the closure also receives the signed-in [`Identity`] so the app can render its chrome (e.g.
    /// the username in the navbar) around the fragment.
    pub fn profile_shell(
        mut self,
        shell: impl Fn(&str, &Identity) -> String + Send + Sync + 'static,
    ) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().profile_shell = Arc::new(shell);
        self
    }

    /// Group whose members may reset other users' passwords (used later). Default `"admin"`.
    pub fn admin_group(mut self, name: impl Into<String>) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().admin_group = name.into();
        self
    }

    /// Groups whose members may manage *other* users' profiles (password resets) on the profile page.
    /// Defaults to `[admin_group]`; set this to broaden or override it. A user can always manage their
    /// own profile regardless.
    pub fn profile_managers<I, S>(mut self, groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Arc::get_mut(&mut self.inner).unwrap().profile_managers =
            Some(groups.into_iter().map(Into::into).collect());
        self
    }

    /// The issuer label authenticator apps show for TOTP 2FA (default `"relativelylight"`). Usually
    /// your app/product name.
    pub fn totp_issuer(mut self, name: impl Into<String>) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().totp_issuer = name.into();
        self
    }

    /// Set the `Secure` cookie attribute (default `true`; set `false` for local http).
    pub fn secure_cookies(mut self, on: bool) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().secure_cookies = on;
        self
    }

    /// Session lifetime in seconds (default 7 days).
    pub fn session_ttl_secs(mut self, secs: i64) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().ttl_secs = secs;
        self
    }

    /// Session cookie name (default `"rl_session"`). Set from a constant or config on startup.
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().cookie_name = name.into();
        self
    }

    /// The configured admin group name.
    pub fn admin_group_name(&self) -> &str {
        &self.inner.admin_group
    }

    /// The configured session cookie name.
    pub fn session_cookie_name(&self) -> &str {
        &self.inner.cookie_name
    }

    /// The path to redirect anonymous users to (default `"/login"` — where [`routes`](Auth::routes)
    /// serves the login form). Gates return [`Decision::NeedsLogin`]; the app redirects here.
    pub fn login_path(&self) -> &str {
        &self.inner.login_path
    }

    /// The self-service profile/password page (default `"/profile"`). Link to it from the app shell
    /// (e.g. the signed-in username). Managing another user is `"{profile_path}/{user_id}"`.
    pub fn profile_path(&self) -> &str {
        &self.inner.profile_path
    }

    /// Whether `who` may reset *other* users' passwords — i.e. belongs to a profile-manager group
    /// (default `[admin_group]`, set with [`profile_managers`](Auth::profile_managers)). Handy for
    /// deciding whether to show an admin-only "reset password" link.
    pub fn can_manage_others(&self, who: &Identity) -> bool {
        self.inner.can_manage_others(who)
    }

    /// The auth pages, to merge into your router:
    /// - `GET/POST /login` and `GET/POST /login/totp` — password, then the TOTP second factor when the
    ///   user has 2FA enabled.
    /// - `GET /logout`.
    /// - `GET/POST /profile` — change your own password + manage your own 2FA.
    /// - `GET/POST /profile/totp` + `POST /profile/totp/disable` — enrol in / disable your own 2FA.
    /// - `GET/POST /profile/{id}` — a manager resets another user's password.
    /// - `POST /profile/{id}/totp/disable` — a manager disables another user's 2FA.
    pub fn routes(&self) -> Router {
        Router::new()
            .route("/login", get(login_form).post(login_submit))
            .route("/login/totp", get(login_totp_form).post(login_totp_submit))
            .route("/logout", get(logout))
            .route("/profile", get(profile_form).post(profile_submit))
            .route("/profile/totp", get(totp_setup_form).post(totp_setup_submit))
            .route("/profile/totp/disable", post(totp_self_disable))
            .route("/profile/{id}", get(manage_form).post(manage_submit))
            .route("/profile/{id}/totp/disable", post(totp_manage_disable))
            .with_state(self.inner.clone())
    }

    /// The logged-in [`Identity`] for a request, resolved from its session cookie (session → user →
    /// groups, one DB round-trip), or `None` if anonymous / expired / inactive. This is the whole of
    /// authn: call it from a gate or a page handler; nothing is injected into the request.
    pub async fn identify(&self, headers: &HeaderMap) -> Option<Identity> {
        let jar = CookieJar::from_headers(headers);
        let token = jar.get(&self.inner.cookie_name)?.value().to_string();
        identity_from(&self.inner, &token).await
    }
}

// ===================== Internals =====================

async fn identity_from(inner: &Inner, token: &str) -> Option<Identity> {
    let session = session::Entity::find_by_id(token.to_string()).one(&inner.db).await.ok()??;
    if session.expires_at < now_secs() || session.awaiting_totp {
        return None; // expired, or password-verified but the TOTP second factor is still pending
    }
    let user = user::Entity::find_by_id(session.user_id).one(&inner.db).await.ok()??;
    if !user.is_active {
        return None;
    }
    let groups = groups_of(&inner.db, user.id).await;
    Some(Identity { id: user.id.to_string(), username: user.username, groups })
}

/// Verify username + password. Returns the user on success (regardless of 2FA) — the caller decides
/// whether a second factor is still required (`user.totp_secret.is_some()`).
async fn verify_credentials(inner: &Inner, username: &str, password: &str) -> Option<user::Model> {
    let user = user::Entity::find()
        .filter(user::Column::Username.eq(username))
        .one(&inner.db)
        .await
        .ok()??;
    (user.is_active && verify_password(&user.password_hash, password)).then_some(user)
}

/// Create a session row and return its token. `awaiting_totp` marks it half-authenticated (password
/// ok, TOTP pending) — [`identity_from`] rejects such sessions until the code is confirmed.
async fn create_session(inner: &Inner, user_id: i32, awaiting_totp: bool) -> Option<String> {
    let token = new_token();
    session::ActiveModel {
        id: Set(token.clone()),
        user_id: Set(user_id),
        expires_at: Set(now_secs() + inner.ttl_secs),
        awaiting_totp: Set(awaiting_totp),
    }
    .insert(&inner.db)
    .await
    .ok()?;
    Some(token)
}

#[derive(serde::Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_form(State(inner): State<Arc<Inner>>) -> Html<String> {
    Html((inner.login_shell)(&login_form_html(None)))
}

async fn login_submit(
    State(inner): State<Arc<Inner>>,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(user) = verify_credentials(&inner, &form.username, &form.password).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Html((inner.login_shell)(&login_form_html(Some("Invalid username or password.")))),
        )
            .into_response();
    };
    let needs_totp = user.totp_secret.is_some();
    let Some(token) = create_session(&inner, user.id, needs_totp).await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response();
    };
    // The session cookie is set either way; while `awaiting_totp` it grants nothing until the second
    // factor is confirmed at /login/totp.
    let jar = jar.add(session_cookie(&inner, token));
    let dest = if needs_totp { "/login/totp" } else { "/" };
    (jar, Redirect::to(dest)).into_response()
}

/// `GET /login/totp` — the second-factor form, reached after a correct password when 2FA is on. Reads
/// the pending session; if there isn't one, sends the visitor back to /login.
async fn login_totp_form(State(inner): State<Arc<Inner>>, headers: HeaderMap) -> Response {
    match pending_totp_user(&inner, &headers).await {
        Some(_) => Html((inner.login_shell)(&totp_login_html(None))).into_response(),
        None => Redirect::to(&inner.login_path).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct TotpForm {
    code: String,
}

/// `POST /login/totp` — verify the code against the pending session's user; on success clear
/// `awaiting_totp` (the session becomes a real login) and land on `/`.
async fn login_totp_submit(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    Form(form): Form<TotpForm>,
) -> Response {
    let Some((session, user)) = pending_totp_user(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let ok = user.totp_secret.as_deref().is_some_and(|s| totp::verify(s, &form.code));
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Html((inner.login_shell)(&totp_login_html(Some("Invalid code. Try again.")))),
        )
            .into_response();
    }
    let mut am: session::ActiveModel = session.into();
    am.awaiting_totp = Set(false);
    let _ = am.update(&inner.db).await;
    Redirect::to("/").into_response()
}

/// Resolve the half-authenticated session (password ok, TOTP pending) and its user from the cookie.
async fn pending_totp_user(inner: &Inner, headers: &HeaderMap) -> Option<(session::Model, user::Model)> {
    let jar = CookieJar::from_headers(headers);
    let token = jar.get(&inner.cookie_name)?.value().to_string();
    let session = session::Entity::find_by_id(token).one(&inner.db).await.ok()??;
    if !session.awaiting_totp || session.expires_at < now_secs() {
        return None;
    }
    let user = user::Entity::find_by_id(session.user_id).one(&inner.db).await.ok()??;
    Some((session, user))
}

async fn logout(State(inner): State<Arc<Inner>>, jar: CookieJar) -> Response {
    if let Some(cookie) = jar.get(&inner.cookie_name) {
        let _ = session::Entity::delete_by_id(cookie.value().to_string()).exec(&inner.db).await;
    }
    let jar = jar.remove(Cookie::build(inner.cookie_name.clone()).path("/").build());
    (jar, Redirect::to("/login")).into_response()
}

// ---- profile / password change ----

#[derive(serde::Deserialize)]
struct ChangeForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
}

#[derive(serde::Deserialize)]
struct ResetForm {
    new_password: String,
    confirm_password: String,
}

/// Resolve the caller from the request cookie (as [`Auth::identify`], but from `Inner`).
async fn identity_of(inner: &Inner, headers: &HeaderMap) -> Option<Identity> {
    let jar = CookieJar::from_headers(headers);
    let token = jar.get(&inner.cookie_name)?.value().to_string();
    identity_from(inner, &token).await
}

async fn user_by_id(db: &DatabaseConnection, id: i32) -> Option<user::Model> {
    user::Entity::find_by_id(id).one(db).await.ok().flatten()
}

/// Whether the caller (by string id) currently has an active TOTP secret.
async fn totp_active(inner: &Inner, id_str: &str) -> bool {
    match id_str.parse::<i32>() {
        Ok(id) => user_by_id(&inner.db, id).await.is_some_and(|u| u.totp_secret.is_some()),
        Err(_) => false,
    }
}

/// `GET /profile` — the self-service change-password form + 2FA status (anonymous → login).
async fn profile_form(State(inner): State<Arc<Inner>>, headers: HeaderMap) -> Response {
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let totp_on = totp_active(&inner, &who.id).await;
    let frag = change_form_html(&who, totp_on, None, None);
    Html((inner.profile_shell)(&frag, &who)).into_response()
}

/// `POST /profile` — verify the current password, then set the new one for the caller.
async fn profile_submit(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    Form(form): Form<ChangeForm>,
) -> Response {
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let user = match who.id.parse::<i32>() {
        Ok(id) => user_by_id(&inner.db, id).await,
        Err(_) => None,
    };
    let Some(user) = user else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let totp_on = user.totp_secret.is_some();

    let error = if !verify_password(&user.password_hash, &form.current_password) {
        Some("Current password is incorrect.")
    } else {
        password_pair_error(&form.new_password, &form.confirm_password)
    };
    if let Some(msg) = error {
        let frag = change_form_html(&who, totp_on, Some(msg), None);
        return (StatusCode::BAD_REQUEST, Html((inner.profile_shell)(&frag, &who))).into_response();
    }

    if set_password(&inner.db, &who.username, &form.new_password).await.is_err() {
        let frag = change_form_html(&who, totp_on, Some("Could not change the password."), None);
        return (StatusCode::INTERNAL_SERVER_ERROR, Html((inner.profile_shell)(&frag, &who)))
            .into_response();
    }
    let frag = change_form_html(&who, totp_on, None, Some("Your password has been changed."));
    Html((inner.profile_shell)(&frag, &who)).into_response()
}

/// `GET /profile/{id}` — a manager's reset form for another user (self → own page; not a manager →
/// 403; unknown user → 404).
async fn manage_form(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    if who.id == id {
        return Redirect::to(&inner.profile_path).into_response();
    }
    if !inner.can_manage_others(&who) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    let Some(target) = target_user(&inner, &id).await else {
        return (StatusCode::NOT_FOUND, "No such user").into_response();
    };
    let frag = reset_form_html(&id, &target.username, target.totp_secret.is_some(), None, None);
    Html((inner.profile_shell)(&frag, &who)).into_response()
}

/// `POST /profile/{id}` — a manager sets another user's password (no current password required).
async fn manage_submit(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ResetForm>,
) -> Response {
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    if who.id == id {
        return Redirect::to(&inner.profile_path).into_response();
    }
    if !inner.can_manage_others(&who) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    let Some(target) = target_user(&inner, &id).await else {
        return (StatusCode::NOT_FOUND, "No such user").into_response();
    };
    let totp_on = target.totp_secret.is_some();

    if let Some(msg) = password_pair_error(&form.new_password, &form.confirm_password) {
        let frag = reset_form_html(&id, &target.username, totp_on, Some(msg), None);
        return (StatusCode::BAD_REQUEST, Html((inner.profile_shell)(&frag, &who))).into_response();
    }
    if set_password(&inner.db, &target.username, &form.new_password).await.is_err() {
        let frag =
            reset_form_html(&id, &target.username, totp_on, Some("Could not set the password."), None);
        return (StatusCode::INTERNAL_SERVER_ERROR, Html((inner.profile_shell)(&frag, &who)))
            .into_response();
    }
    let msg = format!("Password reset for {}.", target.username);
    let frag = reset_form_html(&id, &target.username, totp_on, None, Some(&msg));
    Html((inner.profile_shell)(&frag, &who)).into_response()
}

// ---- TOTP 2FA (setup / verify / disable) ----

/// `GET /profile/totp` — begin enrolment: mint a fresh pending secret, store it on the user, and show
/// the QR + `otpauth://` URL with a verify form. A new secret is generated on each visit.
async fn totp_setup_form(State(inner): State<Arc<Inner>>, headers: HeaderMap) -> Response {
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let Some(user) = current_user(&inner, &who).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let secret = totp::generate_secret();
    let mut am: user::ActiveModel = user.into();
    am.totp_pending = Set(Some(secret.clone()));
    if am.update(&inner.db).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not start 2FA setup").into_response();
    }
    render_totp_setup(&inner, &who, &secret, None)
}

/// `POST /profile/totp` — confirm enrolment: verify the code against the pending secret, then promote
/// it to the active secret (2FA now required at login). On a bad code, re-show the *same* QR.
async fn totp_setup_submit(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    Form(form): Form<TotpForm>,
) -> Response {
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let Some(user) = current_user(&inner, &who).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let Some(pending) = user.totp_pending.clone() else {
        return Redirect::to(&inner.profile_path).into_response(); // nothing in progress
    };
    if !totp::verify(&pending, &form.code) {
        return render_totp_setup(&inner, &who, &pending, Some("That code didn't match. Try again."));
    }
    let mut am: user::ActiveModel = user.into();
    am.totp_secret = Set(Some(pending));
    am.totp_pending = Set(None);
    if am.update(&inner.db).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not enable 2FA").into_response();
    }
    let frag = change_form_html(&who, true, None, Some("Two-factor authentication is now enabled."));
    Html((inner.profile_shell)(&frag, &who)).into_response()
}

/// `POST /profile/totp/disable` — the caller turns off their own 2FA.
async fn totp_self_disable(State(inner): State<Arc<Inner>>, headers: HeaderMap) -> Response {
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let Some(user) = current_user(&inner, &who).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    clear_totp(&inner, user).await;
    let frag = change_form_html(&who, false, None, Some("Two-factor authentication disabled."));
    Html((inner.profile_shell)(&frag, &who)).into_response()
}

/// `POST /profile/{id}/totp/disable` — a manager turns off *another* user's 2FA (they can re-enrol).
/// Managers can disable but never set up 2FA for someone else (enrolment needs the user's device).
async fn totp_manage_disable(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    if who.id == id {
        return Redirect::to(&inner.profile_path).into_response();
    }
    if !inner.can_manage_others(&who) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    let Some(target) = target_user(&inner, &id).await else {
        return (StatusCode::NOT_FOUND, "No such user").into_response();
    };
    let username = target.username.clone();
    clear_totp(&inner, target).await;
    let msg = format!("Two-factor authentication disabled for {username}.");
    let frag = reset_form_html(&id, &username, false, None, Some(&msg));
    Html((inner.profile_shell)(&frag, &who)).into_response()
}

/// The caller's own user row.
async fn current_user(inner: &Inner, who: &Identity) -> Option<user::Model> {
    let id = who.id.parse::<i32>().ok()?;
    user_by_id(&inner.db, id).await
}

/// Clear both the active and pending TOTP secrets on a user (best-effort).
async fn clear_totp(inner: &Inner, user: user::Model) {
    let mut am: user::ActiveModel = user.into();
    am.totp_secret = Set(None);
    am.totp_pending = Set(None);
    let _ = am.update(&inner.db).await;
}

/// Render the 2FA enrolment page (QR + otpauth URL + verify form) for a pending secret.
fn render_totp_setup(inner: &Inner, who: &Identity, secret: &str, error: Option<&str>) -> Response {
    let Some(prov) = totp::provisioning(&inner.totp_issuer, &who.username, secret) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not build QR code").into_response();
    };
    let frag = totp_setup_html(&prov, error);
    Html((inner.profile_shell)(&frag, who)).into_response()
}

/// Look up the target user by the (string) id from the URL. `None` if the id isn't an integer or no
/// such user exists.
async fn target_user(inner: &Inner, id: &str) -> Option<user::Model> {
    let uid = id.parse::<i32>().ok()?;
    user_by_id(&inner.db, uid).await
}

/// Shared validation for the new/confirm password pair.
fn password_pair_error(new: &str, confirm: &str) -> Option<&'static str> {
    if new.is_empty() {
        Some("New password cannot be empty.")
    } else if new != confirm {
        Some("The new passwords do not match.")
    } else {
        None
    }
}

/// Build the session cookie (HttpOnly, SameSite=Strict, Path=/, configurable Secure + Max-Age).
fn session_cookie(inner: &Inner, token: String) -> Cookie<'static> {
    Cookie::build((inner.cookie_name.clone(), token))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .secure(inner.secure_cookies)
        .max_age(time::Duration::seconds(inner.ttl_secs))
        .build()
}

fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The login `<form>` fragment. Semantic HTML with Bootstrap-friendly class hooks — it carries no
/// page chrome and loads no CSS; the app's [`Auth::login_shell`] wraps + styles it.
fn login_form_html(error: Option<&str>) -> String {
    let alert = error
        .map(|e| format!(r#"<div class="alert alert-danger" role="alert">{e}</div>"#))
        .unwrap_or_default();
    format!(
        r#"<form method="post" action="/login">
  {alert}
  <div class="mb-3">
    <label class="form-label" for="rl-username">Username</label>
    <input class="form-control" id="rl-username" name="username" autofocus autocomplete="username">
  </div>
  <div class="mb-3">
    <label class="form-label" for="rl-password">Password</label>
    <input class="form-control" id="rl-password" name="password" type="password" autocomplete="current-password">
  </div>
  <button class="btn btn-primary" type="submit">Log in</button>
</form>"#
    )
}

/// Default page wrapper when the app doesn't provide one: a minimal, unstyled document.
fn default_login_shell(form: &str) -> String {
    format!(r#"<!doctype html><meta charset="utf-8"><title>Log in</title><main>{form}</main>"#)
}

/// Escape text for interpolation into HTML.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// A Bootstrap alert for a form error (danger) or success message — empty when neither is set.
fn alert_html(error: Option<&str>, success: Option<&str>) -> String {
    if let Some(e) = error {
        format!(r#"<div class="alert alert-danger" role="alert">{}</div>"#, esc(e))
    } else if let Some(s) = success {
        format!(r#"<div class="alert alert-success" role="alert">{}</div>"#, esc(s))
    } else {
        String::new()
    }
}

/// The self-service change-password `<form>` fragment plus a two-factor section (Bootstrap-friendly
/// classes; no page chrome — the app's [`Auth::profile_shell`] wraps + styles it). `totp_on` is
/// whether the caller already has 2FA enabled.
fn change_form_html(
    who: &Identity,
    totp_on: bool,
    error: Option<&str>,
    success: Option<&str>,
) -> String {
    let alert = alert_html(error, success);
    let twofa = twofa_self_section(totp_on);
    format!(
        r#"<h1 class="h5 mb-3">Change your password</h1>
<p class="text-muted small">Signed in as <strong>{user}</strong>.</p>
<form method="post" action="/profile">
  {alert}
  <div class="mb-3">
    <label class="form-label" for="rl-current">Current password</label>
    <input class="form-control" id="rl-current" name="current_password" type="password" autocomplete="current-password" autofocus>
  </div>
  <div class="mb-3">
    <label class="form-label" for="rl-new">New password</label>
    <input class="form-control" id="rl-new" name="new_password" type="password" autocomplete="new-password">
  </div>
  <div class="mb-3">
    <label class="form-label" for="rl-confirm">Confirm new password</label>
    <input class="form-control" id="rl-confirm" name="confirm_password" type="password" autocomplete="new-password">
  </div>
  <button class="btn btn-primary" type="submit">Change password</button>
</form>
<hr class="my-4">
{twofa}"#,
        user = esc(&who.username),
    )
}

/// The self two-factor section: current state + a link to set up, or a button to disable.
fn twofa_self_section(on: bool) -> String {
    if on {
        r#"<h2 class="h6">Two-factor authentication</h2>
<p class="text-muted small mb-2">Enabled — a code from your authenticator app is required at login.</p>
<form method="post" action="/profile/totp/disable">
  <button class="btn btn-outline-danger btn-sm" type="submit">Disable 2FA</button>
</form>"#
            .to_string()
    } else {
        r#"<h2 class="h6">Two-factor authentication</h2>
<p class="text-muted small mb-2">Off. Add a second factor with an authenticator app (TOTP).</p>
<a class="btn btn-outline-primary btn-sm" href="/profile/totp">Set up 2FA</a>"#
            .to_string()
    }
}

/// The manager reset-password `<form>` fragment: sets another user's password with no current-password
/// check, plus a section to disable their 2FA. `id` is the target user id (used in the form actions).
fn reset_form_html(
    id: &str,
    username: &str,
    totp_on: bool,
    error: Option<&str>,
    success: Option<&str>,
) -> String {
    let alert = alert_html(error, success);
    let twofa = twofa_manage_section(id, username, totp_on);
    format!(
        r#"<h1 class="h5 mb-3">Reset password</h1>
<p class="text-muted">Set a new password for <strong>{user}</strong> (no current password required).</p>
<form method="post" action="/profile/{id}">
  {alert}
  <div class="mb-3">
    <label class="form-label" for="rl-new">New password</label>
    <input class="form-control" id="rl-new" name="new_password" type="password" autocomplete="new-password" autofocus>
  </div>
  <div class="mb-3">
    <label class="form-label" for="rl-confirm">Confirm new password</label>
    <input class="form-control" id="rl-confirm" name="confirm_password" type="password" autocomplete="new-password">
  </div>
  <button class="btn btn-primary" type="submit">Reset password</button>
</form>
<hr class="my-4">
{twofa}"#,
        user = esc(username),
        id = esc(id),
    )
}

/// The manager two-factor section: disable the target's 2FA (managers can't set it up for others).
fn twofa_manage_section(id: &str, username: &str, on: bool) -> String {
    if on {
        format!(
            r#"<h2 class="h6">Two-factor authentication</h2>
<p class="text-muted small mb-2">This user has 2FA enabled. Disabling it lets them log in with just a password until they set it up again.</p>
<form method="post" action="/profile/{id}/totp/disable">
  <button class="btn btn-outline-danger btn-sm" type="submit">Disable 2FA for {user}</button>
</form>"#,
            id = esc(id),
            user = esc(username),
        )
    } else {
        r#"<h2 class="h6">Two-factor authentication</h2>
<p class="text-muted small mb-0">This user has no two-factor authentication set up.</p>"#
            .to_string()
    }
}

/// The login second-factor `<form>` fragment (shown at `/login/totp` after a correct password).
fn totp_login_html(error: Option<&str>) -> String {
    let alert = alert_html(error, None);
    format!(
        r#"<h1 class="h5 mb-3">Two-factor authentication</h1>
<p class="text-muted small">Enter the 6-digit code from your authenticator app.</p>
<form method="post" action="/login/totp">
  {alert}
  <div class="mb-3">
    <label class="form-label" for="rl-totp">Authentication code</label>
    <input class="form-control" id="rl-totp" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus>
  </div>
  <button class="btn btn-primary" type="submit">Verify</button>
</form>"#
    )
}

/// The 2FA enrolment `<form>` fragment: the QR image, the `otpauth://` URL as copyable text, and a
/// code field to confirm before activation.
fn totp_setup_html(prov: &totp::Provisioning, error: Option<&str>) -> String {
    let alert = alert_html(error, None);
    format!(
        r#"<h1 class="h5 mb-3">Set up two-factor authentication</h1>
<p class="text-muted small">Scan this QR code with an authenticator app (or add the setup URL by hand), then enter the 6-digit code it shows to confirm.</p>
{alert}
<div class="text-center mb-3">
  <img src="{qr}" alt="TOTP QR code" width="200" height="200" style="image-rendering:pixelated">
</div>
<p class="small text-muted mb-1">Setup URL (otpauth)</p>
<pre class="bg-body-secondary p-2 rounded" style="white-space:pre-wrap;word-break:break-all"><code>{url}</code></pre>
<form method="post" action="/profile/totp">
  <div class="mb-3">
    <label class="form-label" for="rl-totp">Authentication code</label>
    <input class="form-control" id="rl-totp" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus>
  </div>
  <button class="btn btn-primary" type="submit">Verify &amp; enable</button>
  <a class="btn btn-link" href="/profile">Cancel</a>
</form>"#,
        qr = esc(&prov.qr_data_uri),
        url = esc(&prov.url),
    )
}

/// Default profile-page wrapper when the app doesn't provide one: a minimal, unstyled document.
fn default_profile_shell(fragment: &str, _who: &Identity) -> String {
    format!(r#"<!doctype html><meta charset="utf-8"><title>Profile</title><main>{fragment}</main>"#)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_group_membership() {
        let who = Identity { id: "1".into(), username: "u".into(), groups: vec!["admin".into()] };
        assert!(who.in_group("admin"));
        assert!(!who.in_group("editors"));
    }

    #[test]
    fn operation_write_classification() {
        assert!(!Operation::List.is_write());
        assert!(!Operation::Read.is_write());
        assert!(Operation::Create.is_write());
        assert!(Operation::Update.is_write());
        assert!(Operation::Delete.is_write());
    }

    #[test]
    fn password_roundtrip() {
        let hash = hash_password("s3cret");
        assert!(verify_password(&hash, "s3cret"));
        assert!(!verify_password(&hash, "wrong"));
    }

    #[test]
    fn identity_in_any_group() {
        let admin = Identity { id: "1".into(), username: "a".into(), groups: vec!["admin".into()] };
        let editor = Identity { id: "2".into(), username: "e".into(), groups: vec!["editors".into()] };
        let managers = vec!["admin".into(), "superadmin".into()];
        assert!(admin.in_any_group(&managers));
        assert!(!editor.in_any_group(&managers));
    }

    #[test]
    fn password_pair_validation() {
        assert!(password_pair_error("", "").is_some());
        assert!(password_pair_error("a", "b").is_some());
        assert!(password_pair_error("a", "a").is_none());
    }
}
