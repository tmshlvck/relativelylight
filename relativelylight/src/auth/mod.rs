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
//! on-demand [`Auth::identify`], the gate presets, admin helpers (`make_admin`, `set_password`,
//! `add_to_group`, …), and per-model enforcement in the `crud` HTTP handlers via
//! `crud::seaorm::Crud::register`. Not yet: a password-change UI, the CSRF/CORS/real-ip/logging
//! middleware, and 2FA/OIDC.
//!
//! The session cookie (name configurable, default `rl_session`) carries only an **opaque token** —
//! the id of a row in the session table; the identity is rebuilt server-side from the DB on each
//! lookup, and deleting the row revokes it.

pub mod group;
pub mod session;
pub mod user;
pub mod user_group;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use async_trait::async_trait;
use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
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

struct Inner {
    db: DatabaseConnection,
    admin_group: String,
    cookie_name: String,
    login_path: String,
    secure_cookies: bool,
    ttl_secs: i64,
    /// Wraps the login-form fragment into a full page. Default: a minimal unstyled document; set
    /// [`Auth::login_shell`] to embed it in your Bootstrap (or other) shell so the app styles it.
    login_shell: LoginShell,
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
                secure_cookies: true,
                ttl_secs: 7 * 24 * 3600,
                login_shell: Arc::new(default_login_shell),
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

    /// Group whose members may reset other users' passwords (used later). Default `"admin"`.
    pub fn admin_group(mut self, name: impl Into<String>) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().admin_group = name.into();
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

    /// `GET/POST /login`, `GET /logout`. Merge into your router.
    pub fn routes(&self) -> Router {
        Router::new()
            .route("/login", get(login_form).post(login_submit))
            .route("/logout", get(logout))
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
    if session.expires_at < now_secs() {
        return None;
    }
    let user = user::Entity::find_by_id(session.user_id).one(&inner.db).await.ok()??;
    if !user.is_active {
        return None;
    }
    let groups = groups_of(&inner.db, user.id).await;
    Some(Identity { id: user.id.to_string(), username: user.username, groups })
}

async fn authenticate(inner: &Inner, username: &str, password: &str) -> Option<String> {
    let user = user::Entity::find()
        .filter(user::Column::Username.eq(username))
        .one(&inner.db)
        .await
        .ok()??;
    if !user.is_active || !verify_password(&user.password_hash, password) {
        return None;
    }
    let token = new_token();
    session::ActiveModel {
        id: Set(token.clone()),
        user_id: Set(user.id),
        expires_at: Set(now_secs() + inner.ttl_secs),
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
    match authenticate(&inner, &form.username, &form.password).await {
        Some(token) => (jar.add(session_cookie(&inner, token)), Redirect::to("/")).into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Html((inner.login_shell)(&login_form_html(Some("Invalid username or password.")))),
        )
            .into_response(),
    }
}

async fn logout(State(inner): State<Arc<Inner>>, jar: CookieJar) -> Response {
    if let Some(cookie) = jar.get(&inner.cookie_name) {
        let _ = session::Entity::delete_by_id(cookie.value().to_string()).exec(&inner.db).await;
    }
    let jar = jar.remove(Cookie::build(inner.cookie_name.clone()).path("/").build());
    (jar, Redirect::to("/login")).into_response()
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
}
