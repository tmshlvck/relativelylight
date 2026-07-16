//! `relativelylight::auth` — authentication (users, sessions, login, argon2id) + authorization
//! (a small [`Authz`] gate trait + presets). Usable on its own (feature `auth`, no `crud`): it gates
//! any axum app. See `docs/AUTH.md` for the full design.
//!
//! First slice (implemented): `user`/`session` SeaORM models, argon2id password hashing, a login /
//! logout flow with an opaque server-side session cookie, a session-resolving middleware
//! ([`Auth::wrap`]), the [`CurrentUser`] extractor, and the [`Authz`] trait + presets. Not yet:
//! groups, password change, 2FA/OIDC, and `crud` gating (the gate exists; wiring it into `crud`
//! handlers comes next).

pub mod group;
pub mod session;
pub mod user;
pub mod user_group;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{Form, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use rand_core::{OsRng, RngCore};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbErr, EntityTrait,
    IntoActiveModel, QueryFilter, Schema, Set,
};

const COOKIE: &str = "rl_session";

// ===================== Authorization =====================

/// The authenticated identity, put into request extensions by the auth middleware. `groups` is
/// empty until the group model lands (next slice).
#[derive(Clone, Debug)]
pub struct Principal {
    pub id: String,
    pub username: String,
    pub groups: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum WriteOp {
    Create,
    Update,
    Delete,
}

/// The authorization gate consulted per (operation, model). `who = None` is anonymous; `model` is
/// the entity slug so one impl can branch per model.
pub trait Authz: Send + Sync {
    fn can_list(&self, who: Option<&Principal>, model: &str) -> bool;
    fn can_read(&self, who: Option<&Principal>, model: &str) -> bool;
    fn can_write(&self, who: Option<&Principal>, model: &str, op: WriteOp) -> bool;
}

/// Everything allowed (no auth).
pub struct Open;
impl Authz for Open {
    fn can_list(&self, _: Option<&Principal>, _: &str) -> bool {
        true
    }
    fn can_read(&self, _: Option<&Principal>, _: &str) -> bool {
        true
    }
    fn can_write(&self, _: Option<&Principal>, _: &str, _: WriteOp) -> bool {
        true
    }
}

/// Any authenticated user may do anything; anonymous denied.
pub struct ValidUsers;
impl Authz for ValidUsers {
    fn can_list(&self, who: Option<&Principal>, _: &str) -> bool {
        who.is_some()
    }
    fn can_read(&self, who: Option<&Principal>, _: &str) -> bool {
        who.is_some()
    }
    fn can_write(&self, who: Option<&Principal>, _: &str, _: WriteOp) -> bool {
        who.is_some()
    }
}

/// Any authenticated user may list/read; writing requires membership in one of `write_groups`.
pub struct UsersReadGroupWrite {
    pub write_groups: Vec<String>,
}
impl Authz for UsersReadGroupWrite {
    fn can_list(&self, who: Option<&Principal>, _: &str) -> bool {
        who.is_some()
    }
    fn can_read(&self, who: Option<&Principal>, _: &str) -> bool {
        who.is_some()
    }
    fn can_write(&self, who: Option<&Principal>, _: &str, _: WriteOp) -> bool {
        who.is_some_and(|p| p.groups.iter().any(|g| self.write_groups.contains(g)))
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

struct Inner {
    db: DatabaseConnection,
    admin_group: String,
    secure_cookies: bool,
    ttl_secs: i64,
}

/// Wires authn into an app: login/logout routes ([`routes`](Auth::routes)) and a session-resolving
/// middleware ([`wrap`](Auth::wrap)) that puts a [`Principal`] into request extensions. The app owns
/// the router; it merges the routes and wraps its router where it likes.
pub struct Auth {
    inner: Arc<Inner>,
}

impl Auth {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            inner: Arc::new(Inner {
                db,
                admin_group: "admin".into(),
                secure_cookies: true,
                ttl_secs: 7 * 24 * 3600,
            }),
        }
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

    /// The configured admin group name.
    pub fn admin_group_name(&self) -> &str {
        &self.inner.admin_group
    }

    /// `GET/POST /login`, `GET /logout`. Merge into your router.
    pub fn routes(&self) -> Router {
        Router::new()
            .route("/login", get(login_form).post(login_submit))
            .route("/logout", get(logout))
            .with_state(self.inner.clone())
    }

    /// Wrap a router so every request resolves the session cookie → `Principal` (in extensions).
    pub fn wrap(&self, router: Router) -> Router {
        router.layer(from_fn_with_state(self.inner.clone(), resolve_session))
    }
}

// ===================== Extractor =====================

/// Extracts the authenticated [`Principal`]; redirects to `/login` when anonymous. Use it on any
/// handler that requires a logged-in user.
pub struct CurrentUser(pub Principal);

impl<S> FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
{
    type Rejection = Redirect;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .map(CurrentUser)
            .ok_or_else(|| Redirect::to("/login"))
    }
}

// ===================== Internals =====================

async fn resolve_session(State(inner): State<Arc<Inner>>, mut req: Request, next: Next) -> Response {
    if let Some(principal) = principal_from(&inner, req.headers()).await {
        req.extensions_mut().insert(principal);
    }
    next.run(req).await
}

async fn principal_from(inner: &Inner, headers: &HeaderMap) -> Option<Principal> {
    let token = cookie_token(headers)?;
    let session = session::Entity::find_by_id(token).one(&inner.db).await.ok()??;
    if session.expires_at < now_secs() {
        return None;
    }
    let user = user::Entity::find_by_id(session.user_id).one(&inner.db).await.ok()??;
    if !user.is_active {
        return None;
    }
    let groups = groups_of(&inner.db, user.id).await;
    Some(Principal { id: user.id.to_string(), username: user.username, groups })
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

async fn login_form() -> Html<String> {
    Html(login_page(None))
}

async fn login_submit(State(inner): State<Arc<Inner>>, Form(form): Form<LoginForm>) -> Response {
    match authenticate(&inner, &form.username, &form.password).await {
        Some(token) => {
            ([(header::SET_COOKIE, cookie_value(&inner, &token))], Redirect::to("/")).into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Html(login_page(Some("Invalid username or password."))),
        )
            .into_response(),
    }
}

async fn logout(State(inner): State<Arc<Inner>>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_token(&headers) {
        let _ = session::Entity::delete_by_id(token).exec(&inner.db).await;
    }
    let cleared = format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0");
    ([(header::SET_COOKIE, cleared)], Redirect::to("/login")).into_response()
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{COOKIE}=");
    raw.split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&prefix).map(str::to_string))
}

fn cookie_value(inner: &Inner, token: &str) -> String {
    let secure = if inner.secure_cookies { "; Secure" } else { "" };
    format!("{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}{secure}", inner.ttl_secs)
}

fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn login_page(error: Option<&str>) -> String {
    let err = error
        .map(|e| format!(r#"<p style="color:#b00">{e}</p>"#))
        .unwrap_or_default();
    format!(
        r#"<!doctype html><meta charset="utf-8"><title>Log in</title>
<h1>Log in</h1>{err}
<form method="post" action="/login">
  <p><label>Username <input name="username" autofocus></label></p>
  <p><label>Password <input name="password" type="password"></label></p>
  <p><button type="submit">Log in</button></p>
</form>"#
    )
}
