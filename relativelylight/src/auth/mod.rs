//! `relativelylight::auth` — authentication (users, sessions, login, argon2id) + authorization
//! (a small [`Authz`] gate trait + presets). Usable on its own (feature `auth`, no `crud`): it gates
//! any axum app. See `docs/AUTH.md` for the full design.
//!
//! There is **no middleware and no injected request context**. Authn is a handful of on-demand
//! lookups on [`Auth`]: given a request's headers, [`Auth::identify`] resolves the session cookie →
//! user → groups in one query and returns an [`Identity`] (or `None` for anonymous). The
//! authorization gate itself lives in [`crate::authz`]; the presets here ([`UserReadWrite`],
//! [`UserReadGroupWrite`]) implement it by resolving the identity with an `Auth` handle and
//! returning a [`Decision`](crate::authz::Decision) the caller renders.
//!
//! Implemented: the `user`/`session`/`group`/`user_group` SeaORM models, argon2id hashing, a
//! login/logout flow with an opaque server-side session cookie (via `axum-extra`'s `CookieJar`),
//! **TOTP two-factor authentication** (a second-factor step at login, plus self-service enrolment /
//! disable on the profile page and a manager disable for other users), on-demand [`Auth::identify`],
//! the gate presets ([`UserReadWrite`], [`UserReadGroupWrite`], [`GroupReadWrite`]), a self-service
//! **profile / password-change** page plus a manager reset (`GET/POST /profile`,
//! `GET/POST /profile/{id}` — see [`Auth::routes`]), admin helpers ([`make_admin`] to seed one,
//! [`reset_admin_access`] for break-glass recovery, [`set_password`], [`add_to_group`], …), and
//! per-model enforcement in the `crud` HTTP handlers via
//! `crud::seaorm::Crud::register`, plus **OIDC single sign-on** (feature `sso`, module [`sso`]:
//! Google / Okta / corporate, with username- and claim-based group mapping and optional
//! auto-registration). Not yet: the CSRF/CORS/real-ip/logging middleware and PassKeys.
//!
//! The session cookie (name configurable, default `rl_session`) carries only an **opaque token** —
//! the id of a row in the session table; the identity is rebuilt server-side from the DB on each
//! lookup, and deleting the row revokes it.

pub mod group;
/// Lockout (§5e): the two DB-backed failure counters — by account name and by source address —
/// braking the unauthenticated credential checks, here and in the app.
pub mod lockout;
/// TOTP **recovery codes** (§5i): single-use codes that get a user back in when the authenticator is
/// gone, issued at enrolment and regenerable from the profile page.
pub mod recovery;
/// Negative-path (rejection) tests for the auth surface — see the module's own docs.
#[cfg(test)]
mod security_tests;
pub mod session;
#[cfg(feature = "sso")]
pub mod sso;

/// The OIDC callback's rejection paths, driven against a fake identity provider (feature `sso`).
#[cfg(all(test, feature = "sso"))]
mod sso_tests;
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
use crate::middleware::RealIp;
use rand_core::OsRng;
use sea_orm::sea_query::TableCreateStatement;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, DbErr,
    EntityTrait, IntoActiveModel, QueryFilter, Schema, Set,
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

// ===================== Authorization gate presets =====================
//
// The presets name the **read audience** and the **write audience**, each one of Public (anyone,
// incl. anonymous) → User (any authenticated user) → Group (member of one of the named groups),
// narrowing left-to-right. `authz::Open` is the Public/Public corner (ungated, always compiled).
// When read and write share an audience the name collapses (`UserReadWrite`, `GroupReadWrite`);
// otherwise it spells both (`UserReadGroupWrite`, `PublicReadGroupWrite`). Anonymous callers to a
// write they could satisfy once logged in get `NeedsLogin`; a logged-in caller lacking the group
// gets `Denied`.

/// Gate: any authenticated user may read *and* write; anonymous → `NeedsLogin`. Holds an [`Auth`]
/// handle to resolve the caller; construct with `UserReadWrite::new(&auth)`.
pub struct UserReadWrite(Auth);

impl UserReadWrite {
    pub fn new(auth: &Auth) -> Self {
        Self(auth.clone())
    }
}

#[async_trait]
impl Authz for UserReadWrite {
    async fn authorize(&self, _: Operation, headers: &HeaderMap) -> Decision {
        match self.0.identify(headers).await {
            Some(_) => Decision::Allow,
            None => Decision::NeedsLogin,
        }
    }
}

/// Gate: any authenticated user may read; a write requires membership in one of `write_groups`
/// (else `Denied`); anonymous → `NeedsLogin`. Construct with
/// `UserReadGroupWrite::new(&auth, ["editors"])`.
pub struct UserReadGroupWrite {
    auth: Auth,
    write_groups: Vec<String>,
}

impl UserReadGroupWrite {
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
impl Authz for UserReadGroupWrite {
    async fn authorize(&self, op: Operation, headers: &HeaderMap) -> Decision {
        match self.auth.identify(headers).await {
            None => Decision::NeedsLogin,
            Some(_) if !op.is_write() => Decision::Allow,
            Some(who) if who.in_any_group(&self.write_groups) => Decision::Allow,
            Some(_) => Decision::Denied,
        }
    }
}

/// Gate: **anyone** (including anonymous) may read; a write requires membership in one of
/// `write_groups` — anonymous writers → `NeedsLogin`, other logged-in users → `Denied`. The
/// public-read sibling of [`UserReadGroupWrite`]; e.g. a publicly readable catalog that only staff
/// may edit. Construct with `PublicReadGroupWrite::new(&auth, ["editors"])`.
pub struct PublicReadGroupWrite {
    auth: Auth,
    write_groups: Vec<String>,
}

impl PublicReadGroupWrite {
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
impl Authz for PublicReadGroupWrite {
    async fn authorize(&self, op: Operation, headers: &HeaderMap) -> Decision {
        if !op.is_write() {
            return Decision::Allow; // public read
        }
        match self.auth.identify(headers).await {
            None => Decision::NeedsLogin,
            Some(who) if who.in_any_group(&self.write_groups) => Decision::Allow,
            Some(_) => Decision::Denied,
        }
    }
}

/// Gate: only members of one of `groups` may read *or* write; anonymous → `NeedsLogin`, any other
/// logged-in user → `Denied`. Construct with `GroupReadWrite::new(&auth, ["admin"])` — the strict
/// sibling of [`UserReadGroupWrite`] (which lets any logged-in user read). Use it to keep whole
/// models (e.g. the user/group tables) group-only, and its [`admits`](GroupReadWrite::admits) helper
/// to decide group-only UI from an already-resolved [`Identity`].
pub struct GroupReadWrite {
    auth: Auth,
    groups: Vec<String>,
}

impl GroupReadWrite {
    pub fn new<I, S>(auth: &Auth, groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            auth: auth.clone(),
            groups: groups.into_iter().map(Into::into).collect(),
        }
    }

    /// Whether an already-resolved identity is in one of the gate's groups (a header-free check, e.g.
    /// for hiding group-only links without a second session lookup).
    pub fn admits(&self, who: &Identity) -> bool {
        who.in_any_group(&self.groups)
    }
}

#[async_trait]
impl Authz for GroupReadWrite {
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

/// The `CREATE TABLE` statements for the auth tables — `auth_user`, `auth_group`, `auth_user_group`,
/// `auth_session` (in that order). Use these to fold the auth schema into your own **`sea-orm-migration`**
/// migration so it's versioned alongside your app tables — the recommended approach for anything
/// long-lived (see `docs/AUTH.md`):
///
/// ```ignore
/// // inside a MigrationTrait::up(&self, manager: &SchemaManager)
/// for stmt in relativelylight::auth::table_create_statements(manager.get_database_backend()) {
///     manager.create_table(stmt).await?;
/// }
/// ```
pub fn table_create_statements(backend: DbBackend) -> Vec<TableCreateStatement> {
    let schema = Schema::new(backend);
    vec![
        schema.create_table_from_entity(user::Entity),
        schema.create_table_from_entity(group::Entity),
        schema.create_table_from_entity(user_group::Entity),
        schema.create_table_from_entity(session::Entity),
        schema.create_table_from_entity(lockout::username_entity::Entity),
        schema.create_table_from_entity(lockout::ip_entity::Entity),
        schema.create_table_from_entity(recovery::entity::Entity),
    ]
}

/// Housekeeping: delete expired sessions and expired lockout rows. **Nothing in this crate schedules
/// it** — call it from the app's own periodic loop (and once at startup), the way you'd run any other
/// retention job. Skipping it is safe: an expired session never authenticates and an expired lockout
/// row reads as unlocked (and resets itself on the next failure); the rows just accumulate.
///
/// Returns how many rows were deleted, in total.
///
/// **Prefer [`Auth::prune`]** if you have an `Auth` to hand. This function sees only the **absolute**
/// session deadline; it takes no `Auth`, so it cannot know your
/// [`session_idle_secs`](Auth::session_idle_secs) and will leave idle-expired rows in place until their
/// absolute deadline passes. Those rows never authenticate either way — it's a tidiness difference, not
/// a security one.
pub async fn prune(db: &DatabaseConnection, lockout: &lockout::Lockout) -> Result<u64, DbErr> {
    let sessions = session::Entity::delete_many()
        .filter(session::Column::ExpiresAt.lt(now_secs()))
        .exec(db)
        .await?
        .rows_affected;
    let usernames =
        lockout::UsernameLockout::new(db.clone(), lockout.username_after, lockout.username_duration_secs)
            .prune()
            .await?;
    let ips = lockout::IpLockout::new(db.clone(), lockout.ip_after, lockout.ip_duration_secs, vec![])
        .prune()
        .await?;
    Ok(sessions + usernames + ips)
}

/// Create the auth tables **if they don't already exist** — a bootstrap convenience for a fresh DB or
/// the examples. Safe to call on every start.
///
/// This is **not** a migration tool: it only ever *creates* missing tables, so it won't add columns
/// or otherwise evolve an existing schema across library upgrades (e.g. the TOTP / SSO columns added
/// to `auth_user`). For anything long-lived, drive the schema with **`sea-orm-migration`** and feed it
/// [`table_create_statements`] instead of calling this. The app owns the database either way.
pub async fn migrate(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    for mut stmt in table_create_statements(backend) {
        stmt.if_not_exists();
        db.execute(backend.build(&stmt)).await?;
    }
    Ok(())
}

/// Validate a username before it becomes an identity key. Enforced by [`create_user`] (and thus the
/// `set_password`/`make_admin` create paths) and by the SSO auto-registration path; apps should also
/// wire it into the admin form —
/// `user_mm.field("username").validate_str(relativelylight::auth::valid_username)`.
///
/// Requires a non-empty name of at most 254 bytes with **no whitespace or control characters** —
/// permissive enough for both plain usernames and email-style names (e.g. an OIDC `email` claim),
/// while keeping spaces / control bytes out of logs, audit records, and the identity/session layer.
pub fn valid_username(s: &str) -> std::result::Result<(), String> {
    crate::validate::non_empty(s)?;
    crate::validate::length_bytes(1, 254)(s)?;
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("username must not contain spaces or control characters".into());
    }
    Ok(())
}

/// Validate a group name (enforced by [`ensure_group`]). Non-empty, ≤ 254 bytes, no control
/// characters. Spaces are allowed (e.g. `"Site Admins"`), unlike [`valid_username`].
pub fn valid_group_name(s: &str) -> std::result::Result<(), String> {
    crate::validate::non_empty(s)?;
    crate::validate::length_bytes(1, 254)(s)?;
    if s.chars().any(|c| c.is_control()) {
        return Err("group name must not contain control characters".into());
    }
    Ok(())
}

/// Insert an active user with the given password (hashed with argon2id).
pub async fn create_user(db: &DatabaseConnection, username: &str, password: &str) -> Result<(), DbErr> {
    valid_username(username).map_err(DbErr::Custom)?;
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

/// Reset an **existing** user's password. Errors if there's no such user — creating an account is
/// [`create_user`]'s job, so a typo'd username can't silently become a new login.
///
/// It writes **only** the hash. Everything that decides whether the account can log in is left
/// exactly as it was: a **disabled** account (`is_active = false`) gets the new password and stays
/// disabled, 2FA stays on, and an SSO account still refuses password login. A password reset is
/// therefore never a way to re-open a closed account — re-opening one is
/// [`reset_admin_access`] (break-glass) or an explicit `is_active` edit in the admin UI.
pub async fn set_password(db: &DatabaseConnection, username: &str, password: &str) -> Result<(), DbErr> {
    let existing = user::Entity::find()
        .filter(user::Column::Username.eq(username))
        .one(db)
        .await?
        .ok_or_else(|| DbErr::Custom(format!("no such user: {username}")))?;
    let mut am = existing.into_active_model();
    am.password_hash = Set(hash_password(password));
    am.update(db).await?;
    Ok(())
}

/// Ensure a group exists (create if missing); return its id. The group name is the app's choice
/// (e.g. a hard-coded constant or a config value — the admin/superadmin group).
pub async fn ensure_group(db: &DatabaseConnection, name: &str) -> Result<i32, DbErr> {
    valid_group_name(name).map_err(DbErr::Custom)?;
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

/// Remove a user (by username) from a group. Idempotent — a missing user, group, or membership is a
/// no-op; the group itself is left in place. Used by SSO login reconciliation.
pub async fn remove_from_group(
    db: &DatabaseConnection,
    username: &str,
    group_name: &str,
) -> Result<(), DbErr> {
    let Some(user) = user::Entity::find().filter(user::Column::Username.eq(username)).one(db).await?
    else {
        return Ok(());
    };
    let Some(group) =
        group::Entity::find().filter(group::Column::Name.eq(group_name)).one(db).await?
    else {
        return Ok(());
    };
    user_group::Entity::delete_by_id((user.id, group.id)).exec(db).await?;
    Ok(())
}

/// Make a user an admin: set their password *and* ensure they're a member of the (configurable) admin
/// group, creating user and group as needed. **Idempotent and safe to run on every start** — the
/// seed-an-admin call the examples make.
///
/// It touches only the password and the group membership: an existing account keeps its `is_active`
/// flag and its 2FA enrolment, so a boot-time seeder can't strip an admin's authenticator. A brand-new
/// account is created active (via [`create_user`]). If the point is to *restore* access to a locked-out
/// admin, use [`reset_admin_access`] — that one is deliberately destructive and operator-run.
pub async fn make_admin(
    db: &DatabaseConnection,
    admin_group: &str,
    username: &str,
    password: &str,
) -> Result<(), DbErr> {
    match user::Entity::find().filter(user::Column::Username.eq(username)).one(db).await? {
        Some(_) => set_password(db, username, password).await?,
        None => create_user(db, username, password).await?,
    }
    add_to_group(db, username, admin_group).await
}

/// **Break-glass admin recovery** — the one path that re-opens an account, for an app's
/// `--set-admin-pw`-style CLI flag:
///
/// ```ignore
/// if let Some(pw) = admin_pw_flag {
///     auth::reset_admin_access(&db, ADMIN_GROUP, "admin", &pw).await?;
///     return Ok(()); // operator action: set it, then exit
/// }
/// ```
///
/// Creates the user if missing, then makes sure they can actually get back in: sets the password,
/// sets `is_active = true`, **clears TOTP 2FA** (both the active and the pending secret), and ensures
/// admin-group membership. So it is destructive by design — an enrolled authenticator is discarded and
/// the admin must re-enrol from `/profile`. **Run it from a CLI flag an operator invokes, never on
/// every start**; the boot-time seeder is [`make_admin`].
///
/// Refuses an **SSO** account (`Err`): clearing its `sso_provider` to graft on a local password would
/// silently take the account out of the identity provider's hands (and its group reconciliation), so
/// point break-glass at a local username instead.
pub async fn reset_admin_access(
    db: &DatabaseConnection,
    admin_group: &str,
    username: &str,
    password: &str,
) -> Result<(), DbErr> {
    match user::Entity::find().filter(user::Column::Username.eq(username)).one(db).await? {
        Some(existing) => {
            if let Some(provider) = existing.sso_key().map(str::to_string) {
                return Err(DbErr::Custom(format!(
                    "{username} signs in through '{provider}' (SSO): a local password would be refused \
                     at login — use a local username for break-glass access, or clear its sso_provider \
                     deliberately first"
                )));
            }
            let mut am = existing.into_active_model();
            am.password_hash = Set(hash_password(password));
            am.is_active = Set(true);
            am.totp_secret = Set(None);
            am.totp_pending = Set(None);
            am.update(db).await?;
        }
        None => create_user(db, username, password).await?,
    }
    add_to_group(db, username, admin_group).await
}

/// Rewrite blank `sso_provider` / `totp_secret` / `totp_pending` values on `auth_user` to `NULL` — a
/// one-off cleanup for rows written before the admin UI knew that an empty input on a nullable column
/// means "nothing here" (see `docs/CRUD.md` § nullable columns). Returns the number of rows touched.
///
/// The readers tolerate blanks either way ([`user::Model::sso_key`], [`totp_key`](user::Model::totp_key)),
/// so this is hygiene rather than a fix: it stops the column being `NULL` for some rows and `""` for
/// others, which is what trips up hand-written queries. Safe to call on every start, or once from a
/// migration.
pub async fn normalize_blank_user_columns(db: &DatabaseConnection) -> Result<u64, DbErr> {
    let mut touched = 0;
    for col in [user::Column::SsoProvider, user::Column::TotpSecret, user::Column::TotpPending] {
        let res = user::Entity::update_many()
            .col_expr(col, sea_orm::sea_query::Expr::value(Option::<String>::None))
            .filter(col.eq(""))
            .exec(db)
            .await?;
        touched += res.rows_affected;
    }
    Ok(touched)
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
/// Renders an extra app-owned section appended below the password/2FA fragment on the *self* profile
/// page (e.g. API-token management). Handed the caller's [`Identity`]; returns an HTML fragment.
type ProfileExtra = Arc<
    dyn Fn(Identity) -> std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send>>
        + Send
        + Sync,
>;

/// Checks a **new** password: `(password, username)` → `Ok(())` or a message to show the user. The
/// username is passed so a policy can refuse a password containing it — that check is cross-field, so a
/// single-field validator can't do it. See [`Auth::password_policy`] / [`Auth::password_check`].
type PasswordCheck = Arc<dyn Fn(&str, &str) -> Result<(), String> + Send + Sync>;

struct Inner {
    db: DatabaseConnection,
    admin_group: String,
    cookie_name: String,
    login_path: String,
    profile_path: String,
    secure_cookies: bool,
    /// The **absolute** session lifetime (see [`Auth::session_ttl_secs`]).
    ttl_secs: i64,
    /// The **idle** session lifetime, `0` = no idle timeout (see [`Auth::session_idle_secs`]).
    idle_secs: i64,
    /// Optional audit sink; fired from the mutating auth handlers (password change, manager reset).
    observer: Option<Arc<dyn crate::observe::WriteObserver>>,
    /// Wraps the login-form fragment into a full page. Default: a minimal unstyled document; set
    /// [`Auth::login_shell`] to embed it in your Bootstrap (or other) shell so the app styles it.
    login_shell: LoginShell,
    /// Wraps the profile/password fragment into a full page (see [`Auth::profile_shell`]).
    profile_shell: ProfileShell,
    /// Optional app-owned section rendered below password/2FA on the self profile page.
    profile_extra: Option<ProfileExtra>,
    /// Groups whose members may reset *other* users' passwords. `None` → fall back to `[admin_group]`.
    profile_managers: Option<Vec<String>>,
    /// Issuer label shown in authenticator apps for TOTP enrolment (the `otpauth://` URL / QR).
    totp_issuer: String,
    /// Name of the double-submit CSRF cookie (see [`crate::csrf`]).
    csrf_cookie: String,
    /// The app's own CSRF rejection page, if any (see [`Auth::csrf_rejection`]).
    csrf_reject: Option<crate::csrf::RejectFn>,
    /// The failure counters: DB-backed, shared with the app for credentials this module never sees.
    usernames: lockout::UsernameLockout,
    ips: lockout::IpLockout,
    /// Strength check for a new password; `None` disables it (see [`Auth::password_policy`]).
    password_check: Option<PasswordCheck>,
}

impl Inner {
    /// Whether this account — or this source address — is locked out of credential checks:
    /// `Some(retry_after_secs)` if so. Checked *before* the secret is looked at, and only on the
    /// unauthenticated routes (`/login`, `/login/totp`). The address comes from
    /// [`RealIp`](crate::middleware::RealIp), resolved once at the edge.
    async fn locked_out(&self, username: &str, ip: std::net::IpAddr) -> Option<i64> {
        let by_user = self.usernames.locked(username).await;
        let by_ip = self.ips.locked(Some(ip)).await;
        match (by_user, by_ip) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }

    /// Record one failed credential check, against the account **and** the source address. Only ever
    /// called for an attempt we actually *checked*.
    async fn record_failure(&self, username: &str, ip: std::net::IpAddr) {
        self.usernames.record_failure(username).await;
        self.ips.record_failure(Some(ip)).await;
    }

    /// Whether a new password is strong enough, per the configured policy (`None` when checking is
    /// switched off). The username is passed as context so a password containing it is refused.
    fn password_error(&self, password: &str, username: &str) -> Option<String> {
        self.password_check.as_ref().and_then(|c| c(password, username).err())
    }

    /// Re-authenticate the holder of `user`: their current password, or a fresh TOTP code when 2FA is
    /// on. `Ok(())` on success **or** when the account has no local factor to ask for. See
    /// [`Auth::reauthenticate`] for what this is protecting against and why the no-factor case passes.
    ///
    /// A code accepted here is **spent** (the §5a replay guard), so it can't then be used to log in or
    /// to confirm a second sensitive action inside its window.
    async fn reauth(&self, user: &user::Model, password: &str, code: &str) -> Result<(), String> {
        let has_password = !user.password_hash.is_empty();
        if !has_password && !user.has_totp() {
            return Ok(()); // nothing to prove with — see the doc comment on `Auth::reauthenticate`
        }
        // The code path first: a fresh code is better evidence of presence than a password, which a
        // browser may have filled in for whoever is sitting there.
        if !code.trim().is_empty() {
            if let Some(secret) = user.totp_key() {
                return match totp::verify_step(secret, code) {
                    Some(step) if user.totp_step_ok(step) => {
                        stamp_login(&self.db, user.id, Some(step)).await; // spend it
                        Ok(())
                    }
                    _ => Err("That code is not valid. Try the current one from your app.".into()),
                };
            }
            return Err("This account has no authenticator app — enter your password instead.".into());
        }
        if !password.is_empty() {
            return if has_password && verify_password(&user.password_hash, password) {
                Ok(())
            } else {
                Err("That password is incorrect.".into())
            };
        }
        Err(match user.has_totp() {
            true => "Confirm with your password or a code from your authenticator app.".into(),
            false => "Confirm with your current password.".into(),
        })
    }

    /// Whether this session is still alive on **both** clocks: inside its absolute deadline, and used
    /// within the idle window (when one is configured). Says nothing about `awaiting_totp` — the callers
    /// differ on whether a half-authenticated session is what they want.
    fn session_live(&self, session: &session::Model) -> bool {
        let now = now_secs();
        if session.expires_at < now {
            return false;
        }
        self.idle_secs == 0 || session.last_seen_at + self.idle_secs >= now
    }

    /// Push a live session's idle clock forward — but only once the stamp is [`IDLE_REFRESH_GRACE`]
    /// stale, so the common case stays a read. A no-op when the idle clock is off, which is what keeps
    /// `idle_secs = 0` exactly as cheap as before this existed.
    async fn touch_session(&self, session: &session::Model) {
        let now = now_secs();
        if self.idle_secs == 0 || now - session.last_seen_at < IDLE_REFRESH_GRACE {
            return;
        }
        // Best-effort and racy on purpose: two concurrent requests writing the same near-identical
        // timestamp is harmless, and a lost update just means the next request tries again.
        let _ = session::Entity::update_many()
            .col_expr(session::Column::LastSeenAt, sea_orm::sea_query::Expr::value(now))
            .filter(session::Column::Id.eq(session.id.clone()))
            .exec(&self.db)
            .await;
    }

    /// Delete a user's sessions, optionally sparing one id (the caller's own). Returns how many went.
    async fn revoke_sessions(&self, user_id: i32, keep: Option<&str>) -> u64 {
        let mut q = session::Entity::delete_many().filter(session::Column::UserId.eq(user_id));
        if let Some(id) = keep {
            q = q.filter(session::Column::Id.ne(id.to_string()));
        }
        q.exec(&self.db).await.map(|r| r.rows_affected).unwrap_or(0)
    }

    /// The CSRF checker for this app: the configured cookie name, `Secure` and the lifetime tracking
    /// the session cookie, so a live session always has a usable token.
    fn csrf(&self) -> crate::csrf::Csrf {
        let mut csrf = crate::csrf::Csrf::new()
            .cookie_name(self.csrf_cookie.clone())
            .secure(self.secure_cookies)
            .ttl_secs(self.ttl_secs);
        // Carried on the handle rather than applied at the call sites, so the app's page covers this
        // module's forms, `csrf::enforce` on the app's own routes, and any `Csrf::reject` it calls itself.
        csrf.reject = self.csrf_reject.clone();
        csrf
    }

    /// The groups that may reset *other* users' passwords: the configured manager groups, defaulting
    /// to the admin group.
    fn manager_groups(&self) -> Vec<String> {
        self.profile_managers.clone().unwrap_or_else(|| vec![self.admin_group.clone()])
    }

    /// Whether `who` may manage *someone else's* profile (i.e. is in a manager group).
    fn can_manage_others(&self, who: &Identity) -> bool {
        who.in_any_group(&self.manager_groups())
    }

    /// Append the app's profile-extra section (if configured) to a self-profile fragment.
    async fn with_profile_extra(&self, frag: String, who: &Identity) -> String {
        match &self.profile_extra {
            Some(hook) => format!("{frag}{}", hook(who.clone()).await),
            None => frag,
        }
    }

    /// Fire the audit observer for a mutating auth action (no-op if none registered). `after` should
    /// describe *what* changed without secrets (never a password hash / TOTP secret).
    async fn notify(
        &self,
        source: &'static str,
        entity: &str,
        key: Option<String>,
        after: serde_json::Value,
        headers: &HeaderMap,
        client_ip: std::net::IpAddr,
    ) {
        let Some(observer) = &self.observer else { return };
        let ev = crate::observe::WriteEvent {
            source,
            op: crate::authz::Operation::Update,
            entity,
            key,
            before: None,
            after: Some(after),
            headers,
            client_ip,
        };
        observer.on_write(&ev).await;
    }
}

/// Stamp a user's `last_login_at` (UTC Unix seconds). Uses a set-based update so it doesn't bump
/// `updated_at` (a login isn't a content change) or re-run the row hook.
/// Stamp `last_login_at`, and — when the login went through the second factor — the TOTP step it spent,
/// so the same code can't be replayed. One statement for both: the replay guard lives on `auth_user`
/// precisely so that recording it costs no extra round-trip, and so that
/// [`clear_totp`] can reset it in the same write that removes the secret.
async fn stamp_login(db: &DatabaseConnection, user_id: i32, totp_step: Option<i64>) {
    let mut q = user::Entity::update_many()
        .col_expr(user::Column::LastLoginAt, sea_orm::sea_query::Expr::value(now_secs()));
    if let Some(step) = totp_step {
        q = q.col_expr(user::Column::TotpLastStep, sea_orm::sea_query::Expr::value(step));
    }
    let _ = q.filter(user::Column::Id.eq(user_id)).exec(db).await;
}

/// Wires authn into an app: login/logout routes ([`routes`](Auth::routes)) and on-demand session
/// lookups ([`identify`](Auth::identify)). The app owns the router and merges the routes where it
/// likes; gates and page handlers call `identify` themselves — there is no middleware. Cheap to
/// clone (an `Arc` inside), so gates hold their own handle.
///
/// **Finish configuring it before cloning it.** The `with_*`/`*_shell` builders need sole ownership
/// of the inner `Arc`, so call them all first; only then clone it (into gate presets like
/// `UserReadWrite::new(&auth)`, `GroupReadWrite::new(&auth, …)`, or `Sso::new(&auth)`). A builder call after a
/// clone exists will panic.
#[derive(Clone)]
pub struct Auth {
    inner: Arc<Inner>,
}

impl Auth {
    pub fn new(db: DatabaseConnection, lockout: lockout::Lockout) -> Self {
        let usernames = lockout::UsernameLockout::new(
            db.clone(),
            lockout.username_after,
            lockout.username_duration_secs,
        );
        let ips = lockout::IpLockout::new(
            db.clone(),
            lockout.ip_after,
            lockout.ip_duration_secs,
            lockout.ip_whitelist,
        );
        Self {
            inner: Arc::new(Inner {
                db,
                admin_group: "admin".into(),
                cookie_name: DEFAULT_COOKIE.into(),
                login_path: "/login".into(),
                profile_path: "/profile".into(),
                secure_cookies: true,
                ttl_secs: 7 * 24 * 3600,
                idle_secs: 8 * 3600,
                observer: None,
                login_shell: Arc::new(default_login_shell),
                profile_shell: Arc::new(default_profile_shell),
                profile_extra: None,
                profile_managers: None,
                totp_issuer: "relativelylight".into(),
                csrf_cookie: crate::csrf::Csrf::new().cookie().to_string(),
                csrf_reject: None,
                usernames,
                ips,
                password_check: Some(policy_check(crate::validate::PasswordPolicy::recommended())),
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

    /// Append an app-rendered section below the password/2FA fragment on the **self** profile page
    /// (`GET /profile` and after a profile POST) — e.g. API-token management. The hook is handed the
    /// caller's [`Identity`] (owned, so the returned future can be `'static`) and returns an HTML
    /// fragment. The manager `/profile/{id}` pages do not include it.
    pub fn profile_extra<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(Identity) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = String> + Send + 'static,
    {
        let h: ProfileExtra = Arc::new(move |who: Identity| Box::pin(hook(who)));
        Arc::get_mut(&mut self.inner).unwrap().profile_extra = Some(h);
        self
    }

    /// Register an audit sink fired from the mutating auth handlers (password change, manager reset)
    /// — see [`crate::observe`]. Share one `Arc` with `Crud::on_write` to capture both surfaces.
    pub fn on_write(mut self, observer: Arc<dyn crate::observe::WriteObserver>) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().observer = Some(observer);
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

    /// The **absolute** session lifetime in seconds (default 7 days) — the deadline stamped once when
    /// the session is created and never moved, so a session dies at that instant however actively it has
    /// been used. It is also the session cookie's `Max-Age`. Pair it with
    /// [`session_idle_secs`](Auth::session_idle_secs), which expires an *unused* session sooner.
    pub fn session_ttl_secs(mut self, secs: i64) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().ttl_secs = secs;
        self
    }

    /// The **idle** session lifetime in seconds — how long a session survives without being used
    /// (default `8 * 3600`, eight hours; `0` disables the idle clock and leaves only the absolute one).
    ///
    /// This is what limits the damage from a stolen cookie: an attacker who lifts one has until the
    /// victim's session goes quiet, not the full week of
    /// [`session_ttl_secs`](Auth::session_ttl_secs). The clock is `auth_session.last_seen_at`, refreshed
    /// **lazily** — at most once a minute per session — so resolving an identity stays a pure read on
    /// almost every request, which matters because a gated page resolves it once *per model* it renders.
    ///
    /// Both clocks apply: a session must be inside the absolute deadline **and** have been used within
    /// the idle window. Set this above your longest plausible "reading a page" gap; setting it above
    /// `session_ttl_secs` is legal but pointless, as the absolute deadline always wins.
    pub fn session_idle_secs(mut self, secs: i64) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().idle_secs = secs.max(0);
        self
    }

    /// The password strength policy applied to a **new** password on this module's own pages — `POST
    /// /profile` (self-service) and `POST /profile/{id}` (a manager's reset, so the reset isn't a way
    /// around the rule).
    ///
    /// **On by default**, at [`PasswordPolicy::recommended`](crate::validate::PasswordPolicy::recommended)
    /// — ≥ 12 characters, screened against common values and trivial patterns, and (here, where the
    /// account is known) against the **username**. Two ways out, because a library shouldn't dictate
    /// this:
    ///
    /// ```ignore
    /// use relativelylight::validate::PasswordPolicy;
    /// auth.password_policy(PasswordPolicy::nist_minimum())         // a different preset
    /// auth.password_policy(PasswordPolicy::from_level(cfg.level))  // …driven by your config
    /// auth.password_policy(PasswordPolicy::recommended().block(["acmecorp"]))  // …with your words
    /// auth.password_policy(None)                                   // off entirely
    /// auth.password_check(|pw, user| my_own_rules(pw, user))       // your own predicate
    /// ```
    ///
    /// It governs **typed input, not code**: `create_user` / `set_password` / `make_admin` /
    /// `reset_admin_access` are unaffected, so a seeder or a break-glass CLI still sets whatever the
    /// operator says. Wire the same policy into the admin UI / JSON API separately — that's a `crud`
    /// field validator, `user.field("password_hash").validate_str(validate::optional(Box::new(
    /// validate::password(policy))))`, as `examples/adminpanel` does. Both surfaces need it, or
    /// whichever one you skip becomes the way around the other.
    pub fn password_policy(mut self, policy: impl Into<Option<crate::validate::PasswordPolicy>>) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().password_check = policy.into().map(policy_check);
        self
    }

    /// Replace the password check with your own predicate: `(password, username) → Result<(), String>`,
    /// where the `Err` is shown to the user. Overrides [`password_policy`](Auth::password_policy)
    /// entirely — use it for a rule the policy can't express (a corpus lookup, an HTTP call to a
    /// breached-password service, a per-group rule).
    pub fn password_check<F>(mut self, check: F) -> Self
    where
        F: Fn(&str, &str) -> Result<(), String> + Send + Sync + 'static,
    {
        Arc::get_mut(&mut self.inner).unwrap().password_check = Some(Arc::new(check));
        self
    }

    /// Session cookie name (default `"rl_session"`). Set from a constant or config on startup.
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().cookie_name = name.into();
        self
    }

    /// Render the **CSRF rejection page** yourself, in your own shell, instead of the built-in bare 403.
    ///
    /// Applies to every form this module renders *and* to [`csrf::enforce`](crate::csrf::enforce) on your
    /// own routes, because the closure travels on the [`csrf()`](Auth::csrf) handle. Keep the same
    /// discipline the default has: a rejected request hasn't proved it came from your site, so don't name
    /// the user, don't set cookies, and keep the status a `403`.
    ///
    /// ```ignore
    /// .csrf_rejection(|| (StatusCode::FORBIDDEN, Html(my_shell("Security check failed", BODY))).into_response())
    /// ```
    pub fn csrf_rejection<F>(mut self, render: F) -> Self
    where
        F: Fn() -> Response + Send + Sync + 'static,
    {
        Arc::get_mut(&mut self.inner).unwrap().csrf_reject = Some(Arc::new(render));
        self
    }

    /// CSRF token cookie name (default `"rl_csrf"`) — see [`crate::csrf`]. As with the session cookie,
    /// give co-hosted apps distinct names.
    pub fn csrf_cookie_name(mut self, name: impl Into<String>) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().csrf_cookie = name.into();
        self
    }

    /// The account-name lockout counter — hand it whatever credential checks the **app** makes itself
    /// (HTTP Basic on a machine endpoint, a DDNS update URL) so one account has one budget across every
    /// surface: burning it there locks the login form too, and clearing one row frees both. See
    /// [`lockout`] for the call shape.
    pub fn username_lockout(&self) -> lockout::UsernameLockout {
        self.inner.usernames.clone()
    }

    /// The source-address lockout counter — the only brake on credentials that carry no account name
    /// (a bearer token). Pass the caller's address; in a handler that is
    /// [`RealIp`](crate::middleware::RealIp), which is the same value this module's own login routes
    /// count against, so one client has one budget across both.
    pub fn ip_lockout(&self) -> lockout::IpLockout {
        self.inner.ips.clone()
    }

    /// The CSRF checker these routes use — hand it to the API so both surfaces share one token
    /// cookie: `crud.csrf(auth.csrf())`. Also usable in your own handlers ([`csrf::Csrf::ensure`] to
    /// hand a token to a page you render, [`csrf::Csrf::verify`] to check a post).
    ///
    /// [`csrf::Csrf::ensure`]: crate::csrf::Csrf::ensure
    /// [`csrf::Csrf::verify`]: crate::csrf::Csrf::verify
    pub fn csrf(&self) -> crate::csrf::Csrf {
        self.inner.csrf()
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

    /// **Re-authenticate** the caller before something sensitive: pass whatever the form submitted as
    /// `password` and `totp_code` (empty strings for "not supplied"). `Ok(())` if either proves the
    /// account holder is present; `Err(message)` is fit to render back into your form.
    ///
    /// A live session is not evidence that its owner is at the keyboard — a stolen cookie *is* a live
    /// session, and the idle window (§5f) bounds how long it lasts but not what it can do inside that
    /// time. So the actions that would let an intruder entrench (turning off 2FA, enrolling their own
    /// authenticator, resetting someone else's password) ask for a factor again. This module already
    /// applies it to its own such routes; use this for yours — deleting an account, rotating an API
    /// token, exporting a dataset:
    ///
    /// ```ignore
    /// let Some(who) = auth.identify(&headers).await else { return redirect_to_login() };
    /// if let Err(msg) = auth.reauthenticate(&who, &form.current_password, &form.totp_code).await {
    ///     return render_form_with_error(&msg);   // 403, and nothing has happened yet
    /// }
    /// delete_everything(&who).await;
    /// ```
    ///
    /// A **fresh TOTP code is preferred** to a password when the account has 2FA: it proves presence,
    /// where a password may have been filled in by the browser for whoever is sitting there. A code
    /// accepted here is **spent** (§5a), so it can't be reused to log in or to wave through a second
    /// action.
    ///
    /// **An account with no local factor passes.** An SSO account has neither password nor local 2FA, so
    /// there is nothing to ask it for; refusing instead would lock every SSO administrator out of the
    /// manager pages permanently. Their assurance is whatever the identity provider gave them — re-auth
    /// through the IdP (an OIDC `prompt=login` round-trip) is the real answer and isn't built yet, so
    /// this is a documented limit, not an oversight. The same applies to a local account whose password
    /// is blank (login already disabled).
    ///
    /// Not lockout-limited, deliberately, for the reason §5e gives: the caller is already authenticated,
    /// so counting failures here would let a stolen session lock the real user out of logging in. Nor is
    /// it needed — guessing a password is no easier here than at `/login`, and a 6-digit code would need
    /// ~10⁶ requests inside its 90-second window.
    pub async fn reauthenticate(
        &self,
        who: &Identity,
        password: &str,
        totp_code: &str,
    ) -> Result<(), String> {
        let Some(user) = current_user(&self.inner, who).await else {
            return Err("Your session is no longer valid — sign in again.".into());
        };
        self.inner.reauth(&user, password, totp_code).await
    }

    /// Whether [`reauthenticate`](Auth::reauthenticate) can actually challenge this account — i.e. it has
    /// a local password or 2FA. `false` for an SSO account (nothing to ask for, so re-auth passes), which
    /// is what to key a "you'll be asked to confirm" hint off in your own UI.
    pub async fn can_reauthenticate(&self, who: &Identity) -> bool {
        match current_user(&self.inner, who).await {
            Some(u) => !u.password_hash.is_empty() || u.has_totp(),
            None => false,
        }
    }

    /// Sign a user out **everywhere**: delete every session row they hold. Returns how many were
    /// deleted. The next request on any of those cookies is anonymous — there is no revocation list to
    /// consult and nothing to expire, which is the advantage of server-side sessions over a JWT.
    ///
    /// The built-in pages call this for you where it matters (a password change, a manager's reset).
    /// Call it yourself when *your* code decides a user's sessions are void — you disabled the account,
    /// an SSO group sync removed their access, or an operator hit a "force logout" button. Note that
    /// deactivating an account (`is_active = false`) already denies every request at
    /// [`identify`](Auth::identify), so this is about tidiness there rather than enforcement.
    pub async fn revoke_sessions(&self, user_id: i32) -> u64 {
        self.inner.revoke_sessions(user_id, None).await
    }

    /// As [`revoke_sessions`](Auth::revoke_sessions), but spares the session `keep` — "sign out my
    /// *other* devices", the form that doesn't log the caller out mid-request. Pass the session cookie's
    /// value ([`session_cookie_name`](Auth::session_cookie_name) tells you which cookie to read).
    pub async fn revoke_other_sessions(&self, user_id: i32, keep: &str) -> u64 {
        self.inner.revoke_sessions(user_id, Some(keep)).await
    }

    /// Housekeeping for **this** `Auth`'s configuration: delete dead sessions — on either clock, so
    /// idle-expired rows go too — and expired lockout rows. Returns the total deleted.
    ///
    /// Prefer this over the free [`prune`] function, which knows only the absolute deadline (it takes no
    /// `Auth`, so it can't see [`session_idle_secs`](Auth::session_idle_secs)). **Nothing here is
    /// scheduled** — call it at startup and from your own periodic loop.
    pub async fn prune(&self) -> Result<u64, DbErr> {
        let now = now_secs();
        let mut cond = sea_orm::Condition::any().add(session::Column::ExpiresAt.lt(now));
        if self.inner.idle_secs > 0 {
            cond = cond.add(session::Column::LastSeenAt.lt(now - self.inner.idle_secs));
        }
        let sessions =
            session::Entity::delete_many().filter(cond).exec(&self.inner.db).await?.rows_affected;
        let usernames = self.inner.usernames.prune().await?;
        let ips = self.inner.ips.prune().await?;
        Ok(sessions + usernames + ips)
    }

    /// The auth pages, to merge into your router:
    /// - `GET/POST /login` and `GET/POST /login/totp` — password, then the TOTP second factor when the
    ///   user has 2FA enabled.
    /// - `GET /logout`.
    /// - `GET/POST /profile` — change your own password + manage your own 2FA.
    /// - `GET/POST /profile/totp` + `POST /profile/totp/disable` — enrol in / disable your own 2FA.
    /// - `POST /profile/totp/recovery` — replace your recovery codes (§5i).
    /// - `POST /profile/sessions/revoke` — sign out your *other* sessions.
    /// - `GET/POST /profile/{id}` — a manager resets another user's password.
    /// - `POST /profile/{id}/totp/disable` — a manager disables another user's 2FA.
    ///
    /// These paths are the module's, so don't also route them yourself — axum panics on an overlap at
    /// merge time. Change where they live with [`login_path`](Auth::login_path)'s and
    /// [`profile_path`](Auth::profile_path)'s configuration, or nest the whole thing under a prefix.
    pub fn routes(&self) -> Router {
        Router::new()
            .route("/login", get(login_form).post(login_submit))
            .route("/login/totp", get(login_totp_form).post(login_totp_submit))
            .route("/logout", get(logout))
            .route("/profile", get(profile_form).post(profile_submit))
            .route("/profile/totp", get(totp_setup_form).post(totp_setup_submit))
            .route("/profile/totp/disable", post(totp_self_disable))
            .route("/profile/totp/recovery", post(recovery_regenerate))
            .route("/profile/sessions/revoke", post(sessions_revoke))
            .route("/profile/{id}", get(manage_form).post(manage_submit))
            .route("/profile/{id}/totp/disable", post(totp_manage_disable))
            .with_state(self.inner.clone())
    }

    /// The logged-in [`Identity`] for a request, resolved from its session cookie (session → user →
    /// groups, one DB round-trip), or `None` if anonymous / expired / inactive. This is the whole of
    /// authn: call it from a gate or a page handler; nothing is injected into the request.
    ///
    /// Takes only the headers and returns only an identity — **by design**, and worth preserving: a
    /// gated page resolves the caller once per model it renders, so this has to stay cheap, and anything
    /// that needed to set a cookie here would have to change every call site. The idle clock is refreshed
    /// with a lazy DB write ([`session_idle_secs`](Auth::session_idle_secs)) precisely so that it doesn't;
    /// the session **id** only ever changes inside a POST handler that already owns its response.
    pub async fn identify(&self, headers: &HeaderMap) -> Option<Identity> {
        let jar = CookieJar::from_headers(headers);
        let token = jar.get(&self.inner.cookie_name)?.value().to_string();
        identity_from(&self.inner, &token).await
    }
}

// ===================== Internals =====================

/// How stale `last_seen_at` must be before a read bothers to refresh it. Identity is resolved once per
/// gated model, so a page rendering five tables resolves it five times; without this grace every one of
/// those reads would become a write.
const IDLE_REFRESH_GRACE: i64 = 60;

async fn identity_from(inner: &Inner, token: &str) -> Option<Identity> {
    let session = session::Entity::find_by_id(token.to_string()).one(&inner.db).await.ok()??;
    if !inner.session_live(&session) || session.awaiting_totp {
        return None; // expired (either clock), or the TOTP second factor is still pending
    }
    let user = user::Entity::find_by_id(session.user_id).one(&inner.db).await.ok()??;
    if !user.is_active {
        return None;
    }
    let groups = groups_of(&inner.db, user.id).await;
    // The session was used: push the idle clock forward, but only once the last stamp has gone stale.
    inner.touch_session(&session).await;
    Some(Identity { id: user.id.to_string(), username: user.username, groups })
}

/// Verify username + password. Returns the user on success (regardless of 2FA) — the caller decides
/// whether a second factor is still required (`user.has_totp()`). SSO accounts
/// (`sso_provider` set) never authenticate by password.
async fn verify_credentials(inner: &Inner, username: &str, password: &str) -> Option<user::Model> {
    let user = user::Entity::find()
        .filter(user::Column::Username.eq(username))
        .one(&inner.db)
        .await
        .ok()??;
    (user.is_active && !user.is_sso() && verify_password(&user.password_hash, password))
        .then_some(user)
}

/// Create a session row and return its token. `awaiting_totp` marks it half-authenticated (password
/// ok, TOTP pending) — [`identity_from`] rejects such sessions until the code is confirmed.
async fn create_session(inner: &Inner, user_id: i32, awaiting_totp: bool) -> Option<String> {
    let token = new_token();
    let now = now_secs();
    session::ActiveModel {
        id: Set(token.clone()),
        user_id: Set(user_id),
        expires_at: Set(now + inner.ttl_secs),
        last_seen_at: Set(now),
        awaiting_totp: Set(awaiting_totp),
    }
    .insert(&inner.db)
    .await
    .ok()?;
    Some(token)
}

/// Give a user exactly **one** live session, freshly minted: everything else they hold is deleted.
/// Returns the new token, to be written into the caller's cookie.
///
/// This is what a password change should do, and today's most useful reason to change a password is
/// "someone else is in my account". Rotating only the caller's own id would leave the intruder's
/// session untouched; deleting every session including the caller's own would sign them out of the page
/// they are reading. So: mint one, drop the rest.
async fn resession(inner: &Inner, user_id: i32) -> Option<String> {
    let token = create_session(inner, user_id, false).await?;
    inner.revoke_sessions(user_id, Some(&token)).await;
    Some(token)
}

/// Replace a session with a fresh id, carrying its user across and clearing `awaiting_totp` — the
/// **privilege-change rotation**. Returns the new token.
///
/// Rotating here is what stops a **planted half-authenticated cookie** from being elevated. Password
/// login can't be fixated (it always mints a new row), but confirming the second factor used to flip
/// `awaiting_totp` on the *same* id: an attacker who knew the password could take a pending session,
/// write its cookie into the victim's browser (cookie-tossing from a sibling host, or an XSS — neither
/// `Secure` nor `SameSite` prevents that), point them at `/login/totp`, and inherit a fully
/// authenticated session the moment the victim typed their own code. A new id leaves the attacker
/// holding a token that was deleted.
async fn rotate_session(inner: &Inner, old: session::Model) -> Option<String> {
    let token = create_session(inner, old.user_id, false).await?;
    // Best-effort: a surviving old row is half-authenticated, so it grants nothing either way.
    let _ = session::Entity::delete_by_id(old.id).exec(&inner.db).await;
    Some(token)
}

#[derive(serde::Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

async fn login_form(State(inner): State<Arc<Inner>>, headers: HeaderMap, jar: CookieJar) -> Response {
    let (token, jar) = csrf_token(&inner, &headers, jar);
    (jar, Html((inner.login_shell)(&login_form_html(None, &token)))).into_response()
}

async fn login_submit(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    RealIp(client_ip): RealIp,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    if !inner.csrf().verify(&headers, form.csrf.as_deref()) {
        // Checked before anything else: a forged post does no DB work *and* can't spend the victim's
        // attempt budget (otherwise cross-site requests could lock a user out).
        return csrf_rejected(&inner);
    }
    if let Some(retry) = inner.locked_out(&form.username, client_ip).await {
        // Locked: the password is never looked at, so this costs no argon2 and says nothing about
        // whether the account exists.
        let (token, jar) = csrf_token(&inner, &headers, jar);
        return too_many_attempts(
            retry,
            jar,
            Html((inner.login_shell)(&login_form_html(Some(&lockout_message(retry)), &token))),
        );
    }
    let Some(user) = verify_credentials(&inner, &form.username, &form.password).await else {
        inner.record_failure(&form.username, client_ip).await;
        let (token, jar) = csrf_token(&inner, &headers, jar);
        return (
            StatusCode::UNAUTHORIZED,
            jar,
            Html((inner.login_shell)(&login_form_html(
                Some("Invalid username or password."),
                &token,
            ))),
        )
            .into_response();
    };
    let needs_totp = user.has_totp();
    let Some(token) = create_session(&inner, user.id, needs_totp).await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response();
    };
    // Credentials accepted → forget this account's failures (the address's are left alone: one valid
    // login shouldn't reset a spraying source's budget).
    inner.usernames.clear(&form.username).await;
    // The session cookie is set either way; while `awaiting_totp` it grants nothing until the second
    // factor is confirmed at /login/totp. The CSRF token is rotated with it (privilege change).
    let (_, csrf_cookie) = inner.csrf().issue();
    let jar = jar.add(session_cookie(&inner, token)).add(csrf_cookie);
    let dest = if needs_totp {
        "/login/totp"
    } else {
        // Login is complete (no 2FA) — stamp last_login now (the TOTP path stamps on confirm, with the
        // step it spent).
        stamp_login(&inner.db, user.id, None).await;
        "/"
    };
    (jar, Redirect::to(dest)).into_response()
}

/// `GET /login/totp` — the second-factor form, reached after a correct password when 2FA is on. Reads
/// the pending session; if there isn't one, sends the visitor back to /login.
async fn login_totp_form(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    match pending_totp_user(&inner, &headers).await {
        Some(_) => {
            let (token, jar) = csrf_token(&inner, &headers, jar);
            (jar, Html((inner.login_shell)(&totp_login_html(None, &token)))).into_response()
        }
        None => Redirect::to(&inner.login_path).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct TotpForm {
    /// At `/login/totp`, the code for the account's active secret. At `/profile/totp`, the code for the
    /// **pending** secret being enrolled — which is why re-authentication there needs its own fields.
    ///
    /// Defaulted rather than required: since a recovery code can satisfy `/login/totp` instead (§5i), a
    /// client that sends only `recovery_code` deserves the ordinary answer, not a 422 about a field it
    /// had no reason to include.
    #[serde(default)]
    code: String,
    /// Re-authentication for `/profile/totp` (§5h); unused at `/login/totp`, where the password was just
    /// checked a moment ago.
    #[serde(default)]
    current_password: String,
    /// A code from the account's *currently active* secret — only meaningful when re-enrolling over an
    /// existing 2FA setup. A first enrolment has no active secret, so the password is the factor.
    #[serde(default)]
    totp_code: String,
    /// A single-use **recovery code** (§5i), accepted at `/login/totp` in place of `code` when the
    /// authenticator is gone. Unused at `/profile/totp`.
    #[serde(default)]
    recovery_code: String,
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

/// The body of a post that carries nothing but the CSRF token (`/profile/sessions/revoke`).
#[derive(serde::Deserialize)]
struct CsrfOnlyForm {
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

/// `POST /login/totp` — verify the code against the pending session's user; on success clear
/// `awaiting_totp` (the session becomes a real login) and land on `/`.
async fn login_totp_submit(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    RealIp(client_ip): RealIp,
    jar: CookieJar,
    Form(form): Form<TotpForm>,
) -> Response {
    if !inner.csrf().verify(&headers, form.csrf.as_deref()) {
        return csrf_rejected(&inner);
    }
    let Some((session, user)) = pending_totp_user(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    // The second factor shares the account's login bucket: password guessing and code guessing are the
    // same account being attacked, and 6 digits deserve the tighter of the two brakes.
    if let Some(retry) = inner.locked_out(&user.username, client_ip).await {
        let (token, jar) = csrf_token(&inner, &headers, jar);
        return too_many_attempts(
            retry,
            jar,
            Html((inner.login_shell)(&totp_login_html(Some(&lockout_message(retry)), &token))),
        );
    }
    // An empty submission presents **no credential**, so it is not a failed check and must not spend the
    // account's budget — §5e's rule, and without it an empty form (a stray double-submit, or a forged
    // cross-site post that happens to carry a token) would grief the real user's login.
    if form.code.trim().is_empty() && recovery::normalize(&form.recovery_code).is_empty() {
        let (token, jar) = csrf_token(&inner, &headers, jar);
        return (
            StatusCode::UNAUTHORIZED,
            jar,
            Html((inner.login_shell)(&totp_login_html(
                Some("Enter the code from your authenticator app, or a recovery code."),
                &token,
            ))),
        )
            .into_response();
    }
    // Two conditions, one answer: the code must be valid *and* must not have been spent already. A
    // replayed code is a failed check as far as the caller (and the lockout) is concerned — saying
    // "that code was already used" would tell an attacker holding a captured code that it was the right
    // one, which is precisely what they don't know yet.
    let step = user.totp_key().and_then(|s| totp::verify_step(s, &form.code));
    let mut ok = step.is_some_and(|step| user.totp_step_ok(step));
    // Failing that, a **recovery code** (§5i) — the way in when the authenticator is gone. Tried second
    // so a normal login never touches the set, and spent on success so each code works exactly once.
    let mut used_recovery = false;
    if !ok && !recovery::normalize(&form.recovery_code).is_empty() {
        ok = recovery::consume(&inner.db, user.id, &form.recovery_code).await;
        used_recovery = ok;
    }
    if !ok {
        inner.record_failure(&user.username, client_ip).await;
        let (token, jar) = csrf_token(&inner, &headers, jar);
        return (
            StatusCode::UNAUTHORIZED,
            jar,
            Html((inner.login_shell)(&totp_login_html(Some("Invalid code. Try again."), &token))),
        )
            .into_response();
    }
    // The second factor is confirmed, so the session gains full privilege — which means a **new id**
    // (see `rotate_session`), a new CSRF token, and the spent step recorded so this code can't be used
    // again inside its ±1-step window.
    let Some(token) = rotate_session(&inner, session).await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response();
    };
    stamp_login(&inner.db, user.id, step).await;
    inner.usernames.clear(&user.username).await;
    let (_, csrf_cookie) = inner.csrf().issue();
    let jar = jar.add(session_cookie(&inner, token)).add(csrf_cookie);
    if used_recovery {
        // Land on the profile rather than `/`: they got in without their authenticator, so the next
        // thing they need is either a re-enrolment or a fresh set of codes, and both live there.
        return (jar, Redirect::to(&inner.profile_path)).into_response();
    }
    (jar, Redirect::to("/")).into_response()
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
    let jar = jar
        .remove(Cookie::build(inner.cookie_name.clone()).path("/").build())
        .remove(inner.csrf().clear_cookie());
    (jar, Redirect::to("/login")).into_response()
}

// ---- profile / password change ----

#[derive(serde::Deserialize)]
struct ChangeForm {
    current_password: String,
    new_password: String,
    confirm_password: String,
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

#[derive(serde::Deserialize)]
struct ResetForm {
    new_password: String,
    confirm_password: String,
    /// The **manager's own** re-authentication (§5h) — not the target's, which they don't know.
    #[serde(default)]
    current_password: String,
    #[serde(default)]
    totp_code: String,
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

/// A post whose only payload is the caller's re-authentication (§5h): the "disable 2FA" buttons.
#[derive(serde::Deserialize)]
struct ReauthForm {
    #[serde(default)]
    current_password: String,
    #[serde(default)]
    totp_code: String,
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
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

/// `GET /profile` — the self-service change-password form + 2FA status (anonymous → login). For an
/// SSO account it's a read-only notice: password + 2FA are managed by the identity provider.
async fn profile_form(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let Some(user) = current_user(&inner, &who).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let (token, jar) = csrf_token(&inner, &headers, jar);
    let frag = match user.sso_key() {
        Some(provider) => inner.with_profile_extra(sso_profile_html(&who, provider), &who).await,
        None => profile_fragment(&inner, &who, &user, None, None, &token).await,
    };
    (jar, Html((inner.profile_shell)(&frag, &who))).into_response()
}

/// `POST /profile` — verify the current password, then set the new one for the caller.
async fn profile_submit(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    RealIp(client_ip): RealIp, // for the audit record, not for limiting
    jar: CookieJar,
    Form(form): Form<ChangeForm>,
) -> Response {
    if !inner.csrf().verify(&headers, form.csrf.as_deref()) {
        return csrf_rejected(&inner);
    }
    let csrf = inner.csrf().token(&headers).unwrap_or_default();
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
    if user.is_sso() {
        return Redirect::to(&inner.profile_path).into_response(); // SSO: password managed by the IdP
    }
    // Not lockout-limited: the caller is *authenticated*, so this isn't brute force from outside —
    // it's someone with a live session, which is a session-theft problem (short TTLs, re-auth before
    // sensitive changes — TODO.md), not a guessing one. Counting it here would also let a stolen
    // session lock the real user out of logging in.
    let error: Option<String> = if !verify_password(&user.password_hash, &form.current_password) {
        Some("Current password is incorrect.".into())
    } else if let Some(msg) = password_pair_error(&form.new_password, &form.confirm_password) {
        Some(msg.into())
    } else {
        // Strength last: the pair check's "they don't match" is more useful than a strength complaint
        // about a value the user may have mistyped anyway.
        inner
            .password_error(&form.new_password, &who.username)
            .map(|e| format!("Your new password {e}."))
    };
    if let Some(msg) = error {
        let frag = profile_fragment(&inner, &who, &user, Some(&msg), None, &csrf).await;
        return (StatusCode::BAD_REQUEST, Html((inner.profile_shell)(&frag, &who))).into_response();
    }

    if set_password(&inner.db, &who.username, &form.new_password).await.is_err() {
        let frag =
            profile_fragment(&inner, &who, &user, Some("Could not change the password."), None, &csrf)
                .await;
        return (StatusCode::INTERNAL_SERVER_ERROR, Html((inner.profile_shell)(&frag, &who)))
            .into_response();
    }
    // The password is changed, so every session it ever unlocked is void: mint one fresh session for
    // the caller and delete the rest. Without this, a password changed *because* someone else got in
    // leaves that someone else logged in — the cookie outlives the credential that produced it.
    // The rendered form must carry whichever token the response's cookie ends up holding, or the next
    // post fails its own double-submit check.
    let (msg, jar, csrf) = match resession(&inner, user.id).await {
        Some(token) => {
            let (csrf, csrf_cookie) = inner.csrf().issue(); // new session ⇒ new CSRF token
            let jar = jar.add(session_cookie(&inner, token)).add(csrf_cookie);
            ("Your password has been changed. Any other sessions have been signed out.", jar, csrf)
        }
        // The password *did* change, so don't claim otherwise; the caller's session simply wasn't
        // rotated. Their old cookie still works, which is no worse than before.
        None => ("Your password has been changed.", jar, csrf),
    };
    inner
        .notify(
            "auth-profile",
            "auth_user",
            Some(who.id.clone()),
            serde_json::json!({ "password_changed": true, "sessions_revoked": true }),
            &headers,
            client_ip,
        )
        .await;
    let frag = profile_fragment(&inner, &who, &user, None, Some(msg), &csrf).await;
    (jar, Html((inner.profile_shell)(&frag, &who))).into_response()
}

/// `GET /profile/{id}` — a manager's reset form for another user (self → own page; not a manager →
/// 403; unknown user → 404).
async fn manage_form(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    jar: CookieJar,
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
    let (token, jar) = csrf_token(&inner, &headers, jar);
    // The manager's own 2FA state decides whether the confirm-it's-you block offers a code field.
    let manager_totp_on =
        current_user(&inner, &who).await.map(|m| m.has_totp()).unwrap_or(false);
    // Don't offer a reset form for an account whose password lives at the identity provider — the POST
    // refuses it, so a form here would only ever produce an error.
    let frag = match target.sso_key() {
        Some(provider) => sso_managed_html(&target.username, provider),
        None => reset_form_html(
            &id,
            &target.username,
            target.has_totp(),
            manager_totp_on,
            None,
            None,
            &token,
        ),
    };
    (jar, Html((inner.profile_shell)(&frag, &who))).into_response()
}

/// `POST /profile/{id}` — a manager sets another user's password (no current password required).
async fn manage_submit(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    RealIp(client_ip): RealIp,
    Path(id): Path<String>,
    Form(form): Form<ResetForm>,
) -> Response {
    if !inner.csrf().verify(&headers, form.csrf.as_deref()) {
        return csrf_rejected(&inner);
    }
    let csrf = inner.csrf().token(&headers).unwrap_or_default();
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
    let totp_on = target.has_totp();

    // Re-authenticate the **manager** (§5h) with their own factor. This route sets a password without
    // knowing the old one — which is the point of it, and also what makes it the most valuable thing a
    // stolen manager session can reach: every account it can reset is an account it can then log in as.
    let Some(manager) = current_user(&inner, &who).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let manager_totp_on = manager.has_totp(); // whether to offer *them* the code field
    if let Err(msg) = inner.reauth(&manager, &form.current_password, &form.totp_code).await {
        let frag =
            reset_form_html(&id, &target.username, totp_on, manager_totp_on, Some(&msg), None, &csrf);
        return (StatusCode::FORBIDDEN, Html((inner.profile_shell)(&frag, &who))).into_response();
    }

    // An SSO account has no local password to set, so refuse rather than store a hash that can never
    // authenticate — the same rule the self-service page applies to itself. Writing one was never a
    // bypass (`verify_credentials` refuses any `sso_provider` account), but it left a dead credential in
    // the row and read, to anyone looking at the audit trail, as if the account now had a password.
    if let Some(provider) = target.sso_key() {
        let msg = format!(
            "{} signs in through {provider} (single sign-on) — its password is managed there, not here.",
            target.username
        );
        let frag =
            reset_form_html(&id, &target.username, totp_on, manager_totp_on, Some(&msg), None, &csrf);
        return (StatusCode::BAD_REQUEST, Html((inner.profile_shell)(&frag, &who))).into_response();
    }

    // The same policy as the self-service page, against the *target's* username — a manager's reset
    // must not be a way around the rule the user themselves has to satisfy.
    let error: Option<String> = password_pair_error(&form.new_password, &form.confirm_password)
        .map(String::from)
        .or_else(|| {
            inner
                .password_error(&form.new_password, &target.username)
                .map(|e| format!("The new password {e}."))
        });
    if let Some(msg) = error {
        let frag =
            reset_form_html(&id, &target.username, totp_on, manager_totp_on, Some(&msg), None, &csrf);
        return (StatusCode::BAD_REQUEST, Html((inner.profile_shell)(&frag, &who))).into_response();
    }
    if set_password(&inner.db, &target.username, &form.new_password).await.is_err() {
        let frag = reset_form_html(
            &id,
            &target.username,
            totp_on,
            manager_totp_on,
            Some("Could not set the password."),
            None,
            &csrf,
        );
        return (StatusCode::INTERNAL_SERVER_ERROR, Html((inner.profile_shell)(&frag, &who)))
            .into_response();
    }
    // A manager resets a password for one of two reasons — the user is locked out, or the account is
    // suspected compromised. The second reason makes signing the target out everywhere mandatory: none
    // of *their* sessions belongs to the credential that exists now. Unlike the self-service path there
    // is no session to spare, so all of them go.
    let revoked = inner.revoke_sessions(target.id, None).await;
    inner
        .notify(
            "auth-admin",
            "auth_user",
            Some(id.clone()),
            serde_json::json!({
                "password_reset_by_manager": true,
                "by": who.username,
                "sessions_revoked": revoked,
            }),
            &headers,
            client_ip,
        )
        .await;
    let msg = match revoked {
        0 => format!("Password reset for {}.", target.username),
        1 => format!("Password reset for {} and 1 session signed out.", target.username),
        n => format!("Password reset for {} and {n} sessions signed out.", target.username),
    };
    let frag =
        reset_form_html(&id, &target.username, totp_on, manager_totp_on, None, Some(&msg), &csrf);
    Html((inner.profile_shell)(&frag, &who)).into_response()
}

// ---- TOTP 2FA (setup / verify / disable) ----

/// `GET /profile/totp` — begin enrolment: mint a fresh pending secret, store it on the user, and show
/// the QR + `otpauth://` URL with a verify form. A new secret is generated on each visit.
async fn totp_setup_form(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let Some(user) = current_user(&inner, &who).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    if user.is_sso() {
        return Redirect::to(&inner.profile_path).into_response(); // SSO: 2FA managed by the IdP
    }
    let secret = totp::generate_secret();
    // Whether they *already* have 2FA decides which factors the confirm block can offer: a re-enrolment
    // can be confirmed with a code from the outgoing authenticator, a first enrolment can't.
    let totp_on = user.has_totp();
    let mut am: user::ActiveModel = user.into();
    am.totp_pending = Set(Some(secret.clone()));
    if am.update(&inner.db).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not start 2FA setup").into_response();
    }
    let (token, jar) = csrf_token(&inner, &headers, jar);
    (jar, render_totp_setup(&inner, &who, &secret, totp_on, None, &token)).into_response()
}

/// `POST /profile/totp` — confirm enrolment: verify the code against the pending secret, then promote
/// it to the active secret (2FA now required at login). On a bad code, re-show the *same* QR.
async fn totp_setup_submit(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    Form(form): Form<TotpForm>,
) -> Response {
    if !inner.csrf().verify(&headers, form.csrf.as_deref()) {
        return csrf_rejected(&inner);
    }
    let csrf = inner.csrf().token(&headers).unwrap_or_default();
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let Some(user) = current_user(&inner, &who).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    if user.is_sso() {
        return Redirect::to(&inner.profile_path).into_response();
    }
    let Some(pending) = user.pending_totp_key().map(str::to_string) else {
        return Redirect::to(&inner.profile_path).into_response(); // nothing in progress
    };
    // Re-authenticated (§5h): the pending code proves possession of *a* device, but not that the device
    // belongs to the account holder. Without this, an intruder with a stolen session could enrol their
    // own authenticator — which doesn't just persist their access, it locks the real user out, since
    // login would then demand a code only the intruder can produce.
    //
    // The password is the factor here: the account's *active* secret is what a code would be checked
    // against, and for a first enrolment there isn't one. An already-enrolled user re-enrolling can use
    // either.
    let totp_on = user.has_totp();
    if let Err(msg) = inner.reauth(&user, &form.current_password, &form.totp_code).await {
        return render_totp_setup(&inner, &who, &pending, totp_on, Some(&msg), &csrf);
    }
    // Not lockout-limited: enrolling is authenticated, and the code being guessed is the caller's own
    // pending secret — there is nobody else's account to reach by guessing it.
    let Some(step) = totp::verify_step(&pending, &form.code) else {
        return render_totp_setup(
            &inner,
            &who,
            &pending,
            totp_on,
            Some("That code didn't match. Try again."),
            &csrf,
        );
    };
    let mut am: user::ActiveModel = user.into();
    am.totp_secret = Set(Some(pending));
    am.totp_pending = Set(None);
    // The confirming code is spent too — otherwise the code just typed here would still work at
    // /login/totp for the rest of its window, which is the same replay by a different door.
    am.totp_last_step = Set(Some(step));
    if am.update(&inner.db).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not enable 2FA").into_response();
    }
    // Issue recovery codes **with** the enrolment and show them once (§5i). Issuing them here rather
    // than leaving it to the user is the difference between a lost phone being an inconvenience and
    // being an account only an administrator can reopen.
    let user_id = who.id.parse::<i32>().unwrap_or_default();
    match recovery::issue(&inner.db, user_id).await {
        Ok(codes) => {
            let frag = recovery_codes_html(
                &codes,
                "Two-factor authentication is now enabled. Save these recovery codes.",
            );
            Html((inner.profile_shell)(&frag, &who)).into_response()
        }
        // 2FA *is* on, so don't imply otherwise; they can generate codes from the profile page.
        Err(_) => {
            let frag = change_form_html(
                &who,
                true,
                Some(0),
                Some("Two-factor authentication is on, but recovery codes could not be created — generate them below."),
                None,
                &csrf,
            );
            Html((inner.profile_shell)(&frag, &who)).into_response()
        }
    }
}

/// `POST /profile/totp/recovery` — replace the caller's recovery codes and show the new set once.
/// **Re-authenticated** (§5h): a fresh set is a fresh way into the account, so an intruder holding a
/// session must not be able to mint one, and the codes it invalidates are the real user's.
async fn recovery_regenerate(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    RealIp(client_ip): RealIp,
    Form(form): Form<ReauthForm>,
) -> Response {
    if !inner.csrf().verify(&headers, form.csrf.as_deref()) {
        return csrf_rejected(&inner);
    }
    let csrf = inner.csrf().token(&headers).unwrap_or_default();
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let Some(user) = current_user(&inner, &who).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    if !user.has_totp() {
        // Codes exist to recover a second factor; without one there is nothing to recover.
        return Redirect::to(&inner.profile_path).into_response();
    }
    if let Err(msg) = inner.reauth(&user, &form.current_password, &form.totp_code).await {
        let frag = profile_fragment(&inner, &who, &user, Some(&msg), None, &csrf).await;
        return (StatusCode::FORBIDDEN, Html((inner.profile_shell)(&frag, &who))).into_response();
    }
    match recovery::issue(&inner.db, user.id).await {
        Ok(codes) => {
            inner
                .notify(
                    "auth-profile",
                    "auth_user",
                    Some(who.id.clone()),
                    serde_json::json!({ "recovery_codes_reissued": codes.len() }),
                    &headers,
                    client_ip,
                )
                .await;
            let frag = recovery_codes_html(
                &codes,
                "Here is your new set. The previous codes no longer work.",
            );
            Html((inner.profile_shell)(&frag, &who)).into_response()
        }
        Err(_) => {
            let frag = profile_fragment(
                &inner,
                &who,
                &user,
                Some("Could not generate new recovery codes."),
                None,
                &csrf,
            )
            .await;
            (StatusCode::INTERNAL_SERVER_ERROR, Html((inner.profile_shell)(&frag, &who)))
                .into_response()
        }
    }
}

/// `POST /profile/sessions/revoke` — the caller signs out every session **except this one**.
async fn sessions_revoke(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    RealIp(client_ip): RealIp,
    Form(form): Form<CsrfOnlyForm>,
) -> Response {
    if !inner.csrf().verify(&headers, form.csrf.as_deref()) {
        return csrf_rejected(&inner);
    }
    let csrf = inner.csrf().token(&headers).unwrap_or_default();
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let Some(user) = current_user(&inner, &who).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    // Spare the caller's own session — identified by the cookie they just used, so a race with their own
    // logout can at worst spare a row that's about to be deleted anyway.
    let current = CookieJar::from_headers(&headers)
        .get(&inner.cookie_name)
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    let revoked = inner.revoke_sessions(user.id, Some(&current)).await;
    inner
        .notify(
            "auth-profile",
            "auth_user",
            Some(who.id.clone()),
            serde_json::json!({ "sessions_revoked": revoked }),
            &headers,
            client_ip,
        )
        .await;
    let msg = match revoked {
        0 => "This is your only session — nothing else to sign out.".to_string(),
        1 => "1 other session signed out.".to_string(),
        n => format!("{n} other sessions signed out."),
    };
    let frag = profile_fragment(&inner, &who, &user, None, Some(&msg), &csrf).await;
    Html((inner.profile_shell)(&frag, &who)).into_response()
}

/// `POST /profile/totp/disable` — the caller turns off their own 2FA. **Re-authenticated** (§5h):
/// removing the second factor is the first thing an intruder with a stolen session would do.
async fn totp_self_disable(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    Form(form): Form<ReauthForm>,
) -> Response {
    if !inner.csrf().verify(&headers, form.csrf.as_deref()) {
        return csrf_rejected(&inner);
    }
    let csrf = inner.csrf().token(&headers).unwrap_or_default();
    let Some(who) = identity_of(&inner, &headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let Some(user) = current_user(&inner, &who).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    if let Err(msg) = inner.reauth(&user, &form.current_password, &form.totp_code).await {
        let frag = profile_fragment(&inner, &who, &user, Some(&msg), None, &csrf).await;
        return (StatusCode::FORBIDDEN, Html((inner.profile_shell)(&frag, &who))).into_response();
    }
    clear_totp(&inner, user).await;
    let frag =
        change_form_html(&who, false, None, None, Some("Two-factor authentication disabled."), &csrf);
    Html((inner.profile_shell)(&frag, &who)).into_response()
}

/// `POST /profile/{id}/totp/disable` — a manager turns off *another* user's 2FA (they can re-enrol).
/// Managers can disable but never set up 2FA for someone else (enrolment needs the user's device).
async fn totp_manage_disable(
    State(inner): State<Arc<Inner>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Form(form): Form<ReauthForm>,
) -> Response {
    if !inner.csrf().verify(&headers, form.csrf.as_deref()) {
        return csrf_rejected(&inner);
    }
    let csrf = inner.csrf().token(&headers).unwrap_or_default();
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
    // Re-authenticate the **manager**, with their own factor — stripping a victim's second factor is
    // most of what a stolen manager session is worth.
    let Some(manager) = current_user(&inner, &who).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let manager_totp_on = manager.has_totp();
    if let Err(msg) = inner.reauth(&manager, &form.current_password, &form.totp_code).await {
        let frag = reset_form_html(
            &id,
            &target.username,
            target.has_totp(),
            manager_totp_on,
            Some(&msg),
            None,
            &csrf,
        );
        return (StatusCode::FORBIDDEN, Html((inner.profile_shell)(&frag, &who))).into_response();
    }
    let username = target.username.clone();
    clear_totp(&inner, target).await;
    let msg = format!("Two-factor authentication disabled for {username}.");
    let frag =
        reset_form_html(&id, &username, false, manager_totp_on, None, Some(&msg), &csrf);
    Html((inner.profile_shell)(&frag, &who)).into_response()
}

/// The whole self-service profile fragment for `user`: the password form, the 2FA section, the recovery
/// codes section (only when 2FA is on — it needs a count from the DB, which is why this is async), the
/// sessions section, and the app's `profile_extra` appended.
async fn profile_fragment(
    inner: &Inner,
    who: &Identity,
    user: &user::Model,
    error: Option<&str>,
    success: Option<&str>,
    csrf: &str,
) -> String {
    let totp_on = user.has_totp();
    let left = match totp_on {
        true => Some(recovery::remaining(&inner.db, user.id).await),
        false => None,
    };
    let frag = change_form_html(who, totp_on, left, error, success, csrf);
    inner.with_profile_extra(frag, who).await
}

/// The caller's own user row.
async fn current_user(inner: &Inner, who: &Identity) -> Option<user::Model> {
    let id = who.id.parse::<i32>().ok()?;
    user_by_id(&inner.db, id).await
}

/// Clear both the active and pending TOTP secrets on a user, the replay guard, and any recovery codes
/// (best-effort). The step **must** go in the same write: leaving a stale ceiling behind would silently
/// reject the first codes of a later re-enrolment, for as long as it took the clock to catch up. The
/// recovery codes go too — they are a way past a second factor that no longer exists, and a later
/// re-enrolment must not inherit a set the user threw away with their old phone.
async fn clear_totp(inner: &Inner, user: user::Model) {
    let user_id = user.id;
    let mut am: user::ActiveModel = user.into();
    am.totp_secret = Set(None);
    am.totp_pending = Set(None);
    am.totp_last_step = Set(None);
    let _ = am.update(&inner.db).await;
    let _ = recovery::clear(&inner.db, user_id).await;
}

/// Render the 2FA enrolment page (QR + otpauth URL + verify form) for a pending secret.
fn render_totp_setup(
    inner: &Inner,
    who: &Identity,
    secret: &str,
    totp_on: bool,
    error: Option<&str>,
    csrf: &str,
) -> Response {
    let Some(prov) = totp::provisioning(&inner.totp_issuer, &who.username, secret) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not build QR code").into_response();
    };
    let frag = totp_setup_html(&prov, totp_on, error, csrf);
    Html((inner.profile_shell)(&frag, who)).into_response()
}

/// Look up the target user by the (string) id from the URL. `None` if the id isn't an integer or no
/// such user exists.
async fn target_user(inner: &Inner, id: &str) -> Option<user::Model> {
    let uid = id.parse::<i32>().ok()?;
    user_by_id(&inner.db, uid).await
}

/// Shared validation for the new/confirm password pair.
/// Adapt a [`PasswordPolicy`](crate::validate::PasswordPolicy) into the stored check, passing the
/// account's username as context so a password containing it is refused.
fn policy_check(policy: crate::validate::PasswordPolicy) -> PasswordCheck {
    Arc::new(move |password: &str, username: &str| policy.check(password, &[username]))
}

fn password_pair_error(new: &str, confirm: &str) -> Option<&'static str> {
    if new.is_empty() {
        Some("New password cannot be empty.")
    } else if new != confirm {
        Some("The new passwords do not match.")
    } else {
        None
    }
}

/// The CSRF token to embed in a form we're about to render, minting (and setting) one if this request
/// carries none. Returns the jar to hand back with the response.
fn csrf_token(inner: &Inner, headers: &HeaderMap, jar: CookieJar) -> (String, CookieJar) {
    let (token, set) = inner.csrf().ensure(headers);
    match set {
        Some(cookie) => (token, jar.add(cookie)),
        None => (token, jar),
    }
}

/// `429 Too Many Requests` with a `Retry-After`, wrapping whatever the caller wants to render (the
/// login form with the message, the profile page, …). `extra` is any additional response part — a
/// `CookieJar` where one is being handed back, or `()`.
fn too_many_attempts<E, B>(retry_after: i64, extra: E, body: B) -> Response
where
    E: axum::response::IntoResponseParts,
    B: IntoResponse,
{
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(axum::http::header::RETRY_AFTER, retry_after.max(1).to_string())],
        extra,
        body,
    )
        .into_response()
}

/// What a locked-out visitor is told: enough to know to come back later, nothing about whether the
/// account exists or how many tries are left.
fn lockout_message(retry_after: i64) -> String {
    let minutes = (retry_after + 59) / 60;
    if minutes <= 1 {
        "Too many failed attempts. Try again in a minute.".to_string()
    } else {
        format!("Too many failed attempts. Try again in about {minutes} minutes.")
    }
}

/// The response to an unsafe request whose CSRF token is missing or wrong: a bare `403` page. It is
/// deliberately shell-less and static — we don't know that the caller is who they claim, so we render
/// nothing about them and set no cookies. A user who hit it with a stale tab just reloads.
fn csrf_rejected(inner: &Inner) -> Response {
    // The app's page when it set one (`Auth::csrf_rejection`), else the built-in below.
    if let Some(render) = &inner.csrf_reject {
        return render();
    }
    let login = esc(&inner.login_path);
    (
        StatusCode::FORBIDDEN,
        Html(format!(
            r#"<!doctype html><meta charset="utf-8"><title>Security check failed</title>
<main><h1>Security check failed</h1>
<p>This form was stale or the request didn't come from this site. Reload the page and try again.</p>
<p><a href="{login}">Back to the login page</a></p></main>"#
        )),
    )
        .into_response()
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
    crate::csrf::random_token() // 256 bits of OS randomness as hex
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// The login `<form>` fragment. Semantic HTML with Bootstrap-friendly class hooks — it carries no
/// page chrome and loads no CSS; the app's [`Auth::login_shell`] wraps + styles it.
fn login_form_html(error: Option<&str>, csrf: &str) -> String {
    let alert = error
        .map(|e| format!(r#"<div class="alert alert-danger" role="alert">{e}</div>"#))
        .unwrap_or_default();
    let csrf = crate::csrf::Csrf::hidden_input(csrf);
    format!(
        r#"<form method="post" action="/login">
  {csrf}
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
    recovery_left: Option<u64>,
    error: Option<&str>,
    success: Option<&str>,
    csrf: &str,
) -> String {
    let alert = alert_html(error, success);
    let twofa = twofa_self_section(totp_on, csrf);
    let recovery = match recovery_left {
        Some(left) => format!("<hr class=\"my-4\">\n{}", recovery_self_section(left, csrf)),
        None => String::new(),
    };
    let sessions = sessions_self_section(csrf);
    let csrf_input = crate::csrf::Csrf::hidden_input(csrf);
    format!(
        r#"<h1 class="h5 mb-3">Change your password</h1>
<p class="text-muted small">Signed in as <strong>{user}</strong>.</p>
<form method="post" action="/profile">
  {csrf_input}
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
{twofa}
{recovery}
<hr class="my-4">
{sessions}"#,
        user = esc(&who.username),
    )
}

/// The recovery-codes section of the profile page: how many are left, and a re-authenticated button to
/// replace the set. Only rendered when 2FA is on — codes recover a second factor, so without one there
/// is nothing for them to do.
fn recovery_self_section(left: u64, csrf: &str) -> String {
    let state = match left {
        0 => "<strong>None left.</strong> If you lose your authenticator now, only an administrator \
              can get you back in — generate a new set."
            .to_string(),
        1 => "<strong>1 code left.</strong> Generate a new set soon.".to_string(),
        n if n <= 3 => format!("<strong>{n} codes left.</strong> Generate a new set soon."),
        n => format!("{n} unused codes."),
    };
    format!(
        r#"<h2 class="h6">Recovery codes</h2>
<p class="text-muted small mb-2">Single-use codes that log you in when your authenticator isn't
available. {state}</p>
<form method="post" action="/profile/totp/recovery">
  {csrf_input}
{reauth}
  <button class="btn btn-outline-secondary btn-sm" type="submit">Generate new codes</button>
</form>
<p class="text-muted small mt-2 mb-0">Generating a set invalidates the previous one.</p>"#,
        csrf_input = crate::csrf::Csrf::hidden_input(csrf),
        reauth = reauth_inputs(
            "rl-rec",
            true,
            "Confirm it's you — a new set is a new way into this account.",
        ),
    )
}

/// The one-time display of a freshly issued set. There is no way back to this page: the codes are
/// hashed on the way in, so if the user doesn't keep them now they are gone.
fn recovery_codes_html(codes: &[String], headline: &str) -> String {
    let items = codes
        .iter()
        .map(|c| format!("<li><code>{}</code></li>", esc(&recovery::display(c))))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"<h1 class="h5 mb-3">Recovery codes</h1>
<div class="alert alert-success">{headline}</div>
<p class="text-muted small">Each code works <strong>once</strong>. Keep them somewhere you can reach
without this account — a password manager, or printed. <strong>They are not shown again:</strong> only
hashes are stored, so this page cannot be reproduced.</p>
<ul class="list-unstyled bg-body-secondary p-3 rounded" style="columns:2;font-size:1.05rem;letter-spacing:.05em">
{items}
</ul>
<a class="btn btn-primary btn-sm" href="/profile">I've saved them</a>"#,
        headline = esc(headline),
    )
}

/// The self sessions section: sign out everywhere else. Deliberately *other* sessions only — a button
/// that logged you out of the page you just clicked it on would be useless, and the honest case for it
/// ("I left myself logged in on a shared machine") wants exactly this shape.
fn sessions_self_section(csrf: &str) -> String {
    format!(
        r#"<h2 class="h6">Other sessions</h2>
<p class="text-muted small mb-2">Signed in somewhere you'd rather not be — a shared or lost device? Sign
out everywhere except here.</p>
<form method="post" action="/profile/sessions/revoke">
  {csrf_input}
  <button class="btn btn-outline-secondary btn-sm" type="submit">Sign out other sessions</button>
</form>"#,
        csrf_input = crate::csrf::Csrf::hidden_input(csrf),
    )
}

/// The confirm-it's-you inputs for a sensitive action (§5h): the account's password, or a fresh code
/// when it has 2FA. `id_prefix` keeps the input ids unique when two of these render on one page.
fn reauth_inputs(id_prefix: &str, totp_on: bool, hint: &str) -> String {
    let code = if totp_on {
        format!(
            r#"  <div class="mb-2">
    <label class="form-label small" for="{id_prefix}-code">…or a code from your authenticator app</label>
    <input class="form-control form-control-sm" id="{id_prefix}-code" name="totp_code"
           inputmode="numeric" autocomplete="one-time-code" placeholder="123456">
  </div>
"#
        )
    } else {
        String::new()
    };
    format!(
        r#"  <p class="text-muted small mb-2">{hint}</p>
  <div class="mb-2">
    <label class="form-label small" for="{id_prefix}-reauth">Your current password</label>
    <input class="form-control form-control-sm" id="{id_prefix}-reauth" name="current_password"
           type="password" autocomplete="current-password">
  </div>
{code}"#,
        hint = esc(hint),
    )
}

/// The self two-factor section: current state + a link to set up, or a button to disable.
fn twofa_self_section(on: bool, csrf: &str) -> String {
    if on {
        format!(
            r#"<h2 class="h6">Two-factor authentication</h2>
<p class="text-muted small mb-2">Enabled — a code from your authenticator app is required at login.</p>
<form method="post" action="/profile/totp/disable">
  {csrf_input}
{reauth}
  <button class="btn btn-outline-danger btn-sm" type="submit">Disable 2FA</button>
</form>"#,
            csrf_input = crate::csrf::Csrf::hidden_input(csrf),
            reauth = reauth_inputs(
                "rl-2fa-off",
                true,
                "Turning off your second factor needs confirming — this is what stops someone \
                 who has taken over your session from removing it.",
            ),
        )
    } else {
        r#"<h2 class="h6">Two-factor authentication</h2>
<p class="text-muted small mb-2">Off. Add a second factor with an authenticator app (TOTP).</p>
<a class="btn btn-outline-primary btn-sm" href="/profile/totp">Set up 2FA</a>"#
            .to_string()
    }
}

/// The **manager's** view of an SSO account: a notice in place of the reset form, since neither the
/// password nor the second factor is ours to set (`sso_profile_html` is the self view of the same fact).
fn sso_managed_html(username: &str, provider: &str) -> String {
    format!(
        r#"<h1 class="h5 mb-3">Manage {user}</h1>
<div class="alert alert-info mb-0">This account signs in through <strong>{prov}</strong> (single
sign-on). Its password and two-factor settings are managed by the identity provider — there is nothing to
reset here. Group memberships come from the SSO mapping and are reconciled at each login.</div>"#,
        user = esc(username),
        prov = esc(provider),
    )
}

/// The profile fragment for an SSO account: a read-only notice — password, 2FA, and groups are all
/// managed by the identity provider, so there's nothing to change locally.
fn sso_profile_html(who: &Identity, provider: &str) -> String {
    format!(
        r#"<h1 class="h5 mb-3">Profile</h1>
<p class="text-muted small">Signed in as <strong>{user}</strong>.</p>
<div class="alert alert-info mb-0">This account signs in through <strong>{prov}</strong> (single
sign-on). Its password, two-factor settings, and group memberships are managed by the identity
provider — there's nothing to change here.</div>"#,
        user = esc(&who.username),
        prov = esc(provider),
    )
}

/// The manager reset-password `<form>` fragment: sets another user's password with no current-password
/// check, plus a section to disable their 2FA. `id` is the target user id (used in the form actions).
fn reset_form_html(
    id: &str,
    username: &str,
    totp_on: bool,
    manager_totp_on: bool,
    error: Option<&str>,
    success: Option<&str>,
    csrf: &str,
) -> String {
    let alert = alert_html(error, success);
    let twofa = twofa_manage_section(id, username, totp_on, manager_totp_on, csrf);
    let csrf_input = crate::csrf::Csrf::hidden_input(csrf);
    format!(
        r#"<h1 class="h5 mb-3">Reset password</h1>
<p class="text-muted">Set a new password for <strong>{user}</strong> — you don't need their current one,
which is why you have to confirm your own identity below.</p>
<form method="post" action="/profile/{id}">
  {csrf_input}
  {alert}
  <div class="mb-3">
    <label class="form-label" for="rl-new">New password</label>
    <input class="form-control" id="rl-new" name="new_password" type="password" autocomplete="new-password" autofocus>
  </div>
  <div class="mb-3">
    <label class="form-label" for="rl-confirm">Confirm new password</label>
    <input class="form-control" id="rl-confirm" name="confirm_password" type="password" autocomplete="new-password">
  </div>
  <hr class="my-3">
{reauth}
  <button class="btn btn-primary" type="submit">Reset password</button>
</form>
<hr class="my-4">
{twofa}"#,
        user = esc(username),
        id = esc(id),
        reauth = reauth_inputs(
            "rl-mgr-pw",
            manager_totp_on,
            "Confirm it's you — this sets a password without knowing the old one, so it's the most \
             valuable thing a stolen session of yours could reach.",
        ),
    )
}

/// The manager two-factor section: disable the target's 2FA (managers can't set it up for others).
fn twofa_manage_section(
    id: &str,
    username: &str,
    on: bool,
    manager_totp_on: bool,
    csrf: &str,
) -> String {
    if on {
        format!(
            r#"<h2 class="h6">Two-factor authentication</h2>
<p class="text-muted small mb-2">This user has 2FA enabled. Disabling it lets them log in with just a password until they set it up again.</p>
<form method="post" action="/profile/{id}/totp/disable">
  {csrf_input}
{reauth}
  <button class="btn btn-outline-danger btn-sm" type="submit">Disable 2FA for {user}</button>
</form>"#,
            id = esc(id),
            user = esc(username),
            csrf_input = crate::csrf::Csrf::hidden_input(csrf),
            reauth = reauth_inputs(
                "rl-mgr-2fa",
                manager_totp_on,
                "Confirm it's you before removing someone else's second factor.",
            ),
        )
    } else {
        r#"<h2 class="h6">Two-factor authentication</h2>
<p class="text-muted small mb-0">This user has no two-factor authentication set up.</p>"#
            .to_string()
    }
}

/// The login second-factor `<form>` fragment (shown at `/login/totp` after a correct password).
fn totp_login_html(error: Option<&str>, csrf: &str) -> String {
    let alert = alert_html(error, None);
    let csrf_input = crate::csrf::Csrf::hidden_input(csrf);
    format!(
        r#"<h1 class="h5 mb-3">Two-factor authentication</h1>
<p class="text-muted small">Enter the 6-digit code from your authenticator app.</p>
<form method="post" action="/login/totp">
  {csrf_input}
  {alert}
  <div class="mb-3">
    <label class="form-label" for="rl-totp">Authentication code</label>
    <input class="form-control" id="rl-totp" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus>
  </div>
  <details class="mb-3">
    <summary class="small text-muted">Lost your authenticator?</summary>
    <div class="mt-2">
      <label class="form-label small" for="rl-recovery">Recovery code</label>
      <input class="form-control" id="rl-recovery" name="recovery_code" autocomplete="off"
             placeholder="abcde-fghij" spellcheck="false">
      <p class="form-text">Each recovery code works once. You'll land on your profile so you can
      re-enrol or generate a new set.</p>
    </div>
  </details>
  <button class="btn btn-primary" type="submit">Verify</button>
</form>"#
    )
}

/// The 2FA enrolment `<form>` fragment: the QR image, the `otpauth://` URL as copyable text, and a
/// code field to confirm before activation.
fn totp_setup_html(
    prov: &totp::Provisioning,
    totp_on: bool,
    error: Option<&str>,
    csrf: &str,
) -> String {
    let alert = alert_html(error, None);
    let csrf_input = crate::csrf::Csrf::hidden_input(csrf);
    let reauth = reauth_inputs(
        "rl-2fa-on",
        totp_on,
        "Confirm it's you: the code above proves you hold that device, not that the account is yours.",
    );
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
  {csrf_input}
  <div class="mb-3">
    <label class="form-label" for="rl-totp">Authentication code</label>
    <input class="form-control" id="rl-totp" name="code" inputmode="numeric" autocomplete="one-time-code" autofocus>
  </div>
  <hr class="my-3">
{reauth}
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

    #[test]
    fn username_validation() {
        assert!(valid_username("alice").is_ok());
        assert!(valid_username("alice@example.com").is_ok()); // email-style (OIDC claim)
        assert!(valid_username("").is_err());
        assert!(valid_username("   ").is_err());
        assert!(valid_username("has space").is_err());
        assert!(valid_username("nul\0byte").is_err());
        assert!(valid_username("line\nbreak").is_err());
        assert!(valid_username(&"x".repeat(255)).is_err());
    }

    #[test]
    fn group_name_validation() {
        assert!(valid_group_name("admin").is_ok());
        assert!(valid_group_name("Site Admins").is_ok()); // spaces allowed, unlike usernames
        assert!(valid_group_name("").is_err());
        assert!(valid_group_name("bad\tname").is_err()); // tab is a control char
    }

    #[test]
    fn migrate_is_idempotent_via_if_not_exists() {
        // The bootstrap `migrate` builds these with IF NOT EXISTS, so re-running on an existing DB
        // won't error ("table already exists"). Verified at the SQL level (no DB needed).
        let stmts = table_create_statements(DbBackend::Sqlite);
        assert_eq!(
            stmts.len(),
            7,
            "user, group, user_group, session, the two lockout tables + totp recovery"
        );
        for mut stmt in stmts {
            stmt.if_not_exists();
            let sql = DbBackend::Sqlite.build(&stmt).sql.to_uppercase();
            assert!(sql.contains("IF NOT EXISTS"), "missing IF NOT EXISTS: {sql}");
        }
        // Without if_not_exists (the raw statements), it's a plain CREATE TABLE — for migrations.
        let raw = DbBackend::Sqlite.build(&table_create_statements(DbBackend::Sqlite)[0]).sql;
        assert!(raw.contains("auth_user"));
    }
}
