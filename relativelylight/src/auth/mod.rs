//! `relativelylight::auth` — authentication (users, sessions, login, argon2id) + authorization
//! (a small [`Authz`] gate trait + presets). Its presets gate the
//! `crud` engine, and any route of the app. See `docs/AUTH.md` for the full design.
//!
//! There is **no middleware and no injected request context**. Authn is a handful of on-demand
//! lookups on [`Auth`]: given a request's headers, [`Auth::identify`] resolves the session cookie →
//! user → groups in one query and returns an [`Identity`] (or `None` for anonymous). The
//! authorization gate itself lives in [`crate::authz`]; the presets here ([`UserReadWrite`],
//! [`UserReadGroupWrite`]) implement it by resolving the identity with an `Auth` handle and
//! returning a [`Decision`] the caller renders.
//!
//! Implemented: the `user`/`session`/`group`/`user_group` SeaORM models, argon2id hashing, a
//! login/logout flow with an opaque server-side session cookie (via `axum-extra`'s `CookieJar`),
//! **TOTP two-factor authentication** (a second-factor step at login, plus self-service enrolment /
//! disable on the profile page and a manager disable for other users), on-demand [`Auth::identify`](crate::auth::Auth::identify),
//! the gate presets ([`UserReadWrite`], [`UserReadGroupWrite`], [`GroupReadWrite`]), a self-service
//! **profile / password-change** page plus a manager reset (`GET/POST /profile`,
//! `GET/POST /profile/{id}` — see [`Auth::routes`]), admin helpers ([`make_admin`] to seed one,
//! [`reset_admin_access`] for break-glass recovery, [`set_password`], [`add_to_group`], …), and
//! per-model enforcement in the `crud` HTTP handlers via
//! `crud::seaorm::Crud::register`, plus **OIDC single sign-on** (feature `sso`, module [`sso`]:
//! Google / Okta / corporate, with username- and claim-based group mapping and optional
//! auto-registration), and **API keys** for machine endpoints (module [`api_key`],
//! [`Auth::identify_key`]). Not yet: PassKeys.
//!
//! The session cookie (name configurable, default `rl_session`) carries only an **opaque token** —
//! the id of a row in the session table; the identity is rebuilt server-side from the DB on each
//! lookup, and deleting the row revokes it.

/// API keys (§5k): bearer keys for the app's machine endpoints, each acting as its owner.
pub mod api_key;
pub mod group;
/// Lockout (§5e): the two DB-backed failure counters — by account name and by source address —
/// braking the unauthenticated credential checks, here and in the app.
pub mod lockout;
/// The HTML pages, as Askama templates in `templates/auth/`.
mod pages;
/// Passkeys (WebAuthn): the credential and challenge tables, and the hardware-binding [`passkey::Class`].
pub mod passkey;
/// Upgrading an existing database to 0.5's schema: the new tables, columns and index.
pub mod upgrade;
/// The passkey ceremonies, routes and configuration (feature `passkeys`, §5l).
#[cfg(feature = "passkeys")]
mod webauthn;
#[cfg(all(test, feature = "passkeys"))]
mod passkey_tests;
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

use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use async_trait::async_trait;
use axum::extract::{Form, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use pages::*;
use crate::authz::{Authz, Decision, Operation};
use crate::middleware::RealIp;
use sea_orm::sea_query::TableCreateStatement;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, DbErr,
    EntityTrait, IntoActiveModel, QueryFilter, Schema, Set,
};

pub use api_key::bearer_token;

const DEFAULT_COOKIE: &str = "rl_session";

// ===================== Identity + gate presets =====================

/// A logged-in identity, resolved on demand by [`Auth::identify`] from the session cookie. It is a
/// plain return value — nothing injects it into the request.
///
/// **`#[non_exhaustive]` with [`Identity::new`]**, because this is the type most likely to grow: an
/// assurance level once PassKeys land. (An API-key caller is an `Identity` inside an
/// [`api_key::KeyIdentity`], which says which key; this type stays the same for both.) Reading it is
/// unaffected; the constructor is there for the cases that legitimately build one — a test double, or a
/// custom identity source of your own.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Identity {
    pub id: String,
    pub username: String,
    pub groups: Vec<String>,
    /// How strongly this session was authenticated (§5m). Always at least the site's
    /// [`min_level`](Auth::min_level): a session below it isn't an identity at all.
    pub level: Level,
    /// Whether, and why, the account should choose a new password (§5m) — for a notice in the app's
    /// shell. `None` for an account with no password.
    pub password_change: Option<user::PasswordChange>,
    /// The session this identity was resolved from, where an SSO confirmation is kept (§5h). `None` for
    /// an identity built with [`Identity::new`] or from an API key.
    pub(crate) session: Option<SessionRef>,
}

/// A session id held by an [`Identity`]. It is the session cookie's value, a credential, so its `Debug`
/// says only that there is one: an app logging `{who:?}` must not write a usable cookie to its logs.
#[derive(Clone)]
pub(crate) struct SessionRef(pub(crate) String);

impl std::fmt::Debug for SessionRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionRef(..)")
    }
}

impl Identity {
    /// An identity from its parts. `id` is the `auth_user` primary key as a string. Its
    /// [`level`](Identity::level) is [`Level::Simple`] and it has no password change due.
    pub fn new(id: impl Into<String>, username: impl Into<String>, groups: Vec<String>) -> Self {
        Self {
            id: id.into(),
            username: username.into(),
            groups,
            level: Level::Simple,
            password_change: None,
            session: None,
        }
    }

    /// The same identity at `level` — for a test double, or an identity source of your own.
    pub fn with_level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// Whether this identity belongs to the named group.
    pub fn in_group(&self, group: &str) -> bool {
        self.groups.iter().any(|g| g == group)
    }

    /// Whether this identity belongs to any of the given groups.
    pub fn in_any_group(&self, groups: &[String]) -> bool {
        self.groups.iter().any(|g| groups.contains(g))
    }
}

// ===================== Assurance level =====================

/// How strongly a session was authenticated — the sign-in policy's one number (§5m, and the table in
/// `docs/DESIGN.md` → auth). Ordered: `Simple < Mfa < Attested`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// One factor: a password alone, or SSO when the app distrusts the IdP
    /// ([`Auth::sso_level`]).
    Simple = 1,
    /// Two factors, or one that is both (a passkey verifies the user itself): a password + TOTP, a
    /// passkey, SSO by default.
    Mfa = 2,
    /// An attested passkey: hardware of a model the site trusts.
    Attested = 3,
}

// ===================== Re-authentication input =====================

/// What a re-authenticating form submits (§5h): any one of the account's factors. Flatten it into your
/// own form's struct (`#[serde(flatten)] reauth: ReauthInput`) and hand it to
/// [`Auth::reauthenticate_with`]; [`Auth::reauth_fields`] renders the inputs it reads.
///
/// `#[non_exhaustive]` so a factor added later isn't a break; build one with `Default` and the fields.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[non_exhaustive]
pub struct ReauthInput {
    /// The account's password.
    #[serde(default)]
    pub current_password: String,
    /// A fresh code from the account's authenticator app.
    #[serde(default)]
    pub totp_code: String,
    /// The passkey challenge the page was rendered with.
    #[serde(default)]
    pub passkey_challenge: String,
    /// The browser's answer to it (JSON), filled in by the passkey script.
    #[serde(default)]
    pub passkey_response: String,
}

impl ReauthInput {
    /// A password and/or a TOTP code, for a caller that has no form to flatten this into (a CLI, a test).
    pub fn password_or_code(password: &str, totp_code: &str) -> Self {
        Self {
            current_password: password.to_string(),
            totp_code: totp_code.to_string(),
            ..Self::default()
        }
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
    // A fresh random salt from the OS (argon2's `getrandom` feature).
    Argon2::default()
        .hash_password(password.as_bytes())
        .expect("argon2 hashing failed")
        .to_string()
}

/// Verify a password against a stored PHC hash (constant-time; `false` on any error).
pub fn verify_password(hash: &str, password: &str) -> bool {
    // The parameters come from the PHC string, so hashes made with other settings still verify.
    Argon2::default().verify_password(password.as_bytes(), hash).is_ok()
}

// ===================== Setup helpers =====================

/// The `CREATE TABLE` statements for the auth tables — `auth_user`, `auth_group`, `auth_user_group`,
/// `auth_session`, the two lockout tables, `auth_totp_recovery`, `auth_api_key`, `auth_passkey` and
/// `auth_webauthn_challenge` (in that order). Use these to fold the auth schema into your own **`sea-orm-migration`**
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
        schema.create_table_from_entity(api_key::entity::Entity),
        schema.create_table_from_entity(passkey::entity::Entity),
        schema.create_table_from_entity(passkey::challenge::Entity),
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
    let challenges = passkey::prune_challenges(db).await?;
    Ok(sessions + usernames + ips + challenges)
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
        db.execute(&stmt).await?;
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
        must_change_password: Set(false),
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
///
/// It does **not** ask the owner to change it (`must_change_password` is cleared): this is the owner's
/// own change, or a seeder's. To set someone's password *for* them, write the row (the hook flags it)
/// or set `must_change_password` yourself.
pub async fn set_password(db: &DatabaseConnection, username: &str, password: &str) -> Result<(), DbErr> {
    let existing = user::Entity::find()
        .filter(user::Column::Username.eq(username))
        .one(db)
        .await?
        .ok_or_else(|| DbErr::Custom(format!("no such user: {username}")))?;
    set_password_hash(db, existing, password, false).await
}

/// Set `user`'s password, and whether its owner must then choose their own (`must_change`): `true`
/// when someone else chose it (a manager's reset), `false` for the owner's own change and for the
/// programmatic helpers. The row hook stamps `password_changed_at`.
async fn set_password_hash(
    db: &DatabaseConnection,
    user: user::Model,
    password: &str,
    must_change: bool,
) -> Result<(), DbErr> {
    let mut am = user.into_active_model();
    am.password_hash = Set(hash_password(password));
    am.must_change_password = Set(must_change);
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
            am.must_change_password = Set(false);
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

type LoginShell = Arc<dyn Fn(&str, &Parts) -> String + Send + Sync>;
/// Wraps the profile/password fragment into a full page. Also handed the resolved [`Identity`] so the
/// app can render its chrome (e.g. the signed-in username in the navbar).
/// What [`Auth::profile_extra`] hands an app's own profile section.
///
/// `#[non_exhaustive]`: the crate constructs it and apps read it, so a field added later (the
/// caller's address, say) costs nobody a break.
#[non_exhaustive]
pub struct ProfileSection {
    /// Whose profile page this is — always the caller's own (the hook is not run on `/profile/{id}`).
    pub who: Identity,
    /// The double-submit CSRF token for **this request**. A form in your section must carry it —
    /// `csrf::Csrf::hidden_input(&s.csrf)` — or its POST is refused like any other.
    pub csrf: String,
    /// This request's headers — for whatever your section reads from the request itself, such as a
    /// display-preference cookie: `time::Tz::from_headers(&s.headers)` gives a
    /// [`time::picker`](crate::time::picker) the caller's current zone.
    pub headers: HeaderMap,
    /// The confirm-it's-you inputs for a sensitive form in your section, as an HTML fragment: the
    /// caller's password, code and passkey, whichever they have — the same block (and passkey
    /// challenge) as the library's own forms on this page. Put it inside your `<form>` and check the
    /// post with [`Auth::reauthenticate_with`].
    pub reauth_fields: String,
}

/// A card for the profile page's grid, for [`Auth::profile_extra`]: `title` (escaped) over `body` (HTML,
/// inserted as is), drawn like the library's own cards so the page stays one grid.
///
/// ```ignore
/// .profile_extra(|s: ProfileSection| async move {
///     auth::profile_card("Notifications", &my_notification_form(&s))
/// })
/// ```
pub fn profile_card(title: &str, body: &str) -> String {
    card_html(title, body)
}

type ProfileShell = Arc<dyn Fn(&str, &Identity, &Parts) -> String + Send + Sync>;
/// Renders an extra app-owned section appended below the password/2FA fragment on the *self* profile
/// page (e.g. API-token management). Handed a [`ProfileSection`]; returns an HTML fragment.
type ProfileExtra = Arc<
    dyn Fn(ProfileSection) -> std::pin::Pin<Box<dyn std::future::Future<Output = String> + Send>>
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
    /// `SameSite=Lax` instead of `Strict` (see [`Auth::same_site_lax`]).
    same_site_lax: bool,
    /// The **absolute** session lifetime (see [`Auth::session_ttl_secs`]).
    ttl_secs: i64,
    /// The **idle** session lifetime, `0` = no idle timeout (see [`Auth::session_idle_secs`]).
    idle_secs: i64,
    /// Optional audit sink; fired from the mutating auth handlers (password change, manager reset).
    observer: Option<Arc<dyn crate::observe::WriteObserver>>,
    /// Optional sink for errors the responses hide (see [`Auth::on_error`]).
    error_observer: Option<Arc<dyn crate::observe::ErrorObserver>>,
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
    /// Self-service API keys on `/profile`, when switched on (see [`Auth::api_keys`]).
    api_keys: Option<api_key::ApiKeys>,
    /// Passkeys, when switched on (see `Auth::passkeys`).
    #[cfg(feature = "passkeys")]
    passkeys: Option<Arc<webauthn::Runtime>>,
    /// The lowest [`Level`] a session must have (see [`Auth::min_level`]).
    min_level: Level,
    /// The level an SSO sign-in counts as (see [`Auth::sso_level`]).
    sso_level: Level,
    /// The password's maximum age in days, `0` = none (see [`Auth::password_max_age_days`]).
    password_max_age_days: u32,
    /// Where an SSO account confirms it's you (§5h): each provider's confirm route, recorded once by
    /// `Sso::routes` (which runs after `Sso` cloned this `Auth`, hence set-once). Unset on a site with
    /// no SSO routes, which then has nowhere to send an SSO account to confirm.
    sso_confirm: std::sync::OnceLock<Vec<SsoConfirmRoute>>,
}

/// One provider's confirm-it's-you route (§5h), as `Sso::routes` records it.
pub(crate) struct SsoConfirmRoute {
    pub(crate) key: String,
    pub(crate) label: String,
    pub(crate) url: String,
}

/// How long an SSO account's confirmation at its provider stays good for, unspent (§5h): long enough to
/// fill a form in after coming back, short enough that it is about this sitting.
#[cfg(feature = "sso")]
pub(crate) const SSO_CONFIRM_SECS: i64 = 300;

impl Inner {
    /// The confirm route of `user`'s provider, when the account signs in through one mounted here.
    fn sso_confirm_route(&self, user: &user::Model) -> Option<&SsoConfirmRoute> {
        let key = user.sso_key()?;
        self.sso_confirm.get()?.iter().find(|r| r.key == key)
    }

    /// Record a confirmation at the provider on the session `token`, good for [`SSO_CONFIRM_SECS`].
    #[cfg(feature = "sso")]
    pub(crate) async fn record_sso_confirmation(&self, token: &str) -> Result<(), DbErr> {
        session::Entity::update_many()
            .col_expr(session::Column::ReauthUntil, sea_orm::sea_query::Expr::value(now_secs() + SSO_CONFIRM_SECS))
            .filter(session::Column::Id.eq(token))
            .exec(&self.db)
            .await?;
        Ok(())
    }

    /// Whether `who`'s session holds an unspent, unexpired confirmation (to say so on the page).
    async fn sso_confirmed(&self, who: &Identity) -> bool {
        let Some(SessionRef(token)) = &who.session else { return false };
        session::Entity::find_by_id(token.clone())
            .one(&self.db)
            .await
            .ok()
            .flatten()
            .and_then(|s| s.reauth_until)
            .is_some_and(|until| until >= now_secs())
    }

    /// Spend `who`'s confirmation: `true` if the session held one still good. One statement that
    /// clears it only where it is unexpired, so two requests racing for it can't both win.
    async fn spend_sso_confirmation(&self, who: &Identity) -> bool {
        let Some(SessionRef(token)) = &who.session else { return false };
        session::Entity::update_many()
            .col_expr(session::Column::ReauthUntil, sea_orm::sea_query::Expr::value(Option::<i64>::None))
            .filter(session::Column::Id.eq(token.as_str()))
            .filter(session::Column::ReauthUntil.gte(now_secs()))
            .exec(&self.db)
            .await
            .is_ok_and(|r| r.rows_affected == 1)
    }

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

    /// Re-authenticate the holder of `user` with any factor the account has: its password, a fresh TOTP
    /// code, its passkey, or for an SSO account a confirmation at its provider (§5h). `Ok(())` on success
    /// **or** when a local account has no factor at all, having nothing to be asked for. See
    /// [`Auth::reauthenticate_with`] for what this is protecting against.
    ///
    /// A passkey counts as a factor, so an account without a password but with a passkey **must**
    /// present one of its factors. A code accepted here is **spent** (the §5a replay guard), and so is a
    /// passkey challenge.
    ///
    /// `who` is whoever is confirming (the manager, on a manager's page): an SSO account's confirmation
    /// at its provider is kept on their session, and spent here.
    async fn reauth(&self, user: &user::Model, who: &Identity, proof: &ReauthInput) -> Result<(), String> {
        // An SSO account's password, if a row has one left over, signs nobody in: it isn't a factor.
        let has_password = !user.password_hash.is_empty() && !user.is_sso();
        let has_passkey = passkey::count(&self.db, user.id).await > 0;
        if !has_password && !user.has_totp() && !has_passkey && !user.is_sso() {
            // A local account with no factor at all, which can't sign in to have a session.
            return Ok(());
        }
        // A passkey first: it proves presence and possession in one step, and the script only fills
        // the answer in when the user chose it.
        if !proof.passkey_response.trim().is_empty() {
            if !has_passkey {
                return Err("This account has no passkey. Use another way to confirm.".into());
            }
            return self.reauth_passkey(user, proof).await;
        }
        // The code next: a fresh code is better evidence of presence than a password, which a browser
        // may have filled in for whoever is sitting there.
        if !proof.totp_code.trim().is_empty() {
            if let Some(secret) = user.totp_key() {
                return match totp::verify_step(secret, &proof.totp_code) {
                    Some(step) if user.totp_step_ok(step) => {
                        stamp_login(&self.db, user.id, Some(step)).await; // spend it
                        Ok(())
                    }
                    _ => Err("That code is not valid. Try the current one from your app.".into()),
                };
            }
            return Err("This account has no authenticator app — enter your password instead.".into());
        }
        if !proof.current_password.is_empty() {
            return if has_password && verify_password(&user.password_hash, &proof.current_password) {
                Ok(())
            } else if !has_password {
                Err("This account has no password. Confirm another way.".into())
            } else {
                Err("That password is incorrect.".into())
            };
        }
        // Nothing typed: an SSO account may have confirmed at its provider before submitting (§5h).
        if user.is_sso() {
            if self.spend_sso_confirmation(who).await {
                return Ok(());
            }
            let Some(route) = self.sso_confirm_route(user) else {
                return Err("This account signs in through a provider this site can't reach to confirm \
                            it's you."
                    .into());
            };
            let label = &route.label;
            return Err(match (user.has_totp(), has_passkey) {
                (false, false) => format!("Confirm with {label} first, then submit again."),
                (true, false) => {
                    format!("Confirm with {label} first, or enter a code from your authenticator app.")
                }
                (false, true) => format!("Confirm with {label} first, or with your passkey."),
                (true, true) => format!(
                    "Confirm with {label} first, or with your passkey or a code from your authenticator app."
                ),
            });
        }
        Err(match (has_password, user.has_totp(), has_passkey) {
            (true, false, false) => "Confirm with your current password.".into(),
            (true, true, false) => {
                "Confirm with your password or a code from your authenticator app.".into()
            }
            (true, false, true) => "Confirm with your password or your passkey.".into(),
            (true, true, true) => {
                "Confirm with your password, a code from your authenticator app, or your passkey.".into()
            }
            (false, true, true) => {
                "Confirm with your passkey or a code from your authenticator app.".into()
            }
            (false, true, false) => "Confirm with a code from your authenticator app.".into(),
            (false, false, _) => "Confirm with your passkey.".into(),
        })
    }

    /// The passkey half of [`reauth`](Inner::reauth).
    #[cfg(feature = "passkeys")]
    async fn reauth_passkey(&self, user: &user::Model, proof: &ReauthInput) -> Result<(), String> {
        let Some(rt) = self.passkeys.clone() else {
            return Err("Passkeys are not enabled on this site.".into());
        };
        let (challenge, response) = (&proof.passkey_challenge, &proof.passkey_response);
        let purpose = webauthn::Purpose::Reauth;
        let checked = rt.verify_user(self, user, purpose, challenge, response).await;
        checked.map(|_| ()).map_err(|r| r.message)
    }

    #[cfg(not(feature = "passkeys"))]
    async fn reauth_passkey(&self, _user: &user::Model, _proof: &ReauthInput) -> Result<(), String> {
        Err("Passkeys are not enabled on this site.".into())
    }

    /// What `user`'s confirm-it's-you blocks can offer, on a page about to be rendered for `who` (the
    /// confirming caller): their factors, a fresh passkey challenge when they have a passkey and
    /// passkeys are on, and for an SSO account its provider's confirmation.
    async fn reauth_view(&self, user: &user::Model, who: &Identity) -> ReauthView {
        let sso = match self.sso_confirm_route(user) {
            Some(r) => Some(pages::SsoConfirmView {
                label: r.label.clone(),
                url: r.url.clone(),
                confirmed: self.sso_confirmed(who).await,
            }),
            None => None,
        };
        ReauthView {
            has_password: !user.password_hash.is_empty() && !user.is_sso(),
            totp_on: user.has_totp(),
            passkey: self.passkey_ask(user).await,
            sso,
        }
    }

    #[cfg(feature = "passkeys")]
    async fn passkey_ask(&self, user: &user::Model) -> Option<PasskeyAsk> {
        let rt = self.passkeys.clone()?;
        rt.ask_user(self, user, webauthn::Purpose::Reauth).await
    }

    #[cfg(not(feature = "passkeys"))]
    async fn passkey_ask(&self, _user: &user::Model) -> Option<PasskeyAsk> {
        None
    }

    /// Whether `user`'s password sign-in continues to a passkey step: passkeys are a second factor here
    /// and the account has one.
    async fn second_factor_ask_possible(&self, user: &user::Model) -> bool {
        #[cfg(feature = "passkeys")]
        if let Some(rt) = &self.passkeys {
            return rt.second_factor() && passkey::count(&self.db, user.id).await > 0;
        }
        let _ = user;
        false
    }

    /// The passkey challenge for `user`'s second step, when [`second_factor_ask_possible`].
    ///
    /// [`second_factor_ask_possible`]: Inner::second_factor_ask_possible
    async fn second_factor_ask(&self, user: &user::Model) -> Option<PasskeyAsk> {
        #[cfg(feature = "passkeys")]
        if let Some(rt) = self.passkeys.clone() {
            if rt.second_factor() {
                return rt.ask_user(self, user, webauthn::Purpose::SecondFactor).await;
            }
        }
        let _ = user;
        None
    }

    /// The [`Level`] a session authenticated by `method` (with a passkey of `class`) has. See the table
    /// in `docs/DESIGN.md` → auth: TOTP lifts a method to `Mfa`, never higher; `Attested` is an
    /// attested passkey. An unknown method (a row from before the column existed) is `Simple`.
    fn level_of(&self, method: Option<session::Method>, class: Option<passkey::Class>) -> Level {
        use session::Method as M;
        let passkey = match class {
            Some(passkey::Class::Attested) => Level::Attested,
            _ => Level::Mfa,
        };
        match method {
            Some(M::Password) | None => Level::Simple,
            Some(M::PasswordTotp | M::PasswordRecovery) => Level::Mfa,
            Some(M::Passkey | M::PasskeyTotp | M::PasskeyRecovery | M::PasswordPasskey) => passkey,
            Some(M::Sso) => self.sso_level,
            Some(M::SsoTotp | M::SsoRecovery) => self.sso_level.max(Level::Mfa),
        }
    }

    /// Whether `who`'s session is below the site's minimum: a restricted session, good only for adding
    /// the factor it lacks on the caller's own profile.
    fn restricted(&self, who: &Identity) -> bool {
        who.level < self.min_level
    }

    /// Where a sign-in that just finished lands: the profile when the session is restricted or the
    /// password should be changed (both explained there), otherwise the app's root.
    fn landing(&self, user: &user::Model, method: session::Method, class: Option<passkey::Class>) -> &str {
        let below = self.level_of(Some(method), class) < self.min_level;
        let change = user.password_change(self.password_max_age_days, now_secs()).is_some();
        match below || change {
            true => &self.profile_path,
            false => "/",
        }
    }

    /// Whether passkeys are on and accept only attested ones — what `Level::Attested` needs.
    fn attested_only(&self) -> bool {
        #[cfg(feature = "passkeys")]
        if let Some(rt) = &self.passkeys {
            return rt.require() == passkey::Class::Attested;
        }
        false
    }

    /// What a restricted session's profile says it needs.
    fn policy_notice(&self, user: &user::Model) -> String {
        let can_passkey = self.passkeys_on() && !user.is_sso();
        match self.min_level {
            Level::Attested => "This site needs a security key of a model it trusts. Add one under \
                Passkeys below; until then you can use only this page."
                .into(),
            _ if can_passkey => "This site needs a second way to confirm it's you. Add an authenticator \
                app or a passkey below; until then you can use only this page."
                .into(),
            _ => "This site needs a second way to confirm it's you. Add an authenticator app below; \
                until then you can use only this page."
                .into(),
        }
    }

    /// What the profile says about a password change that is due.
    fn password_notice(&self, why: user::PasswordChange) -> String {
        match why {
            user::PasswordChange::Expired => format!(
                "Your password is older than {} days, this site's limit. Choose a new one below; you \
                 can keep using the site meanwhile.",
                self.password_max_age_days
            ),
            _ => "Your password was set by an administrator. Choose your own below; you can keep \
                using the site meanwhile."
                .into(),
        }
    }

    /// Whether passkeys are switched on (the feature, and `Auth::passkeys`).
    fn passkeys_on(&self) -> bool {
        #[cfg(feature = "passkeys")]
        {
            self.passkeys.is_some()
        }
        #[cfg(not(feature = "passkeys"))]
        {
            false
        }
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
    /// stale, so the common case stays a read. A no-op when the idle clock is off.
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
            .same_site_lax(self.same_site_lax)
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

    /// A page in the app's profile shell, handed the request so the shell can render its chrome.
    fn page(&self, who: &Identity, frag: &str, req: &Parts) -> Html<String> {
        Html((self.profile_shell)(frag, who, req))
    }

    /// The app's own cards for the caller's profile (`Auth::profile_extra`), or nothing.
    async fn profile_extra(
        &self,
        who: &Identity,
        reauth: &ReauthView,
        csrf: &str,
        headers: &HeaderMap,
    ) -> String {
        let Some(hook) = &self.profile_extra else { return String::new() };
        let ctx = ProfileSection {
            who: who.clone(),
            csrf: csrf.to_string(),
            headers: headers.clone(),
            reauth_fields: reauth_fields_html(reauth, "Confirm it's you."),
        };
        hook(ctx).await
    }

    /// The passkeys card, when passkeys are on and the account isn't SSO.
    #[cfg(feature = "passkeys")]
    async fn passkeys_card(
        &self,
        user: &user::Model,
        reauth: &ReauthView,
        csrf: &str,
        headers: &HeaderMap,
    ) -> Option<String> {
        let rt = self.passkeys.clone().filter(|_| !user.is_sso())?;
        Some(rt.card_html(self, user, reauth, csrf, headers).await)
    }

    #[cfg(not(feature = "passkeys"))]
    async fn passkeys_card(
        &self,
        _user: &user::Model,
        _reauth: &ReauthView,
        _csrf: &str,
        _headers: &HeaderMap,
    ) -> Option<String> {
        None
    }

    /// Fire the audit observer for a mutating auth action (no-op if none registered). `after` should
    /// describe *what* changed without secrets (never a password hash / TOTP secret).
    #[allow(clippy::too_many_arguments)]
    async fn notify(
        &self,
        source: &'static str,
        actor: &str,
        entity: &str,
        key: Option<String>,
        after: serde_json::Value,
        headers: &HeaderMap,
        client_ip: std::net::IpAddr,
    ) {
        self.notify_event(Event {
            source,
            op: crate::authz::Operation::Update,
            actor,
            entity,
            key,
            before: None,
            after: Some(after),
            headers,
            client_ip,
        })
        .await;
    }

    /// Audit a change the caller made to their own account (`auth-profile` on their `auth_user` row).
    async fn notify_own(
        &self,
        who: &Identity,
        after: serde_json::Value,
        headers: &HeaderMap,
        client_ip: std::net::IpAddr,
    ) {
        self.notify("auth-profile", &who.username, "auth_user", Some(who.id.clone()), after, headers, client_ip).await;
    }

    /// Fire the audit observer with any operation — a create, an update or a single-row delete, whose
    /// `before` also becomes the event's one `before_rows` element.
    async fn notify_event(&self, ev: Event<'_>) {
        let Some(observer) = &self.observer else { return };
        let before_rows: Vec<serde_json::Value> = match ev.op {
            crate::authz::Operation::Delete => ev.before.iter().cloned().collect(),
            _ => Vec::new(),
        };
        let ev = crate::observe::WriteEvent {
            source: ev.source,
            op: ev.op,
            entity: ev.entity,
            key: ev.key,
            before: ev.before,
            after: ev.after,
            before_rows: &before_rows,
            actor: Some(ev.actor),
            headers: ev.headers,
            client_ip: ev.client_ip,
        };
        observer.on_write(&ev).await;
    }

    /// Hand an error the response won't mention to the error observer (no-op if none registered).
    async fn report(
        &self,
        source: &'static str,
        during: &'static str,
        error: &(dyn std::error::Error + Send + Sync),
        client_ip: std::net::IpAddr,
    ) {
        let Some(observer) = &self.error_observer else { return };
        let ev = crate::observe::ErrorEvent { source, during, error, client_ip };
        observer.on_error(&ev).await;
    }
}

/// What [`Inner::notify_event`] reports: the fields of a [`WriteEvent`](crate::observe::WriteEvent)
/// an `auth` handler knows. Never put a secret in `before` / `after`.
struct Event<'a> {
    source: &'static str,
    op: crate::authz::Operation,
    actor: &'a str,
    entity: &'a str,
    key: Option<String>,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
    headers: &'a HeaderMap,
    client_ip: std::net::IpAddr,
}

/// SHA-256 of `s`, lowercase hex: what the crate stores in place of a secret (an API key, a recovery
/// code) and how it names one it must not carry (a session, in the SSO transaction cookie).
pub(crate) fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// A sign-in is complete: stamp it ([`stamp_login`]) and report it to the audit observer as an
/// `Update` of `auth_user` from `"auth-login"`, `after` naming the way in (`{"signed_in":
/// "password+totp"}`). Every login path ends here, so none is left out of the audit trail.
async fn complete_login(
    inner: &Inner,
    user: &user::Model,
    method: session::Method,
    totp_step: Option<i64>,
    headers: &HeaderMap,
    client_ip: std::net::IpAddr,
) {
    stamp_login(&inner.db, user.id, totp_step).await;
    inner
        .notify(
            "auth-login",
            &user.username,
            "auth_user",
            Some(user.id.to_string()),
            serde_json::json!({ "signed_in": method.as_str() }),
            headers,
            client_ip,
        )
        .await;
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
                same_site_lax: false,
                ttl_secs: 7 * 24 * 3600,
                idle_secs: 8 * 3600,
                observer: None,
                error_observer: None,
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
                api_keys: None,
                #[cfg(feature = "passkeys")]
                passkeys: None,
                min_level: Level::Simple,
                sso_level: Level::Mfa,
                password_max_age_days: 0,
                sso_confirm: std::sync::OnceLock::new(),
            }),
        }
    }

    /// Wrap the login-form fragment into a full page — embed it in your app's shell so *you* style it
    /// (e.g. a Bootstrap page). The closure receives the `<form>…</form>` fragment (which carries
    /// Bootstrap-friendly classes) and the request's [`Parts`] — URI, headers, extensions — and returns
    /// the full HTML document. The request is there for chrome that depends on it, the same chrome the
    /// rest of your app renders: a theme or display-zone cookie, the active nav item.
    ///
    /// ```ignore
    /// .login_shell(|form, req| page(req, "Log in", form))
    /// ```
    pub fn login_shell(
        mut self,
        shell: impl Fn(&str, &Parts) -> String + Send + Sync + 'static,
    ) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().login_shell = Arc::new(shell);
        self
    }

    /// Wrap the profile/password fragment into a full page — as [`login_shell`](Auth::login_shell),
    /// but the closure also receives the signed-in [`Identity`] so the app can render its chrome (e.g.
    /// the username in the navbar) around the fragment. It wraps every page under the profile path:
    /// `/profile`, `/profile/totp`, the recovery codes and a manager's `/profile/{id}`.
    ///
    /// ```ignore
    /// .profile_shell(|frag, who, req| page(req, Some(who), "Profile", frag))
    /// ```
    pub fn profile_shell(
        mut self,
        shell: impl Fn(&str, &Identity, &Parts) -> String + Send + Sync + 'static,
    ) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().profile_shell = Arc::new(shell);
        self
    }

    /// The app's own **cards** on the caller's own profile page (preferences, a webhook secret; API
    /// keys and passkeys are built in). The profile is a grid of cards; the hook returns the app's,
    /// drawn with [`profile_card`] so they match, and they follow the library's. It gets a
    /// [`ProfileSection`]: the caller, the CSRF token their forms must carry, the request's headers,
    /// and the confirm-it's-you inputs for a sensitive form.
    ///
    /// ```ignore
    /// let auth = Auth::new(db, lockout).profile_extra(|s: ProfileSection| async move {
    ///     let form = format!(r#"<form method="post" action="/webhook-secret/rotate">{}{}
    ///         <button class="btn btn-sm btn-outline-danger">Rotate the secret</button></form>"#,
    ///         relativelylight::csrf::Csrf::hidden_input(&s.csrf), s.reauth_fields);
    ///     auth::profile_card("Webhooks", &form)
    /// });
    /// ```
    ///
    /// Not shown to a restricted session (§5m), nor on a manager's `/profile/{id}`. Check a sensitive
    /// action's *handler* with [`reauthenticate_with`](Auth::reauthenticate_with).
    pub fn profile_extra<F, Fut>(mut self, hook: F) -> Self
    where
        F: Fn(ProfileSection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = String> + Send + 'static,
    {
        let h: ProfileExtra = Arc::new(move |s: ProfileSection| Box::pin(hook(s)));
        Arc::get_mut(&mut self.inner).unwrap().profile_extra = Some(h);
        self
    }

    /// The **minimum assurance level** a session must have (§5m), default [`Level::Simple`] (any
    /// sign-in). A session below it is **restricted**: [`identify`](Auth::identify) treats it as
    /// anonymous, and its only page is the caller's own profile, which says which factor to add.
    /// Adding it steps the session up.
    ///
    /// ```ignore
    /// .min_level(Level::Mfa)   // a password alone is not enough: TOTP, a passkey, or SSO
    /// ```
    ///
    /// [`Level::Attested`] needs passkeys requiring
    /// [`Class::Attested`](passkey::Class::Attested); [`routes`](Auth::routes) panics otherwise.
    pub fn min_level(mut self, level: Level) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().min_level = level;
        self
    }

    /// The level an **SSO** sign-in counts as (§5m), default [`Level::Mfa`]: the identity provider is
    /// trusted to have asked for its own second factor. Set [`Level::Simple`] to distrust it — with a
    /// [`min_level`](Auth::min_level) of `Mfa`, an SSO account then enrols this site's TOTP, and the
    /// TOTP step follows the provider's callback.
    pub fn sso_level(mut self, level: Level) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().sso_level = level;
        self
    }

    /// The password's maximum age in days (§5m), default `0`: none. NIST SP 800-63B advises against
    /// periodic rotation; set it only where you are required to rotate. A password older than this
    /// is a change due: the login lands on the profile, which says so, and the user can go on.
    pub fn password_max_age_days(mut self, days: u32) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().password_max_age_days = days;
        self
    }

    /// Register an audit sink fired from the mutating auth handlers (password change, manager reset)
    /// — see [`crate::observe`]. Share one `Arc` with `Crud::on_write` to capture both surfaces.
    pub fn on_write(mut self, observer: Arc<dyn crate::observe::WriteObserver>) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().observer = Some(observer);
        self
    }

    /// Register a sink for errors the login keeps from the visitor — see
    /// [`crate::observe::ErrorEvent`]. A database failure during sign-in still answers `401 Invalid
    /// username or password` (an outage is nobody's business at the login form), so without this the
    /// cause is lost.
    pub fn on_error(mut self, observer: Arc<dyn crate::observe::ErrorObserver>) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().error_observer = Some(observer);
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

    /// Issue the session and CSRF cookies `SameSite=Lax` instead of `Strict` (default `false`).
    ///
    /// Under `Strict`, a user who follows a link to the app from another site (a mail, a chat, a
    /// ticket) arrives without their session and sees the login page. `Lax` sends the cookie on
    /// such a top-level `GET` — never on a cross-site `POST`, and every write still needs the CSRF
    /// token. The cost: a link elsewhere to `/logout` signs the user out. `SameSite=None` is not
    /// offered. See `docs/AUTH.md` §3.
    pub fn same_site_lax(mut self, on: bool) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().same_site_lax = on;
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
    /// (≥ 12 characters, common values, patterns, the username):
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
    /// It governs **typed input only**: `create_user` / `set_password` / `make_admin` /
    /// `reset_admin_access` are unaffected. Wire the same policy into an admin form separately
    /// (`validate::password`, as `examples/adminpanel` does), or that form is the way around it.
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
    /// the user, don't set cookies, and keep the status a `403`. The closure gets the request's
    /// [`Parts`] for display preferences (a theme or zone cookie), not for working out who is asking.
    ///
    /// ```ignore
    /// .csrf_rejection(|req| (StatusCode::FORBIDDEN, Html(my_shell(req, "Security check failed", BODY))).into_response())
    /// ```
    pub fn csrf_rejection<F>(mut self, render: F) -> Self
    where
        F: Fn(&Parts) -> Response + Send + Sync + 'static,
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
    /// [`RealIp`], which is the same value this module's own login routes
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

    /// Whether [`reauthenticate_with`](Auth::reauthenticate_with) challenges this account: it has a local
    /// password, 2FA or a passkey, or it is an SSO account, which confirms at its provider (§5h). `false`
    /// only for a local account with no factor at all, which passes — what to key a "you'll be asked to
    /// confirm" hint off in your own UI.
    pub async fn can_reauthenticate(&self, who: &Identity) -> bool {
        match target_user(&self.inner, &who.id).await {
            Some(u) => {
                !u.password_hash.is_empty()
                    || u.is_sso()
                    || u.has_totp()
                    || passkey::count(&self.inner.db, u.id).await > 0
            }
            None => false,
        }
    }

    /// Answer a `POST` from the app's own profile card ([`profile_extra`](Auth::profile_extra)) the way
    /// the library answers its own cards: the caller's profile page, with `result` as the one message
    /// at the top (`Ok` a success, `Err` an error; plain text, escaped). `status` is the response's,
    /// e.g. `403` when re-authentication failed. A caller who isn't signed in is sent to the login page.
    ///
    /// ```ignore
    /// async fn rotate(State(app): State<App>, req: Parts, Form(f): Form<RotateForm>) -> Response {
    ///     let Some(who) = app.auth.identify(&req.headers).await else { return Redirect::to("/login").into_response() };
    ///     if let Err(msg) = app.auth.reauthenticate_with(&who, &f.reauth).await {
    ///         return app.auth.profile_reply(&req, StatusCode::FORBIDDEN, Err(&msg)).await;
    ///     }
    ///     // … rotate …
    ///     app.auth.profile_reply(&req, StatusCode::OK, Ok("Webhook secret rotated.")).await
    /// }
    /// ```
    pub async fn profile_reply(&self, req: &Parts, status: StatusCode, result: Result<&str, &str>) -> Response {
        let inner = &self.inner;
        let Some((who, user)) = signed_in(inner, &req.headers).await else {
            return Redirect::to(&inner.login_path).into_response();
        };
        let csrf = inner.csrf().token(&req.headers).unwrap_or_default();
        profile_reply(inner, (&who, &user, &csrf, req), status, result).await
    }

    /// **Re-authenticate** the caller before something sensitive, with whatever factor their form
    /// submitted: the password, a TOTP code, or a passkey, read as a [`ReauthInput`] flattened into the
    /// form. Render the inputs with [`reauth_fields`](Auth::reauth_fields) inside that form. `Ok(())` if
    /// the factor proves the account holder is present; `Err(message)` is fit to render back.
    ///
    /// A live session isn't evidence its owner is present. This module asks for a factor again before
    /// its own sensitive changes; use this for yours (deleting an account, rotating a secret):
    ///
    /// ```ignore
    /// #[derive(Deserialize)]
    /// struct DeleteForm { #[serde(flatten)] reauth: ReauthInput, #[serde(rename = "_csrf")] csrf: String }
    ///
    /// let Some(who) = auth.identify(&headers).await else { return redirect_to_login() };
    /// if let Err(msg) = auth.reauthenticate_with(&who, &form.reauth).await {
    ///     return (StatusCode::FORBIDDEN, render_form_with_error(&msg));   // nothing has happened yet
    /// }
    /// delete_everything(&who).await;
    /// ```
    ///
    /// Without a form (a CLI, a test), build the input: `ReauthInput::password_or_code(pw, code)`.
    ///
    /// A TOTP code or passkey challenge accepted here is **spent** (§5a). An **SSO account** confirms at its
    /// provider before submitting: the confirm-it's-you block links there and back, and the one-use
    /// confirmation it leaves on the session is spent here (AUTH.md §5h). A local account with no
    /// factor at all passes, having nothing to ask for. Not lockout-limited — the caller is
    /// authenticated, and counting would let a stolen session lock the real user out (§5e).
    pub async fn reauthenticate_with(&self, who: &Identity, proof: &ReauthInput) -> Result<(), String> {
        let Some(user) = target_user(&self.inner, &who.id).await else {
            return Err("Your session is no longer valid — sign in again.".into());
        };
        self.inner.reauth(&user, who, proof).await
    }

    /// The confirm-it's-you inputs for one of **your** forms, as an HTML fragment: a password field, a
    /// code field when the account has 2FA, and a "Confirm with your passkey" button when it has a
    /// passkey (with a fresh challenge, and the script that runs it). Only the factors the account has
    /// are offered; `hint` is the sentence above them. Put it inside the `<form>` whose handler calls
    /// [`reauthenticate_with`](Auth::reauthenticate_with). For an SSO account it is a link to confirm at
    /// the provider, which returns to this page (by its `Referer`), or the word that the session holds a
    /// confirmation. Empty for an account with no factor at all.
    pub async fn reauth_fields(&self, who: &Identity, hint: &str) -> String {
        let reauth = match target_user(&self.inner, &who.id).await {
            Some(user) => self.inner.reauth_view(&user, who).await,
            None => ReauthView::none(),
        };
        reauth_fields_html(&reauth, hint)
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
    /// idle-expired rows go too — expired lockout rows and expired WebAuthn challenges. Returns the total deleted.
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
        let challenges = passkey::prune_challenges(&self.inner.db).await?;
        Ok(sessions + usernames + ips + challenges)
    }

    /// The auth pages, to merge into your router:
    /// - `GET/POST /login` and `GET/POST /login/totp` — password, then the TOTP second factor when the
    ///   user has 2FA enabled.
    /// - `GET /logout`.
    /// - `GET/POST /profile` — change your own password + manage your own 2FA.
    /// - `GET/POST /profile/totp` + `POST /profile/totp/disable` — enrol in / disable your own 2FA.
    /// - `POST /profile/totp/recovery` — replace your recovery codes (§5i).
    /// - `POST /profile/sessions/revoke` — sign out your *other* sessions.
    /// - `POST /profile/api-keys` + `POST /profile/api-keys/{id}/revoke` — mint and revoke your own API
    ///   keys, only when [`api_keys`](Auth::api_keys) is on (§5k).
    /// - `GET/POST /profile/{id}` — a manager resets another user's password.
    /// - `POST /profile/{id}/totp/disable` — a manager disables another user's 2FA.
    /// - `POST /profile/{id}/passkeys/remove` — a manager removes another user's passkeys.
    ///
    /// These paths are the module's, so don't also route them yourself — axum panics on an overlap at
    /// merge time. Change where they live with [`login_path`](Auth::login_path)'s and
    /// [`profile_path`](Auth::profile_path)'s configuration, or nest the whole thing under a prefix.
    pub fn routes(&self) -> Router {
        assert!(
            self.inner.min_level < Level::Attested || self.inner.attested_only(),
            "relativelylight: Auth::min_level(Level::Attested) needs passkeys requiring Class::Attested"
        );
        let mut router = Router::new();
        #[cfg(feature = "passkeys")]
        if self.inner.passkeys.is_some() {
            router = webauthn::routes(router);
        }
        if self.inner.api_keys.is_some() {
            router = router
                .route("/profile/api-keys", post(api_key::mint_submit))
                .route("/profile/api-keys/{id}/revoke", post(api_key::revoke_submit));
        }
        router
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
            .route("/profile/{id}/passkeys/remove", post(passkeys_manage_remove))
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
        identity_of(&self.inner, headers).await
    }
}

// ===================== Internals =====================

/// How stale `last_seen_at` must be before a read bothers to refresh it. Identity is resolved once per
/// gated model, so a page rendering five tables resolves it five times; without this grace every one of
/// those reads would become a write.
const IDLE_REFRESH_GRACE: i64 = 60;

async fn identity_from(inner: &Inner, token: &str) -> Option<Identity> {
    let (who, _, restricted) = resolve(inner, token).await?;
    (!restricted).then_some(who)
}

/// A live session's caller: their identity, their row, and whether the session is **restricted**
/// (below [`Auth::min_level`]) — usable only on the caller's own profile, to add the factor it lacks.
async fn resolve(inner: &Inner, token: &str) -> Option<(Identity, user::Model, bool)> {
    let session = session::Entity::find_by_id(token.to_string()).one(&inner.db).await.ok()??;
    if !inner.session_live(&session) || session.awaiting_totp {
        return None; // expired (either clock), or the TOTP second factor is still pending
    }
    // A session a passkey opened counts only while the policy still accepts that passkey's class, so a
    // stricter policy applies to sessions already open, not just to the next sign-in.
    #[cfg(feature = "passkeys")]
    if let (Some(rt), Some(class)) = (&inner.passkeys, session.passkey_class()) {
        if class < rt.require() {
            return None;
        }
    }
    let user = user::Entity::find_by_id(session.user_id).one(&inner.db).await.ok()??;
    if !user.is_active {
        return None;
    }
    let groups = groups_of(&inner.db, user.id).await;
    // The session was used: push the idle clock forward, but only once the last stamp has gone stale.
    inner.touch_session(&session).await;
    let level = inner.level_of(session.method(), session.passkey_class());
    let who = Identity {
        id: user.id.to_string(),
        username: user.username.clone(),
        groups,
        level,
        password_change: user.password_change(inner.password_max_age_days, now_secs()),
        session: Some(SessionRef(token.to_string())),
    };
    Some((who, user, level < inner.min_level))
}

/// Verify username + password. Returns the user on success (regardless of 2FA) — the caller decides
/// whether a second factor is still required (`user.has_totp()`). SSO accounts
/// (`sso_provider` set) never authenticate by password. `Err` is a failed lookup, not a wrong
/// password: the caller reports it and must not count it against the account.
async fn verify_credentials(
    inner: &Inner,
    username: &str,
    password: &str,
) -> Result<Option<user::Model>, DbErr> {
    let Some(user) =
        user::Entity::find().filter(user::Column::Username.eq(username)).one(&inner.db).await?
    else {
        return Ok(None);
    };
    Ok((user.is_active && !user.is_sso() && verify_password(&user.password_hash, password))
        .then_some(user))
}

/// Create a session row and return its token. `awaiting_totp` marks it half-authenticated (password
/// ok, TOTP pending) — [`identity_from`] rejects such sessions until the code is confirmed. `method`
/// records how it was authenticated so far.
async fn create_session(
    inner: &Inner,
    user_id: i32,
    awaiting_totp: bool,
    method: session::Method,
) -> Result<String, DbErr> {
    create_session_class(inner, user_id, awaiting_totp, method, None).await
}

/// [`create_session`], recording the class of the passkey that authenticated it.
async fn create_session_class(
    inner: &Inner,
    user_id: i32,
    awaiting_totp: bool,
    method: session::Method,
    class: Option<passkey::Class>,
) -> Result<String, DbErr> {
    let token = new_token();
    let now = now_secs();
    session::ActiveModel {
        id: Set(token.clone()),
        user_id: Set(user_id),
        expires_at: Set(now + inner.ttl_secs),
        last_seen_at: Set(now),
        awaiting_totp: Set(awaiting_totp),
        method: Set(method.as_str().to_string()),
        passkey_class: Set(class.map(|c| c.as_str().to_string())),
        reauth_until: Set(None),
    }
    .insert(&inner.db)
    .await?;
    Ok(token)
}

/// Give a user exactly **one** live session, freshly minted: everything else they hold is deleted.
/// Returns the new token, to be written into the caller's cookie.
///
/// This is what a password change should do, and today's most useful reason to change a password is
/// "someone else is in my account". Rotating only the caller's own id would leave the intruder's
/// session untouched; deleting every session including the caller's own would sign them out of the page
/// they are reading. So: mint one, drop the rest.
///
/// The new session keeps the method the caller's own session was authenticated with (`method`): a
/// password change proves the password again, not the second factor.
async fn resession(inner: &Inner, user_id: i32, method: session::Method) -> Option<String> {
    let token = create_session(inner, user_id, false, method).await.ok()?;
    inner.revoke_sessions(user_id, Some(&token)).await;
    Some(token)
}

/// Replace a session with a fresh id, carrying its user across and clearing `awaiting_totp` — the
/// **privilege-change rotation**. Returns the new token.
///
/// Rotating here is what stops a **planted half-authenticated cookie** from being elevated. Flipping
/// `awaiting_totp` on the *same* id would let an attacker who knows the password write a pending
/// session's cookie into the victim's browser (cookie-tossing from a sibling host, or an XSS: neither
/// `Secure` nor `SameSite` prevents that), point them at `/login/totp`, and inherit the full session
/// when the victim types their code. A new id leaves the attacker holding a deleted token.
///
/// `method` is how the session is authenticated now that the second factor is in, and `class` the
/// class of the passkey involved, if any.
async fn rotate_session(
    inner: &Inner,
    old: session::Model,
    method: session::Method,
    class: Option<passkey::Class>,
) -> Option<String> {
    let token = create_session_class(inner, old.user_id, false, method, class).await.ok()?;
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

async fn login_form(State(inner): State<Arc<Inner>>, req: Parts, jar: CookieJar) -> Response {
    let headers = &req.headers;
    // A restricted session is signed in, just not enough for the app: the app sends it here, and here
    // sends it to the one page it can use, which says what to add. Without this it would loop.
    if let Some(token) = jar.get(&inner.cookie_name).map(|c| c.value().to_string()) {
        if let Some((_, _, true)) = resolve(&inner, &token).await {
            return Redirect::to(&inner.profile_path).into_response();
        }
    }
    let (token, jar) = csrf_token(&inner, headers, jar);
    (jar, Html((inner.login_shell)(&login_form_html(None, &token, inner.passkeys_on()), &req))).into_response()
}

async fn login_submit(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp,
    jar: CookieJar,
    Form(form): Form<LoginForm>,
) -> Response {
    let headers = &req.headers;
    if !inner.csrf().verify(headers, form.csrf.as_deref()) {
        // Checked before anything else: a forged post does no DB work *and* can't spend the victim's
        // attempt budget (otherwise cross-site requests could lock a user out).
        return csrf_rejected(&inner, &req);
    }
    if let Some(retry) = inner.locked_out(&form.username, client_ip).await {
        // Locked: the password is never looked at, so this costs no argon2 and says nothing about
        // whether the account exists.
        let (token, jar) = csrf_token(&inner, headers, jar);
        return too_many_attempts(
            retry,
            jar,
            Html((inner.login_shell)(&login_form_html(Some(&lockout_message(retry)), &token, inner.passkeys_on()), &req)),
        );
    }
    let user = match verify_credentials(&inner, &form.username, &form.password).await {
        Ok(Some(user)) => Some(user),
        Ok(None) => {
            inner.record_failure(&form.username, client_ip).await;
            None
        }
        Err(e) => {
            // The visitor gets the ordinary rejection; the app gets the cause. Not counted: an outage
            // is no guess, and counting it would lock everyone out once the database is back.
            inner.report("auth-login", "credential lookup", &e, client_ip).await;
            None
        }
    };
    let Some(user) = user else {
        return login_rejected(&inner, &req, jar);
    };
    // A second step when the account has TOTP, or a passkey and passkeys are a second factor here.
    let needs_totp = user.has_totp() || inner.second_factor_ask_possible(&user).await;
    let token = match create_session(&inner, user.id, needs_totp, session::Method::Password).await {
        Ok(token) => token,
        Err(e) => {
            inner.report("auth-login", "session create", &e, client_ip).await;
            return login_rejected(&inner, &req, jar);
        }
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
        complete_login(&inner, &user, session::Method::Password, None, headers, client_ip).await;
        inner.landing(&user, session::Method::Password, None)
    };
    (jar, Redirect::to(dest)).into_response()
}

/// The one answer to a failed sign-in, whatever failed: `401` and the generic message.
fn login_rejected(inner: &Inner, req: &Parts, jar: CookieJar) -> Response {
    let (token, jar) = csrf_token(inner, &req.headers, jar);
    (
        StatusCode::UNAUTHORIZED,
        jar,
        Html((inner.login_shell)(&login_form_html(Some("Invalid username or password."), &token, inner.passkeys_on()), req)),
    )
        .into_response()
}

/// `GET /login/totp` — the second-factor form, reached after a correct password when 2FA is on. Reads
/// the pending session; if there isn't one, sends the visitor back to /login.
async fn login_totp_form(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    jar: CookieJar,
) -> Response {
    let headers = &req.headers;
    match pending_totp_user(&inner, headers).await {
        Some((session, user)) => {
            let (token, jar) = csrf_token(&inner, headers, jar);
            (jar, second_step_page(&inner, &session, &user, None, &token, &req).await).into_response()
        }
        None => Redirect::to(&inner.login_path).into_response(),
    }
}

/// The second-step page (`/login/totp`) for a pending session: the TOTP code (with recovery codes) when
/// the account has TOTP, and its passkey when passkeys are a second factor here and the first step was
/// the password. After a passkey sign-in only TOTP is offered: a passkey can't be its own second factor.
async fn second_step_page(
    inner: &Inner,
    session: &session::Model,
    user: &user::Model,
    error: Option<&str>,
    csrf: &str,
    req: &Parts,
) -> Html<String> {
    let after_password = session.method() == Some(session::Method::Password);
    let passkey = match after_password {
        true => inner.second_factor_ask(user).await,
        false => None,
    };
    Html((inner.login_shell)(&totp_login_html(error, csrf, user.has_totp(), passkey.as_ref()), req))
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
    /// Re-authentication for `/profile/totp` (§5h); unused at `/login/totp`, where the first factor was
    /// just checked. Its `totp_code` is a code from the account's *currently active* secret — only
    /// meaningful when re-enrolling over an existing 2FA setup; a first enrolment has no active
    /// secret, so another factor confirms it.
    #[serde(flatten)]
    reauth: ReauthInput,
    /// A single-use **recovery code** (§5i), accepted at `/login/totp` in place of `code` when the
    /// authenticator is gone. Unused at `/profile/totp`.
    #[serde(default)]
    recovery_code: String,
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

/// The body of a post that carries nothing but the CSRF token: signing out other sessions, revoking an
/// API key, removing a passkey.
#[derive(serde::Deserialize)]
struct CsrfOnlyForm {
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

/// `POST /login/totp` — verify the code against the pending session's user; on success clear
/// `awaiting_totp` (the session becomes a real login) and land on `/`.
async fn login_totp_submit(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp,
    jar: CookieJar,
    Form(form): Form<TotpForm>,
) -> Response {
    let headers = &req.headers;
    if !inner.csrf().verify(headers, form.csrf.as_deref()) {
        return csrf_rejected(&inner, &req);
    }
    let Some((session, user)) = pending_totp_user(&inner, headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    // The second factor shares the account's login bucket: password guessing and code guessing are the
    // same account being attacked, and 6 digits deserve the tighter of the two brakes.
    if let Some(retry) = inner.locked_out(&user.username, client_ip).await {
        let (token, jar) = csrf_token(&inner, headers, jar);
        return too_many_attempts(
            retry,
            jar,
            second_step_page(&inner, &session, &user, Some(&lockout_message(retry)), &token, &req).await,
        );
    }
    // An empty submission presents **no credential**, so it is not a failed check and must not spend the
    // account's budget — §5e's rule, and without it an empty form (a stray double-submit, or a forged
    // cross-site post that happens to carry a token) would grief the real user's login.
    if form.code.trim().is_empty() && recovery::normalize(&form.recovery_code).is_empty() {
        let (token, jar) = csrf_token(&inner, headers, jar);
        return (
            StatusCode::UNAUTHORIZED,
            jar,
            second_step_page(
                &inner,
                &session,
                &user,
                Some("Enter the code from your authenticator app, or a recovery code."),
                &token,
                &req,
            )
            .await,
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
        let (token, jar) = csrf_token(&inner, headers, jar);
        return (
            StatusCode::UNAUTHORIZED,
            jar,
            second_step_page(&inner, &session, &user, Some("Invalid code. Try again."), &token, &req).await,
        )
            .into_response();
    }
    // The second factor is confirmed, so the session gains full privilege — which means a **new id**
    // (see `rotate_session`), a new CSRF token, and the spent step recorded so this code can't be used
    // again inside its ±1-step window.
    // The first step decides the name: a password, a passkey (whose class carries over) or SSO.
    use session::Method as M;
    let method = match (session.method(), used_recovery) {
        (Some(M::Passkey), true) => M::PasskeyRecovery,
        (Some(M::Passkey), false) => M::PasskeyTotp,
        (Some(M::Sso), true) => M::SsoRecovery,
        (Some(M::Sso), false) => M::SsoTotp,
        (_, true) => M::PasswordRecovery,
        (_, false) => M::PasswordTotp,
    };
    let class = session.passkey_class();
    let Some(token) = rotate_session(&inner, session.clone(), method, class).await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response();
    };
    complete_login(&inner, &user, method, step, headers, client_ip).await;
    inner.usernames.clear(&user.username).await;
    let (_, csrf_cookie) = inner.csrf().issue();
    let jar = jar.add(session_cookie(&inner, token)).add(csrf_cookie);
    if used_recovery {
        // Land on the profile rather than `/`: they got in without their authenticator, so the next
        // thing they need is either a re-enrolment or a fresh set of codes, and both live there.
        return (jar, Redirect::to(&inner.profile_path)).into_response();
    }
    (jar, Redirect::to(inner.landing(&user, method, class))).into_response()
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
    /// `current_password` for an account that has one; any other factor for one that doesn't, which
    /// is setting a password rather than changing it.
    #[serde(flatten)]
    reauth: ReauthInput,
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
    #[serde(flatten)]
    reauth: ReauthInput,
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

/// A post whose only payload is the caller's re-authentication (§5h): the "disable 2FA" buttons.
#[derive(serde::Deserialize)]
struct ReauthForm {
    #[serde(flatten)]
    reauth: ReauthInput,
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

/// The session row the request's cookie names, live or not — for reading what it records.
async fn current_session(inner: &Inner, headers: &HeaderMap) -> Option<session::Model> {
    let token = CookieJar::from_headers(headers).get(&inner.cookie_name)?.value().to_string();
    session::Entity::find_by_id(token).one(&inner.db).await.ok()?
}

/// Resolve the caller from the request cookie ([`Auth::identify`] is this, for the app).
async fn identity_of(inner: &Inner, headers: &HeaderMap) -> Option<Identity> {
    let jar = CookieJar::from_headers(headers);
    let token = jar.get(&inner.cookie_name)?.value().to_string();
    identity_from(inner, &token).await
}

/// What every self-service POST starts with: the CSRF check, then the signed-in caller, their row and
/// the token to render back. `Err` is the response to send instead — the rejection page, or the
/// redirect to the login page.
#[allow(clippy::result_large_err)] // the `Err` is the handler's response, returned straight away
async fn self_post(
    inner: &Inner,
    req: &Parts,
    form_csrf: Option<&str>,
) -> std::result::Result<(Identity, user::Model, String), Response> {
    let headers = &req.headers;
    if !inner.csrf().verify(headers, form_csrf) {
        return Err(csrf_rejected(inner, req));
    }
    let csrf = inner.csrf().token(headers).unwrap_or_default();
    let (who, user) =
        signed_in(inner, headers).await.ok_or_else(|| Redirect::to(&inner.login_path).into_response())?;
    Ok((who, user, csrf))
}

/// What every manager `POST` (`/profile/{id}…`) starts with, as [`self_post`] for the caller's own
/// page: the CSRF check, then [`managed_target`], then the manager's own row (whose factor
/// re-authenticates the change), and the CSRF token to render back.
#[allow(clippy::result_large_err)] // the `Err` is the handler's response, returned straight away
async fn manager_post(
    inner: &Inner,
    req: &Parts,
    form_csrf: Option<&str>,
    id: &str,
) -> std::result::Result<(Identity, user::Model, user::Model, String), Response> {
    if !inner.csrf().verify(&req.headers, form_csrf) {
        return Err(csrf_rejected(inner, req));
    }
    let csrf = inner.csrf().token(&req.headers).unwrap_or_default();
    let (who, target) = managed_target(inner, &req.headers, id).await?;
    let manager =
        target_user(inner, &who.id).await.ok_or_else(|| Redirect::to(&inner.login_path).into_response())?;
    Ok((who, manager, target, csrf))
}

/// What every manager route (`/profile/{id}…`) starts with: the caller, who must be a manager acting on
/// *someone else*, and the target's row. `Err` is the response to send instead: the login page, the
/// caller's own profile (their own id), `403` or `404`.
#[allow(clippy::result_large_err)] // the `Err` is the handler's response, returned straight away
async fn managed_target(
    inner: &Inner,
    headers: &HeaderMap,
    id: &str,
) -> std::result::Result<(Identity, user::Model), Response> {
    let Some(who) = identity_of(inner, headers).await else {
        return Err(Redirect::to(&inner.login_path).into_response());
    };
    if who.id == id {
        return Err(Redirect::to(&inner.profile_path).into_response());
    }
    if !inner.can_manage_others(&who) {
        return Err((StatusCode::FORBIDDEN, "Forbidden").into_response());
    }
    match target_user(inner, id).await {
        Some(target) => Ok((who, target)),
        None => Err((StatusCode::NOT_FOUND, "No such user").into_response()),
    }
}

/// `GET /profile` — the self-service change-password form + 2FA status (anonymous → login). For an
/// SSO account it's a read-only notice: password + 2FA are managed by the identity provider.
async fn profile_form(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    jar: CookieJar,
) -> Response {
    let headers = &req.headers;
    let Some((who, user)) = signed_in(&inner, headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    let (token, jar) = csrf_token(&inner, headers, jar);
    let frag = profile_fragment(&inner, &who, &user, None, None, &token, headers).await;
    (jar, inner.page(&who, &frag, &req)).into_response()
}

/// `POST /profile` — verify the current password, then set the new one for the caller.
async fn profile_submit(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp, // for the audit record, not for limiting
    jar: CookieJar,
    Form(form): Form<ChangeForm>,
) -> Response {
    let headers = &req.headers;
    let (who, user, csrf) = match self_post(&inner, &req, form.csrf.as_deref()).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    if user.is_sso() {
        return Redirect::to(&inner.profile_path).into_response(); // SSO: password managed by the IdP
    }
    // Not lockout-limited: the caller is *authenticated*, so this isn't brute force from outside —
    // it's someone with a live session, which is a session-theft problem (short TTLs, re-auth before
    // sensitive changes — docs/TODO.md), not a guessing one. Counting it here would also let a stolen
    // session lock the real user out of logging in.
    //
    // An account with a password proves it with that password. One without (it signs in with a
    // passkey) is *setting* a password, which is a new way in, so it confirms with another factor.
    let has_password = !user.password_hash.is_empty();
    let proved = match has_password {
        true => match verify_password(&user.password_hash, &form.reauth.current_password) {
            true => Ok(()),
            false => Err("Current password is incorrect.".to_string()),
        },
        false => inner.reauth(&user, &who, &form.reauth).await,
    };
    let error: Option<String> = if let Err(msg) = proved {
        Some(msg)
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
        return profile_reply(&inner, (&who, &user, &csrf, &req), StatusCode::BAD_REQUEST, Err(&msg)).await;
    }

    if set_password(&inner.db, &who.username, &form.new_password).await.is_err() {
        let msg = "Could not change the password.";
        return profile_reply(&inner, (&who, &user, &csrf, &req), StatusCode::INTERNAL_SERVER_ERROR, Err(msg)).await;
    }
    // The password is changed, so every session it ever unlocked is void: mint one fresh session for
    // the caller and delete the rest. Without this, a password changed *because* someone else got in
    // leaves that someone else logged in — the cookie outlives the credential that produced it.
    // The rendered form must carry whichever token the response's cookie ends up holding, or the next
    // post fails its own double-submit check.
    let method = current_session(&inner, headers)
        .await
        .and_then(|s| s.method())
        .unwrap_or(session::Method::Password);
    let (msg, jar, csrf) = match resession(&inner, user.id, method).await {
        Some(token) => {
            let (csrf, csrf_cookie) = inner.csrf().issue(); // new session ⇒ new CSRF token
            let jar = jar.add(session_cookie(&inner, token)).add(csrf_cookie);
            ("Your password has been changed. Any other sessions have been signed out.", jar, csrf)
        }
        // The password *did* change, so don't claim otherwise; the caller's session simply wasn't
        // rotated. Their old cookie still works, which is no worse than before.
        None => ("Your password has been changed.", jar, csrf),
    };
    let event = serde_json::json!({ "password_changed": true, "sessions_revoked": true });
    inner.notify_own(&who, event, headers, client_ip).await;
    (jar, profile_page(&inner, &who, &user, None, Some(msg), &csrf, &req).await).into_response()
}

/// `GET /profile/{id}` — a manager's reset form for another user (self → own page; not a manager →
/// 403; unknown user → 404).
async fn manage_form(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    jar: CookieJar,
    Path(id): Path<String>,
) -> Response {
    let headers = &req.headers;
    let (who, target) = match managed_target(&inner, headers, &id).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    let (token, jar) = csrf_token(&inner, headers, jar);
    // An SSO account gets the page too, without the reset form (its password lives at the identity
    // provider, and the POST refuses it) but with its 2FA, which a manager can disable.
    let Some(manager) = target_user(&inner, &who.id).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    (jar, manager_page(&inner, &who, &manager, &target, None, None, &token, &req).await).into_response()
}

/// The manager's page about `target`, with an optional message. The confirm-it's-you blocks offer the
/// **manager's** factors — their own password, code or passkey, never the target's.
#[allow(clippy::too_many_arguments)]
async fn manager_page(
    inner: &Inner,
    who: &Identity,
    manager: &user::Model,
    target: &user::Model,
    error: Option<&str>,
    success: Option<&str>,
    csrf: &str,
    req: &Parts,
) -> Html<String> {
    let id = target.id.to_string();
    let t = Target {
        id: &id,
        sso: target.sso_key(),
        username: &target.username,
        totp_on: target.has_totp(),
        has_password: !target.password_hash.is_empty(),
        passkeys: passkey::count(&inner.db, target.id).await,
    };
    let reauth = inner.reauth_view(manager, who).await;
    inner.page(who, &reset_form_html(&t, &reauth, error, success, csrf), req)
}

/// `POST /profile/{id}` — a manager sets another user's password (no current password required).
async fn manage_submit(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp,
    Path(id): Path<String>,
    Form(form): Form<ResetForm>,
) -> Response {
    let (who, manager, target, csrf) = match manager_post(&inner, &req, form.csrf.as_deref(), &id).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    let headers = &req.headers;
    // The manager re-authenticates with their own factor (§5h): a reset is the most valuable thing a
    // stolen manager session can reach.
    // The reset form again, with a message, re-read so it shows the account as it now stands.
    let page = |error: Option<String>, success: Option<String>| {
        let (inner, who, manager, csrf, req) = (&inner, &who, &manager, &csrf, &req);
        let target_id = target.id;
        async move {
            let Ok(Some(target)) = user::Entity::find_by_id(target_id).one(&inner.db).await else {
                return Html(String::new());
            };
            manager_page(inner, who, manager, &target, error.as_deref(), success.as_deref(), csrf, req)
                .await
        }
    };
    if let Err(msg) = inner.reauth(&manager, &who, &form.reauth).await {
        return (StatusCode::FORBIDDEN, page(Some(msg), None).await).into_response();
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
        return (StatusCode::BAD_REQUEST, page(Some(msg), None).await).into_response();
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
        return (StatusCode::BAD_REQUEST, page(Some(msg), None).await).into_response();
    }
    // A password the manager chose is one the manager knows: the owner is asked to choose their own.
    if set_password_hash(&inner.db, target.clone(), &form.new_password, true).await.is_err() {
        let msg = "Could not set the password.".to_string();
        return (StatusCode::INTERNAL_SERVER_ERROR, page(Some(msg), None).await).into_response();
    }
    // A manager resets a password for one of two reasons — the user is locked out, or the account is
    // suspected compromised. The second reason makes signing the target out everywhere mandatory: none
    // of *their* sessions belongs to the credential that exists now. Unlike the self-service path there
    // is no session to spare, so all of them go.
    let revoked = inner.revoke_sessions(target.id, None).await;
    inner
        .notify(
            "auth-admin",
            &who.username,
            "auth_user",
            Some(id.clone()),
            serde_json::json!({
                "password_reset_by_manager": true,
                "by": who.username,
                "sessions_revoked": revoked,
            }),
            headers,
            client_ip,
        )
        .await;
    let msg = match revoked {
        0 => format!("Password reset for {}.", target.username),
        1 => format!("Password reset for {} and 1 session signed out.", target.username),
        n => format!("Password reset for {} and {n} sessions signed out.", target.username),
    };
    page(None, Some(msg)).await.into_response()
}

// ---- TOTP 2FA (setup / verify / disable) ----

/// `GET /profile/totp` — begin enrolment: mint a fresh pending secret, store it on the user, and show
/// the QR + `otpauth://` URL with a verify form. A new secret is generated on each visit.
async fn totp_setup_form(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    jar: CookieJar,
) -> Response {
    let headers = &req.headers;
    let Some((who, user)) = signed_in(&inner, headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    // An SSO account may enrol TOTP too: a site that distrusts its IdP's second factor
    // (`Auth::sso_level`) asks for its own.
    let secret = totp::generate_secret();
    let mut am: user::ActiveModel = user.into();
    am.totp_pending = Set(Some(secret.clone()));
    // The updated row decides which factors the confirm block can offer: a re-enrolment can be confirmed
    // with a code from the outgoing authenticator, a first enrolment can't.
    let Ok(user) = am.update(&inner.db).await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not start 2FA setup").into_response();
    };
    let (token, jar) = csrf_token(&inner, headers, jar);
    (jar, render_totp_setup(&inner, &who, &user, &secret, None, &token, &req).await).into_response()
}

/// `POST /profile/totp` — confirm enrolment: verify the code against the pending secret, then promote
/// it to the active secret (2FA now required at login). On a bad code, re-show the *same* QR.
async fn totp_setup_submit(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp, // for the audit record
    jar: CookieJar,
    Form(form): Form<TotpForm>,
) -> Response {
    let (who, user, csrf) = match self_post(&inner, &req, form.csrf.as_deref()).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    let Some(pending) = user.pending_totp_key().map(str::to_string) else {
        return Redirect::to(&inner.profile_path).into_response(); // nothing in progress
    };
    // Re-authenticated (§5h): an intruder's own authenticator would lock the real user out. A first
    // enrolment has no active secret to check a code against, so its factor is the password or a passkey.
    if let Err(msg) = inner.reauth(&user, &who, &form.reauth).await {
        return render_totp_setup(&inner, &who, &user, &pending, Some(&msg), &csrf, &req).await;
    }
    // Not lockout-limited: enrolling is authenticated, and the code being guessed is the caller's own
    // pending secret — there is nobody else's account to reach by guessing it.
    let Some(step) = totp::verify_step(&pending, &form.code) else {
        let msg = Some("That code didn't match. Try again.");
        return render_totp_setup(&inner, &who, &user, &pending, msg, &csrf, &req).await;
    };
    let mut am: user::ActiveModel = user.into();
    am.totp_secret = Set(Some(pending));
    am.totp_pending = Set(None);
    // The confirming code is spent too — otherwise the code just typed here would still work at
    // /login/totp for the rest of its window, which is the same replay by a different door.
    am.totp_last_step = Set(Some(step));
    let Ok(user) = am.update(&inner.db).await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not enable 2FA").into_response();
    };
    inner.notify_own(&who, serde_json::json!({ "totp_enabled": true }), &req.headers, client_ip).await;
    // Issue recovery codes **with** the enrolment and show them once (§5i). Issuing them here rather
    // than leaving it to the user is the difference between a lost phone being an inconvenience and
    // being an account only an administrator can reopen.
    // This session has just proved the second factor too: it steps up (§5m), so a restricted session
    // becomes a usable one without signing in again.
    let (jar, csrf) = step_up(&inner, &req.headers, jar, csrf, Factor::Totp).await;
    let who = refreshed(&inner, &req, &jar, who).await;
    match recovery::issue(&inner.db, user.id).await {
        Ok(codes) => {
            let frag = recovery_codes_html(
                &codes,
                "Two-factor authentication is now enabled. Save these recovery codes.",
            );
            (jar, inner.page(&who, &frag, &req)).into_response()
        }
        // 2FA *is* on, so don't imply otherwise; they can generate codes from the profile page.
        Err(_) => {
            let msg = "Two-factor authentication is on, but recovery codes could not be created — generate them below.";
            (jar, profile_page(&inner, &who, &user, Some(msg), None, &csrf, &req).await).into_response()
        }
    }
}

/// The factor a session just enrolled, for [`step_up`].
#[cfg_attr(not(feature = "passkeys"), allow(dead_code))]
enum Factor {
    Totp,
    Passkey(passkey::Class),
}

/// After the caller enrolled `factor` in this very session (and proved it doing so), rotate the session
/// to the stronger method it now stands for: a password session that added TOTP is a password + TOTP
/// session. Returns the jar carrying the new cookies and the CSRF token the response's forms must
/// carry. A session already as strong, or with no row, is left as it is.
async fn step_up(
    inner: &Inner,
    headers: &HeaderMap,
    jar: CookieJar,
    csrf: String,
    factor: Factor,
) -> (CookieJar, String) {
    use session::Method as M;
    let Some(current) = current_session(inner, headers).await else { return (jar, csrf) };
    let (method, class) = match (current.method(), &factor) {
        (Some(M::Password), Factor::Totp) => (M::PasswordTotp, None),
        (Some(M::Password), Factor::Passkey(c)) => (M::PasswordPasskey, Some(*c)),
        (Some(M::Sso), Factor::Totp) => (M::SsoTotp, None),
        (Some(M::Passkey), Factor::Totp) => (M::PasskeyTotp, current.passkey_class()),
        _ => return (jar, csrf),
    };
    match rotate_session(inner, current, method, class).await {
        Some(token) => {
            let (csrf, csrf_cookie) = inner.csrf().issue();
            (jar.add(session_cookie(inner, token)).add(csrf_cookie), csrf)
        }
        None => (jar, csrf),
    }
}

/// The caller as the session `jar` now holds sees them — after a [`step_up`], the stronger session.
async fn refreshed(inner: &Inner, req: &Parts, jar: &CookieJar, who: Identity) -> Identity {
    match signed_in(inner, &req.headers_with_session(jar, &inner.cookie_name)).await {
        Some((w, _)) => w,
        None => who,
    }
}

/// Headers as the next request will send them: these, with the session cookie `jar` now holds — so a
/// handler that just rotated the session can render for the new one.
trait WithSession {
    fn headers_with_session(&self, jar: &CookieJar, name: &str) -> HeaderMap;
}

impl WithSession for Parts {
    fn headers_with_session(&self, jar: &CookieJar, name: &str) -> HeaderMap {
        let mut h = self.headers.clone();
        if let Some(c) = jar.get(name) {
            if let Ok(v) = format!("{name}={}", c.value()).parse() {
                h.insert(axum::http::header::COOKIE, v);
            }
        }
        h
    }
}

/// `POST /profile/totp/recovery` — replace the caller's recovery codes and show the new set once.
/// **Re-authenticated** (§5h): a fresh set is a fresh way into the account, so an intruder holding a
/// session must not be able to mint one, and the codes it invalidates are the real user's.
async fn recovery_regenerate(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp,
    Form(form): Form<ReauthForm>,
) -> Response {
    let headers = &req.headers;
    let (who, user, csrf) = match self_post(&inner, &req, form.csrf.as_deref()).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    if !user.has_totp() {
        // Codes exist to recover a second factor; without one there is nothing to recover.
        return Redirect::to(&inner.profile_path).into_response();
    }
    if let Err(msg) = inner.reauth(&user, &who, &form.reauth).await {
        return profile_reply(&inner, (&who, &user, &csrf, &req), StatusCode::FORBIDDEN, Err(&msg)).await;
    }
    match recovery::issue(&inner.db, user.id).await {
        Ok(codes) => {
            let event = serde_json::json!({ "recovery_codes_reissued": codes.len() });
            inner.notify_own(&who, event, headers, client_ip).await;
            let frag = recovery_codes_html(
                &codes,
                "Here is your new set. The previous codes no longer work.",
            );
            inner.page(&who, &frag, &req).into_response()
        }
        Err(_) => {
            let msg = "Could not generate new recovery codes.";
            let page = profile_page(&inner, &who, &user, Some(msg), None, &csrf, &req).await;
            (StatusCode::INTERNAL_SERVER_ERROR, page).into_response()
        }
    }
}

/// `POST /profile/sessions/revoke` — the caller signs out every session **except this one**.
async fn sessions_revoke(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp,
    Form(form): Form<CsrfOnlyForm>,
) -> Response {
    let headers = &req.headers;
    let (who, user, csrf) = match self_post(&inner, &req, form.csrf.as_deref()).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    // Spare the caller's own session — identified by the cookie they just used, so a race with their own
    // logout can at worst spare a row that's about to be deleted anyway.
    let current = CookieJar::from_headers(headers)
        .get(&inner.cookie_name)
        .map(|c| c.value().to_string())
        .unwrap_or_default();
    let revoked = inner.revoke_sessions(user.id, Some(&current)).await;
    let event = serde_json::json!({ "sessions_revoked": revoked });
    inner.notify_own(&who, event, headers, client_ip).await;
    let msg = match revoked {
        0 => "This is your only session — nothing else to sign out.".to_string(),
        1 => "1 other session signed out.".to_string(),
        n => format!("{n} other sessions signed out."),
    };
    profile_page(&inner, &who, &user, None, Some(&msg), &csrf, &req).await.into_response()
}

/// `POST /profile/totp/disable` — the caller turns off their own 2FA. **Re-authenticated** (§5h):
/// removing the second factor is the first thing an intruder with a stolen session would do.
async fn totp_self_disable(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp, // for the audit record
    Form(form): Form<ReauthForm>,
) -> Response {
    let (who, user, csrf) = match self_post(&inner, &req, form.csrf.as_deref()).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    if let Err(msg) = inner.reauth(&user, &who, &form.reauth).await {
        return profile_reply(&inner, (&who, &user, &csrf, &req), StatusCode::FORBIDDEN, Err(&msg)).await;
    }
    let user = clear_totp(&inner, user).await;
    inner.notify_own(&who, serde_json::json!({ "totp_enabled": false }), &req.headers, client_ip).await;
    let msg = "Two-factor authentication disabled.";
    profile_page(&inner, &who, &user, None, Some(msg), &csrf, &req).await.into_response()
}

/// `POST /profile/{id}/totp/disable` — a manager turns off *another* user's 2FA (they can re-enrol).
/// Managers can disable but never set up 2FA for someone else (enrolment needs the user's device).
async fn totp_manage_disable(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp, // for the audit record
    Path(id): Path<String>,
    Form(form): Form<ReauthForm>,
) -> Response {
    let (who, manager, target, csrf) = match manager_post(&inner, &req, form.csrf.as_deref(), &id).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    let headers = &req.headers;
    if let Err(msg) = inner.reauth(&manager, &who, &form.reauth).await {
        let page = manager_page(&inner, &who, &manager, &target, Some(&msg), None, &csrf, &req).await;
        return (StatusCode::FORBIDDEN, page).into_response();
    }
    let target = clear_totp(&inner, target).await;
    let off = serde_json::json!({ "totp_enabled": false });
    inner.notify("auth-admin", &who.username, "auth_user", Some(target.id.to_string()), off, headers, client_ip).await;
    let msg = format!("Two-factor authentication disabled for {}.", target.username);
    manager_page(&inner, &who, &manager, &target, None, Some(&msg), &csrf, &req).await.into_response()
}

/// `POST /profile/{id}/passkeys/remove` — a manager removes **all** of another user's passkeys,
/// re-authenticated with the manager's own factor. Independent of the password: an account left with
/// neither has no way in until the manager sets a password, which the page says.
async fn passkeys_manage_remove(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp,
    Path(id): Path<String>,
    Form(form): Form<ReauthForm>,
) -> Response {
    let (who, manager, target, csrf) = match manager_post(&inner, &req, form.csrf.as_deref(), &id).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    let headers = &req.headers;
    if let Err(msg) = inner.reauth(&manager, &who, &form.reauth).await {
        let page = manager_page(&inner, &who, &manager, &target, Some(&msg), None, &csrf, &req).await;
        return (StatusCode::FORBIDDEN, page).into_response();
    }
    let removed = match passkey::remove_all(&inner.db, target.id).await {
        Ok(n) => n,
        Err(e) => {
            inner.report("auth-admin", "passkey removal", &e, client_ip).await;
            let msg = "Could not remove the passkeys.";
            let page = manager_page(&inner, &who, &manager, &target, Some(msg), None, &csrf, &req).await;
            return (StatusCode::INTERNAL_SERVER_ERROR, page).into_response();
        }
    };
    // Sessions a passkey opened are no longer backed by anything the account holds.
    let revoked = inner.revoke_sessions(target.id, None).await;
    inner
        .notify(
            "auth-admin",
            &who.username,
            "auth_user",
            Some(id.clone()),
            serde_json::json!({ "passkeys_removed_by_manager": removed, "by": who.username, "sessions_revoked": revoked }),
            headers,
            client_ip,
        )
        .await;
    let msg = match target.password_hash.is_empty() {
        true => format!("{removed} passkey(s) removed. {} has no password either: set one above.", target.username),
        false => format!("{removed} passkey(s) removed from {}.", target.username),
    };
    manager_page(&inner, &who, &manager, &target, None, Some(&msg), &csrf, &req).await.into_response()
}

/// The whole self-service profile fragment for `user`: a grid of cards — the password (or the SSO
/// notice), passkeys when on, 2FA, the recovery codes (only with 2FA on — the count is why this is
/// async), other sessions, API keys when on, and the app's `profile_extra` cards. `error` / `success` is
/// the one message, at the top, for whatever was just done.
async fn profile_fragment(
    inner: &Inner,
    who: &Identity,
    user: &user::Model,
    error: Option<&str>,
    success: Option<&str>,
    csrf: &str,
    headers: &HeaderMap,
) -> String {
    let totp_on = user.has_totp();
    // One view per render: every confirm-it's-you block on the page shares its passkey challenge.
    let reauth = inner.reauth_view(user, who).await;
    let left = match totp_on {
        true => Some(recovery::remaining(&inner.db, user.id).await),
        false => None,
    };
    let restricted = inner.restricted(who);
    let notices = Notices {
        policy: restricted.then(|| inner.policy_notice(user)),
        password: user
            .password_change(inner.password_max_age_days, now_secs())
            .map(|r| inner.password_notice(r)),
    };
    let passkeys = inner.passkeys_card(user, &reauth, csrf, headers).await;
    // A restricted session sees only what adds the factor it lacks: no API keys (a key would carry the
    // account past the policy) and none of the app's own cards.
    let mut more = String::new();
    if !restricted {
        if let Some(config) = &inner.api_keys {
            let keys = api_key::card(&inner.db, config, user.id, headers).await;
            more.push_str(&api_keys_html(&keys, &reauth, csrf));
        }
        more.push_str(&inner.profile_extra(who, &reauth, csrf, headers).await);
    }
    let view = ProfileView {
        sso: user.sso_key(),
        has_password: !user.password_hash.is_empty(),
        reauth: &reauth,
        totp_on,
        recovery_left: left,
        notices: &notices,
        passkeys: passkeys.as_deref(),
        more: &more,
    };
    change_form_html(&view, error, success, csrf)
}

/// The caller's own profile again, answering a post: `result` is the message at the top (`Ok` a success,
/// `Err` a refusal) and `status` the response's. What every profile handler answers with.
async fn profile_reply(
    inner: &Inner,
    (who, user, csrf, req): (&Identity, &user::Model, &str, &Parts),
    status: StatusCode,
    result: Result<&str, &str>,
) -> Response {
    let (error, success) = match result {
        Ok(msg) => (None, Some(msg)),
        Err(msg) => (Some(msg), None),
    };
    (status, profile_page(inner, who, user, error, success, csrf, req).await).into_response()
}

/// The caller's own profile page — [`profile_fragment`] in the app's profile shell.
async fn profile_page(
    inner: &Inner,
    who: &Identity,
    user: &user::Model,
    error: Option<&str>,
    success: Option<&str>,
    csrf: &str,
    req: &Parts,
) -> Html<String> {
    let frag = profile_fragment(inner, who, user, error, success, csrf, &req.headers).await;
    inner.page(who, &frag, req)
}

/// The signed-in caller and their account row; `None` sends them to the login page.
///
/// A **restricted** session (below [`Auth::min_level`]) is accepted here: these are the pages it exists
/// for. Check [`Inner::restricted`] before anything it must not do.
async fn signed_in(inner: &Inner, headers: &HeaderMap) -> Option<(Identity, user::Model)> {
    let token = CookieJar::from_headers(headers).get(&inner.cookie_name)?.value().to_string();
    let (who, user, _) = resolve(inner, &token).await?;
    Some((who, user))
}

/// Clear both the active and pending TOTP secrets on a user, the replay guard, and any recovery codes
/// (best-effort). The step **must** go in the same write: leaving a stale ceiling behind would silently
/// reject the first codes of a later re-enrolment, for as long as it took the clock to catch up. The
/// recovery codes go too — they are a way past a second factor that no longer exists, and a later
/// re-enrolment must not inherit a set the user threw away with their old phone.
///
/// Returns the row as it now stands, to render from (the update is best-effort, so on a failed write
/// that is the row as it was).
async fn clear_totp(inner: &Inner, user: user::Model) -> user::Model {
    let mut am: user::ActiveModel = user.clone().into();
    am.totp_secret = Set(None);
    am.totp_pending = Set(None);
    am.totp_last_step = Set(None);
    let user = am.update(&inner.db).await.unwrap_or(user);
    let _ = recovery::clear(&inner.db, user.id).await;
    user
}

/// Render the 2FA enrolment page (QR + otpauth URL + verify form) for a pending secret. `user` is the
/// caller's row, for the confirm-it's-you block.
async fn render_totp_setup(
    inner: &Inner,
    who: &Identity,
    user: &user::Model,
    secret: &str,
    error: Option<&str>,
    csrf: &str,
    req: &Parts,
) -> Response {
    let Some(prov) = totp::provisioning(&inner.totp_issuer, &who.username, secret) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "could not build QR code").into_response();
    };
    let reauth = inner.reauth_view(user, who).await;
    let frag = totp_setup_html(&prov, &reauth, error, csrf);
    inner.page(who, &frag, req).into_response()
}

/// Look up the target user by the (string) id from the URL. `None` if the id isn't an integer or no
/// such user exists.
async fn target_user(inner: &Inner, id: &str) -> Option<user::Model> {
    let uid = id.parse::<i32>().ok()?;
    user::Entity::find_by_id(uid).one(&inner.db).await.ok().flatten()
}

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
fn csrf_rejected(inner: &Inner, req: &Parts) -> Response {
    // The app's page when it set one (`Auth::csrf_rejection`), else the built-in below.
    if let Some(render) = &inner.csrf_reject {
        return render(req);
    }
    (StatusCode::FORBIDDEN, Html(csrf_rejected_html(&inner.login_path))).into_response()
}

/// Build the session cookie: HttpOnly, SameSite Strict or Lax, Path=/, Secure if set, Max-Age.
fn session_cookie(inner: &Inner, token: String) -> Cookie<'static> {
    Cookie::build((inner.cookie_name.clone(), token))
        .http_only(true)
        .same_site(if inner.same_site_lax { SameSite::Lax } else { SameSite::Strict })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_group_membership() {
        let who = Identity::new("1", "u", vec!["admin".into()]);
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
        let admin = Identity::new("1", "a", vec!["admin".into()]);
        let editor = Identity::new("2", "e", vec!["editors".into()]);
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
            10,
            "user, group, user_group, session, the two lockout tables, totp recovery, api keys, \
             passkeys + webauthn challenges"
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
