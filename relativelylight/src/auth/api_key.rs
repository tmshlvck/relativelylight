//! **API keys**: bearer keys for an app's machine endpoints. See `docs/AUTH.md` §5k.
//!
//! **A key is its owner, and nothing else.** It stores no scope, level or group:
//! [`Auth::identify_key`](super::Auth::identify_key) returns the owner's [`Identity`] with the groups
//! read on that request, so removing a membership or deactivating the account disarms every key that
//! user holds at once. Narrower access for a device means an account of its own in a narrower group.
//!
//! **A key never opens the UI.** [`Auth::identify`](super::Auth::identify) reads only the session
//! cookie; a key is checked only where the app calls `identify_key`, with a token it read from the
//! request itself ([`bearer_token`](super::bearer_token), or a header of its own).
//!
//! **Hashed with SHA-256, not argon2**, for the reason `recovery` gives, made stronger: a
//! machine-generated ≈238-bit secret can't be enumerated however cheap the hash, and a deterministic
//! hash makes the lookup on an unauthenticated path one indexed equality match. The format (lowercase
//! hex of the whole raw key, no salt) is a compatibility promise: keys an app minted into its own table
//! before moving onto this one keep working.

use super::{Auth, Identity, Inner};
use axum::extract::{Form, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use sea_orm::sea_query::TableCreateStatement;
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbBackend, DbErr, EntityTrait, QueryFilter,
    QueryOrder, Schema,
};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::Arc;

/// Random characters after the prefix: 40 from a 62-symbol alphabet ≈ 238 bits.
const BODY_LEN: usize = 40;
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// Characters of the random body kept in the visible `prefix` column, after the app's prefix — enough
/// to tell a user's keys apart in a listing, far too few to help guess one.
const VISIBLE_BODY: usize = 6;
/// The longest label a key may carry.
const NAME_MAX: usize = 128;
/// The longest expiry the mint form accepts: a hundred years, which is "never" with a number on it,
/// and keeps `now + days * 86400` far from overflowing.
const EXPIRES_DAYS_MAX: i64 = 36_500;
/// How stale `last_used_at` must be before a successful lookup rewrites it — so a device polling every
/// second costs one write a minute, not one per request. The session idle clock's grace (§5f).
const LAST_USED_GRACE: i64 = 60;

/// One API key. Table `auth_api_key`.
///
/// `hashed_key` is a SHA-256 of a credential, so treat it as one: hide it in an admin panel (which
/// [`meta_model`] does), and never put it in an audit record.
pub mod entity {
    use sea_orm::entity::prelude::*;

    #[derive(
        Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize,
    )]
    #[sea_orm(table_name = "auth_api_key")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        /// The owner. The key acts as this account and nothing else.
        pub user_id: i32,
        /// A human-readable label ("router at home").
        pub name: String,
        /// SHA-256 of the whole raw key, lowercase hex.
        #[sea_orm(unique)]
        pub hashed_key: String,
        /// The first characters of the raw key (the app's prefix and a few more), for telling keys
        /// apart in a listing.
        pub prefix: String,
        /// Unix seconds the key was minted (`0` for a row migrated from a table that didn't record it).
        pub created_at: i64,
        /// Unix seconds after which the key stops working, or `None` for never.
        pub expires_at: Option<i64>,
        /// Unix seconds the key last authenticated a request, refreshed at most once a minute.
        pub last_used_at: Option<i64>,
        /// Switched off by an administrator; a disabled key is refused like an unknown one.
        pub disabled: bool,
    }

    /// **Cascades** on delete: a key is its owner, so an account that goes takes its keys with it.
    /// Without this a key would outlive the user as a live secret nothing owns, and deleting a user who
    /// holds one would fail on the constraint.
    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::super::user::Entity",
            from = "Column::UserId",
            to = "super::super::user::Column::Id",
            on_delete = "Cascade"
        )]
        User,
    }

    impl Related<super::super::user::Entity> for Entity {
        fn to() -> RelationDef {
            Relation::User.def()
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

/// Self-service API keys on `/profile`, switched on with [`Auth::api_keys`](super::Auth::api_keys).
///
/// `#[non_exhaustive]`: built with [`ApiKeys::new`], so a setting added later costs nobody a break.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ApiKeys {
    prefix: String,
}

impl ApiKeys {
    /// Keys minted on the profile page start with `prefix` (`"climb_"`, `"tddns_"`), so a leaked one
    /// is recognisable to a secret scanner and in a log.
    ///
    /// # Panics
    ///
    /// If `prefix` is longer than 32 bytes or holds anything but ASCII letters, digits, `_` and `-`.
    /// It is configuration, so a bad one is a startup error, not a request-time one.
    pub fn new(prefix: impl Into<String>) -> Self {
        let prefix = prefix.into();
        assert!(
            prefix.len() <= 32
                && prefix.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "relativelylight: API key prefix {prefix:?} must be at most 32 ASCII letters, digits, `_` or `-`"
        );
        Self { prefix }
    }

    /// The configured prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

/// A caller authenticated by an API key: who they are, and which key they used (for the audit trail).
///
/// `#[non_exhaustive]`: the crate builds it and apps read it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct KeyIdentity {
    /// The key's owner, with the groups they hold **now**. Authorize on this exactly as you would a
    /// signed-in user.
    pub identity: Identity,
    /// The key's row id.
    pub key_id: i32,
    /// The key's label.
    pub key_name: String,
    /// The key's visible prefix (the app's prefix and a few more characters).
    pub key_prefix: String,
}

/// Why [`Auth::identify_key`](super::Auth::identify_key) refused a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// No such key, or it is expired or disabled, or its owner is deactivated. One answer for all of
    /// them, so the response says nothing about which. Answer `401`.
    Invalid,
    /// The source address is locked out after too many rejected credentials; retry after this many
    /// seconds. The key was **not** looked at. Answer `429` with `Retry-After`.
    Locked(i64),
    /// The key could not be checked (a database error, already handed to the `on_error` observer).
    /// Never a statement about the key. Answer `500` or `503`.
    Internal,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Invalid => f.write_str("invalid API key"),
            KeyError::Locked(retry) => write!(f, "too many failed attempts; retry in {retry}s"),
            KeyError::Internal => f.write_str("the API key could not be checked"),
        }
    }
}

impl std::error::Error for KeyError {}

/// SHA-256 of a raw key, lowercase hex: what `hashed_key` stores and the lookup matches.
pub fn hash(raw: &str) -> String {
    Sha256::digest(raw.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A fresh raw key: `prefix` and [`BODY_LEN`] OS-random alphanumerics.
fn fresh(prefix: &str) -> String {
    // Rejection sampling, as for recovery codes: a byte at or above the largest multiple of the
    // alphabet's length is redrawn, so every character is exactly uniform.
    let limit = (256 / ALPHABET.len() * ALPHABET.len()) as u8;
    let mut out = String::with_capacity(prefix.len() + BODY_LEN);
    out.push_str(prefix);
    while out.len() < prefix.len() + BODY_LEN {
        let mut buf = [0u8; 32];
        getrandom::fill(&mut buf).expect("the OS random source failed");
        for b in buf {
            if b < limit && out.len() < prefix.len() + BODY_LEN {
                out.push(ALPHABET[b as usize % ALPHABET.len()] as char);
            }
        }
    }
    out
}

/// Mint a key for `user_id` and return its row and the raw key, which exists **only** in this return
/// value: show it once. This is what the profile page calls; call it yourself to issue keys some other
/// way (a provisioning script, an admin action of your own). No re-authentication, no audit event:
/// those are the caller's.
pub async fn mint(
    db: &DatabaseConnection,
    user_id: i32,
    prefix: &str,
    name: &str,
    expires_at: Option<i64>,
) -> Result<(entity::Model, String), DbErr> {
    let raw = fresh(prefix);
    let row = entity::ActiveModel {
        user_id: Set(user_id),
        name: Set(name.to_string()),
        hashed_key: Set(hash(&raw)),
        prefix: Set(raw.chars().take(prefix.len() + VISIBLE_BODY).collect()),
        created_at: Set(super::now_secs()),
        expires_at: Set(expires_at),
        last_used_at: Set(None),
        disabled: Set(false),
        ..Default::default()
    }
    .insert(db)
    .await?;
    Ok((row, raw))
}

/// `user_id`'s keys, newest first.
pub async fn list(db: &DatabaseConnection, user_id: i32) -> Result<Vec<entity::Model>, DbErr> {
    entity::Entity::find()
        .filter(entity::Column::UserId.eq(user_id))
        .order_by_desc(entity::Column::Id)
        .all(db)
        .await
}

/// Delete key `key_id` if **`user_id` owns it**, returning the row that went; `None` if there is no such
/// key or it is someone else's (the two are not told apart).
pub async fn revoke(
    db: &DatabaseConnection,
    user_id: i32,
    key_id: i32,
) -> Result<Option<entity::Model>, DbErr> {
    let Some(row) = entity::Entity::find_by_id(key_id)
        .filter(entity::Column::UserId.eq(user_id))
        .one(db)
        .await?
    else {
        return Ok(None);
    };
    // The owner condition again on the delete itself, so nothing between the read and the write can make
    // this remove a row the caller doesn't own.
    let gone = entity::Entity::delete_many()
        .filter(entity::Column::Id.eq(key_id))
        .filter(entity::Column::UserId.eq(user_id))
        .exec(db)
        .await?
        .rows_affected;
    Ok((gone == 1).then_some(row))
}

/// The `CREATE TABLE` for `auth_api_key` alone — the migration step for an app that already applied
/// [`table_create_statements`](super::table_create_statements) before keys existed.
pub fn table_create_statement(backend: DbBackend) -> TableCreateStatement {
    Schema::new(backend).create_table_from_entity(entity::Entity)
}

/// The table for an accounts panel, with the rules that keep the panel from becoming a way around
/// §5k: `hashed_key` hidden, and the owner, the prefix and the timestamps read-only. Moving a key to
/// another account would hand that account's rights to whoever holds it. Register it behind an admin
/// gate, and turn creation off in the panel (`Table::create(false)`): a key minted there would have no
/// raw value anyone could see.
///
/// ```ignore
/// crud.register(auth::api_key::meta_model(), Arc::new(GroupReadWrite::new(&auth, ["admin"])));
/// ```
#[cfg(feature = "crud")]
pub fn meta_model() -> crate::crud::seaorm::MetaModel<entity::Entity> {
    use entity::Column as C;
    use sea_orm::IdenStatic;
    let mut m = crate::crud::seaorm::MetaModel::new(entity::Entity);
    m.label_column(C::Name.as_str());
    m.field(C::HashedKey.as_str()).hidden = true;
    m.field(C::UserId.as_str()).read_only = true;
    let f = m.field(C::Name.as_str());
    f.label = Some("Label".into());
    f.description = Some("A human-readable name for this key.".into());
    f.validate_str(crate::validate::non_empty);
    let f = m.field(C::Prefix.as_str());
    f.label = Some("Prefix".into());
    f.description = Some(
        "The start of the key, for telling keys apart. The key itself is never stored.".into(),
    );
    f.read_only = true;
    let f = m.field(C::CreatedAt.as_str());
    f.label = Some("Created".into());
    f.read_only = true;
    f.datetime();
    let f = m.field(C::ExpiresAt.as_str());
    f.label = Some("Expires".into());
    f.description = Some("The key stops working at this time. Empty = never.".into());
    f.datetime();
    let f = m.field(C::LastUsedAt.as_str());
    f.label = Some("Last used".into());
    f.read_only = true;
    f.datetime();
    let f = m.field(C::Disabled.as_str());
    f.label = Some("Disabled".into());
    f.description = Some("A disabled key is refused like an unknown one.".into());
    let r = m.relation("user");
    r.label = Some("Owner".into());
    r.read_only = true;
    m
}

/// `Authorization: Bearer <token>` → the token. The scheme is matched case-insensitively (RFC 7235);
/// `None` without the header, with another scheme, or with an empty token.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let v = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = v.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// What [`Auth::identify_key`](super::Auth::identify_key) does.
pub(super) async fn identify(
    inner: &Inner,
    token: &str,
    ip: IpAddr,
) -> Result<KeyIdentity, KeyError> {
    let token = token.trim();
    if token.is_empty() {
        // No credential presented, so nothing was checked and nothing is counted (§5e).
        return Err(KeyError::Invalid);
    }
    if let Some(retry) = inner.ips.locked(Some(ip)).await {
        return Err(KeyError::Locked(retry));
    }
    match lookup(inner, token).await {
        Ok(Some(found)) => Ok(found),
        Ok(None) => {
            inner.ips.record_failure(Some(ip)).await;
            Err(KeyError::Invalid)
        }
        Err(e) => {
            // An outage is no guess: reported, not counted.
            inner.report("auth-api-key", "key lookup", &e, ip).await;
            Err(KeyError::Internal)
        }
    }
}

/// The lookup behind [`identify`], ignoring the lockout: `Ok(None)` for every way a key can be no good.
async fn lookup(inner: &Inner, token: &str) -> Result<Option<KeyIdentity>, DbErr> {
    let Some(key) = entity::Entity::find()
        .filter(entity::Column::HashedKey.eq(hash(token)))
        .one(&inner.db)
        .await?
    else {
        return Ok(None);
    };
    let now = super::now_secs();
    if key.disabled || key.expires_at.is_some_and(|t| t <= now) {
        return Ok(None);
    }
    let Some(user) = super::user::Entity::find_by_id(key.user_id)
        .one(&inner.db)
        .await?
    else {
        return Ok(None);
    };
    if !user.is_active {
        return Ok(None);
    }
    if key.last_used_at.is_none_or(|t| now - t >= LAST_USED_GRACE) {
        // Best-effort, like the session idle clock: a lost update means the next request tries again.
        let _ = entity::Entity::update_many()
            .col_expr(
                entity::Column::LastUsedAt,
                sea_orm::sea_query::Expr::value(now),
            )
            .filter(entity::Column::Id.eq(key.id))
            .exec(&inner.db)
            .await;
    }
    let groups = super::groups_of(&inner.db, user.id).await;
    Ok(Some(KeyIdentity {
        identity: Identity {
            id: user.id.to_string(),
            username: user.username,
            groups,
        },
        key_id: key.id,
        key_name: key.name,
        key_prefix: key.prefix,
    }))
}

// ===================== The profile card =====================

/// One row of the card, formatted for display.
pub(super) struct Row {
    pub id: i32,
    pub name: String,
    pub prefix: String,
    pub created: String,
    pub expires: String,
    pub expired: bool,
    pub used: String,
    pub disabled: bool,
}

/// The card's data: the rows and the zone their times are in.
pub(super) struct Card {
    pub rows: Vec<Row>,
    pub zone: String,
}

/// Load and format `user_id`'s keys for the card, in the caller's display zone.
pub(super) async fn card(db: &DatabaseConnection, user_id: i32, headers: &HeaderMap) -> Card {
    let (zone, fmt) = clock(headers);
    let now = super::now_secs();
    let rows = list(db, user_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|k| Row {
            id: k.id,
            created: if k.created_at > 0 {
                fmt(k.created_at)
            } else {
                "—".into()
            },
            expires: k.expires_at.map(&fmt).unwrap_or_else(|| "never".into()),
            expired: k.expires_at.is_some_and(|t| t <= now),
            used: k.last_used_at.map(&fmt).unwrap_or_else(|| "never".into()),
            name: k.name,
            prefix: k.prefix,
            disabled: k.disabled,
        })
        .collect();
    Card { rows, zone }
}

/// The caller's display zone and a formatter for it: their timezone cookie with feature `tz`, UTC
/// without it.
#[cfg(feature = "tz")]
fn clock(headers: &HeaderMap) -> (String, impl Fn(i64) -> String) {
    let tz = crate::time::Tz::from_headers(headers);
    (tz.name().to_string(), move |t| tz.format(t))
}

#[cfg(not(feature = "tz"))]
fn clock(_headers: &HeaderMap) -> (String, impl Fn(i64) -> String) {
    let fmt = |t: i64| match time::OffsetDateTime::from_unix_timestamp(t) {
        Ok(d) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            d.year(),
            u8::from(d.month()),
            d.day(),
            d.hour(),
            d.minute()
        ),
        Err(_) => t.to_string(),
    };
    ("UTC".to_string(), fmt)
}

#[derive(serde::Deserialize)]
pub(super) struct MintForm {
    #[serde(default)]
    name: String,
    /// Days until expiry; blank (the form's default) means never. A string, because an empty
    /// `<input type=number>` posts `expires_days=`.
    #[serde(default)]
    expires_days: String,
    #[serde(default)]
    current_password: String,
    #[serde(default)]
    totp_code: String,
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

/// The label to store, or the message to show. Blank becomes `"key"`.
fn clean_name(raw: &str) -> Result<String, &'static str> {
    let name = raw.trim();
    if name.chars().count() > NAME_MAX {
        return Err("The label is too long (at most 128 characters).");
    }
    if name.chars().any(char::is_control) {
        return Err("The label can't contain control characters.");
    }
    Ok(if name.is_empty() {
        "key".into()
    } else {
        name.into()
    })
}

/// The expiry to store (`None` = never), or the message to show.
fn clean_expiry(raw: &str, now: i64) -> Result<Option<i64>, &'static str> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    match raw.parse::<i64>() {
        Ok(d) if (1..=EXPIRES_DAYS_MAX).contains(&d) => Ok(Some(now + d * 86_400)),
        _ => Err("The expiry must be a whole number of days from 1 to 36500, or blank for never."),
    }
}

/// `POST /profile/api-keys` — mint a key for the caller and show it once. **Re-authenticated**: a key
/// outlives the session and skips the second factor, so a stolen session must not become one.
pub(super) async fn mint_submit(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    crate::middleware::RealIp(client_ip): crate::middleware::RealIp,
    Form(form): Form<MintForm>,
) -> Response {
    let Some(cfg) = inner.api_keys.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (who, user, csrf) = match super::self_post(&inner, &req, form.csrf.as_deref()).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    if let Err(msg) = inner
        .reauth(&user, &form.current_password, &form.totp_code)
        .await
    {
        return refuse(
            &inner,
            (&who, &user, &csrf, &req),
            StatusCode::FORBIDDEN,
            &msg,
        )
        .await;
    }
    let now = super::now_secs();
    let fields =
        clean_name(&form.name).and_then(|n| clean_expiry(&form.expires_days, now).map(|e| (n, e)));
    let (name, expires_at) = match fields {
        Ok(v) => v,
        Err(msg) => {
            return refuse(
                &inner,
                (&who, &user, &csrf, &req),
                StatusCode::BAD_REQUEST,
                msg,
            )
            .await
        }
    };
    let (key, raw) = match mint(&inner.db, user.id, cfg.prefix(), &name, expires_at).await {
        Ok(v) => v,
        Err(e) => {
            inner
                .report("auth-api-key", "key mint", &e, client_ip)
                .await;
            let msg = "Could not create the key.";
            return refuse(
                &inner,
                (&who, &user, &csrf, &req),
                StatusCode::INTERNAL_SERVER_ERROR,
                msg,
            )
            .await;
        }
    };
    // Never the key or its hash: an audit table is readable, and a credential in it would be a leak.
    inner
        .notify_event(super::Event {
            source: "auth-profile",
            op: crate::authz::Operation::Create,
            actor: &who.username,
            entity: "auth_api_key",
            key: Some(key.id.to_string()),
            before: None,
            after: Some(describe(&key)),
            headers: &req.headers,
            client_ip,
        })
        .await;
    let frag = super::pages::api_key_minted_html(&key.name, &raw);
    inner.page(&who, &frag, &req).into_response()
}

/// The profile page again, with `msg` on the key card and nothing changed.
async fn refuse(
    inner: &Inner,
    (who, user, csrf, req): (&Identity, &super::user::Model, &str, &Parts),
    status: StatusCode,
    msg: &str,
) -> Response {
    (
        status,
        super::profile_page_keys(inner, who, user, Some(msg), None, csrf, req).await,
    )
        .into_response()
}

#[derive(serde::Deserialize)]
pub(super) struct RevokeForm {
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

/// `POST /profile/api-keys/{id}/revoke` — delete one of the caller's own keys. Not re-authenticated:
/// it only removes access. Someone else's key, or none, changes nothing and gets a `404`.
pub(super) async fn revoke_submit(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    crate::middleware::RealIp(client_ip): crate::middleware::RealIp,
    Path(id): Path<String>,
    Form(form): Form<RevokeForm>,
) -> Response {
    if inner.api_keys.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (who, user, csrf) = match super::self_post(&inner, &req, form.csrf.as_deref()).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    let gone = match id.parse::<i32>() {
        Ok(id) => revoke(&inner.db, user.id, id).await,
        Err(_) => Ok(None),
    };
    let (status, error, success) = match gone {
        Ok(Some(key)) => {
            inner
                .notify_event(super::Event {
                    source: "auth-profile",
                    op: crate::authz::Operation::Delete,
                    actor: &who.username,
                    entity: "auth_api_key",
                    key: Some(key.id.to_string()),
                    before: Some(describe(&key)),
                    after: None,
                    headers: &req.headers,
                    client_ip,
                })
                .await;
            (
                StatusCode::OK,
                None,
                Some(format!("Key “{}” revoked.", key.name)),
            )
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Some("No such key.".to_string()),
            None,
        ),
        Err(e) => {
            inner
                .report("auth-api-key", "key revoke", &e, client_ip)
                .await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Some("Could not revoke the key.".to_string()),
                None,
            )
        }
    };
    let page = super::profile_page_keys(
        &inner,
        &who,
        &user,
        error.as_deref(),
        success.as_deref(),
        &csrf,
        &req,
    )
    .await;
    (status, page).into_response()
}

/// A key as the audit trail sees it: label, prefix, expiry. Never the hash.
fn describe(key: &entity::Model) -> serde_json::Value {
    serde_json::json!({
        "user_id": key.user_id,
        "name": key.name,
        "prefix": key.prefix,
        "expires_at": key.expires_at,
    })
}

impl Auth {
    /// Turn on **self-service API keys**: a card on the caller's own `/profile` listing their keys,
    /// minting one (re-authenticated, shown once) and revoking one. See `docs/AUTH.md` §5k.
    ///
    /// ```ignore
    /// let auth = Auth::new(db, lockout).api_keys(ApiKeys::new("climb_"));
    /// ```
    ///
    /// [`identify_key`](Auth::identify_key) works with or without this, for keys an app mints itself.
    pub fn api_keys(mut self, keys: ApiKeys) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().api_keys = Some(keys);
        self
    }

    /// The caller behind an **API key**: its owner's [`Identity`], with the groups they hold now, and
    /// which key it was. `ip` is the caller's address
    /// ([`RealIp`](crate::middleware::RealIp)), the only thing a failure can be counted against.
    ///
    /// The app reads the token from the request — [`bearer_token`](super::bearer_token) for
    /// `Authorization: Bearer`, or a header of its own — and this verifies it:
    ///
    /// ```ignore
    /// let token = auth::bearer_token(&headers).unwrap_or_default();
    /// match auth.identify_key(token, ip).await {
    ///     Ok(k) => { /* authorize k.identity as you would a signed-in user; audit k.key_id */ }
    ///     Err(KeyError::Invalid) => return StatusCode::UNAUTHORIZED.into_response(),
    ///     Err(KeyError::Locked(retry)) => return too_many_requests(retry),
    ///     Err(KeyError::Internal) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    /// }
    /// ```
    ///
    /// Refused as [`KeyError::Invalid`]: an unknown key, an expired or disabled one, or one whose owner
    /// is deactivated — each counted against `ip` on the shared [`IpLockout`](super::lockout::IpLockout).
    /// While `ip` is locked the key is not looked at ([`KeyError::Locked`]). An empty token is refused
    /// without counting. A key **never** satisfies [`identify`](Auth::identify), so it never opens the
    /// UI or passes a gate preset.
    pub async fn identify_key(&self, token: &str, ip: IpAddr) -> Result<KeyIdentity, KeyError> {
        identify(&self.inner, token, ip).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_the_prefix_and_forty_uniform_alphanumerics() {
        let k = fresh("demo_");
        assert!(k.starts_with("demo_"));
        assert_eq!(k.len(), 5 + BODY_LEN);
        assert!(k[5..].bytes().all(|b| b.is_ascii_alphanumeric()), "{k}");
        assert_ne!(fresh("demo_"), k, "two keys must not coincide");
        assert_eq!(fresh("").len(), BODY_LEN, "an empty prefix is allowed");
    }

    #[test]
    fn the_hash_is_sha256_hex_of_the_whole_key() {
        // The compatibility promise: the same digest an app's own table stored (teleddns).
        assert_eq!(
            hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(hash("abc"), hash("abd"));
    }

    #[test]
    fn bearer_token_reads_only_a_non_empty_bearer_credential() {
        let h = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(axum::http::header::AUTHORIZATION, v.parse().unwrap());
            h
        };
        assert_eq!(bearer_token(&h("Bearer abc")), Some("abc"));
        assert_eq!(
            bearer_token(&h("bearer  abc ")),
            Some("abc"),
            "the scheme is case-insensitive"
        );
        assert_eq!(bearer_token(&h("Basic YTpi")), None);
        assert_eq!(bearer_token(&h("Bearer ")), None);
        assert_eq!(bearer_token(&h("Bearer")), None);
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn the_mint_form_bounds_its_inputs() {
        assert_eq!(clean_name("  router  ").unwrap(), "router");
        assert_eq!(clean_name("").unwrap(), "key");
        assert!(clean_name(&"x".repeat(129)).is_err());
        assert!(clean_name("a\nb").is_err());
        assert_eq!(clean_expiry("", 100), Ok(None));
        assert_eq!(clean_expiry("2", 100), Ok(Some(100 + 2 * 86_400)));
        for bad in ["0", "-1", "1.5", "x", "36501", "99999999999999999999"] {
            assert!(clean_expiry(bad, 100).is_err(), "{bad:?}");
        }
    }

    #[cfg(feature = "crud")]
    #[test]
    fn the_panel_model_hides_the_hash_and_pins_the_owner() {
        let mut m = meta_model();
        assert!(
            m.field("hashed_key").hidden,
            "a credential hash is never shown"
        );
        assert!(
            m.field("user_id").read_only && m.relation("user").read_only,
            "a key can't change hands"
        );
        for f in ["prefix", "created_at", "last_used_at"] {
            assert!(m.field(f).read_only, "{f}");
        }
        for f in ["name", "expires_at", "disabled"] {
            assert!(
                !m.field(f).read_only && !m.field(f).hidden,
                "{f} stays editable"
            );
        }
    }

    #[test]
    #[should_panic(expected = "API key prefix")]
    fn a_prefix_with_a_space_is_a_startup_error() {
        ApiKeys::new("my key");
    }
}
