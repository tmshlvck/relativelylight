//! `user` — the authentication principal. Table `auth_user` (prefixed to avoid clashing with app
//! tables). `password_hash` holds an argon2id PHC string; it is never exposed in reads.
//!
//! TOTP 2FA columns (nullable, both hold a base32 secret): `totp_secret` is the **active** secret —
//! when set, a valid code is required at login; `totp_pending` is a secret mid-setup, not yet
//! confirmed. Both are secrets and must never be exposed in reads (mark them `hidden` on the model).
//! `totp_last_step` is the **replay guard** — the last accepted 30-second step, which a later code must
//! exceed (RFC 6238 §5.2). Not a secret (TOTP's security doesn't rest on step secrecy, and it is a
//! coarser version of `last_login_at`), but operator noise worth hiding all the same.
//! As with `sso_provider`, a **blank** secret counts as *no* secret: a `Some("")` written by an admin
//! form (or a CSV import) would otherwise demand a login code that can never verify, locking the
//! account out for good. Ask [`Model::totp_key`] / [`Model::has_totp`] / [`Model::pending_totp_key`].
//!
//! `sso_provider` marks an **externally-authenticated (SSO) account**: `None` is a local account
//! (password login); `Some(key)` means the user signs in via that OIDC provider only — password login
//! is refused and password/2FA can't be set in their profile. Groups are managed by the SSO mapping.
//! **An empty string counts as "no provider"**, same as `None` — a blank text input in an admin form
//! writes `""`, and an account created that way must still be a normal local account. Always ask
//! [`Model::sso_key`] / [`Model::is_sso`] rather than testing the column directly.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "auth_user")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub username: String,
    pub password_hash: String,
    pub is_active: bool,
    pub totp_secret: Option<String>,
    pub totp_pending: Option<String>,
    /// The last TOTP step accepted for this account (Unix seconds / 30), or `None` if 2FA has never
    /// been used. A submitted code must match a step **strictly greater** than this one, so a code
    /// cannot be used twice inside its ±1-step validity window. Cleared whenever 2FA is turned off, so
    /// a re-enrolment never inherits a stale ceiling. See [`Model::totp_step_ok`].
    pub totp_last_step: Option<i64>,
    pub sso_provider: Option<String>,
    /// The WebAuthn **user handle**: a random UUID, set when the account registers its first passkey
    /// and kept for its life, so an authenticator can tell this account's credentials apart. Opaque on
    /// purpose — the spec forbids anything identifying here. `None` until the first enrolment.
    #[sea_orm(unique)]
    pub passkey_handle: Option<String>,
    /// Unix seconds the password was last set, stamped by the row hook whenever a write sets one.
    /// `None` for a row from before the column existed; the age then counts from `created_at`.
    pub password_changed_at: Option<i64>,
    /// The owner must choose a new password: someone else set this one (an administrator's panel
    /// edit, a manager's reset). Set by the row hook below unless the writer set it explicitly; the
    /// owner's own change clears it.
    #[sea_orm(default_value = false)]
    pub must_change_password: bool,
    /// Row lifecycle timestamps — Unix seconds, **UTC**. `created_at`/`updated_at` are maintained by
    /// the `before_save` hook; `last_login_at` is stamped by the login flow (`None` until first login).
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login_at: Option<i64>,
}

/// Why an account should choose a new password (`Identity::password_change`, docs/AUTH.md §5m).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PasswordChange {
    /// Someone other than the owner set it, so it is known to them.
    SetByAnother,
    /// Older than the site's `Auth::password_max_age_days`.
    Expired,
}

impl Model {
    /// Whether this account should choose a new password, and why: `None` for an account with no
    /// password (SSO, passkey-only). `max_age_days` is `Auth::password_max_age_days` (`0` = no limit).
    pub fn password_change(&self, max_age_days: u32, now: i64) -> Option<PasswordChange> {
        if self.password_hash.is_empty() || self.is_sso() {
            return None;
        }
        if self.must_change_password {
            return Some(PasswordChange::SetByAnother);
        }
        let since = self.password_changed_at.unwrap_or(self.created_at);
        (max_age_days > 0 && now - since > i64::from(max_age_days) * 86_400)
            .then_some(PasswordChange::Expired)
    }

    /// The provider key this account signs in through, or `None` for a local (password) account.
    /// Normalizes a **blank** `sso_provider` to `None`: an admin form that leaves the column empty
    /// stores `""`, which must not turn the account into an SSO one that can never log in.
    pub fn sso_key(&self) -> Option<&str> {
        self.sso_provider.as_deref().map(str::trim).filter(|p| !p.is_empty())
    }

    /// Whether this is an SSO (externally-authenticated) account — no local password / 2FA.
    pub fn is_sso(&self) -> bool {
        self.sso_key().is_some()
    }

    /// The **active** TOTP secret, or `None` when 2FA is off. Normalizes a blank secret to `None`:
    /// treating `Some("")` as "2FA on" would require a code at login that no authenticator can
    /// produce — an account locked out of its own login.
    pub fn totp_key(&self) -> Option<&str> {
        self.totp_secret.as_deref().map(str::trim).filter(|s| !s.is_empty())
    }

    /// Whether 2FA is active for this account (a usable [`totp_key`](Model::totp_key)).
    pub fn has_totp(&self) -> bool {
        self.totp_key().is_some()
    }

    /// The secret of an enrolment **in progress**, or `None` when there is none (blank normalized
    /// away, so a blank `totp_pending` isn't mistaken for a half-finished setup).
    pub fn pending_totp_key(&self) -> Option<&str> {
        self.totp_pending.as_deref().map(str::trim).filter(|s| !s.is_empty())
    }

    /// Whether a code matching `step` may still be accepted: the replay guard (RFC 6238 §5.2). A step
    /// at or below [`totp_last_step`](Model::totp_last_step) has already been spent, so the same code
    /// (or an older one still inside the skew window) is refused; a never-used account accepts anything.
    pub fn totp_step_ok(&self, step: i64) -> bool {
        self.totp_last_step.is_none_or(|last| step > last)
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

// N:M: user <-> group via user_group, so an admin UI can edit a user's group membership.
impl Related<super::group::Entity> for Entity {
    fn to() -> RelationDef {
        super::user_group::Relation::Group.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::user_group::Relation::User.def().rev())
    }
}

// Maintain the UTC lifecycle timestamps: stamp created_at on insert, updated_at on every save.
#[async_trait::async_trait]
/// The row hook: lifecycle stamps, and the password's.
///
/// **Any write that sets `password_hash` stamps `password_changed_at`, and flags the account
/// (`must_change_password`) unless the writer set that column itself.** So a password written by
/// anyone but its owner — an administrator's panel edit, an app's own form, a manager's reset —
/// asks the owner to choose their own, without each of those paths having to remember. The owner's
/// own change and the programmatic helpers (`create_user`, `set_password`, …) clear it explicitly.
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        use sea_orm::ActiveValue::Set;
        let now = super::now_secs();
        if insert {
            self.created_at = Set(now);
        }
        self.updated_at = Set(now);
        if self.password_hash.is_set() {
            self.password_changed_at = Set(Some(now));
            if !self.must_change_password.is_set() {
                self.must_change_password = Set(true);
            }
        }
        if insert && !self.must_change_password.is_set() {
            self.must_change_password = Set(false);
        }
        Ok(self)
    }
}
