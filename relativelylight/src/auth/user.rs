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
        // An account created without a password has none (an empty hash, which nothing verifies
        // against): an SSO or passkey-only account. Not a password written, so nothing is stamped.
        if insert && !self.password_hash.is_set() {
            self.password_hash = Set(String::new());
        }
        Ok(self)
    }
}

/// The table for an accounts panel (feature `crud`), configured once here so every panel gets the
/// same rules (docs/AUTH.md §5j):
///
/// - **`password_hash`** is the write-only, argon2-hashed "Password" field, screened by `auth`'s own
///   password policy (`Auth::password_policy` / `password_check`), and **create-only**: it sets an
///   account's first password (blank = none, for an SSO-only account). Every later change is the
///   manager's reset at `/profile/{id}`, which also signs the account out everywhere.
/// - The TOTP columns and `passkey_handle` are hidden: credentials, the replay guard, and the handle
///   every passkey hangs on.
/// - `must_change_password`, `password_changed_at` and the timestamps are shown, read-only: the row
///   hook maintains them, and an editable checkbox would post `false` and keep the flag from ever
///   being set.
/// - `id` links to the account's credentials page, `{profile_path}/{id}` (`Auth::profile_path`), in
///   the cells and wherever one account is shown: there a manager resets the password, turns 2FA off
///   and removes passkeys. `target="_top"`, so from a linked row's dialog it takes the whole window.
/// - `username` is checked with [`valid_username`](super::valid_username); groups are edited through
///   the N:M relation `auth_group` (`auth_user_group` is never a model of its own).
///
/// Register it behind an admin gate, with [`group::meta_model`](super::group::meta_model) for the
/// relation's other side:
///
/// ```ignore
/// let gate = Arc::new(GroupReadWrite::new(&auth, ["admin"]));
/// crud.register(auth::user::meta_model(&auth), gate.clone());
/// crud.register(auth::group::meta_model(), gate.clone());
/// ```
#[cfg(feature = "crud")]
pub fn meta_model(auth: &super::Auth) -> crate::crud::seaorm::MetaModel<Entity> {
    use sea_orm::IdenStatic;
    use Column as C;
    let mut m = crate::crud::seaorm::MetaModel::new(Entity);
    m.label_column(C::Username.as_str());
    let link = credentials_link(auth.profile_path());
    m.field(C::Id.as_str()).format_cell(link.clone()).format_view(link);
    let f = m.field(C::Username.as_str());
    f.label = Some("Username".into());
    f.validate_str(super::valid_username);

    let check = auth.inner.password_check.clone();
    let f = m.field(C::PasswordHash.as_str());
    f.password();
    f.create_only = true;
    // Optional: the row hook stores "no password" when a create leaves it out.
    f.required = false;
    f.description = Some(
        "The first password, set once here; later ones from the account's credentials page. \
         Blank = no password (sign-in through SSO or a passkey only)."
            .into(),
    );
    if let Some(check) = check {
        // The plaintext, before `password()`'s hook hashes it: the same policy `/profile` applies.
        // The username isn't in a field validator's reach, so that one rule is `/profile`'s alone.
        f.validate_str(move |pw| if pw.is_empty() { Ok(()) } else { check(pw, "") });
    }

    for c in [C::TotpSecret, C::TotpPending, C::TotpLastStep, C::PasskeyHandle] {
        m.field(c.as_str()).hidden = true;
    }
    let f = m.field(C::IsActive.as_str());
    f.label = Some("Active".into());
    f.default = Some(serde_json::json!(true));
    f.description =
        Some("Unticked = refused at the door, password or SSO alike, session or not.".into());
    let f = m.field(C::SsoProvider.as_str());
    f.label = Some("SSO provider".into());
    f.description =
        Some("The provider key this account signs in through; blank = a local account.".into());
    for (c, label) in [
        (C::MustChangePassword, "Must change password"),
        (C::PasswordChangedAt, "Password set"),
        (C::LastLoginAt, "Last login"),
        (C::CreatedAt, "Created"),
        (C::UpdatedAt, "Updated"),
    ] {
        let f = m.field(c.as_str());
        f.label = Some(label.into());
        f.read_only = true;
        if !matches!(c, C::MustChangePassword) {
            f.datetime();
        }
    }
    // The relation needs only the other side's identity, not its configuration.
    m.relate(&crate::crud::seaorm::MetaModel::new(super::group::Entity));
    m.relation("auth_group").label = Some("Groups".into());
    m
}

/// An account's id as a link to its credentials page, `{profile_path}/{id}`.
#[cfg(feature = "crud")]
fn credentials_link(
    profile_path: &str,
) -> impl Fn(&crate::crud::fmt::FmtCtx) -> String + Clone + Send + Sync + 'static {
    use crate::crud::fmt::{esc, esc_str};
    let base = esc_str(profile_path.trim_end_matches('/'));
    move |cx| {
        let id = esc(cx.value());
        format!(
            r#"<a href="{base}/{id}" target="_top" title="Password, two-factor and passkeys">{id}</a>"#
        )
    }
}
