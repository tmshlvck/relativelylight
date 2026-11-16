//! **Passkeys (WebAuthn)**: the tables. See `docs/DESIGN.md` → auth and `docs/TODO.md` for the plan.
//!
//! The entities here need no WebAuthn library: a credential is stored as the JSON its library
//! serialises to, and a ceremony's state likewise. So they are compiled with `auth` alone, and an
//! app's schema is the same whether or not it turns the `passkeys` feature on.
//!
//! - [`entity`] — `auth_passkey`, one row per registered credential.
//! - [`challenge`] — `auth_webauthn_challenge`, one row per ceremony in flight: single-use, short-lived,
//!   pruned by [`Auth::prune`](super::Auth::prune).
//! - `auth_user.passkey_handle` — the WebAuthn user handle, set at the account's first enrolment.
//!
//! Upgrading a database from before these: [`upgrade`](super::upgrade).
//! - `auth_session.method` / `passkey_class` — how a session was authenticated.

#[cfg(feature = "passkeys")]
pub use super::webauthn::Passkeys;
use sea_orm::{ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter};

/// How strongly a passkey is bound to hardware, weakest first. A credential's class is recorded when it
/// is registered; the app's policy names the lowest class it accepts, and `Synced` accepts any.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// Backup-eligible: the private key may be copied between devices (iCloud Keychain, Google
    /// Password Manager, a password manager).
    Synced,
    /// Reports itself not backup-eligible: the key stays on one authenticator. **Self-reported** —
    /// nothing proves it.
    DeviceBound,
    /// Proved its make and model with an attestation chain to a CA the app trusts. The only hardware
    /// binding a server can verify.
    Attested,
}

impl Class {
    /// The stored form: `synced`, `device-bound`, `attested`.
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Synced => "synced",
            Class::DeviceBound => "device-bound",
            Class::Attested => "attested",
        }
    }

    /// The stored form back; `None` for anything else, which a check must treat as the weakest.
    pub fn parse(s: &str) -> Option<Class> {
        match s {
            "synced" => Some(Class::Synced),
            "device-bound" => Some(Class::DeviceBound),
            "attested" => Some(Class::Attested),
            _ => None,
        }
    }
}

/// One registered passkey. Table `auth_passkey`.
///
/// `credential` is the library's serialised credential, public key and signature counter included: not
/// a secret, but nothing an operator should edit. Hide it in an admin panel.
pub mod entity {
    use sea_orm::entity::prelude::*;

    #[derive(
        Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize,
    )]
    #[sea_orm(table_name = "auth_passkey")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        /// The owner.
        pub user_id: i32,
        /// A human-readable label ("YubiKey on my keyring").
        pub name: String,
        /// The WebAuthn credential ID, base64url without padding — what a sign-in looks the row up by.
        #[sea_orm(unique)]
        pub credential_id: String,
        /// The serialised credential (JSON).
        #[sea_orm(column_type = "Text")]
        pub credential: String,
        /// [`Class`](super::Class) as stored: `synced`, `device-bound` or `attested`.
        pub class: String,
        /// The authenticator's model (AAGUID), when it reported one.
        pub aaguid: Option<String>,
        /// The backup-eligible flag as last seen. It may only go from false to true; when it does, the
        /// class becomes `synced`.
        pub backup_eligible: bool,
        /// The backup-state flag as last seen.
        pub backup_state: bool,
        /// Unix seconds the passkey was registered.
        pub created_at: i64,
        /// Unix seconds it last signed someone in.
        pub last_used_at: Option<i64>,
    }

    /// **Cascades** on delete: an account that goes takes its passkeys with it.
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

    impl Model {
        /// The stored class; an unrecognised value reads as the weakest.
        pub fn class(&self) -> super::Class {
            super::Class::parse(&self.class).unwrap_or(super::Class::Synced)
        }
    }
}

/// One WebAuthn ceremony in flight. Table `auth_webauthn_challenge`.
///
/// Created when a user asks for a challenge (never on a plain page view, so anonymous traffic can't
/// write rows), consumed by deleting it — whoever deletes it first wins, so a response can't be
/// replayed — and pruned after `expires_at`.
pub mod challenge {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "auth_webauthn_challenge")]
    pub struct Model {
        /// An opaque random token (256 bits, hex), carried by the page that runs the ceremony.
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        /// What the ceremony is for: `register`, `login`, `second-factor` or `reauth`.
        pub purpose: String,
        /// The account it is for; `None` for a passwordless sign-in, where the passkey names the user.
        pub user_id: Option<i32>,
        /// The library's serialised ceremony state (JSON).
        #[sea_orm(column_type = "Text")]
        pub state: String,
        /// Unix seconds after which the challenge is refused and pruned.
        pub expires_at: i64,
    }

    /// Cascades on delete, like everything else that belongs to an account.
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

    impl ActiveModelBehavior for ActiveModel {}
}

// ===================== An account's passkeys (no WebAuthn needed) =====================

/// How many passkeys `user_id` has. `0` on a database error: callers use it to *offer* a factor, and
/// re-authentication treats an account with passkeys it can't count as one it can't confirm.
pub async fn count(db: &DatabaseConnection, user_id: i32) -> u64 {
    use sea_orm::PaginatorTrait;
    entity::Entity::find()
        .filter(entity::Column::UserId.eq(user_id))
        .count(db)
        .await
        .unwrap_or(0)
}

/// `user_id`'s passkeys, oldest first.
pub async fn list(db: &DatabaseConnection, user_id: i32) -> Result<Vec<entity::Model>, DbErr> {
    use sea_orm::QueryOrder;
    entity::Entity::find()
        .filter(entity::Column::UserId.eq(user_id))
        .order_by_asc(entity::Column::Id)
        .all(db)
        .await
}

/// Delete every passkey `user_id` has; returns how many went. What a manager's "remove passkeys" does.
pub async fn remove_all(db: &DatabaseConnection, user_id: i32) -> Result<u64, DbErr> {
    Ok(entity::Entity::delete_many()
        .filter(entity::Column::UserId.eq(user_id))
        .exec(db)
        .await?
        .rows_affected)
}

/// The passkey table for an accounts panel: the credential hidden, everything the ceremonies maintain
/// read-only, and the owner pinned (a passkey moved to another account would sign that account in).
/// The label is editable; deleting a row removes the passkey. Turn creation off in the panel
/// (`Table::create(false)`): a passkey is made only by its authenticator, on `/profile`.
///
/// Deleting the last passkey of an account with no password leaves it no way in until a manager sets
/// a password; the profile pages refuse that, the panel leaves it to the administrator.
///
/// ```ignore
/// crud.register(auth::passkey::meta_model(), Arc::new(GroupReadWrite::new(&auth, ["admin"])));
/// ```
#[cfg(feature = "crud")]
pub fn meta_model() -> crate::crud::seaorm::MetaModel<entity::Entity> {
    use entity::Column as C;
    use sea_orm::IdenStatic;
    let mut m = crate::crud::seaorm::MetaModel::new(entity::Entity);
    m.label_column(C::Name.as_str());
    m.field(C::Credential.as_str()).hidden = true;
    m.field(C::Name.as_str()).label = Some("Label".into());
    for (col, label) in [
        (C::UserId, "Owner"),
        (C::CredentialId, "Credential ID"),
        (C::Class, "Kind"),
        (C::Aaguid, "Model (AAGUID)"),
        (C::BackupEligible, "Can sync"),
        (C::BackupState, "Synced"),
        (C::CreatedAt, "Added"),
        (C::LastUsedAt, "Last used"),
    ] {
        let f = m.field(col.as_str());
        f.read_only = true;
        f.label = Some(label.into());
    }
    m.field(C::CreatedAt.as_str()).datetime();
    m.field(C::LastUsedAt.as_str()).datetime();
    m.field(C::Class.as_str()).description = Some(
        "synced, device-bound (self-reported) or attested (proved by the authenticator).".into(),
    );
    let r = m.relation("user");
    r.label = Some("Owner".into());
    r.read_only = true;
    m
}

/// Delete expired challenges; returns how many went. Part of [`Auth::prune`](super::Auth::prune).
pub(super) async fn prune_challenges(db: &DatabaseConnection) -> Result<u64, DbErr> {
    Ok(challenge::Entity::delete_many()
        .filter(challenge::Column::ExpiresAt.lt(super::now_secs()))
        .exec(db)
        .await?
        .rows_affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "crud")]
    #[test]
    fn the_panel_model_hides_the_credential_and_pins_the_owner() {
        let mut m = meta_model();
        assert!(m.field("credential").hidden);
        assert!(m.field("user_id").read_only && m.relation("user").read_only);
        for f in [
            "credential_id",
            "class",
            "aaguid",
            "backup_eligible",
            "created_at",
            "last_used_at",
        ] {
            assert!(m.field(f).read_only, "{f}");
        }
        assert!(
            !m.field("name").read_only && !m.field("name").hidden,
            "the label stays editable"
        );
    }

    #[test]
    fn classes_order_weakest_first_and_round_trip() {
        assert!(Class::Synced < Class::DeviceBound && Class::DeviceBound < Class::Attested);
        for c in [Class::Synced, Class::DeviceBound, Class::Attested] {
            assert_eq!(Class::parse(c.as_str()), Some(c));
        }
        assert_eq!(Class::parse("Attested"), None, "stored values are exact");
    }
}
