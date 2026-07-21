//! `user` — the authentication principal. Table `auth_user` (prefixed to avoid clashing with app
//! tables). `password_hash` holds an argon2id PHC string; it is never exposed in reads.
//!
//! TOTP 2FA columns (nullable, both hold a base32 secret): `totp_secret` is the **active** secret —
//! when set, a valid code is required at login; `totp_pending` is a secret mid-setup, not yet
//! confirmed. Both are secrets and must never be exposed in reads (mark them `hidden` on the model).
//!
//! `sso_provider` marks an **externally-authenticated (SSO) account**: `None` is a local account
//! (password login); `Some(key)` means the user signs in via that OIDC provider only — password login
//! is refused and password/2FA can't be set in their profile. Groups are managed by the SSO mapping.

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
    pub sso_provider: Option<String>,
    /// Row lifecycle timestamps — Unix seconds, **UTC**. `created_at`/`updated_at` are maintained by
    /// the `before_save` hook; `last_login_at` is stamped by the login flow (`None` until first login).
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login_at: Option<i64>,
}

impl Model {
    /// Whether this is an SSO (externally-authenticated) account — no local password / 2FA.
    pub fn is_sso(&self) -> bool {
        self.sso_provider.is_some()
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
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        let now = super::now_secs();
        if insert {
            self.created_at = sea_orm::ActiveValue::Set(now);
        }
        self.updated_at = sea_orm::ActiveValue::Set(now);
        Ok(self)
    }
}
