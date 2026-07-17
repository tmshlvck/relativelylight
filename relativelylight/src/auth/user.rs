//! `user` — the authentication principal. Table `rl_user` (prefixed to avoid clashing with app
//! tables). `password_hash` holds an argon2id PHC string; it is never exposed in reads.
//!
//! TOTP 2FA columns (nullable, both hold a base32 secret): `totp_secret` is the **active** secret —
//! when set, a valid code is required at login; `totp_pending` is a secret mid-setup, not yet
//! confirmed. Both are secrets and must never be exposed in reads (mark them `hidden` on the model).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "rl_user")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub username: String,
    pub password_hash: String,
    pub is_active: bool,
    pub totp_secret: Option<String>,
    pub totp_pending: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
