//! `session` — a server-side session. Table `auth_session`. `id` is an opaque random token carried in
//! the session cookie; `expires_at` is a Unix timestamp (seconds). Deleting the row revokes it.
//!
//! `awaiting_totp` marks a **half-authenticated** session: the password was verified but the TOTP
//! second factor hasn't been yet. `Auth::identify` treats such a session as anonymous, so the user
//! isn't logged in until the code is confirmed (which clears the flag).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "auth_session")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub user_id: i32,
    pub expires_at: i64,
    pub awaiting_totp: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
