//! `session` — a server-side session. Table `auth_session`. `id` is an opaque random token carried in
//! the session cookie; deleting the row revokes it.
//!
//! **Two independent clocks** (see `docs/AUTH.md` §5f). `expires_at` is the **absolute** deadline,
//! stamped once at creation from `Auth::session_ttl_secs` and never moved: a session dies at that
//! instant however busy it has been. `last_seen_at` is the **idle** clock, refreshed as the session is
//! used, so a session also dies after `Auth::session_idle_secs` of silence. A session is usable while
//! *both* hold, and the id is opaque either way — an expired row never authenticates, whether or not
//! the pruner has collected it yet.
//!
//! `awaiting_totp` marks a **half-authenticated** session: the password was verified but the TOTP
//! second factor hasn't been yet. `Auth::identify` treats such a session as anonymous, so the user
//! isn't logged in until the code is confirmed — at which point the session id is **rotated** (a new
//! row, the old one deleted), so a planted half-authenticated cookie can't be elevated into a real
//! login.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "auth_session")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub user_id: i32,
    /// The **absolute** deadline, Unix seconds — set once at creation, never extended.
    pub expires_at: i64,
    /// Unix seconds of the last request that used this session — the **idle** clock. Refreshed lazily
    /// (at most once a minute) so resolving an identity stays a read on all but the occasional request.
    pub last_seen_at: i64,
    pub awaiting_totp: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
