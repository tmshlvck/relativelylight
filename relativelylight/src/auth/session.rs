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
//!
//! `method` records **how** the session was authenticated ([`Method`]), and `passkey_class` the class
//! of the passkey when one was used, so a policy made stricter can refuse sessions a weaker passkey
//! opened.

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
    /// How the session was authenticated — [`Method`] as stored. Empty for a session created before the
    /// column existed, which reads as `None` from [`Model::method`].
    #[sea_orm(default_value = "")]
    pub method: String,
    /// The [`Class`](super::passkey::Class) of the passkey that opened the session, when one did.
    pub passkey_class: Option<String>,
}

/// How a session was authenticated. `#[non_exhaustive]`: the passkey methods arrive with sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Method {
    /// A password alone, or a password with the second factor still pending (`awaiting_totp`).
    Password,
    /// A password and a TOTP code.
    PasswordTotp,
    /// A password and a recovery code in place of the second factor.
    PasswordRecovery,
    /// An OIDC identity provider.
    Sso,
}

impl Method {
    /// The stored form.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Password => "password",
            Method::PasswordTotp => "password+totp",
            Method::PasswordRecovery => "password+recovery",
            Method::Sso => "sso",
        }
    }

    /// The stored form back; `None` for an empty or unknown value.
    pub fn parse(s: &str) -> Option<Method> {
        match s {
            "password" => Some(Method::Password),
            "password+totp" => Some(Method::PasswordTotp),
            "password+recovery" => Some(Method::PasswordRecovery),
            "sso" => Some(Method::Sso),
            _ => None,
        }
    }
}

impl Model {
    /// How this session was authenticated; `None` for a row from before the column existed.
    pub fn method(&self) -> Option<Method> {
        Method::parse(&self.method)
    }
}

/// `user_id` is a real foreign key onto `auth_user`, **cascading on delete**: deleting an account
/// takes its sessions with it, in the database, whatever route did the deleting (an admin panel's
/// bulk delete, an app's own code, a `DELETE` typed at the console). `identify` refuses an orphaned
/// session anyway — see `security_tests.rs` — but a row that outlives its user is a credential-shaped
/// object nothing owns, and the constraint is what stops one existing at all.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id",
        on_delete = "Cascade"
    )]
    User,
}

impl ActiveModelBehavior for ActiveModel {}
