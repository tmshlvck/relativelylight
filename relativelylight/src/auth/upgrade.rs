//! **Upgrading an existing database to 0.5's `auth` schema** — see `docs/MIGRATION-0.5.md` §3.
//!
//! A database created before 0.5 lacks three tables and six columns. [`migrate`](crate::auth::migrate)
//! creates missing tables but never alters one, so the columns need a migration step of the app's own,
//! and they are needed **before** the upgraded crate runs, whatever features it uses: every read of an
//! account selects the new `auth_user` columns, and every login writes `auth_session.method`.
//!
//! ```ignore
//! // inside a MigrationTrait::up(&self, m: &SchemaManager)
//! use relativelylight::auth::upgrade;
//! for stmt in upgrade::table_create_statements(m.get_database_backend()) { m.create_table(stmt).await?; }
//! for stmt in upgrade::table_alter_statements() { m.alter_table(stmt).await?; }
//! for stmt in upgrade::index_create_statements() { m.create_index(stmt).await?; }
//! ```

use super::{api_key, passkey};
use sea_orm::sea_query::{
    Alias, ColumnDef, Index, IndexCreateStatement, Table, TableAlterStatement, TableCreateStatement,
};
use sea_orm::{DbBackend, Schema};

/// The `CREATE TABLE IF NOT EXISTS` statements for 0.5's new tables: `auth_api_key`,
/// `auth_passkey` and `auth_webauthn_challenge`. `IF NOT EXISTS`, so a database that already has one
/// (an app's own key table renamed to `auth_api_key`, MIGRATION-0.5.md §2) keeps it.
pub fn table_create_statements(backend: DbBackend) -> Vec<TableCreateStatement> {
    let schema = Schema::new(backend);
    let mut stmts = vec![
        schema.create_table_from_entity(api_key::entity::Entity),
        schema.create_table_from_entity(passkey::entity::Entity),
        schema.create_table_from_entity(passkey::challenge::Entity),
    ];
    for t in &mut stmts {
        t.if_not_exists();
    }
    stmts
}

/// The `ALTER TABLE` statements adding 0.5's six columns:
///
/// - `auth_user.passkey_handle` — the WebAuthn user handle;
/// - `auth_user.password_changed_at`, `auth_user.must_change_password` — "password change required";
/// - `auth_session.method`, `auth_session.passkey_class` — how a session was authenticated;
/// - `auth_session.reauth_until` — an SSO account's confirmation at its provider.
///
/// Pair them with [`index_create_statements`]: SQLite can't add a `UNIQUE` column, so the handle's
/// uniqueness is an index of its own. One statement per column, because SQLite takes one column per
/// `ALTER TABLE`.
pub fn table_alter_statements() -> Vec<TableAlterStatement> {
    let add = |table: &str, col: &mut ColumnDef| {
        Table::alter()
            .table(Alias::new(table))
            .add_column(col)
            .to_owned()
    };
    vec![
        add(
            "auth_user",
            ColumnDef::new(Alias::new("passkey_handle")).string().null(),
        ),
        add(
            "auth_user",
            ColumnDef::new(Alias::new("password_changed_at"))
                .big_integer()
                .null(),
        ),
        add(
            "auth_user",
            ColumnDef::new(Alias::new("must_change_password"))
                .boolean()
                .not_null()
                .default(false),
        ),
        add(
            "auth_session",
            ColumnDef::new(Alias::new("method"))
                .string()
                .not_null()
                .default(""),
        ),
        add(
            "auth_session",
            ColumnDef::new(Alias::new("passkey_class")).string().null(),
        ),
        add(
            "auth_session",
            ColumnDef::new(Alias::new("reauth_until")).big_integer().null(),
        ),
    ]
}

/// The unique index on `auth_user.passkey_handle`, for a database upgraded with
/// [`table_alter_statements`]. (A fresh install has the constraint inline.)
pub fn index_create_statements() -> Vec<IndexCreateStatement> {
    vec![Index::create()
        .name("idx-auth_user-passkey_handle")
        .table(Alias::new("auth_user"))
        .col(Alias::new("passkey_handle"))
        .unique()
        .to_owned()]
}
