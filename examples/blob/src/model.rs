//! The app's own tables. **`ticket_document` is the point of this example** — it is
//! BLOBSTORE.md §9's link table, written out.
//!
//! `blob` deliberately stores no owner. A `blob_handle` is an identity and a version chain and
//! nothing else, which is what lets the module depend on neither `crud` nor `auth`. Ownership lives
//! *here*, in the app, where it gets what the library could not have given it:
//!
//! - **A real foreign key onto `auth_user`, with `ON DELETE RESTRICT`.** Deleting a user who still
//!   owns attachments fails — `crud` maps the violation to `409 Conflict` — so an operator has to
//!   reassign first. A `blob`-side `owner_user_id` could only have offered that by making `auth`
//!   mandatory for every consumer of the module.
//! - **A per-kind gate.** `authz::Authz` is `authorize(op, headers)` — per *model*, with no row
//!   argument. That is why row-level access can't live in the library. A table per document kind
//!   dissolves the problem instead of working around it: "may this caller read ticket attachments"
//!   *is* a per-model question, and the gates that already exist answer it. A single
//!   `document(kind, …)` table with a discriminator would need a gate that inspects `kind`, which
//!   the trait cannot express — so many typed tables is the load-bearing choice, not a stylistic one.
//!
//! A second document kind (invoices, say) would be a second table with its own gate, not a `kind`
//! column here.

use sea_orm::entity::prelude::*;
use sea_orm::{ConnectionTrait, Schema};

/// Something to hang documents off.
pub mod ticket {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
    #[sea_orm(table_name = "ticket")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub subject: String,
        pub status: String,
        pub opened_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// One attachment on one ticket: the link between the app's world and the blob store.
pub mod ticket_document {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
    #[sea_orm(table_name = "ticket_document")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub ticket_id: i32,
        /// → `blob_handle.id`. **Never a content digest**: the handle survives every edit of the
        /// document, so this column is written once and never rewritten (BLOBSTORE.md §3.1).
        pub handle_id: Uuid,
        /// → `auth_user.id`, `RESTRICT`. Live state, so deleting the owner must fail rather than
        /// silently orphan or cascade. (Contrast `blob_version.created_by`, which is an immutable
        /// *snapshot string* precisely so it survives the account being deleted — an audit
        /// attribution that vanishes with its user is not one.)
        pub owner_user_id: i32,
        /// The app's own vocabulary. A fixed set the code understands, not centrally enforced.
        pub role: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::ticket::Entity",
            from = "Column::TicketId",
            to = "super::ticket::Column::Id",
            on_delete = "Cascade"
        )]
        Ticket,
        #[sea_orm(
            belongs_to = "relativelylight::auth::user::Entity",
            from = "Column::OwnerUserId",
            to = "relativelylight::auth::user::Column::Id",
            on_delete = "Restrict"
        )]
        Owner,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

/// Create the app's tables. The library's own (`auth`, `blob`) come from their
/// `table_create_statements`; these are ours, and the app owns the ordering.
pub async fn migrate(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    let schema = Schema::new(backend);
    for entity_stmt in [
        schema.create_table_from_entity(ticket::Entity),
        schema.create_table_from_entity(ticket_document::Entity),
    ] {
        let mut stmt = entity_stmt;
        stmt.if_not_exists();
        db.execute(backend.build(&stmt)).await?;
    }
    Ok(())
}
