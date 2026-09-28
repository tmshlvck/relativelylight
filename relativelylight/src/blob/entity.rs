//! The four tables — BLOBSTORE.md §3.2. Plain SeaORM entities, so an app with `crud` + `ui` can
//! register them into the ordinary admin console with no new UI code (§5.3).
//!
//! The foreign keys are declared on the `belongs_to` relations, with their `ON DELETE` actions, so
//! `Schema::create_table_from_entity` emits real constraints — enforced on SQLite too, since `sqlx`
//! sets `PRAGMA foreign_keys = ON`. Which action each one carries is a design statement, not a
//! default:
//!
//! - `blob_version.handle_id` → **Cascade**: versions are the handle's history; deleting the handle
//!   ends it.
//! - `blob_version.blob_id` → **Restrict**: content may not be deleted while a version still points
//!   at it. This is the constraint that makes [`collect_garbage`](super::BlobStore::collect_garbage)'s reachability sweep
//!   safe rather than merely careful — a bug there cannot orphan a version.
//! - `blob_version.prev_version_id` → **Restrict**: the chain is not to be broken in the middle.
//!
//! **A consequence worth knowing before you register these in an admin console.** Because the chain
//! points backwards with `Restrict`, deleting a `blob_handle` row *directly* fails with a foreign-key
//! violation as soon as the document has two versions: the cascade removes them in no particular
//! order, and whichever still has a successor blocks. [`BlobStore::delete_handle`] is the only thing
//! that can delete a document — it clears the back-pointers first, in one transaction.
//!
//! So a console offering a delete button on `blob_handle` or `blob_version` offers one that answers
//! `409 Conflict`, and a `blob_version` create/edit form would write a row outside the store's
//! invariants. **Register both read-only** — and read-only as a *gate*, not merely `read_only`
//! fields, since the fields flag stops a form rewriting a row but leaves the create and delete
//! controls in place. `examples/blob` has a four-line `ReadOnly` gate wrapper.

/// The stable identity (BLOBSTORE.md §3.2). Deliberately almost empty: nothing in here can be wrong,
/// and it is what an app's own tables hold a foreign key to — forever, across every edit.
pub mod handle {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
    #[sea_orm(table_name = "blob_handle")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        /// The current version — **the one mutable pointer in the design** (git's ref). Denormalised
        /// on purpose: without it, listing N handles with their current filenames is a per-row
        /// subquery, which `MetaModel` cannot express.
        ///
        /// Nullable because the handle row is inserted before its first version exists.
        ///
        /// **No declared foreign key**, deliberately: `blob_handle` → `blob_version` →
        /// `blob_handle` is a cycle, and a `CREATE TABLE` that forward-references a table which
        /// doesn't exist yet is rejected by some backends (Postgres among them) however the four
        /// statements are ordered. Breaking the cycle would mean emitting an `ALTER TABLE` after the
        /// fact, i.e. this crate dictating a two-step migration to every app that embeds it.
        ///
        /// So the pointer is maintained transactionally by `BlobStore` — every path that writes a
        /// version sets it in the same transaction — and
        /// [`check_consistency`](super::super::BlobStore::check_consistency) reports any head that doesn't resolve
        /// (`dangling_heads`) as the compensating check.
        pub head_version_id: Option<i64>,
        pub created_at: i64,
        /// Free-form, app-owned, **mutable** (BLOBSTORE.md §3.4). Never ownership or authorization
        /// data — that belongs in the app's own link table, where it can have a real foreign key.
        pub metadata: Option<Json>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// One upload. **Immutable once written**, except the two erasure fields (BLOBSTORE.md §4.8).
pub mod version {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
    #[sea_orm(table_name = "blob_version")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub handle_id: Uuid,
        /// 1, 2, 3… within the handle. Unique with `handle_id`, and **never renumbered** — an erased
        /// version leaves its number behind, so a gap reads as a gap.
        pub seq: i32,
        pub prev_version_id: Option<i64>,
        /// The content. **Not nullable**: a version always has bytes behind it. Destroying content
        /// means deleting the document (`BlobStore::delete_handle`), which takes its whole chain —
        /// there is deliberately no way to hollow out one version and leave the row.
        pub blob_id: String,
        /// The filename **as at this version** — a rename is a new version over the same content.
        pub filename: String,
        /// What the uploader claimed. Advisory, never trusted for dispatch (§10); compare it against
        /// `blob.mime_sniffed` if you want to refuse a mismatch.
        pub mime_declared: String,
        /// An identity **snapshot**, not a key (BLOBSTORE.md §3.3): the username as at upload time,
        /// which survives the account being deleted — as an audit attribution must.
        pub created_by: Option<String>,
        pub created_at: i64,
        /// Free-form, app-owned, **immutable** — facts about *this upload* (§3.4).
        pub metadata: Option<Json>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::handle::Entity",
            from = "Column::HandleId",
            to = "super::handle::Column::Id",
            on_delete = "Cascade"
        )]
        Handle,
        #[sea_orm(
            belongs_to = "super::content::Entity",
            from = "Column::BlobId",
            to = "super::content::Column::Id",
            on_delete = "Restrict"
        )]
        Content,
        #[sea_orm(
            belongs_to = "Entity",
            from = "Column::PrevVersionId",
            to = "Column::Id",
            on_delete = "Restrict"
        )]
        Previous,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

/// The content. Nothing in this row is a fact about *an upload* — only about the bytes. Table `blob`.
///
/// Reached only through a version: nothing else in this crate references content, which is what makes
/// [`collect_garbage`](super::super::BlobStore::collect_garbage) a single question rather than a
/// graph walk.
pub mod content {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
    #[sea_orm(table_name = "blob")]
    pub struct Model {
        /// Lowercase hex SHA-256 — the identity.
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub size_bytes: i64,
        /// Sniffed from the leading bytes. Advisory, never trusted for dispatch (§10).
        pub mime_sniffed: String,
        pub created_at: i64,
        /// When the digest was last confirmed against the stored bytes — by a read, or by a
        /// [`verify`](super::super::BlobStore::verify) sweep. `None` means "not since it was written".
        pub verified_at: Option<i64>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
