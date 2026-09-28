//! Content-addressed file storage with a stable handle and an immutable version chain.
//!
//! The full design is **[docs/BLOBSTORE.md](../../../docs/BLOBSTORE.md)**; this is the orientation.
//!
//! # Three identities, not one
//!
//! | Layer | Type | What it is |
//! |---|---|---|
//! | **Content** | [`BlobId`] | the SHA-256 of some bytes; immutable, deduped, shared |
//! | **Version** | [`VersionId`] | one upload — filename, who, when — pointing at content |
//! | **Handle** | [`HandleId`] | the stable id **your own tables hold a foreign key to** |
//!
//! Collapsing these is the classic error. A digest cannot be an app's foreign key: it changes on
//! every edit, and under dedup it cannot carry per-upload metadata (two people uploading the same
//! PDF would share one filename and one attribution). So content is addressed by digest, a *version*
//! records an upload of it, and a *handle* is what never changes. It's the same split as git
//! (blob / commit / ref), an OCI registry (digest / manifest / tag) and S3 (bytes / versionId / key).
//!
//! # No mandatory coupling
//!
//! This module depends on **neither `crud` nor `auth`**. Ownership and per-document access live in
//! the app's own link table — one per document kind, gated with the `authz` presets you already have
//! (BLOBSTORE.md §9). That is not a shortcut: a typed `owner_user_id` in *your* table gets a real
//! foreign key with `ON DELETE RESTRICT`, which is better integrity than this crate could offer, and
//! a table per kind is what makes the per-model gate sufficient for per-document access.
//!
//! # The smallest thing that works
//!
//! ```no_run
//! # async fn f() -> Result<(), relativelylight::blob::BlobError> {
//! use relativelylight::blob::{BlobStore, FsBackend, PutMeta, WriteContext};
//! # let db: sea_orm::DatabaseConnection = todo!();
//!
//! let backend = FsBackend::new("/var/lib/myapp/blobs");
//! backend.init().await?;                       // fail loudly at startup, not on the first upload
//! let store = BlobStore::new(backend, db);
//!
//! let handle = store
//!     .create(&b"hello"[..], PutMeta::new("greeting.txt").by("alice"), WriteContext::none())
//!     .await?;                                 // `handle` is what your own table stores
//!
//! let v = store.head(handle).await?;
//! let content = store.read(v.id, WriteContext::none()).await?;  // digest-verified on the way out
//! # Ok(()) }
//! ```
//!
//! # Housekeeping is yours to schedule
//!
//! Same rule as [`auth::prune`](crate::auth): this crate spawns no tasks. [`BlobStore::verify`],
//! [`BlobStore::check_consistency`] and [`BlobStore::collect_garbage`] return reports; the app runs them.
//!
//! # Writes are ordered, and the order is the contract
//!
//! Bytes reach the backend **before** any row references them, and the rows then land in one
//! transaction. A crash therefore leaves either nothing or unreferenced bytes — never a row pointing
//! at content that isn't there. That asymmetry is why [`CheckReport::orphaned`] is routine and
//! [`CheckReport::missing`] is an alarm.

mod backend;
mod error;
mod fs;
mod id;
mod store;

pub mod entity;

#[cfg(feature = "blob-ui")]
pub mod ui;


#[cfg(test)]
mod tests;

pub use backend::{BlobBackend, Reader, StagedWrite, StoredEntry};
pub use error::BlobError;
pub use fs::FsBackend;
pub use id::{BlobId, HandleId, VersionId};
pub use store::{
    BlobStore, BrowsePage, BrowseQuery, CheckOptions, CheckReport, CollectReport, ContentInfo,
    ContentStream, CopyReport, DocumentSummary, Ingest, PutMeta, VerifyOptions, VerifyReport,
    VersionInfo, WriteContext, MAX_METADATA_BYTES,
};

use sea_orm::sea_query::TableCreateStatement;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, DbErr, Schema};

/// DDL for the three tables, for an app's own migration to apply — mirroring
/// [`auth::table_create_statements`](crate::auth::table_create_statements), and for the same reason:
/// the app owns the database and its migration history, this crate only knows how to describe its own
/// tables.
///
/// The statements carry the foreign keys **and their `ON DELETE` actions** (versions cascade from
/// their handle; content is `RESTRICT`ed while a version points at it), so the guarantees
/// [`BlobStore::collect_garbage`] relies on are enforced by the database rather than by this crate being
/// careful. Order matters — `blob` and `blob_handle` before `blob_version`.
pub fn table_create_statements(backend: DbBackend) -> Vec<TableCreateStatement> {
    use sea_orm::sea_query::Index;

    let schema = Schema::new(backend);
    let mut version = schema.create_table_from_entity(entity::version::Entity);

    // One uniqueness rule the design depends on, emitted as a table constraint so it holds in the
    // database rather than in this crate's discipline: `create_table_from_entity` derives columns,
    // primary keys and foreign keys from an entity, but knows nothing about this.
    //
    // `(handle_id, seq)` is what stops two concurrent `add_version` calls both deciding they are
    // version 4 — without it the loser silently becomes a second version 4 and the chain forks.
    version.index(
        Index::create()
            .name("idx-blob_version-handle-seq")
            .col(entity::version::Column::HandleId)
            .col(entity::version::Column::Seq)
            .unique(),
    );
    vec![
        schema.create_table_from_entity(entity::content::Entity),
        schema.create_table_from_entity(entity::handle::Entity),
        version,
    ]
}

/// Create the blob tables **if they don't already exist** — a bootstrap for a fresh database or the
/// examples, safe to call on every start.
///
/// **Not a migration tool**: it only ever *creates* missing tables, so it won't evolve a schema
/// across library upgrades. For anything long-lived, drive it with `sea-orm-migration` and feed that
/// [`table_create_statements`] instead.
pub async fn migrate(db: &DatabaseConnection) -> Result<(), DbErr> {
    let backend = db.get_database_backend();
    for mut stmt in table_create_statements(backend) {
        stmt.if_not_exists();
        db.execute(backend.build(&stmt)).await?;
    }
    Ok(())
}
