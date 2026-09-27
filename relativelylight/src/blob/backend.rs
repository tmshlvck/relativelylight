//! [`BlobBackend`] — the storage abstraction (BLOBSTORE.md §4.1).
//!
//! A backend's job is narrower than it looks: durably store bytes under an id, hand them back, and
//! enumerate them. **Hashing, dedup, verification and the write-ordering invariant are not its
//! business** — they live once in [`BlobStore`](super::BlobStore), above this trait, so a second
//! backend cannot get them subtly differently.

use std::pin::Pin;

use async_trait::async_trait;
use futures_core::Stream;
use tokio::io::AsyncRead;

use super::{BlobError, BlobId};

/// A boxed byte source. [`BlobStore`](super::BlobStore) boxes what the app handed it before calling
/// [`BlobBackend::write`], so no caller writes `Box::pin` themselves.
pub type Reader = Pin<Box<dyn AsyncRead + Send>>;

/// One stored object as the backend sees it — used only by
/// [`fsck`](super::BlobStore::fsck) to find bytes the index has never heard of.
#[derive(Clone, Debug)]
pub struct StoredEntry {
    pub id: BlobId,
    /// Unix seconds the object was written, where the backend knows it. `None` disables the orphan
    /// grace period for that entry, which `fsck` treats as "too young to judge" rather than
    /// "collectable" — the conservative direction.
    pub written_at: Option<i64>,
}

/// Durable storage for content-addressed bytes.
///
/// **Deliberately dyn-compatible** (BLOBSTORE.md §4.1): [`write`](BlobBackend::write) takes a boxed
/// [`Reader`] rather than `impl AsyncRead`, because a generic method cannot go in a vtable and
/// `Box<dyn BlobBackend>` is what lets an app choose its backend from configuration at runtime —
/// filesystem in development, an object store in production — without the backend type infecting
/// every handler signature.
#[async_trait]
pub trait BlobBackend: Send + Sync + 'static {
    /// Durably store `data` under `id`. **Must not return `Ok` until the content is safe to be
    /// referenced** — for a filesystem that means write-to-temp + fsync + atomic rename; for an
    /// object store, typically just the PUT.
    ///
    /// [`BlobStore`](super::BlobStore) only inserts the index row after this returns, so whatever
    /// "durable" means for a given backend, that is the ordering protecting the "no row without
    /// bytes" invariant. Writing an id that already exists is a **success, not an error**: content
    /// addressing makes identical content identical, and two concurrent uploads of the same bytes
    /// are a race with no loser.
    async fn write(&self, id: &BlobId, data: Reader) -> Result<(), BlobError>;

    /// Stream the content back. The backend does **not** need to verify anything — `BlobStore`
    /// re-hashes while streaming and compares against the id it asked for.
    async fn read(&self, id: &BlobId) -> Result<Reader, BlobError>;

    async fn exists(&self, id: &BlobId) -> Result<bool, BlobError>;

    /// Only called by [`purge`](super::BlobStore::purge) and
    /// [`fsck`](super::BlobStore::fsck), and only once nothing references the id. Deleting something
    /// already absent is a success — a purge that crashed half-way must be re-runnable.
    async fn delete(&self, id: &BlobId) -> Result<(), BlobError>;

    /// Enumerate what is actually stored. Needed only by [`fsck`](super::BlobStore::fsck), to find
    /// bytes the index has never heard of; a filesystem walks its fan-out directories, an object
    /// store pages its listing API. It is on the trait rather than optional because a backend that
    /// cannot be swept cannot be shown to be complete.
    async fn list(&self) -> Result<Pin<Box<dyn Stream<Item = Result<StoredEntry, BlobError>> + Send>>, BlobError>;
}

/// So a `Box<dyn BlobBackend>` is itself a backend, and `BlobStore<Box<dyn BlobBackend>>` works —
/// the whole point of keeping the trait dyn-compatible.
#[async_trait]
impl BlobBackend for Box<dyn BlobBackend> {
    async fn write(&self, id: &BlobId, data: Reader) -> Result<(), BlobError> {
        (**self).write(id, data).await
    }
    async fn read(&self, id: &BlobId) -> Result<Reader, BlobError> {
        (**self).read(id).await
    }
    async fn exists(&self, id: &BlobId) -> Result<bool, BlobError> {
        (**self).exists(id).await
    }
    async fn delete(&self, id: &BlobId) -> Result<(), BlobError> {
        (**self).delete(id).await
    }
    async fn list(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StoredEntry, BlobError>> + Send>>, BlobError> {
        (**self).list().await
    }
}

/// So a shared backend can be handed to more than one store.
#[async_trait]
impl<T: BlobBackend + ?Sized> BlobBackend for std::sync::Arc<T> {
    async fn write(&self, id: &BlobId, data: Reader) -> Result<(), BlobError> {
        (**self).write(id, data).await
    }
    async fn read(&self, id: &BlobId) -> Result<Reader, BlobError> {
        (**self).read(id).await
    }
    async fn exists(&self, id: &BlobId) -> Result<bool, BlobError> {
        (**self).exists(id).await
    }
    async fn delete(&self, id: &BlobId) -> Result<(), BlobError> {
        (**self).delete(id).await
    }
    async fn list(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StoredEntry, BlobError>> + Send>>, BlobError> {
        (**self).list().await
    }
}
