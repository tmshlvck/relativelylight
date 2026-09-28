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
/// [`check_consistency`](super::BlobStore::check_consistency) to find bytes the index has never heard of.
#[derive(Clone, Debug)]
pub struct StoredEntry {
    pub id: BlobId,
    /// Unix seconds the object was written, where the backend knows it. `None` disables the orphan
    /// grace period for that entry, which `check_consistency` treats as "too young to judge" rather than
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
    /// Begin staging content whose address **isn't known yet**.
    ///
    /// This is the primary write path, and the reason it exists rather than just
    /// [`write`](BlobBackend::write): a blob's id is the digest of its bytes, so the store cannot
    /// name the destination until it has read the whole upload. Staging lets it hash and store in
    /// one pass — the alternative is holding the entire upload in memory, which makes `max_bytes`
    /// a RAM limit instead of a policy one.
    ///
    /// For a filesystem this is a temp file that gets fsynced and renamed on
    /// [`commit`](StagedWrite::commit); for an object store, a temp key and a server-side copy.
    async fn stage(&self) -> Result<Box<dyn StagedWrite>, BlobError>;

    /// Durably store `data` under an id that is **already known** — copying a blob to a backup
    /// backend, where the digest came from the index rather than from the bytes in hand.
    ///
    /// **Must not return `Ok` until the content is safe to be referenced.**
    /// [`BlobStore`](super::BlobStore) only inserts the index row after a write returns, so whatever
    /// "durable" means for a given backend, that is the ordering protecting the "no row without
    /// bytes" invariant. Writing an id that already exists is a **success, not an error**: content
    /// addressing makes identical content identical, and two concurrent uploads of the same bytes
    /// are a race with no loser.
    async fn write(&self, id: &BlobId, data: Reader) -> Result<(), BlobError>;

    /// Stream the content back. The backend does **not** need to verify anything — `BlobStore`
    /// re-hashes while streaming and compares against the id it asked for.
    async fn read(&self, id: &BlobId) -> Result<Reader, BlobError>;

    async fn exists(&self, id: &BlobId) -> Result<bool, BlobError>;

    /// Only called by [`collect_garbage`](super::BlobStore::collect_garbage) and
    /// [`check_consistency`](super::BlobStore::check_consistency), and only once nothing references the id. Deleting something
    /// already absent is a success — a collection that crashed half-way must be re-runnable.
    async fn delete(&self, id: &BlobId) -> Result<(), BlobError>;

    /// Enumerate what is actually stored. Needed only by [`check_consistency`](super::BlobStore::check_consistency), to find
    /// bytes the index has never heard of; a filesystem walks its fan-out directories, an object
    /// store pages its listing API. It is on the trait rather than optional because a backend that
    /// cannot be swept cannot be shown to be complete.
    async fn list(&self) -> Result<Pin<Box<dyn Stream<Item = Result<StoredEntry, BlobError>> + Send>>, BlobError>;
}

/// Content being written before its address is known — see [`BlobBackend::stage`].
///
/// Takes `&mut self` rather than consuming `self`, so it stays usable behind `Box<dyn …>`.
/// **Exactly one** of [`commit`](StagedWrite::commit) or [`abort`](StagedWrite::abort) is called,
/// and never both; an implementation should also clean up on drop, since a panic between them is
/// the one path neither covers.
#[async_trait]
pub trait StagedWrite: Send {
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), BlobError>;

    /// Make the staged bytes durably addressable as `id`. Committing over content that already
    /// exists is a success — the bytes are identical by definition.
    async fn commit(&mut self, id: &BlobId) -> Result<(), BlobError>;

    /// Discard the staged bytes. Errors are swallowed: the caller is already on a failure path, and
    /// failing to clean up leaves litter that `check_consistency` collects rather than anything unsafe.
    async fn abort(&mut self);
}

/// So a `Box<dyn BlobBackend>` is itself a backend, and `BlobStore<Box<dyn BlobBackend>>` works —
/// the whole point of keeping the trait dyn-compatible.
#[async_trait]
impl BlobBackend for Box<dyn BlobBackend> {
    async fn stage(&self) -> Result<Box<dyn StagedWrite>, BlobError> {
        (**self).stage().await
    }
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
    async fn stage(&self) -> Result<Box<dyn StagedWrite>, BlobError> {
        (**self).stage().await
    }
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
