//! [`BlobError`] — BLOBSTORE.md §4.4.

use std::fmt;

use super::BlobId;

/// Everything the store can refuse to do.
#[derive(Debug)]
#[non_exhaustive]
pub enum BlobError {
    /// A backend's own failure, **opaque by design**: `BlobStore` does not know or care whether a
    /// write failed on `ENOSPC` or an S3 timeout, only that it didn't happen. Typing this would mean
    /// enumerating the failure modes of storage systems that don't exist yet.
    Backend(Box<dyn std::error::Error + Send + Sync>),
    Db(sea_orm::DbErr),
    /// The upload exceeded `BlobStore::max_bytes`, or `metadata` exceeded its own cap — caught
    /// **while streaming**, not after buffering (BLOBSTORE.md §10).
    TooLarge { limit: u64 },
    NotFound(String),
    /// The content read back did not hash to the id it was stored under. **No partial bytes reach
    /// the caller** — a silent hand-back of the wrong content is the one thing a content-addressed
    /// store must never do.
    Corrupt { expected: BlobId, found: BlobId },
    BadId(String),
    /// A write that would break the shape of the chain — appending to a handle that doesn't exist,
    /// or amending one with no versions yet.
    Invalid(String),
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlobError::Backend(e) => write!(f, "storage backend: {e}"),
            BlobError::Db(e) => write!(f, "database: {e}"),
            BlobError::TooLarge { limit } => write!(f, "too large: over the {limit}-byte limit"),
            BlobError::NotFound(what) => write!(f, "not found: {what}"),
            BlobError::Corrupt { expected, found } => {
                write!(f, "corrupt: {expected} read back as {found}")
            }
            BlobError::BadId(s) => write!(f, "malformed id: {s:?}"),
            BlobError::Invalid(m) => write!(f, "invalid: {m}"),
        }
    }
}

impl std::error::Error for BlobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BlobError::Backend(e) => Some(&**e),
            BlobError::Db(e) => Some(e),
            _ => None,
        }
    }
}

impl From<sea_orm::DbErr> for BlobError {
    fn from(e: sea_orm::DbErr) -> Self {
        BlobError::Db(e)
    }
}

impl From<std::io::Error> for BlobError {
    fn from(e: std::io::Error) -> Self {
        BlobError::Backend(Box::new(e))
    }
}
