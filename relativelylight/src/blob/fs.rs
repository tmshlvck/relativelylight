//! [`FsBackend`] — the filesystem implementation, and the only backend shipped in v1
//! (BLOBSTORE.md §4.2).
//!
//! Layout: `<root>/ab/cd/abcdef0123…`, two-level fan-out off the digest, plus a `<root>/tmp/`
//! staging directory. The fan-out exists because a single directory holding a million entries is a
//! performance cliff on most filesystems; two levels give 65 536 buckets, which is enough that no
//! bucket is pathological before the store is very large indeed.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures_core::Stream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// Streaming chunk size — big enough that syscall overhead is noise, small enough to be irrelevant
/// to peak memory however large the upload is.
pub(crate) const CHUNK: usize = 64 * 1024;

use super::{BlobBackend, BlobError, BlobId, Reader, StagedWrite, StoredEntry};

/// Content-addressed storage on a local filesystem.
pub struct FsBackend {
    root: PathBuf,
}

impl FsBackend {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Create `<root>` and `<root>/tmp`. **Call once at startup**, so a misconfigured path fails
    /// loudly then rather than on the first upload months later.
    pub async fn init(&self) -> Result<(), BlobError> {
        tokio::fs::create_dir_all(self.tmp_dir()).await?;
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    fn path_for(&self, id: &BlobId) -> PathBuf {
        let (a, b) = id.fanout();
        self.root.join(a).join(b).join(id.as_str())
    }
}

#[async_trait]
impl BlobBackend for FsBackend {
    async fn stage(&self) -> Result<Box<dyn StagedWrite>, BlobError> {
        tokio::fs::create_dir_all(self.tmp_dir()).await?;
        let path = self.tmp_dir().join(format!("{}.tmp", uuid::Uuid::now_v7()));
        let file = tokio::fs::File::create(&path).await?;
        Ok(Box::new(StagedFile { root: self.root.clone(), path, file: Some(file) }))
    }

    async fn write(&self, id: &BlobId, mut data: Reader) -> Result<(), BlobError> {
        // The id is already known, so this could write straight to the final path — but going
        // through the same staging machinery means there is exactly one implementation of
        // "durable before visible" to get right.
        let mut staged = self.stage().await?;
        let mut buf = vec![0u8; CHUNK];
        loop {
            match data.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = staged.write_chunk(&buf[..n]).await {
                        staged.abort().await;
                        return Err(e);
                    }
                }
                Err(e) => {
                    staged.abort().await;
                    return Err(e.into());
                }
            }
        }
        staged.commit(id).await
    }

    async fn read(&self, id: &BlobId) -> Result<Reader, BlobError> {
        let path = self.path_for(id);
        match tokio::fs::File::open(&path).await {
            Ok(f) => Ok(Box::pin(f) as Pin<Box<dyn AsyncRead + Send>>),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(BlobError::NotFound(id.to_string()))
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn exists(&self, id: &BlobId) -> Result<bool, BlobError> {
        Ok(tokio::fs::metadata(self.path_for(id)).await.is_ok())
    }

    async fn delete(&self, id: &BlobId) -> Result<(), BlobError> {
        match tokio::fs::remove_file(self.path_for(id)).await {
            Ok(()) => Ok(()),
            // Already gone is success: a collection that crashed half-way has to be re-runnable.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn list(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StoredEntry, BlobError>> + Send>>, BlobError> {
        // The top-level buckets are read eagerly (at most 256 names); everything under each is read
        // one bucket at a time, so peak memory is one 256th of the store rather than all of it.
        let mut buckets = Vec::new();
        let mut dir = tokio::fs::read_dir(&self.root).await?;
        while let Some(e) = dir.next_entry().await? {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name == "tmp" || name.len() != 2 {
                continue; // staging, or something this backend didn't put here
            }
            buckets.push(e.path());
        }
        buckets.sort();
        Ok(Box::pin(FsList { buckets: buckets.into_iter(), pending: None, ready: Vec::new().into_iter() }))
    }
}

/// Lazily walks one top-level bucket at a time (see [`BlobBackend::list`]).
struct FsList {
    buckets: std::vec::IntoIter<PathBuf>,
    #[allow(clippy::type_complexity)]
    pending: Option<
        Pin<Box<dyn std::future::Future<Output = Result<Vec<StoredEntry>, BlobError>> + Send>>,
    >,
    ready: std::vec::IntoIter<StoredEntry>,
}

impl Stream for FsList {
    type Item = Result<StoredEntry, BlobError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let me = self.get_mut();
        loop {
            if let Some(e) = me.ready.next() {
                return Poll::Ready(Some(Ok(e)));
            }
            if let Some(fut) = me.pending.as_mut() {
                return match fut.as_mut().poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(v)) => {
                        me.pending = None;
                        me.ready = v.into_iter();
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        me.pending = None;
                        Poll::Ready(Some(Err(e)))
                    }
                };
            }
            match me.buckets.next() {
                Some(b) => me.pending = Some(Box::pin(scan_bucket(b))),
                None => return Poll::Ready(None),
            }
        }
    }
}

/// Every valid blob under one `<root>/ab/` bucket. Anything whose name isn't a well-formed digest is
/// ignored rather than reported: this crate did not write it, and guessing about it is how a sweep
/// deletes somebody's unrelated file.
async fn scan_bucket(bucket: PathBuf) -> Result<Vec<StoredEntry>, BlobError> {
    let mut out = Vec::new();
    let mut subs = tokio::fs::read_dir(&bucket).await?;
    while let Some(sub) = subs.next_entry().await? {
        if !sub.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let mut files = tokio::fs::read_dir(sub.path()).await?;
        while let Some(f) = files.next_entry().await? {
            let name = f.file_name();
            let Ok(id) = name.to_string_lossy().parse::<BlobId>() else {
                continue;
            };
            let written_at = f
                .metadata()
                .await
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64);
            out.push(StoredEntry { id, written_at });
        }
    }
    Ok(out)
}

/// One in-flight write: a file under `<root>/tmp/` that becomes addressable content on commit.
///
/// This is where "durable before visible" lives. The bytes are fsynced *before* any name points at
/// them, and the containing directory is fsynced after the rename — otherwise a power failure can
/// lose the rename even though the contents were safe, leaving an index row addressing nothing.
struct StagedFile {
    root: PathBuf,
    path: PathBuf,
    /// `None` once committed or aborted, which is what makes `Drop` a no-op in the normal case.
    file: Option<tokio::fs::File>,
}

#[async_trait]
impl StagedWrite for StagedFile {
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), BlobError> {
        let Some(f) = self.file.as_mut() else {
            return Err(BlobError::Invalid("staged write already finished".into()));
        };
        f.write_all(chunk).await?;
        Ok(())
    }

    async fn commit(&mut self, id: &BlobId) -> Result<(), BlobError> {
        let Some(mut f) = self.file.take() else {
            return Err(BlobError::Invalid("staged write already finished".into()));
        };
        f.flush().await?;
        f.sync_all().await?;
        drop(f);

        let (a, b) = id.fanout();
        let dir = self.root.join(a).join(b);
        let final_path = dir.join(id.as_str());

        // Already there means the identical bytes are already there — the id *is* the content.
        // Discard rather than overwrite: rewriting a file something may be reading right now buys
        // nothing, since by definition it would be rewritten with what it already holds.
        if tokio::fs::metadata(&final_path).await.is_ok() {
            let _ = tokio::fs::remove_file(&self.path).await;
            return Ok(());
        }

        tokio::fs::create_dir_all(&dir).await?;
        tokio::fs::rename(&self.path, &final_path).await?;
        if let Ok(d) = tokio::fs::File::open(&dir).await {
            let _ = d.sync_all().await;
        }
        Ok(())
    }

    async fn abort(&mut self) {
        self.file.take();
        let _ = tokio::fs::remove_file(&self.path).await;
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        // Covers the one path neither `commit` nor `abort` does: a panic, or a future dropped
        // mid-upload because the client hung up. Best-effort and synchronous — a blocking unlink of
        // one temp file is cheap, and the alternative is leaving litter for `check_consistency`.
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
