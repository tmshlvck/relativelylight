//! [`BlobStore`] — the type an app holds (BLOBSTORE.md §4.3).

use std::collections::HashSet;
use std::sync::Arc;

use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, TransactionTrait,
};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::observe::{WriteEvent, WriteObserver};
use crate::authz::Operation;

use super::entity::{content, handle, version};
use super::{BlobBackend, BlobError, BlobId, HandleId, VersionId};

/// The metadata cap from BLOBSTORE.md §3.4, enforced on write. An uncapped free-form column is where
/// an app eventually puts megabytes.
pub const MAX_METADATA_BYTES: usize = 64 * 1024;

/// 512 MiB. This is a **policy** limit, not a memory one — uploads stream through a fixed-size chunk
/// buffer (see [`BlobStore::max_bytes`]) — so it is set by what a back-office app should plausibly
/// accept (a long scanned PDF) rather than by what the process can hold.
const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// How much of the leading content is kept back for MIME sniffing. Everything else streams straight
/// through to the backend without ever being held.
const SNIFF_BYTES: usize = 1024;

/// What one streaming store pass produced.
struct Stored {
    id: BlobId,
    size: u64,
    prefix: Vec<u8>,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// What an upload records about itself. Everything here is a fact about *this upload*, which is why
/// none of it lives on the content row (BLOBSTORE.md §3.1).
#[derive(Clone, Debug, Default)]
pub struct PutMeta {
    pub filename: String,
    /// What the uploader claimed. Advisory — compare against [`ContentInfo::mime_sniffed`] if you
    /// want to refuse a mismatch.
    pub mime_declared: String,
    /// The actor's display identity **as a snapshot**, not a key (BLOBSTORE.md §3.3). An app running
    /// `auth` passes `who.username`.
    pub created_by: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

impl PutMeta {
    pub fn new(filename: impl Into<String>) -> Self {
        Self { filename: filename.into(), ..Default::default() }
    }
    pub fn mime(mut self, m: impl Into<String>) -> Self {
        self.mime_declared = m.into();
        self
    }
    pub fn by(mut self, who: impl Into<String>) -> Self {
        self.created_by = Some(who.into());
        self
    }
    pub fn metadata(mut self, v: serde_json::Value) -> Self {
        self.metadata = Some(v);
        self
    }

    fn check(&self) -> Result<(), BlobError> {
        if self.filename.is_empty() {
            return Err(BlobError::Invalid("filename must not be empty".into()));
        }
        if let Some(m) = &self.metadata {
            let n = serde_json::to_string(m).map(|s| s.len()).unwrap_or(usize::MAX);
            if n > MAX_METADATA_BYTES {
                return Err(BlobError::TooLarge { limit: MAX_METADATA_BYTES as u64 });
            }
        }
        Ok(())
    }
}

/// The request a write is attributable to. `Option`-backed, and [`none`](WriteContext::none) is one
/// call, so using the store outside an HTTP handler is not awkward. **Never read at all** unless an
/// observer is registered.
#[derive(Clone, Copy, Default)]
pub struct WriteContext<'a> {
    headers: Option<&'a http::HeaderMap>,
    client_ip: Option<std::net::IpAddr>,
}

impl<'a> WriteContext<'a> {
    /// No request to attribute — a background job, a migration, the thumbnailer. An event fired with
    /// this carries an empty header map and the unspecified address `0.0.0.0`, which is how a sink
    /// tells "no caller" from a real one.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn from(headers: &'a http::HeaderMap, client_ip: std::net::IpAddr) -> Self {
        Self { headers: Some(headers), client_ip: Some(client_ip) }
    }
}

/// One version, as read back. What a listing, an `<img>` tag or a download route needs without
/// opening the content.
#[derive(Clone, Debug)]
pub struct VersionInfo {
    pub id: VersionId,
    pub handle: HandleId,
    pub seq: i32,
    pub prev: Option<VersionId>,
    pub blob: BlobId,
    pub filename: String,
    pub mime_declared: String,
    pub created_by: Option<String>,
    pub created_at: i64,
    pub metadata: Option<serde_json::Value>,
    /// The content row. `None` only if the index is inconsistent, which
    /// [`check_consistency`](BlobStore::check_consistency) reports.
    pub content: Option<ContentInfo>,
}

impl VersionInfo {
    pub fn size_bytes(&self) -> i64 {
        self.content.as_ref().map(|c| c.size_bytes).unwrap_or(0)
    }
}

#[derive(Clone, Debug)]
pub struct ContentInfo {
    pub id: BlobId,
    pub size_bytes: i64,
    pub mime_sniffed: String,
    pub created_at: i64,
    pub verified_at: Option<i64>,
}

/// An **already-verified** byte stream plus the version it came from. `blob-ui`'s `to_response` turns
/// one into an HTTP reply; anything else reads it directly.
///
/// The digest was checked in full *before* this was handed over (see [`BlobStore::read`]), so the
/// stream is safe to forward straight to a client — and because it is a stream, a 500 MiB scan costs
/// the same memory as a one-line note.
///
/// `Debug` deliberately says nothing about the content: this is user data, and a `{:?}` on someone's
/// error path should not put a document in a log file.
pub struct ContentStream {
    pub info: VersionInfo,
    reader: super::Reader,
}

impl ContentStream {
    /// The verified stream, for forwarding to a response body.
    pub fn into_reader(self) -> super::Reader {
        self.reader
    }

    /// Collect the whole thing into memory. Convenient for small documents and tests; for anything
    /// user-sized prefer [`into_reader`](Self::into_reader), which is the reason this type is a
    /// stream in the first place.
    pub async fn into_bytes(self) -> Result<Vec<u8>, BlobError> {
        let mut buf = Vec::new();
        let mut r = self.reader;
        r.read_to_end(&mut buf).await?;
        Ok(buf)
    }
}

impl std::fmt::Debug for ContentStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentStream").field("info", &self.info).finish_non_exhaustive()
    }
}

/// One page of a browse listing.
#[derive(Clone, Copy, Debug)]
pub struct BrowseQuery<'a> {
    /// Substring match against any version's filename. `None` or empty lists everything.
    pub search: Option<&'a str>,
    pub offset: u64,
    pub limit: u64,
}

impl Default for BrowseQuery<'_> {
    fn default() -> Self {
        Self { search: None, offset: 0, limit: 25 }
    }
}

#[derive(Clone, Debug)]
pub struct BrowsePage {
    pub documents: Vec<DocumentSummary>,
    /// Matching documents in total, not on this page — for the pager.
    pub total: u64,
}

/// A document as a listing shows it.
#[derive(Clone, Debug)]
pub struct DocumentSummary {
    pub handle: HandleId,
    /// The current version. `None` only for a handle with no versions at all, which `check_consistency` reports
    /// as drift.
    pub head: Option<VersionInfo>,
    pub versions: u64,
    pub created_at: i64,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CollectReport {
    /// Content whose row and bytes were deleted because no version pointed at it.
    pub deleted: Vec<BlobId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckReport {
    /// **Alarm.** Index rows whose bytes are absent: a version chain points at nothing.
    pub missing: Vec<BlobId>,
    /// **Routine.** Stored bytes the index has never heard of, older than the grace period — the
    /// expected residue of a crash between `write` and the index insert.
    pub orphaned: Vec<BlobId>,
    /// Orphans too young to judge; they may belong to an upload still in flight.
    pub orphans_too_young: usize,
    /// Handles with no version at all — drift, since every path that creates one gives it a first
    /// version in the same transaction. Handles the *app* no longer references are a different
    /// question, and only the app can answer it: see
    /// [`delete_unreferenced_handles`](BlobStore::delete_unreferenced_handles).
    pub orphan_handles: Vec<HandleId>,
    /// **Alarm.** Handles whose `head_version_id` names a version that isn't there. That pointer is
    /// the one column with no foreign key behind it (see `entity::handle`), so this check is what
    /// stands in for the constraint.
    pub dangling_heads: Vec<HandleId>,
    /// How many orphans were actually deleted (zero unless `collect_orphans` was set).
    pub orphans_collected: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct CheckOptions {
    /// Bytes younger than this are never reported as collectable — otherwise the sweep races an
    /// upload that is between `write` and its index insert. `git gc --prune=2.weeks.ago` and
    /// restic's prune take the same precaution.
    pub orphan_grace_secs: i64,
    /// Actually delete collectable orphans, rather than only counting them. Off by default: nothing
    /// can repair a *missing* blob, but an orphan is harmless, so the asymmetry argues for making
    /// the destructive half opt-in.
    pub collect_orphans: bool,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self { orphan_grace_secs: 24 * 3600, collect_orphans: false }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VerifyOptions {
    /// Check the `n` rows with the stalest `verified_at` first. A full sweep over terabytes is
    /// brutal, so this is incremental by default: run nightly and it converges on a full sweep
    /// without ever being one.
    pub oldest: Option<u64>,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self { oldest: Some(1000) }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub checked: usize,
    /// Rows whose stored bytes no longer hash to their id.
    pub corrupt: Vec<BlobId>,
    /// Rows whose bytes are gone entirely.
    pub missing: Vec<BlobId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopyReport {
    pub copied: Vec<BlobId>,
    pub already_present: Vec<BlobId>,
    pub failed: Vec<BlobId>,
}

/// Digest-verified storage with a stable handle and an immutable version chain.
///
/// `B` is normally [`FsBackend`](super::FsBackend); `BlobStore<Box<dyn BlobBackend>>` works too, so
/// an app choosing its backend from configuration keeps one concrete type in its handlers.
pub struct BlobStore<B: BlobBackend = super::FsBackend> {
    backend: B,
    db: DatabaseConnection,
    max_bytes: u64,
    observer: Option<Arc<dyn WriteObserver>>,
}

impl<B: BlobBackend> BlobStore<B> {
    pub fn new(backend: B, db: DatabaseConnection) -> Self {
        Self { backend, db, max_bytes: DEFAULT_MAX_BYTES, observer: None }
    }

    /// The largest upload accepted, enforced **while streaming** and before anything is committed.
    ///
    /// A **policy** limit, not a memory one: content is hashed and written through a fixed 64 KiB
    /// chunk buffer via [`BlobBackend::stage`], so peak memory is the same for a 500 MiB scan as for
    /// a one-line text file. Set it to whatever your app should accept.
    ///
    /// Note that an axum upload route has its own limit in front of this one: `DefaultBodyLimit` is
    /// **2 MB** and applies to any handler using a buffering extractor (`Bytes`, `Json`, `Form`,
    /// `Multipart`). A route that takes `Body` and streams it bypasses that entirely, leaving this
    /// the only limit in play — which is the shape a large upload wants.
    pub fn max_bytes(mut self, n: u64) -> Self {
        self.max_bytes = n;
        self
    }

    /// Register an audit sink. Mirrors `Crud::on_write` / `Auth::on_write` exactly — same trait, same
    /// event — so one sink registered with all three sees a unified trail.
    pub fn on_write(mut self, observer: Arc<dyn WriteObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    // ===================== writes =====================

    /// Create a handle and its **first** version, in one transaction. The returned id is what an
    /// app's own table stores (BLOBSTORE.md §9).
    pub async fn create(
        &self,
        data: impl AsyncRead + Send + Unpin,
        meta: PutMeta,
        ctx: WriteContext<'_>,
    ) -> Result<HandleId, BlobError> {
        meta.check()?;
        let stored = self.store_bytes(data).await?;
        self.record_create(stored, meta, ctx).await
    }

    /// Append a version to an existing handle and move its head onto it. The previous version is
    /// untouched — that is the whole point of the chain.
    pub async fn add_version(
        &self,
        handle: HandleId,
        data: impl AsyncRead + Send + Unpin,
        meta: PutMeta,
        ctx: WriteContext<'_>,
    ) -> Result<VersionId, BlobError> {
        meta.check()?;
        let stored = self.store_bytes(data).await?;
        self.record_version(handle, stored, meta, ctx).await
    }

    /// A new version over the **same content** — a rename, a corrected MIME type, a re-attribution.
    /// No bytes move, and no new content row appears; the chain records that something about the
    /// document changed without pretending the file did.
    pub async fn relabel(
        &self,
        handle: HandleId,
        meta: PutMeta,
        ctx: WriteContext<'_>,
    ) -> Result<VersionId, BlobError> {
        meta.check()?;
        let prev = self.head_row(handle).await?;
        let blob_id = BlobId::try_from(prev.blob_id.clone())?;

        let now = now_secs();
        let txn = self.db.begin().await?;
        let v = insert_version(
            &txn,
            handle,
            prev.seq + 1,
            Some(VersionId(prev.id)),
            &blob_id,
            &meta,
            now,
        )
        .await?;
        set_head(&txn, handle, v).await?;
        txn.commit().await?;

        self.fire(Operation::Update, Some(v), handle, &meta, ctx).await;
        Ok(v)
    }

    /// Delete a handle and its whole chain (the foreign key cascades). Content that no surviving
    /// version references becomes collectable by [`collect_garbage`](Self::collect_garbage) — it is **not** deleted here,
    /// because dedup means these bytes may still be another document's.
    ///
    /// Call this in the same transaction the app deletes its own document row in (BLOBSTORE.md §9.3).
    pub async fn delete_handle(
        &self,
        handle: HandleId,
        ctx: WriteContext<'_>,
    ) -> Result<(), BlobError> {
        let txn = self.db.begin().await?;
        // Clear the head first: it names a version that is about to go.
        handle::Entity::update_many()
            .col_expr(handle::Column::HeadVersionId, sea_orm::sea_query::Expr::value(Option::<i64>::None))
            .filter(handle::Column::Id.eq(handle.uuid()))
            .exec(&txn)
            .await?;
        // Then break the chain's own back-pointers. `prev_version_id` is `RESTRICT` — deliberately,
        // so nothing can be excised from the middle of a history — and a set-based `DELETE … WHERE`
        // gives no row order, so version 1 is as likely to be deleted first as last and the
        // constraint fires on whichever still has a successor. Nulling the column across the handle
        // first turns the delete back into one statement that cannot depend on order.
        version::Entity::update_many()
            .col_expr(version::Column::PrevVersionId, sea_orm::sea_query::Expr::value(Option::<i64>::None))
            .filter(version::Column::HandleId.eq(handle.uuid()))
            .exec(&txn)
            .await?;
        version::Entity::delete_many()
            .filter(version::Column::HandleId.eq(handle.uuid()))
            .exec(&txn)
            .await?;
        handle::Entity::delete_by_id(handle.uuid()).exec(&txn).await?;
        txn.commit().await?;

        self.fire_raw(Operation::Delete, "blob_handle", Some(handle.to_string()), None, None, ctx)
            .await;
        Ok(())
    }

    // ===================== reads =====================

    pub async fn head(&self, handle: HandleId) -> Result<VersionInfo, BlobError> {
        let row = self.head_row(handle).await?;
        self.hydrate(row).await
    }

    pub async fn version(&self, id: VersionId) -> Result<VersionInfo, BlobError> {
        let row = self.version_row(id).await?;
        self.hydrate(row).await
    }

    /// Alias for [`version`](Self::version) — the index row without opening the content.
    pub async fn info(&self, id: VersionId) -> Result<VersionInfo, BlobError> {
        self.version(id).await
    }

    /// One page of **documents** (handles) with their current version — what a browse screen lists.
    ///
    /// Not expressible as an ordinary `MetaModel` listing: the filename lives on `blob_version`, not
    /// on `blob_handle`, and `head_version_id` carries no declared foreign key (the table cycle,
    /// see `entity::handle`), so `crud` cannot auto-join it. This follows the pointer instead.
    ///
    /// Searching matches **any** version's filename, not just the current one, so a document that
    /// was once called something else is still findable under the old name — which is usually what
    /// someone hunting for it remembers.
    pub async fn browse(&self, q: &BrowseQuery<'_>) -> Result<BrowsePage, BlobError> {
        let mut matching: Option<Vec<uuid::Uuid>> = None;
        if let Some(term) = q.search.map(str::trim).filter(|t| !t.is_empty()) {
            let hits = version::Entity::find()
                .filter(version::Column::Filename.contains(term))
                .all(&self.db)
                .await?;
            let mut ids: Vec<uuid::Uuid> = hits.into_iter().map(|v| v.handle_id).collect();
            ids.sort();
            ids.dedup();
            matching = Some(ids);
        }

        let mut find = handle::Entity::find();
        if let Some(ids) = &matching {
            if ids.is_empty() {
                return Ok(BrowsePage { documents: Vec::new(), total: 0 });
            }
            find = find.filter(handle::Column::Id.is_in(ids.clone()));
        }

        let total = find.clone().count(&self.db).await?;
        let rows = find
            .order_by_desc(handle::Column::CreatedAt)
            .order_by_desc(handle::Column::Id)
            .offset(q.offset)
            .limit(q.limit)
            .all(&self.db)
            .await?;

        // One head lookup and one count per row. That is N+1, deliberately: a page is 25 rows, and
        // the alternative is a hand-written join this crate would then owe on every backend.
        let mut documents = Vec::with_capacity(rows.len());
        for h in rows {
            let head = match h.head_version_id {
                Some(id) => match version::Entity::find_by_id(id).one(&self.db).await? {
                    Some(v) => Some(self.hydrate(v).await?),
                    None => None,
                },
                None => None,
            };
            let versions = version::Entity::find()
                .filter(version::Column::HandleId.eq(h.id))
                .count(&self.db)
                .await?;
            documents.push(DocumentSummary {
                handle: HandleId(h.id),
                head,
                versions,
                created_at: h.created_at,
                metadata: h.metadata,
            });
        }
        Ok(BrowsePage { documents, total })
    }

    /// The whole chain, oldest first.
    pub async fn versions(&self, handle: HandleId) -> Result<Vec<VersionInfo>, BlobError> {
        let rows = version::Entity::find()
            .filter(version::Column::HandleId.eq(handle.uuid()))
            .order_by_asc(version::Column::Seq)
            .all(&self.db)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(self.hydrate(r).await?);
        }
        Ok(out)
    }

    /// Open a version's content, **re-hashing while streaming** and comparing against the recorded
    /// digest. A mismatch is [`BlobError::Corrupt`] and no bytes reach the caller; a silent hand-back
    /// of the wrong content is the one thing a content-addressed store must never do.
    ///
    /// Stamps `verified_at` on success, and fires a `Read` event (BLOBSTORE.md §4.7) — this is the
    /// choke point every served byte passes through.
    pub async fn read(
        &self,
        version: VersionId,
        ctx: WriteContext<'_>,
    ) -> Result<ContentStream, BlobError> {
        let info = self.version(version).await?;
        let blob = info.blob.clone();

        // Two passes, deliberately (BLOBSTORE.md §4.3): hash the content through once, then re-open
        // it to serve. That keeps §2's guarantee exact — no unverified byte ever reaches a caller —
        // at constant memory, and on a local filesystem the second read comes off the page cache.
        // A future backend where re-reading is expensive (an object store: a second round trip and
        // a second egress charge) will want a different strategy; see §12.
        self.verify_content(&blob).await?;
        let reader = self.backend.read(&blob).await?;

        content::Entity::update_many()
            .col_expr(
                content::Column::VerifiedAt,
                sea_orm::sea_query::Expr::value(Some(now_secs())),
            )
            .filter(content::Column::Id.eq(blob.as_str()))
            .exec(&self.db)
            .await?;

        let handle = info.handle;
        self.fire_raw(
            Operation::Read,
            "blob_version",
            Some(version.to_string()),
            Some(version),
            Some(handle),
            ctx,
        )
        .await;
        Ok(ContentStream { info, reader })
    }

    /// Digest-verified content by its **address**, collected into memory.
    ///
    /// For the callers that genuinely need the whole thing at once — image decoding cannot be done
    /// incrementally — and addressed by content rather than by version, so it fires **no** `Read`
    /// event: nobody downloaded a document, something re-read one. Serving bytes to a person is
    /// [`read`](Self::read), which is audited.
    pub async fn read_content(&self, id: &BlobId) -> Result<Vec<u8>, BlobError> {
        self.verify_content(id).await?;
        let mut r = self.backend.read(id).await?;
        let mut bytes = Vec::new();
        r.read_to_end(&mut bytes).await?;
        Ok(bytes)
    }

    // ===================== housekeeping =====================

    /// Re-hash stored content without serving it anywhere. Incremental by default — see
    /// [`VerifyOptions::oldest`].
    pub async fn verify(&self, opts: VerifyOptions) -> Result<VerifyReport, BlobError> {
        let mut q = content::Entity::find().order_by_asc(content::Column::VerifiedAt);
        if let Some(n) = opts.oldest {
            q = q.limit(n);
        }
        let rows = q.all(&self.db).await?;

        let mut report = VerifyReport::default();
        for row in rows {
            let Ok(id) = BlobId::try_from(row.id.clone()) else { continue };
            report.checked += 1;
            match self.verify_content(&id).await {
                Ok(()) => {
                    content::Entity::update_many()
                        .col_expr(
                            content::Column::VerifiedAt,
                            sea_orm::sea_query::Expr::value(Some(now_secs())),
                        )
                        .filter(content::Column::Id.eq(id.as_str()))
                        .exec(&self.db)
                        .await?;
                }
                Err(BlobError::Corrupt { .. }) => report.corrupt.push(id),
                Err(BlobError::NotFound(_)) => report.missing.push(id),
                Err(e) => return Err(e),
            }
        }
        Ok(report)
    }

    /// Reconcile the index against the backend, in the two directions whose severities are opposite
    /// (BLOBSTORE.md §4.6): a **missing** blob is data loss, an **orphan** is the routine residue of
    /// the bytes-before-rows ordering.
    pub async fn check_consistency(&self, opts: CheckOptions) -> Result<CheckReport, BlobError> {
        use futures_core::Stream;
        use std::pin::Pin;

        let mut report = CheckReport::default();

        let indexed: HashSet<String> = content::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|r| r.id)
            .collect();

        // index → backend: a row whose bytes are gone.
        for id in &indexed {
            let Ok(bid) = BlobId::try_from(id.clone()) else { continue };
            if !self.backend.exists(&bid).await? {
                report.missing.push(bid);
            }
        }

        // backend → index: bytes nothing has ever heard of.
        let cutoff = now_secs() - opts.orphan_grace_secs;
        let mut stream: Pin<Box<dyn Stream<Item = Result<super::StoredEntry, BlobError>> + Send>> =
            self.backend.list().await?;
        while let Some(entry) = next(&mut stream).await {
            let entry = entry?;
            if indexed.contains(entry.id.as_str()) {
                continue;
            }
            match entry.written_at {
                Some(t) if t <= cutoff => {
                    if opts.collect_orphans {
                        self.backend.delete(&entry.id).await?;
                        report.orphans_collected += 1;
                    }
                    report.orphaned.push(entry.id);
                }
                // Unknown write time counts as too young: the conservative direction, because
                // deleting an in-flight upload is unrecoverable and leaving litter is not.
                _ => report.orphans_too_young += 1,
            }
        }

        // Handles with no version are always drift; disowned ones need the app to say so.
        for h in handle::Entity::find().all(&self.db).await? {
            let id = HandleId(h.id);
            let empty = version::Entity::find()
                .filter(version::Column::HandleId.eq(h.id))
                .count(&self.db)
                .await?
                == 0;
            if empty {
                report.orphan_handles.push(id);
            }
            if let Some(head) = h.head_version_id {
                if version::Entity::find_by_id(head).one(&self.db).await?.is_none() {
                    report.dangling_heads.push(id);
                }
            }
        }

        Ok(report)
    }

    /// Delete stored content that no version points at, and its bytes.
    ///
    /// **Takes no argument and never touches a document.** Safe to run on a timer: it cannot decide
    /// that a document is unwanted, only that some bytes are unreachable — which, since a version is
    /// the only thing that can reference content, is one query rather than a graph walk.
    ///
    /// Content becomes unreachable when the document that held it is deleted
    /// ([`delete_handle`](Self::delete_handle)), or when a
    /// [`relabel`](Self::relabel)/[`add_version`](Self::add_version) leaves an older blob with no
    /// version left pointing at it. Dedup is why deletion is never immediate: the bytes under one
    /// document may be another's, so "delete this document" can never mean "delete these bytes".
    pub async fn collect_garbage(&self) -> Result<CollectReport, BlobError> {
        let referenced: HashSet<String> = version::Entity::find()
            .all(&self.db)
            .await?
            .into_iter()
            .map(|r| r.blob_id)
            .collect();

        let mut report = CollectReport::default();
        for row in content::Entity::find().all(&self.db).await? {
            if referenced.contains(&row.id) {
                continue;
            }
            let Ok(id) = BlobId::try_from(row.id.clone()) else { continue };
            // Row first, then bytes: the reverse would leave a row addressing nothing if we crashed
            // between them, which is the one state `check_consistency` calls an alarm.
            content::Entity::delete_by_id(row.id).exec(&self.db).await?;
            self.backend.delete(&id).await?;
            report.deleted.push(id);
        }
        Ok(report)
    }

    /// Copy every stored blob's **content** to another backend, re-hashing each on the way through
    /// so a copy cannot faithfully reproduce corruption.
    ///
    /// **Content only — this is not a restorable backup on its own.** The index (which documents
    /// exist, their versions, their filenames) lives in the database, and backing that up is the
    /// app's business, as it is for every other table the app owns. What this gives you is the other
    /// half: the bytes, somewhere else, verified.
    pub async fn copy_content_to(&self, dest: &impl BlobBackend) -> Result<CopyReport, BlobError> {
        let mut report = CopyReport::default();
        for row in content::Entity::find().all(&self.db).await? {
            let Ok(id) = BlobId::try_from(row.id.clone()) else { continue };
            if dest.exists(&id).await.unwrap_or(false) {
                report.already_present.push(id);
                continue;
            }
            // Verify, then stream the copy: a backup that faithfully reproduces corruption is
            // worse than one that reports it, and neither pass holds the blob in memory.
            match self.verify_content(&id).await {
                Ok(()) => match self.backend.read(&id).await {
                    Ok(r) => match dest.write(&id, r).await {
                        Ok(()) => report.copied.push(id),
                        Err(_) => report.failed.push(id),
                    },
                    Err(_) => report.failed.push(id),
                },
                Err(_) => report.failed.push(id),
            }
        }
        Ok(report)
    }

    /// Begin a streaming store whose chunks **you** push (BLOBSTORE.md §4.3).
    ///
    /// [`create`](Self::create) and [`put_version`](Self::put_version) take an [`AsyncRead`] and are
    /// the usual way in. This is for a source that isn't one — notably a `multipart/form-data` field,
    /// which yields chunks from a parser rather than implementing `AsyncRead`, and which `blob-ui`'s
    /// upload path drives directly so an upload never lands in memory on its way to the store.
    ///
    /// ```no_run
    /// # async fn f(store: &relativelylight::blob::BlobStore, mut field: impl Iterator<Item = Vec<u8>>) -> Result<(), relativelylight::blob::BlobError> {
    /// # use relativelylight::blob::{PutMeta, WriteContext};
    /// let mut ingest = store.ingest().await?;
    /// for chunk in field {
    ///     ingest.write_chunk(&chunk).await?;   // aborts itself on error
    /// }
    /// let handle = ingest.commit_new(PutMeta::new("scan.pdf"), WriteContext::none()).await?;
    /// # Ok(()) }
    /// ```
    ///
    /// Dropping an `Ingest` without committing discards the staged bytes.
    pub async fn ingest(&self) -> Result<Ingest<'_, B>, BlobError> {
        use sha2::Digest;
        Ok(Ingest {
            store: self,
            staged: Some(self.backend.stage().await?),
            hasher: sha2::Sha256::new(),
            size: 0,
            prefix: Vec::new(),
        })
    }

    // ===================== internals =====================

    /// The index half of a create: handle + first version + head, in one transaction. Split out so
    /// [`Ingest::commit_new`] and [`create`](Self::create) cannot drift apart.
    async fn record_create(
        &self,
        stored: Stored,
        meta: PutMeta,
        ctx: WriteContext<'_>,
    ) -> Result<HandleId, BlobError> {
        let handle = HandleId::new();
        let now = now_secs();
        let txn = self.db.begin().await?;

        handle::ActiveModel {
            id: Set(handle.uuid()),
            head_version_id: Set(None),
            created_at: Set(now),
            metadata: Set(None),
        }
        .insert(&txn)
        .await?;

        upsert_content(&txn, &stored, now).await?;
        let v = insert_version(&txn, handle, 1, None, &stored.id, &meta, now).await?;
        set_head(&txn, handle, v).await?;

        txn.commit().await?;
        self.fire(Operation::Create, Some(v), handle, &meta, ctx).await;
        Ok(handle)
    }

    /// The index half of an append.
    async fn record_version(
        &self,
        handle: HandleId,
        stored: Stored,
        meta: PutMeta,
        ctx: WriteContext<'_>,
    ) -> Result<VersionId, BlobError> {
        let prev = self.head_row(handle).await?;
        let now = now_secs();
        let txn = self.db.begin().await?;
        upsert_content(&txn, &stored, now).await?;
        let v = insert_version(
            &txn,
            handle,
            prev.seq + 1,
            Some(VersionId(prev.id)),
            &stored.id,
            &meta,
            now,
        )
        .await?;
        set_head(&txn, handle, v).await?;
        txn.commit().await?;

        self.fire(Operation::Update, Some(v), handle, &meta, ctx).await;
        Ok(v)
    }

    /// Hash and store in one streaming pass from an [`AsyncRead`]. Convenience over
    /// [`ingest`](Self::ingest), which is the same loop with the chunks pushed in by the caller.
    async fn store_bytes(
        &self,
        mut data: impl AsyncRead + Send + Unpin,
    ) -> Result<Stored, BlobError> {
        let mut ing = self.ingest().await?;
        let mut chunk = vec![0u8; super::fs::CHUNK];
        loop {
            let n = match data.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    ing.abort().await;
                    return Err(e.into());
                }
            };
            if let Err(e) = ing.write_chunk(&chunk[..n]).await {
                ing.abort().await;
                return Err(e);
            }
        }
        ing.finish().await
    }

    /// Read content through, hashing, and confirm it still matches its id. Reads nothing into memory
    /// beyond one chunk, and hands nothing back — the caller re-opens the content to serve it.
    async fn verify_content(&self, id: &BlobId) -> Result<(), BlobError> {
        use sha2::{Digest, Sha256};

        let mut r = self.backend.read(id).await?;
        let mut chunk = vec![0u8; super::fs::CHUNK];
        let mut hasher = Sha256::new();
        loop {
            let n = r.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            hasher.update(&chunk[..n]);
        }
        let found = BlobId::from_digest(hasher.finalize());
        if &found != id {
            return Err(BlobError::Corrupt { expected: id.clone(), found });
        }
        Ok(())
    }

    async fn head_row(&self, handle: HandleId) -> Result<version::Model, BlobError> {
        let h = handle::Entity::find_by_id(handle.uuid())
            .one(&self.db)
            .await?
            .ok_or_else(|| BlobError::NotFound(format!("handle {handle}")))?;
        let head = h
            .head_version_id
            .ok_or_else(|| BlobError::Invalid(format!("handle {handle} has no versions")))?;
        version::Entity::find_by_id(head)
            .one(&self.db)
            .await?
            .ok_or_else(|| BlobError::NotFound(format!("version {head}")))
    }

    async fn version_row(&self, id: VersionId) -> Result<version::Model, BlobError> {
        version::Entity::find_by_id(id.0)
            .one(&self.db)
            .await?
            .ok_or_else(|| BlobError::NotFound(format!("version {id}")))
    }

    async fn hydrate(&self, row: version::Model) -> Result<VersionInfo, BlobError> {
        let blob = BlobId::try_from(row.blob_id.clone())?;
        let content = content::Entity::find_by_id(blob.as_str()).one(&self.db).await?.and_then(|c| {
            BlobId::try_from(c.id.clone()).ok().map(|id| ContentInfo {
                id,
                size_bytes: c.size_bytes,
                mime_sniffed: c.mime_sniffed,
                created_at: c.created_at,
                verified_at: c.verified_at,
            })
        });
        Ok(VersionInfo {
            id: VersionId(row.id),
            handle: HandleId(row.handle_id),
            seq: row.seq,
            prev: row.prev_version_id.map(VersionId),
            blob,
            filename: row.filename,
            mime_declared: row.mime_declared,
            created_by: row.created_by,
            created_at: row.created_at,
            metadata: row.metadata,
            content,
        })
    }

    async fn fire(
        &self,
        op: Operation,
        version: Option<VersionId>,
        handle: HandleId,
        meta: &PutMeta,
        ctx: WriteContext<'_>,
    ) {
        let after = serde_json::json!({
            "handle_id": handle.to_string(),
            "filename": meta.filename,
            "created_by": meta.created_by,
        });
        self.emit(op, "blob_version", version.map(|v| v.to_string()), version, Some(after), ctx)
            .await;
    }

    async fn fire_raw(
        &self,
        op: Operation,
        entity: &str,
        key: Option<String>,
        version: Option<VersionId>,
        handle: Option<HandleId>,
        ctx: WriteContext<'_>,
    ) {
        let after = handle.map(|h| serde_json::json!({ "handle_id": h.to_string() }));
        self.emit(op, entity, key, version, after, ctx).await;
    }

    async fn emit(
        &self,
        op: Operation,
        entity: &str,
        key: Option<String>,
        version: Option<VersionId>,
        after: Option<serde_json::Value>,
        ctx: WriteContext<'_>,
    ) {
        let Some(obs) = &self.observer else { return };
        let empty = http::HeaderMap::new();
        let ev = WriteEvent {
            source: "blob",
            op,
            entity,
            key,
            before: None,
            before_rows: &[],
            after,
            headers: ctx.headers.unwrap_or(&empty),
            client_ip: ctx
                .client_ip
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            version: version.map(|v| v.0),
        };
        obs.on_write(&ev).await;
    }
}

/// A streaming store in progress — see [`BlobStore::ingest`].
///
/// Enforces [`max_bytes`](BlobStore::max_bytes) as chunks arrive, so an oversized upload is refused
/// part-way through rather than after it has all been received. Any error aborts the staged write
/// before returning, so a caller that gives up mid-upload leaves nothing behind.
pub struct Ingest<'a, B: BlobBackend> {
    store: &'a BlobStore<B>,
    /// `None` once finished — which is also what makes `Drop` a no-op in the normal case.
    staged: Option<Box<dyn super::StagedWrite>>,
    hasher: sha2::Sha256,
    size: u64,
    prefix: Vec<u8>,
}

impl<B: BlobBackend> Ingest<'_, B> {
    /// Hash and store one chunk. On error the staged write is already aborted; do not call again.
    pub async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), BlobError> {
        use sha2::Digest;

        let Some(staged) = self.staged.as_mut() else {
            return Err(BlobError::Invalid("ingest already finished".into()));
        };
        self.size += chunk.len() as u64;
        if self.size > self.store.max_bytes {
            let limit = self.store.max_bytes;
            self.abort().await;
            return Err(BlobError::TooLarge { limit });
        }
        if self.prefix.len() < SNIFF_BYTES {
            let want = (SNIFF_BYTES - self.prefix.len()).min(chunk.len());
            self.prefix.extend_from_slice(&chunk[..want]);
        }
        self.hasher.update(chunk);
        if let Err(e) = staged.write_chunk(chunk).await {
            self.abort().await;
            return Err(e);
        }
        Ok(())
    }

    /// Bytes accepted so far.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Commit the content and create a **new handle** with this as its first version.
    pub async fn commit_new(
        mut self,
        meta: PutMeta,
        ctx: WriteContext<'_>,
    ) -> Result<HandleId, BlobError> {
        if let Err(e) = meta.check() {
            self.abort().await;
            return Err(e);
        }
        let stored = self.finish().await?;
        self.store.record_create(stored, meta, ctx).await
    }

    /// Commit the content as a **new version** of an existing handle.
    pub async fn commit_version(
        mut self,
        handle: HandleId,
        meta: PutMeta,
        ctx: WriteContext<'_>,
    ) -> Result<VersionId, BlobError> {
        if let Err(e) = meta.check() {
            self.abort().await;
            return Err(e);
        }
        let stored = self.finish().await?;
        self.store.record_version(handle, stored, meta, ctx).await
    }

    /// Discard the staged bytes. Idempotent.
    pub async fn abort(&mut self) {
        if let Some(mut s) = self.staged.take() {
            s.abort().await;
        }
    }

    /// Commit the content and return its address, with no index row of its own — what
    /// `put_derived` is built from.
    async fn finish(&mut self) -> Result<Stored, BlobError> {
        use sha2::Digest;

        let Some(mut staged) = self.staged.take() else {
            return Err(BlobError::Invalid("ingest already finished".into()));
        };
        let id = BlobId::from_digest(std::mem::take(&mut self.hasher).finalize());
        // Bytes before rows, always (BLOBSTORE.md §4.3). A crash after this and before the caller's
        // transaction commits leaves an orphan, which `fsck` calls routine.
        staged.commit(&id).await?;
        Ok(Stored { id, size: self.size, prefix: std::mem::take(&mut self.prefix) })
    }
}

/// `Stream::next` without pulling in `futures-util` for one call.
async fn next<S, T>(stream: &mut std::pin::Pin<Box<S>>) -> Option<T>
where
    S: futures_core::Stream<Item = T> + ?Sized,
{
    std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
}

async fn upsert_content<C: sea_orm::ConnectionTrait>(
    db: &C,
    stored: &Stored,
    now: i64,
) -> Result<(), BlobError> {
    content::Entity::insert(content::ActiveModel {
        id: Set(stored.id.to_string()),
        size_bytes: Set(stored.size as i64),
        mime_sniffed: Set(sniff_mime(&stored.prefix)),
        created_at: Set(now),
        verified_at: Set(Some(now)),
    })
    // Already there means the identical bytes are already there — a write that turns out to be a
    // no-op is not an error.
    .on_conflict(OnConflict::column(content::Column::Id).do_nothing().to_owned())
    .do_nothing()
    .exec(db)
    .await?;
    Ok(())
}

async fn insert_version<C: sea_orm::ConnectionTrait>(
    db: &C,
    handle: HandleId,
    seq: i32,
    prev: Option<VersionId>,
    blob: &BlobId,
    meta: &PutMeta,
    now: i64,
) -> Result<VersionId, BlobError> {
    let m = version::ActiveModel {
        handle_id: Set(handle.uuid()),
        seq: Set(seq),
        prev_version_id: Set(prev.map(|v| v.0)),
        blob_id: Set(blob.to_string()),
        filename: Set(meta.filename.clone()),
        mime_declared: Set(meta.mime_declared.clone()),
        created_by: Set(meta.created_by.clone()),
        created_at: Set(now),
        metadata: Set(meta.metadata.clone()),
        ..Default::default()
    }
    .insert(db)
    .await?;
    Ok(VersionId(m.id))
}

async fn set_head<C: sea_orm::ConnectionTrait>(
    db: &C,
    handle: HandleId,
    v: VersionId,
) -> Result<(), BlobError> {
    handle::Entity::update_many()
        .col_expr(handle::Column::HeadVersionId, sea_orm::sea_query::Expr::value(Some(v.0)))
        .filter(handle::Column::Id.eq(handle.uuid()))
        .exec(db)
        .await?;
    Ok(())
}

/// Magic-byte sniffing for the handful of types a back-office store actually sees. Deliberately
/// small: this is **advisory** (BLOBSTORE.md §10) — it exists so an app can compare it against what
/// the uploader claimed, never so anything downstream can dispatch on it.
fn sniff_mime(bytes: &[u8]) -> String {
    let m = match bytes {
        [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, ..] => "image/png",
        [0xff, 0xd8, 0xff, ..] => "image/jpeg",
        [b'G', b'I', b'F', b'8', ..] => "image/gif",
        [b'%', b'P', b'D', b'F', ..] => "application/pdf",
        [b'P', b'K', 0x03, 0x04, ..] => "application/zip",
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => "image/webp",
        [b'<', b's', b'v', b'g', ..] => "image/svg+xml",
        _ if bytes.is_empty() => "application/octet-stream",
        _ if std::str::from_utf8(&bytes[..bytes.len().min(1024)]).is_ok() => "text/plain",
        _ => "application/octet-stream",
    };
    m.to_owned()
}
