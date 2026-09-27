//! [`BlobStore`] — the type an app holds (BLOBSTORE.md §4.3).

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, Set, TransactionTrait,
};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::observe::{WriteEvent, WriteObserver};
use crate::authz::Operation;

use super::entity::{content, handle, variant, version};
use super::{BlobBackend, BlobError, BlobId, HandleId, VersionId};

/// The metadata cap from BLOBSTORE.md §3.4, enforced on write. An uncapped free-form column is where
/// an app eventually puts megabytes.
pub const MAX_METADATA_BYTES: usize = 64 * 1024;

const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

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
    /// `None` once the content has been erased (BLOBSTORE.md §4.8).
    pub blob: Option<BlobId>,
    pub filename: String,
    pub mime_declared: String,
    pub created_by: Option<String>,
    pub created_at: i64,
    pub purged_at: Option<i64>,
    pub metadata: Option<serde_json::Value>,
    /// The content row, absent when the version has been erased.
    pub content: Option<ContentInfo>,
}

impl VersionInfo {
    /// Whether this version's content was deliberately destroyed while its history was kept.
    pub fn is_erased(&self) -> bool {
        self.purged_at.is_some() || self.blob.is_none()
    }

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

/// An open, digest-verified stream plus the version it came from. `blob-ui`'s `to_response` turns one
/// into an HTTP reply; anything else can read it directly.
///
/// `Debug` deliberately prints the byte *count*, never the bytes: this is user content, and a
/// `{:?}` in someone's error path should not put a document into a log file.
pub struct BlobHandle {
    pub info: VersionInfo,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for BlobHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobHandle")
            .field("info", &self.info)
            .field("bytes", &format_args!("<{} bytes>", self.bytes.len()))
            .finish()
    }
}

/// `true` = still referenced, so keep it. Implemented by the app, typically as a `UNION` over its own
/// document tables (BLOBSTORE.md §9) — the crate cannot see those, which is the whole reason this
/// trait exists.
#[async_trait]
pub trait HandleReference: Send + Sync {
    async fn is_referenced(&self, handle: HandleId) -> bool;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PurgeReport {
    /// Content rows whose bytes were deleted because nothing referenced them any more.
    pub content_deleted: Vec<BlobId>,
    /// Handles dropped because the app's [`HandleReference`] disowned them.
    pub handles_deleted: Vec<HandleId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsckReport {
    /// **Alarm.** Index rows whose bytes are absent: a version chain points at nothing.
    pub missing: Vec<BlobId>,
    /// **Routine.** Stored bytes the index has never heard of, older than the grace period — the
    /// expected residue of a crash between `write` and the index insert.
    pub orphaned: Vec<BlobId>,
    /// Orphans too young to judge; they may belong to an upload still in flight.
    pub orphans_too_young: usize,
    /// Handles with no version at all, or (with a checker) that the app disowns.
    pub orphan_handles: Vec<HandleId>,
    /// **Alarm.** Handles whose `head_version_id` names a version that isn't there. That pointer is
    /// the one column with no foreign key behind it (see `entity::handle`), so this check is what
    /// stands in for the constraint.
    pub dangling_heads: Vec<HandleId>,
    /// How many orphans were actually deleted (zero unless `collect_orphans` was set).
    pub orphans_collected: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct FsckOptions {
    /// Bytes younger than this are never reported as collectable — otherwise the sweep races an
    /// upload that is between `write` and its index insert. `git gc --prune=2.weeks.ago` and
    /// restic's prune take the same precaution.
    pub orphan_grace_secs: i64,
    /// Actually delete collectable orphans, rather than only counting them. Off by default: nothing
    /// can repair a *missing* blob, but an orphan is harmless, so the asymmetry argues for making
    /// the destructive half opt-in.
    pub collect_orphans: bool,
}

impl Default for FsckOptions {
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
pub struct BackupReport {
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

    /// The largest upload accepted, enforced **while streaming** rather than after buffering.
    ///
    /// **This is also the per-upload memory cost.** Content must be hashed before the backend can be
    /// told where to put it (the digest *is* the location), so v1 holds the upload in memory to hash
    /// it in one pass. A two-phase `stage`/`commit` pair on [`BlobBackend`] would remove that; it is
    /// recorded as an open question rather than guessed at here. Size this against expected
    /// concurrency, not just against the largest file you want to allow.
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
        let (blob_id, bytes) = self.store_bytes(data).await?;

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

        upsert_content(&txn, &blob_id, bytes.len() as i64, sniff_mime(&bytes), now).await?;
        let v = insert_version(&txn, handle, 1, None, Some(&blob_id), &meta, now).await?;
        set_head(&txn, handle, v).await?;

        txn.commit().await?;
        self.fire(Operation::Create, Some(v), handle, &meta, ctx).await;
        Ok(handle)
    }

    /// Append a version to an existing handle and move its head onto it. The previous version is
    /// untouched — that is the whole point of the chain.
    pub async fn put_version(
        &self,
        handle: HandleId,
        data: impl AsyncRead + Send + Unpin,
        meta: PutMeta,
        ctx: WriteContext<'_>,
    ) -> Result<VersionId, BlobError> {
        meta.check()?;
        let (blob_id, bytes) = self.store_bytes(data).await?;
        let prev = self.head_row(handle).await?;

        let now = now_secs();
        let txn = self.db.begin().await?;
        upsert_content(&txn, &blob_id, bytes.len() as i64, sniff_mime(&bytes), now).await?;
        let v = insert_version(
            &txn,
            handle,
            prev.seq + 1,
            Some(VersionId(prev.id)),
            Some(&blob_id),
            &meta,
            now,
        )
        .await?;
        set_head(&txn, handle, v).await?;
        txn.commit().await?;

        self.fire(Operation::Update, Some(v), handle, &meta, ctx).await;
        Ok(v)
    }

    /// A new version over the **same content** — a rename, a corrected MIME type, a re-attribution.
    /// No bytes move, and no new content row appears; the chain records that something about the
    /// document changed without pretending the file did.
    pub async fn amend(
        &self,
        handle: HandleId,
        meta: PutMeta,
        ctx: WriteContext<'_>,
    ) -> Result<VersionId, BlobError> {
        meta.check()?;
        let prev = self.head_row(handle).await?;
        let blob_id = prev
            .blob_id
            .clone()
            .map(BlobId::try_from)
            .transpose()?;

        let now = now_secs();
        let txn = self.db.begin().await?;
        let v = insert_version(
            &txn,
            handle,
            prev.seq + 1,
            Some(VersionId(prev.id)),
            blob_id.as_ref(),
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
    /// version references becomes collectable by [`purge`](Self::purge) — it is **not** deleted here,
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

    /// Destroy a version's **content** while keeping its place in the history (BLOBSTORE.md §4.8).
    ///
    /// Sets `blob_id = NULL` and `purged_at`, leaving the filename, the attribution and the sequence
    /// number intact, so the record reads *"version 3, uploaded by alice, content destroyed on the
    /// 19th"* rather than going silently discontinuous. The bytes themselves are freed for
    /// [`purge`](Self::purge) once no other version references them.
    pub async fn erase(&self, version: VersionId, ctx: WriteContext<'_>) -> Result<(), BlobError> {
        let row = self.version_row(version).await?;
        let handle = HandleId(row.handle_id);
        let mut am: version::ActiveModel = row.into();
        am.blob_id = Set(None);
        am.purged_at = Set(Some(now_secs()));
        am.update(&self.db).await?;

        self.fire_raw(
            Operation::Delete,
            "blob_version",
            Some(version.to_string()),
            Some(version),
            Some(handle),
            ctx,
        )
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
    ) -> Result<BlobHandle, BlobError> {
        let info = self.version(version).await?;
        let Some(blob) = info.blob.clone() else {
            return Err(BlobError::Erased(version));
        };

        let bytes = self.read_verified(&blob).await?;
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
        Ok(BlobHandle { info, bytes })
    }

    // ===================== variants =====================

    pub async fn variant(
        &self,
        source: &BlobId,
        name: &str,
    ) -> Result<Option<BlobId>, BlobError> {
        let row = variant::Entity::find()
            .filter(variant::Column::BlobId.eq(source.as_str()))
            .filter(variant::Column::Variant.eq(name))
            .one(&self.db)
            .await?;
        row.map(|r| BlobId::try_from(r.derived_blob_id)).transpose()
    }

    pub async fn set_variant(
        &self,
        source: &BlobId,
        name: &str,
        derived: &BlobId,
    ) -> Result<(), BlobError> {
        variant::Entity::insert(variant::ActiveModel {
            blob_id: Set(source.to_string()),
            variant: Set(name.to_owned()),
            derived_blob_id: Set(derived.to_string()),
            generated_at: Set(now_secs()),
            ..Default::default()
        })
        .on_conflict(
            OnConflict::columns([variant::Column::BlobId, variant::Column::Variant])
                .update_columns([variant::Column::DerivedBlobId, variant::Column::GeneratedAt])
                .to_owned(),
        )
        .exec(&self.db)
        .await?;
        Ok(())
    }

    /// Store derived content (a thumbnail, a crop) with no version and no handle: it isn't a
    /// document, it's a rendering of one.
    pub async fn put_derived(&self, data: impl AsyncRead + Send + Unpin) -> Result<BlobId, BlobError> {
        let (id, bytes) = self.store_bytes(data).await?;
        upsert_content(&self.db, &id, bytes.len() as i64, sniff_mime(&bytes), now_secs()).await?;
        Ok(id)
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
            match self.read_verified(&id).await {
                Ok(_) => {
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
    pub async fn fsck(
        &self,
        opts: FsckOptions,
        refs: Option<&dyn HandleReference>,
    ) -> Result<FsckReport, BlobError> {
        use futures_core::Stream;
        use std::pin::Pin;

        let mut report = FsckReport::default();

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
            if empty || matches!(refs, Some(r) if !r.is_referenced(id).await) {
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

    /// Collect content nothing references any more.
    ///
    /// Reachability is computed **inside** the crate: a `blob` row is dead when no
    /// `blob_version.blob_id` and no `blob_variant.derived_blob_id` points at it. `purge(None)` never
    /// touches a handle — the safe default. Passing a [`HandleReference`] additionally drops handles
    /// the app disowns (BLOBSTORE.md §4.6).
    pub async fn purge(
        &self,
        refs: Option<&dyn HandleReference>,
    ) -> Result<PurgeReport, BlobError> {
        let mut report = PurgeReport::default();

        if let Some(checker) = refs {
            for h in handle::Entity::find().all(&self.db).await? {
                let id = HandleId(h.id);
                if !checker.is_referenced(id).await {
                    self.delete_handle(id, WriteContext::none()).await?;
                    report.handles_deleted.push(id);
                }
            }
        }

        let referenced: HashSet<String> = version::Entity::find()
            .filter(version::Column::BlobId.is_not_null())
            .all(&self.db)
            .await?
            .into_iter()
            .filter_map(|r| r.blob_id)
            .chain(
                variant::Entity::find()
                    .all(&self.db)
                    .await?
                    .into_iter()
                    .flat_map(|r| [r.blob_id, r.derived_blob_id]),
            )
            .collect();

        for row in content::Entity::find().all(&self.db).await? {
            if referenced.contains(&row.id) {
                continue;
            }
            let Ok(id) = BlobId::try_from(row.id.clone()) else { continue };
            // Row first, then bytes: the reverse would leave a row addressing nothing if we crashed
            // between them, which is the one state `fsck` calls an alarm.
            content::Entity::delete_by_id(row.id).exec(&self.db).await?;
            self.backend.delete(&id).await?;
            report.content_deleted.push(id);
        }
        Ok(report)
    }

    /// Copy every stored blob to another backend, verifying each digest on the way through.
    pub async fn backup_to(&self, dest: &impl BlobBackend) -> Result<BackupReport, BlobError> {
        let mut report = BackupReport::default();
        for row in content::Entity::find().all(&self.db).await? {
            let Ok(id) = BlobId::try_from(row.id.clone()) else { continue };
            if dest.exists(&id).await.unwrap_or(false) {
                report.already_present.push(id);
                continue;
            }
            match self.read_verified(&id).await {
                Ok(bytes) => {
                    let r: super::Reader = Box::pin(std::io::Cursor::new(bytes));
                    match dest.write(&id, r).await {
                        Ok(()) => report.copied.push(id),
                        Err(_) => report.failed.push(id),
                    }
                }
                Err(_) => report.failed.push(id),
            }
        }
        Ok(report)
    }

    // ===================== internals =====================

    /// Hash and store, enforcing `max_bytes` while reading. Returns the digest and the bytes.
    ///
    /// The content has to be hashed before the backend can be told where to put it — the digest *is*
    /// the location — so v1 reads it into memory once. See [`max_bytes`](Self::max_bytes).
    async fn store_bytes(
        &self,
        mut data: impl AsyncRead + Send + Unpin,
    ) -> Result<(BlobId, Vec<u8>), BlobError> {
        use sha2::{Digest, Sha256};

        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        let mut hasher = Sha256::new();
        loop {
            let n = data.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            if buf.len() as u64 + n as u64 > self.max_bytes {
                return Err(BlobError::TooLarge { limit: self.max_bytes });
            }
            hasher.update(&chunk[..n]);
            buf.extend_from_slice(&chunk[..n]);
        }
        let id = BlobId::from_digest(hasher.finalize());

        // Bytes before rows, always (BLOBSTORE.md §4.3). A crash after this and before the caller's
        // transaction commits leaves an orphan, which `fsck` calls routine.
        let reader: super::Reader = Box::pin(std::io::Cursor::new(buf.clone()));
        self.backend.write(&id, reader).await?;
        Ok((id, buf))
    }

    /// Read content back, re-hashing, and refuse to hand over anything that doesn't match.
    async fn read_verified(&self, id: &BlobId) -> Result<Vec<u8>, BlobError> {
        let mut r = self.backend.read(id).await?;
        let mut bytes = Vec::new();
        r.read_to_end(&mut bytes).await?;
        let found = BlobId::of(&bytes);
        if &found != id {
            return Err(BlobError::Corrupt { expected: id.clone(), found });
        }
        Ok(bytes)
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
        let blob = row.blob_id.clone().map(BlobId::try_from).transpose()?;
        let content = match &blob {
            Some(b) => content::Entity::find_by_id(b.as_str())
                .one(&self.db)
                .await?
                .and_then(|c| {
                    BlobId::try_from(c.id.clone()).ok().map(|id| ContentInfo {
                        id,
                        size_bytes: c.size_bytes,
                        mime_sniffed: c.mime_sniffed,
                        created_at: c.created_at,
                        verified_at: c.verified_at,
                    })
                }),
            None => None,
        };
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
            purged_at: row.purged_at,
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

/// `Stream::next` without pulling in `futures-util` for one call.
async fn next<S, T>(stream: &mut std::pin::Pin<Box<S>>) -> Option<T>
where
    S: futures_core::Stream<Item = T> + ?Sized,
{
    std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await
}

async fn upsert_content<C: sea_orm::ConnectionTrait>(
    db: &C,
    id: &BlobId,
    size: i64,
    mime: String,
    now: i64,
) -> Result<(), BlobError> {
    content::Entity::insert(content::ActiveModel {
        id: Set(id.to_string()),
        size_bytes: Set(size),
        mime_sniffed: Set(mime),
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
    blob: Option<&BlobId>,
    meta: &PutMeta,
    now: i64,
) -> Result<VersionId, BlobError> {
    let m = version::ActiveModel {
        handle_id: Set(handle.uuid()),
        seq: Set(seq),
        prev_version_id: Set(prev.map(|v| v.0)),
        blob_id: Set(blob.map(|b| b.to_string())),
        filename: Set(meta.filename.clone()),
        mime_declared: Set(meta.mime_declared.clone()),
        created_by: Set(meta.created_by.clone()),
        created_at: Set(now),
        purged_at: Set(None),
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
