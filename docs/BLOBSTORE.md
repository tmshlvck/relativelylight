# `relativelylight::blob` — content-addressed file storage — DRAFT SPEC

Status: **core implemented** (feature `blob`); **`blob-ui` and `blob-thumbnail` are not**. §§1–4 and
§§9–11 describe shipped behaviour, pinned by `blob/tests.rs`; §5 (viewer, upload form, admin actions)
and §6 (thumbnailer) are still specification. Where building it changed a decision, the section says
so rather than being quietly rewritten.

## 1. Purpose & scope

Every app in this crate's audience ends up storing files — uploads, generated PDFs, photos — and
re-solving the same problems: content that shouldn't silently corrupt, a storage backend that will
someday not be the local filesystem, a stable identifier its own tables can point a foreign key at, a
way to show a preview without shipping a JS viewer library, and an admin page to look at what's
stored.

**Scope, precisely:**

| In scope | Out of scope |
|---|---|
| Content-addressed storage: write once, read back digest-verified | **Ownership** — who a document belongs to, and to what (§9) |
| A **stable handle** app tables can FK to, and its **version chain** | **Row-level authorization** — may *this* caller see *this* document (§9) |
| A backend trait + a shipped filesystem implementation | The download route itself (§5.4) |
| Viewer, upload form, thumbnailer, a companion admin panel | Backup / retention *policy* (what's worth keeping, for how long) |
| Integrity sweeps, backup and purge *mechanisms* | Anything requiring `auth` (§2) |

The right mental model is `auth` vs. an app's own RBAC group taxonomy: this module owns the mechanism
and ships something usable standalone; an app that needs ownership and per-document access builds a
small typed layer on top — and §9 is that layer, written out, because it's the same six lines in every
app.

## 2. Design tenets

**No mandatory coupling — including to `auth`.** `blob` alone (no `crud`, no `auth`, no `observe`
wiring) is a complete, useful library. Every other layer — versioning, UI, thumbnails, audit — is
additive. Ownership *could* have been a typed FK onto `auth_user`, bought with a hard dependency on
`auth`; §9 shows why the app's own table is the better home for it, and why nothing is lost by
keeping it out.

**Three identities, not one.** Content is addressed by digest; a *version* records one upload; a
*handle* is the stable id everything else points at. Collapsing these is the single most common design
error in file storage, and §3 is mostly about why.

**The backend is a trait; correctness is not.** Hashing, dedup, and the write-ordering invariant that
makes a crash leave only garbage (never a dangling row) live once, in `BlobStore`, above the backend
trait — not re-implemented per backend. A backend's job is narrower than it looks: durably store bytes
under an id, hand them back, and enumerate them.

**Derived content is still content.** A thumbnail is a blob like any other — content-addressed, stored
through the same backend, subject to the same verify/purge machinery. No second storage mechanism, no
separate cache invalidation story.

**The viewer never inlines what it didn't generate itself.** Rendered HTML gets an `<img src>` or
`<embed src>` pointing at a route the app serves; raw uploaded bytes are never interpolated into a
page. §10 says why this isn't optional.

**Downloads stay an app route.** The app knows who may see a given document; this crate does not, and
must not guess. `blob` provides the verified byte-stream and an `axum::Response` builder (§5.4); the
app supplies the route and its own authorization — routed by the *owning document*, not by the handle
(§9.2).

## 3. Database schema & migration

Three tables. The split is the heart of the design, so it comes before the DDL.

### 3.1 Why three tables

A content digest is the wrong thing for an app table to hold a foreign key to, for five reasons that
each bite on their own:

1. **Dedup corrupts per-upload metadata.** Two users upload the same PDF under different names. With
   one row keyed by digest, whoever wrote first owns the filename and the attribution, and the second
   upload is silently mis-recorded. Filename and uploader are facts about an *upload*, not about a
   sequence of bytes.
2. **The digest changes on every edit.** An app table FK'd to it must be rewritten whenever the
   document changes — which is exactly the indirection layer every app would end up building.
3. **Purge needs reference *counting*, not a boolean.** One content row can back many documents; "is
   this content still in use" is not a question any single app table can answer.
4. **Erasure lands on dedup.** Destroying one subject's document must not destroy identical bytes
   another tenant legitimately holds. Same counting problem, with a legal deadline.
5. **Width.** 64 hex characters in every referencing table and every index, versus 16 bytes.

So: **content** is addressed by digest, a **version** records one upload of it, and a **handle** is
the stable identity that never changes and that everything else points at. This is the same three-layer
split as git (blob / commit / ref), an OCI registry (layer digest / manifest / tag), S3 (bytes /
`versionId` / key), CMIS (content stream / version / **version series id**) and JCR (binary /
`nt:frozenNode` / referenceable node uuid). It is also, almost exactly, OCFL — the preservation format
built specifically to put versioning over content-addressed storage.

### 3.2 The tables

```rust
/// The stable identity. Deliberately almost empty: nothing in here can be wrong, and it is what an
/// app's own tables hold a foreign key to — forever, across every edit of the document.
#[sea_orm(table_name = "blob_handle")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,                     // v7: time-ordered, so it doesn't scatter the B-tree
    pub head_version_id: Option<i64>, // the current version — the ONE mutable pointer in the design
    pub created_at: i64,              // Unix seconds UTC
    pub metadata: Option<Json>,       // free-form, app-owned, mutable — see §3.4
}
```

```rust
/// One upload. **Immutable once written**, except the erasure fields (§4.8).
#[sea_orm(table_name = "blob_version")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub handle_id: Uuid,              // FK → blob_handle.id, ON DELETE CASCADE
    pub seq: i32,                     // 1, 2, 3… unique (handle_id, seq)
    pub prev_version_id: Option<i64>, // FK → blob_version.id; None on the first
    pub blob_id: Option<String>,      // FK → blob.id; None once the content has been erased (§4.8)
    pub filename: String,             // as at THIS version — a rename is a new version
    pub mime_declared: String,        // what the uploader claimed; advisory, never trusted (§10)
    pub created_by: Option<String>,   // identity **snapshot**, not a key — see §3.3
    pub created_at: i64,
    pub purged_at: Option<i64>,       // set when the content was erased out from under this version
    pub metadata: Option<Json>,       // free-form, app-owned, immutable — see §3.4
}
// unique (handle_id, seq)
```

```rust
/// The content. Nothing in this row is a fact about *an upload* — only about the bytes.
#[sea_orm(table_name = "blob")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,              // lowercase hex SHA-256 — the identity
    pub size_bytes: i64,
    pub mime_sniffed: String,    // sniffed from the content; advisory, never trusted for dispatch (§10)
    pub created_at: i64,
    pub verified_at: Option<i64>,
}
```

```rust
#[sea_orm(table_name = "blob_variant")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub blob_id: String,         // FK → blob.id, the source
    pub variant: String,         // "thumb" | "mobile" | "desktop", or an app's own string — §6
    pub derived_blob_id: String, // FK → blob.id, the generated content
    pub generated_at: i64,
}
// unique (blob_id, variant)
```

**`prev_version_id` only — there is no `next`.** Storing both directions means appending a version
*rewrites the previous row*, which destroys the property that makes version rows usable as a record at
all, and adds a write race for nothing. "Next" is a query (`WHERE prev_version_id = ?`) or `seq + 1`.
The single mutable pointer in the whole design is `blob_handle.head_version_id` — git's ref, exactly.

**`head_version_id` carries no foreign key** — corrected during implementation, where the original
plan (declare it, rely on nullability to break the cycle) turned out not to work. Nullability lets you
*insert* around a cycle; it does nothing for `CREATE TABLE`, where `blob_handle` referencing
`blob_version` referencing `blob_handle` means one of the two statements forward-references a table
that does not exist yet. No ordering of the four statements fixes that, and backends differ on whether
they tolerate it (Postgres does not). Declaring it would mean shipping an `ALTER TABLE` step — this
crate dictating a two-phase migration to every app that embeds it, to constrain one column.

So the pointer is maintained transactionally instead (every path that writes a version sets it in the
same transaction), and `fsck` reports any head that doesn't resolve as `dangling_heads`, at the same
severity as a missing blob. It is the one integrity rule here enforced by a sweep rather than by the
database, and it is called out as such rather than assumed.

`head_version_id` is denormalised on purpose — without it, an admin listing of N handles showing each
current filename is a per-row subquery that `MetaModel` cannot express.

**The two uniqueness rules are emitted as table constraints**, not left as comments:
`blob_version(handle_id, seq)` and `blob_variant(blob_id, variant)`. The first is what stops two
concurrent `put_version` calls both deciding they are version 4 and forking the chain; the second is
both an integrity rule and a prerequisite, since `set_variant`'s upsert names it as its conflict
target and an `ON CONFLICT` with no matching unique index is an error rather than a no-op.
`Schema::create_table_from_entity` derives columns, primary keys and foreign keys from an entity and
knows about neither, so `table_create_statements` adds them.

### 3.3 `created_by` is a snapshot string, and it is *state*, not audit

An app running `auth` passes `who.username`; an app with its own actor concept (an API key label, a
service name) passes that. It is deliberately **not** a foreign key, and deliberately **not** left to
the audit log:

- **It cannot be an FK** without `blob` depending on `auth`, which §2 refuses. But a typed FK would
  have been near-worthless here anyway: an audit-grade attribution must survive the account being
  deleted, which rules out `RESTRICT` (users become undeletable the moment they upload anything) and
  `CASCADE` (absurd), leaving `SET NULL` — which erases the very fact the column exists to hold.
  Denormalising the identity into the row is what audit practice calls for, not a compromise:
  OCFL's `inventory.json` gives each version a `user` block of `{name, address}` for precisely this
  reason, and a git commit carries an author string, not a pointer into a user registry.
- **It cannot live only in an audit log.** Auditing is optional in this crate by design (§4.7), and an
  app's log is subject to its own retention. A version history that goes anonymous when no observer is
  registered, or when the log rolls over, is not a version history.
- **It must be a column, not a metadata key.** `LogicalType::Json` is explicitly excluded from
  sorting (`crud/seaorm.rs`), and JSON isn't a filterable cell. "Who uploaded this" is the single most
  likely filter on a document history; as a column it gets a sortable header, `?filter[created_by]=…`,
  search and a CSV column. As a key inside a bag it gets a `<textarea>`. And left to convention, one
  app writes `created_by`, the next writes `uploader`, and nothing the crate ships can render either.

The app's own table is where a *typed, FK'd, integrity-enforced* owner lives (§9) — that column is
live state and wants entirely different delete semantics from this one.

### 3.4 `metadata` — the escape hatch, on both tables

Two columns, same type, opposite natures:

| | `blob_version.metadata` | `blob_handle.metadata` |
|---|---|---|
| Nature | **Immutable**, frozen with the row | **Mutable**, current state |
| For | facts about *this upload*: source system, scanner, ingest job id, change reason, the sender's own checksum, original path | facts about the *document over time*: classification, retention class, an external document number |

Three rules, all enforced or documented rather than hoped for:

- **Never put ownership or authorization data in `blob_handle.metadata`.** That is what the app's
  document table (§9) is for, where it is a typed column with a real foreign key, a delete policy and
  a gate. In a JSON bag it has none of those, and the integrity §9 exists to provide is gone.
- **Capped at 64 KiB** on write (`BlobError::TooLarge`). An uncapped free-form column is where an app
  eventually puts megabytes.
- **No secrets.** Both columns are rendered in the admin panel and land in `WriteEvent.before`/`after`.
  The crate's emitters redact the secrets they *know* (password hashes, TOTP secrets); they cannot
  redact an app's arbitrary JSON.

Don't design queries against them: not sortable, not filterable. Wanting to query inside the bag is
the signal to promote the field to a real column in the app's own table.

`blob_handle.metadata` is the weaker of the two, and honestly so: for any app following §9, its own
document table is a better home for everything that would go in it. Its constituency is the §8 app
with no document table at all. One nullable column, breaking to add later — so it ships, documented
narrowly rather than advertised.

### 3.5 Migration

```rust
for stmt in relativelylight::blob::table_create_statements(backend) {
    manager.create_table(stmt).await?;
}
```

`table_create_statements` mirrors `auth::table_create_statements`, for the same reason: the app owns
the database and its migration history; this crate only knows how to describe its own tables. SeaORM's
`Schema::create_table_from_entity` emits the foreign keys from the entities' `belongs_to` relations,
including their `ON DELETE` actions, so the constraints above are real on every backend — and `sqlx`
sets `PRAGMA foreign_keys = ON`, so they are enforced on SQLite too, not just Postgres.

## 4. Rust API

### 4.1 `BlobBackend` — the storage abstraction

```rust
#[async_trait]
pub trait BlobBackend: Send + Sync + 'static {
    /// Durably store `data` under `id`. Must not return `Ok` until the content is safe to be
    /// referenced — for a filesystem this means write-to-temp + fsync + atomic rename; for an
    /// object store, typically just the PUT. `BlobStore` only inserts the index row after this
    /// returns `Ok`, so whatever "durable" means for a given backend, that's the ordering that
    /// protects the "no row without bytes" invariant.
    async fn write(&self, id: &BlobId, data: Reader) -> Result<(), BlobError>;

    /// Stream the content back. `BlobStore::get` re-hashes while streaming and compares against
    /// `id` — the backend does not need to verify anything itself.
    async fn read(&self, id: &BlobId) -> Result<Pin<Box<dyn AsyncRead + Send>>, BlobError>;

    async fn exists(&self, id: &BlobId) -> Result<bool, BlobError>;

    /// Only called by `purge` (§4.6), and only after the index row is gone.
    async fn delete(&self, id: &BlobId) -> Result<(), BlobError>;

    /// Enumerate stored ids, with the time each was written where the backend knows it. Needed only
    /// by `fsck` (§4.6) to find bytes the index has never heard of; a filesystem walks its fan-out
    /// directories, an object store pages `ListObjectsV2`. It is on the trait rather than optional
    /// because a backend that cannot be swept cannot be trusted to be complete.
    async fn list(&self) -> Result<Pin<Box<dyn Stream<Item = Result<StoredEntry, BlobError>> + Send>>, BlobError>;
}

pub struct StoredEntry { pub id: BlobId, pub written_at: Option<i64> }

/// A boxed byte source. `BlobStore` boxes what the app handed it before calling `write`.
pub type Reader = Pin<Box<dyn AsyncRead + Send>>;

/// So a `Box<dyn BlobBackend>` is itself a backend — see below.
#[async_trait]
impl BlobBackend for Box<dyn BlobBackend> { /* forwards */ }
```

**`write` takes a boxed reader, not `impl AsyncRead`, so the trait is dyn-compatible.** A generic
method cannot go in a vtable — that is base Rust, nothing to do with `#[async_trait]`, which handles
`impl Trait` arguments happily by desugaring them to generics. Taking `impl AsyncRead` would compile
and would still leave `Box<dyn BlobBackend>` rejected, which costs two things worth more than the one
allocation per upload it saves: an app could not choose its backend from configuration at runtime
(filesystem in development, object store in production is the obvious case), and `B` would have to be
threaded through every type that touches a store, including `Actions<'a, B>` and every handler
signature mentioning one.

The ergonomics stay on the *app-facing* side regardless: `BlobStore::create` and `put_version` take
`impl AsyncRead + Send + Unpin` and do the boxing themselves, so no caller ever writes `Box::pin`.

### 4.2 `FsBackend` — the shipped implementation

```rust
pub struct FsBackend { root: PathBuf }

impl FsBackend {
    pub fn new(root: impl Into<PathBuf>) -> Self;
    /// Create `<root>/{tmp,ab,…}`. Call once at startup so a misconfigured path fails loudly then,
    /// not on the first upload months later.
    pub async fn init(&self) -> Result<(), BlobError>;
}
```

Layout: `<root>/ab/cd/abcdef0123…`, two-level fan-out, a `<root>/tmp/` staging directory. `write`
streams to a temp file (the caller already knows the id — it computed it), fsyncs, and renames into
place; if the target already exists, it discards the temp file rather than erroring — identical content
is identical.

**An S3/Ceph backend is not shipped in v1.** The trait exists to make one possible without touching
`BlobStore`; §11 records the decision.

### 4.3 `BlobStore` — the type an app holds

```rust
pub struct BlobStore<B: BlobBackend = FsBackend> { /* backend, db, max_bytes, observer */ }

impl<B: BlobBackend> BlobStore<B> {
    pub fn new(backend: B, db: DatabaseConnection) -> Self;
    pub fn max_bytes(self, n: u64) -> Self;   // default 64 MiB, enforced while streaming

    /// Optional. Mirrors `Crud::on_write` / `Auth::on_write` exactly — same `WriteObserver` trait
    /// (`crate::observe`), same event shape, so one sink registered with all three sees a unified
    /// trail. An app with no auditing requirement simply never calls this.
    pub fn on_write(self, observer: Arc<dyn WriteObserver>) -> Self;

    // ---- handles and versions -------------------------------------------------------------

    /// Create a handle and its **first** version in one transaction, streaming `data` and hashing as
    /// it goes. Returns the new handle — this is what an app's own table stores.
    pub async fn create(&self, data: impl AsyncRead + Send + Unpin, meta: PutMeta, ctx: WriteContext<'_>)
        -> Result<HandleId, BlobError>;

    /// Append a version to an existing handle and move `head_version_id` onto it. The previous
    /// version is untouched — that is the whole point of the chain.
    pub async fn put_version(&self, handle: HandleId, data: impl AsyncRead + Send + Unpin,
                             meta: PutMeta, ctx: WriteContext<'_>) -> Result<VersionId, BlobError>;

    /// A new version over the **same content** — a rename, a metadata correction, a re-attribution.
    /// No bytes move.
    pub async fn amend(&self, handle: HandleId, meta: PutMeta, ctx: WriteContext<'_>)
        -> Result<VersionId, BlobError>;

    pub async fn head(&self, handle: HandleId) -> Result<VersionInfo, BlobError>;
    pub async fn versions(&self, handle: HandleId) -> Result<Vec<VersionInfo>, BlobError>;
    pub async fn version(&self, id: VersionId) -> Result<VersionInfo, BlobError>;

    /// Delete a handle, its versions, and its handle-level metadata. Content that no surviving
    /// version references becomes collectable by `purge` (§4.6). Call this in the same transaction
    /// the app deletes its own document row in.
    pub async fn delete_handle(&self, handle: HandleId, ctx: WriteContext<'_>) -> Result<(), BlobError>;

    // ---- content --------------------------------------------------------------------------

    /// Open a version's content, hashing while streaming and comparing to the recorded digest. A
    /// mismatch is `BlobError::Corrupt` — no partial bytes reach the caller — never a silent
    /// hand-back of wrong content. On success, stamps `verified_at` and fires a `Read` event (§4.7).
    pub async fn read(&self, version: VersionId, ctx: WriteContext<'_>) -> Result<BlobHandle, BlobError>;

    /// The version row without opening the content — for a listing or an `<img>` tag that only needs
    /// size/mime/filename.
    pub async fn info(&self, version: VersionId) -> Result<VersionInfo, BlobError>;

    // ---- housekeeping (§4.6) --------------------------------------------------------------

    pub async fn verify(&self, opts: VerifyOptions) -> Result<VerifyReport, BlobError>;
    pub async fn fsck(&self, opts: FsckOptions) -> Result<FsckReport, BlobError>;
    pub async fn purge(&self, refs: Option<&dyn HandleReference>) -> Result<PurgeReport, BlobError>;
    pub async fn backup_to(&self, dest: &impl BlobBackend) -> Result<BackupReport, BlobError>;
    pub async fn erase(&self, version: VersionId, ctx: WriteContext<'_>) -> Result<(), BlobError>;  // §4.8
}
```

```rust
pub struct PutMeta {
    pub filename: String,
    pub mime_declared: String,
    pub created_by: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

pub struct WriteContext<'a> { /* headers + client_ip, both optional */ }
impl<'a> WriteContext<'a> {
    pub fn none() -> Self;                                      // background jobs — no request to attribute
    pub fn from(headers: &'a HeaderMap, client_ip: IpAddr) -> Self;
}
```

Every mutating call and `read` takes a `WriteContext`, matching how every other write path in this
crate carries `headers`/`client_ip` — but it's `Option`-backed and `::none()` is one call, so nothing
about using the store outside an HTTP handler is awkward. If no observer is registered the context is
never read.

**Content is buffered in memory while it is hashed — v1's one real limitation.** The digest *is* the
storage location, so it must be known before the backend can be told where to put anything; with
[`BlobBackend::write`] as specified, that means reading the upload into memory to hash it in one pass.
`max_bytes` (default 64 MiB) is therefore also the per-upload **memory** cost, and should be sized
against expected concurrency rather than only against the largest file to be allowed. The fix is a
two-phase `stage`/`commit` pair on the backend trait (stage to a temp location while hashing, then
commit under the computed digest — a temp file and a rename for a filesystem, a multipart upload and a
copy for an object store); it is §12's first open question rather than something guessed at here.

**Write ordering, and where the transaction starts.** Every content-writing call follows the same
three phases, and the order is the invariant §4.6's `fsck` is designed around:

1. **Hash and store the bytes.** Stream into the backend's `write`, computing the digest as it goes
   and enforcing `max_bytes`. No database work has happened yet.
2. **Open a transaction**, and in it: insert the `blob` row if the digest is new (a conflicting insert
   is a no-op, not an error — identical content is identical), insert the `blob_version` row, and
   update `blob_handle.head_version_id` to point at it. `create` additionally inserts the handle
   itself, with a null head, before the version.
3. **Commit.**

Bytes before rows, always. A crash anywhere leaves either nothing or unreferenced bytes — never a row
pointing at content that isn't there, which is the one failure the index cannot recover from. That
asymmetry is why `fsck` treats an orphan as routine and a missing blob as an alarm, and it only holds
if every path writes in this order; it is stated here rather than left to be rediscovered three times.

**`HandleId`** is a `Uuid` newtype; **`VersionId`** an `i64` newtype; **`BlobId`** a thin newtype over
the 64-lowercase-hex digest (`FromStr`/`Display`/`TryFrom<&str>` rejecting malformed input). A digest
is never client-supplied, and now a type that can't be constructed otherwise rather than a convention.

### 4.4 Errors

```rust
pub enum BlobError {
    Backend(Box<dyn std::error::Error + Send + Sync>),  // a backend's own failure, opaque by design
    Db(DbErr),
    TooLarge { limit: u64 },
    NotFound(String),
    Corrupt { expected: BlobId, found: BlobId },
    Erased(VersionId),          // the version exists; its content was destroyed (§4.8)
    BadId(String),
}
```

`Backend` is intentionally opaque — `BlobStore` doesn't know or care whether a backend failure was a
filesystem `ENOSPC` or an S3 timeout, only that the write didn't happen.

### 4.5 Derived content and `blob_variant`

A thumbnail is produced by hashing its own bytes and storing them exactly like any upload — it becomes
a `blob` row like any other, with no version and no handle (it isn't a document; it's a rendering of
one). `blob_variant` records which derived blob answers which `(source, variant)` pair, so a caller can
ask "does `desktop` already exist for this content" without regenerating it.

```rust
impl<B: BlobBackend> BlobStore<B> {
    pub async fn variant(&self, source: &BlobId, variant: &str) -> Result<Option<BlobId>, BlobError>;
    pub async fn set_variant(&self, source: &BlobId, variant: &str, derived: &BlobId) -> Result<(), BlobError>;
}
```

Variants hang off **content**, not off a version — two versions with identical bytes share one
thumbnail, and a rename doesn't regenerate anything. `blob::thumb` (§6) is the only thing in this crate
that calls `set_variant`; nothing stops an app registering its own derived content (an OG-image crop)
the same way.

### 4.6 Housekeeping: `verify`, `fsck`, `purge`, `backup_to`

Nothing here is scheduled by this crate — same rule as `auth::prune`: it returns a report, **the app
schedules it**.

**`purge`** collects content by *reachability*, which the crate can now compute itself: a `blob` row is
dead when no `blob_version.blob_id` and no `blob_variant.derived_blob_id` points at it. Variant rows
are reference edges like any other, and a variant whose source dies goes with it.

But reachability has a precondition worth stating plainly: **if handles are never deleted, no content
ever becomes unreachable and `purge` does nothing.** Content is freed by exactly three routes, and an
app needs at least one of them:

1. `delete_handle` — the normal case, called alongside the app's own document row.
2. A retention prune of *versions* (keep the last K, or the last N years) — app policy, app-driven.
3. `erase` — §4.8, for content that must be destroyed while its history survives.

**`HandleReference`** is the sweeper for route 1 gone wrong. Foreign keys stop an app deleting a
handle something still points at, but deleting the app's *document* row doesn't cascade upward, so a
handle can be left behind. The crate cannot see this; only the app can:

```rust
#[async_trait]
pub trait HandleReference: Send + Sync {
    /// `true` = still referenced. Typically a UNION over the app's own document tables (§9).
    async fn is_referenced(&self, handle: HandleId) -> bool;
}
```

`purge(None)` collects unreachable *content* only and never touches a handle — the safe default.
`purge(Some(&checker))` additionally deletes handles the app disowns. An app that calls
`delete_handle` diligently never needs the checker; one that wants a safety net implements six lines
of `UNION`.

**`fsck`** reconciles the index against the backend, in two directions whose severities are opposite:

| Finding | Meaning | Severity |
|---|---|---|
| **missing** | a `blob` row whose bytes are absent from the backend | **Alarm.** Data loss; a version chain points at nothing. |
| **orphaned** | bytes the index has never heard of | **Expected.** The §4.1 write ordering is bytes-then-row precisely so a crash leaves this, never the reverse. |
| **orphan handle** | a handle with no version, or (with a `HandleReference`) one nothing references | Drift; report a count even without a checker, so it's visible before it's large. |

Orphaned bytes are only collected past a grace period (`FsckOptions::orphan_grace_secs`, default 24 h,
measured from `StoredEntry::written_at`) — otherwise the sweep races an upload that is mid-flight
between `write` and the index insert. `git gc --prune=2.weeks.ago` and restic's prune take the same
precaution for the same reason.

**`verify`** re-hashes content without serving it anywhere. A full sweep over terabytes is brutal, so
it is incremental by default: `VerifyOptions::oldest(n)` takes the `n` rows with the stalest
`verified_at`, which turned into a nightly job converges on a full sweep without ever being one.

**`backup_to`** copies content to another `BlobBackend` (local→S3, local→a second local path for
offline media), verifying each digest as it goes and reporting what copied, what was already present,
and what failed. Deliberately just a mechanism — *what's worth keeping, for how long* is retention
policy, which §12 does not attempt to settle.

### 4.7 The write observer, and reads

`create` / `put_version` / `amend` / `delete_handle` / `erase` / `purge` fire the existing
`observe::WriteObserver` with `source: "blob"` and the `WriteEvent` shape `crud` and `auth` already
use. One sink registered with `BlobStore::on_write`, `Crud::on_write` and `Auth::on_write` sees one
unified trail; register it with none of them and pay nothing.

**Reads fire too**, because a download of regulated content is itself compliance-weight. This needs no
new type: `WriteEvent.op` is `authz::Operation`, which has carried `Read` and `List` since the gate
trait existed — only `observe.rs`'s doc comment, which still says "Create / Update / Delete", needs
correcting. Three things that *are* decisions, settled here:

- **Where the version goes.** `WriteEvent` gains a `version: Option<VersionId>` field. It is
  `#[non_exhaustive]`, so this is additive; `entity` is `"blob_version"` and `key` the version id,
  with the handle id in `after`.
- **Variants do not fire.** A gallery page with twenty thumbnails would otherwise write twenty audit
  rows per view. `BlobStore::read` on a *version* fires; a variant fetch does not. An app that wants
  thumbnail-level telemetry has an access log for it.
- **Denied reads are the app's to record.** Because the download route and its authorization are the
  app's (§5.4), `read` only ever sees calls that already passed. A refusal never reaches this crate.
  Apps in regimes that require failed-access records must log them at their own gate — the crate says
  so rather than implying coverage it doesn't have.

The trait is still named `WriteObserver`/`WriteEvent` while carrying reads. Renaming is a breaking
change for a marginal gain; the names stay and the docs say what they cover.

### 4.8 Erasure — destroying content without destroying the record

A subject-access erasure ("delete every copy of this person's document") and an audit trail ("the
history must show what happened") are in direct conflict if a version row is the only record and
deleting it is the only way to free the bytes. The resolution is the one records management and S3's
delete markers both use — destroy the content, keep the entry:

```rust
pub async fn erase(&self, version: VersionId, ctx: WriteContext<'_>) -> Result<(), BlobError>;
```

Sets `blob_id = NULL` and `purged_at = now` on the version, leaving `filename`, `created_by`,
`created_at`, `seq` and the chain intact; the content is freed for `purge` once no other version
references it (dedup means "this document's bytes" may still be another document's). The history then
reads *"version 3, uploaded by alice on the 4th, content destroyed on the 19th"* rather than going
silently discontinuous. `read` on such a version is `BlobError::Erased`, not `NotFound` — the
difference matters to a caller and to a log.

Erasing does not rewrite history and does not renumber: `seq` and `prev_version_id` are untouched, so
a gap is visible as a gap.

## 5. Frontend components (feature `blob-ui`, needs `ui`)

Server-rendered Askama fragments; the page works with JavaScript disabled; the one place raw bytes
could become an XSS hole is closed by construction rather than by convention (§10).

### 5.1 Which surfaces take a gate — and which don't

| Surface | Gate | Why |
|---|---|---|
| `Viewer::render()` | **none** | Pure HTML over a `VersionInfo` the caller already holds. No I/O, no database. |
| `UploadForm::render()` | **none** | Static HTML; the POST target is the app's own gated route. |
| `BlobStore::read` / `info` | **none** | Reaching a version id required passing the app's document gate first (§9.2). |
| `blob*` entities as `MetaModel`s | `authz::Authz` | They list **everything**, across every owner. |
| `Actions` (§5.3) | `authz::Authz` | Global and destructive. |

This diverges from `crud::ui`'s rule that `render_for` *is* the read enforcement point, and the
divergence is deliberate rather than an oversight: `Table`/`Form`/`Admin` **query the database while
rendering**, so rendering is the read and gating it is the only place the check can go. `Viewer` does
not — it is a formatting function over data the caller already legitimately obtained. Gating it would
check a caller who, by construction, has already been checked.

Because the gate trait lives in the always-compiled `authz` module, taking an `Arc<dyn Authz>` costs
`blob` **no dependency at all** — `Open` in a build with no `auth`, a preset in one that has it.

### 5.2 Viewer

```rust
pub struct Viewer<'a> { info: &'a VersionInfo, download_url: String }

impl<'a> Viewer<'a> {
    pub fn new(info: &'a VersionInfo, download_url: impl Into<String>) -> Self;
    pub fn render(&self) -> String;   // an HTML fragment, sync — no I/O
}
```

Dispatches on the MIME type to pick a presentation, **always by reference, never by value**:

| MIME | Rendered as |
|---|---|
| `image/*` | `<img src="{download_url}" alt="{esc filename}">` |
| `application/pdf` | `<embed src="{download_url}" type="application/pdf">` with a download-link fallback |
| erased (§4.8) | a disabled placeholder naming the filename and the date the content was destroyed |
| everything else | a plain `<a href="{download_url}">{filename} ({size})</a>` |

No case ever writes blob content into the page — every branch is a URL the browser fetches separately,
with the `Content-Type` the download route sets (§5.4), not a MIME string this component trusted. Even
a maliciously-crafted MIME in the row steers only *which tag* is rendered, never what is parsed as HTML
in the current document.

### 5.3 Upload form and admin actions

```rust
pub struct UploadForm { action: String, accept: Option<String>, max_bytes: Option<u64> }
```

A plain `<form method="post" enctype="multipart/form-data">` with a file input and a submit button.
Parsing the posted body reuses this crate's internal `multipart` module (already used by CSV import);
`blob::ui::decode_upload(body: &[u8]) -> Result<(PutMeta, Bytes), BlobError>` is the one new function
needed there.

**CSRF gap, inherited and stated, not solved here.** `csrf::enforce` does not parse multipart bodies
(`csrf.rs`, `TODO.md`), so an upload route is session-gated but not CSRF-checked. `TODO.md`'s streaming
pre-scan is the eventual fix, shared with `crud::ui`'s CSV import; this module inherits it when it lands.

The three `blob*` tables are plain SeaORM entities, so an app with `crud` + `ui` registers them into
the ordinary console with **zero new UI code** — listing, search, filters, sortable headers:

```rust
let mut h = MetaModel::new(blob_handle::Entity);
let mut v = MetaModel::new(blob_version::Entity);
for f in ["id", "seq", "prev_version_id", "blob_id", "created_by", "created_at"] {
    v.field(f).read_only = true;    // versions are immutable; the write path is BlobStore only
}
crud.register(h, gate.clone());
crud.register(v, gate.clone());
```

Marking every version column read-only is not cosmetic: an editable form over `blob_version` makes the
immutable chain editable, and the audit value evaporates.

What the generic console *can't* express is `verify` / `fsck` / `purge` / `backup_to` — not row
operations, and not `MetaModel`-shaped. Those get one small companion fragment:

```rust
// `B` is usually `FsBackend`; `BlobStore<Box<dyn BlobBackend>>` works too (§4.1), which is how an
// app that picks its backend from configuration keeps one concrete type in its handlers.
pub struct Actions<'a, B: BlobBackend> { store: &'a BlobStore<B>, gate: Arc<dyn Authz> }
impl<'a, B: BlobBackend> Actions<'a, B> {
    pub fn new(store: &'a BlobStore<B>, gate: impl Authz + 'static) -> Self;
    pub async fn render_for(&self, headers: &HeaderMap) -> Result<String, Error>;   // 401/403 from the gate
    pub async fn submit(&self, headers: &HeaderMap, ip: IpAddr, body: &[u8]) -> Result<Outcome, Error>;
}
```

An app mounts it at its own route and adds it to the sidebar with
`Admin::link("Blob store", "/admin/blobs/actions")` — the existing extension point for exactly this
shape of "a page that isn't a registered entity".

### 5.4 The axum response helper

```rust
pub fn to_response(handle: BlobHandle) -> axum::response::Response;
```

Turns a verified `BlobHandle` (an open, hash-checked stream plus its `VersionInfo`) into a `Response`
with `Content-Type`, `Content-Length`, and a `Content-Disposition` built from the version's filename —
**not a route.** The app's own handler authorizes, calls `store.read(version, ctx)`, then calls this to
build the reply. A library-owned download route could do none of the three things that matter here:
verify the digest, decide whether this caller may see it, and emit whatever the app's compliance regime
wants emitted.

## 6. Thumbnailing (feature `blob-thumbnail`)

```rust
pub struct Thumbnailer { targets: Vec<(&'static str, u32)> }  // variant name → target long edge, px

impl Thumbnailer {
    pub fn new() -> Self;   // defaults: ("thumb", 150), ("mobile", 480), ("desktop", 1024)
    pub fn targets(self, targets: Vec<(&'static str, u32)>) -> Self;

    /// Generates whichever configured variants don't already exist for `source` (checked via
    /// `BlobStore::variant`), stores each through the same `store`, and calls `set_variant`.
    pub async fn ensure<B: BlobBackend>(&self, store: &BlobStore<B>, source: &BlobId,
                                        ctx: WriteContext<'_>) -> Result<Vec<(String, BlobId)>, BlobError>;
}
```

v1 covers `image/*` via the `image` crate (resize, re-encode to WebP with a JPEG fallback) —
self-contained, no external process. **PDF first-page thumbnails are explicitly not v1**: every option
(`pdfium`, `mupdf`, shelling out to `pdftoppm`) is either a heavy binding or a process dependency, and
neither belongs in a default feature. `blob-thumbnail-pdf` is reserved as a name.

`ensure` is deliberately headless — nothing about it requires `ui`. It takes a `BlobId`, not a version,
because thumbnails are a property of content (§4.5).

## 7. Feature / module layout

```toml
blob = [
    "dep:sea-orm", "dep:tokio", "dep:sha2", "dep:uuid",
    "dep:tokio-util",     # io::StreamReader — an axum body becomes an AsyncRead (see below)
    "dep:bytes",          # StreamReader's items must be `Buf`
    "dep:futures-core",   # the `Stream` in BlobBackend::list
]
blob-ui = ["blob", "ui"]            # Viewer, UploadForm, Actions, to_response
blob-thumbnail = ["blob", "dep:image"]   # Thumbnailer (raster only, v1)
```

`sea-orm` must have **`with-uuid`** enabled alongside the `with-json` entities already need — the
handle's primary key and `metadata` are what require them.

**Getting an axum body into `put`** is `tokio_util::io::StreamReader`, which wants a
`Stream<Item = Result<B, E>>` with `B: Buf` and `E: Into<io::Error>`. `Body::into_data_stream()`
yields `Result<Bytes, axum::Error>`, so there is a `map_err` in the middle:

```rust
let reader = StreamReader::new(
    body.into_data_stream().map_err(|e| std::io::Error::other(e)),
);
store.create(reader, meta, ctx).await?
```

That conversion lives in `blob-ui` (§5.3's `decode_upload`), so plain `blob` never touches axum.

| Enabled | Gets |
|---|---|
| `blob` only | Storage, versioning, dedup, verify/fsck/backup/purge — no HTTP surface at all |
| `blob` + `blob-thumbnail` | The above plus thumbnail generation, usable from a background job with no `ui` |
| `blob` + `blob-ui` | Storage plus the viewer/upload/admin fragments |
| all three | The full stack |

**No combination requires `crud`, `auth`, or `observe` to be wired to anything** — §2's tenet, checked
against every line rather than asserted once. `authz` is compiled in every build regardless, so the
gates in §5.1 cost nothing.

## 8. Worked example: an app with no ownership or audit

```rust
let backend = FsBackend::new(cfg.blob_root);
backend.init().await?;
let store = BlobStore::new(backend, db.clone());   // no .on_write(), no crud, no auth

// upload
let handle = store.create(body_stream,
    PutMeta { filename, mime_declared, created_by: None, metadata: None },
    WriteContext::from(&headers, ip)).await?;

// download — the app's own route, its own auth check, then this crate's response builder
async fn download(Path(id): Path<Uuid>, State(store): State<Arc<BlobStore>>, headers: HeaderMap) -> Response {
    let head = store.head(HandleId(id)).await?;
    let stream = store.read(head.id, WriteContext::from(&headers, ip)).await?;
    blob::to_response(stream)
}
```

One struct, three calls, a route the app had to write anyway. This is the bar §2 is held to: it must
stay this small when that's all an app wants. Adding a second version later is one more call
(`put_version`) and no schema change anywhere.

## 9. The integration pattern: ownership, in the app's own table

§1 puts ownership out of scope. That is not a shrug — it is where the design gets its integrity, and
the pattern is short enough to write out in full.

### 9.1 A link table per document kind

```rust
#[sea_orm(table_name = "document_invoice")]
pub struct Model {
    pub id: i32,
    pub invoice_id: i32,                 // FK → invoice.id       ON DELETE CASCADE
    pub handle_id: Uuid,                 // FK → blob_handle.id
    pub owner_user_id: i32,              // FK → auth_user.id     ON DELETE RESTRICT
    pub owner_group_id: Option<i32>,     // FK → auth_group.id    ON DELETE SET NULL
    pub role: String,                    // "scan" | "signed copy" | … — the app's own vocabulary
}
```

Everything this buys is a property of being the app's table, not this crate's:

- **Real referential integrity on ownership.** `RESTRICT` means deleting a user who still owns
  documents *fails* — the admin panel returns `409` (`crud` already maps
  `ForeignKeyConstraintViolation` → `Conflict`), and an operator must reassign first. That is the
  behaviour a consistency requirement actually wants, and `blob` could only have offered it by making
  `auth` mandatory for every consumer.
- **Per-kind gates, with the gate trait as it already is.** `authz::Authz` is `authorize(op, headers)`
  — per *model*, with no row argument — which is why row-level access can't live in this crate. A
  table per document kind dissolves the problem instead of working around it: "may this caller read
  invoices" *is* a per-model question, and `crud.register(invoice_docs, GroupReadWrite::new(&auth,
  ["finance"]))` answers it with machinery that already exists. A single
  `document(kind, owner, handle)` table with a discriminator would need a gate that inspects `kind`,
  which the trait cannot express — so **many typed tables is the load-bearing choice, not a
  stylistic one.**
- **Ownership changes land in the app's audit trail** under the app's own entity name, through
  `crud`'s observer, with no special handling.
- **A row per attachment**, so an invoice with three documents is three rows, each separately owned
  and separately roled.

### 9.2 Route downloads by the document, never by the handle

```
GET  /invoice/{invoice_id}/attachment/{n}      ← gated by the invoice gate you already wrote
```

not `GET /blob/{handle_id}`. Then the handle id never appears in a URL, authorization is a gated query
on `document_invoice`, and the handle id is effectively a capability that only a gated query hands out.
Routing by handle instead forces every download route to reverse-join handle → *which* document table →
ownership, which is the one genuinely awkward query in this design. Avoid it by routing.

### 9.3 Deleting

Delete the app's row and the handle together:

```rust
store.delete_handle(handle, ctx).await?;   // in the same transaction as the document row
```

Foreign keys stop you deleting a handle something still points at; nothing stops you deleting the
document row and forgetting the handle. `HandleReference` (§4.6) is the safety net, and `fsck`'s orphan
count is how you notice you need it.

### 9.4 Versioning on top

An app wanting supersession, retirement and "which owner currently shows which document" now needs
almost nothing: the version chain is already there, and `blob_handle.head_version_id` is already "the
current one". What remains is app vocabulary — approval state, effective dates, a retirement flag —
which belongs on the link table above, next to the ownership it travels with. The model this follows
is CMIS's version series and OCFL's inventory; §13 has the reading.

## 10. Security notes

- **MIME type is advisory, never trusted for dispatch.** `Viewer` dispatches on it to pick a *tag*,
  never to decide whether to render raw bytes inline; §5.2 is the enforcement of that rule, not a
  description of it. `mime_declared` (what the uploader said) and `mime_sniffed` (what the bytes look
  like) are stored separately so an app can compare them and refuse the mismatch if it wants to.
- **The viewer never inlines content it did not render itself.** Every branch in §5.2 is a URL, so a
  hostile SVG uploaded as `image/svg+xml` is rendered by the browser as whatever `Content-Type` the
  download route sets — which is the app's problem to get right (serving `image/svg+xml` inline is an
  XSS vector independent of this crate; an app accepting SVG should use `Content-Disposition:
  attachment` or a sandboxing `Content-Security-Policy`), not something `Viewer` can fix by matching
  a filename extension.
- **Uploads are capped while streaming**, not after buffering (`BlobStore::max_bytes`), and so is
  `metadata` (§3.4).
- **Handle ids are capability-shaped.** They are unguessable (UUIDv7's 74 random bits), but §9.2's
  routing rule exists so they never have to be relied on as a secret.
- **`blob_version` must be read-only wherever it is registered** (§5.3) — an editable immutable chain
  is not an immutable chain.
- **Multipart uploads bypass CSRF** until `TODO.md`'s streaming pre-scan lands — §5.3, stated, not
  hidden.

## 11. Decisions (confirmed)

- **No `auth` dependency; ownership lives in the app's table** (§9). Considered and rejected:
  FK'ing `blob_handle.owner_user_id` onto `auth_user`. It would have made `auth` mandatory for every
  consumer, and it turned out to buy nothing — the column where integrity matters (live ownership) is
  better placed in the app's table, and the column where it doesn't (`created_by`, §3.3) wanted a
  snapshot string on audit grounds regardless.
- **Three tables: handle, version, content** (§3.1). The handle is the FK target; the digest never is.
- **`HandleId` is a UUIDv7** — time-ordered, so it doesn't scatter a B-tree the way v4 does, and
  generatable app-side.
- **`created_by` is a typed snapshot column**, not an FK and not a metadata key (§3.3).
- **Free-form `metadata` on both handle and version**, capped, never holding ownership (§3.4).
- **Erasure is a tombstone**, not a row deletion (§4.8).
- **Reads fire audit events; variant fetches do not; denied reads are the app's** (§4.7).
- **Downloads are routed by the owning document and are never a library-owned route** (§5.4, §9.2).
- **Thumbnails are blobs**, hanging off content rather than versions (§4.5).
- **`BlobBackend` stays dyn-compatible**, which is why `write` takes a boxed reader (§4.1). Runtime
  backend selection is worth one allocation per upload.
- **Bytes are written before any row, and rows land in one transaction** (§4.3) — the asymmetry
  `fsck` depends on.
- **Filesystem backend ships in v1; object storage does not.** The trait is the deliverable.
- **PDF thumbnails are out of v1.** Every implementation option is a heavy dependency.

## 12. Open questions

- **Two-phase `stage`/`commit` on `BlobBackend`**, to stop buffering uploads in memory (§4.3). The
  shape is clear; what isn't is whether it is worth a second required method on every backend before
  a deployment actually hits the limit. Until then, `max_bytes` bounds the exposure and says so.
- **S3/Ceph backend: in this crate, or a companion?** A `relativelylight-blob-s3` crate keeps the core
  free of an AWS SDK at the cost of a second crate to version in step. Leaning companion crate.
- **PDF thumbnail approach**, if/when needed: bundled renderer (`pdfium-render`, a large binary) vs.
  shelling out to `pdftoppm` (a runtime dependency on poppler-utils) vs. keeping the `<embed>` fallback
  forever.
- **Variant naming.** Shipping `thumb`/`mobile`/`desktop` as documented conventions over a free-form
  `variant: String` (rather than an enum) lets an app register `"og-image"` through the same call. Worth
  confirming before implementing.
- **Retention/archival policy** for `backup_to` / `purge` / the audit log — deliberately deferred, and
  deliberately *one* answer rather than three.
- **Does `fsck` want a repair mode**, or only a report? Deleting orphaned bytes is safe past the grace
  period; nothing can repair a *missing* one, so the asymmetry may argue for report-only plus an
  explicit `collect_orphans()`.

## 13. Reading

The design is conventional on purpose; these are the places the conventions are written down.

- **[OCFL 1.1](https://ocfl.io/1.1/spec/)** — versioning over content-addressed storage, and the
  closest analogue to §3. Its `inventory.json` version entries are the precedent for §3.3's snapshot.
- **[CMIS 1.1](https://docs.oasis-open.org/cmis/CMIS/v1.1/CMIS-v1.1.html)** and
  **[JCR 2.0 §15](https://developer.adobe.com/experience-manager/reference-materials/spec/jcr/2.0/15_Versioning.html)**
  — the two mature version-series domain models; the vocabulary an app building §9.4 should borrow.
- **[Perkeep permanodes](https://perkeep.org/doc/schema/permanode)** — one page on why an immutable
  content store needs a stable mutable-identity node. §3.1 in miniature.
- **[S3 delete markers](https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeletingObjectVersions.html)**
  and **[Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)** —
  the tombstone pattern §4.8 follows, and retention as a first-class concept.
- **[21 CFR Part 11](https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11)** §11.10(e)
  — three sentences, and the source of "record changes shall not obscure previously recorded
  information", which is why §4.8 exists instead of a `DELETE`.
- **[RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html)** — UUIDv7.
- **[RFC 6962](https://www.rfc-editor.org/rfc/rfc6962.html)** and
  **[Transparent Logs for Skeptical Clients](https://research.swtch.com/tlog)** — if an app ever needs
  its audit log to be tamper-*evident* rather than merely append-only. Not this crate's job, but one
  `prev_hash` column in the app's audit table keeps the option open.
- **[OpenFGA's authorization concepts](https://openfga.dev/docs/authorization-concepts)** — the ReBAC
  vocabulary for what §9's per-model gates deliberately do not attempt.
