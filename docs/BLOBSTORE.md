# `relativelylight::blob` — content-addressed file storage — DRAFT SPEC

Status: **not implemented.** This is `docs/PRD.md` §6 ("Files"), written up properly. No code exists
yet; this document is what gets built, in the same sense `AUTH.md` was before `auth` existed.

## 1. Purpose & scope

Every app in this crate's audience ends up storing files — uploads, generated PDFs, photos — and
re-solving the same four problems: content that shouldn't silently corrupt, a storage backend that
will someday not be the local filesystem, a way to show a preview without shipping a JS viewer
library, and an admin page to look at what's stored. None of that requires an opinion about
*versioning* — supersession, retirement, "which owner currently shows which document" — which is
squarely a per-app business concern (see §9).

**Scope, precisely:**

| In scope | Out of scope |
|---|---|
| Content-addressed storage: write once, read back digest-verified | Versioning ("this supersedes that") |
| A backend trait + a shipped filesystem implementation | Ownership ("this document belongs to that work order") |
| Viewer, upload form, thumbnailer, a companion admin panel | Row-level authorization ("may *this* caller see it") |
| Backup and purge *mechanisms* | Backup and purge *policy* (what's worth keeping, for how long) |

The right mental model is `auth` vs. an app's own RBAC group taxonomy: this module owns the
mechanism and ships something usable standalone; an app that needs more (CLIMB's `attachments.md`,
for one) builds a typed layer on top, the same way CLIMB builds its own group taxonomy on top of
`auth::group`.

## 2. Design tenets

**No mandatory coupling.** `blob` alone (no `crud`, no `auth`, no `observe` wiring) is a complete,
useful library: an app gets digest-verified storage and nothing else. Every other feature layer —
UI, thumbnails, audit — is additive. This is the direct answer to "we may want to use the blob store
in an app with no versioning and/or auditing requirements": that app enables `blob` and stops there.

**The backend is a trait; correctness is not.** Hashing, dedup, and the write-ordering invariant that
makes a crash leave only garbage (never a dangling row) live once, in `BlobStore`, above the backend
trait — not re-implemented per backend. A backend's job is narrower than it looks: durably store
bytes under an id, and hand them back.

**Derived content is still content.** A thumbnail is a blob like any other — content-addressed,
stored through the same backend, subject to the same verify/purge machinery. No second storage
mechanism, no separate cache invalidation story.

**The viewer never inlines what it didn't generate itself.** Rendered HTML gets an `<img src>` or
`<embed src>` pointing at a route the app serves; raw uploaded bytes are never interpolated into a
page. §10 says why this isn't optional.

**Downloads stay an app route.** `blob-store.md`'s own rule, carried over unchanged: the app knows
who may see a given blob; this crate does not, and must not guess. `blob` provides the verified
byte-stream and an `axum::Response` builder (§5.4); the app supplies the route and its own
authorization.

## 3. Database schema & migration

Two tables, same fan-out layout CLIMB's implementation already validated in production use.

```rust
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "blob")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,              // lowercase hex SHA-256 — the identity
    pub size_bytes: i64,
    pub mime_type: String,       // sniffed or supplied; advisory, never trusted for dispatch (§10)
    pub original_filename: Option<String>,
    pub created_at: i64,         // Unix seconds UTC
    pub created_by: Option<String>,   // an opaque actor id the app assigns meaning to — see below
    pub verified_at: Option<i64>,
}
```

```rust
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
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

**`created_by` is `Option<String>`, not an FK.** `blob` must compile and work with `auth` disabled,
so it cannot point a typed foreign key at `auth::user`. An app running `auth` passes
`who.id.to_string()`; an app with its own actor concept (an API key id, a service name) passes that.
This is the same trade `attachments.md` §3 makes for `owner_entity`/`owner_id`, for the identical
reason — the referenced type set isn't knowable here.

```rust
// specs/blob-store.md's migration pattern, unchanged in shape:
for stmt in relativelylight::blob::table_create_statements(backend) {
    manager.create_table(stmt).await?;
}
```

`table_create_statements` (mirroring `auth::table_create_statements`, `mod.rs:278`) is how an app's
own migration creates these tables — same reasoning as `auth`: the app owns the database and its
migration history, this crate only knows how to describe its own tables.

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
    async fn write(&self, id: &BlobId, data: impl AsyncRead + Send + Unpin) -> Result<(), BlobError>;

    /// Stream the content back. `BlobStore::get` re-hashes while streaming and compares against
    /// `id` — the backend does not need to verify anything itself.
    async fn read(&self, id: &BlobId) -> Result<Pin<Box<dyn AsyncRead + Send>>, BlobError>;

    async fn exists(&self, id: &BlobId) -> Result<bool, BlobError>;

    /// Only called by `purge` (§4.6), and only after the index row is gone — an backend impl can
    /// assume a `delete` is never racing a `write` for the same id (ids are content hashes; nothing
    /// deletes and immediately re-creates the same one on purpose).
    async fn delete(&self, id: &BlobId) -> Result<(), BlobError>;
}
```

### 4.2 `FsBackend` — the shipped implementation

The only backend this crate ships day one, and CLIMB's `blob.rs` almost unchanged:

```rust
pub struct FsBackend { root: PathBuf }

impl FsBackend {
    pub fn new(root: impl Into<PathBuf>) -> Self;
    /// Create `<root>/{tmp,ab,…}`. Call once at startup so a misconfigured path fails loudly then,
    /// not on the first upload months later.
    pub async fn init(&self) -> Result<(), BlobError>;
}
```

Layout unchanged from `blob-store.md` §3: `<root>/ab/cd/abcdef0123…`, two-level fan-out, a
`<root>/tmp/` staging directory. `write` streams to a temp file while hashing is done by the caller
(`BlobStore`, which already knows the id before calling `write` — it computed it), fsyncs, and
renames into place; if the target already exists (another concurrent write raced it to the same
content), it discards the temp file rather than erroring — identical content is identical, per
`blob-store.md` §4.1.

**An S3/Ceph backend is not shipped in v1.** The trait exists to make one possible without touching
`BlobStore`; writing one is an app's or a follow-up crate's job until there's a real deployment that
needs it (same answer `blob-store.md` §7 Q1 already gave).

### 4.3 `BlobStore` — the type an app holds

```rust
pub struct BlobStore<B: BlobBackend = FsBackend> {
    backend: B,
    db: DatabaseConnection,
    max_bytes: u64,
    on_write: Option<Arc<dyn WriteObserver>>,
}

impl<B: BlobBackend> BlobStore<B> {
    pub fn new(backend: B, db: DatabaseConnection) -> Self;
    pub fn max_bytes(self, n: u64) -> Self;               // default 64 MiB, enforced while streaming

    /// Optional. Mirrors `Crud::on_write` / `Auth::on_write` exactly — same `WriteObserver` trait
    /// (`crate::observe`), same event shape, so one sink registered with all three sees a unified
    /// trail. An app with no auditing requirement simply never calls this.
    pub fn on_write(self, observer: Arc<dyn WriteObserver>) -> Self;

    /// Streams `data`, hashing as it goes and enforcing `max_bytes`. If the resulting id already has
    /// a row, the stream is dropped and the existing id returned — a write that turns out to be a
    /// no-op is not an error. `ctx` is only consulted if an observer is registered (`headers` +
    /// `client_ip`, same shape `WriteEvent` already needs) — pass `WriteContext::none()` from a
    /// background job (the thumbnailer, a migration) where there is no request to attribute.
    pub async fn put(
        &self,
        data: impl AsyncRead + Send + Unpin,
        meta: PutMeta,
        ctx: WriteContext<'_>,
    ) -> Result<BlobId, BlobError>;

    /// Opens the content, hashing while streaming and comparing to `id`. A mismatch is
    /// `BlobError::Corrupt` — no partial bytes reach the caller — never a silent hand-back of wrong
    /// content. On success, stamps `verified_at`.
    pub async fn get(&self, id: &BlobId, ctx: WriteContext<'_>) -> Result<BlobHandle, BlobError>;

    /// The index row without opening the content — for a listing or an `<img>` tag that only needs
    /// size/mime/filename.
    pub async fn info(&self, id: &BlobId) -> Result<BlobInfo, BlobError>;

    /// Re-hashes without serving the bytes anywhere; for a scheduled integrity sweep rather than
    /// waiting for the next read (`blob-store.md` §7 Q3).
    pub async fn verify(&self, id: &BlobId) -> Result<bool, BlobError>;

    pub async fn backup_to(
        &self,
        dest: &impl BlobBackend,
        filter: Option<&dyn ReferenceCheck>,
    ) -> Result<BackupReport, BlobError>;

    pub async fn purge(&self, checker: &dyn ReferenceCheck) -> Result<PurgeReport, BlobError>;
}
```

```rust
pub struct PutMeta {
    pub mime_type: String,
    pub original_filename: Option<String>,
    pub created_by: Option<String>,
}

pub struct WriteContext<'a> {
    headers: Option<&'a HeaderMap>,
    client_ip: Option<IpAddr>,
}
impl<'a> WriteContext<'a> {
    pub fn none() -> Self { .. }                    // no request to attribute — background jobs
    pub fn from(headers: &'a HeaderMap, client_ip: IpAddr) -> Self { .. }
}
```

`get`/`put` always take a `WriteContext`, matching how every other write path in this crate already
carries `headers`/`client_ip` — but it's `Option`-backed and `::none()` is one call, so nothing about
using the store outside an HTTP handler is awkward. If no observer is registered the context is
never even read.

**`BlobId`** is a thin newtype over the 64-lowercase-hex string (`FromStr`/`Display`/`TryFrom<&str>`
rejecting malformed input) — the same discipline `blob-store.md` §6.1 already states in prose
(`blob.id` is never client-supplied and always exactly 64 hex chars), now a type that can't be
constructed otherwise rather than a convention.

### 4.4 Errors

```rust
pub enum BlobError {
    Backend(Box<dyn std::error::Error + Send + Sync>),  // a backend's own failure, opaque by design
    Db(DbErr),
    TooLarge { limit: u64 },
    NotFound(BlobId),
    Corrupt { id: BlobId, found: BlobId },
    BadId(String),
}
```

`Backend` is intentionally opaque — `BlobStore` doesn't know or care whether a backend failure was a
filesystem `ENOSPC` or an S3 timeout, only that the write didn't happen.

### 4.5 Derived content and `blob_variant`

A thumbnail is produced by hashing its own bytes and calling `BlobStore::put` exactly like any
upload — it becomes a `blob` row like any other, with `original_filename = None` and
`created_by = None` (system-generated, same convention `blob-store.md`'s own table already uses).
`blob_variant` just records which derived blob answers which `(source, variant)` pair, so a caller
can ask "does `post/desktop` already exist" without regenerating it.

```rust
impl<B: BlobBackend> BlobStore<B> {
    pub async fn variant(&self, source: &BlobId, variant: &str) -> Result<Option<BlobId>, BlobError>;
    pub async fn set_variant(&self, source: &BlobId, variant: &str, derived: &BlobId)
        -> Result<(), BlobError>;
}
```

`blob::thumb` (§6) is the only thing in this crate that calls `set_variant`; nothing stops an app
from generating its own derived content and registering it the same way (an OG-image crop, say) —
the mechanism doesn't care what produced the bytes.

### 4.6 Backup and purge

**`backup_to`** copies every blob's content from this store's backend to another `BlobBackend`
(local→S3, local→a second local path for offline media, …), verifying each digest as it goes and
returning a report of what copied, what was already present at the destination, and what failed.
Default is "everything currently in the index"; `filter` narrows it to whatever the caller's
`ReferenceCheck` still considers live. This is deliberately just a mechanism — *what's worth backing
up, for how long* is retention policy, and both `blob-store.md` §7 Q2 and `attachments.md` Q1 already
flag that as an open question this document does not attempt to answer.

**`purge`** deletes blob rows (and their backend content) that `checker.is_referenced` reports as
no longer referenced, **and their `blob_variant` rows and derived blobs alongside them** — a
thumbnail is only ever referenced *through* its source, so once the source is gone the variant goes
with it regardless of what `checker` says (the checker was never asked about the derived id; it
doesn't need its own opinion).

```rust
#[async_trait]
pub trait ReferenceCheck: Send + Sync {
    /// `true` = keep. An app with no versioning layer at all can pass a checker that always returns
    /// `true` (nothing is ever purged) — equivalent to never calling `purge`, spelled out — or wire
    /// it to its own "does anything still point at this" query the moment it has one.
    async fn is_referenced(&self, id: &BlobId) -> bool;
}
```

This is the seam `blob-store.md` §4.3 already anticipated by name ("content becomes collectable once
no `attachment_link`... points at a given `blob_id`") without this crate existing yet to receive it.
An app like CLIMB implements `ReferenceCheck` by querying its own `attachment_version` table; an app
with no versioning concept either never calls `purge`, or implements the trivial always-`true`
checker above.

### 4.7 Write observer (optional audit)

No new trait — `put`/`get`/`purge`/`backup_to` fire the existing `observe::WriteObserver`
(`observe.rs`) with `source: "blob"`, the same `WriteEvent` shape `crud` and `auth` already use
(`op: Create` for `put`, and — because a *read* of regulated content can itself be compliance-weight,
which `crud`'s events don't currently express — `get` fires too, with `op` extended by one variant,
`Operation::Read`, gated so existing `WriteEvent::op` matches stay exhaustive; see §12). An app
registers one sink with `BlobStore::on_write`, `Crud::on_write` and `Auth::on_write` alike and gets
one unified trail, or registers it with none of them and pays nothing.

## 5. Frontend components (feature `blob-ui`, needs `ui`)

Same discipline as the rest of `crud::ui` post-MPA ([MIGRATION-0.3.md](MIGRATION-0.3.md)): server-rendered Askama fragments, the
page works with JavaScript disabled, and the one place raw bytes could become an XSS hole is closed
by construction rather than by convention (§10).

### 5.1 Viewer

```rust
pub struct Viewer<'a> { info: &'a BlobInfo, download_url: String }

impl<'a> Viewer<'a> {
    pub fn new(info: &'a BlobInfo, download_url: impl Into<String>) -> Self;
    pub fn render(&self) -> String;   // an HTML fragment, sync — no I/O, it only reads BlobInfo
}
```

Dispatches on `mime_type` to pick a presentation, **always by reference, never by value**:

| MIME | Rendered as |
|---|---|
| `image/*` | `<img src="{download_url}" alt="{esc filename}">` |
| `application/pdf` | `<embed src="{download_url}" type="application/pdf">` with a download-link fallback |
| everything else | a plain `<a href="{download_url}">{filename} ({size})</a>` |

No case ever writes blob content into the page — every branch is a URL the browser fetches
separately, with the `Content-Type` the download route sets (§5.4), not a MIME string this component
trusted. That's the point: even a maliciously-crafted `mime_type` in the row (it's "advisory, never
trusted for dispatch" per `blob-store.md` §6.4 already) only steers *which tag* is rendered, never
what ends up parsed as HTML in the current document.

### 5.2 Upload form

```rust
pub struct UploadForm { action: String, accept: Option<String>, max_bytes: Option<u64> }

impl UploadForm {
    pub fn new(action: impl Into<String>) -> Self;
    pub fn accept(self, mime_patterns: impl Into<String>) -> Self;  // the `accept` attribute — a hint, not enforcement
    pub fn render(&self) -> String;
}
```

A plain `<form method="post" enctype="multipart/form-data" action="{action}">` with a file input and
a submit button — the exact shape `blobadmin.rs` already hand-writes today, lifted into the crate so
every app stops rewriting it. Parsing the posted body reuses this crate's existing internal
`multipart` module (today used by CSV import and CSRF-in-multipart detection); a new
`blob::ui::decode_upload(body: &[u8]) -> Result<(PutMeta, Bytes), BlobError>` is the one new function
needed there.

**CSRF gap, inherited and stated, not solved here.** `csrf::enforce` does not parse multipart bodies
(`csrf.rs:273`, `TODO.md`), so an upload route is admin/session-gated but not CSRF-checked — the same
accepted limitation `blobadmin.rs` already lives with in CLIMB today. `TODO.md`'s streaming pre-scan
idea is the eventual fix, shared with `crud::ui`'s own CSV import; this module doesn't duplicate that
work, it inherits the fix when it lands.

### 5.3 Admin actions

The blob index (`blob::Entity`) is a plain SeaORM entity — an app with `crud`+`ui` enabled registers
it into the ordinary console exactly the way CLIMB registers `auth::user` today:

```rust
let mut b = MetaModel::new(relativelylight::blob::Entity);
b.label_column("original_filename");
for f in ["id", "size_bytes", "mime_type", "created_at", "verified_at"] { b.field(f).read_only = true; }
crud.register(b, gate);
```

That gives listing, search, and delete (a hard delete through CRUD is fine — it's what `purge`
already does, only manually and one row at a time) for free, with **zero new UI code in this
module.** What the generic console *can't* express is `verify` / `backup_to` / `purge` — not row
operations, and not `MetaModel`-shaped. Those get one small companion fragment:

```rust
pub struct Actions<'a, B: BlobBackend> { store: &'a BlobStore<B> }
impl<'a, B: BlobBackend> Actions<'a, B> {
    pub fn new(store: &'a BlobStore<B>) -> Self;
    pub fn render(&self) -> String;   // three buttons, each a plain <form method="post">
    pub async fn submit(&self, op: &str, headers: &HeaderMap, ip: IpAddr) -> Result<String, Error>;
}
```

An app mounts `Actions` at its own route and adds it to the console's sidebar with
`Admin::link("Blob store", "/admin/blobs/actions")` (`crud::ui::mod.rs:1243`) — the existing,
general-purpose extension point for exactly this shape of "a page that isn't a registered entity,"
already used the same way CLIMB links its bespoke `blobadmin.rs` page today.

### 5.4 The axum response helper

```rust
pub fn to_response(handle: BlobHandle) -> axum::response::Response;
```

Turns a verified `BlobHandle` (an open, hash-checked stream plus its `BlobInfo`) into a `Response`
with `Content-Type`, `Content-Length`, and a `Content-Disposition` built from `original_filename` —
**not a route.** The app's own handler calls `store.get(id, ctx)`, does its own authorization check,
then calls this to build the reply — matching §2's "downloads stay an app route" tenet and
`blob-store.md` §5's existing reasoning almost word for word (verify the digest, check whether this
caller may see it, emit whatever event the app wants — a static file route, or a library-owned one,
can do none of the three).

## 6. Thumbnailing (feature `blob-thumbnail`)

```rust
pub struct Thumbnailer { targets: Vec<(&'static str, u32)> }  // variant name → target long edge, px

impl Thumbnailer {
    pub fn new() -> Self;   // defaults: ("thumb", 150), ("mobile", 480), ("desktop", 1024)
    pub fn targets(self, targets: Vec<(&'static str, u32)>) -> Self;

    /// Generates whichever configured variants don't already exist for `source` (checked via
    /// `BlobStore::variant`), stores each through the same `store`, and calls `set_variant`. Returns
    /// the variants now available, generated or pre-existing.
    pub async fn ensure<B: BlobBackend>(
        &self, store: &BlobStore<B>, source: &BlobId, ctx: WriteContext<'_>,
    ) -> Result<Vec<(String, BlobId)>, BlobError>;
}
```

v1 covers `image/*` via the `image` crate (resize, re-encode to WebP with a JPEG fallback for older
clients) — self-contained, no external process. **PDF first-page thumbnails are explicitly not v1**:
every option (`pdfium`, `mupdf`, shelling out to `pdftoppm`) is either a heavy binding or a process
dependency, and neither belongs in a default feature. `blob-thumbnail-pdf` is reserved as a name for
whichever approach a real need justifies later; §12 leaves the choice open rather than guessing.

`ensure` is deliberately headless — nothing about it requires `ui`. A batch job pre-generating
thumbnails after a bulk import, or an API serving `?variant=thumb` to a mobile client with no HTML in
sight, calls it exactly the same way the viewer's rendering path would.

## 7. Feature / module layout

```toml
blob = ["dep:sea-orm", "dep:tokio", "dep:sha2"]           # core: BlobStore, FsBackend, entities
blob-ui = ["blob", "ui"]                                   # Viewer, UploadForm, Actions, to_response
blob-thumbnail = ["blob", "dep:image"]                     # Thumbnailer (raster only, v1)
```

Every combination is meaningful standalone:

| Enabled | Gets |
|---|---|
| `blob` only | Storage, dedup, verify, backup/purge mechanism — no HTTP surface at all |
| `blob` + `blob-thumbnail` | The above, plus thumbnail generation — usable from a background job with no `ui` |
| `blob` + `blob-ui` | Storage plus the viewer/upload/admin fragments; an app writes its own thumbnailing or skips it |
| all three | The full stack |

No combination requires `crud`, `auth`, or `observe` to be wired to anything — §2's "no mandatory
coupling" tenet, checked against every feature line rather than asserted once.

## 8. Worked example: an app with no versioning or audit

The case that prompted this document's scope line, made concrete — the entire integration:

```rust
let backend = FsBackend::new(cfg.blob_root);
backend.init().await?;
let store = BlobStore::new(backend, db.clone());   // no .on_write(), no crud, no auth

// upload
let id = store.put(body_stream, PutMeta { mime_type, original_filename, created_by: None },
                    WriteContext::from(&headers, ip)).await?;

// download — the app's own route, its own auth check, then this crate's response builder
async fn download(Path(id): Path<BlobId>, State(store): State<Arc<BlobStore>>, headers: HeaderMap) -> Response {
    let handle = store.get(&id, WriteContext::from(&headers, ip)).await?;
    blob::to_response(handle)
}
```

No `attachment` table, no `MetaModel`, no `WriteObserver` impl, no `crud` feature — one struct, two
calls, a route the app already had to write anyway for its own authorization. This is the bar §2 is
held to: it must stay this small when that's all an app wants.

## 9. Composing with a versioning layer

Not this crate's job (§1), but worth naming so a reader lands on `attachments.md` rather than
reinventing it: an app that needs supersession, retirement, and "which owner currently shows which
document" builds a typed layer whose only coupling to this module is `blob_id: FK → blob.id` on its
own version table — `attachments.md` §2.2's `attachment_version.blob_id` is exactly that, unchanged
by this module existing. CLIMB is the reference implementation once its `blob.rs`/`model::blob`
retire in favor of this crate (a follow-up migration, not part of this spec).

## 10. Security notes

- **MIME type is advisory, never trusted for dispatch** — carried over from `blob-store.md` §6.4
  unchanged. `Viewer` dispatches on it to pick a *tag*, never to decide whether to render inline
  raw bytes; §5.1 is the enforcement of that rule, not just a description of it.
- **The viewer never inlines content it did not render itself.** Every branch in §5.1's table is a
  URL, so a hostile SVG or HTML file uploaded as, say, `image/svg+xml` is fetched and rendered by the
  browser as whatever `Content-Type` the download route actually sets — which is the app's problem to
  get right (serving `image/svg+xml` inline is itself an XSS vector independent of this crate; an app
  that accepts SVG uploads should consider `Content-Disposition: attachment` or a
  `Content-Security-Policy` sandboxing the response), not something `Viewer` can fix by string
  matching a filename extension.
- **Uploads are capped while streaming**, not after buffering (`BlobStore::max_bytes`) — same
  discipline `blob-store.md` §6.3 already states.
- **Multipart uploads bypass CSRF** until `TODO.md`'s streaming pre-scan lands — §5.2, stated,
  not hidden.

## 11. Decisions (confirmed)

- **Filesystem backend ships in v1; object storage does not.** The trait is the deliverable; a
  concrete S3/Ceph implementation waits for a deployment that needs one (`blob-store.md` §7 Q1's
  answer, unchanged by this crate existing).
- **Thumbnails are blobs.** No second storage mechanism, no separate cache table beyond the
  `(source, variant) → derived` index `blob_variant` already is.
- **`created_by` is an opaque string, not an FK.** The module must work with `auth` disabled; typing
  it would break that.
- **Downloads are never a library-owned route.** Only a response builder over a caller-supplied,
  already-authorized `BlobHandle`.
- **PDF thumbnails are out of v1.** Every implementation option is a heavy dependency; not worth
  forcing on every consumer of `blob-thumbnail` for a feature only some apps need.

## 12. Open questions

- **`Operation::Read` on `WriteEvent`.** §4.7 wants blob reads to be audit-observable (this crate's
  own `blob-store.md` §6.5 already requires "every download emits an audit event"), but
  `observe::WriteEvent::op` is currently `Create`/`Update`/`Delete` only — reads were never a `crud`
  concern because `crud`'s API was removed with the JSON layer ([MIGRATION-0.3.md](MIGRATION-0.3.md)). Adding a `Read` variant is
  a small, additive change to `observe.rs`, but it's a change to a type `crud`/`auth` also use, so it
  wants a decision, not an assumption made inside this spec.
- **S3/Ceph backend: in this crate, or a companion crate?** A `relativelylight-blob-s3` crate keeps
  the core dependency-free (no AWS SDK pulled in by `blob` alone) at the cost of a second crate to
  version in step. Leaning toward companion crate; not decided.
- **PDF thumbnail approach**, if/when it's needed: bundled renderer (`pdfium-render`, a large
  binary) vs. shelling out to `pdftoppm` (a runtime dependency on poppler-utils being installed) vs.
  skipping PDFs and showing the `application/pdf` `<embed>` fallback forever. Not designed here.
- **Variant naming.** Shipping `thumb`/`mobile`/`desktop` as documented conventions with a free-form
  `variant: String` column (rather than an enum) mirrors `attachments.md`'s `role` column
  (D1 layer 2/3: a fixed set the code understands, not centrally enforced) — an app can register its
  own variant name (`"og-image"`) through the same `set_variant` call. Confirm this is the right
  precedent to follow before implementing, since `attachments.md` §8 Q2 flags the same free-string
  trade-off as still worth revisiting there.
- **Retention/archival policy** for `backup_to`/`purge` — explicitly deferred to whatever answers
  `blob-store.md` §7 Q2, `attachments.md` Q1, and `audit.md` §8 Q1 together, per those documents'
  own instruction not to design it three times.
