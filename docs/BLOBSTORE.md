# `relativelylight::blob` — content-addressed file storage

The guide to the `blob` and `blob-ui` features: files stored under a stable **handle** with an
immutable **version** chain over digest-addressed **content**, the components that put them on a
page, and the ownership pattern that stays in your app. Why it is shaped this way is in
[DESIGN.md](DESIGN.md#blob).

**Two runnable examples.** `cargo run -p blob-example` — tickets with attachments: the streaming
upload, the version chain, the document portal, the admin panel and §8's ownership link table.
`cargo run -p blobthumbnailer-example` — derived content (§4.5).

## 1. Scope

| In scope | Out of scope |
|---|---|
| Content-addressed storage: write once, read back digest-verified | **Ownership** — who a document belongs to (§8) |
| A **stable handle** app tables can FK to, and its **version chain** | **Row-level authorization** — may *this* caller see *this* document (§8) |
| A backend trait + a shipped filesystem backend | The download route itself (§5.4) |
| Viewer, streaming upload, document browser | **Derived content** — thumbnails, previews (§4.5) |
| Consistency checking, garbage collection, content copying | Retention *policy* |

`blob` needs neither `crud` nor `auth`; the UI and the audit hook are additive.

## 2. Guarantees

- **No unverified byte reaches a caller.** Every read is hashed against the recorded digest; a
  mismatch is `BlobError::Corrupt` (§4.3).
- **A crash leaves garbage, never a dangling row.** Bytes are written before any row, and the rows of
  one write land in one transaction (§4.3).
- **History is append-only.** A version is never changed or deleted on its own (§4.8).
- **The viewer never inlines what it didn't generate.** Rendered HTML points `<img src>` /
  `<embed src>` at a route the app serves; uploaded bytes are never interpolated into a page (§9).
- **Downloads are the app's route**, with the app's authorization, routed by the owning document
  (§8.2).

## 3. Database schema & migration

### 3.1 Three tables

**Content** (`blob`) is addressed by its SHA-256 digest and holds only facts about the bytes. A
**version** (`blob_version`) records one upload of some content: filename, declared MIME type,
uploader, time. A **handle** (`blob_handle`) is the stable identity that app tables reference and that
never changes across edits. Never point a foreign key at a digest: dedup would merge two uploads'
filenames and uploaders, and every edit would change it.

### 3.2 The tables

```rust
/// The stable identity — what an app's own tables hold a foreign key to.
#[sea_orm(table_name = "blob_handle")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,                     // v7: time-ordered, so it doesn't scatter the B-tree
    pub head_version_id: Option<i64>, // the current version — the one mutable pointer
    pub created_at: i64,              // Unix seconds UTC
    pub metadata: Option<Json>,       // free-form, app-owned, mutable — see §3.4
}
```

```rust
/// One upload. Immutable once written.
#[sea_orm(table_name = "blob_version")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub handle_id: Uuid,              // FK → blob_handle.id, ON DELETE CASCADE
    pub seq: i32,                     // 1, 2, 3… unique (handle_id, seq)
    pub prev_version_id: Option<i64>, // FK → blob_version.id, RESTRICT; None on the first
    pub blob_id: String,              // FK → blob.id, RESTRICT. Not nullable: a version always has bytes
    pub filename: String,             // as at THIS version — a rename is a new version
    pub mime_declared: String,        // what the uploader claimed; advisory, never trusted (§9)
    pub created_by: Option<String>,   // identity **snapshot**, not a key — see §3.3
    pub created_at: i64,
    pub metadata: Option<Json>,       // free-form, app-owned, immutable — see §3.4
}
```

```rust
/// The content. Nothing here is a fact about *an upload* — only about the bytes.
#[sea_orm(table_name = "blob")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,              // lowercase hex SHA-256 — the identity
    pub size_bytes: i64,
    pub mime_sniffed: String,    // sniffed from the content; advisory (§9)
    pub created_at: i64,
    pub verified_at: Option<i64>,
}
```

- **Only `prev_version_id`, no `next`.** Appending a version never rewrites the previous row; "next"
  is `WHERE prev_version_id = ?` or `seq + 1`.
- **`head_version_id` carries no foreign key.** `blob_handle` → `blob_version` → `blob_handle` is a
  cycle no `CREATE TABLE` order can express without a separate `ALTER TABLE`. Every path that writes a
  version sets the head in the same transaction, and `check_consistency` reports a head that doesn't
  resolve as `dangling_heads`.
- **`(handle_id, seq)` is a unique constraint**, so two concurrent `add_version` calls can't both
  become version 4.

### 3.3 `created_by` is a snapshot string

Pass `who.username`, or your own actor label (an API key name, a service). It is a column rather
than a foreign key, so `blob` needs no `auth` and the attribution survives the account being
deleted; and a column rather than a metadata key, so the admin panel can sort, filter and search by
it. A live, enforced owner belongs in your own table (§8).

### 3.4 `metadata`, on both tables

| | `blob_version.metadata` | `blob_handle.metadata` |
|---|---|---|
| Nature | **immutable**, frozen with the row | **mutable**, current state |
| For | facts about *this upload*: source system, ingest job, change reason | facts about the *document*: classification, an external document number |

- **Never ownership or authorization data** — that is your document table's job (§8).
- **Capped at 64 KiB** on write (`BlobError::TooLarge`).
- **No secrets.** Both are shown in the admin panel and land in `WriteEvent.before`/`after`.
- Not sortable or filterable. Wanting to query a key is the signal to make it a column of your own.

### 3.5 Migration

```rust
for stmt in relativelylight::blob::table_create_statements(backend) {
    manager.create_table(stmt).await?;
}
```

The foreign keys and their `ON DELETE` actions are emitted from the entities, and `sqlx` turns on
`PRAGMA foreign_keys`, so they are enforced on SQLite too. `sea-orm` needs **`with-uuid`** as well as
`with-json`.

## 4. Rust API

### 4.1 `BlobBackend` — the storage abstraction

```rust
#[async_trait]
pub trait BlobBackend: Send + Sync + 'static {
    /// Stage content whose address isn't known yet, then commit it under the digest that falls
    /// out — the primary write path, one pass and no buffering.
    async fn stage(&self) -> Result<Box<dyn StagedWrite>, BlobError>;
    /// Store content under an id that is already known (copying to another backend). Must not
    /// return `Ok` until the content is durable.
    async fn write(&self, id: &BlobId, data: Reader) -> Result<(), BlobError>;
    /// Stream the content back; `BlobStore` verifies it, the backend needn't.
    async fn read(&self, id: &BlobId) -> Result<Pin<Box<dyn AsyncRead + Send>>, BlobError>;
    async fn exists(&self, id: &BlobId) -> Result<bool, BlobError>;
    /// Only called by `collect_garbage`, after the index row is gone.
    async fn delete(&self, id: &BlobId) -> Result<(), BlobError>;
    /// Every stored id, with its write time where known — for `check_consistency`'s orphan sweep.
    async fn list(&self) -> Result<Pin<Box<dyn Stream<Item = Result<StoredEntry, BlobError>> + Send>>, BlobError>;
}

pub struct StoredEntry { pub id: BlobId, pub written_at: Option<i64> }
pub type Reader = Pin<Box<dyn AsyncRead + Send>>;

/// Exactly one of `commit`/`abort` is called; an implementation also cleans up on drop.
#[async_trait]
pub trait StagedWrite: Send {
    async fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), BlobError>;
    async fn commit(&mut self, id: &BlobId) -> Result<(), BlobError>;
    async fn abort(&mut self);
}
```

The trait is dyn-compatible (hence the boxed `Reader`), so `Box<dyn BlobBackend>` is itself a backend
and an app can pick one from configuration. `BlobStore::create` and `add_version` take
`impl AsyncRead` and box it themselves.

### 4.2 `FsBackend` — the shipped implementation

```rust
let backend = FsBackend::new("/var/lib/app/blobs");
backend.init().await?;   // creates <root>/{tmp,ab,…}; call at startup so a bad path fails then
```

Layout: `<root>/ab/cd/abcdef0123…` with a `<root>/tmp/` staging directory. Writes go to a temp file,
are fsynced and renamed into place; content that already exists is left as it is. No object-store
backend ships yet ([TODO.md](TODO.md#blob)).

### 4.3 `BlobStore` — the type an app holds

```rust
impl<B: BlobBackend> BlobStore<B> {
    pub fn new(backend: B, db: DatabaseConnection) -> Self;
    pub fn max_bytes(self, n: u64) -> Self;                       // default 512 MiB, enforced while streaming
    pub fn on_write(self, observer: Arc<dyn WriteObserver>) -> Self;  // optional audit hook (§4.7)

    // handles and versions
    pub async fn create(&self, data: impl AsyncRead + Send + Unpin, meta: PutMeta, ctx: WriteContext<'_>)
        -> Result<HandleId, BlobError>;                           // a handle + its first version
    pub async fn add_version(&self, handle: HandleId, data: impl AsyncRead + Send + Unpin,
        meta: PutMeta, ctx: WriteContext<'_>) -> Result<VersionId, BlobError>;
    pub async fn relabel(&self, handle: HandleId, meta: PutMeta, ctx: WriteContext<'_>)
        -> Result<VersionId, BlobError>;                          // a new version over the same bytes
    pub async fn delete_handle(&self, handle: HandleId, ctx: WriteContext<'_>) -> Result<(), BlobError>;
    pub async fn ingest(&self) -> Result<Ingest<'_, B>, BlobError>;  // feed chunks yourself, then commit

    pub async fn head(&self, handle: HandleId) -> Result<VersionInfo, BlobError>;
    pub async fn versions(&self, handle: HandleId) -> Result<Vec<VersionInfo>, BlobError>;
    pub async fn version(&self, id: VersionId) -> Result<VersionInfo, BlobError>;
    pub async fn info(&self, id: VersionId) -> Result<VersionInfo, BlobError>;   // no content opened
    pub async fn browse(&self, q: &BrowseQuery<'_>) -> Result<BrowsePage, BlobError>;

    // content — verified, stamps `verified_at`, fires a `Read` event
    pub async fn read(&self, version: VersionId, ctx: WriteContext<'_>) -> Result<ContentStream, BlobError>;

    // housekeeping (§4.6)
    pub async fn verify(&self, opts: VerifyOptions) -> Result<VerifyReport, BlobError>;
    pub async fn check_consistency(&self, opts: CheckOptions) -> Result<CheckReport, BlobError>;
    pub async fn collect_garbage(&self) -> Result<CollectReport, BlobError>;
    pub async fn copy_content_to(&self, dest: &impl BlobBackend) -> Result<CopyReport, BlobError>;
}

PutMeta::new("scan.pdf").mime("application/pdf").by(&who.username).metadata(json!({…}))
WriteContext::from(&headers, client_ip)   // or WriteContext::none() for a background job
```

**Nothing is held in memory.** Uploads stream through one 64 KiB chunk while hashing, so `max_bytes`
is a policy limit, not a memory one; an oversized upload is aborted mid-stream. A read hashes the
content through once and then re-opens it to serve, which on a filesystem comes off the page cache.

**Write order.** Every content-writing call (1) streams the bytes into the backend while hashing,
then (2) in one transaction inserts the `blob` row if the digest is new, the version and the new
head, and (3) commits. A crash leaves either nothing or unreferenced bytes, which is why
`check_consistency` treats orphaned bytes as routine and missing ones as an alarm.

`HandleId` is a `Uuid` newtype, `VersionId` an `i64` one, `BlobId` a validated 64-hex-digit digest.

### 4.4 Errors

```rust
pub enum BlobError {
    Backend(Box<dyn std::error::Error + Send + Sync>),  // the backend's own failure, opaque
    Db(DbErr),
    TooLarge { limit: u64 },
    NotFound(String),
    Corrupt { expected: BlobId, found: BlobId },
    BadId(String),
}
```

### 4.5 Derived content is the app's

Thumbnails, previews and OCR text aren't built in: sizes, formats and quality are the app's call. A
thumbnail is an ordinary document — its own handle, referenced from your own table — so it is listed,
read, deleted and collected like everything else. `examples/blobthumbnailer` is the whole of it:
about eighty lines and a `picture` table holding two handles.

### 4.6 Housekeeping

Nothing is scheduled by the crate; each call returns a report and **the app schedules it**:

| When | Call | Why |
|---|---|---|
| at startup | `check_consistency(default)` | `missing` and `dangling_heads` are data loss; know at boot |
| nightly | `collect_garbage()` | frees content the day's deletions made unreachable |
| nightly | `verify(VerifyOptions::oldest(n))` | re-hashes the `n` stalest rows; converges on a full sweep |
| weekly | `check_consistency(collect_orphans)` | deletes the crash residue the daily check only counts |

**`collect_garbage`** deletes content no version points at, and its bytes. It takes no argument and
can never touch a document. Collection is never immediate: with dedup, one document's bytes may be
another's.

**`check_consistency`** reconciles the index against storage:

| Finding | Meaning | Severity |
|---|---|---|
| `missing` | a `blob` row whose bytes are gone | **alarm** — data loss |
| `dangling_heads` | a handle whose head version isn't there | **alarm** |
| `orphan_handles` | a handle with no versions | drift — usually an app that deleted its row and not the handle (§8.3) |
| `orphaned` | stored bytes the index doesn't know | routine crash residue |

Orphaned bytes are only collected with `collect_orphans` set and past `orphan_grace_secs` (default
24 h), so the sweep can't race an upload between its write and its index insert.

**`verify`** re-hashes stored content to catch silent corruption. **`copy_content_to`** copies every
blob to another backend, re-hashing on the way. It copies content only: the index is in your
database, which you back up as you do every other table.

### 4.7 The write observer, and reads

`create`, `add_version`, `relabel` and `delete_handle` fire the shared `observe::WriteObserver` with
`source: "blob"`, `entity: "blob_version"`, the version id as `key` and in `WriteEvent::version`, and
the handle id in `after`. One sink registered with `BlobStore::on_write`, `Crud::on_write` and
`Auth::on_write` sees one trail.

**Reads fire too** (`Operation::Read`), because a download of regulated content can be
compliance-weight. A *refused* read never reaches the store — the authorization is your route's — so
record those at your own gate. `collect_garbage` fires nothing: the auditable act was the
`delete_handle` that made the bytes unreferenced. Log the `CollectReport` if you need the destruction
on record.

### 4.8 Deletion: one path

| You call | Goes immediately | Left for `collect_garbage` |
|---|---|---|
| `delete_handle(h)` | the handle and **all** its versions | its content, once no other version references it |
| *you delete your own document row* | your row only | nothing — the handle is orphaned (§8.3) |
| `collect_garbage()` | unreferenced content and its bytes | — |

- **Nothing deletes content directly**; deletion makes it unreachable and collection removes it.
- **A version is never deleted on its own.** To be rid of a history, delete the document.
- **Destroying content — including for an erasure request — is `delete_handle` plus
  `collect_garbage`.** Dedup applies: bytes go only when no other document shares them. The record of
  who destroyed what is the audit log's, not the chain's.

Deleting a `blob_handle` row *directly* fails with a foreign-key violation once it has two versions
(the cascade order is unspecified and `prev_version_id` is `RESTRICT`). So register `blob_handle` and
`blob_version` in a console **behind a read-only gate**, and delete through `Browser::submit` or
`delete_handle`.

## 5. Frontend components (feature `blob-ui`, needs `ui`)

Server-rendered fragments that work with JavaScript disabled.

| Component | For |
|---|---|
| `Portal` | **one document** on an app page: current version, optional history, optional upload |
| `Viewer` | render one version you already hold — what `Portal` is built from |
| `UploadForm` | the upload form; `as_new_version()` to add to a document |
| `Receiver` | streams a posted upload into the store |
| `Browser` + `Actions` | **the admin panel**: every handle, searchable, with maintenance |
| `Routes` | an optional gated router serving content, plus URLs that match it (§5.5) |
| `to_response` / `to_inline_response` | a verified `ContentStream` as an HTTP reply (§5.4) |

### 5.1 Which surfaces take a gate

| Surface | Gate | Why |
|---|---|---|
| `Viewer::render()` | none | formats a `VersionInfo` you already hold; no I/O |
| `UploadForm::render()` | none | static HTML; the POST target is your gated route |
| `BlobStore::read` / `info` | none | reaching a version id meant passing your document gate (§8.2) |
| `Portal`, `Browser`, `Actions` | `authz::Authz` | they read the database while rendering, so rendering is the read |
| `blob*` entities as `MetaModel`s | `authz::Authz` | they list every document, across every owner |

### 5.2 `Portal` — one document

```rust
Portal::new(store, handle, gate)
    .view_url("/invoice/42/attachment/{version}")  // …or .routes(&mounted) — §5.5
    .versions(true)        // add the history, collapsed
    .display(true)         // embed content the browser can render (default)
    .upload("/invoice/42/attachment/replace")      // a form that adds the *next* version
    .render_for(&headers).await?                   // 401/403 from the gate
```

`upload` offers a new **version** of this document, never a new document: creating one is your
route's job, because something has to record who owns it (§8). `display(false)` drops the embedded
preview, for a page listing many documents.

**`Viewer`** (`Viewer::new(&version, view_url).download_url(url).thumbnail_url(url)`) renders:

| Source | Rendered as |
|---|---|
| a thumbnail was supplied | `<img src="{thumbnail_url}">` linking to the full view |
| `image/png`, `jpeg`, `gif`, `webp` | `<img src="{view_url}">`, `img-fluid` |
| `application/pdf` | `<embed src="{view_url}">` |
| anything else | no preview |

followed by `filename (size) · open · download`. `open` is offered only for types
`to_inline_response` will serve inline, so the viewer never links to something the response refuses.

### 5.3 Upload, and the admin panel

`UploadForm` renders a plain `multipart/form-data` form. **`Receiver`** takes axum's `Body` and
streams the file to the store one chunk at a time, so `max_bytes` is the only size limit in play
(axum's `DefaultBodyLimit` applies to buffering extractors only). It checks the CSRF token **before**
writing anything, which means `_csrf` must arrive ahead of the file part; `UploadForm` renders it
first, and a body with the file first is refused with nothing stored.

The three tables are plain SeaORM entities, so they can go into an ordinary `crud` console:

```rust
let mut v = MetaModel::new(blob_version::Entity);
for f in ["id", "seq", "prev_version_id", "blob_id", "created_by", "created_at"] {
    v.field(f).read_only = true;    // versions are immutable; the write path is BlobStore only
}
crud.register(MetaModel::new(blob_handle::Entity), read_only_gate.clone());
crud.register(v, read_only_gate.clone());
```

A *document* list (current filename per handle) needs a join `crud` can't make, since
`head_version_id` has no declared foreign key. That is **`Browser`**:

```rust
Browser::new(store, gate)
    .title("Documents")                            // its own heading; "" for none
    .view_url("/documents/{handle}/v/{version}")   // your route
    .render_for(&headers, &BrowseState::from_uri(&uri)).await?
```

It lists handles — current filename, type, size, version count, `created_by` — and drills into one
handle's chain. Search matches any version's filename. Its columns use the schema's names
(`handle`, `seq`, `blob`), since it is an operator's view; an end-user list is `Portal`'s job.

**Maintenance** sits in a menu beside the search: **Check consistency** (a *deep* checkbox also
re-hashes the 500 least recently verified blobs) and **Collect garbage**. `Browser::submit` is the
panel's one write entry point — `delete` / `check` / `collect`, each gated — and `delete` is the only
way to remove a document from a console. `Actions` renders the same controls for a page of their
own; link it with `Admin::link("Blob store", "/admin/blobs/actions")`.

### 5.4 The response helper

```rust
pub fn to_response(stream: ContentStream) -> axum::response::Response;          // attachment
pub fn to_inline_response(stream: ContentStream) -> axum::response::Response;   // inline for safe types
```

Builds `Content-Type`, `Content-Length` and a `Content-Disposition` from the version's filename. It
is **not a route**: your handler authorizes, calls `store.read(version, ctx)`, then this.
`to_inline_response` serves inline only an allowlist of types and downgrades the rest to a download,
so a hostile SVG is downloaded rather than executed.

### 5.5 `Routes` — an optional gated router

```rust
let routes = Routes::new("/admin/blob");
app.nest("/admin/blob", routes.router(store.clone(), admin_gate));
Browser::new(&store, gate).routes(&routes)   // components build their URLs from the same object
```

It serves any version by id to whoever passes the one gate you give it — right for an admin panel,
or an app where every signed-in user may see every document. **Wrong** in an app with per-document
ownership: there, write the route yourself (§8.2) and pass `view_url`.

## 6. Features

```toml
blob    = ["dep:sea-orm", "dep:tokio", "dep:sha2", "dep:uuid", "dep:tokio-util", "dep:bytes", "dep:futures-core"]
blob-ui = ["blob", "ui", "dep:multer"]   # Portal, Viewer, UploadForm, Receiver, Browser, Actions, Routes
```

`blob` alone is storage, versioning, dedup, checking, collection and copying, with no HTTP surface.
Neither feature needs `crud`, `auth` or an observer wired to anything.

## 7. The smallest app

```rust
let backend = FsBackend::new(cfg.blob_root);
backend.init().await?;
let store = BlobStore::new(backend, db.clone());   // no observer, no crud, no auth

// upload
let handle = store.create(body_stream, PutMeta::new(filename).mime(mime),
    WriteContext::from(&headers, ip)).await?;

// download — your own route and authorization, then the response builder (`blob-ui`)
async fn download(Path(id): Path<Uuid>, State(store): State<Arc<BlobStore>>, headers: HeaderMap) -> Response {
    let head = store.head(HandleId(id)).await?;
    let stream = store.read(head.id, WriteContext::from(&headers, ip)).await?;
    blob::ui::to_response(stream)
}
```

A second version later is one `add_version` call and no schema change.

## 8. Ownership, in your own table

### 8.1 A link table per document kind

```rust
#[sea_orm(table_name = "document_invoice")]
pub struct Model {
    pub id: i32,
    pub invoice_id: i32,                 // FK → invoice.id       ON DELETE CASCADE
    pub handle_id: Uuid,                 // FK → blob_handle.id
    pub owner_user_id: i32,              // FK → auth_user.id     ON DELETE RESTRICT
    pub owner_group_id: Option<i32>,     // FK → auth_group.id    ON DELETE SET NULL
    pub role: String,                    // "scan" | "signed copy" | … — your vocabulary
}
```

- **Real integrity on ownership.** With `RESTRICT`, deleting a user who still owns documents fails
  with a `409` until someone reassigns them.
- **Per-kind gates.** `Authz` is per model, with no row argument, so a table per kind is what makes
  "may this caller read invoices?" answerable: `crud.register(invoice_docs,
  GroupReadWrite::new(&auth, ["finance"]))`. One `document(kind, …)` table would need a gate that
  inspects `kind`, which the trait can't express.
- **Ownership changes are audited** through `crud`'s observer under your entity's name.
- **One row per attachment**, each separately owned and roled.

Approval states, effective dates or a "retired" flag belong on this table too; the version chain
and `head_version_id` already give you supersession.

### 8.2 Route downloads by the document, never by the handle

```
GET  /invoice/{invoice_id}/attachment/{n}      ← gated by the invoice gate you already have
```

not `GET /blob/{handle_id}`. The handle id then never appears in a URL, and authorization is a
gated query on `document_invoice`. Routing by handle would force every download to reverse-join
handle → document table → owner.

### 8.3 Deleting

```rust
store.delete_handle(handle, ctx).await?;   // alongside deleting the document row
```

Foreign keys stop you deleting a handle something still references, but nothing stops you deleting
the document row and forgetting the handle; `check_consistency`'s `orphan_handles` is how you notice.

## 9. Security notes

- **MIME type is advisory.** `Viewer` uses it only to pick a tag, never to inline bytes.
  `mime_declared` (the uploader's claim) and `mime_sniffed` (the bytes) are stored separately, so you
  can refuse a mismatch.
- **Serve through `to_inline_response`** (§5.4). A route of your own that serves `image/svg+xml`
  inline is an XSS vector.
- **Uploads are capped while streaming** (`max_bytes`), and so is `metadata` (§3.4).
- **Handle ids are unguessable** (UUIDv7, 74 random bits), but §8.2's routing means you never rely on
  that.
- **Register `blob_version` read-only** wherever it appears (§5.3): an editable chain is not an
  immutable one.
- **Uploads through `Receiver` are CSRF-checked** before anything is written (§5.3).
