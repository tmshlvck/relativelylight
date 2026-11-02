# `relativelylight::files` — files on a page

The guide to the `files` feature: reading an upload (several files at once, or from a phone's
camera), serving a file back, and the HTML components for the upload form, a preview and a thumbnail
tile. **Everything else is the app's**: where the bytes live (a directory, a database column, an
object store), what a file is called, what it belongs to, who may see it, and how a page lists files.
Nothing in this module reads, writes, lists or deletes a file. Why it is shaped this way is in
[DESIGN.md](DESIGN.md#files).

**Runnable example:** `cargo run -p files-example` — a flat directory of files with upload (picker
and camera), a listing with thumbnail tiles, preview, download and delete. Its storage
(`src/store.rs`) and thumbnail cache (`src/thumbs.rs`) are app code, written to be copied.

## 1. Scope

| The crate | The app |
|---|---|
| Reading a posted form part by part, streaming: CSRF-checked before the first file, size-capped, hashed and sniffed on the way (§2) | Writing the bytes somewhere, and cleaning up after a refused upload (§5.1) |
| Any byte stream as an HTTP reply, inline only for safe types (§3) | The routes: which file a URL means, and who may fetch it (§5.3) |
| `UploadForm`, `Preview`, `Thumbnail` — fragments from plain values (§4) | Listing files: a table or grid of its own, with the components inside |
| `sniff_mime`, `human_size`, `url_segment` | Names: making a safe one from what a browser sent, and resolving conflicts (§5.1) |
| | An index, ownership and versions, in its own tables (§5.2) |
| | Thumbnails: making them and caching them (§6) |

`files` needs neither `crud`, `auth` nor a database. `csrf` is optional and recommended.

## 2. Upload — `Upload`

A pull API: the crate parses, the app stores. `next()` yields the form's parts in the order the
browser sent them — a text field as `Part::Field(name, value)`, a file as `Part::File(f)` — and the
app reads each file's chunks and writes them wherever it keeps files.

```rust
async fn upload(State(app): State<App>, headers: HeaderMap, body: Body) -> Response {
    let mut up = match Upload::new(&headers, body) {   // `Body`, not a buffering extractor
        Ok(up) => up
            .csrf(&app.csrf)              // auth.csrf(), or a standalone `Csrf`
            .max_bytes(256 << 20)         // per file, enforced while streaming (default 512 MiB)
            .max_files(32),               // per post (default 32)
        Err(e) => return (e.status(), e.to_string()).into_response(),   // 415: not multipart
    };
    let mut save_as = None;
    while let Some(part) = up.next().await? {
        match part {
            Part::Field(name, value) if name == "name" => save_as = Some(value),
            Part::Field(..) => {}
            Part::File(mut f) => {
                // f.filename(), f.declared_mime(), f.mime() — all known before the first chunk
                let mut out = app.storage.create().await?;
                while let Some(chunk) = f.chunk().await? {
                    out.write(&chunk).await?;
                }
                // f.size(), f.sha256() → your index row (§5.2)
                out.commit(&my_name(save_as.as_deref(), f.filename())).await?;
            }
        }
    }
    if up.files() == 0 { /* an empty picker */ }
    Redirect::to("/").into_response()
}
```

**It streams.** Nothing is buffered beyond one chunk and the first `SNIFF_BYTES` (1 KiB) of each
file, so `max_bytes` is a policy limit rather than a memory one, and axum's `DefaultBodyLimit` (which
applies to buffering extractors only) never bites. For a file headed for a database column,
`f.bytes().await` reads the rest into memory — `max_bytes` is then the memory bound.

**The CSRF token must arrive before the first file.** A buffered parser can check the token at the
end because it holds the whole body; a streaming one must decide before the app writes. So a body
with a file part ahead of `_csrf` is refused (`403`) before the app sees a byte of it.
`UploadForm` renders the token first, and browsers post parts in document order.

**The name is known before the file.** `UploadForm` renders its name field before the file inputs,
so a typed name (or any other field the app adds ahead of them) arrives first, and the app can write
straight to the right place.

**What a `FilePart` tells you:**

| Method | |
|---|---|
| `filename()` | as the browser sent it — **untrusted**, possibly empty (a camera capture); never a path |
| `declared_mime()` | the browser's claim |
| `mime()` | what the bytes say (§7) — available before the first chunk, so a type can be refused before anything is written |
| `chunk()` | the next chunk, `None` at the end |
| `bytes()` | the rest, in memory |
| `size()`, `sha256()` | computed while streaming; `sha256()` is `Some` once read to the end — the checksum for your index, at no extra read |

A `FilePart` borrows the upload, so it is read or dropped before the next part is asked for;
dropping it skips the rest of that file. An empty file input (a form with a picker and a camera input
where only one was used) is skipped.

**Errors.** `UploadError` — `NotMultipart` (`415`), `Malformed`, `Csrf` (`403`), `FieldTooLarge`,
`TooLarge`, `TooManyFiles` (`413`), `Finished` — has `status()`. A limit hit or a dropped connection
in the middle of a file comes from `chunk()`; after any error the upload yields only `Finished`.
**What the app wrote of that file — and of earlier ones, if the post is all-or-nothing — is the
app's to discard** (§5.1). A file posted under a field other than `file_field` (default `"file"`) is
`Malformed`.

## 3. Serving — `Download`

```rust
to_inline_response(Download::new(file, &name, mime).content_length(len))  // a file, an object-store stream
to_response(Download::from_bytes(row.content, &row.name))                 // a database column; type sniffed
```

`to_response` is an attachment. `to_inline_response` renders inline **only** `image/png`, `jpeg`,
`gif`, `webp`, `application/pdf` and `text/plain` — under `X-Content-Type-Options: nosniff` and a
sandboxing `Content-Security-Policy` — and turns anything else into an attachment. Pass the type the
**bytes** say (`sniff_mime` of the first `SNIFF_BYTES`, or the type stored at upload).
`Content-Disposition` is built so a filename cannot inject a header or carry a path, with an RFC 5987
`filename*` for non-ASCII.

These are **not routes**: the app's handler authorises the request, finds the bytes, and calls one.
Add caching headers to the returned `Response` as you see fit (§6).

## 4. Components

Bootstrap 5 fragments, never pages; the app owns the shell and any listing. Each takes plain values
— a name, a type, a URL — does no I/O, and takes no gate: the page and the URLs it points at are
gated. Every value is escaped.

### 4.1 `UploadForm`

```rust
UploadForm::new("/upload")
    .csrf(&token)                        // rendered first — §2
    .name_field("name", "Save as")       // a text field, rendered before the file inputs
    .multiple()                          // select several files
    .camera("Or take a photo")           // a second input: capture="environment" opens a phone's camera
    .accept("image/*,application/pdf")   // a hint to the picker, not enforcement
    .max_bytes(256 << 20)                // shown as a hint; the limit is Upload::max_bytes
    .render()
```

The camera input posts to the same field as the picker, so `Upload` needs nothing extra; on a
desktop it is an ordinary image picker.

For one tap on a phone — camera, accept, posted — there is a button instead of a form:

```rust
UploadForm::photo("/upload", "Take a photo").csrf(&token).render()
```

It posts the token and a single file part with no name field, so the app names the picture (a
camera usually sends `image.jpg` or nothing). The post is an inline `onchange="this.form.submit()"`,
the same as the crud filters use; without JavaScript the picture is taken but not sent.

### 4.2 `Preview` — one file, shown in full

```rust
Preview::new(&name, mime, "/raw/scan.pdf")   // the URL serves the content inline
    .size(bytes)
    .download_url("/download/scan.pdf")      // a "download" link
    .render()
```

An `<img>` for an image, an `<embed>` for a PDF, nothing for anything else; then the name, size and
links. "open" is offered exactly for the types `to_inline_response` renders, so a page never promises
what the response would turn into a download. `.links_only()` leaves out the embedded preview.

### 4.3 `Thumbnail` — a tile for a listing

```rust
Thumbnail::new(&name)
    .src("/thumb/photo.jpg")     // the app's thumbnail URL (§6); unset → a badge
    .href("/view/photo.jpg")     // where clicking goes
    .px(64)                      // the tile's edge in CSS pixels
    .render()
```

With a `src`, a square lazy-loaded `<img>` cropped to fit (`object-fit: cover`); without one, a badge
of the same size with the extension ("PDF", "ZIP", "FILE"), so a mixed grid or table column stays
aligned. Make thumbnails at twice `px` and they stay sharp on a phone.

## 5. The app's part

### 5.1 Writing files

Whatever the backend, an upload handler has to get the same few things right. `examples/files`
`src/store.rs` does each in a few lines for a flat directory:

- **Names never become paths.** Make a name from `filename()` — last path component, no control
  characters, no leading dot, bounded length — and accept a name from a URL only if it is already one
  the app could have made.
- **An upload is invisible until complete.** Write to a temporary name (or inside a transaction) and
  make it visible after the last chunk, so a listing never shows half a file and a refused upload
  leaves nothing behind.
- **A taken name is never overwritten by accident.** On a filesystem, `hard_link` from the temporary
  file refuses an existing target, so the check and the claim are one step; try `name (2).ext` next.
  In a database, a unique constraint does the same.

### 5.2 An index, ownership, versions

When the app needs to know more than a name — and a real app does — it keeps a row per file:

```rust
#[sea_orm(table_name = "stored_file")]
pub struct Model {
    pub id: i32,
    pub backend: String,       // "fs", "s3", "db"
    pub path: String,          // where the bytes are, relative to the backend's root
    pub sha256: String,        // FilePart::sha256 — re-hash later to detect a changed file
    pub size: i64,
    pub mime: String,          // FilePart::mime
    pub created_at: i64,
    pub created_by: String,    // a snapshot, so attribution survives the account
}
```

- **Order the writes.** Store the file, then insert the row; delete the row, then the file. A crash
  then leaves only files without rows, which a periodic sweep finds.
- **Assign a path once.** A path built from data (`invoices/2026-10-1234/…`) is computed when the
  file is written and stored; it is not recomputed when the data changes later.

What a file *belongs to* is a link table per kind, with real foreign keys and its own attributes:

```rust
#[sea_orm(table_name = "invoice_file")]
pub struct Model {
    pub id: i32,
    pub invoice_id: i32,       // FK → invoice.id
    pub file_id: i32,          // FK → stored_file.id
    pub role: String,          // "scan" | "signed copy" — the link's property, not the file's
}
```

A table per kind is what makes the per-model gate enough: register `invoice_file` with the invoice
gate. (A link table with columns of its own is an entity; `crud` never registers pure N:M junctions.)
There is no version chain: a new revision is a new file and a new row; "current" is a column or the
newest row.

### 5.3 Routes

Serve files **by the owning record** — `GET /invoice/{id}/file/{n}`, authorised by the invoice gate,
then `to_inline_response` or `to_response` — rather than by a bare file name, which would need a
reverse lookup to authorise. Use `url_segment(name)` when a name does go into a URL: it
percent-encodes everything but unreserved characters, so `/`, `?` and `#` in a name can't change the
route. Delete is a `POST` carrying `_csrf`, checked by the handler (`Csrf::verify`).

## 6. Thumbnails

The crate makes none — `Thumbnail` shows whatever URL it is given. The pattern `examples/files`
uses (`src/thumbs.rs`), and the one we recommend:

- **Made on request, not at upload.** The first request for a thumbnail decodes the image; nothing
  is generated for a file nobody looks at, and a size change needs no backfill.
- **Cached by content hash** — `<cache>/<sha256>-<px>.png`, in a configurable directory (or a table).
  The cache is never stale (a replaced file has a new hash), never has to follow a rename or a
  delete, and can be wiped at any time.
- **Images only**, by the sniffed type, and not SVG. Everything else gets the badge.
- **Bounded.** A pixel-count limit read from the header before decoding (a few KB of PNG can declare
  10 GB of pixels), a source-size cap, and a semaphore on concurrent decodes in `spawn_blocking`. The
  output is always a re-encoded PNG, never the uploaded bytes.
- **HTTP caching.** With the hash in the thumbnail URL (an app with an index table), serve it
  `Cache-Control: max-age=31536000, immutable`. The example has no index, so its URL is the file name;
  it sends the hash as an `ETag` and answers `304` to `If-None-Match`.

## 7. Security notes

- **The content type is advisory.** `FilePart::mime` is from magic numbers (`sniff_mime`: PNG, JPEG,
  GIF, WebP, PDF, ZIP, SVG, UTF-8 text; else `application/octet-stream`). It picks a tag and the
  inline decision; never dispatch on it. Compare it with `declared_mime` if a mismatch matters.
- **Serve through `to_inline_response`.** A route of your own that serves `image/svg+xml` inline is
  an XSS vector.
- **Uploads are CSRF-checked before the app sees a file** when `Upload::csrf` is set. Set it.
- **The filename is untrusted** — the crate passes it through as sent. Unicode is not normalised
  either: a macOS client may send `é` decomposed (NFD). Normalise in the app if names are compared.
- **A filesystem mount bypasses the app.** sshfs or Samba sees the directory with POSIX permissions,
  not your gates; mount it read-only.

## 8. Feature

```toml
files = ["axum", "dep:tokio", "dep:sha2", "dep:tokio-util", "dep:multer"]
```

`Upload::csrf` needs `csrf` too.
