# `relativelylight::files` — files on a page

Reading an upload (several files, or a phone's camera), serving a file back, and the HTML components
for an upload form, a preview and a thumbnail tile. **Storage is the app's**: where the bytes live
(a directory, a database column, an object store), what a file is called, what it belongs to, who may
see it and how a page lists files. Nothing here reads, writes, lists or deletes a file.

**Runnable example:** `cargo run -p files-example` — a flat directory with upload (picker and
camera), a listing with thumbnails, preview, download and delete. Its storage (`src/store.rs`) and
thumbnail cache (`src/thumbs.rs`) are app code, written to be copied.

`files` needs neither `crud`, `auth` nor a database; add `csrf` for `Upload::csrf`.

## 1. Upload — `Upload`

A pull API: `next()` yields the form's parts in the order the browser sent them — a text field as
`Part::Field(name, value)`, a file as `Part::File(f)` — and the app writes each file's chunks
wherever it keeps files.

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
                let mut out = app.storage.create().await?;
                while let Some(chunk) = f.chunk().await? {
                    out.write(&chunk).await?;
                }
                out.commit(&my_name(save_as.as_deref(), f.filename())).await?;
            }
        }
    }
    Redirect::to("/").into_response()
}
```

- **It streams.** Only one chunk and the first `SNIFF_BYTES` (1 KiB) of a file are held, so
  `max_bytes` is a policy limit, not a memory one. `f.bytes()` reads the rest into memory, for a file
  headed for a database column.
- **The CSRF token must arrive before the first file**, or the post is refused (`403`) before the app
  sees a byte. `UploadForm` renders the token first, and browsers post parts in document order.
- **Fields before files.** `UploadForm` renders its name field ahead of the file inputs, so the name
  is known before the first byte.
- **A `FilePart` borrows the upload**: read it or drop it before the next `next()`. Dropping skips the
  rest of that file. An empty file input is skipped.

| `FilePart` | |
|---|---|
| `filename()` | as the browser sent it — **untrusted**, possibly empty (a camera); never a path |
| `declared_mime()` / `mime()` | the browser's claim / what the bytes say — both known before the first chunk |
| `chunk()` / `bytes()` | the next chunk (`None` at the end) / the rest in memory |
| `size()`, `sha256()` | computed while streaming; `sha256()` is `Some` once read to the end |

**Errors.** `UploadError` has `status()`: `NotMultipart` `415`, `Csrf` `403`, `FieldTooLarge` /
`TooLarge` / `TooManyFiles` `413`, `Malformed` (including a file in a field other than `file_field`)
and `Finished` `400`. A limit or a dropped connection mid-file comes from `chunk()`; after any error
the upload yields only `Finished`. **Discarding what the app already wrote is the app's job.**

## 2. Serving — `Download`

```rust
to_inline_response(Download::new(file, &name, mime).content_length(len))  // a file or a stream
to_response(Download::from_bytes(row.content, &row.name))                 // bytes; type sniffed
```

`to_response` is an attachment. `to_inline_response` renders inline **only** PNG, JPEG, GIF, WebP,
PDF and plain text — with `nosniff` and a sandboxing `Content-Security-Policy` — and anything else
as an attachment. Pass the type the **bytes** say (`sniff_mime`, or the type stored at upload). The
filename can't inject a header or carry a path.

These are not routes: the app's handler authorises the request, finds the bytes and calls one.

## 3. Components

Bootstrap 5 fragments built from plain values — no I/O, no gate (the page and the URLs it points at
are gated). Every value is escaped.

### `UploadForm`

```rust
UploadForm::new("/upload")
    .csrf(&token)                        // rendered first — §1
    .name_field("name", "Save as")       // rendered before the file inputs
    .multiple()
    .camera("Or take a photo")           // a second input with capture="environment"
    .accept("image/*,application/pdf")   // a hint to the picker, not enforcement
    .max_bytes(256 << 20)                // shown as a hint; the limit is Upload::max_bytes
    .render()

UploadForm::photo("/upload", "Take a photo").csrf(&token).render()
```

`photo` is a single button: it opens a phone's camera and posts the picture on accept, with no name
field — the app names it (a phone sends `image.jpg`, or nothing). The post is an inline
`onchange="this.form.submit()"`, like the crud filters.

### `Preview`

```rust
Preview::new(&name, mime, "/raw/scan.pdf")   // the URL serves the content inline
    .size(bytes)
    .download_url("/download/scan.pdf")
    .render()
```

An `<img>` for an image, an `<embed>` for a PDF, then the name, size and links. "open" is offered only
for types `to_inline_response` renders inline. `.links_only()` drops the embed.

### `Thumbnail`

```rust
Thumbnail::new(&name).src("/thumb/photo.jpg").href("/view/photo.jpg").px(64).render()
```

A square `<img>` cropped to fit, or — without `src` — a badge of the same size with the extension
("PDF", "FILE"), so a listing stays aligned. Make thumbnails at twice `px` for sharp phone screens.

## 4. The app's part

`examples/files` shows each of these for a flat directory:

- **Names never become paths.** Clean `filename()` (last component, no control characters, no
  leading dot, bounded length); accept a name from a URL only if cleaning leaves it unchanged.
- **Invisible until complete.** Write to a temporary name (or inside a transaction) and publish it
  after the last chunk; a refused upload leaves nothing behind.
- **Never overwrite by accident.** `hard_link` from the temporary file refuses an existing target, so
  the check and the claim are one step; then try `name (2).ext`. In a database, a unique constraint.
- **Serve by the owning record** (`/invoice/{id}/file/{n}`, behind the invoice's gate) where there is
  one. Put names into URLs with `url_segment`. Delete is a `POST` checked with `Csrf::verify`.
- **Thumbnails on request**, cached under the content hash (`<cache>/<sha256>-<px>.png`): nothing is
  made for a file nobody views, and the cache is never stale and can be wiped. Decode images only (not
  SVG), with a pixel limit read before decoding and a cap on concurrent decodes. Send the hash as an
  `ETag`, or with the hash in the URL, `Cache-Control: immutable`.

An app with an index keeps a row per file (path, `sha256`, size, `mime`, created at/by) and a link
table per owning kind, with real foreign keys; a link table with columns of its own is an entity
`crud` can register under the owner's gate.

## 5. Security notes

- **The type is advisory.** `mime()` comes from magic numbers (PNG, JPEG, GIF, WebP, PDF, ZIP, SVG,
  UTF-8 text, else `application/octet-stream`); never dispatch on it.
- **Serve through `to_inline_response`.** Serving `image/svg+xml` inline from a route of your own is
  an XSS vector.
- **Set `Upload::csrf`.**
- **The filename is untrusted** and not Unicode-normalised (macOS may send NFD).
- **A filesystem mount bypasses the app** — sshfs or Samba sees POSIX permissions, not your gates.
