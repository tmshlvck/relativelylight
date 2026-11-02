# Upgrading from 0.4 to 0.5

0.5 replaces the `blob` store with the `files` module. The crate no longer stores, lists or names
files: it reads an upload, serves bytes back safely, and renders the upload form, a preview and a
thumbnail tile. Where files live is the app's. Every step is a compile error; none is silent.
[CHANGELOG.md](../CHANGELOG.md) has the full list, and [FILES.md](FILES.md) the new module.

## 1. Features

```toml
# 0.4
relativelylight = { version = "0.4", features = ["blob-ui"] }
# 0.5
relativelylight = { version = "0.5", features = ["files", "csrf"] }
```

`files` needs neither `crud` nor a database; `csrf` (implied by `auth`) enables `Upload::csrf`.

## 2. Your stored files

The `blob_handle`, `blob_version` and `blob` tables and the content directory are no longer read or
written by the crate. To keep the files, export them **with 0.4** before upgrading — for each handle,
`store.head(handle)` gives the current version's `filename` and digest, and `store.read(version.id, …)`
the bytes:

```rust
// on 0.4, once
for doc in your_document_rows {
    let head = store.head(HandleId(doc.handle_id)).await?;
    let bytes = store.read(head.id, WriteContext::none()).await?.into_bytes().await?;
    // write `bytes` to your new storage under a name of your choosing, and record that name
    // (and head.blob as the sha256) in the column that replaces `handle_id`
}
```

Older versions in a chain are exported the same way from `store.versions(handle)`. Then drop the three
tables in a migration of your own.

## 3. Your link tables

A column holding a `blob_handle.id` becomes whatever identifies the file in your new storage: a path,
a row in your own index table (FILES.md §5.2), or the bytes themselves for small files stored in a
column. The link table pattern itself is unchanged.

## 4. Upload

```rust
// 0.4
let up = Receiver::new(&store).csrf(&csrf).by(Some(who)).receive(&headers, body, ctx).await?;
let handle = up.handle;
// 0.5
let mut up = Upload::new(&headers, body)?.csrf(&csrf).max_bytes(limit);
while let Some(part) = up.next().await? {
    if let Part::File(mut f) = part {
        while let Some(chunk) = f.chunk().await? { /* write it to your storage */ }
        // f.filename(), f.size(), f.sha256(), f.mime() → your row; the uploader is yours to record
    }
}
```

`max_bytes` moved from `BlobStore` to `Upload`. One post may now carry several files. `as_version_of`
is gone: a new revision is a new file. Naming, conflict handling and cleaning up a refused upload are
the app's (FILES.md §5.1); `examples/files/src/store.rs` is a flat-directory version to copy.

## 5. Download

```rust
// 0.4
to_inline_response(store.read(version, ctx).await?)
// 0.5
to_inline_response(Download::new(file, &name, mime).content_length(len))  // a file or a stream
to_inline_response(Download::from_bytes(bytes, &filename))               // a column
```

`Routes` is gone: serving is the app's route, authorised by the owning record (FILES.md §5.3). Reads
no longer fire `Read` events — fire your own from that route if reads must be audited.

## 6. Components

| 0.4 | 0.5 |
|---|---|
| `Viewer::new(&version_info, url)` | `Preview::new(name, mime, url)` |
| `Viewer::download_url` | `Preview::download_url` |
| `Viewer::thumbnail_url` | `Thumbnail::new(name).src(url).href(view_url)` |
| `Portal` (one document + history + upload) | `Preview` + `UploadForm` on your page; history is your rows |
| `Browser`, `Actions` (the store's admin panel) | your own listing, with a `Thumbnail` per row |
| `UploadForm::as_new_version` | `.label(…).submit(…)` |
| — | `UploadForm::multiple`, `camera`, `name_field` |

`human_size` takes a `u64`.

## 7. The write observer

`WriteEvent::version` is removed — only the blob store set it. Delete the field from your observer.

## 8. Housekeeping

`verify`, `check_consistency`, `collect_garbage` and `copy_content_to` are gone with the store. If you
keep an index table, the equivalent is a periodic sweep comparing your storage with it and re-hashing
files against the stored `sha256`.
