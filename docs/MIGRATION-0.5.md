# Upgrading from 0.4 to 0.5

Every step but §3 is a compile error; §3 is a behaviour change. [CHANGELOG.md](../CHANGELOG.md) has the full list.

## 1. `blob` → `files`

The `blob` and `blob-ui` features are removed with everything in them; the crate no longer stores
files. Use `files` ([FILES.md](FILES.md)) and keep the bytes in your own storage.

```toml
relativelylight = { version = "0.5", features = ["files", "csrf"] }
```

If you stored files with 0.4, export them **before upgrading** (`store.head(handle)` and
`store.read(version.id, …)` for each handle), then drop the `blob_handle`, `blob_version` and `blob`
tables.

| 0.4 | 0.5 |
|---|---|
| `Receiver::new(&store)…receive(…)` | `Upload::new(&headers, body)?.csrf(&csrf)`, then `next()` / `chunk()` and write it yourself |
| `store.read(…)` + `to_inline_response` | `to_inline_response(Download::new(reader, &name, mime))` or `Download::from_bytes` |
| `Routes` | your own routes |
| `Viewer` | `Preview::new(name, mime, url)` |
| `Viewer::thumbnail_url` | `Thumbnail::new(name).src(url)` |
| `Portal`, `Browser`, `Actions` | your own page, with `Preview`, `Thumbnail` and `UploadForm` |
| `UploadForm::as_new_version` | gone — a revision is a new file |

## 2. `WriteEvent::version`

Removed. Delete the field from your observer.

## 3. `Table::fixed_filter` pins the writes

A pinned table's form no longer shows the pinned column, its writes always carry the pinned value,
and a row outside the pin is `404` there ([CRUD.md → A pinned filter](CRUD.md#a-pinned-filter)). Most
apps need nothing. If operators used a pinned table to move a row to another parent, or a
`.fields([…])` list named the pinned column, that column is now absent from the form: offer the
change through an unpinned `Table` or the `Admin`.
