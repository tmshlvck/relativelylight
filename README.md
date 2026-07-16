# Rune — `autocrud`

Turn your **SeaORM entities into a JSON CRUD + metadata API and an auto-generated web admin — with
no per-model code.** `autocrud` introspects your entities at runtime: every column becomes a field,
primary/foreign keys are detected, FK relations are discovered. The only thing you declare by hand is
many-to-many. It's built to be *part of* a larger app: your app keeps its own router, page shell, and
OpenAPI document; autocrud plugs into them.

> Status: `autocrud` (the API) and the `alpine` web admin are implemented and used in the examples.
> Auth and file-handling are planned. See [PRD.md](PRD.md) for the roadmap.

## What you get

- **Full CRUD JSON API** per entity — list/get/create/update/delete, with relations written by name
  (`"author": 1`, `"tag": [1,3]`).
- **Search, sort, pagination**, and **set-based bulk delete** (`DELETE …?q=…` / `?ids=…` / `?all=true`).
- **Machine-readable metadata** (ordered fields + relations, logical types) that drives the UI and
  OpenAPI — no per-model schema code.
- **Validation & transforms** — per-field validators, cross-field row validators, `on_read`/`on_write`
  hooks (redact, hash), typed coercion.
- **CSV import/export** that reuses the same validation pipeline.
- **A web admin** (`alpine`): tables with a create/edit modal form, relation pickers (dropdown or
  live search→select), boolean switches, bulk actions, CSV, custom cell renderers — and an `Admin`
  side-panel that composes many models into one page.
- **Runtime OpenAPI 3.1** (`openapi`) with request/response schemas, mergeable into your own document.

The core is backend- and transport-agnostic; SeaORM is one backend behind a small `Accessor` seam.

## Quick start

```toml
# Cargo.toml  (not yet on crates.io — use a path or git dependency)
[dependencies]
autocrud = { path = "autocrud", features = ["alpine", "openapi", "csv"] }
sea-orm  = { version = "1.1", features = ["macros", "with-json"] }
```

```rust
use autocrud::seaorm::{Crud, MetaModel};

// Auto-build a model per entity; only N:M is declared by hand.
let author = MetaModel::new(author::Entity);
let tag    = MetaModel::new(tag::Entity);
let mut post = MetaModel::new(post::Entity);
post.relate(&tag);

let mut crud = Crud::new(db, "/api/v1");    // base path ("" for root)
crud.register(author);
crud.register(post);
crud.register(tag);

// Optional: an admin UI fragment (needs the `alpine` feature). Build it before into_router().
let admin_html = autocrud::alpine::Admin::new(crud.engine()).entities().render()?;

// autocrud's routes as an axum Router — merge into your own app.
let app = axum::Router::new()
    .route("/", axum::routing::get(|| async { /* serve admin_html in your shell */ }))
    .merge(crud.into_router());
```

That serves `GET/POST /api/v1/{entity}`, `GET/PATCH/DELETE /api/v1/{entity}/{id}`, and
`DELETE /api/v1/{entity}` (bulk). Tweak a model before registering:

```rust
post.field("title").label = Some("Title".into());
post.field("password").write_only = true;            // in writes, never in reads
post.field("views").default = Some(serde_json::json!(0));
post.field("title").validate = Some(Box::new(|v| {
    if v.as_str().unwrap_or("").trim().is_empty() { Err("required".into()) } else { Ok(()) }
}));
```

## Features

| Feature | Default | Adds |
|---|---|---|
| `axum` | ✅ | the HTTP router (`Crud::into_router`) |
| `alpine` | | the web admin components (`alpine::Table`, `alpine::Admin`) |
| `openapi` | | runtime OpenAPI 3.1 generation |
| `csv` | | CSV import/export endpoints |

## Examples

Two runnable examples share one seeded in-memory SQLite model (`examples/model`):

```bash
cargo run -p autocrud-example      # per-entity pages (MPA), CSV, Swagger UI
cargo run -p adminpanel-example    # the alpine::Admin side-panel — many models in one page
```

Both serve on <http://127.0.0.1:3000/> with the JSON API under `/api/v1` and Swagger UI at `/docs`.

## Requirements

- Registered entities have a **single-column primary key** and **single-column to-one FKs** (any
  URL-safe scalar — int, UUID, string slug). N:M junction tables are never registered.
- Entities derive `Serialize` (SeaORM's `with-json` feature).

## Documentation

- **[docs/AUTOCRUD.md](docs/AUTOCRUD.md)** — the full guide: `MetaModel`/`MetaField`/`MetaRelation`,
  the HTTP API and formats, query params, validation, metadata, CSV, the web admin, OpenAPI, and how
  to compose with your app.
- **[PRD.md](PRD.md)** — product overview and roadmap.

## License

MIT © Tomas Hlavacek. See [LICENSE](LICENSE).
