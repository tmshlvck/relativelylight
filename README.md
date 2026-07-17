# relativelylight

A web back-office toolkit for Rust. **Auto-generate a JSON CRUD + metadata API and an admin UI from
your ORM entities — with no per-model code**, and (soon) gate them with built-in auth. It composes
*into* your app: you keep your own router, page shell, and OpenAPI document; `relativelylight` plugs
into them.

The crate is **`relativelylight`**, organized into feature-gated modules:
- **`crud`** (default) — the CRUD engine, SeaORM backend, admin UI (`ui`), OpenAPI, CSV.
- **`auth`** — sessions, login, and an authorization gate (usable without `crud`). First slice
  implemented; see [docs/AUTH.md](docs/AUTH.md).

> Status: the `crud` API + `ui` web admin are implemented and used by the examples; `auth` covers
> argon2 login/session, `Authz` gate presets, a self-service profile (password + TOTP 2FA), and OIDC
> single sign-on (feature `sso`). File-handling is planned — see [PRD.md](PRD.md).

## What you get

- **Full CRUD JSON API** per entity — list/get/create/update/delete, relations written by name
  (`"author": 1`, `"tag": [1,3]`).
- **Search, sort, pagination**, and **set-based bulk delete** (`DELETE …?q=…` / `?ids=…` / `?all=true`).
- **Machine-readable metadata** (ordered fields + relations, logical types) that drives the UI and
  OpenAPI — no per-model schema code.
- **Validation & transforms** — field + cross-field validators, `on_read`/`on_write` hooks (redact,
  hash), typed coercion.
- **CSV import/export** reusing the same validation pipeline.
- **A web admin** (`ui`): tables with a create/edit modal form, relation pickers (dropdown or live
  search→select), boolean switches, bulk actions, CSV, custom cell renderers — plus an `Admin`
  side-panel composing many models into one page.
- **Runtime OpenAPI 3.1** (`openapi`) with request/response schemas, mergeable into your own document.

The core is backend- and transport-agnostic; SeaORM is one backend behind a small `Accessor` seam.

## Quick start

```toml
# Cargo.toml  (not yet on crates.io — use a path or git dependency)
[dependencies]
relativelylight = { path = "relativelylight", features = ["ui", "openapi", "csv"] }
sea-orm = { version = "1.1", features = ["macros", "with-json"] }
```

```rust
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::authz::Open;           // gate per model; Open = ungated

// Auto-build a model per entity; only N:M is declared by hand.
let author = MetaModel::new(author::Entity);
let tag    = MetaModel::new(tag::Entity);
let mut post = MetaModel::new(post::Entity);
post.relate(&tag);

let mut crud = Crud::new(db, "/api/v1");    // base path ("" for root)
crud.register(author, Open);                // pass an auth gate to restrict — see docs/AUTH.md
crud.register(post, Open);
crud.register(tag, Open);

// Optional admin UI fragment (needs the `ui` feature). Build it before into_router().
let admin_html = relativelylight::crud::ui::Admin::new(crud.engine()).entities().render()?;

// The CRUD routes as an axum Router — merge into your own app.
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
| `crud` | ✅ | the CRUD engine + SeaORM backend (the `crud` module) |
| `axum` | ✅ | the HTTP router (`Crud::into_router`) |
| `ui` | | the web admin components (`crud::ui::Table`, `crud::ui::Admin`) |
| `openapi` | | runtime OpenAPI 3.1 generation |
| `csv` | | CSV import/export endpoints |
| `auth` | | sessions, on-demand login resolution, TOTP 2FA, a per-model authorization gate |
| `sso` | | OIDC single sign-on (Google / Okta / corporate) + group mapping (implies `auth`) |

Enable only what you use — an unused feature pulls no dependencies.

## Examples

Three runnable examples share one seeded in-memory SQLite model (`examples/model`):

```bash
cargo run -p crud-example          # per-entity pages (MPA), CSV, Swagger UI — open (no auth)
cargo run -p adminpanel-example    # the crud::ui::Admin side-panel — login-gated (admin / password)
cargo run -p auth-example          # auth alone: argon2 login/session gating a page (admin / password)
```

Each serves on <http://127.0.0.1:3000/> (run one at a time). The first two put the JSON API under
`/api/v1` with Swagger at `/docs`.

## Requirements

- Registered entities have a **single-column primary key** and **single-column to-one FKs** (any
  URL-safe scalar — int, UUID, string slug). N:M junction tables are never registered.
- Entities derive `Serialize` (SeaORM's `with-json` feature).

## Documentation

- **[docs/CRUD.md](docs/CRUD.md)** — the full `crud` guide: `MetaModel`/`MetaField`/`MetaRelation`,
  the HTTP API and formats, query params, validation, metadata, CSV, the web admin, OpenAPI, and how
  to compose with your app.
- **[docs/AUTH.md](docs/AUTH.md)** — the auth design (draft).
- **[PRD.md](PRD.md)** — product overview and roadmap.

## License

MIT © Tomas Hlavacek. See [LICENSE](LICENSE).
