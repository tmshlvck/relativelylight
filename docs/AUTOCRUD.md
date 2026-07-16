# autocrud

Turn SeaORM entities into a JSON CRUD + metadata HTTP API — and an optional auto-generated web
admin — with **no per-model code**. `autocrud` introspects your entities at runtime: every column
becomes a field, primary/foreign keys are detected, and FK-backed relations are discovered. The only
thing you declare by hand is many-to-many (SeaORM can't enumerate it).

- [Install & features](#install--features)
- [Quick start](#quick-start)
- [Configuring a model](#configuring-a-model) — `MetaModel`, `MetaField`, `MetaRelation`
- [The HTTP API](#the-http-api) — routes, read/write formats, query params, errors
- [Validation & transforms](#validation--transforms)
- [Metadata](#metadata) — for building UIs
- [CSV import/export](#csv-importexport)
- [Web admin](#web-admin-alpine) — `alpine::Table`
- [OpenAPI](#openapi)
- [Architecture & extending](#architecture--extending)

---

## Install & features

```toml
[dependencies]
autocrud = { version = "*", features = ["alpine", "openapi", "csv"] }
sea-orm  = { version = "1.1", features = ["macros", "with-json"] }
```

| Feature | Default | Pulls | Gives you |
|---|---|---|---|
| `axum` | ✅ | `axum` | the HTTP router (`Crud::into_router`, `Engine::router`) |
| `alpine` | | `askama` | the server-rendered admin table/form (`alpine::Table`) |
| `openapi` | | `utoipa` | runtime OpenAPI 3.1 generation (`openapi::json`) |
| `csv` | | `csv` | CSV import/export routes + `csv_io` |

Entities must serialize to JSON — derive `Serialize` (SeaORM's `with-json` feature enables it on
generated models). **Requirements:** a single-column primary key and single-column to-one foreign
keys (any URL-safe scalar type — int, UUID, string slug). N:M junction tables are never registered,
so their composite keys are fine.

## Quick start

```rust
use autocrud::seaorm::{Crud, MetaModel};

let db = /* sea_orm::DatabaseConnection */;

let author = MetaModel::new(author::Entity);       // fully auto: fields, PK, FK relations
let tag    = MetaModel::new(tag::Entity);

let mut post = MetaModel::new(post::Entity);
post.relate(&tag);                                 // declare the N:M (FK relations are automatic)

let mut crud = Crud::new(db, "/api/v1");           // base_path ("" for root)
crud.register(author);
crud.register(post);
crud.register(tag);

let app = crud.into_router();                       // axum::Router — merge/serve as usual
// axum::serve(listener, app).await?;
```

That serves full CRUD for `author`, `post`, `tag` under `/api/v1` (see [routes](#the-http-api)).
`crud.engine()` / `crud.into_engine()` give the transport-agnostic `Engine` if you want to drive it
without axum.

A runnable example lives in `examples/autocrud` (`cargo run -p autocrud-example`): five related
entities, the admin UI, Swagger, and seed data.

## Configuring a model

`MetaModel::new(entity)` gives you a fully working model. You only touch it to tweak visibility,
add labels/help/defaults, attach validators, or declare N:M.

### `MetaModel<E>`

| Member | Kind | Meaning |
|---|---|---|
| `MetaModel::new(entity)` | ctor | Auto-build from the entity. |
| `.field(name)` / `.fields()` | mut / read | Tweak / iterate a scalar field (panics on unknown name). |
| `.relation(name)` / `.relations()` | mut / read | Tweak / iterate a relation. |
| `.relate(&other)` | mut | Declare a relation to another model — **required for N:M**. Chainable. |
| `slug: String` | field | URL segment; default `slugify(table_name)`. Override before register. |
| `row_label: Box<dyn Fn(&Value) -> String + ...>` | field | Row's display label; default fallback chain (below). |
| `validate_row: Option<...>` | field | Cross-field validator (see [validation](#validation--transforms)). |

`Crud::register(mm)` consumes the model. FK relations need no `relate`; `relate` exists only because
SeaORM can't enumerate N:M — it names the target type once.

```rust
let mut post = MetaModel::new(post::Entity);
post.field("views").read_only = true;
post.field("title").label = Some("Title".into());
post.field("title").description = Some("The post headline.".into());
post.slug = "articles".into();                     // /api/v1/articles
post.row_label = Box::new(|row| row["title"].as_str().unwrap_or_default().to_string());
post.relate(&tag);
```

**Row label** (used in relation links, terse rows, pickers): default is the first present of
`name | title | username | bio | label`, else `#<pk>`. Reassign the closure to override.

### `MetaField`

```rust
pub struct MetaField {
    // introspected (informational):
    pub name: String,
    pub logical_type: LogicalType,   // Int | Float | Bool | Text | Date | DateTime | Uuid | Json | Enum | Other
    pub is_pk: bool,
    pub is_fk: bool,
    // visibility (change freely):
    pub read_only: bool,   // in reads, ignored on write        default: true if is_pk
    pub write_only: bool,  // in writes, omitted from reads      default: false (e.g. password)
    pub hidden: bool,      // in neither reads/writes/metadata   default: true if is_fk
    // presentation (optional; surfaced in metadata for the UI):
    pub label: Option<String>,
    pub description: Option<String>,
    pub default: Option<Value>,        // create-form default (edit uses the row)
    // hooks (optional; all None):
    pub validate:  Option<Box<dyn Fn(&Value) -> Result<(), String> + ...>>,
    pub on_write:  Option<Box<dyn Fn(Value) -> Value + ...>>,   // inbound  (e.g. hash)
    pub on_read:   Option<Box<dyn Fn(&Value) -> Value + ...>>,  // outbound (e.g. redact)
}
```

Defaults tie behavior to structure: **PK → `read_only`**, **FK → `hidden`** (represented by its
relation). The three visibility flags cover both directions — a redacted-but-writable field uses
`on_read`; a write-only secret uses `write_only = true` + `on_write = hash`.

### `MetaRelation`

Auto-discovered from the entity's relations; you rarely construct one. To-one (owns the FK) and N:M
are writable by default; inverse to-many (has_many) is read-only by default.

```rust
pub struct MetaRelation {
    pub name: String,
    pub target: String,              // target table name (mapped to the target's slug for the API)
    pub cardinality: Cardinality,    // ToOne | ToMany
    pub owns_fk: bool,               // true = the FK is on this row (belongs_to)
    pub fk_column: Option<String>,   // Some when owns_fk
    pub read_only: bool,
    pub hidden: bool,
    pub label: Option<String>,
    pub description: Option<String>,
}
```

## The HTTP API

Mounted under `base_path`.

| Method | Path | Action |
|---|---|---|
| `GET` | `/{entity}` | list — search + sort + paginate; `?view=terse`, `?all=true`, `?format=csv` |
| `GET` | `/{entity}/{pk}` | one row (with relations) |
| `POST` | `/{entity}` | create → `201`, returns the row |
| `PATCH` | `/{entity}/{pk}` | partial update → `200`, returns the row |
| `DELETE` | `/{entity}/{pk}` | delete → `200`, returns the deleted row |
| `DELETE` | `/{entity}` | bulk delete matching rows → `{ "deleted": N }` |
| `POST` | `/{entity}/_import` | CSV import (feature `csv`) |

### Read format

A row is a **flat object keyed by column name**. Hidden fields, write-only fields, and raw FK
columns are omitted. Relations embed `{id, label}` (**no URLs** — build them from the relation
metadata's `item_url` template).

```jsonc
GET /api/v1/post/1
{
  "id": 1, "title": "Rust intro", "body": "…", "views": 100,
  "author": { "id": 1, "label": "Ada Lovelace" },   // to-one → {id,label} | null
  "tag": [ { "id": 1, "label": "rust" } ]           // to-many/N:M → array
}
```

`GET`/`POST`/`PATCH`/`DELETE` of a single row return this record directly. **List** returns a page,
each item an envelope:

```jsonc
GET /api/v1/post
{ "total": 45, "page": 1, "per_page": 25,
  "data": [ { "id": 1, "label": "Rust intro", "row": { /* record above */ } } ] }
```

`?view=terse` drops `row`, leaving `{id, label}` per item — ideal for relation pickers. A relation
link, a terse item, and an envelope-minus-`row` are the same shape.

### Write format

Flat object keyed by **writable column names**; relations by name. Absent keys → unchanged (PATCH) /
defaulted (POST). Read-only/hidden fields, the PK on create, and unknown keys are ignored.

```jsonc
POST /api/v1/post
{ "title": "Async Rust", "views": 0, "author": 1, "tag": [1, 3] }
```

| Relation | Value | Effect |
|---|---|---|
| to-one (owns FK) | `id` / `null` | set / clear this row's FK |
| N:M | `[id, …]` | replace this row's junction rows |
| inverse to-many | `[id, …]` | reassign target rows' FK (**read-only by default**) |

Create/update is transactional. Deleting a row clears its N:M junction rows first.

### Query params (list & bulk delete)

All map onto one `ListQuery`; the backend builds the SQL filter from it once (shared by list, terse
pickers, CSV export, and bulk delete).

| Param | Meaning |
|---|---|
| `q=<term>` | naive full-text: `LIKE '%term%'` across text columns |
| `<col>=<val>` | column `LIKE '%val%'` (any non-reserved key) |
| `sort=views:desc,title` | whitelisted column sort (unknown column → 400) |
| `page` / `per_page` | pagination (default `per_page=25`) |
| `all=true` | return every match unpaginated; also the guard that permits a whole-table bulk delete |
| `ids=1,2,3` | restrict to these primary keys (`pk IN (…)`) — drives "delete selected" |
| `view=terse` | list items omit `row` |
| `format=csv` | CSV export instead of JSON |

**Bulk delete** (`DELETE /{entity}`) runs one set-based `DELETE … WHERE` in the backend (plus a
subquery to clear N:M junctions) — not a per-row loop, so it scales to large tables. It refuses to
wipe the whole unfiltered table unless you pass `?all=true`, and returns a count (not the rows).

### Errors

`{ "error": … }` with status **400** (bad body / unknown column), **404** (unknown entity / missing
row), **405** (read-only), **422** (validation, structured — see below), **500** (DB).

## Validation & transforms

Create/update pipeline (hooks optional):

1. Parse JSON object (else 400).
2. Select writable columns (ignore read-only / hidden / PK-on-create / unknown).
3. **Coerce** each field to its logical type (mismatch → field error).
4. Field `validate(&coerced)` → field errors.
5. `MetaModel::validate_row(&map)` → cross-field errors.
6. Any errors → **422**, no write: `{ "error": "validation failed", "fields": {…}, "errors": [ … ] }`.
7. Apply `on_write` (e.g. hash).
8. In one transaction: write scalars, then relation ops.
9. Reload, apply `on_read`, serialize.

Order is **coerce → validate → transform**.

```rust
post.field("title").validate = Some(Box::new(|v| {
    if v.as_str().unwrap_or("").trim().is_empty() { Err("Title cannot be empty".into()) }
    else { Ok(()) }
}));
post.validate_row = Some(Box::new(|fields| {
    let mut errs = autocrud::ValidationErrors::new();
    if fields.get("title") == fields.get("body") { errs.general("Title and body must differ."); }
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}));
```

Field errors render under the field; `errors[]` are cross-field/banner errors.

## Metadata

The structural description a UI needs is available **in-process** (there is no `_meta` HTTP route):

- `Engine::meta_one(slug) -> Value` — one entity's descriptor with ordered `columns`.
- `Engine::meta_all() -> Value` — the entity catalog.

```jsonc
{
  "entity": "post", "url": "/api/v1/post", "primary_key": ["id"],
  "columns": [
    { "kind": "field", "name": "id", "type": "Int", "read_only": true, "write_only": false },
    { "kind": "field", "name": "title", "type": "Text", "read_only": false, "write_only": false,
      "label": "Title", "description": "The post headline." },
    { "kind": "relation", "name": "author", "target": "author", "cardinality": "ToOne",
      "fk_column": "author_id", "read_only": false,
      "list_url": "/api/v1/author", "item_url": "/api/v1/author/{id}" },
    { "kind": "relation", "name": "tag", "target": "tag", "cardinality": "ToMany", "read_only": false,
      "list_url": "/api/v1/tag", "item_url": "/api/v1/tag/{id}" }
  ]
}
```

Columns are **ordered**: a to-one relation appears in place of its FK column; inverse/N:M relations
are appended; hidden columns are omitted. `list_url` fills pickers (`GET {list_url}?q=…&view=terse`);
`item_url` is the link template a consumer expands with a row's id.

## CSV import/export

Feature `csv`. A thin layer over the `Engine` — every imported row goes through the same
coerce/validate pipeline as HTTP.

- **Export:** `GET /{entity}?format=csv` → `text/csv`. Reuses the list route, so `q`/filters/`sort`
  apply — you export exactly what you'd see, unpaginated.
- **Import:** `POST /{entity}/_import` with a CSV body → `{ created, updated, failed, errors: [{row, message}] }`.

Format (round-trippable): header = column names (write-only omitted); field → scalar; to-one → the
target id (blank if none); N:M → ids joined with `|` (e.g. `1|3`). On import a row **with** a PK value
updates that row, **without** creates one; read-only columns are ignored. Import is best-effort — a
failed row is reported with its line number and the rest continue.

## Web admin (`alpine`)

Feature `alpine`. `alpine::Table` renders a Bootstrap-5 + Alpine.js **HTML fragment** for one
entity. The *shape* (columns) is read from the `Engine` in-process and embedded; *data* is fetched
client-side from the JSON API. You provide a shell page that loads Bootstrap 5.3 CSS/JS and Alpine 3
(both via CDN) and drops the fragment into a `<div>`.

```rust
let html: String = autocrud::alpine::Table::new(&engine, "post")
    .title("Post")          // heading + form header; default: the slug
    .read_only(false)       // true → display only (no create/edit/delete, no form)
    .search(true)           // search box → ?q=
    .pagination(true)
    .per_page(30)
    .confirm(true)          // confirm before delete
    .picker_threshold(25)   // relations with > N target rows use a search→select picker
    .render()?;
```

Gives you: search, a `|< << N-3…N…N+3 >> >|` pager, a create/edit **modal form** (typed inputs;
relation dropdown for small targets or live search→select for large ones; inline field + row
validation errors), per-row and bulk delete (delete-selected / delete-all-matching), and CSV
import/export buttons. Field labels/help/defaults and validators come from the `MetaModel` you
registered.

## OpenAPI

Feature `openapi`. Routes are per-entity and known only at runtime, so the document is built at
runtime from the `Engine`:

```rust
let spec: String = autocrud::openapi::json(&engine, "My API");   // serve at /openapi.json
// or: autocrud::openapi::build(&engine, "My API") -> utoipa::openapi::OpenApi
```

Emits the CRUD + bulk-delete operations per entity (tagged by slug, with query/path params). Point
Swagger UI at the served JSON. Per-field response schemas are future work.

## Architecture & extending

The transport-agnostic **`Engine`** is a registry that owns URLs/metadata, does the JSON↔CSV
transform, wires routes, and **forwards finished JSON**. Every backend implements the per-entity
**`Accessor`** trait — `slug` / `pk` / `columns` + `list` / `get` / `create` / `update` / `delete` /
`delete_many`, each data method returning ready-to-send JSON. The trait names no ORM types.

SeaORM is one backend (`autocrud::seaorm`); it does the heavy lifting (introspection, projection,
validation, relation resolution, set-based bulk delete). A different backend (in-memory, another ORM)
is just another `Accessor` implementation reusing the whole engine + router unchanged. See
`../ARCHITECTURE.md` for the design and rationale.
