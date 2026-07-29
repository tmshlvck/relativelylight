# `relativelylight::crud`

Turn SeaORM entities into a JSON CRUD + metadata HTTP API — and an optional auto-generated web
admin — with **no per-model code**. The `crud` module introspects your entities at runtime: every
column becomes a field, primary/foreign keys are detected, and FK-backed relations are discovered.
The only thing you declare by hand is many-to-many (SeaORM can't enumerate it).

- [Install & features](#install--features)
- [Quick start](#quick-start)
- [Configuring a model](#configuring-a-model) — `MetaModel`, `MetaField`, `MetaRelation`
- [The HTTP API](#the-http-api) — routes, read/write formats, query params, errors
- [Validation & transforms](#validation--transforms)
- [Metadata](#metadata) — for building UIs
- [CSV import/export](#csv-importexport)
- [Web admin](#web-admin-ui) — `ui::Table` and `ui::Admin`
- [OpenAPI](#openapi)
- [Composing with your app](#composing-with-your-app) — you own the roots
- [Architecture & extending](#architecture--extending)

---

## Install & features

```toml
[dependencies]
relativelylight = { version = "*", features = ["ui", "openapi", "csv"] }
sea-orm = { version = "1.1", features = ["macros", "with-json"] }
```

| Feature | Default | Pulls | Gives you |
|---|---|---|---|
| `crud` | ✅ | `sea-orm` | the CRUD engine + SeaORM backend (this module) |
| `axum` | ✅ | `axum` | the HTTP router (`Crud::into_router`, `Engine::router`) |
| `ui` | | `askama` | the server-rendered admin components (`crud::ui::Table`, `::Admin`) |
| `openapi` | | `utoipa` | runtime OpenAPI 3.1 generation (`crud::openapi::json`) |
| `csv` | | `csv` | CSV import/export routes + `crud::csv_io` |
| `csrf` | | `rand_core` | `Crud::csrf` — require a CSRF token on writes (implied by `auth`) |

Enable only what you use — an unused feature pulls no dependencies.

Entities must serialize to JSON — derive `Serialize` (SeaORM's `with-json` feature enables it on
generated models). **Requirements:** a single-column primary key and single-column to-one foreign
keys (any URL-safe scalar type — int, UUID, string slug). N:M junction tables are never registered,
so their composite keys are fine.

## Quick start

```rust
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::authz::Open;                  // per-model auth gate; Open = ungated

let db = /* sea_orm::DatabaseConnection */;

let author = MetaModel::new(author::Entity);       // fully auto: fields, PK, FK relations
let tag    = MetaModel::new(tag::Entity);

let mut post = MetaModel::new(post::Entity);
post.relate(&tag);                                 // declare the N:M (FK relations are automatic)

let mut crud = Crud::new(db, "/api/v1");           // base_path ("" for root)
crud.register(author, Open);                       // pass an auth gate to restrict — see docs/AUTH.md
crud.register(post, Open);
crud.register(tag, Open);

let app = crud.into_router();                       // axum::Router — merge/serve as usual
// axum::serve(listener, app).await?;
```

That serves full CRUD for `author`, `post`, `tag` under `/api/v1` (see [routes](#the-http-api)).
`crud.engine()` / `crud.into_engine()` give the transport-agnostic `Engine` if you want to drive it
without axum.

A runnable example lives in `examples/crud` (`cargo run -p crud-example`): five related
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

`Crud::register(mm, gate)` consumes the model and takes its authorization gate (`authz::Open` for
ungated — see [docs/AUTH.md](AUTH.md)). FK relations need no `relate`; `relate` exists only because
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
    pub display: Option<FieldDisplay>, // presentation override, e.g. DateTime (see .datetime())
    // hooks (optional; all None):
    pub validate:  Option<Box<dyn Fn(&Value) -> Result<(), String> + ...>>,
    pub nullable:  bool,        // from the entity: does the column accept NULL? (read-only info)
    pub required:  bool,        // NOT NULL + no default + not the PK → a create must carry it
    pub options: Vec<String>,   // allowed values; introspected from an enum column, or set by hand
    pub blank_is_null: bool,    // nullable + empty string submitted → store NULL (default true)
    pub on_write:  Option<Box<dyn Fn(Value) -> Value + ...>>,   // inbound  (e.g. hash)
    pub on_read:   Option<Box<dyn Fn(&Value) -> Value + ...>>,  // outbound (e.g. redact)
}
```

Defaults tie behavior to structure: **PK → `read_only`**, **FK → `hidden`** (represented by its
relation). The three visibility flags cover both directions — a redacted-but-writable field uses
`on_read`; a write-only secret uses `write_only = true` + `on_write = hash`.

**Password helper (feature `auth`).** For the common password case, `MetaField::password()` does that
whole write-only-secret setup in one call — write-only, labelled `"Password"`, argon2id-hashed on
write, blank by default:

```rust
let mut user = MetaModel::new(auth::user::Entity);
user.field("password_hash").password();   // plaintext in the form → hash in the column, never read back
```

In the admin form it renders as a **masked input**; a blank value on *edit* keeps the current hash
(so editing other fields doesn't wipe the password). A blank on *create* stores an **empty hash**,
which [`auth::verify_password`] can never match — so that account simply has no password login (e.g. an
SSO / PassKey user).

**Datetime helper.** An integer column holding **Unix seconds (UTC)** is stored/validated as an
`Int`, so by default the UI renders it as a plain number. `MetaField::datetime()` flags it as a
datetime *for presentation only*: the table cell shows a readable UTC timestamp
(`YYYY-MM-DD HH:MM:SS UTC`) and the create/edit form uses a `datetime-local` picker (edited in UTC,
stored back as integer seconds). Storage, validation, and the OpenAPI schema are unchanged.

```rust
zone.field("created_at").datetime();   // read-only stamp → formatted cell (no input)
key.field("expires_at").datetime();    // editable timestamp → datetime picker (blank = null)
```

For a read-only column this affects only the cell (read-only fields have no form input). Cells and
the form picker render in UTC by default, or follow a timezone selection when you include the
timezone JS/picker — see **[docs/TIME.md](TIME.md)**.

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
columns are omitted. Relations embed `{id, label}` — just the identity and a display label, **no
URLs**. (The admin UI shows relations as text/badges, not links; if you want a row to link
somewhere, use a [custom formatter](#web-admin-ui).)

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

`{ "error": … }` with status **400** (bad body / unknown column), **401** (the model's gate needs a
login), **403** (the gate denied the caller, *or* a write failed the CSRF check — see below), **404**
(unknown entity / missing row), **405** (read-only), **409** (a unique / foreign-key constraint rejected
the write), **422** (validation, structured — see below), **500** (other DB error).

### CSRF on writes (feature `csrf`)

A cookie-authenticated API is a CSRF target, so the engine can require a double-submit token on every
write:

```rust
crud.csrf(auth.csrf());   // share the auth module's token cookie
```

Each `POST`/`PATCH`/`DELETE` must then echo the `rl_csrf` cookie in an **`X-CSRF-Token`** header, or it
gets `403 {"error":"csrf token missing or invalid"}` — checked *before* the gate, so a forged write
never reaches the database. Reads need no token, and requests carrying an `Authorization` header are
exempt (a Bearer credential isn't ambient). `Table`/`Admin` add the header to their write `fetch` calls
automatically. Off by default; full design in [AUTH.md §7](AUTH.md).

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
    let mut errs = relativelylight::crud::ValidationErrors::new();
    if fields.get("title") == fields.get("body") { errs.general("Title and body must differ."); }
    if errs.is_empty() { Ok(()) } else { Err(errs) }
}));
```

Field errors render under the field; `errors[]` are cross-field/banner errors.

### Nullable columns: `""` vs `NULL`

Nullability is read from the entity (`ColumnDef::is_null()`) into `MetaField::nullable`, reported in the
metadata (`"nullable": true`) and in the OpenAPI schema (as a 3.1 type union, `"type": ["string","null"]`).
It also decides what an **empty** submitted string means:

| Column | Submitted `""` | Stored |
|---|---|---|
| nullable text/uuid/date/datetime | "nothing here" | `NULL` |
| `NOT NULL` | the empty string | `""` |

The canonicalization happens in the engine (right after coercion, before validators and `on_write`), so
**every** writer gets it — the admin UI, an API client, a CSV import. Without it a column ends up `NULL`
for some rows and `""` for others, and every later `is_some()` check becomes a trap: that is exactly how
an account created in the admin panel could end up with `sso_provider = ""` and never log in again
(AUTH.md §5b). Two consequences worth knowing:

- Validators see the canonical value, so a `validate_str` predicate gets `null` (which passes —
  nullability is the column's concern) instead of `""`.
- A `NOT NULL` column is untouched, which is what keeps `MetaField::password()`'s blank-means-no-password
  behaviour working.

Set `field("x").blank_is_null = false` where an empty string is a value you mean to keep distinct from
absent.

### Required columns

`MetaField::required` is introspected as **NOT NULL, no default declared on the entity, and not the
primary key** — the three facts that make an omission a database error rather than a legitimate blank. It
is published as `"required": true` in the metadata, listed in the OpenAPI **create** schema's `required`,
marked with a red `*` in the admin form (unless the field has a `default`, which the form pre-fills — so
`MetaField::password()`, whose blank means "no password", gets no marker), and **enforced by the engine**:

| Write | Field | Result |
|---|---|---|
| create | absent | `422 {"fields":{"title":"required"}}` |
| create or update | explicit `null` | `422` — nulling a `NOT NULL` column can never succeed |
| update | absent | fine: absent means "leave it alone", so partial updates still work |
| either | `""` | fine — `required` means **present**, not non-empty |

Before this, an omitted `NOT NULL` column reached the database, which rejected it, which surfaced as a
**`500` carrying the database's own error text** — the wrong status, no field for the form to highlight,
and the schema leaked to the caller.

Two ways out where introspection guesses wrong:

- `field("x").required = false` — needed when the **database** has a default the entity doesn't declare
  (`DEFAULT now()` in DDL rather than `#[sea_orm(default_value = ..)]`); SeaORM can't see it.
- `field("x").read_only = true` (or `hidden`) exempts it automatically, since a caller then has no way to
  supply it. That is what spares a `created_at`/`updated_at` filled by an
  `ActiveModelBehavior::before_save` hook — **provided you mark it read-only**, as both examples do. An
  app that registers such an entity without doing so will start seeing `422`s on create.

`required` describes presence only. For "must not be blank", add `validate_str(validate::non_empty)`.

One gap it deliberately doesn't cover: a `NOT NULL` column with no default that is **hidden or read-only**
can't be created at all, and still fails at the database. `required` can't help, because a column filled by
an `ActiveModelBehavior::before_save` hook looks identical to one nothing fills — so refusing the write
would break the hook case. If creates on a model fail with a database `NOT NULL` error, look for a hidden or
read-only column with nothing filling it (`examples/time` hides `body`, which is why that demo is
read-only in practice).

### Enumerations: a closed set of values

`MetaField::options` is the list of values a column accepts — empty for everything else. It is
**introspected** from `ColumnType::Enum`, so a Postgres/MySQL enum needs no per-model code:

| Where | Effect |
|---|---|
| admin form | a `<select>` instead of a free-text input (with a blank choice where the column is nullable or not required) |
| metadata | `"options": ["draft","review",…]`, emitted only for columns that have a set |
| OpenAPI | a string schema with `enum`, so a generated client can refuse a bad value without a round trip |
| write path | membership checked before your own validator → `422 {"fields":{"status":"must be one of: …"}}` |

Values match **exactly**; database enums are case-sensitive.

**Declare it by hand for the common SQLite shape.** A `DeriveActiveEnum` with `db_type = "String"` is a text
column as far as the schema is concerned, so there are no variants to find:

```rust
post.field("status").options = vec!["draft".into(), "review".into(), "published".into()];
```

That works on *any* column — the widget and the check key off the list, not the logical type — so it is also
how you close a set that the database doesn't model as an enum at all. Both `examples/crud` and
`examples/adminpanel` do exactly this for `post.status`.

Before this, an enum column fell through to a free-text input and **any** string was accepted: on a real
enum column the database rejected it (a `500`), and on a text-backed one the typo was simply stored.

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
      "fk_column": "author_id", "read_only": false, "list_url": "/api/v1/author" },
    { "kind": "relation", "name": "tag", "target": "tag", "cardinality": "ToMany", "read_only": false,
      "list_url": "/api/v1/tag" }
  ]
}
```

Columns are **ordered**: a to-one relation appears in place of its FK column; inverse/N:M relations
are appended; hidden columns are omitted. `list_url` is the target's list endpoint — the one URL a
consumer needs, to fill relation pickers (`GET {list_url}?q=…&view=terse`).

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

## Web admin (`ui`)

Feature `ui`. Two components — `Table` (one entity) and `Admin` (a side-panel over many). Both
render Bootstrap-5 + Alpine.js **HTML fragments**; you own the shell. `ui::Table` renders one
entity. The *shape* (columns) is read from the `Engine` in-process and embedded; *data* is fetched
client-side from the JSON API. You provide a shell page that loads Bootstrap 5.3 CSS/JS and Alpine 3
(both via CDN) and drops the fragment into a `<div>`.

```rust
let html: String = relativelylight::crud::ui::Table::new(&engine, "post")
    .title("Post")          // heading + form header; default: the slug
    .description("Blog posts — one row per article.")  // optional muted subtitle under the heading
    .read_only(false)       // true → display only (no create/edit/delete, no form)
    .search(true)           // search box → ?q=
    .pagination(true)
    .per_page(30)
    .confirm(true)          // confirm before delete
    .picker_threshold(20)   // relations with > N target rows use a search→select picker (default 20)
    // custom cell renderer — turn the title into a link built from the row:
    .format("title", r#"(v, row) => `<a href="/posts/${row.id}">${v}</a>`"#)
    .render()?;
```

Gives you: search, a `|< << N-3…N…N+3 >> >|` pager, a create/edit **modal form** (inline field + row
validation errors), per-row and bulk delete (delete-selected / delete-all-matching), and CSV
import/export (tucked into a `⋮` overflow menu). Field labels/help/defaults and validators come from
the `MetaModel` you registered.

**Form inputs:** numbers/text as typed inputs, **booleans as a toggle switch**, and **`write_only`
string fields as a masked password input** (secrets like a password: typed in, hashed by an `on_write`
hook, never shown in reads). On **edit** a write-only field starts blank and is *omitted* from the
save when left blank — "leave blank to keep current" — so a blank doesn't clobber the stored secret;
on **create** it's sent as-is (an empty value is allowed, e.g. an account with no password).

The modal is a real **`<form>`** submitted with `fetch` (`@submit.prevent`), so <kbd>Enter</kbd> in any
field saves, and a browser's password manager gets the one form-submission signal it needs to offer to
remember a credential *at the right moment*. Immediately after a successful save — and on Cancel/close —
every `write_only` field is blanked and the form reset, so a secret never lingers in a hidden input.
Without that, Chrome re-offers to save the **previously** created account's password on every
subsequent row you save (it keeps re-detecting the stale value), and offers the wrong credential for
this site. <kbd>Enter</kbd> inside a relation search box searches instead of submitting.

Relations
pick a widget by the target's size (from a `total` probe): **≤ `picker_threshold`** rows → a plain
`<select>` (to-one) / multi-`<select>` (N:M) with all options preloaded; **more** → a live
search→select combobox that queries the target (`GET {list_url}?q=…&view=terse`) with a
`Search N items…` prompt — a single input for to-one, removable chips + an add-search for N:M. The
current selection is seeded from the row, so it stays visible on edit even when it's not in the first
page of results.

**Cell rendering:**
- Fields show their value; **booleans** render as green **Yes** / red **No** badges by default.
- Relations show labels, not links into the API — a to-one as text, a to-many/N:M as a row of
  badges.
- **`.format(column, js)`** overrides a column's cell with your own renderer: a JS arrow function
  `(value, row) => htmlString`, inserted as HTML. `value` is the raw cell value and `row` is the full
  record, so you can build links or badges from any field (e.g. `row.id`). The returned string is
  inserted verbatim — **escape untrusted content yourself**.

### `Admin` — a whole admin in one component

`ui::Admin` composes many `Table`s plus a **side-panel** into one fragment: pick a model to
view/edit (switching is client-side, no reload). You choose the order and interleave **group
headings**, **separators**, and **custom links**:

```rust
let html = relativelylight::crud::ui::Admin::new(&engine)
    .title("Admin")
    .group("Content")
    .entity_with("post", |t| t.per_page(10).format("title", "…"))  // configure the Table
    .entity("tag")                                                 // or defaults
    .separator()
    .group("People")
    .entity_with("user", |t| t.read_only(true))
    .link("API docs", "/docs")                                     // static link (navigates)
    .render()?;
```

Each entity is a full `Table`, so per-row edit, bulk delete, CSV, pickers, and formatters all work
per model. Switching happens in the browser (all tables render into the page; the side-panel toggles
which is visible), so it's a single fragment you drop into your shell — no extra routes. See
`examples/adminpanel`.

Builder methods:

| Method | Effect |
|---|---|
| `.title(name)` | heading above the side-panel |
| `.entity(slug)` | add a model with default `Table` config |
| `.entity_with(slug, \|t\| …)` | add a model, configuring its `Table` |
| `.entities()` | append every registered model (default config) — quick "show everything" |
| `.group(name)` | a group heading in the side-panel |
| `.separator()` | an `<hr>` |
| `.link(label, href)` | a custom static link (navigates normally) |
| `.render()` | the HTML fragment (`Result<String>`) — all write controls shown |
| `.render_for(&headers)` | async; per-request fragment that hides a model's write controls when its auth gate denies a write for the caller (see [docs/AUTH.md](AUTH.md)) |

Items appear in call order, so you control the layout by interleaving `entity*`, `group`,
`separator`, and `link`.

## OpenAPI

Feature `openapi`. Routes are per-entity and known only at runtime, so the document is built at
runtime from the `Engine`:

```rust
let spec: String = relativelylight::crud::openapi::json(&engine, "My API");   // serve at /openapi.json
// or: relativelylight::crud::openapi::build(&engine, "My API") -> utoipa::openapi::OpenApi
```

Emits the CRUD + bulk-delete operations per entity (tagged by slug, with query/path params) **and
component schemas derived from the column metadata**: a read record `{slug}` (typed fields; relations
as `{id, label}`) and a write body `{slug}_write` (writable fields; relations by id). Operations
`$ref` these — request bodies use `{slug}_write`, single-row responses use `{slug}`, and the list
response is the page envelope wrapping `{slug}`. Point Swagger UI at the served JSON and the models
render. Field types carry `format` where useful — `int64`/`double`, and `date` / `date-time` /
`uuid` for those logical types; enum/other are plain `string`.

Use [`merge_into`](#composing-with-your-app) to fold these paths + schemas into your app's own
document instead of serving a standalone one.

## Composing with your app

relativelylight is meant to be **part of** a larger app, not the whole thing. Your app owns the three roots;
relativelylight contributes into them:

- **axum router** — `Crud::into_router()` (or `Engine::router()`) returns a `Router` with crud's
  routes under `base_path`. Your app owns `/` and merges crud in:
  ```rust
  let app = Router::new()
      .route("/", get(home))
      .route("/ui/{slug}", get(ui_page))    // your own routes
      .merge(crud.into_router());           // crud under /api/v1
  ```
  Keep a non-empty `base_path` (e.g. `/api/v1`) so crud's `/{entity}` routes stay under a prefix
  and can't shadow yours.
- **askama shell** — `ui::Table::render()` returns an **HTML fragment**, never a full page. Your
  app owns the chrome (the `<html>`/navbar/footer, and the Bootstrap + Alpine `<script>`/`<link>`
  tags) and drops the fragment into a `<div>`. the library ships no page and imposes no layout. Your
  askama templates and the library's live in a separate crate, so they don't collide.
- **utoipa document** — build your own `OpenApi` (your `info`, `servers`, `security`, and any of your
  own non-crud paths), then merge the crud endpoints + schemas in. `merge` keeps *your*
  `info`/`servers`; it only appends paths and component schemas:
  ```rust
  use utoipa::openapi::{InfoBuilder, OpenApiBuilder};
  let app_doc = OpenApiBuilder::new()
      .info(InfoBuilder::new().title("My App API").version("1.0.0").build())
      // .paths(my_own_paths) …
      .build();
  let doc = relativelylight::crud::openapi::merge_into(app_doc, &engine);   // your root, the crud entities
  ```

The example (`examples/crud`) does all three: it owns `/`, `/ui/{slug}`, `/openapi.json`, `/docs`
and its Bootstrap/Alpine shell, and merges the crud router and OpenAPI into them.

## Write observer (audit)

Register a [`WriteObserver`](../src/observe.rs) with `Crud::on_write` to be notified after every
**committed** write (create / update / delete / bulk-delete) through the engine — the hook for audit
logging. Each write handler fires a `WriteEvent` carrying the change *and* the request context:

```rust
pub struct WriteEvent<'a> {
    pub source: &'static str,   // "crud" here
    pub op: Operation,          // Create | Update | Delete
    pub entity: &'a str,        // slug, e.g. "post"
    pub key: Option<String>,    // pk (None for a bulk delete)
    pub before: Option<Value>,  // prior row (update/delete); None on create
    pub after: Option<Value>,   // new row (create/update); None on delete
    pub headers: &'a HeaderMap, // resolve the actor (auth.identify) + read X-Forwarded-For
    pub client_ip: IpAddr,        // the caller, already resolved by middleware::resolve_real_ip
}

let mut crud = Crud::new(db, "/api/v1");
crud.register(post_mm, gate);
crud.on_write(my_audit_sink.clone());   // Arc<dyn WriteObserver>
```

Notes: the observer runs **after commit** (a failed write fires nothing); `before` on update is a
best-effort pre-fetch; a **bulk delete** reports the affected count in `after` (`{"deleted": N}`), not
every row, so a "delete all" can't blow up the audit. The library provides only the hook and the
`WriteEvent` type — the app owns the audit **table**, resolves the actor from `headers` (e.g.
`auth.identify`), writes the row, and handles retention — the address arrives already resolved, so every
audit row names the same client the lockout counted and the access log printed. The same
`Arc` can also be handed to `Auth::on_write` (see [AUTH.md](AUTH.md)) so one sink captures both the
auto-CRUD and the auth surfaces. **Times are UTC** (`i64` Unix seconds) — see the timezone note in
[PRD.md](PRD.md).

## Architecture & extending

The transport-agnostic **`Engine`** is a registry that owns URLs/metadata, does the JSON↔CSV
transform, wires routes, and **forwards finished JSON**. Every backend implements the per-entity
**`Accessor`** trait — `slug` / `pk` / `columns` + `list` / `get` / `create` / `update` / `delete` /
`delete_many`, each data method returning ready-to-send JSON. The trait names no ORM types.

SeaORM is one backend (`relativelylight::crud::seaorm`); it does the heavy lifting (introspection, projection,
validation, relation resolution, set-based bulk delete). A different backend (in-memory, another ORM)
is just another `Accessor` implementation reusing the whole engine + router unchanged.

Why the seam sits here: relation resolution and field projection are *database* concerns — they run
queries and encode per-model visibility policy — so keeping them behind the accessor lets the engine
stay a pure pass-through. In the SeaORM backend, siblings are resolved through a `Weak`-keyed registry
(no reference cycle; the strong `Arc`s live in the `Engine`), which preserves zero-config
auto-discovery — nothing needs declaring beyond N:M.
