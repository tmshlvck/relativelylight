# `relativelylight::crud`

Turn SeaORM entities into a **server-rendered CRUD admin** with **no per-model code**. The `crud`
module introspects your entities at runtime: every column becomes a field, primary/foreign keys are
detected, and FK-backed relations are discovered. The only thing you declare by hand is many-to-many
(SeaORM can't enumerate it).

There is **no JSON API and no JavaScript framework**. The columns the module computes go straight into
rendered HTML — one Rust `match` per cell and per form input — and writes come back as posted forms.
An app that wants to publish a JSON API writes those handlers itself over the same typed [`Engine`]
(see [Reading and writing](#reading-and-writing)); its shape is a product decision this crate
deliberately doesn't make. [MIGRATION-0.3.md](MIGRATION-0.3.md) records why that changed in 0.3.

New here? **[APP.md](APP.md)** builds a whole app end to end (shell, nav bar, login, admin, your own
pages); this document is the reference for the parts. Coming from 0.2.x?
**[MIGRATION-0.3.md](MIGRATION-0.3.md)**.

- [Install & features](#install--features)
- [Quick start](#quick-start)
- [Configuring a model](#configuring-a-model) — `MetaModel`, `MetaField`, `MetaRelation`
- [Reading and writing](#reading-and-writing) — the engine API, the URL as state, errors, CSRF
- [Validation & transforms](#validation--transforms)
- [Columns](#columns) — what the UI renders from
- [CSV import/export](#csv-importexport)
- [Web UI](#web-ui-ui) — `ui::Table`, `ui::Form` and `ui::Admin`
- [Composing with your app](#composing-with-your-app) — you own the roots
- [Write observer (audit)](#write-observer-audit)
- [Architecture & extending](#architecture--extending)

---

## Install & features

```toml
[dependencies]
relativelylight = { version = "0.3", features = ["ui", "csv"] }
sea-orm = { version = "1.1", features = ["macros", "with-json"] }
```

| Feature | Default | Pulls | Gives you |
|---|---|---|---|
| `crud` | ✅ | `sea-orm` | the CRUD engine + SeaORM backend (this module) |
| `axum` | ✅ | `axum` | the request plumbing the UI needs, and the `middleware` module |
| `ui` | | `askama` | the server-rendered components (`crud::ui::Table`, `::Form`, `::Admin`); implies `axum` + `tz` |
| `csv` | | `csv` | CSV import/export for the UI + `crud::csv_io`; implies `tz` |
| `tz` | | `jiff` | timezone-aware rendering of integer-UTC timestamps (`time`) |
| `csrf` | | `rand_core` | `Crud::csrf` — require a token on writes (implied by `auth`) |

Enable only what you use — an unused feature pulls no dependencies.

Entities must serialize to JSON — derive `Serialize` (SeaORM's `with-json` feature enables it on
generated models). **Requirements:** a single-column primary key and single-column to-one foreign
keys (any URL-safe scalar type — int, UUID, string slug). N:M junction tables are never registered,
so their composite keys are fine.

## Quick start

```rust
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::{Admin, Outcome, ViewState};
use relativelylight::authz::Open;                  // per-model auth gate; Open = ungated

let db = /* sea_orm::DatabaseConnection */;

let author = MetaModel::new(author::Entity);       // fully auto: fields, PK, FK relations
let tag    = MetaModel::new(tag::Entity);

let mut post = MetaModel::new(post::Entity);
post.relate(&tag);                                 // declare the N:M (FK relations are automatic)

let mut crud = Crud::new(db);
crud.register(author, Open);                       // pass an auth gate to restrict — see docs/AUTH.md
crud.register(post, Open);
crud.register(tag, Open);

let engine = Arc::new(crud.into_engine());
```

Then **two handlers** on one route of your own — a `get` that renders, a `post` that writes:

```rust
fn panel(engine: &Engine) -> Admin<'_> {           // one definition, used by both
    Admin::new(engine).title("Admin").entity("author").entity("post").entity("tag")
}

let app = Router::new().route("/admin", get(show).post(save)).with_state(engine);

async fn show(headers: HeaderMap, uri: Uri, State(engine): State<Arc<Engine>>) -> Response {
    let state = ViewState::from_uri(&uri);         // page, sort, filters, search, ?edit=…
    match panel(&engine).render_for(&headers, &state).await {
        Ok(fragment) => Html(my_shell(fragment)).into_response(),
        Err(e) => e.into_response(),               // 401/403 from the model's gate, or a config error
    }
}

async fn save(headers: HeaderMap, uri: Uri, RealIp(ip): RealIp,
              State(engine): State<Arc<Engine>>, body: Bytes) -> Response {
    let state = ViewState::from_uri(&uri);
    match panel(&engine).submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),          // 303 back to the list
        Ok(Outcome::Invalid(state)) => {                                     // re-render with messages
            let fragment = panel(&engine).render_for(&headers, &state).await.unwrap_or_default();
            (StatusCode::UNPROCESSABLE_ENTITY, Html(my_shell(fragment))).into_response()
        }
        Err(e) => e.into_response(),
    }
}
```

That is the whole shape, and it is the same for `Table` and `Form`. `middleware::resolve_real_ip` is
**mandatory** (the write path reads `RealIp` for the audit trail) — see
[Composing with your app](#composing-with-your-app).

Runnable: `cargo run -p crud-example` (five related entities, ungated) and
`cargo run -p adminpanel-example` (the same thing login-gated, with 2FA and lockout panels).

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
| `.label_column(col)` | mut | Label rows by one column — and let *other* entities sort by a relation pointing here (below). |
| `validate_row: Option<...>` | field | Cross-field validator (see [validation](#validation--transforms)). |

`Crud::register(mm, gate)` consumes the model and takes its authorization gate (`authz::Open` for
ungated — see [docs/AUTH.md](AUTH.md)). FK relations need no `relate`; `relate` exists only because
SeaORM can't enumerate N:M — it names the target type once.

```rust
let mut post = MetaModel::new(post::Entity);
post.field("views").read_only = true;
post.field("title").label = Some("Title".into());
post.field("title").description = Some("The post headline.".into());
post.slug = "articles".into();                     // ?entity=articles
post.row_label = Box::new(|row| row["title"].as_str().unwrap_or_default().to_string());
post.relate(&tag);
```

**Row label** (used in relation links, terse rows, pickers): default is the first present of
`name | title | username | bio | label`, else `#<pk>`. Reassign the closure to override.

**Labels and sorting.** Another entity can sort by a relation pointing here — `?sort=author` ordering
by `author.name` rather than `author_id` — but only if the label is expressible as SQL. At registration
the label closure is **probed** once with a synthetic row, so the common one-column case is recognised
whether you wrote it as a closure or declared it:

```rust
author.label_column("name");                                              // declared
author.row_label = Box::new(|r| r["name"].as_str().unwrap_or_default().into()); // probed — same result
author.row_label = Box::new(|r| format!("{} <{}>", r["name"], r["email"]));     // not a column → not sortable
```

The third form still labels rows perfectly; relations pointing at it just report `sortable: false` and
400 an attempt to order by them, rather than quietly sorting by one part of a label. `label_column`
panics on an unknown column, like `field`.

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
    pub display: Option<FieldDisplay>, // form-input override (see widget overrides below)
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
stored back as integer seconds). Storage and validation are unchanged — only the input and the cell.

```rust
zone.field("created_at").datetime();   // read-only stamp → formatted cell (no input)
key.field("expires_at").datetime();    // editable timestamp → datetime picker (blank = null)
```

For a read-only column this affects only the cell (read-only fields have no form input). Cells and
the form picker render in UTC by default, or follow a timezone selection when you include the
timezone JS/picker — see **[docs/TIME.md](TIME.md)**.

### Widget overrides — picking the form input per field

`display` is the general form of the datetime helper: the input a field gets is derived from its type,
and these override that where the type alone can't know better. **Only the form input changes** —
`datetime` aside, cells keep rendering the plain value, because a table row is no place for a slider.

| Helper | Input | Needs |
|---|---|---|
| `.datetime()` | `datetime-local` picker (+ formatted cell) | an `Int` of Unix seconds |
| `.textarea(rows)` | `<textarea>` of `rows` rows | a text column |
| `.radio()` | radio group over `options` | a text column with non-empty `options` |
| `.range(min, max, step)` | slider, with the value shown beside it | `Int` or `Float`, `min < max` |
| `.email()` | `<input type="email">` | a text column |
| `.url()` | `<input type="url">` | a text column |

```rust
post.field("body").textarea(8);                    // prose
post.field("views").range(0.0, 500.0, 1.0);        // slider + readout
post.field("status").options = vec!["draft".into(), "published".into()];
post.field("status").radio();                      // …the options must exist first
author.field("email").email();
author.field("email").validate_str(validate::optional(Box::new(validate::email)));
```

**A widget that can't render its column is a render-time error naming the field** — a `.radio()` with no
`options`, a `.range()` on text, a `.textarea()` on a number — rather than a form quietly showing a
different input than the model asked for. Both `Form` and `Table` check it, so the failure arrives on the
first render.

**`email`/`url` are conveniences, not controls.** They give you the browser's own check and the right
mobile keyboard; a caller hitting the JSON API directly meets none of it, so pair them with
[`validate::email`](DATAINPUT.md) / `validate::url`, which is what actually runs. Likewise a `range`
`step` that doesn't divide an existing value puts the handle at the nearest step while the readout keeps
showing the exact stored number — the readout is the truthful one, since that's what a save would write.

**On the wire** `display` is a plain lowercase string (`"textarea"`, `"radio"`, …) with any parameters in
a sibling `widget` object (`{"rows": 8}`, `{"min":0.0,"max":500.0,"step":1.0}`), so a client switches on a
string rather than unpacking a tagged shape. Adding a widget is one variant in `FieldDisplay`, one case in
the resolver, one branch in the markup.

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

## Reading and writing

Everything is **typed and in-process**: there is no wire format between the engine and the renderer,
and none between your handlers and the engine either.

| `Engine` method | Returns | Notes |
|---|---|---|
| `columns(slug)` | `Vec<Column>` | the ordered field/relation description — what the UI renders from |
| `pk(slug)` | `String` | the primary-key field name |
| `list(slug, &ListQuery, terse)` | `Page` | one page of `RowItem { id, label, row }`; `terse` omits `row` |
| `get(slug, pk)` | `Value` | one finished row |
| `create(slug, &Value)` / `update(slug, pk, &Value)` | `Value` | the written row |
| `delete(slug, pk)` | `Value` | the deleted row |
| `delete_where(slug, &ListQuery)` | `u64` | one set-based `DELETE … WHERE`, not a loop |
| `write_batch(slug, rows)` | `BatchApplied` | many writes as one transaction (what CSV import uses) |
| `decide(slug, op, &headers)` | `Decision` | the model's gate — `Allow` / `NeedsLogin` / `Denied` |

These are also how you publish your own JSON API if you want one: a handler per route, your choice of
shape, your versioning policy.

### Row format

A row is a **flat object keyed by column name**. Hidden fields, write-only fields, and raw FK columns
are omitted. Relations embed `{id, label}` — the identity and a display label, resolved by the
backend, so a rendered cell needs no second query:

```jsonc
{
  "id": 1, "title": "Rust intro", "body": "…", "views": 100,
  "author": { "id": 1, "label": "Ada Lovelace" },   // to-one → {id,label} | null
  "tag": [ { "id": 1, "label": "rust" } ]           // to-many/N:M → array
}
```

### Write format

Flat object keyed by **writable column names**; relations by name. Absent keys → unchanged (update) /
defaulted (create). Read-only/hidden fields, the PK on create, and unknown keys are ignored. The UI's
form decoder ([`ui::decode`](#web-ui-ui)) produces exactly this from a posted body.

```jsonc
{ "title": "Async Rust", "views": 0, "author": 1, "tag": [1, 3] }
```

| Relation | Value | Effect |
|---|---|---|
| to-one (owns FK) | `id` / `null` | set / clear this row's FK |
| N:M | `[id, …]` | replace this row's junction rows |
| inverse to-many | `[id, …]` | reassign target rows' FK (**read-only by default**) |

Create/update is transactional. Deleting a row clears its N:M junction rows first.

### The URL is the view

A rendered table reads its state from the query string — and nowhere else. `ViewState::from_uri(&uri)`
parses it; `ViewState::default()` is page 1, unsorted, unfiltered. Every link the UI emits is
**query-only and relative** (`?page=2`), so a component works on whatever path you serve it from.

| Param | Meaning |
|---|---|
| `q=<term>` | naive full-text: `LIKE '%term%'` across text columns |
| `filter[<name>]=<val>` | **exact** match. `<name>` is a column *or* a to-one relation (`filter[author]=7` → `author_id = 7`); an empty value matches rows that have none (`IS NULL`), and `*` means **no filter** — the value the toolbar's "all" submits, since a `<select>` must submit something and the empty one is taken |
| `sort=views:desc,title` | whitelisted sort (unknown key → an error). A **relation** sorts by the label its cells show |
| `page` / `per_page` | pagination (`per_page` defaults to the component's, else 25) |
| `entity=<slug>` | which panel an [`Admin`](#admin--a-whole-admin-in-one-component) is showing |
| `new=1` / `edit=<pk>` / `import=1` | render the create / edit / CSV-import dialog over the list |
| `show=<pk>` | render the read-only detail dialog over the list |
| `done=…` | what the write that redirected here did (`deleted:17`, `imported:120,3`) — rendered once as an alert, then dropped |
| `format=csv` | your read handler exports instead of rendering (see [CSV](#csv-importexport)) |
| `ids=…` (posted) | the rows a bulk delete ticked; `all=true` is the whole-table guard |

Unknown parameters are **ignored**, so your own may share the URL.

**Why brackets.** The reserved words above (`page`, `sort`, `entity`, …) would shadow a column of the
same name if bare `?<col>=` were accepted. Brackets can't occur in a column or relation name (those
come from Rust identifiers), so `filter[…]` is collision-proof by construction whatever an app calls
its columns. Repeated keys all apply.

**Sorting is total.** The primary key is appended as a final sort key, always. Without it an `ORDER BY`
on a non-unique column leaves the order *within* a tie up to the database, which needn't pick the same
one for the query that fetches page 1 and the query that fetches page 2 — so rows duplicate across
pages while others are never shown. `NULL`s sort last on every backend (SQLite would otherwise put them
first on `ASC`, PostgreSQL last); text ordering follows the database's collation.

**Sorting by a relation** turns `?sort=author` into `ORDER BY author.name` through a left join, so the
list is ordered by the label the cell *shows* rather than the foreign key behind it. It needs the
target to know which column its label comes from — see [`label_column`](#metamodele) — and applies to
a **to-one that owns its FK** only: a row has many tags, so there is no single label to order it by,
and to-many/N:M report `sortable: false` and refuse an attempt. Each column carries `sortable`, so the
UI knows which headers to make links without guessing.

**Bulk delete** runs one set-based `DELETE … WHERE` in the backend (plus a subquery to clear N:M
junctions) — not a per-row loop, so it scales. It refuses to wipe the whole unfiltered table unless
`ListQuery::all` is set, which is what the table's "Delete all N matching" button does and its "Delete
selected" does not. A `filter[…]` counts as narrowing it.

### Errors

[`crud::Error`](https://docs.rs/relativelylight/latest/relativelylight/crud/enum.Error.html) maps to
**400** (bad body / unknown column), **401** (the model's gate needs a login), **403** (denied, *or* a
failed CSRF check), **404** (unknown entity / missing row), **405** (read-only), **409** (a unique or
foreign-key constraint rejected the write), **422** (validation), **500** (other DB error) — via
`IntoResponse`, as plain text, because a page-level error belongs in your shell. A `Validation` error
from a posted form is not an error at all to the UI: `submit` returns `Outcome::Invalid` so the dialog
can re-render with the messages in place.

### CSRF on writes (feature `csrf`)

Cookie-authenticated writes are a CSRF target, so the engine can require a double-submit token:

```rust
crud.csrf(auth.csrf());   // share the auth module's token cookie
```

Every form the UI renders then carries a hidden `_csrf` input, and `submit` refuses a body without a
matching one — checked *before* the gate, so a forged write reaches neither the session lookup nor the
database. Reads need no token, and requests carrying an `Authorization` header are exempt (a Bearer
credential isn't ambient). The **cookie must already exist** when the page renders: `auth`'s login
issues it; an app without `auth` calls `Csrf::ensure` in its page handler. Off by default only because
a `crud` build without `auth` may have no cookies at all; full design in [AUTH.md §7](AUTH.md).

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
column description (`Column::Field { nullable: true, .. }`), which is how the form knows an empty
input means `null` here and `""` elsewhere.
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
is reported as `Column::Field { required: true, .. }`, marked with a red `*` in the form (a field with
a `default` is pre-filled instead — so `MetaField::password()`, whose blank means "no password", gets no
marker), and **enforced by the engine**:

| Write | Field | Result |
|---|---|---|
| create | absent | a validation error on `title`, shown beside that field |
| create or update | explicit `null` | refused — nulling a `NOT NULL` column can never succeed |
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

**Who fills a `created_at`, then?** Not the database and not the engine — a SeaORM
`ActiveModelBehavior::before_save` hook, in Rust, during the insert (that is how `auth_user.created_at` /
`updated_at` work). The chain for a column the client leaves out entirely: the field is `read_only`, so the
engine skips it *and* exempts it from `required`; the backend builds the `ActiveModel` without it; the hook
stamps it; the row comes back with the value. There's a test that runs exactly that against a real database,
and a second half asserting the hazard — **forget the `read_only` and the create is refused**, because from
the engine's side a hook-filled column is indistinguishable from one nothing fills. (`updated_at` is
restamped on every save by the same hook, which is why `auth`'s login flow bumps `last_login_at` with a
set-based `update_many` instead: that path doesn't run `ActiveModelBehavior`, so a login doesn't count as a
content change.)

One gap this deliberately doesn't cover: a `NOT NULL` column with no default that is **hidden or read-only**
*and has no hook* can't be created at all, and still fails at the database. `required` can't help, because a column filled by
an `ActiveModelBehavior::before_save` hook looks identical to one nothing fills — so refusing the write
would break the hook case. If creates on a model fail with a database `NOT NULL` error, look for a hidden or
read-only column with nothing filling it. (This is why the timezone demo has its own `event` table in
`examples/model` rather than reusing `post`: hiding `post`'s `NOT NULL` `body` and `author` to get a
one-timestamp form made the form unable to create anything at all.)

### Enumerations: a closed set of values

`MetaField::options` is the list of values a column accepts — empty for everything else. It is
**introspected** from `ColumnType::Enum`, so a Postgres/MySQL enum needs no per-model code:

| Where | Effect |
|---|---|
| admin form | a `<select>` instead of a free-text input (with a blank choice where the column is nullable or not required) |
| metadata | `"options": ["draft","review",…]`, emitted only for columns that have a set |
| CSV | an unknown value is rejected on import like any other invalid cell |
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

## Columns

`Engine::columns(slug) -> Vec<Column>` is the structural description the UI renders from — and the
thing to read if you are writing your own screens or your own API.

```rust
pub enum Column {
    Field {
        name: String, logical_type: LogicalType, read_only: bool, write_only: bool,
        nullable: bool, required: bool, options: Vec<String>,
        label: Option<String>, description: Option<String>, default: Option<Value>,
        display: Option<FieldDisplay>, sortable: bool,
    },
    Relation {
        name: String, target: String, cardinality: Cardinality,
        fk_column: Option<String>, read_only: bool,
        label: Option<String>, description: Option<String>, sortable: bool,
    },
}
```

Columns are **ordered**: a to-one relation appears in place of its FK column; inverse/N:M relations
are appended; hidden columns are omitted. `sortable` says whether `?sort=<name>` is accepted (false
for `Json`/`Other` fields, and for a relation whose target has no known label column).

Each variant is one arm of the renderer's `match`, which is the point of doing this in Rust: adding a
`LogicalType` or a `FieldDisplay` is a compile error in every place that must handle it, where the
previous design dispatched on strings in JavaScript that no compiler read.

## CSV import/export

Feature `csv`. A thin layer over the `Engine` — every imported row goes through the same
coerce/validate pipeline as HTTP.

- **Export:** `Table::csv(&headers, &state)`, which the toolbar's Export link asks for by putting
  `?format=csv` on the page's own URL — so your read handler answers it (three lines; see the
  examples). It applies the view's search, filters and sort, unpaginated: **you export exactly what is
  on screen.**
- **Import:** the same menu's "Import CSV…" opens a dialog (`?import=1`) with two independent
  actions — **upload a file**, or **paste the rows** — each with its own button. Both post
  `_op=import`, and `submit` applies them identically from there.

**The file goes straight to the server** as `multipart/form-data`; no JavaScript reads it first.
That matters for exactly the cases where an import is hard: an unusual encoding, a file too big to
percent-encode into a text field, bytes the browser would mangle. The server has the bytes and can
say precisely what is wrong with them. Three things follow:

- **Encoding.** A UTF-8 BOM (what a spreadsheet writes) is stripped. Anything that isn't UTF-8 is
  **refused by name** — "isn't valid UTF-8 (byte 41) — re-save it as UTF-8" — rather than guessed at,
  because nobody sees the file before it applies and mojibake in the database is worse than a retry.
- **Size.** The body reaches your handler through axum's `DefaultBodyLimit` (2 MB). Raise it on that
  route with `DefaultBodyLimit::max(…)` if imports are larger.
- **CSRF.** The token rides in a part of the multipart body. `submit` reads it from there, and so
  does the [`csrf::enforce`](AUTH.md) layer, so a route that accepts uploads can sit behind the
  layer like any other. The layer holds the body to find the token, bounded by
  `Csrf::max_upload` (16 MiB by default) — set that a little above the largest upload you accept.

**A refused import reopens the dialog**, with the per-row report in its banner (`line 4: title:
required`) and the rows back in the paste box however they arrived — so a bad cell is fixed in
place rather than by re-picking a file. Since an import is all-or-nothing, redirecting to an
unchanged list would look exactly like an import that had worked.

Format (round-trippable): header = column names (write-only omitted); field → scalar; a `datetime`
field → `YYYY-MM-DD HH:MM` **in the caller's timezone**, so the file agrees with the screen (see
[TIME.md](TIME.md)); to-one → the target id (blank if none); N:M → ids joined with `|` (e.g. `1|3`).
On import a row **with** a PK value updates that row, **without** creates one; read-only columns are
ignored, and datetimes are read back through the same zone.

**Import is all-or-nothing.** One backend transaction covers the whole file, so a file that fails on line
40 leaves the first 39 rows unapplied — you fix the spreadsheet and re-upload it, rather than hunting for
which half landed. Two details follow from that:

- **Every invalid row is reported in one pass.** Validation runs across the whole file *before* the
  transaction opens, so four bad cells come back as four errors, not one per re-upload. Each carries its
  1-based CSV line and the offending column (`"title: required"`, not "invalid row").
- **A database-level failure can only be found by trying**, so a unique-constraint violation or a missing
  update target aborts at that row and rolls the rest back. The report then names that one row.

Under the hood this is [`Accessor::write_batch`], added because a transaction lives *below* the backend
seam: the engine cannot open one, so looping over `create` could never be atomic however carefully it was
written. A backend without transactions inherits a default implementation that applies rows one at a time
and stops at the first failure — not atomic, and documented as such; the SeaORM backend overrides it.

[`Accessor::write_batch`]: https://docs.rs/relativelylight/latest/relativelylight/crud/trait.Accessor.html#method.write_batch

## Web UI (`ui`)

Feature `ui`. Three components, **one implementation**:

- [`Table`](#table) — one entity: search, sortable headers, filters, a pager, CSV, bulk delete, and a
  create/edit dialog.
- [`Form`](#form--a-standalone-createedit-form) — the same form standalone, for your own pages.
- [`Admin`](#admin--a-whole-admin-in-one-component) — a side panel over many `Table`s.

All three return **HTML fragments**: your app owns `<html>`, the Bootstrap 5 stylesheet and the
layout. There is no JavaScript framework, no JSON in between, and no client-side state.

```rust
let html = Table::new(&engine, "post")
    .title("Posts")
    .per_page(20)
    .filter("author")
    .sort("title")
    .render_for(&headers, &state).await?;
```

**What to put in your shell:** Bootstrap 5's CSS, and `crud::ui::CSS` — about forty lines Bootstrap
doesn't cover (mostly the `<dialog>`, whose own `.modal` assumes Bootstrap's JavaScript):

```html
<link href="…/bootstrap.min.css" rel="stylesheet">
<style>{{ css|safe }}</style>   <!-- pass relativelylight::crud::ui::CSS -->
```

### How it works

Three rules, and the rest follows.

**The URL is the state** ([above](#the-url-is-the-view)). Page, sort keys, filters, the search term,
which entity is active and which row is being edited all live in the query string, so every view is a
link you can bookmark, mail, or put in a runbook.

**Modals are `<dialog open>`, rendered server-side.** `?edit=7` renders the list *and* the open dialog
in one response; the browser supplies the backdrop, ESC-to-close and the top layer with no script. A
rejected write re-renders the same dialog with the messages beside the fields and the operator's input
still in them.

**Writes are POST → 303 → GET.** `submit` returns a relative target (`?page=2#row-7`), so the browser
lands back on the row that changed. One request per save, where the previous design took two (POST,
then re-fetch the whole table).

**What a write did is reported once, in the URL.** A delete or an import redirects with
`?done=deleted:17` / `?done=imported:120,3`, which the next render turns into one Bootstrap alert
above the table and then forgets — a refresh doesn't repeat it, and a second tab can't see it,
because there is no server-side flash to get out of step. A create or an update reports nothing: the
redirect already lands on the row it changed, and an alert on every save is noise.

### The two handlers

Reads stay your route, so you keep your own shell, your own login redirect and your own error pages.
Writes post back to that same path:

| | |
|---|---|
| `render_for(&headers, &state) -> Result<String>` | the fragment. Consults the model's gate: `401`/`403` rather than rows a caller may not read, and write controls only for a caller who may write |
| `submit(&headers, ip, &body, &state) -> Result<Outcome>` | CSRF → gate → apply → audit. `Outcome::Done(url)` to redirect to, or `Outcome::Invalid(state)` to re-render. `body` is **raw bytes** (`axum::body::Bytes`), because a CSV upload is a file |
| `csv(&headers, &state) -> Result<String>` | the view as CSV, when `state.csv` is set (feature `csv`) |

Both are `async`, and both take the request's headers — which is how the timezone cookie, the session
cookie and the CSRF token reach the render. The full worked shape is in [Quick start](#quick-start)
and in all three examples.

### `Table`

| Builder | Effect |
|---|---|
| `title` / `description` | heading and a muted subtitle |
| `search(bool)` | the search box (default on) |
| `pagination(bool)` / `per_page(n)` | the pager (default on, 30) |
| `per_page_choices([…])` | the sizes the toolbar offers (default `[10, 30, 100, 250]`; empty hides the control) |
| `per_page_max(n)` | the largest page this table will fetch, however large a `?per_page=` asks for (default **10,000**) |
| `detail(bool)` | the per-row **View** action and its read-only dialog (default on) |
| `read_only(bool)` | no Create/Edit/Delete and no dialog, for anyone |
| `confirm(bool)` | an `onclick` confirm on destructive buttons (default on) |
| `columns([…])` | which columns the **table** shows, and in what order (default: all of them) |
| `fields([…])` / `omit([…])` | which columns the **dialog's form** shows, and in what order |
| `row_class(closure)` | a CSS class per row, from the row — `(row) -> class` |
| `sort(col)` / `sort_desc(col)` | the default sort, used until the URL says otherwise |
| `filter(name)` | a filter `<select>` in the toolbar, for a column or a to-one relation |
| `fixed_filter(name, value)` | a filter **pinned** to one value, with no control — a table *about* that value |
| `format(col, closure)` | a custom cell renderer, `(value, row) -> HTML` |
| `picker_threshold(n)` | how many target rows a relation may list as a `<select>` (default 20) |
| `dom_id(id)` | namespaces the fragment's id, so two tables of one entity can share a page |

**Every filter in force is chipped**, whether the table declared a control for it or not — one
arriving from an `Admin`'s shared control, or typed into the URL, is still narrowing what is on
screen and still says so.

**Filters narrow everything at once.** Because the choice is in the URL, it applies to the listing, the
CSV export and "delete all matching" alike — no button can act on a wider set than the one on screen —
and it shows as a chip above the table, because a narrowed table that looked like a whole one is how
an operator concludes their rows were deleted. A pinned or shared filter's chip has no ✕: it isn't
that table's to clear.

**`columns` and `row_class` are the table's own** — a column left out of `columns` is still edited
in the dialog and still exported to CSV, and `row_class` puts a class on the `<tr>` so a table can
say something no column says:

```rust
Table::new(&engine, "invoice")
    .columns(["number", "customer", "due", "total"])       // not the other sixteen
    .row_class(|row| match row["status"].as_str() {
        Some("overdue") => "table-danger".into(),
        _ => String::new(),
    })
```

Both are checked: a name `columns` doesn't recognise is a render-time error naming it, and the class
is escaped like any other attribute.

**`format` is a Rust closure** whose output is inserted verbatim, so wrap database values in
`crud::ui::esc`:

```rust
.format("title", |v, row| format!(r#"<a href="/post/{}">{}</a>"#, esc(&row["id"]), esc(v)))
```

That is the one place app-supplied HTML enters the page; everything else is escaped by the template
engine, and the escaping is tested against `<script>`-bearing data in every cell, label, chip, option
and input value (`crud/ui_tests.rs`).

**Relations in the form.** A to-one whose target has at most `picker_threshold` rows renders as a
`<select>` of labels; above that it renders an id input, because the alternative is shipping thousands
of `<option>`s or a search box that needs a fetch endpoint this crate no longer has. A to-many renders
as a multi-select.

**A filter control does the same, for the same reason and one more.** Under the threshold it is a
`<select>`; above it, a text input that says how many values there are. A truncated menu would not
just hide most of them — with the value in force missing from the list, no `<option>` would be
selected and the browser would display the first one, so the control would confidently name a filter
the table isn't using. A chip always shows the target's **label** (`Author: Ada Lovelace`), resolved
by an exact id lookup, rather than the id the URL carries.

**The read-only row.** Every table offers a **View** action per row, opening `?show=<pk>` — a dialog
listing *every* published column, not just the writable ones. It is the only way to see a generated
id, a hook-stamped `created_at`, or the whole of a long text column the table shows a corner of, and
the only row view a caller who may not write gets at all. Values come from the same renderer as the
cells, so relations show labels, datetimes are in the caller's zone, and a `format` closure applies.
Write-only columns are left out — the backend never returns one, so the row would be blank beside
"Password". `detail(false)` removes it.

**Searching.** Typing submits the view two seconds after you stop; Enter submits at once. A submit
is a page load, so it waits for a pause rather than chasing keystrokes — and the input takes focus
back with the caret at the end, since the reload it just caused would otherwise drop it.

**Choosing a page size.** The sizes sit beside the pager as **links** (no form, no script), and the
URL carries the answer; `per_page_choices` sets them.
`?per_page=` is user input, so it is **clamped** to `per_page_max` (default 10,000) — unclamped, it
is a cheap way to make a server read a whole table into memory and render it. The clamp normalises
the view state itself, so every link the page renders carries the clamped number rather than
propagating the greedy one. CSV export is unaffected: it is explicitly unpaginated.

**Where a validation message lands.** A message keyed to a column appears **under that column's
input**, with the input marked invalid; a cross-field message from `validate_row` appears as a
**banner at the top of the dialog**. A field message naming a column the form *doesn't render* is
promoted into that banner as `column: message` — otherwise it would be a refused form with nothing
marked and no stated reason.

**Refusals, not surprises.** Rendering fails — naming the column — for an unknown or read-only field in
`fields`/`omit`, an unsortable `sort`, a `filter` on a column that doesn't exist, a widget that can't
render its column, or a create form that omits a column the engine requires. A control that silently
did nothing is the bug that gets found in production.

### `Form` — a standalone create/edit form

The same form, without the table: for a signup page, a "new ticket" screen, a settings page — anywhere
`Admin` is the wrong shape. It reads the entity's columns, so the widgets, required markers, enum
dropdowns, relation pickers, datetime handling and validation messages all come free and stay in step
with the model.

```rust
// GET /ticket/new
let html = Form::new(&engine, "ticket")
    .title("New ticket")
    .fields(["subject", "body", "priority"])   // subset *and* order; default is every writable column
    .submit_label("Open ticket")
    .cancel("/tickets")
    .redirect("/tickets/{id}")                 // where submit points after a save; {id} = the new row
    .render_for(&headers, &state).await?;
```

`edit(id)` turns it into an update form. Without `redirect`, `submit` returns `?saved=1` and the form
renders `saved_message` when it sees that. `heading(bool)` forces the card header on or off (the
default is on if there is a title or description), and `dom_id` namespaces it.

Note a column `default` pre-fills the *input* — it is never applied server-side — so a required field
still has to be rendered for its value to be sent. Omitting one is a render-time error saying exactly
that.

### `Admin` — a whole admin in one component

```rust
let html = Admin::new(&engine)
    .title("Admin")
    .base("/admin")                            // a path per model — see below; omit for `?entity=`
    .filter("zone")                            // one control, applied to every table that has the column
    .group("Content")
    .entity_with("post", |t| t.per_page(10))
    .entity("tag")
    .separator()
    .group("People")
    .entity_with("user", |t| t.read_only(true))
    .link("Log out", "/logout")
    .render_for(&headers, &state).await?;
```

### Addressing a model

Two shapes, and the only difference is what the side panel's links look like.

**One page, `?entity=post`** (the default). One route, one pair of handlers:

```rust
.route("/admin", get(show).post(save))
```

**A path per model, `/admin/post`** — `Admin::base("/admin")`. Still one route and one pair of
handlers; the path parameter says which model, and your handler passes it on:

```rust
.route("/admin/{entity}", get(show).post(save))

let mut state = ViewState::from_uri(&uri);
state.entity = Some(entity);                   // the path decides, not the query
```

Everything *inside* a table is relative — `?page=2`, `?edit=7`, `?format=csv` — so it resolves
against whichever path the panel is served from, and a write still redirects to the list it came
from. Filters that travel ride along as the query, so a nav link reads `/admin/tag?filter[zone]=3`.

The path form is worth the one parameter for deep links: `/admin/post?edit=7` says what it is where
`?entity=post&edit=7` has to be read twice. `examples/adminpanel` uses it; `examples/crud` shows the
same idea without an `Admin` at all, one entity per page at `/post`, `/tag`, `/event`.

`?entity=post` (or `/admin/post`) renders **that entity's table and no other** — the nav is links,
not nine hidden panels. (The previous design rendered every panel into every response and showed one with
`x-show`; a nine-entity page cost 9,441 lines of HTML, where this costs about 500.)

`entities()` appends every registered entity in registration order. `submit` writes to the entity a
posted body names, **provided this panel lists it** — an entity it doesn't list is refused before any
gate is consulted, so a panel's contents are part of what it permits and not merely of what it shows.

**`filter(name)` is the shape that matters when an admin lists many tables of the same kind** —
fifteen per-type DNS record tables, say. An operator works inside one zone at a time, so they pick it
once and it follows them from table to table, because each nav link carries it — **to the tables
that have the column**. A link to one that doesn't stays clean, and a filter that reaches a table
whose entity can't honour it is ignored rather than passed to a backend that would refuse the whole
listing. So a shared filter narrows every table it means something in, and nothing else. Like `fixed_filter`, it narrows a **view**; scoping who may see what is
[`authz`](AUTH.md)'s job.

### The JavaScript that is left

Eleven inline attributes across the templates, about fifteen lines in total, **all of them
enhancement** — every one has a working path without it:

| | Without it |
|---|---|
| search: `oninput` debounce (2s), `onkeydown` Enter, `onfocus` caret-to-end | the `<noscript>` **Apply** button submits the form |
| the same pair on a large-target filter input | as above |
| `onchange="this.form.submit()"` on a filter `<select>` | as above |
| `onclick="return confirm(…)"` on destructive buttons | the POST still goes, and the server still asks the gate (`confirm(false)` removes it) |
| `onclick` on the select-all checkbox | tick the rows individually |
| `oninput` on a range slider's read-out | the slider still posts its value |

There is no script file, no framework, and nothing generated per entity. The **Apply** button exists
only inside `<noscript>`, because with scripting the search submits itself and an always-visible
Apply is a button nobody presses; without it, a form whose only other controls are text inputs has
no way to submit (a browser submits on Enter only when there is exactly one text field, and a
large-target filter makes two).

## Composing with your app

relativelylight is meant to be **part of** a larger app, not the whole thing. Your app owns the roots;
this module contributes into them.

- **The router is yours.** This module adds no routes at all. You write `get(show).post(save)` on a
  path of your choosing and call `render_for` / `submit` from them ([Quick start](#quick-start)), so
  the login redirect, the error page and the shell stay yours. Every link the components render is
  relative to that path, so they never need to know it.
- **`middleware::resolve_real_ip` is mandatory**, as the outermost layer:
  ```rust
  let app = app.layer(axum::middleware::from_fn_with_state(
      relativelylight::middleware::TrustProxy(cfg.trust_proxy),
      relativelylight::middleware::resolve_real_ip,
  ));
  ```
  `submit` takes the address from the `RealIp` extension it inserts, so the audit events, the auth
  lockout and your own request log can't disagree about who called.
- **The page shell is yours.** `render_for` returns an **HTML fragment**, never a full page. Your app
  owns the `<html>`, the navbar, the Bootstrap stylesheet and `crud::ui::CSS`. Your askama templates
  and the library's live in separate crates, so they can't collide.
- **The API, if you want one, is yours.** Publish whatever endpoints your clients need over
  [`Engine`](#reading-and-writing). Nothing in this module assumes they exist.

`examples/crud` does all of it ungated (including a `/dashboard` page built from the engine);
`examples/adminpanel` does it behind `auth` with 2FA, lockout panels and a timezone cookie.
[APP.md](APP.md) walks through the whole composition — shell, nav bar, login page, dashboards,
hand-written forms and multi-step workflows.

## Write observer (audit)

Register a [`WriteObserver`](../relativelylight/src/observe.rs) with `Crud::on_write` to be notified after every
**committed** write (create / update / delete / bulk-delete) through the engine — the hook for audit
logging. Each write handler fires a `WriteEvent` carrying the change *and* the request context:

```rust
pub struct WriteEvent<'a> {
    pub source: &'static str,   // "autocrud" here (an `auth` handler names itself too)
    pub op: Operation,          // Create | Update | Delete
    pub entity: &'a str,        // slug, e.g. "post"
    pub key: Option<String>,    // pk (None for a bulk delete)
    pub before: Option<Value>,  // prior row (update/delete); None on create
    pub after: Option<Value>,   // new row (create/update); None on delete
    pub headers: &'a HeaderMap, // resolve the actor (auth.identify) + read X-Forwarded-For
    pub client_ip: IpAddr,        // the caller, already resolved by middleware::resolve_real_ip
}

let mut crud = Crud::new(db);
crud.register(post_mm, gate);
crud.on_write(my_audit_sink.clone());   // Arc<dyn WriteObserver>
```

Notes: the observer runs **after commit** (a failed write fires nothing); `before` on update is a
best-effort pre-fetch; a **bulk delete** reports the affected count in `after` (`{"deleted": N}`), not
every row, so a "delete all" can't blow up the audit. The library provides only the hook and the
`WriteEvent` type — the app owns the audit **table**, resolves the actor from `headers` (e.g.
`auth.identify`), writes the row, and handles retention — the address arrives already resolved, so every
audit row names the same client the lockout counted and your request log printed. The same
`Arc` can also be handed to `Auth::on_write` (see [AUTH.md](AUTH.md)) so one sink captures both the
auto-CRUD and the auth surfaces — which is why each emitter names **itself** in `source`: with one sink
behind several of them, that value is what tells them apart. It says `autocrud` (this crate's
auto-generated CRUD), not a bare `crud`, which names nothing in particular in an app that has CRUD
screens of its own; store it as it arrives rather than translating it. **Times are UTC**
(`i64` Unix seconds) — see the timezone note in [PRD.md](PRD.md).

**Runnable:** [`examples/audit`](../examples/audit/src/main.rs) is the whole thing in about sixty
lines — one sink on `Crud::on_write` *and* `Auth::on_write`, printing `source op entity#key
actor@address` plus a per-field diff of `before`/`after`, beside a request log built on the same
`RealIp`. Two practical notes it makes concrete: the sink is `async` and runs **inside the request**
(after the commit, before the response), so real work belongs on a channel rather than in it; and
resolving the actor means calling `Auth::identify` from a sink that was constructed *before* `Auth`
was — a `OnceLock` closes that loop.

## Architecture & extending

The **`Engine`** is a registry: it holds the entities, consults each model's gate, and forwards data
to and from accessors. Every backend implements the per-entity **`Accessor`** trait — `slug` / `pk` /
`columns` + `list` / `get` / `create` / `update` / `delete` / `delete_many` / `write_batch`, each data
method returning finished rows. The trait names no ORM types.

Its real job is **type erasure**: `Arc<dyn Accessor>` lets one registry hold entities of different
Rust types (`SeaAccessor<E>` is generic over the entity), which is why the seam exists even with a
single backend. It is *not* a stability promise — expect `Accessor` and `Column` to gain members in
any release.

SeaORM is one backend (`relativelylight::crud::seaorm`); it does the heavy lifting (introspection, projection,
validation, relation resolution, set-based bulk delete). A different backend (in-memory, another ORM)
is just another `Accessor` implementation reusing the whole engine + router unchanged.

Why the seam sits here: relation resolution and field projection are *database* concerns — they run
queries and encode per-model visibility policy — so keeping them behind the accessor lets the engine
stay a pure pass-through. In the SeaORM backend, siblings are resolved through a `Weak`-keyed registry
(no reference cycle; the strong `Arc`s live in the `Engine`), which preserves zero-config
auto-discovery — nothing needs declaring beyond N:M.
