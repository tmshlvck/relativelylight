# Rune — Architecture

How the code is shaped and where the seams are. For *using* the library see
[docs/AUTOCRUD.md](docs/AUTOCRUD.md); for the product vision and status see [PRD.md](PRD.md).

## The layers

```
   Frontend flavors   alpine::Table (+ modal form)          [future: HtmxAdmin, pure-client SPA]
                            │ shape in-process, data via the API
   ── stable API ──   REST/JSON + in-process metadata
   Engine             registry · URLs/metadata · OpenAPI · JSON↔CSV · axum router (feature)
                            │ forwards finished JSON over
   Seam               Accessor  (per-entity: metadata + finished-JSON CRUD/bulk)
                            │ implemented by
   Backend flavors    seaorm::Crud (SeaORM)                 [future: memory::Crud, …]
```

A *backend flavor* turns a data source into the API; a *frontend flavor* consumes it. The API is the
fixed contract, so the two vary independently.

## The seam: `Accessor`

The **`Engine`** is deliberately thin — a registry of entities that owns URLs + metadata (for OpenAPI
and the UI), does the generic JSON↔CSV transform, wires routes, and otherwise just **forwards finished
JSON** to/from accessors (plus the bulk-delete guard). It does **no** row assembly or relation
resolution.

The per-entity **`Accessor`** trait is correspondingly small:

```rust
fn slug() · fn pk() · fn columns() -> [ColumnMeta]              // metadata
async list(q, terse) · get · create · update · delete · delete_many   // finished JSON
```

Every data method returns ready-to-send JSON — visible fields projected, `on_read` applied, relations
embedded as `{id, label}`. **The trait names no ORM types** and carries no resolution mechanics, so a
backend is free to produce that JSON however it likes.

Why the seam sits here: relation resolution and field projection are *database* concerns (they run
queries, they encode per-model visibility policy). Keeping them behind the accessor lets the engine
stay a pure pass-through and lets a backend resolve relations the cheapest way it can.

## Backend flavor: `autocrud::seaorm`

The only module that touches SeaORM. `SeaAccessor<E>` holds a `DatabaseConnection`, the `MetaModel<E>`
config, and a shared `SeaRegistry`. It does the heavy lifting:

- **Introspection** — `MetaModel::new` reads columns, PK/FK, and FK relations; `.relate()` names N:M
  target types (the one thing SeaORM can't enumerate).
- **Projection & validation** — `MetaField` visibility + `on_read`; the coerce→validate→transform
  write pipeline.
- **Relation resolution** — to-one / inverse / N:M resolved against sibling entities via the
  `SeaRegistry`, a `Weak`-keyed `table → row-source` map. Using `Weak` (the strong `Arc`s live in the
  `Engine` as `dyn Accessor`) avoids a reference cycle. This keeps SeaORM's zero-config auto-discovery
  — nothing needs declaring beyond N:M.
- **Bulk delete** — one set-based `DELETE … WHERE` plus a subquery per N:M junction, in a transaction.

`Crud` wires each `SeaAccessor` into both the `Engine` and the registry. A second backend just
implements `Accessor` and reuses the whole engine + router unchanged.

Two runtime facts worth knowing: SeaORM's `is_owner` is inverted vs. intuition (`owns_fk =
!is_owner`), and monomorphization means a runtime slug can't become a type — entities are held as
`Arc<dyn Accessor>` keyed by slug, and the one place a concrete target type is named is the N:M
resolver captured at `.relate()`.

## Frontend flavor: `autocrud::alpine`

Hybrid rendering: the **shape** is read from the `Engine` in-process (askama-compiled HTML fragment,
columns embedded as a JSON blob) so there's no `_meta` round-trip; the **data** is fetched
client-side by Alpine.js from the JSON API. The app supplies the shell (Bootstrap 5 + Alpine via CDN)
and drops the fragment into a `<div>`. Feature-set and config: [docs/AUTOCRUD.md](docs/AUTOCRUD.md#web-admin-alpine).

## Crate layout

One `autocrud` crate, feature-gated:

| Module | Feature | Role |
|---|---|---|
| `engine` | (core) + `axum` | the seam, contract types, `Engine`; the router/handlers under `axum` |
| `seaorm` | (core) | SeaORM backend — introspection, `MetaModel`, `Crud` |
| `alpine` | `alpine` | server-rendered admin table + form (pulls `askama`) |
| `openapi` | `openapi` | runtime OpenAPI generation (pulls `utoipa`) |
| `csv_io` | `csv` | CSV import/export (pulls `csv`) |

The engine never references `MetaField`/`MetaRelation` — it only consumes
`Accessor::columns() -> [ColumnMeta]`, which is why those config types belong to the backend flavor.
Splitting into a workspace (`autocrud-core` / `-sea` / `-alpine`) is mechanical and deferred until
dependency boundaries or release cadence demand it.
