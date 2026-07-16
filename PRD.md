# Rune — Product Requirements Document

**Rune** turns Rust ORM entities into a full back-office stack — a JSON CRUD + metadata API, an
auto-generated web admin, authentication/authorization, and file handling — with **no per-model
code**. It's built from composable components; take the pieces you need.

| Component | What | Status |
|---|---|---|
| **autocrud** (§1) | SeaORM entities → JSON CRUD + machine-readable metadata API | ✅ implemented |
| **Rune Admin** (§2) | auto-generated web admin: table, create/edit form, bulk + CSV, Swagger | 🟡 in progress |
| **Auth** (§3) | user + group model, TOTP 2FA, PassKeys, OIDC | ⛔ planned |
| **Files** (§4) | multi-file upload / display / download / camera capture | ⛔ planned |

> ✅ implemented & verified · 🟡 partial · ⛔ future.

The engine crate is **`autocrud`**; the SeaORM backend is **`autocrud::seaorm`**. This document is the
product spec and roadmap. For the full API, usage, and design, see
**[docs/AUTOCRUD.md](docs/AUTOCRUD.md)**.

## Vision: one API, many backends and frontends

Rune is an **umbrella**. A *backend flavor* turns some data source into a stable JSON + metadata HTTP
API (§1); a *frontend flavor* consumes that API to render an admin UI (§2). The API is the fixed
contract in the middle, so backends and frontends vary independently. Today there is one backend
(SeaORM) and one frontend (`alpine`); the seam is designed so a second of either drops in without a
core change.

---

## 1. autocrud — CRUD + metadata API ✅

Introspects SeaORM entities at runtime and serves, with no per-model code:

1. a **`MetaModel` builder** — auto-generated from an entity, lightly tweakable;
2. a **structural, ordered `columns`** metadata description (fields + relations, FK in place);
3. a coherent **HTTP API** — full CRUD (with relations), search/sort/paginate, and bulk delete.

The metadata is **purely structural** (types, keys, relations) plus optional presentation hints
(label / help / default) a UI may use. It's the backend-agnostic contract every backend satisfies
and every frontend consumes.

**Locked design decisions:**
- **Metadata shape** — one ordered `columns` list; a to-one relation appears in place of its FK
  column; inverse/N:M appended.
- **Relations by name** — raw FK columns are hidden from the wire; you write `"author": 1`.
- **Finished JSON at the seam** — the backend returns ready-to-send rows (visibility + `on_read`
  applied, relations embedded as `{id, label}`); the engine forwards them. No URLs in the data plane;
  relation metadata carries only `list_url` (for form pickers).
- **Single-column PK + single-column to-one FK** on registered entities (any URL-safe scalar). N:M
  junction tables are internal and never registered.
- **Facade** — `autocrud::seaorm::Crud::new(db, base_path)` → `.register(mm)` → `.into_router()`.

**Full API and usage:** [docs/AUTOCRUD.md](docs/AUTOCRUD.md) — registration, `MetaModel`/`MetaField`/
`MetaRelation`, routes, read/write formats, query params, validation & transforms, metadata, CSV,
OpenAPI.

**Deferred / open:**
- Second backend (`autocrud::memory`, …) — the seam is ORM-neutral, no refactor needed.
- Relation reads are per-target queries (N+1) — batch/join later, backend-internal.
- Composite-PK URL token + `row_key` escape hatch; **409** constraint mapping (currently 500).
- Enum `options`, nullable/`required` extraction, richer field metadata.

---

## 2. Rune Admin — auto-generated web admin (`autocrud::alpine`) 🟡

A slightly-customizable admin UI generated from the model, composed of reusable components. Rendering
is hybrid: the **shape** (columns) is read from the `Engine` in-process and embedded into a
server-rendered HTML fragment; the **data** is fetched client-side from the JSON API. The app
provides the shell (loads Bootstrap 5 + Alpine.js, drops in the fragment).

**Done:** `alpine::Table` — search, the `|< << … >> >|` pager, a create/edit modal form (typed
inputs, relation dropdown or search→select picker, inline validation), per-row + bulk delete, CSV
import/export; plus runtime OpenAPI + Swagger in the example. Usage:
[docs/AUTOCRUD.md → Web admin](docs/AUTOCRUD.md#web-admin-alpine).

**Deferred:** standalone `alpine::Form`, an `alpine::Admin` shell/orchestrator, per-field widgets,
transactional CSV import. A future server-rendered `HtmxAdmin` frontend is possible on the same seam.

---

## 3. Auth — authentication & authorization ⛔ (planned)

A package providing a **user + group** model (SeaORM entities) and authentication via **TOTP 2FA**,
**PassKeys** (WebAuthn), and **OIDC**, plus authorization gating for the API and admin (per-entity /
per-operation policy, row-level filters). Not specified yet.

## 4. Files — file handling ⛔ (planned)

A package to **upload multiple documents** (PDF, MS Office / LibreOffice, images), **display and
download** them, and **capture a photo from the device camera** and upload it. Not specified yet.

## 5. Open questions

- **Presentation config** (widgets, formatting beyond label/help/default) lives downstream of the
  metadata, on the frontend components — not in the wire contract.
- **Auth** and **Files** need their own specs once the metadata contract has settled in use.
