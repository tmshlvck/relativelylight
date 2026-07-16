# Rune — Product Requirements Document

**Rune** turns Rust ORM entities into a full back-office stack — a JSON CRUD + metadata API, an
auto-generated web admin, authentication/authorization, and file handling — with **no per-model
code**. It's built from composable components; take the pieces you need.

| Component | What | Status |
|---|---|---|
| **autocrud** (§1) | SeaORM entities → JSON CRUD + machine-readable metadata API | ✅ implemented |
| **Rune Admin** (§2) | auto-generated web admin: table, create/edit form, admin side-panel, bulk + CSV | ✅ implemented |
| **`auth`** (§3) | standalone crate: user + group model, sessions, TOTP 2FA, PassKeys, OIDC, `Authz` gate | ⛔ planned (draft spec) |
| **Files** (§4) | multi-file upload / display / download / camera capture | ⛔ planned |

> ✅ implemented & verified · 🟡 partial · ⛔ future.

This document is the product overview and roadmap. For **how to use it** — the full API, formats,
and design — see **[docs/AUTOCRUD.md](docs/AUTOCRUD.md)**; for a lead-in, **[README.md](README.md)**.

## Vision: one API, many backends and frontends

Rune is an **umbrella**. A *backend flavor* turns some data source into a stable JSON + metadata HTTP
API (§1); a *frontend flavor* consumes that API to render an admin UI (§2). The API is the fixed
contract in the middle, so backends and frontends vary independently. Today there is one backend
(SeaORM) and one frontend (`alpine`); the seam is designed so a second of either drops in without a
core change. The library is always **part of** a larger app — the app owns its axum router, its page
shell, and its OpenAPI document; autocrud contributes routes, HTML fragments, and API schemas into
them.

---

## 1. autocrud — CRUD + metadata API ✅

Introspects SeaORM entities at runtime and serves, with no per-model code: full CRUD (with
relations), search / sort / paginate, bulk delete, CSV import/export, and a machine-readable,
structural `columns` description that drives the UI and OpenAPI. One `MetaModel` per entity is
auto-generated and lightly tweakable (labels, visibility, defaults, validators, N:M).

The metadata is the backend-agnostic contract every backend satisfies and every frontend consumes;
the backend returns finished JSON and the engine forwards it.

**Public API and full behavior:** [docs/AUTOCRUD.md](docs/AUTOCRUD.md).

**Roadmap / deferred:**
- A second backend (`autocrud::memory`, another ORM) — the `Accessor` seam is ORM-neutral, so this
  needs no core change.
- Relation reads are per-target queries (N+1) — batch/join inside the backend later.
- Composite-PK URL token + a `row_key` escape hatch; map constraint violations to **409** (now 500).
- Richer field metadata (enum `options`, nullable/`required`).

---

## 2. Rune Admin — auto-generated web admin (`autocrud::alpine`) ✅

A customizable admin UI generated from the model. Rendering is hybrid: the column **shape** is read
from the engine in-process and embedded in a server-rendered HTML **fragment**; **data** is fetched
client-side from the JSON API. The app supplies the shell (Bootstrap 5 + Alpine.js) and drops the
fragment in.

- **`Table`** — one entity: search, windowed pager, a create/edit modal form (typed inputs, boolean
  switch, relation dropdown or search→select picker, inline validation), per-row + bulk delete, CSV
  import/export, boolean/relation badges, and custom per-column cell renderers.
- **`Admin`** — a model side-panel over many `Table`s (configurable order, group headings,
  separators, custom links); client-side model switching.

**Public API and full behavior:** [docs/AUTOCRUD.md → Web admin](docs/AUTOCRUD.md#web-admin-alpine).

**Roadmap / deferred:** a standalone `alpine::Form`, per-field widget overrides, transactional CSV
import, and (further out) a server-rendered `HtmxAdmin` frontend on the same seam.

---

## 3. Auth — authentication & authorization ⛔ (planned; **draft spec**)

A **standalone `auth` crate** (usable without autocrud) providing a **user + group** model (SeaORM)
and authentication via **TOTP 2FA**, **PassKeys** (WebAuthn), and **OIDC**, plus authorization gating
for the API and admin (per-operation policy; row-level later). `autocrud` optionally depends on it to
gate its endpoints. The core design is drafted in **[docs/AUTH.md](docs/AUTH.md)**: cookie +
server-side session, argon2id, an `Authz` gate (`can_list`/`can_read`/`can_write`) with presets, and
a middleware stack (real-ip, logging, CORS, CSRF). Playground: `examples/auth`.

## 4. Files — file handling ⛔ (planned)

A package to **upload multiple documents** (PDF, MS Office / LibreOffice, images), **display and
download** them, and **capture a photo from the device camera** and upload it. Not specified yet.

## 5. Open questions

- **Presentation config** (widgets, formatting beyond label/help/default) lives downstream of the
  metadata, on the frontend components — not in the wire contract.
- **Auth** and **Files** need their own specs once the metadata contract has settled in use.
