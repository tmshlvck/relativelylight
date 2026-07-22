# relativelylight — Product Requirements Document

**relativelylight** turns Rust ORM entities into a full back-office stack — a JSON CRUD + metadata
API, an auto-generated web admin, authentication/authorization, and file handling — with **no
per-model code**. It's one crate of composable, feature-gated modules; take the pieces you need.

| Module | What | Status |
|---|---|---|
| **`crud`** (§1) | SeaORM entities → JSON CRUD + machine-readable metadata API | ✅ implemented |
| **`crud::ui`** (§2) | auto-generated web admin: table, create/edit form, admin side-panel, bulk + CSV | ✅ implemented |
| **`auth`** (§3) | user + group model, sessions, login, `Authz` gate (+ planned TOTP 2FA, PassKeys, OIDC) | 🟡 first slice done |
| **Files** (§4) | multi-file upload / display / download / camera capture | ⛔ planned |

> ✅ implemented & verified · 🟡 partial · ⛔ future.

This document is the product overview and roadmap. For **how to use it** — the full API, formats, and
design — see **[docs/CRUD.md](docs/CRUD.md)** and **[docs/AUTH.md](docs/AUTH.md)**; for a lead-in,
**[README.md](README.md)**.

## Vision: one API, many backends and frontends

`relativelylight` is an **umbrella**. A *backend flavor* turns some data source into a stable JSON +
metadata HTTP API (§1); a *frontend flavor* consumes that API to render an admin UI (§2). The API is
the fixed contract in the middle, so backends and frontends vary independently. Today there is one
backend (SeaORM) and one frontend (`crud::ui`); the seam is designed so a second of either drops in
without a core change. The library is always **part of** a larger app — the app owns its axum router,
its page shell, and its OpenAPI document; the library contributes routes, HTML fragments, and API
schemas into them.

---

## 1. `crud` — CRUD + metadata API ✅

Introspects SeaORM entities at runtime and serves, with no per-model code: full CRUD (with
relations), search / sort / paginate, bulk delete, CSV import/export, and a machine-readable,
structural `columns` description that drives the UI and OpenAPI. One `MetaModel` per entity is
auto-generated and lightly tweakable (labels, visibility, defaults, validators, N:M).

The metadata is the backend-agnostic contract every backend satisfies and every frontend consumes;
the backend returns finished JSON and the engine forwards it.

**Public API and full behavior:** [docs/CRUD.md](docs/CRUD.md).

**Roadmap / deferred:**
- A second backend (in-memory, another ORM) — the `Accessor` seam is ORM-neutral, so this needs no
  core change.
- Relation reads are per-target queries (N+1) — batch/join inside the backend later.
- Composite-PK URL token + a `row_key` escape hatch. (Unique / FK constraint violations now map to
  **409**.)
- Richer field metadata (enum `options`, nullable/`required`).

---

## 2. `crud::ui` — auto-generated web admin ✅

A customizable admin UI generated from the model. Rendering is hybrid: the column **shape** is read
from the engine in-process and embedded in a server-rendered HTML **fragment**; **data** is fetched
client-side from the JSON API. The app supplies the shell (Bootstrap 5 + Alpine.js) and drops the
fragment in.

- **`Table`** — one entity: search, windowed pager, a create/edit modal form (typed inputs, boolean
  switch, relation dropdown or search→select picker, inline validation), per-row + bulk delete, CSV
  import/export, boolean/relation badges, and custom per-column cell renderers.
- **`Admin`** — a model side-panel over many `Table`s (configurable order, group headings,
  separators, custom links); client-side model switching.

**Public API and full behavior:** [docs/CRUD.md → Web admin](docs/CRUD.md#web-admin-ui).

**Roadmap / deferred:** a standalone `Form` component, per-field widget overrides, transactional CSV
import, and (further out) a server-rendered `htmx` frontend on the same seam.

---

## 3. `auth` — authentication & authorization ⛔ (planned; **draft spec**)

A feature-gated module (usable without `crud`) providing a **user + group** model (SeaORM) and
authentication, plus authorization gating for the API and admin (per-operation policy; row-level
later). **First slice implemented:** argon2id login/logout with a server-side session cookie,
on-demand session resolution (`Auth::identify` → `Identity`; **no middleware**), a per-model `Authz`
gate (`authorize(op, &headers) -> Decision`) with presets, per-model wiring into `crud`
(`Crud::authz` / `register_authz` → 401/403), and admin helpers (`make_admin`, `set_password`, …) —
see `examples/auth` + `examples/adminpanel`. **Planned:** password-change UI, CSRF/CORS/real-ip
layers, per-user UI control-hiding, **TOTP 2FA**, **PassKeys**, **OIDC**. Design:
**[docs/AUTH.md](docs/AUTH.md)**.

## 4. Files — file handling ⛔ (planned)

Upload multiple documents (PDF, MS Office / LibreOffice, images), display and download them, and
capture a photo from the device camera and upload it. Not specified yet.

## 4a. `observe` — the write-observer / audit hook ✅

An always-compiled seam ([`observe`](src/observe.rs)) for **audit logging**. An audit record needs
both *what changed* (old/new row data, seen at the data layer) and *who/how* (actor, auth type, client
IP, seen only at the HTTP layer); no single layer has both. So the library fires a
[`WriteEvent`](observe::WriteEvent) — carrying the change **and** the request context (`headers` +
socket `peer`) — from the points that do: each `crud` write handler and each mutating `auth` handler.
The **app registers one [`WriteObserver`](observe::WriteObserver)** (`Crud::on_write` /
`Auth::on_write`, one `Arc` shared by both), resolves the actor itself (`auth.identify`), derives the
IP, and **persists the audit row in its own table** — the library ships the hook, not an audit schema.
**Retention/pruning is the app's responsibility.** See [docs/CRUD.md](docs/CRUD.md#write-observer-audit)
and [docs/AUTH.md](docs/AUTH.md).

Auth entities also carry **UTC lifecycle timestamps** — `created_at`/`updated_at` (maintained by a
SeaORM `before_save` hook) on `auth_user`/`auth_group`, plus `last_login_at` on `auth_user` (stamped by
the login/TOTP/SSO flows).

## 5. Open questions

- **Presentation config** (widgets, formatting beyond label/help/default) lives downstream of the
  metadata, on the frontend components — not in the wire contract.
- **auth** and **files** get their own specs once the metadata contract has settled in use.
- **Timezones (done).** The DB and the JSON API standardize on **UTC** (`i64` Unix seconds);
  presentation is a **frontend** concern. `time::JS` provides `RLTime` (UTC / browser-local /
  named-zone formatting + DST-correct datetime-local conversion), an Alpine `$store.tz` selection, and
  `time::TzPicker` (the picker). `Table` datetime columns follow the selection; the wire contract
  stays UTC and conversion happens only at render time. Full guide: [docs/TIME.md](docs/TIME.md).
  Remaining refinement: nicer zone abbreviations (Intl `short` yields `GMT+2`, not `CEST`).
