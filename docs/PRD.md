# relativelylight — Product Requirements Document

**relativelylight** turns Rust ORM entities into a full back-office stack — a JSON CRUD + metadata
API, an auto-generated web admin, authentication/authorization, and file handling — with **no
per-model code**. It's one crate of composable, feature-gated modules; take the pieces you need.

This document is the **product overview and roadmap**: what each module is *for*, its status, and
what's still ahead. It intentionally does **not** teach usage — for a lead-in see
**[../README.md](../README.md)**, and for the full API/design see the per-module guides linked below.
For the concrete backlog see **[../TODO.md](../TODO.md)**.

| Module | What it's for | Status | Guide |
|---|---|---|---|
| **`crud`** (§1) | SeaORM entities → JSON CRUD + machine-readable metadata API | ✅ implemented | [CRUD.md](CRUD.md) |
| **`crud::ui`** (§2) | auto-generated web UI: standalone form, table, side-panel, bulk + CSV | ✅ implemented | [CRUD.md → Web UI](CRUD.md#web-ui-ui) |
| **`auth`** (§3) | user/group model, sessions, login, TOTP 2FA, OIDC SSO, per-model `Authz` gate | 🟡 major slice done | [AUTH.md](AUTH.md) |
| **`middleware`** | `resolve_real_ip` (required — the caller's address, resolved once into a `RealIp` extension) + `access_log` | ✅ | [AUTH.md §4](AUTH.md) |
| **`observe`** (§4) | write-observer hook for audit logging (change + request context) | ✅ implemented | [CRUD.md → Write observer](CRUD.md#write-observer-audit) |
| **`time`** (§5) | timezone-aware display of UTC timestamps (helpers + `$store.tz` + picker) | ✅ implemented | [TIME.md](TIME.md) |
| **`validate`** | reusable typed field validators + normalizers, shared by CRUD and hand-written APIs | ✅ implemented | [DATAINPUT.md](DATAINPUT.md) |
| **Files** (§6) | multi-file upload / display / download / camera capture | ⛔ planned | — |

> ✅ implemented & verified · 🟡 partial (core done, hardening/extras ahead) · ⛔ future.

## Vision: one API, many backends and frontends

`relativelylight` is an **umbrella**. A *backend flavor* turns some data source into a stable JSON +
metadata HTTP API (§1); a *frontend flavor* consumes that API to render an admin UI (§2). The API is
the fixed contract in the middle, so backends and frontends vary independently. Today there is one
backend (SeaORM) and one frontend (`crud::ui`); the seam is designed so a second of either drops in
without a core change.

The library is always **part of** a larger app — the app owns its axum router, its page shell, and its
OpenAPI document; the library contributes routes, HTML fragments, and API schemas into them. This is a
hard design invariant, not a convenience.

---

## 1. `crud` — CRUD + metadata API ✅

**Requirement:** given SeaORM entities, serve a complete data API with *no per-model code* — full CRUD
(including relations), search / sort / paginate, bulk delete, CSV import/export, and a
machine-readable, structural `columns` description that drives both the UI and OpenAPI. Per-entity
config (labels, visibility, defaults, validators, N:M) is a light, optional layer over introspection.

The metadata is the **backend-agnostic contract** every backend satisfies and every frontend consumes:
the backend returns finished JSON; the engine forwards it and adds the metadata envelope.

**Roadmap / deferred:**
- A second backend (in-memory, another ORM) behind the ORM-neutral `Accessor` seam — no core change.
- Batch relation reads (relation resolution is currently per-target — N+1).
- Composite-PK URL token + a `row_key` escape hatch.
- Richer field metadata: **done** — `nullable` (canonicalizing an empty submitted string to `NULL`),
  `required` (enforced on create and on an explicit `null`, replacing a database `500` with a `422`), and
  enum `options` (introspected from `ColumnType::Enum` or declared by hand; a `<select>`, an OpenAPI `enum`,
  and a membership check).

## 2. `crud::ui` — auto-generated web admin ✅

**Requirement:** a customizable admin UI generated from the model, with no hand-written forms.
Rendering is hybrid: the column **shape** is read from the engine in-process and embedded in a
server-rendered HTML **fragment**; **data** is fetched client-side from the JSON API. The app supplies
the shell (Bootstrap 5 + Alpine.js) and drops the fragment in.

- **`Form`** — one entity's create/edit form, standalone, for the **app's own** pages: field subset +
  order, gate-aware rendering (`401`/`403` rather than a form that can't submit), redirect-or-callback
  after save, and render-time refusal of a form that could never work (unknown / read-only / required-but
  -unrendered column).
- **`Table`** — one entity: search, windowed pager, that same form in a modal (typed inputs, boolean
  switch, enum dropdown, relation dropdown or search→select picker, timezone-aware datetime picker,
  inline validation), per-row + bulk delete, CSV import/export, boolean/relation badges, custom cell
  renderers.
- **`Admin`** — a model side-panel over many `Table`s (configurable order, group headings,
  separators, custom links) with client-side model switching.

`Form` and `Table`'s modal are **one implementation** behind shared partials (widgets in one, behaviour
in the other), so the requirement above — *no hand-written forms* — is met once and `Admin` stays a
composition of the parts rather than a fourth thing to maintain.

**Roadmap / deferred:** per-field widget overrides, transactional CSV
import, and (further out) a server-rendered `htmx` frontend on the same seam.

## 3. `auth` — authentication & authorization 🟡

**Requirement:** a feature-gated module (usable **without** `crud`) providing a user + group model
(SeaORM), authentication, and per-operation authorization gating for both the API and the admin.
Identity is resolved **on demand** (no middleware, nothing injected into the request).

**Implemented:** argon2id login/logout with a server-side session cookie; `Auth::identify → Identity`;
a per-model `Authz` gate with presets (`Open` / `UserReadWrite` / `UserReadGroupWrite` /
`PublicReadGroupWrite` / `GroupReadWrite`) wired into `crud` (→ 401/403); self-service profile with
password change; **TOTP 2FA**
(enrol/verify/login/disable, single-use codes, plus **recovery codes** for a lost authenticator); **OIDC SSO** (feature `sso`: Google / Okta / corporate,
claim→group
mapping, optional auto-registration, cached provider discovery, and a callback whose rejection paths are
tested against a fake IdP); **double-submit CSRF protection** (feature `csrf`: always on for
the login/profile forms, `Crud::csrf` for the API, a `csrf::enforce` layer for the app's own routes, and an
app-supplied rejection page); **attempt limiting** on the unauthenticated
credential checks (DB-backed lockout → 429, by account name and by source address, both mandatory, the
unlock being a row delete in the admin panel); **session lifetime + revocation** (absolute *and* idle
clocks, id rotation when the second factor completes, a password change or manager reset signing the
user's other sessions out, "sign out other sessions" on `/profile`); **re-authentication before sensitive
changes** (a password or a fresh TOTP code before disabling/enrolling 2FA or a manager's reset, plus
`Auth::reauthenticate` for app-owned actions); a **password-strength policy**
(`validate::PasswordPolicy` — length-first, no composition rules per NIST SP 800-63B; on by default on the
profile pages, opt-out two ways, wired separately into the admin form); UTC lifecycle timestamps
on the auth entities. The rejection
paths (bad credentials, unusable sessions, wrong TOTP codes, replayed codes, idle/expired sessions,
non-manager profile writes, each gate preset) are covered by an automated negative-path suite —
[AUTH.md §10a](AUTH.md).

**Roadmap / deferred (see [../TODO.md](../TODO.md) for the ordered backlog):**
re-auth through the IdP for SSO accounts, breached-password screening, and CSRF on multipart bodies.
(Client-IP resolution and the access log shipped as `middleware`; CORS is documented rather than wrapped,
and **app-issued API tokens are deliberately the app's** — the gate is handed the request headers, so an
API-first service verifies its own tokens and gates the generated CRUD routes with them, while this crate
owns the web door.) **PassKeys/WebAuthn** is parked at
**milestone 0.3+** (nothing needs it yet; it stays the only answer to real-time phishing), and
**row-level authorization** is filed as *transformative* — it reshapes the `Authz` trait rather than
extending it, so it waits for a requirement an app can't meet in its own handler.

## 4. `observe` — the write-observer / audit hook ✅

**Requirement:** make audit logging possible without baking an audit schema into the library. An audit
record needs both *what changed* (old/new row data, seen at the data layer) and *who/how* (actor, auth
type, client IP, seen only at the HTTP layer); no single layer has both.

The always-compiled `observe` seam fires a `WriteEvent` — carrying the change **and** the request
context (`headers` + the already-resolved `client_ip`) — from each `crud` write handler and each mutating
`auth` handler. The **app registers one `WriteObserver`** (`Crud::on_write` / `Auth::on_write`, one `Arc`
shared by both), resolves the actor itself, and **persists the audit row in its own table**. The address
needs no deriving: it is the one `middleware::resolve_real_ip` decided, so an audit row, a lockout row and
an access-log line all name the same client.
Retention/pruning is the app's responsibility.

## 5. `time` — timezone-aware presentation ✅

**Requirement:** the DB and every API standardize on **UTC** (`i64` Unix seconds); showing times in a
viewer's local or a chosen timezone is a **frontend** concern only — the wire contract never carries
offsets. The library must let an app render/edit timestamps in UTC, browser-local, or a named zone
without touching the data model or storing anything on `auth_user`.

`time::JS` ships `RLTime` (UTC / browser-local / named-zone formatting, an explicit UTC formatter, a
"local (UTC)" helper, and DST-correct `datetime-local` ⇆ Unix-seconds conversion), an Alpine
`$store.tz` selection, and `time::TzPicker` (the picker). `Table` datetime columns follow the
selection; conversion happens only at render time. The app owns the policy (hardcoded UTC /
browser-local / per-session / app-stored / server-defined) via `window.RL_TZ`.

**Roadmap / deferred:** nicer zone abbreviations (Intl `short` yields `GMT+2`, not `CEST`); an optional
app-side helper for the "store the user's TZ" case (kept out of `auth_user`).

## 6. Files — file handling ⛔ (planned)

Upload multiple documents (PDF, MS Office / LibreOffice, images), display and download them, and
capture a photo from the device camera and upload it. Not specified yet.

## 7. Open questions

- **Presentation config** (widgets, formatting beyond label/help/default) lives downstream of the
  metadata, on the frontend components — not in the wire contract.
- **auth** and **files** get their own full specs as the metadata contract settles in use.
