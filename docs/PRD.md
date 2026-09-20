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
| **`middleware`** | `resolve_real_ip` (required — the caller's address, resolved once into a `RealIp` extension). No logging: the crate writes nothing, see `examples/access_log` | ✅ | [AUTH.md §4](AUTH.md) |
| **`observe`** (§4) | write-observer hook for audit logging (change + request context) | ✅ implemented | [CRUD.md → Write observer](CRUD.md#write-observer-audit) |
| **`time`** (§5) | timezone-aware display of UTC timestamps (helpers + `$store.tz` + picker) | ✅ implemented | [TIME.md](TIME.md) |
| **`validate`** | reusable typed field validators + normalizers, shared by CRUD and hand-written APIs | ✅ implemented | [DATAINPUT.md](DATAINPUT.md) |
| **`blob`** (§6) | content-addressed file storage, viewer, thumbnailer, admin panel | 🟡 draft spec | [BLOBSTORE.md](BLOBSTORE.md) |

> ✅ implemented & verified · 🟡 partial (core done, hardening/extras ahead) · ⛔ future.

## Vision: one contract, many backends and frontends

`relativelylight` is an **umbrella**. A *backend flavor* turns some data source into entities the
engine can serve (§1); a *frontend flavor* renders them (§2). The contract in the middle is
**`Vec<Column>` + `Page`** — typed Rust, in-process — so backends and frontends vary independently.
Today there is one backend (SeaORM) and one frontend (`crud::ui`).

That contract used to be a JSON + metadata HTTP API. **0.3 removed it** (see `MPA.md`): its only
consumer was this crate's own JavaScript, and publishing a wire format for an in-process seam cost an
untyped middle, a 477-line OpenAPI generator, and ~1,450 lines of client code no compiler read. An app
that wants a JSON API for its *own* clients writes those handlers over the same `Engine` — where the
versioning and shape decisions belong to it.

The library is always **part of** a larger app — the app owns its axum router and its page shell; the
library contributes HTML fragments and the write path behind them. This is a hard design invariant, not
a convenience.

---

## 1. `crud` — the CRUD engine ✅

**Requirement:** given SeaORM entities, provide complete CRUD with *no per-model code* — relations
included, plus search / filter / sort / paginate, bulk delete, CSV import/export, and a typed,
structural `columns` description the renderer matches on. Per-entity config (labels, visibility,
defaults, validators, N:M) is a light, optional layer over introspection.

**Relations are first-class in queries, not just in reads:** `filter[<relation>]` matches the foreign
key behind the name a caller already knows, and `sort=<relation>` orders by the *label* the relation
renders as (a join onto the target's label column) rather than the id behind it — so a list can be
ordered the way it is read. Where a label isn't a single column, or a row has many of them, the column
reports `sortable: false` and the engine refuses, rather than ordering by a guess.

`Vec<Column>` + `Page` is the **backend-agnostic contract** every backend satisfies and every frontend
consumes: the backend returns finished rows; the engine forwards them.

**Roadmap / deferred:**
- A second backend (in-memory, another ORM) behind the ORM-neutral `Accessor` seam — no core change.
- Batch relation reads (relation resolution is currently per-target — N+1).
- Composite-PK URL token + a `row_key` escape hatch.
- Richer field description: **done** — `nullable` (canonicalizing an empty submitted string to `NULL`),
  `required` (enforced on create and on an explicit `null`, replacing a database `500` with a validation
  message), and enum `options` (introspected from `ColumnType::Enum` or declared by hand; a `<select>`
  or radio group, plus a membership check).

## 2. `crud::ui` — auto-generated web admin ✅

**Requirement:** a customizable admin UI generated from the model, with no hand-written forms.
Rendering is **entirely server-side**: columns and rows go from the engine into HTML in one pass, with
a Rust `match` per cell and per input. The app supplies the shell (Bootstrap 5's stylesheet plus
`crud::ui::CSS`) and drops the fragment in; there is no JavaScript framework and no client-side state.

The **URL is the view** — page, sort, filters, search, active entity, open dialog — so every screen is
linkable; writes are `POST` → `303` → `GET` from the app's own route, via `submit`.

- **`Form`** — one entity's create/edit form, standalone, for the **app's own** pages: field subset +
  order, per-field widget overrides (textarea / radio / slider / email / url / datetime), gate-aware
  rendering (`401`/`403` rather than a form that can't submit), a redirect or a saved message after a
  save, and render-time refusal of a form that could never work (unknown / read-only /
  required-but-unrendered column).
- **`Table`** — one entity: search, **sortable headers** (relations included), **filter controls** (a
  relation picker, an enum's values, a boolean, or a value pinned by the page), windowed pager, that
  same form in a native `<dialog>` (typed inputs, boolean switch, enum dropdown or radio group,
  relation dropdown, timezone-aware datetime picker, inline validation that keeps the operator's
  input), per-row + bulk delete, CSV import/export,
  boolean/relation badges, custom cell renderers. A filter governs the export and the bulk delete as
  well as the listing, so no control can act on a wider set than the one on screen.
- **`Admin`** — a model side panel over many `Table`s (configurable order, group headings, separators,
  custom links), rendering **one** of them per request (`?entity=post`), plus **one filter shared
  across every listed table that has the column** — the difference between usable and unusable once an
  admin lists many tables of the same shape.

All three are **one implementation**, so the requirement above — *no hand-written forms* — is met once
and `Admin` stays a composition of the parts rather than a fourth thing to maintain.

**Roadmap / deferred:** search-as-you-type on relations whose target is too large to list (it needs a
fetch endpoint, deliberately absent — an id input is the current answer); multipart CSRF so CSV import
can take a file rather than a paste; optional cross-document view transitions.

## 3. `auth` — authentication & authorization 🟡

**Requirement:** a feature-gated module (usable **without** `crud`) providing a user + group model
(SeaORM), authentication, and per-operation authorization gating for every rendered and written
surface.
Identity is resolved **on demand** (no middleware, nothing injected into the request).

**Implemented:** argon2id login/logout with a server-side session cookie; `Auth::identify → Identity`;
a per-model `Authz` gate with presets (`Open` / `UserReadWrite` / `UserReadGroupWrite` /
`PublicReadGroupWrite` / `GroupReadWrite`) wired into `crud` (→ 401/403); self-service profile with
password change; **TOTP 2FA**
(enrol/verify/login/disable, single-use codes, plus **recovery codes** for a lost authenticator); **OIDC SSO** (feature `sso`: Google / Okta / corporate,
claim→group
mapping, optional auto-registration, cached provider discovery, and a callback whose rejection paths are
tested against a fake IdP); **double-submit CSRF protection** (feature `csrf`: always on for
the login/profile forms, `Crud::csrf` for the admin's writes, a `csrf::enforce` layer for the app's own routes, and an
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
(Client-IP resolution shipped as `middleware`; request logging is the app's — the crate writes nothing,
see `examples/access_log`. CORS is documented rather than wrapped,
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

**Requirement:** the database standardizes on **UTC** (`i64` Unix seconds); showing times in a chosen
timezone is a presentation concern only — nothing stored ever carries an offset. The library must let
an app render and edit timestamps in UTC or a named zone without touching the data model or storing
anything on `auth_user`.

**Rendering happens on the server** (feature `tz`, one dependency: `jiff`). The selected zone rides in
a cookie, `Tz::from_headers` reads it, and `Tz::format` / `format_input` / `parse` do the work — so a
table cell, a `datetime-local` input and **a CSV export** all agree, which they could not while the
zone was known only to the browser. `time::TzPicker` renders the control; setting the cookie is a
four-line route of the app's own, because a fragment renderer can't write a response header. DST gaps
and folds resolve by the IANA rules and are covered by unit tests.

**Roadmap / deferred:** nicer zone abbreviations (`CEST` rather than `GMT+2`); seeding the cookie from
the browser's own zone on a first visit (three lines of app-side JavaScript, deliberately not shipped).

## 6. `blob` — content-addressed file storage 🟡

Digest-verified storage behind a backend trait (filesystem shipped; object storage a future
implementation of the same trait), a server-rendered viewer/upload/thumbnail/admin layer with no
JavaScript beyond `ui`'s existing budget, and backup/purge mechanisms an app supplies its own policy
to. Deliberately stops short of versioning or ownership — those are an app's own typed layer on top
(CLIMB's `attachments.md` is the reference case this scope line was drawn against). Full design:
[BLOBSTORE.md](BLOBSTORE.md).

## 7. Open questions

- **Presentation config** (widgets, formatting beyond label/help/default) lives downstream of the
  metadata, on the frontend components — not in the wire contract.
- **auth** and **files** get their own full specs as the metadata contract settles in use.
