# relativelylight — Product Requirements Document

**relativelylight** turns Rust ORM entities into a full back-office stack — a typed CRUD engine, an
auto-generated server-rendered web admin, authentication/authorization, and file handling — with **no
per-model code**. It's one crate of composable, feature-gated modules; take the pieces you need.

This document is the **product overview, the architecture decisions, and the roadmap**: what each
module is *for*, what was decided across all of them, and what is still ahead.

It deliberately does **not** enumerate features or teach usage — each module's guide owns that, and a
second copy here would be a second thing to keep true. If a paragraph below could be moved into
`CRUD.md` or `AUTH.md` without loss, it belongs there. For a lead-in see
**[../README.md](../README.md)**; for the concrete backlog, **[TODO.md](TODO.md)**.

| Module | What it's for | Status | Guide |
|---|---|---|---|
| **`crud`** (§1) | SeaORM entities → a typed CRUD engine (list/read/write/validate/gate) | ✅ implemented | [CRUD.md](CRUD.md) |
| **`crud::ui`** (§2) | auto-generated web UI: standalone form, table, side-panel, bulk + CSV | ✅ implemented | [CRUD.md → Web UI](CRUD.md#web-ui-ui) |
| **`auth`** (§3) | user/group model, sessions, login, TOTP 2FA, OIDC SSO, per-model `Authz` gate | 🟡 major slice done | [AUTH.md](AUTH.md) |
| **`middleware`** | `resolve_real_ip` (required — the caller's address, resolved once into a `RealIp` extension). No logging: the crate writes nothing, see `examples/audit` | ✅ | [AUTH.md §4](AUTH.md) |
| **`observe`** (§4) | write-observer hook for audit logging (change + request context) | ✅ implemented | [CRUD.md → Write observer](CRUD.md#write-observer-audit) |
| **`time`** (§5) | timezone-aware display of UTC timestamps (helpers + `$store.tz` + picker) | ✅ implemented | [TIME.md](TIME.md) |
| **`validate`** | reusable typed field validators + normalizers, shared by CRUD and hand-written APIs | ✅ implemented | [DATAINPUT.md](DATAINPUT.md) |
| **`blob`** (§6) | content-addressed file storage + version chain, streaming upload, document portal, admin panel | 🟢 shipped | [BLOBSTORE.md](BLOBSTORE.md) |

> ✅ implemented & verified · 🟡 partial (core done, hardening/extras ahead) · ⛔ future.

## Vision: one contract, many backends and frontends

`relativelylight` is an **umbrella**. A *backend flavor* turns some data source into entities the
engine can serve (§1); a *frontend flavor* renders them (§2). The contract in the middle is
**`Vec<Column>` + `Page`** — typed Rust, in-process — so backends and frontends vary independently.
Today there is one backend (SeaORM) and one frontend (`crud::ui`).

That contract used to be a JSON + metadata HTTP API. **0.3 removed it** (see [MIGRATION-0.3.md](MIGRATION-0.3.md)): its only
consumer was this crate's own JavaScript, and publishing a wire format for an in-process seam cost an
untyped middle, a 477-line OpenAPI generator, and ~1,450 lines of client code no compiler read. An app
that wants a JSON API for its *own* clients writes those handlers over the same `Engine` — where the
versioning and shape decisions belong to it.

The library is always **part of** a larger app — the app owns its axum router and its page shell; the
library contributes HTML fragments and the write path behind them. This is a hard design invariant, not
a convenience.

## Architecture decisions

The invariants that hold across every module. Each is argued where it bites, in the module guides;
collected here because they are what makes the pieces fit together, and because an addition that
breaks one of them should have to argue with this list first.

1. **The library is part of an app, never its frame.** The app owns the axum router, the page shell
   and the URLs. Modules contribute HTML *fragments* and the write path behind them. `auth::routes`
   and `blob::ui::Routes` are the two exceptions, both opt-in and both mounted by the app at a path
   it chooses.
2. **The contract in the middle is typed and in-process** — `Vec<Column>` + `Page`, not a wire
   format. 0.3 removed the JSON layer that used to sit there; an app wanting a JSON API for its own
   clients writes it over the same `Engine`, where the versioning decisions belong to it.
3. **No mandatory coupling between modules.** `auth` works without `crud`; `blob` needs neither.
   Every feature an app doesn't enable costs it no dependencies. The one exception is deliberate and
   named: `middleware::resolve_real_ip` is required, so the lockout, the audit events and the app's
   own log cannot disagree about who called.
4. **Authorization is a per-model gate handed the request headers**, resolving identity itself. Two
   consequences the modules lean on: a gate needs no middleware and injects nothing, and *row-level*
   access is out of scope — an app expresses it by shape instead (a table per document kind, §6),
   which turns a row question into a model question the existing gate already answers.
5. **The app owns its database.** Modules describe their own tables (`table_create_statements`) and
   the app's migration applies them. Nothing migrates itself on start except the examples.
6. **State and audit are different things.** A table says what something *is*; the `observe` seam
   says what someone *did*. Neither is asked to do the other's job — which is why `created_by` is a
   snapshot column rather than an audit lookup, and why a deleted document leaves no tombstone in
   its own chain.
7. **Server-rendered, no JavaScript framework, and the URL is the state.** Page, sort, filters,
   search, the open dialog: all in the query string, so every view is a link and the library needs
   no route of its own. Interactivity uses native elements (`<dialog>`, `<details>`) rather than a
   runtime.
8. **Policy belongs to the app; mechanism belongs here.** Retention, ownership, thumbnail sizes,
   what a request log contains — all refused on purpose, each with the same reasoning: the crate
   cannot know, and a wrong default is worse than an absent one.

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

Three components — **`Form`** (one entity, standalone, for the app's own pages), **`Table`** (one
entity with search, sorting, filters, pager, dialog editor, bulk delete, CSV) and **`Admin`** (a side
panel over many tables, rendering one per request). What each offers is
[CRUD.md → Web UI](CRUD.md#web-ui-ui); what matters here is that a filter governs the CSV export and
the bulk delete as well as the listing, so no control can act on a wider set than the one on screen.

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

**Implemented:** password login with server-side sessions, TOTP 2FA with recovery codes, OIDC SSO,
CSRF, attempt lockout, session lifetime and revocation, re-authentication before sensitive changes, a
password-strength policy, and the gate presets wired into `crud`. [AUTH.md](AUTH.md) is the guide;
what belongs here is that the **rejection** paths — bad credentials, unusable sessions, replayed
codes, non-manager profile writes, each gate preset — are covered by an automated negative-path suite
([AUTH.md §10a](AUTH.md)), because a security module that only tests its happy path is testing the
wrong half.

**Roadmap / deferred (see [TODO.md](TODO.md) for the ordered backlog):**
re-auth through the IdP for SSO accounts, breached-password screening, and CSRF on multipart bodies.
(Client-IP resolution shipped as `middleware`; request logging is the app's — the crate writes nothing,
see `examples/audit`. CORS is documented rather than wrapped,
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
shared by both), resolves the actor itself, and **persists the audit row in its own table**
(`examples/audit` is a runnable sink, printing one line per committed write). The address
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

## 6. `blob` — content-addressed file storage 🟢

Digest-verified storage behind a backend trait (filesystem shipped; object storage a future
implementation of the same trait), a server-rendered viewer/upload/browser layer with no JavaScript
beyond `ui`'s existing budget, and consistency-checking, collection and copying mechanisms an app
supplies its own policy to.

Three tables, because one is the classic mistake: a **handle** with a stable id an app's own tables
hold a foreign key to, an immutable **version** chain recording each upload, and digest-addressed
**content** underneath. Versioning is therefore in scope — it is what makes the handle stable, and
without it every app rebuilds the same indirection. **Ownership is not**, and neither is row-level
access: those live in a per-document-kind link table in the app, which is what keeps `blob` free of
any dependency on `auth` while giving ownership a *better* foreign key than an in-crate column could
(BLOBSTORE.md §9; CLIMB's `attachments.md` is the reference case the scope line was drawn against).
Full design: [BLOBSTORE.md](BLOBSTORE.md).

**Status: built** — storage and the chain in `blob`, the components in `blob-ui`, both pinned by
tests. Two runnable showcases: **`examples/blob`** (attachments on an app's own pages, with the
ownership link table and the admin panel) and **`examples/blobthumbnailer`** (a smaller app whose
subject is derived content — thumbnails generated and stored by the *app*, since the crate ships no
thumbnailer).

**Deliberately smaller than it was.** A thumbnailer, a variant index and partial erasure were built
and then removed: each added a second way to think about the same data, and this is load-bearing
infrastructure in every app that uses it. What is left is documents, their versions, the bytes
underneath, and one way to delete. BLOBSTORE.md §4.5 and §4.8 record both reversals and why.

## 7. Open questions

Per-module questions live in each guide's own section; these are the ones that cut across.

- **A second backend.** The `Accessor` seam exists for it and nothing in the engine assumes SeaORM,
  but until something real sits behind it the seam is untested as an abstraction rather than as
  code. The same is true of `BlobBackend`: one implementation is not proof of a good trait.
- **Where a second frontend would strain the contract.** `Vec<Column>` + `Page` is shaped by the one
  renderer that consumes it. A second would be the first honest test of whether it is a contract or
  just an interface.
- **Row-level authorization** stays out (decision 4), on the bet that shape — a table per kind —
  answers it. That bet holds for documents; it has not been tested by an app whose rows differ in
  visibility *within* one kind.
