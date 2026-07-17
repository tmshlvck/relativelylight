# CLAUDE.md — developing `relativelylight`

Orientation for working **on** this library (not yet a guide for apps *using* it — that comes once
the modules settle). Read this first, then the deeper docs it points to.

## What this is

`relativelylight` turns Rust ORM entities into a full back-office stack — a JSON CRUD + metadata
API, an auto-generated web admin, and auth — **with no per-model code**. One crate, composable
feature-gated modules. It's a **library that plugs into an app**, never the whole app: the app keeps
its own axum router, page shell, and OpenAPI document; `relativelylight` contributes routes, HTML
fragments, and API schemas into them.

Status (see `PRD.md` for the roadmap):

| Module | What | Status |
|---|---|---|
| `crud` | SeaORM entities → JSON CRUD + machine-readable metadata API | ✅ implemented |
| `crud::ui` | auto-generated Bootstrap/Alpine web admin (`Table`, `Admin`) | ✅ implemented |
| `auth` | user/group/session model, argon2 login, `Authz` gate | 🟡 first slice |
| Files | multi-file upload/display/download/camera | ⛔ planned |

## Where things live

Workspace (`Cargo.toml`): the library `relativelylight/` + four example crates under `examples/`.

```
relativelylight/src/
  lib.rs            module wiring + top-level doc
  authz.rs          (66)  ALWAYS compiled: Authz trait, Operation, Decision, Open gate
  crud/
    mod.rs                re-exports; the crud module doc
    engine.rs     (668)  backend-agnostic core: Accessor seam, contract types, Engine, axum router
    seaorm.rs     (975)  the SeaORM backend: introspection, MetaModel/MetaField/MetaRelation, Crud
    ui.rs         (334)  feature `ui`: Table + Admin (askama → Bootstrap 5 + Alpine 3 fragments)
    openapi.rs    (299)  feature `openapi`: runtime OpenAPI 3.1 from the Engine metadata
    csv_io.rs     (234)  feature `csv`: CSV import/export over the same validation pipeline
  auth/
    mod.rs        (496)  feature `auth`: Auth, Identity, identify, login/logout, gate presets, hashing
    user.rs group.rs user_group.rs session.rs   SeaORM models for auth

examples/
  model/          shared domain: author, post, tag, post_tag (N:M), profile, user; setup() seeds
                  an in-memory SQLite DB. The library knows nothing about this crate.
  crud/           crud-example       — per-entity MPA pages, CSV, Swagger; open (no auth)
  adminpanel/     adminpanel-example — crud::ui::Admin side-panel; login-gated
  auth/           auth-example       — auth alone (no crud) gating a page
```

LOC in parentheses — use it to find the right file fast.

## Build / test / run

```bash
cargo build                       # default features (crud + axum)
cargo build --all-features        # everything
cargo test --all-features         # unit tests live in engine.rs, openapi.rs, auth/mod.rs
cargo clippy --all-features

cargo run -p crud-example         # http://127.0.0.1:3000/  (Swagger at /docs, API under /api/v1)
cargo run -p adminpanel-example   # http://127.0.0.1:3000/  (admin/password = rw · editor/password = ro)
cargo run -p auth-example         # http://127.0.0.1:3000/  (admin/password)
```

Examples all bind `127.0.0.1:3000` — **run one at a time**. Each rebuilds a fresh seeded in-memory
SQLite DB on start, so there's no state to reset.

### Features

`default = ["crud", "axum"]`. Others: `ui`, `openapi`, `csv` (all imply `crud`), and `auth` (usable
*without* `crud` — enable `["auth"]` alone to gate any axum app). An unused feature pulls no deps.
When editing a feature-gated module, build/test with that feature on — `--all-features` is the safe
default.

## Design invariants — don't break these

- **No per-model code.** `MetaModel::new(entity)` introspects everything (fields, PK, FK relations).
  The *only* hand-declaration is N:M via `.relate(&other)` (SeaORM can't enumerate it).
- **The app owns the roots.** The library returns an `axum::Router` to merge, HTML **fragments**
  (never full pages), and OpenAPI paths/schemas to merge — never a whole router, page, or document.
- **Metadata is the contract.** The backend-agnostic `Engine` owns URLs/metadata and forwards
  finished JSON; each backend implements the per-entity `Accessor` trait (names no ORM types) and
  returns ready-to-send JSON. SeaORM is *one* backend behind that seam — keep DB concerns (relation
  resolution, projection, visibility policy) inside the accessor so the engine stays a pass-through.
- **auth has no middleware.** Identity is resolved on demand: `Auth::identify(&headers) ->
  Option<Identity>`. Nothing is injected into request extensions; no layer ordering, no
  `FromRequestParts` magic.
- **`authz` is always compiled** (only needs `http` + `async-trait`), so `Crud::register(model,
  gate)` takes a gate in every build — `Open` when ungated. Identity-resolving gate presets
  (`ValidUsers`, `UsersReadGroupWrite`) live in `auth`.
- **UI hiding is cosmetic; the API gate is the enforcement point.** `Admin::render_for` hides write
  controls the caller can't use, but an unauthorized write is still rejected (403) at the handler.

## The deeper docs (read before changing behavior in that area)

- `docs/CRUD.md` — the full `crud` guide: `MetaModel`/`MetaField`/`MetaRelation`, HTTP API + wire
  formats, query params, the validation pipeline (coerce → validate → transform), metadata, CSV, the
  web admin, OpenAPI, and composing with an app. **Keep this in sync when you change crud behavior.**
- `docs/AUTH.md` — the `auth` design (draft spec): what's implemented vs planned, the session/CSRF
  decisions, the gate contract and presets, the app-side wiring.
- `PRD.md` — product overview, module status, roadmap / deferred items.
- `README.md` — the outward-facing pitch + quick start.

These docs are detailed and current; treat them as the source of truth for intended behavior and
update them alongside code changes.

## Conventions

- SeaORM 1.1; axum 0.8; askama 0.13; utoipa 5. Entities need a **single-column PK** and
  **single-column to-one FKs** (any URL-safe scalar); N:M junction tables are never registered.
- Match the surrounding style — the codebase favors terse, well-commented modules; keep doc comments
  (`//!`, `///`) current since they carry real API contract.
- Errors: `{ "error": … }` with 400/404/405/422/500 (validation is structured 422 — see CRUD.md).
