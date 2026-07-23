# relativelylight

A web back-office toolkit for Rust. From your SeaORM entities it auto-generates a **JSON CRUD +
metadata API**, an **admin UI**, and **authentication/authorization** (sessions, login, TOTP 2FA, a
per-model gate) — **with no per-model code**. It's a library you compose *into* your app: you keep
your own axum router, page shell, and OpenAPI document; `relativelylight` contributes routes, HTML
fragments, and API schemas into them.

This file is a using-it orientation. For the complete guides see **[docs/CRUD.md](docs/CRUD.md)**,
**[docs/AUTH.md](docs/AUTH.md)**, and **[docs/TIME.md](docs/TIME.md)**; for the roadmap,
**[docs/PRD.md](docs/PRD.md)**.

## Install & features

```toml
[dependencies]
relativelylight = { version = "*", features = ["ui", "openapi", "csv", "auth"] }
sea-orm = { version = "1.1", features = ["macros", "with-json"] }
```

| Feature | Default | Gives you |
|---|---|---|
| `crud` | ✅ | the CRUD engine + SeaORM backend (the `crud` module) |
| `axum` | ✅ | the HTTP router (`Crud::into_router`, `Engine::router`) |
| `ui` | | the web admin components (`crud::ui::Table`, `crud::ui::Admin`) |
| `openapi` | | runtime OpenAPI 3.1 (`crud::openapi`) |
| `csv` | | CSV import/export endpoints |
| `auth` | | sessions, login, **TOTP 2FA**, profile/password pages, and the identity-resolving gate presets |
| `sso` | | **OIDC single sign-on** (Google / Okta / corporate) + group mapping (implies `auth`) |

Enable only what you use — an unused feature pulls no dependencies. `auth` works **without** `crud`
(gate any axum app on its own). The always-on `authz` module (the gate trait + `Open`) is compiled in
every build.

**Entity requirements:** derive `Serialize`/`Deserialize` (SeaORM's `with-json`), a **single-column
primary key**, and **single-column to-one FKs** (any URL-safe scalar — int, UUID, slug). N:M junction
tables are never registered.

## CRUD + admin UI in a few lines

```rust
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::authz::Open;                 // per-model gate; Open = ungated

let author = MetaModel::new(author::Entity);      // fully auto: fields, PK, FK relations
let tag    = MetaModel::new(tag::Entity);
let mut post = MetaModel::new(post::Entity);
post.relate(&tag);                                // the only hand-declaration: N:M

let mut crud = Crud::new(db, "/api/v1");          // base path ("" for root)
crud.register(author, Open);
crud.register(post, Open);
crud.register(tag, Open);

let app = crud.into_router();                     // axum::Router — merge into your app
```

That serves `GET/POST /api/v1/{entity}`, `GET/PATCH/DELETE /api/v1/{entity}/{id}`, and bulk
`DELETE /api/v1/{entity}` (search/sort/paginate, relations by name, CSV, structured 422 validation).
Tweak a model before registering — labels, visibility, defaults, validators, hooks:

```rust
post.field("title").label = Some("Title".into());
post.field("views").default = Some(serde_json::json!(0));
post.field("title").validate = Some(Box::new(|v|
    if v.as_str().unwrap_or("").trim().is_empty() { Err("required".into()) } else { Ok(()) }));
```

Admin UI (feature `ui`) — server-rendered Bootstrap 5 + Alpine fragments you drop into your shell:

```rust
let html = relativelylight::crud::ui::Admin::new(crud.engine())
    .title("Admin")
    .entity_with("post", |t| t.per_page(10))
    .entity("tag")
    .render()?;                                   // or .render_for(&headers) to gate write controls
```

`Table` renders one entity (search, pager, create/edit modal, relation pickers, bulk delete, CSV,
custom cell renderers); `Admin` composes many `Table`s behind a side-panel. Full reference:
[docs/CRUD.md → Web admin](docs/CRUD.md#web-admin-ui).

## Auth (feature `auth`)

Sessions + login with an on-demand identity lookup — **no middleware, nothing injected into the
request**:

```rust
use relativelylight::auth::{Auth, UserReadGroupWrite, GroupReadWrite};

let auth = Auth::new(db.clone())
    .admin_group("admin")
    .secure_cookies(true)          // false for local http
    .totp_issuer("My App")         // label authenticator apps show for 2FA
    .login_shell(|form| /* wrap the login fragment in your page */ todo!())
    .profile_shell(|frag, who| /* wrap the profile/2FA fragment; `who` is the caller */ todo!());

let app = axum::Router::new()
    .merge(auth.routes())          // /login, /login/totp, /logout, /profile (+ password & 2FA)
    .merge(engine.router());       // your gated crud API

// A page handler resolves the caller itself — this is the whole of page-level auth:
let who = auth.identify(&headers).await;   // Option<Identity>; None → redirect to auth.login_path()
```

- **Gate presets** (per model, passed to `Crud::register(model, gate)`) name the read/write audience
  (Public → User → Group): `authz::Open` (public R+W, ungated), `UserReadWrite::new(&auth)` (any
  logged-in user R+W), `UserReadGroupWrite::new(&auth, ["editors"])` (logged-in read, group write),
  `PublicReadGroupWrite::new(&auth, ["editors"])` (public read, group write),
  `GroupReadWrite::new(&auth, ["admin"])` (group-only, read *and* write). Or implement `authz::Authz`
  yourself. The engine maps a gate's `Decision` to `200`/`401`/`403`.
- **Profile / password**: `/profile` lets any user change their own password; a manager (a
  profile-manager group, default `[admin_group]`) resets others at `/profile/{id}`.
- **TOTP 2FA**: users enrol from `/profile` (QR + `otpauth://` URL, verify-before-activate); once on,
  login requires the code at `/login/totp`. Self-disable, plus manager disable for others. Expose a
  password column as a hashed, write-only field with `MetaField::password()`.
- **SSO / OIDC** (feature `sso`): `auth::sso::Sso` adds Google / Okta / corporate sign-in
  (`/sso/{provider}/login` + `/callback`). Local groups come from a **union** of a global
  username-regexp table and a per-provider claim table, reconciled onto the user each login. Optional
  per-provider auto-registration; SSO accounts have no local password/2FA. Configure `Auth` **fully
  before** cloning it into `Sso::new(&auth)`.

Full design + wiring: **[docs/AUTH.md](docs/AUTH.md)**.

## Composing with your app — you own the roots

`relativelylight` is always *part of* a larger app:

- **Router** — merge `Crud::into_router()` / `Engine::router()` / `Auth::routes()` into your own
  `Router`. Keep crud under a prefix (`/api/v1`) so its `/{entity}` routes can't shadow yours.
- **Page shell** — `ui::Table`/`Admin` and the auth login/profile pages return **HTML fragments**,
  never full pages. Your app owns the `<html>`, Bootstrap/Alpine `<script>`/`<link>` tags, and layout.
- **OpenAPI** — build your own `OpenApi` (your `info`/`servers`) and fold crud's paths + schemas in
  with `crud::openapi::merge_into(doc, &engine)`.

## Run the examples

```bash
cargo run -p crud-example         # :3000  per-entity pages, CSV, Swagger — open, no auth
cargo run -p adminpanel-example   # :3000  crud::ui::Admin, login-gated, inline accounts + 2FA (admin/password, editor/password)
cargo run -p auth-example         # :3000  auth alone (no crud): login, /secret, /profile + 2FA (admin/password)
cargo run -p time-example         # :3001  timezone picker + server/user-TZ backend hooks (see docs/TIME.md)
```

Run one at a time (fresh seeded in-memory SQLite each start); they print an access-log line per
request. The first three share port 3000, `time-example` uses 3001. The first two put the JSON API
under `/api/v1` with Swagger at `/docs`.

## Documentation

- **[docs/CRUD.md](docs/CRUD.md)** — the full `crud` guide: `MetaModel`/`MetaField`/`MetaRelation`,
  the HTTP API and wire formats, query params, the validation pipeline, metadata, CSV, the web admin,
  OpenAPI, the write-observer audit hook, and composing with your app. (Examples: `crud`, `adminpanel`.)
- **[docs/AUTH.md](docs/AUTH.md)** — the `auth` guide: sessions, login, TOTP 2FA, OIDC SSO, the gate
  presets, profile/password pages, and app-side wiring. (Examples: `auth`, `adminpanel`.)
- **[docs/TIME.md](docs/TIME.md)** — time & timezones: UTC storage/API, the `RLTime` helpers, the
  `$store.tz` selection, and `TzPicker`. (Examples: `time`, `adminpanel`.)
- **[docs/DATAINPUT.md](docs/DATAINPUT.md)** — the `validate` module: typed field validators +
  normalizers (IP/network, ranges, lengths, enums, hostname/FQDN, hex, email/URL), the crud `field`
  adapters, and the `MetaField::validate_str/_int` sugar. Same predicate on CRUD + hand-written APIs.
- **[docs/PRD.md](docs/PRD.md)** — product overview, module status, roadmap.
- **[TODO.md](TODO.md)** — the ordered backlog.

---

## Working *on* the library — keep the docs current

It's a Cargo workspace: the crate lives in `relativelylight/` (`crud/`, `auth/`, `authz.rs`,
`observe.rs`, `time.rs`, front-end assets in `assets/`) with runnable examples in `examples/`. Build
with `cargo build --all-features`, test `cargo test --all-features`, lint `cargo clippy
--all-features`. Deps: SeaORM 1.1, axum 0.8, askama 0.13, utoipa 5, totp-rs 5.7.

**The docs are the source of truth — treat them as part of the change, not an afterthought.** When you
add or change functionality:

- Update the **per-module guide** that owns it (`docs/CRUD.md`, `docs/AUTH.md`, `docs/TIME.md`) — the
  public API, wire formats, and behavior. Keep Rust doc-comments (the in-code contract) consistent too.
- Reflect it in **an example**: extend the closest one, or add a new `examples/*` (and register it in
  the root `Cargo.toml` `members` + link it from the relevant doc's "Examples" note + the README/AGENTS
  example lists). Every user-facing feature should be demonstrated somewhere runnable.
- Adding or promoting a **module/feature**? Update the module table + status in `docs/PRD.md`, add a
  pointer in `README.md` and this file's Documentation list, and move any now-shipped item out of
  `TODO.md` (add new follow-ups there with a one-line rationale).
- `docs/PRD.md` is **requirements + roadmap only** — no usage tutorials (those live in the guides);
  `README.md` is the user's starting point (what it is + pointers); this file is the using-it/working-on
  orientation. Don't duplicate content across them — cross-link instead.
