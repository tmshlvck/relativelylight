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
| `csrf` | | the **double-submit CSRF token** (`csrf` module) — always on for `auth`'s forms, opt-in for the API; implied by `auth` |
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
  profile-manager group, default `[admin_group]`) resets others at `/profile/{id}`. Both screen the new
  password against a **`validate::PasswordPolicy`** — on by default at `recommended()` (≥ 12 chars,
  common-value + pattern + username screening, **no** composition rules, per NIST SP 800-63B). Opt out
  with `Auth::password_policy(None)` / another preset / `from_level(n)`, or replace it with
  `Auth::password_check(closure)`. It governs **typed input only** — `create_user`/`set_password`/
  `make_admin` are exempt, so a seeder or break-glass CLI still works. Wire the *same* policy into the
  admin form separately (`field("password_hash").validate_str(validate::optional(Box::new(
  validate::password(policy))))`) or that surface becomes the way around it — `examples/adminpanel`
  drives both from one `PASSWORD_LEVEL` value. See [docs/AUTH.md §5g](docs/AUTH.md).
- **TOTP 2FA**: users enrol from `/profile` (QR + `otpauth://` URL, verify-before-activate); once on,
  login requires the code at `/login/totp`. Self-disable, plus manager disable for others. A code is
  single-use (`auth_user.totp_last_step` records the step it spent — RFC 6238 §5.2; hide the column in an
  admin panel). Expose a
  password column as a hashed, write-only field with `MetaField::password()`.
- **Recovery codes** (`auth::recovery`, `docs/AUTH.md` §5i): ten single-use codes issued **with** the 2FA
  enrolment and shown once; spent in the `recovery_code` field at `/login/totp` (which then lands on
  `/profile`); regenerable there under re-auth; destroyed when 2FA is turned off. Hashed with **SHA-256,
  not argon2** — they're machine-generated high-entropy secrets, so a slow hash buys nothing and would put
  ten verifications on the unauthenticated login path. Table `auth_totp_recovery`; **don't** register it in
  an admin panel (every row is a credential hash).
- **Lockout** (`auth::lockout`): the **unauthenticated** credential checks (`POST /login`, `POST
  /login/totp`) are braked by two DB-backed counters — by account name and by source address —
  configured *mandatorily* on `Auth::new(db, Lockout { .. })`. Authenticated checks (`/profile`
  password, 2FA enrolment) are deliberately **not** limited: that's session theft, not brute force.
  An app that checks credentials itself must use the same counters, not a second limiter —
  `auth.username_lockout()` / `auth.ip_lockout()` (`locked` / `record_failure` / `clear`), so one
  account has one budget everywhere. The unlock is **deleting the row** in the admin panel (register
  `lockout::username_entity` / `ip_entity`), which is gated, CSRF-checked and audited for free.
  The per-address half resolves the client with `net::client_ip(trust_proxy, ..)` — `Lockout::trust_proxy`
  picks socket peer vs the **right-most** `X-Forwarded-For` hop (the one your proxy appended; the entries
  left of it are caller-supplied), and an app should call the same function for its logs
  and audit rows so one client is one key (`Auth::client_ip(closure)` overrides for CDN/multi-hop).
  One trusted hop is the **final** design — no CIDR list, no RFC 7239.
  `Lockout::ip_whitelist` (CIDRs via `net::parse_nets`) exempts addresses from locking on every surface;
  there is no username equivalent by design. Pruning
  expired rows — and dead sessions — is `auth.prune()`, which **the app schedules**;
  the crate spawns no tasks. Worked examples: `examples/auth`'s `GET /api/whoami` + prune loop,
  `examples/adminpanel`'s lockout panels.
- **Re-auth before sensitive changes** (`docs/AUTH.md` §5h): disabling 2FA, enrolling 2FA, a manager's
  password reset and a manager's 2FA disable all require a **password or a fresh TOTP code** in the same
  request (a code is spent when used). A live session isn't evidence its owner is present. Gate your own
  sensitive routes the same way with `auth.reauthenticate(&who, pw, code)` — `examples/auth`'s
  `POST /api-token/rotate` is the worked pattern. Accounts with no local factor (SSO) pass unchallenged;
  `Auth::can_reauthenticate` reports that.
- **Sessions** (`docs/AUTH.md` §5f): two clocks — `session_ttl_secs` (absolute, 7 days) and
  `session_idle_secs` (idle, 8 hours; `0` disables), both enforced by `identify`, the idle stamp
  refreshed lazily so a read stays a read. The session id **rotates** when the second factor completes
  (a planted half-authenticated cookie can't be elevated), a **password change or manager reset revokes
  the user's other sessions**, and `/profile` carries a "Sign out other sessions" button
  (`Auth::revoke_sessions` / `revoke_other_sessions` for your own code).
- **CSRF**: every form `auth` renders carries a hidden `_csrf` token checked on POST; turn it on for the
  JSON API with `crud.csrf(auth.csrf())` (the admin UI's `fetch` writes then send `X-CSRF-Token`
  automatically). `Authorization`-bearing requests are exempt. See [docs/AUTH.md §7](docs/AUTH.md).
- **SSO / OIDC** (feature `sso`): `auth::sso::Sso` adds Google / Okta / corporate sign-in
  (`/sso/{provider}/login` + `/callback`). Local groups come from a **union** of a global
  username-regexp table and a per-provider claim table, reconciled onto the user each login. Optional
  per-provider auto-registration; SSO accounts have no local password/2FA — and no local *reset* either,
  self-service or manager. Configure `Auth` **fully before** cloning it into `Sso::new(&auth)`.
  The username claim is matched **case-insensitively** (a provider that changes case must not acquire a
  second account); a **disabled** account is refused, as on the password door; provider discovery is cached
  for an hour. The callback's rejection paths are tested against a **fake IdP** (`auth/sso_tests.rs`) — a
  live provider can't be asked for an expired token or one signed by the wrong key.

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
cargo run -p auth-example         # :3000  auth alone (no crud): login, /secret, /profile + 2FA, re-auth demo (admin/password)
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
- **[CHANGELOG.md](CHANGELOG.md)** — per-release notes; land user-visible changes under `## Unreleased`
  as you make them (breaking changes first, with the upgrade step), so a release is a rename + a tag.

---

## Working *on* the library — keep the docs current

It's a Cargo workspace: the crate lives in `relativelylight/` (`crud/`, `auth/`, `authz.rs`,
`observe.rs`, `time.rs`, front-end assets in `assets/`) with runnable examples in `examples/`. Build
with `cargo build --all-features`, test `cargo test --all-features`, lint `cargo clippy
--all-features`. Deps: SeaORM 1.1, axum 0.8, askama 0.13, utoipa 5, totp-rs 5.7.

**Security behavior is tested by rejection.** `auth/security_tests.rs` and `crud/gate_tests.rs` drive
the real routers over in-memory SQLite and assert the *negative* cases — bad password, bogus/expired/
half-authenticated session, wrong TOTP code, non-manager profile writes, each gate preset's decision,
and that a denied request never reaches the backend. Touching login, sessions, 2FA, the profile pages,
or a gate means extending them (with a positive control, so the negatives can't pass vacuously); see
[docs/AUTH.md §10a](docs/AUTH.md) for what they cover and what they deliberately don't.

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
- Anything a **user would notice** (new API, changed default, fixed bug, breaking behaviour) gets an
  entry in `CHANGELOG.md` under `## Unreleased` **in the same change** — breaking items first, each with
  the concrete upgrade step. Releasing is then: rename that heading to `## [x.y.z] — YYYY-MM-DD`, add its
  compare link, bump `relativelylight/Cargo.toml`, commit `Release vx.y.z`, tag, push the tag. A
  behaviour break bumps the **minor** while we're pre-1.0 (Cargo treats `0.1.x` as one compatible range).
- `docs/PRD.md` is **requirements + roadmap only** — no usage tutorials (those live in the guides);
  `README.md` is the user's starting point (what it is + pointers); this file is the using-it/working-on
  orientation. Don't duplicate content across them — cross-link instead.
