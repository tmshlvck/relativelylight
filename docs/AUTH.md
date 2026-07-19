# relativelylight — the `auth` module (authn + authz) — DRAFT SPEC

Status: **implemented** (feature `auth`, usable without `crud`): `user`/`session`/`group`/
`user_group` SeaORM models, argon2id hashing, login/logout with an opaque server-side session cookie
(via `axum-extra`'s `CookieJar`; cookie name configurable, default `rl_session`), **on-demand session
resolution** ([`Auth::identify`] → `Option<Identity>`; **no middleware, nothing injected into the
request**), the always-compiled `authz` gate trait + presets (`authz::Open`,
`auth::ValidUsers::new(&auth)`, `auth::UsersReadGroupWrite::new(&auth, [..])`,
`auth::AdminOnly::new(&auth, [..])`), a self-service **profile / password-change page** plus a
manager-only reset for other users (`GET/POST /profile`, `GET/POST /profile/{id}`), **TOTP two-factor
authentication** (login second factor + self-service enrol/disable + manager disable — see §5a),
**OIDC single sign-on** (feature `sso`: Google / Okta / corporate, with username- and claim-based group
mapping and optional auto-registration — see §5b), admin helpers (`migrate`, `create_user`,
`set_password`, `ensure_group`, `add_to_group`, `remove_from_group`, `make_admin`), and
**per-model enforcement in the `crud` HTTP handlers** via `crud::seaorm::Crud::register(model, gate)`,
mapping the gate's `Decision` to 401/403, plus per-request UI control-hiding via
`Admin`/`Table::render_for`. **Not yet:** CSRF/CORS/real-ip/logging middleware, PassKeys/OIDC. The rest
of this doc is the design these grow into.

The login, password-change, and 2FA pages are plain **MPA `<form>` posts** — no JS (the enrolment QR
is a server-rendered inline PNG). The library renders the form fragment (Bootstrap-friendly classes);
the app wraps + styles it via `Auth::login_shell` / `Auth::profile_shell`. General rule: keep security
features as simple as possible.

`auth` is a **feature-gated module** of the `relativelylight` crate — authentication (users,
sessions, login, password hashing) *and* authorization (a small gate trait + presets) together. It's usable **on its own** (enable only `features = ["auth"]` to gate any
axum app), and the `crud` module *optionally* consults it to gate the generated API + admin. It also
keeps the door open for 2FA (TOTP / PassKeys), OIDC SSO, and app-defined API tokens.

**Independence:** `auth` does not require `crud`. When both are enabled, each `crud` handler consults
the model's `relativelylight::auth::Authz` gate, which resolves the identity itself from the request
headers; when `auth` is off, `crud` is ungated (`Open`).

**No middleware.** Authn is not a layer that injects a context — it is a handful of on-demand lookups
on [`Auth`]. Given a request's headers, `Auth::identify` resolves the session cookie → user → groups
(one DB round-trip) and returns an `Option<Identity>`. A gate or a page handler calls it when it needs
to know who's asking; nothing is stored in request extensions. This keeps the whole feature small: no
layer ordering, no state-injection, no `FromRequestParts` magic — just a method you call.

Sibling docs: [docs/CRUD.md](CRUD.md) (the API/UI), [PRD.md](../PRD.md) (roadmap).

## 1. Goals & principles

- **Standalone.** `auth` gates any axum app on its own; `crud` is just one consumer. (authn and authz
  live together — authz is only a trait + a few impls, not worth its own module.)
- **Super simple.** No middleware, no injected context. Authn is `Auth::identify(&headers) ->
  Option<Identity>`; a gate is one async method that returns allow / needs-login / denied. The app
  calls what it needs where it needs it.
- **One identity, everywhere.** The same `Auth::identify` resolves the caller for the `crud` API, the
  admin UI, *and* the app's own handlers — one lookup, one `Identity`.
- **The app owns the roots.** As with the router / shell / OpenAPI (see CRUD.md § Composing with your
  app), auth is applied *by the app* to its router. `auth` provides login routes, the gate trait,
  gate builders, and SeaORM models — the app wires them where it wants, so it can leave `/metrics`
  public, IP-gate an internal API, or bearer-auth its own namespace.
- **Secure by default.** HttpOnly cookies, argon2id hashing, SameSite, sane CORS.
- **Don't shut doors.** The identity is resolved from *pluggable* credential sources; the session
  cookie is the built-in, and Bearer/API-token / OIDC sources slot in later behind the same
  `identify`-style lookup without changing the gate or the app's call sites.

## 2. Layering

There is **no authn/session middleware**. The optional cross-cutting layers (real-ip, logging, CORS,
CSRF — §4/§7) are still `tower`/axum layers the app applies, but *identity resolution is not a layer*:

```
client → [real-ip] → [request logging] → [CORS] → [CSRF for cookie-auth writes] → router
                                          ├─ crud routes       (each handler → model's Authz gate)
                                          ├─ admin UI pages    (handler calls Auth::identify → redirect)
                                          └─ app's own routes  (call Auth::identify, or not)
```

- **authn** is `Auth::identify(&headers) -> Option<Identity>`: resolve the session cookie → user →
  groups on demand (None = anonymous). Nothing is injected into the request.
- **authz** is a per-model `Authz` gate; each `crud` handler consults its model's gate, which resolves
  the identity itself. The same gate builders (and `identify`) are callable from the app's handlers.

Everything lives in `relativelylight::auth`: the `Identity` / `Authz` / `Decision` contract plus the
SeaORM users/sessions + login + hashing. The `crud` module references `auth::Authz` / `auth::Decision`
only when the `auth` feature is enabled (see §9).

## 3. Identity mechanism — DECIDED: server-side session

**Server-side session, carried in an opaque cookie.** A random session id in a
`Set-Cookie: HttpOnly; Secure; SameSite=Strict` cookie, backed by a SeaORM `session` table (user id,
created/expires, and later a 2FA/assurance level + IP/UA).

Comparison for *our* model (a server-rendered admin + same-origin JSON API inside one app):

| | Cookie + server-side session (rec.) | Stateless signed/encrypted cookie | Bearer JWT (Authorization header) |
|---|---|---|---|
| XSS token theft | **Immune** (HttpOnly; JS can't read) | Immune (HttpOnly) | **Exposed** if held in JS/localStorage |
| Revocation (logout, ban, "sign out everywhere", password change) | **Instant** (delete rows) | Hard (needs denylist / short TTL + refresh) | Hard (same) |
| Server state | a `session` table | none | none |
| CSRF | needs SameSite (+ token) | same | none (no ambient cookie) |
| Fits SeaORM-centric admin + 2FA/OIDC later | **Yes** (session row holds assurance level) | partial | partial |
| Best for | our admin + same-origin API | tiny/stateless deployments | SPAs / cross-service APIs |

JWT's wins (stateless, cross-service) don't apply to a single monolith, and its revocation story is
poor — bad for an admin that must be able to disable a user *now*. So the built-in is the cookie
session. **Bearer tokens are still first-class for the app's own API**, and a future API-token source
can resolve the *same* `Identity` — but that's app-issued, not the admin's login session.

Cookie attributes: `HttpOnly`, `Secure` (configurable off for local http), `SameSite=Strict` (or
`Lax` if the app needs top-level cross-site GETs), `Path=/`, a rolling idle timeout + absolute
lifetime.

## 4. Middleware the module provides

All optional, all applied by the app; defaults chosen for "safe but works out of the box".

- **Real client IP** — parse `Forwarded` / `X-Forwarded-For` with a **configurable trusted-proxy**
  list (never trust the header blind). Exposed as a `ClientIp` extractor; used by logging and
  available to the app. Default: trust none (use the socket peer) unless proxies are configured.
- **Request logging** — one structured line per request: method, path, status, latency, client IP,
  and principal (user id / "anon"). Built on `tower_http::trace` or a thin custom layer.
- **CORS** — `tower_http::cors::CorsLayer`. **Open by default** (any origin, credentials off); the
  app narrows to an allow-list of origins (turning credentials on when it does, required for
  cookie-auth cross-origin).
- **CSRF** — see §7.

## 5. authn — users, sessions, login, passwords

SeaORM models (the app runs the migration / `create_table_from_entity`):

- **`user`** — `id`, `username` (unique), `password_hash`, `is_active`, and the TOTP 2FA columns
  `totp_secret` / `totp_pending` (nullable base32; §5a). (An OIDC-subject column can be added later,
  additively.)
- **`group`** + **`user_group`** (N:M) — group membership drives authz.
- **`session`** — `id` (opaque token), `user_id`, `expires_at`, and `awaiting_totp` (a
  half-authenticated session — password ok, second factor pending; §5a).

These are ordinary `crud`-registerable entities (so the admin can manage users/groups), with
`password_hash` marked `write_only` + hashed via `on_write`, and never emitted in reads.

### Database schema & migrations

`auth::migrate(&db)` creates the four tables **if they don't already exist** — a bootstrap for a fresh
DB or the examples, safe to call on every start. It is **not** a migration engine: it only *creates*
missing tables, so it won't add columns when you upgrade the library (e.g. the TOTP / SSO columns on
`rl_user`) or otherwise evolve the schema.

For anything long-lived, drive the schema with **`sea-orm-migration`** — SeaORM's alembic-equivalent:
versioned `up`/`down` migrations, applied once and tracked in a `seaql_migrations` table. Fold the auth
tables into your *initial* migration via `auth::table_create_statements(backend)`, and run the migrator
**embedded in your binary** at startup (no external tool needed; `sea-orm-cli migrate` works too):

```rust
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
struct InitAuth;

#[async_trait::async_trait]
impl MigrationTrait for InitAuth {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        // rl_user / rl_group / rl_user_group / rl_session — from the library entities.
        for stmt in relativelylight::auth::table_create_statements(m.get_database_backend()) {
            m.create_table(stmt).await?;
        }
        // … your own app tables via m.create_table(schema.create_table_from_entity(App::Entity)) …
        Ok(())
    }
    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        for t in ["rl_session", "rl_user_group", "rl_group", "rl_user"] {
            m.drop_table(Table::drop().table(Alias::new(t)).to_owned()).await?;
        }
        Ok(())
    }
}

pub struct Migrator;
#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> { vec![Box::new(InitAuth)] }
}

// at startup — instead of auth::migrate(&db):
Migrator::up(&db, None).await?;
```

`table_create_statements` reflects the auth entities' **current** shape, so it's ideal for the initial
migration; when a later library version adds a column, add your own `ALTER TABLE` migration for it
(the columns each release adds are noted here in §5a/§5b). Add `sea-orm-migration` to your app's
`Cargo.toml` (match your `sea-orm` version).

- **Password hashing:** **argon2id** (via the `argon2` crate) with sane params; verification is
  constant-time. (bcrypt is acceptable but argon2id is the current best default.)
- **Login page:** a server-rendered `username` + `password` form component (askama fragment, like the
  `crud::ui` components) posting to a built-in login handler that verifies the hash, creates a
  `session` row, and sets the cookie. On success → redirect; on failure → re-render with an error.
- **Logout:** deletes the session row + clears the cookie.
- **Password change / profile — implemented.** `Auth::routes()` serves a self-service page at
  `GET/POST /profile` (verify current password → set new hash; any signed-in user changes their own)
  and a manager reset at `GET/POST /profile/{id}` (set another user's password with **no** current
  password). The library renders the `<form>` fragment; the app wraps it via `Auth::profile_shell`
  (like `login_shell`, but also handed the resolved `Identity`, so the app's chrome can show the
  signed-in user). Managing *another* user requires membership in a **profile-manager group**
  (default `[admin_group]`, override with `Auth::profile_managers([..])`); a caller may always manage
  their own, and `/profile/{self}` redirects to `/profile`. `Auth::can_manage_others(&who)` tells the
  app whether to surface an admin-only "reset password" link. The **admin group name is configurable**
  (default `"admin"`).

## 5a. TOTP two-factor authentication — implemented

A second factor (RFC 6238 TOTP, via the `totp-rs` crate) on top of username + password. When a user
has 2FA enabled, a correct password isn't enough — they must also enter the 6-digit code from their
authenticator app. Defaults are the widely-compatible SHA1 / 6 digits / 30s step / ±1 skew.

**Data.** Two nullable base32 columns on `user`: `totp_secret` (the **active** secret — its presence
means 2FA is on) and `totp_pending` (a secret mid-enrolment, not yet confirmed). One flag on
`session`: `awaiting_totp` — a session created after a correct password but before the second factor.
`Auth::identify` treats an `awaiting_totp` session as **anonymous**, so the user is not logged in until
the code is confirmed.

**Login flow.** `POST /login` verifies the password, then:
- no 2FA → create a normal session, redirect `/`.
- 2FA on → create an `awaiting_totp` session (cookie set, but grants nothing), redirect `/login/totp`.
  `GET /login/totp` shows the code form; `POST /login/totp` verifies the code against the pending
  session's user and, on success, clears `awaiting_totp` (the session becomes a real login) → `/`. A
  wrong code → 401, re-render.

**Enrolment (self-service, verify-before-activate).** `GET /profile/totp` mints a fresh secret, stores
it as `totp_pending`, and shows **both** a QR code (a server-rendered inline PNG — no JS) **and** the
`otpauth://…` URL as copyable text. `POST /profile/totp` checks the entered code against the pending
secret; only on success is it promoted to `totp_secret` (2FA now required at login). A wrong code
re-shows the same QR. `Auth::totp_issuer(name)` sets the issuer label authenticator apps display
(default `"relativelylight"`).

**Disable.** `POST /profile/totp/disable` turns off the caller's own 2FA. A **manager** (a
profile-manager group, §5) can disable *another* user's 2FA via `POST /profile/{id}/totp/disable`
(shown on the `/profile/{id}` page) — but managers can never *set up* 2FA for someone else, since
enrolment needs that user's device. Disabling clears both `totp_secret` and `totp_pending`.

The profile page (`GET /profile`) shows a 2FA section reflecting the current state: a "Set up 2FA"
link when off, or a "Disable 2FA" button when on.

## 5b. SSO / OpenID Connect — implemented (feature `sso`)

Sign users in through an external OIDC identity provider — Google, Okta, or any compliant corporate
IdP — via the Authorization Code flow with PKCE. Built on the `openidconnect` crate (discovery, PKCE,
nonce, ID-token signature/aud/iss/exp verification); the QR-free, cookie-carried transaction survives
the round-trip to the provider. Configured at app start; usable alongside password login + 2FA.

**Accounts.** An SSO login resolves to an `rl_user` whose **`sso_provider`** column marks it external.
Such accounts have **no local password and no 2FA** — `verify_credentials` refuses a password login,
and the profile page shows a read-only notice instead of the password / 2FA controls. With a
provider's **auto-registration** on, an unknown user is created on first login; with it off, an admin
must pre-create the user and set its `sso_provider` to the provider key first, else the login is
refused. A local (password) account can't be signed into via SSO, and an account bound to one provider
can't sign in through another.

**Group mapping — union of two tables, reconciled every login.**
- A **global username-pattern table** — `regexp → [groups]` (`Sso::username_group_rule`) — matched
  against the resolved username. This is the fallback for providers with no usable group claim (plain
  Google OIDC), where the email/username is all you have.
- A **per-provider claim table** — `claim-value → [groups]` (`SsoProvider::claim_group_rule` +
  `groups_claim`) — matched against each value of the provider's configured groups claim (Okta / a
  corporate IdP emitting group names).

The login's groups are the **union** of both. On every login the set is **reconciled** onto the user:
groups in the set are added, groups the user has that aren't in the set are removed. So an SSO user's
groups are fully managed by these rules — don't hand-assign groups to an SSO account, they'll be
stripped on next login.

**Routes & config.** `Sso::new(&auth)` (after `auth` is fully configured — see the `Auth` note about
cloning) holds the global rules + providers; `Sso::routes()` serves `GET {base}/{key}/login` (redirect
to the provider) and `GET {base}/{key}/callback` (exchange, verify, map, sign in), default base
`/sso`. `Sso::buttons()` gives `(label, url)` pairs for the login page. Per provider: issuer,
client id/secret, redirect URL, scopes, `username_claim` (default `preferred_username`; Google →
`email`), optional `groups_claim`, the claim table, and `auto_register`.

```rust
use relativelylight::auth::sso::{Sso, SsoProvider};

let sso = Sso::new(&auth)                                   // build auth fully first
    .username_group_rule(r"@example\.com$", ["staff"])     // regexp → groups (Google, no claims)
    .provider(SsoProvider::new("google", "Google",
        "https://accounts.google.com", client_id, client_secret,
        "https://app.example.com/sso/google/callback")
        .username_claim("email").auto_register(true))
    .provider(SsoProvider::new("okta", "Okta",
        "https://corp.okta.com", okta_id, okta_secret,
        "https://app.example.com/sso/okta/callback")
        .groups_claim("groups")                            // claim table drives groups
        .claim_group_rule("eng-admins", ["admin"])
        .claim_group_rule("eng", ["editors"]));
let app = app.merge(sso.routes());
```

> **Verification note.** The login→provider redirect (discovery, PKCE, `state`, `nonce`, the
> transaction cookie) is verified end-to-end against Google's live discovery; the group-mapping and
> reconciliation logic is unit-tested. The **callback** (code exchange + ID-token verification) can't
> be exercised here without real provider credentials + user consent — test it against your own IdP.

## 6. authz — the gate

The gate trait lives in **`relativelylight::authz`** — always compiled, independent of the `auth`
feature, so a model can be registered with a gate (`Open`) even in a build with no auth:

```rust
// relativelylight::authz
pub enum Operation { List, Read, Create, Update, Delete }
pub enum Decision  { Allow, NeedsLogin, Denied }

#[async_trait]
pub trait Authz: Send + Sync {
    async fn authorize(&self, op: Operation, headers: &HeaderMap) -> Decision;
}
pub struct Open;                        // allow everything
impl<T: Authz + ?Sized> Authz for Arc<T> {…}   // so one Arc gate can guard many models

// relativelylight::auth
pub struct Identity { pub id: String, pub username: String, pub groups: Vec<String> }
```

A gate is **attached per model**, so it takes no model argument — instead of one impl branching on a
slug, you hand different models different gates. It's given the request headers and resolves the
identity *itself* (the identity-resolving presets hold an [`Auth`] handle and call
`auth.identify(headers)`), so it can also key off anything else in the request. It returns a
`Decision` the caller renders: the `crud` engine maps `Allow`/`NeedsLogin`/`Denied` →
`200`/`401`/`403`; a page handler serves `NeedsLogin` as a redirect to `Auth::login_path`. (Row-level
checks — per-row read/filter — are a future extension; out of scope for v1.)

**Presets:**
- **`authz::Open`** — everything allowed (no auth); pass it when a model needs no gating.
- **`auth::ValidUsers::new(&auth)`** — any authenticated user may do anything; anonymous → `NeedsLogin`.
- **`auth::UsersReadGroupWrite::new(&auth, ["admin"])`** — any authenticated user may list/read; a
  write needs membership in one of the groups (else `Denied`); anonymous → `NeedsLogin`.
- **`auth::AdminOnly::new(&auth, ["admin"])`** — the stricter sibling: *only* members of one of the
  groups may do anything (read **or** write); anonymous → `NeedsLogin`, any other logged-in user →
  `Denied`. Use it to keep whole models admin-only (e.g. the `rl_user` / `rl_group` tables). Its
  `admits(&Identity)` method is a header-free membership check for deciding admin-only UI.
- **Custom** — implement `authz::Authz` (full RBAC over users/groups, an app's own API tokens, IP
  allow-lists — anything, since you get the headers and can call `auth.identify`).

> The profile page's "manage another user" rule is **not** an `Authz` gate — the header-only trait
> can't see *which* user is targeted. That row-aware self-or-manager check lives in the `/profile/{id}`
> handler (configured by `Auth::profile_managers`), not in a model gate.

**Configuration — one gate per model, at registration.** `Crud::register(model, gate)` takes the gate
alongside the model. Pass `Open` for an ungated model, a preset, or a shared `Arc<dyn Authz>` (it
implements `Authz`, so the same instance can guard several models). There is no separate default — the
gate is always explicit at the call site.

**Enforcement:** each `crud` handler consults its model's gate *before* touching the engine, passing
the request headers → the gate resolves the identity and returns a `Decision` → **401** (`NeedsLogin`)
/ **403** (`Denied`) / proceed (`Allow`). The admin UI reads the *same* per-model gate: `Admin`/`Table`
have an async `render_for(&headers)` that hides a model's Create/Edit/Delete controls when its gate
denies a write for the caller (the API remains the actual enforcement point).

### App-side API (the whole picture)

What the app writes to wire it all up — the library gives login routes, the gate trait, gate
builders, and on-demand `identify`; the app composes them (it still owns the router):

```rust
use relativelylight::auth::{Auth, UsersReadGroupWrite};
use relativelylight::authz::Open;
use relativelylight::crud::seaorm::Crud;
use std::sync::Arc;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

// 1. authn: SeaORM-backed sessions + login/logout/password. Cheap to clone (Arc inside).
let auth = Auth::new(db.clone())
    .admin_group("admin")        // group that may reset others' passwords (configurable)
    .secure_cookies(true);       // false for local http

// 2. crud: each model registered with its gate. Share one gate via Arc, or vary per model.
let content = Arc::new(UsersReadGroupWrite::new(&auth, ["editors", "admin"]));
let mut crud = Crud::new(db, "/api/v1");
crud.register(post_mm, content.clone());                          // logged-in read, group write
crud.register(user_mm, UsersReadGroupWrite::new(&auth, ["admin"])); // admins only, for this model
crud.register(healthcheck_mm, Open);                              // ungated

// 3. compose — the app owns the root router. No middleware, no wrapping.
let engine = Arc::new(crud.into_engine());
let app = axum::Router::new()
    .merge(auth.routes())              // GET/POST /login, /logout, (/password …)
    .route("/", get(admin_page))       // the app's own (gated) pages/handlers
    .merge(engine.clone().router());   // the gated JSON API

// The app's own page resolves the caller on demand — this is the whole of page-level auth:
async fn admin_page(headers: HeaderMap, State(app): State<AppState>) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    // Render the admin *for this caller* — write controls hide where the gate denies a write:
    let body = build_admin(&app.engine).render_for(&headers).await.unwrap_or_default();
    // …wrap `body` (and use who.username / who.in_group("admin") …) in your shell
    todo!()
}
```

`auth.routes()` are the login/logout/password endpoints. Anything the app wants to leave open (e.g.
`/metrics`) simply never calls `identify`.

## 7. CSRF — DECIDED: always-on double-submit token

Cookie-authenticated **unsafe** requests (POST/PATCH/DELETE) must carry a CSRF token, validated
against a cookie-bound value (double-submit). This is defense-in-depth on top of SameSite=Strict:

- A `csrf` cookie (readable by JS — *not* HttpOnly) is issued alongside the session; unsafe requests
  must echo it in an `X-CSRF-Token` header (or `_csrf` form field). The server compares the two.
- The `crud::ui` admin's `fetch` calls add the header automatically (the token is embedded in the
  rendered fragment); a helper embeds it in server-rendered forms (login, password change).
- **Bearer-authenticated requests are exempt** (no ambient cookie → no CSRF vector), so the app's
  token-based API isn't burdened.
- Safe methods (GET/HEAD) and unauthenticated requests need no token.

So `Table`/`Admin` and the login/password forms work out of the box; an app writing its own
cookie-authenticated client just reads the `csrf` cookie and sets the header.

## 8. Future-proofing (not in v1, but designed for)

- **TOTP 2FA — done (§5a).** Implemented as an `awaiting_totp` session flag + `totp_secret` on the
  user. **PassKeys/WebAuthn** would slot in similarly (a session assurance level a policy can require
  for sensitive models).
- **OIDC SSO — done (§5b, feature `sso`).** The callback creates a `session` for the mapped user —
  the same session model. Group memberships come from the username/claim mapping tables.
- **App API tokens:** the app issues tokens and adds an **identity source** that maps a Bearer token →
  `Identity` (a gate that checks the header instead of the cookie); the gate contract and all call
  sites are unchanged. The built-in session source ships; token sources are app- or future-provided.

## 9. Module / feature layout

`auth` is a **module of the `relativelylight` crate**, gated by the **`auth`** feature — usable
without `crud`:

- **`auth`** — `Identity`, on-demand `Auth::identify`, the gate presets (`ValidUsers`,
  `UsersReadGroupWrite`, which impl `authz::Authz`), the SeaORM `user`/`group`/`session` models,
  argon2id hashing, the session cookie, and login/logout/password-change routes + components. (The
  gate trait itself — `Authz`/`Operation`/`Decision`/`Open` — lives in the always-on `authz` module.
  The cross-cutting layers — real-ip · logging · CORS · CSRF — are still planned; identity itself is
  *not* a layer.) Pulls `sea-orm`, `argon2`, a cookie lib, `rand`, `time`; shares `axum` +
  `async-trait` with the crud engine.
- The **`authz`** module (the `Authz` trait, `Operation`, `Decision`, `Open`) is **always compiled**
  (it only needs `http` + `async-trait`), so `Crud::register(model, gate)` takes a gate in every
  build — pass `Open` when nothing needs gating. The identity-resolving presets live in `auth`.
- The **`sso`** feature (implies `auth`) adds `auth::sso` — the OIDC relying-party + group mapping
  (§5b). Pulls `openidconnect` (async `reqwest` + rustls), `regex`, and `base64`.

Usage: `relativelylight = { features = ["auth"] }` for auth-only (no CRUD deps);
`features = ["crud", "auth"]` for a gated CRUD API + admin; add `"sso"` for OIDC single sign-on.

## 10. Examples

- **`examples/auth`** — uses **`auth` alone (no `crud`)** to prove it stands on its own: a login
  page, a session cookie, and a `/secret` page gated by an on-demand `auth.identify(&headers)` check
  (redirect to `login_path` when anonymous). The `/secret` page shows the signed-in user and links to
  the self-service **`/profile`** page — password change **and TOTP 2FA** enrolment/disable — wrapped
  in the app's chrome via `profile_shell`, plus the `--set-admin-pw` startup path. **SSO** is wired in
  (feature `sso`) and enabled by setting `SSO_GOOGLE_CLIENT_ID` / `SSO_GOOGLE_CLIENT_SECRET` in the
  env: a "Sign in with Google" button appears and `/sso/google/*` is served (username→group rule for
  `@example.com`, auto-register on).
- **`examples/adminpanel`** — **login-gated** `crud::ui::Admin`: the page calls
  `auth.identify(&headers)` (→ redirect to `/login` when anonymous), the content models are registered
  with a shared `UsersReadGroupWrite::new(&auth, ["admin"])` gate (any logged-in user reads; the admin
  group writes), and the panel is rendered per request with `render_for` so write controls hide for
  non-writers. The navbar shows the signed-in user, linking to **`/profile`** (self password change).
  The auth **`rl_user` / `rl_group`** tables are also surfaced — gated `AdminOnly::new(&auth, ["admin"])`
  (admin-only, read included) and shown only to managers. Accounts are **created/edited inline**: one
  `user.field("password_hash").password()` call (the `MetaField::password()` helper, see CRUD.md)
  exposes it as a write-only **Password** field (masked input) whose plaintext is argon2-hashed on
  write and never returned in reads; an **empty password is allowed** and stored as an empty hash, so
  password login is simply disabled (a future SSO / PassKey account). New
  accounts default `is_active = true`, and each user id also links to `/profile/{id}` for a dedicated
  reset. Two logins: `admin` (read-write, manager) and `editor` (read-only). Verified end-to-end:
  anonymous → 303; `admin` → reads + writes, creates accounts with/without a password, resets
  `editor`'s password via `/profile/2`; `editor` → read-only panel with no Accounts section, own
  `/profile` works, `/profile/1` and the `rl_user` API both 403. Empty-password accounts cannot log in
  with any password (`verify_password` fails against the empty hash). **TOTP 2FA** verified
  end-to-end: enrol (QR + otpauth URL, wrong code rejected, correct code activates); login then
  requires the second factor (`/login/totp`, awaiting session can't reach `/profile`); self-disable
  and admin-disable-for-`editor` both work; a non-manager gets 403 disabling someone else's.
- **`examples/crud`** — the ungated counterpart (`Open`), so there's a no-login demo.

All three examples print an **access log** line per request (source IP · method · URI · HTTP status)
via a small `axum::middleware::from_fn` layer + `into_make_service_with_connect_info`.

> **Note — UI vs API enforcement.** The adminpanel renders the panel *per request* via
> `Admin::render_for(&headers)`, which hides each model's Create/Edit/Delete controls when its gate
> denies a write for the caller — so the `editor` login gets a read-only panel. The **API gate stays
> the actual enforcement point**: hiding a button is cosmetic; an unauthorized write is rejected there
> (403) regardless.

## 11. Decisions (confirmed)

1. **Packaging** — ✅ a **feature-gated `auth` module** in the single `relativelylight` crate (authn +
   authz together). Usable without `crud`; `crud` optionally consults it.
2. **Identity** — ✅ cookie + **server-side session** (SeaORM `session` table).
3. **CSRF** — ✅ **always-on double-submit token** for cookie-authenticated unsafe requests; Bearer
   requests exempt.
4. **authz config** — ✅ **one gate per model, explicit at registration**: `Crud::register(model,
   gate)`. Each gate is attached per model (no slug arg), is handed the request headers, and resolves
   the identity itself → a `Decision`. The trait lives in the always-on `authz` module (`Open` for
   ungated). **No middleware**: authn is on-demand `Auth::identify(&headers)`.
5. **Defaults** — ✅ hashing **argon2id**, admin group **`"admin"`** (configurable); presets
   `authz::Open` / `ValidUsers::new(&auth)` / `UsersReadGroupWrite::new(&auth, [..])` /
   `AdminOnly::new(&auth, [..])` / custom.
6. **2FA** — ✅ **TOTP** (RFC 6238) as a login second factor with self-service enrolment/disable and
   manager disable (§5a); PassKeys/WebAuthn remain future.
7. **SSO** — ✅ **OIDC** (feature `sso`) for Google / Okta / corporate, with username- and claim-based
   group mapping (union + reconcile) and optional per-provider auto-registration (§5b).

## 12. Open (later)

- Row-level authorization (per-row read checks / list filters — the gate seeing the row/query).
- PassKeys/WebAuthn, app-issued API tokens (extra principal source) — §8.
- Session store scaling (shared store) if the app runs multiple instances.
- Security hardening — login attempt rate-limiting/lockout, CSRF, TOTP recovery codes, re-auth before
  sensitive changes (see `TODO.md`). SSO: cache provider discovery instead of per-request.
