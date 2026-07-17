# relativelylight — the `auth` module (authn + authz) — DRAFT SPEC

Status: **first slice implemented** (feature `auth`, usable without `crud`): `user`/`session`/`group`/
`user_group` SeaORM models, argon2id hashing, login/logout with an opaque server-side session cookie
(via `axum-extra`'s `CookieJar`; cookie name configurable, default `rl_session`), a session-resolving
middleware ([`Auth::wrap`]), the [`CurrentUser`] extractor, the [`Authz`] trait + presets
(`Open`/`ValidUsers`/`UsersReadGroupWrite`), admin helpers (`migrate`, `create_user`, `set_password`,
`ensure_group`, `add_to_group`, `make_admin`), and **enforcement in the `crud` HTTP handlers** via
`crud::seaorm::Crud::authz` (401/403). **Not yet:** password-change UI, CSRF/CORS/real-ip/logging
middleware, 2FA/OIDC. The rest of this doc is the design these grow into.

The login (and later password-change) pages are plain **MPA `<form>` posts** — no JS. The library
renders the form fragment (Bootstrap-friendly classes); the app wraps + styles it via
`Auth::login_shell`. General rule: keep security features as simple as possible.

`auth` is a **feature-gated module** of the `relativelylight` crate — authentication (users,
sessions, login, password hashing) *and* authorization (a small gate trait + presets) together. It's usable **on its own** (enable only `features = ["auth"]` to gate any
axum app), and the `crud` module *optionally* consults it to gate the generated API + admin. It also
keeps the door open for 2FA (TOTP / PassKeys), OIDC SSO, and app-defined API tokens.

**Independence:** `auth` does not require `crud`. When both are enabled, `crud`'s handlers read
`relativelylight::auth::Principal` from the request and consult `relativelylight::auth::Authz`; when
`auth` is off, `crud` is ungated (`Open`).

Sibling docs: [docs/CRUD.md](CRUD.md) (the API/UI), [PRD.md](../PRD.md) (roadmap).

## 1. Goals & principles

- **Standalone.** `auth` gates any axum app on its own; `crud` is just one consumer. (authn and authz
  live together — authz is only a trait + a few impls, not worth its own module.)
- **One identity, everywhere.** The same authenticated principal gates the `crud` API, the admin UI,
  *and* the app's own handlers — via one extractor + one authorization trait.
- **The app owns the roots.** As with the router / shell / OpenAPI (see CRUD.md § Composing with your
  app), auth is applied *by the app* to its router. `auth` provides middleware layers, extractors,
  login routes, the gate trait, and SeaORM models — the app wires them where it wants, so it can
  leave `/metrics` public, IP-gate an internal API, or bearer-auth its own namespace.
- **Secure by default.** HttpOnly cookies, argon2id hashing, SameSite, sane CORS.
- **Don't shut doors.** The principal is resolved from *pluggable* credential sources; the session
  cookie is the built-in, and Bearer/API-token / OIDC sources slot in later without changing the gate
  or the app's call sites.

## 2. Layering

Request path (outermost → innermost), all as `tower`/axum layers the app applies:

```
client → [real-ip] → [request logging] → [CORS] → [session] → [authn: resolve Principal]
       → [CSRF for cookie-auth writes] → router
                                          ├─ crud routes       (gated by Authz)
                                          ├─ admin UI pages    (gated by Authz / login redirect)
                                          └─ app's own routes  (use CurrentUser + Authz, or not)
```

- **authn** puts an `Option<Principal>` into request extensions (None = anonymous).
- **authz** is consulted per (operation, model) inside the `crud` handlers, and is callable from the
  app's own handlers.

Everything lives in `relativelylight::auth`: the `Principal` / `Authz` contract plus the SeaORM
users/sessions + login + hashing + middleware. The `crud` module references `auth::Principal` /
`auth::Authz` only when the `auth` feature is enabled (see §9).

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
can resolve the *same* `Principal` — but that's app-issued, not the admin's login session.

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

- **`user`** — `id`, `username` (unique), `password_hash`, `is_active`, timestamps. (2FA columns and
  OIDC-subject added later, additively.)
- **`group`** + **`user_group`** (N:M) — group membership drives authz.
- **`session`** — `id` (opaque token), `user_id`, `created_at`, `expires_at` (+ later assurance
  level, ip, user_agent).

These are ordinary `crud`-registerable entities (so the admin can manage users/groups), with
`password_hash` marked `write_only` + hashed via `on_write`, and never emitted in reads.

- **Password hashing:** **argon2id** (via the `argon2` crate) with sane params; verification is
  constant-time. (bcrypt is acceptable but argon2id is the current best default.)
- **Login page:** a server-rendered `username` + `password` form component (askama fragment, like the
  `crud::ui` components) posting to a built-in login handler that verifies the hash, creates a
  `session` row, and sets the cookie. On success → redirect; on failure → re-render with an error.
- **Logout:** deletes the session row + clears the cookie.
- **Password change:** a self-service component (verify current password → set new hash), easy to
  link from the app shell so any signed-in user can change their own password. When rendered for an
  **admin-group** user it can target *another* user (reset without the current password), so admins
  can change anyone's password. The **admin group name is configurable** (default `"admin"`).

## 6. authz — the gate

```rust
pub struct Principal {
    pub id: String,             // user pk, stringified
    pub username: String,
    pub groups: Vec<String>,
    // extensible: assurance level (2FA), token scopes, … added additively
}

pub enum WriteOp { Create, Update, Delete }

pub trait Authz: Send + Sync {
    fn can_list (&self, who: Option<&Principal>, model: &str) -> bool;
    fn can_read (&self, who: Option<&Principal>, model: &str) -> bool;
    fn can_write(&self, who: Option<&Principal>, model: &str, op: WriteOp) -> bool;
}
```

`who = None` is anonymous (so an `Open` preset can allow it). `model` is the slug, so a single impl
can branch per model. (Row-level checks — `can_read(row)`, row filters — are a future extension of
this trait; out of scope for v1.)

**Presets** (a handful of impls; names provisional):
- **`Open`** — everything allowed (no auth); the default when no gate is set.
- **`ValidUsers`** — any authenticated principal may do anything; anonymous denied.
- **`UsersReadGroupWrite { write_groups }`** — any authenticated principal may list/read; write
  requires membership in one of `write_groups`.
- **Custom** — implement `Authz` (this is where an app builds full RBAC over the users/groups, or
  authorizes its own API tokens).

**Configuration — one shared gate for all models.** The gate is an `Arc<dyn Authz>` handed to the
`crud` engine; because every method receives the model slug, one impl can still branch per model when
it needs to. There is no separate per-model registration in v1 — a single instance keeps the app-side
API tiny and lets the app share the *same* gate with its own handlers. (Default when `.authz(..)` is
never called: `Open`.)

**Enforcement:** each `crud` handler extracts `Option<Principal>` from request extensions and
consults the gate before touching the engine → **401** if the op needs a principal and none is
present, **403** if present but not permitted. The app's own handlers call the same gate (or the
`CurrentUser` extractor) for consistent rules.

### App-side API (the whole picture)

What the app writes to wire it all up — the library gives layers, routes, an extractor, and a gate;
the app composes them (it still owns the router):

```rust
use relativelylight::auth::{Auth, Authz, CurrentUser, UsersReadGroupWrite};
use relativelylight::crud::seaorm::Crud;
use std::sync::Arc;

// 1. authn: SeaORM-backed sessions + login/logout/password + the middleware stack.
let auth = Auth::new(db.clone())
    .admin_group("admin")        // group that may reset others' passwords (configurable)
    .secure_cookies(true)        // false for local http
    .trusted_proxies(["10.0.0.0/8".parse()?]); // for real-client-ip behind a proxy

// 2. authz: one gate, shared by crud and the app's own handlers.
let gate: Arc<dyn Authz> = Arc::new(UsersReadGroupWrite {
    write_groups: vec!["editors".into(), "admin".into()],
});

// 3. crud, gated by the shared gate.
let crud = Crud::new(db, "/api/v1").authz(gate.clone());

// 4. compose — the app owns the root router.
let app = axum::Router::new()
    .merge(auth.routes())              // GET/POST /login, /logout, (/password …)
    .route("/", get(admin_page))       // the app's own (gated) pages/handlers
    .merge(crud.into_router());        // the gated JSON API
let app = auth.wrap(app);              // session → Principal (later: real-ip · logging · CORS · CSRF)

// The app's own handler uses the same identity + gate:
async fn my_handler(user: CurrentUser, State(gate): State<Arc<dyn Authz>>) -> impl IntoResponse {
    if !gate.can_read(Some(&user.principal()), "report") { /* 403 */ }
    // …
}
```

`auth.layer()` is the composed middleware from §2/§4 (each piece individually configurable);
`auth.routes()` are the login/logout/password endpoints; `CurrentUser` is the extractor backed by the
session the layer resolved. Anything the app wants to leave open (e.g. `/metrics`) is simply not
gated — it just doesn't call the gate.

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

- **2FA (TOTP, PassKeys/WebAuthn):** the `session` row carries an assurance level; a second-factor
  step upgrades it; `Authz` impls (or a policy) can require a level for sensitive models.
- **OIDC SSO:** a callback creates a `session` for the mapped user — same session model.
- **App API tokens:** the app issues tokens and adds a **principal source** that maps a Bearer token →
  `Principal`; the gate and all call sites are unchanged. The built-in session source ships; token
  sources are app- or future-provided.

## 9. Module / feature layout

`auth` is a **module of the `relativelylight` crate**, gated by the **`auth`** feature — usable
without `crud`:

- **`auth`** — `Principal`, `WriteOp`, `Authz` + presets (`Open`, `ValidUsers`,
  `UsersReadGroupWrite`, …), the SeaORM `user`/`group`/`session` models, argon2id hashing, the session
  cookie, the middleware stack (session · real-ip · logging · CORS · CSRF), the `CurrentUser`
  extractor, and login/logout/password-change routes + components. Pulls `sea-orm`, `argon2`,
  `tower-http`, a cookie lib, `rand`, `time` (+ an XFF parser or `axum-client-ip`); shares `axum` with
  the router.
- The **`crud` gating glue** (`Crud::authz`, reading `Principal` in handlers) compiles only when both
  `crud` and `auth` are enabled. With `crud` but not `auth`, `crud` is `Open` (unchanged).

Usage: `relativelylight = { features = ["auth"] }` for auth-only (no CRUD deps);
`features = ["crud", "auth"]` for a gated CRUD API + admin.

## 10. Example: `examples/auth`

Deliberately uses **`auth` alone — no `crud`** — to prove it stands on its own. A playground that
grows with the implementation. **Now:** a public page + a page to be gated (stub, ungated).
**Next (with `auth`):** a login page, a session cookie, and the "secret" page gated by `ValidUsers`;
then self-service password change. Gating a `crud` API with the same `auth` is shown by adding a gate
to the `crud`/`adminpanel` examples.

## 11. Decisions (confirmed)

1. **Packaging** — ✅ a **feature-gated `auth` module** in the single `relativelylight` crate (authn +
   authz together). Usable without `crud`; `crud` optionally consults it.
2. **Identity** — ✅ cookie + **server-side session** (SeaORM `session` table).
3. **CSRF** — ✅ **always-on double-submit token** for cookie-authenticated unsafe requests; Bearer
   requests exempt.
4. **authz config** — ✅ **one shared `Arc<dyn Authz>` for all models** (the impl gets the model slug
   and may branch); no per-model registration in v1.
5. **Defaults** — ✅ hashing **argon2id**, admin group **`"admin"`** (configurable); presets `Open` /
   `ValidUsers` / `UsersReadGroupWrite` / custom.

## 12. Open (later)

- Row-level authorization (`can_read(row)` / list filters).
- 2FA (TOTP, PassKeys), OIDC SSO, app-issued API tokens (extra principal source) — §8.
- Session store scaling (shared store) if the app runs multiple instances.
