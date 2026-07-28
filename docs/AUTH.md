# relativelylight — the `auth` module (authn + authz) — DRAFT SPEC

Status: **implemented** (feature `auth`, usable without `crud`): `user`/`session`/`group`/
`user_group` SeaORM models, argon2id hashing, login/logout with an opaque server-side session cookie
(via `axum-extra`'s `CookieJar`; cookie name configurable, default `rl_session`), **on-demand session
resolution** ([`Auth::identify`] → `Option<Identity>`; **no middleware, nothing injected into the
request**), the always-compiled `authz` gate trait + presets (`authz::Open`,
`auth::UserReadWrite::new(&auth)`, `auth::UserReadGroupWrite::new(&auth, [..])`,
`auth::GroupReadWrite::new(&auth, [..])`), a self-service **profile / password-change page** plus a
manager-only reset for other users (`GET/POST /profile`, `GET/POST /profile/{id}`), **TOTP two-factor
authentication** (login second factor + self-service enrol/disable + manager disable — see §5a),
**OIDC single sign-on** (feature `sso`: Google / Okta / corporate, with username- and claim-based group
mapping and optional auto-registration — see §5b), admin helpers (`migrate`, `create_user`,
`set_password`, `ensure_group`, `add_to_group`, `remove_from_group`, `make_admin`,
`reset_admin_access`), and **per-model enforcement in the `crud` HTTP handlers** via
`crud::seaorm::Crud::register(model, gate)` — mapping the gate's `Decision` to 401/403, plus
per-request UI control-hiding via `Admin`/`Table::render_for` — **double-submit CSRF protection**
(feature `csrf`, §7: always on for the module's own forms, `Crud::csrf` for the API), and
**lockout** on the unauthenticated credential checks (§5e: two DB-backed counters, by account name and
by source address, shared with the app's own credential checks and cleared by deleting a row in the
admin panel). **Not yet:** the
CORS/logging middleware (client-IP resolution is shipped as `net::client_ip` — §4), PassKeys. The rest of this doc is the design these grow into.

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

Sibling docs: [docs/CRUD.md](CRUD.md) (the API/UI), [PRD.md](PRD.md) (roadmap).

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

- **Real client IP** — **shipped** as [`relativelylight::net::client_ip`](../relativelylight/src/net.rs):
  a `trust_proxy` flag selects the socket peer or the **right-most** `X-Forwarded-For` hop (falling back
  to `X-Real-IP`), IPv4-mapped addresses collapse to IPv4, and `auth`'s lockout uses it (§5e). The
  boolean is **final**: a trusted-proxy CIDR list and RFC 7239 `Forwarded` parsing were both considered
  and rejected — one trusted hop is exactly what a firewalled port behind nginx/Caddy or a cluster
  ingress is, and anything stranger (a CDN ahead of your own proxy, `CF-Connecting-IP`) overrides the
  resolution wholesale with `Auth::client_ip` rather than describing a chain in config. Still wanted: a
  `ClientIp` extractor / layer so an app doesn't thread `(headers, peer)` by hand.
- **Request logging** — one structured line per request: method, path, status, latency, client IP,
  and principal (user id / "anon"). Built on `tower_http::trace` or a thin custom layer.
- **CORS** — `tower_http::cors::CorsLayer`. **Open by default** (any origin, credentials off); the
  app narrows to an allow-list of origins (turning credentials on when it does, required for
  cookie-auth cross-origin).
- **CSRF** — see §7.
- **Lockout** — not a layer: the unauthenticated login handlers brake themselves, see §5e.

## 5. authn — users, sessions, login, passwords

SeaORM models (the app runs the migration / `create_table_from_entity`):

- **`user`** — `id`, `username` (unique), `password_hash`, `is_active`, and the TOTP 2FA columns
  `totp_secret` / `totp_pending` (nullable base32) + `totp_last_step` (the replay guard; §5a). (An
  OIDC-subject column can be added later,
  additively.) `username` is validated at every creation path (`create_user`, and the SSO
  auto-register path) by `auth::valid_username` — non-empty, ≤ 254 bytes, no spaces/control chars
  (permissive enough for email-style names). Wire the same check into the admin form:
  `user_mm.field("username").validate_str(relativelylight::auth::valid_username)`. Group names get
  `auth::valid_group_name` (via `ensure_group`).
- **`group`** + **`user_group`** (N:M) — group membership drives authz.
- **`session`** — `id` (opaque token), `user_id`, `expires_at` (the **absolute** deadline),
  `last_seen_at` (the **idle** clock; §5f), and `awaiting_totp` (a
  half-authenticated session — password ok, second factor pending; §5a).

These are ordinary `crud`-registerable entities (so the admin can manage users/groups), with
`password_hash` marked `write_only` + hashed via `on_write`, and never emitted in reads.

### Database schema & migrations

`auth::migrate(&db)` creates the six tables **if they don't already exist** — a bootstrap for a fresh
DB or the examples, safe to call on every start. It is **not** a migration engine: it only *creates*
missing tables, so it won't add columns when you upgrade the library (e.g. the TOTP / SSO columns on
`auth_user`) or otherwise evolve the schema.

> **Upgrading to 0.2.0** adds two columns to existing tables, which `migrate` will *not* create for you:
> ```sql
> ALTER TABLE auth_session ADD COLUMN last_seen_at BIGINT NOT NULL DEFAULT 0;  -- idle clock (§5f)
> ALTER TABLE auth_user    ADD COLUMN totp_last_step BIGINT NULL;              -- replay guard (§5a)
> ```
> The `DEFAULT 0` on `last_seen_at` makes every pre-existing session read as idle-expired, so everyone
> signs in again once — the safe direction. Backfill it to `strftime('%s','now')` (or your dialect's
> equivalent) instead if you'd rather not log your users out on deploy.

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
        // auth_user / auth_group / auth_user_group / auth_session + the two lockout tables —
        // from the library entities.
        for stmt in relativelylight::auth::table_create_statements(m.get_database_backend()) {
            m.create_table(stmt).await?;
        }
        // … your own app tables via m.create_table(schema.create_table_from_entity(App::Entity)) …
        Ok(())
    }
    async fn down(&self, m: &SchemaManager) -> Result<(), DbErr> {
        for t in [
            "auth_ip_lockout",
            "auth_username_lockout",
            "auth_session",
            "auth_user_group",
            "auth_group",
            "auth_user",
        ] {
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
  (default `"admin"`). Both paths write **only the password hash** — see the helper contract below — and
  both **revoke sessions**: the self-service page replaces the caller's session and deletes their others,
  a manager's reset deletes all of the target's (§5f).

### Admin helpers — who may re-open an account

Three helpers with deliberately different blast radii, so a routine password reset can never restore
login capability by accident:

| helper | creates? | password | `is_active` | TOTP 2FA | group |
|---|---|---|---|---|---|
| `set_password(db, user, pw)` | ❌ `Err` if unknown | set | untouched | untouched | — |
| `make_admin(db, group, user, pw)` | ✅ (active) | set | untouched | untouched | ensured |
| `reset_admin_access(db, group, user, pw)` | ✅ (active) | set | **→ true** | **cleared** | ensured |

- **`set_password`** is a *reset*, not an upsert: an unknown username is an error (creating accounts is
  `create_user`'s job), so a typo can't silently become a new login. A **disabled** account gets the new
  password and stays disabled; 2FA stays on; an SSO account still refuses password login. This is what
  `POST /profile` and `POST /profile/{id}` call.
- **`make_admin`** is the **boot-time seeder** (what the examples call on every start): idempotent, and
  it never strips an existing admin's `is_active` flag or authenticator.
- **`reset_admin_access`** is **break-glass recovery**, for an operator-invoked `--set-admin-pw` flag:
  it re-activates the account and **discards its TOTP enrolment** so a locked-out admin can get back in
  and re-enrol from `/profile`. Destructive by design — don't call it on every start. It **refuses an
  SSO account** (`Err` naming the provider): grafting a local password on would quietly take the
  account out of the identity provider's hands (and out of its group reconciliation), so point
  break-glass at a local username instead.

Re-enabling a disabled *non-admin* account stays an explicit `is_active` edit (e.g. in the admin UI).

## 5a. TOTP two-factor authentication — implemented

A second factor (RFC 6238 TOTP, via the `totp-rs` crate) on top of username + password. When a user
has 2FA enabled, a correct password isn't enough — they must also enter the 6-digit code from their
authenticator app. Defaults are the widely-compatible SHA1 / 6 digits / 30s step / ±1 skew.

**Data.** Two nullable base32 columns on `user`: `totp_secret` (the **active** secret — its presence
means 2FA is on) and `totp_pending` (a secret mid-enrolment, not yet confirmed), plus `totp_last_step`
(the replay guard, below). One flag on
`session`: `awaiting_totp` — a session created after a correct password but before the second factor.
`Auth::identify` treats an `awaiting_totp` session as **anonymous**, so the user is not logged in until
the code is confirmed.

**Login flow.** `POST /login` verifies the password, then:
- no 2FA → create a normal session, redirect `/`.
- 2FA on → create an `awaiting_totp` session (cookie set, but grants nothing), redirect `/login/totp`.
  `GET /login/totp` shows the code form; `POST /login/totp` verifies the code against the pending
  session's user and, on success, **rotates the session id** (§5f) into a full login → `/`. A
  wrong code → 401, re-render.

**Replay guard (RFC 6238 §5.2).** A code is valid for its own 30-second step *and* the two neighbours
(±1 skew for clock drift), so the same six digits work for about 90 seconds. `totp_last_step` records
the step each accepted code belonged to, and a later code must match a **strictly greater** step — so a
code can be used exactly once. Enrolment spends a step too, or the code that confirmed setup would still
work at `/login/totp` afterwards. Turning 2FA off clears the guard in the same write that clears the
secret; leaving a stale ceiling would silently refuse the first codes of a re-enrolment.

A replayed code is refused with the *same* message as a wrong one — "already used" would confirm to
someone holding a captured code that they hold a real one — and it counts against the account's lockout
budget like any other failure.

Be clear about what this does and doesn't buy, because the headline TOTP threat is **not** on the list.
Real-time phishing (an Evilginx-style proxy) relays the victim's code to the real server *once*, so
there is no second use to reject; the guard is powerless there, and only phishing-resistant factors
(WebAuthn — see §8) help. What it does close is reuse of a code the victim genuinely spent, by someone
who also has the password: a shoulder-surf, a screen share, a code read aloud on a support call, a
mistyped-into-the-wrong-window code. Narrow, but the standard requires it and it costs one column.

**Enrolment (self-service, verify-before-activate).** `GET /profile/totp` mints a fresh secret, stores
it as `totp_pending`, and shows **both** a QR code (a server-rendered inline PNG — no JS) **and** the
`otpauth://…` URL as copyable text. `POST /profile/totp` checks the entered code against the pending
secret; only on success is it promoted to `totp_secret` (2FA now required at login). A wrong code
re-shows the same QR. `Auth::totp_issuer(name)` sets the issuer label authenticator apps display
(default `"relativelylight"`).

**Blank = off.** As with `sso_provider`, a blank `totp_secret` counts as *no* secret (`Model::totp_key`
/ `has_totp`), and a blank `totp_pending` as *no* enrolment in progress. Treating `Some("")` as "2FA on"
would demand a login code no authenticator can produce — an account locked out of its own login — and
an empty text input in an admin form is exactly how that value appears.

**Disable.** `POST /profile/totp/disable` turns off the caller's own 2FA. A **manager** (a
profile-manager group, §5) can disable *another* user's 2FA via `POST /profile/{id}/totp/disable`
(shown on the `/profile/{id}` page) — but managers can never *set up* 2FA for someone else, since
enrolment needs that user's device. Disabling clears `totp_secret`, `totp_pending` **and**
`totp_last_step`.

The profile page (`GET /profile`) shows a 2FA section reflecting the current state: a "Set up 2FA"
link when off, or a "Disable 2FA" button when on.

## 5b. SSO / OpenID Connect — implemented (feature `sso`)

Sign users in through an external OIDC identity provider — Google, Okta, or any compliant corporate
IdP — via the Authorization Code flow with PKCE. Built on the `openidconnect` crate (discovery, PKCE,
nonce, ID-token signature/aud/iss/exp verification); the QR-free, cookie-carried transaction survives
the round-trip to the provider. Configured at app start; usable alongside password login + 2FA.

**Accounts.** An SSO login resolves to an `auth_user` whose **`sso_provider`** column marks it external.
Such accounts have **no local password and no 2FA** — `verify_credentials` refuses a password login,
and the profile page shows a read-only notice instead of the password / 2FA controls. With a
provider's **auto-registration** on, an unknown user is created on first login; with it off, an admin
must pre-create the user and set its `sso_provider` to the provider key first, else the login is
refused. A local (password) account can't be signed into via SSO, and an account bound to one provider
can't sign in through another. A **blank** `sso_provider` counts as *no* provider, exactly
like `NULL`: an admin form that leaves the column empty writes `""`, and the account it creates must stay
an ordinary local one. Ask `user::Model::sso_key()` / `is_sso()` rather than testing the column — the
normalization then holds everywhere (password login, the profile page, break-glass recovery, and the SSO
callback's own account check). Rows written *before* the admin UI learned to send `null` for an empty
nullable column can be tidied with `auth::normalize_blank_user_columns(&db)` (blank `sso_provider` /
`totp_secret` / `totp_pending` → `NULL`; idempotent, safe on every start) — hygiene only, since the
readers tolerate blanks either way.

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

**Account resolution.** The username claim is matched **case-insensitively**, because providers are not
consistent about case and an IdP that switched from `alice@corp` to `Alice@corp` would otherwise miss the
existing account and — with auto-registration on — create a second one: two rows, two group sets, one
human. A pre-created account keeps its own spelling; ties (rows differing only in case, which nothing
here creates) go to the lowest id. Local password login still matches **exactly** — changing that would
be a behaviour break for every existing account. The refusals are the same whatever the case: a local
account is recognised as local, and an account bound to another provider as bound.

A **disabled** account (`is_active = false`) is refused, before anything is written — the same rule
`verify_credentials` applies to password login, so that deactivating an account means the same thing on
both doors. (It was already impossible to *act* as a disabled user, since `identify` re-checks the flag,
but the login used to get as far as reconciling groups and stamping `last_login_at`.)

**Discovery is cached** per provider for an hour, along with the signing keys it carries. Before that it
was fetched on *every* request — twice per sign-in — which cost two extra round-trips, failed the whole
sign-in whenever the provider's endpoint was briefly slow, and, since `/sso/{key}/login` needs no
authentication, let anyone aim a flood of outbound requests at your provider by looping on it. An hour is
safe for key rotation: providers publish a new signing key well before retiring the old one.

> **The transaction cookie is not signed — and signing it would not help.** `state`, `nonce` and the PKCE
> verifier ride in a `HttpOnly` cookie as base64 JSON, so the `state` check compares two values that both
> came from that cookie. Anyone who can **write** a cookie for your host (a sibling-host XSS,
> cookie-tossing, an active attacker on plain http) can therefore supply a transaction of their choosing
> and complete a login in the victim's browser — *login CSRF*: the victim ends up signed in as the
> **attacker's** identity. Note the direction: the attacker gains none of the victim's access; the harm is
> a victim who acts inside an account someone else controls.
>
> Signing the cookie would stop forgery and change nothing here, because forgery isn't needed:
> `/sso/{key}/login` hands a genuine transaction to whoever asks, so an attacker can plant a validly
> signed one of their own. The protection therefore rests on the same assumption as the double-submit
> CSRF token (§7) — a cross-site attacker can neither read your cookies nor set one for your host — which
> in practice means HTTPS (ideally HSTS), no XSS, and not sharing a registrable domain with something you
> don't trust.

> **Verification.** The callback is covered by an automated suite (`auth/sso_tests.rs`) that runs the
> shipped client against a **fake IdP** on a loopback port — real discovery over HTTP, real RSA
> signatures — so every rejection path is exercised in CI. See §10a.

## 5c. Lifecycle timestamps — implemented

The auth entities carry UTC timestamps (`i64` Unix seconds), maintained automatically:

- `auth_user`: `created_at`, `updated_at`, `last_login_at` (nullable).
- `auth_group`: `created_at`, `updated_at`.

`created_at`/`updated_at` are stamped by a SeaORM `ActiveModelBehavior::before_save` hook (created on
insert, updated on every save) — so they're correct no matter who writes (admin CRUD, the profile page,
`create_user`/`set_password`, …). `last_login_at` is **not** a hook; the login flows stamp it with a
set-based update (so it doesn't bump `updated_at`) on completion: `login_submit` (no-2FA), the TOTP
confirm (`login/totp`), and the SSO callback. Mark these fields `read_only` on the `MetaModel` so the
admin shows but doesn't edit them (see `examples/adminpanel`). All times are UTC; rendering them in the
viewer's timezone is a frontend concern (see [docs/TIME.md](TIME.md)).

## 5d. Write observer — audit hook (implemented)

`auth` fires the shared [`WriteObserver`](../src/observe.rs) (see [CRUD.md](CRUD.md#write-observer-audit))
from its **mutating handlers**, so auth-table changes made *outside* the crud engine are still audited:

- `POST /profile` — password change (`source = "auth-profile"`).
- `POST /profile/{id}` — a manager reset (`source = "auth-admin"`).

Each event carries the request `headers` + socket `peer` (so the app resolves the actor and client IP)
and an `after` payload describing *what* changed — **never a secret**: password hashes and TOTP secrets
are redacted (e.g. `{"password_changed": true}`). Register the sink with `Auth::on_write(observer)`;
share one `Arc` with `Crud::on_write` so a single audit sink covers both surfaces:

```rust
let audit = Arc::new(MyAuditSink::new(db.clone()));
let auth = Auth::new(db.clone()).on_write(audit.clone()) /* …other builders… */;
let mut crud = Crud::new(db, "/admin/api");
crud.on_write(audit.clone());
```

The app owns the audit table + retention; the library only emits the events. (Auditing login events and
TOTP enable/disable can be layered on the same hook later; `last_login_at` already records logins.)

## 5e. Lockout: the brute-force brake — implemented

The brake in front of the **unauthenticated** credential checks. Two counters, two tables, two
deliberately separate types (`auth::lockout::{UsernameLockout, IpLockout}`) — they do the same
arithmetic today and are expected to diverge (a username whitelist wants regexes, an address
whitelist wants CIDRs).

**The rule.** A checked-and-rejected credential upserts a row (`failures += 1`, `last_failure_at =
now`) *unless* the key is already at the limit — a locked key records nothing, so an attacker cannot
push the expiry out by continuing. A key is locked while `failures >= after` **and** `last_failure_at +
duration > now`; the handler then answers **`429` with `Retry-After`** and never looks at the submitted
secret, so a locked account costs no argon2 work and the response is identical for a real and a
made-up username (no enumeration hint). Once the window passes the row reads as absent and the pruner
deletes it. Effective semantics: **"`after` failures, each within `duration` of the previous, lock the
key for `duration` after the last one"** — a decaying window, not a strict sliding one.

**What is braked — and what deliberately isn't:**

| Check | Counted against | Why |
|---|---|---|
| `POST /login` (password) | account + address | the anonymous guessing surface |
| `POST /login/totp` (second factor) | account + address | still unauthenticated (the session grants nothing until the code is confirmed), and 6 digits are the most guessable secret we hold |
| the app's own checks (`Auth::username_lockout` / `ip_lockout`) | whichever it passes | same counters, so one account has one budget everywhere |
| `POST /profile` (current password) | **not limited** | the caller is *authenticated*: that's session theft, whose mitigations are short TTLs and re-auth (TODO.md) — and counting it would let a stolen session lock the real user out of logging in |
| `POST /profile/totp` (enrolment code) | **not limited** | authenticated, and the code guessed is the caller's *own* pending secret |
| `POST /profile/{id}` (manager reset) | **not limited** | verifies no secret; gated by group membership instead |

**Configuration is mandatory** — it is an argument to `Auth::new`, not a builder call, so there is no
way to end up with an unbraked login by forgetting one:

```rust
let auth = Auth::new(db, Lockout {
    username_after: 10,          // failed logins per account before it locks (0 = off)
    username_duration_secs: 900,
    ip_after: 100,               // failed checks per source address (0 = off)
    ip_duration_secs: 900,
});
// Lockout::default() is exactly the values above.
```

`*_after: 0` switches a counter off completely — nothing is read, nothing is written. A `*_duration_secs`
of `0` is *not* the way to do that: it is clamped to 1 second, so rows are still written and the lock
just expires immediately. The two windows are independent on purpose (an address is a coarser subject
than an account, so it usually deserves a different one).

```rust
```

The address budget is deliberately far looser than the account one: a locked address turns away *valid*
callers too, which matters when your users share one (CGNAT, an office NAT).

**Who is the client?** The per-address half needs an address, and there are exactly two right answers —
which one applies is a security boundary, so it is a config flag rather than a guess:

```rust
Lockout { trust_proxy: false, .. }   // exposed directly: the socket peer is the client
Lockout { trust_proxy: true,  .. }   // behind a proxy you control: the right-most X-Forwarded-For hop
```

That is [`net::client_ip`](crate::net::client_ip) — which reads the **right-most** `X-Forwarded-For`
entry, the one your proxy appended, because everything to its left is whatever the caller chose to send
(nginx's `proxy_add_x_forwarded_for`, HAProxy's `option forwardfor` and Caddy all append). Reading the
left-most entry would let any caller pick its own address and so walk past an admission list, out of a
lockout, or into someone else's audit row. A proxy that *replaces* the header leaves one entry, where
both readings agree. Two hops (a CDN in front of your own proxy) are out of scope for the flag by
design — override the resolution with `Auth::client_ip` there (§4).

The app should call the same function for its own logging, audit rows and limits — then a failed login and a failed API call from one client land on the **same** row,
canonicalized the same way (an IPv4-mapped `::ffff:a.b.c.d` peer and a plain `a.b.c.d` forwarded hop are
otherwise two different keys).

Get the flag wrong in either direction and it bites: unproxied with `trust_proxy: true`, a caller picks
whose address gets locked out by sending a header; proxied with `trust_proxy: false`, every user is
bucketed under the proxy's address, where a hundred failures lock your whole login form. There is no
default that is safe for both, which is why it has to be stated.

For chains stranger than "one proxy sets `X-Forwarded-For`" — several hops to walk, a CDN header like
`CF-Connecting-IP` — `Auth::client_ip(|headers, peer| ..)` replaces the resolution outright.

**Whitelisting addresses.** `Lockout::ip_whitelist` takes CIDRs (build it with `net::parse_nets`, which
also accepts bare addresses) that are never counted and never locked — an office range, a monitoring
probe, the host a fleet NATs through. It matches across families and representations, so a rule written
`::ffff:198.51.100.0/120` covers a client that arrives as plain `198.51.100.9`, and vice versa. The
exemption applies on **every** surface, this module's and the app's, since both go through `IpLockout`.

It does *not* exempt the account counter, and there is deliberately **no username whitelist**: an
account that can never be locked out is an account whose password can be guessed at forever. The
address list exists for the opposite reason — so one shared address cannot take everyone down with it.

Setting `ip_after: 0` turns per-address counting off everywhere, leaving the per-account brake — which
still covers the common case of one account being guessed at, just not spraying across many.

**The app's own credential checks share these counters.** An app that authenticates callers itself —
API tokens, HTTP Basic on a machine endpoint, a DDNS update URL — must not keep a second limiter, or an
account gets two budgets and an unlock frees only half of them:

```rust
let usernames = auth.username_lockout();   // in AppState; cheap to clone
let ips = auth.ip_lockout();

if let Some(retry) = usernames.locked(username).await { return too_many(retry) }   // before the secret
match check_credential(...) {
    Ok(who) => { usernames.clear(username).await; Ok(who) }
    Err(_)  => { usernames.record_failure(username).await; Err(unauthorized()) }   // checked & rejected
}
```

Rules that matter: pass **no** username when the credential names no account (a bearer token) and let
the address counter carry it; pass the **real** client address; and only ever record a credential you
actually checked and rejected — never one with no credential at all, a failed CSRF check, or one you
turned away *because* it was locked, or a third party can spend someone else's budget.
`record_failure` returns whether *this* failure tripped the lock, so you log once instead of on every
subsequent attempt. `examples/auth` has a working one (`GET /api/whoami`).

**The unlock is a row delete.** The two entities (`lockout::username_entity`, `lockout::ip_entity`) are
ordinary SeaORM models: register them in your admin panel and an operator can see who is being guessed
at and clear a row — gated by your `Authz`, CSRF-checked, and audited by your `WriteObserver` like any
other write. No bespoke endpoint, no CLI, no shelling into the host. `examples/adminpanel` registers
both as read-only-plus-delete panels.

**Housekeeping is the app's.** Nothing in this crate schedules anything — no background task, no timer.
`Auth::prune()` deletes dead sessions *and* expired lockout rows from both tables; call
it at startup and from whatever periodic loop the app already has (both examples do). Prefer it over the
free `auth::prune(&db, lockout)`, which takes no `Auth` and so can only see the absolute session deadline,
not the idle one (§5f). Skipping either is
safe: a dead session never authenticates and an expired lockout row reads as unlocked and resets
itself on the next failure — the rows just accumulate.

## 5f. Session lifetime & revocation — implemented

A session is a row, so revoking one is a `DELETE` and there is no token to keep believing after the
fact. That's the whole advantage over a JWT (§3), and this section is what the module does with it.

**Two clocks, both enforced at `identify`.**

| clock | column | configured by | default | what it bounds |
|---|---|---|---|---|
| absolute | `expires_at` | `Auth::session_ttl_secs` | 7 days | how long a session can *ever* live, however busy |
| idle | `last_seen_at` | `Auth::session_idle_secs` | 8 hours | how long an *unused* session survives |

The idle clock is the one that bounds a stolen cookie: without it an attacker who lifts a cookie has the
full absolute window, whether or not the victim ever comes back. `session_idle_secs(0)` switches it off
and leaves exactly the pre-0.2.0 behaviour. The absolute deadline always wins — a session used a second
ago but past `expires_at` is dead.

`last_seen_at` is refreshed **lazily**: a read only writes when the stamp is more than a minute stale.
That matters because `identify` is called once per gated model — an `Admin` page with five tables
resolves the caller five times — so an eager refresh would turn one page render into five writes.

**`Auth::identify(&headers) -> Option<Identity>` does not change**, and shouldn't: it stays a cheap call
that needs no response to write into. Everything that changes a session **id** happens inside a POST
handler that already owns its response.

**Rotation on privilege gain.** Password login can't be fixated — it always mints a new row with a
server-generated id, so a cookie value an attacker chose is never elevated. The gap was the *second*
factor, which used to flip `awaiting_totp` on the same id: an attacker who knew the password could take
a half-authenticated session, write its cookie into the victim's browser (cookie-tossing from a sibling
host, or an XSS — neither `Secure` nor `SameSite` stops that), send them to `/login/totp`, and inherit a
full session the moment the victim typed their own code. Confirming the second factor now issues a **new
id** and deletes the old row, so the attacker is left holding a token that no longer exists. The CSRF
token rotates with it.

**A password change signs out everything else.** The commonest reason to change a password is "I think
someone else is in my account", and a session that outlives the credential that created it defeats
exactly that. So `POST /profile` mints one fresh session for the caller and **deletes every other
session they hold** — including their own previous id, since that's one of the values that might have
been copied. A manager's reset at `POST /profile/{id}` deletes **all** of the target's sessions (there is
no session of theirs to spare).

**On demand.** `POST /profile/sessions/revoke` — the "Sign out other sessions" button on the profile
page — deletes the caller's other sessions and keeps the one they're using. The app-facing forms are
`Auth::revoke_sessions(user_id)` and `Auth::revoke_other_sessions(user_id, keep)`; call them when *your*
code decides a user's sessions are void (you disabled the account, a group sync removed their access, an
operator hit a force-logout). Note that `is_active = false` already denies every request at `identify`,
so revoking there is tidiness rather than enforcement.

**Not yet.** Re-authentication before sensitive changes (a fresh password or code before disabling 2FA)
is still open — see `TODO.md`. Until it lands, a stolen *live* session can still turn 2FA off, which is
why the idle window matters.

**Durable and shared, on purpose.** The rows survive a restart (a deploy must not hand every attacker a
fresh budget) and every replica sees the same counts. The cost is a write per *failed* check and a read
per check, which is nothing: failures are rare in normal operation, a locked key is read-only, and the
password path is dominated by argon2 anyway.

**Known trade-off.** A lockout is also a small denial-of-service handle: someone who knows an account
name can keep it locked by failing on purpose, and now that the rows are durable a restart no longer
clears it. That is why the lock is short, lifts on its own, and can be cleared from the admin panel.
The alternative — progressive delays — holds a server task open per attempt, which is its own risk.

## 5g. Password strength — implemented

`Auth` screens a **new** password on its own pages — `POST /profile` and a manager's `POST /profile/{id}`
— against a [`validate::PasswordPolicy`](DATAINPUT.md). **On by default**, at
`PasswordPolicy::recommended()`.

**Length first, composition rules off.** That follows NIST SP 800-63B, which recommends screening for
length and against known-bad values and explicitly advises *against* requiring character-class mixtures:
users satisfy `upper + digit + special` with `Password1!` and `Summer2024!`, so the rule costs usability
and buys a search space every cracking ruleset already covers. The flags exist
(`PasswordPolicy::legacy_composition()`) because audits still ask for them; no other preset sets them.

| preset | length | screening | composition |
|---|---|---|---|
| `nist_minimum()` | ≥ 8 | common values, patterns, context words | — |
| `recommended()` *(default)* | ≥ 12 | same | — |
| `legacy_composition()` | ≥ 12 | same | upper + lower + digit + symbol |

`PasswordPolicy::from_level(1\|2\|3)` maps a config integer onto those, so an app can expose
`password_level` and be done; an unrecognised value lands on `recommended()` rather than the weakest one.

What every preset enforces: a minimum **and a maximum** length (a bound is a security control — the value
is fed to argon2, and hashing an unbounded input burns CPU per request), no control characters, and
screening against a built-in list of common values (matched whole, after folding and stripping a
digit/symbol tail, so `Password1!` is caught), your own `blocklist` words (matched as substrings — the app
name, a product name), and patterns (one repeated character, or any run of six consecutive characters like
`123456`). Everything printable is allowed — spaces, punctuation, emoji — and nothing is truncated.

On this surface the policy also gets the **username** as context, so a password containing it is refused.
That check is inherently cross-field, which is why a single-field `crud` validator can't do it.

**The built-in list is a floor, not a breach corpus** — a few dozen perennial values plus keyboard walks.
Real breach screening means a local corpus or an online service (HIBP's k-anonymity API); that's an
app-level dependency and a network call, so it isn't built in. Add your own via `blocklist`, or replace
the check entirely.

**Opt out, two ways** — a library shouldn't dictate this:

```rust
use relativelylight::validate::PasswordPolicy;
auth.password_policy(PasswordPolicy::nist_minimum())        // another preset
auth.password_policy(PasswordPolicy::from_level(cfg.level)) // …from your config
auth.password_policy(PasswordPolicy::recommended().block(["acmecorp"]))
auth.password_policy(None)                                  // off
auth.password_check(|pw, username| my_rules(pw, username))  // your own predicate, replaces the policy
```

**It governs typed input, not code.** `create_user` / `set_password` / `make_admin` /
`reset_admin_access` are unaffected, so a seeder or a break-glass CLI still sets whatever the operator
says — if the policy governed those, a deployment could be left with no way to set a first password.

**Both surfaces or neither.** `Auth` covers its own pages; the admin UI and JSON API are a separate
`crud` field validator, and whichever you skip becomes the way around the other:

```rust
user_mm.field("password_hash").password();
user_mm.field("password_hash")
    .validate_str(validate::optional(Box::new(validate::password(policy))));
```

`optional` matters: blank has a meaning on that column (blank on create = no password / login disabled,
blank on edit = keep the current one), and without it "leave blank" becomes a validation error. The crud
pipeline is **coerce → validate → transform**, so the validator sees the plaintext before
`MetaField::password()`'s argon2 hook hashes it — no engine change needed. `examples/adminpanel` wires
both halves from one `PASSWORD_LEVEL` env value, `0` switching them off together.

## 5h. Re-authentication before sensitive changes — implemented

A live session proves that **someone** logged in once. It does not prove that the account's owner is the
one asking now — a stolen cookie *is* a live session. The idle clock (§5f) bounds how long such a cookie
lasts; this bounds what it can **do** while it lasts. So the actions that would let an intruder entrench
ask for a factor again, per request:

| route | whose factor | why this one |
|---|---|---|
| `POST /profile/totp/disable` | the caller's | removing the second factor is step one for an intruder |
| `POST /profile/totp` (enrol) | the caller's | otherwise they enrol *their own* authenticator — which doesn't just persist access, it **locks the real user out**, since login then wants a code only they can produce |
| `POST /profile/{id}` (reset) | the **manager's** | sets a password without knowing the old one; every account it reaches is one the session can then log in as |
| `POST /profile/{id}/totp/disable` | the **manager's** | strips a victim's second factor |

`POST /profile` (your own password change) already required the current password, so it was
re-authenticated before this existed. `POST /profile/sessions/revoke` deliberately is **not**: it only
ever *removes* access, and a user racing to evict an intruder shouldn't be slowed down.

**Either factor.** A `current_password` or a `totp_code` satisfies it. A **fresh code is preferred** when
the account has 2FA — it proves presence, where a password may have been filled in by the browser for
whoever is sitting there — and a code accepted here is **spent** (§5a), so one captured code can't wave
through both a sensitive action and a login. Enrolment is the one asymmetric case: a *first* enrolment has
no active secret to check a code against, so the password is the factor; a re-enrolment can use either.

**An account with no local factor passes.** An SSO account has neither password nor local 2FA, so there is
nothing to ask it for, and refusing would lock every SSO administrator out of the manager pages
permanently. Their assurance is whatever the IdP gave them. Re-auth *through* the provider (an OIDC
`prompt=login` round-trip returning to the pending action) is the real answer and isn't built — a
documented limit, not an oversight. The same holds for a local account whose password is blank, which
already can't log in.

**Not lockout-limited**, for §5e's reason: the caller is authenticated, so counting failures here would let
a stolen session lock the real user out of logging in. Nor is it needed — guessing a password is no easier
here than at `/login`, and a 6-digit code would take ~10⁶ requests inside its 90-second window.

**For your own routes**, which is where most sensitive actions live:

```rust
let Some(who) = auth.identify(&headers).await else { return redirect_to_login() };
if let Err(msg) = auth.reauthenticate(&who, &form.current_password, &form.totp_code).await {
    return (StatusCode::FORBIDDEN, render_form_with_error(&msg));  // nothing has happened yet
}
delete_the_thing(&who).await;
```

`Auth::can_reauthenticate(&who)` says whether the account *can* be challenged (false for SSO), for a UI
hint. `examples/auth` gates a `POST /api-token/rotate` on it — the pattern to copy, including returning
the refusal before anything is written.

**Deliberately per-request, not a window.** A "you confirmed five minutes ago" grace period would need
another `auth_session` column and a window during which a stolen session is dangerous again. These are
rare actions; typing a password twice to reset two users is a fair price for having no open window.

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

**Presets.** Each names its **read audience** and **write audience**, each one of Public (anyone,
incl. anonymous) → User (any authenticated user) → Group (member of one of the named groups),
narrowing left-to-right; the name collapses to `‹Audience›ReadWrite` when read and write share an
audience. A caller who could satisfy a write once logged in gets `NeedsLogin`; a logged-in caller
lacking the group gets `Denied`.

- **`authz::Open`** — public read + write (no auth); the Public/Public corner. Pass it when a model
  needs no gating (also the only preset available when the `auth` feature is off).
- **`auth::UserReadWrite::new(&auth)`** — any authenticated user may read + write; anonymous → `NeedsLogin`.
- **`auth::UserReadGroupWrite::new(&auth, ["editors"])`** — any authenticated user may read; a
  write needs membership in one of the groups (else `Denied`); anonymous → `NeedsLogin`.
- **`auth::PublicReadGroupWrite::new(&auth, ["editors"])`** — **anyone** (incl. anonymous) may read; a
  write needs group membership (anonymous writer → `NeedsLogin`, other logged-in → `Denied`). The
  public-read sibling of `UserReadGroupWrite` — e.g. a publicly readable catalog only staff may edit.
- **`auth::GroupReadWrite::new(&auth, ["admin"])`** — the strict corner: *only* members of one of the
  groups may read **or** write; anonymous → `NeedsLogin`, any other logged-in user → `Denied`. Use it
  to keep whole models group-only (e.g. the `auth_user` / `auth_group` tables). Its
  `admits(&Identity)` method is a header-free membership check for deciding group-only UI.
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
use relativelylight::auth::{lockout::Lockout, Auth, GroupReadWrite, UserReadGroupWrite};
use relativelylight::authz::Open;
use relativelylight::crud::seaorm::Crud;
use std::sync::Arc;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

// 1. authn: SeaORM-backed sessions + login/logout/password. Cheap to clone (Arc inside).
//    The brute-force brake is a `new` argument, not a builder call — it isn't optional (§5e).
let auth = Auth::new(db.clone(), Lockout::default())
    .admin_group("admin")        // group that may reset others' passwords (configurable)
    .secure_cookies(true)        // false for local http
    .session_idle_secs(8 * 3600); // idle timeout inside the 7-day absolute one (§5f); 0 disables

// 2. crud: each model registered with its gate. Share one gate via Arc, or vary per model.
let content = Arc::new(UserReadGroupWrite::new(&auth, ["editors", "admin"]));
let mut crud = Crud::new(db, "/api/v1");
crud.register(post_mm, content.clone());                          // logged-in read, group write
crud.register(user_mm, GroupReadWrite::new(&auth, ["admin"]));    // admins only (read + write)
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
`/metrics`) simply never calls `identify`. The one thing the app must **schedule** is housekeeping:
`auth.prune()` on its own loop (§5f/§5e) — the crate spawns no tasks.

## 7. CSRF — implemented (double-submit token, feature `csrf`)

Cookie-authenticated **unsafe** requests (POST/PATCH/PUT/DELETE) must carry a CSRF token, checked
against a cookie-bound value (double-submit). Defense-in-depth on top of `SameSite=Strict`. The module
is `relativelylight::csrf` (feature `csrf`, implied by `auth`); the type is `Csrf`.

**The token.** 256 random bits (hex) in the `rl_csrf` cookie (name configurable) — `SameSite=Strict`,
`Path=/`, `Secure` unless told otherwise, lifetime matching the session TTL, and deliberately **not
`HttpOnly`**: the admin UI's JS must read it. That is safe because the token is *not a credential* —
it grants nothing on its own. A same-site client can always satisfy the check (read your own cookie,
echo it); a cross-site attacker cannot, because they can neither read your cookie nor set one for your
host. That asymmetry *is* the protection.

An unsafe request presents it in either:
- the **`_csrf` form field** — MPA `<form>` posts (every fragment `auth` renders embeds the hidden
  input), or
- the **`X-CSRF-Token` header** — `fetch`/XHR clients, including `crud::ui`.

**Where it's enforced.**

| Surface | Enforcement | Rejection |
|---|---|---|
| `Auth::routes()` — `/login`, `/login/totp`, `/profile*` | **always on** | `403` + a bare "Security check failed" page |
| the `crud` JSON API | **opt-in**: `crud.csrf(auth.csrf())` | `403 {"error":"csrf token missing or invalid"}` |
| your own handlers | call `Csrf::verify` yourself | yours |

On the auth routes the check runs **first** — before the password comparison, before any DB work — so a
forged post costs nothing and can't be used as an argon2 amplifier. Same in the engine: the CSRF check
precedes the gate, so a forged write never reaches a session lookup, let alone the backend. Safe methods
(GET/HEAD, i.e. every read) need no token. A page render **issues** the cookie if the request has none
(`Csrf::ensure`), and login / 2FA-completion **rotate** it along with the session; logout clears it.

**`Authorization`-bearing requests are exempt** — an API credential isn't ambient, so a cross-site
request can't borrow it and there's nothing to protect. This keeps a token-based API unburdened (and
holds the door open for the app-issued API tokens of §8).

**Wiring it up.** `auth`'s own pages need nothing. For the API, hand the engine the same checker so both
surfaces share one cookie:

```rust
let auth = Auth::new(db.clone()).secure_cookies(false);   // configure Auth fully first
let mut crud = Crud::new(db, "/api/v1");
crud.register(post, gate);
crud.csrf(auth.csrf());          // writes now require X-CSRF-Token
```

`Table`/`Admin` then read the cookie name off the engine and add the header to every write `fetch`
(create, update, both deletes, CSV import) — nothing to pass in. An app-owned page that posts to its own
route does the two halves itself:

```rust
let (token, set) = auth.csrf().ensure(&headers);          // → hidden input / JS-readable cookie
let jar = if let Some(c) = set { jar.add(c) } else { jar };
// …and in the POST handler:
if !auth.csrf().verify(&headers, form.csrf.as_deref()) { return StatusCode::FORBIDDEN.into_response(); }
```

> **Note — one deviation from the original sketch.** `crud::ui` reads the token from the cookie at
> request time rather than having it baked into the rendered fragment. Same check, but a fragment
> rendered before a rotation (or cached) can't go stale, and `Table::render()` keeps working without
> request headers.

**Limits.** There is no `Csrf` tower layer yet, and the 403 page isn't themeable — both in
[TODO.md](../TODO.md). Note also that a **co-hosted** app sharing the host must use a distinct
`csrf_cookie_name` (cookies aren't port-scoped), exactly as with the session cookie.

## 8. Future-proofing (not in v1, but designed for)

- **TOTP 2FA — done (§5a).** Implemented as an `awaiting_totp` session flag + `totp_secret` on the
  user. **PassKeys/WebAuthn** would slot in similarly (a session assurance level a policy can require
  for sensitive models) — parked at **milestone 0.3+**: nothing driving the crate needs it yet, and it is
  a large surface (a credentials table, browser ceremonies, and an assurance level that would likely add
  a field to `Identity`). It remains the only real answer to real-time phishing, which TOTP and its
  replay guard do not address.
- **OIDC SSO — done (§5b, feature `sso`).** The callback creates a `session` for the mapped user —
  the same session model. Group memberships come from the username/claim mapping tables.
- **App API tokens:** the app issues tokens and adds an **identity source** that maps a Bearer token →
  `Identity` (a gate that checks the header instead of the cookie); the gate contract and all call
  sites are unchanged. The built-in session source ships; token sources are app- or future-provided.

## 9. Module / feature layout

`auth` is a **module of the `relativelylight` crate**, gated by the **`auth`** feature — usable
without `crud`:

- **`auth`** — `Identity`, on-demand `Auth::identify`, the gate presets (`UserReadWrite`,
  `UserReadGroupWrite`, which impl `authz::Authz`), the SeaORM `user`/`group`/`session` models,
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
  in the app's chrome via `profile_shell`. It also carries the worked example of **re-authentication for an
  app's own sensitive action** (§5h): `POST /api-token/rotate`, reached from a form on `/secret`, resolves
  the caller, calls `Auth::reauthenticate` with whatever the form submitted, and returns the refusal
  *before* anything is written — the order that makes a rejection a no-op. Plus the `--set-admin-pw` break-glass startup path
  (`reset_admin_access`; the demo admin is seeded with `make_admin`). **Attempt limiting** is tuned down
  to 5 failures / 5 minutes per account with a 15-per-IP cap (§5e) and verified end-to-end: the 5th bad
  password locks the account (`429` + `Retry-After: ~298`, the correct password refused with it), and
  spraying `ghost1…ghostN` from one address trips the IP cap at its 15th failure. **SSO** is wired in
  (feature `sso`) and enabled by setting `SSO_GOOGLE_CLIENT_ID` / `SSO_GOOGLE_CLIENT_SECRET` in the
  env: a "Sign in with Google" button appears and `/sso/google/*` is served (username→group rule for
  `@example.com`, auto-register on).
- **`examples/adminpanel`** — **login-gated** `crud::ui::Admin`: the page calls
  `auth.identify(&headers)` (→ redirect to `/login` when anonymous), the content models are registered
  with a shared `UserReadGroupWrite::new(&auth, ["admin"])` gate (any logged-in user reads; the admin
  group writes), and the panel is rendered per request with `render_for` so write controls hide for
  non-writers. The navbar shows the signed-in user, linking to **`/profile`** (self password change).
  The auth **`auth_user` / `auth_group`** tables are also surfaced — gated `GroupReadWrite::new(&auth, ["admin"])`
  (admin-only, read included) and shown only to managers. Accounts are **created/edited inline**: one
  `user.field("password_hash").password()` call (the `MetaField::password()` helper, see CRUD.md)
  exposes it as a write-only **Password** field (masked input) whose plaintext is argon2-hashed on
  write and never returned in reads; an **empty password is allowed** and stored as an empty hash, so
  password login is simply disabled (a future SSO / PassKey account). New
  accounts default `is_active = true`, and each user id also links to `/profile/{id}` for a dedicated
  reset. Two logins: `admin` (read-write, manager) and `editor` (read-only). Verified end-to-end:
  anonymous → 303; `admin` → reads + writes, creates accounts with/without a password, resets
  `editor`'s password via `/profile/2`; `editor` → read-only panel with no Accounts section, own
  `/profile` works, `/profile/1` and the `auth_user` API both 403. **CSRF** is on for the API
  (`crud.csrf(auth.csrf())`) and verified end-to-end in a browser: the panel's create/update/delete
  `fetch` calls carry `X-CSRF-Token` and succeed, the same write by `curl` without the header is
  `403 {"error":"csrf token missing or invalid"}`, reads are unaffected, and `POST /profile` without the
  hidden `_csrf` field is 403. Empty-password accounts cannot log in
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

## 10a. Automated tests — the negative paths

The examples above verify the happy paths by hand; the **rejection** paths are pinned by an automated
suite (`cargo test --all-features`) that runs the shipped routers against a fresh in-memory SQLite DB
(`tower::ServiceExt::oneshot`, no socket). Two modules:

- **`auth/security_tests.rs`** — sessions, login, TOTP, profile:
  - a cookie is worth nothing unless its row is **live, unexpired, past the second factor, and its
    user active** — expired, `awaiting_totp`, deactivated-user, deleted-user, forged, empty,
    truncated, and wrong-cookie-name tokens all resolve to anonymous, as does a token offered as
    `Authorization: Bearer …` (there is no header identity source yet);
  - `POST /login` returns **401 with no session cookie and no session row** for a wrong/empty/prefix
    password, an unknown user, an **inactive** account, and an **SSO** account (correct password
    included); the error text stays generic. Session tokens are 256 random bits and never repeat, and
    the cookie is `HttpOnly; SameSite=Strict; Path=/` (+ `Secure` unless `secure_cookies(false)`);
  - a password-only login to a 2FA account yields a **half-authenticated** session that identifies as
    anonymous and can't open `/profile`; `/login/totp` refuses a wrong, empty, malformed, or
    **another user's** code (401, session stays pending, no `last_login_at`) and refuses to run at all
    without a pending session (no session / full session / expired session → back to `/login`);
  - enrolment activates 2FA **only** on a code matching the pending secret (a wrong code keeps the
    same pending secret and leaves 2FA off; a POST with nothing pending is a no-op), and the enrolment
    page never renders another user's secret;
  - `/profile` needs the **current password** (wrong/empty/case-changed → 400, old password still
    works, new one not set) and rejects an empty or mismatched new pair; every profile route redirects
    anonymous / bogus / pending / expired callers to the login page **without touching the target**;
  - a plain user gets **403** on `/profile/{id}`, its reset POST, and `/profile/{id}/totp/disable`,
    and the target's password + TOTP secret are provably unchanged; narrowing `profile_managers`
    excludes even the admin group; unknown/non-numeric ids are 404; and a manager aiming the
    no-current-password reset at **themselves** is bounced to `/profile` (it's not a way around the
    current-password check). SSO accounts can't set a local password or enrol local 2FA, and a
    manager's reset aimed at an SSO account still can't produce a password login; a reset of a
    **disabled** account stores the new hash but leaves it disabled and unable to log in (same for
    the `make_admin` seeder, which also leaves an enrolled authenticator alone), while `set_password`
    refuses an unknown username outright and **break-glass `reset_admin_access`** does re-open the
    account (password + `is_active` + 2FA cleared + admin group, verified by an actual login) but
    refuses SSO targets;
  - the **gate presets** are asserted as a matrix — anonymous, logged-in non-member, and member ×
    read/write — and every preset treats an expired, half-authenticated, or deactivated session as
    anonymous. `GroupReadWrite::admits` follows a revoked membership on the next `identify`.
  - a **blank `totp_secret`** is no second factor: login completes in one step with no half-authenticated
    session, the profile page offers "Set up 2FA", a code against a blank `totp_pending` activates
    nothing, and a real secret still demands the second factor.
  - a **blank `sso_provider`** is a local account: password login works, the profile page offers the
    password form (not the SSO notice), 2FA enrolment is available and break-glass doesn't refuse it,
    while a real provider key still refuses password login (whitespace-only counts as blank too).
  - **lockout** (§5e): the decay arithmetic is unit-tested against explicit timestamps (locks only at
    the limit, the wait shrinks and then expires, `after = 0` disables, keys are folded and capped);
    over HTTP against the real tables, an account locks after the configured failures and then refuses
    even the **correct** password with `429` + `Retry-After` and creates no session, a made-up username
    gets a byte-identical response, case can't dodge the row, another account is unaffected, a
    successful login deletes the row, a **locked row is not touched by further attempts** (so the
    expiry can't be pushed out), the TOTP step shares the account's row (a correct code refused while
    locked, password login locked with it), **the authenticated checks — profile password and 2FA
    enrolment — are not limited at all** and write no rows, **CSRF-rejected posts spend no budget**,
    forwarded headers are ignored unless `trust_proxy` is set (a spoofed `X-Forwarded-For` is not
    counted; the peer is) and believed when it is (the forwarded hop is locked, another client behind
    the same proxy isn't, and the proxy's own address never is), a custom `client_ip` resolver overrides
    both, `net::client_ip` is unit-tested for chains / `X-Real-IP` / junk / IPv4-mapped collapsing, the
    app's handles
    share the account's row in **both** directions, deleting the row is the unlock, the address counter
    brakes credentials that name no account, an **whitelisted address is never locked or even written**
    however it arrives (plain v4, real v6, mapped, and a mapped *rule* against a plain client) while an
    address outside the list still locks, one client is **one row** whether it arrives mapped or plain,
    and `prune` drops expired rows while leaving live ones.
  - **re-authentication** (§5h): each of the four sensitive routes is driven with nothing, an empty
    factor, a wrong password and a wrong code — all `403`, with the account provably unchanged (2FA still
    on, the victim's old password still working, a pending enrolment still pending so the user can finish
    it) — and then with the right factor as the control. A **fresh TOTP code** is shown to re-authenticate
    in place of a password *and to be spent doing so*: the same code is then refused for a second action.
    An account with **no local factor** (an SSO manager) is shown to pass unchallenged, since refusing
    would lock SSO administrators out of the manager pages. `Auth::reauthenticate` /
    `can_reauthenticate` are tested directly too: right password, wrong password, right password in the
    wrong case, a code on an account with no 2FA, and the same code twice.
  - **password strength** (§5g): the default policy refuses a short password, a common value (including
    one doubled, or with a digit/symbol tail), a value containing a six-character run, and one containing
    the account's **own username** — on the self-service page *and* on a manager's reset, since the reset
    has no current-password check and would otherwise be the easier way round. Each rejection is checked
    to leave the old password working and the new one unstored. All three escapes are exercised: policy
    `None` accepts `hunter2`, a looser preset accepts ten characters while still screening common values,
    and a custom `password_check` closure replaces the policy and sees the username. The library helpers
    (`create_user` / `set_password`) are proved **not** to be governed by it, with a real login as the
    control.
  - **session lifetime & revocation** (§5f): an **idle** session is refused while still inside its
    absolute deadline, and an absolutely-expired one is refused despite a fresh `last_seen_at` — so
    neither clock can be mistaken for the other; using a session advances the idle stamp, a *recent*
    stamp is deliberately **not** rewritten (the lazy-refresh guarantee), and `session_idle_secs(0)`
    leaves an untouched session valid to its absolute deadline. Completing the second factor **changes
    the session id**: the half-authenticated token is deleted rather than elevated (the planted-cookie
    fixation path), and the new one identifies. A password change deletes every other session the user
    holds *and* rotates the caller's own id, leaving them a working replacement and other users
    untouched; a manager's reset deletes all of the target's; `POST /profile/sessions/revoke` deletes
    the caller's others while keeping the one in use, and is CSRF-checked like every unsafe route.
    `Auth::prune` collects idle-dead and expired rows and spares live ones.
  - **TOTP replay** (§5a): the same code is refused the second time — with the *same* wording as a wrong
    code, leaving the replaying session half-authenticated and the recorded step unmoved — while the
    matched step itself is unit-tested (the current step and both skew neighbours resolve to their own
    step, two steps out matches nothing), and disabling 2FA clears the guard so a re-enrolment isn't
    refused by a stale ceiling.
  - **CSRF** (§7): every unsafe auth route rejects a missing, cookie-less, header-only, mismatched, or
    blank token with `403` and no cookies set — checked with a *fully authorized manager session*, so
    only the token is missing — and nothing changes behind it; a `GET` form page issues the cookie
    (JS-readable, `SameSite=Strict`) and embeds the same value, the matching post succeeds, and login
    rotates the token; even a correct TOTP code is refused without one; logout clears the cookie; an
    `Authorization`-bearing request is exempt; and a configured cookie name means the default name no
    longer satisfies the check.
- **`auth/sso_tests.rs`** (feature `sso`) — the **OIDC callback**, against a **fake IdP** on a loopback
  port serving a discovery document, a JWKS and a token endpoint that mints ID tokens to order. The client
  side is the shipped code: real discovery over HTTP, real RSA signature verification. A live provider was
  rejected as the target — it can't run in CI, can't be asked for an expired token or one signed by the
  wrong key, and would make the suite depend on someone else's uptime, so the negative cases (the whole
  point) would go untested.
  A full sign-in is the positive control — session cookie set, account auto-registered as external with no
  local password, `last_login_at` stamped, groups the union of a username rule and a claim rule, the
  transaction cookie cleared — and against it: a callback with **no transaction cookie**, a forged /
  truncated / missing `state`, a missing `code`, a provider-reported `error`, and a transaction opened at
  one provider presented at **another**; an ID token **signed by a key outside the JWKS**, for another
  **audience**, from another **issuer**, **expired**, bound to another **nonce**, carrying an empty nonce,
  or absent entirely; a token missing the configured **username claim**, or carrying one that can't be an
  identity key (empty, blank, containing a space or tab); an unknown account with **auto-registration
  off**; a **disabled** account (with re-activation as the control); a **local password account**, which
  cannot be taken over through SSO; and an account **bound to a different provider**. Every rejection is
  checked for *no session cookie and no session row*, and for leaving the account's binding and stamps
  untouched. Two behaviours are asserted directly rather than assumed: the username claim resolves
  **case-insensitively** (no lower-cased duplicate account, still exactly one row), and **discovery is
  fetched once** and reused across sign-ins (counted at the fake IdP).
- **`crud/gate_tests.rs`** — the API enforcement point, over the real engine router with a stub
  `Accessor` that counts calls: every route authorizes with the right `Operation`, `NeedsLogin` → 401
  and `Denied` → 403 with a JSON error body, a rejected request **never reaches the backend** (so a
  gate checked after the write would fail, not pass quietly), an unregistered model is a plain 404,
  and the real `UserReadGroupWrite` preset over a real login cookie gives anonymous 401 everywhere,
  a non-member reads-only (403 on writes, zero backend writes), and a member full access. With
  `set_csrf` configured, writes without a matching `X-CSRF-Token` are `403` and never reach the backend
  (header alone, cookie alone, mismatch, blank), reads still need no token, a Bearer client is exempt,
  and `Table` emits the header logic only when the engine enforces CSRF.

Each group carries a positive control (a correct login, a correct TOTP code, an allowing gate) so a
mistake that breaks *everything* can't make the negatives pass vacuously.

**Not covered by tests** (and open in [TODO.md](../TODO.md)): TOTP recovery codes, which don't exist yet,
and re-authentication *through an identity provider* for SSO accounts (§5h's documented limit). What the
SSO suite deliberately doesn't reach: the *provider's* own behaviour (consent screens, refresh tokens,
userinfo),
and the browser-side redirect to the authorization endpoint, which is a `Location` header we assert but
don't follow.

## 11. Decisions (confirmed)

1. **Packaging** — ✅ a **feature-gated `auth` module** in the single `relativelylight` crate (authn +
   authz together). Usable without `crud`; `crud` optionally consults it.
2. **Identity** — ✅ cookie + **server-side session** (SeaORM `session` table).
3. **CSRF** — ✅ **double-submit token** (feature `csrf`, §7): always on for the module's own forms,
   `Crud::csrf(auth.csrf())` for the JSON API; `Authorization`-bearing requests exempt.
4. **authz config** — ✅ **one gate per model, explicit at registration**: `Crud::register(model,
   gate)`. Each gate is attached per model (no slug arg), is handed the request headers, and resolves
   the identity itself → a `Decision`. The trait lives in the always-on `authz` module (`Open` for
   ungated). **No middleware**: authn is on-demand `Auth::identify(&headers)`.
5. **Defaults** — ✅ hashing **argon2id**, admin group **`"admin"`** (configurable); presets
   `authz::Open` / `UserReadWrite::new(&auth)` / `UserReadGroupWrite::new(&auth, [..])` /
   `PublicReadGroupWrite::new(&auth, [..])` / `GroupReadWrite::new(&auth, [..])` / custom.
6. **2FA** — ✅ **TOTP** (RFC 6238) as a login second factor with self-service enrolment/disable and
   manager disable (§5a); PassKeys/WebAuthn remain future.
7. **SSO** — ✅ **OIDC** (feature `sso`) for Google / Okta / corporate, with username- and claim-based
   group mapping (union + reconcile) and optional per-provider auto-registration (§5b).
8. **Attempt limiting** — ✅ **DB-backed lockout** (429 + `Retry-After`) on the *unauthenticated*
   credential checks (§5e), by account name and by source address, both mandatory in `Auth::new`; the
   unlock is deleting the row in the admin panel. Authenticated checks are deliberately unlimited.
9. **Session lifetime** — ✅ **two clocks** (§5f): an absolute deadline (7 days) plus an idle timeout
   (8 hours, `session_idle_secs(0)` to disable), the id rotated on privilege gain, and a password change
   or manager reset revoking the user's other sessions.
10. **Client IP** — ✅ a **`trust_proxy` boolean**, one trusted hop, reading the **right-most**
    `X-Forwarded-For` entry (§4). A trusted-proxy CIDR list and RFC 7239 `Forwarded` were considered and
    rejected; stranger chains override with `Auth::client_ip`.

## 12. Open (later)

- Row-level authorization (per-row read checks / list filters — the gate seeing the row/query). Filed
  under *Transformative* in `TODO.md`: it reshapes the one trait apps implement by hand, so it needs
  **additional** `Authz` methods with defaults rather than a changed `authorize` signature, `Decision`
  must stay fieldless, and the list-filter half reaches into `ListQuery`/`Accessor` too. Deferred until a
  requirement arrives that an app can't meet in its own handler.
- PassKeys/WebAuthn, app-issued API tokens (extra principal source) — §8.
- Security hardening — **TOTP recovery codes** is the one that remains (see `TODO.md`); lockout (§5e),
  CSRF (§7), session lifetime/revocation (§5f), the password policy (§5g) and re-authentication before
  sensitive changes (§5h) have all landed, as has SSO discovery caching. Still open there: re-auth through
  the IdP for SSO accounts, and breached-password screening.
- Session store scaling: sessions are already shared across replicas (they're rows), so this is a
  performance question — the per-request read, and the lazy idle-refresh write — not a correctness one.
