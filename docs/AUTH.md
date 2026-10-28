# `relativelylight::auth` — authentication and authorization

Feature `auth`, usable without `crud`. It provides:

- users, groups and server-side sessions (SeaORM tables), argon2id password hashing;
- login/logout, a self-service profile page (password, TOTP 2FA, recovery codes) and a manager reset
  (§5, §5a, §5i);
- OIDC single sign-on with group mapping (feature `sso`, §5b);
- lockout on the unauthenticated credential checks (§5e), session lifetimes and revocation (§5f), a
  password policy (§5g), re-authentication before sensitive changes (§5h);
- double-submit CSRF (feature `csrf`, §7);
- per-model gate presets for `crud` (§6).

**There is no authn middleware.** `Auth::identify(&headers)` resolves the session cookie → user →
groups in one round-trip and returns `Option<Identity>`; a gate or a page handler calls it when it
needs to know who is asking, and nothing is injected into the request.

The pages are plain `<form>` posts with no JavaScript (the enrolment QR is an inline PNG). The library
renders fragments; the app wraps them with `Auth::login_shell` / `Auth::profile_shell`. See
[APP.md](APP.md) for the whole composition and [DESIGN.md](DESIGN.md#auth) for why it is built this
way.

## 1. How it fits

```
client → resolve_real_ip → [your request log] → [CORS] → router
                                                  ├─ crud UI       (each write → the model's Authz gate)
                                                  ├─ auth::routes  (/login, /logout, /profile…)
                                                  └─ your routes   (call Auth::identify, or not)
```

- **authn** is `Auth::identify(&headers) -> Option<Identity>`, called where it is needed — a gate, a
  page handler. Anything you want public (`/metrics`) simply never calls it.
- **authz** is one `Authz` gate per model (§6), handed the raw headers, so it can also accept a
  credential this crate knows nothing about, such as your own API tokens.
- **CSRF** is built into `auth`'s routes and the `crud` UI, and is a layer for your own routes (§7).

## 2. Features

| Feature | Adds | Pulls |
|---|---|---|
| (always) | `authz`: the `Authz` trait, `Operation`, `Decision`, `Open` | `http`, `async-trait` |
| `auth` | users, groups, sessions, login, profile pages, 2FA, lockout, gate presets | `sea-orm`, `argon2`, `totp-rs`, `askama`, cookies; implies `csrf` |
| `sso` | `auth::sso`: OIDC sign-in and group mapping (§5b) | `openidconnect`, `regex`, `base64` |

`auth` works without `crud`: `features = ["auth"]` for login alone, `["crud", "auth"]` for a gated
admin, plus `"sso"` for single sign-on.

## 3. Identity mechanism: server-side session

**A server-side session in an opaque cookie.** A random 256-bit id, backed by a row in
`auth_session`; deleting the row revokes it at once, which is what logout, "sign out everywhere" and
disabling an account rely on. A bearer token for your own API is the app's to issue and verify (§6).

Cookie attributes: `HttpOnly`, `Secure` (`secure_cookies(false)` for local http), `SameSite=Strict`,
`Path=/`, and a lifetime matching the session's (§5f).

**`SameSite=Lax`** (`Auth::same_site_lax(true)`, for the session and CSRF cookies together): under
`Strict`, a user following a link to the app from a mail, a chat or a ticket arrives without their
session and meets the login page. `Lax` sends the cookie on that top-level `GET` and still never on
a cross-site `POST`; every write needs the CSRF token either way. The cost is that a link elsewhere
to `/logout` signs the user out. `SameSite=None` is not offered.

## 4. Middleware the module provides

- **Real client IP — mandatory.** [`middleware::resolve_real_ip`](../relativelylight/src/middleware.rs)
  resolves the caller once, at the outermost layer, into a `RealIp` request extension that everything
  in the crate reads. `TrustProxy(false)` means the socket peer; `TrustProxy(true)` means the
  **right-most** `X-Forwarded-For` entry (the one your proxy appended), falling back to `X-Real-IP`
  and then the peer. `auth`'s login routes and the `crud` write handlers answer `500` if it isn't
  installed. For anything else — a CDN ahead of your proxy, `CF-Connecting-IP` — write your own
  middleware inserting `RealIp`; there is no hook.

  Get the flag right: unproxied with `TrustProxy(true)`, a caller chooses whose address gets locked
  out by sending a header; proxied with `TrustProxy(false)`, every user shares the proxy's address and
  a hundred failures lock the whole login form.
- **Request logging — yours.** The crate ships none and writes nothing to stdout or stderr.
  [`examples/audit`](../examples/audit/src/main.rs) has the dozen lines in two variants: the handler
  puts the caller in the response extensions for the layer to read (free), or the layer calls
  `Auth::identify` itself (one lookup per request). Neither can name a bearer-token caller, which is
  verified inside the handler; log that from the handler, where extracting `RealIp` gives the same
  address:

  ```rust
  async fn api_write(RealIp(ip): RealIp, headers: HeaderMap) -> Response {
      let Some(principal) = verify_api_token(&headers).await else {
          eprintln!("{ip} api-token rejected");
          return StatusCode::UNAUTHORIZED.into_response();
      };
      eprintln!("{ip} {principal} api-write ok");
      // …
  }
  ```
- **CORS — use `tower_http::cors::CorsLayer` directly.** Most deployments need none: every page and
  form post comes from one origin. A cross-origin browser client can't use the session cookie at all
  (it is `SameSite`), so it needs a token in an `Authorization` header, which is CSRF-exempt (§7). If
  you do allow a cross-origin caller, allow `content-type` and `x-csrf-token`, and never pair
  `allow_credentials(true)` with `Any` origins.

  ```rust
  let cors = CorsLayer::new()
      .allow_origin(["https://console.example.com".parse().unwrap()])
      .allow_methods([Method::GET, Method::POST])
      .allow_headers([header::CONTENT_TYPE, header::HeaderName::from_static("x-csrf-token")]);
  ```
- **CSRF** — §7. **Lockout** is not a layer: the login handlers brake themselves (§5e).

## 5. authn — users, sessions, login, passwords

The tables, all ordinary SeaORM entities an admin panel can register (§5j):

- **`auth_user`** — `id`, `username` (unique), `password_hash` (argon2id), `is_active`,
  `sso_provider` (§5b), the 2FA columns `totp_secret` / `totp_pending` / `totp_last_step` (§5a), and
  timestamps (§5c). Every creation path validates the username with `auth::valid_username`
  (non-empty, ≤ 254 bytes, no spaces or control characters); wire the same check into an admin form
  with `user_mm.field("username").validate_str(auth::valid_username)`.
- **`auth_group`** + **`auth_user_group`** (N:M) — group membership drives the gates.
- **`auth_session`** — the opaque id, `user_id`, `expires_at` (absolute deadline), `last_seen_at`
  (idle clock, §5f) and `awaiting_totp` (password accepted, second factor pending).
- **`auth_totp_recovery`** — hashed single-use recovery codes (§5i).
- **`auth_username_lockout`**, **`auth_ip_lockout`** — the lockout counters (§5e).

Deleting an account **cascades** to its sessions, recovery codes and memberships, whoever deletes it.
The lockout tables key on a submitted name and an address, so they have no foreign key.

### Database schema & migrations

`auth::migrate(&db)` creates the tables that don't exist yet — a bootstrap for a fresh database or the
examples, safe on every start. It never alters a table, so for anything long-lived drive the schema
with [`sea-orm-migration`](https://www.sea-ql.org/SeaORM/docs/migration/setting-up-migration/) and
take the DDL from `auth::table_create_statements`, so your tables match a fresh install:

```rust
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
struct InitAuth;

#[async_trait::async_trait]
impl MigrationTrait for InitAuth {
    async fn up(&self, m: &SchemaManager) -> Result<(), DbErr> {
        for stmt in relativelylight::auth::table_create_statements(m.get_database_backend()) {
            m.create_table(stmt).await?;
        }
        Ok(())
    }
}
```

`table_create_statements` describes the tables as they are now; when a release adds a column, the
[CHANGELOG](../CHANGELOG.md) says so and you add an `ALTER TABLE` migration for it.

**Login** (`POST /login`) verifies the argon2id hash in constant time, creates a session row and sets
the cookie; a failure re-renders the form with a generic error. **Logout** deletes the row and clears
the cookie.

**The profile pages.** `Auth::routes()` serves a self-service page at `GET/POST /profile` (change
your own password, given the current one; 2FA; recovery codes; sign out other sessions) and a
manager's reset at `GET/POST /profile/{id}` (set another user's password without theirs). Managing
someone else needs membership in a **profile-manager group** (default the admin group, `"admin"`;
override with `Auth::profile_managers([..])`); `/profile/{self}` redirects to `/profile`, and
`Auth::can_manage_others(&who)` tells you whether to show a reset link. The library renders the
fragment and your `Auth::profile_shell` wraps it, handed the `Identity` for your chrome. Both paths
write only the password hash and revoke sessions (§5f).

**Extending the profile page — `Auth::profile_extra`.** The password/2FA fragment is rarely the whole
of "my account": an app wants API tokens, notification preferences, a data export, a list of the
user's own things. Register a hook and it renders **below** the library's fragment, on the caller's
own `/profile` only (a manager's `/profile/{id}` doesn't get it — resetting someone's password is no
licence to touch their tokens):

```rust
use relativelylight::auth::ProfileSection;
use relativelylight::csrf::Csrf;

let auth = Auth::new(db, lockout).profile_extra(|s: ProfileSection| async move {
    let rows = my_api_tokens(&s.who.id).await;                 // `s.who` is the caller
    format!(r#"<hr><h2 class="h6">API tokens</h2>{rows}
               <form method="post" action="/api-token/new">{}
               <button class="btn btn-sm btn-outline-primary">Issue a token</button></form>"#,
            Csrf::hidden_input(&s.csrf))                        // `s.csrf` is *this request's* token
});
```

`s.csrf` is what makes the section able to hold a real form: the hook never sees the request, so it
could not mint a token itself, and a form without one is refused like any other POST (§7). The
section's *handler* is an ordinary route of yours — put
[`reauthenticate`](#5h-re-authentication-before-sensitive-changes) at the top of it if
the action is sensitive, which for an API token it is. `examples/auth` does exactly this: its
`POST /api-token/rotate` is reached from a `profile_extra` section and re-authenticates before it
does anything.

Three things it is not: it is **not** a way to replace the password/2FA fragment (that's
`profile_shell`, which wraps the whole page in your chrome), it is **not** rendered for managers
looking at someone else, and it is **not** run on the login page.

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

## 5a. TOTP two-factor authentication

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

It stops a spent code being reused by someone who also has the password (a shoulder-surf, a screen
share). It does nothing against real-time phishing, where a proxy relays the code once; that needs a
phishing-resistant factor such as WebAuthn ([TODO.md](TODO.md#auth)).

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

**Recovery codes.** A lost authenticator is handled by single-use recovery codes, issued with the
enrolment — see §5i.

**Disable.** `POST /profile/totp/disable` turns off the caller's own 2FA. A **manager** (a
profile-manager group, §5) can disable *another* user's 2FA via `POST /profile/{id}/totp/disable`
(shown on the `/profile/{id}` page) — but managers can never *set up* 2FA for someone else, since
enrolment needs that user's device. Disabling clears `totp_secret`, `totp_pending` **and**
`totp_last_step`.


## 5b. SSO / OpenID Connect (feature `sso`)

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
callback's own account check). `auth::normalize_blank_user_columns(&db)` rewrites blank
`sso_provider` / `totp_secret` / `totp_pending` values to `NULL` if you want the column tidy;
idempotent, and optional, since every reader treats a blank as absent.

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

A **disabled** account (`is_active = false`) is refused before anything is written, as password
login refuses it.

**Discovery is cached** per provider for an hour, with the signing keys it carries, so a sign-in costs
no extra round trips and looping on `/sso/{key}/login` can't flood your provider. An hour is safe for
key rotation: providers publish a new key well before retiring the old one.

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


## 5c. Lifecycle timestamps

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

## 5d. Write observer — audit hook

`auth` fires the shared [`WriteObserver`](../relativelylight/src/observe.rs)
([CRUD.md](CRUD.md#write-observer-audit)) from its own writes, which happen outside the `crud`
engine:

| Action | `source` |
|---|---|
| your password change (`POST /profile`), new recovery codes, signing out other sessions | `auth-profile` |
| a manager's reset (`POST /profile/{id}`) | `auth-admin` |

Each event carries the headers, the resolved `client_ip`, **`actor`** (the username who acted — read
it rather than calling `identify`, since a password change has already rotated the caller's session),
and an `after` describing what changed with no secret in it (`{"password_changed": true}`). Logins
and 2FA changes don't fire yet ([TODO.md](TODO.md#auth)); `last_login_at` records logins. Share one
`Arc` with `Crud::on_write` so a single sink covers both:

```rust
let audit = Arc::new(MyAuditSink::new(db.clone()));
let auth = Auth::new(db.clone(), lockout).on_write(audit.clone());
let mut crud = Crud::new(db);
crud.on_write(audit.clone());
```

The app owns the audit table and its retention. [`examples/audit`](../examples/audit/src/main.rs)
prints a line per committed write next to a request log built on the same `RealIp`.

## 5e. Lockout: the brute-force brake

The brake in front of the **unauthenticated** credential checks: one counter per account name and one
per source address (`auth::lockout::{UsernameLockout, IpLockout}`), each in its own table. The rows are
durable and shared, so a restart or a second replica doesn't hand an attacker a fresh budget.

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
| `POST /profile` (current password) | **not limited** | the caller is *authenticated*: that's session theft, whose mitigations are short TTLs and re-authentication (§5h) — and counting it would let a stolen session lock the real user out of logging in |
| `POST /profile/totp` (enrolment code) | **not limited** | authenticated, and the code guessed is the caller's *own* pending secret |
| `POST /profile/{id}` (manager reset) | **not limited** | verifies no secret; gated by group membership instead |

**Configuration is mandatory** — it is an argument to `Auth::new`, not a builder call, so there is no
way to end up with an unbraked login by forgetting one:

```rust
// `Lockout` is #[non_exhaustive]: build from the defaults, which are exactly the values below.
let auth = Auth::new(db, Lockout::default()
    .accounts(10, 900)     // failed logins per account before it locks, and for how long (0 = off)
    .addresses(100, 900)); // …and per source address (0 = off)

// The fields are public too, so assignment works where a builder would read worse:
let mut lockout = Lockout::default();
lockout.ip_whitelist = relativelylight::net::parse_nets(&cfg.office_ranges);
```

`*_after: 0` switches a counter off completely — nothing is read, nothing is written. A `*_duration_secs`
of `0` is *not* the way to do that: it is clamped to 1 second, so rows are still written and the lock
just expires immediately. The two windows are independent on purpose (an address is a coarser subject
than an account, so it usually deserves a different one). The address budget is far looser than the
account one because a locked address turns away *valid* callers too, which matters when users share
one (CGNAT, an office NAT).

**Who is the client?** The per-address half uses the `RealIp` that `middleware::resolve_real_ip`
resolved (§4). Use the same value for your own logging, audit rows and limits, so a failed login and a
failed API call from one client land on the **same** row (an IPv4-mapped `::ffff:a.b.c.d` and a plain
`a.b.c.d` are canonicalized to one key).

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

**The trade-off.** Someone who knows an account name can keep it locked by failing on purpose. That is
why the lock is short, lifts on its own, and can be cleared from the admin panel; the alternative,
progressive delays, holds a server task open per attempt.

## 5f. Session lifetime & revocation

A session is a row, so revoking one is a `DELETE` (§3).

**Two clocks, both enforced at `identify`.**

| clock | column | configured by | default | what it bounds |
|---|---|---|---|---|
| absolute | `expires_at` | `Auth::session_ttl_secs` | 7 days | how long a session can *ever* live, however busy |
| idle | `last_seen_at` | `Auth::session_idle_secs` | 8 hours | how long an *unused* session survives |

The idle clock is the one that bounds a stolen cookie: without it an attacker who lifts a cookie has the
full absolute window, whether or not the victim ever comes back. `session_idle_secs(0)` switches it off
leaving only the absolute deadline. The absolute deadline always wins — a session used a second
ago but past `expires_at` is dead.

`last_seen_at` is refreshed **lazily**: a read only writes when the stamp is more than a minute stale.
That matters because `identify` is called once per gated model — an `Admin` page with five tables
resolves the caller five times — so an eager refresh would turn one page render into five writes.

**`Auth::identify(&headers) -> Option<Identity>` does not change**, and shouldn't: it stays a cheap call
that needs no response to write into. Everything that changes a session **id** happens inside a POST
handler that already owns its response.

**Rotation on privilege gain.** Password login always mints a new row with a server-generated id, and
confirming the second factor issues **another new id** and deletes the half-authenticated one. So a
session cookie an attacker planted in the victim's browser (cookie-tossing, an XSS) is never elevated
by the victim's own login. The CSRF token rotates with it.

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

## 5g. Password strength

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

**Both surfaces or neither.** `Auth` covers its own pages; the admin UI's writes are a separate
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

## 5h. Re-authentication before sensitive changes

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

`POST /profile` (your own password change) asks for the current password anyway.
`POST /profile/sessions/revoke` is **not** re-authenticated: it only removes access, and a user racing
to evict an intruder shouldn't be slowed down.

**Either factor.** A `current_password` or a `totp_code` satisfies it. A **fresh code is preferred** when
the account has 2FA — it proves presence, where a password may have been filled in by the browser for
whoever is sitting there — and a code accepted here is **spent** (§5a), so one captured code can't wave
through both a sensitive action and a login. Enrolment is the one asymmetric case: a *first* enrolment has
no active secret to check a code against, so the password is the factor; a re-enrolment can use either.

**An account with no local factor passes.** An SSO account has neither password nor local 2FA, so there is
nothing to ask it for, and refusing would lock every SSO administrator out of the manager pages
permanently. Their assurance is whatever the IdP gave them; re-authenticating through the provider is
[open work](TODO.md#auth). The same holds for a local account whose password is blank, which already
can't log in.

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

**Per request, not a window.** There is no "you confirmed five minutes ago" grace period, which would
reopen exactly the window a stolen session needs; resetting two users means confirming twice.

## 5i. TOTP recovery codes

The answer to "my phone is gone". Without them, an enrolled user who loses their authenticator can only
be let back in by a manager disabling their 2FA (§5a) — workable for staff with an IT department, useless
for everyone else, and an availability problem the moment §5h means a live session can no longer simply
switch 2FA off.

**Ten single-use codes**, issued automatically **with** the enrolment and shown once. `auth::recovery`
owns them: `issue`, `consume`, `remaining`, `clear`, plus the `entity` (table `auth_totp_recovery`).

- **Use:** at `POST /login/totp`, in the `recovery_code` field instead of the 6-digit `code` — no separate
  route. A recovery login lands on **`/profile`** rather than `/`, because the next thing that user needs
  is to re-enrol or generate a fresh set. The session id rotates exactly as it does for a code (§5f).
- **Spent on use**, so each code works once; the row is *marked* rather than deleted, which keeps "a
  recovery code was used" visible afterwards.
- **Regenerate** from the profile page (`POST /profile/totp/recovery`), which is **re-authenticated**
  (§5h) — a new set is a new way into the account, so an intruder holding a session must not be able to
  mint one. Issuing a set invalidates the previous one, which is what makes regeneration the right
  response to "I think my codes leaked".
- **Destroyed when 2FA is turned off**, self-service or by a manager: they are a way past a second factor,
  so without one they would just be a weaker second password — and a later re-enrolment must not inherit
  a set the user threw away with their old phone.
- The profile page shows how many are unused, and says so more loudly at ≤ 3 and at 0.
- 2FA stays **on** after a recovery login. The code got them in; it didn't decide their factor policy.

**Hashed with SHA-256, not argon2 — deliberately.** Codes are machine-generated with ~49 bits of entropy
(10 characters from a 30-symbol Crockford-style alphabet, so nothing reads as `0`/`1`), which is exactly
the case argon2 is *not* for: no attacker enumerates a 49-bit space however cheap the hash. What a slow
hash would cost is real and paid by the defender — a submitted code must be matched against the user's
whole set, so up to ten argon2 verifications (≈190 MiB transient, most of a second) on the
**unauthenticated** login path, per attempt. A single SHA-256 makes it one indexed equality lookup: O(1),
no comparison loop, and nothing whose duration depends on how far into the set the match was. The hash is
domain-separated by user id, so a row lifted from one account cannot be replayed against another.

**A recovery code does not satisfy re-authentication** (§5h). It gets you *in*; it does not authorise
entrenching. Otherwise one leaked code would be both a login *and* a licence to remove the second factor
it just bypassed — and for re-auth the password already covers the lost-authenticator case.

**Guessing is braked** by the same per-account counter as a wrong TOTP code (§5e). An **empty**
submission — no code and no recovery code — is refused *without* counting, since presenting nothing is
not a failed check, and counting it would let a stray double-submit or a forged post grief the real user's
login.

**Schema.** `auth_totp_recovery` is in `table_create_statements`, so an app with its own migrations needs
a step for it. Don't register the entity in an admin panel: every row is a hash of a credential, and there
is nothing an operator can usefully do to one that the "generate new codes" button doesn't do properly.

## 5j. Where accounts come from — there is **no registration page**

This module ships login, not sign-up, and that is a decision rather than a gap. Who may join, what is
verified before they do (an email? an invite? a payment? a manager's approval?), and what an account is
worth on arrival are product questions with no defensible default — a library that answered them would
be wrong for most apps and, in the wrong deployment, wrong in the direction of letting strangers in.

So an account comes into being in exactly four ways, all of them the app's own call:

| Route | Call | Typical use |
|---|---|---|
| an operator creates it | the **accounts panel** (below), or `auth::create_user(db, user, pw)` | the normal one |
| SSO creates it on first login | per-provider **auto-registration** (§5b) | a corporate IdP owns the roster |
| the app's boot seeder | `auth::make_admin(db, group, user, pw)` — idempotent | the first admin |
| break-glass, from a shell | `auth::reset_admin_access(db, group, user, pw)` behind a CLI flag | nobody can get in |

The last two are deliberately exempt from the password policy (§5g), which governs *typed* input only —
otherwise a deployment could be left with no way to set a first password at all.

**Want public signup anyway?** Write the page: a `crud::ui::Form` over `auth_user` (or a hand-written
form) posting to a route of yours that validates whatever you require and calls `create_user` +
`add_to_group`. Doing it in the app is what lets you put an invite token, a rate limit or an email
round trip in front of it — and it keeps that policy visible in your code rather than buried in a
library default.

### The accounts panel

`auth`'s tables are ordinary SeaORM entities, so an operator's screen is the ordinary admin over them —
no bespoke user-management UI, and no second permission model. [`examples/auth`](../examples/auth/src/main.rs)
builds one in about sixty lines; the parts that matter:

```rust
let mut user  = MetaModel::new(auth::user::Entity);
let mut group = MetaModel::new(auth::group::Entity);

user.field("password_hash").password();          // write-only, argon2 on write, never read back
user.field("password_hash")                       // the *same* policy Auth applies to /profile
    .validate_str(validate::optional(Box::new(validate::password(policy))));
for f in ["totp_secret", "totp_pending", "totp_last_step"] { user.field(f).hidden = true; }

user.label_column("username");
group.label_column("name");
user.relate(&group);                              // ← the line that makes the panel *useful*
group.relate(&user);

crud.register(user,  Arc::new(GroupReadWrite::new(&auth, [ADMIN_GROUP])));
crud.register(group, Arc::new(GroupReadWrite::new(&auth, [ADMIN_GROUP])));
```

Four things are load-bearing:

1. **`user.relate(&group)`** — `auth_user_group` is an N:M junction and is never registered as a model
   of its own, so without this declaration the panel can create an account and cannot put it in a
   group. Since the gate checks *group membership*, that is a screen that can make users who can do
   nothing. (It also gives you the reverse view: a group's Members picker.)
2. **`GroupReadWrite`, not `UserReadGroupWrite`** — reads included. A list of accounts is not
   something a logged-in stranger should be able to enumerate, and `render_for` is where that is
   enforced: a non-admin gets `403`, not a page with the buttons greyed out.
3. **`password_hash().password()` plus the policy** — wire the policy into `Auth` *and* this form, or
   the form becomes the way around it (§5g).
4. **Hide the TOTP columns.** The secret and the pending secret are credentials; `totp_last_step` is
   the replay guard, and hand-editing it either lets a code be replayed or locks the user out of their
   own authenticator. 2FA is managed from `/profile`, never from a CRUD form. **Never register
   `auth::recovery::entity`** at all — every row of it is a credential hash.

Register `lockout::username_entity` / `lockout::ip_entity` in the same panel (§5e) and the unlock
becomes an ordinary gated, CSRF-checked, audited `DELETE` rather than a bespoke endpoint.

What the panel deliberately cannot do: **enrol or reset someone's 2FA** (a manager can only *disable*
it, from `/profile/{id}`, under re-auth — §5h), and **reset an SSO account's password** (there is none
to reset — §5b).

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
`200`/`401`/`403`; a page handler serves `NeedsLogin` as a redirect to `Auth::login_path`. The gate
decides per model, not per row.

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

**Enforcement.** `crud::ui`'s `render_for` asks the gate before reading and `submit` before writing,
answering **401** (`NeedsLogin`) or **403** (`Denied`) before the database is touched. `render_for`
also hides the controls the gate would refuse, and a hidden control's write is refused too. A handler
of yours that calls `Engine` directly must call `Engine::decide` first.

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
let mut crud = Crud::new(db);
crud.register(post_mm, content.clone());                          // logged-in read, group write
crud.register(user_mm, GroupReadWrite::new(&auth, ["admin"]));    // admins only (read + write)
crud.register(healthcheck_mm, Open);                              // ungated

// 3. compose — the app owns the root router. No middleware, no wrapping.
let engine = Arc::new(crud.into_engine());
let app = axum::Router::new()
    .merge(auth.routes())              // /login, /login/totp, /logout, /profile…
    .route("/", get(admin_page))       // the app's own (gated) pages/handlers
    ;                                  // your own gated admin routes (see CRUD.md § Quick start)

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

The one thing the app must **schedule** is housekeeping: `auth.prune()` on its own loop (§5e) — the
crate spawns no tasks.

## 7. CSRF (double-submit token, feature `csrf`)

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
- the **`X-CSRF-Token` header** — for `fetch`/XHR clients of your own.

**Where it's enforced.**

| Surface | Enforcement | Rejection |
|---|---|---|
| `Auth::routes()` — `/login`, `/login/totp`, `/profile*` | **always on** | `403` + a bare "Security check failed" page |
| the `crud` admin UI's writes | **opt-in**: `crud.csrf(auth.csrf())` | `403`, before the gate or the database |
| your own unsafe routes | **`csrf::enforce`** as a layer, or call `Csrf::verify` yourself | the shared page (see below) |

On the auth routes the check runs **first** — before the password comparison, before any DB work — so a
forged post costs nothing and can't be used as an argon2 amplifier. Same in the engine: the CSRF check
precedes the gate, so a forged write never reaches a session lookup, let alone the backend. Safe methods
(GET/HEAD, i.e. every read) need no token. A page render **issues** the cookie if the request has none
(`Csrf::ensure`), and login / 2FA-completion **rotate** it along with the session; logout clears it.

**`Authorization`-bearing requests are exempt** — an API credential isn't ambient, so a cross-site
request can't borrow it and there's nothing to protect. Your own token-authenticated API routes need
no CSRF token.

**A layer for your own routes.** Rather than calling `Csrf::verify` in every handler, put
`csrf::enforce` in front of the ones that need it:

```rust
use axum::middleware::from_fn_with_state;

let guarded = Router::new()
    .route("/account/delete", post(delete_account))
    .route("/api-token/rotate", post(rotate_token))
    .with_state(state)
    .layer(from_fn_with_state(auth.csrf(), relativelylight::csrf::enforce));
```

Pass the **same** `auth.csrf()` handle, or the cookie names won't agree. Keep it on a `Router` holding
only the routes you want guarded — it refuses *every* unsafe request that arrives without a token, which
is the point, and so does not belong in front of an endpoint meant for non-browser clients (those are
exempt anyway, being `Authorization`-bearing).

It checks, in order: safe methods pass; `Authorization`-bearing requests pass; the `X-CSRF-Token` header;
and failing that, for `application/x-www-form-urlencoded` bodies **under 64 KiB**, the `_csrf` field — the
body is buffered, checked, and handed to the handler intact, so a plain MPA `<form>` post needs nothing
from the handler. A **multipart** body is deliberately *not* parsed (an upload shouldn't be buffered to
find a token): send the header there, or check it in the handler. `examples/auth` guards its
`POST /api-token/rotate` this way.

**Your own rejection page.** The built-in `403` is shell-less and static on purpose: a rejected request
hasn't proved it came from your site, so nothing about the caller is rendered and no cookies are set.
`Auth::csrf_rejection(|| ..)` (or `Csrf::on_reject`) replaces it with your own, and because the closure
travels on the `csrf()` handle, one setting covers the library's forms **and** `csrf::enforce` on your
routes. Keep the same discipline: don't name the user, don't set cookies, stay a `403`. It deliberately
does **not** apply to a hand-written API of yours answering a machine.

**Wiring it up.** `auth`'s own pages need nothing. For the admin UI's writes, hand the engine the same
checker so both surfaces share one cookie:

```rust
let auth = Auth::new(db.clone(), Lockout::default()).secure_cookies(false); // configure Auth fully first
let mut crud = Crud::new(db);
crud.register(post, gate);
crud.csrf(auth.csrf());          // every rendered form now carries `_csrf`, and writes check it
```

`Table`/`Form`/`Admin` then render a hidden `_csrf` input in every form they emit, and `submit` checks
it on every write (create, update, both deletes, CSV import) — nothing to pass in. The **cookie must
already exist** when the page renders: `auth`'s login issues it. An app-owned page that posts to its own
route does the two halves itself:

```rust
let (token, set) = auth.csrf().ensure(&headers);          // → hidden input / JS-readable cookie
let jar = if let Some(c) = set { jar.add(c) } else { jar };
// …and in the POST handler:
if !auth.csrf().verify(&headers, form.csrf.as_deref()) { return StatusCode::FORBIDDEN.into_response(); }
```

`crud::ui` reads the token from the cookie at request time rather than baking it into the fragment,
so a fragment rendered before a rotation (or cached) can't go stale.

A **co-hosted** app sharing the host must use a distinct `csrf_cookie_name` (cookies aren't
port-scoped), exactly as with the session cookie.

## 8. Examples

- **[`examples/auth`](../examples/auth/src/main.rs)** — `auth` up close: the login page, a `/secret`
  page gated by `identify`, the self-service `/profile` with 2FA in the app's chrome, an accounts panel
  at `/admin` (§5j), lockout tuned down to 5 failures per account so it is easy to trip, and
  `POST /api-token/rotate` — an app's own sensitive action behind `csrf::enforce` and
  `Auth::reauthenticate` (§5h, §7), reached from a `profile_extra` section. SSO is wired in when
  `SSO_GOOGLE_CLIENT_ID` / `SSO_GOOGLE_CLIENT_SECRET` are set. `--set-admin-pw` is the break-glass path.
- **[`examples/adminpanel`](../examples/adminpanel/src/main.rs)** — a login-gated `crud::ui::Admin`
  with CSRF on, content models behind `UserReadGroupWrite` (everyone reads, `admin` writes), the
  account tables behind `GroupReadWrite` and shown only to managers, and the password policy wired into
  both `Auth` and the account form. Logins: `admin` and `editor` (read-only).
- **[`examples/audit`](../examples/audit/src/main.rs)** — one observer on both `Auth` and `Crud`, and a
  request log built on `RealIp`.

## 9. Tests — the negative paths

The rejection paths are pinned by `cargo test --all-features`, which drives the shipped routers over
in-memory SQLite:

- **`auth/security_tests.rs`** — sessions (expired, idle, half-authenticated, deactivated, forged and
  bearer-presented tokens all resolve to anonymous), login, TOTP and its replay guard, recovery codes,
  the profile and manager pages, re-authentication, the password policy, lockout (including the proxy
  flag and the whitelist), session rotation and revocation, CSRF on every unsafe route, and the gate
  presets as a matrix of caller × operation.
- **`auth/sso_tests.rs`** (feature `sso`) — the OIDC callback against a **fake IdP** on a loopback
  port (real discovery, real RSA signatures): missing or forged state, wrong key, audience, issuer,
  nonce, an expired token, missing claims, auto-registration off, disabled, local and
  other-provider accounts.
- **`crud/gate_tests.rs`** — every UI write asks its gate with the right `Operation` and a refused one
  never reaches the backend; CSRF on every write.

Each group has a **positive control** — a correct login, a valid code, an allowing gate — so a change
that breaks everything can't make the negatives pass vacuously.
