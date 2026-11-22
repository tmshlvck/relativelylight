# `relativelylight::auth` — authentication and authorization

Always compiled, beside the admin it gates. It provides:

- users, groups and server-side sessions (SeaORM tables), argon2id password hashing;
- login/logout, a self-service profile page (password, TOTP 2FA, recovery codes) and a manager reset
  (§5, §5a, §5i);
- OIDC single sign-on with group mapping (feature `sso`, §5b);
- lockout on the unauthenticated credential checks (§5e), session lifetimes and revocation (§5f), a
  password policy (§5g), re-authentication before sensitive changes (§5h);
- API keys for machine endpoints, each acting as its owner, with self-service on `/profile` (§5k);
- passkeys: sign-in without a password, a second factor, re-authentication (feature `passkeys`, §5l);
- a sign-in policy as one minimum assurance level, and "password change required" (§5m);
- double-submit CSRF (always on, §7);
- per-model gate presets for `crud` (§6).

**There is no authn middleware.** `Auth::identify(&headers)` resolves the session cookie → user →
groups in one round-trip and returns `Option<Identity>`; a gate or a page handler calls it when it
needs to know who is asking, and nothing is injected into the request.

The pages are plain `<form>` posts with no JavaScript (the enrolment QR is an inline PNG). The library
renders fragments; the app wraps them with `Auth::login_shell` / `Auth::profile_shell`. See
[APP.md](APP.md) for the whole composition and [DESIGN.md](DESIGN.md#auth) for why it is built this
way. This file is the usage guide; the reasoning behind each security rule — what it defends
against, and why it is that way — is in [AUTH-SECURITY.md](AUTH-SECURITY.md); the rules only the app
can keep are listed in [SECURITY.md](SECURITY.md).

## 1. How it fits

```
client → resolve_real_ip → [your request log] → [CORS] → router
                                                  ├─ crud UI       (each write → the model's Authz gate)
                                                  ├─ auth::routes  (/login, /logout, /profile…)
                                                  └─ your routes   (call Auth::identify, or not)
```

- **authn** is `Auth::identify(&headers) -> Option<Identity>`, called where it is needed — a gate, a
  page handler. Anything you want public (`/metrics`) simply never calls it.
- **API keys** are `Auth::identify_key(token, ip)`, called by the machine endpoints that accept one
  (§5k). `identify` never accepts a key.
- **authz** is one `Authz` gate per model (§6), handed the raw headers, so it can also accept a
  credential this crate knows nothing about.
- **CSRF** is built into `auth`'s routes and the `crud` UI, and is a layer for your own routes (§7).

<a id="the-paths-auth-claims"></a>**The paths `auth` claims.** Fixed, but for the `/sso` prefix; everything
else is the app's ([APP.md → Your URL namespace](APP.md#your-url-namespace)):

| Mounted by | Paths |
|---|---|
| `Auth::routes()` | `/login`, `/login/totp`, `/logout`; `/profile`, `/profile/totp`, `/profile/totp/disable`, `/profile/totp/recovery`, `/profile/sessions/revoke`, `/profile/api-keys…` (with `Auth::api_keys`); `/profile/{id}`, `/profile/{id}/totp/disable`, `/profile/{id}/passkeys/remove` |
| `Auth::routes()`, feature `passkeys` | `/login/passkey`, `/login/passkey/finish`, `/login/totp/passkey`, `/profile/passkeys…`, `/profile/password/remove`, `/auth/passkey.js` |
| `Sso::routes()` | `/sso/{key}/login`, `/sso/{key}/callback`, `/sso/{key}/reauth`; the prefix is `Sso::base_path` |

## 2. Features

`auth` is always compiled, with the admin it gates ([why](DESIGN.md#principles)). Two features add
to it:

| Feature | Adds | Pulls |
|---|---|---|
| `sso` | `auth::sso`: OIDC sign-in and group mapping (§5b) | `openidconnect` |
| `passkeys` | passkeys: sign-in, a second factor, re-authentication, the profile section (§5l) | `webauthn-rs` |

The gate trait itself (`authz`: `Authz`, `Operation`, `Decision`, `Open`) is separate from `auth`, so
an app can write a gate of its own over any credential.

## 3. Identity mechanism: server-side session

**A server-side session in an opaque cookie.** A random 256-bit id, backed by a row in
`auth_session`; deleting the row revokes it at once, which is what logout, "sign out everywhere" and
disabling an account rely on. The session is the only credential that opens the UI. A machine
endpoint can take an **API key** instead (§5k), but only where the app checks for one.

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
- **Request logging — yours.** The crate ships none and writes nothing to stdout or stderr; errors
  it keeps from the caller reach you through `Auth::on_error` (§5d).
  [`examples/audit`](../examples/audit/src/main.rs) has the dozen lines in two variants: the handler
  puts the caller in the response extensions for the layer to read (free), or the layer calls
  `Auth::identify` itself (one lookup per request). Neither can name an API-key caller, which is
  verified inside the handler (§5k); the handler names it, as the example's `/api/whoami` does, or
  logs a line itself, where extracting `RealIp` gives the same address:

  ```rust
  async fn api_write(State(app): State<App>, RealIp(ip): RealIp, headers: HeaderMap) -> Response {
      let token = auth::bearer_token(&headers).unwrap_or_default();
      let Ok(caller) = app.auth.identify_key(token, ip).await else {
          eprintln!("{ip} api key rejected");
          return StatusCode::UNAUTHORIZED.into_response();
      };
      eprintln!("{ip} {} key {} api-write ok", caller.identity.username, caller.key_id);
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
  `sso_provider` (§5b), the 2FA columns `totp_secret` / `totp_pending` / `totp_last_step` (§5a),
  `passkey_handle` (the WebAuthn user handle, set at the first passkey enrolment),
  `password_changed_at` / `must_change_password` (§5m), and timestamps (§5c). Every creation path validates the username with `auth::valid_username`
  (non-empty, ≤ 254 bytes, no spaces or control characters), the accounts panel's
  `user::meta_model` included.
- **`auth_group`** + **`auth_user_group`** (N:M) — group membership drives the gates.
- **`auth_session`** — the opaque id, `user_id`, `expires_at` (absolute deadline), `last_seen_at`
  (idle clock, §5f), `awaiting_totp` (password accepted, second factor pending), and `method` /
  `passkey_class`: how the session was authenticated (`password`, `password+totp`,
  `password+recovery`, `password+passkey`, `passkey`, `passkey+totp`, `passkey+recovery`, `sso`,
  `sso+totp`, `sso+recovery`) and the class of the passkey when one was used. The session's level
  (§5m) is read from these. Empty for a row from
  before the column existed.
- **`auth_totp_recovery`** — hashed single-use recovery codes (§5i).
- **`auth_api_key`** — hashed API keys (§5k).
- **`auth_passkey`**, **`auth_webauthn_challenge`** — passkeys and the WebAuthn ceremonies in flight
  (§5l). Both exist with or without the `passkeys` feature. Expired challenges are pruned by
  `auth.prune()`.
- **`auth_username_lockout`**, **`auth_ip_lockout`** — the lockout counters (§5e).

Deleting an account **cascades** to its sessions, recovery codes, API keys, passkeys, challenges and
memberships, whoever deletes it.
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

**The profile pages.** `Auth::routes()` serves the caller's own page at `GET/POST /profile` (their
password, passkeys, 2FA, recovery codes, sessions, API keys) and a manager's **credentials page** at
`GET /profile/{id}`: reset another user's password without theirs (which signs them out
everywhere, §5f), disable their 2FA, remove their passkeys, each confirmed with the manager's own
factor (§5h). Managing someone else needs membership in a **profile-manager group**, which is the
admin group (`Auth::admin_group`, default `"admin"`) unless `Auth::profile_managers([..])` names
others; `Auth::can_manage_others(&who)` answers it. `/profile/{self}` redirects to `/profile`. The
library renders the fragment and your `Auth::profile_shell` wraps it, handed the `Identity` and the
request's `http::request::Parts` for your chrome.

**The profile page is cards in columns**, one on a phone and two on a wide screen
([why](DESIGN.md#auth)):
- the password (or, for an SSO account, the provider);
- passkeys (§5l) and two-factor;
- recovery codes, when 2FA is on;
- other sessions, and API keys (§5k).

One message, at the top, answers whatever was just done. Your `profile_shell` gives it a wide
column, not a narrow card of its own.

**Your own cards — `Auth::profile_extra`.** "My account" is rarely only sign-in: an app wants
preferences, a webhook secret, a data export, a list of the user's own things. The hook returns your
cards, drawn with `auth::profile_card(title, body)` so they look like the library's, and they follow
its own on the caller's own `/profile`. A manager's `/profile/{id}` doesn't get them — resetting
someone's password is no licence to touch their settings — and neither does a restricted session
(§5m):

```rust
use relativelylight::auth::{self, ProfileSection};
use relativelylight::csrf::Csrf;

let auth = Auth::new(db, lockout).profile_extra(|s: ProfileSection| async move {
    let zone = time::picker(&Tz::from_headers(&s.headers));   // a preference
    let form = format!(r#"<form method="post" action="/webhook-secret/rotate">{}{}
        <button class="btn btn-sm btn-outline-danger">Rotate the secret</button></form>"#,
        Csrf::hidden_input(&s.csrf),   // `s.csrf` is *this request's* token
        s.reauth_fields);              // the caller's confirm-it's-you inputs
    auth::profile_card("Preferences", &zone) + &auth::profile_card("Webhook secret", &form)
});
```

What the hook is handed, in `ProfileSection`:
- **`s.csrf`** is what makes a card able to hold a real form. The hook can't mint a token itself, and
  a form without one is refused like any other POST (§7).
- **`s.headers`** are the request's headers, for a card that reads a preference cookie, such as a
  [timezone picker](TIME.md#3-the-picker-and-the-first-visit) showing the caller's current zone.
- **`s.reauth_fields`** are the caller's confirm-it's-you inputs (password, code, passkey), sharing
  the page's passkey challenge.

A card's *handler* is an ordinary route of yours. Put
[`reauthenticate_with`](#5h-re-authentication-before-sensitive-changes) at the top of it if the
action is sensitive, as it is for a secret. Answer with **`Auth::profile_reply`**, as the library's
own cards do: the profile page again, with one message at the top (`Ok` a success, `Err` an error).

```rust
async fn rotate(State(app): State<App>, req: Parts, Form(f): Form<RotateForm>) -> Response {
    let Some(who) = app.auth.identify(&req.headers).await else { return Redirect::to("/login").into_response() };
    if let Err(msg) = app.auth.reauthenticate_with(&who, &f.reauth).await {
        return app.auth.profile_reply(&req, StatusCode::FORBIDDEN, Err(&msg)).await; // nothing changed
    }
    // … rotate …
    app.auth.profile_reply(&req, StatusCode::OK, Ok("Webhook secret rotated.")).await
}
```

`examples/auth` has both cards above.

### Admin helpers — who may re-open an account

Three helpers with deliberately different blast radii
([why](AUTH-SECURITY.md#the-admin-helpers)):

| helper | creates? | password | `is_active` | TOTP 2FA | group |
|---|---|---|---|---|---|
| `set_password(db, user, pw)` | ❌ `Err` if unknown | set | untouched | untouched | — |
| `make_admin(db, group, user, pw)` | ✅ (active) | set | untouched | untouched | ensured |
| `reset_admin_access(db, group, user, pw)` | ✅ (active) | set | **→ true** | **cleared** | ensured |

- **`set_password`** is a *reset*, not an upsert: an unknown username is an error (creating accounts is
  `create_user`'s job). A **disabled** account gets the new
  password and stays disabled; 2FA stays on; an SSO account still refuses password login. This is what
  `POST /profile` and `POST /profile/{id}` call.
- **`make_admin`** is the **boot-time seeder** (what the examples call on every start): idempotent, and
  it never strips an existing admin's `is_active` flag or authenticator.
- **`reset_admin_access`** is **break-glass recovery**, for an operator-invoked `--set-admin-pw` flag:
  it re-activates the account and **discards its TOTP enrolment**, its recovery codes and the replay
  guard with it, so a locked-out admin can get back in and re-enrol from `/profile`. Destructive by design — don't call it on every start. It **refuses an
  SSO account** (`Err` naming the provider); point break-glass at a local username instead.

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

**Replay guard (RFC 6238 §5.2).** A code is accepted for its own 30-second step and the two
neighbours (±1 skew). `totp_last_step` records the step each accepted code belonged to, and a later
code must match a **strictly greater** step, so a code can be used exactly once. Enrolment spends a
step too, and turning 2FA off clears the guard with the secret. A replayed code is refused with the
same message as a wrong one and counts against the account's lockout budget. It does not stop
real-time phishing; a passkey does (§5l). ([why](AUTH-SECURITY.md#totp))

**Enrolment (self-service, verify-before-activate).** `GET /profile/totp` mints a fresh secret, stores
it as `totp_pending`, and shows **both** a QR code (a server-rendered inline PNG — no JS) **and** the
`otpauth://…` URL as copyable text. `POST /profile/totp` checks the entered code against the pending
secret; only on success is it promoted to `totp_secret` (2FA now required at login). A wrong code
re-shows the same QR. `Auth::totp_issuer(name)` sets the issuer label authenticator apps display
(default `"relativelylight"`).

**Blank = off.** As with `sso_provider`, a blank `totp_secret` counts as *no* secret (`Model::totp_key`
/ `has_totp`), and a blank `totp_pending` as *no* enrolment in progress
([why](AUTH-SECURITY.md#totp)).

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
Such accounts have **no local password and no passkeys** — `verify_credentials` refuses a password
login, and the profile page shows the provider in place of the password controls. They **may** enrol
this site's TOTP, which a site that distrusts its IdP requires (`Auth::sso_level`, §5m); the TOTP step
then follows the provider's callback. With a
provider's **auto-registration** on, an unknown user is created on first login; with it off, an admin
must pre-create the user and set its `sso_provider` to the provider key first, else the login is
refused. A local (password) account can't be signed into via SSO, and an account bound to one provider
can't sign in through another. A **blank** `sso_provider` counts as *no* provider, exactly
like `NULL` ([why](AUTH-SECURITY.md#totp)). Ask `user::Model::sso_key()` / `is_sso()` rather than testing the column — the
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
to the provider), `GET {base}/{key}/callback` (exchange, verify, map, sign in) and
`GET {base}/{key}/reauth` (an SSO account confirming it's you before a sensitive change, §5h),
default base `/sso`. `Sso::buttons()` gives `(label, url)` pairs for the login page. Per provider:
issuer, client id/secret, redirect URL, scopes, `username_claim` (default `preferred_username`;
Google → `email`), optional `groups_claim`, the claim table, `auto_register`, and
`reauth_max_age(secs)` to make §5h's confirmation strict.

**Google and strict confirmation.** Google never asks a signed-in user for their password again, and
sends `auth_time` only to a verified, published app with **Session age claims** on (Google Auth
Platform → Settings → Advanced settings), so under `reauth_max_age` a Google user is refused unless
they happened to sign in within the window. Leave Google at the default; Okta, Entra ID and Keycloak
re-prompt.

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

**The callback leaves by a page, not a redirect.** It answers with a page that moves on to the app
(or back to the confirming page) by itself: the provider sent the browser there, so a redirect
would still be a cross-site navigation, on which a `SameSite=Strict` session cookie isn't sent, and
the browser would land signed out ([why](AUTH-SECURITY.md#re-authentication)).

**Trying it by hand:** [SSO_TESTING_KEYCLOAK.md](SSO_TESTING_KEYCLOAK.md) runs Keycloak in a
container and points `examples/auth` at it.

**Account resolution.** The username claim is matched **case-insensitively**
([why](AUTH-SECURITY.md#sso)). A pre-created account keeps its own spelling; ties (rows differing
only in case, which nothing here creates) go to the lowest id. Local password login still matches
**exactly**. The refusals are the same whatever the case: a local account is recognised as local, and
an account bound to another provider as bound.

A **disabled** account (`is_active = false`) is refused before anything is written, as password
login refuses it.

**Discovery is cached** per provider for an hour, with the signing keys it carries
([why](AUTH-SECURITY.md#sso)).

> **The transaction cookie** (`state`, `nonce` and the PKCE verifier, base64 JSON in an `HttpOnly`
> cookie) is not signed, and is protected against login CSRF only as well as your cookies are: serve
> the site over HTTPS (ideally HSTS), keep it free of XSS, and don't share a registrable domain with
> something you don't trust ([why](AUTH-SECURITY.md#the-transaction-cookie)).

**`cargo audit` reports `rsa` (RUSTSEC-2023-0071, the Marvin attack)** in any build with `sso`. It
does not apply here: SSO only verifies signatures and holds no RSA private key. Ignore the advisory
in your `.cargo/audit.toml`, with that reason, until `openidconnect` moves to a fixed `rsa`
([why](AUTH-SECURITY.md#the-rsa-advisory)).

## 5c. Lifecycle timestamps

The auth entities carry UTC timestamps (`i64` Unix seconds), maintained automatically:

- `auth_user`: `created_at`, `updated_at`, `last_login_at` (nullable).
- `auth_group`: `created_at`, `updated_at`.

`created_at`/`updated_at` are stamped by a SeaORM `ActiveModelBehavior::before_save` hook (created on
insert, updated on every save) — so they're correct no matter who writes (admin CRUD, the profile page,
`create_user`/`set_password`, …). `last_login_at` is **not** a hook; the login flows stamp it with a
set-based update (so it doesn't bump `updated_at`) on completion: `login_submit` (no-2FA), the TOTP
confirm (`login/totp`), and the SSO callback. The accounts panel's `user::meta_model` shows them
read-only. All times are UTC; rendering them in the
viewer's timezone is a frontend concern (see [docs/TIME.md](TIME.md)).

## 5d. Write observer — audit hook

`auth` fires the shared [`WriteObserver`](../relativelylight/src/observe.rs)
([CRUD.md](CRUD.md#write-observer-audit)) from its own writes, which happen outside the `crud`
engine:

| Action | `source` |
|---|---|
| your password change (`POST /profile`), new recovery codes, signing out other sessions | `auth-profile` |
| minting or revoking one of your API keys (§5k): `Create` / `Delete` on `auth_api_key` | `auth-profile` |
| adding or removing one of your passkeys (§5l): `Create` / `Delete` on `auth_passkey`; removing your password | `auth-profile` |
| a manager's reset (`POST /profile/{id}`), a manager removing someone's passkeys | `auth-admin` |
| turning your 2FA on or off: `{"totp_enabled": true}` / `false` on `auth_user` | `auth-profile` |
| a manager turning someone's 2FA off: `{"by": "<manager>", "totp_enabled": false}` | `auth-admin` |
| a completed sign-in, by any way in: `{"signed_in": "password+totp"}` on `auth_user`, the session's method (§5m) | `auth-login` |

Each event carries the headers, the resolved `client_ip`, **`actor`** (the username who acted — read
it rather than calling `identify`, since a password change has already rotated the caller's session),
and an `after` (and, for a delete, a `before`) describing what changed with no secret in it
(`{"password_changed": true}`). A sign-in fires once, when it completes: the password step of a 2FA
account is not one yet, and a refused attempt fires nothing (the lockout counters and the error
observer hold those). Share one `Arc` with `Engine::on_write` so a single sink covers both:

```rust
let audit = Arc::new(MyAuditSink::new(db.clone()));
let auth = Auth::new(db.clone(), lockout).on_write(audit.clone());
let mut engine = crud.into_engine();     // after registering the models
engine.on_write(audit.clone());
```

The app owns the audit table and its retention. [`examples/audit`](../examples/audit/src/main.rs)
prints a line per committed write next to a request log built on the same `RealIp`.

**Errors the login hides** go to a second sink, `Auth::on_error`
([`ErrorObserver`](../relativelylight/src/observe.rs)). A database failure during sign-in — the
credential lookup or the session insert — answers the visitor exactly like a wrong password (`401`,
"Invalid username or password"), and is **not** counted against the account or the address: an
outage is no guess. The cause arrives as an `ErrorEvent` (`source`, `during`, the `error`,
`client_ip`); without a sink it is dropped, since the crate writes nothing to stdout or stderr.

```rust
let auth = Auth::new(db.clone(), lockout).on_write(audit.clone()).on_error(Arc::new(MyErrorLog));
```

[`examples/audit`](../examples/audit/src/main.rs) prints one stderr line per event.

## 5e. Lockout: the brute-force brake

The brake in front of the **unauthenticated** credential checks: one counter per account name and one
per source address (`auth::lockout::{UsernameLockout, IpLockout}`), each in its own table. The rows are
durable and shared across restarts and replicas.

**The rule.** A checked-and-rejected credential upserts a row (`failures += 1`, `last_failure_at =
now`) *unless* the key is already at the limit — a locked key records nothing. A key is locked while
`failures >= after` **and** `last_failure_at + duration > now`; the handler then answers **`429` with
`Retry-After`** and never looks at the submitted secret, the same for a real and a made-up username.
Once the window passes the row reads as absent and the pruner deletes it. Effective semantics:
**"`after` failures, each within `duration` of the previous, lock the key for `duration` after the
last one"** — a decaying window, not a strict sliding one. ([why](AUTH-SECURITY.md#lockout))

**What is braked — and what deliberately isn't** ([why each](AUTH-SECURITY.md#lockout)):

| Check | Counted against |
|---|---|
| `POST /login` (password) | account + address |
| `POST /login/totp` (second factor) | account + address |
| the app's own checks (`Auth::username_lockout` / `ip_lockout`) | whichever it passes |
| `POST /profile` (current password) | **not limited** (authenticated; see re-authentication, §5h) |
| `POST /profile/totp` (enrolment code) | **not limited** (authenticated) |
| `POST /profile/{id}` (manager reset) | **not limited** (verifies no secret; gated by group membership) |
| `POST /login/passkey/finish` (passkey sign-in, §5l) | address |
| `POST /login/totp/passkey` (passkey second factor, §5l) | account + address |
| `Auth::identify_key` (API key, §5k) | address |

**Configuration is mandatory** — it is an argument to `Auth::new`, not a builder call:

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
just expires immediately. The two windows are independent, and the address budget is far looser
than the account one, since a locked address turns away every caller sharing it (CGNAT, an office
NAT) ([why](AUTH-SECURITY.md#lockout)).

**Who is the client?** The per-address half uses the `RealIp` that `middleware::resolve_real_ip`
resolved (§4). Use the same value for your own logging, audit rows and limits, so a failed login and a
failed API call from one client land on the **same** row (an IPv4-mapped `::ffff:a.b.c.d` and a plain
`a.b.c.d` are canonicalized to one key).

**Whitelisting addresses.** `Lockout::ip_whitelist` takes CIDRs (build it with `net::parse_nets`, which
also accepts bare addresses) that are never counted and never locked — an office range, a monitoring
probe, the host a fleet NATs through. It matches across families and representations, so a rule written
`::ffff:198.51.100.0/120` covers a client that arrives as plain `198.51.100.9`, and vice versa. The
exemption applies on **every** surface, this module's and the app's, since both go through `IpLockout`.

It does *not* exempt the account counter, and there is deliberately **no username whitelist**
([why](AUTH-SECURITY.md#lockout)).

Setting `ip_after: 0` turns per-address counting off everywhere, leaving the per-account brake — which
still covers the common case of one account being guessed at, just not spraying across many.

**The app's own credential checks share these counters.** An app that authenticates callers itself —
HTTP Basic on a machine endpoint, a DDNS update URL — must not keep a second limiter
([why](AUTH-SECURITY.md#lockout)). (API keys, §5k, already count against the address counter inside
`identify_key`.)

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
turned away *because* it was locked ([why](AUTH-SECURITY.md#lockout)).
`record_failure` returns whether *this* failure tripped the lock, so you log once instead of on every
subsequent attempt. `examples/auth` has a working one (`GET /api/whoami`).

**The unlock is a row delete.** Both counters are ordinary tables: in the accounts panel
([§5j](#the-accounts-panel)) an operator sees who is being guessed at and deletes a row — gated,
CSRF-checked and audited like any other write.

**Housekeeping is the app's.** Nothing in this crate schedules anything — no background task, no timer.
`Auth::prune()` deletes dead sessions *and* expired lockout rows from both tables; call
it at startup and from whatever periodic loop the app already has (both examples do). Skipping it is
safe; the rows just accumulate.

**The trade-off.** Someone who knows an account name can keep it locked by failing on purpose; the
lock is short, lifts on its own, and can be cleared from the admin panel
([why](AUTH-SECURITY.md#lockout)).

## 5f. Session lifetime & revocation

A session is a row, so revoking one is a `DELETE` (§3).

**Two clocks, both enforced at `identify`.**

| clock | column | configured by | default | what it bounds |
|---|---|---|---|---|
| absolute | `expires_at` | `Auth::session_ttl_secs` | 7 days | how long a session can *ever* live, however busy |
| idle | `last_seen_at` | `Auth::session_idle_secs` | 8 hours | how long an *unused* session survives |

The idle clock is the one that bounds a stolen cookie ([why](AUTH-SECURITY.md#sessions-and-cookies)).
`session_idle_secs(0)` switches it off leaving only the absolute deadline. The absolute deadline
always wins — a session used a second ago but past `expires_at` is dead.

`last_seen_at` is refreshed **lazily**: a read only writes when the stamp is more than a minute stale.

**`Auth::identify(&headers) -> Option<Identity>` never changes a session id.** Everything that changes
a session **id** happens inside a POST handler that already owns its response.

**Rotation on privilege gain.** Password login always mints a new row with a server-generated id, and
confirming the second factor issues **another new id** and deletes the half-authenticated one, so a
planted session cookie is never elevated by the victim's own login
([why](AUTH-SECURITY.md#sessions-and-cookies)). The CSRF token rotates with it, on every way in:
password, second factor, passkey and the SSO callback.

**A password change signs out everything else** ([why](AUTH-SECURITY.md#sessions-and-cookies)).
`POST /profile` mints one fresh session for the caller and **deletes every other session they hold**,
including their own previous id. A manager's reset at `POST /profile/{id}` deletes **all** of the
target's sessions (there is no session of theirs to spare).

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

The policy itself — the presets, what every one of them enforces, and why composition rules are off —
is described once, in [DATAINPUT.md → Passwords](DATAINPUT.md#passwords). What `Auth` adds is the
**username** as context, so a password containing it is refused. That check is cross-field, which is
why a single-field `crud` validator can't do it.

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
says ([why](AUTH-SECURITY.md#password-policy)).

**One policy, every surface.** `Auth` applies it on its own pages, and the accounts panel's
`user::meta_model(&auth)` reads it from the same `Auth` for the first password an operator types.
An app's **own** form that sets a password is a third surface: screen it the same way (with the
policy you gave `Auth`, or `validate::password(policy)` on a `crud` field), or that form is the way
around it. `examples/adminpanel` drives the policy from one `PASSWORD_LEVEL` env value, `0`
switching it off.

## 5h. Re-authentication before sensitive changes

A live session proves only that someone logged in once, so the actions that would let an intruder
holding a stolen session entrench ask for a factor again, per request
([why](AUTH-SECURITY.md#re-authentication)):

| route | whose factor |
|---|---|
| `POST /profile/totp/disable` | the caller's |
| `POST /profile/totp` (enrol) | the caller's |
| `POST /profile/{id}` (reset) | the **manager's** |
| `POST /profile/{id}/totp/disable` | the **manager's** |
| `POST /profile/api-keys` (mint, §5k) | the caller's |
| `POST /profile/passkeys` (add, §5l) | the caller's |
| `POST /profile/password/remove` (§5l) | the caller's |
| `POST /profile` without a password (setting one) | the caller's |
| `POST /profile/{id}/passkeys/remove` | the **manager's** |

`POST /profile` (your own password change) asks for the current password anyway.
`POST /profile/sessions/revoke`, `POST /profile/api-keys/{id}/revoke` and
`POST /profile/passkeys/{id}/remove` are **not** re-authenticated: each only removes access.

**Any factor the account has.** A `current_password`, a `totp_code`, or a passkey (§5l) satisfies it;
the confirm block offers only the factors the account has. A **fresh code is preferred** when
the account has 2FA, and a code accepted here is **spent** (§5a). Enrolment is the one asymmetric
case: a *first* enrolment has no active secret to check a code against, so the password is the
factor; a re-enrolment can use either.

**An SSO account confirms at its provider** ([why](AUTH-SECURITY.md#re-authentication)). Its
confirm block offers **Confirm with Google** (beside a TOTP or passkey it has added): a round trip to
the provider and back to the page, after which one action in the next five minutes passes. It needs
`Sso::routes()` mounted (`GET {base}/{key}/reauth`, §5b), or the account is refused. The round trip
back as the same account is the confirmation; `SsoProvider::reauth_max_age(secs)` also requires a
sign-in at most `secs` old, for providers that re-prompt (§5b).

A local account with no password, no TOTP and no passkey passes, having nothing to be asked for (it
can't sign in either). An account with a passkey and no password **does** have a factor, and must
present it.

**Not lockout-limited**: the caller is authenticated (§5e; [why](AUTH-SECURITY.md#re-authentication)).

**For your own routes**, which is where most sensitive actions live:

```rust
#[derive(Deserialize)]
struct DeleteForm { #[serde(flatten)] reauth: auth::ReauthInput /* , your fields */ }

// rendering: the inputs for whichever factors the caller has, inside your <form>
let fields = auth.reauth_fields(&who, "Confirm it's you before deleting.").await;

// handling the post
let Some(who) = auth.identify(&headers).await else { return redirect_to_login() };
if let Err(msg) = auth.reauthenticate_with(&who, &form.reauth).await {
    return (StatusCode::FORBIDDEN, render_form_with_error(&msg));  // nothing has happened yet
}
delete_the_thing(&who).await;
```

Without a form to flatten into (a CLI, a test), build the input with
`ReauthInput::password_or_code(password, code)`. `Auth::can_reauthenticate(&who)` says whether the
account is challenged at all (`false` only for a local account with no factor), for a UI hint. `examples/auth` gates a `POST /webhook-secret/rotate` on it — the pattern to copy, including returning
the refusal before anything is written.

**Per request, not a window.** There is no "you confirmed five minutes ago" grace period
([why](AUTH-SECURITY.md#re-authentication)); resetting two users means confirming twice.

## 5i. TOTP recovery codes

The answer to "my phone is gone"; otherwise only a manager disabling their 2FA (§5a) lets such a user
back in ([why](AUTH-SECURITY.md#recovery-codes)).

**Ten single-use codes**, issued automatically **with** the enrolment and shown once. `auth::recovery`
owns them: `issue`, `consume`, `remaining`, `clear`, plus the `entity` (table `auth_totp_recovery`).

- **Use:** at `POST /login/totp`, in the `recovery_code` field instead of the 6-digit `code` — no separate
  route. A recovery login lands on **`/profile`** rather than `/`, because the next thing that user needs
  is to re-enrol or generate a fresh set. The session id rotates exactly as it does for a code (§5f).
- **Spent on use**, so each code works once; the row is *marked* rather than deleted, which keeps "a
  recovery code was used" visible afterwards.
- **Regenerate** from the profile page (`POST /profile/totp/recovery`), which is **re-authenticated**
  (§5h). Issuing a set invalidates the previous one, so regenerate when codes may have leaked.
- **Destroyed when 2FA is turned off**, self-service or by a manager
  ([why](AUTH-SECURITY.md#recovery-codes)).
- The profile page shows how many are unused, and says so more loudly at ≤ 3 and at 0.
- 2FA stays **on** after a recovery login. The code got them in; it didn't decide their factor policy.

**Hashed with SHA-256, not argon2** — deliberately ([why](AUTH-SECURITY.md#recovery-codes)). Codes
are 10 characters from a 30-symbol Crockford-style alphabet (nothing reads as `0`/`1`), ~49 bits of
entropy, and the hash is domain-separated by user id.

**A recovery code does not satisfy re-authentication** (§5h). It gets you *in*; it does not authorise
entrenching ([why](AUTH-SECURITY.md#recovery-codes)).

**Guessing is braked** by the same per-account counter as a wrong TOTP code (§5e). An **empty**
submission — no code and no recovery code — is refused *without* counting
([why](AUTH-SECURITY.md#recovery-codes)).

**Schema.** `auth_totp_recovery` is in `table_create_statements`, so an app with its own migrations needs
a step for it. It is the one `auth` table an admin panel never shows (§5j).

## 5j. Where accounts come from — there is **no registration page**

This module ships login, not sign-up, and that is a decision rather than a gap
([why](AUTH-SECURITY.md#accounts)).

So an account comes into being in exactly four ways, all of them the app's own call:

| Route | Call | Typical use |
|---|---|---|
| an operator creates it | the **accounts panel** (below), or `auth::create_user(db, user, pw)` | the normal one |
| SSO creates it on first login | per-provider **auto-registration** (§5b) | a corporate IdP owns the roster |
| the app's boot seeder | `auth::make_admin(db, group, user, pw)` — idempotent | the first admin |
| break-glass, from a shell | `auth::reset_admin_access(db, group, user, pw)` behind a CLI flag | nobody can get in |

The last two are deliberately exempt from the password policy (§5g), which governs *typed* input only
([why](AUTH-SECURITY.md#password-policy)).

**Want public signup anyway?** Write the page: a form posting to a route of yours that checks
whatever you require first (an invite token, a rate limit, an email round trip) and calls
`create_user` + `add_to_group`, which validate the username as every creation path does.

### The accounts panel

`auth`'s tables are ordinary SeaORM entities, so an operator's screen is the ordinary admin over them —
no bespoke user-management UI, and no second permission model. Each table comes configured from the
library, so every app's panel follows the same rules:

```rust
let gate = Arc::new(GroupReadWrite::new(&auth, [ADMIN_GROUP]));
crud.register(auth::user::meta_model(&auth), gate.clone());   // accounts, and their groups
crud.register(auth::group::meta_model(), gate.clone());       // groups, and their members
crud.register(auth::api_key::meta_model(), gate.clone());     // §5k
crud.register(auth::passkey::meta_model(), gate.clone());     // §5l, read-only
crud.register(auth::lockout::username_meta_model(), gate.clone()); // §5e, delete = unlock
crud.register(auth::lockout::ip_meta_model(), gate);
```

and in the panel each table offers only what is done there. The account's id links to its
credentials page, `{profile_path}/{id}`, wherever an account is shown: `auth::user::meta_model`
declares that link ([CRUD.md → display formatters](CRUD.md#display-formatters--how-a-field-is-shown)).

```rust
admin
    .entity("auth_user")
    .entity("auth_group")
    .entity_with("auth_api_key", |t| t.create(false))      // minted on /profile, shown once
    .entity_with("auth_passkey", |t| t.read_only(true))    // removed on /profile/{id}
    .entity_with("auth_username_lockout", |t| t.create(false).edit(false))  // delete = unlock
    .entity_with("auth_ip_lockout", |t| t.create(false).edit(false))
```

Register only the tables your features use (`api_key` and `passkey` need theirs). This is the whole
setup; the sections below point here.

**The panel holds account data; the credentials page holds credentials.** One place for each, so
the rules that go with a task can't be skipped by doing it in the other place:

| | the panel (`/admin`, the CRUD admin) | the credentials page (`/profile/{id}`) |
|---|---|---|
| username, active, SSO provider | edit | |
| groups (`auth_user_group`, an N:M relation) | edit, from either side | |
| the **first** password | set on create (blank = none) | |
| a later password | | reset (signs the account out) |
| password set when, change required | shown, read-only | |
| TOTP | | disable (re-authenticated) |
| passkeys | listed, read-only | remove (re-authenticated) |
| API keys | disable, re-date, delete | |
| lockouts | delete = unlock | |
| `totp_*`, `passkey_handle`, password hash | hidden | |

What `user::meta_model` does, and why:

1. **The groups relation** — `auth_user_group` is an N:M junction and is never registered as a model
   of its own. Without the relation the panel could create an account and not put it in a group,
   and since the gate checks *group membership*, that is a screen that can make users who can do
   nothing.
2. **The first password only** (`MetaField::create_only`): write-only, argon2-hashed, screened by the
   policy `Auth` was given (§5g). The edit form has no password field, and an update carrying one is
   refused: a later password is the credentials page's, which also signs the account out (§5f).
3. **The TOTP columns and `passkey_handle` hidden.** They are credentials, the replay guard and the
   key every passkey hangs on ([why](AUTH-SECURITY.md#accounts)). **Never register
   `auth::recovery::entity`** at all — every row of it is a credential hash.
4. **`must_change_password` and the timestamps read-only** (§5m). The hook sets the flag when the
   panel sets someone's first password; an editable checkbox would post `false` and keep it from ever
   being set ([why](AUTH-SECURITY.md#the-sign-in-policy-and-password-change)).

The gate is **`GroupReadWrite`, not `UserReadGroupWrite`** — reads included, so a non-admin can't list
the accounts: `render_for` answers `403` ([why](AUTH-SECURITY.md#accounts)).

What neither page can do: **enrol someone's 2FA or passkey** (only the owner can, on `/profile`), and
**reset an SSO account's password** (there is none to reset — §5b).

## 5k. API keys

Bearer keys for the app's machine endpoints: a device updating DNS, an agent calling an MCP server, a
script calling a JSON API. `auth::api_key` holds the table, the resolver and the self-service card on
`/profile`.

**A key is its owner, and nothing else.** A key stores no scope, level or group. The resolver returns
the owner's `Identity` with the groups as they are **on this request**, so removing a membership or
deactivating the account disarms every key that user holds at once. To give a device less than its
human owner can do, give the device **its own account** in a narrower group and a key of that account.
The scope then lives in group membership, where it is visible and revocable, and the audit trail names
the device, not a person.

**A key never opens the UI.** `Auth::identify(&headers)` reads only the session cookie, so a key
presented as a cookie or in an `Authorization` header is anonymous to every gate, to the `crud` UI
and to `/profile`. A key is checked only where the app asks for it:

```rust
use relativelylight::auth::{self, api_key::KeyError};
use relativelylight::middleware::RealIp;

async fn update(State(app): State<App>, RealIp(ip): RealIp, headers: HeaderMap) -> Response {
    // The app chooses where the credential comes from: `Authorization: Bearer`, a vendor header…
    let Some(token) = auth::bearer_token(&headers) else { return StatusCode::UNAUTHORIZED.into_response() };
    let caller = match app.auth.identify_key(token, ip).await {
        Ok(k) => k,                                    // k.identity, k.key_id, k.key_name, k.key_prefix
        Err(KeyError::Invalid) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(KeyError::Locked(retry)) => return too_many(retry),   // 429 + Retry-After
        Err(KeyError::Internal) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    // …then the same authorization as a signed-in user: caller.identity.in_group("dns")
}
```

The app parses the request and `identify_key` verifies the token. `auth::bearer_token` reads
`Authorization: Bearer <key>` (the scheme is case-insensitive); an app that also takes the key from a
header of its own (teleddns's Cloudflare-compatible `X-Auth-Key`) passes that value instead.
`identify_key` refuses, as `Invalid`:

- an unknown key;
- an expired key (`expires_at` reached);
- a key an administrator disabled;
- a key whose owner is deactivated.

**Lockout.** A key carries no account name, so only the **source address** is braked, on the same
`IpLockout` counter as `/login` (§5e). While the address is locked, `identify_key` answers
`Locked(retry)` without looking up the key. A rejected key counts one failure. An empty token
presents no credential and is refused without counting. A good key clears nothing
([why](AUTH-SECURITY.md#api-keys)). A database failure is `Internal`, goes to
the `on_error` observer and is not counted.

**What a request logs is the app's.** `identify_key` writes nothing to stdout. Request logging
belongs to your middleware or proxy (`examples/audit`). Audit with the `key_id` it returns: a write
made with a key is the owner's write, made with that key.

**Self-service on `/profile`**, switched on with `Auth::api_keys`:

```rust
use relativelylight::auth::api_key::ApiKeys;

let auth = Auth::new(db, lockout).api_keys(ApiKeys::new("climb_"));
```

`ApiKeys::name_placeholder("Claude Code on my laptop")` sets the hint in the mint form's empty label
field, for what a key is for in your app (default "what will use it, e.g. a script").

The card lists the caller's keys (label, prefix, created, expires, last used, and whether disabled)
and offers:

| route | does | guard |
|---|---|---|
| `POST /profile/api-keys` | mint a key with a label and an optional expiry in days, and show the raw key **once** | CSRF + **re-authentication** (§5h) |
| `POST /profile/api-keys/{id}/revoke` | delete one of the caller's own keys | CSRF |

Minting is re-authenticated; revoking is not ([why](AUTH-SECURITY.md#api-keys)). A request naming
someone else's key changes nothing. Both fire a `WriteEvent` (`auth_api_key`,
`Create` / `Delete`) with the label, the prefix and the expiry, never the key or its hash. A
manager's `/profile/{id}` doesn't show the card. An administrator manages other users' keys in the
panel (below). Without `api_keys` the card and its routes are absent, and `identify_key` still
works, for keys an app mints itself with `api_key::mint`.

**The key.** `{prefix}` followed by 40 random alphanumeric characters (≈ 238 bits). The prefix makes
a leaked key recognisable (secret scanners, logs). The table stores the first `prefix + 6` characters
for telling keys apart in a listing, and the **SHA-256** of the whole key, not argon2
([why](AUTH-SECURITY.md#api-keys)). `last_used_at` is refreshed lazily, at most once a minute per
key, as the session idle clock is (§5f).

**Schema.** `auth_api_key`: `id`, `user_id` (FK `auth_user`, **cascade**: a key is its owner and
goes with it), `name`, `hashed_key` (unique), `prefix`, `created_at`, `expires_at`, `last_used_at`,
`disabled`. It is in `table_create_statements`, so `auth::migrate` creates it, and in
`upgrade::table_create_statements` for an app upgrading with its own migrations. Expired keys are
not pruned. They stay listed as expired until their owner or an administrator deletes them.

**In the accounts panel** ([§5j](#the-accounts-panel)), `api_key::meta_model()` hides the hash and
keeps the owner, the prefix and the timestamps read-only ([why](AUTH-SECURITY.md#api-keys)). An
administrator can disable, re-label, re-date or delete any key, but not mint one: a key minted there
would have no raw value anyone could see.

## 5l. Passkeys (feature `passkeys`)

Passkeys (WebAuthn) sign a user in with a fingerprint, face, device PIN or security key, with nothing
to type. They are phishing-resistant where TOTP is not ([why](AUTH-SECURITY.md#passkeys)). The crate
uses `webauthn-rs` (pure Rust).

```rust
use relativelylight::auth::passkey::{Class, Passkeys};

let auth = Auth::new(db, lockout).passkeys(
    Passkeys::new("example.com", "https://example.com")   // the domain, and the origin the site is served at
        .rp_name("Example")                                // what authenticators show
        .require(Class::DeviceBound)                       // optional: the lowest class accepted (below)
        .second_factor(true),                              // optional: a passkey after a password, beside TOTP
);
```

A passkey is bound to the domain (`rp_id`) for good, so choose the one the site will keep. Browsers
refuse passkeys on a bare IP address; locally, use `localhost`.

**What it adds:**

- "Sign in with a passkey" on `/login`. The passkey names the account, so no username is typed. When
  the account also has TOTP, the TOTP step follows.
- A passkeys card on `/profile`: list, add, remove, and "Remove my password". Adding happens on the
  page itself: the form carries the registration challenge, and "Add a passkey" runs the browser's
  prompt, after the prompt that confirms it's you when nothing was typed, then posts. No page in
  between, and nothing written to the account until a passkey is added.
- A passkey on every confirm-it's-you form (§5h): the library's own, and the app's
  (`Auth::reauth_fields` / `reauthenticate_with`, or `ProfileSection::reauth_fields` in a
  `profile_extra` section).
- With `second_factor(true)`, a password sign-in by an account that has a passkey continues to a
  passkey step at `/login/totp`, beside TOTP.
- `passkey::meta_model()` for the accounts panel (below).

**An account's life.** An administrator creates an account with a password (§5j). The user can add
TOTP and passkeys. With a passkey they can remove their password, and keep TOTP as a second step
after the passkey or not. An account with no password can't remove its last passkey until it sets a
password again ("Set a password" on `/profile`, confirmed with the passkey). SSO accounts get no
passkeys. A manager can always reset a password, disable TOTP and remove passkeys
(`POST /profile/{id}/passkeys/remove`), each confirmed with the manager's own factor. There is no
self-service recovery: an account that loses its only passkey is the administrator's to reopen.

**Classes.** Each passkey is recorded with how strongly it is bound to hardware:

| Class | Means | Proof |
|---|---|---|
| `synced` | can be copied between devices (iCloud Keychain, Google Password Manager, a password manager) | the authenticator says so |
| `device-bound` | stays on one authenticator | **self-reported**: the authenticator says so |
| `attested` | a hardware authenticator of a model the site trusts | an attestation chain to a CA the app configured |

`require(class)` sets the lowest class accepted. It is checked when a passkey is added, at every use,
and against open sessions: a session a passkey opened stops counting once its class is below the
policy. `Class::Attested` needs `attestation_ca(pem, aaguid, description)` entries, the vendor's root
CA and the model's AAGUID, and fails at startup without one. Synced passkeys can never be attested.

**How a ceremony runs.** WebAuthn needs the browser's API, so passkeys need JavaScript.
- **The common case.** The page embeds the challenge. The script (`GET /auth/passkey.js`, cacheable,
  allowed by a strict `script-src 'self'`) runs the browser's prompt on a click, puts the answer in
  a hidden field and submits the form. The server answers with the usual 303 or a page.
- **"Sign in with a passkey" on `/login`** has no challenge yet, because a page view writes nothing.
  On the click, the script posts the same form asking for JSON (`Accept: application/json`) and
  gets the challenge, its options and where to post the answer. The prompt opens on that same click,
  and the answer is posted as a form. If no JSON comes back (a lockout page), or the browser won't
  open the prompt after the round trip, the next click falls back to a page with its own button.
  That is also what a browser without JavaScript gets.
- **Challenges.** A challenge is a database row (`auth_webauthn_challenge`), single-use and valid for
  five minutes, pruned by `auth.prune()`. A sign-in challenge is created only on the click, so
  anonymous page views write nothing. A signed-in page with a confirm-it's-you form creates one per
  render.
- **Without JavaScript,** passkey sign-in still works through that page; the confirm-it's-you
  buttons do nothing, and everything else works.

**Registration asks for a discoverable credential** (one the authenticator can offer without a
username). Phones and laptops always make one; a security key needs a free slot, and one that can't
make a discoverable credential can't be added.

**Lockout** (§5e). A failed passkey sign-in counts against the **address**; a failed passkey second
factor counts against the account and the address, like a TOTP code
([why](AUTH-SECURITY.md#passkeys)). An expired or unknown challenge checks nothing and counts nothing.

**Re-authentication** (§5h) accepts the passkey, and an account with a passkey and no password
**must** use one of its factors. An SSO account confirms at its provider, or with a passkey it has
added.

**What a session records.** `auth_session.method` is `passkey`, `passkey+totp`, `passkey+recovery`
or `password+passkey`, and `passkey_class` the class of the passkey used.

**A passkey whose device starts syncing it.** The spec lets an authenticator turn a credential
backup-eligible later. `webauthn-rs` allows that when a user's own challenge is answered (re-auth, the
second factor), and the passkey is reclassified `synced`. It refuses it in the username-less sign-in,
before checking the signature, so that sign-in fails like an unknown passkey. The user signs in
another way, removes the passkey and adds it again.

**In the accounts panel** ([§5j](#the-accounts-panel)) passkeys are an inventory, read-only: who
holds which kind and when it was last used, the credential hidden. Removing someone's passkey is
the manager's, on `/profile/{id}`; only an authenticator makes one.

**Audit** (§5d). Adding and removing a passkey fire `Create` / `Delete` on `auth_passkey` with its
label, class and AAGUID, never the credential. Removing a password and a manager's removal fire
`Update` on `auth_user`.

## 5m. The sign-in policy, and "password change required"

**One minimum assurance level.** Each way of signing in has a level, and the app sets the lowest it
accepts:

```rust
use relativelylight::auth::Level;

let auth = Auth::new(db, lockout)
    .min_level(Level::Mfa)          // default Level::Simple: any sign-in
    .sso_level(Level::Simple);        // default Level::Mfa: trust the IdP's own second factor
```

| Signed in with | Level |
|---|---|
| a password | `Simple` |
| a password + TOTP (or a recovery code), a password + passkey | `Mfa` |
| a passkey (§5l) | `Mfa` |
| an attested passkey, alone or with anything | `Attested` |
| SSO | `sso_level`, `Mfa` by default |
| SSO + TOTP | at least `Mfa` |

TOTP lifts a method to `Mfa`, never higher ([why](AUTH-SECURITY.md#the-sign-in-policy-and-password-change)).
`min_level(Level::Attested)` needs passkeys requiring
`Class::Attested`; `routes()` panics otherwise. Typical settings:

| The site wants | Set |
|---|---|
| any sign-in (the default) | nothing |
| a password + TOTP, a passkey, or SSO | `min_level(Level::Mfa)` |
| the same, and our own TOTP after SSO | `min_level(Level::Mfa).sso_level(Level::Simple)` |
| attested security keys only | `min_level(Level::Attested)` and passkeys `require(Class::Attested)` |

**The level is read from the session** (its recorded method and passkey class) on every request, so a
stricter policy applies to sessions already open. `Identity::level` carries it, for an app that wants
more for one action than the site's minimum, such as a signature:

```rust
if who.level < Level::Attested { return refuse("sign with your security key"); }
```

**A session below the minimum is restricted.** `identify` returns `None`, so the app and every gate
treat it as anonymous. The caller's own `/profile` still works: the login lands there, a notice says
which factor to add, and only the sections that add one are shown (no API keys, no `profile_extra`).
`GET /login` with a restricted session goes to `/profile` too, so an app that redirects anonymous
callers to the login page doesn't loop. A restricted session can't mint an API key or manage others.
**Adding the factor steps the session up**: TOTP or a passkey enrolled on `/profile` rotates the
session to the stronger method (a new id, the same as completing a second factor at login), and the
user goes on without signing in again. API keys (§5k) are outside the policy: a key's identity is
`Simple`, and only a session that meets the minimum can mint one.

**SSO accounts may enrol TOTP** for this. With `sso_level(Level::Simple)` and a `Mfa` minimum, an SSO
user's first sign-in is restricted and asks for TOTP; after that, the TOTP step follows the provider's
callback.

**"Password change required."** Two columns on `auth_user`: `password_changed_at` (when the password
was last set) and `must_change_password` (someone other than the owner set it).

- **The row hook flags it.** Any write that sets `password_hash` stamps `password_changed_at` and sets
  `must_change_password`, unless the writer set that column itself. So a password an administrator
  sets in the accounts panel (an account's first), an app's own form, or a manager's reset at
  `/profile/{id}` asks its
  owner to choose their own. The owner's change on `/profile` clears it, and so do the programmatic
  helpers (`create_user`, `set_password`, `make_admin`, `reset_admin_access`): those are the
  owner's or a seeder's.
- **The accounts panel shows both read-only** (`user::meta_model`): an editable flag would never be
  set ([why](AUTH-SECURITY.md#the-sign-in-policy-and-password-change)), and `password_changed_at` is
  the library's to stamp.
- **`Auth::password_max_age_days(n)`**, default `0` (no limit), makes a password older than `n` days
  due. Set it only where a rotation is required
  ([why](AUTH-SECURITY.md#the-sign-in-policy-and-password-change)). A row from before the column
  existed counts from `created_at`.
- **Due is a notice, not a lock.** The login lands on `/profile`, which says why, and the user can go
  on into the app. `Identity::password_change` (`SetByAnother` or `Expired`) is there for the app's
  shell, as `examples/adminpanel`'s navbar badge shows. Accounts with no password (SSO, passkey-only)
  are never due.

**Schema.** `password_changed_at`, `must_change_password` and the session's method are among 0.5's
upgrade statements (`auth::upgrade`,
[MIGRATION-0.5.md](MIGRATION-0.5.md#3-new-auth-columns-and-tables)).

## 6. authz — the gate

The gate trait lives in **`relativelylight::authz`** — kept apart from `auth`, so a gate of your
own needs nothing from it:

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
  needs no gating.
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
- **Custom** — implement `authz::Authz` (full RBAC over users/groups, an app's own credential, IP
  allow-lists — anything, since you get the headers and can call `auth.identify`).

> The profile page's "manage another user" rule is **not** an `Authz` gate — the header-only trait
> can't see *which* user is targeted. That row-aware self-or-manager check lives in the `/profile/{id}`
> handler (configured by `Auth::profile_managers`), not in a model gate.

**Configuration — one gate per model, at registration.** `Crud::register(model, gate)` takes the gate
alongside the model. Pass `Open` for an ungated model, a preset, or a shared `Arc<dyn Authz>` (it
implements `Authz`, so the same instance can guard several models). There is no separate default — the
gate is always explicit at the call site.

**Enforcement.** `crud`'s `render_for` asks the gate before reading and `submit` before writing,
answering **401** (`NeedsLogin`) or **403** (`Denied`) before the database is touched. `render_for`
also hides the controls the gate would refuse, and a hidden control's write is refused too. A handler
of yours that calls `Engine` directly must call `Engine::decide` first.

**The whole app** — `Auth`, the gates, the panel, the router and the shell put together — is
[APP.md](APP.md).

## 7. CSRF (double-submit token)

Cookie-authenticated **unsafe** requests (POST/PATCH/PUT/DELETE) must carry a CSRF token, checked
against a cookie-bound value (double-submit). Defense-in-depth on top of `SameSite=Strict`. The module
is `relativelylight::csrf` (always on); the type is `Csrf`.

**The token.** 256 random bits (hex) in the `rl_csrf` cookie (name configurable) — `SameSite=Strict`,
`Path=/`, `Secure` unless told otherwise, lifetime matching the session TTL, and deliberately **not
`HttpOnly`**: the admin UI's JS must read it, and the token grants nothing on its own
([why](AUTH-SECURITY.md#csrf)).

An unsafe request presents it in either:
- the **`_csrf` form field** — MPA `<form>` posts (every fragment `auth` renders embeds the hidden
  input), or
- the **`X-CSRF-Token` header** — for `fetch`/XHR clients of your own.

**Where it's enforced.**

| Surface | Enforcement | Rejection |
|---|---|---|
| `Auth::routes()` — `/login`, `/login/totp`, `/profile*` | **always on** | `403` + a bare "Security check failed" page |
| the `crud` admin UI's writes | **opt-in**: `engine.csrf(auth.csrf())` | `403`, before the gate or the database |
| your own unsafe routes | **`csrf::enforce`** as a layer (it reads a multipart body too, below) | the shared page (see below) |

On the auth routes the check runs **first** — before the password comparison, before any DB work.
Same in the engine: the CSRF check precedes the gate ([why](AUTH-SECURITY.md#csrf)). Safe methods
(GET/HEAD, i.e. every read) need no token. A page render **issues** the cookie if the request has none
(`Csrf::ensure`), and login / 2FA-completion **rotate** it along with the session; logout clears it.

**`Authorization`-bearing requests are exempt** ([why](AUTH-SECURITY.md#csrf)). Your own token-authenticated API routes need
no CSRF token.

**Your own routes: the layer.** Put `csrf::enforce` in front of the routes that need it:

```rust
use axum::middleware::from_fn_with_state;

let guarded = Router::new()
    .route("/account/delete", post(delete_account))
    .route("/webhook-secret/rotate", post(rotate_secret))
    .with_state(state)
    .layer(from_fn_with_state(auth.csrf(), relativelylight::csrf::enforce));
```

Pass the **same** `auth.csrf()` handle, or the cookie names won't agree. Keep it on a `Router` holding
only the routes you want guarded — it refuses *every* unsafe request that arrives without a token, which
is the point, and so does not belong in front of an endpoint meant for non-browser clients (those are
exempt anyway, being `Authorization`-bearing).

It checks, in order: safe methods pass; `Authorization`-bearing requests pass; the `X-CSRF-Token` header;
and failing that, the `_csrf` field of the body — an `application/x-www-form-urlencoded` body **under
64 KiB**, or a `multipart/form-data` body under `Csrf::max_upload` (16 MiB; set it a little above your
largest upload), refused if larger or malformed ([why](AUTH-SECURITY.md#csrf)). The body is buffered,
checked, and handed to the handler intact, so a plain MPA `<form>` post, with or without a file, needs
nothing from the handler. `examples/auth` guards its `POST /webhook-secret/rotate` this way. A
streaming `files::Upload` route checks the token itself (`Upload::csrf`), so keep it off the layer.

**Your own rejection page.** The built-in `403` is shell-less and static on purpose: nothing about the
caller is rendered and no cookies are set ([why](AUTH-SECURITY.md#csrf)).
`Auth::csrf_rejection(|req| ..)` (or `Csrf::on_reject`) replaces it with your own, and because the closure
travels on the `csrf()` handle, one setting covers the library's forms **and** `csrf::enforce` on your
routes. The closure gets the request's `http::request::Parts`, for display preferences such as a
theme or zone cookie. Keep the same discipline: don't name the user, don't set cookies, stay a `403`. It deliberately
does **not** apply to a hand-written API of yours answering a machine.

**Wiring it up.** `auth`'s own pages need nothing. For the admin UI's writes, hand the engine the same
checker so both surfaces share one cookie:

```rust
let auth = Auth::new(db.clone(), Lockout::default()).secure_cookies(false); // configure Auth fully first
let mut crud = Crud::new(db);
crud.register(post, gate);
let mut engine = crud.into_engine();
engine.csrf(auth.csrf());          // every rendered form now carries `_csrf`, and writes check it
```

`Table`/`Form`/`Admin` then render a hidden `_csrf` input in every form they emit, and `submit` checks
it on every write (create, update, both deletes, CSV import) — nothing to pass in. The **cookie must
already exist** when the page renders: `auth`'s login issues it. An app-owned page with a form of its
own issues the token and renders it; the route it posts to sits behind the layer:

```rust
let (token, set) = auth.csrf().ensure(&headers);          // Csrf::hidden_input(&token) in the form
let jar = if let Some(c) = set { jar.add(c) } else { jar };
```

`crud`'s components read the token from the cookie at request time rather than baking it into the fragment
([why](AUTH-SECURITY.md#csrf)).

A **co-hosted** app sharing the host must use a distinct `csrf_cookie_name` (cookies aren't
port-scoped), exactly as with the session cookie.

## 8. Examples

- **[`examples/auth`](../examples/auth/src/main.rs)** — the skeleton of an intranet app.
  - **The shell:** one shell around every page, the library's included: a navbar with the links the
    user may follow, and their name opening Profile and Log out (the only links to either).
  - **The pages:** a dashboard of cards by role, a `/secret` page gated by `identify`, and the
    accounts panel at `/admin` (§5j: users, groups, everyone's API keys and passkeys, lockouts) for
    the admin group, with a 403 page for anyone else.
  - **Two demo accounts:** `admin` and `alice` (not an admin).
  - **Also:** lockout tuned down to 5 failures per account so it is easy to trip, API keys minted on `/profile` and accepted by `/api/whoami` beside
  HTTP Basic (§5k), passkeys (§5l; browse to `http://localhost:3000`), and
  `POST /webhook-secret/rotate` — an app's own sensitive action behind `csrf::enforce` and
  `Auth::reauthenticate_with` (§5h, §7), reached from a `profile_extra` card, confirmable with
  a passkey, and answered with `Auth::profile_reply`. SSO is wired in when
  `SSO_GOOGLE_CLIENT_ID` / `SSO_GOOGLE_CLIENT_SECRET` are set, or any OpenID Connect provider's
  `SSO_OIDC_ISSUER` / `SSO_OIDC_CLIENT_ID` / `SSO_OIDC_CLIENT_SECRET`
  ([SSO_TESTING_KEYCLOAK.md](SSO_TESTING_KEYCLOAK.md) sets up Keycloak for it).
  `--set-admin-pw` is the break-glass path.
- **[`examples/adminpanel`](../examples/adminpanel/src/main.rs)** — a login-gated `crud::Admin`
  with CSRF on, content models behind `UserReadGroupWrite` (everyone reads, `admin` writes), the
  account tables (the library's `meta_model()`s) behind `GroupReadWrite` and shown only to managers,
  and the password policy from one `PASSWORD_LEVEL` setting. Logins: `admin` and `editor` (read-only).
- **[`examples/audit`](../examples/audit/src/main.rs)** — one observer on both `Auth` and `Crud` (API
  key mint and revoke included) and on the app's own API write (`WriteEvent::new`), and a request log
  built on `RealIp` that names an API-key caller from its handler (`/api/whoami`,
  `PUT /api/posts/{id}/title`). Its accounts tables, for the admin, show an account edit in the
  same audit trail.

## 9. Tests — the negative paths

Security behaviour is tested by rejection: `cargo test --all-features` drives the shipped routers
over in-memory SQLite and asserts the negative cases (bad credentials, unusable sessions, replayed
codes, refused writes, CSRF), each group with a positive control. What each test file covers is listed
in [AUTH-SECURITY.md → Tests](AUTH-SECURITY.md#tests--the-negative-paths); a change to login,
sessions, 2FA, passkeys, the profile pages, a gate or API keys extends them.
