# What an app must get right

The crate secures what it renders and the writes behind it; the rules below are the ones only the app
can keep, because they are about how it wires the crate in, what it writes itself, and what it
registers. Each is one line here and lives in full in the guide whose job it is; follow the link for
the how. The crate's own security reasoning (what each built-in rule defends against) is
[AUTH-SECURITY.md](AUTH-SECURITY.md); a whole app built the right way is [APP.md](APP.md).

Go through the list before a deployment goes out ([APP.md §9](APP.md#9-checklist) points here).

## Wiring

- [ ] **`middleware::resolve_real_ip` is the outermost layer** (the last `.layer`), with the right
      `TrustProxy` for how the app is deployed, and `serve` uses
      `into_make_service_with_connect_info::<SocketAddr>()`. Behind a CDN, write your own middleware
      inserting `RealIp`; there is no hook. The login routes and the crud writes answer `500` without
      it ([AUTH.md §4](AUTH.md#4-middleware-the-module-provides)).
- [ ] **Every write carries the CSRF token**: `crud.csrf(auth.csrf())` and `Upload::csrf` are set,
      every hand-written `POST` route is behind `csrf::enforce` (a multipart one checks the token
      itself), and `Csrf::max_upload` is above the largest upload a guarded route takes
      ([AUTH.md §7](AUTH.md#7-csrf-double-submit-token)).
- [ ] **`secure_cookies(true)` in production**, behind TLS (the default; `false` is for local http)
      ([AUTH.md §3](AUTH.md#3-identity-mechanism-server-side-session)).
- [ ] **With SSO, `Auth` is configured fully before `Sso::new(&auth)`** clones it, and
      `Sso::routes()` is mounted: an SSO account re-authenticates through its provider, and without
      the routes it is refused ([AUTH.md §5b](AUTH.md#5b-sso--openid-connect-feature-sso)).

## Gates

- [ ] **Every model is registered with a real gate.** `authz::Open` is public, writes included
      ([AUTH.md §6](AUTH.md#6-authz--the-gate)).
- [ ] **A handler that calls `Engine` directly asks `Engine::decide` first.** `Table::render_for`,
      `Form::submit` and the other components are where the gate is enforced; `Engine` itself is
      ungated ([CRUD.md → Reading and writing](CRUD.md#reading-and-writing)).
- [ ] **An API key never opens a page.** Only the machine endpoints that take a key call
      `Auth::identify_key`; a gate or page that accepted one would let a credential that skips 2FA
      into the UI ([AUTH.md §5k](AUTH.md#5k-api-keys)).
- [ ] **A restricted session reaches nothing new.** Below `Auth::min_level`, `identify` returns
      `None`; a section, action or key minting of the app's that bypassed `identify` would carry the
      account past the policy ([AUTH.md §5m](AUTH.md#5m-the-sign-in-policy-and-password-change-required)).

## Columns and tables

- [ ] **A display formatter escapes what it shows.** The HTML of `format_cell` / `format_view` is
      inserted verbatim: pass every value through `crud::fmt::esc`
      ([CRUD.md → Display formatters](CRUD.md#display-formatters--how-a-field-is-shown)).
- [ ] **`on_read` / `on_write` never mask a value.** They are a storage codec, an inverse pair that
      also fills the edit form; a secret is `write_only` or `hidden`, and shown differently by a
      formatter ([CRUD.md → A column's way in and out](CRUD.md#a-columns-way-in-and-out)).
- [ ] **`auth_*` tables are registered only through their `meta_model()`** (`user`, `group`,
      `api_key`, `passkey`, `lockout::{username,ip}_meta_model`), and `auth::recovery::entity` not
      at all: every row of it is a credential hash ([AUTH.md → The accounts panel](AUTH.md#the-accounts-panel)).

## Credentials the app handles itself

- [ ] **The app's own password form applies the policy** given to `Auth` (`user::meta_model(&auth)`
      on a `crud` field, or `validate::password`), or that form is the way around it
      ([AUTH.md §5g](AUTH.md#5g-password-strength)).
- [ ] **A helper of the app's that writes the owner's own password sets `must_change_password` to
      `false`** in the same write; otherwise the row hook flags it as set by someone else
      ([AUTH.md §5m](AUTH.md#5m-the-sign-in-policy-and-password-change-required)).
- [ ] **The app checking credentials itself uses the shared lockout counters**
      (`auth.username_lockout()` / `auth.ip_lockout()`), not a second limiter, and doesn't count a bad
      key again: `identify_key` already did ([AUTH.md §5e](AUTH.md#5e-lockout-the-brute-force-brake)).

## Files

- [ ] **Names never become paths**, uploads are invisible until complete, and a file is served by its
      owning record behind that record's gate ([FILES.md §4](FILES.md#4-the-apps-part)).
- [ ] **Stored files are served through `to_inline_response`**, never inline from a route of your
      own (SVG is an XSS vector), and `mime()` is never dispatched on
      ([FILES.md §5](FILES.md#5-security-notes)).
