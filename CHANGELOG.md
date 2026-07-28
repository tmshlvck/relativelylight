# Changelog

All notable changes to `relativelylight`, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow Cargo's semver for `0.x`
crates, where a **breaking change bumps the minor** (`0.1.x` is treated as one compatible range, so an
app depending on `"0.1"` must not be able to pick up a behaviour break silently).

Work that has landed on `main` but isn't tagged yet lives under **Unreleased**; releasing renames that
heading to the version + date and adds a compare link. Per-entry commit hashes are given where a change
is easy to miss in a diff.

## Unreleased

Next tag: **0.2.0** — this cycle turns security defaults *on*, which is a behaviour break for anything
already using `auth`.

### Breaking

- **`auth`'s own forms now require a CSRF token.** `POST /login`, `/login/totp`, and every `/profile*`
  write verify a double-submit token before anything else and answer `403` without it. The rendered
  fragments carry it, so a browser is unaffected — a **script that posts to `/login`** must now read the
  `rl_csrf` cookie and echo it in the `_csrf` field or the `X-CSRF-Token` header. (`9b97e02`)
- **`Auth::new` takes a second argument**: `Auth::new(db, Lockout { .. })`. The brute-force brake is
  mandatory and no longer a builder call — `Lockout::default()` is 10 failed logins per account and 100
  per source address, both for 15 minutes, with the socket peer untrusted. `login_limit`,
  `login_limit_per_ip`, `attempt_limit_per_ip`, `no_login_limit`, `clear_login_attempts` and
  `attempts()` are **gone**; the replacements are the config struct and
  `Auth::{username_lockout, ip_lockout}`. Tests or tooling that hammer `/login` set `username_after: 0`.
- **The counters live in the database**, in two new tables (`auth_username_lockout`, `auth_ip_lockout`,
  both in `table_create_statements`) instead of a process-local map. They survive restarts, are shared
  by every replica, and — the point — an operator **unlocks by deleting a row** in the ordinary admin
  panel, gated and audited like any other write, instead of restarting the service. An app with its own
  migrations needs a step for the two tables.
- **Only the unauthenticated checks are braked now.** `POST /login` and `POST /login/totp` count against
  the account and the address; the **profile password check and 2FA enrolment no longer count at all** —
  the caller there is authenticated, which is a session-theft problem, and counting it let a stolen
  session lock the real user out of logging in.
- **Nothing is scheduled by the crate.** Expired sessions and expired lockout rows are cleared by
  `auth::prune(&db, &lockout)`, which the **app** must call (startup + its own periodic loop). Previously
  the in-memory counters swept themselves; sessions were never cleaned at all.
- **`Lockout` is `Clone`, not `Copy`** (it carries the whitelist), and `auth::prune` takes it by
  reference — `clone()` it if you both construct `Auth` and keep a copy for a prune loop.
- **`auth::set_password` is a reset, not an upsert.** An unknown username is now an `Err` instead of
  creating an account, and it no longer sets `is_active = true`, so a password reset can't silently
  re-open a disabled account. Use `create_user` to create, or the new `reset_admin_access` for
  break-glass recovery. (`a4f14a7`)
- **An empty string submitted for a nullable column is stored as `NULL`**, not `""` (text / uuid / date
  / datetime; `NOT NULL` columns keep `""`). Opt out per field with `blank_is_null = false`. (`8419948`)
- **Two new columns on existing auth tables.** `auth_session.last_seen_at` (the idle clock) and
  `auth_user.totp_last_step` (the TOTP replay guard). `auth::migrate` only ever *creates* missing tables,
  so an existing database needs the `ALTER TABLE`s itself:
  ```sql
  ALTER TABLE auth_session ADD COLUMN last_seen_at BIGINT NOT NULL DEFAULT 0;
  ALTER TABLE auth_user    ADD COLUMN totp_last_step BIGINT NULL;
  ```
  With `DEFAULT 0` every existing session reads as idle-expired and everyone signs in once more — the
  safe direction. Backfill `last_seen_at` to "now" instead if you'd rather not. If you register
  `auth_user` in an admin panel, mark the new column `hidden` (see `examples/adminpanel`).
- **Sessions now expire when idle**, after 8 hours by default, *inside* the unchanged 7-day absolute
  lifetime. `Auth::session_ttl_secs` keeps its exact meaning (the absolute deadline, and the cookie's
  `Max-Age`); the new clock is `Auth::session_idle_secs`, and `session_idle_secs(0)` restores the old
  behaviour exactly. Both are enforced by `Auth::identify`.
- **Completing the TOTP second factor changes the session id.** `POST /login/totp` now issues a new
  session and deletes the half-authenticated one instead of promoting it in place. A browser follows the
  `Set-Cookie` and notices nothing; a **script that holds the cookie value across the 2FA step** must
  re-read it from the response.
- **Changing a password signs out that user's other sessions**, and a manager's reset at
  `POST /profile/{id}` signs out *all* of the target's. Previously a stolen cookie survived the password
  change meant to evict it. A script that keeps a session across its own password change must re-read
  the cookie (`POST /profile` returns a replacement).
- **A TOTP code can only be used once** (RFC 6238 §5.2). Codes were valid for their whole ±1-step window,
  about 90 seconds, however many times they were presented. A replayed code is now refused exactly like a
  wrong one — and, deliberately, is *reported* like one, so a captured code isn't confirmed as genuine.
  Test suites that reuse one code for two logins in the same 30-second step will need a fresh code.
- **Source-level:** `MetaField` gained public fields (`nullable`, `blank_is_null`) and
  `crud::ColumnMeta::Field` gained `nullable` — struct-literal construction and exhaustive matches need
  updating, which matters if you implement the `Accessor` seam yourself. `crud::Error` gained a `Csrf`
  variant. `session::Model` and `user::Model` each gained a public field (above), so struct-literal
  construction of those needs updating too.

### Added

- **`csrf` module** (feature `csrf`, implied by `auth`) — the double-submit token from AUTH.md §7:
  `Csrf::{issue, ensure, token, verify, clear_cookie, hidden_input}`, `Auth::csrf()`,
  `Auth::csrf_cookie_name()`, and `Crud::csrf(..)` / `Engine::set_csrf(..)` to require
  `X-CSRF-Token` on API writes (off by default; `Authorization`-bearing requests are always exempt).
  `crud::ui`'s tables add the header to their write `fetch` calls automatically.
- **`auth::lockout`** (AUTH.md §5e) — the brake, as two DB-backed counters with deliberately separate
  types: `UsernameLockout` (by account name) and `IpLockout` (by source address), configured by the
  `Lockout` struct on `Auth::new`. `locked` / `record_failure` / `clear` / `prune`, all async. A failure
  upserts a row unless the key is already locked (so a lock can't be held open); a key is locked while
  `failures >= after` and `last_failure_at + duration > now`.
- **`Auth::username_lockout()` / `Auth::ip_lockout()`** — the same counters, for the credential checks an
  app makes *itself* (API tokens, HTTP Basic on a machine endpoint). One account has one budget across
  every surface, and one row delete frees all of them. Worked example: `examples/auth`'s
  `GET /api/whoami`.
- **`Auth::prune()`** — one housekeeping call for dead sessions (**both** clocks) *and* expired lockout
  rows, scheduled by the app (both examples run it hourly). The free `auth::prune(&db, lockout)` still
  works but sees only the absolute session deadline, since it has no `Auth` to read `session_idle_secs`
  from; prefer the method.
- **`Auth::session_idle_secs(secs)`** — the idle session clock (default 8 hours, `0` to disable), backed
  by `auth_session.last_seen_at` and refreshed lazily (at most once a minute per session, so resolving an
  identity stays a read on almost every request). AUTH.md §5f.
- **`Auth::revoke_sessions(user_id)` / `Auth::revoke_other_sessions(user_id, keep)`** — sign a user out
  everywhere, or everywhere but here. Call them when *your* code decides a user's sessions are void (an
  account you disabled, a group sync that removed access, an operator's force-logout button).
- **"Sign out other sessions" on `/profile`** (`POST /profile/sessions/revoke`) — the self-service form of
  the above, CSRF-checked like every other unsafe auth route. If your app already routes that path,
  rename it: axum panics on an overlap when `auth.routes()` is merged.
- **`relativelylight::net`** — client-address resolution, the real-ip work AUTH.md §4
  promised: `net::client_ip(trust_proxy, headers, peer)` picks the socket peer or the **right-most**
  `X-Forwarded-For` hop (falling back to `X-Real-IP`) and collapses IPv4-mapped addresses, so one client is one key
  across your logs, audit rows and limits. `Lockout::trust_proxy` feeds it for the login routes, and
  `Auth::client_ip(closure)` overrides it for stranger chains (several hops, a CDN header). The module
  also carries the CIDR helpers that go with an address — `parse_nets`, `in_nets`, `canonical_net` —
  which match across both families and the IPv4-mapped form.
- **`Lockout::ip_whitelist`** — CIDRs that are never counted and never locked out (an office range, a
  monitoring probe, a NAT a fleet shares), on every surface at once. No username equivalent, on
  purpose: an account that can never lock is an account that can be guessed at forever.
- **`auth::reset_admin_access`** — break-glass admin recovery for a `--set-admin-pw`-style flag: sets
  the password, re-activates the account, clears TOTP, ensures admin-group membership, and refuses SSO
  accounts.
- **Blank-tolerant accessors on `user::Model`** — `sso_key`, `is_sso`, `totp_key`, `has_totp`,
  `pending_totp_key`, plus `auth::normalize_blank_user_columns(&db)` to tidy rows already stored with
  `""`.
- **Nullability in the metadata** — introspected from `ColumnDef::is_null()`, exposed as
  `"nullable": true` in the entity metadata and as an OpenAPI 3.1 type union
  (`"type": ["string","null"]`), and used by the admin form to send `null` for an empty nullable input
  and to mark NOT-NULL-without-default columns with a `*`.
- **The admin create/edit modal is a real `<form>`** — <kbd>Enter</kbd> saves, and a browser's password
  manager gets one clean save prompt instead of re-offering the previously created account's password.
- **A `--set-admin-pw` break-glass flag in `examples/adminpanel`** too, so both auth-using examples
  demonstrate the same discipline: one `ADMIN_GROUP` constant drives the gate, `Auth::admin_group`, the
  boot-time seeder *and* the recovery path (they must never drift apart — an "admin" outside the group
  the gate checks can't administer anything).
- **An SSO callback test suite** (`auth/sso_tests.rs`, feature `sso`) — the shipped OIDC client driven
  against a **fake identity provider** on a loopback port (real discovery over HTTP, real RSA signatures),
  so the callback's rejection paths run in CI: no transaction cookie, forged/truncated/missing `state`, a
  transaction cashed in at another provider, and ID tokens signed by an untrusted key or carrying the wrong
  audience, wrong issuer, an expired `exp`, or another nonce — plus disabled, local, and wrongly-bound
  accounts. A live IdP can't produce those cases; that's why the fake one exists. See AUTH.md §10a.
- **Negative-path test suites** (`auth/security_tests.rs`, `crud/gate_tests.rs`) — the shipped routers
  driven over in-memory SQLite, asserting the rejections: bad credentials, unusable sessions, wrong
  TOTP codes, non-manager profile writes, every gate preset's decision, and that a denied request never
  reaches the backend. See AUTH.md §10a for what they cover and what they deliberately don't.

### Fixed

- **An account created in the admin panel could never log in.** A blank `sso_provider` (what an empty
  text input writes) counted as an SSO account, so password login was refused and the profile page
  offered nothing to change. (`98f4964`)
- **A blank `totp_secret` locked an account out permanently** — it demanded a login code no
  authenticator can produce, and burned the attempt-limit budget trying. (`c9d8957`)
- **A manager password reset silently re-enabled a disabled account** (`set_password` set
  `is_active = true`). (`a4f14a7`)
- **SSO ignored `is_active`.** A **disabled** account could complete an OIDC login: it never authenticated
  (`identify` re-checks the flag) but the callback still reconciled the account's groups, stamped
  `last_login_at`, and minted a session row — so "disable this account" meant one thing on the password
  door and another on the SSO door, and the audit trail recorded a login that never happened.
- **Provider discovery was fetched on every request**, twice per sign-in. It is now cached per provider for
  an hour (signing keys included). Besides the two round-trips, this made a sign-in fail whenever the
  provider's discovery endpoint was briefly slow, and — since `/sso/{key}/login` needs no authentication —
  let anyone turn a request loop into a flood of outbound traffic aimed at your provider.
- **A database error during SSO account lookup was returned verbatim** to an unauthenticated caller,
  putting SQL and schema detail in an HTTP response body. It is now a generic message.
- **A rejected SSO callback left its transaction cookie in place** for the rest of its ten minutes; every
  exit now clears it.
- **The SSO username claim is matched case-insensitively.** A provider that changed the case of what it
  emits would otherwise miss the existing account and, with auto-registration on, create a second one —
  two rows and two group sets for one person. Local password login still matches exactly.
- **Two concurrent first logins for the same new SSO user** raced on the unique index and produced a 500;
  the loser now re-reads the row the winner wrote.
- **A manager's password reset is refused for an SSO account**, the way the self-service page already
  refused itself, and `GET /profile/{id}` shows a notice instead of a reset form. It was never a bypass
  (`verify_credentials` refuses any `sso_provider` account) but it stored a hash that could never
  authenticate and read, in the audit trail, like a real credential.
- **Chrome re-offered the last-created account's password** on every subsequent save in the admin
  modal, because the secret stayed in a hidden input. (`98f4964`)

### Security

- **`net::client_ip` reads the right-most `X-Forwarded-For` entry, not the left-most.** A proxy appends
  the address it observed to whatever the caller sent (nginx `$proxy_add_x_forwarded_for`, HAProxy
  `option forwardfor`, Caddy), so the left-most entry is caller-controlled: reading it let anyone choose
  their own address and thereby pass an IP admission list, sit inside a lockout whitelist, dodge a
  lockout by rotating the value, or file audit rows under someone else's address. Deployments whose
  proxy *replaces* the header are unaffected (one entry, same answer). If you have two trusted hops, the
  right-most is the inner proxy — override the resolution with `Auth::client_ip` there. A trusted-proxy
  CIDR list was considered and rejected; `trust_proxy: bool` is the permanent shape (AUTH.md §4).

- **Session fixation at the second factor is closed.** `POST /login/totp` used to elevate the same session
  id from half- to fully-authenticated. An attacker who knew the password could obtain a pending session,
  plant its cookie in the victim's browser (cookie-tossing from a sibling host, or an XSS — `Secure` and
  `SameSite` don't prevent either), send them to `/login/totp`, and inherit a full session as soon as the
  victim entered their own code. The id is now rotated and the old row deleted.

- **A password change now evicts the sessions it was meant to evict**, and a TOTP code can no longer be
  replayed within its ~90-second validity window. Both are documented in AUTH.md §5f / §5a — including
  what the replay guard does *not* buy: real-time phishing proxies relay a code once, so they are
  unaffected, and only a phishing-resistant factor (WebAuthn) addresses them.

- CSRF protection and the login lockout close the two gaps AUTH.md had listed as open. Documented
  limits: per-source-IP counting on *our* login routes only happens once the app supplies a
  `client_ip` resolver, because the library refuses to guess an address it can't trust — behind a reverse
  proxy the socket peer is the proxy, and a shared bucket could lock out every user. An app with its own
  credential surfaces shares these counters rather than running a second limiter, so an account can't be
  given two budgets. Durable lockouts also make griefing durable (a restart no longer clears one), which
  is why the lock is short and the admin panel can delete the row.
- Still open (see [TODO.md](TODO.md)): re-authentication before disabling 2FA or changing a password,
  TOTP recovery codes and a replay guard, session-id rotation on privilege change, and invalidating a
  user's other sessions after a password change.

### Upgrading

1. If you want CSRF on the JSON API (recommended for a cookie-authenticated admin), add
   `crud.csrf(auth.csrf());` — the admin UI then sends the header on its own.
2. If anything scripts `POST /login`, teach it the token, or exempt it with an `Authorization` header.
3. Replace `set_password` calls that were creating accounts with `create_user`, and point a
   `--set-admin-pw`-style flag at `reset_admin_access`.
4. Run `auth::normalize_blank_user_columns(&db)` once to null out blank `sso_provider` /
   `totp_secret` / `totp_pending` values written by earlier versions.
5. If a test or job makes many failed logins, call `.no_login_limit()` on that `Auth` or raise
   `.login_limit(..)`.
6. Pass a `Lockout` to `Auth::new`, drop any `login_limit*` / `no_login_limit` builder calls, and add a
   migration step for `auth_username_lockout` + `auth_ip_lockout`.
7. Schedule `auth::prune(&db, lockout)` — nothing else cleans expired sessions or lockout rows.
8. If your app authenticates callers itself, route those checks through `auth.username_lockout()` /
   `auth.ip_lockout()` (AUTH.md §5e) and delete any limiter of your own. Register the two entities in
   your admin panel so operators can unlock; there is no longer a `clear_login_attempts` call.

## [0.1.2] — 2026-07-23

Adds `relativelylight::validate` (reusable typed field validators + normalizers, shared by the CRUD
write path and hand-written APIs) and username / group-name validation in `auth`.

## [0.1.1] — 2026-07-22

Renames the authorization presets to a consistent `<ReadAudience>Read<WriteAudience>Write` scheme
(`ValidUsers` → `UserReadWrite`, `UsersReadGroupWrite` → `UserReadGroupWrite`, `AdminOnly` →
`GroupReadWrite`) and adds the missing corner, `PublicReadGroupWrite`.

## 0.1.0

First published release: the `crud` engine + SeaORM backend, the Bootstrap/Alpine admin UI, OpenAPI and
CSV adapters, and the `auth` module (sessions, login, TOTP 2FA, OIDC SSO, per-model gates).

[0.1.2]: https://github.com/tmshlvck/relativelylight/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/tmshlvck/relativelylight/compare/v0.1.0...v0.1.1
