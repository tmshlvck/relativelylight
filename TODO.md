# TODO

Backlog for `relativelylight`, highest-impact first. See [docs/PRD.md](docs/PRD.md) for the product
roadmap and [docs/AUTH.md](docs/AUTH.md) for the auth design these expand on. Keep this list current:
tick/remove items as they ship, and add new ones with a one-line rationale.

## Security hardening (auth)

Highest priority first.

- [ ] **Re-authenticate an SSO account through its identity provider.** Re-auth ships for local accounts
  (AUTH.md §5h: password or a fresh TOTP code, on the four sensitive routes, plus
  `Auth::reauthenticate` for app-owned ones). An account with **no local factor** — every SSO login —
  passes unchallenged, because there is nothing to ask it for and refusing would lock SSO administrators
  out of the manager pages for good. The real answer is an OIDC round-trip with `prompt=login` (or
  `max_age=0`) that returns to the pending action, which needs somewhere to park that action across the
  redirect — the first piece of server-side state this module would keep for a half-finished request, so
  it wants designing rather than bolting on. Until then §5h states the limit plainly.
  (A time-boxed "you confirmed recently" window was also considered and rejected: it needs an
  `auth_session` column *and* reopens a period in which a stolen session is dangerous again. These
  actions are rare enough to confirm every time.)
- **Recovery-code backfill — decided: not needed.** Recovery codes ship (AUTH.md §5i) and are issued with
  the enrolment, so only accounts that enrolled in 2FA under an *earlier* version lack a set. No production
  deployment has such an account, so there is nothing to migrate and no auto-issue path is worth its
  surprises (a set appearing mid-login, or a nag that only reaches people who visit their profile). An app
  that ever does need one calls `recovery::issue` itself. The profile page already says "None left" loudly,
  which covers the case honestly.
- [ ] **Lockout follow-ups.** The two DB-backed counters ship (AUTH.md §5e), durable, shared by every
  replica and by the app's own credential checks, with the unlock being a row delete in the admin panel.
  Address **whitelists** ship too (`Lockout::ip_whitelist`, CIDRs across both families and the mapped
  form). A *username* whitelist was considered and rejected: an account that can never be locked out is
  an account whose password can be guessed at forever, so if one is ever wanted it needs a better story
  than "skip the counter" — a raised limit, perhaps.
- [ ] **CSRF follow-ups — both listed items have shipped** (AUTH.md §7): `csrf::enforce` is the layer for
  app-owned unsafe routes, and `Auth::csrf_rejection` / `Csrf::on_reject` is the rejection hook, shared by
  the library's forms and the layer. What's left is a deliberate gap: the layer reads the `X-CSRF-Token`
  header and, for URL-encoded bodies under 64 KiB, the `_csrf` field — a **multipart** body is not parsed,
  because buffering an upload to find a token is worse than asking that surface to send the header. If a
  real app hits it (a file upload from a JS-less form), the fix is a streaming pre-scan that stops at the
  first non-field part: a chunk of work for a narrow case, so it waits for the case.
- [ ] **A CORS layer (AUTH.md §4)** — the last of the cross-cutting middleware. Client-IP resolution and the
  access log **shipped** as `middleware::resolve_real_ip` (mandatory, one `RealIp` extension read by every
  consumer) and `middleware::access_log`; the `trust_proxy` boolean is final, and there is deliberately no
  resolver hook — a stranger topology writes its own middleware inserting the same extension. What remains
  is CORS, which needs none of that (it is about `Origin`): a thin `tower_http::cors` wrapper with defaults
  that suit a cookie-auth app, i.e. *not* `Any` with credentials on, which the spec forbids and browsers
  reject. Also still open: an access-log line that can name the principal without paying an `identify` per
  request, which needs a way for a handler to hand back the identity it already resolved.
- [ ] **Breached-password screening.** The policy ships (`validate::PasswordPolicy`, AUTH.md §5g:
  length-first, no composition rules, on by default on both surfaces, opt-out two ways). Its
  common-value list is deliberately a **floor** — a few dozen perennial values plus keyboard walks,
  matched whole. The real control NIST asks for is a check against **breach data**, which means either a
  local corpus (tens of MB, so a data file or a feature-gated download, not a `const`) or an online
  lookup (HIBP's k-anonymity range API — a network call per password change, and a dependency an app may
  not want). Both are app-level decisions, which is why `Auth::password_check(closure)` exists; the open
  question is whether a *helper* for the HIBP form is worth shipping behind a feature, given it needs an
  HTTP client and a caching story.
- [ ] **Sign or otherwise bind the SSO transaction cookie — only if the assumption stops holding.**
  Analysed and **deferred with cause** (AUTH.md §5b): `state`/`nonce`/PKCE ride in an unsigned cookie, so
  anyone able to *write* a cookie for the host can plant a transaction and produce a login CSRF (the victim
  signed in as the attacker). Signing was considered and rejected — `/sso/{key}/login` hands a genuine
  transaction to anyone who asks, so an attacker plants a validly signed one instead and nothing changes.
  It rests on the same assumption as the double-submit CSRF token. If a deployment ever *can't* hold that
  assumption (a shared registrable domain, http), the fix isn't a signature — it's binding the transaction
  to something server-side, which means state the module currently doesn't keep.

## Auth features

- [ ] **SSO / OIDC follow-ups.** Base OIDC ships (feature `sso`, AUTH.md §5b), and so now do the two
  follow-ups that were listed here: provider discovery is **cached** (one hour, per provider, keys
  included), and the callback is **covered by tests** — against a fake IdP on a loopback port rather than a
  live one, which is what makes the rejection paths (wrong key, wrong audience, wrong issuer, expired,
  replayed nonce) testable at all (AUTH.md §10a). Remaining, none of it urgent: refresh-token handling and
  `userinfo` (we read claims from the ID token only, which is enough for username + groups), RP-initiated
  logout at the provider (`end_session_endpoint`), and a smoke test against a real IdP as a *release* step
  rather than a CI one.
- [ ] **PassKeys / WebAuthn** as an additional second factor / passwordless — **milestone 0.3+**, not
  before. Deliberately parked: the enterprise apps driving this crate authenticate against passwords +
  TOTP (or their IdP via `sso`), so nothing needs it today, and it's a large surface — a `webauthn-rs`
  dependency, a credentials table, registration/assertion ceremonies with browser JS, and an assurance
  level on the session that a gate could require. That last part is why it wants a milestone of its own
  rather than a spare afternoon: `Identity` would likely gain a field, which is a source break.
  It stays the right answer to real-time phishing, which neither TOTP nor its replay guard addresses
  (AUTH.md §5a) — revisit when an app actually faces that threat.
- [ ] **App-issued API tokens** — a Bearer identity source resolving the same `Identity`.

(Row-level authorization moved to *Transformative* below — it reshapes the `Authz` trait rather than
adding to it.)

## crud / engine

> **Adding to `MetaField` is free** (it's `#[non_exhaustive]`); publishing through `Column::Field` is not,
> because that *variant* can't be non-exhaustive without making the `Accessor` seam unimplementable out of
> crate — see the type's doc comment. `required` and enum `options`, the two additions this note was written
> for, have both shipped (CRUD.md § Required columns, § Enumerations), so the batching advice now applies
> only to whatever comes next.

- [ ] Batch relation reads (avoid N+1 on relation resolution). Keep it inside the SeaORM backend — the
  resolution already happens behind `Accessor::list`, so this can be **purely internal**; a new
  `Accessor` method would be a break for anyone implementing the seam.

## crud::ui / time

- [ ] Standalone `Form` component + per-field widget overrides. The widget override means another public
  `MetaField` field — batch it with the metadata additions above rather than breaking twice.
- [ ] Transactional CSV import.
- [ ] Nicer timezone abbreviations in `time` (Intl `short` yields `GMT+2`, not `CEST`).

## Transformative — deferred until there is real demand

Not scheduled, and not "someday" items either: each one **reshapes a published interface** rather than
adding to it, so it changes the crate's contract with every existing user. None is worth starting on
spec — only when a concrete requirement arrives that can't be met any other way, and then deliberately,
timed with a minor bump. The reasoning is recorded here so it doesn't have to be re-derived each time
one of them looks tempting.

- **Row-level authorization** — per-row read checks / list filters, i.e. the gate seeing the row or the
  query rather than just the headers. Wanted often enough to keep re-proposing itself, but `Authz` is the
  one trait apps implement by hand, so the shape matters more than the feature: it must arrive as
  **additional** methods carrying default impls, never a changed `authorize` signature, and `Decision`
  must stay fieldless (it's `Copy`, and a variant with a payload would remove that as well as breaking
  exhaustive matches). The list-filter half also reaches into `ListQuery` and probably `Accessor`, which
  is what makes it transformative rather than additive. Meanwhile an app that needs per-row rules can
  enforce them in its own handler, as `/profile/{id}`'s self-or-manager check already does.
- **Composite-PK URL token + a `row_key` escape hatch.** Every entity today has a single-column PK, and
  the seam is built on it: `Accessor::pk() -> String`, the `/{entity}/{id}` URL shape, and `RowItem.id`.
  Widening `pk()` breaks every `Accessor` implementation, including any an app wrote itself. Revisit only
  when a real composite-PK table needs exposing through auto-CRUD; a `row_key` hatch *could* arrive
  additively (a new trait method with a default impl) if the requirement turns out to be narrower than
  full composite-key support. Junction tables don't count — they're never registered.
- **A second backend behind the `Accessor` seam** would very likely force changes to that trait, which is
  public and documented as the extension point. Worth doing partly *because* it would flush out the gaps
  — but it should be timed with a minor bump, not slipped into a patch.
