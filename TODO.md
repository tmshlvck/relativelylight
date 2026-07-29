# TODO

Backlog for `relativelylight`, highest-impact first. See [docs/PRD.md](docs/PRD.md) for the product
roadmap and [docs/AUTH.md](docs/AUTH.md) for the auth design these expand on. Keep this list current:
tick/remove items as they ship, and add new ones with a one-line rationale.

> **Convention:** `- [ ]` is work still to do. A plain `-` bullet is a **recorded decision** — considered
> and rejected, or bounded on purpose — kept so the reasoning isn't re-derived when the idea resurfaces.
> An item whose only content is "this shipped" belongs in [CHANGELOG.md](CHANGELOG.md), not here.

## Next: cut 0.2.0

Everything the 0.2.0 cycle set out to do has landed — the security defaults are on, the schema and API
breaks are in, and `CHANGELOG.md`'s `## Unreleased` has the full upgrade path. Nothing below blocks the
tag; all of it is post-0.2.0 work.

- [ ] **Release 0.2.0**: rename `## Unreleased` to `## [0.2.0] — YYYY-MM-DD` + compare link, bump
  `relativelylight/Cargo.toml`, commit `Release v0.2.0`, tag, push the tag.

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
- [ ] **Breached-password screening.** The policy ships (`validate::PasswordPolicy`, AUTH.md §5g), but its
  common-value list is deliberately a **floor** — a few dozen perennial values plus keyboard walks, matched
  whole. The control NIST actually asks for is a check against **breach data**, which means either a local
  corpus (tens of MB: a data file or a feature-gated download, not a `const`) or an online lookup (HIBP's
  k-anonymity range API — a network call per password change, and a dependency an app may not want). Both
  are app-level calls, which is why `Auth::password_check(closure)` exists; the open question is only
  whether a *helper* for the HIBP form earns a feature flag, given it needs an HTTP client and a caching
  story.
- [ ] **CSRF on a multipart body** — the one deliberate gap. `csrf::enforce` reads the `X-CSRF-Token`
  header and, for URL-encoded bodies under 64 KiB, the `_csrf` field; a **multipart** body isn't parsed,
  because buffering an upload to find a token is worse than asking that surface to send the header. The fix
  is a streaming pre-scan that stops at the first non-field part — a chunk of work for a narrow case, so it
  waits for a real one (a file upload from a JS-less form).
- **No *username* whitelist for lockout.** Addresses can be exempted (`Lockout::ip_whitelist`); accounts
  can't, on purpose. An account that can never be locked out is an account whose password can be guessed
  at forever. If one is ever wanted it needs a better story than "skip the counter" — a raised limit, say.
- **Recovery-code backfill — not needed.** Codes are issued *with* the enrolment (AUTH.md §5i), so only an
  account that enrolled under an earlier version lacks a set, and no deployment has one. An auto-issue path
  would buy surprises (a set appearing mid-login, or a nag that only reaches people who visit their
  profile); an app that ever needs one calls `recovery::issue` itself. The profile page already says
  "None left" loudly.
- **SSO transaction cookie — deferred with cause; revisit only if the assumption stops holding.**
  `state`/`nonce`/PKCE ride in an unsigned cookie (AUTH.md §5b), so anyone able to *write* a cookie for the
  host can plant a transaction and produce a login CSRF (the victim signed in as the attacker). Signing was
  considered and rejected: `/sso/{key}/login` hands a genuine transaction to anyone who asks, so an attacker
  plants a validly signed one instead and nothing changes. It rests on the same assumption as the
  double-submit CSRF token. If a deployment ever *can't* hold that assumption (a shared registrable domain,
  http), the fix isn't a signature — it's binding the transaction to something server-side, which means
  state this module doesn't currently keep.

## middleware / cookies

- [ ] **Configurable cookie `SameSite`** — the real feature behind the CORS question. Session and CSRF
  cookies are hardcoded `Strict`, which is the right default and blocks two legitimate cases: a top-level
  cross-site GET landing on a logged-in page (wants `Lax`), and a cross-origin SPA using cookies (wants
  `None; Secure`, and would then lean entirely on the CSRF token). `Lax` is a small, safe addition; `None`
  should stay unsupported until app-issued tokens land, since it trades away the defence AUTH.md §7 calls
  defence-in-depth.
- [ ] **A principal in the access log.** `middleware::access_log` logs no username, because naming one
  means an `Auth::identify` — session + user + groups — on *every* request, including those that never
  needed an identity. The fix isn't more work in the log line; it's a way for a handler that already
  resolved the caller to hand that back (a response extension, say), so the log uses it when it's there
  and skips it when it isn't.
- **CORS — no wrapper; document it instead.** `tower_http::cors::CorsLayer` is self-contained (it answers
  preflight `OPTIONS` and sets the `Access-Control-*` headers); wrapping it would add a dependency and a
  layer of our opinions over zero logic. AUTH.md §4 carries the guidance, including the two things only
  this crate can tell you: allow **`x-csrf-token`** or every admin-UI write fails its preflight, and a
  cross-origin *browser* client can't use the session cookie at all (it's `SameSite=Strict`), so
  `allow_credentials` is beside the point and such a client wants a token.

## Auth features

- [ ] **App-issued API tokens** — a Bearer identity source resolving the same `Identity`.
- [ ] **SSO / OIDC leftovers** (none urgent). Base OIDC ships with cached discovery and fake-IdP coverage
  of the rejection paths (AUTH.md §5b, §10a). Left: refresh-token handling and `userinfo` (we read claims
  from the ID token only, which covers username + groups), RP-initiated logout at the provider
  (`end_session_endpoint`), and a smoke test against a real IdP as a *release* step rather than a CI one.
- [ ] **PassKeys / WebAuthn** as an additional second factor / passwordless — **milestone 0.3+**, not
  before. Deliberately parked: the enterprise apps driving this crate authenticate against passwords +
  TOTP (or their IdP via `sso`), so nothing needs it today, and it's a large surface — a `webauthn-rs`
  dependency, a credentials table, registration/assertion ceremonies with browser JS, and an assurance
  level on the session that a gate could require. That last part is why it wants its own milestone rather
  than a spare afternoon: `Identity` would likely gain a field, which is a source break. It stays the
  right answer to real-time phishing, which neither TOTP nor its replay guard addresses (AUTH.md §5a) —
  revisit when an app actually faces that threat.

## crud / engine

> **Adding to `MetaField` is free** (it's `#[non_exhaustive]`); publishing through `Column::Field` is not,
> because that *variant* can't be non-exhaustive without making the `Accessor` seam unimplementable out of
> crate — see the type's doc comment. So batch anything that needs publishing to the front end into one
> release rather than breaking twice.

- [ ] Batch relation reads (avoid N+1 on relation resolution). Keep it inside the SeaORM backend — the
  resolution already happens behind `Accessor::list`, so this can be **purely internal**; a new
  `Accessor` method would be a break for anyone implementing the seam.

## crud::ui / time

- [ ] Standalone `Form` component + per-field widget overrides. The widget override means another public
  `MetaField` field — batch it with the metadata additions above rather than breaking twice.
- **Timezone abbreviations — `GMT+1`/`GMT+2` is the wanted output.** Not a defect to fix: the offset is
  unambiguous and locale-independent, where an abbreviation asks the reader to know which one means +2, and
  the alternatives are worse (`timeZoneName: 'long'` varies by locale and can give "Central European
  Standard Time"; our own table would be ours to keep correct forever). DST itself is `Intl` + the
  browser's IANA database, verified across both transition instants — see
  [docs/TIME.md §2a](docs/TIME.md).

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
