# TODO

Backlog for `relativelylight`, highest-impact first. See [docs/PRD.md](docs/PRD.md) for the product
roadmap and [docs/AUTH.md](docs/AUTH.md) for the auth design these expand on. Keep this list current:
tick/remove items as they ship, and add new ones with a one-line rationale.

## Security hardening (auth)

Highest priority first.

- [ ] **Re-authenticate before sensitive changes.** Require the current password (or a fresh TOTP
  code) before disabling 2FA, changing the password, or (later) removing a PassKey. Now the **top**
  security item: with sessions bounded (§5f) the remaining hole is a *live* stolen session turning 2FA
  off. Note the shape of the break — `POST /profile/totp/disable` and friends gain a required field, so
  it's a wire break for anything scripting those forms, and a "fresh auth" window would want another
  `auth_session` column (worth batching with any other schema change).
- [ ] **TOTP recovery / backup codes.** One-time recovery codes issued at enrolment, so a user who
  loses their authenticator isn't locked out (today only a manager can disable their 2FA). Costs a new
  table (so a migration step for apps) and a new route — check it against the app's own routes, since
  axum panics on an overlap at merge time. Decide what happens for users already enrolled with no codes.
- [ ] **Lockout follow-ups.** The two DB-backed counters ship (AUTH.md §5e), durable, shared by every
  replica and by the app's own credential checks, with the unlock being a row delete in the admin panel.
  Address **whitelists** ship too (`Lockout::ip_whitelist`, CIDRs across both families and the mapped
  form). A *username* whitelist was considered and rejected: an account that can never be locked out is
  an account whose password can be guessed at forever, so if one is ever wanted it needs a better story
  than "skip the counter" — a raised limit, perhaps.
- [ ] **CSRF follow-ups.** The double-submit token ships (AUTH.md §7). Remaining: a `Csrf` layer for
  app-owned unsafe routes (today each handler calls `Csrf::verify` itself), and a rejection hook so an
  app can render the 403 in its own shell instead of the built-in page.
- [ ] **Cross-cutting middleware (AUTH.md §4).** Client-IP resolution ships as `net::client_ip`
  (`trust_proxy` → peer or the **right-most** `X-Forwarded-For` hop / `X-Real-IP`, IPv4-mapped collapsed),
  used by the lockout. A trusted-proxy **CIDR list** and RFC 7239 `Forwarded` were considered and
  **rejected**: one trusted hop is exactly what a firewalled port behind nginx/Caddy or a cluster ingress
  is, the boolean is a permanent part of the API, and stranger chains (a CDN ahead of your own proxy, a
  provider header) override the resolution wholesale with `Auth::client_ip` — which already exists, and
  costs no configuration surface for the deployments that don't need it. Remaining: a
  `ClientIp` extractor/layer so apps stop threading `(headers, peer)`, structured request logging, and a
  configurable CORS layer.
- [ ] **Password-complexity validator (`validate::password`) — low priority.** Nothing enforces password
  strength today: not the admin UI, not the JSON API, and not `POST /profile` (`password_pair_error` only
  checks non-empty + match). The `crud` pipeline is already the right shape — the order is **coerce →
  validate → transform** (`MetaModel::prepare_write`, CRUD.md § Validation), so a field validator sees the
  **plaintext** before `MetaField::password()`'s argon2 `on_write` hashes it, and
  `user.field("password_hash").validate_str(validate::password(..))` needs no engine change. Wanted: a
  `PasswordPolicy { min_len, require_upper, require_digit, require_special, blocklist }` plus three
  presets, so an app maps a config value (`password_level = 2`) onto one:
  1. ≥ 6 chars with at least one capital **or** digit;
  2. ≥ 8 chars with capitals, digits **and** specials;
  3. as (2), plus reject anything containing `password`, `user`, `auth`, `123`, … (case-insensitive
     substring).
  **Applies to a non-empty value only** — an empty secret keeps its existing meaning (blank on edit =
  "keep current", blank on create = login disabled), so the policy wraps in `validate::optional`.
  **One policy, both surfaces:** the *same* validator must run in the Admin UI/API (where the app
  chooses it per model) *and* on the self-service profile page — otherwise `/profile` stays a way around
  the rule. That means a home in `auth` too (`Auth::password_policy(..)`, honoured by `POST /profile`
  and, if it should apply there, `set_password`/`create_user`). Notes: a field validator only runs when
  the field is *present* in the body, so "a password is required" still needs `validate_row` or the
  planned `required` metadata; "must not contain the username" is inherently cross-field
  (`validate_row`, not this validator); and NIST SP 800-63B discourages composition rules in favour of
  length + a breached-password list, so a length-only + blocklist preset is worth offering as well.
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

> **Land the `MetaField` / `ColumnMeta::Field` additions together, in one release.** Both items below add
> public fields to those two types, which is a source break for exhaustive matches and struct literals —
> i.e. for anyone implementing the `Accessor` seam. One combined break costs a reader one upgrade note;
> three dribbled-out ones cost three. If the `Form` component's per-field widget override (below) is
> wanted too, it belongs in the same batch.

- [ ] **Enum `options`.** SeaORM reports `ColumnType::Enum { name, variants }`, so the variant list is
  **introspectable** — auto-discovered, no per-model code, consistent with the rest of the crate. Today
  an enum column falls through to a free-text input in the admin form and any string is accepted on
  write. Wanted: `MetaField::options: Vec<String>` (empty = not an enum), carried into `ColumnMeta`, the
  `_meta` JSON and OpenAPI (`"enum": [..]`), a `<select>` in the form, and membership enforced on write.
  Must stay hand-settable — a `DeriveActiveEnum` column stored as text (the common SQLite shape) reports
  as `String`, so the app supplies the list: `field("status").options = vec![..]`.
- [ ] **Engine-side `required` enforcement.** `nullable` ships (from `ColumnDef::is_null()`, in the
  metadata + OpenAPI, driving the `""`→`NULL` canonicalization). The admin form *already* derives
  "must fill" client-side (`mustFill` in `table.html`: not read-only, not nullable, no default) and marks
  the label `*`, but the comment there is honest — it's advisory, and the server still lets a missing
  `NOT NULL` column reach the database as a 500 instead of a 422 field error. Wanted: `MetaField::required`
  (same derivation, app-overridable), published in `ColumnMeta` so the UI and OpenAPI stop re-deriving it
  (OpenAPI could then emit a real `required: [..]` on the create schema), and checked in
  `MetaModel::prepare_write`.
  Two constraints that are easy to get wrong: enforce on **create only** — on PATCH an absent field means
  "unchanged", so requiring it would make partial updates impossible — and keep the existing skip rules
  (hidden / read-only / PK), which is what exempts a column filled by an
  `ActiveModelBehavior::before_save` hook, *provided* the app marked it read-only. `auth_user`'s
  `created_at` / `updated_at` are exactly that shape: both examples mark them read-only, an app that
  didn't would start getting 422s. Hence the per-field opt-out, and a loud release note.
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
