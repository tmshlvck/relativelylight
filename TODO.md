# TODO

Backlog for `relativelylight`, highest-impact first. See [docs/PRD.md](docs/PRD.md) for the product
roadmap and [docs/AUTH.md](docs/AUTH.md) for the auth design these expand on. Keep this list current:
tick/remove items as they ship, and add new ones with a one-line rationale.

## Security hardening (auth)

Highest priority first.

- [ ] **Re-authenticate before sensitive changes.** Require the current password (or a fresh TOTP
  code) before disabling 2FA, changing the password, or (later) removing a PassKey.
- [ ] **TOTP recovery / backup codes.** One-time recovery codes issued at enrolment, so a user who
  loses their authenticator isn't locked out (today only a manager can disable their 2FA).
- [ ] **TOTP replay guard.** Reject a code that was already used within its 30s window (track the last
  accepted step per user) to prevent replay inside the skew window.
- [ ] **Lockout follow-ups.** The two DB-backed counters ship (AUTH.md §5e), durable, shared by every
  replica and by the app's own credential checks, with the unlock being a row delete in the admin panel.
  Remaining: **allow-lists** — usernames by regex and addresses by CIDR, so a service account or an
  office range is never locked out (the two types are separate precisely so these can differ). The
  client address is the app's to resolve (`Auth::client_ip`), so the real-ip middleware below would
  only make that wiring optional, not fix a gap.
- [ ] **CSRF follow-ups.** The double-submit token ships (AUTH.md §7). Remaining: a `Csrf` layer for
  app-owned unsafe routes (today each handler calls `Csrf::verify` itself), and a rejection hook so an
  app can render the 403 in its own shell instead of the built-in page.
- [ ] **Cross-cutting middleware (AUTH.md §4).** Client-IP resolution now exists as `net::client_ip`
  (`trust_proxy` → peer or left-most `X-Forwarded-For`/`X-Real-IP`, IPv4-mapped collapsed), used by the
  lockout. Remaining: a trusted-proxy **CIDR list** instead of one boolean, RFC 7239 `Forwarded`, a
  `ClientIp` extractor/layer so apps stop threading `(headers, peer)`, structured request logging, and a
  configurable CORS layer.
- [ ] **Session hardening.** Rotate the session id on privilege change (login, 2FA completion),
  optional idle vs. absolute timeout, and "sign out everywhere" (delete a user's sessions). Include
  invalidating a user's **other** sessions when their password is changed or reset by a manager —
  today a stolen cookie survives the password change that was meant to kick it out.
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
- [ ] **Guard the manager reset on SSO accounts.** `POST /profile/{id}` writes a local password hash
  onto an `sso_provider` account (login is still refused, so it's hygiene, not a bypass) — refuse it
  the way the self-service page already does.

## Auth features

- [ ] **SSO / OIDC follow-ups.** Base OIDC ships (feature `sso`, AUTH.md §5b). Remaining: cache
  provider discovery (currently fetched per-request); verify the callback against a live IdP.
- [ ] **PassKeys / WebAuthn** as an additional second factor / passwordless.
- [ ] **App-issued API tokens** — a Bearer identity source resolving the same `Identity`.
- [ ] **Row-level authorization** — per-row read checks / list filters (the gate seeing the row/query).

## crud / engine

- [ ] Second backend behind the `Accessor` seam (in-memory or another ORM).
- [ ] Batch relation reads (avoid N+1 on relation resolution).
- [ ] Composite-PK URL token + a `row_key` escape hatch.
- [ ] Richer field metadata: enum `options`, and **engine-side `required` enforcement**. `nullable`
  now ships (read from `ColumnDef::is_null()`, in the metadata + OpenAPI, driving the `""`→`NULL`
  canonicalization and the form's `*` marker), but a missing `NOT NULL` column is still whatever the
  database says (a 500) rather than a 422 field error. Enforcing presence needs care: columns filled by
  an `ActiveModelBehavior::before_save` hook (`created_at`/`updated_at`) are legitimately absent from the
  body, so it needs an opt-out per field rather than a blanket derive.

## crud::ui / time

- [ ] Standalone `Form` component + per-field widget overrides.
- [ ] Transactional CSV import.
- [ ] Nicer timezone abbreviations in `time` (Intl `short` yields `GMT+2`, not `CEST`).
