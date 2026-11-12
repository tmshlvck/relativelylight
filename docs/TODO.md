# TODO

Open work, highest impact first, and the only place for it. `- [ ]` is work to do; a plain `-` is a
**decision** (rejected or bounded on purpose), kept so it isn't re-derived. Shipped work goes to
[CHANGELOG.md](../CHANGELOG.md); the design is [DESIGN.md](DESIGN.md).

## crud / crud::ui

- [ ] **Customisable search.** `q` is `LIKE '%term%'` over the entity's own text columns only. Let an
  app search relation labels (a record by its zone's origin) and supply its own search (full-text,
  a `tsvector`, an external index) per entity. Asked for by CLIMB; bigger than a builder flag, since
  it reaches the `Accessor` seam.
- [ ] **Range filter on a native `DateTime` column.** `Table::range_filter` reads integer
  `.datetime()`, number, `Date` and text columns; a naive `DateTime` has no zone to read the day in.
- [ ] **More filter operators** (`filter[ttl][gt]=300`, `[is_null]`). `[from]`/`[to]` ranges and the
  `fixed_in` set pin have shipped; the URL grammar nests for the rest. Wait for a real need.
- [ ] **Ask each gate once per request.** A built-in gate resolves the caller (session, user,
  groups: a few queries) on every `permits`/`decide`. One render asks several: the table's
  controls, each linked relation's Read, a form's relation fields (memoised per form since the
  relation dialogs; not across the table, its links and its dialog). A per-request memo keyed by
  `(slug, op)`, or resolving the identity once and handing it to `Authz`, would make it one. Cheap on
  SQLite; it adds up on a busy list page with a remote database.
- [ ] **A standalone `Form` writes only what it is.** `Form::new` still accepts a posted update and
  `Form::edit(id)` a create, or an update of another `_id`; the picker's forms are already strict
  (`Form::embedded`). Making every `Form` strict closes it for app pages too, but breaks an app that
  renders `.edit(id)` and submits with a plain `Form::new`: a minor bump with a migration step.
- [ ] **Cross-document view transitions** for POST → 303 → GET. Cheap to try, easy to get wrong (a 422
  re-render animated as a navigation).
- **`Table`'s API is stable for 0.4** — no split into `List`/`Search`/… pieces; the per-action
  switches cover turning a control off.
- **No browser tests in CI**; `ui_tests.rs` covers the server half of the picker.
- **No timezone abbreviations per cell.** The zone is named once per page.
- **No type-changing codec until needed.** Cents shown as `12.34` is a formatter plus a validated
  input.
- **No charts.** Tooltips need a client runtime and SVG can't measure text; use Chart.js on a page of
  your own.

## auth

- [ ] **Re-authenticate SSO accounts through the IdP** (`prompt=login`), which needs somewhere to park
  the pending action across the redirect. Until then an account with no local factor passes
  re-authentication (AUTH.md §5h).
- [ ] **Audit logins and 2FA enable/disable.** Password changes, resets, recovery-code reissue and
  session revocation fire `WriteEvent`s; these don't yet (`last_login_at` records logins).
- [ ] **Breached-password screening** (HIBP range API or a local corpus). Possible today through
  `Auth::password_check`; the question is whether a helper earns a feature flag.
- [ ] **SSO leftovers:** refresh tokens, `userinfo`, RP-initiated logout, a real-IdP smoke test at
  release.
- [ ] **Passkeys (WebAuthn)**, feature `passkeys`, on branch `passkeys`. The design is in
  [DESIGN.md → auth](DESIGN.md#auth). Phases:
  - [ ] **0. Spike.** Confirm in `webauthn-rs` 0.6 that an `AttestedPasskey` can be used for a
    discoverable login, that the backup flags are exposed when a passkey is registered, and that
    `webauthn-authenticator-rs`'s software authenticator can produce synced, device-bound and
    attested credentials for the tests.
  - [ ] **1. Schema:**
    - `auth_passkey` (owner with cascade, label, credential id, credential JSON, class, AAGUID,
      backup flags, created, last used);
    - `auth_webauthn_challenge` (single-use, five minutes, pruned by `auth.prune()`);
    - `auth_user.passkey_handle`;
    - the authentication method on `auth_session`.

    Migration steps go in the current `MIGRATION-x.y.md`.
  - [ ] **2. Enrolment** on `/profile`, re-authenticated. Enrolling a passkey switches the account
    to passwordless: the password and TOTP are removed and recovery codes are issued. With
    `second_factor(true)` the user can instead keep the password and use the passkey after it.
    Enrolment is refused for SSO accounts and for a class below the policy.
  - [ ] **3. Sign-in:**
    - passwordless, from a button on `/login`;
    - the second-factor step beside TOTP, when enabled;
    - the class checked on every use, and the backup-eligible flag re-checked;
    - lockout on the address for passwordless, on the account for the second factor.
  - [ ] **4. Re-authentication.** `reauthenticate` and every re-auth form accept a passkey, and a
    passkey counts as a local factor, so a passwordless account no longer passes re-auth with
    nothing.
  - [ ] **5. The rest:**
    - a manager removes a user's passkeys;
    - a manager's password reset of a passwordless user removes their passkeys;
    - `passkey::meta_model()` for the admin panel;
    - rejection tests with positive controls;
    - `examples/auth`, AUTH.md §5l, the changelog, and the MSRV bump to 1.89.
  - [ ] **Later:**
    - mandatory passkeys, with a restricted "enrol now" session;
    - browser autofill of passkeys on the login page;
    - device names from FIDO metadata;
    - an AAGUID allowlist.
- **No scopes on API keys.** A key is its owner (AUTH.md §5k); narrower access is an account of its
  own in a narrower group. Revisit only for a third-party OAuth client, which is a different design.
- **Expired API keys are not pruned.** They stay listed as expired, as evidence, until someone
  deletes them.
- **No username whitelist for lockout.** An account that can't be locked out can be guessed at forever.
- **No recovery-code backfill.** Codes are issued with enrolment; `recovery::issue` exists for an app.
- **The SSO transaction cookie stays unsigned.** Anyone can get a validly signed one from
  `/sso/{key}/login`; the real fix would be server-side state.

## Deferred: changes to a published interface

Each reshapes a contract rather than adding to it, so each waits for a concrete requirement and a
minor bump.

- **Row-level authorization.** Must arrive as new `Authz` methods with default impls; `Decision`
  stays fieldless. The bet so far is that a table per kind answers it; that holds for documents and
  hasn't met rows that differ in visibility within one kind.
- **Composite primary keys.** `Accessor::pk() -> String`, the URL shape and `RowItem.id` assume one
  column. A `row_key` hook could be additive if the need is narrower.
- **A second `Accessor` backend or a second frontend.** Each seam (`Accessor`,
  `Vec<Column>` + `Page`) has one implementation; a second would very likely change it.
- Adding to `MetaField` is free (`#[non_exhaustive]`); adding to `Column::Field` breaks an exhaustive
  `match`, so batch those.
