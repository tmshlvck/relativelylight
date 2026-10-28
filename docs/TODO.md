# TODO

Open work, highest impact first, and the only place for it. `- [ ]` is work to do; a plain `-` is a
**decision** (rejected or bounded on purpose), kept so it isn't re-derived. Shipped work goes to
[CHANGELOG.md](../CHANGELOG.md); the design is [DESIGN.md](DESIGN.md).

## crud / crud::ui

- [ ] **Filter operators** (`filter[ttl][gt]=300`, `[in]`, `[is_null]`). The URL grammar already
  nests; wait for a real need.
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
- [ ] **PassKeys / WebAuthn**, when an app faces real-time phishing (TOTP doesn't stop a relaying
  proxy). Likely adds an assurance level to the session and a field to `Identity`.
- **No username whitelist for lockout.** An account that can't be locked out can be guessed at forever.
- **No recovery-code backfill.** Codes are issued with enrolment; `recovery::issue` exists for an app.
- **The SSO transaction cookie stays unsigned.** Anyone can get a validly signed one from
  `/sso/{key}/login`; the real fix would be server-side state.

## blob

- [ ] **A second backend (S3/Ceph)** — probably a companion crate, to keep an AWS SDK out of the core.
  It forces the read-path question: verify-then-serve reads content twice, which is cheap on a
  filesystem and two round trips on an object store (options: a `reread_is_cheap()` predicate,
  buffering under a threshold, or hashing while streaming and aborting on mismatch).
- [ ] **Retention / archival policy** for `copy_content_to`, collection and the audit log — one answer
  rather than three, when an app needs it.

## Deferred: changes to a published interface

Each reshapes a contract rather than adding to it, so each waits for a concrete requirement and a
minor bump.

- **Row-level authorization.** Must arrive as new `Authz` methods with default impls; `Decision`
  stays fieldless. The bet so far is that a table per kind answers it; that holds for documents and
  hasn't met rows that differ in visibility within one kind.
- **Composite primary keys.** `Accessor::pk() -> String`, the URL shape and `RowItem.id` assume one
  column. A `row_key` hook could be additive if the need is narrower.
- **A second `Accessor` backend or a second frontend.** Each seam (`Accessor`, `BlobBackend`,
  `Vec<Column>` + `Page`) has one implementation; a second would very likely change it.
- Adding to `MetaField` is free (`#[non_exhaustive]`); adding to `Column::Field` breaks an exhaustive
  `match`, so batch those.
