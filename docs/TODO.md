# TODO

The backlog, highest impact first. `- [ ]` is work to do; a plain `-` is a **decision** (rejected or
bounded on purpose), kept so it isn't re-derived. Shipped work goes to [CHANGELOG.md](../CHANGELOG.md),
not here.

## crud / crud::ui

- [ ] **Filter operators** (`filter[ttl][gt]=300`, `[in]`, `[is_null]`). The URL grammar already
  nests; wait for a real need.
- [ ] **Cross-document view transitions** for POST → 303 → GET. Cheap to try, easy to get wrong (a 422
  re-render animated as a navigation).
- [ ] **Render `auth`'s pages with Askama**, as `crud::ui` does: one escaping story. It touches every
  security-tested page, so do it on its own with the negative-path suite as the guard.
- **`Table`'s API is stable for 0.4** — no split into `List`/`Search`/… pieces; the per-action
  switches cover turning a control off.
- **No browser tests in CI** (no Playwright); `ui_tests.rs` covers the server half of the picker.
- **Per-column search in the URL — removed.** `ListQuery::search` still carries it for app code.
- **Timezone abbreviations — absent.** The zone is named once per page; a per-cell `CEST` asks the
  reader to know the offset.
- **A type-changing codec — not until needed.** `on_read`/`on_write` run on the column's own type, so
  cents shown as `12.34` is a formatter plus a validated input.
- **Charts — dropped.** A server-rendered SVG module was specified (`git show 8a02dfb`) and dropped:
  tooltips need a client runtime and SVG can't measure text. Use Chart.js on a read-only page.

## auth

- [ ] **Re-authenticate SSO accounts through the IdP** (`prompt=login`), which needs somewhere to park
  the pending action across the redirect. Until then AUTH.md §5h states the limit.
- [ ] **Breached-password screening** (HIBP range API or a local corpus). Possible today through
  `Auth::password_check`; the question is whether a helper earns a feature flag.
- [ ] **SSO leftovers:** refresh tokens, `userinfo`, RP-initiated logout, a real-IdP smoke test at
  release.
- [ ] **PassKeys / WebAuthn**, when an app faces real-time phishing. Likely adds a field to `Identity`.
- **No username whitelist for lockout.** An account that can't be locked out can be guessed at forever.
- **No recovery-code backfill.** Codes are issued with enrolment; `recovery::issue` exists for an app.
- **The SSO transaction cookie stays unsigned.** Anyone can get a validly signed one from
  `/sso/{key}/login`; the real fix would be server-side state.
- **API tokens are the app's.** The gate gets the raw headers, so an app verifies its own tokens.
- **Request logging is the app's** (`examples/audit`). The crate writes nothing to stdout or stderr.
- **CORS is documented, not wrapped** (AUTH.md §4): allow `x-csrf-token`.

## blob

- **The read path assumes re-reading is cheap** (BLOBSTORE.md §4.3) — true of a filesystem. Revisit
  with a second backend.

## Deferred: changes to a published interface

Each reshapes a contract rather than adding to it, so each waits for a concrete requirement and a
minor bump.

- **Row-level authorization.** Must arrive as new `Authz` methods with default impls; `Decision`
  stays fieldless.
- **Composite primary keys.** `Accessor::pk() -> String`, the URL shape and `RowItem.id` assume one
  column. A `row_key` hook could be additive if the need is narrower.
- **A second `Accessor` backend** would very likely change the trait.
- Adding to `MetaField` is free (`#[non_exhaustive]`); adding to `Column::Field` breaks an exhaustive
  `match`, so batch those.
