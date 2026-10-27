# relativelylight — product requirements

**relativelylight** turns Rust ORM entities into a back-office stack — a typed CRUD engine, a
server-rendered web admin, authentication/authorization and file storage — with **no per-model
code**. One crate of feature-gated modules; take the pieces you need.

This document is the product overview, the cross-cutting decisions and the roadmap. Usage lives in
the module guides; the ordered backlog is [TODO.md](TODO.md).

| Module | What it's for | Status | Guide |
|---|---|---|---|
| `crud` | SeaORM entities → a typed engine: list/read/write/validate/gate | ✅ | [CRUD.md](CRUD.md) |
| `crud::ui` | the generated web UI: form, table, admin panel, relation picker, CSV | ✅ | [CRUD.md → Web UI](CRUD.md#web-ui-ui) |
| `auth` | users/groups, sessions, login, TOTP 2FA, OIDC SSO, per-model gate presets | ✅ (extras ahead) | [AUTH.md](AUTH.md) |
| `middleware` | `resolve_real_ip` — required; the caller's address, resolved once | ✅ | [AUTH.md §4](AUTH.md) |
| `observe` | the write observer for audit logging | ✅ | [CRUD.md → Write observer](CRUD.md#write-observer-audit) |
| `time` | server-side rendering of integer-UTC timestamps in the request's zone | ✅ | [TIME.md](TIME.md) |
| `validate` | typed field validators and normalizers | ✅ | [DATAINPUT.md](DATAINPUT.md) |
| `blob` | content-addressed file storage + version chain, upload, viewer, browser | ✅ | [BLOBSTORE.md](BLOBSTORE.md) |

## Architecture decisions

An addition that breaks one of these should have to argue with this list first.

1. **The library is part of an app, never its frame.** The app owns the router, the page shell and
   the URLs; modules contribute HTML fragments and the write path behind them. `auth::routes` and
   `blob::ui::Routes` are the opt-in exceptions, mounted where the app chooses.
2. **The contract in the middle is typed and in-process** — `Vec<Column>` + `Page`, not a wire format.
   An app wanting a JSON API writes it over `Engine`, where its versioning belongs.
3. **No mandatory coupling between modules.** `auth` works without `crud`; `blob` needs neither; an
   unused feature costs no dependencies. The one required piece is `middleware::resolve_real_ip`, so
   the lockout, audit events and the app's log agree about who called.
4. **Authorization is a per-model gate handed the request headers.** It resolves identity itself, so
   it needs no middleware. Row-level access is out of scope; an app expresses it by shape (a table per
   document kind) or in its own handler.
5. **The app owns its database.** Modules describe their tables (`table_create_statements`); the app's
   migration applies them.
6. **State and audit are different things.** A table says what something *is*; `observe` says what
   someone *did*.
7. **Server-rendered, no JavaScript framework, the URL is the state.** Page, sort, filters, search and
   the open dialog live in the query string; interactivity uses native elements. The one script is the
   relation picker's, and without it the field still saves its selection.
8. **Policy belongs to the app; mechanism belongs here.** Retention, ownership, thumbnail sizes, the
   shape of a request log: the crate can't know, and a wrong default is worse than none.

## Modules

**`crud`.** Complete CRUD from SeaORM entities with no per-model code: relations, search, filter,
sort, pagination, bulk delete, CSV, and a typed `columns` description the renderer matches on.
Relations are first-class in queries: `filter[author]` matches the FK behind the name, `sort=author`
orders by the label the cell shows. Per-entity configuration (labels, visibility, defaults,
validators, N:M) is an optional layer over introspection.

**`crud::ui`.** `Form`, `Table` and `Admin` are one implementation, so a fix lands in all three. A
filter governs the listing, the CSV export and the bulk delete alike, so no control acts on a wider set
than the one on screen. A relation too large for a `<select>` is edited in a `Picker` dialog over the
target's own table, under the target's gate; `RelationField` is that same input for a form the app
writes.

**`auth`.** Usable without `crud`. Password login with server-side sessions, TOTP 2FA with recovery
codes, OIDC SSO, CSRF, lockout, session lifetimes and revocation, re-authentication before sensitive
changes, a password policy, and gate presets. The rejection paths are covered by a negative-path suite
([AUTH.md §10a](AUTH.md)). There is no registration page and no API-token system on purpose: both are
app decisions ([AUTH.md §5j](AUTH.md)).

**`observe`.** An audit record needs *what changed* (the data layer) and *who* (the HTTP layer). The
`WriteEvent` carries both — the change plus the headers and resolved address — from every `crud` and
`auth` write. The app registers one `WriteObserver` and persists the row in its own table
(`examples/audit`).

**`time`.** Storage is UTC `i64` seconds; the zone is presentation only. It rides in a cookie and is
applied on the server, so a cell, a `datetime-local` input and a CSV export agree.

**`blob`.** A **handle** with a stable id the app's tables reference, an immutable **version** chain,
and digest-addressed **content** underneath. Ownership lives in the app's own link table
([BLOBSTORE.md §9](BLOBSTORE.md)), which keeps `blob` independent of `auth`. A thumbnailer, a variant
index and partial erasure were built and removed (BLOBSTORE.md §4.5, §4.8).

## Roadmap

In [TODO.md](TODO.md), ordered. The larger items:

- Batch relation reads (today N+1 per relation column).
- Re-authentication of SSO accounts through the identity provider.
- PassKeys/WebAuthn, when an app faces real-time phishing.

## Open questions

- **A second backend.** The `Accessor` and `BlobBackend` seams have one implementation each; one is
  not proof of a good trait.
- **A second frontend.** `Vec<Column>` + `Page` is shaped by its one renderer.
- **Row-level authorization** stays out (decision 4) on the bet that a table per kind answers it. That
  holds for documents; it hasn't met rows that differ in visibility within one kind.
