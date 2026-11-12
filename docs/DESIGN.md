# relativelylight — design

**relativelylight** turns SeaORM entities into a back-office stack — a typed CRUD engine, a
server-rendered admin, authentication/authorization and file uploads/downloads — with **no per-model
code**.
One crate of feature-gated modules; take the pieces you need.

This is the design: what each module is for and the decisions an addition should have to argue with.
Usage lives in the guides; open work is in [TODO.md](TODO.md).

| Module | What it's for | Guide |
|---|---|---|
| `crud` | SeaORM entities → a typed engine: list/read/write/validate/gate | [CRUD.md](CRUD.md) |
| `crud::ui` | the web UI: form, table, admin panel, relation picker, CSV | [CRUD.md → Web UI](CRUD.md#web-ui-ui) |
| `auth` | users/groups, sessions, login, TOTP 2FA, OIDC SSO, API keys, gate presets | [AUTH.md](AUTH.md) |
| `middleware` | `resolve_real_ip` — required; the caller's address, resolved once | [AUTH.md §4](AUTH.md#4-middleware-the-module-provides) |
| `observe` | the write observer for audit logging, and the error observer for failures a response hides | [CRUD.md → Write observer](CRUD.md#write-observer-audit) |
| `time` | integer-UTC timestamps rendered in the request's zone | [TIME.md](TIME.md) |
| `validate` | typed field validators and normalizers | [DATAINPUT.md](DATAINPUT.md) |
| `files` | a streaming upload reader, safe download responses, upload/preview/thumbnail components | [FILES.md](FILES.md) |

## Principles

1. **The library is part of an app, never its frame.** The app owns the router, the page shell and
   the URLs; modules contribute HTML fragments and the write path behind them. `auth::routes` is the
   opt-in exception, mounted where the app chooses.
2. **The contract in the middle is typed and in-process** — `Vec<Column>` + `Page`, not a wire format.
   An app wanting a JSON API writes it over `Engine`, where its versioning belongs.
3. **No mandatory coupling between modules.** `auth` works without `crud`; `files` needs neither; an
   unused feature costs no dependencies. The one required piece is `middleware::resolve_real_ip`, so
   the lockout, audit events and the app's log agree about who called.
4. **Authorization is a per-model gate handed the request headers.** It resolves identity itself, so
   it needs no middleware and works for credentials this crate doesn't know.
   Row-level access is out of scope; an app expresses it by shape (a table per document kind) or in
   its own handler.
5. **The app owns its database.** Modules describe their tables (`table_create_statements`); the app's
   migration applies them.
6. **State and audit are different things.** A table says what something *is*; `observe` says what
   someone *did*.
7. **Server-rendered, no JavaScript framework, the URL is the state.** Page, sort, filters, search and
   the open dialog live in the query string. The one script is the relation picker's, and without it
   the field still saves.
8. **Policy belongs to the app; mechanism belongs here.** Retention, ownership, registration,
   thumbnails, request logging: the crate can't know, and a wrong default is worse than none. The
   crate spawns no tasks and writes nothing to stdout or stderr.

## crud and crud::ui

- **Introspection first, configuration as a layer.** Every column, key and to-one relation comes from
  the entity; only N:M is declared (`relate`), because SeaORM can't enumerate it.
- **The `Accessor` seam is type erasure.** `Arc<dyn Accessor>` lets one `Engine` hold entities of
  different Rust types. Relation resolution and projection are database work, so they stay behind
  it, in the SeaORM backend, a page at a time (one query per relation). It is not a stability
  promise: `Accessor` and `Column` may gain members in any release.
- **One implementation of the UI.** `Form`, `Table` and `Admin` share their code, and a filter governs
  the listing, the export and the bulk delete alike, so no control acts on a wider set than the one
  on screen. A hidden control is a refused write, not just a missing button.
- **"+ New" creates in a dialog, never in a draft.** A relation field's "+ New" (`picker_create`) opens
  the target's create form in an iframe over the form being filled in, and the script adds the
  saved row to the field. The outer form is never posted or reloaded, so nothing has to be kept on
  the server. Keeping a half-filled form there instead would break "the URL is the state" and work
  without JavaScript only at that cost. The price: each dialog's row is saved when its form is, so
  an abandoned outer form leaves it unlinked. "+" follows the foreign key, so it never creates child
  rows (the other side of a 1:N); those are the app's own pages, as inline child rows were
  decided against. The nesting cap (four forms) is the script's; each level is gated on its own.
- **A linked row opens over the page, not instead of it.** `picker_view` reuses the dialog stack:
  the row and its edit form are pages of the picker route, reached through a relation
  (`?pick=post.author&show=3`), so a link can't name an unrelated table, and each is gated on the
  target as the target's own table would be. After an edit the script renames the links in place
  rather than reloading, since a reload would lose a form being filled in underneath.
- **Display and storage are separate.** `format_cell`/`format_view` are display only; `on_read` /
  `on_write` are an inverse codec on the column's own type.

## auth

- **Server-side sessions in an opaque HttpOnly cookie**, not JWTs: a session is a row, so logout,
  "sign out everywhere" and disabling a user take effect at once. `identify(&headers)` resolves the
  cookie on demand; nothing is injected into the request.
- **CSRF is a double-submit token** on every cookie-authenticated write; a request carrying
  `Authorization` is exempt, since that credential isn't ambient.
- **Lockout brakes only the unauthenticated checks**, in database rows shared across replicas, and is
  an argument to `Auth::new` so it can't be forgotten. Authenticated checks are guarded by
  re-authentication instead; counting them would let a stolen session lock the owner out.
- **The client address is resolved once**, by mandatory middleware: the socket peer, or the right-most
  `X-Forwarded-For` hop behind one trusted proxy. Anything stranger is the app's own middleware
  inserting `RealIp`; there is no hook.
- **Sensitive changes re-authenticate per request**, with no grace window to inherit.
- **An API key is its owner.** It stores no scope: the resolver returns the owner's identity with
  the groups read on that request, so narrower access means an account of its own. Keys were first
  left to the apps as product policy. They moved here when two apps (teleddns, CLIMB) had settled on
  the same policy and the same table, and both had to wire the resolver to this crate's lockout
  counters by hand. Since a key names no account, the address counter is the brake.
- **A key never opens the UI.** `identify` reads only the session cookie, and keys have their own
  entry point, `identify_key`, which the app calls on the routes that take one. The crate doesn't
  read the header itself: where the credential arrives is the app's choice.
- **Not here, on purpose:** a registration page, request logging, scoped keys. Each is product
  policy; the gate receives the headers, so an app's own credential needs no change here.

## files

- **The crate handles files on a page; the app stores them.** Apps keep small files in a database
  column, large ones on disk or in an object store, and their own index row for either; one store
  type fits none of them. So nothing in `files` reads, writes, lists or deletes a file.
- **The upload is a pull API, not a sink.** The app pulls each file's chunks, so the same loop writes
  to a file, a column or an object store with no trait in between. The crate keeps what is easy to get
  wrong: the CSRF token checked before the first file, limits enforced while streaming, the type
  sniffed and the hash computed on the way. Cleaning up a refused upload is the app's.
- **Components take values, never call back.** Listings are the app's, because what a row shows is.
- **Previews are by reference, except text.** An image or a PDF is a URL, so the response's allowlist
  decides what renders. Text has no tag that shows it by reference without an `<iframe>` of awkward
  size, so `Preview::text` takes the bytes — from the app, since the component does no I/O — and
  escapes them into a `<pre>`, capped at 5 MiB so a log file can't become a 1 GB page.
- **Thumbnails, versions and ownership are the app's** — policy, and an image decoder no other app
  should pay for.
- **Downloads are the app's route**; the crate supplies the response, where the inline/attachment
  decision lives.
