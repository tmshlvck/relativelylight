# relativelylight — design

**relativelylight** turns SeaORM entities into a back-office stack — a typed CRUD engine, a
server-rendered admin, authentication/authorization and file storage — with **no per-model code**.
One crate of feature-gated modules; take the pieces you need.

This is the design: what each module is for and the decisions an addition should have to argue with.
Usage lives in the guides; open work is in [TODO.md](TODO.md).

| Module | What it's for | Guide |
|---|---|---|
| `crud` | SeaORM entities → a typed engine: list/read/write/validate/gate | [CRUD.md](CRUD.md) |
| `crud::ui` | the web UI: form, table, admin panel, relation picker, CSV | [CRUD.md → Web UI](CRUD.md#web-ui-ui) |
| `auth` | users/groups, sessions, login, TOTP 2FA, OIDC SSO, gate presets | [AUTH.md](AUTH.md) |
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
   it needs no middleware and works for credentials this crate doesn't know (an app's API tokens).
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
- **Not here, on purpose:** a registration page, API tokens, request logging. Each is product policy;
  the gate receives the headers, so an app's own tokens need no change here.

## files

- **The crate handles files on a page; the app stores them.** 0.4 shipped a content-addressed store
  (handle → version chain → digest, three tables, garbage collection). It was correct and nobody's
  shape: an app wanted small files in a database column, large ones on disk under names a person can
  read, and an index row of its own pointing at either. The store was neither transactional like a
  column, scalable like an object store, nor browsable like a directory — so 0.5 removed it and kept
  what every one of those choices needs.
- **No storage layer of any size.** A safe flat directory type, an upload-sink trait, a gated router
  and a file list with delete buttons were all drafted for 0.5 and dropped: each forced a shape on
  the app — a sink to implement, a listing to fit, a router serving by name — when the app already
  has its own idea of all three. What remains does no I/O on the app's storage at all.
- **The upload is a pull API, not a sink.** `Upload::next` yields parts in document order and the app
  pulls each file's chunks, so the same loop writes to a file, a column or an object store with no
  trait in between. The crate keeps what is easy to get wrong: the CSRF token checked *before* the
  first file (a streaming parser can't check it afterwards), limits enforced while streaming, the
  type sniffed before the first chunk, the hash computed on the way. The price is that cleaning up a
  refused upload is the app's — which it has to own anyway for its index row or transaction.
- **Components take values, never call back.** `UploadForm`, `Preview` and `Thumbnail` render from a
  name, a type and URLs. Listing is the app's: a table or grid of its own design, with the components
  inside, because what a row shows (an owner, a date, actions) is the app's.
- **No thumbnailer, no versions, no ownership here.** Thumbnails are the app's, made on request into a
  content-hash cache ([FILES.md §6](FILES.md#6-thumbnails)) — a pure function would have been
  shippable, but it would pull in an image decoder for every app using `files`. A revision is a new
  file; ownership is a link table with real foreign keys and a per-kind gate. Each is policy.
- **Downloads are the app's route**, authorised by the owning record; the crate supplies the response
  builder, which is where the inline/attachment decision has to live.
