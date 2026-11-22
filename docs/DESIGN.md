# relativelylight — design

**relativelylight** turns SeaORM entities into a back-office stack — a typed CRUD engine, a
server-rendered admin, authentication/authorization and file uploads/downloads — with **no per-model
code**.
One crate: the engine, the admin, `auth` and timezones are always there; `sso`, `passkeys` and `files`
are features.

This is the design: what each module is for and the decisions an addition should have to argue with.
Usage lives in the guides; open work is in [TODO.md](TODO.md).

| Module | What it's for | Guide |
|---|---|---|
| `crud` | SeaORM entities → a typed engine (list/read/write/validate/gate) and its web UI: table, form, admin panel, relation picker, CSV | [CRUD.md](CRUD.md) |
| `auth` | users/groups, sessions, login, TOTP 2FA, OIDC SSO, API keys, gate presets | [AUTH.md](AUTH.md); the reasoning in [AUTH-SECURITY.md](AUTH-SECURITY.md) |
| `authz` | the per-model gate trait (`Authz`, `Decision`, `Open`), apart from `auth` so a gate can use any credential | [AUTH.md §6](AUTH.md#6-authz--the-gate) |
| `middleware` | `resolve_real_ip` — required; the caller's address, resolved once | [AUTH.md §4](AUTH.md#4-middleware-the-module-provides) |
| `csrf` | the double-submit token every cookie-authenticated write checks | [AUTH.md §7](AUTH.md#7-csrf-double-submit-token) |
| `observe` | the write observer for audit logging, and the error observer for failures a response hides | [CRUD.md → Write observer](CRUD.md#write-observer-audit) |
| `time` | instants as integer UTC seconds, rendered in the request's zone; dates as native `DATE` | [TIME.md](TIME.md) |
| `validate` | typed field validators and normalizers | [DATAINPUT.md](DATAINPUT.md) |
| `files` | a streaming upload reader, safe download responses, upload/preview/thumbnail components | [FILES.md](FILES.md) |

## Principles

1. **The library is part of an app, never its frame.** The app owns the router, the page shell and
   the URLs; modules contribute HTML fragments and the write path behind them. `auth::routes` is the
   opt-in exception, mounted where the app chooses.
2. **The contract in the middle is typed and in-process** — `Vec<Column>` + `Page`, not a wire format.
   An app wanting a JSON API writes it over `Engine`, where its versioning belongs.
3. **A feature must name a real build that leaves it out.** The crate is for an admin of structured
   data, and that admin needs everything it is made of: the engine and its UI, CSV, timezones, the
   CSRF token, axum, and `auth` — the data needs gates, the gates need users, and the users live in
   the database the admin shows, so an admin without `auth` and an `auth` without the admin are
   builds nobody makes. None of those is a feature. Their switches caught nobody's build and cost a
   cfg pair at each use, two code paths per switch (a CSV-less import that answered "needs the `csv`
   feature", a UTC-only clock beside the zoned one), an "implies" note in every feature that needed
   another, and a release matrix of a dozen builds. Three switches are left, each for a build that
   exists: **`sso`** (an OIDC client and its HTTP stack, some 120 crates), **`passkeys`**
   (`webauthn-rs`, some 130 crates, and the MSRV) and **`files`** (a module an admin of records often
   doesn't use). None of them needs another. Modules stay decoupled in the code all the same: the
   engine reaches identity only through the `authz` gate, and `files` touches neither the engine nor
   the database. The one required piece of wiring is `middleware::resolve_real_ip`, so the lockout,
   audit events and the app's log agree about who called.
4. **Authorization is a per-model gate handed the request headers.** It resolves identity itself, so
   it needs no middleware and works for credentials this crate doesn't know.
   Row-level access is out of scope; an app expresses it by shape (a table per document kind) or in
   its own handler.
5. **The app owns its database.** Modules describe their tables (`table_create_statements`); the app's
   migration applies them.
6. **State and audit are different things.** A table says what something *is*; `observe` says what
   someone *did*.
7. **Server-rendered, no JavaScript framework, the URL is the state.** Page, sort, filters, search and
   the open dialog live in the query string. Three small scripts, no framework: `crud::JS` makes the
   dialogs modal and drives the relation picker (everything works without it, only plainer),
   `time::JS` sets the zone cookie from the browser, and the passkey script reaches a browser API no
   form can.
8. **Policy belongs to the app; mechanism belongs here.** Retention, ownership, registration,
   thumbnails, request logging: the crate can't know, and a wrong default is worse than none. The
   crate spawns no tasks and writes nothing to stdout or stderr.
9. **One way to do each thing, and an obvious one.** The API, the pages and the design stay
   orthogonal: each task has one place where it is done, and that place is where a reader would look
   for it. A second way, even a convenience, must earn its place by removing something harder: a
   link that saves a long walk through navigation, not one that repeats the navbar. Two ways drift
   apart: the panel's password field once skipped the sign-out the manager's reset does. When a
   second way turns up, remove one, or make one call the other.

## crud

- **One flat public surface.** Everything an app names is at `crud::` (`Crud`, `MetaModel`, `Table`,
  `Engine`, `Accessor`, `esc`, …); the submodules are private. The paths used to follow the layers
  (`crud::seaorm`, `crud::engine`, `crud::ui`, `crud::fmt`, `crud::csv_io`), so an app imported
  from four of them to set up one admin, `seaorm` named a backend that has no alternative, and the
  docs drifted between two spellings of one item (`esc` was in `crud::ui`, then `crud::fmt`). The
  module grew to the shape it will keep, about 60 names, which one list holds. Inside, `seaorm`
  (introspection, queries, `MetaModel`) is apart from `meta` (the field and relation settings, no
  SeaORM) and `registry` (`Crud`).
- **`Accessor` stays public.** An app may want its own UI or JSON API over `Engine`, or a backend
  of its own; the trait names no ORM types.
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
- **Search matches what is printed**, in one query: an `OR` of a substring branch per field, and a
  subquery per relation on its label rebuilt in SQL (hence labels declared as columns). Subqueries,
  not joins, so no row repeats and "delete all matching" stays a plain `DELETE … WHERE`. Instants
  are the exception the database can't print in a viewer's zone: a term naming a period finds them.
  It sees only what the table shows: a hidden field searched is an oracle on its value.
- **Display and storage are separate.** `format_cell`/`format_view` are display only; `on_read` /
  `on_write` are an inverse codec on the column's own type.
- **A field's display formatters belong to its model** (`MetaField::format_cell` / `format_view`),
  not to a table. Every surface that shows a row reads the model: the table, its View dialog,
  `Admin`, the linked-row dialog (`picker_view`) and an app's own view. A formatter kept on `Table`
  could reach only that table: the linked-row dialog builds a default `Table` of the target, so
  an app's link to the record's own page never showed there. On the model it is declared once, the
  same on every table of the entity. **No per-table override:** nobody has needed one, and adding
  one later breaks nothing, while removing one would.
  - **The closure takes one context argument**: the value, the row (a link needs the key while
    it formats another column), and the request headers. The headers carry what depends on the
    viewer, the timezone first (`Tz::from_headers`). The argument is a struct (`FmtCtx`), so the
    crate can add a member later without breaking anyone's closures. Being on the field, it names
    no column. It is synchronous: display that needs a query belongs to the app's own view.
  - **Its output is HTML, inserted verbatim.** That is the point of it, and also the risk: a value
    it fails to escape is stored XSS. The docs say so wherever a formatter is introduced.
    `FmtCtx`, `esc` and `truncate` live beside `MetaField`, which names them.
  - **Display only:** never the edit form, the CSV export, search or sort, which work on the stored
    value.
  - **The picker's list applies no cell formatter.** There a click chooses a row, and a link in
    the cell would take the browser away from a half-filled form. The linked-row dialog applies
    `format_view`: leaving the page from it is what such a link is for, and `target="_top"` takes
    the whole window instead of the iframe. A picker-specific formatter waits for a need.
- **A relation's picker threshold is the relation's**: `MetaRelation::picker_threshold(n)`, with a
  crate-wide default beside `picker_path` (50). It decides only how a relation's input renders in
  a form, so it was never the table's to set. Three builders (`Table`, `Form`, `RelationField`)
  each carried a copy that could disagree, for example between a `Form` and the same entity's
  edit dialog.
- **What holds for every row of an entity is the entity's model**: its rows' own page
  (`MetaModel::view_path`), whether "+ New" creates it (`picker_create`), the fields that form shows
  (`picker_create_fields`) and a row's CSS class (`row_class`), reported to the UI as `EntityMeta`
  (`Accessor::meta`). Each sat elsewhere and was said twice or keyed by slug: a row's page was
  `Table::detail_href` for View and `Crud::view_path(slug, …)` for a relation's link, two settings
  for one fact that could disagree; the "+ New" exception list and the create form's fields were
  slug lists on `Crud` and `Picker`, where a misspelt slug did nothing. The rule for a setting:
  if it describes the data it belongs on the model, and if it describes one screen (`columns`,
  `fields`, the filters and pins, `initial`) it stays on that screen. Precedence for "+ New" is
  relation, then target, then app.
  - **`row_class` returns `Option<String>`** and takes a `RowCtx` (the row and the request headers),
    for the same reasons `FmtCtx` is a struct: the viewer's zone decides "due today", and a member
    can be added without breaking closures. Its output is an attribute value, escaped, not HTML.
  - **A table's View doesn't also open the dialog when the model names a page.** Two views of one
    row, one of them reachable only by typing `?show=`, would be two ways to look at it. So
    `view_path` is a page of the app's own, never a table's `?show=`; a relation's link without
    the script falls back to the picker's page, which exists for every row.
- **One column type per kind of time value** ([TIME.md §1](TIME.md#1-storage-model)). An instant is
  integer Unix seconds: it compares, sorts and adds as an integer, in the same SQL and on an ordinary
  index on SQLite and PostgreSQL alike, where native timestamps are text in several shapes on SQLite
  and a real type on PostgreSQL, two code paths to keep right. A calendar date is a native `DATE`,
  because a date isn't an instant: as midnight-UTC seconds it would show the previous day west of
  UTC. Its fixed-width `YYYY-MM-DD` sorts as text on SQLite, so the crate accepts exactly that form,
  since SQLite refuses nothing. Native date-time columns stay read-only rather than become a second
  way to store an instant. A recurring time ("every day at 10:00 in Prague") is a rule, a wall-clock
  time plus a zone name, and its occurrences are instants; no storage type answers it, so none is
  bent to.

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
- **Passkeys: one app-wide policy, by class.** The lowest class accepted (`Synced < DeviceBound <
  Attested`) and whether a passkey may be a second factor are the site's, not the user's. *Attested*
  is the only hardware binding a server can verify; *device-bound* is the authenticator's word.
  Each credential's class is recorded at registration and checked at every use, so a stricter
  policy applies at the next sign-in ([AUTH.md §5l](AUTH.md#5l-passkeys-feature-passkeys)).
- **An account always keeps a way in.** Accounts come from an administrator, with a password (no
  self-registration). With a passkey the user may drop the password, but not the last passkey of an
  account without one. TOTP is a second factor after any primary method; SSO accounts get no local
  password or passkey. A manager can always reset a password, disable TOTP and remove passkeys,
  each independently. Recovery is the administrator's ([TODO.md](TODO.md#auth) holds self-service).
- **The accounts panel holds account data; the credentials page holds credentials** (principle 9).
  The panel (the CRUD admin over `auth_*`, configured by the library's `meta_model()`s) edits who an
  account is and sets only its first password; `/profile/{id}` changes credentials, under
  re-authentication, signing the account out where that applies
  ([AUTH.md → The accounts panel](AUTH.md#the-accounts-panel)). **Why:** a password set in the
  panel would skip the reset's sign-out, and a passkey deleted there re-authentication.
- **WebAuthn posts a form, with one JSON answer.** The page embeds the challenge, the script runs the
  browser's prompt and submits; the challenge is a single-use row, created on demand so anonymous
  page views write nothing. **The exception** is "Sign in with a passkey": a page between the click
  and the prompt was a step too many, and a challenge in every `/login` view would write a row per
  anonymous visit. So the click posts the same form asking for JSON and opens the prompt on that
  click. One answer on an existing route, not an API. Every ceremony starts on a click, since
  browsers want a gesture (Safari insists). What the code relies on in `webauthn-rs` is in
  [AUTH-SECURITY.md → Passkeys](AUTH-SECURITY.md#passkeys).
- **The sign-in policy is one minimum assurance level** (`Simple < Mfa < Attested`), not a set of
  flags: each way of signing in has a level, and the session's recorded method decides it on every
  request, so a stricter policy applies to sessions already open
  ([AUTH.md §5m](AUTH.md#5m-the-sign-in-policy-and-password-change-required) has the table).
  - **TOTP lifts a method to `Mfa`, never higher**, so "attested hardware only" stays expressible.
    (The first draft had TOTP add a level, which made passkey + TOTP equal to attested hardware.)
  - **Below the minimum a session is restricted, not refused:** it is anonymous to the app, and its
    own `/profile` lets the user add the factor, which steps the session up.
- **"Password change required" is a flag and a timestamp,** not `updated_at`, which any edit moves.
  The row hook sets the flag whenever someone other than the owner writes a password, so no path
  has to remember. A change due is a notice, not a lock; a maximum age is off by default (NIST SP
  800-63B advises against rotation).
- **The profile is cards in columns, not tabs.** Tabs would need a `?tab=` on every form's answer or
  a script, and a message could land on a tab nobody is looking at. Columns, not rows: a card that
  grows pushes only the cards under it. **One message at the top** answers whatever was just done,
  an app's card included (`Auth::profile_reply`).
- **Re-authentication is per request, not a window.** The proof travels with the sensitive form
  itself: a password, a TOTP code, or a passkey assertion over a challenge rendered into that form.
  Nothing records "re-authenticated at", so there is no grace period for a stolen session to ride
  on (AUTH.md §5h). An SSO account's proof can't travel in the form (it is a round trip to the
  provider), so it is made first and kept on the session, **one-use**: spent by the next sensitive
  action, it is per request still ([why](AUTH-SECURITY.md#re-authentication)).
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
