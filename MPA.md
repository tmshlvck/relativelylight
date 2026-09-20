# MPA: re-homing the web UI in Rust, and deleting the wire it was built on

A plan to re-implement `crud::ui` (`Table`, `Form`, `Admin`) as a server-rendered multi-page app, and
to **delete the JSON API, the metadata API and the OpenAPI document with it** — because that wire
exists to feed the JavaScript this plan removes.

Status: **implemented** on branch `mpa`, unreleased. The upgrade path for applications is
**`MPA_MIGRATION.md`** (and `CHANGELOG.md` → Unreleased); building an app on the result is
**`docs/APP.md`**. §13 below records what was built and the seven places where it differs from this
plan; the rest of the document is left as written, as the reasoning the change was made from.

Revision 2. Revision 1 listed "the JSON API does not change" as a non-goal; that was wrong, and
reversing it is what makes the rest of this plan a net *deletion* rather than a second rendering path
bolted beside the first.

---

## 1. Why

Four measurements, taken on `main`.

**The page is the same thing many times.** A rendered `Admin` panel is `table.html` (615) +
`_form_core.html` (263) + `_form_fields.html` (171) = **1,049 lines per entity**. `examples/adminpanel`
registers 9, so its admin page is **9,441 lines / 521 KB** (136 KB gzipped — gzip's 32 KB window can't
dedupe copies 58 KB apart, so nine panels really do cost ~8.5× one). `admin.html` renders every panel
and shows one (`x-show="active === '{{ p.slug }}'"`).

**Type information is computed in Rust and then thrown away.** `Table::render_inner` (`ui.rs:205`) calls
`engine.columns(&slug)` and holds a fully typed `Vec<Column>` — then re-derives it as
`columns_json` from `meta_one` (`ui.rs:209-214`) so that untyped JavaScript can dispatch on it. Every
`c.kind === "relation"`, `c.display === "datetime"`, `c.type === "Bool"` in the Alpine code is a `match`
that Rust would have checked exhaustively, deliberately deferred to a language that cannot check it.

**The extension points are strings of another language.** The entire customization surface of `Table`
beyond layout flags is:

```rust
pub fn format(mut self, column: impl Into<String>, js: impl Into<String>) -> Self   // ui.rs:183
pub fn on_saved(mut self, js: impl Into<String>) -> Self                            // ui.rs:505
```

JavaScript source passed as a Rust `String`, checked by neither compiler and covered by no test.

**And the JSON API is that JavaScript's backend, not a product.** `openapi.rs` (477) describes it,
`engine.rs`'s `mod http` (295) serves it, `meta_all`/`meta_one`/`column_json` (~115) assemble the
metadata it publishes, and `csv_io.rs` (230) reads that metadata back out of untyped JSON it just
produced — inside one process, from typed values it already had. Its shape (`{id, label}` relation
embedding, `?view=terse`, `_meta`'s column objects, the `422` field map) is a set of internal
conventions of the table component, published by accident. Nobody outside this repo consumes it.

Against that, note what already works: **`auth` is already a pure MPA.** 2,733 lines in `auth/mod.rs`
render forms server-side and answer writes with `Redirect::to(...)` — login, TOTP, recovery codes,
profile, password change, manager reset — with **zero JavaScript**, backed by 3,033 lines of
`security_tests.rs`. This plan does not propose an experiment. It proposes making `crud::ui` work the
way half the library already works, and removing the thing that made it not.

### 1.1 Why the API can go

An application that needs a JSON API for its own consumers should write one. It has the database, it has
SeaORM, and the questions its API must answer — versioning, field selection, bearer tokens, rate limits,
pagination style — are product decisions this library has no business making. What the library owes such
an app is the **backend**: `MetaModel` configuration, the coerce → validate → hook write pipeline, the
`authz` gate, the write observer, and now a *typed* `Engine` to call. Not a URL space.

The API between this crate's backend and its own table/form/admin components was never a contract, was
never documented as stable, and is about to stop existing on the client side. Keeping it would mean
maintaining a published wire format, its OpenAPI description and its CSV adapter for zero consumers.

**Confirmed for this branch:** nothing outside this repo consumes `/api/v1`. The removal is a plain
deletion with a `CHANGELOG` entry and no replacement example.

### Non-goals

- **No business-process modelling.** No "Action" verb, no workflow engine. Apps that need multi-stage
  processes hand-write those pages and embed `Form`/`Table` where a step happens to be a plain table or
  form. Making that embedding cheaper is a *goal* (§8), but the process itself is the application's.
- **No change to the write pipeline.** Coercion, validation, transforms, hooks, N:M resolution and the
  SeaORM introspection stay exactly as they are. This plan changes what calls them and what renders
  their output.
- **No Bootstrap replacement.** The markup stays Bootstrap 5 classes and the app keeps loading the CSS.
  Bootstrap's **JavaScript** bundle stops being required, as does Alpine.
- **No rewrite of `auth`'s hand-rolled HTML.** `auth` builds strings with `format!` + `esc`; the new
  `crud::ui` uses Askama (which auto-escapes, §9). Unifying them is a later, separable cleanup.

---

## 2. Architecture

Three rules, and everything else follows.

**The URL is the state.** Page, sort keys, filters, search term, which entity is active, and which row is
being edited all live in the query string. Today they live in Alpine component fields plus `localStorage`
plus a URL fragment (`table.html:346-370`). One location instead of three: a filtered, sorted, paginated
view becomes linkable and bookmarkable for free, and the "9 panels rendered, 1 shown" problem disappears
because `?entity=post` renders exactly one table.

The vocabulary is the one the API already parses — `page`, `per_page`, `q`, `search[col]`, `filter[name]`,
`sort=a,b:desc`, `ids`, `all` — plus `entity`, `new`, `edit`. So `parse_list_query` (`engine.rs:933`) is
**moved, not written**, and `docs/CRUD.md § Query params` survives retargeted from a wire format to a URL
format.

**Modals are `<dialog open>`, rendered server-side.** Native HTML gives the backdrop, ESC-to-close, focus
trapping and the top layer with no script. `?edit=7` renders the list *and* the open dialog in one
response. Validation errors re-render the same dialog with the values and the messages in place — which is
strictly better than today, where a `422` is mapped back onto fields by hand (`_form_core.html:240-249`).

**Writes are POST → 303 → GET.** Exactly the pattern `auth` already uses (`auth/mod.rs:1348`, `1476`,
`1500`). The redirect target carries the list state back plus `#row-{id}`, so the browser lands on the row
that was just edited.

### 2.1 Reads stay the app's route; writes get one library route

CLAUDE.md's composition rule is that the app owns the roots. Keep it: **all three components stay
fragment renderers** the app calls from its own handler, which is also the smallest possible migration —
an existing GET handler keeps its shape and gains a state argument.

Writes need somewhere to POST, and a `422` needs to re-render a page, which needs the app's shell.
`auth` already solved this with `login_shell` / `profile_shell`; follow the precedent — and keep it to
**one route per UI surface**:

```rust
fn panel(engine: &Engine) -> Admin<'_> {          // configured in one place, used twice
    Admin::new(engine)
        .mount("/admin")                          // the app's own page URL: links and form actions
        .shell(|frag, headers| my_error_page(frag, headers))   // sync, as auth's shells are
        .entity_with("post", |t| t.per_page(10))
        .entity("tag")
}

let app = app
    .route("/admin", get(admin_page))             // the app's read route, unchanged in shape
    .merge(panel(&engine).routes());              // adds exactly: POST /admin
```

Every write POSTs to the mount with a hidden `_op` (`create` | `update` | `delete` | `delete_many` |
`import` | `tz`), `_entity` and `_id`, so the router gains **one** route and the handler is a `match` on
`_op`. There is no API left to be tasteful about paths for, and this keeps `csrf::enforce`'s urlencoded
`_csrf` scan working unchanged (`csrf.rs:273`).

A read-only surface never calls `routes()` and needs no mount.

### 2.2 Round trips

Worth stating plainly, because it is the usual objection: a save today is **two** sequential requests —
`save()` POSTs, then `afterSave()` calls `closeModal()` + `load()` (`table.html:579-582`), re-fetching and
re-rendering the entire table body. The MPA save is **one**: POST → 303 → the list renders. Fewer requests
and less rendering work than the current design, not more.

### 2.3 Scroll position

The honest trade, and the thing to prototype first (§10). A full-document navigation resets scroll;
`#row-{id}` in the redirect target lands the browser on the row that changed, which is what an operator
wants after an edit. Back/forward scroll restoration is native. Cross-document view transitions
(`@view-transition { navigation: auto }`) plus a `view-transition-name` on the edited row can carry visual
continuity if the anchor jump feels abrupt.

**Server-side session state for scroll position is explicitly rejected.** It is client state; putting it in
the session makes it wrong the moment a second tab exists and makes every render depend on mutable server
state.

---

## 3. The deletion ledger

What goes, measured. The point of the plan is this table.

| Deleted | Lines | Note |
|---|---:|---|
| `crud/openapi.rs`, the `openapi` feature, the `utoipa` dependency | 477 | no API to describe |
| `engine.rs` `mod http` JSON handlers + `IntoResponse for Error`'s JSON bodies | ~250 | of 295; `parse_list_query` (~45) moves to §2's URL state |
| `engine.rs` `meta_all`, `meta_one`, `column_json`, `entity_url`, `base_path` | ~115 | the metadata wire |
| `engine.rs` `list`'s JSON re-wrap; `FieldDisplay::params` + its `Serialize`; `Serialize` on `LogicalType`/`Cardinality`/`ValidationErrors` | ~60 | all of it exists to cross a wire |
| `templates/table.html` `<script>` (247-614) | 368 | |
| `templates/_form_core.html` | 263 | |
| `templates/_form_fields.html` | 171 | |
| `templates/form.html` `<script>` (36-96) | 61 | |
| `templates/admin.html` scripts (the `rlSharedFilters` bootstrap + panel switcher) | ~25 | replaced by one query param |
| `assets/rl-time.js` | 212 | §7 |
| `assets/rl-tz-picker.html` (Alpine dropdown) | 20 | becomes a ~15-line form |
| `ui.rs` `columns_json` / `filters_json` / `sort_json` / formatter JS-literal assembly | ~45 | |
| `csv_io.rs` JSON-poking (`columns()`, `col["kind"]` string matching, `csv_to_json` by type *name*) | ~40 net | rewritten over `Vec<Column>`; **shorter and type-checked** |
| `docs/CRUD.md` §The HTTP API (125), §Metadata (30), §OpenAPI (21) | ~176 | |
| **Total** | **~2,280** | plus `list_tests.rs` (396) and `gate_tests.rs` (448) retargeted |

Added, all generic and model-agnostic (**no procedural macros**):

| Added | Est. lines |
|---|---:|
| `ui/state.rs` — `ViewState` ↔ query string (parser moved from `engine.rs`), pager/sort arithmetic lifted from the JS | ~150 |
| `ui/render.rs` — one function walking `Vec<Column>` × `Page` into rendered rows and cells | ~200 |
| `ui/widgets.rs` — one `match Column` → form input, replacing `widgetOf` | ~250 |
| `ui/decode.rs` — urlencoded body → write body: `payload()`'s rules (empty-vs-null, `Int` omission, write-only "keep current") in Rust | ~150 |
| `ui/routes.rs` — the single POST handler, 303s, `422` re-render, bulk ops, CSV | ~300 |
| Askama templates — list, pager, toolbar, dialog, fields, admin nav | ~350 |
| `assets/rl.css` (`<dialog>` + a few Bootstrap gaps), `assets/rl.js` (§6) | ~80 |
| **Total** | **~1,480** |

**Net ≈ −800 lines of crate code**, one fewer build dependency (`utoipa`), two fewer runtime dependencies
for the app (Alpine, Bootstrap JS), one new optional dependency (a tz database, §7) — and the rendered
adminpanel page goes from **9,441 lines to roughly 700**.

The row stays `serde_json::Value`. It is already the generic row representation and it keeps that job —
this is why no macro is needed anywhere: the inputs (`Vec<Column>`, `Page`) are already computed in Rust
at `ui.rs:205`, and the work is a nested loop over them.

---

## 4. The Rust API after this change

Model configuration — the bulk of what an app writes — is **untouched**. So is everything outside `crud`.

### 4.1 Unchanged

| Surface | Note |
|---|---|
| `MetaModel` / `MetaField` / `MetaRelation`, incl. widget overrides, `validate_str/_int`, `password()`, `label_column`, `relate` | untouched |
| `Crud::register`, `on_write`, `engine`, `into_engine` | untouched |
| `Column`, `Page`, `RowItem`, `ListQuery`, `LogicalType`, `FieldDisplay`, `Cardinality`, `Error`, `ValidationErrors` | kept; only their `Serialize` impls go |
| `Accessor` | **kept** — it is the type-erasure boundary (`Arc<dyn Accessor>` over a per-entity generic `SeaAccessor<E>`), not merely a second-backend hook, so it stays even with one backend |
| The whole `auth` module and its routes | untouched |
| `authz` gates, `observe::WriteObserver` (incl. `source: "autocrud"`), `csrf`, `middleware`, `validate`, `net` | untouched |
| `Table`: `new`, `title`, `description`, `search`, `pagination`, `per_page`, `read_only`, `confirm`, `picker_threshold`, `sort`, `sort_desc`, `filter`, `fixed_filter` | meaning preserved |
| `Form`: `new`, `edit`, `title`, `description`, `heading`, `fields`, `omit`, `submit_label`, `saved_message`, `cancel`, `redirect`, `picker_threshold`, `dom_id` | preserved |
| `Admin`: `new`, `title`, `filter`, `entities`, `entity`, `entity_with`, `group`, `separator`, `link` | preserved |
| Fragment contract — all three return HTML fragments, never full pages; app owns `<html>` and shell | preserved |

### 4.2 Breaking

| Before | After | Upgrade |
|---|---|---|
| `Crud::new(db, "/api/v1")` | `Crud::new(db)` | `base_path` was the API's mount; the UI's mount now lives on the UI component |
| `crud.into_router()`, `engine.router()` | `panel.routes()` (§2.1) | the router is the UI's, and it is one POST route |
| `crud::openapi::{build, merge_into, json}`, feature `openapi` | — | removed; an app describing its own API describes its own handlers |
| `engine.meta_all()`, `meta_one()`, `entity_url()`, `csrf_cookie_name()`, `base_path()` | `engine.columns(slug)` | typed `Vec<Column>` was always the real answer |
| `engine.list(..) -> Value` | `-> Page` | the JSON wrapper had one caller left |
| `Table::format(col, js: &str)` | `Table::format(col, Arc<dyn Fn(&Value, &Value) -> String>)` | a Rust closure returning HTML, called during render (§9 on escaping) |
| `Form::on_saved(js)` | — | it existed to run JS after a `fetch`; there is no `fetch`. `redirect()` / `saved_message()` cover the uses |
| `Form::dom_id` namespaced an Alpine component | namespaces DOM ids only | signature kept, meaning narrowed |
| `render()` / `render_for(&headers)` | `render_for(&headers, &ViewState)` | the state the URL carries has to arrive from the app's handler |
| `time::JS`, `time::TzPicker` (Alpine) | `time::TzPicker` (a form) + server formatting | §7; `time` moves behind a feature |
| `crud.csrf(auth.csrf())` optional | CSRF **always** enforced on UI writes; `.csrf(auth.csrf())` to share auth's cookie, else an internal `Csrf::new()` | deletes the `Option<Csrf>` branch and is the safer default |

New: `Table::mount`/`shell`/`routes`, same on `Form` and `Admin`; `Table::fields`/`omit` (free from the
unification in §5); `crud::ui::esc`; `crud::ui::CSS`.

The `format` closure upgrade, in `examples/adminpanel`:

```rust
// before — interpolates database content into HTML with no escaping at all
.format("title", r#"(v, row) => `<a href="/api/v1/post/${row.id}" target="_blank">${v}</a>`"#)
// after
.format("title", |v, row| format!(r#"<a href="/post/{}">{}</a>"#, esc(&row["id"]), esc(v)))
```

Escaping becomes the library's problem to make easy rather than the app's to remember — the current line
is an XSS hole in our own example, which this closes by construction.

A behaviour break pre-1.0 bumps the **minor**: this is **0.3.0**, with every row above as a `CHANGELOG`
breaking entry carrying its upgrade step.

### 4.3 Recorded decisions

- **`Accessor` stays public but stops being a stability promise.** It has one implementor and exists for
  type erasure. Saying so in its docs lets `Column` gain fields without the `#[non_exhaustive]`-plus-
  constructor ceremony currently argued at `engine.rs:248-254`.
- **`Engine` and `Crud` stay two types.** Merging them would break `register`/`engine()` for no deletion.
- **No `Html`/`Cell` newtype for `format`.** A `String` plus a public `esc` matches what `auth` already
  does and keeps the closure trivially writable; the type would move the footgun, not remove it.
- **No JS relation picker** (§6), which is why `picker_threshold` survives with a new mechanism rather
  than being deleted.

---

## 5. Behaviour inventory

Every behaviour the current JS implements, and where it goes. This is the acceptance checklist.

### 5.1 Listing

| Today (JS) | MPA |
|---|---|
| `load()` fetch + render rows | server renders `<tbody>` from `Page` |
| `goto(p)`, `pageWindow()`, `jump()` | `<a href="?page=N">`; the window/jump arithmetic moves to Rust verbatim |
| `onSearch()` debounce | `<form method="get">` with the search input; Enter submits |
| `toggleSort(c, shiftKey)` | header `<a>` carrying the next `sort=` list. Multi-key becomes an explicit "+" affordance per header instead of shift-click — discoverable, and zero JS |
| `sortDir`/`sortAria`/`sortRank` | rendered attributes |
| filter `<select>` + `onFilter` | same `<form method="get">`; a submit button, or `onchange="this.form.submit()"` as a one-attribute enhancement |
| `filterBig` search picker | §6 |
| `activeChips()` | server-rendered from the parsed state |
| shared `Admin` filter via `localStorage` + `ru-filter` events + `rlSharedFilters` bootstrap (`admin.html:9-28`) | one query param, propagated into every link the page renders. **Deletes the bootstrap script, the event bus and the storage round-trip.** |
| `terse(url)` promise cache for relation labels | gone — the backend already resolves relation labels into rows (`RowItem.label`) |
| panel switching (`x-show` over 9 panels) | `?entity=post` renders one table |
| `load()` "Refresh" button | the page reload that a link already is |

### 5.2 Forms

| Today (JS) | MPA |
|---|---|
| `widgetOf(c)` (`_form_core.html:66-78`) | a Rust `match` on `Column` — exhaustive, compiler-checked |
| `formCols()` (only/omit/read_only) | Rust filter, already mirrored by `check_widgets`/`check_fields` |
| `blankForm()` / `fromRow(row)` | server renders inputs with values already in them |
| `payload()` — empty-vs-null, `Int` omission, write-only "keep current" | `ui/decode.rs`. The rules already exist server-side; this removes the *second* copy |
| `mustFill(c)` red `*` | rendered from `Column::required` |
| `422` → `fieldErrors` / `rowErrors` mapping | re-render with `ValidationErrors` in place |
| `clearSecrets()` | a write-only input is simply never rendered with a value |
| `openCreate()` pre-filling from active filters | the create link carries the filter values |
| `openEdit()` re-fetching the row | the GET that renders the dialog *is* the fetch |
| `csrfHeaders()` | `Csrf::hidden_input` (`csrf.rs:184`), already there |

### 5.3 Bulk operations

| Today (JS) | MPA |
|---|---|
| `toggleRow` / `selected[]` | checkboxes named `ids` inside one `<form method="post">` — the same `ids` param `ListQuery::pk_in` already takes |
| `deleteSelected()` | that form's submit button (`_op=delete_many`) |
| `deleteAllMatching()` | a second submit button carrying the view's query + `all=true` |
| `pageAllSelected()` / `togglePage()` | ~3 lines of shared JS (§6) |
| `confirm(...)` dialogs | `onsubmit="return confirm(…)"`, a one-attribute enhancement |
| CSV export `exportUrl()` | already a plain `<a href>`; keep, now pointing at the mount with the view's query |
| `importCsv()` fetch + `alert()` | `<form>` → 303 with a flash message. **Blocker:** `csrf::enforce` doesn't parse multipart (`csrf.rs:273`, TODO.md). Two ways out, decided in phase 4: (a) the streaming pre-scan TODO.md describes, ~60 lines, also closing that gap for apps; (b) a paste-CSV `<textarea>` in a urlencoded form, which works today at zero cost |

### 5.4 What the deleted API took with it

| Endpoint | Where its function lives now |
|---|---|
| `GET /{entity}` | the app's read route → `render_for` |
| `GET /{entity}?view=terse` | the relation picker's own GET, §6 |
| `GET /{entity}/{pk}` | the dialog render |
| `POST` / `PATCH` / `DELETE /{entity}[/{pk}]` | `POST {mount}` with `_op` |
| `GET /{entity}?format=csv` | `<a href="{mount}?…&format=csv">` on the UI's POST-less route (a GET on the mount the app already routes) |
| `POST /{entity}/_import` | `POST {mount}` with `_op=import` |
| `GET /_meta`, `/{entity}/_meta` | `Engine::columns` — in-process and typed |
| the OpenAPI document | — |

---

## 6. The JavaScript that survives

One file, served once, cached, no per-entity generation. Everything in it is **enhancement**: the page
works with JS disabled.

1. **Select-all-on-page** — ~3 lines.
2. **Timezone cookie seeding** from `Intl.DateTimeFormat().resolvedOptions().timeZone` when unset — ~3
   lines, once (§7).
3. **Optional niceties**: `onchange="this.form.submit()"` on filter selects, `onsubmit="return confirm()"`
   on destructive buttons. Inline attributes, not a file.

Budget: **under 30 lines**, against ~900 lines of JavaScript today, generated nine times into every
adminpanel page.

Revision 1 budgeted 150 lines, mostly for a search-as-you-type relation picker against `?view=terse`. With
no JSON API that would mean inventing an internal fetch endpoint — the exact thing this plan deletes — so
the picker becomes **a plain GET instead**: under `picker_threshold` a `<select>`, over it a "choose…"
link that renders a search-and-pick `<dialog>` (one round trip per search, the result carried back as a
hidden id). Slower to use, nothing to maintain, and it works without script.

If the budget grows past 30 lines during implementation, that is the signal to stop and reconsider, not to
keep adding.

---

## 7. Time

Currently `assets/rl-time.js` (212 lines) plus an Alpine `$store.tz` renders UTC seconds in the user's
zone client-side, and `TzPicker` is an Alpine dropdown.

**Decided: the selected zone goes in a cookie and the server formats.** That deletes `rl-time.js`, the
Alpine store and the picker's Alpine binding; makes `TzPicker` a plain form (`POST {mount}` with `_op=tz`
→ set cookie → 303 back); and — the real win — makes **CSV export match what is on screen**, which it
cannot today because the server has no idea what zone the browser chose. DST-straddling correctness (the
subject of `examples/time`) becomes a Rust unit test instead of a JS one.

It costs one dependency: an IANA tz database, needed both to format an epoch in a named zone and to decode
a `datetime-local` input back to epoch seconds.

- New feature **`tz`**, implied by `ui`; `pub mod time` moves behind it (today it is always compiled
  because it is dependency-free, which stops being true).
- Dependency choice at implementation time: `chrono-tz` (self-contained, compiles the database in, larger
  binary) or `jiff` (system `/usr/share/zoneinfo`, with a bundled-database feature for images that lack
  it). **Default to the self-contained one** unless the binary size argues otherwise — a container with no
  tzdata rendering every timestamp wrong is a worse failure than a megabyte.
- Residual JS: the ~3 lines that seed the cookie from the browser's zone on first visit (§6).
- `docs/TIME.md` (204 lines) is rewritten around the cookie; `time::JS` is deleted from its API.

---

## 8. What else gets simpler

- **A hand-written application page** (the aircraft-maintenance work-order screens) can embed a rendered
  `Table` or `Form` as **plain HTML**, without adopting Alpine, the `ruTable_*` component namespace, or
  the library's fetch conventions. Today embedding `Form` drags all of that in.
- **`Table`, `Form` and `Admin` become one implementation** rather than three that share two partials:
  one core of state → columns → rows/widgets → HTML, with three thin configurations over it. `Table`
  gains `fields`/`omit` for free; a widget fix lands in all three by construction, not by discipline.
- **`csv_io` stops round-tripping through JSON metadata** it produced itself in the same process.
- **CSRF stops being optional** on the write path (§4.2), deleting a branch and an accessor.
- **One state parser instead of three state stores** (query string vs Alpine fields vs `localStorage`).
- **`docs/CRUD.md` loses ~176 lines** of wire-format documentation and gains a shorter UI section.

---

## 9. Testing

`ui_tests.rs` (545) covers render-refusal cases (unknown / read-only / required-but-unrendered columns,
widget fit, escaping of a title). Those stay and must keep passing.

New, following the `auth/security_tests.rs` pattern of driving the real router over in-memory SQLite:

- **Gate tests retargeted.** `gate_tests.rs` (448) asserts each preset's decision on the JSON API; the
  single POST route is the new surface and needs the same negative cases — including that a denied write
  never reaches the backend, and that `401` vs `403` still separate "log in" from "not for you".
- **CSRF on the write route**, with a positive control.
- **Escaping, exhaustively.** Every rendered cell, label, filter chip, option and input value gets a test
  with `<script>`-bearing data. Today this is the client's problem via `x-text`; server-rendering makes it
  ours. Askama's `.html` templates auto-escape `{{ }}`, so the rule is: **`|safe` appears only where a
  `format` closure's output is inserted**, and that one site is tested directly.
- **`ui/decode.rs` round-trips.** Empty-vs-null on nullable columns, `Int` omission, write-only "keep
  current", to-many id lists — the rules that currently live twice, tested once now that they live once.
- **State round-trip.** A URL with page + multi-key sort + filters + search renders the same set
  `Engine::list` returns for the equivalent `ListQuery`, and the CSV export of that view matches it.
- **`list_tests.rs`** (396) drops its HTTP layer and calls the typed `Engine::list` directly — shorter,
  and testing the thing the UI now calls.

---

## 10. Prototype first

Before committing to phases, build one throwaway spike: **`examples/adminpanel`'s `post` table,
server-rendered, with a `<dialog>` edit that saves and returns.** It answers the questions that decide the
design, and nothing else here is worth doing if they answer badly:

1. Does `#row-{id}` after a save feel acceptable, or is a view transition needed? (§2.3)
2. Does the generic `Vec<Column>` × `Page` loop stay generic, or does the first real model force a special
   case? (The empirical test of the no-macros claim.)
3. Is `Vec<Column>` genuinely sufficient, or does something in `meta_one`'s JSON turn out to be load-bearing
   for rendering? (If so, it becomes a field on `Column` — cheap, per §4.3.)
4. Does `<dialog>` sit acceptably inside Bootstrap 5 CSS without Bootstrap's modal JS? (§11)

---

## 11. Phases

Each phase leaves the workspace building and `main`-equivalent functionality working. The JSON API keeps
serving the old Alpine UI until phase 7 deletes both together, so the branch stays coherent throughout —
at the cost of one ~20-line adapter in phase 2, written to be deleted.

1. **Spike** (§10). Throwaway. Decide the four questions.
2. **Typed core.** `Engine::list -> Page`; `csv_io` over `Vec<Column>`; `ViewState` extracted from
   `parse_list_query`; `crud::ui::esc`; `assets/rl.css`. The JSON handlers adapt `Page` → JSON at the
   boundary. Old UI untouched, all tests green.
3. **Read path.** Rows, cells, pager, sort links, filter form, chips, CSV export link.
   `Table::render_for(&headers, &state)`. Rendered beside the old table in an example so the comparison is
   direct. Measure the HTML size at 100 rows × 20 columns here (§12).
4. **Write path.** Widget `match`, form decode, `<dialog>`, the single POST route, 303, `422` re-render,
   `shell`, mandatory CSRF, bulk ops. Resolve the CSV-import multipart decision (§5.3). `Form` lands on the
   same core; `on_saved` retires.
5. **`Admin`.** `?entity=` single-panel rendering, shared filter as a query param, nav. The 9,441 → ~700
   line reduction lands here.
6. **Time.** The `tz` feature, cookie + server formatting, `TzPicker` as a form, delete `rl-time.js`,
   rewrite `docs/TIME.md`, update `examples/time`.
7. **Cut over and delete.** Delete the Alpine templates, `mod http`'s JSON handlers, `openapi.rs`, the
   `openapi` feature and `utoipa`; `Crud::new(db)`; retarget `gate_tests`/`list_tests`; update all four
   examples (dropping their Swagger routes); rewrite `docs/CRUD.md` §Web UI and delete §The HTTP API /
   §Metadata / §OpenAPI; `docs/PRD.md` module table; `README.md` (including the crate description, which
   currently advertises the API and Alpine); `CHANGELOG` breaking entries; **0.3.0**.

Order rationale: phases 3-4 prove or disprove the design, phase 5 is where the payoff lands, and every
deletion that would strand the old UI is deferred to phase 7 so the branch is mergeable-in-principle until
the end.

Before tagging, the feature-combination build from CLAUDE.md must be re-run with the new feature set
(`openapi` gone, `tz` added), since `--all-features` cannot catch a feature that forgets to enable what it
uses.

---

## 12. Risks

- **`<dialog>` inside Bootstrap 5 CSS.** Bootstrap's modal CSS assumes its own JS. Answered by the spike
  (§10, question 4); the fallback is ~60 lines in `assets/rl.css`, which is budgeted.
- **The `format` closure is a raw-HTML API.** Mitigated by making `esc` the easy path and testing the one
  `|safe` site (§9), but it hands apps a footgun — the same one the JS version had, less visibly.
- **Large tables render more HTML per request** than a JSON page does. Probably irrelevant at `per_page`
  defaults; measured in phase 3, and the cure (a lower default `per_page`) is a one-line config, against a
  9,441-line page today.
- **The tz dependency** (§7) is the one thing this plan *adds*, in a crate whose install table promises an
  unused feature pulls no dependencies. Confined to the new `tz` feature, implied only by `ui`.
- **Two rendering paths coexist during phases 2-6.** Time-boxed by phase 7; the risk is stalling
  mid-migration. The coexistence cost is deliberately one small adapter, so there is nothing to grow
  attached to.
- **Deleting a public API surface is irreversible for someone.** Confirmed as no-one for this branch
  (§1.1); if that changes, the answer is an app-side handler over the typed `Engine`, not a revival.
- **No search-as-you-type on relation pickers** (§6) — a real usability regression on large targets,
  accepted in exchange for the fetch endpoint it would otherwise require. Revisit only with a measured
  complaint.

---

## 13. What was built — and where it differs from this plan

Implemented as one change rather than the seven phases of §11: with the API deleted in the same pass,
the coexistence adapter phase 2 called for was never needed, and nothing but the spike would have been
throwaway work. Tests came first for the parts that already had them (`gate_tests`, `list_tests`,
`ui_tests` were rewritten against the new API before the examples were touched).

**All 262 library tests pass**, `cargo clippy --all-features --all-targets` is clean, and every feature
combination in CLAUDE.md's matrix builds — which caught one real bug: `csv` used `Tz` without enabling
`tz`, exactly the class of mistake `--all-features` cannot see.

### The measurements, as measured

| | Planned | Actual |
|---|---|---|
| net crate source (non-test) | ≈ −800 | **−281** |
| deleted outright | — | `openapi.rs` 477, `ui.rs` 890, Alpine templates + JS **1,446** |
| new renderer | ≈ 1,480 | `ui/` 2,273 (incl. 1,387 in `mod.rs`), templates 220, `rl.css` 36, `urlform.rs` 100 |
| test suite | "extended" | **+516** lines |
| rendered adminpanel page | ≈ 700 lines | **498 lines / 25 KB** (from 9,441 / 521 KB) |
| JavaScript | < 30 lines | **~15 lines of inline attributes, no file** (3 at first; a debounced search and a few affordances since) |

The net deletion is smaller than estimated because the new code carries the doc comments and the
render-time refusals the JS never had, and because `ui/mod.rs` absorbed the three components' builders
(890 lines of the old `ui.rs`) rather than replacing them. The claim that mattered held: **the
per-request payload fell by ~20×**, and the parts a compiler now checks are the parts that used to be
strings.

### Seven deviations

1. **The library contributes no routes at all** — §2.1 proposed one `POST` route per surface plus a
   `shell` closure. Instead `submit(&headers, ip, &body, &state) -> Outcome` is a method the app calls
   from its own `post` handler, and `Outcome::Invalid(state)` hands the state back for the app to
   re-render with *its own* shell. That deletes the shell closure, the router plumbing, the
   `Arc<Engine>`-vs-`&Engine` mismatch a `Router` would have forced, and the mount path: every link is
   relative, so the library never learns where it lives. Cost: ~8 lines of app code per surface, shown
   in all three examples. This is more in keeping with "the app owns the roots" than the plan was.
2. **CSRF stayed opt-in** (`Crud::csrf`) rather than becoming mandatory. Making it required would have
   added a builder argument every app must satisfy and deleted no code; the `Option` was already there.
   The examples enable it, and `gate_tests` covers both states.
3. **No timezone `_op=tz` in `submit`.** Setting a cookie needs a response, which a fragment renderer
   never writes, so `TzPicker` posts to a four-line route of the app's own (`Tz::cookie()` returns the
   `Set-Cookie` value). Keeping it out of `submit` kept `Outcome` to two variants.
4. **The large-relation picker is an id input**, not §6's zero-JS search sub-dialog: carrying the
   operator's in-progress form values through a search round trip means putting them all in the URL,
   which is real work for a rare case. `picker_threshold` still decides; `TODO.md` records both ways
   forward and what would justify each.
5. **CSV import takes a pasted textarea**, i.e. §5.3's option (b). A urlencoded body carries the
   `_csrf` field `csrf::enforce` already finds, so nothing was blocked on the multipart parser — which
   now has a concrete caller waiting in `TODO.md` instead of being a hypothetical.
6. **`search[col]=term` was dropped from the URL vocabulary** (the plan kept the whole API grammar). No
   control ever rendered it, so it was surface with no user; `ListQuery::search` still carries it for
   app code calling the engine, which is where per-column search belongs.
7. **`jiff`, not `chrono-tz`** — one crate instead of two, reading the host's IANA database, with UTC as
   the documented fallback when a host has none. §7 left this open.

### One example fewer

`examples/time` is **gone**, folded into `examples/crud` (its `event` table now lives in
`examples/model`, rows and DST comments intact, reachable at `/ui/event`). The plan assumed it would
be updated (§11 phase 6), and it was — but once the timezone policy stopped being ~120 lines of
JavaScript (`window.RL_TZ`, an `onChange` hook posting to a fake profile endpoint, a server-zone
endpoint, load-time adoption) and became "which `Tz` your handler passes", the example's whole
subject was four lines that `examples/adminpanel` already shows. What remained unique was the
DST-straddling dataset, and that is worth keeping — as a table in an existing example, not as a
crate with its own shell, seed and workspace entry. DST *correctness* is now a unit test, which is
better coverage than a page someone has to look at.

### One thing the plan missed

**Reads had to become gated.** With the API as the enforcement point, `Table::render_for` only decided
which *buttons* to draw; delete the API and that function becomes the only thing standing between a
caller and the rows. It now consults the gate for `List` (and `Read` when a dialog is open) and answers
`401`/`403`, and `crud/gate_tests.rs` asserts both that and that the backend is never reached. Nothing
in this document anticipated it — it fell out of the first gate test written against the new surface,
which is the argument for having written the tests first.
