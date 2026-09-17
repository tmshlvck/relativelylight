# MPA: re-homing the web UI in Rust

A plan to re-implement `crud::ui` (`Table`, `Form`, `Admin`) as a server-rendered multi-page app,
keeping the API that applications build against, deleting most of the JavaScript, and moving the work
into Rust where the compiler can see it.

Status: **plan only**, branch `mpa`. Nothing here is implemented.

---

## 1. Why

Three measurements, taken on `main`:

**The page is the same thing many times.** A rendered `Admin` panel is `table.html` (615) +
`_form_core.html` (263) + `_form_fields.html` (171) = **1,049 lines per entity**. `examples/adminpanel`
registers 9, so its admin page is **9,441 lines / 521 KB** (136 KB gzipped — gzip's 32 KB window can't
dedupe copies 58 KB apart, so nine panels really do cost ~8.5× one). `admin.html` renders every panel
and shows one (`x-show="active === '{{ p.slug }}'"`).

**Type information is computed in Rust and then thrown away.** `Table::render_inner` (`ui.rs:205`) calls
`engine.columns(&slug)` and holds a fully typed `Vec<Column>` — then serializes it to `columns_json`
(`ui.rs:210-214`) so that untyped JavaScript can dispatch on it. Every `c.kind === "relation"`,
`c.display === "datetime"`, `c.type === "Bool"` in the Alpine code is a `match` that Rust would have
checked exhaustively, deliberately deferred to a language that cannot check it.

**The extension points are strings of another language.** The entire customization surface of `Table`
beyond layout flags is:

```rust
pub fn format(mut self, column: impl Into<String>, js: impl Into<String>) -> Self   // ui.rs:184
pub fn on_saved(mut self, js: impl Into<String>) -> Self                            // ui.rs:505
```

JavaScript source passed as a Rust `String`, checked by neither compiler and covered by no test.

Against that, note what already works: **`auth` is already a pure MPA.** 2,733 lines in `auth/mod.rs`
render forms server-side and answer writes with `Redirect::to(...)` — login, TOTP, recovery codes,
profile, password change, manager reset — with **zero JavaScript**, backed by 3,033 lines of
`security_tests.rs`. This plan does not propose an experiment. It proposes making `crud::ui` work the
way half the library already works.

### Non-goals

- **The JSON API does not change.** `/api/v1/...`, its wire formats, query params, CSV endpoints, 422
  shape and OpenAPI document stay exactly as they are. Apps like the DDNS service consume it directly
  and must not notice this work happened. The MPA becomes a *second consumer* of `Accessor`, not a
  replacement for the first.
- **No async/backend logic changes.** Applications adding their own REST endpoints and background work
  are out of scope and unaffected.
- **No business-process modelling in the library.** No "Action" verb, no workflow engine. Apps that need
  multi-stage processes hand-write those pages and embed `Form`/`Table` where a step happens to be a
  plain table or form. Making that embedding cheaper is a *goal* (§6), but the process itself is the
  application's.

---

## 2. The compatibility contract

The assumption: an application's web interface is essentially `examples/adminpanel` — an `Admin`
fragment rendered into the app's own shell, gated by `auth`, with the app adding JSON endpoints and
invisible backend work elsewhere. That shape must keep compiling and keep working.

### Unchanged

| Surface | Note |
|---|---|
| `Crud::new` / `register` / `into_router` / `csrf` | untouched |
| `Engine` — `router`, `meta_all`, `meta_one`, `columns`, `tables`, `entity_url`, `set_observer`, `set_csrf` | untouched; `meta_*` still serves API clients |
| `Accessor` trait (`engine.rs:442`) | **untouched** — this is the seam the MPA renders from |
| `Column`, `Page`, `RowItem`, `ListQuery`, `LogicalType`, `FieldDisplay`, `Cardinality` | untouched |
| The whole `auth` module and its routes | untouched |
| `authz` gates, `observe::WriteObserver`, `csrf`, `middleware`, `validate`, `net` | untouched |
| `MetaModel` / `MetaField` / `MetaRelation` (incl. widget overrides, `validate_str`, `password()`) | untouched |
| `Table`: `new`, `title`, `description`, `search`, `pagination`, `per_page`, `read_only`, `confirm`, `picker_threshold`, `sort`, `sort_desc`, `filter`, `fixed_filter`, `render`, `render_for` | signatures and meaning preserved |
| `Form`: `new`, `edit`, `title`, `description`, `heading`, `fields`, `omit`, `submit_label`, `saved_message`, `cancel`, `redirect`, `picker_threshold`, `dom_id`, `render`, `render_for` | preserved |
| `Admin`: `new`, `title`, `filter`, `entities`, `entity`, `entity_with`, `group`, `separator`, `link`, `render`, `render_for` | preserved |
| Fragment contract — all three return HTML fragments, never full pages; app owns `<html>` and shell | preserved |

`render()` / `render_for(&headers)` keep their signatures, so **existing call sites compile unchanged**
and render page 1, unsorted, unfiltered — the current default. Reading URL state is opt-in (§4.1).

### Breaking — two methods

**`Table::format(column, js)`** → `Table::format(column, impl Fn(&Value, &Value) -> String)`.

A Rust closure returning an HTML string, called during render. `examples/adminpanel` upgrades like this:

```rust
// before
.format("title", r#"(v, row) => `<a href="/api/v1/post/${row.id}" target="_blank">${v}</a>`"#)
// after
.format("title", |v, row| format!(
    r#"<a href="/api/v1/post/{}" target="_blank">{}</a>"#,
    esc(&row["id"]), esc(v)))
```

Escaping becomes the library's problem to make easy, not the app's to remember — today that template
literal interpolates database content straight into HTML with no escaping at all, which is an XSS hole
in the current example that this change closes by construction.

**`Form::on_saved(js)`** → removed. It exists to run JS after a `fetch`; there is no `fetch`. `redirect()`
and `saved_message()` already cover what it was used for.

Both are `CHANGELOG.md` breaking entries with the upgrade step, and a **minor** bump (pre-1.0).

---

## 3. The architecture

Three rules, and everything else follows.

**The URL is the state.** Page, sort keys, filters, search term, which entity is active, and which row
is being edited all live in the query string. Today they live in Alpine component fields plus
`localStorage` plus a URL fragment (`table.html:346-370`). One location instead of three: a filtered,
sorted, paginated view becomes linkable and bookmarkable for free, and the "9 panels rendered, 1 shown"
problem disappears because `?entity=post` renders exactly one table.

**Modals are `<dialog open>`, rendered server-side.** Native HTML gives the backdrop, ESC-to-close, focus
trapping and the top layer with no script. `?edit=7` renders the list *and* the open dialog in one
response. Validation errors re-render the same dialog with the values and the messages in place — which
is strictly better than today, where a 422 is mapped back onto fields by hand
(`_form_core.html:240-249`).

**Writes are POST → 303 → GET.** Exactly the pattern `auth` already uses (`auth/mod.rs:1348`, `1476`,
`1500`). The redirect target carries the list state back plus `#row-{id}`, so the browser lands on the
row that was just edited.

### 3.1 Round trips

Worth stating plainly, because it is the usual objection: a save today is **two** sequential requests —
`save()` POSTs, then `afterSave()` calls `closeModal()` + `load()` (`table.html:579-582`), re-fetching
and re-rendering the entire table body. The MPA save is **one**: POST → 303 → the list renders. This is
fewer requests and less rendering work than the current design, not more.

### 3.2 Scroll position

The honest trade, and the thing to prototype first (§8). A full-document navigation resets scroll;
`#row-{id}` in the redirect target lands the browser on the row that changed, which is what an operator
actually wants after an edit. Back/forward scroll restoration is native. Cross-document view
transitions (`@view-transition { navigation: auto }`) plus a `view-transition-name` on the edited row
can carry visual continuity if the anchor jump feels abrupt.

**Server-side session state for scroll position is explicitly rejected.** It is client state; putting it
in the session makes it wrong the moment a second tab exists and makes every render depend on mutable
server state.

### 3.3 Where the write routes live

`Table`/`Form`/`Admin` render fragments and own no routes — the app owns the route and calls `.render()`.
That stays true for **reads**. Writes need somewhere to POST, and a 422 needs to re-render a full page,
which means the library needs the app's shell.

`auth` already solved this exact problem with `login_shell` / `profile_shell` closures. Follow the
precedent:

```rust
let admin = Admin::new(&engine)
    .shell(|frag, who| my_page(frag, who))   // same shape as Auth::profile_shell
    .base_path("/admin");                    // where its write routes mount

let app = app.merge(admin.routes());         // POST targets + 303s + 422 re-renders
```

An app that only ever GETs and renders (a read-only dashboard) never calls `routes()` and is unaffected.

---

## 4. Behaviour inventory

Every behaviour the current JS implements, and where it goes. This is the acceptance checklist.

### 4.1 Listing

| Today (JS) | MPA |
|---|---|
| `load()` fetch + render rows | server renders `<tbody>` from `Page` |
| `goto(p)`, `pageWindow()`, `jump()` | `<a href="?page=N">`; the window/jump arithmetic moves to Rust verbatim |
| `onSearch()` debounce | `<form method="get">` with the search input; Enter submits |
| `toggleSort(c, shiftKey)` | header `<a>` carrying the next `sort=` list. Multi-key becomes an explicit "+" affordance per header instead of shift-click — discoverable, and zero JS |
| `sortDir`/`sortAria`/`sortRank` | rendered attributes |
| filter `<select>` + `onFilter` | same `<form method="get">`; a submit button, or `onchange="this.form.submit()"` as a one-attribute enhancement |
| `filterBig` search picker | see §5 |
| `activeChips()` | server-rendered from the parsed state |
| shared `Admin` filter via `localStorage` + `ru-filter` events + `rlSharedFilters` bootstrap script (`admin.html:9-28`) | one query param, propagated into every entity link the page renders. **Deletes the bootstrap script, the event bus, and the storage round-trip.** |
| `terse(url)` promise cache for relation labels | gone — the backend already resolves relation labels into rows (`RowItem.label`); no client fetch to cache |
| panel switching (`x-show` over 9 panels) | `?entity=post` renders one table |

`Table`/`Admin` gain `.state(&ViewState)` (or equivalent) carrying page/sort/filters/q parsed from the
query string. Omitting it yields today's defaults, which is why existing call sites still compile.

### 4.2 Forms

| Today (JS) | MPA |
|---|---|
| `widgetOf(c)` (`_form_core.html:66-78`) | a Rust `match` on `Column` — exhaustive, compiler-checked |
| `formCols()` (only/omit/read_only) | Rust filter, already mirrored by `check_widgets` |
| `blankForm()` / `fromRow(row)` | server renders inputs with values already in them |
| `payload()` (`_form_core.html:203-...`) — empty-vs-null, `Int` omission, write-only "keep current" | Rust form decoding. The rules already exist server-side; this removes the *second* copy in JS |
| `mustFill(c)` red `*` | rendered from `Column::required` |
| 422 → `fieldErrors` / `rowErrors` mapping | re-render with `ValidationErrors` in place |
| `clearSecrets()` | a write-only input is simply never rendered with a value |
| `openCreate()` pre-filling from active filters | the create link carries the filter values |
| `openEdit()` re-fetching the row | the GET that renders the dialog *is* the fetch |
| `csrfHeaders()` | hidden `_csrf` input — already supported (`csrf.rs:32`) |

### 4.3 Bulk operations

| Today (JS) | MPA |
|---|---|
| `toggleRow` / `selected[]` | checkboxes inside one `<form method="post">` |
| `deleteSelected()` | that form's submit button |
| `deleteAllMatching()` | a second submit button carrying the current query |
| `pageAllSelected()` / `togglePage()` | **the one real loss.** Either drop it (the "delete all N matching" button covers the common case) or accept ~3 lines of shared JS. Decide during §9 phase 2 |
| `confirm(...)` dialogs | a `<dialog>` confirmation step, or `onsubmit="return confirm(…)"` as a one-attribute enhancement |
| CSV export `exportUrl()` | already a plain `<a href>`; keep |
| `importCsv()` fetch + `alert()` | `<form enctype="multipart/form-data">` → 303 with a flash message. **Blocker:** `csrf::enforce` does not parse multipart (`csrf.rs:273`) — the import form needs the token in a header, a query param, or multipart support added. Must be resolved before CSV import ships |

### 4.4 Time

Currently `assets/rl-time.js` (212 lines) plus an Alpine `$store.tz` renders UTC seconds in the user's
zone client-side.

MPA: **the selected zone goes in a cookie and the server formats.** `time.rs` already owns the logic.
This deletes `rl-time.js`, deletes the Alpine store, makes `TzPicker` a plain `<form>`, and — the real
win — makes **CSV export match what is on screen**, which it cannot today because the server has no idea
what zone the browser chose.

Residual JS: ~3 lines, once, to seed the cookie from
`Intl.DateTimeFormat().resolvedOptions().timeZone` when it is unset. `docs/TIME.md` needs rewriting
around the cookie.

---

## 5. The JavaScript that survives

One file, served once, cached, no per-entity generation. Everything in it is **enhancement**: the page
works with JS disabled.

1. **Relation picker for large targets** (`pBig` / `pSearch` / `pPickOne` / `pAddMany`). Search-as-you-type
   against `?view=terse&q=`. The zero-JS fallback is a search field with a submit button that re-renders
   the dialog with results — correct, just chattier. This is the only behaviour with a genuine argument
   for script.
2. **Select-all-on-page** (~3 lines), if §4.3 keeps it.
3. **Timezone cookie seeding** (~3 lines, one time).
4. **Optional niceties**: `onchange="this.form.submit()"` on filter selects, `onsubmit="return confirm()"`
   on destructive buttons.

Budget: **under 150 lines total**, in `assets/`, reviewable in one sitting — against ~450 lines today
generated nine times into every page. If it grows past that during implementation, that is the signal to
stop and reconsider, not to keep adding.

---

## 6. Rust simplification

Deletions:

- `templates/_form_core.html` (263) and `templates/_form_fields.html` (171) — gone
- `templates/table.html` — the `<script>` block (`table.html:247-614`, ~370 lines) gone; the markup stays
  and becomes a real Askama template over `Vec<Column>` + `Page`
- `assets/rl-time.js` (212) — gone (§4.4)
- `ui.rs` — `columns_json`, `filters_json`, `formatters` JS-literal assembly (`ui.rs:210-221`), and
  `sort_json` all stop existing; these exist only to cross the wire

Additions, all generic and model-agnostic (**no procedural macros**):

- one function walking `Vec<Column>` × `Page` into rendered rows
- one `match Column` → widget renderer, replacing `widgetOf`
- form decoding (`payload()`'s rules, in Rust)
- URL state parse/build (`ViewState` ↔ query string)
- pagination/sort arithmetic lifted from the JS

The row stays `serde_json::Value`. It is already the generic row representation and it keeps that job —
this is why no macro is needed anywhere: the inputs (`Vec<Column>`, `Page`) are already computed in Rust
at `ui.rs:205`, and the work is a nested loop over them.

Secondary win: a hand-written application page (the aircraft-maintenance work-order screens) can embed
a rendered `Table` or `Form` as **plain HTML**, without adopting Alpine, the `ruTable_*` component
namespace, or the library's fetch conventions. Today embedding `Form` drags all of that in.

Dependency effect: the `ui` fragment stops requiring Alpine and Bootstrap's JS bundle. Bootstrap **CSS**
stays (the markup is Bootstrap 5 classes, and dropping it is not in scope).

---

## 7. Testing

`ui_tests.rs` covers render-refusal cases (unknown/read-only/required-but-unrendered columns, widget
fit). Those stay and must keep passing.

New, following the `auth/security_tests.rs` pattern of driving the real router over in-memory SQLite:

- **Gate tests extended to the MPA write routes.** `crud/gate_tests.rs` asserts each preset's decision on
  the JSON API; the POST/303 routes are a new unauthenticated surface and need the same negative cases —
  including that a denied write never reaches the backend.
- **CSRF on every MPA write route**, with a positive control.
- **Escaping.** Every rendered cell, label, filter chip and input value gets a test with
  `<script>`-bearing data. Today this is the client's problem via `x-text`; server-rendering makes it
  ours, and §2's `format` change hands apps a raw-HTML API — so escaping needs tests, not care.
- **Round-trip state**: a URL with page + multi-key sort + filters + search renders the same set the JSON
  API returns for the equivalent query, and CSV export of that view matches it.

---

## 8. Prototype first

Before committing to phases, build one throwaway spike: **`examples/adminpanel`'s `post` table, server-rendered,
with an `<dialog>` edit that saves and returns.** It answers the three questions that decide the
design, and nothing else in this plan is worth doing if they answer badly:

1. Does `#row-{id}` after a save feel acceptable, or is a view transition needed? (§3.2)
2. Does the generic `Vec<Column>` × `Page` loop stay generic, or does the first real model force a
   special case? (This is the empirical test of the no-macros claim.)
3. How much does the large-target relation picker actually lose without JS? (§5)

---

## 9. Phases

Each phase leaves `main`-equivalent functionality working.

1. **Spike** (§8). Throwaway. Decide on the three questions.
2. **`Table` read path.** `ViewState`, server-rendered rows, paging, search, sort, filters, chips, CSV
   export link. Read-only — no writes yet. Both paths coexist behind a feature or a builder flag so the
   comparison is direct.
3. **`Form`, and `Table`'s dialog.** Widget `match`, form decode, POST routes, 303, 422 re-render, the
   `shell` closure. Resolve the CSV-import CSRF blocker (§4.3). Retire `on_saved`.
4. **`Admin`.** `?entity=` single-panel rendering, shared filter as a query param, nav. This is where the
   9,441 → ~1,100 line reduction lands.
5. **Bulk ops + time.** Selection form, delete-selected / delete-all, CSV import; timezone cookie,
   delete `rl-time.js`, rewrite `docs/TIME.md`.
6. **Cut over.** Delete the Alpine templates, change `format` to a closure, update `examples/adminpanel`
   and `examples/crud` and `examples/time`, rewrite `docs/CRUD.md` § Web UI, `CHANGELOG.md` breaking
   entries with upgrade steps, minor version bump.

Order rationale: phases 2-3 are where the design is proven or disproven, phase 4 is where the payoff
lands, and the breaking changes are deferred to phase 6 so the branch stays mergeable-in-principle until
the end.

---

## 10. Risks

- **Bootstrap modal → `<dialog>`.** Bootstrap 5's modal CSS assumes its own JS. `<dialog>` styling needs
  checking against the existing look; possible small CSS shim.
- **The `format` closure is a raw-HTML API.** Mitigated by making escaping the easy path and testing it
  (§7), but it hands apps a footgun the JS version also had — less visibly.
- **Large tables render more HTML per request** than a JSON page does. Probably irrelevant at
  `per_page` defaults, worth measuring in phase 2 at 100 rows × 20 columns.
- **Two rendering paths coexist during phases 2-5.** Time-boxed by phase 6; the risk is stalling
  mid-migration and keeping both indefinitely.
- **`ui` becomes stateful about URLs**, which the library previously left entirely to the app. §3.3 keeps
  reads fragment-only to limit this, but `routes()` is new surface area.
