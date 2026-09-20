# Migrating to 0.3.0

0.3.0 re-homes the web UI in Rust. `crud::ui` renders plain server-side HTML, and **the JSON API, the
metadata API and the OpenAPI document are removed** — that wire existed to feed the JavaScript this
release deletes. The appendix at the end is the reasoning; everything before it is the upgrade.

```toml
relativelylight = { version = "0.3", features = ["ui", "csv", "auth"] }   # note: no "openapi"
```

**How long this takes.** An app that renders an admin and nothing else: about twenty minutes — one
router change, two handlers, and a build error per `render()` call. An app that *published* the JSON
API to its own clients has more to do, because those endpoints are now yours to write (§9); the
library gives you the same typed calls they were built on.

- [1. Is this release for you?](#1-is-this-release-for-you)
- [2. Cargo.toml](#2-cargotoml)
- [3. `Crud::new` loses its path](#3-crudnew-loses-its-path)
- [4. The router: one merge becomes two handlers](#4-the-router-one-merge-becomes-two-handlers)
- [5. `render()` → `render_for(&headers, &state)`](#5-render--render_forheaders-state)
- [6. `Table::format` takes a closure](#6-tableformat-takes-a-closure)
- [7. `Form::on_saved` is gone](#7-formon_saved-is-gone)
- [8. Timezones move to the server](#8-timezones-move-to-the-server)
- [9. If you published the JSON API](#9-if-you-published-the-json-api)
- [10. CSV](#10-csv)
- [11. Behaviour changes that aren't API changes](#11-behaviour-changes-that-arent-api-changes)
- [12. What did *not* change](#12-what-did-not-change)
- [13. Compile-error cheat sheet](#13-compile-error-cheat-sheet)
- [14. Full before/after](#14-full-beforeafter)
- [15. Symbol reference](#15-symbol-reference)
- [Appendix: why the rewrite happened](#appendix-why-the-rewrite-happened)

---

## 1. Is this release for you?

| If your app… | Then |
|---|---|
| renders `Admin`/`Table`/`Form` and nothing else | §§2–8. The shape of your page handler barely changes |
| serves `/api/v1/...` to *its own* clients (scripts, mobile, another service) | §9 as well — you now own those routes |
| publishes an OpenAPI document containing crud's paths | §9. The generator is gone; describe your own handlers |
| uses `auth` without `crud` | nothing to do. `auth` is untouched |
| implements `Accessor` itself | `Column`/`Page`/`RowItem` gained derives and `Accessor` is no longer a stability promise; recompile and follow the errors |

Everything below is a compile error if you miss it, with one exception flagged in §11 (reads became
gated, which is a behaviour change your tests should notice before your users do).

## 2. Cargo.toml

```diff
-relativelylight = { version = "0.2", features = ["ui", "openapi", "csv", "auth"] }
+relativelylight = { version = "0.3", features = ["ui", "csv", "auth"] }
```

- **`openapi` no longer exists.** Cargo fails with `does not have feature openapi`, which is the
  first thing you'll see.
- `ui` now implies `axum` and a new `tz` feature; `csv` implies `tz`. You don't have to name them.
- Drop `utoipa` from your own dependencies if it was there only for the merged document.
- `tz` pulls [`jiff`](https://docs.rs/jiff) for the IANA timezone database (§8).

Your page shell loses two `<script>` tags and gains one `<style>`:

```diff
 <link href="…/bootstrap.min.css" rel="stylesheet">
-<style>[x-cloak] { display: none !important; }</style>
-<script defer src="…/alpinejs@3.x.x/dist/cdn.min.js"></script>
-<script>{{ time_js|safe }}</script>
+<style>{{ css|safe }}</style>          {# relativelylight::crud::ui::CSS #}
 …
-<script src="…/bootstrap.bundle.min.js"></script>
```

Bootstrap's **stylesheet** is still required. Its JavaScript bundle is not, and neither is Alpine.

## 3. `Crud::new` loses its path

```diff
-let mut crud = Crud::new(db, "/api/v1");
+let mut crud = Crud::new(db);
```

There is no mount prefix any more: every link the UI renders is query-only and relative (`?page=2`),
so a component works on whatever path you serve it from and the library never learns that path.

## 4. The router: one merge becomes two handlers

This is the substantive change. `Crud::into_router()` and `Engine::router()` are gone; the library
contributes **no routes**. You write a `get` that renders and a `post` that writes, on the same path:

```diff
 let app = Router::new()
     .route("/admin", get(admin_page))
-    .merge(crud.into_router())
+    .route("/admin", get(admin_show).post(admin_save))
     .merge(auth.routes())
     .layer(from_fn_with_state(TrustProxy(cfg.trust_proxy), resolve_real_ip));
```

```rust
use relativelylight::crud::ui::{Admin, Outcome, ViewState};
use relativelylight::middleware::RealIp;

// Build the panel in a function: both handlers must describe the same one, or a link the page
// renders won't match what the write path accepts.
fn panel(engine: &Engine) -> Admin<'_> {
    Admin::new(engine).title("Admin").entity("post").entity("tag")
}

async fn admin_show(State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri) -> Response {
    let state = ViewState::from_uri(&uri);
    match panel(&app.engine).render_for(&headers, &state).await {
        Ok(fragment) => Html(my_shell(fragment)).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn admin_save(
    State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri, RealIp(ip): RealIp,
    body: Bytes,                                   // raw bytes: a CSV upload is a file
) -> Response {
    let state = ViewState::from_uri(&uri);
    match panel(&app.engine).submit(&headers, ip, &body, &state).await {
        // A relative target: "?entity=post&page=2#row-7".
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        // Rejected by validation: re-render with the messages *and* the operator's input in place.
        Ok(Outcome::Invalid(state)) => {
            let fragment = panel(&app.engine).render_for(&headers, &state).await.unwrap_or_default();
            (StatusCode::UNPROCESSABLE_ENTITY, Html(my_shell(fragment))).into_response()
        }
        Err(e) => e.into_response(),
    }
}
```

Three things to get right:

- **`RealIp` is required** on the write handler — `submit` takes the caller's address for the audit
  trail. `middleware::resolve_real_ip` was already mandatory; now a second thing reads it.
- **Take the body as `axum::body::Bytes`, not `String`.** The CSV import dialog uploads a file as
  `multipart/form-data`, and `submit` reads the token and the file out of it; a `String` extractor
  would mangle the bytes. Ordinary urlencoded forms are unaffected.
- **Don't redirect on `Invalid`.** That throws away what the operator typed. Re-render and answer
  `422`.
- **The `get` and the `post` must share a path**, because the forms post to `action=""` (the current
  URL) and the redirect target is relative to it.

## 5. `render()` → `render_for(&headers, &state)`

All three components: `render()` and `render_for(&headers)` are replaced by one
**`async fn render_for(&headers, &state)`**.

```diff
-let html = Admin::new(&engine).entity("post").render()?;
+let state = ViewState::from_uri(&uri);            // page, sort, filters, search, ?edit=…
+let html = Admin::new(&engine).entity("post").render_for(&headers, &state).await?;
```

- **It is now `async`**, because rendering reads rows. A handler that used to be sync isn't.
- **`ViewState::default()`** is page 1, unsorted, unfiltered — fine for a page that ignores the URL,
  but you lose paging and sorting, so parse the URI unless you mean it.
- **The `render()` variant is gone on purpose.** With no API behind the UI, `render_for` is the read
  enforcement point; a render that couldn't consult the gate would be a way around it.
- **Pre-rendering at startup no longer works** (it never really did — it froze page 1). Render per
  request.

If your handler was sync, it becomes `async`; if it built pages in `main` and stored them in a
`HashMap`, delete that and render in the handler.

## 6. `Table::format` takes a closure

```diff
-.format("title", r#"(v, row) => `<a href="/api/v1/post/${row.id}">${v}</a>`"#)
+.format("title", |v, row| format!(r#"<a href="/post/{}">{}</a>"#, esc(&row["id"]), esc(v)))
```

`use relativelylight::crud::ui::esc;`. The closure runs during render and its output is inserted
verbatim, so **wrap anything from the database in `esc`** — that is the one place app HTML enters the
page. (The JavaScript version interpolated database content unescaped; several apps, including our
own example, had an XSS hole there. This closes it by construction, provided you call `esc`.)

Signature: `Fn(&Value, &Value) -> String + Send + Sync + 'static`, taking `(cell value, whole row)`.

## 7. `Form::on_saved` is gone

It ran JavaScript after a `fetch`; there is no `fetch`.

```diff
-.on_saved("(row) => { location.href = '/tickets/' + row.id }")
+.redirect("/tickets/{id}")        // {id} is replaced with the saved row's id
```

Without `redirect`, `Form::submit` returns `?saved=1` and the form shows `saved_message` when it sees
that parameter — which is why the standalone form's `get` should parse `ViewState::from_uri`.

## 8. Timezones move to the server

`time::JS`, `window.RL_TZ`, `window.RLTime` and the Alpine `$store.tz` are gone. The selected zone now
rides in a cookie and **the server formats**, so a CSV export finally matches the screen.

```diff
-<script>window.RL_TZ = { mode: 'utc', persist: 'local' };</script>
-<script>{{ time_js|safe }}</script>
-{{ tz_picker|safe }}                     {# TzPicker::new().render() #}
+{{ tz_picker|safe }}                     {# TzPicker::new().render(&Tz::from_headers(&headers), back) #}
```

Add the four-line route the picker posts to:

```rust
async fn set_tz(Form(f): Form<HashMap<String, String>>) -> Response {
    let tz = Tz::named(f.get("tz").map(String::as_str).unwrap_or("UTC"));
    let back = f.get("back").cloned().unwrap_or_else(|| "/".into());
    ([(header::SET_COOKIE, tz.cookie())], Redirect::to(&back)).into_response()
}
```

Configure which zones it offers — `TzPicker::new()` (UTC + Europe + US), `.all_zones()`, or
`.zones(cfg.timezones)` from your own configuration. The crate's own lists exclude the Russian
Federation and Belarus. Full guide: [TIME.md](TIME.md).

If you never showed a picker, you have nothing to do: everything renders UTC, as it did.

## 9. If you published the JSON API

The endpoints are yours now. This is a transfer of ownership, not a loss of capability — the engine
calls the old handlers were built on are public, typed, and unchanged in meaning. A faithful
reproduction of the removed routes is about forty lines:

```rust
use relativelylight::crud::engine::{Engine, Error, Page};
use relativelylight::crud::ui::ViewState;          // reuse the query-string parser

async fn api_list(State(e): State<Arc<Engine>>, headers: HeaderMap,
                  Path(entity): Path<String>, uri: Uri) -> Result<Json<Value>, Error> {
    authorize(&e, Operation::List, &entity, &headers).await?;     // your gate check — see below
    let q = ViewState::from_query(uri.query().unwrap_or("")).to_list_query(25);
    let page: Page = e.list(&entity, &q, false).await?;
    Ok(Json(json!({
        "total": page.total, "page": page.page, "per_page": page.per_page,
        "data": page.data.iter().map(|it| json!({
            "id": it.id, "label": it.label, "row": it.row,
        })).collect::<Vec<_>>(),
    })))
}

async fn api_get(State(e): State<Arc<Engine>>, headers: HeaderMap,
                 Path((entity, pk)): Path<(String, String)>) -> Result<Json<Value>, Error> {
    authorize(&e, Operation::Read, &entity, &headers).await?;
    Ok(Json(e.get(&entity, &pk).await?))
}

async fn api_create(State(e): State<Arc<Engine>>, headers: HeaderMap,
                    Path(entity): Path<String>, Json(body): Json<Value>)
    -> Result<(StatusCode, Json<Value>), Error> {
    authorize(&e, Operation::Create, &entity, &headers).await?;
    Ok((StatusCode::CREATED, Json(e.create(&entity, &body).await?)))
}

// update → e.update(&entity, &pk, &body), delete → e.delete(&entity, &pk),
// bulk delete → e.delete_where(&entity, &q)   … all the same shape.

/// The gate check the old handlers ran. Do this *before* touching the engine.
async fn authorize(e: &Engine, op: Operation, entity: &str, headers: &HeaderMap)
    -> Result<(), Error> {
    match e.decide(entity, op, headers).await {
        Decision::Allow => Ok(()),
        Decision::NeedsLogin => Err(Error::Unauthorized),
        Decision::Denied => Err(Error::Forbidden),
    }
}

let api = Router::new()
    .route("/{entity}", get(api_list).post(api_create).delete(api_delete_many))
    .route("/{entity}/{pk}", get(api_get).patch(api_update).delete(api_delete))
    .with_state(engine.clone());
let app = app.nest("/api/v1", api);
```

Four things the old handlers did that you must not forget:

1. **The gate, before the work** (`authorize` above). `Engine` does not check it for you — the UI's
   `submit` does, but a hand-written route is on its own.
2. **CSRF**, if the API is cookie-authenticated: put the routes behind
   `csrf::enforce`, or check `Authorization` yourself. Bearer-credentialed clients are exempt by
   design.
3. **The audit event.** `Crud::on_write` fires only for writes the UI applies. Call your
   `WriteObserver` from these handlers too, with a `source` naming your API, if the audit trail is
   meant to be complete.
4. **`Error` already implements `IntoResponse`** — as plain text, not JSON. Map it yourself if your
   clients expect a JSON body:
   `Err(e) => (status_of(&e), Json(json!({ "error": e.one_line() }))).into_response()`.

**Do you actually still need it?** Worth asking once: a browser-only admin doesn't, and the reason
this API was removed is that nothing but the deleted JavaScript consumed it. If you keep it, you now
control its shape and versioning, which is the point.

**OpenAPI.** `crud::openapi::{build, merge_into, json}` are gone with the generator. Describe your own
handlers with utoipa's `#[utoipa::path]` macros on the functions above — you're writing the routes,
so the annotations go where the routes are.

## 10. CSV

The endpoints are gone; the capability moved into the UI.

```diff
-// GET /api/v1/post?format=csv         (a route the library served)
+// The toolbar's Export link puts ?format=csv on your own page. Answer it in the read handler:
+if state.csv {
+    return match panel(&app.engine).csv(&headers, &state).await {
+        Ok(csv) => ([(header::CONTENT_TYPE, "text/csv; charset=utf-8")], csv).into_response(),
+        Err(e) => e.into_response(),
+    };
+}
```

Import is now a dialog in the table's CSV menu (`?import=1`), offering a **file upload** or a paste;
both post `_op=import` and are handled by `submit` like any other write. The upload is real
`multipart/form-data`, and the `_csrf` token rides in a part of it — which both `submit` and the
`csrf::enforce` layer now read, so a guarded route can accept uploads.

`csv_io::export`/`import` changed signature: they take `&[Column]` and a `&Tz` instead of re-deriving
columns from metadata JSON. Exported datetimes are in the caller's zone.

## 11. Behaviour changes that aren't API changes

These compile silently. Check them.

- **Reads are gated.** `render_for` now consults the model's gate for `List` (and `Read` when a
  dialog is open) and returns `401`/`403`. Previously the API enforced reads and the UI only hid
  buttons. **If your panel lists a model some of its users may not read, they now get an error page
  instead of a table** — list those models conditionally, as `examples/adminpanel` does for the
  accounts section.
- **The URL carries the view.** Page, sort, filters, search, the active entity and the open dialog are
  query parameters. Anything of your own in that query string survives (unknown parameters are
  ignored), but don't reuse the names in [CRUD.md § The URL is the view](docs/CRUD.md#the-url-is-the-view).
- **`Admin` renders one entity per request** (`?entity=post`), not every panel with one shown.
  Deep links into your admin should carry `?entity=`.
- **Multi-key sort** is an explicit `+` on each header instead of shift-click.
- **The create/edit modal is a `<dialog>`** opened by `?new=1` / `?edit={id}`, not by a button that
  toggles a div. You can link straight to a row's editor.
- **`per_page` defaults to 30** in `Table` (25 in a hand-built `ListQuery`), as before.
- **Relations above `picker_threshold`** render an id input rather than a search-as-you-type combobox
  (that needed the fetch endpoint this release removes). Raise the threshold if your target lists are
  moderate — a `<select>` of a few hundred options is fine.

## 12. What did *not* change

Most of what you wrote, in other words:

- **Model configuration** — `MetaModel`, `MetaField`, `MetaRelation`, `relate`, `label_column`,
  `hidden`, `read_only`, `write_only`, `password()`, `default`, `options`, the widget overrides
  (`textarea`, `radio`, `range`, `email`, `url`, `datetime`), `validate`, `validate_str/_int`,
  `on_read`/`on_write`, `validate_row`.
- **The whole `auth` module**: sessions, login, TOTP, recovery codes, SSO, lockout, profile pages,
  re-auth, `identify`, the gate presets, `login_shell`/`profile_shell`.
- **`authz`**, **`observe`** (including `source: "autocrud"`), **`csrf`**, **`middleware`**,
  **`validate`**, **`net`**.
- **Query semantics**: `filter[name]`, `sort=a,b:desc` including sorting by a relation's label, the
  primary-key tiebreaker, `q`, the bulk-delete guard.
- **The validation pipeline** and its messages.
- **The fragment contract**: all three components return HTML fragments; your app owns the page.

## 13. Compile-error cheat sheet

| Error | Fix |
|---|---|
| `package does not have feature openapi` | §2 |
| `no method named into_router found for struct Crud` | §4 |
| `no method named router found for Arc<Engine>` | §4 |
| `this function takes 1 argument but 2 were supplied` on `Crud::new` | §3 |
| `no method named render found for struct Table/Form/Admin` | §5 |
| `this method takes 2 arguments but 1 was supplied` on `render_for` | §5 — add `&state` |
| `` `impl Future` is not a `String` `` after `render_for` | §5 — it's `async` now; `.await` it |
| `expected an Fn(&Value, &Value) closure, found str` | §6 |
| `no method named on_saved` | §7 |
| `unresolved import relativelylight::time::JS` | §8 |
| `no function or associated item named meta_one/meta_all/entity_url` | §9 — use `columns` / your own URLs |
| `no method named csrf_cookie_name` | the UI renders its own hidden `_csrf`; delete the call |
| `Engine::list` "expected Value, found Page" | §9 — it returns `Page` now |
| `cannot find type Uri / HeaderMap in this scope` | `use axum::http::{HeaderMap, Uri};` |
| `expected &[u8], found &String` on `submit` | take the body as `axum::body::Bytes` (§4) |

## 14. Full before/after

A minimal gated admin, complete, both versions.

**0.2.x**

```rust
let mut crud = Crud::new(db.clone(), "/api/v1");
crud.register(post_mm, gate.clone());
crud.csrf(auth.csrf());
let engine = Arc::new(crud.into_engine());

let app = Router::new()
    .route("/", get(home))
    .with_state(state)
    .merge(auth.routes())
    .merge(engine.clone().router())
    .layer(from_fn_with_state(TrustProxy(false), resolve_real_ip));

async fn home(headers: HeaderMap, State(app): State<Arc<App>>) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let body = Admin::new(&app.engine).entity("post").render_for(&headers).await.unwrap();
    Html(Shell::page("Admin", who.username, body).render().unwrap()).into_response()
}
```

**0.3.0**

```rust
let mut crud = Crud::new(db.clone());
crud.register(post_mm, gate.clone());
crud.csrf(auth.csrf());
let engine = Arc::new(crud.into_engine());

let app = Router::new()
    .route("/", get(home).post(save))          // ← one route gains a POST
    .route("/tz", post(set_tz))                // ← if you show a timezone picker
    .with_state(state)
    .merge(auth.routes())
    .layer(from_fn_with_state(TrustProxy(false), resolve_real_ip));

fn panel(app: &App) -> Admin<'_> {             // ← shared by both handlers
    Admin::new(&app.engine).entity("post")
}

async fn home(headers: HeaderMap, uri: Uri, State(app): State<Arc<App>>) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let state = ViewState::from_uri(&uri);
    match panel(&app).render_for(&headers, &state).await {
        Ok(body) => Html(Shell::page("Admin", who.username, body).render().unwrap()).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn save(
    headers: HeaderMap, uri: Uri, RealIp(ip): RealIp, State(app): State<Arc<App>>, body: Bytes,
) -> Response {
    if app.auth.identify(&headers).await.is_none() {
        return Redirect::to(app.auth.login_path()).into_response();
    }
    let state = ViewState::from_uri(&uri);
    match panel(&app).submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        Ok(Outcome::Invalid(state)) => match panel(&app).render_for(&headers, &state).await {
            Ok(body) => (StatusCode::UNPROCESSABLE_ENTITY,
                         Html(Shell::page("Admin", "", body).render().unwrap())).into_response(),
            Err(e) => e.into_response(),
        },
        Err(e) => e.into_response(),
    }
}
```

Net: one extra handler, one shared `panel()` function, a `ViewState`, and the router merge deleted.
`examples/adminpanel` is this with 2FA, lockout panels, CSV and a timezone cookie;
[APP.md](APP.md) builds the rest of a real app around it.

## 15. Symbol reference

**Removed**

| Symbol | Replacement |
|---|---|
| `Crud::into_router`, `Engine::router` | your own `get`/`post` handlers (§4) |
| `crud::openapi::{build, merge_into, json}`, feature `openapi` | describe your own handlers (§9) |
| `Engine::meta_all`, `Engine::meta_one` | `Engine::columns` (typed) |
| `Engine::entity_url`, `Engine::base_path` | links are relative; there is no mount path |
| `Engine::csrf_cookie_name` | the UI renders the hidden `_csrf` itself |
| `Table::render`, `Form::render`, `Admin::render` | `render_for(&headers, &state).await` |
| `Form::on_saved` | `Form::redirect` / `saved_message` |
| `time::JS`, `time::ZONES` | `time::Tz` + `zones_default()` / `zones_all()` / `ZONES_EUROPE` / `ZONES_US` |
| `FieldDisplay::params`, `Serialize` on `LogicalType`/`Cardinality`/`FieldDisplay` | — (wire-only) |

**Changed**

| Symbol | 0.2.x | 0.3.0 |
|---|---|---|
| `Crud::new` | `(db, base_path)` | `(db)` |
| `Engine::new` | `(base_path)` | `()` |
| `Engine::list` | `-> Value` | `-> Page` |
| `Engine::delete_where` | `-> Value` | `-> u64` |
| `Table::format` | `(col, js: &str)` | `(col, impl Fn(&Value, &Value) -> String)` |
| `submit` body | — (new in 0.3) | `&[u8]`: pass `axum::body::Bytes` |
| `render_for` | `(&headers) -> Result<String>` | `async (&headers, &state) -> Result<String>` |
| `csv_io::export`/`import` | `(engine, slug, …)` | `(engine, slug, &[Column], …, &Tz)` |
| `TzPicker::render` | `()` | `(&Tz, back)` |
| feature `ui` | needs `askama` | also implies `axum` + `tz` |
| feature `csv` | needs `csv` | also implies `tz` |

**New**

`crud::ui::{ViewState, Mode, Done, Outcome, esc, esc_str, CSS}`,
`Table::{columns, row_class, detail, per_page_choices, per_page_max, fields, omit, dom_id, submit, csv}`,
`Admin::base` (a path per model, `/admin/post`, instead of `?entity=post`),
`Csrf::max_upload`,
`Form::submit`, `Admin::{submit, csv}`, `Engine::pk`, `time::{Tz, COOKIE, ZONES_EUROPE, ZONES_US,
EXCLUDED, zones_default, zones_all, is_excluded}`, `TzPicker::{action, all_zones, unknown_zones}`,
`FieldDisplay::is_datetime`, feature `tz`.

---

Questions this document doesn't answer are probably in [CRUD.md](CRUD.md) (the components
and the engine), [APP.md](APP.md) (composing a whole app), or the appendix below (why any of this
happened). If something here is wrong or missing, that's a bug in the guide — please say so.

---

# Appendix: why the rewrite happened

This is the design record for 0.3, folded in from the plan it was built from (`MPA.md`, deleted at
the end of the branch — the full text with its phase plan and risk table is in git history). It
answers "why" rather than "how to upgrade", and nothing below is needed to migrate an app.

## A1. The four measurements

Taken on 0.2.1, before anything moved.

**The page was the same thing many times.** A rendered `Admin` panel was `table.html` (615 lines) +
`_form_core.html` (263) + `_form_fields.html` (171) = **1,049 lines per entity**, repeated per
registered model. `examples/adminpanel` registers nine, so its admin page was **9,441 lines /
521 KB** — 136 KB gzipped, because gzip's 32 KB window can't dedupe copies 58 KB apart. `admin.html`
rendered every panel and showed one (`x-show="active === '{{ p.slug }}'"`).

**Type information was computed in Rust and then thrown away.** `Table::render_inner` called
`engine.columns(&slug)` and held a fully typed `Vec<Column>` — then re-derived it as `columns_json`
from `meta_one` so that untyped JavaScript could dispatch on it. Every `c.kind === "relation"`,
`c.display === "datetime"`, `c.type === "Bool"` in the Alpine code was a `match` that Rust would have
checked exhaustively, deliberately deferred to a language that cannot check it.

**The extension points were strings of another language.** The whole customization surface of `Table`
beyond layout flags was `format(column, js: String)` and `on_saved(js: String)`: JavaScript source
passed as a Rust `String`, checked by neither compiler and covered by no test.

**And the JSON API was that JavaScript's backend, not a product.** `openapi.rs` (477 lines) described
it, `engine.rs`'s `mod http` (295) served it, `meta_all`/`meta_one`/`column_json` (~115) assembled the
metadata it published, and `csv_io.rs` (230) read that metadata back out of untyped JSON it had just
produced — inside one process, from typed values it already had. Its shape (`{id, label}` relation
embedding, `?view=terse`, `_meta`'s column objects, the `422` field map) was a set of internal
conventions of the table component, published by accident.

Against that stood the counter-example inside the same crate: **`auth` was already a pure MPA.**
Login, TOTP, recovery codes, profile, password change and manager reset all rendered server-side and
answered writes with `Redirect::to(…)`, with zero JavaScript, behind 3,000 lines of
`security_tests.rs`. 0.3 was not an experiment — it made `crud::ui` work the way half the library
already worked.

## A2. Why the API could go

An application that needs a JSON API for its own consumers should write one. It has the database, it
has SeaORM, and the questions its API must answer — versioning, field selection, bearer tokens, rate
limits, pagination style — are product decisions this library has no business making. What the
library owes such an app is the **backend**: `MetaModel` configuration, the coerce → validate → hook
write pipeline, the `authz` gate, the write observer, and a *typed* `Engine` to call. Not a URL space.
§9 above is that argument turned into code.

The API between the backend and the crate's own table/form/admin components was never a contract,
never documented as stable, and stopped existing on the client side with the JavaScript. Keeping it
would have meant maintaining a published wire format, its OpenAPI description and its CSV adapter for
zero consumers.

## A3. What was explicitly not attempted

- **No business-process modelling.** No "Action" verb, no workflow engine. Apps that need multi-stage
  processes hand-write those pages and embed `Form`/`Table` where a step is a plain table or form —
  making that embedding cheap was a goal, and is what [APP.md](APP.md) §6 documents.
- **No change to the write pipeline.** Coercion, validation, transforms, hooks, N:M resolution and the
  SeaORM introspection are untouched; 0.3 changed what calls them and what renders their output.
- **No Bootstrap replacement.** The markup is still Bootstrap 5 classes and the app still loads the
  CSS. Bootstrap's *JavaScript* bundle stopped being required, as did Alpine.
- **No rewrite of `auth`'s hand-rolled HTML.** `auth` builds strings with `format!` + `esc`;
  `crud::ui` uses Askama. Unifying them is a later, separable cleanup.

## A4. Recorded decisions

- **`Accessor` stays public but is not a stability promise.** It has one implementor and exists for
  type erasure. Saying so in its docs lets `Column` gain fields without `#[non_exhaustive]` ceremony.
- **`Engine` and `Crud` stay two types.** Merging them would break `register`/`engine()` and delete
  nothing.
- **No `Html`/`Cell` newtype for `format`.** A `String` plus a public `esc` matches what `auth`
  already does and keeps the closure trivially writable; a type would move the footgun, not remove it.
- **No JavaScript relation picker**, which is why `picker_threshold` survives with a new mechanism
  rather than being deleted. See A6.4.
- **CSRF stayed opt-in** (`Crud::csrf`) rather than becoming mandatory: requiring it would add a
  builder argument every app must satisfy and delete no code. The examples enable it, and
  `gate_tests` covers both states.

## A5. The result, measured the same way

| | Planned | Actual |
|---|---|---|
| net crate source (non-test) | ≈ −800 | **−281** |
| deleted outright | — | `openapi.rs` 477, `ui.rs` 890, Alpine templates + JS **1,446** |
| new renderer | ≈ 1,480 | `ui/` 3,018 across ten modules, templates 220, `rl.css` 36, `urlform.rs` 100 |
| test suite | "extended" | **+516** lines |
| rendered adminpanel page | ≈ 700 lines | **498 lines / 25 KB** (from 9,441 / 521 KB) |
| JavaScript | < 30 lines | **~15 lines of inline attributes, no file** |

The net deletion is smaller than estimated because the new code carries doc comments and render-time
refusals the JavaScript never had, and because `ui/` absorbed the three components' builders rather
than replacing them. The claim that mattered held: **the per-request payload fell by ~20×**, and the
parts a compiler now checks are the parts that used to be strings.

## A6. Where the result differs from the plan

1. **The library contributes no routes at all.** The plan proposed one `POST` route per surface plus a
   `shell` closure. Instead `submit(&headers, ip, &body, &state) -> Outcome` is a method the app calls
   from its own `post` handler, and `Outcome::Invalid(state)` hands the state back for the app to
   re-render in *its own* shell. That deleted the shell closure, the router plumbing, the
   `Arc<Engine>`-vs-`&Engine` mismatch a `Router` would have forced, and the mount path: every link is
   relative, so the library never learns where it lives. Cost: ~8 lines of app code per surface (§4).
2. **No timezone `_op=tz` in `submit`.** Setting a cookie needs a response, which a fragment renderer
   never writes, so `TzPicker` posts to a four-line route of the app's own (`Tz::cookie()` returns the
   `Set-Cookie` value). Keeping it out of `submit` kept `Outcome` to two variants.
3. **`search[col]=term` was dropped from the URL vocabulary.** No control ever rendered it, so it was
   surface with no user; `ListQuery::search` still carries it for app code calling the engine.
4. **The large-relation picker is an id input**, not the zero-JS search sub-dialog the plan sketched:
   carrying the operator's in-progress form values through a search round trip means putting them all
   in the URL, which is real work for a rare case. `picker_threshold` still decides;
   [TODO.md](TODO.md) records both ways forward.
5. **CSV import posts the file itself.** The plan's fallback was a pasted `<textarea>` because
   `csrf::enforce` couldn't read a multipart body; the parser was written instead (`multipart.rs`, no
   new dependency), so the modal offers both a file upload and a paste box and neither involves
   JavaScript.
6. **`jiff`, not `chrono-tz`** — one crate instead of two, reading the host's IANA database, with UTC
   as the documented fallback when a host has none. The plan left this open.
7. **`examples/time` is gone**, folded into `examples/crud` (its `event` table now lives in
   `examples/model`, DST rows and comments intact, at `/event`). Once the timezone policy stopped
   being ~120 lines of JavaScript and became "which `Tz` your handler passes", the example's whole
   subject was four lines `examples/adminpanel` already showed. The DST-straddling dataset was worth
   keeping — as a table in an existing example, and as a unit test, which is better coverage than a
   page someone has to look at.

## A7. The one thing the plan missed

**Reads had to become gated.** With the API as the enforcement point, `Table::render_for` only decided
which *buttons* to draw; delete the API and that function becomes the only thing standing between a
caller and the rows. It now consults the gate for `List` (and `Read` when a dialog is open) and
answers `401`/`403`, and `crud/gate_tests.rs` asserts both that and that the backend is never reached.
Nothing in the plan anticipated it — it fell out of the first gate test written against the new
surface, which is the argument for having written the tests first.
