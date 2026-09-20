# Building an app with relativelylight

A cookbook for the shape almost every deployment wants: **one page shell, a login page, a top nav
bar, an admin behind it, and your own pages beside it** — dashboards, custom forms, multi-step
workflows.

The library contributes fragments and a write path. *You* own the router, the `<html>`, and every
decision about layout. This document is the worked example of that division, using
`relativelylight = { version = "0.3", features = ["ui", "csv", "auth"] }`.

- [1. The skeleton](#1-the-skeleton) — one shell, one state, one layer
- [2. The page shell and the nav bar](#2-the-page-shell-and-the-nav-bar)
- [3. The login page](#3-the-login-page)
- [4. The admin](#4-the-admin) — two handlers
- [5. Your own pages](#5-your-own-pages) — embedding a table or a form
- [6. Dashboards](#6-dashboards) — reading from the engine
- [7. Custom forms the library doesn't render](#7-custom-forms-the-library-doesnt-render)
- [8. Multi-step workflows](#8-multi-step-workflows)
- [9. Checklist](#9-checklist)

Runnable versions of §§2–6 are `examples/adminpanel` (gated: login, 2FA, lockout panels) and
`examples/crud` (open: per-entity pages, a standalone form, a dashboard, timezones).

---

## 1. The skeleton

```rust
/// Everything a handler needs, behind one `Arc`.
struct App {
    engine: Arc<Engine>,
    auth: Auth,
    db: DatabaseConnection,      // for the queries the engine doesn't cover (§6, §7)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = connect().await?;   // your own sea_orm::Database::connect
    auth::migrate(&db).await?;                           // creates the auth_* tables

    let auth = Auth::new(db.clone(), Lockout::default().accounts(5, 300).addresses(15, 300))
        .admin_group("admin")
        .secure_cookies(!cfg.dev)                        // false only for local http
        .totp_issuer("Acme Ops")
        .login_shell(login_shell)                        // §3
        .profile_shell(profile_shell);                   // §3

    let mut crud = Crud::new(db.clone());
    let gate = Arc::new(UserReadGroupWrite::new(&auth, ["admin"]));
    crud.register(MetaModel::new(post::Entity), gate.clone());   // configure fields here as you like
    crud.register(MetaModel::new(tag::Entity), gate.clone());
    crud.csrf(auth.csrf());                              // cookie-authenticated writes → one token
    let engine = Arc::new(crud.into_engine());

    let app = Arc::new(App { engine, auth: auth.clone(), db: db.clone() });

    let router = Router::new()
        .route("/", get(dashboard))                      // §6
        .route("/admin", get(admin_show).post(admin_save))   // §4
        .route("/tickets/new", get(ticket_new).post(ticket_create))  // §5
        .route("/tz", post(set_tz))                      // §2
        .with_state(app)
        .merge(auth.routes())                            // /login, /logout, /profile, 2FA
        // REQUIRED, and outermost.
        .layer(from_fn_with_state(TrustProxy(cfg.trust_proxy), resolve_real_ip));

    // Housekeeping is yours: the crate spawns nothing.
    tokio::spawn({
        let auth = auth.clone();
        async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop { tick.tick().await; let _ = auth.prune().await; }
        }
    });

    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
```

Three things are load-bearing:

1. **`resolve_real_ip` must be the outermost layer.** The write path reads `RealIp` for the audit
   trail, and `auth`'s lockout counts by it; without the layer those routes answer `500` and say so.
2. **`crud.csrf(auth.csrf())`** puts the admin's forms and the login/profile forms on one token
   cookie. Skip it and the admin's writes are unprotected against cross-site posts.
3. **One `Arc<App>`** holding the engine, the `Auth` handle and your database — every handler below
   takes it as `State`.

## 2. The page shell and the nav bar

One askama template, one function, every page. The library never emits `<html>`.

```html
{# templates/shell.html #}
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }} · Acme Ops</title>
  <link href="/static/bootstrap.min.css" rel="stylesheet">
  <style>{{ css|safe }}</style>          {# relativelylight::crud::ui::CSS #}
</head>
<body class="bg-body-tertiary">
  <nav class="navbar navbar-expand bg-dark" data-bs-theme="dark">
    <div class="container-fluid">
      <a class="navbar-brand" href="/">Acme Ops</a>
      <ul class="navbar-nav me-auto">
        {% for item in nav %}
        <li class="nav-item">
          <a class="nav-link {% if item.active %}active{% endif %}" href="{{ item.href }}">{{ item.label }}</a>
        </li>
        {% endfor %}
      </ul>
      <div class="d-flex align-items-center gap-2">
        {{ tz_picker|safe }}                                    {# §2, below #}
        {% if !user.is_empty() %}
        <a class="navbar-text text-light" href="/profile">{{ user }}</a>
        <a class="btn btn-outline-light btn-sm" href="/logout">Log out</a>
        {% endif %}
      </div>
    </div>
  </nav>
  <main class="container-fluid my-4">{{ body|safe }}</main>
</body>
</html>
```

```rust
#[derive(Template)]
#[template(path = "shell.html")]
struct Shell {
    title: String,
    user: String,            // empty = anonymous
    nav: Vec<NavItem>,
    body: String,            // the fragment
    tz_picker: String,
    css: &'static str,
}

struct NavItem { label: &'static str, href: &'static str, active: bool }

impl Shell {
    /// Every page goes through here. `who` is `None` for anonymous pages.
    fn new(title: &str, who: Option<&Identity>, uri: &Uri, headers: &HeaderMap, body: String) -> Self {
        let here = uri.path();
        Self {
            title: title.into(),
            user: who.map(|w| w.username.clone()).unwrap_or_default(),
            nav: [("Dashboard", "/"), ("Admin", "/admin"), ("Tickets", "/tickets")]
                .map(|(label, href)| NavItem { label, href, active: here == href })
                .into(),
            body,
            // The picker returns to the page it was used on, so a zone change doesn't lose the view.
            tz_picker: TzPicker::new().render(&Tz::from_headers(headers), full_path(uri)),
            css: CSS,
        }
    }
    fn html(self) -> Response { Html(self.render().unwrap_or_default()).into_response() }

    /// For the two pages `auth` renders for us (§3): no request in hand, so no nav highlighting and
    /// no timezone picker — just the chrome.
    fn plain(title: &str, user: &str, body: String) -> Self {
        Self { title: title.into(), user: user.into(), nav: Vec::new(), body,
               tz_picker: String::new(), css: CSS }
    }
}

fn full_path(uri: &Uri) -> &str { uri.path_and_query().map(|p| p.as_str()).unwrap_or("/") }

/// One query parameter of your own, for pages that need something `ViewState` doesn't carry (§8).
fn query_param<'a>(uri: &'a Uri, key: &str) -> Option<&'a str> {
    uri.query()?
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}
```

**The timezone route** is four lines and the only thing your app does about timezones
([TIME.md](TIME.md)); everything the library renders then follows the cookie — cells, datetime
inputs, and CSV exports alike:

```rust
async fn set_tz(Form(f): Form<HashMap<String, String>>) -> Response {
    let tz = Tz::named(f.get("tz").map(String::as_str).unwrap_or("UTC"));
    let back = f.get("back").cloned().unwrap_or_else(|| "/".into());
    ([(header::SET_COOKIE, tz.cookie())], Redirect::to(&back)).into_response()
}
```

Offer the zones your deployment cares about — usually a list from your own configuration:
`TzPicker::new().zones(cfg.timezones)`, `.all_zones()`, or the default (UTC + Europe + US).

**A "who is this?" helper**, used by every gated page:

```rust
/// Resolve the caller, or hand back a redirect to the login page.
async fn require_login(app: &App, headers: &HeaderMap) -> Result<Identity, Response> {
    match app.auth.identify(headers).await {
        Some(who) => Ok(who),
        None => Err(Redirect::to(app.auth.login_path()).into_response()),
    }
}
```

## 3. The login page

`auth` renders the login form, handles the POST, the lockout, the TOTP second factor and the
recovery codes. You supply the chrome by giving it a closure — the fragment comes in, a full page
goes out:

```rust
fn login_shell(form: &str) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto" style="max-width:24rem"><div class="card-body">
             <h1 class="h5 mb-3">Sign in</h1>{form}
           </div></div>"#
    );
    Shell::plain("Sign in", "", body).render().unwrap_or_default()
}

/// The profile page (password change, 2FA enrolment, recovery codes, "sign out other sessions").
/// `who` is the caller, so the nav bar can show them.
fn profile_shell(fragment: &str, who: &Identity) -> String {
    Shell::plain("Profile", &who.username, fragment.to_string()).render().unwrap_or_default()
}
```

Both are **sync** closures returning a `String`: they run inside `auth`'s own handlers, which is why
they can't await your database — and they get no `Uri` or `HeaderMap`, so a nav bar that needs either
(the active-page highlight, the timezone picker) wants the simpler `Shell::plain` above.

`Auth::csrf_rejection(closure)` styles the `403` page the same way. Nothing else about login is
yours: `/login`, `/login/totp`, `/logout`, `/profile` and `/profile/{id}` all come from
`auth.routes()`.

## 4. The admin

Two handlers, one panel definition. This is the whole of it:

```rust
fn panel<'a>(app: &'a App, who: &Identity) -> Admin<'a> {
    let mut admin = Admin::new(&app.engine)
        .title("Admin")
        .filter("zone")                                  // one control across every table that has it
        .group("Content")
        .entity_with("post", |t| t.per_page(25).format("title", |v, row| {
            format!(r#"<a href="?entity=post&amp;edit={}">{}</a>"#, esc(&row["id"]), esc(v))
        }))
        .entity("tag");
    if app.auth.can_manage_others(who) {                 // admins also get the accounts section
        admin = admin.separator().group("Accounts")
            .entity_with("auth_user", |t| t.title("Login accounts"))
            .entity_with("auth_group", |t| t.title("Groups"));
    }
    admin
}

async fn admin_show(State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri) -> Response {
    let who = match require_login(&app, &headers).await { Ok(w) => w, Err(r) => return r };
    let state = ViewState::from_uri(&uri);
    if state.csv {                                       // the toolbar's Export link
        return match panel(&app, &who).csv(&headers, &state).await {
            Ok(csv) => ([(header::CONTENT_TYPE, "text/csv; charset=utf-8")], csv).into_response(),
            Err(e) => e.into_response(),
        };
    }
    match panel(&app, &who).render_for(&headers, &state).await {
        Ok(body) => Shell::new("Admin", Some(&who), &uri, &headers, body).html(),
        Err(e) => e.into_response(),                     // 401/403 from the model's gate
    }
}

async fn admin_save(
    State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri, RealIp(ip): RealIp,
    body: Bytes,                               // raw bytes — the CSV import dialog uploads a file
) -> Response {
    let who = match require_login(&app, &headers).await { Ok(w) => w, Err(r) => return r };
    let state = ViewState::from_uri(&uri);
    match panel(&app, &who).submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        Ok(Outcome::Invalid(state)) => match panel(&app, &who).render_for(&headers, &state).await {
            Ok(body) => (StatusCode::UNPROCESSABLE_ENTITY,
                         Shell::new("Admin", Some(&who), &uri, &headers, body).html()).into_response(),
            Err(e) => e.into_response(),
        },
        Err(e) => e.into_response(),
    }
}
```

Points worth internalising:

- **Build the panel with a function, not a `let`.** Both handlers must describe the same panel, or a
  link the page renders won't match what the write path accepts.
- **`render_for` enforces reads.** A caller whose gate refuses `List` gets `401`/`403` here, not a
  page with the rows in it. Hiding buttons is a *second* thing it does, not the main one.
- **`Outcome::Invalid` carries a `ViewState`** with the messages and the operator's input; re-render
  with it and answer `422`. Don't redirect — that would throw the input away.
- **Everything the panel links to is relative** (`?entity=tag&page=2`), so it works wherever you mount
  it, and both handlers must live on the same path.

## 5. Your own pages

### A table on a page of yours

Same two handlers, `Table` instead of `Admin`. `fixed_filter` is how you make a page that is *about*
one value:

```rust
// GET/POST /zones/{id}/records
fn records<'a>(app: &'a App, zone: &str) -> Table<'a> {
    Table::new(&app.engine, "record")
        .title("Records")
        .fixed_filter("zone", zone)      // pinned: no control, a chip, and a create pre-filled with it
        .sort("name")
        .per_page(50)
}
```

The pinned value narrows the listing, the CSV export and "delete all matching" together. It is a
**view**, not an authorization boundary — scoping who may see what is [`authz`](AUTH.md)'s job.

### A form on a page of yours

```rust
fn ticket_form(app: &App) -> Form<'_> {
    Form::new(&app.engine, "ticket")
        .title("New ticket")
        .fields(["subject", "body", "priority", "assignee"])   // subset *and* order
        .submit_label("Open ticket")
        .cancel("/tickets")
        .redirect("/tickets/{id}")                              // {id} = the new row
}

async fn ticket_new(State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri) -> Response {
    let who = match require_login(&app, &headers).await { Ok(w) => w, Err(r) => return r };
    match ticket_form(&app).render_for(&headers, &ViewState::from_uri(&uri)).await {
        Ok(body) => Shell::new("New ticket", Some(&who), &uri, &headers, body).html(),
        Err(Error::Unauthorized) => Redirect::to(app.auth.login_path()).into_response(),
        Err(e) => e.into_response(),
    }
}
// ticket_create mirrors admin_save, with ticket_form(&app) in place of panel(…).
```

`Form::render_for` **refuses** rather than rendering something that can't work: an unknown or
read-only column, or a create that omits a column the engine requires (a column `default` pre-fills
the input, so the field still has to be rendered for its value to be sent). Those are programming
errors and the message names the column.

## 6. Dashboards

A dashboard is your own template plus whatever the engine can answer. There is no special support and
none is needed — `Engine` is a normal typed API:

```rust
async fn dashboard(State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri) -> Response {
    let who = match require_login(&app, &headers).await { Ok(w) => w, Err(r) => return r };

    // Counts: ask for one row and read `total` — the backend still runs a COUNT, not a fetch.
    let count = |slug: &'static str, q: ListQuery| {
        let engine = app.engine.clone();
        async move { engine.list(slug, &q, true).await.map(|p| p.total).unwrap_or(0) }
    };
    let open = count("ticket", ViewState::from_query("filter[status]=open").to_list_query(1)).await;
    let total = count("ticket", ViewState::default().to_list_query(1)).await;

    // A recent-activity list, rendered as a real table with its own links.
    let recent = Table::new(&app.engine, "ticket")
        .title("Recently updated")
        .read_only(true)                 // a dashboard shows; the admin edits
        .search(false)
        .pagination(false)
        .per_page(5)
        .sort_desc("updated_at")
        .render_for(&headers, &ViewState::default())
        .await
        .unwrap_or_default();

    let body = DashboardTmpl { open, total, recent }.render().unwrap_or_default();
    Shell::new("Dashboard", Some(&who), &uri, &headers, body).html()
}
```

Two habits worth keeping:

- **`read_only(true)` + `pagination(false)` + `search(false)`** turns a `Table` into a plain panel of
  rows — the cheapest way to get consistent cells, badges, relation labels and timezone-correct
  timestamps on a page that isn't an admin. Add `columns([…])` to show four of the model's twenty,
  and `row_class(|row| …)` to colour the ones that need attention.
- **For anything the engine can't express** — a `GROUP BY`, a window function, a join across three
  tables — use SeaORM (or raw SQL) against the same `DatabaseConnection` you handed to `Crud`. Mixing
  is expected: the engine is for CRUD-shaped questions and gets out of the way for the rest.

## 7. Custom forms the library doesn't render

When a screen isn't "one row of one entity" — a settings page spanning three tables, a form with a
file upload, an action with no row behind it — hand-write it and keep the *validation* shared:

```rust
// The same predicates the model uses, called directly (see DATAINPUT.md).
if let Err(msg) = validate::hostname(&input.host) { errors.field("host", msg); }
if let Err(msg) = validate::int_range(1, 65535)(input.port.into()) { errors.field("port", msg); }
```

Two things to carry over from the library's own forms, because they are easy to forget:

- **The CSRF token.** Issue-and-echo in your own handler:
  ```rust
  let (token, set_cookie) = auth.csrf().ensure(&headers);     // render Csrf::hidden_input(&token)
  ```
  …or put the routes behind the layer and stop thinking about it:
  ```rust
  .layer(from_fn_with_state(auth.csrf(), relativelylight::csrf::enforce))
  ```
- **Re-authentication before anything sensitive.** A live session is not evidence its owner is
  present: `auth.reauthenticate(&who, password, code).await` before rotating a credential, changing a
  payout account, or deleting an installation. See [AUTH.md §5h](AUTH.md).

And if you want the write to appear in the same audit trail as the admin's, call your
`WriteObserver` yourself with a `WriteEvent` naming your own `source`.

## 8. Multi-step workflows

The library models rows, not processes — deliberately ([PRD §7](PRD.md)). A wizard is your handlers,
your state, and the library's forms wherever a step happens to be one row. Unlike §§2–6 there is no
runnable example of this one; it is a pattern, assembled from pieces each of which is demonstrated
elsewhere.

**Carry the step in the URL, and the work-in-progress in a row.** Not in the session: a session is
per-browser, so a second tab corrupts it, and nothing survives a restart.

```rust
// /onboarding/{id}?step=2   — `id` is a draft row you created at step 1
async fn onboarding(State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri, Path(id): Path<String>)
    -> Response
{
    let who = match require_login(&app, &headers).await { Ok(w) => w, Err(r) => return r };
    let state = ViewState::from_uri(&uri);
    let step: u8 = query_param(&uri, "step").and_then(|s| s.parse().ok()).unwrap_or(1);

    let fragment = match step {
        // Steps that are "fill in these columns of this row" are just a Form with a field subset…
        1 => Form::new(&app.engine, "installation").edit(&id)
                .fields(["customer", "site", "contact_email"])
                .submit_label("Next: hardware")
                .redirect(&format!("/onboarding/{id}?step=2"))
                .render_for(&headers, &state).await,
        2 => Form::new(&app.engine, "installation").edit(&id)
                .fields(["router_model", "serial", "wan_kind"])
                .submit_label("Next: review")
                .redirect(&format!("/onboarding/{id}?step=3"))
                .render_for(&headers, &state).await,
        // …and a step that isn't gets hand-written.
        _ => review_page(&app, &id).await,
    };
    match fragment {
        Ok(body) => Shell::new("Onboarding", Some(&who), &uri, &headers,
                               format!("{}{body}", steps_bar(step))).html(),
        Err(e) => e.into_response(),
    }
}
```

What makes this work:

- **`Form::redirect` is the "next" button.** Each step's save sends the browser to the next step's
  URL, so back/forward, refresh and a bookmarked half-finished workflow all behave.
- **A draft row, not a scratch struct.** Create it on entry (`status = "draft"`), let each step write
  its own columns, and have the final step flip the status inside a transaction. Validation then runs
  per step, by the same rules the admin uses, and an abandoned workflow is a row you can list and
  reap — one of the things `Table` with a `fixed_filter("status", "draft")` is good for.
- **Enforce the order server-side** if it matters. The URL is guessable; check the row's state at the
  top of the handler and redirect back to the earliest incomplete step rather than trusting `?step=`.
- **A step with no row behind it** (a confirmation, an external call, a file upload) is an ordinary
  hand-written page — §7. Mixing the two is the intended shape, not a workaround.
- **The POST handler is the usual one.** Each step's form posts back to its own URL, so
  `/onboarding/{id}` needs a `post` beside its `get` that calls the *same step's* `Form::submit` and
  handles `Outcome::Invalid` by re-rendering that step — exactly as in §4.

## 9. Checklist

Before a deployment goes out:

- [ ] `resolve_real_ip` is the **outermost** layer, and `serve` uses
      `into_make_service_with_connect_info::<SocketAddr>()`.
- [ ] `crud.csrf(auth.csrf())` is set, and any hand-written POST route is behind `csrf::enforce` or
      checks the token itself. (Don't put the **UI's** write route behind that layer: it doesn't
      parse multipart, so it would reject CSV uploads. `submit` checks the token itself.)
- [ ] `secure_cookies(true)` in production; the app is behind TLS.
- [ ] Every model is registered with a real gate — `Open` is public, including writes.
- [ ] `auth.prune()` runs on a schedule (the crate spawns nothing).
- [ ] Secrets are `write_only` / `hidden`; `auth::recovery::entity` is **not** registered in an admin
      panel, and `totp_secret` / `totp_pending` / `totp_last_step` are hidden.
- [ ] A password policy is configured on **both** surfaces — `Auth::password_policy` *and* the
      `auth_user` form's validator ([AUTH.md §5g](AUTH.md)).
- [ ] A `WriteObserver` is registered if you need an audit trail, and its rows are retained somewhere
      you can read them.
- [ ] Your shell loads Bootstrap 5's stylesheet **and** `crud::ui::CSS`.

## See also

- [CRUD.md](CRUD.md) — the engine, the columns, the URL as view state, the components' full API.
- [AUTH.md](AUTH.md) — sessions, 2FA, SSO, the gate presets, CSRF, lockout.
- [TIME.md](TIME.md) — the timezone cookie, the picker, configuring the offered zones.
- [DATAINPUT.md](DATAINPUT.md) — validators you can call from a hand-written form.
- [MPA_MIGRATION.md](../MPA_MIGRATION.md) — upgrading an app from 0.2.x.
