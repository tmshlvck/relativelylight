//! crud example — the server-rendered UI, ungated.
//!
//! One page per entity (`/ui/{slug}`), the **standalone `Form`** on the app's own pages
//! (`/post/new`, `/post/{id}/edit`), a table *about one value* at `/author/{id}/posts`, CSV export,
//! and a create/edit `<dialog>` that opens from the URL. No JavaScript framework, no JSON API: the
//! only script on the page is Bootstrap's CSS-free `confirm()` on a delete button, which the library
//! writes as an attribute.
//!
//! The shape to copy is the **two handlers per surface** at the bottom of this file: a `get` that
//! renders a fragment into the app's shell, and a `post` that hands the body to the library and
//! redirects. `examples/adminpanel` is the gated counterpart.
//!
//! Try:  open http://127.0.0.1:3000/   ·   /post/new   ·   /author/1/posts   ·   Export CSV
//!
//! `/dashboard` is the other half of the story (see docs/APP.md): a page of the app's own, built
//! from the same engine — counts read straight off `Engine::list`, and a read-only `Table` embedded
//! as a panel rather than an admin.

use askama::Template;
use axum::body::Bytes;
use axum::extract::{Form as AxumForm, Path, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use model::{author, event, post, profile, tag, user};
use relativelylight::authz::Open;
use relativelylight::crud::engine::{Engine, Result as CrudResult};
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::{esc, Form, Outcome, Table, ViewState, CSS};
use relativelylight::middleware::RealIp;
use relativelylight::time::{Tz, TzPicker};
use relativelylight::validate;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Template)]
#[template(path = "shell.html")]
struct Shell {
    title: String,
    entities: Vec<String>,
    current: String,
    body: String,
    css: &'static str,
    /// The navbar timezone form (`time::TzPicker`), posting to our own `/tz`.
    tz_picker: String,
    /// Wrap the body in a card. The table pages want it; a `Form` renders its own card, and two
    /// nested ones look like a mistake.
    boxed: bool,
}

struct App {
    engine: Arc<Engine>,
    entities: Vec<String>,
}

/// The per-request bits every page needs beyond its own data: who is asking (the timezone cookie
/// lives in their headers) and where they are (so the picker can return there).
#[derive(Clone, Copy)]
struct Req<'a> {
    headers: &'a HeaderMap,
    uri: &'a Uri,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = model::setup().await?;

    let mut author_mm = MetaModel::new(author::Entity);
    let user_mm = MetaModel::new(user::Entity);
    let profile_mm = MetaModel::new(profile::Entity);
    let mut post_mm = MetaModel::new(post::Entity);
    let mut tag_mm = MetaModel::new(tag::Entity);
    post_mm.relate(&tag_mm);
    tag_mm.relate(&post_mm);

    // Label author rows by their name — and, because the column is *declared* rather than computed in
    // a closure, `post` can be sorted by its `author` column: the engine turns `?sort=author` into an
    // ORDER BY on `author.name`, so the order matches the labels on screen. A model whose label isn't
    // a single column simply reports the relation as unsortable instead of guessing.
    author_mm.label_column("name");

    // Per-field presentation config (labels / help text / create defaults).
    post_mm.field("title").label = Some("Title".into());
    post_mm.field("title").description = Some("The post headline (required).".into());
    post_mm.field("body").description = Some("Full text of the post.".into());
    // **Per-field widget overrides.** The default input is derived from the column type; these pick a
    // different one where the type alone can't know better. Cells are unaffected — a table row is no
    // place for a slider.
    post_mm.field("body").textarea(8); // prose wants more than a one-line input
    post_mm.field("views").default = Some(serde_json::json!(0));
    post_mm.field("views").range(0.0, 500.0, 1.0);
    post_mm.field("views").description = Some("View counter — defaults to 0 on create.".into());
    // A **closed set of values**. `status` is a plain text column in SQLite, so the allowed values are
    // declared here — which turns the form input into a dropdown and makes anything else a validation
    // error instead of a stored typo. A Postgres/MySQL enum column needs none of this: the variants
    // are introspected from `ColumnType::Enum`.
    post_mm.field("status").options =
        vec!["draft".into(), "review".into(), "published".into(), "archived".into()];
    post_mm.field("status").description = Some("Editorial state — a closed set.".into());
    // The same closed set as a **radio group** rather than a dropdown: four choices worth seeing at
    // once. (`radio` needs `options`, so it's set above — reversing these two lines is a render-time
    // error naming the field.)
    post_mm.field("status").radio();
    post_mm.field("published").label = Some("Published".into());
    post_mm.field("published").default = Some(serde_json::json!(true));
    // An int column holding **Unix seconds** → a datetime picker in the form and a readable cell in
    // the table, storage staying integer UTC. Both are rendered **server-side** in the caller's zone;
    // this example sets no timezone cookie, so that zone is UTC (see `examples/time`).
    post_mm.field("published_at").datetime();
    post_mm.field("published_at").label = Some("Published at".into());
    post_mm.field("published_at").description = Some("When it went live.".into());
    post_mm.relation("author").label = Some("Author".into());
    post_mm.relation("tag").label = Some("Tags".into());

    // Demo validators from `relativelylight::validate` — typed predicates wired via the
    // `validate_str` / `validate_int` sugar (see docs/DATAINPUT.md). The same predicates are callable
    // from a hand-written endpoint; here they plug into the auto-CRUD write path, and a failure comes
    // back in the dialog beside the field that caused it.
    post_mm.field("title").validate_str(validate::all_of(vec![
        Box::new(validate::non_empty),
        Box::new(validate::length(1, 80)),
    ]));
    post_mm.field("views").validate_int(validate::int_min(0)); // a view count is never negative

    // A normalizer (on_write transform) + a validator on the author: trim the name, require a
    // 2-letter ISO country code.
    author_mm.field("name").on_write = Some(validate::field::str_transform(validate::normalize::trim));
    author_mm.field("name").validate_str(validate::non_empty);
    author_mm.field("country").description = Some("ISO 3166-1 alpha-2 country code, e.g. \"US\".".into());
    author_mm.field("country").validate_str(validate::length(2, 2));
    // `email`/`url` widgets: the browser's own check plus the right mobile keyboard. That check is a
    // convenience, not the control — the validator beside each one is what actually runs.
    author_mm.field("email").email();
    author_mm.field("email").validate_str(validate::optional(Box::new(validate::email)));
    author_mm.field("homepage").url();
    author_mm.field("homepage").validate_str(validate::optional(Box::new(validate::url)));

    // A cross-field row validator → the dialog's banner rather than one field's message.
    post_mm.validate_row = Some(Box::new(|fields| {
        let get = |k: &str| fields.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let mut errs = relativelylight::crud::ValidationErrors::new();
        if !get("title").is_empty() && get("title") == get("body") {
            errs.general("Title and body must differ.");
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }));

    // The timezone demo's table: one name, one integer-UTC timestamp. `.datetime()` is the whole
    // configuration — the cell, the form input and the CSV cell are then rendered in the caller's
    // zone, server-side (see docs/TIME.md).
    let mut event_mm = MetaModel::new(event::Entity);
    event_mm.field("name").label = Some("Event".into());
    event_mm.field("happens_at").label = Some("Happens at".into());
    event_mm.field("happens_at").description =
        Some("Type a wall-clock time in the selected zone; it is stored as integer UTC seconds.".into());
    event_mm.field("happens_at").datetime();

    // Ungated demo: every model takes the `Open` gate (no auth). See `adminpanel` for a gated app.
    let mut crud = Crud::new(db);
    crud.register(author_mm, Open);
    crud.register(post_mm, Open);
    crud.register(user_mm, Open);
    crud.register(profile_mm, Open);
    crud.register(tag_mm, Open);
    crud.register(event_mm, Open);

    let engine = Arc::new(crud.into_engine());
    let entities = engine.tables();
    let app = Arc::new(App { engine, entities: entities.clone() });

    let router = Router::new()
        .route("/", get(home))
        .route("/dashboard", get(dashboard))
        // Two handlers per surface: render on GET, hand the body to the library on POST.
        .route("/ui/{slug}", get(entity_page).post(entity_write))
        .route("/post/new", get(new_post).post(save_new_post))
        .route("/post/{id}/edit", get(edit_post).post(save_post))
        .route("/author/{id}/posts", get(author_posts).post(author_posts_write))
        // The timezone picker's handler — four lines, and the whole of this app's side of the
        // feature. Everything the library renders then follows the cookie.
        .route("/tz", post(set_tz))
        .with_state(app)
        // One resolution of the caller's address for the whole app (see relativelylight::middleware).
        // Mandatory: the write handlers read `RealIp` for the audit trail.
        .layer(axum::middleware::from_fn_with_state(
            relativelylight::middleware::TrustProxy(false),
            relativelylight::middleware::resolve_real_ip,
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("relativelylight on  http://127.0.0.1:3000/");
    println!("Standalone form     http://127.0.0.1:3000/post/new");
    println!("Pinned filter       http://127.0.0.1:3000/author/1/posts");
    println!("Timezones + DST     http://127.0.0.1:3000/ui/event   (pick a zone in the navbar)");
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

// ---- the per-entity table pages ----

/// This app's table configuration, in one place: both handlers below build it the same way, so the
/// links a page renders and the writes it accepts can't drift apart.
fn table<'a>(engine: &'a Engine, slug: &str) -> Table<'a> {
    let mut t = Table::new(engine, slug)
        .title(capitalize(slug))
        .read_only(slug == "user") // display only; the rest are read-write
        .per_page(5); // small, so the example exercises the pager (post → 9 pages)
    if slug == "post" {
        t = t
            // Custom cell renderer: link each title to its own edit page. Escaping is the app's job
            // and `esc` is how — the closure's output is inserted verbatim.
            .format("title", |v, row| {
                format!(r#"<a href="/post/{}/edit">{}</a>"#, esc(&row["id"]), esc(v))
            })
            // A filter on a *relation*: the toolbar gets an author picker, and choosing one narrows
            // the listing, the CSV export and "delete all matching" alike. Sorting by `author` orders
            // by the name shown in the cell rather than the foreign key.
            .filter("author")
            .sort("title");
    }
    t
}

async fn home() -> Redirect {
    Redirect::to("/ui/post")
}

/// Set the zone cookie and come back to the page it was set from.
async fn set_tz(AxumForm(fields): AxumForm<HashMap<String, String>>) -> Response {
    let tz = Tz::named(fields.get("tz").map(String::as_str).unwrap_or("UTC"));
    let back = fields.get("back").cloned().unwrap_or_else(|| "/".into());
    ([(header::SET_COOKIE, tz.cookie())], Redirect::to(&back)).into_response()
}

// ---- a page of the app's own: a dashboard (docs/APP.md §6) ----
//
// Nothing here is a library feature. The counts are `Engine::list` asked for one row — the backend
// still runs a COUNT, and `Page::total` is the answer — and the panel is an ordinary `Table` with
// its chrome turned off. The point of the example is that a custom page and the admin read the same
// model, so a status renders the same way in both.

#[derive(Template)]
#[template(path = "dashboard.html")]
struct Dashboard {
    cards: Vec<(&'static str, u64)>,
    recent: String,
}

async fn dashboard(State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri) -> Response {
    let count = |slug: &'static str, query: &str| {
        let engine = app.engine.clone();
        let q = ViewState::from_query(query).to_list_query(1);
        async move { engine.list(slug, &q, true).await.map(|p| p.total).unwrap_or(0) }
    };

    // A read-only `Table` is the cheapest way to get consistent cells, relation labels and
    // timezone-correct timestamps on a page that isn't an admin.
    let recent = Table::new(&app.engine, "post")
        .title("Recently published")
        .read_only(true)
        .search(false)
        .pagination(false)
        .per_page(5)
        .sort_desc("published_at")
        .format("title", |v, row| {
            format!(r#"<a href="/post/{}/edit">{}</a>"#, esc(&row["id"]), esc(v))
        })
        .render_for(&headers, &ViewState::default())
        .await;

    let body = Dashboard {
        cards: vec![
            ("Posts", count("post", "").await),
            ("Published", count("post", "filter[status]=published").await),
            ("Drafts", count("post", "filter[status]=draft").await),
            ("Authors", count("author", "").await),
        ],
        recent: match recent {
            Ok(html) => html,
            Err(e) => return e.into_response(),
        },
    }
    .render();

    match body {
        Ok(body) => render(&app, "dashboard", Req { headers: &headers, uri: &uri }, Ok(body), false),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn entity_page(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    uri: Uri,
    Path(slug): Path<String>,
) -> Response {
    let state = ViewState::from_uri(&uri);
    let table = table(&app.engine, &slug);
    // The toolbar's Export link is `?format=csv` on this same page, so the export is this handler's
    // other answer — and it exports the view on screen, filters and sort included.
    if state.csv {
        return match table.csv(&headers, &state).await {
            Ok(csv) => (
                [
                    (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                    (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{slug}.csv\"")),
                ],
                csv,
            )
                .into_response(),
            Err(e) => e.into_response(),
        };
    }
    render(&app, &slug, Req { headers: &headers, uri: &uri }, table.render_for(&headers, &state).await, true)
}

async fn entity_write(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    uri: Uri,
    RealIp(ip): RealIp,
    Path(slug): Path<String>,
    body: Bytes,
) -> Response {
    let state = ViewState::from_uri(&uri);
    let table = table(&app.engine, &slug);
    match table.submit(&headers, ip, &body, &state).await {
        // Relative, so it comes back to this page — the library never learns its path.
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        // Refused: re-render with the messages and the typed values in place.
        Ok(Outcome::Invalid(state)) => {
            let html = table.render_for(&headers, &state).await;
            let page = render(&app, &slug, Req { headers: &headers, uri: &uri }, html, true);
            (StatusCode::UNPROCESSABLE_ENTITY, page).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// One author's posts — a page that is *about* one value, so the filter is pinned rather than offered.
///
/// `fixed_filter` gives no control to change it; the table shows it as a chip so the listing can't be
/// mistaken for the whole set, and a create from here pre-selects that author. It narrows the
/// **view** only — authorization is [`authz`]'s business, not the table's.
fn pinned<'a>(engine: &'a Engine, author_id: &str) -> Table<'a> {
    Table::new(engine, "post")
        .title("Posts")
        .fixed_filter("author", author_id)
        .sort("title")
        .per_page(5)
}

async fn author_posts(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
) -> Response {
    let state = ViewState::from_uri(&uri);
    let html = pinned(&app.engine, &id).render_for(&headers, &state).await;
    render(&app, "post", Req { headers: &headers, uri: &uri }, html, true)
}

async fn author_posts_write(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    uri: Uri,
    RealIp(ip): RealIp,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let state = ViewState::from_uri(&uri);
    let table = pinned(&app.engine, &id);
    match table.submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        Ok(Outcome::Invalid(state)) => {
            let html = table.render_for(&headers, &state).await;
            let page = render(&app, "post", Req { headers: &headers, uri: &uri }, html, true);
            (StatusCode::UNPROCESSABLE_ENTITY, page).into_response()
        }
        Err(e) => e.into_response(),
    }
}

// ---- the standalone form on the app's own pages (crud::ui::Form) ----
//
// The building block the admin table is assembled from, used directly. Note what *isn't* here: no
// field list in HTML, no input types, no validation wiring, no relation lookups. The form is built
// from the model's columns, so `status` is a radio group of its four values, `published_at` gets a
// datetime picker, `author` a `<select>` and `tag` a multi-select — and a validation failure lands on
// the field that caused it.

/// A user-facing form shows a chosen subset, in a chosen order — not every writable column, which is
/// the admin's job. `views` has to be among them even though it has a default of 0: the default
/// pre-fills the *input*, so the field must be rendered for the value to be sent. Drop it and
/// rendering fails here, naming the column, instead of the save failing in the browser.
fn new_form(engine: &Engine) -> Form<'_> {
    Form::new(engine, "post")
        .title("New post")
        .description("The same form the admin table opens in a dialog — on a page of your own.")
        .fields(["title", "body", "status", "views", "published", "published_at", "author", "tag"])
        .submit_label("Create post")
        .cancel("/ui/post")
        .redirect("/post/{id}/edit")
}

async fn new_post(State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri) -> Response {
    let state = ViewState::from_uri(&uri);
    let html = new_form(&app.engine).render_for(&headers, &state).await;
    render(&app, "post", Req { headers: &headers, uri: &uri }, html, false)
}

async fn save_new_post(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    uri: Uri,
    RealIp(ip): RealIp,
    body: Bytes,
) -> Response {
    let state = ViewState::from_uri(&uri);
    let form = new_form(&app.engine);
    match form.submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        Ok(Outcome::Invalid(state)) => {
            let html = form.render_for(&headers, &state).await;
            let page = render(&app, "post", Req { headers: &headers, uri: &uri }, html, false);
            (StatusCode::UNPROCESSABLE_ENTITY, page).into_response()
        }
        Err(e) => e.into_response(),
    }
}

fn edit_form<'a>(engine: &'a Engine, id: &str) -> Form<'a> {
    Form::new(engine, "post")
        .edit(id)
        .title(format!("Edit post #{id}"))
        .cancel("/ui/post")
        .saved_message("Saved.")
}

async fn edit_post(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
) -> Response {
    let state = ViewState::from_uri(&uri);
    let html = edit_form(&app.engine, &id).render_for(&headers, &state).await;
    render(&app, "post", Req { headers: &headers, uri: &uri }, html, false)
}

async fn save_post(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    uri: Uri,
    RealIp(ip): RealIp,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    let state = ViewState::from_uri(&uri);
    let form = edit_form(&app.engine, &id);
    match form.submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        Ok(Outcome::Invalid(state)) => {
            let html = form.render_for(&headers, &state).await;
            let page = render(&app, "post", Req { headers: &headers, uri: &uri }, html, false);
            (StatusCode::UNPROCESSABLE_ENTITY, page).into_response()
        }
        Err(e) => e.into_response(),
    }
}

// ---- the shell ----

/// Wrap a rendered fragment in the app's shell — or report why it couldn't render. A misconfigured
/// table or form (unknown column, a create missing a required one) is a programming error, and the
/// message says which column; in a gated app `Unauthorized` would redirect to the login page instead.
fn render(app: &App, current: &str, req: Req<'_>, fragment: CrudResult<String>, boxed: bool) -> Response {
    match fragment {
        Ok(body) => {
            let back = req.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
            let page = Shell {
                title: "relativelylight".into(),
                entities: app.entities.clone(),
                current: current.into(),
                body,
                css: CSS,
                tz_picker: TzPicker::new().render(&Tz::from_headers(req.headers), back),
                boxed,
            }
            .render();
            match page {
                Ok(html) => Html(html).into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Err(e) => e.into_response(),
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}
