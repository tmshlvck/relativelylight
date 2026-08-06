//! crud example — registers the model, serves the JSON API under /api/v1 (CRUD + metadata +
//! CSV import/export), a relativelylight UI (one page per entity, linked MPA-style from the navbar), a
//! **standalone `Form`** on its own pages (/post/new, /post/{id}/edit), and Swagger UI at /docs over the
//! generated OpenAPI.
//!
//! Try:  open http://127.0.0.1:3000/   ·   /post/new   ·   Swagger at /docs   ·   spec at /openapi.json

use askama::Template;
use relativelylight::authz::Open;
use relativelylight::crud::engine::Engine;
use relativelylight::crud::ui::{Form, Table};
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::validate;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use model::{author, post, profile, tag, user};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use utoipa::openapi::{InfoBuilder, OpenApiBuilder};

#[derive(Template)]
#[template(path = "shell.html")]
struct Shell {
    title: String,
    entities: Vec<String>,
    current: String,
    body: String,
    /// Wrap the body in a card. The table pages want it; a `Form` renders its own card, and two nested
    /// ones look like a mistake.
    boxed: bool,
}

struct App {
    pages: HashMap<String, String>, // slug -> full shell page
    first: String,
    openapi: String,
    /// Shared with the API router: the form pages are rendered **per request** (the row id is in the
    /// URL), so unlike the table pages they can't be pre-rendered at startup.
    engine: Arc<Engine>,
    entities: Vec<String>,
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
    // ORDER BY on `author.name`, so the order matches the labels on screen. A model whose label isn't a
    // single column simply reports the relation as unsortable instead of guessing.
    author_mm.label_column("name");

    // Per-field presentation config (labels / help text / create defaults) — demo of the hooks.
    post_mm.field("title").label = Some("Title".into());
    post_mm.field("title").description = Some("The post headline (required).".into());
    post_mm.field("body").description = Some("Full text of the post.".into());
    // **Per-field widget overrides.** The default input is derived from the column type; these pick a
    // different one where the type alone can't know better. Cells are unaffected — a table row is no
    // place for a slider.
    post_mm.field("body").textarea(8); // prose wants more than a one-line input
    post_mm.field("views").default = Some(serde_json::json!(0));
    // A slider, with the value shown beside it. `step` is 1 because these are whole view counts: a step
    // that doesn't divide the stored value puts the handle at the nearest step while the readout keeps
    // showing the exact number (which is what would be saved) — truthful, but confusing to look at.
    post_mm.field("views").range(0.0, 500.0, 1.0);
    post_mm.field("views").description = Some("View counter — defaults to 0 on create.".into());
    // A **closed set of values**. `status` is a plain text column in SQLite, so the allowed values are
    // declared here — which turns the form input into a dropdown, publishes them as `enum` in the OpenAPI
    // schema, and makes anything else a 422 instead of a stored typo. A Postgres/MySQL enum column needs
    // none of this: the variants are introspected from `ColumnType::Enum`.
    post_mm.field("status").options =
        vec!["draft".into(), "review".into(), "published".into(), "archived".into()];
    post_mm.field("status").description = Some("Editorial state — a closed set.".into());
    // The same closed set as a **radio group** rather than a dropdown: four choices worth seeing at once.
    // (`radio` needs `options`, so it's set above — reversing these two lines is a render-time error.)
    post_mm.field("status").radio();
    post_mm.field("published").label = Some("Published".into());
    post_mm.field("published").default = Some(serde_json::json!(true));
    // An int column holding **Unix seconds** → a datetime picker in the form and a readable cell in the
    // table, storage and wire staying integer UTC. This shell doesn't load `time::JS`, so both fall back
    // to plain UTC rather than a selected zone (see docs/TIME.md; the `time` example wires the picker up).
    post_mm.field("published_at").datetime();
    post_mm.field("published_at").label = Some("Published at".into());
    post_mm.field("published_at").description = Some("When it went live (UTC).".into());
    post_mm.relation("author").label = Some("Author".into());
    post_mm.relation("tag").label = Some("Tags".into());

    // Demo validators from `relativelylight::validate` — typed predicates wired via the
    // `validate_str` / `validate_int` sugar (see docs/DATAINPUT.md). The same predicates are callable
    // directly from a hand-written endpoint; here they plug into the auto-CRUD write path.
    post_mm
        .field("title")
        .validate_str(validate::all_of(vec![Box::new(validate::non_empty), Box::new(validate::length(1, 80))]));
    post_mm.field("views").validate_int(validate::int_min(0)); // a view count is never negative

    // A normalizer (on_write transform) + a validator on the author: trim the name, require a
    // 2-letter ISO country code.
    author_mm.field("name").on_write = Some(validate::field::str_transform(validate::normalize::trim));
    author_mm.field("name").validate_str(validate::non_empty);
    author_mm.field("country").description = Some("ISO 3166-1 alpha-2 country code, e.g. \"US\".".into());
    author_mm.field("country").validate_str(validate::length(2, 2));
    // `email`/`url` widgets: the browser's own check plus the right mobile keyboard. That check is a
    // convenience, not the control — the validator beside each one is what actually runs, and is what a
    // caller hitting the JSON API directly meets.
    author_mm.field("email").email();
    author_mm.field("email").validate_str(validate::optional(Box::new(validate::email)));
    author_mm.field("homepage").url();
    author_mm.field("homepage").validate_str(validate::optional(Box::new(validate::url)));

    // A cross-field row validator (form banner) — unchanged, shows the non-`validate` hook.
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

    // Ungated demo: every model takes the `Open` gate (no auth). See `adminpanel` for a gated app.
    let mut crud = Crud::new(db, "/api/v1");
    crud.register(author_mm, Open);
    crud.register(post_mm, Open);
    crud.register(user_mm, Open);
    crud.register(profile_mm, Open);
    crud.register(tag_mm, Open);

    // One shared engine: the router serves the API from it, the table pages are pre-rendered from it
    // below, and the /post/new + /post/{id}/edit handlers render a `Form` from it per request.
    let engine = Arc::new(crud.into_engine());
    let entities = engine.tables();
    // The app owns the OpenAPI document root (its own info/servers/version); the crud entity
    // endpoints + schemas are merged in. A real app would also add its own your own paths here.
    let app_doc = OpenApiBuilder::new()
        .info(
            InfoBuilder::new()
                .title("relativelylight API")
                .version("1.0.0")
                .description(Some("Example app — the app owns the OpenAPI root; crud contributes the entity endpoints."))
                .build(),
        )
        .build();
    let openapi = relativelylight::crud::openapi::merge_into(app_doc, &engine)
        .to_pretty_json()
        .unwrap_or_default();
    let mut pages = HashMap::new();
    for slug in &entities {
        // `user` is a read-only table (display only); the rest are read-write with a form.
        let mut table = Table::new(&engine, slug)
            .title(capitalize(slug))
            .read_only(slug == "user")
            .per_page(5); // small so the example exercises the pager (post → 9 pages)
        // Default picker_threshold (20) demos both widgets on the post form: author (6 rows) stays a
        // plain dropdown, while tags (40 rows) crosses over to the search→select combobox.
        if slug == "post" {
            // Custom cell renderer (demo of Table::format): link each title to the **standalone**
            // edit form, so the same row is editable both ways — the table's modal and its own page.
            table = table.format(
                "title",
                r#"(v, row) => `<a href="/post/${row.id}/edit">${v}</a>`"#,
            );
            // A filter on a *relation*: the toolbar gets an author picker, and choosing one narrows
            // the listing, the CSV export and "delete all matching" alike. Sorting by `author` orders
            // by the name shown in the cell rather than the foreign key — `author_mm.label_column`
            // below is what makes that possible.
            table = table.filter("author").sort("title");
        }
        let table = table.render()?;
        let page = Shell {
            title: "relativelylight".into(),
            entities: entities.clone(),
            current: slug.clone(),
            body: table,
            boxed: true,
        }
        .render()?;
        pages.insert(slug.clone(), page);
    }
    let app = Arc::new(App {
        first: entities.first().cloned().unwrap_or_default(),
        pages,
        openapi,
        engine: engine.clone(),
        entities: entities.clone(),
    });

    let ui = Router::new()
        .route("/", get(home))
        .route("/ui/{slug}", get(ui_page))
        .route("/post/new", get(post_new))
        .route("/post/{id}/edit", get(post_edit))
        .route("/author/{id}/posts", get(author_posts))
        .route("/openapi.json", get(openapi_json))
        .route("/docs", get(docs))
        .with_state(app);

    // No request log: this crate ships none (it writes nothing anywhere). `examples/access_log` is a
    // dozen lines you can copy, in two variants.
    let app_router = ui
        .merge(engine.router())
        // One resolution of the caller's address for the whole app (see relativelylight::middleware).
        .layer(axum::middleware::from_fn_with_state(
            relativelylight::middleware::TrustProxy(false),
            relativelylight::middleware::resolve_real_ip,
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("relativelylight on   http://127.0.0.1:3000/");
    println!("Standalone form  http://127.0.0.1:3000/post/new");
    println!("Swagger UI on   http://127.0.0.1:3000/docs");
    println!("JSON API under  http://127.0.0.1:3000/api/v1");
    axum::serve(listener, app_router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

async fn home(State(app): State<Arc<App>>) -> impl IntoResponse {
    match app.pages.get(&app.first) {
        Some(html) => Html(html.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "no entities registered").into_response(),
    }
}

async fn ui_page(State(app): State<Arc<App>>, Path(slug): Path<String>) -> impl IntoResponse {
    match app.pages.get(&slug) {
        Some(html) => Html(html.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "unknown entity").into_response(),
    }
}

// ---- the standalone form on the app's own pages (crud::ui::Form) ----
//
// This is the building block the admin panel is assembled from, used directly. Note what *isn't* here:
// no field list in HTML, no input types, no validation wiring, no relation lookups. The form is built
// from the model's published metadata, so `status` is a dropdown of its four values, `published_at` gets
// a datetime picker, `author` a plain <select> and `tags` a search→select combobox (40 rows crosses the
// picker threshold) — and a 422 from the API lands on the field that caused it.

/// Create a post on its own page, then go to its edit page.
async fn post_new(State(app): State<Arc<App>>) -> Response {
    // A user-facing form shows a chosen subset, in a chosen order — not every writable column, which is
    // the admin's job. `views` has to be among them even though it has a default of 0: the default
    // pre-fills the *input*, so the field must be rendered for the value to be sent. Drop it and
    // rendering fails here, naming the column, instead of the save 422-ing in the browser.
    let form = Form::new(&app.engine, "post")
        .title("New post")
        .description("The same form the admin table opens in a modal — on a page of your own.")
        .fields(["title", "body", "status", "views", "published", "published_at", "author", "tag"])
        .submit_label("Create post")
        .cancel("/ui/post")
        .redirect("/post/{id}/edit")
        .render();
    render_form(&app, "post", form)
}

/// One author's posts — a page that is *about* one value, so the filter is pinned rather than offered.
///
/// `fixed_filter` gives no control to change it; the table shows it as a chip so the listing can't be
/// mistaken for the whole set, and the create form pre-selects that author. It narrows the **view**
/// only — the API is still queryable for other authors, which is [`authz`]'s business, not the table's.
/// Rendered per request because the pinned value comes from the URL.
async fn author_posts(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let table = Table::new(&app.engine, "post")
        .title("Posts")
        .fixed_filter("author", &id)
        .sort("title")
        .per_page(5)
        .render();
    match table {
        Ok(html) => {
            let page = Shell {
                title: "relativelylight".into(),
                entities: app.entities.clone(),
                current: "post".into(),
                body: html,
                boxed: true,
            }
            .render();
            match page {
                Ok(p) => Html(p).into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Edit an existing post on its own page.
async fn post_edit(State(app): State<Arc<App>>, Path(id): Path<String>) -> Response {
    let form = Form::new(&app.engine, "post")
        .edit(&id)
        .title(format!("Edit post #{id}"))
        .cancel("/ui/post")
        .saved_message("Saved. The table will show the change on its next load.")
        .render();
    render_form(&app, "post", form)
}

/// Wrap a rendered form in the app's shell — or report why it couldn't render. In a gated app
/// `render_for` would be used instead, and `Unauthorized` would redirect to the login page.
fn render_form(app: &App, current: &str, form: relativelylight::crud::Result<String>) -> Response {
    match form {
        Ok(html) => {
            let page = Shell {
                title: "relativelylight".into(),
                entities: app.entities.clone(),
                current: current.into(),
                body: html,
                boxed: false,
            }
            .render();
            match page {
                Ok(p) => Html(p).into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        // A misconfigured form (unknown column, or a create missing a required one) is a programming
        // error, and says which column — see crud::ui::Form.
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn openapi_json(State(app): State<Arc<App>>) -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/json")],
        app.openapi.clone(),
    )
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

async fn docs() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><meta charset="utf-8"><title>API docs</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css"></head>
<body><div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>window.onload=()=>{SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui'});};</script>
</body></html>"#,
    )
}
