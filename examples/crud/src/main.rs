//! crud example — registers the model, serves the JSON API under /api/v1 (CRUD + metadata +
//! CSV import/export), a relativelylight UI (one page per entity, linked MPA-style from the navbar), and
//! Swagger UI at /docs over the generated OpenAPI.
//!
//! Try:  open http://127.0.0.1:3000/   ·   Swagger at /docs   ·   spec at /openapi.json

use askama::Template;
use relativelylight::authz::Open;
use relativelylight::crud::ui::Table;
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::validate;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
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
    table: String,
}

struct App {
    pages: HashMap<String, String>, // slug -> full shell page
    first: String,
    openapi: String,
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

    // Per-field presentation config (labels / help text / create defaults) — demo of the hooks.
    post_mm.field("title").label = Some("Title".into());
    post_mm.field("title").description = Some("The post headline (required).".into());
    post_mm.field("body").description = Some("Full text of the post.".into());
    post_mm.field("views").default = Some(serde_json::json!(0));
    post_mm.field("views").description = Some("View counter — defaults to 0 on create.".into());
    post_mm.field("published").label = Some("Published".into());
    post_mm.field("published").default = Some(serde_json::json!(true));
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

    // Pre-render one shell page per entity (shape read in-process; data is fetched client-side).
    let engine = crud.engine();
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
    let openapi = relativelylight::crud::openapi::merge_into(app_doc, engine)
        .to_pretty_json()
        .unwrap_or_default();
    let mut pages = HashMap::new();
    for slug in &entities {
        // `user` is a read-only table (display only); the rest are read-write with a form.
        let mut table = Table::new(engine, slug)
            .title(capitalize(slug))
            .read_only(slug == "user")
            .per_page(5); // small so the example exercises the pager (post → 9 pages)
        // Default picker_threshold (20) demos both widgets on the post form: author (6 rows) stays a
        // plain dropdown, while tags (40 rows) crosses over to the search→select combobox.
        if slug == "post" {
            // Custom cell renderer: link the title to the row's JSON record (demo of Table::format).
            table = table.format(
                "title",
                r#"(v, row) => `<a href="/api/v1/post/${row.id}" target="_blank">${v}</a>`"#,
            );
        }
        let table = table.render()?;
        let page = Shell {
            title: "relativelylight".into(),
            entities: entities.clone(),
            current: slug.clone(),
            table,
        }
        .render()?;
        pages.insert(slug.clone(), page);
    }
    let app = Arc::new(App {
        first: entities.first().cloned().unwrap_or_default(),
        pages,
        openapi,
    });

    let ui = Router::new()
        .route("/", get(home))
        .route("/ui/{slug}", get(ui_page))
        .route("/openapi.json", get(openapi_json))
        .route("/docs", get(docs))
        .with_state(app);

    let app_router =
        ui.merge(crud.into_router()).layer(axum::middleware::from_fn(access_log));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("relativelylight on   http://127.0.0.1:3000/");
    println!("Swagger UI on   http://127.0.0.1:3000/docs");
    println!("JSON API under  http://127.0.0.1:3000/api/v1");
    axum::serve(listener, app_router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

/// Access log: one line per request — source IP, method, URI, and HTTP status.
async fn access_log(ConnectInfo(addr): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let res = next.run(req).await;
    println!("{} {} {} -> {}", addr.ip(), method, uri, res.status().as_u16());
    res
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
