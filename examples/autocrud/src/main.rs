//! autocrud example — registers the model, serves the JSON API under /api/v1 (CRUD + metadata +
//! CSV import/export), a Rune Admin UI (one page per entity, linked MPA-style from the navbar), and
//! Swagger UI at /docs over the generated OpenAPI.
//!
//! Try:  open http://127.0.0.1:3000/   ·   Swagger at /docs   ·   spec at /openapi.json

use askama::Template;
use autocrud::alpine::Table;
use autocrud::seaorm::{Crud, MetaModel};
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use model::{author, post, profile, tag, user};
use std::collections::HashMap;
use std::sync::Arc;

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

    let author_mm = MetaModel::new(author::Entity);
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
    post_mm.relation("author").label = Some("Author".into());
    post_mm.relation("tag").label = Some("Tags".into());

    // Demo validators: a field validator (shown under the field) and a row validator (form banner).
    post_mm.field("title").validate = Some(Box::new(|v| {
        let s = v.as_str().unwrap_or("");
        if s.trim().is_empty() {
            Err("Title cannot be empty".into())
        } else if s.chars().count() > 80 {
            Err("Title too long (max 80 characters)".into())
        } else {
            Ok(())
        }
    }));
    post_mm.validate_row = Some(Box::new(|fields| {
        let get = |k: &str| fields.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let mut errs = autocrud::ValidationErrors::new();
        if !get("title").is_empty() && get("title") == get("body") {
            errs.general("Title and body must differ.");
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }));

    let mut crud = Crud::new(db, "/api/v1");
    crud.register(author_mm);
    crud.register(post_mm);
    crud.register(user_mm);
    crud.register(profile_mm);
    crud.register(tag_mm);

    // Pre-render one shell page per entity (shape read in-process; data is fetched client-side).
    let engine = crud.engine();
    let entities = engine.tables();
    let openapi = autocrud::openapi::json(engine, "Rune autocrud API");
    let mut pages = HashMap::new();
    for slug in &entities {
        // `user` is a read-only table (display only); the rest are read-write with a form.
        let table = Table::new(engine, slug)
            .title(capitalize(slug))
            .read_only(slug == "user")
            .per_page(5) // small so the example exercises the pager (post → 9 pages)
            // Low threshold to demo both relation widgets: on the post form the author (6 rows)
            // stays a plain dropdown, while tags (8 rows) crosses over to the search→select picker.
            .picker_threshold(7)
            .render()?;
        let page = Shell {
            title: "Rune Admin".into(),
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

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("Rune Admin on   http://127.0.0.1:3000/");
    println!("Swagger UI on   http://127.0.0.1:3000/docs");
    println!("JSON API under  http://127.0.0.1:3000/api/v1");
    axum::serve(listener, ui.merge(crud.into_router())).await?;
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
