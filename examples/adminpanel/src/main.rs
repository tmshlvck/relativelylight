//! adminpanel example — the `autocrud::alpine::Admin` component.
//!
//! One page: a model side-panel (with group headings, a separator, and custom links) beside the
//! selected model's table + edit form. This replaces the hand-written per-entity page loop of the
//! `autocrud` example. The app still owns the three roots: the axum router (`/` is ours; autocrud is
//! merged under `/api/v1`), the askama shell (chrome + Bootstrap/Alpine), and the OpenAPI document
//! (our info; autocrud's entity endpoints merged in — no UI/docs routes leak into it).
//!
//! Try:  open http://127.0.0.1:3000/   ·   Swagger at /docs   ·   spec at /openapi.json

use askama::Template;
use autocrud::alpine::Admin;
use autocrud::seaorm::{Crud, MetaModel};
use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use model::{author, post, profile, tag, user};
use std::sync::Arc;
use utoipa::openapi::{InfoBuilder, OpenApiBuilder};

#[derive(Template)]
#[template(path = "shell.html")]
struct Shell {
    title: String,
    body: String,
}

struct App {
    page: String,
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

    // Per-field presentation + validation (drives the labels / help / defaults / errors in the form).
    post_mm.field("title").label = Some("Title".into());
    post_mm.field("title").description = Some("The post headline (required).".into());
    post_mm.field("views").default = Some(serde_json::json!(0));
    post_mm.field("published").label = Some("Published".into());
    post_mm.field("published").default = Some(serde_json::json!(true));
    post_mm.relation("author").label = Some("Author".into());
    post_mm.relation("tag").label = Some("Tags".into());
    post_mm.field("title").validate = Some(Box::new(|v| {
        if v.as_str().unwrap_or("").trim().is_empty() {
            Err("Title cannot be empty".into())
        } else {
            Ok(())
        }
    }));

    let mut crud = Crud::new(db, "/api/v1");
    crud.register(author_mm);
    crud.register(post_mm);
    crud.register(user_mm);
    crud.register(profile_mm);
    crud.register(tag_mm);

    let engine = crud.engine();

    // The Admin component: choose the order, group the models, drop in separators and custom links.
    // `user` is read-only; `post`'s title links to its record. Everything else uses defaults.
    let admin = Admin::new(engine)
        .title("Rune Admin")
        .group("Content")
        .entity_with("post", |t| {
            t.per_page(10).format(
                "title",
                r#"(v, row) => `<a href="/api/v1/post/${row.id}" target="_blank">${v}</a>`"#,
            )
        })
        .entity("tag")
        .separator()
        .group("People")
        .entity("author")
        .entity_with("user", |t| t.read_only(true))
        .entity("profile")
        .separator()
        .group("Reference")
        .link("API docs (Swagger)", "/docs")
        .link("OpenAPI JSON", "/openapi.json")
        .render()?;

    let page = Shell { title: "Rune Admin".into(), body: admin }.render()?;

    // The app owns the OpenAPI root; autocrud's entity endpoints + schemas are merged in.
    let app_doc = OpenApiBuilder::new()
        .info(InfoBuilder::new().title("Rune Admin API").version("1.0.0").build())
        .build();
    let openapi = autocrud::openapi::merge_into(app_doc, engine)
        .to_pretty_json()
        .unwrap_or_default();

    let app = Arc::new(App { page, openapi });

    let ui = Router::new()
        .route("/", get(home))
        .route("/openapi.json", get(openapi_json))
        .route("/docs", get(docs))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("Admin panel on  http://127.0.0.1:3000/");
    println!("Swagger UI on   http://127.0.0.1:3000/docs");
    println!("JSON API under  http://127.0.0.1:3000/api/v1");
    axum::serve(listener, ui.merge(crud.into_router())).await?;
    Ok(())
}

async fn home(State(app): State<Arc<App>>) -> impl IntoResponse {
    Html(app.page.clone())
}

async fn openapi_json(State(app): State<Arc<App>>) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/json")], app.openapi.clone())
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
