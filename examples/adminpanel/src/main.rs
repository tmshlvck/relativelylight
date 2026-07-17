//! adminpanel example — the `relativelylight::crud::ui::Admin` component, **login-gated** with the
//! `auth` module. Anonymous requests are redirected to `/login`; the JSON API is gated by an
//! `Authz` gate (logged-in users may read; only the admin group may write). Log in as
//! `admin` / `password`.
//!
//! Shows the whole stack composed by the app: the axum router (`/` ours, crud under `/api/v1`,
//! `auth` routes merged, the session middleware wrapping it all), the askama shell, the OpenAPI
//! document, and the authn/authz gate. (The `crud-example` is the ungated counterpart.)
//!
//! Try:  open http://127.0.0.1:3000/   ·   Swagger at /docs   ·   spec at /openapi.json

use askama::Template;
use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use model::{author, post, profile, tag, user};
use relativelylight::auth::{self, Auth, CurrentUser, UsersReadGroupWrite};
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::Admin;
use std::sync::Arc;
use utoipa::openapi::{InfoBuilder, OpenApiBuilder};

// The superadmin group (configurable). Its members may write; other logged-in users may only read.
const ADMIN_GROUP: &str = "admin";

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

    // auth: create the auth tables and seed an admin user in the admin group.
    auth::migrate(&db).await?;
    auth::make_admin(&db, ADMIN_GROUP, "admin", "password").await?;

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

    // The authorization gate: any logged-in user may list/read; only the admin group may write.
    let mut crud = Crud::new(db.clone(), "/api/v1")
        .authz(Arc::new(UsersReadGroupWrite { write_groups: vec![ADMIN_GROUP.into()] }));
    crud.register(author_mm);
    crud.register(post_mm);
    crud.register(user_mm);
    crud.register(profile_mm);
    crud.register(tag_mm);

    let engine = crud.engine();

    let admin = Admin::new(engine)
        .title("relativelylight")
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
        .link("Log out", "/logout")
        .render()?;

    let page = Shell { title: "relativelylight".into(), body: admin }.render()?;

    // The app owns the OpenAPI root; the crud entity endpoints + schemas are merged in.
    let app_doc = OpenApiBuilder::new()
        .info(InfoBuilder::new().title("relativelylight API").version("1.0.0").build())
        .build();
    let openapi = relativelylight::crud::openapi::merge_into(app_doc, engine)
        .to_pretty_json()
        .unwrap_or_default();

    let app = Arc::new(App { page, openapi });

    // authn: session middleware + login/logout routes, with a Bootstrap-styled login page.
    let auth = Auth::new(db)
        .secure_cookies(false) // local http
        .admin_group(ADMIN_GROUP)
        .login_shell(login_shell);

    let ui = Router::new()
        .route("/", get(home)) // login-gated (CurrentUser)
        .route("/openapi.json", get(openapi_json))
        .route("/docs", get(docs))
        .with_state(app);

    // Merge our pages, the login routes, and the gated API; wrap it all in the session middleware.
    let app_router = auth.wrap(ui.merge(auth.routes()).merge(crud.into_router()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("Admin panel on  http://127.0.0.1:3000/   (log in as admin / password)");
    println!("Swagger UI on   http://127.0.0.1:3000/docs");
    println!("JSON API under  http://127.0.0.1:3000/api/v1");
    axum::serve(listener, app_router).await?;
    Ok(())
}

// Requires a logged-in user; `CurrentUser` redirects anonymous visitors to /login.
async fn home(_user: CurrentUser, State(app): State<Arc<App>>) -> impl IntoResponse {
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

// The app styles the library's login form: drop it into our shell as a centered card.
fn login_shell(form: &str) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto" style="max-width:24rem"><div class="card-body">
<h1 class="h5 mb-3">Log in</h1>{form}
<p class="text-muted small mt-2 mb-0">Demo: <code>admin</code> / <code>password</code></p>
</div></div>"#
    );
    Shell { title: "Log in".into(), body }.render().unwrap_or_default()
}
