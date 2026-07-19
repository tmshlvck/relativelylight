//! adminpanel example — the `relativelylight::crud::ui::Admin` component, **login-gated** with the
//! `auth` module. Anonymous requests are redirected to `/login`; the JSON API is gated by an
//! `Authz` gate (logged-in users may read; only the admin group may write) and the panel is rendered
//! *per request* so write controls hide for users who can't write. Two demo logins:
//! `admin` / `password` (read-write) and `editor` / `password` (read-only).
//!
//! Shows the whole stack composed by the app: the axum router (`/` ours, crud under `/api/v1`,
//! `auth` routes merged, the session middleware wrapping it all), the askama shell, the OpenAPI
//! document, and the authn/authz gate. (The `crud-example` is the ungated counterpart.)
//!
//! Try:  open http://127.0.0.1:3000/   ·   Swagger at /docs   ·   spec at /openapi.json

use askama::Template;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use std::net::SocketAddr;
use model::{author, post, profile, tag, user};
use relativelylight::auth::{self, AdminOnly, Auth, Identity, UsersReadGroupWrite};
use relativelylight::crud::engine::Engine;
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
    user: String, // signed-in username (empty when anonymous) → navbar link to /profile
    body: String,
}

struct App {
    engine: Arc<Engine>,
    openapi: String,
    auth: Auth,
}

// The admin fragment's structure (nav groups, per-model table config). Built fresh per request so it
// can be rendered *for the caller*. `is_manager` marks callers in the admin group: only they get the
// `AdminOnly`-gated Accounts section (the auth users/groups), where each user-id links to its
// password-reset page. Non-managers would get 403 reading those models, so we omit the section for them.
fn build_admin(engine: &Engine, is_manager: bool) -> Admin<'_> {
    let mut admin = Admin::new(engine)
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
        .entity("profile");
    if is_manager {
        admin = admin
            .separator()
            .group("Accounts (auth)")
            // Login accounts: create/edit inline (password is the write-only field above); the id
            // links to /profile/{id} for a dedicated password reset. Password never shows in reads.
            .entity_with("auth_user", |t| {
                t.title("Login accounts").format(
                    "id",
                    r#"(v, row) => `<a href="/profile/${row.id}" title="Reset password">${v}</a>`"#,
                )
            })
            .entity_with("auth_group", |t| t.title("Groups"));
    }
    admin
        .separator()
        .group("Reference")
        .link("API docs (Swagger)", "/docs")
        .link("Log out", "/logout")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = model::setup().await?;

    // auth: create the auth tables and seed an admin user in the admin group.
    auth::migrate(&db).await?;
    auth::make_admin(&db, ADMIN_GROUP, "admin", "password").await?;
    // A second, non-admin user to show the gate at work: `editor` may read everything but write
    // nothing — the panel renders read-only for them (no Create/Edit/Delete) and the API returns 403.
    auth::create_user(&db, "editor", "password").await?;

    // authn: on-demand session lookups + login/logout routes, Bootstrap-styled login page. No
    // middleware — gates and page handlers call `auth.identify(&headers)` themselves.
    let auth = Auth::new(db.clone())
        .secure_cookies(false) // local http
        .admin_group(ADMIN_GROUP)
        .totp_issuer("relativelylight admin") // shown in authenticator apps for 2FA
        .login_shell(login_shell)
        .profile_shell(profile_shell); // the app's chrome around the library's profile page

    let author_mm = MetaModel::new(author::Entity);
    let user_mm = MetaModel::new(user::Entity);
    let profile_mm = MetaModel::new(profile::Entity);
    let mut post_mm = MetaModel::new(post::Entity);
    let mut tag_mm = MetaModel::new(tag::Entity);
    post_mm.relate(&tag_mm);
    tag_mm.relate(&post_mm);

    // The auth login accounts + groups, surfaced in the admin. `.password()` turns `password_hash`
    // into a write-only, argon2-hashed "Password" field in one call: plaintext in the form, a hash in
    // the column, never returned in reads. An empty password stores an empty hash — no password can
    // verify against it, so password login is disabled (e.g. for future SSO / PassKey users).
    let mut auth_user_mm = MetaModel::new(auth::user::Entity);
    auth_user_mm.field("password_hash").password();
    auth_user_mm.field("password_hash").description = Some(
        "Optional. Leave blank to create an account with no password (password login disabled). \
         On edit, blank keeps the current password."
            .into(),
    );
    // The TOTP secret columns are secrets — never expose them in reads/writes/metadata. (2FA is
    // managed from the profile page, not the crud form.)
    auth_user_mm.field("totp_secret").hidden = true;
    auth_user_mm.field("totp_pending").hidden = true;
    // New accounts are active by default (so a freshly created user with a password can log in).
    auth_user_mm.field("is_active").default = Some(serde_json::json!(true));
    let auth_group_mm = MetaModel::new(auth::group::Entity);

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

    // One gate for the whole panel: any logged-in user may list/read; only the admin group may write.
    // A shared `Arc` (it implements `Authz`) guards every model; each gate resolves the caller from
    // the request itself (via the `auth` handle it holds).
    let gate = Arc::new(UsersReadGroupWrite::new(&auth, [ADMIN_GROUP]));
    let mut crud = Crud::new(db.clone(), "/api/v1");
    crud.register(author_mm, gate.clone());
    crud.register(post_mm, gate.clone());
    crud.register(user_mm, gate.clone());
    crud.register(profile_mm, gate.clone());
    crud.register(tag_mm, gate.clone());
    // The auth accounts/groups are admin-only, read included (the new `AdminOnly` preset).
    let admin_gate = Arc::new(AdminOnly::new(&auth, [ADMIN_GROUP]));
    crud.register(auth_user_mm, admin_gate.clone());
    crud.register(auth_group_mm, admin_gate.clone());

    // One shared engine: the router serves the API from it, and the page handler renders the admin
    // fragment from it *per request* (so write controls hide for users who can't write).
    let engine = Arc::new(crud.into_engine());

    // The app owns the OpenAPI root; the crud entity endpoints + schemas are merged in.
    let app_doc = OpenApiBuilder::new()
        .info(InfoBuilder::new().title("relativelylight API").version("1.0.0").build())
        .build();
    let openapi = relativelylight::crud::openapi::merge_into(app_doc, &engine)
        .to_pretty_json()
        .unwrap_or_default();

    let app = Arc::new(App { engine: engine.clone(), openapi, auth: auth.clone() });

    let ui = Router::new()
        .route("/", get(home)) // login-gated (see `home`)
        .route("/openapi.json", get(openapi_json))
        .route("/docs", get(docs))
        .with_state(app);

    // Merge our pages, the login routes, and the gated API. No middleware: each handler/gate does
    // its own on-demand session lookup.
    let app_router = ui
        .merge(auth.routes())
        .merge(engine.router())
        .layer(axum::middleware::from_fn(access_log));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("Admin panel on  http://127.0.0.1:3000/   (admin/password = read-write · editor/password = read-only)");
    println!("Swagger UI on   http://127.0.0.1:3000/docs");
    println!("JSON API under  http://127.0.0.1:3000/api/v1");
    // ConnectInfo gives the middleware the peer socket address for the access log.
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

// Requires a logged-in user: resolve the session on demand, redirect anonymous visitors to the login
// page, then render the admin *for this caller* — non-admins get a read-only panel (no Create/Edit/
// Delete), while the API enforces the same rule. No middleware, no extractor.
async fn home(headers: HeaderMap, State(app): State<Arc<App>>) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    // Managers (members of the admin group) get the accounts section + user-id → reset links.
    let is_manager = app.auth.can_manage_others(&who);
    let body = match build_admin(&app.engine, is_manager).render_for(&headers).await {
        Ok(html) => html,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let page = Shell { title: "relativelylight".into(), user: who.username, body }
        .render()
        .unwrap_or_default();
    Html(page).into_response()
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

// The app styles the library's login form: drop it into our shell as a centered card. Anonymous, so
// the navbar shows no user link.
fn login_shell(form: &str) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto" style="max-width:24rem"><div class="card-body">
<h1 class="h5 mb-3">Log in</h1>{form}
<p class="text-muted small mt-2 mb-0">Demo: <code>admin</code> / <code>password</code></p>
</div></div>"#
    );
    Shell { title: "Log in".into(), user: String::new(), body }.render().unwrap_or_default()
}

// The app styles the library's profile/password page the same way. The library hands us the caller's
// identity, so the navbar shows their username (and Log out) just like the admin page.
fn profile_shell(fragment: &str, who: &Identity) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto" style="max-width:32rem"><div class="card-body">{fragment}
<a class="d-inline-block mt-3" href="/">&larr; Back to admin</a></div></div>"#
    );
    Shell { title: "Profile".into(), user: who.username.clone(), body }.render().unwrap_or_default()
}
