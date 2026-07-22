//! time example — the smallest possible demo of relativelylight's timezone handling.
//!
//! One table (`post`, which has a `published_at` timestamp) served with the CRUD API + UI, plus the
//! `relativelylight::time` frontend (RLTime + the `$store.tz` picker). It also shows the two optional
//! backend integrations from `docs/TIME.md`:
//!
//!   GET  /api/settings/timezone   → the **server's** timezone (policy (e): adopt on load)
//!   GET  /api/me/timezone         → a (randomly assigned) **stored user** preference (policy (d))
//!   PUT  /api/me/timezone         → the UI posts the user's pick here; we log it to the console
//!
//! The DB/API stay integer-UTC throughout — only display changes. Storage is a fresh in-memory DB.
//!
//! Try:  open http://127.0.0.1:3001/  (watch the server console as you change the picker)

use askama::Template;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use relativelylight::authz::Open;
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::Table;
use relativelylight::time::{TzPicker, JS as TIME_JS};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Template)]
#[template(path = "shell.html")]
struct Shell {
    table: String,
    server_tz: String,
    time_js: &'static str,
    tz_picker: String,
}

struct App {
    page: String,
    // Round-robin over a few zones so GET /api/me/timezone returns a different "stored preference"
    // each load — standing in for a per-user column you'd read from your own model.
    next_user_tz: AtomicUsize,
}

const USER_TZS: &[&str] =
    &["America/New_York", "Asia/Tokyo", "Europe/Prague", "Pacific/Auckland", "America/Sao_Paulo"];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = model::setup().await?;

    // One editable datetime column (Unix seconds, UTC) → a timezone-aware picker in the form.
    let mut post_mm = MetaModel::new(model::post::Entity);
    post_mm.field("title").label = Some("Title".into());
    post_mm.field("published_at").label = Some("Published at".into());
    post_mm.field("published_at").description =
        Some("Editable timestamp — shown and edited in the selected zone; stored as UTC.".into());
    post_mm.field("published_at").datetime();
    // Hide the noise so the table focuses on the timestamp.
    post_mm.field("body").hidden = true;
    post_mm.relation("author").hidden = true;

    let mut crud = Crud::new(db, "/api/v1");
    crud.register(post_mm, Open);

    let engine = crud.engine();
    let table = Table::new(engine, "post").title("Posts").per_page(8).render()?;

    let page = Shell {
        table,
        server_tz: server_timezone(),
        time_js: TIME_JS,
        tz_picker: TzPicker::new().render(),
    }
    .render()?;

    let app = Arc::new(App { page, next_user_tz: AtomicUsize::new(0) });

    let ui = Router::new()
        .route("/", get(home))
        .route("/api/settings/timezone", get(server_tz_endpoint))
        .route("/api/me/timezone", get(get_user_tz).put(set_user_tz))
        .with_state(app);

    let app_router = ui.merge(crud.into_router()).layer(axum::middleware::from_fn(access_log));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001").await?;
    println!("time example on  http://127.0.0.1:3001/   (change the picker → watch this console)");
    axum::serve(listener, app_router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

async fn home(State(app): State<Arc<App>>) -> impl IntoResponse {
    Html(app.page.clone())
}

/// Policy (e): report the host's timezone so the UI can adopt it (matching server/syslog times).
async fn server_tz_endpoint() -> impl IntoResponse {
    Json(json!({ "zone": server_timezone() }))
}

/// Policy (d): a stored per-user preference. Here we just rotate through a list to simulate different
/// users; a real app would read a column off its own user/profile model.
async fn get_user_tz(State(app): State<Arc<App>>) -> impl IntoResponse {
    let i = app.next_user_tz.fetch_add(1, Ordering::Relaxed) % USER_TZS.len();
    Json(json!({ "mode": "zone", "zone": USER_TZS[i] }))
}

/// The UI calls this (via RL_TZ.onChange) whenever the user changes the picker. A real app would
/// persist it; we just log it, to make the round-trip visible.
async fn set_user_tz(Json(body): Json<Value>) -> impl IntoResponse {
    println!("[time-example] UI set user timezone → {body}");
    StatusCode::NO_CONTENT
}

/// Best-effort host timezone: `$TZ`, else the `/etc/localtime` symlink target, else UTC.
fn server_timezone() -> String {
    if let Ok(tz) = std::env::var("TZ") {
        if !tz.is_empty() {
            return tz;
        }
    }
    if let Ok(target) = std::fs::read_link("/etc/localtime") {
        let s = target.to_string_lossy();
        if let Some((_, zone)) = s.split_once("zoneinfo/") {
            return zone.to_string();
        }
    }
    "UTC".into()
}

async fn access_log(ConnectInfo(addr): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Response {
    let (method, uri) = (req.method().clone(), req.uri().clone());
    let res = next.run(req).await;
    println!("{} {} {} -> {}", addr.ip(), method, uri, res.status().as_u16());
    res
}
