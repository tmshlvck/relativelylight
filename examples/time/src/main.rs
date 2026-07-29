//! time example — the smallest possible demo of relativelylight's timezone handling.
//!
//! One table of its own — an `event` with a name and one `happens_at` timestamp — served with the CRUD
//! API + UI, plus the `relativelylight::time` frontend (RLTime + the `$store.tz` picker). It also shows
//! the two optional backend integrations from `docs/TIME.md`:
//!
//!   GET  /api/settings/timezone   → the **server's** timezone (policy (e): adopt on load)
//!   GET  /api/me/timezone         → a (randomly assigned) **stored user** preference (policy (d))
//!   PUT  /api/me/timezone         → the UI posts the user's pick here; we log it to the console
//!
//! The DB/API stay integer-UTC throughout — only display changes. Storage is a fresh in-memory DB.
//!
//! The seeded rows **straddle a DST transition on purpose**: pick `Europe/Prague` (or any zone that
//! observes DST) and the January rows show `GMT+1` while the June ones show `GMT+2`, from the same
//! integer column. That difference is the whole point of the module.
//!
//! Try:  open http://127.0.0.1:3000/  (watch the server console as you change the picker)

mod event;

use askama::Template;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use relativelylight::authz::Open;
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::{Form, Table};
use relativelylight::time::{TzPicker, JS as TIME_JS};
use sea_orm::{
    ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbErr, Schema,
    Set,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Template)]
#[template(path = "shell.html")]
struct Shell {
    table: String,
    form: String,
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
    let db = setup().await?;

    // One editable datetime column (Unix seconds, UTC) → a timezone-aware picker in the form.
    let mut event_mm = MetaModel::new(event::Entity);
    event_mm.field("name").label = Some("Event".into());
    event_mm.field("happens_at").label = Some("Happens at".into());
    event_mm.field("happens_at").description =
        Some("Editable timestamp — shown and edited in the selected zone; stored as UTC.".into());
    event_mm.field("happens_at").datetime();

    let mut crud = Crud::new(db, "/api/v1");
    crud.register(event_mm, Open);

    let engine = crud.engine();
    let table = Table::new(engine, "event").title("Events").per_page(8).render()?;
    // The same datetime widget in a standalone `Form` (crud::ui::Form) — one component, two hosts, and
    // the picker follows the page's zone selection in both.
    let form = Form::new(engine, "event")
        .title("Add an event")
        .description("Type a local time in the selected zone; it's stored as integer UTC seconds.")
        .submit_label("Add")
        .saved_message("Added. Refresh the table (↻) to see it.")
        .render()?;

    let page = Shell {
        table,
        form,
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

    let app_router = ui.merge(crud.into_router()).layer(axum::middleware::from_fn(relativelylight::middleware::access_log))
        // One resolution of the caller's address for the whole app (see relativelylight::middleware).
        .layer(axum::middleware::from_fn_with_state(
            relativelylight::middleware::TrustProxy(false),
            relativelylight::middleware::resolve_real_ip,
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("time example on  http://127.0.0.1:3000/   (change the picker → watch this console)");
    axum::serve(listener, app_router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

/// An in-memory SQLite DB with the `event` table and a few rows **either side of a DST transition**, so
/// the zone picker has something to show: in `Europe/Prague` the January rows read `GMT+1` and the June
/// ones `GMT+2`, from the same stored integers.
///
/// The pool is pinned to one permanent connection deliberately: an in-memory database lives *inside* its
/// connection, and a pool recycles connections (SeaORM defaults to a 30-minute `max_lifetime`), which
/// would take the tables with it — an example that worked, then answered `no such table: event` half an
/// hour later. A second connection would see its own empty database, so one it is. A real app pointing at
/// a file or a server needs none of this.
async fn setup() -> Result<DatabaseConnection, DbErr> {
    const FOREVER: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);
    let mut opt = ConnectOptions::new("sqlite::memory:".to_owned());
    opt.max_connections(1).min_connections(1).idle_timeout(FOREVER).max_lifetime(FOREVER);
    let db = Database::connect(opt).await?;

    let backend = db.get_database_backend();
    let stmt = Schema::new(backend).create_table_from_entity(event::Entity);
    db.execute(backend.build(&stmt)).await?;

    // (name, Unix seconds UTC) → what a `Europe/Prague` viewer sees. The EU switches on the last Sunday
    // of March and October at 01:00 UTC, which in 2026 is the 29th and the 25th.
    let rows: &[(&str, Option<i64>)] = &[
        ("New Year's fireworks", Some(1767268800)), // 2026-01-01 12:00 UTC → 13:00 GMT+1
        ("Winter standup", Some(1768212000)),       // 2026-01-12 10:00 UTC → 11:00 GMT+1
        ("Spring forward (01:00Z)", Some(1774746000)), // 2026-03-29 01:00 UTC → 03:00 GMT+2 (02:00 skipped)
        ("Midsummer picnic", Some(1780315200)),     // 2026-06-01 12:00 UTC → 14:00 GMT+2
        ("Summer release", Some(1783238400)),       // 2026-07-05 08:00 UTC → 10:00 GMT+2
        ("Fall back (01:00Z)", Some(1792890000)),   // 2026-10-25 01:00 UTC → 02:00 GMT+1 (02:00 repeats)
        ("Someday (no date yet)", None),            // a nullable timestamp, cleared
    ];
    for (i, (name, happens_at)) in rows.iter().enumerate() {
        event::ActiveModel {
            id: Set(i as i32 + 1),
            name: Set((*name).into()),
            happens_at: Set(*happens_at),
        }
        .insert(&db)
        .await?;
    }
    Ok(db)
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
