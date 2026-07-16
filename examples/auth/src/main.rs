//! examples/auth — the `auth` module used **without** `crud` (auth stands on its own). See
//! `docs/AUTH.md`. A public page, a `/secret` page gated by login, `/login` + `/logout`, and a
//! configurable admin group. Also demonstrates the `--set-admin-pw <pw>` startup path.
//!
//!   cargo run -p auth-example                            # serve; log in as admin / password
//!   cargo run -p auth-example -- --set-admin-pw s3cret   # (re)set admin pw + admin-group membership

use axum::response::Html;
use axum::routing::get;
use axum::Router;
use relativelylight::auth::{self, Auth, CurrentUser};
use sea_orm::Database;

// The superadmin group name is the app's choice — a constant here, but it could come from config.
const ADMIN_GROUP: &str = "superadmin";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::connect("sqlite::memory:").await?;
    auth::migrate(&db).await?;

    // How an app wires a `--set-admin-pw` CLI flag: (re)create the admin user + admin group and set
    // the password, then exit. (This example's DB is in-memory, so it's a call-site demo; a real app
    // would point at a persistent database.)
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--set-admin-pw") {
        let pw = args.get(i + 1).map(String::as_str).unwrap_or("");
        auth::make_admin(&db, ADMIN_GROUP, "admin", pw).await?;
        println!("admin password set and added to '{ADMIN_GROUP}'");
        return Ok(());
    }

    // Otherwise seed a demo admin (in the admin group) and serve.
    auth::make_admin(&db, ADMIN_GROUP, "admin", "password").await?;
    let auth = Auth::new(db).secure_cookies(false).admin_group(ADMIN_GROUP);

    let app = Router::new()
        .route("/", get(public))
        .route("/secret", get(secret)) // gated by the CurrentUser extractor
        .merge(auth.routes()); // /login, /logout
    let app = auth.wrap(app); // resolve the session cookie → Principal for every request

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001").await?;
    println!("auth playground on http://127.0.0.1:3001/   (log in as admin / password)");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn public() -> Html<&'static str> {
    Html(
        r#"<!doctype html><meta charset="utf-8"><title>relativelylight auth playground</title>
<h1>Public page</h1>
<p><a href="/secret">/secret</a> requires a login · <a href="/login">/login</a></p>"#,
    )
}

// Requires an authenticated user; `CurrentUser` redirects to /login when anonymous.
async fn secret(CurrentUser(user): CurrentUser) -> Html<String> {
    Html(format!(
        r#"<!doctype html><meta charset="utf-8"><title>Protected</title>
<h1>Protected page</h1><p>Signed in as <b>{}</b> — groups: [{}]. <a href="/logout">Log out</a></p>"#,
        user.username,
        user.groups.join(", "),
    ))
}
