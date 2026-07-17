//! examples/auth — the `auth` module used **without** `crud` (auth stands on its own). See
//! `docs/AUTH.md`. A public page, a `/secret` page gated by login, `/login` + `/logout`, and a
//! configurable admin group. Also demonstrates the `--set-admin-pw <pw>` startup path.
//!
//!   cargo run -p auth-example                            # serve; log in as admin / password
//!   cargo run -p auth-example -- --set-admin-pw s3cret   # (re)set admin pw + admin-group membership

use axum::response::Html;
use axum::routing::get;
use axum::Router;
use axum_extra::extract::CookieJar;
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
    let auth = Auth::new(db)
        .secure_cookies(false) // local http, so no `Secure` attribute
        .admin_group(ADMIN_GROUP)
        // The library renders the login *form*; the app styles it. Here: a Bootstrap page.
        .login_shell(bootstrap_login);

    let app = Router::new()
        .route("/", get(public))
        .route("/secret", get(secret)) // gated by the CurrentUser extractor
        .merge(auth.routes()); // /login, /logout
    let app = auth.wrap(app); // resolve the session cookie → Principal for every request

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("auth playground on http://127.0.0.1:3000/   (log in as admin / password)");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn public() -> Html<String> {
    Html(page(
        "Public page",
        r#"<p><a href="/secret">/secret</a> requires a login · <a href="/login">/login</a></p>"#,
    ))
}

// Requires an authenticated user; `CurrentUser` redirects to /login when anonymous. `CookieJar` lets
// us show the session cookie (a playground affordance — don't surface session tokens in real apps).
async fn secret(CurrentUser(user): CurrentUser, jar: CookieJar) -> Html<String> {
    let cookie = jar.get("rl_session").map(|c| c.value().to_string()).unwrap_or_default();
    Html(page(
        "Protected page",
        &format!(
            r#"<p>Signed in as <b>{}</b> — groups: [{}].</p>
<p class="small text-muted mb-1">session cookie</p>
<pre class="bg-body-secondary p-2 rounded"><code>rl_session={}</code></pre>
<a class="btn btn-outline-secondary btn-sm" href="/logout">Log out</a>"#,
            user.username,
            user.groups.join(", "),
            cookie,
        ),
    ))
}

/// Bootstrap page wrapper for the app's own pages.
fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
<body class="bg-body-tertiary"><main class="container py-4" style="max-width:40rem">
<h1 class="h4 mb-3">{title}</h1>{body}</main></body></html>"#
    )
}

/// The app's shell for the library's login form — this is where the app styles it (Bootstrap card).
fn bootstrap_login(form: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Log in</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
<body class="bg-body-tertiary"><main class="container" style="max-width:24rem">
<div class="card shadow-sm mt-5"><div class="card-body">
<h1 class="h4 mb-3">Log in</h1>{form}</div></div>
<p class="text-center text-muted small mt-2">Demo: <code>admin</code> / <code>password</code></p>
</main></body></html>"#
    )
}
