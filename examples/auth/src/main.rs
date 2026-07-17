//! examples/auth — the `auth` module used **without** `crud` (auth stands on its own). See
//! `docs/AUTH.md`. A public page, a `/secret` page gated by login, `/login` + `/logout`, and a
//! configurable admin group. Also demonstrates the `--set-admin-pw <pw>` startup path.
//!
//!   cargo run -p auth-example                            # serve; log in as admin / password
//!   cargo run -p auth-example -- --set-admin-pw s3cret   # (re)set admin pw + admin-group membership

use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use axum_extra::extract::CookieJar;
use relativelylight::auth::sso::{Sso, SsoButton, SsoProvider};
use relativelylight::auth::{self, Auth, Identity};
use sea_orm::Database;
use std::net::SocketAddr;

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

    // Optional SSO from env (no hard-coded secrets). Decide whether it's configured *before* building
    // `auth`, because the login page shows the SSO buttons — and `auth` must be fully configured
    // before it's cloned (`Sso::new` clones it; a builder call after that would panic).
    let google = std::env::var("SSO_GOOGLE_CLIENT_ID")
        .ok()
        .zip(std::env::var("SSO_GOOGLE_CLIENT_SECRET").ok());
    let sso_buttons = if google.is_some() {
        sso_buttons_html(&[SsoButton { label: "Google".into(), url: "/sso/google/login".into() }])
    } else {
        String::new()
    };

    let auth = Auth::new(db)
        .secure_cookies(false) // local http, so no `Secure` attribute
        .admin_group(ADMIN_GROUP)
        .totp_issuer("relativelylight auth demo") // shown in authenticator apps for 2FA
        .login_shell(move |form| bootstrap_login(form, &sso_buttons))
        .profile_shell(bootstrap_profile);

    // auth is now fully configured — safe to clone it into the Sso.
    let sso = google.map(|(id, secret)| build_sso(&auth, id, secret));

    // No middleware: `secret` resolves the session itself via `auth.identify`. The app router carries
    // the `Auth` handle as state so handlers can reach it; the login/logout routes bring their own.
    let mut app = Router::new()
        .route("/", get(public))
        .route("/secret", get(secret)) // gated on demand (see `secret`)
        .with_state(auth.clone())
        .merge(auth.routes()); // /login, /logout, /profile (password + 2FA), /login/totp
    if let Some(sso) = &sso {
        app = app.merge(sso.routes()); // /sso/{provider}/login + /callback
    }
    let app = app.layer(axum::middleware::from_fn(access_log));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("auth playground on http://127.0.0.1:3000/   (log in as admin / password)");
    if sso.is_some() {
        println!("SSO enabled: 'Sign in with Google' button on the login page");
    }
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

/// Build SSO config from env, so the demo needs no hard-coded secrets. Set `SSO_GOOGLE_CLIENT_ID` +
/// `SSO_GOOGLE_CLIENT_SECRET` (and optionally `SSO_BASE_URL`, default `http://127.0.0.1:3000`) to
/// enable a "Sign in with Google" button; unset → SSO disabled. The redirect URL registered with the
/// provider must be `{SSO_BASE_URL}/sso/google/callback`.
fn build_sso(auth: &Auth, client_id: String, client_secret: String) -> Sso {
    let base = std::env::var("SSO_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".into());
    Sso::new(auth)
        // Google carries no usable group claim → map local groups by username. Here: anyone whose
        // email ends in @example.com becomes "staff" (add your own rules / an admin regex).
        .username_group_rule(r"@example\.com$", ["staff"])
        .provider(
            SsoProvider::new(
                "google",
                "Google",
                "https://accounts.google.com",
                client_id,
                client_secret,
                format!("{base}/sso/google/callback"),
            )
            .username_claim("email") // Google's stable human identifier
            .auto_register(true), // create unknown users on first login (demo convenience)
        )
}

/// Render the SSO login buttons (appended under the password form).
fn sso_buttons_html(buttons: &[SsoButton]) -> String {
    if buttons.is_empty() {
        return String::new();
    }
    let mut s = String::from(r#"<hr class="my-3"><p class="text-muted small mb-2">Or sign in with:</p>"#);
    for b in buttons {
        s.push_str(&format!(
            r#"<a class="btn btn-outline-secondary w-100 mb-2" href="{}">{}</a>"#,
            b.url, b.label
        ));
    }
    s
}

/// Access log: one line per request — source IP, method, URI, and HTTP status.
async fn access_log(ConnectInfo(addr): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let res = next.run(req).await;
    println!("{} {} {} -> {}", addr.ip(), method, uri, res.status().as_u16());
    res
}

async fn public() -> Html<String> {
    Html(page(
        "Public page",
        r#"<p><a href="/secret">/secret</a> requires a login · <a href="/login">/login</a></p>"#,
    ))
}

// Requires an authenticated user: resolve the session on demand and redirect anonymous visitors to
// the login page. `CookieJar` lets us show the session cookie (a playground affordance — don't
// surface session tokens in real apps).
async fn secret(State(auth): State<Auth>, headers: HeaderMap, jar: CookieJar) -> Response {
    let Some(who) = auth.identify(&headers).await else {
        return Redirect::to(auth.login_path()).into_response();
    };
    let name = auth.session_cookie_name();
    let cookie = jar.get(name).map(|c| c.value().to_string()).unwrap_or_default();
    Html(page(
        "Protected page",
        &format!(
            r#"<p>Signed in as <b>{}</b> — groups: [{}].</p>
<p class="small text-muted mb-1">session cookie</p>
<pre class="bg-body-secondary p-2 rounded"><code>{name}={}</code></pre>
<a class="btn btn-primary btn-sm" href="/profile">Change password</a>
<a class="btn btn-outline-secondary btn-sm" href="/logout">Log out</a>"#,
            who.username,
            who.groups.join(", "),
            cookie,
        ),
    ))
    .into_response()
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

/// The app's shell for the library's profile/password page. The library hands us the caller's
/// identity so the page can greet them; we wrap the change-password form in our Bootstrap chrome.
fn bootstrap_profile(fragment: &str, who: &Identity) -> String {
    page(
        &format!("Profile — {}", who.username),
        &format!(
            r#"<div class="card shadow-sm"><div class="card-body">{fragment}</div></div>
<a class="d-inline-block mt-3" href="/secret">&larr; Back to /secret</a>"#
        ),
    )
}

/// The app's shell for the library's login form — this is where the app styles it (Bootstrap card).
/// `sso_buttons` is the optional SSO button block appended under the password form.
fn bootstrap_login(form: &str, sso_buttons: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Log in</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
<body class="bg-body-tertiary"><main class="container" style="max-width:24rem">
<div class="card shadow-sm mt-5"><div class="card-body">
<h1 class="h4 mb-3">Log in</h1>{form}{sso_buttons}</div></div>
<p class="text-center text-muted small mt-2">Demo: <code>admin</code> / <code>password</code></p>
</main></body></html>"#
    )
}
