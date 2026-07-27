//! examples/auth — the `auth` module used **without** `crud` (auth stands on its own). See
//! `docs/AUTH.md`. A public page, a `/secret` page gated by login, `/login` + `/logout`, and a
//! configurable admin group. Also demonstrates the `--set-admin-pw <pw>` break-glass startup path and
//! an **app-owned credential check** (`/api/whoami`, HTTP Basic) braked with the *same* attempt
//! counters as the login form via [`Auth::attempts`] — see `brute-force brake` below.
//!
//!   cargo run -p auth-example                            # serve; log in as admin / password
//!   TRUST_PROXY=1 cargo run -p auth-example               # …behind a proxy: believe X-Forwarded-For
//!   cargo run -p auth-example -- --set-admin-pw s3cret   # break-glass: pw + enable + clear 2FA + group
//!   curl -u admin:password    127.0.0.1:3000/api/whoami  # the app's own credential check
//!   curl -u admin:nope -i     127.0.0.1:3000/api/whoami  # 5 of these → 429, and /login locks too
//!
//! It also shows the two housekeeping duties the library leaves to the app: it schedules
//! `auth::prune` (expired sessions + expired lockout rows), and a real app would register the two
//! lockout entities in its admin panel so an operator can see who is locked out and clear a row.

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use axum_extra::extract::CookieJar;
use relativelylight::auth::lockout::{IpLockout, Lockout, UsernameLockout};
use relativelylight::net::client_ip;
use relativelylight::auth::sso::{Sso, SsoButton, SsoProvider};
use relativelylight::auth::{self, Auth, Identity};
use sea_orm::{ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter};
use std::net::{IpAddr, SocketAddr};

// The superadmin group name is the app's choice — a constant here, but it could come from config.
// **Use the one name everywhere**: the gate / `admin_group`, the boot-time seeder, and break-glass
// recovery. If those three ever disagree, an "admin" is created outside the group the gate checks.
const ADMIN_GROUP: &str = "superadmin";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::connect("sqlite::memory:").await?;
    auth::migrate(&db).await?;

    // How an app wires a `--set-admin-pw` CLI flag: **break-glass** admin recovery — create-or-reset
    // the password, re-activate the account, clear its TOTP 2FA, ensure admin-group membership, exit.
    // Operator-run only (it discards an enrolled authenticator); the boot-time seeder below is
    // `make_admin`. (This example's DB is in-memory, so it's a call-site demo; a real app would point
    // at a persistent database.)
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--set-admin-pw") {
        let pw = args.get(i + 1).map(String::as_str).unwrap_or("");
        auth::reset_admin_access(&db, ADMIN_GROUP, "admin", pw).await?;
        println!("admin password set, account enabled, 2FA cleared, added to '{ADMIN_GROUP}'");
        return Ok(());
    }

    // Otherwise seed a demo admin (in the admin group) and serve. `make_admin` is idempotent and
    // leaves an existing account's `is_active` / 2FA alone, so it's safe on every start.
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

    // The brute-force brake is mandatory — `Auth::new` takes its configuration. Here: 5 failed logins
    // per account and 15 per source address, both for 5 minutes (the library defaults are 10 / 100 per
    // 15 min).
    let lockout = Lockout {
        username_after: 5,
        username_duration_secs: 300,
        ip_after: 15,
        ip_duration_secs: 300,
        // Who the client is, for the per-address half: the socket peer normally, the forwarded hop when
        // this example runs behind a proxy (`TRUST_PROXY=1`). The library resolves it either way.
        trust_proxy: trust_proxy_from_env(),
        // Addresses that are never locked out — an office range, a monitoring probe. Empty here so the
        // demo can actually lock itself out from localhost; a real app builds it with
        // `relativelylight::net::parse_nets(&cfg.allow_list)` (v4/v6, bare hosts, CIDRs).
        ip_allow: Vec::new(),
    };
    let auth_db = db.clone(); // the app's own endpoint checks passwords itself
    let db_for_prune = db.clone();
    let auth = Auth::new(db, lockout.clone())
        .secure_cookies(false) // local http, so no `Secure` attribute
        .admin_group(ADMIN_GROUP)
        .totp_issuer("relativelylight auth demo") // shown in authenticator apps for 2FA
        .login_shell(move |form| bootstrap_login(form, &sso_buttons))
        .profile_shell(bootstrap_profile);

    // auth is now fully configured — safe to clone it into the Sso.
    let sso = google.map(|(id, secret)| build_sso(&auth, id, secret));

    // No middleware: `secret` resolves the session itself via `auth.identify`. The app router carries
    // its own state (the `Auth` handle, the DB, and the shared attempt counters) so handlers can reach
    // them; the login/logout routes bring their own.
    let state = AppState {
        auth: auth.clone(),
        db: auth_db,
        // The *same* counters the login form uses, so one account has one budget across both.
        usernames: auth.username_lockout(),
        ips: auth.ip_lockout(),
    };
    let mut app = Router::new()
        .route("/", get(public))
        .route("/secret", get(secret)) // gated on demand (see `secret`)
        .route("/api/whoami", get(whoami)) // the app's own credential check (see `whoami`)
        .with_state(state)
        .merge(auth.routes()); // /login, /logout, /profile (password + 2FA), /login/totp
    if let Some(sso) = &sso {
        app = app.merge(sso.routes()); // /sso/{provider}/login + /callback
    }
    let app = app.layer(axum::middleware::from_fn(access_log));

    // Housekeeping is the **app's** job — the library schedules nothing. `auth::prune` deletes expired
    // sessions and expired lockout rows (both counters); run it once at startup and then on whatever
    // loop the app already has. Skipping it is safe, just untidy: an expired session never
    // authenticates and an expired lockout row reads as unlocked.
    let prune_db = db_for_prune.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            match auth::prune(&prune_db, &lockout).await {
                Ok(0) => {}
                Ok(n) => println!("pruned {n} expired session/lockout rows"),
                Err(e) => eprintln!("prune failed: {e}"),
            }
        }
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("auth playground on http://127.0.0.1:3000/   (log in as admin / password)");
    if sso.is_some() {
        println!("SSO enabled: 'Sign in with Google' button on the login page");
    }
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

/// `TRUST_PROXY=1` (or `true`) tells the lockout to believe `X-Forwarded-For` — set it when you put a
/// reverse proxy in front of this example, and leave it unset when it listens on the port itself. It is
/// a security boundary, not a convenience: unproxied, the header is attacker-supplied.
fn trust_proxy_from_env() -> bool {
    matches!(std::env::var("TRUST_PROXY").as_deref(), Ok("1") | Ok("true"))
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
        r#"<p><a href="/secret">/secret</a> requires a login · <a href="/login">/login</a></p>
<p class="small text-muted"><code>GET /api/whoami</code> takes HTTP Basic — the app checks it itself,
braked with the same attempt counters as the login form.</p>"#,
    ))
}

// Requires an authenticated user: resolve the session on demand and redirect anonymous visitors to
// the login page. `CookieJar` lets us show the session cookie (a playground affordance — don't
// surface session tokens in real apps).
async fn secret(State(app): State<AppState>, headers: HeaderMap, jar: CookieJar) -> Response {
    let auth = &app.auth;
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

/// What the app's own routes need: the `Auth` handle, a DB connection, and the shared attempt
/// counters. `Attempts` is cheap to clone, so it lives in the state like any other handle.
#[derive(Clone)]
struct AppState {
    auth: Auth,
    db: DatabaseConnection,
    usernames: UsernameLockout,
    ips: IpLockout,
}

/// `GET /api/whoami` — an **app-owned** credential check (HTTP Basic against the same user table),
/// standing in for the API-token endpoint a real app would have. `auth` never sees this request, so
/// braking it is the app's job — and it must use the library's counters, not its own, so that:
///
/// - one account has **one** budget: burning it here locks `/login` too, and vice versa;
/// - `Auth::clear_login_attempts` (the operator unlock) frees every surface at once.
///
/// The shape to copy: check `locked` *before* the secret, record only a credential you actually
/// checked and rejected, clear the account on success.
async fn whoami(
    State(app): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    // A request with no credential at all is a plain 401 — never counted, or an anonymous scanner
    // could lock out everyone who shares its address.
    let Some((username, password)) = basic_auth(&headers) else {
        return unauthorized("send HTTP Basic credentials");
    };
    // The *same* resolution the login route uses, so a client that fails here and fails there lands on
    // one row: `relativelylight::net::client_ip` with this app's proxy flag.
    let ip: Option<IpAddr> = client_ip(trust_proxy_from_env(), &headers, Some(peer.ip()));

    if let Some(retry) = locked(&app, &username, ip).await {
        // Refused without looking at the password: no argon2 work, and no hint about the account.
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, retry.to_string())],
            format!("too many failed attempts — retry in {retry}s\n"),
        )
            .into_response();
    }

    let user = auth::user::Entity::find()
        .filter(auth::user::Column::Username.eq(&username))
        .one(&app.db)
        .await
        .ok()
        .flatten()
        // An SSO account's password isn't ours to check, and a 2FA account's password isn't the whole
        // credential — a machine endpoint should hand those users an API token instead.
        .filter(|u| u.is_active && !u.is_sso() && !u.has_totp());
    let ok = user.as_ref().is_some_and(|u| auth::verify_password(&u.password_hash, &password));
    if !ok {
        let by_user = app.usernames.record_failure(&username).await;
        let by_ip = app.ips.record_failure(ip).await;
        if by_user || by_ip {
            println!("locked out: {username} / {} (too many failed checks)", peer.ip());
        }
        return unauthorized("bad credentials");
    }
    app.usernames.clear(&username).await; // a good credential forgets the account's failures
    format!("ok: {username}\n").into_response()
}

/// The longer of the account's and the address's remaining lockout, if either is locked.
async fn locked(app: &AppState, username: &str, ip: Option<IpAddr>) -> Option<i64> {
    let (by_user, by_ip) = (app.usernames.locked(username).await, app.ips.locked(ip).await);
    match (by_user, by_ip) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// The username + password from an `Authorization: Basic` header, if it carries one.
fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    use base64::Engine;
    let raw = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(raw.strip_prefix("Basic ")?).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (u, p) = text.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

fn unauthorized(why: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(axum::http::header::WWW_AUTHENTICATE, "Basic realm=\"api\"")],
        format!("{why}\n"),
    )
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
