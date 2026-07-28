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

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use axum_extra::extract::CookieJar;
use relativelylight::auth::lockout::{IpLockout, Lockout, UsernameLockout};
use relativelylight::middleware::RealIp;
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
        // Addresses that are never locked out — an office range, a monitoring probe. Empty here so the
        // demo can actually lock itself out from localhost; a real app builds it with
        // `relativelylight::net::parse_nets(&cfg.allow_list)` (v4/v6, bare hosts, CIDRs).
        ip_whitelist: Vec::new(),
    };
    let auth_db = db.clone(); // the app's own endpoint checks passwords itself
    let auth = Auth::new(db, lockout)
        .secure_cookies(false) // local http, so no `Secure` attribute
        .admin_group(ADMIN_GROUP)
        // Session clocks left at the library defaults: 7 days absolute, 8 hours idle. Changing your
        // password (or a manager resetting it) signs every other session out; "Sign out other sessions"
        // on /profile does it on demand. See `session_ttl_secs` / `session_idle_secs`.
        .totp_issuer("relativelylight auth demo") // shown in authenticator apps for 2FA
        // The CSRF refusal, in this app's own shell instead of the library's bare page. One closure
        // covers the library's forms *and* `csrf::enforce` on the routes above, because it travels on the
        // `auth.csrf()` handle. Same discipline as the default: no user named, no cookies set, still 403.
        .csrf_rejection(|| {
            (
                StatusCode::FORBIDDEN,
                Html(page(
                    "Security check failed",
                    r#"<div class="alert alert-danger">That form was stale, or the request didn't come
from this site. Reload the page and try again.</div>
<a class="btn btn-outline-secondary btn-sm" href="/">Start over</a>"#,
                )),
            )
                .into_response()
        })
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
    // The app's own **unsafe** routes, behind `csrf::enforce` — the layer form of the check, so the
    // handler doesn't call `Csrf::verify` itself. It takes the *same* `auth.csrf()` handle the library's
    // forms use, so one cookie serves both, and it accepts either the `X-CSRF-Token` header (a `fetch`
    // client) or the `_csrf` field of a form post. Kept in its own Router so the layer guards exactly
    // these routes: it refuses every unsafe request without a token, which is not what you want in front
    // of, say, `/api/whoami`.
    let guarded = Router::new()
        // An app-owned **sensitive** action: CSRF-checked by the layer, then identity-checked by
        // `Auth::reauthenticate` inside the handler (see `rotate_api_token`).
        .route("/api-token/rotate", post(rotate_api_token))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(auth.csrf(), relativelylight::csrf::enforce));

    let mut app = Router::new()
        .route("/", get(public))
        .route("/secret", get(secret)) // gated on demand (see `secret`)
        .route("/api/whoami", get(whoami)) // the app's own credential check (see `whoami`)
        .with_state(state)
        .merge(guarded)
        .merge(auth.routes()); // /login, /logout, /profile (password + 2FA), /login/totp
    if let Some(sso) = &sso {
        app = app.merge(sso.routes()); // /sso/{provider}/login + /callback
    }
    // The caller's address is resolved **once**, at the outermost layer, and read from there by the
    // access log, `auth`'s lockout, the audit events and this app's own `/api/whoami` — so all four name
    // the same client. This app used to resolve it in three places with two copies of the proxy flag; the
    // layer is what makes that impossible. Mandatory: `auth`'s login routes 500 without it.
    let app = app
        .layer(axum::middleware::from_fn(relativelylight::middleware::access_log))
        .layer(axum::middleware::from_fn_with_state(
            relativelylight::middleware::TrustProxy(trust_proxy_from_env()),
            relativelylight::middleware::resolve_real_ip,
        ));

    // Housekeeping is the **app's** job — the library schedules nothing. `Auth::prune` deletes dead
    // sessions (absolute *and* idle expiry — it knows this `Auth`'s configuration, which the free
    // `auth::prune(&db, &lockout)` can't) plus expired lockout rows; run it once at startup and then on
    // whatever loop the app already has. Skipping it is safe, just untidy: a dead session never
    // authenticates and an expired lockout row reads as unlocked.
    let prune_auth = auth.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            match prune_auth.prune().await {
                Ok(0) => {}
                Ok(n) => println!("pruned {n} dead session/lockout rows"),
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
    // This page renders a form that posts to a CSRF-guarded route, so it needs a token: `ensure` reuses
    // the request's if it has one and mints one otherwise, handing back the cookie to set in that case.
    let (csrf_token, csrf_cookie) = auth.csrf().ensure(&headers);
    let jar = match csrf_cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    let body = Html(page(
        "Protected page",
        &format!(
            r#"<p>Signed in as <b>{}</b> — groups: [{}].</p>
<p class="small text-muted mb-1">session cookie</p>
<pre class="bg-body-secondary p-2 rounded"><code>{name}={}</code></pre>
<a class="btn btn-primary btn-sm" href="/profile">Change password</a>
<a class="btn btn-outline-secondary btn-sm" href="/logout">Log out</a>
<hr class="my-4">
<h2 class="h6">An app-owned sensitive action</h2>
<p class="small text-muted">Rotating this account's API token is the kind of thing a live session alone
shouldn't be enough for — a stolen cookie <em>is</em> a live session. So the app asks the caller to prove
they are present, with <code>Auth::reauthenticate</code>: the same factors the library's own sensitive
pages take (your password, or a fresh 2FA code), and the same single-use rule for codes.</p>
<form method="post" action="/api-token/rotate">
  {csrf_input}
  <div class="mb-2" style="max-width:22rem">
    <label class="form-label small" for="rot-pw">Your current password</label>
    <input class="form-control form-control-sm" id="rot-pw" name="current_password" type="password"
           autocomplete="current-password">
  </div>
  <div class="mb-2" style="max-width:22rem">
    <label class="form-label small" for="rot-code">…or a code from your authenticator app</label>
    <input class="form-control form-control-sm" id="rot-code" name="totp_code" inputmode="numeric"
           autocomplete="one-time-code" placeholder="123456">
  </div>
  <button class="btn btn-outline-danger btn-sm" type="submit">Rotate API token</button>
</form>"#,
            who.username,
            who.groups.join(", "),
            cookie,
            csrf_input = relativelylight::csrf::Csrf::hidden_input(&csrf_token),
        ),
    ));
    (jar, body).into_response()
}

/// What an app's own sensitive route submits: the caller's re-authentication. (A real one would carry a
/// CSRF token too — `auth.csrf()` — which the library's own forms demonstrate.)
#[derive(serde::Deserialize)]
struct RotateForm {
    #[serde(default)]
    current_password: String,
    #[serde(default)]
    totp_code: String,
}

/// `POST /api-token/rotate` — **the showcase for re-authentication before a sensitive change.**
///
/// The pattern to copy, in order:
/// 1. resolve the caller (`identify`); anonymous goes to the login page;
/// 2. **`reauthenticate`**, and return its error *before anything happens*, so a refusal is a no-op;
/// 3. only then do the destructive thing.
///
/// Why bother when the caller already has a session? Because a session proves someone logged in once,
/// not that the account's owner is the one asking now. The idle timeout bounds how long a stolen cookie
/// lives; this bounds what it can *do* while it lives. An account with no local factor (an SSO login)
/// passes step 2 — there is nothing to ask it for — which `Auth::can_reauthenticate` reports if you want
/// to say so in your own UI.
async fn rotate_api_token(
    State(app): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RotateForm>,
) -> Response {
    let auth = &app.auth;
    let Some(who) = auth.identify(&headers).await else {
        return Redirect::to(auth.login_path()).into_response();
    };
    if let Err(msg) = auth.reauthenticate(&who, &form.current_password, &form.totp_code).await {
        // 403, and nothing has changed — the old token is still the token.
        return (
            StatusCode::FORBIDDEN,
            Html(page(
                "Confirm it's you",
                &format!(
                    r#"<div class="alert alert-danger">{msg}</div>
<p class="small text-muted">Nothing was changed.</p>
<a class="btn btn-outline-secondary btn-sm" href="/secret">Back</a>"#
                ),
            )),
        )
            .into_response();
    }
    // Re-authenticated. A real app would mint and store a token here; this one only says it would, since
    // the point of the example is the check above.
    Html(page(
        "API token rotated",
        &format!(
            r#"<div class="alert alert-success">Confirmed — a new API token would now be issued for
<b>{}</b>, and the old one revoked.</div>
<a class="btn btn-outline-secondary btn-sm" href="/secret">Back</a>"#,
            who.username
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
    RealIp(ip): RealIp,
    headers: HeaderMap,
) -> Response {
    // A request with no credential at all is a plain 401 — never counted, or an anonymous scanner
    // could lock out everyone who shares its address.
    let Some((username, password)) = basic_auth(&headers) else {
        return unauthorized("send HTTP Basic credentials");
    };
    // No resolution to do and no proxy flag to remember: `RealIp` is the address the middleware already
    // worked out, which is by construction the one `/login` counted against. That's the point of it.
    if let Some(retry) = locked(&app, &username, Some(ip)).await {
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
        let by_ip = app.ips.record_failure(Some(ip)).await;
        if by_user || by_ip {
            println!("locked out: {username} / {ip} (too many failed checks)");
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
