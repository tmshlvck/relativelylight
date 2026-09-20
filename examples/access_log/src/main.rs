//! examples/access_log — **the app writes its own request log.**
//!
//! relativelylight ships no `access_log` middleware, on purpose. It writes nothing to stdout or stderr
//! anywhere in the crate: it resolves *who is calling* once, at the edge
//! ([`resolve_real_ip`](relativelylight::middleware::resolve_real_ip) →
//! [`RealIp`](relativelylight::middleware::RealIp)), and what you do with that is yours. A request log
//! is a dozen lines, and the dozen differ per app — a structured `tracing` event or a line on stderr;
//! the query string or just the path; a level you can turn down on a chatty endpoint. Shipping one
//! shape would have meant a logging dependency in the library and an opinion about all of it.
//!
//! So here are the dozen lines, in the two shapes that actually come up:
//!
//! | Variant | Names the user on | Costs |
//! |---|---|---|
//! | [`access_log`] (default) | routes that opt in by returning an [`Actor`] | nothing |
//! | [`access_log_identify`] (`NAME_EVERY_REQUEST=1`) | every request with a session cookie | one `Auth::identify` per request |
//!
//! Both read the same `RealIp`, so their address always matches the one `auth`'s lockout counted and
//! the audit hook recorded. Neither is more correct than the other — pick by whether naming an
//! *anonymous* request's route matters more than a session lookup on every hit.
//!
//! ```text
//! cargo run -p access-log-example                            # serve on :3000, log in as admin / password
//! NAME_EVERY_REQUEST=1 cargo run -p access-log-example       # …name the user on every route
//! TRUST_PROXY=1 cargo run -p access-log-example              # …behind a proxy: believe X-Forwarded-For
//! ```
//!
//! Log in and watch. The lesson is the **third column**, and which lines have something in it:
//!
//! ```text
//! 127.0.0.1       -      GET  /            200 0ms      before logging in: nobody to name
//! 127.0.0.1       -      POST /login       303 431ms    the library's route  ─┐
//! 127.0.0.1       admin  GET  /            200 1ms      ours: it knows you    │ under variant 1,
//! 127.0.0.1       admin  GET  /private     200 1ms      ours: it knows you    │ only our own
//! 127.0.0.1       -      GET  /profile     200 2ms      the library's route  ─┘ handlers can say
//! ```
//!
//! A route of **ours** names the caller because its handler had to resolve one anyway, and hands
//! that name to the log on the way out — no second lookup. A route of the **library's** (`/login`,
//! `/profile`, `/logout`) prints `-`, because there is no handler of ours in it to volunteer
//! anything. If you want those named too, that is what `NAME_EVERY_REQUEST=1` buys, and what it
//! costs is one session lookup on every request in the process — including the ones that never
//! needed an identity.

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use relativelylight::auth::lockout::Lockout;
use relativelylight::auth::{self, Auth};
use relativelylight::middleware::{resolve_real_ip, RealIp, TrustProxy};
use sea_orm::{ConnectOptions, Database};
use std::time::Duration;

/// The username to print for a request, put in the **response** extensions by a handler that has
/// already resolved one. That's the trick that makes the cheap variant work: the log line is written
/// *after* `next.run(req)`, so anything the handler learned on the way through is available by then.
///
/// It is a *response* extension rather than a request one because the handler is where identity
/// becomes known — a bearer token isn't verified until the handler checks it, which is precisely why
/// a library-level layer could never do this for you.
#[derive(Clone)]
struct Actor(String);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // An in-memory SQLite database lives inside its connection, and a pool recycles connections — so pin
    // it to one connection that never retires, or the tables vanish after 30 minutes (see the CHANGELOG).
    const FOREVER: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);
    let mut opt = ConnectOptions::new("sqlite::memory:".to_owned());
    opt.max_connections(1).min_connections(1).idle_timeout(FOREVER).max_lifetime(FOREVER);
    let db = Database::connect(opt).await?;
    auth::migrate(&db).await?;
    auth::make_admin(&db, "admin", "admin", "password").await?;

    let auth = Auth::new(db, Lockout::default()).secure_cookies(false).admin_group("admin");

    let state = AppState { auth: auth.clone() };
    let app = Router::new()
        .route("/", get(public))
        .route("/private", get(private))
        .with_state(state.clone())
        .merge(auth.routes()); // /login, /logout, /profile

    // The layer order that matters. `Router::layer` **wraps**, so the layer added *last* is outermost
    // and runs *first* — which means the request log has to be added **before** `resolve_real_ip` in
    // order to run **inside** it and see the address. Get this backwards and every line reads `-`.
    let name_everyone = std::env::var("NAME_EVERY_REQUEST").is_ok_and(|v| v == "1");
    let app = if name_everyone {
        app.layer(axum::middleware::from_fn_with_state(state, access_log_identify))
    } else {
        app.layer(axum::middleware::from_fn(access_log))
    };
    let trust_proxy = std::env::var("TRUST_PROXY").is_ok_and(|v| v == "1");
    let app = app.layer(axum::middleware::from_fn_with_state(
        TrustProxy(trust_proxy),
        resolve_real_ip, // OUTERMOST — mandatory; `auth`'s login routes 500 without it
    ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("access-log demo on http://127.0.0.1:3000/   (log in as admin / password)");
    println!(
        "naming: {}",
        if name_everyone {
            "every request with a session — one Auth::identify per request, including /login and /profile"
        } else {
            "this app's own routes (/ and /private), which name themselves for free; the library's \
             routes (/login, /profile, /logout) log `-` — set NAME_EVERY_REQUEST=1 to name those too"
        }
    );
    println!("{:<15} {:<6} {:<4} {:<12} status ms", "address", "user", "verb", "path");
    // `into_make_service_with_connect_info` is what gives `resolve_real_ip` a socket peer to fall back
    // on. Without it, a request carrying no usable forwarded header is refused with a 500 that says so.
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
    Ok(())
}

// ─────────────────────────── the log line: variant 1, free ───────────────────────────

/// One line per request: address, user, method, target, status, latency.
///
/// This is the whole of it — copy it, then change what you print. Things worth changing that the
/// library could not have chosen for you:
///
/// - **`println!` → `tracing::info!`** with these as fields, if the app has a subscriber (most do).
///   That buys structured output in journald and, more importantly, a **level**: a high-volume
///   endpoint you can turn down is the main thing a hardcoded `eprintln!` can't give you.
/// - **`uri().path()` → `path_and_query()`** where the query *is* the request. A DDNS or webhook
///   endpoint logged without its query says almost nothing.
/// - **The User-Agent**, when you care which client is misbehaving.
///
/// `RealIp` is taken as an extractor, so a missing [`resolve_real_ip`] layer is a `500` naming it
/// rather than a log full of `-`. Read `req.extensions().get::<RealIp>()` instead if you'd rather
/// degrade than fail — an app shouldn't necessarily fall over because a log field is unavailable.
async fn access_log(RealIp(ip): RealIp, req: Request, next: Next) -> Response {
    let started = std::time::Instant::now();
    let method = req.method().to_string();
    let target = req.uri().path().to_string();

    let res = next.run(req).await;

    // Whatever the handler decided to tell us about itself. Anonymous routes — and any request
    // rejected *before* reaching a handler — leave it unset and print `-`, which is honest.
    let who = res.extensions().get::<Actor>().map(|a| a.0.as_str()).unwrap_or("-");
    println!(
        "{ip:<15} {who:<6} {method:<4} {target:<12} {} {}ms",
        res.status().as_u16(),
        started.elapsed().as_millis()
    );
    res
}

// ────────────────────── the log line: variant 2, a lookup per request ──────────────────────

/// The same line, but the **middleware** resolves the user instead of waiting for a handler to
/// volunteer one — so `/login`, `/profile` and every other library-owned route get named too.
///
/// The cost is exactly one [`Auth::identify`] per request: a session lookup, a user lookup and a group
/// query, on requests that never needed an identity. For an operator console at a handful of requests
/// per second that is nothing; for a public API at thousands it is a real bill, which is why the
/// library refuses to make the choice for you.
///
/// Note what it still cannot name: a caller authenticating with a **bearer token**. That credential
/// isn't checked until the handler checks it, so identity doesn't exist yet out here — and a request
/// that *fails* authentication, the one most worth naming, never produces a name at all. For those,
/// variant 1 plus a line from the handler is not a workaround, it is the better answer.
async fn access_log_identify(
    State(app): State<AppState>,
    RealIp(ip): RealIp,
    req: Request,
    next: Next,
) -> Response {
    let started = std::time::Instant::now();
    let method = req.method().to_string();
    let target = req.uri().path().to_string();
    let who = match app.auth.identify(req.headers()).await {
        Some(id) => id.username,
        None => "-".to_string(),
    };

    let res = next.run(req).await;

    println!(
        "{ip:<15} {who:<6} {method:<4} {target:<12} {} {}ms",
        res.status().as_u16(),
        started.elapsed().as_millis()
    );
    res
}

// ─────────────────────────────────── the demo app ───────────────────────────────────

#[derive(Clone)]
struct AppState {
    auth: Auth,
}

/// The app's own landing page, and the first thing you see after logging in — so this is where the
/// mechanism has to be visible. It resolves the caller because the page greets them, and hands that
/// name to the log rather than letting the log go and find it again.
async fn public(State(app): State<AppState>, req: Request) -> Response {
    let who = app.auth.identify(req.headers()).await;
    let body = Html(format!(
        r#"<h1>access-log demo</h1>
<p>{}</p>
<p>Watch the terminal:</p>
<ul>
  <li><b>this page</b> and <a href="/private">/private</a> are <i>ours</i> — their log lines name you
      once you are logged in, at no extra cost: the handler already knew.</li>
  <li><a href="/profile">/profile</a>, <a href="/login">/login</a> and <a href="/logout">/logout</a>
      are the <i>library's</i> — no handler of ours is in them to volunteer a name, so they log
      <code>-</code>. Restart with <code>NAME_EVERY_REQUEST=1</code> to name those too, at one
      session lookup per request.</li>
</ul>
<p><a href="/login">log in</a> · <a href="/profile">profile</a> · <a href="/logout">log out</a></p>"#,
        match &who {
            Some(id) => format!("Signed in as <b>{}</b> — this request's log line says so.", id.username),
            None => "Not signed in, so this request's log line names nobody.".to_string(),
        }
    ));
    let mut res = (StatusCode::OK, body).into_response();
    if let Some(id) = who {
        res.extensions_mut().insert(Actor(id.username));
    }
    res
}

/// Login-gated, and the worked example of variant 1: it already resolved an identity to decide whether
/// to serve the page, so it hands that name to the log by returning an [`Actor`] alongside the body.
/// **No second lookup** — the point of putting it on the response rather than asking for it up front.
async fn private(State(app): State<AppState>, req: Request) -> Response {
    let Some(who) = app.auth.identify(req.headers()).await else {
        return Redirect::to("/login").into_response();
    };
    let body = Html(format!(
        "<h1>hello {}</h1><p>The log line for this request names you.</p><p><a href=\"/\">back</a></p>",
        who.username
    ));
    // The whole mechanism: attach the name, and the layer outside picks it up on the way out.
    let mut res = (StatusCode::OK, body).into_response();
    res.extensions_mut().insert(Actor(who.username));
    res
}
