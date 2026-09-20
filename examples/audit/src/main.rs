//! examples/audit — **who called, and what they changed.**
//!
//! Two records every back-office keeps, neither of them shipped by relativelylight, and one value
//! that makes them agree:
//!
//! | Record | The library gives you | The app writes |
//! |---|---|---|
//! | request log | [`RealIp`](relativelylight::middleware::RealIp) — the caller's address, resolved once at the edge | the line ([`access_log`], [`access_log_identify`]) |
//! | audit trail | a [`WriteEvent`](relativelylight::observe::WriteEvent) per committed write, carrying before/after, headers and that same address | the record ([`AuditLog`]) |
//!
//! The crate writes nothing to stdout or stderr anywhere, on purpose: a log line is a dozen lines of
//! code and the dozen differ per app — a structured `tracing` event or a line on stderr, the query
//! string or just the path, a level you can turn down on a chatty endpoint. An audit *row* differs
//! even more: its table, its retention, and who counts as the actor are product decisions. Shipping
//! either shape would have meant a logging dependency in the library and an opinion about all of it.
//!
//! So here are both, printed to stdout, in about sixty lines between them.
//!
//! **The point is that the address is the same one in every record.** `resolve_real_ip` decides it
//! once, at the outermost layer; the request log prints that value, the audit line prints that
//! value, and `auth`'s lockout counts against that value. Nothing re-derives it from a header and a
//! proxy policy it has to know about, so the three can't disagree about who was here.
//!
//! ```text
//! cargo run -p audit-example                            # serve on :3000, log in as admin / password
//! NAME_EVERY_REQUEST=1 cargo run -p audit-example       # …name the user on every request, not just ours
//! TRUST_PROXY=1 cargo run -p audit-example              # …behind a proxy: believe X-Forwarded-For
//! ```
//!
//! Log in, edit a post at `/data/post`, change your password at `/profile`, and watch:
//!
//! ```text
//! 127.0.0.1       admin  GET  /data/post   200 3ms
//! audit  autocrud    update post#1       admin@127.0.0.1  title: "Hello" → "Hello, world"
//! 127.0.0.1       admin  POST /data/post   303 12ms
//! audit  auth-profile update auth_user#1  admin@127.0.0.1  password_hash: (changed)
//! ```
//!
//! The audit line is emitted **after the write commits** and before the redirect, from inside the
//! library's write path — so it sees a change that happened, not one that was attempted, and it sees
//! `auth`'s own writes (a password change, a 2FA enrolment, a manager's reset) as well as the CRUD
//! panel's. One observer, registered on both.
//!
//! # The two shapes of the request log
//!
//! | Variant | Names the user on | Costs |
//! |---|---|---|
//! | [`access_log`] (default) | routes that opt in by returning an [`Actor`] | nothing |
//! | [`access_log_identify`] (`NAME_EVERY_REQUEST=1`) | every request with a session cookie | one `Auth::identify` per request |
//!
//! Neither is more correct. Pick by whether naming an *anonymous* request's route matters more than
//! a session lookup on every hit.
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
//! anything. `NAME_EVERY_REQUEST=1` names those too, at one session lookup per request — including
//! the ones that never needed an identity. Note what neither can name: a caller authenticating with
//! a **bearer token**, which isn't checked until the handler checks it.
//!
//! The audit line has no such problem: by the time a write commits, the library knows exactly whose
//! request it was.

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use relativelylight::auth::lockout::Lockout;
use relativelylight::auth::{self, Auth, UserReadWrite};
use relativelylight::authz::Operation;
use relativelylight::crud::engine::Engine;
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::{Admin, Outcome, ViewState, CSS};
use relativelylight::middleware::{resolve_real_ip, RealIp, TrustProxy};
use relativelylight::observe::{WriteEvent, WriteObserver};
use serde_json::Value;
use std::sync::{Arc, OnceLock};

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
    // `model::setup()` is the shared demo schema (posts, authors, tags), seeded, on a pinned
    // single-connection in-memory SQLite — see its docs for why the pool is pinned.
    let db = model::setup().await?;
    auth::migrate(&db).await?;
    auth::make_admin(&db, "admin", "admin", "password").await?;

    // **The audit sink, registered on both write paths.** One `Arc`, handed to `Auth::on_write` and
    // `Crud::on_write`, so a password change and a post edit land in the same place in the same
    // shape — which is the point of `WriteEvent::source` naming the emitter.
    //
    // The `OnceLock` is the chicken and the egg: the observer wants to name the actor, and naming
    // the actor means calling `Auth::identify`, and `Auth` is being built with the observer in it.
    // An app persisting audit rows hits exactly this and solves it exactly this way.
    let audit = Arc::new(AuditLog::default());

    let auth = Auth::new(db.clone(), Lockout::default())
        .secure_cookies(false)
        .admin_group("admin")
        .on_write(audit.clone());
    audit.attach(auth.clone());

    // Something ordinary to edit, so there are CRUD writes to audit. Any logged-in user may read and
    // write; the gate is checked per request, and a refused write emits no event because it never
    // happened.
    let mut author = MetaModel::new(model::author::Entity);
    author.label_column("name");
    let mut post = MetaModel::new(model::post::Entity);
    post.relation("author").label = Some("Author".into());
    post.field("published_at").datetime(); // a timestamp an operator can read, in their own zone
    let gate = Arc::new(UserReadWrite::new(&auth));
    let mut crud = Crud::new(db);
    crud.register(author, gate.clone());
    crud.register(post, gate);
    crud.csrf(auth.csrf());
    crud.on_write(audit.clone());
    let engine = Arc::new(crud.into_engine());

    let state = AppState { auth: auth.clone(), engine };
    let app = Router::new()
        .route("/", get(public))
        .route("/private", get(private))
        .route("/data", get(|| async { Redirect::to("/data/post") }))
        .route("/data/{entity}", get(panel_show).post(panel_save))
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
    println!("audit demo on http://127.0.0.1:3000/   (log in as admin / password)");
    println!("edit something at /data/post, or change your password at /profile, and watch the audit lines");
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

// ─────────────────────────────── the audit trail ───────────────────────────────

/// The whole audit sink: print one line per **committed** write. Swap the `println!` for an insert
/// into your own table and this is a real audit log.
///
/// What the library hands you and why each piece is there:
///
/// - **`source`** — which surface wrote (`"autocrud"` for the admin panel, `"auth-profile"` /
///   `"auth-admin"` for `auth`'s own pages). One sink normally takes all of them plus the app's own
///   events, so this is what tells them apart.
/// - **`before` / `after`** — the row either side of the change, secrets already redacted by the
///   emitter. `before` is `None` on a create, `after` is `None` on a delete.
/// - **`headers`** — resolve the actor from these. The library deliberately does *not* name one for
///   you: an app may authenticate by session, by bearer token, or by a service account, and only it
///   knows which.
/// - **`client_ip`** — already resolved by `resolve_real_ip`, so this line's address is the same one
///   the request log printed and the lockout counted.
///
/// `on_write` is `async` and runs **in the request**, after the commit and before the response. Keep
/// it short: a slow sink is slow writes. An app doing real work here (a remote log, an expensive
/// insert) should hand the event to a channel and return.
#[derive(Default)]
struct AuditLog {
    /// Set once, after `Auth` is built — see the chicken-and-egg note at the call site.
    auth: OnceLock<Auth>,
}

impl AuditLog {
    fn attach(&self, auth: Auth) {
        let _ = self.auth.set(auth);
    }
}

#[async_trait::async_trait]
impl WriteObserver for AuditLog {
    async fn on_write(&self, ev: &WriteEvent<'_>) {
        // Resolving the actor is the app's job, from the headers the event carries. Two cases print
        // `-`: a write with no session at all (a seeder, or a route authenticating some other way),
        // and — worth knowing — a **self-service password change**, because that write rotates the
        // caller's session id, so the cookie on the request it came from is already spent by the
        // time this runs. The event's `key` still names the row, and a manager's reset (source
        // `auth-admin`) names the manager normally.
        let who = match self.auth.get() {
            Some(auth) => match auth.identify(ev.headers).await {
                Some(id) => id.username,
                None => "-".to_string(),
            },
            None => "-".to_string(),
        };
        let key = ev.key.clone().unwrap_or_else(|| "*".into()); // `*` = a bulk delete: no single row
        println!(
            "audit  {:<12} {:<6} {}#{key:<6} {who}@{}  {}",
            ev.source,
            format!("{:?}", ev.op).to_lowercase(),
            ev.entity,
            ev.client_ip,
            changes(ev),
        );
    }
}

/// What actually changed, as `field: before → after`. An update usually touches one column out of
/// twenty, and a line that prints all twenty is a line nobody reads. (A real audit **row** would
/// store the whole `before`/`after` JSON and compute this at display time — a diff is cheap to
/// recompute and impossible to un-discard.)
fn changes(ev: &WriteEvent<'_>) -> String {
    let (before, after) = (ev.before.as_ref(), ev.after.as_ref());
    let (Some(Value::Object(b)), Some(Value::Object(a))) = (before, after) else {
        // One side is absent. On a create or a delete that is the whole row, and the operation says
        // which. `auth`'s own events are the third shape: an update whose `after` is a summary of
        // what happened ("password_changed") rather than a row, because the row is mostly secrets.
        return match (ev.op, before, after) {
            (_, Some(v), None) => format!("removed {}", one_line(v)),
            (Operation::Create, None, Some(v)) => format!("created {}", one_line(v)),
            (_, None, Some(v)) => one_line(v),
            _ => String::new(),
        };
    };
    let diff: Vec<String> = a
        .iter()
        .filter(|(k, v)| b.get(*k) != Some(*v))
        .map(|(k, v)| format!("{k}: {} → {}", scalar(b.get(k)), scalar(Some(v))))
        .collect();
    match diff.is_empty() {
        true => "(no visible change)".into(), // e.g. only a redacted column moved
        false => diff.join(", "),
    }
}

fn one_line(row: &Value) -> String {
    clip(&row.to_string(), 72)
}

fn scalar(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "∅".into(),
        Some(Value::String(s)) => format!("\"{}\"", clip(s, 24)),
        Some(other) => other.to_string(),
    }
}

/// Truncate to `n` **characters** — not bytes. Row data is arbitrary text, and slicing it by byte
/// index panics the moment a column holds an em dash or an accent. (Asked how this was found: a
/// seeded post whose body contains "—".)
fn clip(s: &str, n: usize) -> String {
    match s.char_indices().nth(n) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_string(),
    }
}

// ─────────────────────────── the CRUD panel being audited ───────────────────────────

/// Two handlers, as every `crud::ui` surface has: this one renders.
async fn panel_show(
    State(app): State<AppState>,
    Path(entity): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let mut state = ViewState::from_uri(&uri);
    state.entity = Some(entity);
    let mut res = match panel(&app.engine).render_for(&headers, &state).await {
        Ok(body) => Html(shell(&body)).into_response(),
        Err(e) => e.into_response(),
    };
    res.extensions_mut().insert(Actor(who.username));
    res
}

/// …and this one writes, which is what produces the audit lines.
async fn panel_save(
    State(app): State<AppState>,
    Path(entity): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    RealIp(ip): RealIp,
    body: Bytes,
) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let mut state = ViewState::from_uri(&uri);
    state.entity = Some(entity);
    let ui = panel(&app.engine);
    let mut res = match ui.submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        Ok(Outcome::Invalid(state)) => match ui.render_for(&headers, &state).await {
            Ok(body) => (StatusCode::UNPROCESSABLE_ENTITY, Html(shell(&body))).into_response(),
            Err(e) => e.into_response(),
        },
        Err(e) => e.into_response(),
    };
    // Variant 1 again: this handler knew who was calling, so the request log gets the name for free.
    res.extensions_mut().insert(Actor(who.username));
    res
}

fn panel(engine: &Engine) -> Admin<'_> {
    Admin::new(engine)
        .title("Data")
        .base("/data")
        .entity("post")
        .entity("author")
        .separator()
        .link("Home", "/")
        .link("Profile", "/profile")
}

fn shell(body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Data</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>{CSS}</style></head><body class="bg-body-tertiary"><main class="container py-4">{body}</main>
</body></html>"#
    )
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
    engine: Arc<Engine>,
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
