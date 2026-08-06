//! Negative-path tests for the **API enforcement point**: the `crud` HTTP surface consulting a
//! model's gate. The auth side (who a cookie resolves to) is covered by `auth::security_tests`; this
//! covers what the engine does with the answer, over the real router:
//!
//! - every route authorizes with the right [`Operation`] — a read gate can't be used to write;
//! - `NeedsLogin` → `401`, `Denied` → `403`, with a JSON error body;
//! - a rejected request **never reaches the backend** (the stub [`Accessor`] counts calls, so a gate
//!   that's checked *after* the write would fail the test rather than pass silently);
//! - an unregistered model has no gate and is a plain `404` — not an open door.

use super::engine::{Accessor, Column, Engine, ListQuery, Page, Result};
use crate::auth::{migrate, Auth, UserReadGroupWrite};
use crate::authz::{Authz, Decision, Operation};
use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use sea_orm::Database;
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt; // oneshot

/// How many times the backend was asked to do something. A gate that leaks lets one of the write
/// counters move.
#[derive(Default)]
struct Calls {
    reads: AtomicUsize,
    writes: AtomicUsize,
}

impl Calls {
    fn read(&self) {
        self.reads.fetch_add(1, Ordering::SeqCst);
    }
    fn write(&self) {
        self.writes.fetch_add(1, Ordering::SeqCst);
    }
    fn snapshot(&self) -> (usize, usize) {
        (self.reads.load(Ordering::SeqCst), self.writes.load(Ordering::SeqCst))
    }
}

/// A do-nothing accessor that only records that it was called.
struct Stub {
    calls: Arc<Calls>,
}

#[async_trait::async_trait]
impl Accessor for Stub {
    fn slug(&self) -> &str {
        "thing"
    }
    fn pk(&self) -> String {
        "id".into()
    }
    fn columns(&self) -> Vec<Column> {
        let field = |name: &str, nullable: bool| Column::Field {
            required: !nullable,
            options: Vec::new(),
            name: name.into(),
            logical_type: crate::crud::LogicalType::Text,
            read_only: false,
            write_only: false,
            nullable,
            label: None,
            description: None,
            default: None,
            display: None,
            sortable: true,
        };
        let mut status = field("status", true);
        if let Column::Field { options, .. } = &mut status {
            *options = vec!["draft".into(), "live".into()];
        }
        vec![field("name", false), field("nickname", true), status]
    }
    async fn list(&self, _q: &ListQuery, _terse: bool) -> Result<Page> {
        self.calls.read();
        Ok(Page { total: 0, page: 1, per_page: 25, data: Vec::new() })
    }
    async fn get(&self, _pk: &str) -> Result<Option<Value>> {
        self.calls.read();
        Ok(Some(serde_json::json!({ "id": 1 })))
    }
    async fn create(&self, _body: &Value) -> Result<Value> {
        self.calls.write();
        Ok(serde_json::json!({ "id": 1 }))
    }
    async fn update(&self, _pk: &str, _body: &Value) -> Result<Option<Value>> {
        self.calls.write();
        Ok(Some(serde_json::json!({ "id": 1 })))
    }
    async fn delete(&self, _pk: &str) -> Result<Option<Value>> {
        self.calls.write();
        Ok(Some(serde_json::json!({ "id": 1 })))
    }
    async fn delete_many(&self, _q: &ListQuery) -> Result<u64> {
        self.calls.write();
        Ok(0)
    }
}

/// A gate that always answers the same thing, and records the operations it was asked about.
struct Fixed {
    decision: Decision,
    seen: std::sync::Mutex<Vec<Operation>>,
}

#[async_trait::async_trait]
impl Authz for Fixed {
    async fn authorize(&self, op: Operation, _headers: &HeaderMap) -> Decision {
        self.seen.lock().unwrap().push(op);
        self.decision
    }
}

/// One request per routed method, with the `Operation` the engine should authorize it as.
fn routes() -> Vec<(&'static str, &'static str, &'static str, Operation)> {
    let mut r = vec![
        ("GET", "/api/v1/thing", "", Operation::List),
        ("GET", "/api/v1/thing/1", "", Operation::Read),
        ("POST", "/api/v1/thing", r#"{"name":"x"}"#, Operation::Create),
        ("PATCH", "/api/v1/thing/1", r#"{"name":"x"}"#, Operation::Update),
        ("DELETE", "/api/v1/thing/1", "", Operation::Delete),
        ("DELETE", "/api/v1/thing?all=true", "", Operation::Delete),
    ];
    if cfg!(feature = "csv") {
        r.push(("POST", "/api/v1/thing/_import", "id\n1\n", Operation::Create));
    }
    r
}

fn app(gate: Arc<dyn Authz>) -> (axum::Router, Arc<Calls>) {
    build(gate, None)
}

fn build(gate: Arc<dyn Authz>, csrf: Option<crate::csrf::Csrf>) -> (axum::Router, Arc<Calls>) {
    let calls = Arc::new(Calls::default());
    let mut engine = Engine::new("/api/v1");
    engine.add(Arc::new(Stub { calls: calls.clone() }), gate);
    if let Some(csrf) = csrf {
        engine.set_csrf(csrf);
    }
    // The address-resolving layer is mandatory for any app using this crate — the engine's write
    // handlers take a `RealIp` for the audit event — so the fixture wires it like a real app.
    let router = Arc::new(engine).router().layer(axum::middleware::from_fn_with_state(
        crate::middleware::TrustProxy(false),
        crate::middleware::resolve_real_ip,
    ));
    (router, calls)
}

/// Give a request the connection info a real server supplies, so `resolve_real_ip` can do its job.
fn with_peer(req: &mut Request<Body>) {
    let addr: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
    req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
}

/// A request with an arbitrary set of extra headers (for the CSRF token / Bearer cases).
async fn send_with(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, String) {
    let mut b = Request::builder().method(method).uri(uri);
    if !body.is_empty() {
        let ct = if body.starts_with('{') { "application/json" } else { "text/csv" };
        b = b.header(header::CONTENT_TYPE, ct);
    }
    for (name, value) in headers {
        b = b.header(*name, *value);
    }
    let mut req = b.body(Body::from(body.to_string())).unwrap();
    with_peer(&mut req);
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn send(app: &axum::Router, method: &str, uri: &str, body: &str, cookie: Option<&str>) -> (StatusCode, String) {
    let mut b = Request::builder().method(method).uri(uri);
    if !body.is_empty() {
        let ct = if body.starts_with('{') { "application/json" } else { "text/csv" };
        b = b.header(header::CONTENT_TYPE, ct);
    }
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    let mut req = b.body(Body::from(body.to_string())).unwrap();
    with_peer(&mut req);
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn a_needs_login_gate_makes_every_route_401_and_never_calls_the_backend() {
    let gate = Arc::new(Fixed { decision: Decision::NeedsLogin, seen: Default::default() });
    let (app, calls) = app(gate.clone());
    for (method, uri, body, op) in routes() {
        let (status, text) = send(&app, method, uri, body, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
        assert!(text.contains("unauthorized"), "{method} {uri}: JSON error body, got {text}");
        assert_eq!(gate.seen.lock().unwrap().last().copied(), Some(op), "{method} {uri}: wrong op");
    }
    assert_eq!(calls.snapshot(), (0, 0), "a rejected request must not reach the backend");
}

#[tokio::test]
async fn a_denied_gate_makes_every_route_403_and_never_calls_the_backend() {
    let gate = Arc::new(Fixed { decision: Decision::Denied, seen: Default::default() });
    let (app, calls) = app(gate);
    for (method, uri, body, _) in routes() {
        let (status, text) = send(&app, method, uri, body, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
        assert!(text.contains("forbidden"), "{method} {uri}: JSON error body, got {text}");
    }
    assert_eq!(calls.snapshot(), (0, 0), "a rejected request must not reach the backend");
}

#[tokio::test]
async fn an_allowing_gate_reaches_the_backend() {
    // The control for the two tests above — otherwise "never called" would pass on a broken router.
    let gate = Arc::new(Fixed { decision: Decision::Allow, seen: Default::default() });
    let (app, calls) = app(gate);
    for (method, uri, body, _) in routes() {
        let (status, _) = send(&app, method, uri, body, None).await;
        assert!(status.is_success(), "{method} {uri} → {status}");
    }
    let (reads, writes) = calls.snapshot();
    assert!(reads >= 2, "list + get (an update also reads the audit 'before' snapshot): {reads}");
    assert!(writes >= 4, "create, update, delete, bulk delete (+ csv import): {writes}");
}

#[tokio::test]
async fn an_unregistered_model_is_404_not_an_open_door() {
    let gate = Arc::new(Fixed { decision: Decision::Allow, seen: Default::default() });
    let (app, _) = app(gate);
    for (method, uri, body, _) in routes() {
        let uri = uri.replace("thing", "other");
        let (status, _) = send(&app, method, &uri, body, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}");
    }
}

#[tokio::test]
async fn a_real_group_gate_rejects_anonymous_and_non_member_writes() {
    // End-to-end: the shipped `UserReadGroupWrite` preset over a real session cookie.
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrate(&db).await.unwrap();
    let auth = Auth::new(db.clone(), crate::auth::lockout::Lockout::default()).secure_cookies(false);
    crate::auth::create_user(&db, "alice", "pw").await.unwrap();
    crate::auth::create_user(&db, "editor", "pw").await.unwrap();
    crate::auth::add_to_group(&db, "editor", "editors").await.unwrap();

    let gate = Arc::new(UserReadGroupWrite::new(&auth, ["editors"]));
    let (app, calls) = app(gate);

    // Anonymous: 401 everywhere, nothing reaches the backend.
    for (method, uri, body, _) in routes() {
        let (status, _) = send(&app, method, uri, body, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "anonymous {method} {uri}");
    }
    assert_eq!(calls.snapshot(), (0, 0));

    // A logged-in non-member may read but not write.
    let cookie = login(&auth, "alice").await;
    for (method, uri, body, op) in routes() {
        let (status, _) = send(&app, method, uri, body, Some(&cookie)).await;
        if op.is_write() {
            assert_eq!(status, StatusCode::FORBIDDEN, "non-member {method} {uri}");
        } else {
            assert!(status.is_success(), "non-member read {method} {uri} → {status}");
        }
    }
    assert_eq!(calls.snapshot().1, 0, "a non-member's writes must not reach the backend");

    // A member of the write group may write (the control).
    let cookie = login(&auth, "editor").await;
    for (method, uri, body, op) in routes().into_iter().filter(|(.., op)| op.is_write()) {
        let (status, _) = send(&app, method, uri, body, Some(&cookie)).await;
        assert!(status.is_success(), "member {method} {uri} ({op:?}) → {status}");
    }
    assert!(calls.snapshot().1 >= 4, "the member's writes did reach the backend");
}

/// Log `username` in through the real login route and return their `Cookie:` header. The login form is
/// CSRF-protected, so the post carries a double-submit token pair like a browser would.
async fn login(auth: &Auth, username: &str) -> String {
    let auth_app = auth.routes();
    let csrf = "a".repeat(64);
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("{}={csrf}", auth.csrf().cookie()))
        .body(Body::from(format!("username={username}&password=pw&_csrf={csrf}")))
        .unwrap();
    let auth_app = auth_app.layer(axum::middleware::from_fn_with_state(
        crate::middleware::TrustProxy(false),
        crate::middleware::resolve_real_ip,
    ));
    let mut req = req;
    with_peer(&mut req);
    let res = auth_app.oneshot(req).await.unwrap();
    assert!(res.status().is_redirection(), "login failed for {username}");
    let name = auth.session_cookie_name();
    let value = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix(&format!("{name}=")))
        .and_then(|rest| rest.split(';').next())
        .expect("session cookie");
    format!("{name}={value}")
}

// ===================== CSRF on the JSON API =====================

#[tokio::test]
async fn with_csrf_configured_writes_need_the_header_and_reads_do_not() {
    let csrf = crate::csrf::Csrf::new().secure(false);
    let token = "c".repeat(64);
    let cookie = format!("{}={token}", csrf.cookie());
    let gate = Arc::new(Fixed { decision: Decision::Allow, seen: Default::default() });
    let (app, calls) = build(gate, Some(csrf.clone()));

    for (method, uri, body, op) in routes() {
        // Reads never need a token; writes are rejected without one — even though the gate allows.
        let (status, text) = send_with(&app, method, uri, body, &[("cookie", &cookie)]).await;
        if op.is_write() {
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri} without the header");
            assert!(text.contains("csrf"), "{method} {uri}: says why — {text}");
        } else {
            assert!(status.is_success(), "{method} {uri} is safe → no token needed, got {status}");
        }
    }
    assert_eq!(calls.snapshot().1, 0, "no write reached the backend");

    // The matching header (what crud::ui sends) lets them through.
    for (method, uri, body, op) in routes().into_iter().filter(|(.., op)| op.is_write()) {
        let (status, _) =
            send_with(&app, method, uri, body, &[("cookie", &cookie), (crate::csrf::HEADER, &token)])
                .await;
        assert!(status.is_success(), "{method} {uri} ({op:?}) with a matching token → {status}");
    }
    assert!(calls.snapshot().1 >= 4, "writes reached the backend once the token matched");
}

#[tokio::test]
async fn a_wrong_or_cookieless_token_does_not_pass_the_api_check() {
    let csrf = crate::csrf::Csrf::new().secure(false);
    let token = "c".repeat(64);
    let cookie = format!("{}={token}", csrf.cookie());
    let gate = Arc::new(Fixed { decision: Decision::Allow, seen: Default::default() });
    let (app, calls) = build(gate, Some(csrf));

    let cases: [(&str, Vec<(&str, &str)>); 4] = [
        ("header alone (attacker can set headers, not cookies)", vec![(crate::csrf::HEADER, &token)]),
        ("cookie alone", vec![("cookie", &cookie)]),
        ("mismatched pair", vec![("cookie", &cookie), (crate::csrf::HEADER, "nope")]),
        ("empty header", vec![("cookie", &cookie), (crate::csrf::HEADER, "")]),
    ];
    for (what, headers) in cases {
        let (status, _) = send_with(&app, "POST", "/api/v1/thing", r#"{"a":1}"#, &headers).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "POST with {what}");
    }
    assert_eq!(calls.snapshot().1, 0, "none of them reached the backend");
}

#[tokio::test]
async fn a_bearer_api_client_is_exempt_from_the_csrf_check() {
    let gate = Arc::new(Fixed { decision: Decision::Allow, seen: Default::default() });
    let (app, calls) = build(gate, Some(crate::csrf::Csrf::new()));
    let (status, _) = send_with(
        &app,
        "POST",
        "/api/v1/thing",
        r#"{"a":1}"#,
        &[("authorization", "Bearer token-abc")],
    )
    .await;
    assert!(status.is_success(), "a non-cookie credential needs no CSRF token, got {status}");
    assert_eq!(calls.snapshot().1, 1);
}

#[cfg(feature = "ui")]
#[tokio::test]
async fn the_table_ui_sends_the_token_only_when_the_engine_enforces_it() {
    use crate::crud::ui::Table;
    let calls = Arc::new(Calls::default());
    let gate: Arc<dyn Authz> = Arc::new(Fixed { decision: Decision::Allow, seen: Default::default() });

    let mut plain = Engine::new("/api/v1");
    plain.add(Arc::new(Stub { calls: calls.clone() }), gate.clone());
    let html = Table::new(&plain, "thing").render().unwrap();
    assert!(
        html.contains(r#"const name = "";"#),
        "no CSRF configured → the fetch helper has no cookie to read, so it sends no header"
    );

    let mut guarded = Engine::new("/api/v1");
    guarded.add(Arc::new(Stub { calls }), gate);
    guarded.set_csrf(crate::csrf::Csrf::new().cookie_name("app_csrf"));
    let html = Table::new(&guarded, "thing").render().unwrap();
    assert!(html.contains(r#"const name = "app_csrf";"#), "reads the configured cookie name");
    assert!(html.contains(r#""x-csrf-token""#), "and echoes it in the header");
    // Every write path sends it (create/update via save, both deletes, CSV import).
    assert_eq!(html.matches("csrfHeaders()").count(), 6, "one definition + five call sites");
}

#[cfg(feature = "ui")]
#[tokio::test]
async fn the_table_ui_is_told_which_columns_are_nullable() {
    // The form needs it twice over: to send `null` (not "") when a nullable input is left empty, and to
    // mark the columns a row can't be written without.
    use crate::crud::ui::Table;
    let gate: Arc<dyn Authz> = Arc::new(Fixed { decision: Decision::Allow, seen: Default::default() });
    let mut engine = Engine::new("/api/v1");
    engine.add(Arc::new(Stub { calls: Arc::new(Calls::default()) }), gate);
    let html = Table::new(&engine, "thing").render().unwrap();

    assert!(html.contains(r#""nullable":true"#), "nullability reaches the embedded column metadata");
    assert!(html.contains(r#""nullable":false"#));
    assert!(html.contains("c.nullable"), "…and the payload builder consults it");
    assert!(html.contains("mustFill(c)"), "…and the label marks what must be filled");

    // `required` is published rather than re-derived by the form (it used to guess from nullable+default).
    assert!(html.contains(r#""required":true"#), "the engine's own required flag is embedded");
    assert!(html.contains(r#""required":false"#));
    assert!(html.contains("c.required !== true"), "…and the marker reads it rather than guessing");

    // A closed set of values reaches the form, which renders it as a dropdown.
    assert!(html.contains(r#""options":["draft","live"]"#), "the allowed values are embedded: {html}");
    assert!(html.contains("hasOptions(c)"), "…and the form switches widget on them");
    assert!(html.contains("x-for=\"o in c.options\""), "…rendering one <option> each");
    // Columns without a set carry no `options` key at all — the payload is read on every page load.
    let per_column: Vec<&str> = html.split(r#""kind":"field""#).skip(1).collect();
    assert_eq!(
        per_column.iter().filter(|c| c.split(r#""kind""#).next().unwrap_or("").contains("options")).count(),
        1,
        "only the one column with a set mentions options"
    );
}
