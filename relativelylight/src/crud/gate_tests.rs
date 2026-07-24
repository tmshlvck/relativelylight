//! Negative-path tests for the **API enforcement point**: the `crud` HTTP surface consulting a
//! model's gate. The auth side (who a cookie resolves to) is covered by `auth::security_tests`; this
//! covers what the engine does with the answer, over the real router:
//!
//! - every route authorizes with the right [`Operation`] — a read gate can't be used to write;
//! - `NeedsLogin` → `401`, `Denied` → `403`, with a JSON error body;
//! - a rejected request **never reaches the backend** (the stub [`Accessor`] counts calls, so a gate
//!   that's checked *after* the write would fail the test rather than pass silently);
//! - an unregistered model has no gate and is a plain `404` — not an open door.

use super::engine::{Accessor, ColumnMeta, Engine, ListQuery, Page, Result};
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
    fn columns(&self) -> Vec<ColumnMeta> {
        Vec::new()
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
    let calls = Arc::new(Calls::default());
    let mut engine = Engine::new("/api/v1");
    engine.add(Arc::new(Stub { calls: calls.clone() }), gate);
    (Arc::new(engine).router(), calls)
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
    let res = app.clone().oneshot(b.body(Body::from(body.to_string())).unwrap()).await.unwrap();
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
    let auth = Auth::new(db.clone()).secure_cookies(false);
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

/// Log `username` in through the real login route and return their `Cookie:` header.
async fn login(auth: &Auth, username: &str) -> String {
    let auth_app = auth.routes();
    let req = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!("username={username}&password=pw")))
        .unwrap();
    let res = auth_app.oneshot(req).await.unwrap();
    assert!(res.status().is_redirection(), "login failed for {username}");
    let set = res.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
    let name = auth.session_cookie_name();
    let value = set.strip_prefix(&format!("{name}=")).unwrap().split(';').next().unwrap();
    format!("{name}={value}")
}
