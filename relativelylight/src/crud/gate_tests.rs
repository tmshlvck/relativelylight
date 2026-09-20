//! Negative-path tests for the **enforcement point**: the UI's write path consulting a model's gate.
//! The auth side (who a cookie resolves to) is covered by `auth::security_tests`; this covers what
//! the engine does with the answer.
//!
//! - every write authorizes with the right [`Operation`] — a read gate can't be used to write, and a
//!   create gate can't be used to delete;
//! - **reads are gated too.** That is new and it matters: there is no JSON API behind this UI any
//!   more, so `render_for` is the enforcement point for reading, not merely for hiding buttons;
//! - `NeedsLogin` → `401`, `Denied` → `403`;
//! - a rejected request **never reaches the backend** (the stub [`Accessor`] counts calls, so a gate
//!   checked *after* the write would fail the test rather than pass silently);
//! - an unregistered model is `404` — not an open door;
//! - CSRF: every write needs the token, reads need nothing, and a bearer client is exempt.

use super::engine::{Accessor, Column, Engine, Error, ListQuery, Page, Result};
use super::ui::{Table, ViewState};
use crate::auth::{migrate, Auth, UserReadGroupWrite};
use crate::authz::{Authz, Decision, Operation};
use axum::body::Body;
use axum::http::{header, HeaderMap, Request};
use sea_orm::Database;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt; // oneshot

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// How many times the backend was asked to do something. A gate that leaks lets one of the counters
/// move.
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
        vec![field("id", true), field("name", false), field("nickname", true)]
    }
    async fn list(&self, _q: &ListQuery, _terse: bool) -> Result<Page> {
        self.calls.read();
        Ok(Page::new(0, 1, 25, Vec::new()))
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

impl Fixed {
    fn new(decision: Decision) -> Arc<Fixed> {
        Arc::new(Fixed { decision, seen: Default::default() })
    }
    fn seen(&self) -> Vec<Operation> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl Authz for Fixed {
    async fn authorize(&self, op: Operation, _headers: &HeaderMap) -> Decision {
        self.seen.lock().unwrap().push(op);
        self.decision
    }
}

/// Every write the UI can post, with the `Operation` it must be authorized as.
fn writes() -> Vec<(&'static str, String, Operation)> {
    let mut w = vec![
        ("create", "_op=create&name=x".to_string(), Operation::Create),
        ("update", "_op=update&_id=1&name=x".to_string(), Operation::Update),
        ("delete one", "_del=1".to_string(), Operation::Delete),
        ("delete selected", "_op=delete_selected&ids=1".to_string(), Operation::Delete),
        ("delete all", "_op=delete_all".to_string(), Operation::Delete),
    ];
    if cfg!(feature = "csv") {
        w.push(("import", "_op=import&csv=name%0Ax%0A".to_string(), Operation::Create));
    }
    w
}

fn engine_with(gate: Arc<dyn Authz>, csrf: Option<crate::csrf::Csrf>) -> (Engine, Arc<Calls>) {
    let calls = Arc::new(Calls::default());
    let mut engine = Engine::new();
    engine.add(Arc::new(Stub { calls: calls.clone() }), gate);
    if let Some(csrf) = csrf {
        engine.set_csrf(csrf);
    }
    (engine, calls)
}

fn no_headers() -> HeaderMap {
    HeaderMap::new()
}

fn cookie(value: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(header::COOKIE, value.parse().unwrap());
    h
}

// ===================== the gate =====================

#[tokio::test]
async fn a_needs_login_gate_refuses_every_write_and_never_calls_the_backend() {
    let (engine, calls) = engine_with(Fixed::new(Decision::NeedsLogin), None);
    let table = Table::new(&engine, "thing");
    for (what, body, _) in writes() {
        let err = table
            .submit(&no_headers(), IP, body.as_bytes(), &ViewState::default())
            .await
            .expect_err("anonymous writes must be refused");
        assert!(matches!(err, Error::Unauthorized), "{what}: {err}");
    }
    assert_eq!(calls.snapshot().1, 0, "not one write reached the backend");
}

#[tokio::test]
async fn a_denied_gate_refuses_every_write_and_never_calls_the_backend() {
    let (engine, calls) = engine_with(Fixed::new(Decision::Denied), None);
    let table = Table::new(&engine, "thing");
    for (what, body, _) in writes() {
        let err = table.submit(&no_headers(), IP, body.as_bytes(), &ViewState::default()).await.unwrap_err();
        assert!(matches!(err, Error::Forbidden), "{what}: {err}");
    }
    assert_eq!(calls.snapshot().1, 0);
}

#[tokio::test]
async fn an_allowing_gate_reaches_the_backend() {
    // The positive control: without it the negatives above could pass because nothing works at all.
    let (engine, calls) = engine_with(Fixed::new(Decision::Allow), None);
    let table = Table::new(&engine, "thing");
    for (what, body, _) in writes() {
        table
            .submit(&no_headers(), IP, body.as_bytes(), &ViewState::default())
            .await
            .unwrap_or_else(|e| panic!("{what} should be allowed: {e}"));
    }
    assert!(calls.snapshot().1 >= 5, "every write landed: {:?}", calls.snapshot());
}

#[tokio::test]
async fn each_write_is_authorized_as_the_operation_it_actually_is() {
    for (what, body, expected) in writes() {
        let gate = Fixed::new(Decision::Allow);
        let (engine, _) = engine_with(gate.clone(), None);
        Table::new(&engine, "thing")
            .submit(&no_headers(), IP, body.as_bytes(), &ViewState::default())
            .await
            .expect("allowed");
        assert!(
            gate.seen().contains(&expected),
            "{what} must be authorized as {expected:?}, got {:?}",
            gate.seen()
        );
    }
}

#[tokio::test]
async fn reading_is_gated_and_not_merely_decorated() {
    // With no JSON API behind it, `render_for` *is* the read enforcement point. A reader who may not
    // list the entity must not receive its rows in an HTML page either.
    for (decision, expect) in [
        (Decision::NeedsLogin, Error::Unauthorized),
        (Decision::Denied, Error::Forbidden),
    ] {
        let (engine, calls) = engine_with(Fixed::new(decision), None);
        let err = Table::new(&engine, "thing")
            .render_for(&no_headers(), &ViewState::default())
            .await
            .expect_err("a table nobody may read must not render");
        assert_eq!(err.to_string(), expect.to_string());
        assert_eq!(calls.snapshot().0, 0, "and the rows were never fetched");
    }
}

#[tokio::test]
async fn a_write_gate_alone_does_not_open_the_dialog_for_reading_a_row() {
    struct WriteOnly;
    #[async_trait::async_trait]
    impl Authz for WriteOnly {
        async fn authorize(&self, op: Operation, _h: &HeaderMap) -> Decision {
            if op.is_write() {
                Decision::Allow
            } else {
                Decision::Denied
            }
        }
    }
    let (engine, calls) = engine_with(Arc::new(WriteOnly), None);
    let err = Table::new(&engine, "thing")
        .render_for(&no_headers(), &ViewState::from_query("edit=1"))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Forbidden), "{err}");
    assert_eq!(calls.snapshot().0, 0, "the row was never read");
}

#[tokio::test]
async fn an_unregistered_model_is_not_an_open_door() {
    let (engine, calls) = engine_with(Fixed::new(Decision::Allow), None);
    let ghost = Table::new(&engine, "ghost");
    assert!(matches!(
        ghost.render_for(&no_headers(), &ViewState::default()).await.unwrap_err(),
        Error::NotFound
    ));
    assert!(matches!(
        ghost.submit(&no_headers(), IP, b"_op=create&name=x", &ViewState::default()).await.unwrap_err(),
        Error::NotFound
    ));
    assert_eq!(calls.snapshot(), (0, 0));
}

// ===================== a real gate preset, over a real database =====================

#[tokio::test]
async fn a_real_group_gate_rejects_anonymous_and_non_member_writes() {
    let db = Database::connect("sqlite::memory:").await.expect("sqlite");
    migrate(&db).await.expect("migrate");
    let lockout = crate::auth::lockout::Lockout::default();
    let auth = Auth::new(db.clone(), lockout).secure_cookies(false);
    crate::auth::create_user(&db, "editor", "pw").await.expect("editor");
    crate::auth::create_user(&db, "reader", "pw").await.expect("reader");
    crate::auth::add_to_group(&db, "editor", "writers").await.expect("group");

    let gate = Arc::new(UserReadGroupWrite::new(&auth, ["writers"]));
    let (engine, calls) = engine_with(gate, None);
    let table = Table::new(&engine, "thing");
    let state = ViewState::default();

    // Anonymous: 401 on write, and no read either (this preset requires a login to read).
    for (what, body, _) in writes() {
        let err = table.submit(&no_headers(), IP, body.as_bytes(), &state).await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized), "anonymous {what}: {err}");
    }
    assert!(matches!(
        table.render_for(&no_headers(), &state).await.unwrap_err(),
        Error::Unauthorized
    ));

    // A logged-in non-member may read, and write nothing.
    let reader = login(&auth, "reader").await;
    table.render_for(&cookie(&reader), &state).await.expect("a logged-in user may read");
    for (what, body, _) in writes() {
        let err = table.submit(&cookie(&reader), IP, body.as_bytes(), &state).await.unwrap_err();
        assert!(matches!(err, Error::Forbidden), "non-member {what}: {err}");
    }
    let html = table.render_for(&cookie(&reader), &state).await.expect("reads");
    assert!(!html.contains("+ New"), "and is offered no write controls");
    assert_eq!(calls.snapshot().1, 0, "no write reached the backend");

    // A member may write (the control).
    let editor = login(&auth, "editor").await;
    for (what, body, _) in writes() {
        table
            .submit(&cookie(&editor), IP, body.as_bytes(), &state)
            .await
            .unwrap_or_else(|e| panic!("member {what}: {e}"));
    }
    assert!(calls.snapshot().1 >= 5, "the member's writes did reach the backend");
}

/// Log `username` in through the real login route and return their `Cookie:` header. The login form is
/// CSRF-protected, so the post carries a double-submit token pair like a browser would.
async fn login(auth: &Auth, username: &str) -> String {
    let csrf = "a".repeat(64);
    let mut req = Request::builder()
        .method("POST")
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, format!("{}={csrf}", auth.csrf().cookie()))
        .body(Body::from(format!("username={username}&password=pw&_csrf={csrf}")))
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo("127.0.0.1:9999".parse::<std::net::SocketAddr>().unwrap()));
    let app = auth.routes().layer(axum::middleware::from_fn_with_state(
        crate::middleware::TrustProxy(false),
        crate::middleware::resolve_real_ip,
    ));
    let res = app.oneshot(req).await.unwrap();
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

// ===================== CSRF on the write path =====================

#[tokio::test]
async fn with_csrf_configured_every_write_needs_the_token_and_reads_need_nothing() {
    let csrf = crate::csrf::Csrf::new().secure(false);
    let token = "c".repeat(64);
    let jar = format!("{}={token}", csrf.cookie());
    let (engine, calls) = engine_with(Fixed::new(Decision::Allow), Some(csrf));
    let table = Table::new(&engine, "thing");
    let state = ViewState::default();

    // A read is safe: no token, no problem.
    table.render_for(&cookie(&jar), &state).await.expect("reads need no token");

    for (what, body, _) in writes() {
        let err = table.submit(&cookie(&jar), IP, body.as_bytes(), &state).await.unwrap_err();
        assert!(matches!(err, Error::Csrf), "{what} without a token: {err}");

        let with_token = format!("{body}&_csrf={token}");
        table
            .submit(&cookie(&jar), IP, with_token.as_bytes(), &state)
            .await
            .unwrap_or_else(|e| panic!("{what} with the token: {e}"));
    }
    assert!(calls.snapshot().1 >= 5, "the tokened writes landed");
}

#[tokio::test]
async fn a_wrong_or_cookieless_token_does_not_pass() {
    let csrf = crate::csrf::Csrf::new().secure(false);
    let token = "c".repeat(64);
    let jar = format!("{}={token}", csrf.cookie());
    let (engine, calls) = engine_with(Fixed::new(Decision::Allow), Some(csrf));
    let table = Table::new(&engine, "thing");
    let state = ViewState::default();

    // Right shape, wrong value — a token an attacker guessed rather than read from the cookie.
    let err = table
        .submit(&cookie(&jar), IP, format!("_op=create&name=x&_csrf={}", "d".repeat(64)).as_bytes(), &state)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Csrf), "{err}");

    // A form token with no cookie to match it against is no evidence at all.
    let err = table
        .submit(&no_headers(), IP, format!("_op=create&name=x&_csrf={token}").as_bytes(), &state)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Csrf), "{err}");
    assert_eq!(calls.snapshot().1, 0);
}

#[tokio::test]
async fn a_bearer_client_is_exempt_from_the_csrf_check() {
    // An API credential isn't ambient, so a cross-site request can't borrow it.
    let csrf = crate::csrf::Csrf::new().secure(false);
    let (engine, calls) = engine_with(Fixed::new(Decision::Allow), Some(csrf));
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
    Table::new(&engine, "thing")
        .submit(&headers, IP, b"_op=create&name=x", &ViewState::default())
        .await
        .expect("a bearer write needs no form token");
    assert_eq!(calls.snapshot().1, 1);
}

#[tokio::test]
async fn a_form_carries_a_token_exactly_when_the_engine_enforces_one() {
    let state = ViewState::from_query("new=1");
    let (plain, _) = engine_with(Fixed::new(Decision::Allow), None);
    let html = Table::new(&plain, "thing").render_for(&no_headers(), &state).await.unwrap();
    assert!(!html.contains("_csrf"), "no checker, no hidden field: {html}");

    let csrf = crate::csrf::Csrf::new().secure(false);
    let token = "e".repeat(64);
    let jar = format!("{}={token}", csrf.cookie());
    let (guarded, _) = engine_with(Fixed::new(Decision::Allow), Some(csrf));
    let html = Table::new(&guarded, "thing").render_for(&cookie(&jar), &state).await.unwrap();
    assert!(
        html.contains(&format!(r#"<input type="hidden" name="_csrf" value="{token}">"#)),
        "the form must echo the cookie: {html}"
    );
}
