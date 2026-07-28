//! Negative-path tests for `auth` — the "wrong credentials / wrong session / wrong user must be
//! rejected" half of the contract. The positive paths are exercised by the examples and by a handful
//! of controls here (a correct login, a correct TOTP code) that keep the negatives from being vacuous.
//!
//! They run against a fresh in-memory SQLite database and drive the real [`Auth::routes`] router with
//! `tower`'s `oneshot`, so what's under test is the shipped HTTP behavior, not a re-implementation.
//! Each test names the security property it pins:
//!
//! - **sessions** — a cookie only authenticates while its row is live, unexpired, past the second
//!   factor, and its user is active (`identify` is the only authn entry point).
//! - **login** — bad password / unknown user / inactive account / SSO account are all rejected with
//!   `401` and no session cookie.
//! - **TOTP** — a wrong or foreign code never completes the half-authenticated session, and a wrong
//!   code during enrolment never activates 2FA.
//! - **profile** — a password change needs the current password; resetting *another* user's password
//!   or disabling their 2FA needs a manager group, and a rejected request changes nothing.
//! - **gates** — every preset's decision for anonymous / non-member / member callers, including that
//!   an expired, half-authenticated, or deactivated session is treated as anonymous.

use super::*;
use crate::auth::lockout::Lockout;
use crate::authz::{Decision, Operation};
use crate::validate::PasswordPolicy;
use axum::body::Body;
use axum::http::{header, Request};
use sea_orm::Database;
use tower::ServiceExt; // oneshot

const PW: &str = "correct-horse-battery-staple";
/// A second *acceptable* password. It has to satisfy the default policy (§5g) like any other — the
/// suite changes passwords constantly, and a fixture the policy refuses would fail every one of those
/// tests for the wrong reason.
const OTHER_PW: &str = "trombone-hedgehog-marmalade";
/// A password the default policy refuses, for the tests that are *about* the policy: seven characters,
/// and `hunter` with a digit stuck on the end is on the common-value list twice over.
const WEAK_PW: &str = "hunter2";
/// The CSRF token the fixture's posts carry. Double-submit is stateless — what matters is that the
/// cookie and the submitted value agree, so a test can pick the value.
const CSRF: &str = "5cbf19b46ff34d0a8de0dcbe12b6b7e2c0c1a5f4b3e2d1c0b9a8978685746352";

// ===================== Fixture =====================

/// A configured `Auth` over a fresh in-memory DB, plus its router.
struct Fx {
    db: DatabaseConnection,
    auth: Auth,
    app: Router,
}

impl Fx {
    async fn new() -> Fx {
        Fx::build(Lockout::default(), |a| a).await
    }

    /// As [`Fx::new`], with a chance to configure `Auth` before it's cloned into the router (the
    /// builders need sole ownership of the inner `Arc`).
    async fn with(configure: impl FnOnce(Auth) -> Auth) -> Fx {
        Fx::build(Lockout::default(), configure).await
    }

    /// As [`Fx::new`] with a specific lockout policy (it is a `new` argument, not a builder).
    async fn with_lockout(lockout: Lockout) -> Fx {
        Fx::build(lockout, |a| a).await
    }

    async fn build(lockout: Lockout, configure: impl FnOnce(Auth) -> Auth) -> Fx {
        let db = Database::connect("sqlite::memory:").await.expect("sqlite in-memory");
        migrate(&db).await.expect("migrate");
        let auth = configure(Auth::new(db.clone(), lockout).secure_cookies(false));
        let app = auth.routes();
        Fx { db, auth, app }
    }

    /// Add an active local user with password [`PW`]; returns its id.
    async fn user(&self, username: &str) -> i32 {
        create_user(&self.db, username, PW).await.expect("create_user");
        self.row(username).await.id
    }

    /// Add an active local user who is a member of `group`; returns its id.
    async fn user_in(&self, username: &str, group: &str) -> i32 {
        let id = self.user(username).await;
        add_to_group(&self.db, username, group).await.expect("add_to_group");
        id
    }

    async fn row(&self, username: &str) -> user::Model {
        user::Entity::find()
            .filter(user::Column::Username.eq(username))
            .one(&self.db)
            .await
            .expect("query")
            .expect("user exists")
    }

    async fn update_user(&self, username: &str, edit: impl FnOnce(&mut user::ActiveModel)) {
        let mut am: user::ActiveModel = self.row(username).await.into();
        edit(&mut am);
        am.update(&self.db).await.expect("update user");
    }

    async fn deactivate(&self, username: &str) {
        self.update_user(username, |am| am.is_active = Set(false)).await;
    }

    /// Turn `username` into an SSO account (no local password / 2FA).
    async fn make_sso(&self, username: &str, provider: &str) {
        self.update_user(username, |am| am.sso_provider = Set(Some(provider.into()))).await;
    }

    /// Switch 2FA on for `username`, returning the active secret.
    async fn enable_totp(&self, username: &str) -> String {
        let secret = totp::generate_secret();
        let s = secret.clone();
        self.update_user(username, move |am| am.totp_secret = Set(Some(s))).await;
        secret
    }

    /// Whether `password` still authenticates `username` (used to assert a rejected change was a
    /// no-op — a `403`/`400` that silently wrote anyway would be the real bug).
    async fn password_works(&self, username: &str, password: &str) -> bool {
        verify_password(&self.row(username).await.password_hash, password)
    }

    /// A login post carrying `X-Forwarded-For`, as a proxy would send it.
    async fn post_forwarded(&self, xff: &str, username: &str, password: &str) -> Resp {
        self.post_with_header("x-forwarded-for", xff, username, password).await
    }

    /// A login post carrying a CDN-style client header (for the custom-resolver test).
    async fn post_cdn(&self, ip: &str, username: &str, password: &str) -> Resp {
        self.post_with_header("cf-connecting-ip", ip, username, password).await
    }

    /// A login post with one extra header, plus a socket peer (`127.0.0.1`) — so a test can tell which
    /// of the two the lockout actually counted.
    async fn post_with_header(&self, name: &str, value: &str, username: &str, password: &str) -> Resp {
        let (body, cookie) =
            self.browser_post(&form(&[("username", username), ("password", password)]), None);
        let mut req = self
            .req("POST", "/login", Some(&cookie))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(name, value)
            .body(Body::from(body))
            .unwrap();
        let addr: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
        self.send(req).await
    }

    /// The account's lockout row, if it has one.
    async fn lockout_row(&self, username: &str) -> Option<lockout::username_entity::Model> {
        lockout::username_entity::Entity::find_by_id(username.to_lowercase())
            .one(&self.db)
            .await
            .expect("query")
    }

    async fn session_row(&self, token: &str) -> Option<session::Model> {
        session::Entity::find_by_id(token.to_string()).one(&self.db).await.expect("query")
    }

    /// A live, fully authenticated session for `username` (the shortcut the login tests avoid).
    async fn session_for(&self, username: &str) -> String {
        let id = self.row(username).await.id;
        create_session_row(&self.db, id, now_secs() + 3600, false).await
    }

    /// `Cookie:` header value carrying `token` under the configured session cookie name.
    fn cookie(&self, token: &str) -> String {
        format!("{}={token}", self.auth.session_cookie_name())
    }

    fn headers(&self, cookie: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(c) = cookie {
            h.insert(header::COOKIE, c.parse().unwrap());
        }
        h
    }

    /// `identify` for a request carrying `token`.
    async fn identify_token(&self, token: &str) -> Option<Identity> {
        self.auth.identify(&self.headers(Some(&self.cookie(token)))).await
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> Resp {
        self.send(self.req("GET", path, cookie).body(Body::empty()).unwrap()).await
    }

    /// Post as a browser filling in one of our forms: the body carries the hidden `_csrf` field and
    /// the request carries the matching token cookie. Use [`post_raw`](Fx::post_raw) to post without
    /// one (that's what the CSRF tests do).
    async fn post(&self, path: &str, form: &str, cookie: Option<&str>) -> Resp {
        let (body, cookie) = self.browser_post(form, cookie);
        self.post_raw(path, &body, Some(&cookie)).await
    }

    /// As [`post`](Fx::post), but the request also carries a socket peer, as it would behind
    /// `into_make_service_with_connect_info` — that's where the per-IP limiter gets its address.
    async fn post_from(&self, path: &str, form: &str, cookie: Option<&str>, peer: &str) -> Resp {
        let (body, cookie) = self.browser_post(form, cookie);
        let mut req = self
            .req("POST", path, Some(&cookie))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let addr: std::net::SocketAddr = peer.parse().expect("peer address");
        req.extensions_mut().insert(axum::extract::ConnectInfo(addr));
        self.send(req).await
    }

    /// The body + cookie header a browser would send for one of our forms (hidden `_csrf` + cookie).
    fn browser_post(&self, form: &str, cookie: Option<&str>) -> (String, String) {
        let body = if form.is_empty() {
            format!("{}={CSRF}", crate::csrf::FIELD)
        } else {
            format!("{form}&{}={CSRF}", crate::csrf::FIELD)
        };
        let csrf_cookie = format!("{}={CSRF}", self.auth.csrf().cookie());
        let cookie = match cookie {
            Some(c) => format!("{c}; {csrf_cookie}"),
            None => csrf_cookie,
        };
        (body, cookie)
    }

    /// Try to log in with the wrong password `n` times, returning the last response.
    async fn fail_login(&self, username: &str, n: usize) -> Resp {
        let mut last = None;
        for _ in 0..n {
            last = Some(
                self.post("/login", &form(&[("username", username), ("password", "wrong")]), None)
                    .await,
            );
        }
        last.expect("at least one attempt")
    }

    /// Log in with the *correct* password.
    async fn try_login(&self, username: &str) -> Resp {
        self.post("/login", &form(&[("username", username), ("password", PW)]), None).await
    }

    /// Post exactly what's given — nothing added, so the CSRF check sees only what the caller sent.
    async fn post_raw(&self, path: &str, form: &str, cookie: Option<&str>) -> Resp {
        let req = self
            .req("POST", path, cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form.to_string()))
            .unwrap();
        self.send(req).await
    }

    fn req(&self, method: &str, path: &str, cookie: Option<&str>) -> axum::http::request::Builder {
        let mut b = Request::builder().method(method).uri(path);
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        b
    }

    async fn send(&self, req: Request<Body>) -> Resp {
        let res = self.app.clone().oneshot(req).await.expect("router response");
        let status = res.status();
        let headers = res.headers().clone();
        let body = axum::body::to_bytes(res.into_body(), 1 << 20).await.expect("body");
        Resp { status, headers, body: String::from_utf8_lossy(&body).into_owned() }
    }
}

/// Insert a session row directly — the only way to forge the states a client can't reach through the
/// login flow (expired, half-authenticated, orphaned). `last_seen_at` is stamped *now*, so the idle
/// clock is satisfied and the row's liveness turns purely on `expires_at`;
/// [`create_idle_session_row`] is the variant for testing the other clock.
async fn create_session_row(
    db: &DatabaseConnection,
    user_id: i32,
    expires_at: i64,
    awaiting_totp: bool,
) -> String {
    create_session_row_seen(db, user_id, expires_at, now_secs(), awaiting_totp).await
}

/// As [`create_session_row`], but with an explicit `last_seen_at` — for driving the **idle** timeout
/// independently of the absolute one.
async fn create_session_row_seen(
    db: &DatabaseConnection,
    user_id: i32,
    expires_at: i64,
    last_seen_at: i64,
    awaiting_totp: bool,
) -> String {
    let token = new_token();
    session::ActiveModel {
        id: Set(token.clone()),
        user_id: Set(user_id),
        expires_at: Set(expires_at),
        last_seen_at: Set(last_seen_at),
        awaiting_totp: Set(awaiting_totp),
    }
    .insert(db)
    .await
    .expect("insert session");
    token
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn location(&self) -> Option<&str> {
        self.headers.get(header::LOCATION)?.to_str().ok()
    }

    /// Every `Set-Cookie` value on the response.
    fn set_cookies(&self) -> Vec<&str> {
        self.headers.get_all(header::SET_COOKIE).iter().filter_map(|v| v.to_str().ok()).collect()
    }

    /// The session token the response hands out, if any (ignoring a removal, which has an empty value).
    fn session_token(&self, name: &str) -> Option<String> {
        let prefix = format!("{name}=");
        self.set_cookies().iter().find_map(|c| {
            let rest = c.strip_prefix(&prefix)?;
            let value = rest.split(';').next().unwrap_or("");
            (!value.is_empty()).then(|| value.to_string())
        })
    }

    /// Assert this is a redirect to `path`.
    fn assert_redirect(&self, path: &str) {
        assert!(
            self.status.is_redirection(),
            "expected a redirect to {path}, got {} — body: {}",
            self.status,
            self.body
        );
        assert_eq!(self.location(), Some(path), "wrong redirect target");
    }
}

// ===================== Sessions: what a cookie is worth =====================

#[tokio::test]
async fn no_or_unusable_cookie_does_not_identify() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let token = fx.session_for("alice").await;

    // No cookie header at all.
    assert!(fx.auth.identify(&fx.headers(None)).await.is_none());
    // Some other cookie, no session cookie.
    assert!(fx.auth.identify(&fx.headers(Some("other=1"))).await.is_none());
    // Right name, empty / unknown / near-miss values.
    for value in ["", "deadbeef", "'; DROP TABLE auth_session;--", &token[1..], &format!("{token}x")] {
        assert!(
            fx.identify_token(value).await.is_none(),
            "an unknown token must not authenticate: {value:?}"
        );
    }
    // A valid token under the *wrong* cookie name is worthless.
    assert!(fx.auth.identify(&fx.headers(Some(&format!("session={token}")))).await.is_none());
    // The cookie is the only identity source today: a token offered as a Bearer credential (or any
    // other header) must not authenticate until an API-token source is actually implemented.
    let mut bearer = HeaderMap::new();
    bearer.insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
    assert!(fx.auth.identify(&bearer).await.is_none(), "no header-based identity source exists");
    // Control: the real token under the real name does identify.
    assert_eq!(fx.identify_token(&token).await.map(|w| w.username), Some("alice".into()));
}

#[tokio::test]
async fn expired_session_does_not_identify() {
    let fx = Fx::new().await;
    let id = fx.user("alice").await;
    let stale = create_session_row(&fx.db, id, now_secs() - 1, false).await;
    assert!(fx.identify_token(&stale).await.is_none(), "an expired session must not authenticate");
    // The boundary: expiry in the future still works, so the check isn't rejecting everything.
    let live = create_session_row(&fx.db, id, now_secs() + 60, false).await;
    assert!(fx.identify_token(&live).await.is_some());
}

#[tokio::test]
async fn an_idle_session_does_not_identify_even_inside_its_absolute_deadline() {
    // The two clocks are independent, and this is the one that limits a stolen cookie: the absolute
    // deadline is a week away, but nobody has used the session for longer than the idle window.
    let fx = Fx::with(|a| a.session_idle_secs(600)).await;
    let id = fx.user("alice").await;
    let far = now_secs() + 7 * 24 * 3600;

    let idle = create_session_row_seen(&fx.db, id, far, now_secs() - 601, false).await;
    assert!(fx.identify_token(&idle).await.is_none(), "past the idle window: must not authenticate");
    // Controls: just inside the window still works, and so does the same row once it's been touched.
    let fresh = create_session_row_seen(&fx.db, id, far, now_secs() - 599, false).await;
    assert!(fx.identify_token(&fresh).await.is_some(), "inside the idle window");

    // And the absolute deadline still wins over a busy session — a session used a second ago but past
    // its expiry is dead, or the absolute cap would be unenforceable.
    let expired = create_session_row_seen(&fx.db, id, now_secs() - 1, now_secs(), false).await;
    assert!(fx.identify_token(&expired).await.is_none(), "absolute expiry beats a fresh last_seen");
}

#[tokio::test]
async fn using_a_session_pushes_the_idle_clock_forward() {
    // Otherwise an idle timeout would log out an actively working user at a fixed interval.
    let fx = Fx::with(|a| a.session_idle_secs(600)).await;
    let id = fx.user("alice").await;
    // Stale enough to be refreshed (past IDLE_REFRESH_GRACE) but still inside the idle window.
    let stale_stamp = now_secs() - 120;
    let token = create_session_row_seen(&fx.db, id, now_secs() + 3600, stale_stamp, false).await;

    assert!(fx.identify_token(&token).await.is_some(), "still live");
    let seen = fx.session_row(&token).await.unwrap().last_seen_at;
    assert!(seen > stale_stamp, "last_seen_at must advance: {seen} vs {stale_stamp}");

    // But a *recent* stamp is left alone — identity is resolved once per gated model, so refreshing on
    // every read would turn one page render into several writes.
    let recent = now_secs() - 1;
    let token = create_session_row_seen(&fx.db, id, now_secs() + 3600, recent, false).await;
    assert!(fx.identify_token(&token).await.is_some());
    assert_eq!(
        fx.session_row(&token).await.unwrap().last_seen_at,
        recent,
        "a fresh stamp must not be rewritten"
    );
}

#[tokio::test]
async fn the_idle_clock_is_off_when_it_is_configured_off() {
    // `session_idle_secs(0)` must be exactly the old behaviour: only the absolute deadline applies.
    let fx = Fx::with(|a| a.session_idle_secs(0)).await;
    let id = fx.user("alice").await;
    let ancient = create_session_row_seen(&fx.db, id, now_secs() + 3600, 0, false).await;
    assert!(
        fx.identify_token(&ancient).await.is_some(),
        "with no idle clock, an untouched session stays valid to its absolute deadline"
    );
}

#[tokio::test]
async fn prune_collects_idle_dead_sessions_and_spares_live_ones() {
    let fx = Fx::with(|a| a.session_idle_secs(600)).await;
    let id = fx.user("alice").await;
    let far = now_secs() + 7 * 24 * 3600;
    let idle = create_session_row_seen(&fx.db, id, far, now_secs() - 601, false).await;
    let live = create_session_row_seen(&fx.db, id, far, now_secs(), false).await;
    let expired = create_session_row(&fx.db, id, now_secs() - 1, false).await;

    fx.auth.prune().await.expect("prune");

    assert!(fx.session_row(&idle).await.is_none(), "idle-dead row collected");
    assert!(fx.session_row(&expired).await.is_none(), "absolutely-expired row collected");
    assert!(fx.session_row(&live).await.is_some(), "a live session must survive pruning");
}

#[tokio::test]
async fn half_authenticated_session_does_not_identify() {
    let fx = Fx::new().await;
    let id = fx.user("alice").await;
    let pending = create_session_row(&fx.db, id, now_secs() + 3600, true).await;
    assert!(
        fx.identify_token(&pending).await.is_none(),
        "a password-verified session awaiting TOTP must grant nothing"
    );
}

#[tokio::test]
async fn session_of_deactivated_or_deleted_user_does_not_identify() {
    let fx = Fx::new().await;
    let id = fx.user("alice").await;
    let token = fx.session_for("alice").await;
    assert!(fx.identify_token(&token).await.is_some(), "control: live session");

    fx.deactivate("alice").await;
    assert!(
        fx.identify_token(&token).await.is_none(),
        "deactivating a user must kill their live sessions"
    );

    user::Entity::delete_by_id(id).exec(&fx.db).await.unwrap();
    assert!(fx.identify_token(&token).await.is_none(), "an orphaned session must not authenticate");
}

#[tokio::test]
async fn logout_revokes_the_session_row_so_a_copied_cookie_is_dead() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let token = fx.session_for("alice").await;

    let res = fx.get("/logout", Some(&fx.cookie(&token))).await;
    res.assert_redirect("/login");
    assert!(fx.session_row(&token).await.is_none(), "logout must delete the session row");
    // Not just cleared client-side: the token itself is worthless afterwards.
    assert!(fx.identify_token(&token).await.is_none());
    // A second (or anonymous) logout is a harmless no-op, not an error.
    fx.get("/logout", Some(&fx.cookie(&token))).await.assert_redirect("/login");
    fx.get("/logout", None).await.assert_redirect("/login");
}

// ===================== Login =====================

#[tokio::test]
async fn login_rejects_bad_credentials_without_creating_a_session() {
    let fx = Fx::new().await;
    fx.user("alice").await;

    let cases: [(&str, &str, &str); 5] = [
        ("alice", OTHER_PW, "wrong password"),
        ("alice", "", "empty password"),
        ("alice", &PW[..PW.len() - 1], "password prefix"),
        ("nobody", PW, "unknown user"),
        ("ALICE", PW, "username is not a password bypass"),
    ];
    for (username, password, what) in cases {
        let res = fx.post("/login", &form(&[("username", username), ("password", password)]), None).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{what} must be rejected");
        assert!(
            res.session_token(fx.auth.session_cookie_name()).is_none(),
            "{what}: no session cookie may be issued"
        );
        assert!(res.body.contains("Invalid username or password"), "{what}: generic error only");
        assert_eq!(
            session::Entity::find().all(&fx.db).await.unwrap().len(),
            0,
            "{what}: no session row may be created"
        );
    }
}

#[tokio::test]
async fn login_rejects_inactive_and_sso_accounts() {
    let fx = Fx::new().await;
    fx.user("gone").await;
    fx.deactivate("gone").await;
    fx.user("federated").await;
    fx.make_sso("federated", "okta").await;

    for username in ["gone", "federated"] {
        let res = fx.post("/login", &form(&[("username", username), ("password", PW)]), None).await;
        assert_eq!(
            res.status,
            StatusCode::UNAUTHORIZED,
            "{username}: correct password must not be enough"
        );
        assert!(res.session_token(fx.auth.session_cookie_name()).is_none());
    }
    // Control: an ordinary active local account with the same password does log in.
    fx.user("alice").await;
    let ok = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    ok.assert_redirect("/");
    assert!(ok.session_token(fx.auth.session_cookie_name()).is_some());
}

#[tokio::test]
async fn login_with_2fa_yields_only_a_half_authenticated_session() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    fx.enable_totp("alice").await;

    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    res.assert_redirect("/login/totp");
    let token = res.session_token(fx.auth.session_cookie_name()).expect("pending session cookie");
    assert!(fx.session_row(&token).await.unwrap().awaiting_totp);
    assert!(
        fx.identify_token(&token).await.is_none(),
        "the password alone must not authenticate a 2FA account"
    );
    // …and it doesn't open the profile pages either.
    fx.get("/profile", Some(&fx.cookie(&token))).await.assert_redirect("/login");
}

#[tokio::test]
async fn session_cookie_is_httponly_samesite_strict_and_path_scoped() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let cookie = res
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(fx.auth.session_cookie_name()))
        .expect("session cookie")
        .to_string();
    assert!(cookie.contains("HttpOnly"), "not HttpOnly: {cookie}");
    assert!(cookie.contains("SameSite=Strict"), "not SameSite=Strict: {cookie}");
    assert!(cookie.contains("Path=/"), "not path-scoped: {cookie}");
    assert!(!cookie.contains("Secure"), "secure_cookies(false) was requested: {cookie}");

    // The default (and what production must use) is Secure.
    let secure = Fx::with(|a| a.secure_cookies(true)).await;
    secure.user("alice").await;
    let res =
        secure.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let cookie = res
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(secure.auth.session_cookie_name()))
        .expect("session cookie")
        .to_string();
    assert!(cookie.contains("Secure"), "secure_cookies(true) must set Secure: {cookie}");
}

#[tokio::test]
async fn session_tokens_are_unpredictable() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let mut seen = std::collections::HashSet::new();
    for _ in 0..16 {
        let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
        let token = res.session_token(fx.auth.session_cookie_name()).expect("cookie");
        assert_eq!(token.len(), 64, "256 bits of hex: {token}");
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(seen.insert(token), "session tokens must never repeat");
    }
}

// ===================== The TOTP second factor =====================

#[tokio::test]
async fn totp_step_needs_a_pending_session() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let secret = fx.enable_totp("alice").await;
    let code = totp::current_code(&secret);
    let full = fx.session_for("alice").await; // already past the second factor
    let expired = create_session_row(&fx.db, fx.row("alice").await.id, now_secs() - 1, true).await;

    for cookie in [None, Some(fx.cookie("deadbeef")), Some(fx.cookie(&full)), Some(fx.cookie(&expired))] {
        let c = cookie.as_deref();
        fx.get("/login/totp", c).await.assert_redirect("/login");
        // A correct code is still worth nothing without a pending session to attach it to.
        fx.post("/login/totp", &form(&[("code", &code)]), c).await.assert_redirect("/login");
    }
}

#[tokio::test]
async fn totp_step_rejects_a_wrong_or_foreign_code() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    fx.user("mallory").await;
    fx.enable_totp("alice").await;
    let mallorys = fx.enable_totp("mallory").await;

    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let token = res.session_token(fx.auth.session_cookie_name()).unwrap();
    let cookie = fx.cookie(&token);

    for code in ["", "000000", "12345", "abcdef", &totp::current_code(&mallorys)] {
        let res = fx.post("/login/totp", &form(&[("code", code)]), Some(&cookie)).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "code {code:?} must be rejected");
        assert!(
            fx.session_row(&token).await.unwrap().awaiting_totp,
            "code {code:?}: the session must stay half-authenticated"
        );
        assert!(fx.identify_token(&token).await.is_none(), "code {code:?}: still not logged in");
    }
    assert!(
        fx.row("alice").await.last_login_at.is_none(),
        "a failed second factor is not a login"
    );
}

#[tokio::test]
async fn totp_step_completes_the_session_on_the_right_code() {
    // The control for the two tests above: the same flow with the correct code does log in — and the
    // session it lands on is a **new** one (see the rotation test below).
    let fx = Fx::new().await;
    fx.user("alice").await;
    let secret = fx.enable_totp("alice").await;

    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let pending = res.session_token(fx.auth.session_cookie_name()).unwrap();
    let res = fx
        .post(
            "/login/totp",
            &form(&[("code", &totp::current_code(&secret))]),
            Some(&fx.cookie(&pending)),
        )
        .await;
    res.assert_redirect("/");
    let token = res.session_token(fx.auth.session_cookie_name()).expect("a rotated session cookie");
    assert!(!fx.session_row(&token).await.unwrap().awaiting_totp);
    assert_eq!(fx.identify_token(&token).await.map(|w| w.username), Some("alice".into()));
}

#[tokio::test]
async fn completing_the_second_factor_rotates_the_session_id() {
    // Session fixation at the 2FA step. Password login can't be fixated (it always mints a fresh row),
    // but confirming the second factor used to elevate the *same* id — so an attacker who knew the
    // password could take a half-authenticated token, plant its cookie in the victim's browser, send
    // them to /login/totp, and inherit a full session the moment the victim typed their own code.
    let fx = Fx::new().await;
    fx.user("alice").await;
    let secret = fx.enable_totp("alice").await;

    // The attacker's half-authenticated session, obtained with the stolen password.
    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let planted = res.session_token(fx.auth.session_cookie_name()).unwrap();
    assert!(fx.session_row(&planted).await.unwrap().awaiting_totp, "half-authenticated as set up");

    // The victim, holding that planted cookie, completes their own second factor.
    let res = fx
        .post(
            "/login/totp",
            &form(&[("code", &totp::current_code(&secret))]),
            Some(&fx.cookie(&planted)),
        )
        .await;
    res.assert_redirect("/");

    // The planted token is gone, not elevated — the attacker's copy authenticates nothing.
    let issued = res.session_token(fx.auth.session_cookie_name()).expect("a new session cookie");
    assert_ne!(issued, planted, "the session id must change on privilege gain");
    assert!(fx.session_row(&planted).await.is_none(), "the planted row must be deleted");
    assert!(fx.identify_token(&planted).await.is_none(), "the planted token must be dead");
    // And the victim is properly logged in on the new one (so the negative isn't vacuous).
    assert_eq!(fx.identify_token(&issued).await.map(|w| w.username), Some("alice".into()));
}

#[tokio::test]
async fn a_totp_code_cannot_be_used_twice() {
    // The replay guard (RFC 6238 §5.2). A code stays valid for ±1 step — about 90 seconds — so without
    // this, anyone who observes a code the victim actually used (a shoulder-surf, a screen share, a code
    // read out on a support call) and who also has the password can log in on it before it ages out.
    let fx = Fx::new().await;
    fx.user("alice").await;
    let secret = fx.enable_totp("alice").await;
    let code = totp::current_code(&secret);

    // First use: accepted, and the spent step is recorded on the account.
    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let pending = res.session_token(fx.auth.session_cookie_name()).unwrap();
    let res =
        fx.post("/login/totp", &form(&[("code", &code)]), Some(&fx.cookie(&pending))).await;
    res.assert_redirect("/");
    let spent = fx.row("alice").await.totp_last_step.expect("the accepted step is recorded");

    // Second use of the *same* code, on a fresh half-authenticated session: refused, and refused with
    // the same wording as a wrong code — "already used" would confirm to a captor that they hold a
    // genuine code.
    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let replay = res.session_token(fx.auth.session_cookie_name()).unwrap();
    let res = fx.post("/login/totp", &form(&[("code", &code)]), Some(&fx.cookie(&replay))).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "a replayed code must be refused");
    assert!(res.body.contains("Invalid code"), "and must not admit the code was real: {}", res.body);
    assert!(
        fx.session_row(&replay).await.unwrap().awaiting_totp,
        "the replaying session stays half-authenticated"
    );
    assert!(fx.identify_token(&replay).await.is_none(), "so it grants nothing");
    assert_eq!(fx.row("alice").await.totp_last_step, Some(spent), "the guard didn't move");
}

#[tokio::test]
async fn disabling_2fa_clears_the_replay_guard() {
    // A stale step would outlive the secret and silently reject the first codes of a re-enrolment, for
    // as long as it took the clock to pass the old ceiling.
    let fx = Fx::new().await;
    fx.user("alice").await;
    let secret = fx.enable_totp("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);

    // Spend a step through a real login so the guard is genuinely set.
    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let pending = res.session_token(fx.auth.session_cookie_name()).unwrap();
    fx.post(
        "/login/totp",
        &form(&[("code", &totp::current_code(&secret))]),
        Some(&fx.cookie(&pending)),
    )
    .await;
    assert!(fx.row("alice").await.totp_last_step.is_some(), "guard set by the login");

    let res = fx.post("/profile/totp/disable", &reauth_form(&[]), Some(&cookie)).await;
    assert_eq!(res.status, StatusCode::OK);
    let row = fx.row("alice").await;
    assert!(row.totp_secret.is_none(), "2FA off");
    assert!(row.totp_last_step.is_none(), "and the replay guard cleared with it");
}

#[tokio::test]
async fn totp_enrolment_only_activates_on_a_matching_code() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);

    // Starting enrolment stores a *pending* secret — 2FA is not on yet.
    let setup = fx.get("/profile/totp", Some(&cookie)).await;
    assert_eq!(setup.status, StatusCode::OK);
    let pending = fx.row("alice").await.totp_pending.expect("pending secret stored");
    assert!(fx.row("alice").await.totp_secret.is_none(), "enrolment must not activate on its own");

    // A wrong code re-shows the form and leaves 2FA off.
    let res = fx.post("/profile/totp", &reauth_form(&[("code", "000000")]), Some(&cookie)).await;
    assert!(res.body.contains("didn't match"), "expected the retry form: {}", res.body);
    let row = fx.row("alice").await;
    assert!(row.totp_secret.is_none(), "a wrong code must not enable 2FA");
    assert_eq!(row.totp_pending.as_deref(), Some(pending.as_str()), "same pending secret is kept");

    // Control: the matching code promotes it.
    let res = fx.post("/profile/totp", &reauth_form(&[("code", &totp::current_code(&pending))]), Some(&cookie)).await;
    assert_eq!(res.status, StatusCode::OK);
    let row = fx.row("alice").await;
    assert_eq!(row.totp_secret.as_deref(), Some(pending.as_str()));
    assert!(row.totp_pending.is_none(), "the pending secret is consumed");
}

#[tokio::test]
async fn totp_enrolment_post_without_a_pending_secret_does_nothing() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);

    let res = fx.post("/profile/totp", &reauth_form(&[("code", "000000")]), Some(&cookie)).await;
    res.assert_redirect("/profile");
    let row = fx.row("alice").await;
    assert!(row.totp_secret.is_none() && row.totp_pending.is_none());
}

#[tokio::test]
async fn enrolment_page_never_leaks_another_users_secret() {
    // /profile/totp mints a secret for *the caller*; the QR/otpauth URL must be bound to their name.
    let fx = Fx::new().await;
    fx.user("alice").await;
    fx.user("mallory").await;
    let mallorys = fx.enable_totp("mallory").await;

    let res = fx.get("/profile/totp", Some(&fx.cookie(&fx.session_for("alice").await))).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(!res.body.contains(&mallorys), "another user's secret must never be rendered");
    assert!(res.body.contains("alice"), "the otpauth URL is for the caller");
}

// ===================== Profile pages =====================

/// Every profile route, with a body where one is needed. Used to sweep the anonymous case.
fn profile_routes(other_id: i32) -> Vec<(&'static str, String, String)> {
    vec![
        ("GET", "/profile".into(), String::new()),
        ("POST", "/profile".into(), form(&[
            ("current_password", PW),
            ("new_password", OTHER_PW),
            ("confirm_password", OTHER_PW),
        ])),
        ("GET", "/profile/totp".into(), String::new()),
        ("POST", "/profile/totp".into(), form(&[("code", "000000")])),
        ("POST", "/profile/totp/disable".into(), String::new()),
        ("GET", format!("/profile/{other_id}"), String::new()),
        ("POST", format!("/profile/{other_id}"), form(&[
            ("new_password", OTHER_PW),
            ("confirm_password", OTHER_PW),
        ])),
        ("POST", format!("/profile/{other_id}/totp/disable"), String::new()),
    ]
}

#[tokio::test]
async fn anonymous_and_bogus_sessions_reach_no_profile_route() {
    let fx = Fx::new().await;
    let victim = fx.user("victim").await;
    let victim_secret = fx.enable_totp("victim").await;
    let expired = create_session_row(&fx.db, victim, now_secs() - 1, false).await;
    let pending = create_session_row(&fx.db, victim, now_secs() + 60, true).await;

    for cookie in [None, Some(fx.cookie("deadbeef")), Some(fx.cookie(&expired)), Some(fx.cookie(&pending))] {
        let c = cookie.as_deref();
        for (method, path, body) in profile_routes(victim) {
            let res = match method {
                "GET" => fx.get(&path, c).await,
                _ => fx.post(&path, &body, c).await,
            };
            assert!(
                res.status.is_redirection() && res.location() == Some("/login"),
                "{method} {path} with cookie {cookie:?} must redirect to the login page, got {}",
                res.status
            );
        }
    }
    // Nothing was touched along the way.
    let row = fx.row("victim").await;
    assert!(fx.password_works("victim", PW).await, "victim's password must be unchanged");
    assert_eq!(row.totp_secret.as_deref(), Some(victim_secret.as_str()), "2FA still enabled");
}

#[tokio::test]
async fn password_change_requires_the_current_password() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);

    for (current, what) in [("", "empty"), (OTHER_PW, "wrong"), (&PW.to_uppercase(), "wrong case")] {
        let res = fx
            .post(
                "/profile",
                &form(&[
                    ("current_password", current),
                    ("new_password", OTHER_PW),
                    ("confirm_password", OTHER_PW),
                ]),
                Some(&cookie),
            )
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{what} current password must be rejected");
        assert!(res.body.contains("Current password is incorrect"));
        assert!(fx.password_works("alice", PW).await, "{what}: the old password must still work");
        assert!(!fx.password_works("alice", OTHER_PW).await, "{what}: the new one must not be set");
    }
}

#[tokio::test]
async fn password_change_rejects_an_empty_or_mismatched_new_password() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);

    for (new, confirm, what) in
        [("", "", "empty"), ("", OTHER_PW, "empty with confirm"), (OTHER_PW, "typo", "mismatch")]
    {
        let res = fx
            .post(
                "/profile",
                &form(&[
                    ("current_password", PW),
                    ("new_password", new),
                    ("confirm_password", confirm),
                ]),
                Some(&cookie),
            )
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{what} must be rejected");
        assert!(fx.password_works("alice", PW).await, "{what}: password unchanged");
        assert!(
            !fx.row("alice").await.password_hash.is_empty(),
            "{what}: the hash must never be blanked (an empty hash verifies nothing but is a footgun)"
        );
    }
    // Control: a valid pair does change it.
    let res = fx
        .post(
            "/profile",
            &form(&[
                ("current_password", PW),
                ("new_password", OTHER_PW),
                ("confirm_password", OTHER_PW),
            ]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(fx.password_works("alice", OTHER_PW).await);
    assert!(!fx.password_works("alice", PW).await, "the old password must stop working");
}

/// Enrol `username` in 2FA through the real pages and return `(active secret, recovery codes)` — the
/// only way to obtain the codes, since they're shown once and hashed on the way in.
async fn enrol_with_codes(fx: &Fx, username: &str, cookie: &str) -> (String, Vec<String>) {
    assert_eq!(fx.get("/profile/totp", Some(cookie)).await.status, StatusCode::OK);
    let pending = fx.row(username).await.totp_pending.expect("pending secret");
    let res = fx
        .post("/profile/totp", &reauth_form(&[("code", &totp::current_code(&pending))]), Some(cookie))
        .await;
    assert_eq!(res.status, StatusCode::OK, "enrolment: {}", res.body);
    // Scrape the displayed codes out of the one page that ever shows them.
    let codes: Vec<String> = res
        .body
        .split("<code>")
        .skip(1)
        .filter_map(|s| s.split("</code>").next())
        .map(recovery::normalize)
        .filter(|c| c.len() == 10)
        .collect();
    assert_eq!(codes.len(), recovery::SET_SIZE, "a full set is shown once: {}", res.body);
    (pending, codes)
}

#[tokio::test]
async fn enrolment_issues_recovery_codes_shown_once_and_stored_hashed() {
    let fx = Fx::new().await;
    let id = fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    let (_secret, codes) = enrol_with_codes(&fx, "alice", &cookie).await;

    assert_eq!(recovery::remaining(&fx.db, id).await, recovery::SET_SIZE as u64);
    // Stored hashed: no row contains a code, so a database read is not a way in.
    let rows = recovery::entity::Entity::find().all(&fx.db).await.expect("query");
    assert_eq!(rows.len(), recovery::SET_SIZE);
    for row in &rows {
        assert_eq!(row.code_hash.len(), 64, "sha-256 hex");
        assert!(row.used_at.is_none(), "a fresh set is unused");
        assert!(!codes.iter().any(|c| row.code_hash.contains(c)), "no plaintext in the row");
    }
    // Revisiting the profile shows the count, never the codes again.
    let page = fx.get("/profile", Some(&cookie)).await;
    assert!(page.body.contains("Recovery codes"), "the section is there");
    assert!(page.body.contains("10 unused codes"), "with a count: {}", page.body);
    for c in &codes {
        assert!(!page.body.contains(c), "a code must never be shown twice");
    }
}

#[tokio::test]
async fn a_recovery_code_completes_a_login_once() {
    // The whole point: the authenticator is gone, and this is the way back in.
    let fx = Fx::new().await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    let (_secret, codes) = enrol_with_codes(&fx, "alice", &cookie).await;

    // Password gets you to the second-factor step, as usual.
    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    res.assert_redirect("/login/totp");
    let pending = res.session_token(fx.auth.session_cookie_name()).unwrap();

    // A recovery code completes it — landing on the profile, since re-enrolling is the next thing they
    // need — and the session id rotates just as it does for a code.
    let res = fx
        .post(
            "/login/totp",
            &form(&[("recovery_code", &recovery::display(&codes[0]))]),
            Some(&fx.cookie(&pending)),
        )
        .await;
    res.assert_redirect("/profile");
    let token = res.session_token(fx.auth.session_cookie_name()).expect("a session cookie");
    assert_ne!(token, pending, "the session id must still rotate");
    assert_eq!(fx.identify_token(&token).await.map(|w| w.username), Some("alice".into()));
    assert_eq!(recovery::remaining(&fx.db, fx.row("alice").await.id).await, 9, "one spent");

    // The same code a second time is refused, and 2FA stays on.
    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let pending = res.session_token(fx.auth.session_cookie_name()).unwrap();
    let res = fx
        .post("/login/totp", &form(&[("recovery_code", &codes[0])]), Some(&fx.cookie(&pending)))
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "a spent code must not work twice");
    assert!(fx.identify_token(&pending).await.is_none(), "and grants nothing");
    assert!(fx.row("alice").await.has_totp(), "using a code does not turn 2FA off");
    assert_eq!(recovery::remaining(&fx.db, fx.row("alice").await.id).await, 9, "no further spend");
}

#[tokio::test]
async fn a_wrong_recovery_code_is_refused_and_costs_an_attempt() {
    // A recovery code is a credential, so guessing at one has to be braked like guessing a password.
    let fx = Fx::with_lockout(Lockout { username_after: 3, ..Lockout::default() }).await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    let (_secret, codes) = enrol_with_codes(&fx, "alice", &cookie).await;

    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let pending = res.session_token(fx.auth.session_cookie_name()).unwrap();

    // An **empty** submission presents no credential, so it is refused *without* costing an attempt —
    // otherwise a stray double-submit, or a forged post carrying a token, would grief the real user.
    for empty in ["", "----", "  "] {
        let res = fx
            .post("/login/totp", &form(&[("recovery_code", empty)]), Some(&fx.cookie(&pending)))
            .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{empty:?} is refused");
        assert!(fx.lockout_row("alice").await.is_none(), "{empty:?} must not be counted");
    }

    // Three *actual* wrong guesses, which is the configured limit.
    for bad in ["not-a-code", "abcde-fghij", "zzzzz-zzzzz"] {
        let res = fx
            .post("/login/totp", &form(&[("recovery_code", bad)]), Some(&fx.cookie(&pending)))
            .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{bad:?} must be refused");
        assert!(fx.identify_token(&pending).await.is_none());
    }
    // Those attempts were counted, so the account is now locked — even against a *valid* code.
    let res = fx
        .post("/login/totp", &form(&[("recovery_code", &codes[0])]), Some(&fx.cookie(&pending)))
        .await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS, "guessing must be braked: {}", res.body);
    assert_eq!(
        recovery::remaining(&fx.db, fx.row("alice").await.id).await,
        recovery::SET_SIZE as u64,
        "and a locked-out attempt must not spend a code"
    );
}

#[tokio::test]
async fn recovery_codes_are_bound_to_one_account() {
    // The stored hash is domain-separated by user id, so a code (or a lifted row) can't be replayed
    // against a different account.
    let fx = Fx::new().await;
    fx.user("alice").await;
    fx.user("bob").await;
    let alice_cookie = fx.cookie(&fx.session_for("alice").await);
    let bob_cookie = fx.cookie(&fx.session_for("bob").await);
    let (_, alice_codes) = enrol_with_codes(&fx, "alice", &alice_cookie).await;
    let (_, bob_codes) = enrol_with_codes(&fx, "bob", &bob_cookie).await;
    assert!(alice_codes.iter().all(|c| !bob_codes.contains(c)), "different sets");

    // Bob's second-factor step, with one of Alice's codes.
    let res = fx.post("/login", &form(&[("username", "bob"), ("password", PW)]), None).await;
    let pending = res.session_token(fx.auth.session_cookie_name()).unwrap();
    let res = fx
        .post("/login/totp", &form(&[("recovery_code", &alice_codes[0])]), Some(&fx.cookie(&pending)))
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "another account's code must not work");
    let alice_id = fx.row("alice").await.id;
    assert_eq!(recovery::remaining(&fx.db, alice_id).await, 10, "and must not be spent");
}

#[tokio::test]
async fn regenerating_replaces_the_set_and_needs_re_authentication() {
    let fx = Fx::new().await;
    let id = fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    let (_secret, old) = enrol_with_codes(&fx, "alice", &cookie).await;

    // A new set is a new way in, so an intruder holding the session must not be able to mint one.
    for (body, what) in [(form(&[]), "no confirmation"), (form(&[("current_password", "nope")]), "a wrong one")] {
        let res = fx.post("/profile/totp/recovery", &body, Some(&cookie)).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "regenerating with {what} must be refused");
    }
    // The old set is untouched by those refusals.
    assert_eq!(recovery::remaining(&fx.db, id).await, 10);

    let res = fx.post("/profile/totp/recovery", &reauth_form(&[]), Some(&cookie)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let new: Vec<String> = res
        .body
        .split("<code>")
        .skip(1)
        .filter_map(|s| s.split("</code>").next())
        .map(recovery::normalize)
        .filter(|c| c.len() == 10)
        .collect();
    assert_eq!(new.len(), recovery::SET_SIZE, "a full new set");
    assert!(new.iter().all(|c| !old.contains(c)), "a different set");
    assert_eq!(recovery::remaining(&fx.db, id).await, 10, "exactly one set exists");

    // An old code is dead — which is the point of regenerating when you think they leaked.
    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let pending = res.session_token(fx.auth.session_cookie_name()).unwrap();
    let res = fx
        .post("/login/totp", &form(&[("recovery_code", &old[0])]), Some(&fx.cookie(&pending)))
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "a superseded code must not work");
    // …and a new one is alive.
    let res = fx
        .post("/login/totp", &form(&[("recovery_code", &new[0])]), Some(&fx.cookie(&pending)))
        .await;
    res.assert_redirect("/profile");
}

#[tokio::test]
async fn turning_2fa_off_destroys_the_recovery_codes() {
    // They are a way past a second factor; with no second factor they are just a second password, and a
    // later re-enrolment must not inherit a set the user threw away with their old phone.
    let fx = Fx::new().await;
    let id = fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    let (_secret, codes) = enrol_with_codes(&fx, "alice", &cookie).await;

    let res = fx.post("/profile/totp/disable", &reauth_form(&[]), Some(&cookie)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(recovery::remaining(&fx.db, id).await, 0, "the set is gone");
    assert!(
        recovery::entity::Entity::find().all(&fx.db).await.unwrap().is_empty(),
        "rows deleted, not merely marked"
    );
    // A manager's disable clears them too.
    let fx2 = Fx::with(|a| a.admin_group("admin")).await;
    fx2.user_in("boss", "admin").await;
    let victim = fx2.user("victim").await;
    let vcookie = fx2.cookie(&fx2.session_for("victim").await);
    enrol_with_codes(&fx2, "victim", &vcookie).await;
    let bcookie = fx2.cookie(&fx2.session_for("boss").await);
    let res = fx2
        .post(&format!("/profile/{victim}/totp/disable"), &reauth_form(&[]), Some(&bcookie))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(recovery::remaining(&fx2.db, victim).await, 0, "cleared by the manager path too");
    let _ = codes;
}

#[tokio::test]
async fn a_recovery_code_does_not_satisfy_re_authentication() {
    // Deliberate (§5i): a recovery code gets you *in*, it doesn't authorise entrenching. Otherwise one
    // leaked code would be both a login and a licence to remove the second factor it bypassed — and the
    // password already covers the lost-authenticator case for re-auth.
    let fx = Fx::new().await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    let (_secret, codes) = enrol_with_codes(&fx, "alice", &cookie).await;

    for field in ["totp_code", "recovery_code", "current_password"] {
        let res = fx
            .post("/profile/totp/disable", &form(&[(field, &codes[0])]), Some(&cookie))
            .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "a recovery code in {field} must not confirm");
        assert!(fx.row("alice").await.has_totp(), "2FA still on");
    }
    assert_eq!(
        recovery::remaining(&fx.db, fx.row("alice").await.id).await,
        recovery::SET_SIZE as u64,
        "and no code was consumed by the attempt"
    );
}

#[tokio::test]
async fn disabling_your_own_2fa_needs_re_authentication() {
    // The first thing an intruder holding a stolen session does is remove the second factor. A live
    // session is not evidence that its owner is at the keyboard, so this asks again.
    let fx = Fx::new().await;
    fx.user("alice").await;
    fx.enable_totp("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);

    for (body, what) in [
        (form(&[]), "nothing offered"),
        (form(&[("current_password", "")]), "an empty password"),
        (form(&[("current_password", OTHER_PW)]), "the wrong password"),
        (form(&[("totp_code", "000000")]), "a wrong code"),
        (form(&[("totp_code", "")]), "an empty code"),
    ] {
        let res = fx.post("/profile/totp/disable", &body, Some(&cookie)).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{what} must not disable 2FA");
        assert!(fx.row("alice").await.has_totp(), "{what}: 2FA must still be on");
    }
    // Control: the right password does it.
    let res = fx.post("/profile/totp/disable", &reauth_form(&[]), Some(&cookie)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(!fx.row("alice").await.has_totp(), "2FA is off");
}

#[tokio::test]
async fn a_fresh_totp_code_re_authenticates_and_is_spent_doing_so() {
    // A code is *better* evidence than a password — a browser may have filled the password in for
    // whoever is sitting there. It must be single-use here too, or one captured code would wave through
    // both a sensitive action and a login.
    let fx = Fx::new().await;
    fx.user("alice").await;
    let secret = fx.enable_totp("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    let code = totp::current_code(&secret);

    // Enrol over the top of the existing 2FA, confirming with a code from the *outgoing* authenticator.
    let setup = fx.get("/profile/totp", Some(&cookie)).await;
    assert_eq!(setup.status, StatusCode::OK);
    let pending = fx.row("alice").await.totp_pending.expect("pending secret");
    let res = fx
        .post(
            "/profile/totp",
            &form(&[("code", &totp::current_code(&pending)), ("totp_code", &code)]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "a code re-authenticates: {}", res.body);
    assert_eq!(fx.row("alice").await.totp_key(), Some(pending.as_str()), "the new secret is active");

    // That code is now spent: it can't re-authenticate a second action…
    let res = fx.post("/profile/totp/disable", &form(&[("totp_code", &code)]), Some(&cookie)).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "a spent code must not confirm again");
    assert!(fx.row("alice").await.has_totp(), "2FA still on");
    // …and the guard has moved past it, which is what makes that true.
    assert!(fx.row("alice").await.totp_last_step.is_some(), "the step was recorded");
}

#[tokio::test]
async fn enrolling_2fa_needs_re_authentication() {
    // Otherwise an intruder enrols *their own* authenticator, which doesn't merely persist their access
    // — it locks the real user out, because login then demands a code only the intruder can produce.
    let fx = Fx::new().await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    assert_eq!(fx.get("/profile/totp", Some(&cookie)).await.status, StatusCode::OK);
    let pending = fx.row("alice").await.totp_pending.expect("pending secret");

    // A correct code for the pending secret proves possession of a device — not that the account is
    // theirs. Without the password it isn't enough.
    let res = fx
        .post("/profile/totp", &form(&[("code", &totp::current_code(&pending))]), Some(&cookie))
        .await;
    assert!(res.body.contains("Confirm"), "expected the confirm prompt: {}", res.body);
    assert!(fx.row("alice").await.totp_secret.is_none(), "2FA must not be enabled");
    assert_eq!(
        fx.row("alice").await.totp_pending.as_deref(),
        Some(pending.as_str()),
        "the same enrolment is still pending, so the user can finish it"
    );

    // Control: same code, with the password.
    let res = fx
        .post(
            "/profile/totp",
            &reauth_form(&[("code", &totp::current_code(&pending))]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(fx.row("alice").await.has_totp(), "2FA is on");
}

#[tokio::test]
async fn manager_actions_need_the_managers_own_re_authentication() {
    // These two are what a stolen *manager* session is worth: reset any password (and then log in as
    // that user), or strip anyone's second factor. Both now ask the manager to prove they're present.
    let fx = Fx::with(|a| a.admin_group("admin")).await;
    fx.user_in("boss", "admin").await;
    let victim = fx.user("victim").await;
    fx.enable_totp("victim").await;
    let cookie = fx.cookie(&fx.session_for("boss").await);

    for (body, what) in [
        (form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]), "no confirmation"),
        (
            form(&[
                ("new_password", OTHER_PW),
                ("confirm_password", OTHER_PW),
                ("current_password", "wrong-one"),
            ]),
            "a wrong confirmation",
        ),
    ] {
        let res = fx.post(&format!("/profile/{victim}"), &body, Some(&cookie)).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "reset with {what} must be refused");
        assert!(fx.password_works("victim", PW).await, "{what}: the old password still works");
        assert!(!fx.password_works("victim", OTHER_PW).await, "{what}: the new one wasn't set");
    }
    for (body, what) in [(form(&[]), "no confirmation"), (form(&[("current_password", "x")]), "a wrong one")] {
        let res = fx.post(&format!("/profile/{victim}/totp/disable"), &body, Some(&cookie)).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "2FA disable with {what} must be refused");
        assert!(fx.row("victim").await.has_totp(), "{what}: the victim keeps their second factor");
    }
    // Controls: with the manager's own password, both go through.
    let res = fx
        .post(
            &format!("/profile/{victim}/totp/disable"),
            &reauth_form(&[]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(!fx.row("victim").await.has_totp());
    let res = fx
        .post(
            &format!("/profile/{victim}"),
            &reauth_form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(fx.password_works("victim", OTHER_PW).await);
}

#[tokio::test]
async fn an_account_with_no_local_factor_is_not_challenged() {
    // An SSO account has neither password nor local 2FA, so there is nothing to ask it for. Refusing
    // instead would lock every SSO administrator out of the manager pages permanently — a documented
    // limit (§5h), not an oversight: re-auth through the identity provider is the real answer.
    let fx = Fx::with(|a| a.admin_group("admin")).await;
    fx.user_in("boss", "admin").await;
    fx.make_sso("boss", "okta").await;
    // An SSO account's password hash is what `create_user` left; blank it, as a real SSO account has.
    fx.update_user("boss", |am| am.password_hash = Set(String::new())).await;
    let victim = fx.user("victim").await;
    let cookie = fx.cookie(&fx.session_for("boss").await);

    let res = fx
        .post(
            &format!("/profile/{victim}"),
            &form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "an SSO manager can still work: {}", res.body);
    assert!(fx.password_works("victim", OTHER_PW).await);

    // And the public API says so, which is what an app should key its own UI hint off.
    let who = fx.identify_token(&fx.session_for("boss").await).await.expect("identity");
    assert!(!fx.auth.can_reauthenticate(&who).await, "nothing to challenge with");
    assert!(fx.auth.reauthenticate(&who, "", "").await.is_ok(), "so re-auth passes");
}

#[tokio::test]
async fn the_reauthenticate_api_accepts_a_password_or_a_code_and_nothing_else() {
    // The surface an app gates its *own* sensitive routes with (`examples/auth` uses it for one).
    let fx = Fx::new().await;
    fx.user("alice").await;
    let who = fx.identify_token(&fx.session_for("alice").await).await.expect("identity");

    assert!(fx.auth.can_reauthenticate(&who).await, "a local account can be challenged");
    assert!(fx.auth.reauthenticate(&who, PW, "").await.is_ok(), "the current password");
    for (pw, code, what) in [
        ("", "", "nothing"),
        (OTHER_PW, "", "the wrong password"),
        (&PW.to_uppercase(), "", "the right password in the wrong case"),
        ("", "000000", "a code when the account has no 2FA"),
    ] {
        assert!(
            fx.auth.reauthenticate(&who, pw, code).await.is_err(),
            "{what} must not re-authenticate"
        );
    }

    // With 2FA on, a current code works and a stale one doesn't.
    let secret = fx.enable_totp("alice").await;
    assert!(fx.auth.reauthenticate(&who, "", &totp::current_code(&secret)).await.is_ok());
    assert!(
        fx.auth.reauthenticate(&who, "", &totp::current_code(&secret)).await.is_err(),
        "the same code twice is a replay, even here"
    );
    assert!(fx.auth.reauthenticate(&who, PW, "").await.is_ok(), "the password still works");
}

#[tokio::test]
async fn the_password_policy_applies_to_the_self_service_page() {
    // On by default: a weak password is refused, and refused *without writing* — the old one still works.
    let fx = Fx::new().await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);

    for (weak, why) in [
        (WEAK_PW, "too short and a common value"),
        ("shortish", "under twelve characters"),
        ("passwordpassword", "a common value doubled"),
        ("abcdef-quintessence", "contains a run"),
        ("alice-in-wonderland", "contains the username"),
    ] {
        let res = fx
            .post(
                "/profile",
                &form(&[
                    ("current_password", PW),
                    ("new_password", weak),
                    ("confirm_password", weak),
                ]),
                Some(&cookie),
            )
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{weak:?} ({why}) must be refused");
        assert!(fx.password_works("alice", PW).await, "{weak:?}: the old password must still work");
        assert!(!fx.password_works("alice", weak).await, "{weak:?}: must not be stored");
    }
    // Control: an acceptable password still goes through, so the policy isn't refusing everything.
    let res = fx
        .post(
            "/profile",
            &form(&[
                ("current_password", PW),
                ("new_password", OTHER_PW),
                ("confirm_password", OTHER_PW),
            ]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(fx.password_works("alice", OTHER_PW).await);
}

#[tokio::test]
async fn the_password_policy_applies_to_a_managers_reset_too() {
    // Otherwise the reset route is the way around the rule the user has to satisfy — and it's the route
    // with *no* current-password check, so it would be the easier way.
    let fx = Fx::with(|a| a.admin_group("admin")).await;
    fx.user_in("boss", "admin").await;
    let victim = fx.user("victim").await;
    let cookie = fx.cookie(&fx.session_for("boss").await);

    for weak in [WEAK_PW, "victim-of-fashion"] {
        let res = fx
            .post(
                &format!("/profile/{victim}"),
                &reauth_form(&[("new_password", weak), ("confirm_password", weak)]),
                Some(&cookie),
            )
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{weak:?} must be refused");
        assert!(!fx.password_works("victim", weak).await, "{weak:?}: must not be stored");
    }
    // …including the username check, which uses the **target's** name, not the manager's.
    let res = fx
        .post(
            &format!("/profile/{victim}"),
            &reauth_form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "control: a good password is accepted");
    assert!(fx.password_works("victim", OTHER_PW).await);
}

#[tokio::test]
async fn the_password_policy_can_be_loosened_replaced_or_switched_off() {
    // A library shouldn't dictate this, so all three ways out have to actually work.
    //
    // Each part checks its **rejections first and its acceptance last**: a successful change rotates the
    // caller's session (see `changing_your_password_signs_out_every_other_session`), so a POST made after
    // one with the same cookie would be answered as anonymous — a redirect, not the verdict under test.
    //
    // 1. Off entirely — `hunter2` is accepted, which is the app's choice to make.
    let fx = Fx::with(|a| a.password_policy(None)).await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    // The pair check is *not* part of the policy, so it still applies with the policy off.
    let res = fx
        .post(
            "/profile",
            &form(&[("current_password", PW), ("new_password", "a"), ("confirm_password", "b")]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "mismatched pair is still refused");
    let res = fx
        .post(
            "/profile",
            &form(&[
                ("current_password", PW),
                ("new_password", WEAK_PW),
                ("confirm_password", WEAK_PW),
            ]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "policy off: {}", res.body);
    assert!(fx.password_works("alice", WEAK_PW).await);

    // 2. A looser preset: eight characters, still screened for common values.
    let fx = Fx::with(|a| a.password_policy(PasswordPolicy::nist_minimum())).await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    // The screening survives the looser length…
    let res = fx
        .post(
            "/profile",
            &form(&[
                ("current_password", PW),
                ("new_password", "password1"),
                ("confirm_password", "password1"),
            ]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "a common value is still refused");
    // …while ten characters, which the default would refuse, is now fine.
    let mid = "mangosteen";
    let res = fx
        .post(
            "/profile",
            &form(&[("current_password", PW), ("new_password", mid), ("confirm_password", mid)]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "nist_minimum accepts ten characters: {}", res.body);
    assert!(fx.password_works("alice", mid).await);

    // 3. An app's own predicate, replacing the policy outright — and it sees the username.
    let fx = Fx::with(|a| {
        a.password_check(|pw, username| {
            if pw.contains(username) {
                Err("must not contain your name".into())
            } else if pw.len() < 4 {
                Err("must be at least 4 characters".into())
            } else {
                Ok(())
            }
        })
    })
    .await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    for (pw, ok) in [("xy", false), ("alice1234", false), ("wxyz", true)] {
        let res = fx
            .post(
                "/profile",
                &form(&[("current_password", PW), ("new_password", pw), ("confirm_password", pw)]),
                Some(&cookie),
            )
            .await;
        let expected = if ok { StatusCode::OK } else { StatusCode::BAD_REQUEST };
        assert_eq!(res.status, expected, "custom check on {pw:?}: {}", res.body);
        if ok {
            assert!(fx.password_works("alice", pw).await, "{pw:?} should have been stored");
        }
    }
}

#[tokio::test]
async fn the_password_policy_does_not_govern_the_library_helpers() {
    // `create_user` / `set_password` / `make_admin` are called by the app's own code — a seeder, a
    // break-glass CLI — not by a person typing into a form. The policy governs typed input; if it
    // governed these, a deployment could be left with no way to set a password at all.
    let fx = Fx::new().await;
    create_user(&fx.db, "seeded", WEAK_PW).await.expect("create_user ignores the policy");
    assert!(fx.password_works("seeded", WEAK_PW).await);
    set_password(&fx.db, "seeded", "short").await.expect("set_password ignores the policy");
    assert!(fx.password_works("seeded", "short").await);
    // And the account really can log in with it, so this isn't a write that produces a dead credential.
    let res = fx.post("/login", &form(&[("username", "seeded"), ("password", "short")]), None).await;
    res.assert_redirect("/");
}

#[tokio::test]
async fn changing_your_password_signs_out_every_other_session() {
    // The most common reason to change a password is "I think someone else is in my account", and a
    // cookie that outlives the credential that produced it defeats exactly that. So: the other sessions
    // die, and the caller's own id is rotated (their old cookie was one of the ones that might be copied).
    let fx = Fx::new().await;
    let id = fx.user("alice").await;
    let mine = fx.session_for("alice").await;
    let elsewhere = fx.session_for("alice").await; // a laptop, or the intruder
    let other_user = fx.user("bob").await;
    let bobs = fx.session_for("bob").await;

    let res = fx
        .post(
            "/profile",
            &form(&[
                ("current_password", PW),
                ("new_password", OTHER_PW),
                ("confirm_password", OTHER_PW),
            ]),
            Some(&fx.cookie(&mine)),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(fx.password_works("alice", OTHER_PW).await, "control: the password did change");

    assert!(fx.session_row(&elsewhere).await.is_none(), "the other session must be deleted");
    assert!(fx.identify_token(&elsewhere).await.is_none(), "and must authenticate nothing");
    assert!(fx.session_row(&mine).await.is_none(), "the caller's old id is rotated away too");
    // The caller is handed a working replacement, so they aren't logged out mid-page.
    let issued = res.session_token(fx.auth.session_cookie_name()).expect("a replacement cookie");
    assert_ne!(issued, mine);
    assert_eq!(fx.identify_token(&issued).await.map(|w| w.username), Some("alice".into()));
    // Nobody else is touched.
    assert!(fx.identify_token(&bobs).await.is_some(), "another user's session must be untouched");
    let _ = (id, other_user);
}

#[tokio::test]
async fn a_manager_reset_signs_the_target_out_everywhere() {
    // The other half: a manager resetting a password for a suspected-compromised account must not leave
    // the intruder's session live. Here there is no session to spare — all of the target's go.
    let fx = Fx::with(|a| a.admin_group("admin")).await;
    fx.user_in("boss", "admin").await;
    let victim = fx.user("victim").await;
    let victims = fx.session_for("victim").await;
    let bosses = fx.session_for("boss").await;

    let res = fx
        .post(
            &format!("/profile/{victim}"),
            &reauth_form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]),
            Some(&fx.cookie(&bosses)),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(fx.password_works("victim", OTHER_PW).await, "control: the reset happened");
    assert!(fx.session_row(&victims).await.is_none(), "the target's session must be deleted");
    assert!(fx.identify_token(&victims).await.is_none());
    assert!(fx.identify_token(&bosses).await.is_some(), "the manager stays signed in");
}

#[tokio::test]
async fn sign_out_other_sessions_keeps_the_caller_and_needs_a_csrf_token() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let mine = fx.session_for("alice").await;
    let elsewhere = fx.session_for("alice").await;
    fx.user("bob").await;
    let bobs = fx.session_for("bob").await;

    // The control that the feature is actually reachable: the profile page renders the form.
    let page = fx.get("/profile", Some(&fx.cookie(&mine))).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("/profile/sessions/revoke"), "the profile page must offer it");
    assert!(page.body.contains("Sign out other sessions"), "with a label: {}", page.body);

    // Unsafe route, so it is CSRF-checked like every other one — a cross-site post must not be able to
    // sign someone out of their devices.
    let res = fx.post_raw("/profile/sessions/revoke", "", Some(&fx.cookie(&mine))).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "no token, no revocation");
    assert!(fx.session_row(&elsewhere).await.is_some(), "and nothing was deleted");

    let res = fx.post("/profile/sessions/revoke", &form(&[]), Some(&fx.cookie(&mine))).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(fx.session_row(&elsewhere).await.is_none(), "the other session goes");
    assert!(fx.session_row(&mine).await.is_some(), "the caller's own session stays");
    assert!(fx.identify_token(&mine).await.is_some(), "so the page they're on keeps working");
    assert!(fx.identify_token(&bobs).await.is_some(), "another user is untouched");
}

#[tokio::test]
async fn a_plain_user_cannot_reset_another_users_password_or_2fa() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let victim = fx.user("victim").await;
    let victim_secret = fx.enable_totp("victim").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);

    for (method, path) in [
        ("GET", format!("/profile/{victim}")),
        ("POST", format!("/profile/{victim}")),
        ("POST", format!("/profile/{victim}/totp/disable")),
    ] {
        let body = form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]);
        let res = match method {
            "GET" => fx.get(&path, Some(&cookie)).await,
            _ => fx.post(&path, &body, Some(&cookie)).await,
        };
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{method} {path} must be forbidden");
    }
    let row = fx.row("victim").await;
    assert!(fx.password_works("victim", PW).await, "victim's password must be unchanged");
    assert!(!fx.password_works("victim", OTHER_PW).await);
    assert_eq!(row.totp_secret.as_deref(), Some(victim_secret.as_str()), "2FA must stay enabled");
}

#[tokio::test]
async fn group_membership_alone_is_not_manager_rights() {
    // profile_managers(["superadmin"]) — a member of some *other* group (even the admin group) is
    // not a profile manager once the manager set has been narrowed.
    let fx = Fx::with(|a| a.profile_managers(["superadmin"])).await;
    fx.user_in("editor", "editors").await;
    fx.user_in("admin", "admin").await;
    let victim = fx.user("victim").await;

    for who in ["editor", "admin"] {
        let token = fx.session_for(who).await;
        let res = fx.get(&format!("/profile/{victim}"), Some(&fx.cookie(&token))).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{who} must not manage other profiles");
        let identity = fx.identify_token(&token).await.unwrap();
        assert!(
            !fx.auth.can_manage_others(&identity),
            "{who}: can_manage_others must agree with the route"
        );
    }
    // Control: a member of the configured manager group may.
    fx.user_in("root", "superadmin").await;
    let cookie = fx.cookie(&fx.session_for("root").await);
    let res = fx.get(&format!("/profile/{victim}"), Some(&cookie)).await;
    assert_eq!(res.status, StatusCode::OK);
}

#[tokio::test]
async fn manager_reset_of_an_unknown_user_is_a_404() {
    let fx = Fx::new().await;
    fx.user_in("admin", "admin").await;
    let cookie = fx.cookie(&fx.session_for("admin").await);
    let body = form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]);

    for id in ["9999", "not-a-number", "1e3", "-1"] {
        assert_eq!(
            fx.get(&format!("/profile/{id}"), Some(&cookie)).await.status,
            StatusCode::NOT_FOUND,
            "GET /profile/{id}"
        );
        assert_eq!(
            fx.post(&format!("/profile/{id}"), &body, Some(&cookie)).await.status,
            StatusCode::NOT_FOUND,
            "POST /profile/{id}"
        );
        assert_eq!(
            fx.post(&format!("/profile/{id}/totp/disable"), "", Some(&cookie)).await.status,
            StatusCode::NOT_FOUND,
            "POST /profile/{id}/totp/disable"
        );
    }
}

#[tokio::test]
async fn the_manager_route_is_not_a_way_around_your_own_current_password() {
    // A manager pointing the no-current-password reset form at *themselves* is bounced to /profile,
    // so the current-password check can't be skipped (and a stolen session can't rotate the password).
    let fx = Fx::new().await;
    let admin = fx.user_in("admin", "admin").await;
    let cookie = fx.cookie(&fx.session_for("admin").await);

    let res = fx
        .post(
            &format!("/profile/{admin}"),
            &reauth_form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]),
            Some(&cookie),
        )
        .await;
    res.assert_redirect("/profile");
    assert!(fx.password_works("admin", PW).await, "password must be unchanged");
    assert!(!fx.password_works("admin", OTHER_PW).await);
}

#[tokio::test]
async fn a_password_reset_does_not_re_enable_a_disabled_account() {
    // `set_password` writes only the hash: the new password is stored, but a closed account stays
    // closed — a reset must not be a back door to re-activation.
    let fx = Fx::new().await;
    fx.user_in("admin", "admin").await;
    let disabled = fx.user("disabled").await;
    fx.deactivate("disabled").await;
    let cookie = fx.cookie(&fx.session_for("admin").await);

    let res = fx
        .post(
            &format!("/profile/{disabled}"),
            &reauth_form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    let row = fx.row("disabled").await;
    assert!(verify_password(&row.password_hash, OTHER_PW), "the new password is stored");
    assert!(!row.is_active, "the account must stay disabled");

    // …and it still can't log in with either password.
    for password in [PW, OTHER_PW] {
        let res =
            fx.post("/login", &form(&[("username", "disabled"), ("password", password)]), None).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "a disabled account never logs in");
    }
    // The same holds for the boot-time seeder.
    make_admin(&fx.db, "admin", "disabled", PW).await.unwrap();
    assert!(!fx.row("disabled").await.is_active, "make_admin must not re-activate either");
}

#[tokio::test]
async fn set_password_refuses_an_unknown_user_instead_of_creating_one() {
    // A typo'd username must not silently become a new login.
    let fx = Fx::new().await;
    assert!(set_password(&fx.db, "nobody", PW).await.is_err());
    assert_eq!(user::Entity::find().all(&fx.db).await.unwrap().len(), 0, "no account was created");
    // Control: it does reset an existing user.
    fx.user("alice").await;
    set_password(&fx.db, "alice", OTHER_PW).await.unwrap();
    assert!(fx.password_works("alice", OTHER_PW).await);
}

#[tokio::test]
async fn the_seeder_leaves_an_existing_admins_2fa_alone() {
    // `make_admin` runs on every start in the examples: it must never strip an enrolled authenticator.
    let fx = Fx::new().await;
    fx.user("admin").await;
    let secret = fx.enable_totp("admin").await;

    make_admin(&fx.db, "admin", "admin", PW).await.unwrap();
    let row = fx.row("admin").await;
    assert_eq!(row.totp_secret.as_deref(), Some(secret.as_str()), "2FA must survive re-seeding");
    let who = fx.identify_token(&fx.session_for("admin").await).await.unwrap();
    assert!(who.in_group("admin"), "group membership is ensured");
}

#[tokio::test]
async fn break_glass_reopens_a_locked_out_admin_but_refuses_sso_accounts() {
    let fx = Fx::new().await;
    fx.user("admin").await;
    fx.enable_totp("admin").await;
    fx.deactivate("admin").await; // disabled *and* holding an authenticator nobody has

    reset_admin_access(&fx.db, "admin", "admin", OTHER_PW).await.unwrap();
    let row = fx.row("admin").await;
    assert!(row.is_active, "break-glass re-activates");
    assert!(row.totp_secret.is_none() && row.totp_pending.is_none(), "break-glass clears 2FA");

    // The point of it: the admin can log in with the new password, with no second-factor step.
    let res = fx.post("/login", &form(&[("username", "admin"), ("password", OTHER_PW)]), None).await;
    res.assert_redirect("/"); // not /login/totp
    let token = res.session_token(fx.auth.session_cookie_name()).expect("session cookie");
    let who = fx.identify_token(&token).await.expect("logged in");
    assert!(who.in_group("admin"), "and lands in the admin group");
    assert!(!fx.password_works("admin", PW).await, "the old password is gone");

    // It refuses to graft a local password onto an SSO account (that would take it out of the IdP's
    // hands), and leaves the account untouched.
    fx.user("federated").await;
    fx.make_sso("federated", "okta").await;
    let err = reset_admin_access(&fx.db, "admin", "federated", OTHER_PW).await.unwrap_err();
    assert!(format!("{err}").contains("okta"), "the error names the provider: {err}");
    let row = fx.row("federated").await;
    assert!(row.is_sso() && fx.password_works("federated", PW).await, "untouched");
    assert_eq!(
        fx.post("/login", &form(&[("username", "federated"), ("password", OTHER_PW)]), None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn break_glass_creates_the_admin_when_there_is_none() {
    // A fresh database: the flag has to bootstrap the account, not just reset it.
    let fx = Fx::new().await;
    reset_admin_access(&fx.db, "admin", "root", PW).await.unwrap();
    let row = fx.row("root").await;
    assert!(row.is_active && row.totp_secret.is_none());
    let res = fx.post("/login", &form(&[("username", "root"), ("password", PW)]), None).await;
    res.assert_redirect("/");
    let who = fx.identify_token(&res.session_token(fx.auth.session_cookie_name()).unwrap()).await;
    assert!(who.expect("logged in").in_group("admin"));
}

#[tokio::test]
async fn an_sso_account_cannot_set_a_local_password_or_enrol_2fa() {
    let fx = Fx::new().await;
    fx.user("federated").await;
    fx.make_sso("federated", "okta").await;
    let cookie = fx.cookie(&fx.session_for("federated").await);

    // The profile page is a read-only notice…
    let res = fx.get("/profile", Some(&cookie)).await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(res.body.contains("single"), "expected the SSO notice: {}", res.body);
    assert!(!res.body.contains("current_password"), "no password form for an SSO account");

    // …and the write routes are refused, not just hidden.
    let res = fx
        .post(
            "/profile",
            &form(&[
                ("current_password", PW),
                ("new_password", OTHER_PW),
                ("confirm_password", OTHER_PW),
            ]),
            Some(&cookie),
        )
        .await;
    res.assert_redirect("/profile");
    assert!(fx.password_works("federated", PW).await, "the local hash must not be rewritten");
    assert!(!fx.password_works("federated", OTHER_PW).await);

    fx.get("/profile/totp", Some(&cookie)).await.assert_redirect("/profile");
    fx.post("/profile/totp", &form(&[("code", "000000")]), Some(&cookie))
        .await
        .assert_redirect("/profile");
    let row = fx.row("federated").await;
    assert!(row.totp_secret.is_none() && row.totp_pending.is_none(), "no local 2FA for SSO accounts");
}

#[tokio::test]
async fn a_manager_reset_cannot_turn_an_sso_account_into_a_password_login() {
    // A manager's reset is **refused** for an SSO target, the way the self-service page refuses itself:
    // there is no local password to set, so storing a hash would only leave a dead credential in the row
    // that reads like a real one. And the defence behind it must hold regardless — `verify_credentials`
    // refuses a password login for any `sso_provider` account — so even a hash written some other way
    // (an admin-panel edit, a CSV import) can't become a bypass.
    let fx = Fx::new().await;
    let sso = fx.user("federated").await;
    let before = fx.row("federated").await.password_hash;
    fx.make_sso("federated", "okta").await;
    fx.user_in("admin", "admin").await;
    let cookie = fx.cookie(&fx.session_for("admin").await);

    // The GET offers a notice, not a reset form — a form here could only ever error.
    let page = fx.get(&format!("/profile/{sso}"), Some(&cookie)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("okta"), "the provider is named: {}", page.body);
    assert!(!page.body.contains("new_password"), "no reset form for an SSO account: {}", page.body);

    let res = fx
        .post(
            &format!("/profile/{sso}"),
            &reauth_form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "the reset must be refused");
    assert!(res.body.contains("single sign-on"), "and say why: {}", res.body);
    let row = fx.row("federated").await;
    assert!(row.is_sso(), "the account stays external");
    assert_eq!(row.password_hash, before, "and its stored hash is untouched");

    for password in [PW, OTHER_PW] {
        let res =
            fx.post("/login", &form(&[("username", "federated"), ("password", password)]), None).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "SSO accounts never log in by password");
        assert!(res.session_token(fx.auth.session_cookie_name()).is_none());
    }

    // Control: a *local* target is still resettable through the same route.
    let local = fx.user("local").await;
    let res = fx
        .post(
            &format!("/profile/{local}"),
            &reauth_form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(fx.password_works("local", OTHER_PW).await, "the guard didn't break the normal path");
}

#[tokio::test]
async fn the_cleanup_helper_nulls_blank_columns() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    fx.user("bob").await;
    fx.update_user("alice", |am| {
        am.sso_provider = Set(Some(String::new()));
        am.totp_secret = Set(Some(String::new()));
        am.totp_pending = Set(Some(String::new()));
    })
    .await;
    fx.update_user("bob", |am| am.sso_provider = Set(Some("okta".into()))).await;

    let touched = normalize_blank_user_columns(&fx.db).await.unwrap();
    assert_eq!(touched, 3, "one row × three columns");
    let alice = fx.row("alice").await;
    assert!(alice.sso_provider.is_none() && alice.totp_secret.is_none() && alice.totp_pending.is_none());
    assert_eq!(fx.row("bob").await.sso_provider.as_deref(), Some("okta"), "real values untouched");
    // Idempotent: nothing left to do on a second run.
    assert_eq!(normalize_blank_user_columns(&fx.db).await.unwrap(), 0);
}

#[tokio::test]
async fn a_blank_totp_secret_is_no_second_factor() {
    // Same trap as a blank `sso_provider`, with a worse outcome: treating `Some("")` as "2FA on" would
    // demand a login code that no authenticator can produce — the account could never log in again.
    let fx = Fx::new().await;
    fx.user("alice").await;
    fx.update_user("alice", |am| {
        am.totp_secret = Set(Some(String::new()));
        am.totp_pending = Set(Some("   ".into()));
    })
    .await;
    let row = fx.row("alice").await;
    assert!(!row.has_totp(), "blank is not an active secret");
    assert_eq!(row.totp_key(), None);
    assert_eq!(row.pending_totp_key(), None, "blank is not an enrolment in progress");

    // Login completes in one step — no second factor demanded, no half-authenticated session.
    let res = fx.try_login("alice").await;
    res.assert_redirect("/");
    let token = res.session_token(fx.auth.session_cookie_name()).expect("logged in");
    assert!(!fx.session_row(&token).await.unwrap().awaiting_totp);
    assert!(fx.identify_token(&token).await.is_some());

    // The profile page offers to *set up* 2FA rather than to disable it…
    let page = fx.get("/profile", Some(&fx.cookie(&token))).await;
    assert!(page.body.contains("Set up 2FA"), "2FA reads as off: {}", page.body);
    assert!(!page.body.contains("Disable 2FA"));
    // …and a code posted against the blank pending secret can't activate anything.
    let res = fx.post("/profile/totp", &form(&[("code", "000000")]), Some(&fx.cookie(&token))).await;
    res.assert_redirect("/profile"); // "nothing in progress"
    assert!(!fx.row("alice").await.has_totp());

    // Control: a real secret does demand the second factor.
    let secret = fx.enable_totp("alice").await;
    assert_eq!(fx.row("alice").await.totp_key(), Some(secret.as_str()));
    fx.try_login("alice").await.assert_redirect("/login/totp");
}

#[tokio::test]
async fn a_blank_sso_provider_is_a_local_account() {
    // An admin form that leaves the nullable `sso_provider` column empty writes `""` — the account it
    // creates must still be an ordinary local one. Treating `Some("")` as "external" silently produced
    // accounts that could never log in and whose profile page offered nothing to change.
    let fx = Fx::new().await;
    fx.user("alice").await;
    fx.update_user("alice", |am| am.sso_provider = Set(Some(String::new()))).await;
    let row = fx.row("alice").await;
    assert!(!row.is_sso(), "blank is not a provider");
    assert_eq!(row.sso_key(), None);

    // …so password login works,
    let res = fx.try_login("alice").await;
    res.assert_redirect("/");
    let token = res.session_token(fx.auth.session_cookie_name()).expect("logged in");
    // …the profile page offers the password form rather than the read-only SSO notice,
    let page = fx.get("/profile", Some(&fx.cookie(&token))).await;
    assert!(page.body.contains("current_password"), "local password form: {}", page.body);
    assert!(!page.body.contains("single sign-on"));
    // …2FA enrolment is available,
    assert_eq!(fx.get("/profile/totp", Some(&fx.cookie(&token))).await.status, StatusCode::OK);
    // …and break-glass doesn't refuse it as an external account.
    reset_admin_access(&fx.db, "admin", "alice", OTHER_PW).await.unwrap();
    assert!(fx.password_works("alice", OTHER_PW).await);

    // Whitespace-only is blank too; a real key still means SSO.
    fx.update_user("alice", |am| am.sso_provider = Set(Some("   ".into()))).await;
    assert!(!fx.row("alice").await.is_sso(), "whitespace is not a provider");
    fx.update_user("alice", |am| am.sso_provider = Set(Some("okta".into()))).await;
    let row = fx.row("alice").await;
    assert!(row.is_sso() && row.sso_key() == Some("okta"));
    assert_eq!(
        fx.post("/login", &form(&[("username", "alice"), ("password", OTHER_PW)]), None).await.status,
        StatusCode::UNAUTHORIZED,
        "a real provider still refuses password login"
    );
}

// ===================== Attempt limiting (brute-force brake) =====================

impl Resp {
    /// The `Retry-After` value, which every 429 must carry.
    fn retry_after(&self) -> i64 {
        self.headers
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| panic!("a 429 must carry Retry-After: {:?}", self.headers))
    }

    /// Assert this is a lockout response: 429, a sane `Retry-After`, a message that says to come back
    /// later — and nothing that reveals whether the account exists.
    fn assert_locked_out(&self, window: i64) {
        assert_eq!(self.status, StatusCode::TOO_MANY_REQUESTS, "expected a lockout: {}", self.body);
        let retry = self.retry_after();
        assert!(retry >= 1 && retry <= window, "Retry-After {retry} outside 1..={window}");
        assert!(self.body.contains("Too many failed attempts"), "{}", self.body);
        assert!(!self.body.to_lowercase().contains("no such"), "no enumeration hint");
    }
}

/// A policy that locks an account after `after` failures for `secs`, with the address counter off —
/// so a test about accounts isn't also tripping the address budget.
fn by_account(after: u32, secs: i64) -> Lockout {
    Lockout { username_after: after, username_duration_secs: secs, ip_after: 0, ..Lockout::default() }
}

#[tokio::test]
async fn login_locks_the_account_after_the_configured_failures() {
    let fx = Fx::with_lockout(by_account(3, 900)).await;
    fx.user("alice").await;

    for i in 1..=3 {
        let res = fx.fail_login("alice", 1).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "failure {i} is a plain 401");
    }
    // The 4th attempt is refused *with the correct password* — the secret is never looked at.
    let res = fx.try_login("alice").await;
    res.assert_locked_out(900);
    assert!(res.session_token(fx.auth.session_cookie_name()).is_none(), "no session cookie");
    assert_eq!(session::Entity::find().all(&fx.db).await.unwrap().len(), 0, "no session row");
    assert!(fx.password_works("alice", PW).await, "and the account is otherwise untouched");
}

#[tokio::test]
async fn an_unknown_username_locks_the_same_way() {
    // Otherwise the lockout itself would reveal which accounts exist.
    let fx = Fx::with_lockout(by_account(2, 900)).await;
    fx.user("alice").await;
    fx.fail_login("ghost", 2).await;
    let ghost = fx.post("/login", &form(&[("username", "ghost"), ("password", "x")]), None).await;
    ghost.assert_locked_out(900);

    fx.fail_login("alice", 2).await;
    let alice = fx.try_login("alice").await;
    alice.assert_locked_out(900);
    assert_eq!(ghost.status, alice.status);
    assert_eq!(ghost.body, alice.body, "same response for a real and a made-up account");
}

#[tokio::test]
async fn a_lockout_is_per_account_and_case_cannot_dodge_it() {
    let fx = Fx::with_lockout(by_account(2, 900)).await;
    fx.user("alice").await;
    fx.user("bob").await;

    // Two failures as "alice", a third as "ALICE" — same row, so alice is locked…
    fx.fail_login("alice", 2).await;
    fx.post("/login", &form(&[("username", "ALICE"), ("password", "wrong")]), None)
        .await
        .assert_locked_out(900);
    fx.try_login("alice").await.assert_locked_out(900);
    // …while bob is unaffected.
    fx.try_login("bob").await.assert_redirect("/");
}

#[tokio::test]
async fn a_locked_account_records_nothing_so_the_lock_cannot_be_held_open() {
    // The row must keep the failure count and timestamp of the attempt that locked it; if further
    // attempts bumped `last_failure_at`, an attacker could keep someone locked out indefinitely.
    let fx = Fx::with_lockout(by_account(2, 900)).await;
    fx.user("alice").await;
    fx.fail_login("alice", 2).await;
    let locked_at = fx.lockout_row("alice").await.expect("row");

    for _ in 0..5 {
        fx.fail_login("alice", 1).await.assert_locked_out(900);
    }
    let after = fx.lockout_row("alice").await.expect("row");
    assert_eq!(after.failures, locked_at.failures, "count unchanged while locked");
    assert_eq!(after.last_failure_at, locked_at.last_failure_at, "expiry not pushed out");
}

#[tokio::test]
async fn a_successful_login_clears_the_accounts_failures() {
    let fx = Fx::with_lockout(by_account(3, 900)).await;
    fx.user("alice").await;

    fx.fail_login("alice", 2).await;
    fx.try_login("alice").await.assert_redirect("/"); // clears the row
    assert!(fx.lockout_row("alice").await.is_none(), "the row is gone, not just reset");
    // If the count had survived, the next two failures would lock the account.
    let res = fx.fail_login("alice", 2).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "the counter restarted: {}", res.body);
    fx.try_login("alice").await.assert_redirect("/");
}

#[tokio::test]
async fn the_totp_step_shares_the_accounts_bucket() {
    // The second factor is still an *unauthenticated* check — the session grants nothing until the
    // code is confirmed — and 6 digits are the most guessable secret we hold.
    let fx = Fx::with_lockout(by_account(3, 900)).await;
    fx.user("alice").await;
    let secret = fx.enable_totp("alice").await;

    let res = fx.try_login("alice").await;
    res.assert_redirect("/login/totp");
    let session = fx.cookie(&res.session_token(fx.auth.session_cookie_name()).unwrap());

    for _ in 0..3 {
        let res = fx.post("/login/totp", &form(&[("code", "000000")]), Some(&session)).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    }
    // A *correct* code is now refused too — 6 digits get the same brake as the password.
    let code = totp::current_code(&secret);
    let res = fx.post("/login/totp", &form(&[("code", &code)]), Some(&session)).await;
    res.assert_locked_out(900);
    assert!(fx.session_row(&session[session.find('=').unwrap() + 1..]).await.unwrap().awaiting_totp);
    // And because it's one bucket, password login is locked as well.
    fx.try_login("alice").await.assert_locked_out(900);
}

#[tokio::test]
async fn a_forged_post_cannot_spend_the_attempt_budget() {
    // If CSRF-rejected posts counted, any site could lock a user out of their account by making a
    // browser fire off a handful of cross-site logins.
    let fx = Fx::with_lockout(by_account(3, 900)).await;
    fx.user("alice").await;

    for _ in 0..20 {
        let res = fx
            .post_raw("/login", &form(&[("username", "alice"), ("password", "wrong")]), None)
            .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "no CSRF token → rejected before counting");
    }
    assert!(fx.lockout_row("alice").await.is_none(), "nothing was recorded");
    fx.try_login("alice").await.assert_redirect("/"); // not locked
}

#[tokio::test]
async fn authenticated_credential_checks_are_not_limited() {
    // Deliberate: the brake exists for *unauthenticated* brute force. Someone posting to /profile
    // already holds a session, which is a session-theft problem with its own mitigations — and if we
    // counted it, a stolen session could lock the real user out of logging in.
    let fx = Fx::with_lockout(by_account(3, 900)).await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    let wrong = form(&[
        ("current_password", OTHER_PW),
        ("new_password", "new-secret"),
        ("confirm_password", "new-secret"),
    ]);

    for _ in 0..10 {
        let res = fx.post("/profile", &wrong, Some(&cookie)).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "rejected, but never locked out");
    }
    assert!(fx.lockout_row("alice").await.is_none(), "no lockout row for an authenticated check");
    fx.try_login("alice").await.assert_redirect("/"); // login untouched
    assert!(fx.password_works("alice", PW).await, "and no password was changed");
}

#[tokio::test]
async fn enrolment_codes_are_not_limited_either() {
    // Also authenticated, and the code being guessed is the caller's *own* pending secret — there is
    // no other account to reach by guessing it.
    let fx = Fx::with_lockout(by_account(3, 900)).await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    fx.get("/profile/totp", Some(&cookie)).await; // mints the pending secret
    let pending = fx.row("alice").await.totp_pending.expect("pending secret");

    for _ in 0..10 {
        let res = fx.post("/profile/totp", &reauth_form(&[("code", "000000")]), Some(&cookie)).await;
        assert_eq!(res.status, StatusCode::OK, "a wrong code just re-shows the form");
    }
    assert!(fx.lockout_row("alice").await.is_none());
    // The right code still enrols; nothing was locked on the way.
    fx.post("/profile/totp", &reauth_form(&[("code", &totp::current_code(&pending))]), Some(&cookie)).await;
    assert!(fx.row("alice").await.has_totp(), "2FA enabled");
}

#[tokio::test]
async fn forwarded_headers_are_ignored_unless_the_app_trusts_a_proxy() {
    // The security-critical direction: unproxied, `X-Forwarded-For` is attacker-supplied, so a caller
    // must not be able to choose whose address gets locked out. Failures are counted against the peer.
    let fx = Fx::with_lockout(Lockout { ip_after: 2, trust_proxy: false, ..Lockout::default() }).await;
    fx.user("alice").await;

    for _ in 0..2 {
        fx.post_forwarded("9.9.9.9", "ghost", "wrong").await;
    }
    assert_eq!(fx.auth.ip_lockout().locked("9.9.9.9".parse().ok()).await, None, "spoof not counted");
    let peer = fx.auth.ip_lockout().locked("127.0.0.1".parse().ok()).await;
    assert!(peer.is_some(), "the socket peer was counted instead");
    // …so the lockout follows the real connection, whatever header it sent.
    fx.post_forwarded("1.2.3.4", "alice", PW).await.assert_locked_out(900);
}

#[tokio::test]
async fn a_trusted_proxy_makes_the_forwarded_hop_the_subject() {
    // The proxied deployment: one flag, and the library resolves the client itself.
    let fx = Fx::with_lockout(Lockout {
        username_after: 100,
        ip_after: 2,
        trust_proxy: true,
        ..Lockout::default()
    })
    .await;
    fx.user("alice").await;

    for _ in 0..2 {
        fx.post_forwarded("198.51.100.9", "ghost", "wrong").await;
    }
    assert!(fx.auth.ip_lockout().locked("198.51.100.9".parse().ok()).await.is_some());
    fx.post_forwarded("198.51.100.9", "alice", PW).await.assert_locked_out(900);
    // Another client behind the same proxy is untouched, and the proxy's own address was never counted.
    fx.post_forwarded("203.0.113.7", "alice", PW).await.assert_redirect("/");
    assert_eq!(fx.auth.ip_lockout().locked("127.0.0.1".parse().ok()).await, None, "peer not counted");
}

#[tokio::test]
async fn a_custom_resolver_overrides_the_built_in_one() {
    // For chains stranger than "one proxy sets X-Forwarded-For" — here a CDN's own header, with
    // `trust_proxy` left off to prove the override wins outright.
    let fx = Fx::build(
        Lockout { username_after: 100, ip_after: 2, trust_proxy: false, ..Lockout::default() },
        |a| {
            a.client_ip(|headers, _peer| {
                headers.get("cf-connecting-ip")?.to_str().ok()?.trim().parse().ok()
            })
        },
    )
    .await;
    fx.user("alice").await;

    for _ in 0..2 {
        fx.post_cdn("198.51.100.9", "ghost", "wrong").await;
    }
    assert!(fx.auth.ip_lockout().locked("198.51.100.9".parse().ok()).await.is_some());
    fx.post_cdn("198.51.100.9", "alice", PW).await.assert_locked_out(900);
    fx.post_cdn("203.0.113.7", "alice", PW).await.assert_redirect("/");
    assert_eq!(fx.auth.ip_lockout().locked("127.0.0.1".parse().ok()).await, None, "peer not counted");
}

#[tokio::test]
async fn per_ip_limiting_catches_username_spraying_when_the_peer_is_the_client() {
    // The default deployment: exposed directly, so the socket peer is the client and needs no wiring.
    let fx = Fx::with_lockout(Lockout {
        username_after: 100,
        ip_after: 3,
        ip_duration_secs: 900,
        ..Lockout::default()
    })
    .await;
    fx.user("alice").await;
    let attacker = "203.0.113.7:5000";

    for i in 0..3 {
        let res = fx
            .post_from(
                "/login",
                &form(&[("username", &format!("ghost{i}")), ("password", "wrong")]),
                None,
                attacker,
            )
            .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "spray {i}");
    }
    // A fourth attempt from that address is refused — even a *valid* login for an untouched account.
    let res = fx
        .post_from("/login", &form(&[("username", "alice"), ("password", PW)]), None, attacker)
        .await;
    res.assert_locked_out(900);
    assert!(res.session_token(fx.auth.session_cookie_name()).is_none());
    // Another address is unaffected, and so is the account itself.
    fx.post_from("/login", &form(&[("username", "alice"), ("password", PW)]), None, "198.51.100.9:443")
        .await
        .assert_redirect("/");
}

#[tokio::test]
async fn a_whitelisted_address_is_never_locked_out_however_it_arrives() {
    // The office range / monitoring probe case. The exemption has to hold for every way an address can
    // reach us — plain v4, real v6, and the IPv4-mapped form a dual-stack listener reports — and for
    // both the login route and the app's own surfaces, since both go through `IpLockout`.
    let allow = crate::net::parse_nets(&[
        "10.0.0.0/8".into(),
        "2001:db8::/32".into(),
        "::ffff:198.51.100.0/120".into(), // written mapped; must still match a plain v4 client
    ]);
    let fx = Fx::with_lockout(Lockout {
        username_after: 0, // isolate the address counter
        ip_after: 2,
        trust_proxy: true,
        ip_whitelist: allow,
        ..Lockout::default()
    })
    .await;
    fx.user("alice").await;
    let ips = fx.auth.ip_lockout();

    for exempt in ["10.9.9.9", "::ffff:10.9.9.9", "2001:db8::1", "198.51.100.9", "::ffff:198.51.100.9"] {
        let addr: std::net::IpAddr = exempt.parse().unwrap();
        assert!(ips.whitelisted(addr), "{exempt} is on the list");
        // Failures are neither counted nor checked, however many arrive…
        for _ in 0..5 {
            assert!(!ips.record_failure(Some(addr)).await, "{exempt} never trips");
            fx.post_forwarded(exempt, "ghost", "wrong").await;
        }
        assert_eq!(ips.locked(Some(addr)).await, None, "{exempt} is not locked");
        // …and a good login from there still works.
        fx.post_forwarded(exempt, "alice", PW).await.assert_redirect("/");
    }
    assert_eq!(
        lockout::ip_entity::Entity::find().all(&fx.db).await.unwrap().len(),
        0,
        "no rows were written for whitelisted addresses"
    );

    // An address outside every rule still locks, on the same two failures.
    for _ in 0..2 {
        fx.post_forwarded("203.0.113.7", "ghost", "wrong").await;
    }
    fx.post_forwarded("203.0.113.7", "alice", PW).await.assert_locked_out(900);
}

#[tokio::test]
async fn one_client_is_one_row_whether_it_arrives_mapped_or_plain() {
    // A dual-stack listener reports an IPv4 client as ::ffff:a.b.c.d while a proxy reports a.b.c.d.
    // Both must spend the same budget, or the limit is silently doubled.
    let fx = Fx::with_lockout(Lockout {
        username_after: 0,
        ip_after: 2,
        ..Lockout::default()
    })
    .await;
    let ips = fx.auth.ip_lockout();
    let mapped: std::net::IpAddr = "::ffff:203.0.113.7".parse().unwrap();
    let plain: std::net::IpAddr = "203.0.113.7".parse().unwrap();

    assert!(!ips.record_failure(Some(mapped)).await);
    assert!(ips.record_failure(Some(plain)).await, "the second failure trips — one shared row");
    assert!(ips.locked(Some(mapped)).await.is_some(), "locked when asked in mapped form");
    assert!(ips.locked(Some(plain)).await.is_some(), "and in plain form");
    let rows = lockout::ip_entity::Entity::find().all(&fx.db).await.unwrap();
    assert_eq!(rows.len(), 1, "one row");
    assert_eq!(rows[0].ip, "203.0.113.7", "stored canonicalized");
}

// --------- the app's own credential checks, through the same counters ---------

#[tokio::test]
async fn the_apps_own_checks_share_the_accounts_bucket_in_both_directions() {
    // The point of handing out the lockout handles: an account has *one* budget however it is reached.
    let fx = Fx::with_lockout(by_account(3, 900)).await;
    fx.user("alice").await;
    let usernames = fx.auth.username_lockout();

    // App-side failures lock the login form…
    for i in 1..=2 {
        assert!(!usernames.record_failure("alice").await, "failure {i} is under the limit");
    }
    assert!(usernames.record_failure("ALICE").await, "the 3rd trips it (and case is folded)");
    fx.try_login("alice").await.assert_locked_out(900);

    // …and login failures lock the app's endpoint.
    let fx = Fx::with_lockout(by_account(3, 900)).await;
    fx.user("bob").await;
    let usernames = fx.auth.username_lockout();
    assert_eq!(usernames.locked("bob").await, None, "no failures yet");
    fx.fail_login("bob", 3).await;
    let retry = usernames.locked("bob").await.expect("the app sees the login failures");
    assert!((1..=900).contains(&retry), "Retry-After {retry} inside the window");
    assert_eq!(usernames.locked("carol").await, None, "another account is untouched");
}

#[tokio::test]
async fn deleting_the_row_is_the_unlock() {
    // This is what an operator does in the admin panel — the entity is an ordinary table, so the
    // unlock is a gated, audited DELETE and needs no bespoke endpoint.
    let fx = Fx::with_lockout(by_account(2, 900)).await;
    fx.user("alice").await;
    fx.fail_login("alice", 2).await;
    fx.try_login("alice").await.assert_locked_out(900);

    lockout::username_entity::Entity::delete_by_id("alice".to_string())
        .exec(&fx.db)
        .await
        .expect("delete the lockout row");
    fx.try_login("alice").await.assert_redirect("/");
}

#[tokio::test]
async fn the_ip_counter_brakes_credentials_that_name_no_account() {
    // A bearer token carries no username, so the address is the only thing its failures can be
    // counted against — this is the app's path, with the address the app resolved.
    let fx = Fx::with_lockout(Lockout { ip_after: 3, ip_duration_secs: 900, ..Lockout::default() }).await;
    let ips = fx.auth.ip_lockout();
    let client: Option<std::net::IpAddr> = "198.51.100.9".parse().ok();

    for i in 1..=2 {
        assert!(!ips.record_failure(client).await, "failure {i} under the limit");
    }
    assert!(ips.record_failure(client).await, "the 3rd trips it");
    assert!(ips.locked(client).await.is_some());
    assert_eq!(ips.locked("198.51.100.10".parse().ok()).await, None, "another client is free");
    assert_eq!(ips.locked(None).await, None, "an unknown address can't be keyed on");
}

#[tokio::test]
async fn a_limit_of_zero_switches_a_counter_off_and_prune_clears_expired_rows() {
    let off = Fx::with_lockout(Lockout { username_after: 0, ip_after: 0, ..Lockout::default() }).await;
    off.user("alice").await;
    let res = off.fail_login("alice", 25).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "no lockout when disabled");
    assert!(off.lockout_row("alice").await.is_none(), "and nothing is written");
    off.try_login("alice").await.assert_redirect("/");

    // Pruning drops rows whose lockout has expired, and leaves live ones alone.
    let fx = Fx::with_lockout(by_account(2, 900)).await;
    fx.user("alice").await;
    fx.fail_login("alice", 2).await;
    let stale = lockout::username_entity::ActiveModel {
        username: Set("ghost".to_string()),
        failures: Set(9),
        last_failure_at: Set(now_secs() - 10_000),
    };
    stale.insert(&fx.db).await.expect("stale row");
    let removed = prune(&fx.db, &by_account(2, 900)).await.expect("prune");
    assert_eq!(removed, 1, "only the expired row went");
    assert!(fx.lockout_row("alice").await.is_some(), "the live lockout stays");
    fx.try_login("alice").await.assert_locked_out(900);
}

// ===================== CSRF (double-submit token) =====================

/// Every unsafe route `auth::routes()` serves, with a body that would otherwise succeed or at least
/// get past extraction. Used to sweep the CSRF failure modes.
fn unsafe_routes(other_id: i32) -> Vec<(String, String)> {
    vec![
        ("/login".into(), form(&[("username", "alice"), ("password", PW)])),
        ("/login/totp".into(), form(&[("code", "000000")])),
        (
            "/profile".into(),
            form(&[
                ("current_password", PW),
                ("new_password", OTHER_PW),
                ("confirm_password", OTHER_PW),
            ]),
        ),
        ("/profile/totp".into(), form(&[("code", "000000")])),
        ("/profile/totp/disable".into(), String::new()),
        ("/profile/sessions/revoke".into(), String::new()),
        (format!("/profile/{other_id}"), form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)])),
        (format!("/profile/{other_id}/totp/disable"), String::new()),
    ]
}

#[tokio::test]
async fn every_unsafe_auth_route_rejects_a_missing_or_mismatched_token() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let victim = fx.user("victim").await;
    let victim_secret = fx.enable_totp("victim").await;
    // A *fully authenticated manager* session: authorization would allow all of this. Only the missing
    // CSRF token stands in the way, which is exactly what's under test.
    fx.user_in("admin", "admin").await;
    let session = fx.cookie(&fx.session_for("admin").await);
    let cookie_name = fx.auth.csrf().cookie().to_string();
    let other = "b".repeat(64);

    for (path, body) in unsafe_routes(victim) {
        // Each of these is a request a cross-site attacker could actually make.
        let cases = [
            ("no token at all", body.clone(), session.clone()),
            (
                "cookie but no submitted token",
                body.clone(),
                format!("{session}; {cookie_name}={CSRF}"),
            ),
            (
                "submitted token but no cookie",
                format!("{body}&_csrf={CSRF}"),
                session.clone(),
            ),
            (
                "stale token (cookie rotated)",
                format!("{body}&_csrf={other}"),
                format!("{session}; {cookie_name}={CSRF}"),
            ),
            (
                "empty cookie and empty field",
                format!("{body}&_csrf="),
                format!("{session}; {cookie_name}="),
            ),
        ];
        for (what, body, cookie) in cases {
            let res = fx.post_raw(&path, &body, Some(&cookie)).await;
            assert_eq!(res.status, StatusCode::FORBIDDEN, "POST {path} with {what}");
            assert!(res.body.contains("Security check failed"), "POST {path}: {}", res.body);
            assert!(res.set_cookies().is_empty(), "POST {path} with {what}: sets no cookies");
        }
    }

    // Nothing happened: no password changed, no 2FA touched, no session created.
    assert!(fx.password_works("victim", PW).await && fx.password_works("admin", PW).await);
    assert!(!fx.password_works("victim", OTHER_PW).await);
    assert_eq!(fx.row("victim").await.totp_secret.as_deref(), Some(victim_secret.as_str()));
    assert!(fx.row("admin").await.totp_pending.is_none(), "no enrolment was started");
}

#[tokio::test]
async fn a_form_page_issues_the_token_and_the_matching_post_succeeds() {
    // The end-to-end MPA flow: GET the form (cookie + hidden field), post it back, it works.
    let fx = Fx::new().await;
    fx.user("alice").await;

    let page = fx.get("/login", None).await;
    let set = page
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(fx.auth.csrf().cookie()))
        .expect("the form page issues a token cookie")
        .to_string();
    assert!(!set.contains("HttpOnly"), "the UI's JS must be able to read it: {set}");
    assert!(set.contains("SameSite=Strict"), "{set}");
    let token = page.session_token(fx.auth.csrf().cookie()).expect("token value");
    assert!(
        page.body.contains(&format!(r#"name="_csrf" value="{token}""#)),
        "the form embeds the same token: {}",
        page.body
    );

    let res = fx
        .post_raw(
            "/login",
            &form(&[("username", "alice"), ("password", PW), ("_csrf", &token)]),
            Some(&format!("{}={token}", fx.auth.csrf().cookie())),
        )
        .await;
    res.assert_redirect("/");
    assert!(res.session_token(fx.auth.session_cookie_name()).is_some(), "logged in");
    // Login is a privilege change → the token is rotated with the session.
    let rotated = res.session_token(fx.auth.csrf().cookie()).expect("a fresh csrf cookie");
    assert_ne!(rotated, token, "the CSRF token must rotate at login");
}

#[tokio::test]
async fn a_second_factor_page_carries_a_token_and_logout_clears_the_cookie() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let secret = fx.enable_totp("alice").await;

    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let session = fx.cookie(&res.session_token(fx.auth.session_cookie_name()).unwrap());
    let totp_cookie = res.session_token(fx.auth.csrf().cookie()).expect("rotated at login");

    // The TOTP form embeds the current token, and the code post needs it.
    let page = fx.get("/login/totp", Some(&format!("{session}; {}={totp_cookie}", fx.auth.csrf().cookie()))).await;
    assert!(page.body.contains(&format!(r#"value="{totp_cookie}""#)), "{}", page.body);
    let bad = fx
        .post_raw("/login/totp", &form(&[("code", &totp::current_code(&secret))]), Some(&session))
        .await;
    assert_eq!(bad.status, StatusCode::FORBIDDEN, "even a correct code needs the token");

    // Logout is a GET (SameSite=Strict covers it) and clears both cookies the browser sends.
    let both = format!("{session}; {}={totp_cookie}", fx.auth.csrf().cookie());
    let out = fx.get("/logout", Some(&both)).await;
    let cleared: Vec<&str> = out.set_cookies();
    assert!(
        cleared.iter().any(|c| c.starts_with(&format!("{}=", fx.auth.csrf().cookie()))),
        "logout clears the csrf cookie too: {cleared:?}"
    );
    assert!(out.session_token(fx.auth.csrf().cookie()).is_none(), "cleared, not reissued");
}

#[tokio::test]
async fn a_bearer_request_is_exempt_from_the_csrf_check() {
    // No ambient cookie → no CSRF vector, so the check must not stand in an API client's way. The
    // request still gets no further than authn (there is no Bearer identity source yet).
    let fx = Fx::new().await;
    fx.user("alice").await;
    let req = fx
        .req("POST", "/profile", None)
        .header(header::AUTHORIZATION, "Bearer some-api-token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form(&[
            ("current_password", PW),
            ("new_password", OTHER_PW),
            ("confirm_password", OTHER_PW),
        ])))
        .unwrap();
    let res = fx.send(req).await;
    res.assert_redirect("/login"); // past CSRF, stopped by authn
    assert_ne!(res.status, StatusCode::FORBIDDEN);
    assert!(fx.password_works("alice", PW).await, "and it changed nothing");
}

#[tokio::test]
async fn the_csrf_cookie_name_follows_the_configuration() {
    let fx = Fx::with(|a| a.csrf_cookie_name("app_csrf")).await;
    fx.user("alice").await;
    let page = fx.get("/login", None).await;
    assert!(
        page.set_cookies().iter().any(|c| c.starts_with("app_csrf=")),
        "configured name is used: {:?}",
        page.set_cookies()
    );
    // The default name is then just another attacker-controlled cookie: it must not satisfy the check.
    let token = page.session_token("app_csrf").unwrap();
    let res = fx
        .post_raw(
            "/login",
            &form(&[("username", "alice"), ("password", PW), ("_csrf", &token)]),
            Some(&format!("rl_csrf={token}")),
        )
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "wrong cookie name proves nothing");
}

// ===================== Gate presets =====================

/// The decision each preset returns for a read and a write by one caller.
async fn decisions(fx: &Fx, cookie: Option<&str>) -> Vec<(&'static str, Decision, Decision)> {
    let headers = fx.headers(cookie);
    let read = Operation::List;
    let write = Operation::Update;
    let gates: Vec<(&'static str, Box<dyn Authz>)> = vec![
        ("Open", Box::new(crate::authz::Open)),
        ("UserReadWrite", Box::new(UserReadWrite::new(&fx.auth))),
        ("UserReadGroupWrite", Box::new(UserReadGroupWrite::new(&fx.auth, ["editors"]))),
        ("PublicReadGroupWrite", Box::new(PublicReadGroupWrite::new(&fx.auth, ["editors"]))),
        ("GroupReadWrite", Box::new(GroupReadWrite::new(&fx.auth, ["editors"]))),
    ];
    let mut out = Vec::new();
    for (name, gate) in gates {
        out.push((name, gate.authorize(read, &headers).await, gate.authorize(write, &headers).await));
    }
    out
}

#[tokio::test]
async fn gate_presets_decide_by_audience() {
    use Decision::*;
    let fx = Fx::new().await;
    fx.user("alice").await; // plain logged-in user, no groups
    fx.user_in("editor", "editors").await;

    // Anonymous: only the public audiences are open.
    assert_eq!(
        decisions(&fx, None).await,
        vec![
            ("Open", Allow, Allow),
            ("UserReadWrite", NeedsLogin, NeedsLogin),
            ("UserReadGroupWrite", NeedsLogin, NeedsLogin),
            ("PublicReadGroupWrite", Allow, NeedsLogin),
            ("GroupReadWrite", NeedsLogin, NeedsLogin),
        ]
    );

    // A logged-in non-member: reads where the audience is User or Public, never a group write.
    let alice = fx.cookie(&fx.session_for("alice").await);
    assert_eq!(
        decisions(&fx, Some(&alice)).await,
        vec![
            ("Open", Allow, Allow),
            ("UserReadWrite", Allow, Allow),
            ("UserReadGroupWrite", Allow, Denied),
            ("PublicReadGroupWrite", Allow, Denied),
            ("GroupReadWrite", Denied, Denied),
        ]
    );

    // A member of the write group: allowed everywhere (the control).
    let editor = fx.cookie(&fx.session_for("editor").await);
    assert!(
        decisions(&fx, Some(&editor)).await.iter().all(|(_, r, w)| *r == Allow && *w == Allow),
        "a member of the named group is allowed by every preset"
    );
}

#[tokio::test]
async fn gates_treat_unusable_sessions_as_anonymous() {
    use Decision::*;
    let fx = Fx::new().await;
    let editor = fx.user_in("editor", "editors").await;

    // Each of these is a cookie that must not carry the editor's privileges.
    let expired = create_session_row(&fx.db, editor, now_secs() - 1, false).await;
    let pending = create_session_row(&fx.db, editor, now_secs() + 60, true).await;
    let live = fx.session_for("editor").await;
    let forged = fx.cookie("f".repeat(64).as_str());
    fx.deactivate("editor").await; // `live` now belongs to a disabled account

    for (what, cookie) in [
        ("expired", fx.cookie(&expired)),
        ("awaiting TOTP", fx.cookie(&pending)),
        ("deactivated user", fx.cookie(&live)),
        ("forged token", forged),
    ] {
        for (name, read, write) in decisions(&fx, Some(&cookie)).await {
            if name == "Open" || (name == "PublicReadGroupWrite" && read == Allow) {
                continue; // public audiences are open to anonymous by design
            }
            assert_eq!(read, NeedsLogin, "{what}: {name} read must be anonymous, not allowed");
            assert_eq!(write, NeedsLogin, "{what}: {name} write must be anonymous, not allowed");
        }
    }
}

#[tokio::test]
async fn group_read_write_admits_only_members() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    fx.user_in("editor", "editors").await;
    let gate = GroupReadWrite::new(&fx.auth, ["editors"]);

    let alice = fx.identify_token(&fx.session_for("alice").await).await.unwrap();
    let editor = fx.identify_token(&fx.session_for("editor").await).await.unwrap();
    assert!(!gate.admits(&alice), "a non-member must not be admitted");
    assert!(gate.admits(&editor));
    // A revoked membership is reflected on the next identify (groups are read per lookup).
    remove_from_group(&fx.db, "editor", "editors").await.unwrap();
    let editor = fx.identify_token(&fx.session_for("editor").await).await.unwrap();
    assert!(!gate.admits(&editor), "removing the group must revoke access without a new session");
}

// ===================== Helpers =====================

/// Percent-encode a form body from `(name, value)` pairs.
fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// A form for one of the **re-authenticated** routes (§5h), confirming with the caller's password
/// [`PW`]. Spelled out as its own helper so a test that *means* to omit the confirmation (there are
/// several) is visibly using plain [`form`] instead.
fn reauth_form(pairs: &[(&str, &str)]) -> String {
    let mut all: Vec<(&str, &str)> = vec![("current_password", PW)];
    all.extend_from_slice(pairs);
    form(&all)
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
