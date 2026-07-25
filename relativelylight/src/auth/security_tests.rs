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
use crate::authz::{Decision, Operation};
use axum::body::Body;
use axum::http::{header, Request};
use sea_orm::Database;
use tower::ServiceExt; // oneshot

const PW: &str = "correct-horse-battery-staple";
const OTHER_PW: &str = "hunter2";
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
        Fx::with(|a| a).await
    }

    /// As [`Fx::new`], with a chance to configure `Auth` before it's cloned into the router (the
    /// builders need sole ownership of the inner `Arc`).
    async fn with(configure: impl FnOnce(Auth) -> Auth) -> Fx {
        let db = Database::connect("sqlite::memory:").await.expect("sqlite in-memory");
        migrate(&db).await.expect("migrate");
        let auth = configure(Auth::new(db.clone()).secure_cookies(false));
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
/// login flow (expired, half-authenticated, orphaned).
async fn create_session_row(
    db: &DatabaseConnection,
    user_id: i32,
    expires_at: i64,
    awaiting_totp: bool,
) -> String {
    let token = new_token();
    session::ActiveModel {
        id: Set(token.clone()),
        user_id: Set(user_id),
        expires_at: Set(expires_at),
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
    // The control for the two tests above: the same flow with the correct code does log in.
    let fx = Fx::new().await;
    fx.user("alice").await;
    let secret = fx.enable_totp("alice").await;

    let res = fx.post("/login", &form(&[("username", "alice"), ("password", PW)]), None).await;
    let token = res.session_token(fx.auth.session_cookie_name()).unwrap();
    let res = fx
        .post("/login/totp", &form(&[("code", &totp::current_code(&secret))]), Some(&fx.cookie(&token)))
        .await;
    res.assert_redirect("/");
    assert!(!fx.session_row(&token).await.unwrap().awaiting_totp);
    assert_eq!(fx.identify_token(&token).await.map(|w| w.username), Some("alice".into()));
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
    let res = fx.post("/profile/totp", &form(&[("code", "000000")]), Some(&cookie)).await;
    assert!(res.body.contains("didn't match"), "expected the retry form: {}", res.body);
    let row = fx.row("alice").await;
    assert!(row.totp_secret.is_none(), "a wrong code must not enable 2FA");
    assert_eq!(row.totp_pending.as_deref(), Some(pending.as_str()), "same pending secret is kept");

    // Control: the matching code promotes it.
    let res = fx.post("/profile/totp", &form(&[("code", &totp::current_code(&pending))]), Some(&cookie)).await;
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

    let res = fx.post("/profile/totp", &form(&[("code", "000000")]), Some(&cookie)).await;
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
            &form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]),
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
            &form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]),
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
    // The manager reset route doesn't refuse SSO targets the way the self-service page does (see
    // TODO.md), so it does write a local hash. What must hold regardless: `verify_credentials`
    // refuses a password login for any `sso_provider` account, so that write can't become a bypass.
    let fx = Fx::new().await;
    let sso = fx.user("federated").await;
    fx.make_sso("federated", "okta").await;
    fx.user_in("admin", "admin").await;
    let cookie = fx.cookie(&fx.session_for("admin").await);

    let res = fx
        .post(
            &format!("/profile/{sso}"),
            &form(&[("new_password", OTHER_PW), ("confirm_password", OTHER_PW)]),
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert!(fx.row("federated").await.is_sso(), "the account stays external");
    for password in [PW, OTHER_PW] {
        let res =
            fx.post("/login", &form(&[("username", "federated"), ("password", password)]), None).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "SSO accounts never log in by password");
        assert!(res.session_token(fx.auth.session_cookie_name()).is_none());
    }
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

#[tokio::test]
async fn login_locks_the_account_after_the_configured_failures() {
    let fx = Fx::with(|a| a.login_limit(3, 900)).await;
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
    let fx = Fx::with(|a| a.login_limit(2, 900)).await;
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
    let fx = Fx::with(|a| a.login_limit(2, 900)).await;
    fx.user("alice").await;
    fx.user("bob").await;

    // Two failures as "alice", a third as "ALICE" — same bucket, so alice is locked…
    fx.fail_login("alice", 2).await;
    fx.post("/login", &form(&[("username", "ALICE"), ("password", "wrong")]), None)
        .await
        .assert_locked_out(900);
    fx.try_login("alice").await.assert_locked_out(900);
    // …while bob is unaffected.
    fx.try_login("bob").await.assert_redirect("/");
}

#[tokio::test]
async fn a_successful_login_clears_the_accounts_failures() {
    let fx = Fx::with(|a| a.login_limit(3, 900)).await;
    fx.user("alice").await;

    fx.fail_login("alice", 2).await;
    fx.try_login("alice").await.assert_redirect("/"); // clears the bucket
    // If the count had survived, the next two failures would lock the account.
    let res = fx.fail_login("alice", 2).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "the counter restarted: {}", res.body);
    fx.try_login("alice").await.assert_redirect("/");
}

#[tokio::test]
async fn the_totp_step_shares_the_accounts_bucket() {
    let fx = Fx::with(|a| a.login_limit(3, 900)).await;
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
    let fx = Fx::with(|a| a.login_limit(3, 900)).await;
    fx.user("alice").await;

    for _ in 0..20 {
        let res = fx
            .post_raw("/login", &form(&[("username", "alice"), ("password", "wrong")]), None)
            .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "no CSRF token → rejected before counting");
    }
    fx.try_login("alice").await.assert_redirect("/"); // not locked
}

#[tokio::test]
async fn the_profile_password_check_has_its_own_bucket() {
    let fx = Fx::with(|a| a.login_limit(3, 900)).await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    let wrong = form(&[
        ("current_password", OTHER_PW),
        ("new_password", "new-secret"),
        ("confirm_password", "new-secret"),
    ]);

    for _ in 0..3 {
        let res = fx.post("/profile", &wrong, Some(&cookie)).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST);
    }
    // Locked here — even a *correct* current password is refused…
    let right = form(&[
        ("current_password", PW),
        ("new_password", "new-secret"),
        ("confirm_password", "new-secret"),
    ]);
    fx.post("/profile", &right, Some(&cookie)).await.assert_locked_out(900);
    assert!(fx.password_works("alice", PW).await, "the password was not changed");
    // …but fumbling it here must not lock the account out of logging in.
    fx.try_login("alice").await.assert_redirect("/");
}

#[tokio::test]
async fn enrolment_codes_are_limited_in_their_own_bucket() {
    let fx = Fx::with(|a| a.login_limit(3, 900)).await;
    fx.user("alice").await;
    let cookie = fx.cookie(&fx.session_for("alice").await);
    fx.get("/profile/totp", Some(&cookie)).await; // mints the pending secret
    let pending = fx.row("alice").await.totp_pending.expect("pending secret");

    for _ in 0..3 {
        let res = fx.post("/profile/totp", &form(&[("code", "000000")]), Some(&cookie)).await;
        assert_eq!(res.status, StatusCode::OK, "a wrong code re-shows the form");
    }
    // The correct code is refused while locked, so 2FA stays off and the secret stays pending.
    let res = fx
        .post("/profile/totp", &form(&[("code", &totp::current_code(&pending))]), Some(&cookie))
        .await;
    res.assert_locked_out(900);
    let row = fx.row("alice").await;
    assert!(row.totp_secret.is_none(), "not enabled");
    assert_eq!(row.totp_pending.as_deref(), Some(pending.as_str()), "still mid-enrolment");
    fx.try_login("alice").await.assert_redirect("/"); // login unaffected
}

#[tokio::test]
async fn per_ip_limiting_is_off_by_default() {
    // Spraying distinct usernames from one address: each account keeps its own small budget, so nothing
    // locks. This is exactly the gap `login_limit_per_ip` closes — and why it needs real client IPs.
    let fx = Fx::with(|a| a.login_limit(3, 900)).await;
    fx.user("alice").await;
    for i in 0..10 {
        let res = fx
            .post_from(
                "/login",
                &form(&[("username", &format!("ghost{i}")), ("password", "wrong")]),
                None,
                "203.0.113.7:5000",
            )
            .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "spray {i} is not rate-limited by default");
    }
    fx.try_login("alice").await.assert_redirect("/");
}

#[tokio::test]
async fn per_ip_limiting_catches_username_spraying_when_enabled() {
    let fx = Fx::with(|a| a.login_limit(100, 900).login_limit_per_ip(3)).await;
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
async fn an_operator_can_unlock_an_account_and_can_switch_limiting_off() {
    let fx = Fx::with(|a| a.login_limit(2, 900)).await;
    fx.user("alice").await;
    fx.fail_login("alice", 2).await;
    fx.try_login("alice").await.assert_locked_out(900);

    fx.auth.clear_login_attempts("alice");
    fx.try_login("alice").await.assert_redirect("/");

    // …and an app that limits at its edge can turn ours off entirely.
    let open = Fx::with(|a| a.no_login_limit()).await;
    open.user("alice").await;
    let res = open.fail_login("alice", 25).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "no lockout when disabled");
    open.try_login("alice").await.assert_redirect("/");
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
