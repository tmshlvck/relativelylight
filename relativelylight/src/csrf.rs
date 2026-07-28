//! `relativelylight::csrf` — CSRF protection for **cookie-authenticated unsafe requests**
//! (POST/PATCH/PUT/DELETE), as a **double-submit token** (feature `csrf`, implied by `auth`). See
//! `docs/AUTH.md` §7.
//!
//! A random token lives in a cookie that JavaScript *can* read (deliberately **not** `HttpOnly` — it
//! is not a credential), and an unsafe request must echo it back, either in the
//! [`X-CSRF-Token`](HEADER) header or in a [`_csrf`](FIELD) form field. The server only checks that
//! the two match ([`Csrf::verify`]) — no server-side state, nothing to expire, and any first-party
//! client can satisfy it (read your own cookie, echo it). A cross-site attacker cannot: the same-origin
//! policy stops them reading the cookie, and they cannot set one for your host — which is the whole
//! point. This is defense-in-depth *on top of* the session cookie's `SameSite=Strict`.
//!
//! Where it's enforced:
//! - **`auth`'s own routes** — always on. Every form fragment the module renders carries the hidden
//!   [`_csrf`](FIELD) field, and each `POST` verifies it before anything else (before the password
//!   check, before any DB work). The token cookie is issued/refreshed when a form page is rendered and
//!   rotated at login.
//! - **the `crud` JSON API** — opt-in per engine: `Crud::csrf(auth.csrf())` (or
//!   `Engine::set_csrf`). Once set, every write handler requires the header; the `crud::ui` tables
//!   add it to their `fetch` calls automatically (they read the cookie name off the engine).
//! - **your own handlers** — call [`Csrf::verify`] yourself, and [`Csrf::ensure`] to hand a token to a
//!   page you render.
//!
//! **Requests carrying an `Authorization` header are exempt**: a Bearer/API credential is not ambient,
//! so a cross-site request can't borrow it and there is nothing to protect.

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use http::HeaderMap;
use rand_core::{OsRng, RngCore};

/// The form field an MPA `<form>` submits the token in.
pub const FIELD: &str = "_csrf";
/// The header a `fetch`/XHR client submits the token in.
pub const HEADER: &str = "x-csrf-token";
/// Default token cookie name.
const DEFAULT_COOKIE: &str = "rl_csrf";

/// A 256-bit random token as lowercase hex. Also used for session ids.
pub(crate) fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time byte comparison (the length is not secret — tokens are fixed-width). Shared with
/// `auth::totp`, which compares candidate codes the same way.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Renders the response for a rejected request — see [`Csrf::on_reject`].
#[cfg(feature = "axum")]
pub(crate) type RejectFn =
    std::sync::Arc<dyn Fn() -> axum::response::Response + Send + Sync + 'static>;

/// The double-submit CSRF checker: a cookie name + the cookie attributes to issue it with. Cheap to
/// clone; hold one per app (`Auth::csrf()` builds the one `auth` uses, so handing that to
/// `Crud::csrf` keeps both surfaces on the same cookie).
#[derive(Clone)]
pub struct Csrf {
    cookie: String,
    secure: bool,
    ttl_secs: i64,
    /// The app's own rejection page, if it set one ([`Csrf::on_reject`]).
    #[cfg(feature = "axum")]
    pub(crate) reject: Option<RejectFn>,
}

// Hand-written because the rejection hook is a closure: `#[derive(Debug)]` can't see through it, and a
// `Csrf` that stopped being `Debug` would be an annoying break for anyone logging their config.
impl std::fmt::Debug for Csrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Csrf");
        s.field("cookie", &self.cookie).field("secure", &self.secure).field("ttl_secs", &self.ttl_secs);
        #[cfg(feature = "axum")]
        s.field("on_reject", &self.reject.as_ref().map(|_| "<set>").unwrap_or("<default>"));
        s.finish()
    }
}

impl Default for Csrf {
    fn default() -> Self {
        Self::new()
    }
}

impl Csrf {
    /// A checker with the defaults: cookie `rl_csrf`, `Secure`, 7-day lifetime.
    pub fn new() -> Self {
        Self {
            cookie: DEFAULT_COOKIE.into(),
            secure: true,
            ttl_secs: 7 * 24 * 3600,
            #[cfg(feature = "axum")]
            reject: None,
        }
    }

    /// Token cookie name (default `"rl_csrf"`). Give co-hosted apps distinct names — same-host apps
    /// share a cookie jar, and a name clash means each one's token check fights the other's.
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.cookie = name.into();
        self
    }

    /// Set the `Secure` cookie attribute (default `true`; `false` for local http).
    pub fn secure(mut self, on: bool) -> Self {
        self.secure = on;
        self
    }

    /// Token cookie lifetime in seconds (default 7 days). Match your session TTL so a live session
    /// always has a usable token.
    pub fn ttl_secs(mut self, secs: i64) -> Self {
        self.ttl_secs = secs;
        self
    }

    /// The configured cookie name.
    pub fn cookie(&self) -> &str {
        &self.cookie
    }

    /// The token this request carries in its cookie, if any.
    pub fn token(&self, headers: &HeaderMap) -> Option<String> {
        let jar = CookieJar::from_headers(headers);
        let value = jar.get(&self.cookie)?.value().to_string();
        (!value.is_empty()).then_some(value)
    }

    /// A fresh token plus the cookie carrying it — add the cookie to your response. Use this to
    /// **rotate** the token (e.g. at login); [`ensure`](Csrf::ensure) is the "only if missing" variant.
    pub fn issue(&self) -> (String, Cookie<'static>) {
        let token = random_token();
        (token.clone(), self.cookie_for(token))
    }

    /// The token for this request, minting one if the request has none: `(token, Some(cookie))` when a
    /// new one was minted (add it to the response), `(token, None)` when the request already had one.
    pub fn ensure(&self, headers: &HeaderMap) -> (String, Option<Cookie<'static>>) {
        match self.token(headers) {
            Some(token) => (token, None),
            None => {
                let (token, cookie) = self.issue();
                (token, Some(cookie))
            }
        }
    }

    /// A removal cookie for the token (pair it with clearing the session at logout).
    pub fn clear_cookie(&self) -> Cookie<'static> {
        Cookie::build(self.cookie.clone()).path("/").build()
    }

    /// Whether this unsafe request passes the double-submit check: the token in the cookie must equal
    /// the one presented in `form_token` (the [`_csrf`](FIELD) field, if the caller parsed a form) or
    /// the [`X-CSRF-Token`](HEADER) header. A request with an `Authorization` header is **exempt**
    /// (not cookie-authenticated). No cookie, no presented token, or a mismatch → `false`.
    ///
    /// Call it only for unsafe methods; GET/HEAD need no token.
    pub fn verify(&self, headers: &HeaderMap, form_token: Option<&str>) -> bool {
        if headers.contains_key(http::header::AUTHORIZATION) {
            return true; // Bearer/API credential: nothing ambient to abuse
        }
        let Some(expected) = self.token(headers) else {
            return false;
        };
        let presented = form_token
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .or_else(|| header_token(headers));
        matches!(presented, Some(p) if ct_eq(expected.as_bytes(), p.as_bytes()))
    }

    /// The hidden input to drop into a server-rendered `<form>` so its POST carries the token.
    pub fn hidden_input(token: &str) -> String {
        format!(r#"<input type="hidden" name="{FIELD}" value="{}">"#, escape_attr(token))
    }

    /// Render the rejection page **yourself**, instead of the built-in bare 403.
    ///
    /// The default is deliberately shell-less and static: a rejected request hasn't proved it came from
    /// this site, so nothing about the caller is rendered and no cookies are set. That's safe but
    /// jarring in an app with its own chrome — this hook lets you keep the chrome without giving any of
    /// that up, provided your closure follows the same rules (don't name the user, don't set cookies,
    /// keep the status a `403`).
    ///
    /// The hook is shared: set it on the `Csrf` you hand to [`Auth::csrf_rejection`] and it covers the
    /// login/profile pages, [`enforce`] on your own routes, and anywhere you call
    /// [`reject`](Csrf::reject) directly. It does **not** apply to the `crud` JSON API, which answers a
    /// machine with `403 {"error":"csrf token missing or invalid"}` — an HTML shell there would be wrong.
    ///
    /// [`Auth::csrf_rejection`]: crate::auth::Auth::csrf_rejection
    #[cfg(feature = "axum")]
    pub fn on_reject<F>(mut self, render: F) -> Self
    where
        F: Fn() -> axum::response::Response + Send + Sync + 'static,
    {
        self.reject = Some(std::sync::Arc::new(render));
        self
    }

    /// The response for a request that failed the check: the app's [`on_reject`](Csrf::on_reject) page
    /// if it set one, else a bare, shell-less `403`.
    #[cfg(feature = "axum")]
    pub fn reject(&self) -> axum::response::Response {
        use axum::response::IntoResponse;
        if let Some(render) = &self.reject {
            return render();
        }
        (
            http::StatusCode::FORBIDDEN,
            [(http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            r#"<!doctype html><meta charset="utf-8"><title>Security check failed</title>
<main><h1>Security check failed</h1>
<p>This form was stale, or the request didn't come from this site. Reload the page and try again.</p></main>"#,
        )
            .into_response()
    }

    fn cookie_for(&self, token: String) -> Cookie<'static> {
        // Readable by JS on purpose (the `fetch` clients echo it); the *session* cookie stays HttpOnly.
        Cookie::build((self.cookie.clone(), token))
            .http_only(false)
            .same_site(SameSite::Strict)
            .path("/")
            .secure(self.secure)
            .max_age(time::Duration::seconds(self.ttl_secs))
            .build()
    }
}

/// The largest form body [`enforce`] will buffer to look for a `_csrf` field. Generous for a form, small
/// enough that the layer can't be used to make a server hold arbitrary memory; a bigger unsafe request
/// (a file upload) must carry the token in the [`HEADER`] instead.
#[cfg(feature = "axum")]
const MAX_BUFFERED_FORM: usize = 64 * 1024;

/// Middleware that enforces the double-submit token on **your own** unsafe routes, so each handler
/// doesn't have to call [`Csrf::verify`] itself. Wire it with axum's `from_fn_with_state`:
///
/// ```ignore
/// use axum::middleware::from_fn_with_state;
///
/// let guarded = Router::new()
///     .route("/account/delete", post(delete_account))
///     .route("/api-token/rotate", post(rotate_token))
///     .layer(from_fn_with_state(auth.csrf(), relativelylight::csrf::enforce));
/// ```
///
/// Pass the **same** `Csrf` the rest of the app uses (`auth.csrf()`), or the cookie names won't match.
/// Apply it to a `Router` holding only the routes you want guarded: it rejects *any* unsafe request that
/// arrives without a token, which is the point, and would therefore break an endpoint that is meant to
/// take a Bearer credential from a non-browser client — though those are exempt anyway (see below).
///
/// **What it checks**, in order:
/// - **Safe methods pass** untouched (`GET`, `HEAD`, `OPTIONS`, `TRACE`) — there is nothing to protect.
/// - **`Authorization`-bearing requests pass**: an API credential isn't ambient, so a cross-site request
///   can't borrow it (the same exemption [`Csrf::verify`] makes).
/// - the [`X-CSRF-Token`](HEADER) header, for `fetch`/XHR clients;
/// - failing that, and **only** for `application/x-www-form-urlencoded` bodies under
///   [`MAX_BUFFERED_FORM`], the [`_csrf`](FIELD) field — the body is buffered, checked, and handed on
///   intact, so a plain MPA `<form>` post works without the handler doing anything.
///
/// A multipart form is *not* parsed: give those the header, or check them in the handler. Everything else
/// gets [`Csrf::reject`], so your [`on_reject`](Csrf::on_reject) page applies here too.
#[cfg(feature = "axum")]
pub async fn enforce(
    axum::extract::State(csrf): axum::extract::State<Csrf>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use http::Method;
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE) {
        return next.run(req).await;
    }
    // The header form needs no body, so try it first and leave the request untouched.
    if csrf.verify(req.headers(), None) {
        return next.run(req).await;
    }
    if !is_urlencoded_form(req.headers()) {
        return csrf.reject();
    }
    // A form post: buffer, read `_csrf`, then rebuild the request so the handler still sees its body.
    let (parts, body) = req.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_BUFFERED_FORM).await else {
        return csrf.reject(); // unreadable or over the cap — either way we can't find a token
    };
    let token = form_field(&bytes, FIELD);
    if !csrf.verify(&parts.headers, token.as_deref()) {
        return csrf.reject();
    }
    next.run(axum::extract::Request::from_parts(parts, axum::body::Body::from(bytes))).await
}

/// Whether the body is a URL-encoded form (ignoring any `; charset=…` parameter).
#[cfg(feature = "axum")]
fn is_urlencoded_form(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/x-www-form-urlencoded"))
        .unwrap_or(false)
}

/// Pull one field out of a URL-encoded body. Hand-rolled for the same reason as the rest of this crate's
/// small parsers: it is a dozen lines and saves a dependency, and a token is hex so the only decoding
/// that matters is `+` and `%XX`.
#[cfg(feature = "axum")]
fn form_field(body: &[u8], name: &str) -> Option<String> {
    let body = std::str::from_utf8(body).ok()?;
    for pair in body.split('&') {
        let (k, v) = pair.split_once('=')?;
        if percent_decode(k) == name {
            return Some(percent_decode(v));
        }
    }
    None
}

#[cfg(feature = "axum")]
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn header_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(HEADER)?.to_str().ok()?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// Minimal attribute escaping for the hidden input (tokens are hex, but never interpolate blind).
fn escape_attr(s: &str) -> String {
    s.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(cookie: Option<&str>, header: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(c) = cookie {
            h.insert(http::header::COOKIE, c.parse().unwrap());
        }
        if let Some(t) = header {
            h.insert(HEADER, t.parse().unwrap());
        }
        h
    }

    #[test]
    fn matching_header_passes_everything_else_fails() {
        let csrf = Csrf::new();
        let (token, _) = csrf.issue();
        let cookie = format!("rl_csrf={token}");

        assert!(csrf.verify(&headers(Some(&cookie), Some(&token)), None), "cookie == header");
        // The failures: no cookie, no token presented, a wrong/blank/truncated token.
        assert!(!csrf.verify(&headers(None, Some(&token)), None), "header alone proves nothing");
        assert!(!csrf.verify(&headers(Some(&cookie), None), None), "cookie alone proves nothing");
        assert!(!csrf.verify(&headers(Some(&cookie), Some("")), None), "blank header");
        assert!(!csrf.verify(&headers(Some(&cookie), Some(&token[1..])), None), "truncated");
        assert!(!csrf.verify(&headers(Some(&cookie), Some(&random_token())), None), "other token");
        assert!(!csrf.verify(&headers(Some("rl_csrf="), Some("")), None), "both empty is not a match");
    }

    #[test]
    fn form_field_is_accepted_and_falls_back_to_the_header() {
        let csrf = Csrf::new();
        let (token, _) = csrf.issue();
        let cookie = format!("rl_csrf={token}");

        assert!(csrf.verify(&headers(Some(&cookie), None), Some(&token)), "form field matches");
        assert!(csrf.verify(&headers(Some(&cookie), None), Some(&format!(" {token} "))), "trimmed");
        assert!(!csrf.verify(&headers(Some(&cookie), None), Some("nope")), "wrong form field");
        // An empty field is "not presented" → fall back to the header rather than failing outright.
        assert!(csrf.verify(&headers(Some(&cookie), Some(&token)), Some("")));
    }

    #[test]
    fn a_bearer_request_is_exempt() {
        let csrf = Csrf::new();
        let mut h = headers(None, None);
        h.insert(http::header::AUTHORIZATION, "Bearer abc123".parse().unwrap());
        assert!(csrf.verify(&h, None), "an API credential is not ambient — nothing to protect");
    }

    #[test]
    fn issue_and_ensure_cookie_attributes() {
        let csrf = Csrf::new().cookie_name("app_csrf").secure(false).ttl_secs(60);
        let (token, cookie) = csrf.issue();
        assert_eq!(cookie.name(), "app_csrf");
        assert_eq!(cookie.value(), token);
        assert_eq!(cookie.http_only(), Some(false), "the UI's JS must be able to read it");
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.secure(), Some(false));
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.max_age(), Some(time::Duration::seconds(60)));

        // `ensure` mints only when the request has no token.
        let (fresh, set) = csrf.ensure(&headers(None, None));
        assert!(set.is_some() && fresh.len() == 64);
        let (kept, set) = csrf.ensure(&headers(Some(&format!("app_csrf={fresh}")), None));
        assert_eq!(kept, fresh);
        assert!(set.is_none(), "an existing token is reused, not rotated");
    }

    #[test]
    fn tokens_are_unpredictable_and_hex() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let t = random_token();
            assert_eq!(t.len(), 64);
            assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(seen.insert(t), "tokens must never repeat");
        }
    }

    #[test]
    fn form_bodies_are_parsed_enough_to_find_the_token() {
        // Only enough URL-decoding to find `_csrf` among whatever else the form sent.
        let body = b"name=alice&_csrf=deadbeef&note=hi+there";
        assert_eq!(form_field(body, FIELD).as_deref(), Some("deadbeef"));
        assert_eq!(form_field(b"_csrf=abc", FIELD).as_deref(), Some("abc"));
        assert_eq!(form_field(b"a=1&b=2", FIELD), None, "absent field");
        assert_eq!(form_field(b"", FIELD), None);
        // Percent- and plus-decoding, on both sides of the pair.
        assert_eq!(form_field(b"%5Fcsrf=x", "_csrf").as_deref(), Some("x"), "encoded name");
        assert_eq!(percent_decode("a+b%20c"), "a b c");
        assert_eq!(percent_decode("100%"), "100%", "a trailing % is not an escape");
        assert_eq!(percent_decode("%zz"), "%zz", "invalid hex is left alone");

        assert!(is_urlencoded_form(&{
            let mut h = HeaderMap::new();
            h.insert(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded".parse().unwrap());
            h
        }));
        assert!(is_urlencoded_form(&{
            let mut h = HeaderMap::new();
            h.insert(
                http::header::CONTENT_TYPE,
                "Application/X-WWW-Form-Urlencoded; charset=utf-8".parse().unwrap(),
            );
            h
        }), "case and parameters must not matter");
        assert!(!is_urlencoded_form(&{
            let mut h = HeaderMap::new();
            h.insert(http::header::CONTENT_TYPE, "multipart/form-data; boundary=x".parse().unwrap());
            h
        }));
        assert!(!is_urlencoded_form(&HeaderMap::new()), "no content-type is not a form");
    }

    #[test]
    fn the_rejection_hook_replaces_the_built_in_page() {
        use axum::response::IntoResponse;
        let default = Csrf::new().reject();
        assert_eq!(default.status(), http::StatusCode::FORBIDDEN);

        let custom = Csrf::new()
            .on_reject(|| (http::StatusCode::FORBIDDEN, "in my own shell").into_response());
        let res = custom.reject();
        assert_eq!(res.status(), http::StatusCode::FORBIDDEN, "still a 403");
        // The hook travels with a clone, which is how it reaches `enforce` and the auth routes.
        assert!(custom.clone().reject.is_some());
        // `Debug` still works, which the derive couldn't have given us with a closure in there.
        assert!(format!("{custom:?}").contains("<set>"));
        assert!(format!("{:?}", Csrf::new()).contains("<default>"));
    }

    #[test]
    fn hidden_input_carries_the_token() {
        let html = Csrf::hidden_input("abc\"><script>");
        assert!(html.contains(r#"name="_csrf""#));
        assert!(!html.contains("<script>"), "escaped: {html}");
    }
}
