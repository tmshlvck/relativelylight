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

/// Constant-time byte comparison (the length is not secret — tokens are fixed-width).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The double-submit CSRF checker: a cookie name + the cookie attributes to issue it with. Cheap to
/// clone; hold one per app (`Auth::csrf()` builds the one `auth` uses, so handing that to
/// `Crud::csrf` keeps both surfaces on the same cookie).
#[derive(Clone, Debug)]
pub struct Csrf {
    cookie: String,
    secure: bool,
    ttl_secs: i64,
}

impl Default for Csrf {
    fn default() -> Self {
        Self::new()
    }
}

impl Csrf {
    /// A checker with the defaults: cookie `rl_csrf`, `Secure`, 7-day lifetime.
    pub fn new() -> Self {
        Self { cookie: DEFAULT_COOKIE.into(), secure: true, ttl_secs: 7 * 24 * 3600 }
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
    fn hidden_input_carries_the_token() {
        let html = Csrf::hidden_input("abc\"><script>");
        assert!(html.contains(r#"name="_csrf""#));
        assert!(!html.contains("<script>"), "escaped: {html}");
    }
}
