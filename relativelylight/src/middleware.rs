//! `relativelylight::middleware` — the request-pipeline layers: `resolve_real_ip` (who is calling)
//! and `access_log` (one line per request). Feature `axum`.
//!
//! **`resolve_real_ip` is mandatory for any app using this crate.** It resolves the caller's address
//! **once**, at the edge, and puts it in a request extension as `RealIp`; everything downstream — the
//! `auth` lockout, the access log, your own handlers, the audit events — reads that one value. Before it
//! existed, each of those resolved the address itself, and they disagreed: the lockout counted the
//! forwarded hop while the access log printed the socket peer, so a log line and the thing it described
//! named different clients.
//!
//! ```ignore
//! use axum::middleware::from_fn_with_state;
//! use relativelylight::middleware::{access_log, resolve_real_ip, TrustProxy};
//!
//! let app = app
//!     .layer(from_fn_with_state((), access_log))                       // inner: logs the request
//!     .layer(from_fn_with_state(TrustProxy(cfg.trust_proxy), resolve_real_ip)); // outer: resolves first
//!
//! // …and the server must supply the socket address:
//! axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
//! ```
//!
//! **Order matters**: `Router::layer` wraps, so the layer added *last* is outermost and runs *first*.
//! `resolve_real_ip` must be outermost, or the layers inside it won't see a `RealIp`.
//!
//! **If your topology is stranger than one proxy**, don't look for a hook — there isn't one, on purpose.
//! Write your own middleware that inserts a `RealIp` extension however your CDN reports the client, put
//! it where `resolve_real_ip` would go, and every consumer works unchanged.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode};

/// The caller's resolved address, in a request extension. Extract it in any handler:
///
/// ```ignore
/// async fn handler(RealIp(ip): RealIp) -> String { format!("hello {ip}") }
/// ```
///
/// **Always canonical.** [`resolve_real_ip`] folds an IPv4-mapped IPv6 address (`::ffff:a.b.c.d` — what a
/// dual-stack listener reports for an IPv4 client) to plain IPv4 before inserting it, so downstream code
/// may compare, key and print this value without normalizing again: one client is one address whether it
/// arrived over a v4-only socket, a dual-stack one, or a proxy header. The deprecated IPv4-*compatible*
/// form `::a.b.c.d` is **not** folded — nothing emits it, and treating it as IPv4 would invent an
/// equivalence its own semantics don't have. `auth`'s lockout canonicalizes again regardless, since an app
/// may hand it an address that never came through here.
///
/// **Extraction fails with `500`** when the extension is missing, i.e. when [`resolve_real_ip`] isn't in
/// the stack — deliberately, because the alternative is an `Option` that app code turns into
/// `unwrap_or(127.0.0.1)` and files in an audit row. A misconfiguration you meet on the first request
/// beats one that quietly writes the wrong address forever.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RealIp(pub IpAddr);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for RealIp {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<RealIp>().copied().ok_or_else(missing_layer)
    }
}

/// The one response for "the address wasn't resolved", worded so the fix is obvious from the body.
fn missing_layer() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "relativelylight: no RealIp in the request. Add the middleware at the outermost layer:\n  \
         .layer(from_fn_with_state(TrustProxy(trust_proxy), relativelylight::middleware::resolve_real_ip))\n\
         and serve with .into_make_service_with_connect_info::<SocketAddr>().",
    )
        .into_response()
}

/// Whether a reverse proxy in front of the app may be believed about who the client is — the state
/// [`resolve_real_ip`] takes, and the same flag your config almost certainly already has.
///
/// `false`: the **socket peer** is the client, and forwarded headers are ignored entirely. Correct for a
/// directly exposed app, and the only safe reading there — those headers are attacker-supplied, so
/// believing them would let a caller choose whose address gets logged, rate-limited or locked out.
///
/// `true`: the proxy's headers are believed (see [`resolve_real_ip`] for which). Set it **only** when
/// nothing can reach the app except that proxy. Leaving it `false` behind a proxy is the other failure:
/// every user buckets under the proxy's address, where one lockout takes down your whole login form.
#[derive(Clone, Copy, Debug)]
pub struct TrustProxy(pub bool);

/// Resolve the caller's address and put it in the request as [`RealIp`]. **The outermost layer.**
///
/// With [`TrustProxy(false)`](TrustProxy) the socket peer is the answer, full stop.
///
/// With `TrustProxy(true)`, in order:
/// 1. the **right-most** `X-Forwarded-For` entry — the hop *your* proxy appended, which is the only one
///    it vouches for; everything to its left is whatever the caller chose to send. nginx
///    (`proxy_add_x_forwarded_for`), Caddy (`reverse_proxy`) and HAProxy (`option forwardfor`) all append,
///    so the last entry is theirs. A proxy that *replaces* the header leaves one entry and both readings
///    agree.
/// 2. `X-Real-IP`, for a proxy configured to set that instead (nginx's `realip` module convention).
/// 3. the socket peer, if neither header is present or parseable.
///
/// **Only those two headers, deliberately.** Not `CF-Connecting-IP`, `True-Client-IP` or RFC 7239
/// `Forwarded`. Reading more headers *weakens* the check rather than widening it: nginx, Caddy and HAProxy
/// set and sanitize the two above but pass a client's `CF-Connecting-IP` straight through, so trusting
/// that header would let anyone behind such a proxy forge an address and have it beat their proxy's honest
/// `X-Forwarded-For`. Behind a CDN, insert [`RealIp`] from your own middleware instead — see the module
/// docs.
///
/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is normalized to plain IPv4, so a dual-stack listener and a proxy
/// reporting plain IPv4 agree on one address for one client.
///
/// **Answers `500` if it cannot resolve anything at all** — no usable header *and* no
/// `ConnectInfo` — because that means the server wasn't started with
/// `into_make_service_with_connect_info`, and an app that can't name its callers shouldn't quietly carry
/// on lockout-counting and audit-logging without them.
pub async fn resolve_real_ip(
    State(TrustProxy(trust_proxy)): State<TrustProxy>,
    mut req: Request,
    next: Next,
) -> Response {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    let Some(ip) = client_ip(trust_proxy, req.headers(), peer) else {
        return missing_layer();
    };
    req.extensions_mut().insert(RealIp(ip));
    next.run(req).await
}

/// One line per request on stderr: method, path, status, latency and the caller's [`RealIp`].
///
/// ```text
/// 127.0.0.1 POST /login 303 12ms
/// ```
///
/// Put it **inside** [`resolve_real_ip`] (i.e. add it to the router first) so it can see the address. If
/// it can't — the layer is missing or ordered wrongly — it logs `-` and warns **once** rather than failing
/// the request: taking an app down because a log field is unavailable would be a self-inflicted outage.
/// `auth` is the surface that hard-fails without an address, because there a missing one silently degrades
/// the lockout.
///
/// **No principal.** Naming the user would mean an `Auth::identify` — a session, user and groups lookup —
/// on *every* request, including the ones that never needed an identity. That's a large bill for a log
/// field, and the write-side story is already better served by the audit hook
/// ([`observe`](crate::observe)), which sees who changed what. If you want it anyway, write your own
/// version of this function; it is fifteen lines.
pub async fn access_log(req: Request, next: Next) -> Response {
    let started = std::time::Instant::now();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let ip = req.extensions().get::<RealIp>().copied();
    if ip.is_none() {
        warn_missing_real_ip_once();
    }
    let res = next.run(req).await;
    let who = match ip {
        Some(RealIp(ip)) => ip.to_string(),
        None => "-".to_string(),
    };
    eprintln!(
        "{who} {method} {path} {} {}ms",
        res.status().as_u16(),
        started.elapsed().as_millis()
    );
    res
}

/// Complain about a missing [`RealIp`] the first time only — a per-request warning would bury the log it
/// is trying to help with.
fn warn_missing_real_ip_once() {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        eprintln!(
            "relativelylight: access_log found no RealIp — add resolve_real_ip as the OUTERMOST layer \
             (the router's last .layer call). Logging '-' for the address until then."
        );
    }
}

/// The resolution itself, as a pure function — what [`resolve_real_ip`] calls, and what a hand-written
/// middleware for an exotic topology can fall back to ("read my CDN's header, else the normal rules").
///
/// `None` only when there is nothing at all to go on: no usable header *and* no `peer`.
pub fn client_ip(trust_proxy: bool, headers: &HeaderMap, peer: Option<IpAddr>) -> Option<IpAddr> {
    use crate::net::canonical;
    if trust_proxy {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            // Right-most: the hop our own proxy appended. Anything further left came from the caller.
            if let Some(ip) = xff.rsplit(',').next().and_then(|f| f.trim().parse::<IpAddr>().ok()) {
                return Some(canonical(ip));
            }
        }
        if let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
        {
            return Some(canonical(ip));
        }
    }
    peer.map(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use http::Request as HttpRequest;
    use tower::ServiceExt;

    /// A router that echoes the resolved address, so a test sees exactly what a handler would.
    fn app(trust_proxy: bool) -> Router {
        Router::new()
            .route("/", get(|RealIp(ip): RealIp| async move { ip.to_string() }))
            .layer(axum::middleware::from_fn_with_state(
                TrustProxy(trust_proxy),
                resolve_real_ip,
            ))
    }

    async fn call(app: Router, req: HttpRequest<Body>) -> (StatusCode, String) {
        let res = app.oneshot(req).await.expect("response");
        let status = res.status();
        let body = axum::body::to_bytes(res.into_body(), 1 << 16).await.expect("body");
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn req(headers: &[(&str, &str)], peer: Option<&str>) -> HttpRequest<Body> {
        let mut b = HttpRequest::builder().uri("/");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut req = b.body(Body::empty()).unwrap();
        if let Some(p) = peer {
            // An IPv6 literal needs brackets in a socket address; IPv4 must not have them.
            let ip: IpAddr = p.parse().expect("a valid address");
            req.extensions_mut().insert(ConnectInfo(SocketAddr::new(ip, 4321)));
        }
        req
    }

    #[tokio::test]
    async fn an_exposed_app_uses_the_socket_peer_and_ignores_headers() {
        // The security-critical direction: a caller must not be able to choose its own address.
        let (status, body) = call(
            app(false),
            req(
                &[("x-forwarded-for", "9.9.9.9"), ("x-real-ip", "8.8.8.8"), ("cf-connecting-ip", "7.7.7.7")],
                Some("203.0.113.7"),
            ),
        )
        .await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "203.0.113.7"));
    }

    #[tokio::test]
    async fn behind_a_proxy_the_appended_hop_wins() {
        // Right-most: what our proxy added. Everything left of it is caller-supplied.
        let (status, body) = call(
            app(true),
            req(&[("x-forwarded-for", "198.51.100.9, 203.0.113.7")], Some("10.0.0.1")),
        )
        .await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "203.0.113.7"));

        // X-Real-IP is the fallback when there is no chain…
        let (_, body) = call(app(true), req(&[("x-real-ip", "198.51.100.10")], Some("10.0.0.1"))).await;
        assert_eq!(body, "198.51.100.10");
        // …and the peer is the fallback when there is neither.
        let (_, body) = call(app(true), req(&[], Some("10.0.0.1"))).await;
        assert_eq!(body, "10.0.0.1");
    }

    #[tokio::test]
    async fn a_cdn_header_is_never_believed_by_the_default() {
        // Trusting it would let a client behind nginx forge an address that beats the proxy's own
        // X-Forwarded-For — the reason this middleware reads two headers and not five.
        let (_, body) = call(
            app(true),
            req(
                &[("cf-connecting-ip", "1.2.3.4"), ("true-client-ip", "5.6.7.8"), ("x-forwarded-for", "203.0.113.7")],
                Some("10.0.0.1"),
            ),
        )
        .await;
        assert_eq!(body, "203.0.113.7", "the proxy's hop, not the forgeable CDN header");
        // With no XFF at all, a forged CDN header still loses to the socket peer.
        let (_, body) = call(app(true), req(&[("cf-connecting-ip", "1.2.3.4")], Some("10.0.0.1"))).await;
        assert_eq!(body, "10.0.0.1");
    }

    #[tokio::test]
    async fn no_address_at_all_is_a_configuration_error() {
        // No ConnectInfo and no usable header: the server wasn't started with connect info, so say so
        // instead of carrying on without an address.
        let (status, body) = call(app(false), req(&[], None)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("into_make_service_with_connect_info"), "the fix is in the body: {body}");
    }

    #[tokio::test]
    async fn the_extractor_fails_loudly_when_the_layer_is_missing() {
        // The whole point of the strict extractor: no silent Option to mishandle.
        let bare = Router::new().route("/", get(|RealIp(ip): RealIp| async move { ip.to_string() }));
        let (status, body) = call(bare, req(&[], Some("203.0.113.7"))).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("resolve_real_ip"), "names the missing layer: {body}");
    }

    #[tokio::test]
    async fn every_form_an_address_can_arrive_in_lands_on_one_canonical_value() {
        // The invariant everything downstream leans on: a `RealIp` is **already canonical**, so the
        // lockout's row key, an audit row and a log line agree whatever the listener or proxy reported.
        // The three shapes that actually occur, from both a socket and a header:
        for (peer, expect, what) in [
            ("192.0.2.1", "192.0.2.1", "IPv4 from a v4-only socket — unchanged"),
            ("::ffff:192.0.2.1", "192.0.2.1", "IPv4 via a dual-stack socket — folded to v4"),
            ("2001:db8::1", "2001:db8::1", "a real IPv6 client — untouched"),
        ] {
            let (status, body) = call(app(false), req(&[], Some(peer))).await;
            assert_eq!((status, body.as_str()), (StatusCode::OK, expect), "{what}");
        }
        // …and the same folding for an address that arrives in a trusted header rather than the socket,
        // so a proxy reporting the mapped form can't open a second bucket for one client.
        for (header, value) in [("x-forwarded-for", "::ffff:192.0.2.1"), ("x-real-ip", "::ffff:192.0.2.1")] {
            let (_, body) = call(app(true), req(&[(header, value)], Some("10.0.0.1"))).await;
            assert_eq!(body, "192.0.2.1", "{header} in mapped form must fold too");
        }
        // A *mixed* chain: the proxy appended a mapped form of the same client that another request
        // reported plain. Both must reduce to one address.
        let (_, body) =
            call(app(true), req(&[("x-forwarded-for", "9.9.9.9, ::ffff:203.0.113.7")], None)).await;
        assert_eq!(body, "203.0.113.7");

        // Deliberately *not* folded: the deprecated IPv4-**compatible** form (`::a.b.c.d`, no `ffff`).
        // `to_ipv4_mapped` matches only the mapped form, and that's the right call — nothing in use emits
        // the compatible form, and quietly treating `::203.0.113.7` as an IPv4 client would invent an
        // equivalence the address's own semantics don't have. It stays IPv6, which `IpAddr`'s own
        // `Display` writes in hex (`::cb00:7107`) rather than the dotted form it was typed in — so this
        // is also a reminder that the *canonical* text of an address is whatever `IpAddr` says, which is
        // what the lockout keys on.
        let (_, body) = call(app(false), req(&[], Some("::203.0.113.7"))).await;
        assert_eq!(body, "::cb00:7107", "the compatible form stays IPv6, rendered canonically");
    }

    #[tokio::test]
    async fn the_access_log_survives_a_missing_address() {
        // It logs '-' and warns rather than failing the request: an app must not fall over because a log
        // field is unavailable.
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(access_log));
        let (status, body) = call(app, req(&[], Some("203.0.113.7"))).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "ok"));
    }

    #[test]
    fn a_caller_cannot_choose_its_own_address_behind_an_appending_proxy() {
        // nginx's `$proxy_add_x_forwarded_for` (and HAProxy's `option forwardfor`, and Caddy) append what
        // they see to what the caller sent. Reading the left-most entry would hand every caller a free
        // choice of address — and with it a way past an admission list, out of a lockout, or into someone
        // else's audit trail. The proxy's own entry is always the last one.
        let peer: Option<IpAddr> = "10.0.0.1".parse().ok(); // the proxy
        for spoof in ["127.0.0.1", "10.0.0.1", "::1", "192.0.2.1, 198.51.100.1"] {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-for", format!("{spoof}, 203.0.113.7").parse().unwrap());
            assert_eq!(
                client_ip(true, &h, peer),
                "203.0.113.7".parse().ok(),
                "caller claimed {spoof:?} and must not be believed"
            );
        }
        // Garbage falls back to the peer rather than dropping the address entirely.
        let mut junk = HeaderMap::new();
        junk.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        assert_eq!(client_ip(true, &junk, peer), peer);
        assert_eq!(client_ip(true, &HeaderMap::new(), peer), peer, "no header at all");
        assert_eq!(client_ip(false, &HeaderMap::new(), None), None, "nothing to go on");
    }

    #[tokio::test]
    async fn the_documented_layer_order_puts_the_address_in_the_log() {
        // `Router::layer` wraps, so the *last* layer added is outermost and runs first. If this ordering
        // were wrong, `access_log` would never see a RealIp — which is the mistake the docs warn about.
        let app = Router::new()
            .route("/", get(|RealIp(ip): RealIp| async move { ip.to_string() }))
            .layer(axum::middleware::from_fn(access_log))
            .layer(axum::middleware::from_fn_with_state(TrustProxy(true), resolve_real_ip));
        let (status, body) =
            call(app, req(&[("x-forwarded-for", "203.0.113.7")], Some("10.0.0.1"))).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "203.0.113.7"));
    }
}
