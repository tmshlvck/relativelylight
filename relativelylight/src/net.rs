//! `relativelylight::net` — resolving a request's **client address**.
//!
//! Every deployment answers "who is calling?" one of two ways, and the difference is a security
//! boundary, not a preference:
//!
//! - **Exposed directly** — the socket peer is the client. Forwarded headers are attacker-supplied and
//!   must be ignored, or a caller picks which address gets rate-limited, logged or locked out.
//! - **Behind a reverse proxy you control** — the peer is the proxy, and the client is the address the
//!   proxy itself appended to `X-Forwarded-For` (the **right-most** entry — see [`client_ip`]), or
//!   `X-Real-IP`.
//!
//! [`client_ip`] is that decision as one function, driven by the `trust_proxy` flag an app almost
//! certainly already has in its config. `auth` uses it for the per-address half of the lockout
//! (`docs/AUTH.md` §5e); an app should use the same call for its own logging, audit rows and limits, so
//! that one client is one key everywhere.
//!
//! It also carries the CIDR helpers that go with an address — [`parse_nets`], [`in_nets`] and
//! [`canonical_net`] — so an whitelist matches whichever way the client arrived: IPv4, IPv6, or the
//! `::ffff:a.b.c.d` form a dual-stack listener reports. `auth`'s lockout uses them for
//! [`Lockout::ip_allow`](crate::auth::lockout::Lockout::ip_allow); an app should use the same ones for
//! its own network rules.
//!
//! **Scope, deliberately.** One trusted hop, no trusted-proxy CIDR list and no RFC 7239 `Forwarded`
//! parsing yet — see `docs/AUTH.md` §4 and `TODO.md`. That covers the ordinary "one proxy in front"
//! case and is safe as long as `trust_proxy` really means "nothing reaches me except that proxy". A
//! richer configuration can extend this without changing the call shape.

use http::HeaderMap;
use ipnet::{IpNet, Ipv4Net};
use std::net::IpAddr;

/// The client address of a request: the **right-most** `X-Forwarded-For` entry when `trust_proxy` is
/// set (else `X-Real-IP`), and the socket `peer` otherwise. `None` when neither is available (no
/// connection info and no usable header).
///
/// **Right-most, not left-most, and that is the security-relevant part.** A proxy appends the address
/// *it* observed to whatever the caller already sent — `proxy_add_x_forwarded_for` in nginx, `option
/// forwardfor` in HAProxy, Caddy's `reverse_proxy` — so the last entry is the one your proxy vouches
/// for and everything to its left is caller-supplied. Reading the left-most entry would let any caller
/// pick its own address by sending a header, defeating whatever the address is used for (an admission
/// list, a lockout, an audit trail). With a proxy that *replaces* the header instead, there is only one
/// entry and the two readings agree.
///
/// The limit of a boolean: it says "exactly one hop I trust". Behind **two** proxies (a CDN in front of
/// your own), the right-most entry is the inner proxy, not the end user — that needs a trusted-proxy
/// CIDR list, which is `docs/AUTH.md` §4 and still to come.
///
/// IPv4-mapped IPv6 (`::ffff:192.0.2.1`) is normalized to plain IPv4, so a dual-stack listener and a
/// proxy that reports plain IPv4 agree on one key for one client.
///
/// ```
/// use relativelylight::net::client_ip;
/// # use http::HeaderMap;
/// let mut headers = HeaderMap::new();
/// // What an appending proxy produces from a caller that sent "X-Forwarded-For: 198.51.100.9".
/// headers.insert("x-forwarded-for", "198.51.100.9, 203.0.113.7".parse().unwrap());
/// let peer = Some("10.0.0.1".parse().unwrap()); // the proxy itself
///
/// // Behind a trusted proxy: the hop *it* added, not the one the caller claimed.
/// assert_eq!(client_ip(true, &headers, peer), "203.0.113.7".parse().ok());
/// // Exposed directly: the header is attacker-controlled, so it is ignored entirely.
/// assert_eq!(client_ip(false, &headers, peer), "10.0.0.1".parse().ok());
/// ```
pub fn client_ip(trust_proxy: bool, headers: &HeaderMap, peer: Option<IpAddr>) -> Option<IpAddr> {
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

/// Normalize an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to plain IPv4; anything else unchanged.
/// A dual-stack listener reports IPv4 clients in the mapped form, so without this the same client can
/// end up under two different keys depending on how the server was bound.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Parse CIDR strings into networks, skipping anything unparseable. A bare address is accepted as a
/// single host (`/32` or `/128`), and IPv4-mapped IPv6 networks are canonicalized to IPv4 — so a rule
/// written either way matches a client resolved either way (see [`canonical_net`]).
///
/// ```
/// use relativelylight::net::{in_nets, parse_nets};
/// let nets = parse_nets(&["10.0.0.0/8".into(), "2001:db8::/32".into(), "::ffff:192.0.2.0/120".into()]);
/// assert!(in_nets(&nets, "10.9.9.9".parse().unwrap()));
/// assert!(in_nets(&nets, "2001:db8::1".parse().unwrap()));
/// assert!(in_nets(&nets, "192.0.2.5".parse().unwrap()), "mapped rule, plain client");
/// assert!(!in_nets(&nets, "192.168.1.1".parse().unwrap()));
/// ```
pub fn parse_nets(cidrs: &[String]) -> Vec<IpNet> {
    cidrs
        .iter()
        .filter_map(|s| {
            let s = s.trim();
            s.parse::<IpNet>()
                .ok()
                .or_else(|| s.parse::<IpAddr>().ok().map(IpNet::from))
                .map(canonical_net)
        })
        .collect()
}

/// Whether `ip` falls in any of `nets`. The address is canonicalized first, so an IPv4 client reported
/// as `::ffff:a.b.c.d` still matches an IPv4 rule.
pub fn in_nets(nets: &[IpNet], ip: IpAddr) -> bool {
    let ip = canonical(ip);
    nets.iter().any(|n| n.contains(&ip))
}

/// The rule-side counterpart of [`canonical`]: an IPv4-mapped IPv6 network (`::ffff:a.b.c.d/N`, N≥96)
/// becomes the equivalent IPv4 network (`/N-96`). Genuine IPv6 networks are untouched. Without this, a
/// rule written in mapped form would never match a client whose address was canonicalized to IPv4.
pub fn canonical_net(net: IpNet) -> IpNet {
    if let IpNet::V6(v6) = net {
        if let Some(v4) = v6.addr().to_ipv4_mapped() {
            if v6.prefix_len() >= 96 {
                if let Ok(n) = Ipv4Net::new(v4, v6.prefix_len() - 96) {
                    return IpNet::V4(n);
                }
            }
        }
    }
    net
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        s.parse().ok()
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn an_untrusted_deployment_ignores_forwarded_headers() {
        // The security-critical direction: a client must not be able to choose its own identity.
        let h = headers(&[("x-forwarded-for", "9.9.9.9"), ("x-real-ip", "8.8.8.8")]);
        assert_eq!(client_ip(false, &h, ip("203.0.113.7")), ip("203.0.113.7"));
        assert_eq!(client_ip(false, &h, None), None, "and no peer means no address at all");
    }

    #[test]
    fn a_trusted_proxy_supplies_the_client() {
        let peer = ip("10.0.0.1");
        // Right-most entry: the hop the proxy appended, not what the caller claimed.
        let chain = headers(&[("x-forwarded-for", " 198.51.100.9 , 10.0.0.2 ")]);
        assert_eq!(client_ip(true, &chain, peer), ip("10.0.0.2"));
        // X-Real-IP is the fallback when there's no XFF.
        let real = headers(&[("x-real-ip", "198.51.100.10")]);
        assert_eq!(client_ip(true, &real, peer), ip("198.51.100.10"));
        // XFF wins when both are present.
        let both = headers(&[("x-forwarded-for", "198.51.100.9"), ("x-real-ip", "198.51.100.10")]);
        assert_eq!(client_ip(true, &both, peer), ip("198.51.100.9"));
        // Garbage falls back to the peer rather than dropping the address.
        let junk = headers(&[("x-forwarded-for", "not-an-ip")]);
        assert_eq!(client_ip(true, &junk, peer), peer);
        assert_eq!(client_ip(true, &HeaderMap::new(), peer), peer, "no header at all");
    }

    #[test]
    fn a_caller_cannot_choose_its_own_address_behind_an_appending_proxy() {
        // nginx's `$proxy_add_x_forwarded_for` (and HAProxy's `option forwardfor`, and Caddy) append
        // what they see to what the caller sent. Reading the left-most entry would hand every caller a
        // free choice of address — and with it a way past an admission list, out of a lockout, or into
        // someone else's audit trail. The proxy's own entry is always the last one.
        let peer = ip("10.0.0.1"); // the proxy
        for spoof in ["127.0.0.1", "10.0.0.1", "::1", "192.0.2.1, 198.51.100.1"] {
            let forged = format!("{spoof}, 203.0.113.7"); // proxy appended the real client
            let h = headers(&[("x-forwarded-for", &forged)]);
            assert_eq!(
                client_ip(true, &h, peer),
                ip("203.0.113.7"),
                "caller claimed {spoof:?} and must not be believed"
            );
        }
        // A single entry (a proxy that *replaces* the header) is unambiguous either way.
        let replaced = headers(&[("x-forwarded-for", "203.0.113.7")]);
        assert_eq!(client_ip(true, &replaced, peer), ip("203.0.113.7"));
    }

    #[test]
    fn whitelists_match_across_families_and_representations() {
        // Every combination that can reach us: a rule in either family or in mapped form, against a
        // client address that arrived as plain IPv4, real IPv6, or IPv4-mapped IPv6.
        let nets = parse_nets(&[
            "10.0.0.0/8".into(),
            "192.0.2.7".into(),          // bare address → /32
            "2001:db8::/32".into(),
            "::ffff:198.51.100.0/120".into(), // mapped rule → 198.51.100.0/24
            "not-a-cidr".into(),         // junk is skipped, not fatal
        ]);
        for (client, expected, what) in [
            ("10.9.9.9", true, "plain v4 in a v4 rule"),
            ("::ffff:10.9.9.9", true, "mapped v4 in a v4 rule"),
            ("192.0.2.7", true, "bare host rule"),
            ("::ffff:192.0.2.7", true, "mapped client, bare host rule"),
            ("2001:db8::1", true, "v6 in a v6 rule"),
            ("198.51.100.9", true, "plain v4 in a *mapped* rule"),
            ("::ffff:198.51.100.9", true, "mapped v4 in a mapped rule"),
            ("192.168.1.1", false, "v4 outside every rule"),
            ("2001:db9::1", false, "v6 outside every rule"),
        ] {
            assert_eq!(in_nets(&nets, client.parse().unwrap()), expected, "{what}");
        }
        assert!(!in_nets(&[], "10.9.9.9".parse().unwrap()), "an empty list allows nothing");
    }

    #[test]
    fn ipv4_mapped_addresses_collapse_to_one_key() {
        // A dual-stack listener reports IPv4 clients as ::ffff:a.b.c.d; a proxy reports a.b.c.d. Both
        // must be the same key, or one client gets two lockout rows.
        assert_eq!(client_ip(false, &HeaderMap::new(), ip("::ffff:192.0.2.1")), ip("192.0.2.1"));
        let h = headers(&[("x-forwarded-for", "::ffff:192.0.2.1")]);
        assert_eq!(client_ip(true, &h, None), ip("192.0.2.1"));
        // Real IPv6 is untouched.
        assert_eq!(client_ip(false, &HeaderMap::new(), ip("2001:db8::1")), ip("2001:db8::1"));
    }
}
