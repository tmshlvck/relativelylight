//! `relativelylight::net` — the **address vocabulary** shared by everything that handles a client IP:
//! canonicalization (`canonical`, `canonical_net`) and CIDR matching (`parse_nets`, `in_nets`).
//!
//! Deliberately no *policy* — resolving "who is calling" is
//! [`middleware::resolve_real_ip`](crate::middleware::resolve_real_ip)'s job, and it lives there because
//! it needs a request. What is left here is the part two unrelated consumers both need and neither should
//! own: the middleware canonicalizes the address it resolves, and `auth`'s lockout canonicalizes the key it
//! writes and matches [`Lockout::ip_whitelist`](crate::auth::lockout::Lockout::ip_whitelist) against it.
//!
//! The canonicalization matters more than it looks: a dual-stack listener reports an IPv4 client as
//! `::ffff:a.b.c.d` while a proxy reports `a.b.c.d`. Without folding those together, one client gets two
//! lockout rows and a whitelist rule written one way misses a client that arrived the other.

use ipnet::{IpNet, Ipv4Net};
use std::net::IpAddr;

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
        // must canonicalize to the same key, or one client gets two lockout rows.
        assert_eq!(canonical(ip("::ffff:192.0.2.1").unwrap()), ip("192.0.2.1").unwrap());
        assert_eq!(canonical(ip("192.0.2.1").unwrap()), ip("192.0.2.1").unwrap(), "idempotent");
        // Real IPv6 is untouched.
        assert_eq!(canonical(ip("2001:db8::1").unwrap()), ip("2001:db8::1").unwrap());
    }
}
