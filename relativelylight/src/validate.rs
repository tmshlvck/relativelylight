//! Reusable field validators + normalizers — see `docs/DATAINPUT.md`.
//!
//! Validators are **typed predicates on the natural Rust type** (`fn(&str) -> Result<(), String>`,
//! or a factory returning `impl Fn(i64) -> Result<(), String>`), not `serde_json::Value` closures.
//! That makes the *same* check callable from a hand-written endpoint (which already holds a `&str` /
//! `i64`) and from the auto-CRUD write path: the latter goes through the thin adapters in
//! [`field`], which lift a typed predicate into a [`crud::Validator`](crate::crud::seaorm::Validator).
//!
//! The core (addresses, ranges, lengths, enums, hostnames, hex, uuid, url, email) is **std-only** and
//! always compiled. `regex_match` needs the `validate-regex` feature; `base64`/`base64_url` need
//! `validate-base64` (both reuse crates already in the tree). See `docs/DATAINPUT.md` § 6 for why the
//! rest is deliberately hand-rolled rather than pulling in `url`/`idna`/`email` crates.
//!
//! ```
//! use relativelylight::validate;
//! assert!(validate::ipv4("1.2.3.4").is_ok());
//! assert!(validate::ipv4("1.2.3.a").is_err());
//! assert!(validate::int_range(0, 65535)(70000).is_err());
//! ```

// ============================== Numbers ==============================

/// Inclusive integer range `[min, max]`.
pub fn int_range(min: i64, max: i64) -> impl Fn(i64) -> Result<(), String> {
    move |v| {
        if v < min || v > max {
            Err(format!("must be between {min} and {max}"))
        } else {
            Ok(())
        }
    }
}

/// `[min, i64::MAX]` — a lower bound only.
pub fn int_min(min: i64) -> impl Fn(i64) -> Result<(), String> {
    int_range(min, i64::MAX)
}

/// `[i64::MIN, max]` — an upper bound only.
pub fn int_max(max: i64) -> impl Fn(i64) -> Result<(), String> {
    int_range(i64::MIN, max)
}

/// A usable TCP/UDP port: `1..=65535` (0 is never a service port).
pub fn port(v: i64) -> Result<(), String> {
    if (1..=65535).contains(&v) {
        Ok(())
    } else {
        Err("must be a port number between 1 and 65535".into())
    }
}

/// Inclusive float range `[min, max]`; rejects `NaN`.
pub fn float_range(min: f64, max: f64) -> impl Fn(f64) -> Result<(), String> {
    move |v| {
        if v.is_nan() {
            Err("must be a number".into())
        } else if v < min || v > max {
            Err(format!("must be between {min} and {max}"))
        } else {
            Ok(())
        }
    }
}

// ============================== Network ==============================
// `std::net` is authoritative: it rejects `1.2.3.a`, `256.0.0.1`, leading-zero octets, `::g`, etc.

/// A dotted-quad IPv4 address.
pub fn ipv4(s: &str) -> Result<(), String> {
    s.parse::<std::net::Ipv4Addr>()
        .map(|_| ())
        .map_err(|_| "not a valid IPv4 address".into())
}

/// An IPv6 address (compressed / v4-mapped forms accepted).
pub fn ipv6(s: &str) -> Result<(), String> {
    s.parse::<std::net::Ipv6Addr>()
        .map(|_| ())
        .map_err(|_| "not a valid IPv6 address".into())
}

/// An IP address of either family.
pub fn ip(s: &str) -> Result<(), String> {
    s.parse::<std::net::IpAddr>()
        .map(|_| ())
        .map_err(|_| "not a valid IP address".into())
}

fn split_prefix(s: &str) -> Option<(&str, u8)> {
    let (addr, len) = s.split_once('/')?;
    Some((addr, len.parse().ok()?))
}

/// `a.b.c.d/len` with `len` in `0..=32` (host bits allowed — the lax form).
pub fn ipv4_network(s: &str) -> Result<(), String> {
    match split_prefix(s) {
        Some((a, len)) if len <= 32 && a.parse::<std::net::Ipv4Addr>().is_ok() => Ok(()),
        _ => Err("not a valid IPv4 network (a.b.c.d/len)".into()),
    }
}

/// `addr/len` with `len` in `0..=128` (host bits allowed — the lax form).
pub fn ipv6_network(s: &str) -> Result<(), String> {
    match split_prefix(s) {
        Some((a, len)) if len <= 128 && a.parse::<std::net::Ipv6Addr>().is_ok() => Ok(()),
        _ => Err("not a valid IPv6 network (addr/len)".into()),
    }
}

/// An IP network of either family.
pub fn ip_network(s: &str) -> Result<(), String> {
    ipv4_network(s)
        .or_else(|_| ipv6_network(s))
        .map_err(|_| "not a valid IP network".into())
}

// ============================== Strings ==============================

/// Reject empty and whitespace-only strings.
pub fn non_empty(s: &str) -> Result<(), String> {
    if s.trim().is_empty() {
        Err("must not be empty".into())
    } else {
        Ok(())
    }
}

/// Length in **Unicode scalar values** (what a user sees), inclusive `[min, max]`.
pub fn length(min: usize, max: usize) -> impl Fn(&str) -> Result<(), String> {
    move |s| {
        let n = s.chars().count();
        if n < min || n > max {
            Err(format!("length must be between {min} and {max} characters"))
        } else {
            Ok(())
        }
    }
}

/// Length in **bytes** (UTF-8 octets), inclusive `[min, max]` — for octet-bounded columns
/// (e.g. a DNS label, ≤ 63 octets).
pub fn length_bytes(min: usize, max: usize) -> impl Fn(&str) -> Result<(), String> {
    move |s| {
        let n = s.len();
        if n < min || n > max {
            Err(format!("length must be between {min} and {max} bytes"))
        } else {
            Ok(())
        }
    }
}

/// Membership in a fixed set (case-sensitive).
pub fn one_of(allowed: &'static [&'static str]) -> impl Fn(&str) -> Result<(), String> {
    move |s| {
        if allowed.contains(&s) {
            Ok(())
        } else {
            Err(format!("must be one of: {}", allowed.join(", ")))
        }
    }
}

/// Membership in a fixed set, ASCII-case-insensitive (e.g. CAA `tag`: `issue`/`issuewild`/`iodef`).
pub fn one_of_ci(allowed: &'static [&'static str]) -> impl Fn(&str) -> Result<(), String> {
    move |s| {
        if allowed.iter().any(|a| a.eq_ignore_ascii_case(s)) {
            Ok(())
        } else {
            Err(format!("must be one of: {}", allowed.join(", ")))
        }
    }
}

/// A hex string: `[0-9a-fA-F]`, non-empty, even number of digits.
pub fn hex(s: &str) -> Result<(), String> {
    if !s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("not a valid hex string (an even number of hex digits)".into())
    }
}

/// A hex string of exactly `bytes` bytes (i.e. `2 * bytes` hex digits) — e.g. a DS digest.
pub fn hex_len(bytes: usize) -> impl Fn(&str) -> Result<(), String> {
    move |s| {
        if s.len() == bytes * 2 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(())
        } else {
            Err(format!("must be {bytes} bytes ({} hex digits)", bytes * 2))
        }
    }
}

/// A canonical `8-4-4-4-12` hex UUID (any version).
pub fn uuid(s: &str) -> Result<(), String> {
    let groups = [8usize, 4, 4, 4, 12];
    let parts: Vec<&str> = s.split('-').collect();
    let ok = parts.len() == groups.len()
        && parts
            .iter()
            .zip(groups)
            .all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()));
    if ok {
        Ok(())
    } else {
        Err("not a valid UUID".into())
    }
}

/// A pragmatic email check: exactly one `@`, non-empty local part, and a hostname-shaped domain with
/// a dot. **Not** RFC 5322 — it catches typos, which is the goal. For stricter needs use
/// [`regex_match`] with your own pattern.
pub fn email(s: &str) -> Result<(), String> {
    let bad = || Err("not a valid email address".to_string());
    let Some((local, domain)) = s.split_once('@') else {
        return bad();
    };
    if local.is_empty()
        || local.chars().any(|c| c.is_whitespace())
        || domain.is_empty()
        || domain.contains('@')
        || !domain.contains('.')
    {
        return bad();
    }
    hostname(domain).map_err(|_| "not a valid email address".into())
}

/// A well-formed `http`/`https` URL (scheme + `://` + a non-empty host). Hand-rolled, std-only — not
/// full WHATWG parsing; use [`url_scheme`] to widen the accepted schemes.
pub fn url(s: &str) -> Result<(), String> {
    url_scheme(&["http", "https"])(s)
}

/// Like [`url`] but with a caller-supplied scheme allow-list.
pub fn url_scheme(schemes: &'static [&'static str]) -> impl Fn(&str) -> Result<(), String> {
    move |s| {
        let Some((scheme, rest)) = s.split_once("://") else {
            return Err("not a valid URL".into());
        };
        if !schemes.contains(&scheme) {
            return Err(format!("URL scheme must be one of: {}", schemes.join(", ")));
        }
        // authority = everything up to the first '/', '?' or '#'; strip optional userinfo + port.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let hostport = authority.rsplit('@').next().unwrap_or("");
        let host = hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(hostport);
        if host.is_empty() {
            Err("URL is missing a host".into())
        } else {
            Ok(())
        }
    }
}

// ============================== DNS-shaped ==============================

/// One LDH label: `1..=63` chars, ASCII letters/digits/hyphen (plus `_` when `underscore`), no
/// leading/trailing hyphen.
fn valid_label(l: &str, underscore: bool) -> bool {
    let b = l.as_bytes();
    if b.is_empty() || b.len() > 63 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        let ok = c.is_ascii_alphanumeric() || c == b'-' || (underscore && c == b'_');
        if !ok {
            return false;
        }
        if c == b'-' && (i == 0 || i == b.len() - 1) {
            return false;
        }
    }
    true
}

/// A relative hostname: one or more strict LDH labels, total ≤ 253 chars, **no** trailing dot.
pub fn hostname(s: &str) -> Result<(), String> {
    let bad = || Err("not a valid hostname".to_string());
    if s.is_empty() || s.len() > 253 || s.ends_with('.') {
        return bad();
    }
    if s.split('.').all(|l| valid_label(l, false)) {
        Ok(())
    } else {
        bad()
    }
}

/// A fully-qualified (absolute) domain name: [`hostname`] rules **plus** a required trailing dot —
/// matching how DNS rdata targets are stored. The bare root `"."` is accepted.
pub fn fqdn(s: &str) -> Result<(), String> {
    let Some(rest) = s.strip_suffix('.') else {
        return Err("a fully-qualified name must end with a dot".into());
    };
    if rest.is_empty() {
        return Ok(()); // root
    }
    hostname(rest).map_err(|_| "not a valid fully-qualified domain name".into())
}

/// A lenient DNS name: like [`hostname`] but tolerates leading-underscore labels (`_dmarc`,
/// `_acme-challenge`), an optional leading `*` wildcard label, and an optional trailing dot. Use for
/// owner/label fields; use [`hostname`]/[`fqdn`] for rdata targets.
pub fn dns_name(s: &str) -> Result<(), String> {
    let bad = || Err("not a valid DNS name".to_string());
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return bad();
    }
    for (i, label) in s.split('.').enumerate() {
        if i == 0 && label == "*" {
            continue; // wildcard
        }
        if !valid_label(label, true) {
            return bad();
        }
    }
    Ok(())
}

// ============================== Feature-gated ==============================

/// Match a regular expression. Compiles the pattern **once**; panics at construction on an invalid
/// pattern (it is developer input, not user input). The escape hatch for anything not covered above.
#[cfg(feature = "validate-regex")]
pub fn regex_match(pattern: &str) -> impl Fn(&str) -> Result<(), String> {
    let re = regex::Regex::new(pattern).expect("validate::regex_match: invalid regex pattern");
    move |s| {
        if re.is_match(s) {
            Ok(())
        } else {
            Err("invalid format".into())
        }
    }
}

/// Standard-alphabet base64 with valid padding (e.g. a DNSKEY public key).
#[cfg(feature = "validate-base64")]
pub fn base64(s: &str) -> Result<(), String> {
    use ::base64::Engine;
    ::base64::engine::general_purpose::STANDARD
        .decode(s)
        .map(|_| ())
        .map_err(|_| "not valid base64".into())
}

/// URL-safe-alphabet base64 with valid padding.
#[cfg(feature = "validate-base64")]
pub fn base64_url(s: &str) -> Result<(), String> {
    use ::base64::Engine;
    ::base64::engine::general_purpose::URL_SAFE
        .decode(s)
        .map(|_| ())
        .map_err(|_| "not valid base64 (url-safe)".into())
}

// ============================== Combinators ==============================

/// A boxed string predicate — the element type of [`all_of`] / argument of [`optional`], [`each`].
pub type StrPredicate = Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// Run predicates in order; return the **first** failure. `all_of(vec![Box::new(non_empty),
/// Box::new(fqdn)])`.
pub fn all_of(preds: Vec<StrPredicate>) -> impl Fn(&str) -> Result<(), String> {
    move |s| {
        for p in &preds {
            p(s)?;
        }
        Ok(())
    }
}

/// An empty string passes; otherwise delegate to `f`. For nullable / blank-allowed columns.
pub fn optional(f: StrPredicate) -> impl Fn(&str) -> Result<(), String> {
    move |s| {
        if s.is_empty() {
            Ok(())
        } else {
            f(s)
        }
    }
}

/// Split on `sep` and validate every element with `f`; reports the offending element's index.
pub fn each(sep: char, f: StrPredicate) -> impl Fn(&str) -> Result<(), String> {
    move |s| {
        for (i, part) in s.split(sep).enumerate() {
            f(part).map_err(|e| format!("element {i}: {e}"))?;
        }
        Ok(())
    }
}

// ============================== Normalizers ==============================

/// Value-cleaning transforms for the `on_write` hook (not validators — they *accept and
/// canonicalize* rather than reject). See `docs/DATAINPUT.md` § 5.
pub mod normalize {
    /// Strip surrounding whitespace.
    pub fn trim(s: &str) -> String {
        s.trim().to_string()
    }

    /// ASCII-lowercase (safe for hostnames; leaves non-ASCII untouched).
    pub fn lowercase(s: &str) -> String {
        s.to_ascii_lowercase()
    }

    /// Append a trailing dot if missing (make a name absolute). Empty stays empty.
    pub fn ensure_trailing_dot(s: &str) -> String {
        if s.is_empty() || s.ends_with('.') {
            s.to_string()
        } else {
            format!("{s}.")
        }
    }

    /// Re-emit an IP address in its canonical form (best-effort: unparseable input is left as-is).
    pub fn canonical_ip(s: &str) -> String {
        s.parse::<std::net::IpAddr>()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| s.to_string())
    }
}

// ============================== crud adapters ==============================

/// Adapters that lift a typed predicate/normalizer into the `serde_json::Value`-shaped hooks the CRUD
/// engine expects ([`Validator`](crate::crud::seaorm::Validator) /
/// [`WriteTransform`](crate::crud::seaorm::WriteTransform)). Compiled only with the `crud` feature.
///
/// Most callers should prefer the [`MetaField::validate_str`](crate::crud::seaorm::MetaField::validate_str)
/// / [`validate_int`](crate::crud::seaorm::MetaField::validate_int) builder sugar, which wraps these.
#[cfg(feature = "crud")]
pub mod field {
    use crate::crud::seaorm::{Validator, WriteTransform};
    use serde_json::Value;

    /// Lift a `&str` predicate into a field [`Validator`]. A `null` value passes (nullability is the
    /// column's concern); a non-string, non-null value is a type error (coercion normally catches it
    /// first).
    pub fn str_field<F>(f: F) -> Validator
    where
        F: Fn(&str) -> Result<(), String> + Send + Sync + 'static,
    {
        Box::new(move |v: &Value| match v.as_str() {
            Some(s) => f(s),
            None if v.is_null() => Ok(()),
            None => Err("expected a string".into()),
        })
    }

    /// Lift an `i64` predicate into a field [`Validator`]. `null` passes; a non-integer, non-null
    /// value is a type error.
    pub fn int_field<F>(f: F) -> Validator
    where
        F: Fn(i64) -> Result<(), String> + Send + Sync + 'static,
    {
        Box::new(move |v: &Value| match v.as_i64() {
            Some(n) => f(n),
            None if v.is_null() => Ok(()),
            None => Err("expected an integer".into()),
        })
    }

    /// Lift a `&str -> String` normalizer into a field [`WriteTransform`] (non-string values pass
    /// through untouched).
    pub fn str_transform<F>(f: F) -> WriteTransform
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        Box::new(move |v: Value| match v.as_str() {
            Some(s) => Value::String(f(s)),
            None => v,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_accepts_and_rejects() {
        assert!(ipv4("1.2.3.4").is_ok());
        assert!(ipv4("0.0.0.0").is_ok());
        assert!(ipv4("255.255.255.255").is_ok());
        for bad in ["1.2.3.a", "1.2.3", "1.2.3.4.5", "256.0.0.1", "", "1.2.3.4 ", "::1"] {
            assert!(ipv4(bad).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn ipv6_and_ip() {
        assert!(ipv6("::1").is_ok());
        assert!(ipv6("2001:db8::1").is_ok());
        assert!(ipv6("::ffff:1.2.3.4").is_ok());
        assert!(ipv6("::g").is_err());
        assert!(ipv6("1.2.3.4").is_err());
        assert!(ip("1.2.3.4").is_ok());
        assert!(ip("::1").is_ok());
        assert!(ip("nope").is_err());
    }

    #[test]
    fn networks() {
        assert!(ipv4_network("10.0.0.0/8").is_ok());
        assert!(ipv4_network("10.0.0.0/33").is_err());
        assert!(ipv4_network("10.0.0.0").is_err());
        assert!(ipv6_network("2001:db8::/32").is_ok());
        assert!(ipv6_network("2001:db8::/129").is_err());
        assert!(ip_network("10.0.0.0/8").is_ok());
        assert!(ip_network("2001:db8::/32").is_ok());
        assert!(ip_network("bad").is_err());
    }

    #[test]
    fn ranges_and_port() {
        let r = int_range(0, 65535);
        assert!(r(0).is_ok());
        assert!(r(65535).is_ok());
        assert!(r(-1).is_err());
        assert!(r(65536).is_err());
        assert!(int_min(5)(5).is_ok() && int_min(5)(4).is_err());
        assert!(int_max(5)(5).is_ok() && int_max(5)(6).is_err());
        assert!(port(53).is_ok());
        assert!(port(0).is_err() && port(70000).is_err());
        assert!(float_range(0.0, 1.0)(0.5).is_ok());
        assert!(float_range(0.0, 1.0)(f64::NAN).is_err());
        assert!(float_range(0.0, 1.0)(2.0).is_err());
    }

    #[test]
    fn strings() {
        assert!(non_empty("x").is_ok());
        assert!(non_empty("   ").is_err() && non_empty("").is_err());
        assert!(length(1, 3)("ab").is_ok() && length(1, 3)("abcd").is_err());
        assert!(length(1, 3)("").is_err());
        assert!(one_of(&["a", "b"])("a").is_ok() && one_of(&["a", "b"])("c").is_err());
        assert!(one_of_ci(&["issue"])("ISSUE").is_ok());
        assert!(one_of(&["issue"])("ISSUE").is_err());
    }

    #[test]
    fn hex_and_uuid() {
        assert!(hex("deadBEEF").is_ok());
        assert!(hex("abc").is_err() && hex("xy").is_err() && hex("").is_err());
        assert!(hex_len(2)("dead").is_ok() && hex_len(2)("de").is_err());
        assert!(uuid("123e4567-e89b-12d3-a456-426614174000").is_ok());
        assert!(uuid("123e4567e89b12d3a456426614174000").is_err());
        assert!(uuid("123e4567-e89b-12d3-a456-42661417400g").is_err());
    }

    #[test]
    fn email_and_url() {
        assert!(email("a@b.com").is_ok());
        for bad in ["a@b", "@b.com", "a@", "a@@b.com", "nope", "a b@c.com"] {
            assert!(email(bad).is_err(), "{bad} should be rejected");
        }
        assert!(url("https://example.com/x?y=1").is_ok());
        assert!(url("http://user@host:8080/").is_ok());
        assert!(url("ftp://example.com").is_err());
        assert!(url("http://").is_err());
        assert!(url("example.com").is_err());
        assert!(url_scheme(&["ftp"])("ftp://host").is_ok());
    }

    #[test]
    fn dns_names() {
        assert!(hostname("example.com").is_ok());
        assert!(hostname("a-b.example.com").is_ok());
        assert!(hostname("example.com.").is_err()); // trailing dot → not a relative hostname
        assert!(hostname("-bad.com").is_err() && hostname("bad-.com").is_err());
        assert!(hostname("_dmarc.example.com").is_err()); // strict LDH
        assert!(hostname(&format!("{}.com", "a".repeat(64))).is_err()); // label too long

        assert!(fqdn("example.com.").is_ok());
        assert!(fqdn(".").is_ok()); // root
        assert!(fqdn("example.com").is_err()); // missing trailing dot

        assert!(dns_name("_dmarc.example.com").is_ok());
        assert!(dns_name("*.example.com").is_ok());
        assert!(dns_name("example.com.").is_ok()); // trailing dot tolerated
        assert!(dns_name("bad_.com-").is_err());
    }

    #[test]
    fn combinators() {
        let v = all_of(vec![Box::new(non_empty), Box::new(fqdn)]);
        assert!(v("example.com.").is_ok());
        assert!(v("").is_err()); // fails non_empty
        assert!(v("example.com").is_err()); // fails fqdn

        let opt = optional(Box::new(ipv4));
        assert!(opt("").is_ok() && opt("1.2.3.4").is_ok() && opt("bad").is_err());

        let list = each(',', Box::new(ipv4));
        assert!(list("1.2.3.4,5.6.7.8").is_ok());
        assert!(list("1.2.3.4,bad").is_err());
    }

    #[test]
    fn normalizers() {
        assert_eq!(normalize::trim("  x  "), "x");
        assert_eq!(normalize::lowercase("EXAMPLE.COM"), "example.com");
        assert_eq!(normalize::ensure_trailing_dot("example.com"), "example.com.");
        assert_eq!(normalize::ensure_trailing_dot("example.com."), "example.com.");
        assert_eq!(normalize::ensure_trailing_dot(""), "");
        assert_eq!(normalize::canonical_ip("::0001"), "::1");
        assert_eq!(normalize::canonical_ip("bad"), "bad");
    }

    #[cfg(feature = "crud")]
    #[test]
    fn crud_adapters() {
        use serde_json::{json, Value};
        let v = field::str_field(ipv4);
        assert!(v(&json!("1.2.3.4")).is_ok());
        assert!(v(&json!("bad")).is_err());
        assert!(v(&Value::Null).is_ok()); // null → nullability's concern
        assert!(v(&json!(5)).is_err()); // wrong type

        let n = field::int_field(int_range(0, 10));
        assert!(n(&json!(5)).is_ok() && n(&json!(11)).is_err());
        assert!(n(&Value::Null).is_ok());

        let t = field::str_transform(normalize::ensure_trailing_dot);
        assert_eq!(t(json!("example.com")), json!("example.com."));
        assert_eq!(t(json!(5)), json!(5)); // non-string passes through
    }

    #[cfg(feature = "validate-base64")]
    #[test]
    fn base64_checks() {
        assert!(base64("aGVsbG8=").is_ok());
        assert!(base64("not base64!!").is_err());
        assert!(base64_url("aGVsbG8=").is_ok());
    }

    #[cfg(feature = "validate-regex")]
    #[test]
    fn regex_checks() {
        let v = regex_match(r"^\d{3}$");
        assert!(v("123").is_ok() && v("12").is_err() && v("abc").is_err());
    }
}
