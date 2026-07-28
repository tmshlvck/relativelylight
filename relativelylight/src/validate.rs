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

// ============================== Passwords ==============================

/// A password strength policy — **length first, composition rules off**.
///
/// That shape is deliberate and follows NIST SP 800-63B, which recommends screening a chosen password
/// for length and against a list of known-bad values, and explicitly advises **against** requiring
/// mixtures of character classes: users satisfy `Upper + digit + special` with `Password1!` and
/// `Summer2024!`, so the rule costs usability and buys a search space an attacker's cracking rules
/// already cover. The composition flags exist because external audits still ask for them
/// ([`legacy_composition`](PasswordPolicy::legacy_composition)) — they are off in every other preset.
///
/// What the presets do enforce: a **minimum length** (the one control that reliably helps), a
/// **maximum** so a megabyte of text can't be handed to argon2 as a cheap way to spend your CPU, no
/// control characters, and screening against [common values](PasswordPolicy::blocklist), your own
/// context words, and trivially patterned strings. Everything printable is otherwise allowed —
/// spaces, punctuation, emoji — and nothing is ever truncated.
///
/// **Not a breached-password corpus.** The built-in list is a floor: the few dozen values that top
/// every leak analysis, plus keyboard walks. A real check against breach data means a local corpus or
/// an online service (e.g. HIBP's k-anonymity range API), which is an app-level dependency and a
/// network call, so it isn't built in — add your own list via `blocklist`, or wrap this with
/// [`all_of`] and your own predicate.
///
/// ```
/// use relativelylight::validate::PasswordPolicy;
/// let p = PasswordPolicy::recommended();               // ≥ 12 chars, no composition rules
/// assert!(p.check("correct horse battery staple", &[]).is_ok());
/// assert!(p.check("short", &[]).is_err());             // too short
/// assert!(p.check("Password1234", &[]).is_err());      // a known-bad value with a digit tail
/// assert!(p.check("aaaaaaaaaaaaaa", &[]).is_err());    // one repeated character
/// // Context words are rejected as substrings — the caller supplies them (`auth` passes the username).
/// assert!(p.check("acmecorp-payroll-1", &["acmecorp"]).is_err());
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PasswordPolicy {
    /// Minimum length in **characters** (not bytes), so a non-ASCII password isn't judged by its
    /// UTF-8 size. NIST's floor for a user-chosen secret is 8; 12 is the sensible default.
    pub min_len: usize,
    /// Maximum length in characters. A limit is a *security* control, not a restriction: the value is
    /// fed to argon2, and hashing an unbounded input is a way to burn server CPU on request. Keep it
    /// well above any real password — NIST asks that at least 64 be accepted.
    pub max_len: usize,
    /// Require an uppercase letter. **Off** in every preset but
    /// [`legacy_composition`](PasswordPolicy::legacy_composition) — see the type's note.
    pub require_upper: bool,
    /// Require a lowercase letter. Off by default.
    pub require_lower: bool,
    /// Require a digit. Off by default.
    pub require_digit: bool,
    /// Require a character that is neither alphanumeric nor a space. Off by default.
    pub require_special: bool,
    /// Extra values to reject, matched **case-insensitively as substrings** — the app's own name, its
    /// domain, a product name. Containment (not equality) is right here: `acmecorp2024` is exactly the
    /// password this is meant to stop. `auth` adds the account's own username when it checks.
    pub blocklist: Vec<String>,
    /// Screen against the built-in list of common values (default `true`).
    pub screen_common: bool,
    /// Reject a single repeated character (`aaaaaaaa`), and any value **containing** a run of six or
    /// more consecutive characters (`12345678`, `abcdefgh`, `987654`, and `x123456y`). Default `true`.
    pub reject_patterns: bool,
}

/// The values that top every leak analysis, plus keyboard walks. Matched after case-folding and after
/// stripping a trailing run of digits/punctuation, so `Password1!` and `letmein2024` are caught too.
/// Deliberately short — see [`PasswordPolicy`] on why this isn't a breach corpus.
const COMMON_PASSWORDS: &[&str] = &[
    "password", "passwd", "pass", "secret", "letmein", "welcome", "admin", "administrator", "root",
    "user", "guest", "test", "login", "changeme", "default", "master", "dragon", "monkey", "football",
    "baseball", "sunshine", "princess", "iloveyou", "trustno", "starwars", "superman", "batman",
    "shadow", "michael", "jennifer", "jordan", "harley", "ranger", "hunter", "buster", "soccer",
    "hockey", "killer", "george", "andrew", "charlie", "thomas", "robert", "daniel", "summer",
    "winter", "spring", "autumn", "qwerty", "qwertyuiop", "azerty", "qwertz", "asdf", "asdfgh",
    "asdfghjkl", "zxcvbn", "zxcvbnm", "1qaz2wsx", "qazwsx", "abc", "abcd", "abcdef", "abcdefg",
    "123", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890", "111111",
    "000000", "121212", "654321", "photoshop", "relativelylight",
];

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self::recommended()
    }
}

impl PasswordPolicy {
    /// **NIST's floor**: ≥ 8 characters, screened for common values and trivial patterns, no
    /// composition rules. Use when an existing user base would be disrupted by anything longer.
    pub fn nist_minimum() -> Self {
        Self {
            min_len: 8,
            max_len: 128,
            require_upper: false,
            require_lower: false,
            require_digit: false,
            require_special: false,
            blocklist: Vec::new(),
            screen_common: true,
            reject_patterns: true,
        }
    }

    /// **The default**: as [`nist_minimum`](PasswordPolicy::nist_minimum) but ≥ 12 characters — the
    /// single change that buys the most, and short enough that a three-word phrase satisfies it.
    pub fn recommended() -> Self {
        Self { min_len: 12, ..Self::nist_minimum() }
    }

    /// ≥ 12 characters **plus** upper, lower, digit and special — for an audit or policy document that
    /// requires character classes. Offered because that requirement is real, not because it helps:
    /// see the note on [`PasswordPolicy`]. Prefer [`recommended`](PasswordPolicy::recommended).
    pub fn legacy_composition() -> Self {
        Self {
            require_upper: true,
            require_lower: true,
            require_digit: true,
            require_special: true,
            ..Self::recommended()
        }
    }

    /// Map a config integer onto a preset: `1` → [`nist_minimum`](PasswordPolicy::nist_minimum),
    /// `2` → [`recommended`](PasswordPolicy::recommended), `3` →
    /// [`legacy_composition`](PasswordPolicy::legacy_composition). Anything else → `recommended`, so a
    /// typo in a config file lands on the sensible policy rather than the weakest one.
    pub fn from_level(level: u8) -> Self {
        match level {
            1 => Self::nist_minimum(),
            3 => Self::legacy_composition(),
            _ => Self::recommended(),
        }
    }

    /// Reject these values as substrings, case-insensitively (see
    /// [`blocklist`](PasswordPolicy::blocklist)).
    pub fn block<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.blocklist.extend(values.into_iter().map(Into::into));
        self
    }

    /// Set the minimum length (characters).
    pub fn min_len(mut self, n: usize) -> Self {
        self.min_len = n;
        self
    }

    /// Check `password`, additionally rejecting any of `context` as a substring — the caller's
    /// cross-field words, e.g. the account's own username. Returns a message fit to show the user:
    /// NIST asks that a rejection say *why*, so the next attempt can be better rather than luckier.
    pub fn check(&self, password: &str, context: &[&str]) -> Result<(), String> {
        let chars = password.chars().count();
        if chars < self.min_len {
            return Err(format!("must be at least {} characters long", self.min_len));
        }
        if chars > self.max_len {
            return Err(format!("must be at most {} characters long", self.max_len));
        }
        // Control characters are never intended — they arrive by paste accident or by a client that
        // mangled the field, and would be impossible to retype.
        if password.chars().any(char::is_control) {
            return Err("must not contain control characters".into());
        }
        if self.require_upper && !password.chars().any(char::is_uppercase) {
            return Err("must contain an uppercase letter".into());
        }
        if self.require_lower && !password.chars().any(char::is_lowercase) {
            return Err("must contain a lowercase letter".into());
        }
        if self.require_digit && !password.chars().any(|c| c.is_numeric()) {
            return Err("must contain a digit".into());
        }
        if self.require_special
            && !password.chars().any(|c| !c.is_alphanumeric() && !c.is_whitespace())
        {
            return Err("must contain a symbol".into());
        }

        let folded = password.to_lowercase();
        for word in self.blocklist.iter().map(|s| s.as_str()).chain(context.iter().copied()) {
            let word = word.trim().to_lowercase();
            if word.len() >= 3 && folded.contains(&word) {
                return Err("must not contain a name or word associated with this account".into());
            }
        }
        if self.screen_common {
            // Strip a trailing run of digits/symbols so the perennial `password1!` shape is caught by
            // the same list entry as `password`.
            let stem = folded.trim_end_matches(|c: char| !c.is_alphabetic() || c.is_numeric());
            let stem = if stem.is_empty() { folded.as_str() } else { stem };
            let repeated = |w: &str| {
                // `passwordpassword` — long enough to pass a length rule, no harder to guess than one
                // copy. Only an exact whole-string repetition counts.
                !w.is_empty() && folded.len() > w.len() && folded.len().is_multiple_of(w.len()) && {
                    let n = folded.len() / w.len();
                    folded == w.repeat(n)
                }
            };
            // Whole-value comparison, **not** a substring search: entries like `abc`, `user` and
            // `master` appear inside any number of perfectly good passphrases, and rejecting
            // "the master plan for dinner" would teach users to distrust the check.
            if COMMON_PASSWORDS.iter().any(|w| *w == folded || *w == stem || repeated(w)) {
                return Err("is a commonly used password — choose something less predictable".into());
            }
        }
        if self.reject_patterns && is_patterned(password) {
            return Err("must not repeat one character or contain a run like 123456".into());
        }
        Ok(())
    }
}

/// The shortest ascending/descending run treated as a pattern. Six is the classic `123456` / `abcdef`;
/// shorter would start rejecting ordinary words (`rst` in "worst", `stu` in "student").
const MIN_RUN: usize = 6;

/// Whether the value is one repeated character, or *contains* a run of [`MIN_RUN`] consecutive
/// characters in either direction. Checked over `char`s, so it holds outside ASCII too.
///
/// The run check is a **substring** test on purpose: `123456789012` is long enough to satisfy any
/// length rule and is nothing but a keyboard walk with two digits appended, which a whole-string test
/// would wave through. False positives are rare — ordinary passphrases don't contain `abcdef`.
fn is_patterned(password: &str) -> bool {
    let chars: Vec<char> = password.chars().collect();
    if chars.len() < 2 {
        return false;
    }
    // A single repeated character: a step of 0, which the run scan below deliberately ignores.
    if chars.iter().all(|c| *c == chars[0]) {
        return true;
    }
    let mut run = 1usize; // characters in the current ±1 run, including its first
    let mut step = 0i32;
    for w in chars.windows(2) {
        let d = w[1] as i32 - w[0] as i32;
        if (d == 1 || d == -1) && (run == 1 || d == step) {
            run += 1;
            step = d;
            if run >= MIN_RUN {
                return true;
            }
        } else {
            run = 1;
            step = 0;
        }
    }
    false
}

/// A [`PasswordPolicy`] as a plain string predicate, for the crud write path:
/// `user.field("password_hash").validate_str(validate::password(policy))`.
///
/// The order of the crud pipeline is **coerce → validate → transform**, so this sees the *plaintext*
/// the form submitted, before [`MetaField::password`](crate::crud::seaorm::MetaField::password)'s
/// `on_write` hashes it — no engine change needed.
///
/// **Wrap it in [`optional`] if blank has a meaning on that column**, which it does for
/// `MetaField::password()`: blank on edit means "keep the current password", blank on create means "no
/// password, login disabled". Without `optional` those become validation errors.
///
/// Context words (the account's own username) can't be seen by a single-field validator — that's
/// cross-field, so it belongs in `validate_row`, or on the `auth` surface, which knows the user and
/// passes the username to [`PasswordPolicy::check`] itself.
pub fn password(policy: PasswordPolicy) -> impl Fn(&str) -> Result<(), String> {
    move |s| policy.check(s, &[])
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
    fn password_policy_screens_length_common_values_and_patterns() {
        let p = PasswordPolicy::recommended();
        // The shape the policy is *for*: long, unremarkable, no character-class gymnastics.
        for good in [
            "correct horse battery staple",
            "twelvechars!",
            "ᚠᚢᚦᚨᚱᚲᚷᚹᚺᚾᛁᛃ",              // non-ASCII counts by character, not by UTF-8 byte
            "🙂🙃🙂🙃🙂🙃🙂🙃🙂🙃🙂🙃",
            "aaaaaaaaaaab",                 // repeated but not *entirely* one character
        ] {
            assert!(p.check(good, &[]).is_ok(), "{good:?} should pass: {:?}", p.check(good, &[]));
        }
        // Too short, including a value that would pass every composition rule ever written.
        for short in ["", "x", "Aa1!Aa1!", "Sh0rt!"] {
            assert!(p.check(short, &[]).is_err(), "{short:?} is under 12 characters");
        }
        // Known-bad values, including the digit/symbol-tail shapes a composition rule invites.
        for common in [
            "passwordpassword",
            "Password1234",
            "letmein2024!",
            "qwertyuiop12",
            "123456789012",
            "administrator",
        ] {
            assert!(p.check(common, &[]).is_err(), "{common:?} is a common value");
        }
        // Whole-string patterns, in both directions.
        for pattern in ["aaaaaaaaaaaaaa", "abcdefghijklm", "nmlkjihgfedcba"] {
            assert!(p.check(pattern, &[]).is_err(), "{pattern:?} is a run");
        }
        // Control characters can't be retyped, so they're never what the user meant.
        assert!(p.check("goodpassphrase\n", &[]).is_err());
        assert!(p.check("good\0passphrase", &[]).is_err());
        // A maximum exists so an unbounded input can't be handed to argon2 as a CPU bill.
        assert!(p.check(&"a1B2c3!x".repeat(50), &[]).is_err(), "800 characters is refused");
    }

    #[test]
    fn password_policy_rejects_context_words() {
        // Cross-field in spirit — `auth` passes the account's username, an app passes its own name.
        let p = PasswordPolicy::recommended().block(["AcmeCorp"]);
        assert!(p.check("acmecorp-secrets", &[]).is_err(), "the configured word, folded");
        assert!(p.check("xxACMECORPxxxxxx", &[]).is_err(), "any case, anywhere in the value");
        assert!(p.check("unrelated phrase here", &[]).is_ok());
        // Caller-supplied context, e.g. the username.
        assert!(p.check("alice-in-wonderland", &["alice"]).is_err());
        assert!(p.check("alice-in-wonderland", &["bob"]).is_ok());
        // Two characters is too short to screen on — it would reject almost everything.
        assert!(p.check("alice-in-wonderland", &["al"]).is_ok(), "a 2-char context word is ignored");
        assert!(p.check("alice-in-wonderland", &[""]).is_ok(), "and an empty one can't match");
    }

    #[test]
    fn password_policy_presets_and_levels() {
        assert_eq!(PasswordPolicy::nist_minimum().min_len, 8);
        assert_eq!(PasswordPolicy::recommended().min_len, 12);
        assert_eq!(PasswordPolicy::default().min_len, 12);
        // The minimum accepts a shorter secret that `recommended` refuses — and still screens it.
        assert!(PasswordPolicy::nist_minimum().check("mangosteen", &[]).is_ok());
        assert!(PasswordPolicy::recommended().check("mangosteen", &[]).is_err());
        assert!(PasswordPolicy::nist_minimum().check("password", &[]).is_err(), "still screened");

        // No preset but the legacy one imposes character classes.
        for p in [PasswordPolicy::nist_minimum(), PasswordPolicy::recommended()] {
            assert!(!p.require_upper && !p.require_digit && !p.require_special && !p.require_lower);
        }
        let legacy = PasswordPolicy::legacy_composition();
        assert!(legacy.check("all lowercase words", &[]).is_err(), "wants upper/digit/symbol");
        assert!(legacy.check("Tr0ubadour&Cheese", &[]).is_ok());

        // A config integer maps onto the presets, and an unknown value lands on the sensible one.
        assert_eq!(PasswordPolicy::from_level(1).min_len, 8);
        assert_eq!(PasswordPolicy::from_level(2).min_len, 12);
        assert!(PasswordPolicy::from_level(3).require_special);
        assert_eq!(PasswordPolicy::from_level(9).min_len, 12, "a typo must not weaken the policy");
        assert!(!PasswordPolicy::from_level(0).require_special);
    }

    #[test]
    fn password_predicate_wraps_for_the_crud_path() {
        let check = password(PasswordPolicy::recommended());
        assert!(check("a decent passphrase").is_ok());
        assert!(check("short").is_err());
        // Blank is a *meaning* on a password column (keep current / no password), so the caller wraps
        // in `optional` — the predicate itself has no opinion.
        assert!(check("").is_err(), "the bare predicate rejects blank");
        let lenient = optional(Box::new(password(PasswordPolicy::recommended())));
        assert!(lenient("").is_ok(), "wrapped, blank passes through");
        assert!(lenient("short").is_err(), "but a real value is still checked");
    }

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
