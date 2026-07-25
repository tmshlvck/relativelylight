//! Attempt limiting for the credential checks — the brute-force brake in front of `POST /login`, the
//! TOTP second factor, the profile password check, and 2FA enrolment. See `docs/AUTH.md` §5e.
//!
//! **Sliding window, temporary lockout.** Each failure is recorded against a key; while a key has
//! `max` failures inside the last `window` seconds it is *locked* — the handler answers `429` with a
//! `Retry-After` and never looks at the submitted secret (so a locked-out account costs no argon2 work
//! and leaks nothing about whether it exists). Attempts made *while locked* are **not** recorded, so an
//! attacker can't hold a lock open indefinitely: it lifts as the recorded failures age out of the
//! window. A successful login clears the account's failures, and
//! [`Auth::clear_login_attempts`](crate::auth::Auth::clear_login_attempts) is the operator's unlock.
//!
//! **In-memory, per process.** The counters live in this process's heap: they reset on restart, and
//! each replica of a horizontally-scaled deployment counts on its own (N replicas → N× the effective
//! budget). That is a deliberate trade for zero schema and zero DB traffic on the hot path; an app that
//! needs shared or durable counters should put a limiter in front of the app (or its proxy) instead.

use std::collections::HashMap;
use std::sync::Mutex;

/// Above this many tracked keys, a `record` also sweeps expired ones — an attacker spraying random
/// usernames must not be able to grow the map without bound.
const SWEEP_ABOVE: usize = 1024;

/// How many failures within how long lock a key out. `max_*` of `None` (or `0`) disables that key.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LoginLimit {
    /// Failures per account name before it's locked. Default `Some(10)`.
    pub(crate) max_username: Option<u32>,
    /// Failures per source IP before it's locked. Default `None` — see `Auth::login_limit_per_ip`.
    pub(crate) max_ip: Option<u32>,
    /// The sliding window, in seconds. Default 900 (15 minutes).
    pub(crate) window_secs: i64,
}

impl Default for LoginLimit {
    fn default() -> Self {
        Self { max_username: Some(10), max_ip: None, window_secs: 15 * 60 }
    }
}

/// The failure counters. Cheap to share (one mutex; the critical section is a `Vec` push/retain).
#[derive(Default, Debug)]
pub(crate) struct Limiter {
    hits: Mutex<HashMap<String, Vec<i64>>>,
}

impl Limiter {
    /// Seconds until `key` may try again, or `None` if it isn't locked. `max == 0` means "no limit".
    pub(crate) fn locked_for(&self, key: &str, max: u32, window: i64, now: i64) -> Option<i64> {
        if max == 0 {
            return None;
        }
        let hits = self.hits.lock().ok()?;
        let fresh: Vec<i64> = fresh_hits(hits.get(key)?, window, now);
        if (fresh.len() as u32) < max {
            return None;
        }
        // Locked until the oldest counted failure ages out of the window.
        let oldest = *fresh.first().unwrap_or(&now);
        Some((oldest + window - now).max(1))
    }

    /// Record one failure against `key` (pruning what has aged out).
    pub(crate) fn record(&self, key: &str, window: i64, now: i64) {
        let Ok(mut hits) = self.hits.lock() else { return };
        let entry = hits.entry(key.to_string()).or_default();
        *entry = fresh_hits(entry, window, now);
        entry.push(now);
        if hits.len() > SWEEP_ABOVE {
            hits.retain(|_, times| times.iter().any(|t| *t > now - window));
        }
    }

    /// Forget every failure recorded against `key` (a success, or an operator unlock).
    pub(crate) fn clear(&self, key: &str) {
        if let Ok(mut hits) = self.hits.lock() {
            hits.remove(key);
        }
    }
}

/// The recorded failures still inside the window, oldest first.
fn fresh_hits(times: &[i64], window: i64, now: i64) -> Vec<i64> {
    let mut fresh: Vec<i64> = times.iter().copied().filter(|t| *t > now - window).collect();
    fresh.sort_unstable();
    fresh
}

/// The key namespaces. Separate buckets so that, say, fumbling your current password on the profile
/// page can't lock you out of logging in — while the password step and the TOTP step of one login
/// deliberately **share** the account's bucket (both are that account being guessed at).
pub(crate) fn login_key(username: &str) -> String {
    format!("login:{}", username.to_lowercase())
}
pub(crate) fn ip_key(ip: std::net::IpAddr) -> String {
    format!("ip:{ip}")
}
pub(crate) fn profile_key(username: &str) -> String {
    format!("profile:{}", username.to_lowercase())
}
pub(crate) fn enrol_key(username: &str) -> String {
    format!("enrol:{}", username.to_lowercase())
}

/// Every user-keyed namespace for `username` — what an operator unlock clears.
pub(crate) fn all_user_keys(username: &str) -> [String; 3] {
    [login_key(username), profile_key(username), enrol_key(username)]
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: i64 = 900;
    const MAX: u32 = 3;

    /// Record `n` failures at `now`.
    fn fail(l: &Limiter, key: &str, n: usize, now: i64) {
        for _ in 0..n {
            l.record(key, WINDOW, now);
        }
    }

    #[test]
    fn locks_only_at_the_limit() {
        let l = Limiter::default();
        assert_eq!(l.locked_for("k", MAX, WINDOW, 1_000), None, "an unknown key is never locked");
        fail(&l, "k", 2, 1_000);
        assert_eq!(l.locked_for("k", MAX, WINDOW, 1_000), None, "under the limit");
        fail(&l, "k", 1, 1_000);
        assert_eq!(l.locked_for("k", MAX, WINDOW, 1_000), Some(WINDOW), "the 3rd failure locks");
    }

    #[test]
    fn the_lock_lifts_as_failures_age_out() {
        let l = Limiter::default();
        fail(&l, "k", MAX as usize, 1_000);
        // Part-way through the window it's still locked, and says how long is left.
        assert_eq!(l.locked_for("k", MAX, WINDOW, 1_000 + 300), Some(600));
        assert_eq!(l.locked_for("k", MAX, WINDOW, 1_000 + WINDOW - 1), Some(1));
        // Once the oldest failure is outside the window the count drops below max.
        assert_eq!(l.locked_for("k", MAX, WINDOW, 1_000 + WINDOW + 1), None);
    }

    #[test]
    fn attempts_while_locked_do_not_extend_the_lock() {
        // The handler only records a *checked* failure, never one it refused with 429 — so a stream of
        // attacker attempts can't keep an account locked forever. Simulated here by not recording.
        let l = Limiter::default();
        fail(&l, "k", MAX as usize, 1_000);
        for t in 1_001..1_100 {
            assert!(l.locked_for("k", MAX, WINDOW, t).is_some(), "still locked at {t}");
        }
        assert_eq!(l.locked_for("k", MAX, WINDOW, 1_000 + WINDOW + 1), None, "and it does lift");
    }

    #[test]
    fn clear_and_key_isolation() {
        let l = Limiter::default();
        fail(&l, "login:alice", MAX as usize, 1_000);
        fail(&l, "login:bob", 1, 1_000);
        assert!(l.locked_for("login:alice", MAX, WINDOW, 1_000).is_some());
        assert_eq!(l.locked_for("login:bob", MAX, WINDOW, 1_000), None, "keys are independent");

        l.clear("login:alice");
        assert_eq!(l.locked_for("login:alice", MAX, WINDOW, 1_000), None, "cleared");
        // A clear is not a permanent exemption — the next burst locks again.
        fail(&l, "login:alice", MAX as usize, 1_000);
        assert!(l.locked_for("login:alice", MAX, WINDOW, 1_000).is_some());
    }

    #[test]
    fn a_max_of_zero_disables_the_key() {
        let l = Limiter::default();
        fail(&l, "k", 50, 1_000);
        assert_eq!(l.locked_for("k", 0, WINDOW, 1_000), None, "0 = no limit, never lock out");
    }

    #[test]
    fn spraying_distinct_keys_does_not_grow_the_map_without_bound() {
        let l = Limiter::default();
        // Old junk from a spray, then fresh traffic well past the sweep threshold.
        for i in 0..SWEEP_ABOVE + 200 {
            l.record(&format!("login:junk{i}"), WINDOW, 1_000);
        }
        let later = 1_000 + WINDOW + 1;
        for i in 0..10 {
            l.record(&format!("login:real{i}"), WINDOW, later);
        }
        let tracked = l.hits.lock().unwrap().len();
        assert!(tracked <= 200 + 10, "expired keys are swept, {tracked} left");
        assert!(tracked >= 10, "but live ones are kept");
    }

    #[test]
    fn keys_are_namespaced_and_case_folded() {
        assert_eq!(login_key("Alice"), "login:alice", "case can't dodge the account bucket");
        assert_ne!(login_key("alice"), profile_key("alice"));
        assert_ne!(profile_key("alice"), enrol_key("alice"));
        assert_eq!(all_user_keys("alice").len(), 3, "an unlock clears every user-keyed bucket");
        assert_eq!(ip_key("10.0.0.1".parse().unwrap()), "ip:10.0.0.1");
    }

    #[test]
    fn defaults_are_username_only() {
        let d = LoginLimit::default();
        assert_eq!(d.max_username, Some(10));
        assert_eq!(d.max_ip, None, "per-IP is opt-in: behind a proxy every caller shares one IP");
        assert_eq!(d.window_secs, 900);
    }
}
