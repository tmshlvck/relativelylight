//! Lockout — the brute-force brake in front of the **unauthenticated** credential checks: `POST
//! /login`, the still-pending second factor at `POST /login/totp`, and whatever the app checks itself
//! (HTTP Basic on a machine endpoint, an API token). See `docs/AUTH.md` §5e.
//!
//! Two counters, two tables, two deliberately separate types: [`UsernameLockout`] keyed by account
//! name and [`IpLockout`] keyed by source address. They do the same arithmetic today and are expected
//! to diverge (a username whitelist wants regexes, an address whitelist wants CIDRs), so they don't
//! share an implementation.
//!
//! **The rule.** A failure upserts the row (`failures += 1`, `last_failure_at = now`) *unless* the key
//! is already at the limit — a locked key records nothing, so an attacker can't push the expiry out.
//! A key is locked while `failures >= after` and `last_failure_at + duration > now`; once that passes,
//! the row reads as absent again and [`prune`](UsernameLockout::prune) deletes it. So the effective
//! semantics are **"`after` failures, each within `duration` of the previous, lock the key for
//! `duration` after the last one"** — a decaying window, not a strict sliding one. A successful check
//! clears the row.
//!
//! **Why the database.** These rows are the operator's interface: they show who is being guessed at,
//! and deleting one *is* the unlock — through the app's ordinary admin panel, gated, CSRF-checked and
//! audited like any other entity, with no bespoke endpoint. They also survive a restart (a deploy
//! must not hand every attacker a fresh budget) and are shared by every replica. Failures are rare in
//! normal operation, so this costs the DB nothing: a locked key is read-only, and a healthy system
//! writes here about never.
//!
//! **Nothing here is scheduled.** Expired rows are harmless (they read as absent and reset themselves
//! on the next failure), so pruning is the app's housekeeping call — see [`crate::auth::prune`].

use ipnet::IpNet;
use sea_orm::sea_query::OnConflict;
use sea_orm::ActiveValue::Set;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, IntoActiveModel,
    QueryFilter,
};
use std::net::IpAddr;
use std::sync::Arc;

/// How many failures lock a key out, and for how long. Passed to [`Auth::new`](crate::auth::Auth::new)
/// — the brake is not optional, so there is no way to forget to configure it; `0` failures disables a
/// counter for a deployment that limits at its edge.
///
/// Defaults: 10 failures per account, 100 per address, both for 15 minutes. The address budget is
/// deliberately far looser: a locked address turns away *valid* callers too, which matters when your
/// users share one (CGNAT, an office NAT, a reverse proxy).
///
/// The *address* half needs to know who the client is: on this module's login routes that is
/// [`trust_proxy`](Self::trust_proxy) (peer vs forwarded header), or a custom
/// [`Auth::client_ip`](crate::auth::Auth::client_ip) resolver. The app's own surfaces pass an address to
/// [`IpLockout`] themselves and are unaffected.
#[derive(Clone, Debug)]
pub struct Lockout {
    /// Failed logins for one account name before it is locked (`0` = never).
    pub username_after: u32,
    /// How long that account stays locked, in seconds — and, equivalently, how much silence resets its
    /// counter. Clamped to at least 1: a zero duration means the lock expires the moment it is taken,
    /// so disable a counter with `username_after: 0` (which writes no rows) rather than a zero here.
    pub username_duration_secs: i64,
    /// Failed credential checks from one address before it is locked (`0` = never).
    pub ip_after: u32,
    /// How long that address stays locked, in seconds (see [`username_duration_secs`] for what a zero
    /// does). The two windows are independent: an address is a coarser subject than an account, so it
    /// is usually worth a different one.
    ///
    /// [`username_duration_secs`]: Lockout::username_duration_secs
    pub ip_duration_secs: i64,
    /// Whether a reverse proxy in front of the app may be believed about who the client is — the same
    /// flag an app almost certainly has in its own config, passed straight through to
    /// [`net::client_ip`](crate::net::client_ip).
    ///
    /// `false` (the default) means the login routes count the **socket peer**, which is correct for a
    /// directly exposed app and the only safe reading there: forwarded headers are attacker-supplied,
    /// so trusting them would let a caller choose whose address gets locked out. `true` means the
    /// left-most `X-Forwarded-For` (or `X-Real-IP`) entry is the client — set it **only** if nothing
    /// can reach the app except your proxy, and remember that leaving it `false` behind a proxy buckets
    /// every user under the proxy's address, where a hundred failures lock your whole login form.
    ///
    /// Exotic setups (several hops, a CDN's own header) override the whole resolution with
    /// [`Auth::client_ip`](crate::auth::Auth::client_ip) instead.
    pub trust_proxy: bool,
    /// Addresses that are **never** locked out, as CIDRs — your office range, a monitoring probe, the
    /// host a fleet of devices NATs through. Build it with [`net::parse_nets`](crate::net::parse_nets),
    /// which accepts bare addresses as single hosts and takes IPv4 and IPv6 (an IPv4-mapped rule
    /// matches a plain IPv4 client and vice versa, so it cannot matter how the address reached us).
    ///
    /// An whitelisted address is neither counted nor checked — on *every* surface, this module's and
    /// the app's, since both go through [`IpLockout`]. It does not exempt the **account** counter: an
    /// whitelisted office can still lock one account by guessing at it, which is the point (the
    /// address list is there so one shared address can't take everyone down with it).
    ///
    /// Empty by default. There is deliberately no username whitelist: an account that must never be
    /// locked out is an account whose password can be guessed at forever.
    pub ip_whitelist: Vec<IpNet>,
}

impl Default for Lockout {
    fn default() -> Self {
        Self {
            username_after: 10,
            username_duration_secs: 15 * 60,
            ip_after: 100,
            ip_duration_secs: 15 * 60,
            trust_proxy: false,
            ip_whitelist: Vec::new(),
        }
    }
}

/// A locked-out account. Table `auth_username_lockout`, one row per account name that has recent
/// failures — including names that don't exist, which must be counted too or the lockout itself
/// becomes an account-enumeration oracle. Register it in your admin panel (read + delete) to give
/// operators the unlock.
pub mod username_entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
    #[sea_orm(table_name = "auth_username_lockout")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        /// The submitted account name, lower-cased so case can't dodge the bucket.
        pub username: String,
        pub failures: i32,
        /// Unix seconds of the most recent counted failure.
        pub last_failure_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// A locked-out source address. Table `auth_ip_lockout`, one row per address with recent failures.
pub mod ip_entity {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
    #[sea_orm(table_name = "auth_ip_lockout")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        /// The client address, canonicalized (`IpAddr`'s own text form).
        pub ip: String,
        pub failures: i32,
        /// Unix seconds of the most recent counted failure.
        pub last_failure_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// The account-name counter. Cheap to clone (a DB handle plus two numbers); get one from
/// [`Auth::username_lockout`](crate::auth::Auth::username_lockout) so the app's own credential checks
/// share the login form's budget.
#[derive(Clone, Debug)]
pub struct UsernameLockout {
    db: DatabaseConnection,
    after: u32,
    duration: i64,
}

impl UsernameLockout {
    pub(crate) fn new(db: DatabaseConnection, after: u32, duration_secs: i64) -> Self {
        Self { db, after, duration: duration_secs.max(1) }
    }

    /// Seconds until this account may be checked again, or `None` if it isn't locked. A pure read:
    /// call it *before* looking at the submitted secret, so a locked account costs no argon2 work and
    /// the answer says nothing about whether it exists.
    pub async fn locked(&self, username: &str) -> Option<i64> {
        if self.after == 0 {
            return None;
        }
        let row = username_entity::Entity::find_by_id(normalize_username(username))
            .one(&self.db)
            .await
            .ok()??;
        retry_after(row.failures, row.last_failure_at, self.after, self.duration)
    }

    /// Record one **checked and rejected** credential. Returns whether this failure is the one that
    /// locked the account, so the caller can log it once instead of on every subsequent attempt.
    ///
    /// Never record an attempt you refused for another reason — no credential presented, a failed CSRF
    /// check, or one already locked out — or a third party can spend someone else's budget.
    pub async fn record_failure(&self, username: &str) -> bool {
        if self.after == 0 {
            return false;
        }
        let (key, now) = (normalize_username(username), now_secs());
        let existing = username_entity::Entity::find_by_id(key.clone()).one(&self.db).await.ok().flatten();
        let failures = match existing {
            // At or over the limit: leave the row alone. A locked key records nothing, so continued
            // attempts can't push the expiry out.
            Some(row) if row.failures as u32 >= self.after => return false,
            // An expired row starts over rather than resuming an old count.
            Some(row) => {
                let n = if row.last_failure_at + self.duration <= now { 1 } else { row.failures + 1 };
                let mut am = row.into_active_model();
                am.failures = Set(n);
                am.last_failure_at = Set(now);
                let _ = am.update(&self.db).await;
                n
            }
            None => {
                let am = username_entity::ActiveModel {
                    username: Set(key),
                    failures: Set(1),
                    last_failure_at: Set(now),
                };
                // A concurrent first failure may have inserted it already; both then agree on 1, which
                // under-counts by one at most — the safe direction.
                let _ = username_entity::Entity::insert(am)
                    .on_conflict(OnConflict::new().do_nothing().to_owned())
                    .do_nothing()
                    .exec(&self.db)
                    .await;
                1
            }
        };
        failures as u32 >= self.after
    }

    /// Forget this account's failures — a successful check, or an operator unlock.
    pub async fn clear(&self, username: &str) {
        let _ = username_entity::Entity::delete_by_id(normalize_username(username))
            .exec(&self.db)
            .await;
    }

    /// Delete rows whose lockout has expired. Optional for correctness (an expired row reads as absent
    /// and resets itself on the next failure) — this just keeps the table, and the admin panel, clean.
    /// Returns the number of rows removed.
    pub async fn prune(&self) -> Result<u64, DbErr> {
        let cutoff = now_secs() - self.duration;
        let res = username_entity::Entity::delete_many()
            .filter(username_entity::Column::LastFailureAt.lt(cutoff))
            .exec(&self.db)
            .await?;
        Ok(res.rows_affected)
    }

    /// The configured `(after, duration_secs)`.
    pub fn limits(&self) -> (u32, i64) {
        (self.after, self.duration)
    }
}

/// The source-address counter — the only thing that brakes credentials carrying no account name (a
/// bearer token) and the only thing that catches username spraying.
#[derive(Clone, Debug)]
pub struct IpLockout {
    db: DatabaseConnection,
    after: u32,
    duration: i64,
    /// Never-locked-out networks (`Arc` so cloning the handle stays cheap).
    whitelist: Arc<Vec<IpNet>>,
}

impl IpLockout {
    pub(crate) fn new(
        db: DatabaseConnection,
        after: u32,
        duration_secs: i64,
        whitelist: Vec<IpNet>,
    ) -> Self {
        Self { db, after, duration: duration_secs.max(1), whitelist: Arc::new(whitelist) }
    }

    /// Whether this address is on the whitelist, and so never locked out or counted. Also the
    /// place to look when a lockout "isn't working": an over-broad rule silently exempts everyone.
    pub fn whitelisted(&self, ip: IpAddr) -> bool {
        crate::net::in_nets(&self.whitelist, ip)
    }

    /// Seconds until this address may be checked again, or `None` if it isn't locked (also `None` for
    /// an unknown address — there is nothing to key on). Pass the **real** client address.
    pub async fn locked(&self, ip: Option<IpAddr>) -> Option<i64> {
        let ip = ip?;
        if self.after == 0 || self.whitelisted(ip) {
            return None;
        }
        let row = ip_entity::Entity::find_by_id(canonical_key(ip)).one(&self.db).await.ok()??;
        retry_after(row.failures, row.last_failure_at, self.after, self.duration)
    }

    /// Record one checked-and-rejected credential from this address; returns whether it just locked.
    pub async fn record_failure(&self, ip: Option<IpAddr>) -> bool {
        let (Some(ip), true) = (ip, self.after > 0) else { return false };
        if self.whitelisted(ip) {
            return false; // never counted, so an whitelisted address can never accumulate a lockout
        }
        let (key, now) = (canonical_key(ip), now_secs());
        let existing = ip_entity::Entity::find_by_id(key.clone()).one(&self.db).await.ok().flatten();
        let failures = match existing {
            Some(row) if row.failures as u32 >= self.after => return false, // locked: record nothing
            Some(row) => {
                let n = if row.last_failure_at + self.duration <= now { 1 } else { row.failures + 1 };
                let mut am = row.into_active_model();
                am.failures = Set(n);
                am.last_failure_at = Set(now);
                let _ = am.update(&self.db).await;
                n
            }
            None => {
                let am = ip_entity::ActiveModel {
                    ip: Set(key),
                    failures: Set(1),
                    last_failure_at: Set(now),
                };
                let _ = ip_entity::Entity::insert(am)
                    .on_conflict(OnConflict::new().do_nothing().to_owned())
                    .do_nothing()
                    .exec(&self.db)
                    .await;
                1
            }
        };
        failures as u32 >= self.after
    }

    /// Forget this address's failures. **Not** called on a successful check: one valid credential
    /// shouldn't refund the budget a spraying source is burning.
    pub async fn clear(&self, ip: IpAddr) {
        let _ = ip_entity::Entity::delete_by_id(canonical_key(ip)).exec(&self.db).await;
    }

    /// Delete rows whose lockout has expired (see [`UsernameLockout::prune`]).
    pub async fn prune(&self) -> Result<u64, DbErr> {
        let cutoff = now_secs() - self.duration;
        let res = ip_entity::Entity::delete_many()
            .filter(ip_entity::Column::LastFailureAt.lt(cutoff))
            .exec(&self.db)
            .await?;
        Ok(res.rows_affected)
    }

    /// The configured `(after, duration_secs)`.
    pub fn limits(&self) -> (u32, i64) {
        (self.after, self.duration)
    }
}

// ===================== Shared arithmetic (the only thing the two share) =====================

/// Seconds left on the lockout, or `None` when the key is free: under the limit, or the last failure
/// has aged out (an expired row counts as no row — the pruner will collect it).
fn retry_after(failures: i32, last_failure_at: i64, after: u32, duration: i64) -> Option<i64> {
    if after == 0 {
        return None; // counter disabled
    }
    let expires = last_failure_at + duration;
    let now = now_secs();
    ((failures as u32) >= after && expires > now).then(|| (expires - now).max(1))
}

/// One address, one row: an IPv4 client seen as `::ffff:a.b.c.d` (dual-stack listener) and the same
/// client reported as `a.b.c.d` by a proxy must not end up as two keys.
fn canonical_key(ip: IpAddr) -> String {
    crate::net::canonical(ip).to_string()
}

/// Account names are case-folded and length-capped: the key is attacker-supplied (unknown names are
/// counted on purpose), so it must not become a way to write arbitrarily long rows.
fn normalize_username(username: &str) -> String {
    let lower = username.trim().to_lowercase();
    lower.chars().take(190).collect()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AFTER: u32 = 3;
    const DURATION: i64 = 900;

    #[test]
    fn locks_only_at_the_limit_and_reports_the_wait() {
        let now = now_secs();
        assert_eq!(retry_after(2, now, AFTER, DURATION), None, "under the limit");
        let retry = retry_after(3, now, AFTER, DURATION).expect("locked at the limit");
        assert!((1..=DURATION).contains(&retry), "retry {retry} inside the window");
        // Part-way through, the wait shrinks; past it, the row reads as free again.
        let retry = retry_after(9, now - 300, AFTER, DURATION).expect("still locked");
        assert!((1..=DURATION - 299).contains(&retry), "retry {retry} has decayed");
        assert_eq!(retry_after(9, now - DURATION, AFTER, DURATION), None, "aged out");
        assert_eq!(retry_after(9, now - DURATION - 1, AFTER, DURATION), None);
    }

    #[test]
    fn a_limit_of_zero_never_locks() {
        assert_eq!(retry_after(1000, now_secs(), 0, DURATION), None);
    }

    #[test]
    fn usernames_are_folded_trimmed_and_capped() {
        assert_eq!(normalize_username("  Alice "), "alice");
        assert_eq!(normalize_username(&"x".repeat(500)).len(), 190, "attacker-supplied key is capped");
    }
}
