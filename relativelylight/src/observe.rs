//! Write-observer hook — the seam for **audit logging**. **Always compiled** (needs only `http` +
//! `serde_json` + `async-trait`), so both `crud` and `auth` can fire events in any build.
//!
//! An audit record needs two things that live in different layers: *what changed* (old/new row data,
//! known at the data layer) and *who/how* (the authenticated user, auth type, client IP — known only
//! at the HTTP layer). Neither SeaORM's `ActiveModelBehavior` nor a plain tower layer sees both. So
//! the library fires a [`WriteEvent`] at the points that do — each `crud` write handler and each
//! mutating `auth` handler — carrying the change **and** the request context ([`headers`] +
//! [`client_ip`]). The app registers one [`WriteObserver`] (via `Crud::on_write` / `Auth::on_write`),
//! resolves the actor itself (e.g. `auth.identify(ev.headers)`), and persists a row in its own audit
//! table. The address arrives **already resolved** — see
//! [`middleware::resolve_real_ip`](crate::middleware::resolve_real_ip) — so every audit row names the
//! same client the lockout and the access log did.
//!
//! [`headers`]: WriteEvent::headers
//! [`client_ip`]: WriteEvent::client_ip
//!
//! **Times are UTC.** The library stores/returns timestamps as `i64` Unix seconds (UTC); an audit
//! sink should do the same. (Presenting them in the viewer's local/preferred timezone is a frontend
//! concern — see `docs/TIME.md`.)

use crate::authz::Operation;
use async_trait::async_trait;
use http::HeaderMap;
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;

/// A committed state-changing write, handed to the registered [`WriteObserver`]. Borrows the request
/// pieces (the observer reads what it needs synchronously and must not retain the references).
pub struct WriteEvent<'a> {
    /// Which surface produced it — `"crud"` (the auto-CRUD API/admin) or an `auth` handler
    /// (`"auth-profile"`, `"auth-login"`, `"auth-admin"`, …). Apps use their own labels for their
    /// hand-written surfaces.
    pub source: &'static str,
    /// The mutation kind (`Create` / `Update` / `Delete`).
    pub op: Operation,
    /// The affected entity (table/slug), e.g. `"auth_user"`, `"zone"`.
    pub entity: &'a str,
    /// The affected row's primary key, stringified (`None` for a bulk delete).
    pub key: Option<String>,
    /// Prior row state where known (update/delete); `None` on create. **Never** put secrets here
    /// (password hashes, TOTP secrets) — the emitters redact them.
    pub before: Option<Value>,
    /// New row state where known (create/update); `None` on delete.
    pub after: Option<Value>,
    /// The request headers — resolve the actor from here (`auth.identify`).
    pub headers: &'a HeaderMap,
    /// The caller's address, already resolved by
    /// [`middleware::resolve_real_ip`](crate::middleware::resolve_real_ip) — so an audit row records the
    /// **same** address the lockout counted and the access log printed, rather than each observer
    /// re-deriving one from `headers` and a proxy policy it has to know about.
    pub client_ip: IpAddr,
}

/// A sink for [`WriteEvent`]s. Register one with `Crud::on_write` and/or `Auth::on_write`; the same
/// `Arc` can be shared by both (the blanket impl below forwards through `Arc`).
#[async_trait]
pub trait WriteObserver: Send + Sync {
    async fn on_write(&self, event: &WriteEvent<'_>);
}

#[async_trait]
impl<T: WriteObserver + ?Sized> WriteObserver for Arc<T> {
    async fn on_write(&self, event: &WriteEvent<'_>) {
        (**self).on_write(event).await
    }
}
