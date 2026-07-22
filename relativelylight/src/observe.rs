//! Write-observer hook — the seam for **audit logging**. **Always compiled** (needs only `http` +
//! `serde_json` + `async-trait`), so both `crud` and `auth` can fire events in any build.
//!
//! An audit record needs two things that live in different layers: *what changed* (old/new row data,
//! known at the data layer) and *who/how* (the authenticated user, auth type, client IP — known only
//! at the HTTP layer). Neither SeaORM's `ActiveModelBehavior` nor a plain tower layer sees both. So
//! the library fires a [`WriteEvent`] at the points that do — each `crud` write handler and each
//! mutating `auth` handler — carrying the change **and** the request context ([`headers`] +
//! [`peer`]). The app registers one [`WriteObserver`] (via `Crud::on_write` / `Auth::on_write`),
//! resolves the actor itself (e.g. `auth.identify(ev.headers)`), derives the client IP from
//! `headers`/`peer`, and persists a row in its own audit table.
//!
//! [`headers`]: WriteEvent::headers
//! [`peer`]: WriteEvent::peer
//!
//! **Times are UTC.** The library stores/returns timestamps as `i64` Unix seconds (UTC); an audit
//! sink should do the same. (Presenting them in the viewer's local/preferred timezone is a frontend
//! concern — see `docs/TIME.md`.)

use crate::authz::Operation;
use async_trait::async_trait;
use http::HeaderMap;
use serde_json::Value;
use std::net::SocketAddr;
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
    /// The request headers — resolve the actor (`auth.identify`) and read `X-Forwarded-For` from here.
    pub headers: &'a HeaderMap,
    /// The socket peer address, when the server was started with connection info — the real client IP
    /// for a *direct* (non-proxied) connection. Combine with `headers` + a trusted-proxy policy.
    pub peer: Option<SocketAddr>,
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
