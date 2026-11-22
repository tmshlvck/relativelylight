//! Write-observer hook — the seam for **audit logging**. **Always compiled** (needs only `http` +
//! `serde_json` + `async-trait`), so both `crud` and `auth` can fire events in any build.
//!
//! An audit record needs two things that live in different layers: *what changed* (old/new row data,
//! known at the data layer) and *who/how* (the authenticated user, auth type, client IP — known only
//! at the HTTP layer). Neither SeaORM's `ActiveModelBehavior` nor a plain tower layer sees both. So
//! the library fires a [`WriteEvent`] at the points that do — each `crud` write handler and each
//! mutating `auth` handler — carrying the change **and** the request context ([`headers`] +
//! [`client_ip`]). The app registers one [`WriteObserver`] (via `Engine::on_write` / `Auth::on_write`),
//! takes the actor from [`actor`](WriteEvent::actor) or resolves it itself
//! (`auth.identify(ev.headers)`), and persists a row in its own audit
//! table. The address arrives **already resolved** — see
//! [`middleware::resolve_real_ip`](crate::middleware::resolve_real_ip) — so every audit row names the
//! same client the lockout and the access log did.
//!
//! [`headers`]: WriteEvent::headers
//! [`client_ip`]: WriteEvent::client_ip
//!
//! **Errors the caller must not see** go to a second sink, [`ErrorObserver`]. Where answering
//! honestly would leak something — a login that failed because the database did, not the password —
//! the crate answers as if nothing went wrong *there* and hands the real error to the app instead.
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
///
/// **`#[non_exhaustive]`**: a field added later (a request id, a trace context) isn't a break. An app
/// that reports its own writes builds one with [`WriteEvent::new`] and the builders.
#[non_exhaustive]
pub struct WriteEvent<'a> {
    /// Which surface produced it — `"autocrud"` (the auto-CRUD API/admin) or an `auth` handler
    /// (`"auth-profile"`, `"auth-login"`, `"auth-admin"`, …). Apps use their own labels for their
    /// hand-written surfaces.
    ///
    /// Each emitter names **itself** here, because one sink is normally registered with both
    /// `Engine::on_write` and `Auth::on_write` (and usually takes the app's own events too), so this is
    /// what tells them apart. It says `autocrud` — this crate's auto-generated CRUD — rather than a
    /// bare `crud`, which in an app that has CRUD screens of its own names nothing in particular.
    pub source: &'static str,
    /// What the caller did: `Create` / `Update` / `Delete` from `crud` and `auth`. The type has
    /// carried all five since the gate trait existed, and a sink that also takes the app's own
    /// events (a download of regulated content, say) should expect `Read` and `List` as well.
    pub op: Operation,
    /// The affected entity (table/slug), e.g. `"auth_user"`, `"zone"`.
    pub entity: &'a str,
    /// The affected row's primary key, stringified (`None` for a bulk delete).
    pub key: Option<String>,
    /// Prior row state where known (update/delete); `None` on create. **Never** put secrets here
    /// (password hashes, TOTP secrets) — the emitters redact them.
    ///
    /// For a **bulk** delete this is `None` — one row cannot describe many. Read
    /// [`before_rows`](WriteEvent::before_rows) instead, which carries every delete uniformly.
    pub before: Option<Value>,
    /// Every row a **delete** removed, finished as a listing would render them: one element for a
    /// single-row delete, `N` for a bulk one, and empty for anything that is not a delete.
    ///
    /// A bulk delete is a set-based `DELETE … WHERE` that fires no per-row hook, so this is how an app
    /// with derived state (a search index, a cache, a parent record) learns what went: the engine reads
    /// the rows inside the deleting transaction. Prefer it over [`before`](WriteEvent::before) for
    /// deletes: one shape for all three.
    pub before_rows: &'a [Value],
    /// New row state where known (create/update); `None` on delete.
    pub after: Option<Value>,
    /// The username of the caller, when the emitter authenticated them itself: every `auth` event.
    /// `None` from `crud`, which leaves identity to the gate — resolve it from
    /// [`headers`](WriteEvent::headers).
    ///
    /// It matters for a self-service password change, which rotates the session before the event
    /// fires: `auth.identify(headers)` then finds nobody, because that cookie is already spent.
    pub actor: Option<&'a str>,
    /// The request headers — resolve the actor from here (`auth.identify`) when
    /// [`actor`](WriteEvent::actor) is `None`.
    pub headers: &'a HeaderMap,
    /// The caller's address, already resolved by
    /// [`middleware::resolve_real_ip`](crate::middleware::resolve_real_ip) — so an audit row records the
    /// **same** address the lockout counted and the access log printed, rather than each observer
    /// re-deriving one from `headers` and a proxy policy it has to know about.
    pub client_ip: IpAddr,
}

impl<'a> WriteEvent<'a> {
    /// An event of the **app's own** — a write its own handler made (an API endpoint taking an API
    /// key, a hand-written form) — for the same sink `crud` and `auth` report to. Name the surface in
    /// `source` (`"api"`, `"import-job"`), then add what is known:
    ///
    /// ```ignore
    /// let ev = WriteEvent::new("api", Operation::Update, "post", &headers, ip)
    ///     .key(id.to_string())
    ///     .before(old_row)
    ///     .after(new_row)
    ///     .actor(&caller.identity.username);
    /// audit.on_write(&ev).await;
    /// ```
    ///
    /// For a delete, hand the removed rows to [`before_rows`](WriteEvent::before_rows) as well — one
    /// element for a single row — so a sink reads every delete the same way.
    pub fn new(
        source: &'static str,
        op: Operation,
        entity: &'a str,
        headers: &'a HeaderMap,
        client_ip: IpAddr,
    ) -> Self {
        Self {
            source,
            op,
            entity,
            key: None,
            before: None,
            before_rows: &[],
            after: None,
            actor: None,
            headers,
            client_ip,
        }
    }

    /// The affected row's primary key.
    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    /// The row as it was (an update or a delete). No secrets: the emitter redacts.
    pub fn before(mut self, row: Value) -> Self {
        self.before = Some(row);
        self
    }

    /// Every row a delete removed (see [`WriteEvent::before_rows`](WriteEvent#structfield.before_rows)).
    pub fn before_rows(mut self, rows: &'a [Value]) -> Self {
        self.before_rows = rows;
        self
    }

    /// The row as it is now (a create or an update). No secrets.
    pub fn after(mut self, row: Value) -> Self {
        self.after = Some(row);
        self
    }

    /// Who did it, when the emitter authenticated them itself — e.g. the owner of the API key the
    /// request carried, whom `auth.identify(headers)` would not find.
    pub fn actor(mut self, actor: &'a str) -> Self {
        self.actor = Some(actor);
        self
    }
}

/// A sink for [`WriteEvent`]s. Register one with `Engine::on_write` and/or `Auth::on_write`; the same
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

/// An error the crate kept from the caller, handed to the registered [`ErrorObserver`]. The response
/// said something deliberately unremarkable (a login answers `401 Invalid username or password`
/// whether the password was wrong or the database was gone), so this is the only place the real cause
/// surfaces. Without an observer it is dropped: the crate writes nothing to stdout or stderr.
///
/// **`#[non_exhaustive]`**, as [`WriteEvent`].
#[non_exhaustive]
pub struct ErrorEvent<'a> {
    /// The surface that hid it, in [`WriteEvent::source`]'s vocabulary (`"auth-login"`).
    pub source: &'static str,
    /// What the crate was doing, for a log line: `"credential lookup"`, `"session create"`.
    pub during: &'static str,
    /// The error itself. Database errors carry no row data, but a driver's message may name tables or
    /// columns — fine for a server log, not for a response.
    pub error: &'a (dyn std::error::Error + Send + Sync),
    /// The caller's address, resolved as for [`WriteEvent::client_ip`].
    pub client_ip: IpAddr,
}

/// A sink for [`ErrorEvent`]s — typically one line to the app's log. Register it with
/// `Auth::on_error`.
#[async_trait]
pub trait ErrorObserver: Send + Sync {
    async fn on_error(&self, event: &ErrorEvent<'_>);
}

#[async_trait]
impl<T: ErrorObserver + ?Sized> ErrorObserver for Arc<T> {
    async fn on_error(&self, event: &ErrorEvent<'_>) {
        (**self).on_error(event).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_apps_own_event_is_built_with_what_it_knows() {
        let headers = HeaderMap::new();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let ev = WriteEvent::new("api", Operation::Update, "post", &headers, ip)
            .key("7")
            .before(serde_json::json!({ "title": "a" }))
            .after(serde_json::json!({ "title": "b" }))
            .actor("alice");
        assert_eq!(
            (ev.source, ev.entity, ev.key.as_deref(), ev.actor),
            ("api", "post", Some("7"), Some("alice"))
        );
        assert_eq!(ev.after.unwrap()["title"], "b");
        assert!(ev.before_rows.is_empty(), "not a delete");

        let removed = [serde_json::json!({ "id": 7 })];
        let ev =
            WriteEvent::new("api", Operation::Delete, "post", &headers, ip).before_rows(&removed);
        assert_eq!(ev.before_rows.len(), 1);
        assert!(ev.after.is_none() && ev.actor.is_none());
    }
}
