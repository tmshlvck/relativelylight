//! [`Routes`] — an optional gated router for serving content, and the URLs that match it.
//!
//! # Read this before mounting it
//!
//! BLOBSTORE.md §2 says downloads stay an app route, and §9.2 says route by the *owning document*
//! rather than by the handle. That still holds for anything user-facing: the app knows that Alice
//! may see invoice 42's attachment and Bob may not, and this crate cannot.
//!
//! What this offers is the other case — a surface where **one gate covers the whole store**:
//!
//! - the blob admin panel ([`Browser`](super::Browser) / [`Portal`](super::Portal)), where the
//!   audience is operators and the question "may they see *this* one" does not arise;
//! - an app where every signed-in user may see everything, which is a real shape and not always a
//!   mistake.
//!
//! **If neither describes your app, do not mount this.** A caller who can reach it can fetch any
//! version by id, because the only check is the gate you passed. There is no per-document question
//! asked, and mounting it behind a `UserReadWrite` gate on an app that *does* have per-document
//! ownership silently undoes that ownership. Write the route yourself and hand the components its
//! URLs instead — every one of them takes them.
//!
//! # Why the URLs live here too
//!
//! [`Routes`] builds both the router and the links the components render, so a component cannot
//! point at a path the router doesn't serve. The alternative — a base path written once in the
//! router and again in every component — is a mismatch waiting to be discovered by a 404.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use http::{HeaderMap, StatusCode};

use crate::authz::{Authz, Decision, Operation};
use crate::blob::{BlobBackend, BlobError, BlobStore, VersionId, WriteContext};

/// A mount point for content serving: the router, and the URLs that reach it.
#[derive(Clone, Debug)]
pub struct Routes {
    base: String,
}

impl Routes {
    /// `base` is where the router will be nested, e.g. `"/blob"`. A trailing slash is trimmed.
    pub fn new(base: impl Into<String>) -> Self {
        let base = base.into();
        Self { base: base.trim_end_matches('/').to_string() }
    }

    /// Serve content **inline** — what an `<img>`/`<embed>` fetches, and what "Open" opens. Falls
    /// back to an attachment for types that are not safe to render (see
    /// [`to_inline_response`](super::to_inline_response)).
    pub fn view(&self, version: VersionId) -> String {
        format!("{}/{version}", self.base)
    }

    /// Serve content as an attachment.
    pub fn download(&self, version: VersionId) -> String {
        format!("{}/{version}/download", self.base)
    }

    /// The router to nest at `base`.
    ///
    /// Every served byte goes through [`BlobStore::read`], so the digest is verified in full before
    /// anything is handed over and the read is audited like any other.
    pub fn router<B: BlobBackend>(
        &self,
        store: Arc<BlobStore<B>>,
        gate: impl Authz + 'static,
    ) -> Router {
        let state = Serving { store, gate: Arc::new(gate) };
        Router::new()
            .route("/{version}", get(view::<B>))
            .route("/{version}/download", get(download::<B>))
            .with_state(state)
    }
}

struct Serving<B: BlobBackend> {
    store: Arc<BlobStore<B>>,
    gate: Arc<dyn Authz>,
}

// `#[derive(Clone)]` would demand `B: Clone`, which a backend has no reason to be — both fields are
// already behind an `Arc`.
impl<B: BlobBackend> Clone for Serving<B> {
    fn clone(&self) -> Self {
        Self { store: self.store.clone(), gate: self.gate.clone() }
    }
}

async fn view<B: BlobBackend>(
    State(s): State<Serving<B>>,
    Path(version): Path<i64>,
    headers: HeaderMap,
    crate::middleware::RealIp(ip): crate::middleware::RealIp,
) -> Response {
    serve(s, version, headers, ip, false).await
}

async fn download<B: BlobBackend>(
    State(s): State<Serving<B>>,
    Path(version): Path<i64>,
    headers: HeaderMap,
    crate::middleware::RealIp(ip): crate::middleware::RealIp,
) -> Response {
    serve(s, version, headers, ip, true).await
}

async fn serve<B: BlobBackend>(
    s: Serving<B>,
    version: i64,
    headers: HeaderMap,
    ip: std::net::IpAddr,
    attach: bool,
) -> Response {
    match s.gate.authorize(Operation::Read, &headers).await {
        Decision::Allow => {}
        Decision::NeedsLogin => return StatusCode::UNAUTHORIZED.into_response(),
        Decision::Denied => return StatusCode::FORBIDDEN.into_response(),
    }

    // `RealIp` is required, as everywhere else that records who called: the layer is mandatory
    // (`middleware::resolve_real_ip`) and answers 500 naming itself if it is missing, which is a
    // better failure than an audit trail that quietly says "unknown".
    let ctx = WriteContext::from(&headers, ip);

    match s.store.read(VersionId(version), ctx).await {
        Ok(stream) if attach => super::to_response(stream),
        Ok(stream) => super::to_inline_response(stream),
        Err(BlobError::NotFound(_)) => StatusCode::NOT_FOUND.into_response(),
        // A digest mismatch is data loss, not a bad request — say so rather than 404ing, or a
        // corrupt blob looks like a missing one and nobody investigates.
        Err(BlobError::Corrupt { .. }) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "stored content failed its digest check")
                .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_urls_match_the_paths_the_router_serves() {
        // The reason both live on one type: a base path written twice is a 404 waiting to happen.
        let r = Routes::new("/blob/");
        assert_eq!(r.view(VersionId(7)), "/blob/7");
        assert_eq!(r.download(VersionId(7)), "/blob/7/download");
    }
}
