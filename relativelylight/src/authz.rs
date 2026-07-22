//! The authorization gate — the seam between the `crud` engine (which enforces) and `auth` (which
//! resolves identities). **Always compiled**, independent of the `auth`/`axum` features, so a model
//! can be registered with a gate in any build (`Open` when nothing needs gating).
//!
//! A gate is attached **per model** (so it takes no model argument), is handed the request headers,
//! and returns a [`Decision`]. The engine maps `Allow`/`NeedsLogin`/`Denied` → `200`/`401`/`403`; a
//! page handler serves `NeedsLogin` as a redirect to the login page. The gate resolves the caller
//! itself — the identity-resolving presets (`UserReadWrite`, `UserReadGroupWrite`) live in
//! [`crate::auth`] because they need an `Auth` handle; `Open` (allow everything) lives here.

use async_trait::async_trait;
use http::HeaderMap;
use std::sync::Arc;

/// The CRUD operation being authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    List,
    Read,
    Create,
    Update,
    Delete,
}

impl Operation {
    /// Whether this operation mutates data.
    pub fn is_write(self) -> bool {
        matches!(self, Operation::Create | Operation::Update | Operation::Delete)
    }
}

/// A gate's answer. The caller renders it: the `crud` engine maps `Allow`/`NeedsLogin`/`Denied` to
/// `200`/`401`/`403`; a page handler serves `NeedsLogin` as a redirect to the login page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    NeedsLogin,
    Denied,
}

/// Authorizes one operation on one endpoint. Attached per model (so no model argument) and handed the
/// request headers, so it can resolve the identity itself (via an `Auth` handle) and inspect anything
/// else it needs.
#[async_trait]
pub trait Authz: Send + Sync {
    async fn authorize(&self, op: Operation, headers: &HeaderMap) -> Decision;
}

/// Everything allowed (no auth). Pass this to `Crud::register` when a model needs no gating.
pub struct Open;

#[async_trait]
impl Authz for Open {
    async fn authorize(&self, _: Operation, _: &HeaderMap) -> Decision {
        Decision::Allow
    }
}

/// Lets a shared `Arc<dyn Authz>` (or `Arc<G>`) be passed wherever a gate is expected — so the same
/// gate instance can guard several models.
#[async_trait]
impl<T: Authz + ?Sized> Authz for Arc<T> {
    async fn authorize(&self, op: Operation, headers: &HeaderMap) -> Decision {
        (**self).authorize(op, headers).await
    }
}
