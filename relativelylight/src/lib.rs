//! **relativelylight** — a web back-office toolkit for Rust. Auto-generate a **server-rendered** CRUD
//! admin UI from your ORM entities with no per-model code, and gate it with built-in authentication +
//! authorization. Composes *into* your app — you keep your router and your page shell.
//!
//! Feature-gated modules:
//! - [`crud`] (default): the CRUD engine, the SeaORM backend, the admin UI, CSV — see `docs/CRUD.md`.
//! - `auth`: sessions, login, and identity resolution — see `docs/AUTH.md`.
//! - [`csrf`] (with `auth`): the double-submit CSRF token for cookie-authenticated writes.
//! - [`authz`] (always on): the per-model authorization gate consulted by the engine.
//!
//! ```ignore
//! use relativelylight::crud::seaorm::{Crud, MetaModel};
//! use relativelylight::authz::Open;
//! let mut post = MetaModel::new(post::Entity);
//! post.relate(&tag);                          // declare N:M
//! let mut crud = Crud::new(db);
//! crud.register(post, Open);                  // each model takes a gate (Open = ungated)
//! let engine = crud.into_engine();            // render tables/forms from it on your own routes
//! ```

/// The per-model authorization gate: the [`Authz`](authz::Authz) trait, [`Operation`](authz::Operation) /
/// [`Decision`](authz::Decision), and the [`Open`](authz::Open) gate. Identity-resolving presets live
/// in [`auth`].
pub mod authz;

/// The write-observer hook for audit logging: [`WriteEvent`](observe::WriteEvent) +
/// [`WriteObserver`](observe::WriteObserver), fired by `crud` and `auth` write paths with the request
/// context so the app can record who/what/from-where. Always compiled.
/// Client-address resolution (`trust_proxy` → socket peer vs forwarded headers). The primitive behind
/// [`middleware::resolve_real_ip`]; apps use the middleware, not this, so one client is one address
/// everywhere. Also carries the CIDR helpers.
pub mod net;

/// The request-pipeline layer: [`resolve_real_ip`](middleware::resolve_real_ip), which resolves the
/// caller's address once into a [`RealIp`](middleware::RealIp) extension and is **required** by anything
/// in this crate that needs to know who is calling. There is no request log here — see `examples/audit`.
#[cfg(feature = "axum")]
pub mod middleware;

pub mod observe;

#[cfg(feature = "crud")]
pub mod crud;

#[cfg(feature = "auth")]
pub mod auth;

/// `application/x-www-form-urlencoded` encode/decode, shared by `csrf`, `time` and `crud::ui`.
#[cfg(any(feature = "csrf", feature = "tz", feature = "ui"))]
mod urlform;

/// A strict reader for a buffered `multipart/form-data` body — how a file reaches the server
/// without JavaScript in the middle (see `crud::ui`'s CSV import), and how [`csrf`] finds the token
/// in one.
#[cfg(any(feature = "ui", feature = "csrf"))]
mod multipart;

/// Double-submit CSRF protection for cookie-authenticated writes: [`Csrf`](csrf::Csrf) issues and
/// verifies the token. Always on for `auth`'s own forms; opt-in for the `crud` API via `Crud::csrf`.
/// Feature `csrf` (implied by `auth`). See [`docs/AUTH.md` §7](https://github.com/tmshlvck/relativelylight/blob/main/docs/AUTH.md).
#[cfg(feature = "csrf")]
pub mod csrf;

/// Timezone-aware presentation of UTC timestamps: [`Tz`](time::Tz) (the zone for one request, from a
/// cookie) and the [`TzPicker`](time::TzPicker) form. Storage stays integer-UTC; formatting happens
/// **server-side**, so a CSV export matches the screen. Feature `tz` (implied by `ui`). See
/// [`docs/TIME.md`](https://github.com/tmshlvck/relativelylight/blob/main/docs/TIME.md).
#[cfg(feature = "tz")]
pub mod time;

/// Reusable field validators + normalizers ([`ipv4`](validate::ipv4), [`int_range`](validate::int_range),
/// [`hostname`](validate::hostname), …) as typed predicates, plus the [`field`](validate::field) adapters
/// that plug them into the CRUD write path. Std-only core, always compiled. See
/// [`docs/DATAINPUT.md`](https://github.com/tmshlvck/relativelylight/blob/main/docs/DATAINPUT.md).
pub mod validate;
