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

/// The per-model authorization gate: [`Authz`](authz::Authz), [`Operation`](authz::Operation),
/// [`Decision`](authz::Decision) and the [`Open`](authz::Open) gate. Identity-resolving presets live
/// in `auth`.
pub mod authz;

/// Client-address resolution and the CIDR helpers — the primitive behind
/// [`middleware::resolve_real_ip`], which apps use instead.
pub mod net;

/// [`resolve_real_ip`](middleware::resolve_real_ip): resolves the caller's address once into a
/// [`RealIp`](middleware::RealIp) extension. **Required** by everything here that needs to know who
/// called.
#[cfg(feature = "axum")]
pub mod middleware;

pub mod observe;

#[cfg(feature = "crud")]
pub mod crud;

#[cfg(feature = "auth")]
pub mod auth;

/// Content-addressed file storage under a stable handle and version chain — see `docs/BLOBSTORE.md`.
#[cfg(feature = "blob")]
pub mod blob;

/// `application/x-www-form-urlencoded` encode/decode, shared by `csrf`, `time` and `crud::ui`.
#[cfg(any(feature = "csrf", feature = "tz", feature = "ui"))]
mod urlform;

/// HTML escaping for fragments built without a template (`ui` implies `tz`, `auth` implies `csrf`).
#[cfg(any(feature = "csrf", feature = "tz"))]
mod html;

/// A strict reader for a buffered `multipart/form-data` body (the CSV import; the token in [`csrf`]).
#[cfg(any(feature = "ui", feature = "csrf"))]
mod multipart;

/// Double-submit CSRF protection for cookie-authenticated writes ([`Csrf`](csrf::Csrf)). Always on for
/// `auth`'s forms; opt-in for `crud` via `Crud::csrf`. See `docs/AUTH.md` §7.
#[cfg(feature = "csrf")]
pub mod csrf;

/// Server-side rendering of integer-UTC timestamps in the request's zone: [`Tz`](time::Tz) (from a
/// cookie) and [`TzPicker`](time::TzPicker). See `docs/TIME.md`.
#[cfg(feature = "tz")]
pub mod time;

/// Typed field validators and normalizers, plus the [`field`](validate::field) adapters for the CRUD
/// write path. See `docs/DATAINPUT.md`.
pub mod validate;
