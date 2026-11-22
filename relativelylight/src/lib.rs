//! **relativelylight** — a web back-office toolkit for Rust. Auto-generate a **server-rendered** CRUD
//! admin UI from your ORM entities with no per-model code, and gate it with built-in authentication +
//! authorization. Composes *into* your app — you keep your router and your page shell.
//!
//! Modules:
//! - [`crud`]: the CRUD engine, the SeaORM backend, the admin UI, CSV — see `docs/CRUD.md`.
//! - [`auth`]: sessions, login, 2FA, API keys and identity resolution — see `docs/AUTH.md`; SSO and
//!   passkeys are the features `sso` and `passkeys`.
//! - [`time`]: timestamps in the viewer's zone — see `docs/TIME.md`.
//! - `files` (feature `files`): uploads and downloads — see `docs/FILES.md`.
//! - [`authz`] (the per-model gate the engine consults), [`csrf`] (the double-submit token for
//!   cookie-authenticated writes), [`middleware`] (`resolve_real_ip`), [`validate`], [`observe`].
//!
//! ```ignore
//! use relativelylight::crud::{Crud, MetaModel};
//! use relativelylight::authz::Open;
//! let mut post = MetaModel::new(post::Entity);
//! post.relate(&tag);                          // declare N:M
//! let mut crud = Crud::new(db);
//! crud.register(post, Open);                  // each model takes a gate (Open = ungated)
//! let engine = crud.into_engine();            // render tables/forms from it on your own routes
//! ```
#![cfg_attr(docsrs, feature(doc_cfg))]

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
pub mod middleware;

pub mod observe;

pub mod crud;

pub mod auth;

/// Files on a page — a streaming upload reader, download responses and the upload/preview/thumbnail
/// components; storage is the app's. See `docs/FILES.md`.
#[cfg(feature = "files")]
pub mod files;

/// `application/x-www-form-urlencoded` encode/decode, shared by `csrf`, `time` and `crud`'s components.
mod urlform;

/// HTML escaping for fragments built without a template, and `crud::esc`.
mod html;

/// `bytes` as lowercase hex: tokens, and the SHA-256 digests the crate stores and compares.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    out
}

/// A strict reader for a buffered `multipart/form-data` body (the CSV import; the token in [`csrf`]).
mod multipart;

/// Double-submit CSRF protection for cookie-authenticated writes ([`Csrf`](csrf::Csrf)). Enforced on
/// `auth`'s forms; opt-in for `crud` via `Engine::csrf`. See `docs/AUTH.md` §7.
pub mod csrf;

/// Server-side rendering of integer-UTC timestamps in the request's zone: [`Tz`](time::Tz) (from a
/// cookie), [`picker`](time::picker) and [`JS`](time::JS). See `docs/TIME.md`.
pub mod time;

/// Typed field validators and normalizers, plus the [`field`](validate::field) adapters for the CRUD
/// write path. See `docs/DATAINPUT.md`.
pub mod validate;
