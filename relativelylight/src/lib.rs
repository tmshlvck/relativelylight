//! **relativelylight** — a web back-office toolkit for Rust. Auto-generate a JSON CRUD + metadata
//! API and an admin UI from your ORM entities with no per-model code, and (soon) gate them with
//! built-in authentication + authorization. Composes *into* your app — you keep your router, page
//! shell, and OpenAPI document.
//!
//! Feature-gated modules:
//! - [`crud`] (default): the CRUD engine, SeaORM backend, admin UI, OpenAPI, CSV — see
//!   `docs/CRUD.md`.
//! - `auth`: sessions, login, and identity resolution — see `docs/AUTH.md`.
//! - [`authz`] (always on): the per-model authorization gate consulted by the engine.
//!
//! ```ignore
//! use relativelylight::crud::seaorm::{Crud, MetaModel};
//! use relativelylight::authz::Open;
//! let mut post = MetaModel::new(post::Entity);
//! post.relate(&tag);                          // declare N:M
//! let mut crud = Crud::new(db, "/api/v1");
//! crud.register(post, Open);                  // each model takes a gate (Open = ungated)
//! let app = crud.into_router();               // axum Router — merge into your app
//! ```

/// The per-model authorization gate: the [`Authz`](authz::Authz) trait, [`Operation`](authz::Operation) /
/// [`Decision`](authz::Decision), and the [`Open`](authz::Open) gate. Identity-resolving presets live
/// in [`auth`].
pub mod authz;

#[cfg(feature = "crud")]
pub mod crud;

#[cfg(feature = "auth")]
pub mod auth;
