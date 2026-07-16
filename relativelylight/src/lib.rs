//! **relativelylight** — a web back-office toolkit for Rust. Auto-generate a JSON CRUD + metadata
//! API and an admin UI from your ORM entities with no per-model code, and (soon) gate them with
//! built-in authentication + authorization. Composes *into* your app — you keep your router, page
//! shell, and OpenAPI document.
//!
//! Feature-gated modules:
//! - [`crud`] (default): the CRUD engine, SeaORM backend, admin UI, OpenAPI, CSV — see
//!   `docs/CRUD.md`.
//! - `auth` (planned): sessions, login, and the authorization gate — see `docs/AUTH.md`.
//!
//! ```ignore
//! use relativelylight::crud::seaorm::{Crud, MetaModel};
//! let mut post = MetaModel::new(post::Entity);
//! post.relate(&tag);                          // declare N:M
//! let mut crud = Crud::new(db, "/api/v1");
//! crud.register(post);
//! let app = crud.into_router();               // axum Router — merge into your app
//! ```

#[cfg(feature = "crud")]
pub mod crud;

#[cfg(feature = "auth")]
pub mod auth;
