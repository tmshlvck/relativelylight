//! `relativelylight::crud` — auto-generated CRUD/search/relations over ORM entities, with no
//! per-model code, plus a JSON API and an admin UI.
//!
//! [`engine`] is the backend-agnostic core (the [`Accessor`] seam, contract types, the [`Engine`],
//! and — behind the `axum` feature — the HTTP router); [`seaorm`] is the SeaORM backend
//! (introspection + `MetaModel` + `Crud`). [`ui`] (feature `ui`) is the Bootstrap/Alpine admin
//! components; [`openapi`] and [`csv_io`] are optional adapters. See `docs/CRUD.md`.

pub mod engine;
pub mod seaorm;

#[cfg(feature = "ui")]
pub mod ui;

#[cfg(feature = "openapi")]
pub mod openapi;

#[cfg(feature = "csv")]
pub mod csv_io;

pub use engine::{
    coerce, default_label, slugify, Accessor, Cardinality, ColumnMeta, Engine, Error, ListQuery,
    LogicalType, Page, Result, RowItem, ValidationErrors,
};
