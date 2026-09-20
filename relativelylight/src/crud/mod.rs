//! `relativelylight::crud` — auto-generated CRUD/search/relations over ORM entities, with no
//! per-model code, rendered as a server-side admin UI.
//!
//! [`engine`] is the backend-agnostic core (the [`Accessor`] seam, the contract types and the
//! [`Engine`] registry); [`seaorm`] is the SeaORM backend (introspection + `MetaModel` + `Crud`).
//! [`ui`] (feature `ui`) renders the tables and forms — plain HTML, no JavaScript framework, no JSON
//! in between. [`csv_io`] is an optional adapter. See `docs/CRUD.md`.

pub mod engine;
pub mod seaorm;

/// Negative-path tests for gate enforcement on the UI's write path (needs `auth` for the presets).
#[cfg(all(test, feature = "ui", feature = "auth"))]
mod gate_tests;

/// Listing over a real database: sorting by a relation's label, `filter[…]`, page stability.
/// Needs `ui` — it lists through the `ViewState` a URL parses to, exactly as a rendered table does.
#[cfg(all(test, feature = "ui"))]
mod list_tests;

#[cfg(feature = "ui")]
pub mod ui;

/// Tests for the rendered UI: render-time checks, field selection, gating, escaping, form decoding.
#[cfg(all(test, feature = "ui"))]
mod ui_tests;

#[cfg(feature = "csv")]
pub mod csv_io;

pub use engine::{
    coerce, default_label, slugify, Accessor, BatchApplied, Cardinality, Column, Engine, Error,
    ListQuery,
    LogicalType, Page, Result, RowItem, ValidationErrors,
};
