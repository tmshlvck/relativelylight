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

/// Relation reads over a real database: what each kind resolves to, the inverse cap, and a page's
/// query count staying flat as its rows grow.
#[cfg(all(test, feature = "ui"))]
mod relation_tests;

/// `Table::range_filter` over a real database: dates in the viewer's zone, open ends, the range
/// holding for "delete all matching" and the export; `ListQuery::range` / `one_of` at the engine.
#[cfg(all(test, feature = "ui"))]
mod range_tests;

/// `Table::fixed_filter` holding for the writes over a real database: the pinned value written on
/// create, update and import, and a row outside the pin refused.
#[cfg(all(test, feature = "ui"))]
mod pin_tests;

/// A column's transforms end to end over a real database: typed text, `blank_is_null`, and
/// `on_read`/`on_write` as an inverse pair (form and CSV).
#[cfg(all(test, feature = "ui"))]
mod transform_tests;

/// Option labels (`MetaField::options_from_display` / `option_labels`) over a real database: shown
/// wherever a value is, never what is stored, posted or exported.
#[cfg(all(test, feature = "ui"))]
mod option_label_tests;

/// "+" on a relation field (`Crud::picker_create`) over a real database: offered by the target's
/// gates, the picker's create form refused by them, create-only, CSRF-checked, the new row reported.
#[cfg(all(test, feature = "ui"))]
mod picker_create_tests;

#[cfg(feature = "ui")]
pub mod ui;

/// Tests for the rendered UI: render-time checks, field selection, gating, escaping, form decoding.
#[cfg(all(test, feature = "ui"))]
mod ui_tests;

#[cfg(feature = "csv")]
pub mod csv_io;

/// Typed text ↔ value, shared by the form decoder and CSV — one reading of an empty cell.
#[cfg(any(feature = "ui", feature = "csv"))]
mod text;

pub use engine::{
    coerce, default_label, slugify, Accessor, BatchApplied, Cardinality, Column, Engine, Error,
    ListQuery,
    LogicalType, Page, Result, RowItem, ValidationErrors,
};
