//! `relativelylight::crud` — auto-generated CRUD/search/relations over ORM entities, with no
//! per-model code, rendered as a server-side admin UI. See `docs/CRUD.md`.
//!
//! **Everything public is here, at `crud::`**; the submodules are private, so an import names what
//! it uses, never a layer. What there is:
//!
//! - **Configuring** — [`Crud`] registers [`MetaModel`]s over one connection; a model holds
//!   [`MetaField`]s and [`MetaRelation`]s, display formatters ([`Fmt`], [`FmtCtx`], [`esc`]) and
//!   entity-wide settings ([`EntityMeta`], [`RowClass`]).
//! - **Rendering** — [`Table`], [`Form`], [`Admin`], [`Picker`], [`RelationField`], driven by
//!   the URL ([`ViewState`]); a write answers an [`Outcome`]. [`CSS`] and [`JS`] go in the shell.
//! - **The engine** — [`Engine`] (list/get/create/update/delete and the gate, [`Engine::decide`])
//!   over one [`Accessor`] per model, speaking [`Column`], [`ListQuery`], [`Page`], [`RowItem`] and
//!   [`Error`]: what an app's own UI or JSON API is written over. [`export_csv`] / [`import_csv`]
//!   are CSV over it.
//!
//! Inside: `engine` is the backend-agnostic core, `seaorm` the SeaORM backend (introspection,
//! queries, `MetaModel`), `meta` the field and relation settings, `registry` the `Crud` facade, `ui`
//! the components, `csv_io` the CSV adapter.

mod engine;
mod fmt;
mod meta;
mod registry;
mod seaorm;

/// Negative-path tests for gate enforcement on the UI's write path (over `auth`'s presets).
#[cfg(test)]
mod gate_tests;

/// Listing over a real database: sorting by a relation's label, `filter[…]`, page stability.
#[cfg(test)]
mod list_tests;

/// Relation reads over a real database: what each kind resolves to, the inverse cap, and a page's
/// query count staying flat as its rows grow.
#[cfg(test)]
mod relation_tests;

/// `Table::range_filter` over a real database: dates in the viewer's zone, open ends, the range
/// holding for "delete all matching" and the export; `ListQuery::range` / `one_of` at the engine.
#[cfg(test)]
mod range_tests;
/// The built-in search over a real database: what the table shows, relations' labels, instants by
/// the period a term names.
#[cfg(test)]
mod search_tests;

/// `Table::fixed_filter` holding for the writes over a real database: the pinned value written on
/// create, update and import, and a row outside the pin refused.
#[cfg(test)]
mod pin_tests;

/// A column's transforms end to end over a real database: typed text, `blank_is_null`, and
/// `on_read`/`on_write` as an inverse pair (form and CSV).
#[cfg(test)]
mod transform_tests;

/// Option labels (`MetaField::options_from_display` / `option_labels`) over a real database: shown
/// wherever a value is, never what is stored, posted or exported.
#[cfg(test)]
mod option_label_tests;

/// "+" on a relation field (`Crud::picker_create`) over a real database: offered by the target's
/// gates, the picker's create form refused by them, create-only, CSRF-checked, the new row reported.
#[cfg(test)]
mod picker_create_tests;

mod ui;

/// Tests for the rendered UI: render-time checks, field selection, gating, escaping, form decoding.
#[cfg(test)]
mod ui_tests;

mod csv_io;

/// Typed text ↔ value, shared by the form decoder and CSV — one reading of an empty cell.
mod text;

pub use csv_io::{export_csv, import_csv, ImportError, ImportReport};
pub use engine::{
    coerce, default_label, parse_date, slugify, Accessor, BatchApplied, Cardinality, Column, Engine,
    EntityMeta, Error, FieldDisplay, ListQuery, LogicalType, Page, Result, RowItem, ValidationErrors,
};
pub use fmt::{esc, esc_str, truncate, Fmt, FmtCtx, RowClass, RowCtx};
pub use meta::{MetaField, MetaRelation, ReadTransform, RowLabel, RowValidator, Validator, WriteTransform};
pub use registry::Crud;
pub use seaorm::MetaModel;
pub use ui::{Admin, Done, Form, Mode, Outcome, Picker, RelationField, Table, ViewState, CSS, JS};
