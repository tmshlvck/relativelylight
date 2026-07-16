//! autocrud — auto-generated CRUD/search/relations over ORM entities, with no per-model code.
//!
//! Two core modules: [`engine`] is the backend-agnostic core (the [`Accessor`] seam, contract types,
//! the [`Engine`], and — behind the `axum` feature — the HTTP router); [`seaorm`] is the SeaORM
//! backend (introspection + `MetaModel` + `Crud`). A future backend (memory / no-SQL / filesystem)
//! is just another module implementing `Accessor`.
//!
//! ```ignore
//! use autocrud::seaorm::{Crud, MetaModel};
//! let mut post = MetaModel::new(post::Entity);
//! post.relate(&tag);                          // declare N:M
//! let mut crud = Crud::new(db, "/api/v1");
//! crud.register(author);
//! crud.register(post);
//! crud.register(tag);
//! let app = crud.into_router();               // axum Router
//! ```
//!
//! See `docs/AUTOCRUD.md` for the full guide and `PRD.md` for the product spec.

pub mod engine;
pub mod seaorm;

#[cfg(feature = "alpine")]
pub mod alpine;

#[cfg(feature = "openapi")]
pub mod openapi;

#[cfg(feature = "csv")]
pub mod csv_io;

pub use engine::{
    coerce, default_label, slugify, Accessor, Cardinality, ColumnMeta, Engine, Error, ListQuery,
    LogicalType, Page, Result, RowItem, ValidationErrors,
};
