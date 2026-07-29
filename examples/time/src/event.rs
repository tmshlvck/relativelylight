//! The example's own tiny table: a name and one timestamp.
//!
//! It deliberately doesn't reuse the shared `model::post`, which carries `NOT NULL` columns (`body`, an
//! `author` FK) that a timezone demo has no use for. Hiding them made the form unable to create a row at
//! all — a hidden column is never written, and a `NOT NULL` column with no value is a database error. Three
//! columns, all satisfiable from the form, and the demo says what it means.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "event")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub name: String,
    /// **Unix seconds, UTC** — the one thing this example is about. Nullable, so the form can also
    /// demonstrate clearing a timestamp.
    pub happens_at: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
