//! A tiny table for the **timezone** demo: a name, an instant and a calendar date, nothing else.
//!
//! It deliberately doesn't reuse `post`, which carries `NOT NULL` columns (`body`, an `author` FK) that
//! a timezone demo has no use for: hiding them made the form unable to create a row at all — a hidden
//! column is never written, and a `NOT NULL` column with no value is a database error. Three columns,
//! all satisfiable from the form, and the demo says what it means.
//!
//! Its rows (see `seed`) sit either side of both 2026 DST transitions, so picking a zone that observes
//! DST shows the January rows an hour apart from the June ones — from identical stored integers.
//! Its `rsvp_by` dates don't move at all: a date has no zone (docs/TIME.md §1).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "event")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub name: String,
    /// An instant: **Unix seconds, UTC** in a `BIGINT`, a `DateTime<Utc>` in Rust. Nullable, so the
    /// form can also demonstrate clearing a timestamp.
    pub happens_at: Option<ChronoUnixTimestamp>,
    /// A calendar date: a native `DATE` (`YYYY-MM-DD` text on SQLite), the same day for every viewer
    /// whatever their zone. Rendered as a date input.
    pub rsvp_by: Option<Date>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
