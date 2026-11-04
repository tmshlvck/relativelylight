use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "post")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub title: String,
    pub body: String,
    pub views: i32,
    pub published: bool,
    /// Optional publish time — Unix seconds, UTC. Demonstrates an *editable* datetime column
    /// (`.datetime()` in the admin config → a timezone-aware datetime picker in the form).
    pub published_at: Option<i64>,
    /// A closed set of values — see [`Status`]. Nothing in the examples declares the allowed values: the
    /// admin introspects them from the column type.
    pub status: Option<Status>,
    pub author_id: i32,
}

/// A post's editorial state. **`db_type = "Enum"`** makes the column report `ColumnType::Enum` with these
/// variants, so the admin renders a dropdown and refuses anything else with no per-model code. That holds
/// on SQLite too: it has no enum type, so the column is created as text and sea-query skips the cast it
/// makes on Postgres — the database stores `"draft"`, `"review"`, …. (On Postgres the same entity needs a
/// real `post_status` enum type in the database.)
///
/// (`db_type = "String(..)"` would store the same text but report a plain string column, leaving the app
/// to declare the set with `field("status").options_from::<Status>()` — the choice on Postgres when new
/// variants shouldn't need a migration.)
///
/// The serde names must match the `string_value`s: the admin reads rows through `Serialize`, so a variant
/// serialized as `"Draft"` would match none of the options.
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum, serde::Serialize, serde::Deserialize)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "post_status")]
#[serde(rename_all = "lowercase")]
pub enum Status {
    #[sea_orm(string_value = "draft")]
    Draft,
    #[sea_orm(string_value = "review")]
    Review,
    #[sea_orm(string_value = "published")]
    Published,
    #[sea_orm(string_value = "archived")]
    Archived,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::author::Entity",
        from = "Column::AuthorId",
        to = "super::author::Column::Id"
    )]
    Author,
}

impl Related<super::author::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Author.def()
    }
}

// N:M: post <-> tag via post_tag
impl Related<super::tag::Entity> for Entity {
    fn to() -> RelationDef {
        super::post_tag::Relation::Tag.def()
    }

    fn via() -> Option<RelationDef> {
        Some(super::post_tag::Relation::Post.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
