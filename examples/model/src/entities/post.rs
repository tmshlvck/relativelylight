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
    /// A closed set of values held as text — the shape a SQLite app has, since a `DeriveActiveEnum` with
    /// `db_type = "String"` is just a text column to the schema. The examples declare the allowed values
    /// with `field("status").options = …`, which turns the form input into a dropdown and makes anything
    /// outside the list a 422. (A Postgres/MySQL `ColumnType::Enum` needs none of that — the variants are
    /// introspected.)
    pub status: Option<String>,
    pub author_id: i32,
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
