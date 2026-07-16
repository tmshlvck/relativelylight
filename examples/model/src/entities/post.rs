use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "post")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub title: String,
    pub body: String,
    pub views: i32,
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
