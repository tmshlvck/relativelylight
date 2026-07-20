//! `group` — a named group for authorization (e.g. the configurable admin/superadmin group). Table
//! `auth_group`. Membership is the `user_group` join.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "auth_group")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(unique)]
    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

// N:M: group <-> user via user_group (the inverse side of the membership relation).
impl Related<super::user::Entity> for Entity {
    fn to() -> RelationDef {
        super::user_group::Relation::User.def()
    }
    fn via() -> Option<RelationDef> {
        Some(super::user_group::Relation::Group.def().rev())
    }
}

impl ActiveModelBehavior for ActiveModel {}
