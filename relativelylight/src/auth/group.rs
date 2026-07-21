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
    /// Row lifecycle timestamps — Unix seconds, **UTC**, maintained by the `before_save` hook.
    pub created_at: i64,
    pub updated_at: i64,
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

// Maintain the UTC lifecycle timestamps: created_at on insert, updated_at on every save.
#[async_trait::async_trait]
impl ActiveModelBehavior for ActiveModel {
    async fn before_save<C>(mut self, _db: &C, insert: bool) -> Result<Self, DbErr>
    where
        C: ConnectionTrait,
    {
        let now = super::now_secs();
        if insert {
            self.created_at = sea_orm::ActiveValue::Set(now);
        }
        self.updated_at = sea_orm::ActiveValue::Set(now);
        Ok(self)
    }
}
