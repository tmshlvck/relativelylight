//! `user_group` — the user↔group membership join (composite PK). Table `auth_user_group`.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "auth_user_group")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub user_id: i32,
    #[sea_orm(primary_key, auto_increment = false)]
    pub group_id: i32,
}

/// Both sides **cascade on delete**. A membership is meaningless without the user *and* the group it
/// joins, so the row goes when either end does. Without this the constraint defaults to `NO ACTION`,
/// which does not merely leak rows — it makes deleting a user who belongs to any group *fail*
/// (`ForeignKeyConstraintViolation` → `409`), so an admin panel cannot remove an account without
/// unpicking its memberships by hand first.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::user::Entity",
        from = "Column::UserId",
        to = "super::user::Column::Id",
        on_delete = "Cascade"
    )]
    User,
    #[sea_orm(
        belongs_to = "super::group::Entity",
        from = "Column::GroupId",
        to = "super::group::Column::Id",
        on_delete = "Cascade"
    )]
    Group,
}

impl ActiveModelBehavior for ActiveModel {}
