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

/// The table for an accounts panel: the name checked with
/// [`valid_group_name`](super::valid_group_name), the timestamps read-only, and the members edited
/// through the N:M relation `auth_user`. Registered next to
/// [`user::meta_model`](super::user::meta_model).
pub fn meta_model() -> crate::crud::MetaModel<Entity> {
    use sea_orm::IdenStatic;
    use Column as C;
    let mut m = crate::crud::MetaModel::new(Entity);
    m.label_column(C::Name.as_str());
    let f = m.field(C::Name.as_str());
    f.label = Some("Group".into());
    f.validate_str(super::valid_group_name);
    for (c, label) in [(C::CreatedAt, "Created"), (C::UpdatedAt, "Updated")] {
        let f = m.field(c.as_str());
        f.label = Some(label.into());
        f.read_only = true;
        f.datetime();
    }
    // The relation needs only the other side's identity, not its configuration.
    m.relate(&crate::crud::MetaModel::new(super::user::Entity));
    m.relation("auth_user").label = Some("Members".into());
    m
}
