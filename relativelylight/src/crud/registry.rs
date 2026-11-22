//! [`Crud`]: registering SeaORM models over one database connection, and the app-wide defaults.

use super::seaorm::{MetaModel, SeaRegistry};
use crate::crud::Engine;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, IntoActiveModel};
use serde::Serialize;
use std::sync::Arc;

pub struct Crud {
    engine: Engine,
    db: DatabaseConnection,
    registry: Arc<SeaRegistry>,
}

impl Crud {
    /// A registry over one database connection. There is no mount path: the UI components render
    /// links relative to whatever URL the app serves them on.
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            engine: Engine::new(),
            db,
            registry: Arc::new(SeaRegistry::default()),
        }
    }

    /// Register a model behind an authorization gate. Pass [`Open`](crate::authz::Open) for an
    /// ungated endpoint, or a gate built from your [`Auth`](crate::auth::Auth) — e.g.
    /// `crud.register(post, UserReadGroupWrite::new(&auth, ["admin"]))`. Share one gate across models
    /// by passing an `Arc<dyn Authz>` (it implements the trait). Each gate is handed the request,
    /// resolves the identity itself, and returns a [`Decision`](crate::authz::Decision) → the handler
    /// maps it to `200`/`401`/`403`.
    pub fn register<E, G>(&mut self, model: MetaModel<E>, gate: G) -> &mut Self
    where
        E: EntityTrait + Send + Sync,
        E::Model: Serialize + Sync + IntoActiveModel<E::ActiveModel>,
        E::ActiveModel: ActiveModelTrait<Entity = E> + Default + Send + Sync,
        G: crate::authz::Authz + 'static,
    {
        let acc = self.registry.accessor(self.db.clone(), model);
        self.engine.add(acc, Arc::new(gate));
        self
    }

    /// The underlying backend-agnostic engine — what the UI components render from, and what an app
    /// publishing its own JSON API would call.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
    /// The engine, registration done: configure it ([`Engine::csrf`], [`Engine::on_write`],
    /// [`Engine::picker_path`], …) and hand it to the components.
    pub fn into_engine(self) -> Engine {
        self.engine
    }
}
