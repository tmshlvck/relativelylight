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

    /// Register an audit sink fired after each committed write (create/update/delete/bulk-delete)
    /// through this engine — see [`crate::observe`]. Share one `Arc` with `Auth::on_write` to capture
    /// both the auto-CRUD and auth surfaces in one place.
    pub fn on_write(&mut self, observer: Arc<dyn crate::observe::WriteObserver>) -> &mut Self {
        self.engine.set_observer(observer);
        self
    }

    /// Require a valid **CSRF token** on every write through this registry — the double-submit token
    /// from [`crate::csrf`]. Pass the app's checker so the UI's forms and the `auth` login/profile
    /// forms share one token cookie:
    ///
    /// ```ignore
    /// crud.csrf(auth.csrf());   // the UI's forms now carry a hidden `_csrf`, and writes check it
    /// ```
    ///
    /// Writes then answer `403` unless the posted form echoes the cookie (or the request carries an
    /// `Authorization` header, which is exempt). Any app whose writes are cookie-authenticated wants
    /// this; it is off by default only because an app whose writes carry no cookie needs no token.
    /// See `docs/AUTH.md` §7.
    pub fn csrf(&mut self, csrf: crate::csrf::Csrf) -> &mut Self {
        self.engine.set_csrf(csrf);
        self
    }

    /// Where the app serves [`crud::Picker`](crate::crud::Picker): the dialog that edits a
    /// relation too large for a `<select>`. The crate adds no route — mount one `GET` handler on this
    /// path (see `docs/CRUD.md`). Without it, every relation stays a `<select>` however large it is.
    pub fn picker_path(&mut self, path: impl Into<String>) -> &mut Self {
        self.engine.set_picker_path(path);
        self
    }

    /// How many target rows a relation's form input may list as a `<select>` before it uses the
    /// picker (default 50). A relation's own
    /// [`MetaRelation::picker_threshold`](crate::crud::MetaRelation::picker_threshold) overrides it.
    pub fn picker_threshold(&mut self, n: u64) -> &mut Self {
        self.engine.set_picker_threshold(n);
        self
    }

    /// Offer **"+ New"** on relation fields: create the missing target row in a dialog over the
    /// form, and come back with it chosen. Off by default; a target's own
    /// [`MetaModel::picker_create`](crate::crud::MetaModel::picker_create) and a relation's [`MetaRelation::create`](crate::crud::MetaRelation::create) override it. Needs [`picker_path`](Crud::picker_path),
    /// and the picker route must answer `POST` too ([`Picker::submit`](crate::crud::Picker::submit))
    /// — see `docs/CRUD.md` → "Creating the missing row".
    pub fn picker_create(&mut self, on: bool) -> &mut Self {
        self.engine.set_picker_create(on);
        self
    }

    /// Make each relation's label a **link to the linked row**: in a table's cells and its View
    /// dialog, a post's author opens that author's details in a dialog over the page, with Edit when
    /// the caller may update it, and closing it returns to where they were. Off by default. Needs
    /// [`picker_path`](Crud::picker_path), whose route serves those pages and (for Edit) answers
    /// `POST`. A link is drawn only when the caller may read the target — see `docs/CRUD.md` →
    /// "Viewing the linked row".
    pub fn picker_view(&mut self, on: bool) -> &mut Self {
        self.engine.set_picker_view(on);
        self
    }

    /// The underlying backend-agnostic engine — what the UI components render from, and what an app
    /// publishing its own JSON API would call.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
    pub fn into_engine(self) -> Engine {
        self.engine
    }
}
