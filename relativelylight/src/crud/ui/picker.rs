//! [`Picker`] — the page inside the dialog that edits a relation too large for a `<select>`, and
//! (with `Crud::picker_create`) the form that creates the row a relation field is missing.

use super::state::{Mode, ViewState};
use super::widgets;
use super::{authorize, render, render_err, Form, Outcome, Table};
use crate::authz::Operation;
use crate::crud::engine::{Cardinality, Column, Engine, Error, Result};
use askama::Template;
use http::HeaderMap;
use std::net::IpAddr;

/// What the picker's page shows after its create form saved: the new row, as data the dialog's
/// script reads to choose it in the form underneath.
#[derive(Template)]
#[template(path = "picker_created.html")]
struct CreatedTmpl {
    id: String,
    label: String,
}

/// The target's own table, with a radio (to-one) or a checkbox (to-many) per row — what a relation
/// field opens when its target has more rows than `picker_threshold`.
///
/// The crate adds no route: serve this from one `GET` handler of your own, on the path you gave
/// `Crud::picker_path`, wrapped in a **bare** shell (no navigation; Bootstrap and [`CSS`](super::CSS)).
/// The page that opened the dialog reads its inputs directly, so this page needs no script.
///
/// ```ignore
/// // .route("/pick", get(pick))
/// async fn pick(State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri) -> Response {
///     let state = ViewState::from_uri(&uri);
///     match Picker::new(&app.engine).render_for(&headers, &state).await {
///         Ok(html) => Html(bare_shell(&html)).into_response(),
///         Err(e) => e.into_response(),
///     }
/// }
/// ```
///
/// The URL names the **relation** (`?pick=post.tag`), never the target, so only a real relation
/// can be browsed, and the rows are a `Table` render of the target: refused (`401`/`403`) when the
/// caller may not list it, whatever they may do to the source.
///
/// **Creating the missing row.** With `Crud::picker_create(true)` a relation field also gets a
/// "+ New" (below its `<select>`, or in this picker's dialog) that opens this page as the target's
/// **create form** (`?pick=post.author&new=1`). It posts back
/// to the same URL — route `POST` to [`submit`](Picker::submit) — and a saved row lands on
/// `?pick=post.author&created=<id>`, which reports the row so the dialog can choose it in the form
/// underneath. That form's own relations get their "+" too, so the dialogs nest (the script stops
/// at four forms deep).
pub struct Picker<'a> {
    engine: &'a Engine,
    per_page: u64,
    create_fields: Vec<(String, Vec<String>)>,
}

/// The relation a `?pick=` names: its target, and whether it is a to-many.
struct Picked {
    target: String,
    many: bool,
}

impl<'a> Picker<'a> {
    pub fn new(engine: &'a Engine) -> Self {
        Self { engine, per_page: 10, create_fields: Vec::new() }
    }

    /// Rows per page in the dialog. Default 10.
    pub fn per_page(mut self, n: u64) -> Self {
        self.per_page = n.max(1);
        self
    }

    /// The fields the create form for `target` shows, in this order — as [`Form::fields`]. Without
    /// it the form shows every writable column of the target. Keyed by the **target** entity, so
    /// one call covers every relation that points at it.
    pub fn create_fields<I, S>(mut self, target: impl Into<String>, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let target = target.into();
        self.create_fields.retain(|(t, _)| *t != target);
        self.create_fields.push((target, names.into_iter().map(Into::into).collect()));
        self
    }

    /// Render the picker for the relation `?pick=` names: the target's rows, or with `&new=1` its
    /// create form, or with `&created=<id>` the row that form just made. `400` if it names none, or
    /// no relation of that entity, or asks for a create the app didn't turn on.
    pub async fn render_for(&self, headers: &HeaderMap, state: &ViewState) -> Result<String> {
        let picked = self.picked(state)?;
        if let Some(id) = &state.created {
            self.creating()?;
            // The label is a read of the target; "+" is only offered to who may list it.
            authorize(self.engine, Operation::List, &picked.target, headers).await?;
            let found =
                widgets::chosen_options(self.engine, &picked.target, std::slice::from_ref(id), None, true)
                    .await?;
            let label = found.into_iter().next().map(|o| o.label).unwrap_or_else(|| id.clone());
            return CreatedTmpl { id: id.clone(), label }.render().map_err(render_err);
        }
        if state.mode == Mode::New {
            self.creating()?;
            authorize(self.engine, Operation::List, &picked.target, headers).await?;
            return self.form(&picked.target).render_for(headers, state).await;
        }
        Table::new(self.engine, picked.target)
            .per_page(self.per_page)
            .render_pick(headers, state, picked.many)
            .await
    }

    /// Apply the create form's posted body (`?pick=…&new=1`). Saved: `Done` with
    /// `?pick=…&created=<id>` — redirect there (`303`), into the same dialog. Rejected:
    /// `Invalid` — answer `422` with [`render_for`](Picker::render_for) of that state, the form with
    /// its messages. It only ever **creates**: the target's create gate decides, CSRF is checked
    /// as on every write, and a posted update is refused.
    pub async fn submit(
        &self,
        headers: &HeaderMap,
        client_ip: IpAddr,
        body: &[u8],
        state: &ViewState,
    ) -> Result<Outcome> {
        let picked = self.picked(state)?;
        self.creating()?;
        if state.mode != Mode::New {
            return Err(Error::BadRequest("crud::ui::Picker: a write needs ?new=1".into()));
        }
        authorize(self.engine, Operation::List, &picked.target, headers).await?;
        match self.form(&picked.target).redirect("{id}").submit(headers, client_ip, body, state).await? {
            Outcome::Done(id) => {
                let (slug, relation) = state.pick.as_ref().expect("picked() checked it");
                let pick = format!("{slug}.{relation}");
                Ok(Outcome::Done(format!(
                    "?{}",
                    crate::urlform::query(&[("pick".into(), pick), ("created".into(), id)])
                )))
            }
            invalid => Ok(invalid),
        }
    }

    fn form(&self, target: &str) -> Form<'a> {
        let form = Form::new(self.engine, target).only_create().submit_label("Create");
        match self.create_fields.iter().find(|(t, _)| t == target) {
            Some((_, names)) => form.fields(names.clone()),
            None => form,
        }
    }

    fn creating(&self) -> Result<()> {
        match self.engine.picker_create_path() {
            Some(_) => Ok(()),
            None => Err(Error::BadRequest("crud::ui::Picker: creating is off (Crud::picker_create)".into())),
        }
    }

    fn picked(&self, state: &ViewState) -> Result<Picked> {
        let Some((slug, relation)) = &state.pick else {
            return Err(Error::BadRequest("crud::ui::Picker: no ?pick=<entity>.<relation>".into()));
        };
        let cols = self.engine.columns(slug)?;
        let found = cols.iter().find(|c| render::name_of(c) == relation);
        let Some(Column::Relation { target, cardinality, .. }) = found else {
            return Err(Error::BadRequest(format!("crud::ui::Picker: {slug} has no relation '{relation}'")));
        };
        Ok(Picked { target: target.clone(), many: *cardinality == Cardinality::ToMany })
    }
}
