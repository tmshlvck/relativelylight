//! [`Picker`] — the page inside the dialog that edits a relation too large for a `<select>`, and
//! (with `Crud::picker_create`) the form that creates the row a relation field is missing.

use super::decode::Posted;
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
///
/// **Viewing the linked row.** With `Crud::picker_view(true)` a relation's label in a table (and in
/// its View dialog) links to the row: `?pick=post.author&show=3` is that author, read-only, with
/// relation links of its own and an Edit (`&edit=3`) when the caller may update it. The edit form
/// posts to [`submit`](Picker::submit) as well, and a saved edit lands back on the row with
/// `&saved=1`, which the dialog's script reads to update the label underneath.
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
            self.creating(&picked.target)?;
            // The label is a read of the target; "+" is only offered to who may list it.
            authorize(self.engine, Operation::List, &picked.target, headers).await?;
            let found =
                widgets::chosen_options(self.engine, &picked.target, std::slice::from_ref(id), None, true)
                    .await?;
            let label = found.into_iter().next().map(|o| o.label).unwrap_or_else(|| id.clone());
            return CreatedTmpl { id: id.clone(), label }.render().map_err(render_err);
        }
        match &state.mode {
            Mode::New => {
                self.creating(&picked.target)?;
                authorize(self.engine, Operation::List, &picked.target, headers).await?;
                return self.form(&picked.target).render_for(headers, state).await;
            }
            Mode::Show(id) => {
                self.viewing()?;
                authorize(self.engine, Operation::Read, &picked.target, headers).await?;
                let edit = match self.engine.permits(&picked.target, Operation::Update, headers).await {
                    true => self.href(state, "edit", id),
                    false => String::new(),
                };
                return Table::new(self.engine, &picked.target)
                    .render_linked(headers, id, edit, state.saved)
                    .await;
            }
            Mode::Edit(id) => {
                self.viewing()?;
                authorize(self.engine, Operation::Read, &picked.target, headers).await?;
                return Form::new(self.engine, &picked.target)
                    .edit(id.clone())
                    .only_update()
                    .cancel(self.href(state, "show", id))
                    .render_for(headers, state)
                    .await;
            }
            _ => {}
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
        if let Mode::Edit(id) = &state.mode {
            return self.save_edit(&picked, id, headers, client_ip, body, state).await;
        }
        self.creating(&picked.target)?;
        if state.mode != Mode::New {
            return Err(Error::BadRequest("crud::ui::Picker: a write needs ?new=1 or ?edit=<id>".into()));
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

    /// The linked row's edit form, posted: an update of exactly the row the URL names, under the
    /// target's Update gate (and Read, as for the page), back to the row with `saved=1`.
    async fn save_edit(
        &self,
        picked: &Picked,
        id: &str,
        headers: &HeaderMap,
        client_ip: IpAddr,
        body: &[u8],
        state: &ViewState,
    ) -> Result<Outcome> {
        self.viewing()?;
        authorize(self.engine, Operation::Read, &picked.target, headers).await?;
        // The form posts the row's id as `_id`; one naming another row is not this page's write.
        if Posted::read(headers, body)?.one("_id") != Some(id) {
            return Err(Error::BadRequest("crud::ui::Picker: the posted row is not the URL's".into()));
        }
        let form = Form::new(self.engine, &picked.target).edit(id.to_string()).only_update().redirect("{id}");
        match form.submit(headers, client_ip, body, state).await? {
            Outcome::Done(_) => Ok(Outcome::Done(format!("{}&saved=1", self.href(state, "show", id)))),
            invalid => Ok(invalid),
        }
    }

    /// `?pick=<this relation>&<key>=<id>`.
    fn href(&self, state: &ViewState, key: &str, id: &str) -> String {
        let (slug, relation) = state.pick.as_ref().expect("picked() checked it");
        let pairs = [("pick".to_string(), format!("{slug}.{relation}")), (key.to_string(), id.to_string())];
        format!("?{}", crate::urlform::query(&pairs))
    }

    fn viewing(&self) -> Result<()> {
        match self.engine.picker_view_path() {
            Some(_) => Ok(()),
            None => Err(Error::BadRequest("crud::ui::Picker: linked rows are off (Crud::picker_view)".into())),
        }
    }

    fn form(&self, target: &str) -> Form<'a> {
        let form = Form::new(self.engine, target).only_create().submit_label("Create");
        match self.create_fields.iter().find(|(t, _)| t == target) {
            Some((_, names)) => form.fields(names.clone()),
            None => form,
        }
    }

    fn creating(&self, target: &str) -> Result<()> {
        match self.engine.picker_create_path(target) {
            Some(_) => Ok(()),
            None => Err(Error::BadRequest(format!(
                "crud::ui::Picker: creating {target} is off (Crud::picker_create / picker_create_except)"
            ))),
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
