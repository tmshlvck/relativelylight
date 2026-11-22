//! [`Picker`] — the page inside the dialog that edits a relation too large for a `<select>`, and
//! (with `Crud::picker_create`) the form that creates the row a relation field is missing.

use super::state::{Mode, ViewState};
use super::{authorize, render, render_err, Form, Outcome, Table};
use crate::authz::Operation;
use crate::crud::engine::find;
use crate::crud::{Cardinality, Column, Engine, Error, Result};
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
/// // .route("/_rl/pick", get(pick))
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
}

/// The relation a `?pick=` names, its target, and what it allows here: viewing (and editing) its
/// rows, creating one. The two switches are resolved once: the relation's own choice
/// (`MetaRelation::links` / `create`), else the app's.
struct Picked {
    slug: String,
    relation: String,
    target: String,
    many: bool,
    view: bool,
    create: bool,
}

impl Picked {
    /// `?pick=<this relation>&<key>=<value>`, relative: the next page in the same dialog.
    fn href(&self, key: &str, value: &str) -> String {
        pick_href("", &self.slug, &self.relation, Some((key, value)))
    }
}

/// `<path>?pick=<slug>.<relation>` and one more pair: every URL into the picker is this shape.
pub(crate) fn pick_href(path: &str, slug: &str, relation: &str, extra: Option<(&str, &str)>) -> String {
    let mut pairs = vec![("pick".to_string(), format!("{slug}.{relation}"))];
    pairs.extend(extra.map(|(k, v)| (k.to_string(), v.to_string())));
    format!("{path}?{}", crate::urlform::query(&pairs))
}

impl<'a> Picker<'a> {
    pub fn new(engine: &'a Engine) -> Self {
        Self { engine, per_page: 10 }
    }

    /// Rows per page in the dialog. Default 10.
    pub fn per_page(mut self, n: u64) -> Self {
        self.per_page = n.max(1);
        self
    }

    /// Render the picker for the relation `?pick=` names: the target's rows; with `&new=1` its
    /// create form, with `&created=<id>` the row that form just made; with `&show=<id>` a linked
    /// row, with `&edit=<id>` its edit form. `400` if it names no relation of that entity, or asks
    /// for a page the relation doesn't offer.
    pub async fn render_for(&self, headers: &HeaderMap, state: &ViewState) -> Result<String> {
        let p = self.picked(state)?;
        match (&state.created, &state.mode) {
            (Some(id), _) => {
                // The label is a read of the target; "+" is only offered to who may list it.
                self.open_create(&p, headers).await?;
                let label = render::label(self.engine, &p.target, id).await?;
                CreatedTmpl { id: id.clone(), label }.render().map_err(render_err)
            }
            (None, Mode::New) => {
                self.open_create(&p, headers).await?;
                self.form(&p.target).render_for(headers, state).await
            }
            (None, Mode::Show(id)) => {
                self.open_view(&p, headers).await?;
                let edit = match self.engine.permits(&p.target, Operation::Update, headers).await {
                    true => p.href("edit", id),
                    false => String::new(),
                };
                let saved = match state.saved {
                    true => Some((format!("{}:{id}", p.target), render::label(self.engine, &p.target, id).await?)),
                    false => None,
                };
                Table::new(self.engine, &p.target).render_linked(headers, id, edit, saved).await
            }
            (None, Mode::Edit(id)) => {
                self.open_view(&p, headers).await?;
                self.edit_form(&p, id).cancel(p.href("show", id)).render_for(headers, state).await
            }
            _ => {
                let table = Table::new(self.engine, &p.target).per_page(self.per_page);
                table.render_pick(headers, state, p.many).await
            }
        }
    }

    /// Apply a posted form: the create form (`&new=1`) or a linked row's edit (`&edit=<id>`).
    /// Saved: `Done` — redirect there (`303`), into the same dialog: `&created=<id>`, or the row
    /// with `&saved=1`. Rejected: `Invalid` — answer `422` with [`render_for`](Picker::render_for)
    /// of that state, the form with its messages. The create form only creates and the edit only
    /// updates the row its URL names; the target's gates decide, and CSRF is checked as on every
    /// write.
    pub async fn submit(
        &self,
        headers: &HeaderMap,
        client_ip: IpAddr,
        body: &[u8],
        state: &ViewState,
    ) -> Result<Outcome> {
        let p = self.picked(state)?;
        match &state.mode {
            Mode::New => {
                self.open_create(&p, headers).await?;
                match self.form(&p.target).redirect("{id}").submit(headers, client_ip, body, state).await? {
                    Outcome::Done(id) => Ok(Outcome::Done(p.href("created", &id))),
                    invalid => Ok(invalid),
                }
            }
            Mode::Edit(id) => {
                self.open_view(&p, headers).await?;
                // `.edit(id)` pins the write to the URL's row: a posted `_id` naming another is refused.
                match self.edit_form(&p, id).redirect("{id}").submit(headers, client_ip, body, state).await? {
                    Outcome::Done(_) => Ok(Outcome::Done(format!("{}&saved=1", p.href("show", id)))),
                    invalid => Ok(invalid),
                }
            }
            _ => Err(Error::BadRequest("crud::Picker: a write needs ?new=1 or ?edit=<id>".into())),
        }
    }

    /// The prelude of every page past the plain picker: the relation offers it (`on`, else `400`,
    /// as when the app has it off), and the caller passes the target's `op` gate.
    async fn open(&self, p: &Picked, on: bool, op: Operation, headers: &HeaderMap) -> Result<()> {
        if !on {
            return Err(Error::BadRequest(format!(
                "crud::Picker: {}.{} offers no such page (Crud::picker_create / picker_view, \
                 MetaModel::picker_create, MetaRelation::create / links)",
                p.slug, p.relation
            )));
        }
        authorize(self.engine, op, &p.target, headers).await
    }

    /// [`open`](Self::open) the create form and what it reports: "+ New" offered, and the target
    /// listable — the page that reports the new row shows its label.
    async fn open_create(&self, p: &Picked, headers: &HeaderMap) -> Result<()> {
        self.open(p, p.create, Operation::List, headers).await
    }

    /// [`open`](Self::open) a linked row or its edit form: links offered, and the row readable.
    async fn open_view(&self, p: &Picked, headers: &HeaderMap) -> Result<()> {
        self.open(p, p.view, Operation::Read, headers).await
    }

    /// The edit form of a linked row, inside the picker's dialog.
    fn edit_form(&self, p: &Picked, id: &str) -> Form<'a> {
        Form::new(self.engine, &p.target).edit(id.to_string()).embedded()
    }

    fn form(&self, target: &str) -> Form<'a> {
        let form = Form::new(self.engine, target).embedded().submit_label("Create");
        // The target's own choice (`MetaModel::picker_create_fields`), else every writable field.
        match self.engine.meta(target).map(|m| m.picker_create_fields) {
            Ok(names) if !names.is_empty() => form.fields(names),
            _ => form,
        }
    }

    fn picked(&self, state: &ViewState) -> Result<Picked> {
        let Some((slug, relation)) = &state.pick else {
            return Err(Error::BadRequest("crud::Picker: no ?pick=<entity>.<relation>".into()));
        };
        let cols = self.engine.columns(slug)?;
        let found = find(&cols, relation);
        let Some(Column::Relation { target, cardinality, links, create, .. }) = found else {
            return Err(Error::BadRequest(format!("crud::Picker: {slug} has no relation '{relation}'")));
        };
        Ok(Picked {
            view: self.engine.picker_view_path(*links).is_some(),
            create: self.engine.picker_create_path(target, *create).is_some(),
            slug: slug.clone(),
            relation: relation.clone(),
            target: target.clone(),
            many: *cardinality == Cardinality::ToMany,
        })
    }
}
