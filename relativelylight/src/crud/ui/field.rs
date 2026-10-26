//! [`RelationField`] — one relation input, select-or-picker, for a form the app writes itself.

use super::checks::render_err;
use super::decode::Posted;
use super::render;
use super::widgets::{self, FieldV, Widget};
use super::write::missing_ids;
use crate::crud::engine::{Cardinality, Column, Engine, Error, Result, ValidationErrors};
use askama::Template;
use http::HeaderMap;

#[derive(Template)]
#[template(path = "field.html")]
struct FieldTmpl {
    f: FieldV,
}

/// One relation's input, for a `<form>` of the app's own — the same input `Form`, `Table` and `Admin`
/// render for that relation: a `<select>` (a multi-select for a to-many) while the target has at most
/// [`picker_threshold`](RelationField::picker_threshold) rows, else the selection as badges plus a
/// button opening the [`Picker`](super::Picker) dialog. One function decides that and one template
/// draws it, for all four, so the field can't drift from the crate's own forms.
///
/// It is named by a **relation** of a registered entity (`"post"`, `"tag"`), because that is what
/// the picker browses (`?pick=post.tag`): the rows offered are the relation's target, under the
/// target's gate. The form it sits in needn't be about that entity at all — a bulk operation, a
/// filter, a wizard step — and it writes nothing: the app reads the ids back with
/// [`read`](RelationField::read) and does what it likes with them. Define it once and use it in both
/// handlers:
///
/// ```ignore
/// fn tags(engine: &Engine) -> RelationField<'_> {
///     RelationField::new(engine, "post", "tag").name("tags").label("Tags to add")
/// }
///
/// // GET: render it into your form (selected ids from wherever your form's state lives)
/// let input = tags(&engine).selected(&ids).render_for(&headers).await?;
///
/// // POST: the ids that were chosen — each checked to be a row of the target
/// let ids: Vec<String> = tags(&engine).read(&headers, &body).await?;
/// ```
///
/// The picker needs what it needs in a `Form`: `Crud::picker_path`, the `GET` route serving
/// [`Picker`](super::Picker), and [`JS`](super::JS) in the page shell. Without them the field is a
/// `<select>` of every row, which still works.
///
/// **Gate.** The target's `List` decides whether its rows are offered at all; a caller who may not
/// list it sees the current selection, as ids, with no way to browse — exactly as in a `Form`.
/// `render_for` reads nothing else, so it needs no gate of its own: the write your handler makes with
/// the ids is where the authority to change anything is checked.
pub struct RelationField<'a> {
    engine: &'a Engine,
    slug: String,
    relation: String,
    name: Option<String>,
    label: Option<String>,
    help: Option<String>,
    error: String,
    required: bool,
    selected: Vec<String>,
    picker_threshold: u64,
}

impl<'a> RelationField<'a> {
    /// The relation `relation` of the registered entity `slug`.
    pub fn new(engine: &'a Engine, slug: impl Into<String>, relation: impl Into<String>) -> Self {
        Self {
            engine,
            slug: slug.into(),
            relation: relation.into(),
            name: None,
            label: None,
            help: None,
            error: String::new(),
            required: false,
            selected: Vec::new(),
            picker_threshold: 50,
        }
    }

    /// The input's `name` (and DOM id, `f-{name}`). Default: the relation's name. Set it when the
    /// form already has a field by that name, or holds two fields over one relation.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    /// The label. Default: the relation's label, as the crate's forms show it.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
    /// Help text under the input. Default: the relation's description.
    pub fn help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }
    /// Marks the label required (`*`). Presentation only: [`read`](RelationField::read) returns what
    /// was posted, empty or not, and the check is your handler's.
    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }
    /// A message shown under the input, styled as invalid — your handler's reason for re-rendering.
    pub fn error(mut self, message: impl Into<String>) -> Self {
        self.error = message.into();
        self
    }
    /// The ids currently chosen (the target's primary keys, as text). Labels are looked up. For a
    /// to-one, at most the first is shown.
    pub fn selected<I>(mut self, ids: I) -> Self
    where
        I: IntoIterator,
        I::Item: ToString,
    {
        self.selected = ids.into_iter().map(|id| id.to_string()).filter(|id| !id.is_empty()).collect();
        self
    }
    /// How many target rows a `<select>` may list before the field switches to the picker.
    /// Default 50, as in [`Form`](super::Form).
    pub fn picker_threshold(mut self, n: u64) -> Self {
        self.picker_threshold = n;
        self
    }

    fn input_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.relation)
    }

    fn column(&self) -> Result<(String, Cardinality, String, String)> {
        let cols = self.engine.columns(&self.slug)?;
        match cols.iter().find(|c| render::name_of(c) == self.relation) {
            Some(col @ Column::Relation { target, cardinality, description, .. }) => Ok((
                target.clone(),
                *cardinality,
                render::label_of(col),
                description.clone().unwrap_or_default(),
            )),
            _ => Err(Error::BadRequest(format!(
                "crud::ui::RelationField: {} has no relation '{}'",
                self.slug, self.relation
            ))),
        }
    }

    /// Render the field: a `<div class="mb-3">` with the label, the input and any error — a fragment
    /// for the inside of your `<form>`. `400` when `slug` has no relation by that name, `404` when
    /// there is no entity `slug`.
    pub async fn render_for(&self, headers: &HeaderMap) -> Result<String> {
        let (target, cardinality, label, description) = self.column()?;
        let many = cardinality == Cardinality::ToMany;
        let mut ids = self.selected.clone();
        if !many {
            ids.truncate(1);
        }
        let rel = widgets::Relations { slug: &self.slug, threshold: self.picker_threshold, headers };
        let widget: Widget =
            widgets::relation(self.engine, &rel, &self.relation, &target, many, ids, None).await?;
        FieldTmpl {
            f: FieldV {
                name: self.input_name().to_string(),
                label: self.label.clone().unwrap_or(label),
                required: self.required,
                help: self.help.clone().unwrap_or(description),
                error: self.error.clone(),
                widget,
            },
        }
        .render()
        .map_err(render_err)
    }

    /// The ids posted for this field **unchecked** — for re-showing a rejected form with what the
    /// operator chose still in it (`.selected(field.posted(..)?)`), as a `Form` does; an id that names
    /// no row shows as typed. Never write these: [`read`](RelationField::read) is the checked way in.
    pub fn posted(&self, headers: &HeaderMap, body: &[u8]) -> Result<Vec<String>> {
        let posted = Posted::read(headers, body)?;
        let mut ids: Vec<String> = posted
            .all(self.input_name())
            .into_iter()
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .collect();
        if self.column()?.1 == Cardinality::ToOne {
            ids.truncate(1);
        }
        Ok(ids)
    }

    /// The ids posted for this field, in order, blanks dropped (a `<select>`'s "—"); a to-one gives at
    /// most one. Every id is checked to be a row of the target — the same check a `Form` save makes,
    /// since the picker posts hidden inputs, as editable as any typed id — and one that isn't is
    /// `Err(Error::Validation)` with a message under this field's name ("no tag matches '99'"), ready
    /// for [`error`](RelationField::error). That an id *exists* is all this says: whether this caller
    /// may link it, or write whatever you write with it, is your handler's check.
    /// URL-encoded and multipart bodies; `400` for a multipart body that can't be parsed.
    pub async fn read(&self, headers: &HeaderMap, body: &[u8]) -> Result<Vec<String>> {
        let (target, _, _, _) = self.column()?;
        let ids = self.posted(headers, body)?;
        let missing = missing_ids(self.engine, &target, &ids).await?;
        if !missing.is_empty() {
            let mut errors = ValidationErrors::new();
            errors.field(self.input_name(), format!("no {target} matches '{}'", missing.join("', '")));
            return Err(Error::Validation(errors));
        }
        Ok(ids)
    }
}
