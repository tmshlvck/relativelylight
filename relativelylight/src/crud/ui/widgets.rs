//! One `match` from [`Column`] to a form input, and **the value** in it: the operator's own rejected
//! input if there was one, else the row being edited, else the form's initial value, else the
//! column's create-default, else nothing.

use super::state::ViewState;
use crate::authz::Operation;
use crate::crud::engine::{Cardinality, Column, Engine, FieldDisplay, ListQuery, LogicalType, Result};
use crate::time::Tz;
use http::HeaderMap;
use serde_json::Value;

pub(crate) struct FieldV {
    pub name: String,
    pub label: String,
    pub required: bool,
    pub help: String,
    pub error: String,
    pub widget: Widget,
    /// Where this relation field's **"+"** opens a create form for a new target row — the picker
    /// path with `?pick=<slug>.<relation>&new=1`. Empty: no "+" (see [`create_src`]).
    pub create: String,
}

pub(crate) struct Opt {
    pub value: String,
    pub label: String,
    pub selected: bool,
}

pub(crate) enum Widget {
    /// `type` is `text` / `email` / `url` / `password`, from the column's display override.
    Text { value: String, kind: &'static str, placeholder: String },
    Textarea { value: String, rows: u16 },
    Number { value: String, step: &'static str },
    Range { value: String, min: f64, max: f64, step: f64 },
    Switch { on: bool },
    Select { options: Vec<Opt>, blank: bool },
    Radio { options: Vec<Opt> },
    /// Integer Unix seconds, edited as wall-clock time in `zone`.
    DateTime { value: String, zone: String },
    /// A to-many relation: every target row as a multi-select.
    Multi { options: Vec<Opt> },
    /// A relation whose target is too large to list: the selection, read-only, posted back by one
    /// hidden input per id — and, when the app serves a [`Picker`](super::Picker), a button opening
    /// it in a dialog at `src`. `crud::ui::JS` does the editing; without it the selection still
    /// saves unchanged. `note` says why there is no list (empty when there's nothing to say).
    Picked { chosen: Vec<Opt>, many: bool, src: String, note: String },
}

/// What a relation input needs beyond its column: whose field it is (the picker's `?pick=` names
/// it), how many target rows a `<select>` may list, and who is asking — the **target's** gate
/// decides whether its rows are listed at all, since a form for one table is no licence to read
/// another.
pub(crate) struct Relations<'r> {
    pub slug: &'r str,
    pub threshold: u64,
    pub headers: &'r HeaderMap,
    /// The gates' answers so far in this render, `(target, op, allowed)`: a gate may cost a session
    /// lookup, and a form asks the same target's List for its input and its "+ New", and again for
    /// a second relation to the same table.
    gates: std::sync::Mutex<Vec<(String, Operation, bool)>>,
}

impl<'r> Relations<'r> {
    pub fn new(slug: &'r str, threshold: u64, headers: &'r HeaderMap) -> Self {
        Self { slug, threshold, headers, gates: Default::default() }
    }

    /// `engine.permits(target, op, headers)`, asked once per render.
    async fn permits(&self, engine: &Engine, target: &str, op: Operation) -> bool {
        let known = |g: &Vec<(String, Operation, bool)>| {
            g.iter().find(|(t, o, _)| t == target && *o == op).map(|(_, _, ok)| *ok)
        };
        if let Some(ok) = known(&self.gates.lock().unwrap()) {
            return ok;
        }
        let ok = engine.permits(target, op, self.headers).await;
        self.gates.lock().unwrap().push((target.to_string(), op, ok));
        ok
    }
}

/// What one form, for one request, adds to the columns: initial values for a create
/// (`Form::initial`, `Table::initial`), and the sets a pinned view's writes must stay in
/// (`Table::fixed_in`), which narrow those columns' inputs to the set.
#[derive(Default)]
pub(crate) struct Presets<'p> {
    pub initial: &'p [(String, Value)],
    pub sets: &'p [(String, Vec<String>)],
}

impl Presets<'_> {
    fn initial_of(&self, name: &str) -> Option<&Value> {
        self.initial.iter().find(|(n, _)| n == name).map(|(_, v)| v)
    }
    fn set_of(&self, name: &str) -> Option<&[String]> {
        self.sets.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_slice())
    }
}

/// Build the form's fields for one entity.
///
/// `row` is the record being edited (`None` when creating). `rendered` decides which columns the form
/// shows — the same predicate the decoder uses, so a column that isn't rendered is also not accepted
/// from a posted body.
#[allow(clippy::too_many_arguments)] // one form's context, passed straight through
pub(crate) async fn fields(
    engine: &Engine,
    cols: &[Column],
    rendered: &(dyn Fn(&str) -> bool + Send + Sync),
    row: Option<&Value>,
    state: &ViewState,
    tz: &Tz,
    rel: &Relations<'_>,
    presets: &Presets<'_>,
) -> Result<Vec<FieldV>> {
    let mut out = Vec::new();
    for col in cols.iter().filter(|c| writable(c) && rendered(super::render::name_of(c))) {
        let name = super::render::name_of(col).to_string();
        let (widget, create) = match presets.set_of(&name) {
            // A pinned set is a choice among rows the view already names; a new row isn't one.
            Some(set) => (within(engine, col, row, state, tz, rel, presets, set).await?, String::new()),
            None => {
                let create = match col {
                    Column::Relation { target, create, .. } => {
                        create_src(engine, rel, &name, target, *create).await
                    }
                    Column::Field { .. } => String::new(),
                };
                (widget(engine, col, row, state, tz, rel, presets).await?, create)
            }
        };
        out.push(FieldV {
            widget,
            create,
            label: super::render::label_of(col),
            required: matches!(col, Column::Field { required: true, .. }),
            help: help_of(col),
            error: state.field_error(&name).unwrap_or_default().to_string(),
            name,
        });
    }
    Ok(out)
}

pub(crate) fn writable(col: &Column) -> bool {
    match col {
        Column::Field { read_only, .. } | Column::Relation { read_only, .. } => !read_only,
    }
}

fn help_of(col: &Column) -> String {
    match col {
        Column::Field { description, .. } | Column::Relation { description, .. } => {
            description.clone().unwrap_or_default()
        }
    }
}

/// The input for a column pinned to a set (`Table::fixed_in`): a choice among the set and nothing
/// else — a value outside it would only be refused. No blank option, since blank isn't in the set.
/// A relation's choices are the target rows the set names, with their labels when the caller may
/// list the target, else the ids.
#[allow(clippy::too_many_arguments)]
async fn within(
    engine: &Engine,
    col: &Column,
    row: Option<&Value>,
    state: &ViewState,
    tz: &Tz,
    rel: &Relations<'_>,
    presets: &Presets<'_>,
    set: &[String],
) -> Result<Widget> {
    let name = super::render::name_of(col);
    let options = match col {
        Column::Field { display: Some(FieldDisplay::Radio), options, .. } => {
            let value = field_value(col, row, state, tz, presets);
            let allowed: Vec<String> = options.iter().filter(|o| set.contains(o)).cloned().collect();
            return Ok(Widget::Radio { options: choices(col, &allowed, &value) });
        }
        Column::Field { .. } => {
            let value = field_value(col, row, state, tz, presets);
            choices(col, set, &value)
        }
        Column::Relation { target, .. } => {
            let chosen = relation_values(name, row, state, presets);
            let labels = match engine.permits(target, Operation::List, rel.headers).await {
                true => {
                    let q = ListQuery { pk_in: set.to_vec(), all: true, ..Default::default() };
                    match engine.list(target, &q, true).await {
                        Ok(page) => page.data,
                        Err(crate::crud::engine::Error::BadRequest(_)) => Vec::new(),
                        Err(e) => return Err(e),
                    }
                }
                false => Vec::new(),
            };
            set.iter()
                .map(|id| Opt {
                    selected: chosen.contains(id),
                    label: labels
                        .iter()
                        .find(|it| super::render::text(Some(&it.id)) == *id)
                        .map(|it| it.label.clone())
                        .unwrap_or_else(|| id.clone()),
                    value: id.clone(),
                })
                .collect()
        }
    };
    Ok(Widget::Select { options, blank: false })
}

async fn widget(
    engine: &Engine,
    col: &Column,
    row: Option<&Value>,
    state: &ViewState,
    tz: &Tz,
    rel: &Relations<'_>,
    presets: &Presets<'_>,
) -> Result<Widget> {
    let name = super::render::name_of(col);
    match col {
        Column::Field { logical_type, options, display, nullable, required, write_only, .. } => {
            let value = field_value(col, row, state, tz, presets);
            Ok(match (display, logical_type) {
                (Some(FieldDisplay::Textarea { rows }), _) => {
                    Widget::Textarea { value, rows: *rows }
                }
                (Some(FieldDisplay::DateTime), _) => {
                    Widget::DateTime { value, zone: tz.name().to_string() }
                }
                (Some(FieldDisplay::Range { min, max, step }), _) => Widget::Range {
                    value: if value.is_empty() { min.to_string() } else { value },
                    min: *min,
                    max: *max,
                    step: *step,
                },
                (Some(FieldDisplay::Radio), _) => Widget::Radio {
                    options: choices(col, options, &value),
                },
                (Some(FieldDisplay::Email), _) => {
                    Widget::Text { value, kind: "email", placeholder: String::new() }
                }
                (Some(FieldDisplay::Url), _) => {
                    Widget::Text { value, kind: "url", placeholder: String::new() }
                }
                // A closed set of values → a dropdown: the choices are discoverable and a typo is
                // impossible. The blank option appears only where the column accepts one.
                _ if !options.is_empty() => Widget::Select {
                    options: choices(col, options, &value),
                    blank: *nullable || !*required,
                },
                (_, LogicalType::Bool) => Widget::Switch { on: value == "true" },
                (_, LogicalType::Int) => Widget::Number { value, step: "1" },
                (_, LogicalType::Float) => Widget::Number { value, step: "any" },
                // A write-only column (a password) is never rendered with a value — there is nothing
                // to show, and on edit an empty input means "keep the current one".
                _ if *write_only => Widget::Text {
                    value: String::new(),
                    kind: "password",
                    placeholder: if row.is_some() { "unchanged".into() } else { String::new() },
                },
                _ => Widget::Text { value, kind: "text", placeholder: String::new() },
            })
        }
        Column::Relation { target, cardinality, .. } => {
            // Rejected input is ids only; the edited row embeds `{id, label}`, so its labels are free.
            // (A create has no row to embed labels; its initial ids are looked up instead.)
            let linked = match (state.posted(name), row) {
                (None, Some(_)) => Some(linked_options(name, row)),
                _ => None,
            };
            let many = *cardinality == Cardinality::ToMany;
            let ids = relation_values(name, row, state, presets);
            relation(engine, rel, name, target, many, ids, linked).await
        }
    }
}

/// A relation's input — a `<select>` while the target is small, else the selection with a button
/// opening the [`Picker`](super::Picker). The **one** place that decision is made: [`fields`] calls it
/// for `Form`/`Table`/`Admin`, and [`RelationField`](super::RelationField) for an app's own form.
///
/// `relation` is the relation's name on `rel.slug` (what the picker's `?pick=` names); `ids` the
/// current selection, and `linked` the same selection with labels when they're already in hand.
pub(crate) async fn relation(
    engine: &Engine,
    rel: &Relations<'_>,
    relation: &str,
    target: &str,
    many: bool,
    ids: Vec<String>,
    linked: Option<Vec<Opt>>,
) -> Result<Widget> {
    let listable = rel.permits(engine, target, Operation::List).await;
    let as_options = |page: &crate::crud::engine::Page| -> Vec<Opt> {
        page.data
            .iter()
            .map(|it| {
                let value = super::render::text(Some(&it.id));
                Opt { selected: ids.contains(&value), label: it.label.clone(), value }
            })
            .collect()
    };
    let query = |all: bool| match all {
        // Every row: a posted multi-select *replaces* the relation set, so a linked row the
        // list left out would be unlinked by saving. (`per_page: 0` is the backend's
        // default page, not "no limit".)
        true => ListQuery { all: true, ..Default::default() },
        false => ListQuery { per_page: rel.threshold.max(1), ..Default::default() },
    };
    let select = |options: Vec<Opt>| match many {
        true => Widget::Multi { options },
        false => Widget::Select { options, blank: true },
    };
    // One capped listing answers "is it small?" — `total` counts past the cap.
    let probe = if listable { Some(engine.list(target, &query(false), true).await?) } else { None };
    let picker = engine.picker_path();
    match (&probe, picker) {
        (Some(page), _) if page.total <= rel.threshold => Ok(select(as_options(page))),
        // No picker to open: the whole list, however long. A page that errored once its
        // table grew past a number would be worse than a long menu.
        (Some(_), None) => Ok(select(as_options(&engine.list(target, &query(true), true).await?))),
        (Some(page), Some(path)) => Ok(Widget::Picked {
            chosen: chosen_options(engine, target, &ids, linked, true).await?,
            many,
            src: super::picker::pick_href(path, rel.slug, relation, None),
            note: format!("{} {target} rows — too many to list here.", page.total),
        }),
        // The caller may not list the target: what this row already links to (the row's
        // own read shows those labels anyway), and no way to browse for more.
        (None, _) => Ok(Widget::Picked {
            chosen: chosen_options(engine, target, &ids, linked, false).await?,
            many,
            src: String::new(),
            note: String::new(),
        }),
    }
}

/// Where a relation field's "+" opens, or empty for none. Offered only when the relation turned it
/// on (`MetaRelation::create`, `explicit`) or else the app did (`Crud::picker_create`), and the
/// caller may both **create** the target and **list** it — the page that reports the new row
/// shows its label, which is a read. Each nested form asks again for
/// its own relations, so how deep the dialogs go is the gates' answer (and the script's cap).
pub(crate) async fn create_src(
    engine: &Engine,
    rel: &Relations<'_>,
    relation: &str,
    target: &str,
    explicit: Option<bool>,
) -> String {
    let Some(path) = engine.picker_create_path(target, explicit) else { return String::new() };
    let allowed = rel.permits(engine, target, Operation::Create).await
        && rel.permits(engine, target, Operation::List).await;
    if !allowed {
        return String::new();
    }
    super::picker::pick_href(path, rel.slug, relation, Some(("new", "1")))
}

/// The `{id, label}` pairs an edited row embeds for a relation.
fn linked_options(name: &str, row: Option<&Value>) -> Vec<Opt> {
    let items: Vec<&Value> = match row.and_then(|r| r.get(name)) {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(Value::Null) | None => Vec::new(),
        Some(one) => vec![one],
    };
    items
        .into_iter()
        .map(|it| Opt {
            value: super::render::text(it.get("id")),
            label: super::render::text(it.get("label")),
            selected: true,
        })
        .collect()
}

/// The current selection of a relation the form doesn't list, with labels: `linked` when the caller
/// already has them (the row being edited), else looked up for `ids` (a rejected save, or an app's
/// own form). Not looked up when the caller may not list the target (`listable` false): the ids
/// someone posted are no reason to tell them what those rows are called, so they show as ids.
async fn chosen_options(
    engine: &Engine,
    target: &str,
    ids: &[String],
    linked: Option<Vec<Opt>>,
    listable: bool,
) -> Result<Vec<Opt>> {
    if let Some(linked) = linked {
        return Ok(linked);
    }
    let opt = |value: String, label: String| Opt { value, label, selected: true };
    if ids.is_empty() || !listable {
        return Ok(ids.iter().map(|id| opt(id.clone(), id.clone())).collect());
    }
    let q = ListQuery { pk_in: ids.to_vec(), all: true, ..Default::default() };
    let found = match engine.list(target, &q, true).await {
        Ok(page) => page.data,
        // An id that can't be a key of the target (text for an integer key): the write check
        // reports it beside the field; here it just shows as typed.
        Err(crate::crud::engine::Error::BadRequest(_)) => Vec::new(),
        Err(e) => return Err(e),
    };
    Ok(ids
        .iter()
        .map(|id| {
            let label = found
                .iter()
                .find(|it| super::render::text(Some(&it.id)) == *id)
                .map(|it| it.label.clone())
                .unwrap_or_else(|| id.clone());
            opt(id.clone(), label)
        })
        .collect())
}

/// A closed option set of `col`'s, with the current value marked and each shown by its label.
fn choices(col: &Column, options: &[String], value: &str) -> Vec<Opt> {
    options
        .iter()
        .map(|o| Opt {
            value: o.clone(),
            label: super::render::option_label(col, o).to_string(),
            selected: o == value,
        })
        .collect()
}

/// The value for a scalar input: rejected input → the edited row → the form's initial value → the
/// column's create-default → empty.
fn field_value(col: &Column, row: Option<&Value>, state: &ViewState, tz: &Tz, presets: &Presets<'_>) -> String {
    let name = super::render::name_of(col);
    if let Some(posted) = state.posted(name) {
        return posted.first().cloned().unwrap_or_default();
    }
    let datetime = matches!(col, Column::Field { display: Some(d), .. } if d.is_datetime());
    if let Some(row) = row {
        let raw = row.get(name);
        return match (datetime, raw.and_then(Value::as_i64)) {
            (true, Some(secs)) => tz.format_input(secs),
            (true, None) => String::new(),
            _ => super::render::text(raw),
        };
    }
    // Creating: the form's initial value, then `MetaField::default`. Both pre-fill the *input*
    // (neither is applied server-side), which is why a required column still has to be rendered
    // for its value to be sent.
    if let Some(v) = presets.initial_of(name) {
        return match (datetime, v.as_i64()) {
            (true, Some(secs)) => tz.format_input(secs),
            (true, None) => String::new(),
            _ => super::render::text(Some(v)),
        };
    }
    match col {
        Column::Field { default: Some(d), .. } if datetime => {
            d.as_i64().map(|s| tz.format_input(s)).unwrap_or_default()
        }
        Column::Field { default: Some(d), .. } => super::render::text(Some(d)),
        _ => String::new(),
    }
}

/// The ids currently chosen for a relation — from rejected input, from the row, or (creating) from
/// the form's initial value: one id, or an array of them for a to-many.
fn relation_values(name: &str, row: Option<&Value>, state: &ViewState, presets: &Presets<'_>) -> Vec<String> {
    if let Some(posted) = state.posted(name) {
        return posted.iter().filter(|v| !v.is_empty()).cloned().collect();
    }
    if row.is_none() {
        return match presets.initial_of(name) {
            Some(Value::Array(ids)) => ids.iter().map(|v| super::render::text(Some(v))).collect(),
            Some(Value::Null) | None => Vec::new(),
            Some(id) => vec![super::render::text(Some(id))],
        };
    }
    let Some(raw) = row.and_then(|r| r.get(name)) else { return Vec::new() };
    match raw {
        Value::Array(items) => {
            items.iter().map(|i| super::render::text(i.get("id"))).collect()
        }
        Value::Null => Vec::new(),
        one => vec![super::render::text(one.get("id"))],
    }
}
