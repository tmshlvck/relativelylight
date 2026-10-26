//! One `match` from [`Column`] to a form input — the Rust replacement for `widgetOf(c)` and the
//! eleven mutually-exclusive `<template x-if>` branches it drove.
//!
//! Picking the input is the easy half. The half worth doing in Rust is **the value**: what goes in the
//! input is the operator's own rejected input if there was one, else the row being edited, else the
//! column's create-default, else nothing — an ordering that was previously spread across
//! `blankForm()`, `fromRow()`, and a `422` handler that reassembled it from a JSON error body.

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
}

/// Build the form's fields for one entity.
///
/// `row` is the record being edited (`None` when creating). `rendered` decides which columns the form
/// shows — the same predicate the decoder uses, so a column that isn't rendered is also not accepted
/// from a posted body.
pub(crate) async fn fields(
    engine: &Engine,
    cols: &[Column],
    rendered: &(dyn Fn(&str) -> bool + Send + Sync),
    row: Option<&Value>,
    state: &ViewState,
    tz: &Tz,
    rel: &Relations<'_>,
) -> Result<Vec<FieldV>> {
    let mut out = Vec::new();
    for col in cols.iter().filter(|c| writable(c) && rendered(super::render::name_of(c))) {
        let name = super::render::name_of(col).to_string();
        out.push(FieldV {
            widget: widget(engine, col, row, state, tz, rel).await?,
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

async fn widget(
    engine: &Engine,
    col: &Column,
    row: Option<&Value>,
    state: &ViewState,
    tz: &Tz,
    rel: &Relations<'_>,
) -> Result<Widget> {
    let name = super::render::name_of(col);
    match col {
        Column::Field { logical_type, options, display, nullable, required, write_only, .. } => {
            let value = field_value(col, row, state, tz);
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
                    options: choices(options, &value),
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
                    options: choices(options, &value),
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
            let linked = match state.posted(name) {
                Some(_) => None,
                None => Some(linked_options(name, row)),
            };
            let many = *cardinality == Cardinality::ToMany;
            relation(engine, rel, name, target, many, relation_values(name, row, state), linked).await
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
    let listable = engine.permits(target, Operation::List, rel.headers).await;
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
            src: format!("{path}?pick={}.{relation}", rel.slug),
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

/// A closed option set, with the current value marked.
fn choices(options: &[String], value: &str) -> Vec<Opt> {
    options
        .iter()
        .map(|o| Opt { value: o.clone(), label: o.clone(), selected: o == value })
        .collect()
}

/// The value for a scalar input: rejected input → the edited row → the column's create-default → empty.
fn field_value(col: &Column, row: Option<&Value>, state: &ViewState, tz: &Tz) -> String {
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
    // Creating: `MetaField::default` pre-fills the *input* (it is a form default, never applied
    // server-side), which is why a required column still has to be rendered for its value to be sent.
    match col {
        Column::Field { default: Some(d), .. } if datetime => {
            d.as_i64().map(|s| tz.format_input(s)).unwrap_or_default()
        }
        Column::Field { default: Some(d), .. } => super::render::text(Some(d)),
        _ => String::new(),
    }
}

/// The ids currently chosen for a relation — from rejected input, or from the row.
fn relation_values(name: &str, row: Option<&Value>, state: &ViewState) -> Vec<String> {
    if let Some(posted) = state.posted(name) {
        return posted.iter().filter(|v| !v.is_empty()).cloned().collect();
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
