//! One `match` from [`Column`] to a form input — the Rust replacement for `widgetOf(c)` and the
//! eleven mutually-exclusive `<template x-if>` branches it drove.
//!
//! Picking the input is the easy half. The half worth doing in Rust is **the value**: what goes in the
//! input is the operator's own rejected input if there was one, else the row being edited, else the
//! column's create-default, else nothing — an ordering that was previously spread across
//! `blankForm()`, `fromRow()`, and a `422` handler that reassembled it from a JSON error body.

use super::state::ViewState;
use crate::crud::engine::{Cardinality, Column, Engine, FieldDisplay, LogicalType, Result};
use crate::time::Tz;
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
    /// A to-one relation whose target has more rows than `picker_threshold`: the id, typed. The
    /// alternative — shipping thousands of `<option>`s, or a search box that needs a fetch endpoint —
    /// is what this deliberately doesn't do. `count` is how many rows there are, so the label can say.
    Reference { value: String, current: String, target: String, count: u64 },
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
    threshold: u64,
) -> Result<Vec<FieldV>> {
    let mut out = Vec::new();
    for col in cols.iter().filter(|c| writable(c) && rendered(super::render::name_of(c))) {
        let name = super::render::name_of(col).to_string();
        out.push(FieldV {
            widget: widget(engine, col, row, state, tz, threshold).await?,
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
    threshold: u64,
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
            // One terse listing of the target, capped: `total` then says whether a picker would have
            // been a wall of options.
            let q = crate::crud::engine::ListQuery {
                per_page: threshold.max(1),
                ..Default::default()
            };
            let page = engine.list(target, &q, true).await?;
            let chosen = relation_values(name, row, state);
            let opts = |page: &crate::crud::engine::Page| -> Vec<Opt> {
                page.data
                    .iter()
                    .map(|it| {
                        let value = super::render::text(Some(&it.id));
                        Opt { selected: chosen.contains(&value), label: it.label.clone(), value }
                    })
                    .collect()
            };
            match cardinality {
                Cardinality::ToMany => Ok(Widget::Multi { options: opts(&page) }),
                Cardinality::ToOne if page.total > threshold => Ok(Widget::Reference {
                    value: chosen.first().cloned().unwrap_or_default(),
                    current: current_label(name, row),
                    target: target.clone(),
                    count: page.total,
                }),
                Cardinality::ToOne => {
                    Ok(Widget::Select { options: opts(&page), blank: true })
                }
            }
        }
    }
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

fn current_label(name: &str, row: Option<&Value>) -> String {
    super::render::text(row.and_then(|r| r.get(name)).and_then(|v| v.get("label")))
}
