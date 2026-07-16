//! `autocrud::alpine` — server-rendered admin components (Bootstrap 5 + Alpine.js fragments).
//!
//! `Table` renders a table for one entity: read-only, or read-write with a Create button, per-row
//! Edit/Delete, and a modal create/update form (validation errors shown inline). The shape is read
//! from the `Engine` in-process and embedded; data + writes go through the JSON API. The app shell
//! must have loaded Bootstrap 5 and Alpine.js (PRD §2.1).

use crate::engine::{Engine, Error, Result};
use askama::Template;
use serde_json::Value;

#[derive(Template)]
#[template(path = "table.html")]
struct TableTemplate {
    title: String,
    data_url: String,
    columns_json: String,
    search: bool,
    pagination: bool,
    per_page: u64,
    editable: bool,
    confirm: bool,
    picker_threshold: u64,
    formatters: String, // JS object literal: { "col": (value, row) => htmlString, … }
}

/// A table for one registered entity, rendered as an HTML fragment for the app shell.
pub struct Table<'a> {
    engine: &'a Engine,
    slug: String,
    title: Option<String>,
    search: bool,
    pagination: bool,
    per_page: u64,
    read_only: bool,
    confirm: bool,
    picker_threshold: u64,
    formatters: Vec<(String, String)>,
}

impl<'a> Table<'a> {
    pub fn new(engine: &'a Engine, slug: impl Into<String>) -> Self {
        Self {
            engine,
            slug: slug.into(),
            title: None,
            search: true,
            pagination: true,
            per_page: 30,
            read_only: false,
            confirm: true,
            picker_threshold: 20,
            formatters: Vec::new(),
        }
    }

    /// Display label for the entity (table heading + form header). Default: the slug.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
    pub fn search(mut self, on: bool) -> Self {
        self.search = on;
        self
    }
    pub fn pagination(mut self, on: bool) -> Self {
        self.pagination = on;
        self
    }
    pub fn per_page(mut self, n: u64) -> Self {
        self.per_page = n;
        self
    }
    /// Read-only table: no Create/Edit/Delete, no form. Default: false (read-write).
    pub fn read_only(mut self, on: bool) -> Self {
        self.read_only = on;
        self
    }
    /// Ask for confirmation before delete. Default: true.
    pub fn confirm(mut self, on: bool) -> Self {
        self.confirm = on;
        self
    }
    /// Relation form widget cutover: targets with more rows than this use a live search→select
    /// combobox instead of a plain `<select>`. Default: 20.
    pub fn picker_threshold(mut self, n: u64) -> Self {
        self.picker_threshold = n;
        self
    }

    /// Custom cell renderer for a column, as a JS arrow function `(value, row) => htmlString`
    /// (the returned HTML is inserted verbatim, so escape any untrusted content yourself). Overrides
    /// the default rendering for that column — e.g. turn a name into a link:
    /// `.format("name", "(v, row) => `<a href=\"/things/${row.id}\">${v}</a>`")`.
    pub fn format(mut self, column: impl Into<String>, js: impl Into<String>) -> Self {
        self.formatters.push((column.into(), js.into()));
        self
    }

    /// Render the table fragment. Errors if the entity isn't registered.
    pub fn render(&self) -> Result<String> {
        let desc = self.engine.meta_one(&self.slug)?;
        let columns_json = desc
            .get("columns")
            .cloned()
            .unwrap_or(Value::Array(vec![]))
            .to_string();
        // Build a JS object literal { "col": (value,row)=>…, … } from the configured formatters.
        let entries: Vec<String> = self
            .formatters
            .iter()
            .map(|(col, js)| format!("{}: ({})", Value::String(col.clone()), js))
            .collect();
        let formatters = format!("{{{}}}", entries.join(", "));
        let tmpl = TableTemplate {
            data_url: self.engine.entity_url(&self.slug),
            title: self.title.clone().unwrap_or_else(|| self.slug.clone()),
            columns_json,
            search: self.search,
            pagination: self.pagination,
            per_page: self.per_page,
            editable: !self.read_only,
            confirm: self.confirm,
            picker_threshold: self.picker_threshold,
            formatters,
        };
        tmpl.render().map_err(|e| Error::Backend(e.to_string()))
    }
}
