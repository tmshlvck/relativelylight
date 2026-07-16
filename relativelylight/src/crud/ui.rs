//! `relativelylight::crud::ui` — server-rendered admin components (Bootstrap 5 + Alpine.js fragments).
//!
//! `Table` renders a table for one entity: read-only, or read-write with a Create button, per-row
//! Edit/Delete, and a modal create/update form (validation errors shown inline). `Admin` composes
//! many `Table`s plus a side-panel into one page: pick a model to view/edit, with configurable
//! ordering, group headings, separators, and custom links. Both are **fragments** — the app owns
//! the shell (chrome + Bootstrap/Alpine tags); data + writes go through the JSON API.

use crate::crud::engine::{Engine, Error, Result};
use askama::Template;
use serde_json::Value;

#[derive(Template)]
#[template(path = "table.html")]
struct TableTemplate {
    id: String, // unique per instance (the slug) — namespaces the Alpine component on shared pages
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
            id: self.slug.clone(),
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

// ===================== Admin =====================

/// One side-panel entry, flattened for the template (`kind` selects how it renders).
struct AdminNav {
    kind: &'static str, // "entity" | "group" | "separator" | "link"
    slug: String,
    label: String,
    href: String,
}

/// A rendered entity table, shown when its side-panel entry is active.
struct AdminPanel {
    slug: String,
    html: String,
}

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminTemplate {
    title: String,
    has_title: bool,
    nav: Vec<AdminNav>,
    panels: Vec<AdminPanel>,
    first: String,
}

enum AdminItem<'a> {
    Entity(Table<'a>),
    Group(String),
    Separator,
    Link { label: String, href: String },
}

/// An admin fragment: a side-panel listing models (plus optional group headings, separators, and
/// custom links) next to the selected model's `Table`. Include it in an app-provided shell that
/// loads Bootstrap 5 + Alpine.js. Switching models is client-side (no reload).
///
/// ```ignore
/// let html = relativelylight::crud::ui::Admin::new(&engine)
///     .title("Admin")
///     .group("Content")
///     .entity_with("post", |t| t.per_page(10))
///     .entity("tag")
///     .separator()
///     .group("People")
///     .entity_with("user", |t| t.read_only(true))
///     .link("API docs", "/docs")
///     .render()?;
/// ```
pub struct Admin<'a> {
    engine: &'a Engine,
    title: Option<String>,
    items: Vec<AdminItem<'a>>,
}

impl<'a> Admin<'a> {
    pub fn new(engine: &'a Engine) -> Self {
        Self { engine, title: None, items: Vec::new() }
    }

    /// Heading shown above the side-panel.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Append every registered entity (default `Table` config), in engine order.
    pub fn entities(mut self) -> Self {
        for slug in self.engine.tables() {
            self.items.push(AdminItem::Entity(Table::new(self.engine, slug)));
        }
        self
    }

    /// Append one entity with default `Table` config.
    pub fn entity(self, slug: impl Into<String>) -> Self {
        self.entity_with(slug, |t| t)
    }

    /// Append one entity, configuring its `Table` (read-only, per_page, formatters, …).
    pub fn entity_with(
        mut self,
        slug: impl Into<String>,
        config: impl FnOnce(Table<'a>) -> Table<'a>,
    ) -> Self {
        let table = config(Table::new(self.engine, slug));
        self.items.push(AdminItem::Entity(table));
        self
    }

    /// A group heading in the side-panel.
    pub fn group(mut self, name: impl Into<String>) -> Self {
        self.items.push(AdminItem::Group(name.into()));
        self
    }

    /// A horizontal separator (`<hr>`) in the side-panel.
    pub fn separator(mut self) -> Self {
        self.items.push(AdminItem::Separator);
        self
    }

    /// A custom static link in the side-panel (navigates normally).
    pub fn link(mut self, label: impl Into<String>, href: impl Into<String>) -> Self {
        self.items.push(AdminItem::Link { label: label.into(), href: href.into() });
        self
    }

    /// Render the admin fragment. Errors if a referenced entity isn't registered.
    pub fn render(&self) -> Result<String> {
        let mut nav = Vec::new();
        let mut panels = Vec::new();
        let mut first = String::new();
        for item in &self.items {
            match item {
                AdminItem::Entity(table) => {
                    let slug = table.slug.clone();
                    let label = table.title.clone().unwrap_or_else(|| slug.clone());
                    if first.is_empty() {
                        first = slug.clone();
                    }
                    panels.push(AdminPanel { slug: slug.clone(), html: table.render()? });
                    nav.push(AdminNav { kind: "entity", slug, label, href: String::new() });
                }
                AdminItem::Group(name) => nav.push(AdminNav {
                    kind: "group",
                    slug: String::new(),
                    label: name.clone(),
                    href: String::new(),
                }),
                AdminItem::Separator => nav.push(AdminNav {
                    kind: "separator",
                    slug: String::new(),
                    label: String::new(),
                    href: String::new(),
                }),
                AdminItem::Link { label, href } => nav.push(AdminNav {
                    kind: "link",
                    slug: String::new(),
                    label: label.clone(),
                    href: href.clone(),
                }),
            }
        }
        AdminTemplate {
            has_title: self.title.is_some(),
            title: self.title.clone().unwrap_or_default(),
            nav,
            panels,
            first,
        }
        .render()
        .map_err(|e| Error::Backend(e.to_string()))
    }
}
