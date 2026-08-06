//! `relativelylight::crud::ui` — server-rendered UI components (Bootstrap 5 + Alpine.js fragments).
//!
//! Two building blocks and one composition of them:
//!
//! - [`Form`] — a create/edit form for one entity, standalone. For an app's own pages (a signup form,
//!   a "new ticket" screen) where the admin's shape is wrong.
//! - [`Table`] — a table for one entity: read-only, or read-write with a Create button, per-row
//!   Edit/Delete, and the same form in a modal (validation errors inline).
//! - [`Admin`] — many `Table`s plus a side-panel: pick a model to view/edit, with configurable
//!   ordering, group headings, separators, and custom links.
//!
//! `Form` and `Table`'s modal are **one implementation**: the field widgets live in the
//! `_form_fields.html` partial and the behaviour (payload shaping, `422` mapping, CSRF header,
//! relation pickers, datetime conversion) in `_form_core.html`, which both hosts include. The hosts
//! differ only in chrome and in what happens after a save. So a widget or a fix lands in both, and
//! `Admin` remains what it was meant to be — a free composition of the parts, not a separate thing.
//!
//! All three are **fragments**: the app owns the shell (chrome + Bootstrap/Alpine tags); data and
//! writes go through the JSON API.

use crate::authz::{Decision, Operation};
use crate::crud::engine::{Column, Engine, Error, Result};
use askama::Template;
use http::HeaderMap;
use serde_json::Value;

#[derive(Template)]
#[template(path = "table.html")]
struct TableTemplate {
    id: String, // unique per instance (the slug) — namespaces the Alpine component on shared pages
    title: String,
    description: String, // optional subtitle under the heading (empty = none)
    data_url: String,
    columns_json: String,
    search: bool,
    pagination: bool,
    per_page: u64,
    editable: bool,
    confirm: bool,
    picker_threshold: u64,
    formatters: String, // JS object literal: { "col": (value, row) => htmlString, … }
    /// CSRF cookie name to echo in write requests, or empty when the engine doesn't enforce CSRF.
    csrf_cookie: String,
    /// JS array literal of filter controls: `[{name, fixed, shared}]` (`fixed` = a pinned value the
    /// user can't change, else `null`).
    filters_json: String,
    /// JS array literal of the initial sort keys: `[{col, desc}]`.
    sort_json: String,
}

/// A table for one registered entity, rendered as an HTML fragment for the app shell.
#[derive(Clone)]
pub struct Table<'a> {
    engine: &'a Engine,
    slug: String,
    title: Option<String>,
    description: Option<String>,
    search: bool,
    pagination: bool,
    per_page: u64,
    read_only: bool,
    confirm: bool,
    picker_threshold: u64,
    formatters: Vec<(String, String)>,
    filters: Vec<FilterSpec>,
    sort: Vec<(String, bool)>,
}

/// One filter control on a table: a column or relation name, optionally pinned to a value.
#[derive(Clone)]
struct FilterSpec {
    name: String,
    fixed: Option<String>,
    /// Driven by an [`Admin`]-level control shared across tables rather than one of this table's own.
    shared: bool,
}

impl<'a> Table<'a> {
    pub fn new(engine: &'a Engine, slug: impl Into<String>) -> Self {
        Self {
            engine,
            slug: slug.into(),
            title: None,
            description: None,
            search: true,
            pagination: true,
            per_page: 30,
            read_only: false,
            confirm: true,
            picker_threshold: 20,
            formatters: Vec::new(),
            filters: Vec::new(),
            sort: Vec::new(),
        }
    }

    /// Display label for the entity (table heading + form header). Default: the slug.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
    /// An optional description shown as a muted subtitle under the table heading — a good place to
    /// explain what the entity is and when to use it.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
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

    /// Initial sort: ascending by `column`. A relation sorts by the label its cells show — provided
    /// the target declares which column that is (see
    /// [`MetaModel::label_column`](crate::crud::seaorm::MetaModel::label_column)); a column the API
    /// won't sort by is a render-time error naming it. Call repeatedly for secondary keys.
    pub fn sort(mut self, column: impl Into<String>) -> Self {
        self.sort.push((column.into(), false));
        self
    }
    /// Initial sort: descending by `column`. See [`sort`](Table::sort).
    pub fn sort_desc(mut self, column: impl Into<String>) -> Self {
        self.sort.push((column.into(), true));
        self
    }

    /// A filter control in the toolbar, narrowing the table to rows whose `name` equals the chosen
    /// value. `name` is a column or a to-one relation — `filter("zone")` on a records table gives a
    /// zone picker, reusing the same widget the form's relation field uses (a `<select>`, or a live
    /// search box once the target outgrows [`picker_threshold`](Table::picker_threshold)).
    ///
    /// The choice applies to the listing, the CSV export and "delete all matching" alike, so the
    /// buttons can't act on a wider set than the one on screen, and it shows as a chip above the table
    /// — a filtered table that looked unfiltered is how someone concludes their rows were deleted.
    pub fn filter(mut self, name: impl Into<String>) -> Self {
        self.filters.push(FilterSpec { name: name.into(), fixed: None, shared: false });
        self
    }

    /// A filter pinned to one value and not offered as a control — a table that is *about* one zone,
    /// e.g. on a `/zone/{id}/records` page.
    ///
    /// This narrows a **view**, it is not an authorization boundary: the API is still queryable for
    /// other values by anyone the model's gate admits. Scoping who may see what is
    /// [`authz`](crate::authz)'s job.
    pub fn fixed_filter(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.filters.push(FilterSpec {
            name: name.into(),
            fixed: Some(value.into()),
            shared: false,
        });
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

    /// Render the table fragment, showing write controls unless the table is `read_only`. Use this
    /// for open/pre-rendered pages; for per-request gating use [`render_for`](Table::render_for).
    /// Errors if the entity isn't registered.
    pub fn render(&self) -> Result<String> {
        self.render_inner(!self.read_only)
    }

    /// Render the table fragment for a specific request: the Create/Edit/Delete controls are shown
    /// only if the table is writable *and* the model's gate permits a write for this caller. Read
    /// access is unaffected (the API still enforces it). Errors if the entity isn't registered.
    pub async fn render_for(&self, headers: &HeaderMap) -> Result<String> {
        let editable = !self.read_only
            && self.engine.permits(&self.slug, Operation::Create, headers).await;
        self.render_inner(editable)
    }

    fn render_inner(&self, editable: bool) -> Result<String> {
        let cols = self.engine.columns(&self.slug)?;
        check_widgets(&self.slug, &cols)?;
        check_sort(&self.slug, &cols, &self.sort)?;
        let filters = self.applicable_filters(&cols)?;
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
            description: self.description.clone().unwrap_or_default(),
            columns_json,
            search: self.search,
            pagination: self.pagination,
            per_page: self.per_page,
            editable,
            confirm: self.confirm,
            picker_threshold: self.picker_threshold,
            formatters,
            csrf_cookie: self.engine.csrf_cookie_name().unwrap_or_default().to_string(),
            filters_json: Value::Array(
                filters
                    .iter()
                    .map(|f| {
                        serde_json::json!({
                            "name": f.name,
                            "fixed": f.fixed,
                            "shared": f.shared,
                        })
                    })
                    .collect(),
            )
            .to_string(),
            sort_json: Value::Array(
                self.sort
                    .iter()
                    .map(|(c, d)| serde_json::json!({ "col": c, "desc": d }))
                    .collect(),
            )
            .to_string(),
        };
        tmpl.render().map_err(|e| Error::Backend(e.to_string()))
    }

    /// The filters this table will actually render.
    ///
    /// A filter named directly is an error if the entity has no such column or relation — a silently
    /// dropped control would leave the operator filtering nothing and not knowing it. A **shared**
    /// filter is different: [`Admin`] offers one control to every table it lists, and most of them
    /// legitimately have no such column, so those are skipped rather than refused.
    fn applicable_filters(&self, cols: &[Column]) -> Result<Vec<FilterSpec>> {
        let mut out = Vec::new();
        for f in &self.filters {
            let known = cols.iter().any(|c| match c {
                Column::Field { name, .. } => *name == f.name,
                Column::Relation { name, fk_column, .. } => *name == f.name && fk_column.is_some(),
            });
            if known {
                out.push(f.clone());
            } else if !f.shared {
                return Err(Error::BadRequest(format!(
                    "crud::ui({}): cannot filter by '{}': no such column or to-one relation",
                    self.slug, f.name
                )));
            }
        }
        Ok(out)
    }
}

/// Refuse a widget that can't render its column, naming the field — a `Radio` with no `options`, a
/// `Range` on text, a `Textarea` on a number. Checked by **both** hosts at render time, because the
/// alternative is a form quietly showing a different input than the model asked for, which is the sort of
/// thing that's noticed in production and not in review. See [`FieldDisplay::fits`].
/// Refuse an initial sort the API would reject, naming the column — same reasoning as
/// [`check_widgets`]: a table that silently ignored `.sort("zone")` would look like it worked.
fn check_sort(slug: &str, cols: &[Column], sort: &[(String, bool)]) -> Result<()> {
    for (want, _) in sort {
        let found = cols.iter().find(|c| match c {
            Column::Field { name, .. } | Column::Relation { name, .. } => name == want,
        });
        let ok = match found {
            Some(Column::Field { sortable, .. }) | Some(Column::Relation { sortable, .. }) => {
                *sortable
            }
            None => {
                return Err(Error::BadRequest(format!(
                    "crud::ui({slug}): cannot sort by '{want}': no such column or relation"
                )))
            }
        };
        if !ok {
            return Err(Error::BadRequest(format!(
                "crud::ui({slug}): column '{want}' is not sortable"
            )));
        }
    }
    Ok(())
}

fn check_widgets(slug: &str, cols: &[Column]) -> Result<()> {
    for c in cols {
        if let Column::Field { name, logical_type, options, display: Some(d), .. } = c {
            if let Err(why) = d.fits(*logical_type, !options.is_empty()) {
                return Err(Error::BadRequest(format!("crud::ui({slug}): field '{name}': {why}")));
            }
        }
    }
    Ok(())
}

// ===================== Form =====================

#[derive(Template)]
#[template(path = "form.html")]
struct FormTemplate {
    id: String, // unique per instance — namespaces the Alpine component on shared pages
    title: String,
    description: String,
    has_heading: bool,
    has_description: bool,
    data_url: String,
    columns_json: String,
    picker_threshold: u64,
    /// CSRF cookie name to echo in write requests, or empty when the engine doesn't enforce CSRF.
    csrf_cookie: String,
    mode: &'static str, // "create" | "edit"
    edit_id_js: String, // JS literal: a quoted id, or `null` on create
    only_json: String,
    omit_json: String,
    on_saved_js: String, // JS literal: an arrow function, or `null`
    redirect_js: String, // JS literal: a quoted URL, or `null`
    submit_label: String,
    saved_message_js: String, // JS literal: a quoted message
    has_cancel: bool,
    cancel_href: String,
}

/// A standalone create/edit form for one registered entity, rendered as an HTML fragment — the same
/// form [`Table`] shows in its modal, without the table.
///
/// This is the building block for an app's **own** pages, where [`Admin`] is the wrong shape: a
/// signup form, a "new ticket" page, a settings screen. It reads the entity's published metadata, so
/// the widgets, the required markers, the enum dropdowns, the relation pickers, the datetime handling
/// and the `422` field-error mapping all come for free and stay in step with the model.
///
/// ```ignore
/// // Create: only these fields, in this order, then go to the new row's page.
/// let html = Form::new(&engine, "ticket")
///     .title("New ticket")
///     .fields(["subject", "body", "priority", "assignee"])
///     .submit_label("Open ticket")
///     .redirect("/tickets/{id}")
///     .render_for(&headers).await?;      // 401/403 if the gate says no
///
/// // Edit an existing row:
/// let html = Form::new(&engine, "ticket").edit(id).omit(["assignee"]).render()?;
/// ```
///
/// **It talks to the JSON API**, like `Table`: the entity's routes must be mounted, and the page must
/// load Bootstrap 5 + Alpine (plus [`time::JS`](crate::time::JS) if any column is a datetime). When
/// the engine enforces CSRF the form echoes the cookie automatically — but the cookie has to exist, so
/// issue it when rendering the page (`Csrf::ensure`, as `auth`'s own pages do).
pub struct Form<'a> {
    engine: &'a Engine,
    slug: String,
    dom_id: Option<String>,
    title: Option<String>,
    description: Option<String>,
    heading: Option<bool>,
    edit_id: Option<String>,
    only: Vec<String>,
    omit: Vec<String>,
    submit_label: Option<String>,
    saved_message: Option<String>,
    cancel_href: Option<String>,
    on_saved: Option<String>,
    redirect: Option<String>,
    picker_threshold: u64,
}

impl<'a> Form<'a> {
    /// A form that **creates** a row of `slug`. Add [`edit`](Form::edit) to load and update one.
    pub fn new(engine: &'a Engine, slug: impl Into<String>) -> Self {
        Self {
            engine,
            slug: slug.into(),
            dom_id: None,
            title: None,
            description: None,
            heading: None,
            edit_id: None,
            only: Vec::new(),
            omit: Vec::new(),
            submit_label: None,
            saved_message: None,
            cancel_href: None,
            on_saved: None,
            redirect: None,
            picker_threshold: 20,
        }
    }

    /// Edit this existing row: the form fetches it on load and saves with `PATCH`. Without this the
    /// form creates (`POST`).
    pub fn edit(mut self, id: impl Into<String>) -> Self {
        self.edit_id = Some(id.into());
        self
    }

    /// Heading shown in the card header. Setting a title (or a description) shows the header; without
    /// either there is none, since an app page usually has its own heading already.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
    /// A muted line under the title — what this form is for.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
    /// Force the card header on or off, overriding the "on if titled" default.
    pub fn heading(mut self, on: bool) -> Self {
        self.heading = Some(on);
        self
    }

    /// Render **only** these columns, in this order. Without it the form shows every writable column,
    /// which is the admin's default and rarely what a user-facing form wants. Rendering errors on an
    /// unknown or read-only name, and (when creating) on omitting a column the engine requires.
    pub fn fields<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.only = names.into_iter().map(Into::into).collect();
        self
    }

    /// Drop these columns from the form, keeping the rest (the complement of
    /// [`fields`](Form::fields); applied after it if both are given).
    pub fn omit<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.omit = names.into_iter().map(Into::into).collect();
        self
    }

    /// Text on the submit button. Default: `Save`.
    pub fn submit_label(mut self, label: impl Into<String>) -> Self {
        self.submit_label = Some(label.into());
        self
    }

    /// The confirmation shown after a successful save when there's no [`redirect`](Form::redirect) or
    /// [`on_saved`](Form::on_saved). Default: `Saved.`
    pub fn saved_message(mut self, msg: impl Into<String>) -> Self {
        self.saved_message = Some(msg.into());
        self
    }

    /// Show a Cancel link to this URL. Without it there's no Cancel button (a page usually has its
    /// own way back).
    pub fn cancel(mut self, href: impl Into<String>) -> Self {
        self.cancel_href = Some(href.into());
        self
    }

    /// Go here after a successful save. `{id}` is replaced with the saved row's id (URL-encoded), so
    /// `"/tickets/{id}"` lands on the new row. Takes precedence over [`on_saved`](Form::on_saved).
    pub fn redirect(mut self, url: impl Into<String>) -> Self {
        self.redirect = Some(url.into());
        self
    }

    /// Run this JS after a successful save instead of showing the message — an arrow function
    /// `(row) => { … }` receiving the saved row (`null` if the API returned no body). Inserted into a
    /// `<script>` verbatim, so it's your code, not user input.
    pub fn on_saved(mut self, js: impl Into<String>) -> Self {
        self.on_saved = Some(js.into());
        self
    }

    /// Relation widget cutover: targets with more rows than this use a live search→select combobox
    /// instead of a plain `<select>`. Default: 20.
    pub fn picker_threshold(mut self, n: u64) -> Self {
        self.picker_threshold = n;
        self
    }

    /// Namespaces the form's Alpine component, so two forms for the *same* entity can share a page.
    /// Default: the slug. Must be a valid JS identifier fragment.
    pub fn dom_id(mut self, id: impl Into<String>) -> Self {
        self.dom_id = Some(id.into());
        self
    }

    /// Render the form fragment. Errors if the entity isn't registered, if a named column doesn't
    /// exist or is read-only, or if creating without a column the engine requires.
    pub fn render(&self) -> Result<String> {
        self.render_inner()
    }

    /// Render the form for a specific request, refusing rather than rendering a form the caller could
    /// never submit: `Err(Error::Unauthorized)` (→ `401`) when the gate wants a login, and
    /// `Err(Error::Forbidden)` (→ `403`) when it's simply not permitted. A page handler can turn the
    /// first into a redirect to the login page.
    pub async fn render_for(&self, headers: &HeaderMap) -> Result<String> {
        let op = if self.edit_id.is_some() { Operation::Update } else { Operation::Create };
        match self.engine.decide(&self.slug, op, headers).await {
            Decision::Allow => self.render_inner(),
            Decision::NeedsLogin => Err(Error::Unauthorized),
            Decision::Denied => Err(Error::Forbidden),
        }
    }

    /// Check the configured field list against the model *before* rendering, so a typo or an
    /// unsatisfiable create fails here — with a message naming the column — instead of rendering a
    /// form whose save can only ever `422`.
    fn check_fields(&self) -> Result<()> {
        let cols = self.engine.columns(&self.slug)?;
        check_widgets(&self.slug, &cols)?;
        let mut known: Vec<&str> = Vec::new();
        let mut read_only: Vec<&str> = Vec::new();
        // Writable columns, with whether a create *must* render one. Note a `default` does **not** excuse
        // it: `MetaField::default` is a *create-form* default — the form pre-fills the input with it (and
        // drops the `*` marker), but the engine never applies it server-side, so a required column that
        // isn't rendered simply isn't sent and the create fails with `field: required`.
        let mut writable: Vec<(&str, bool)> = Vec::new();
        for c in &cols {
            match c {
                Column::Field { name, read_only: ro, required, .. } => {
                    known.push(name);
                    if *ro {
                        read_only.push(name);
                    } else {
                        writable.push((name, *required));
                    }
                }
                Column::Relation { name, read_only: ro, .. } => {
                    known.push(name);
                    if *ro {
                        read_only.push(name);
                    } else {
                        writable.push((name, false));
                    }
                }
            }
        }

        for name in self.only.iter().chain(self.omit.iter()) {
            if read_only.contains(&name.as_str()) {
                return Err(Error::BadRequest(format!(
                    "crud::ui::Form({}): column '{name}' is read-only, so a form can't write it",
                    self.slug
                )));
            }
            if !known.contains(&name.as_str()) {
                return Err(Error::BadRequest(format!(
                    "crud::ui::Form({}): no column '{name}' — known columns: {}",
                    self.slug,
                    known.join(", ")
                )));
            }
        }

        // A create must be able to satisfy every required column; an edit needn't, since the row
        // already has values for the fields this form doesn't show.
        if self.edit_id.is_none() {
            let missing: Vec<&str> = writable
                .iter()
                .filter(|(name, must)| *must && !self.renders(name))
                .map(|(name, _)| *name)
                .collect();
            if !missing.is_empty() {
                return Err(Error::BadRequest(format!(
                    "crud::ui::Form({}): creating needs {}, which this form doesn't show — add {} to \
                     .fields(), or use .edit(id). A column `default` doesn't help: it pre-fills the \
                     input, so the field still has to be rendered for the value to be sent",
                    self.slug,
                    missing.join(", "),
                    if missing.len() == 1 { "it" } else { "them" }
                )));
            }
        }
        Ok(())
    }

    /// Whether the rendered form includes this column — mirroring `formCols()` in `_form_core.html`.
    fn renders(&self, name: &str) -> bool {
        let included = self.only.is_empty() || self.only.iter().any(|n| n == name);
        included && !self.omit.iter().any(|n| n == name)
    }

    fn render_inner(&self) -> Result<String> {
        let desc = self.engine.meta_one(&self.slug)?;
        self.check_fields()?;
        let columns_json =
            desc.get("columns").cloned().unwrap_or(Value::Array(vec![])).to_string();
        let js_str = |s: &str| Value::String(s.to_string()).to_string();
        let tmpl = FormTemplate {
            id: self.dom_id.clone().unwrap_or_else(|| self.slug.clone()),
            title: self.title.clone().unwrap_or_else(|| self.slug.clone()),
            description: self.description.clone().unwrap_or_default(),
            has_heading: self
                .heading
                .unwrap_or(self.title.is_some() || self.description.is_some()),
            has_description: self.description.is_some(),
            data_url: self.engine.entity_url(&self.slug),
            columns_json,
            picker_threshold: self.picker_threshold,
            csrf_cookie: self.engine.csrf_cookie_name().unwrap_or_default().to_string(),
            mode: if self.edit_id.is_some() { "edit" } else { "create" },
            edit_id_js: self.edit_id.as_deref().map_or("null".to_string(), &js_str),
            only_json: Value::from(self.only.clone()).to_string(),
            omit_json: Value::from(self.omit.clone()).to_string(),
            on_saved_js: self.on_saved.clone().unwrap_or_else(|| "null".to_string()),
            redirect_js: self.redirect.as_deref().map_or("null".to_string(), &js_str),
            submit_label: self.submit_label.clone().unwrap_or_else(|| "Save".to_string()),
            saved_message_js: js_str(self.saved_message.as_deref().unwrap_or("Saved.")),
            has_cancel: self.cancel_href.is_some(),
            cancel_href: self.cancel_href.clone().unwrap_or_default(),
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
    /// JS array of the shared filter names, for the pre-Alpine restore script. The controls
    /// themselves are rendered by each `Table`.
    filter_names_json: String,
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
    filters: Vec<String>,
}

impl<'a> Admin<'a> {
    pub fn new(engine: &'a Engine) -> Self {
        Self { engine, title: None, items: Vec::new(), filters: Vec::new() }
    }

    /// One filter control in the side-panel, applied to **every** listed table that has a column or
    /// to-one relation of that name; tables without one are unaffected.
    ///
    /// This is the shape that matters when an admin lists many tables of the same shape — fifteen
    /// per-type DNS record tables, say. An operator works inside one zone at a time, so they pick it
    /// once here rather than re-picking it on every table they switch to. The choice is remembered
    /// across visits and travels in the URL fragment, so a filtered admin can be linked to.
    ///
    /// Like [`Table::fixed_filter`], this narrows a **view** and is not an authorization boundary.
    pub fn filter(mut self, name: impl Into<String>) -> Self {
        self.filters.push(name.into());
        self
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

    /// Render the admin fragment, showing each writable table's write controls. Use this for
    /// open/pre-rendered pages; for per-request gating use [`render_for`](Admin::render_for). Errors
    /// if a referenced entity isn't registered.
    pub fn render(&self) -> Result<String> {
        let (nav, first, entities) = self.nav_and_entities();
        let mut panels = Vec::with_capacity(entities.len());
        for table in entities {
            panels.push(AdminPanel { slug: table.slug.clone(), html: table.render()? });
        }
        self.assemble(nav, first, panels)
    }

    /// Render the admin fragment for a specific request: each table hides its Create/Edit/Delete
    /// controls unless the model's gate permits a write for this caller. Errors if a referenced
    /// entity isn't registered.
    pub async fn render_for(&self, headers: &HeaderMap) -> Result<String> {
        let (nav, first, entities) = self.nav_and_entities();
        let mut panels = Vec::with_capacity(entities.len());
        for table in entities {
            panels.push(AdminPanel { slug: table.slug.clone(), html: table.render_for(headers).await? });
        }
        self.assemble(nav, first, panels)
    }

    /// Build the side-panel nav (in item order), the first entity slug, and the entity tables (in
    /// order) — everything except the rendered panel HTML, which the caller renders sync or async.
    fn nav_and_entities(&self) -> (Vec<AdminNav>, String, Vec<Table<'a>>) {
        let mut nav = Vec::new();
        let mut first = String::new();
        let mut entities = Vec::new();
        for item in &self.items {
            match item {
                AdminItem::Entity(table) => {
                    let slug = table.slug.clone();
                    let label = table.title.clone().unwrap_or_else(|| slug.clone());
                    if first.is_empty() {
                        first = slug.clone();
                    }
                    nav.push(AdminNav { kind: "entity", slug, label, href: String::new() });
                    // Offer every shared filter to every table; `applicable_filters` drops the ones
                    // this entity has no column for (most of them, usually) without complaining.
                    let mut table = table.clone();
                    for name in &self.filters {
                        table.filters.push(FilterSpec {
                            name: name.clone(),
                            fixed: None,
                            shared: true,
                        });
                    }
                    entities.push(table);
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
        (nav, first, entities)
    }

    fn assemble(&self, nav: Vec<AdminNav>, first: String, panels: Vec<AdminPanel>) -> Result<String> {
        self.check_filters()?;
        AdminTemplate {
            has_title: self.title.is_some(),
            title: self.title.clone().unwrap_or_default(),
            nav,
            panels,
            first,
            filter_names_json: Value::Array(
                self.filters.iter().cloned().map(Value::String).collect(),
            )
            .to_string(),
        }
        .render()
        .map_err(|e| Error::Backend(e.to_string()))
    }

    /// A shared filter no listed entity has any column for is an error: every table would drop it, so
    /// the admin would render no control at all — which reads as a broken feature rather than a typo.
    fn check_filters(&self) -> Result<()> {
        for name in &self.filters {
            let known = self.items.iter().any(|i| match i {
                AdminItem::Entity(t) => self.engine.columns(&t.slug).is_ok_and(|cols| {
                    cols.iter().any(|c| match c {
                        Column::Field { name: n, .. } => n == name,
                        Column::Relation { name: n, fk_column, .. } => {
                            n == name && fk_column.is_some()
                        }
                    })
                }),
                _ => false,
            });
            if !known {
                return Err(Error::BadRequest(format!(
                    "crud::ui(Admin): cannot filter by '{name}': no listed entity has such a \
                     column or to-one relation"
                )));
            }
        }
        Ok(())
    }
}
