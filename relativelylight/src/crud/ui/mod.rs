//! `relativelylight::crud::ui` — the admin UI, rendered on the server as plain HTML.
//!
//! Three components, one implementation:
//!
//! - [`Table`] — one entity: search, sortable headers, filters, a pager, CSV, bulk delete, and a
//!   create/edit `<dialog>`.
//! - [`Form`] — the same form standalone, for an app's own pages.
//! - [`Admin`] — a side panel over many `Table`s.
//!
//! All three are **fragments**: the app owns `<html>`, the Bootstrap 5 stylesheet, and the layout.
//! There is no JavaScript framework, no JSON in between, and no client-side state — the URL is the
//! state ([`ViewState`]), writes are `POST` → `303` → `GET`, and the dialog is a native
//! `<dialog open>`. Include [`CSS`] once per page for the few rules Bootstrap doesn't cover.
//!
//! # Two handlers per surface
//!
//! Reads stay the app's route, so the app keeps owning its own shell, its own auth redirect and its
//! own error pages. Writes post back to that same URL, and the library does the work:
//!
//! ```ignore
//! use relativelylight::crud::ui::{Admin, Outcome, ViewState};
//!
//! fn panel(engine: &Engine) -> Admin<'_> {          // one definition, used by both handlers
//!     Admin::new(engine).title("Admin").entity("post").entity("tag")
//! }
//!
//! let app = Router::new().route("/admin", get(show).post(save));
//!
//! async fn show(headers: HeaderMap, uri: Uri, State(app): State<Arc<App>>) -> Response {
//!     let state = ViewState::from_uri(&uri);
//!     let frag = panel(&app.engine).render_for(&headers, &state).await?;
//!     Html(my_shell(frag)).into_response()
//! }
//!
//! async fn save(headers: HeaderMap, uri: Uri, RealIp(ip): RealIp, State(app): State<Arc<App>>,
//!               body: String) -> Response {
//!     let state = ViewState::from_uri(&uri);
//!     match panel(&app.engine).submit(&headers, ip, &body, &state).await? {
//!         // Relative, so it lands back on this same page — the library never learns its path.
//!         Outcome::Done(to) => Redirect::to(&to).into_response(),
//!         // Rejected: re-render with the messages and the typed values in place.
//!         Outcome::Invalid(state) => {
//!             let frag = panel(&app.engine).render_for(&headers, &state).await?;
//!             (StatusCode::UNPROCESSABLE_ENTITY, Html(my_shell(frag))).into_response()
//!         }
//!     }
//! }
//! ```

mod decode;
mod render;
mod state;
mod widgets;

pub use state::{Done, Mode, ViewState};

use crate::authz::{Decision, Operation};
use crate::crud::engine::{Column, Engine, Error, ListQuery, Result, ValidationErrors};
use crate::time::Tz;
use askama::Template;
use decode::Posted;
use http::HeaderMap;
use render::{Cell, Chip, HeadV, Pager, RowV};
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;
use widgets::{FieldV, Opt, Widget};

/// The stylesheet the components need beyond Bootstrap 5 (about thirty lines, mostly `<dialog>`).
/// Inline it once in your shell: `<style>{{ relativelylight::crud::ui::CSS }}</style>`.
pub const CSS: &str = include_str!("../../../assets/rl.css");

/// A custom cell renderer: `(value, row) -> HTML`. Its output is inserted **verbatim**, so escape
/// anything that came from the database with [`esc`].
pub type Fmt = Arc<dyn Fn(&Value, &Value) -> String + Send + Sync>;

/// Escape a JSON scalar for inclusion in HTML — what a [`Table::format`] closure wraps its values in.
/// A `String` loses its quotes; anything else prints as JSON.
///
/// ```ignore
/// .format("title", |v, row| format!(r#"<a href="/post/{}">{}</a>"#, esc(&row["id"]), esc(v)))
/// ```
pub fn esc(value: &Value) -> String {
    esc_str(&render::text(Some(value)))
}

/// Escape a string for inclusion in HTML text or a quoted attribute.
pub fn esc_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// What a [`submit`](Table::submit) did.
///
/// (`Invalid` makes this 240 bytes where `Done` needs 24. Boxing it would save a one-per-request
/// stack move and cost every caller a `*state` deref in the match arm they write most often — not a
/// trade worth making for a value returned once per HTTP write.)
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Outcome {
    /// Applied. Redirect to this **relative** URL (`?entity=post&page=2#row-7`), which is the list
    /// the write came from, scrolled to the row that changed.
    Done(String),
    /// Refused by validation. Re-render the surface with this state: the dialog reopens with the
    /// messages beside the fields and the operator's input still in them. Answer `422`.
    Invalid(ViewState),
}

// ===================== Table =====================

#[derive(Template)]
#[template(path = "table.html")]
struct TableTmpl {
    dom_id: String,
    title: String,
    description: String,
    search: bool,
    editable: bool,
    confirm: bool,
    csv: bool,
    q: String,
    csrf: String,
    span: usize,
    keep: Vec<(String, String)>,
    controls: Vec<ControlV>,
    chips: Vec<Chip>,
    heads: Vec<HeadV>,
    rows: Vec<RowV>,
    pager: Pager,
    csv_href: String,
    new_href: String,
    import_href: String,
    dialog: String,
    /// What the write that redirected here did, reported once ("17 records deleted."). Empty
    /// otherwise.
    flash: String,
    /// The same view without the report — where the alert's dismiss link goes.
    flash_dismiss: String,
}

struct ControlV {
    name: String,
    label: String,
    /// The `<select>`'s options — empty when the target has more rows than we will list, in which
    /// case the control is a text input instead.
    options: Vec<Opt>,
    /// The value in force (for the text input), and what it stands for.
    chosen: String,
    chosen_label: String,
    /// How many rows the target has, when that is more than this control can list. `0` otherwise.
    too_many: u64,
}

#[derive(Template)]
#[template(path = "dialog.html")]
struct DialogTmpl {
    op: &'static str,
    id: String,
    csrf: String,
    title: String,
    submit_label: String,
    cancel_href: String,
    errors: Vec<String>,
    fields: Vec<FieldV>,
}

#[derive(Template)]
#[template(path = "import.html")]
struct ImportTmpl {
    title: String,
    csrf: String,
    header: String,
    cancel_href: String,
    errors: Vec<String>,
    /// What was submitted, when an import came back refused — so it can be corrected in place
    /// rather than pasted again.
    csv: String,
}

/// One filter control: a column or relation name, optionally pinned.
#[derive(Clone)]
struct FilterSpec {
    name: String,
    fixed: Option<String>,
    /// Offered by [`Admin::filter`] to every table it lists, rather than by this table itself — so a
    /// table with no such column skips it instead of refusing to render.
    shared: bool,
}

/// A table for one registered entity, rendered as an HTML fragment for the app's shell.
#[derive(Clone)]
pub struct Table<'a> {
    engine: &'a Engine,
    slug: String,
    dom_id: Option<String>,
    title: Option<String>,
    description: Option<String>,
    search: bool,
    pagination: bool,
    per_page: u64,
    read_only: bool,
    confirm: bool,
    picker_threshold: u64,
    fields: Vec<String>,
    omit: Vec<String>,
    columns: Vec<String>,
    formatters: Vec<(String, Fmt)>,
    row_class: Option<RowClass>,
    filters: Vec<FilterSpec>,
    sort: Vec<(String, bool)>,
}

/// A per-row CSS class: `(row) -> class`. See [`Table::row_class`].
pub type RowClass = Arc<dyn Fn(&Value) -> String + Send + Sync>;

impl<'a> Table<'a> {
    pub fn new(engine: &'a Engine, slug: impl Into<String>) -> Self {
        Self {
            engine,
            slug: slug.into(),
            dom_id: None,
            title: None,
            description: None,
            search: true,
            pagination: true,
            per_page: 30,
            read_only: false,
            confirm: true,
            picker_threshold: 20,
            fields: Vec::new(),
            omit: Vec::new(),
            columns: Vec::new(),
            formatters: Vec::new(),
            row_class: None,
            filters: Vec::new(),
            sort: Vec::new(),
        }
    }

    /// Display label for the entity (table heading + dialog header). Default: the slug.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }
    /// A muted subtitle under the heading — what the entity is and when to use it.
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
    /// Read-only table: no Create/Edit/Delete and no dialog. Default: false.
    pub fn read_only(mut self, on: bool) -> Self {
        self.read_only = on;
        self
    }
    /// Ask for confirmation before a delete (an `onsubmit` confirm — the one bit of inline script,
    /// and harmless without it: the POST still asks the server). Default: true.
    pub fn confirm(mut self, on: bool) -> Self {
        self.confirm = on;
        self
    }
    /// How many target rows a to-one relation may list as a `<select>` before the form asks for the
    /// id instead. Default: 20. (There is no search-as-you-type picker: that needs a fetch endpoint,
    /// and this crate no longer has one — see `MPA.md` §6.)
    pub fn picker_threshold(mut self, n: u64) -> Self {
        self.picker_threshold = n;
        self
    }
    /// Show **only** these columns in the **table**, in this order. Default: every published
    /// column, in the model's order.
    ///
    /// This is the table, not the form — a column left out here is still edited in the dialog (use
    /// [`fields`](Table::fields) / [`omit`](Table::omit) for that) and still exported to CSV. It is
    /// for the usual case where a model has twenty columns and a console needs five of them across
    /// the screen. An unknown name is a render-time error naming it.
    pub fn columns<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.columns = names.into_iter().map(Into::into).collect();
        self
    }

    /// A CSS class for each row, from the row itself — how a table says something without a column
    /// saying it:
    ///
    /// ```ignore
    /// .row_class(|row| match row["status"].as_str() {
    ///     Some("overdue") => "table-danger".into(),
    ///     Some("draft") => "text-body-secondary".into(),
    ///     _ => String::new(),
    /// })
    /// ```
    ///
    /// The value lands in the `<tr class>` attribute and is escaped like any other; Bootstrap's
    /// `table-*` contextual classes are the obvious things to reach for.
    pub fn row_class<F>(mut self, class: F) -> Self
    where
        F: Fn(&Value) -> String + Send + Sync + 'static,
    {
        self.row_class = Some(Arc::new(class));
        self
    }

    /// Show **only** these columns in the dialog's form, in this order. Default: every writable
    /// column. Rendering errors on an unknown or read-only name.
    pub fn fields<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.fields = names.into_iter().map(Into::into).collect();
        self
    }
    /// Drop these columns from the dialog's form, keeping the rest.
    pub fn omit<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.omit = names.into_iter().map(Into::into).collect();
        self
    }
    /// Default sort, used until the URL says otherwise: ascending by `column`. A relation sorts by
    /// the label its cells show, provided the target declares which column that is (see
    /// [`MetaModel::label_column`](crate::crud::seaorm::MetaModel::label_column)); a column the
    /// backend won't sort by is a render-time error naming it. Call again for secondary keys.
    pub fn sort(mut self, column: impl Into<String>) -> Self {
        self.sort.push((column.into(), false));
        self
    }
    /// Default sort, descending. See [`sort`](Table::sort).
    pub fn sort_desc(mut self, column: impl Into<String>) -> Self {
        self.sort.push((column.into(), true));
        self
    }
    /// A filter control in the toolbar, narrowing the table to rows whose `name` equals the chosen
    /// value. `name` is a column or a to-one relation — `filter("zone")` gives a zone picker.
    ///
    /// The choice lives in the URL, so it applies to the listing, the CSV export and "delete all
    /// matching" alike: no button acts on a wider set than the one on screen.
    pub fn filter(mut self, name: impl Into<String>) -> Self {
        self.filters.push(FilterSpec { name: name.into(), fixed: None, shared: false });
        self
    }
    /// A filter pinned to one value and offered as no control — a table that is *about* one value,
    /// e.g. on a `/zone/{id}/records` page. It narrows a **view**; it is not an authorization
    /// boundary ([`authz`](crate::authz) is).
    pub fn fixed_filter(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.filters.push(FilterSpec {
            name: name.into(),
            fixed: Some(value.into()),
            shared: false,
        });
        self
    }
    /// Custom cell renderer for a column: `(value, row) -> HTML`, called during render. The output is
    /// inserted verbatim, so wrap database values in [`esc`]:
    ///
    /// ```ignore
    /// .format("title", |v, row| format!(r#"<a href="/post/{}">{}</a>"#, esc(&row["id"]), esc(v)))
    /// ```
    pub fn format<F>(mut self, column: impl Into<String>, render: F) -> Self
    where
        F: Fn(&Value, &Value) -> String + Send + Sync + 'static,
    {
        self.formatters.push((column.into(), Arc::new(render)));
        self
    }
    /// Namespaces the fragment's DOM id, so two tables for the same entity can share a page.
    pub fn dom_id(mut self, id: impl Into<String>) -> Self {
        self.dom_id = Some(id.into());
        self
    }

    /// Render the table for this request and this view. Write controls appear only if the table is
    /// writable *and* the model's gate permits a write for this caller.
    ///
    /// Errors if the entity isn't registered, or if the configuration can't be honoured (an unknown
    /// filter/sort column, a widget that can't render its column) — naming the column, because a
    /// control that silently did nothing is the bug that gets found in production.
    pub async fn render_for(&self, headers: &HeaderMap, state: &ViewState) -> Result<String> {
        let cols = self.engine.columns(&self.slug)?;
        check_widgets(&self.slug, &cols)?;
        check_sort(&self.slug, &cols, &self.sort)?;
        // **The read enforcement point.** With no JSON API behind the UI, a caller who may not list
        // this entity must not receive its rows in an HTML page either — so this is a refusal, not a
        // matter of which buttons get drawn.
        authorize(self.engine, Operation::List, &self.slug, headers).await?;
        if *state.mode() != Mode::List {
            authorize(self.engine, Operation::Read, &self.slug, headers).await?;
        }
        let editable = !self.read_only
            && self.engine.permits(&self.slug, Operation::Create, headers).await;
        let tz = Tz::from_headers(headers);
        let state = self.effective_state(state, &cols)?;
        let page = self.engine.list(&self.slug, &self.list_query(&state), false).await?;
        let csrf = csrf_token(self.engine, headers);
        let shown = self.shown_columns(&cols)?;
        let (controls, chips) = self.filter_views(&cols, &state).await?;

        let dialog = match (state.mode(), editable) {
            (Mode::List, _) | (_, false) => String::new(),
            (Mode::Import, true) => self.import_dialog(&cols, &state, &csrf)?,
            (mode, true) => self.dialog(&cols, mode, &state, &tz, &csrf).await?,
        };
        TableTmpl {
            dom_id: self.dom_id.clone().unwrap_or_else(|| format!("rl-{}", self.slug)),
            title: self.title.clone().unwrap_or_else(|| self.slug.clone()),
            description: self.description.clone().unwrap_or_default(),
            search: self.search,
            editable,
            confirm: self.confirm,
            csv: cfg!(feature = "csv"),
            q: state.q.clone(),
            span: shown.len() + if editable { 2 } else { 0 },
            keep: self.keep(&state),
            controls,
            chips,
            heads: render::heads(&shown, &state),
            rows: render::rows(&page, &shown, &self.formatters, self.row_class.as_ref(), &state, &tz),
            pager: if self.pagination {
                render::pager(&page, &state)
            } else {
                Pager { total: page.total, page: 1, pages: 1, links: Vec::new() }
            },
            csv_href: state.href_csv(),
            new_href: state.href_new(),
            import_href: state.href_import(),
            flash: state.done.map(|d| d.message()).unwrap_or_default(),
            flash_dismiss: state.href_dismiss(),
            csrf,
            dialog,
        }
        .render()
        .map_err(render_err)
    }

    /// Apply a posted form. See [`Outcome`], and the module docs for the two-handler shape.
    pub async fn submit(
        &self,
        headers: &HeaderMap,
        client_ip: IpAddr,
        body: &[u8],
        state: &ViewState,
    ) -> Result<Outcome> {
        let cols = self.engine.columns(&self.slug)?;
        let state = self.effective_state(state, &cols)?;
        let renders = |name: &str| self.renders(name);
        let surface = Surface {
            engine: self.engine,
            slug: &self.slug,
            renders: &renders,
            query: self.list_query(&state),
        };
        write(&surface, &cols, headers, client_ip, body, &state).await
    }

    /// This view as CSV — the same rows, filters, sort and search, unpaginated, with datetimes in the
    /// caller's zone so the file matches the screen. Serve it from your read handler when
    /// [`ViewState::csv`] is set (that is what the toolbar's Export link asks for).
    #[cfg(feature = "csv")]
    pub async fn csv(&self, headers: &HeaderMap, state: &ViewState) -> Result<String> {
        authorize(self.engine, Operation::List, &self.slug, headers).await?;
        let cols = self.engine.columns(&self.slug)?;
        let state = self.effective_state(state, &cols)?;
        crate::crud::csv_io::export(
            self.engine,
            &self.slug,
            &cols,
            &self.list_query(&state),
            &Tz::from_headers(headers),
        )
        .await
    }

    /// The URL state with this table's pinned filters forced on, and its default sort applied when
    /// the URL asks for none.
    fn effective_state(&self, state: &ViewState, cols: &[Column]) -> Result<ViewState> {
        let mut out = state.clone();
        if out.sort.is_empty() {
            out.sort = self.sort.clone();
        }
        for f in self.applicable_filters(cols)? {
            if let Some(value) = f.fixed {
                out.filters.retain(|(n, _)| *n != f.name);
                out.filters.push((f.name, value));
            }
        }
        Ok(out)
    }

    fn list_query(&self, state: &ViewState) -> ListQuery {
        state.to_list_query(self.per_page)
    }

    /// Hidden inputs that carry the rest of the view through the toolbar's GET form. Not the page
    /// (a new search starts at the first one) and not the filters it renders itself.
    fn keep(&self, state: &ViewState) -> Vec<(String, String)> {
        let rendered: Vec<&str> = self.filters.iter().map(|f| f.name.as_str()).collect();
        let mut out = Vec::new();
        if let Some(e) = &state.entity {
            out.push(("entity".to_string(), e.clone()));
        }
        for (name, value) in &state.filters {
            if !rendered.contains(&name.as_str()) {
                out.push((format!("filter[{name}]"), value.clone()));
            }
        }
        if !state.sort.is_empty() {
            let keys: Vec<String> = state
                .sort
                .iter()
                .map(|(c, d)| if *d { format!("{c}:desc") } else { c.clone() })
                .collect();
            out.push(("sort".to_string(), keys.join(",")));
        }
        if state.per_page > 0 {
            out.push(("per_page".to_string(), state.per_page.to_string()));
        }
        out
    }

    /// The columns this table puts on screen: [`columns`](Table::columns) if set, else all of them.
    /// A name that isn't a column is an error rather than a silently missing one.
    fn shown_columns(&self, cols: &[Column]) -> Result<Vec<Column>> {
        if self.columns.is_empty() {
            return Ok(cols.to_vec());
        }
        self.columns
            .iter()
            .map(|want| {
                cols.iter()
                    .find(|c| render::name_of(c) == want)
                    .cloned()
                    .ok_or_else(|| {
                        Error::BadRequest(format!(
                            "crud::ui({}): cannot show column '{want}': no such column or relation \
                             — known: {}",
                            self.slug,
                            cols.iter().map(render::name_of).collect::<Vec<_>>().join(", ")
                        ))
                    })
            })
            .collect()
    }

    /// The filter controls for the toolbar and the chips above the table, in one pass — they ask
    /// the same questions ("what is this filter set to, and what does that value mean?") and the
    /// answer costs a query.
    async fn filter_views(
        &self,
        cols: &[Column],
        state: &ViewState,
    ) -> Result<(Vec<ControlV>, Vec<Chip>)> {
        let mut controls = Vec::new();
        let mut chips = Vec::new();

        for f in self.applicable_filters(cols)? {
            let col = cols.iter().find(|c| render::name_of(c) == f.name);
            let label = col.map(render::label_of).unwrap_or_else(|| f.name.clone());
            let chosen = match &f.fixed {
                Some(pinned) => pinned.clone(),
                None => state
                    .filters
                    .iter()
                    .find(|(n, _)| *n == f.name)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default(),
            };

            // What the value *means*, for the chip: a relation's cells show labels, so a chip
            // reading "Author: 7" next to rows reading "Ada Lovelace" is the table talking about
            // itself in two languages.
            let chosen_label = match (col, chosen.is_empty()) {
                (Some(Column::Relation { target, .. }), false) => {
                    self.label_of(target, &chosen).await?
                }
                _ => chosen.clone(),
            };

            if !chosen.is_empty() {
                let pinned = f.fixed.is_some() || f.shared;
                chips.push(Chip {
                    label: label.clone(),
                    value: chosen_label.clone(),
                    clear_href: (!pinned).then(|| state.href_filter(&f.name, "")),
                });
            }

            if f.fixed.is_some() {
                continue; // pinned: a chip, and no control to change it with
            }

            let (options, too_many) = match col {
                Some(Column::Relation { target, .. }) => {
                    // One page of the target, capped: `total` then says whether listing them all
                    // would be a wall of options — or, worse, a list quietly missing the one in
                    // force, which would leave the control showing a value that isn't the filter.
                    let q = ListQuery {
                        per_page: self.picker_threshold.max(1),
                        ..Default::default()
                    };
                    let page = self.engine.list(target, &q, true).await?;
                    if page.total > self.picker_threshold {
                        (Vec::new(), page.total)
                    } else {
                        let options = page
                            .data
                            .iter()
                            .map(|it| {
                                let value = render::text(Some(&it.id));
                                Opt { selected: value == chosen, label: it.label.clone(), value }
                            })
                            .collect();
                        (options, 0)
                    }
                }
                Some(Column::Field { options, .. }) => (
                    options
                        .iter()
                        .map(|o| Opt {
                            value: o.clone(),
                            label: o.clone(),
                            selected: *o == chosen,
                        })
                        .collect(),
                    0,
                ),
                _ => (Vec::new(), 0),
            };

            controls.push(ControlV { name: f.name, label, options, chosen, chosen_label, too_many });
        }
        Ok((controls, chips))
    }

    /// One target row's label, for a filter value. `ids=` is an exact primary-key lookup, so this
    /// costs one row however large the target is.
    async fn label_of(&self, target: &str, value: &str) -> Result<String> {
        let q = ListQuery {
            pk_in: vec![value.to_string()],
            per_page: 1,
            ..Default::default()
        };
        Ok(self
            .engine
            .list(target, &q, true)
            .await?
            .data
            .first()
            .map(|it| it.label.clone())
            .unwrap_or_else(|| value.to_string()))
    }

    /// The create/edit dialog for the row the URL names.
    async fn dialog(
        &self,
        cols: &[Column],
        mode: &Mode,
        state: &ViewState,
        tz: &Tz,
        csrf: &str,
    ) -> Result<String> {
        let creating = *mode == Mode::New;
        check_fields(&self.slug, cols, &self.fields, &self.omit, creating)?;
        let row = match mode {
            Mode::Edit(id) => Some(self.engine.get(&self.slug, id).await?),
            _ => None,
        };
        let fields = widgets::fields(
            self.engine,
            cols,
            &|name| self.renders(name),
            row.as_ref(),
            state,
            tz,
            self.picker_threshold,
        )
        .await?;
        let title = self.title.clone().unwrap_or_else(|| self.slug.clone());
        let errors = banner(state, &fields);
        DialogTmpl {
            op: if creating { "create" } else { "update" },
            id: match mode {
                Mode::Edit(id) => id.clone(),
                _ => String::new(),
            },
            csrf: csrf.to_string(),
            title: if creating { format!("New {title}") } else { format!("Edit {title}") },
            submit_label: "Save".into(),
            cancel_href: state.href_list(),
            errors,
            fields,
        }
        .render()
        .map_err(render_err)
    }

    /// The CSV import dialog: a file picker (read in the browser) and a paste box, posting the same
    /// urlencoded body either way. Empty without the `csv` feature — there would be nothing to do.
    fn import_dialog(&self, cols: &[Column], state: &ViewState, csrf: &str) -> Result<String> {
        if !cfg!(feature = "csv") {
            return Ok(String::new());
        }
        ImportTmpl {
            title: self.title.clone().unwrap_or_else(|| self.slug.clone()),
            csrf: csrf.to_string(),
            header: csv_header(cols),
            cancel_href: state.href_list(),
            // An import that was refused comes back here with its per-row report and its text.
            errors: state.row_errors().to_vec(),
            csv: state.posted("csv").and_then(|v| v.first().cloned()).unwrap_or_default(),
        }
        .render()
        .map_err(render_err)
    }

    /// The filters this table will actually render. One named directly is an error if the entity has
    /// no such column — a silently dropped control would leave the operator filtering nothing and not
    /// knowing it. A **shared** one is skipped instead, since [`Admin`] offers it to every table.
    fn applicable_filters(&self, cols: &[Column]) -> Result<Vec<FilterSpec>> {
        let mut out = Vec::new();
        for f in &self.filters {
            if is_filterable(cols, &f.name) {
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

    fn renders(&self, name: &str) -> bool {
        renders(&self.fields, &self.omit, name)
    }
}

// ===================== Form =====================

#[derive(Template)]
#[template(path = "form.html")]
struct FormTmpl {
    dom_id: String,
    has_header: bool,
    title: String,
    description: String,
    op: &'static str,
    id: String,
    csrf: String,
    saved: String,
    errors: Vec<String>,
    fields: Vec<FieldV>,
    cancel_href: String,
    submit_label: String,
}

/// A standalone create/edit form for one registered entity — the same form [`Table`] shows in its
/// dialog, without the table.
///
/// This is the building block for an app's **own** pages, where [`Admin`] is the wrong shape: a signup
/// form, a "new ticket" page, a settings screen. It reads the entity's columns, so the widgets, the
/// required markers, the enum dropdowns, the relation pickers, the datetime handling and the
/// validation messages all come for free and stay in step with the model.
///
/// ```ignore
/// // GET /ticket/new
/// let html = Form::new(&engine, "ticket")
///     .title("New ticket")
///     .fields(["subject", "body", "priority"])
///     .redirect("/tickets/{id}")
///     .render_for(&headers, &state).await?;   // 401/403 rather than a form that can't submit
/// ```
pub struct Form<'a> {
    engine: &'a Engine,
    slug: String,
    dom_id: Option<String>,
    title: Option<String>,
    description: Option<String>,
    heading: Option<bool>,
    edit_id: Option<String>,
    fields: Vec<String>,
    omit: Vec<String>,
    submit_label: Option<String>,
    saved_message: Option<String>,
    cancel_href: Option<String>,
    redirect: Option<String>,
    picker_threshold: u64,
}

impl<'a> Form<'a> {
    /// A form that **creates** a row of `slug`. Add [`edit`](Form::edit) to update one.
    pub fn new(engine: &'a Engine, slug: impl Into<String>) -> Self {
        Self {
            engine,
            slug: slug.into(),
            dom_id: None,
            title: None,
            description: None,
            heading: None,
            edit_id: None,
            fields: Vec::new(),
            omit: Vec::new(),
            submit_label: None,
            saved_message: None,
            cancel_href: None,
            redirect: None,
            picker_threshold: 20,
        }
    }

    /// Edit this existing row: the form renders its current values and saves over them.
    pub fn edit(mut self, id: impl Into<String>) -> Self {
        self.edit_id = Some(id.into());
        self
    }
    /// Heading in the card header. Setting a title (or a description) shows the header; without
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
    /// Render **only** these columns, in this order. Without it the form shows every writable
    /// column, which is the admin's default and rarely what a user-facing form wants.
    pub fn fields<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.fields = names.into_iter().map(Into::into).collect();
        self
    }
    /// Drop these columns, keeping the rest (the complement of [`fields`](Form::fields)).
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
    /// The confirmation shown after a save when there is no [`redirect`](Form::redirect).
    /// Default: `Saved.`
    pub fn saved_message(mut self, msg: impl Into<String>) -> Self {
        self.saved_message = Some(msg.into());
        self
    }
    /// Show a Cancel link to this URL. Without it there is no Cancel button.
    pub fn cancel(mut self, href: impl Into<String>) -> Self {
        self.cancel_href = Some(href.into());
        self
    }
    /// Where [`submit`](Form::submit) points after a successful save. `{id}` is replaced with the
    /// saved row's id, so `"/tickets/{id}"` lands on the new row. Without it the form redirects to
    /// itself and shows [`saved_message`](Form::saved_message).
    pub fn redirect(mut self, url: impl Into<String>) -> Self {
        self.redirect = Some(url.into());
        self
    }
    /// See [`Table::picker_threshold`].
    pub fn picker_threshold(mut self, n: u64) -> Self {
        self.picker_threshold = n;
        self
    }
    /// Namespaces the fragment's DOM id, so two forms for the same entity can share a page.
    pub fn dom_id(mut self, id: impl Into<String>) -> Self {
        self.dom_id = Some(id.into());
        self
    }

    /// Render the form, refusing rather than rendering one the caller could never submit:
    /// `Err(Error::Unauthorized)` (→ `401`) when the gate wants a login, `Err(Error::Forbidden)`
    /// (→ `403`) when it simply isn't permitted. A page handler turns the first into a redirect to
    /// the login page.
    ///
    /// `state` carries a rejected write's messages; [`ViewState::default`] is a fresh form. A
    /// `?saved=1` in your redirect target shows the saved message.
    pub async fn render_for(&self, headers: &HeaderMap, state: &ViewState) -> Result<String> {
        let op = if self.edit_id.is_some() { Operation::Update } else { Operation::Create };
        match self.engine.decide(&self.slug, op, headers).await {
            Decision::Allow => {}
            Decision::NeedsLogin => return Err(Error::Unauthorized),
            Decision::Denied => return Err(Error::Forbidden),
        }
        let cols = self.engine.columns(&self.slug)?;
        check_widgets(&self.slug, &cols)?;
        check_fields(&self.slug, &cols, &self.fields, &self.omit, self.edit_id.is_none())?;
        let tz = Tz::from_headers(headers);
        let row = match &self.edit_id {
            Some(id) => Some(self.engine.get(&self.slug, id).await?),
            None => None,
        };
        let fields = widgets::fields(
            self.engine,
            &cols,
            &|name| renders(&self.fields, &self.omit, name),
            row.as_ref(),
            state,
            &tz,
            self.picker_threshold,
        )
        .await?;
        FormTmpl {
            dom_id: self.dom_id.clone().unwrap_or_default(),
            has_header: self
                .heading
                .unwrap_or(self.title.is_some() || self.description.is_some()),
            title: self.title.clone().unwrap_or_else(|| self.slug.clone()),
            description: self.description.clone().unwrap_or_default(),
            op: if self.edit_id.is_some() { "update" } else { "create" },
            id: self.edit_id.clone().unwrap_or_default(),
            csrf: csrf_token(self.engine, headers),
            saved: match state.saved {
                true => self.saved_message.clone().unwrap_or_else(|| "Saved.".into()),
                false => String::new(),
            },
            errors: banner(state, &fields),
            fields,
            cancel_href: self.cancel_href.clone().unwrap_or_default(),
            submit_label: self.submit_label.clone().unwrap_or_else(|| "Save".into()),
        }
        .render()
        .map_err(render_err)
    }

    /// Apply this form's posted body. On success the target is [`redirect`](Form::redirect) with
    /// `{id}` filled in, else `?saved=1` on the current URL.
    pub async fn submit(
        &self,
        headers: &HeaderMap,
        client_ip: IpAddr,
        body: &[u8],
        state: &ViewState,
    ) -> Result<Outcome> {
        let cols = self.engine.columns(&self.slug)?;
        let shown = |name: &str| renders(&self.fields, &self.omit, name);
        let surface = Surface {
            engine: self.engine,
            slug: &self.slug,
            renders: &shown,
            query: ListQuery::default(),
        };
        match write(&surface, &cols, headers, client_ip, body, state).await? {
            Outcome::Done(to) => Ok(Outcome::Done(match &self.redirect {
                // `to` is `?…#row-{id}` — the id is what a redirect template wants.
                Some(url) => url.replace("{id}", to.rsplit("#row-").next().unwrap_or_default()),
                None => "?saved=1".to_string(),
            })),
            invalid => Ok(invalid),
        }
    }
}

// ===================== Admin =====================

enum NavV {
    Entity { label: String, href: String, active: bool },
    Group(String),
    Separator,
    Link { label: String, href: String },
}

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminTmpl {
    title: String,
    nav: Vec<NavV>,
    panel: String,
}

/// (`Entity` is much the largest variant, and that is fine: the enum is a per-request configuration
/// list of a dozen items at most, so boxing it would trade a deref in every match for nothing.)
#[allow(clippy::large_enum_variant)]
enum AdminItem<'a> {
    Entity(Table<'a>),
    Group(String),
    Separator,
    Link { label: String, href: String },
}

/// A side panel listing models (plus group headings, separators and custom links) next to **one**
/// model's [`Table`] — the one `?entity=` names, or the first.
///
/// ```ignore
/// let html = Admin::new(&engine)
///     .title("Admin")
///     .group("Content")
///     .entity_with("post", |t| t.per_page(10))
///     .entity("tag")
///     .separator()
///     .link("Log out", "/logout")
///     .render_for(&headers, &state).await?;
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

    /// Heading above the side panel.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// One filter control offered to **every** listed table that has a column or to-one relation of
    /// that name; tables without one are unaffected.
    ///
    /// This is the shape that matters when an admin lists many tables of the same kind — fifteen
    /// per-type DNS record tables, say. An operator works inside one zone at a time, so they pick it
    /// once and it follows them from table to table, because every nav link carries it. Like
    /// [`Table::fixed_filter`], it narrows a **view** and is not an authorization boundary.
    pub fn filter(mut self, name: impl Into<String>) -> Self {
        self.filters.push(name.into());
        self
    }

    /// Append every registered entity, in registration order, with default `Table` config.
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
    /// Append one entity, configuring its `Table`.
    pub fn entity_with(
        mut self,
        slug: impl Into<String>,
        config: impl FnOnce(Table<'a>) -> Table<'a>,
    ) -> Self {
        self.items.push(AdminItem::Entity(config(Table::new(self.engine, slug))));
        self
    }
    /// A group heading in the side panel.
    pub fn group(mut self, name: impl Into<String>) -> Self {
        self.items.push(AdminItem::Group(name.into()));
        self
    }
    /// A horizontal rule in the side panel.
    pub fn separator(mut self) -> Self {
        self.items.push(AdminItem::Separator);
        self
    }
    /// A static link in the side panel.
    pub fn link(mut self, label: impl Into<String>, href: impl Into<String>) -> Self {
        self.items.push(AdminItem::Link { label: label.into(), href: href.into() });
        self
    }

    /// Render the panel for this request: the nav, plus the active entity's table (whose own write
    /// controls hide unless the caller may write it).
    pub async fn render_for(&self, headers: &HeaderMap, state: &ViewState) -> Result<String> {
        self.check_filters()?;
        let active = self.active(state)?;
        let panel = active.render_for(headers, state).await?;
        AdminTmpl {
            title: self.title.clone().unwrap_or_default(),
            nav: self.nav(&active.slug, state),
            panel,
        }
        .render()
        .map_err(render_err)
    }

    /// Apply a posted form to the entity it names (`_entity`, else the active one). An entity this
    /// panel doesn't list is refused before any gate is consulted: the panel's contents are part of
    /// what it permits, not merely of what it shows.
    pub async fn submit(
        &self,
        headers: &HeaderMap,
        client_ip: IpAddr,
        body: &[u8],
        state: &ViewState,
    ) -> Result<Outcome> {
        let posted = Posted::read(headers, body)?;
        let named = posted.one("_entity").map(str::to_string).or_else(|| state.entity.clone());
        let table = match named {
            Some(slug) => self.table(&slug).ok_or(Error::NotFound)?,
            None => self.active(state)?,
        };
        table.submit(headers, client_ip, body, state).await
    }

    /// The CSV export of the active table — see [`Table::csv`].
    #[cfg(feature = "csv")]
    pub async fn csv(&self, headers: &HeaderMap, state: &ViewState) -> Result<String> {
        self.active(state)?.csv(headers, state).await
    }

    /// The table `?entity=` names, else the first listed — with the shared filters attached.
    fn active(&self, state: &ViewState) -> Result<Table<'a>> {
        let chosen = match &state.entity {
            Some(slug) => self.table(slug).ok_or(Error::NotFound)?,
            None => self
                .items
                .iter()
                .find_map(|i| match i {
                    AdminItem::Entity(t) => Some(self.with_shared(t)),
                    _ => None,
                })
                .ok_or_else(|| {
                    Error::BadRequest("crud::ui(Admin): no entities listed".to_string())
                })?,
        };
        Ok(chosen)
    }

    fn table(&self, slug: &str) -> Option<Table<'a>> {
        self.items.iter().find_map(|i| match i {
            AdminItem::Entity(t) if t.slug == slug => Some(self.with_shared(t)),
            _ => None,
        })
    }

    /// Offer every shared filter to this table; `applicable_filters` drops the ones it has no column
    /// for (most of them, usually) without complaining.
    fn with_shared(&self, table: &Table<'a>) -> Table<'a> {
        let mut table = table.clone();
        for name in &self.filters {
            table.filters.push(FilterSpec {
                name: name.clone(),
                fixed: None,
                shared: true,
            });
        }
        table
    }

    fn nav(&self, active: &str, state: &ViewState) -> Vec<NavV> {
        self.items
            .iter()
            .map(|item| match item {
                AdminItem::Entity(t) => NavV::Entity {
                    label: t.title.clone().unwrap_or_else(|| t.slug.clone()),
                    href: state.href_entity(&t.slug),
                    active: t.slug == active,
                },
                AdminItem::Group(name) => NavV::Group(name.clone()),
                AdminItem::Separator => NavV::Separator,
                AdminItem::Link { label, href } => {
                    NavV::Link { label: label.clone(), href: href.clone() }
                }
            })
            .collect()
    }

    /// A shared filter no listed entity has any column for is an error: every table would drop it, so
    /// the panel would render no control at all — which reads as a broken feature rather than a typo.
    fn check_filters(&self) -> Result<()> {
        for name in &self.filters {
            let known = self.items.iter().any(|i| match i {
                AdminItem::Entity(t) => {
                    self.engine.columns(&t.slug).is_ok_and(|cols| is_filterable(&cols, name))
                }
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

// ===================== The write path, shared by all three =====================

/// What `write` needs to know about the surface a body was posted from.
struct Surface<'a> {
    engine: &'a Engine,
    slug: &'a str,
    /// Which columns the form rendered — a crafted body naming another one is ignored.
    renders: &'a (dyn Fn(&str) -> bool + Send + Sync),
    /// The view's own query, so a bulk delete can only ever hit the rows on screen.
    query: ListQuery,
}

/// CSRF check → gate → apply → audit → where to go next. One function for every write the UI does,
/// which is why the negative cases only have to be tested once (`crud::gate_tests`).
async fn write(
    s: &Surface<'_>,
    cols: &[Column],
    headers: &HeaderMap,
    client_ip: IpAddr,
    body: &[u8],
    state: &ViewState,
) -> Result<Outcome> {
    let posted = Posted::read(headers, body)?;
    let op = Op::of(&posted)?;
    if !s.engine.csrf_ok(headers, posted.one("_csrf")) {
        return Err(Error::Csrf);
    }
    authorize(s.engine, op.operation(), s.slug, headers).await?;

    let tz = Tz::from_headers(headers);
    let mut anchor = String::new();
    let mut done: Option<Done> = None;
    let (before, after, key) = match &op {
        Op::Create | Op::Update => {
            let id = posted.one("_id").unwrap_or("").to_string();
            let write_body = decode::to_write_body(cols, s.renders, &posted, &tz);
            let mode = if matches!(op, Op::Create) {
                Mode::New
            } else {
                Mode::Edit(id.clone())
            };
            let outcome = match &op {
                Op::Create => s.engine.create(s.slug, &write_body).await.map(|row| (None, row)),
                _ => {
                    let before = s.engine.get(s.slug, &id).await.ok();
                    s.engine.update(s.slug, &id, &write_body).await.map(|row| (before, row))
                }
            };
            match outcome {
                Ok((before, row)) => {
                    anchor = render::text(row.get(&s.engine.pk(s.slug)?));
                    (before, Some(row), Some(anchor.clone()))
                }
                // The one error that isn't an error: re-render the dialog with the messages and the
                // operator's input still in it.
                Err(Error::Validation(errors)) => {
                    return Ok(Outcome::Invalid(state.with_rejection(
                        errors,
                        posted.values(),
                        mode,
                    )))
                }
                Err(e) => return Err(e),
            }
        }
        Op::DeleteOne(id) => {
            let row = s.engine.delete(s.slug, id).await?;
            done = Some(Done::Deleted(1));
            (Some(row), None, Some(id.clone()))
        }
        Op::DeleteSelected => {
            let ids: Vec<String> = posted.all("ids").iter().map(|s| s.to_string()).collect();
            if ids.is_empty() {
                return Ok(Outcome::Done(format!("?{}", state.to_query())));
            }
            let mut q = s.query.clone();
            q.pk_in = ids;
            let n = s.engine.delete_where(s.slug, &q).await?;
            done = Some(Done::Deleted(n));
            (None, Some(serde_json::json!({ "deleted": n })), None)
        }
        Op::DeleteAll => {
            let mut q = s.query.clone();
            q.all = true; // this view's filters still apply — the button says "matching"
            let n = s.engine.delete_where(s.slug, &q).await?;
            done = Some(Done::Deleted(n));
            (None, Some(serde_json::json!({ "deleted": n })), None)
        }
        Op::Import => {
            // The file the operator chose, read as bytes on the server — or, if they pasted
            // instead, the textarea. Either way it is the same import from here on.
            let text = match posted.file("file") {
                Some(bytes) => match csv_text(bytes) {
                    Ok(text) => text,
                    Err(why) => {
                        let mut errors = ValidationErrors::new();
                        errors.general(why);
                        return Ok(Outcome::Invalid(state.with_rejection(
                            errors,
                            posted.values(),
                            Mode::Import,
                        )));
                    }
                },
                None => posted.one("csv").unwrap_or("").to_string(),
            };
            let report = import_csv(s, cols, &text, &tz).await?;
            // The import is all-or-nothing, so a file with bad rows applied *nothing* — say so, in
            // the dialog, with the text still in it. Redirecting to an unchanged list would look
            // like the import had worked.
            if let Some(errors) = import_rejection(&report) {
                // Put the rows back in the dialog's box, however they arrived, so the operator can
                // fix a cell instead of re-picking a file they can no longer see.
                let mut values = posted.values();
                values.insert("csv".to_string(), vec![text]);
                return Ok(Outcome::Invalid(state.with_rejection(errors, values, Mode::Import)));
            }
            done = Some(Done::Imported {
                created: report.get("created").and_then(Value::as_u64).unwrap_or(0),
                updated: report.get("updated").and_then(Value::as_u64).unwrap_or(0),
            });
            (None, Some(report), None)
        }
    };
    notify(s.engine, op.operation(), s.slug, key.as_deref(), before.as_ref(), after.as_ref(), headers, client_ip)
        .await;

    // Back to the list the write came from: the view's own query, plus either a one-shot report of
    // what happened or an anchor onto the row that changed.
    let mut target = format!("?{}", state.to_query());
    if let Some(done) = done {
        let separator = if target.ends_with('?') { "" } else { "&" };
        target.push_str(&format!("{separator}done={}", done.query()));
    }
    if !anchor.is_empty() {
        target.push_str(&format!("#row-{anchor}"));
    }
    Ok(Outcome::Done(target))
}

/// An uploaded file's bytes as CSV text: a UTF-8 BOM (what a spreadsheet writes) is dropped, and
/// anything that isn't UTF-8 is refused by name rather than imported as mojibake — the operator
/// can't see the file before it applies, so a wrong guess would reach the database unnoticed.
fn csv_text(bytes: &[u8]) -> std::result::Result<String, String> {
    let bytes = bytes.strip_prefix("\u{feff}".as_bytes()).unwrap_or(bytes);
    String::from_utf8(bytes.to_vec()).map_err(|e| {
        format!(
            "That file isn't valid UTF-8 (byte {}). Re-save it as UTF-8 — a spreadsheet calls this \
             \"CSV UTF-8\" — or paste the rows below.",
            e.utf8_error().valid_up_to()
        )
    })
}

/// A CSV import's per-row failures as messages for the dialog's banner, or `None` if it applied.
/// Each carries the 1-based line, so a spreadsheet is fixed once rather than per re-upload.
fn import_rejection(report: &Value) -> Option<ValidationErrors> {
    let failed = report.get("failed").and_then(Value::as_u64).unwrap_or(0);
    if failed == 0 {
        return None;
    }
    let mut errors = ValidationErrors::new();
    errors.general(format!("{failed} row(s) rejected — nothing was imported."));
    for e in report.get("errors").and_then(Value::as_array).into_iter().flatten() {
        let row = e.get("row").and_then(Value::as_u64).unwrap_or(0);
        let message = e.get("message").and_then(Value::as_str).unwrap_or("invalid");
        errors.general(format!("line {row}: {message}"));
    }
    Some(errors)
}

#[cfg(feature = "csv")]
async fn import_csv(s: &Surface<'_>, cols: &[Column], text: &str, tz: &Tz) -> Result<Value> {
    let report = crate::crud::csv_io::import(s.engine, s.slug, cols, text, tz).await?;
    serde_json::to_value(&report).map_err(|e| Error::Backend(e.to_string()))
}

#[cfg(not(feature = "csv"))]
async fn import_csv(_s: &Surface<'_>, _cols: &[Column], _text: &str, _tz: &Tz) -> Result<Value> {
    Err(Error::BadRequest("CSV import needs the `csv` feature".into()))
}

/// The operations a posted body can ask for. `_del=<id>` is its own key rather than an `_op` value
/// because a `<button>` submits one name/value pair, and a per-row delete needs to say which row.
enum Op {
    Create,
    Update,
    DeleteOne(String),
    DeleteSelected,
    DeleteAll,
    Import,
}

impl Op {
    fn of(posted: &Posted) -> Result<Op> {
        if let Some(id) = posted.one("_del") {
            return Ok(Op::DeleteOne(id.to_string()));
        }
        match posted.one("_op").unwrap_or("") {
            "create" => Ok(Op::Create),
            "update" => Ok(Op::Update),
            "delete_selected" => Ok(Op::DeleteSelected),
            "delete_all" => Ok(Op::DeleteAll),
            "import" => Ok(Op::Import),
            other => Err(Error::BadRequest(format!("crud::ui: unknown form operation '{other}'"))),
        }
    }

    fn operation(&self) -> Operation {
        match self {
            Op::Create | Op::Import => Operation::Create,
            Op::Update => Operation::Update,
            Op::DeleteOne(_) | Op::DeleteSelected | Op::DeleteAll => Operation::Delete,
        }
    }
}

/// Consult the model's gate and map the decision to `401`/`403`.
async fn authorize(
    engine: &Engine,
    op: Operation,
    slug: &str,
    headers: &HeaderMap,
) -> Result<()> {
    match engine.decide(slug, op, headers).await {
        Decision::Allow => Ok(()),
        Decision::NeedsLogin => Err(Error::Unauthorized),
        Decision::Denied => Err(Error::Forbidden),
    }
}

#[allow(clippy::too_many_arguments)]
async fn notify(
    engine: &Engine,
    op: Operation,
    entity: &str,
    key: Option<&str>,
    before: Option<&Value>,
    after: Option<&Value>,
    headers: &HeaderMap,
    client_ip: IpAddr,
) {
    engine
        .observe(crate::observe::WriteEvent {
            source: "autocrud",
            op,
            entity,
            key: key.map(str::to_string),
            before: before.cloned(),
            after: after.cloned(),
            headers,
            client_ip,
        })
        .await;
}

/// The hidden `_csrf` value, or empty when this engine enforces no token. The **cookie** must already
/// exist — `auth`'s login issues it; an app without `auth` calls `Csrf::ensure` when rendering the
/// page (see `docs/AUTH.md` §7).
#[cfg(feature = "csrf")]
fn csrf_token(engine: &Engine, headers: &HeaderMap) -> String {
    engine.csrf().and_then(|c| c.token(headers)).unwrap_or_default()
}

#[cfg(not(feature = "csrf"))]
fn csrf_token(_engine: &Engine, _headers: &HeaderMap) -> String {
    String::new()
}

// ===================== Shared render-time checks =====================

/// What goes in a form's banner: the cross-field messages, plus any field message naming a column
/// this form doesn't show — which would otherwise be a rejection with nothing marked.
fn banner(state: &ViewState, fields: &[FieldV]) -> Vec<String> {
    let rendered: Vec<String> = fields.iter().map(|f| f.name.clone()).collect();
    let mut out = state.row_errors().to_vec();
    out.extend(state.orphan_errors(&rendered));
    out
}

fn renders(only: &[String], omit: &[String], name: &str) -> bool {
    let included = only.is_empty() || only.iter().any(|n| n == name);
    included && !omit.iter().any(|n| n == name)
}

/// Whether `name` is something this entity can be filtered by: any published field, or a to-one
/// relation (whose FK the backend resolves).
fn is_filterable(cols: &[Column], name: &str) -> bool {
    cols.iter().any(|c| match c {
        Column::Field { name: n, .. } => n == name,
        Column::Relation { name: n, fk_column, .. } => n == name && fk_column.is_some(),
    })
}

/// Refuse a default sort the backend would reject, naming the column — a table that silently ignored
/// `.sort("zone")` would look like it worked.
fn check_sort(slug: &str, cols: &[Column], sort: &[(String, bool)]) -> Result<()> {
    for (want, _) in sort {
        match cols.iter().find(|c| render::name_of(c) == want) {
            Some(c) if render::sortable(c) => {}
            Some(_) => {
                return Err(Error::BadRequest(format!(
                    "crud::ui({slug}): column '{want}' is not sortable"
                )))
            }
            None => {
                return Err(Error::BadRequest(format!(
                    "crud::ui({slug}): cannot sort by '{want}': no such column or relation"
                )))
            }
        }
    }
    Ok(())
}

/// Refuse a widget that can't render its column, naming the field — a `Radio` with no `options`, a
/// `Range` on text, a `Textarea` on a number. The alternative is a form quietly showing a different
/// input than the model asked for, which is the sort of thing noticed in production and not in review.
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

/// Check a configured field list against the model *before* rendering, so a typo or an unsatisfiable
/// create fails here — naming the column — instead of rendering a form whose save can only ever fail.
fn check_fields(
    slug: &str,
    cols: &[Column],
    only: &[String],
    omit: &[String],
    creating: bool,
) -> Result<()> {
    let known: Vec<&str> = cols.iter().map(render::name_of).collect();
    let read_only: Vec<&str> = cols
        .iter()
        .filter(|c| !widgets::writable(c))
        .map(render::name_of)
        .collect();

    for name in only.iter().chain(omit.iter()) {
        if read_only.contains(&name.as_str()) {
            return Err(Error::BadRequest(format!(
                "crud::ui({slug}): column '{name}' is read-only, so a form can't write it"
            )));
        }
        if !known.contains(&name.as_str()) {
            return Err(Error::BadRequest(format!(
                "crud::ui({slug}): no column '{name}' — known columns: {}",
                known.join(", ")
            )));
        }
    }

    // A create must be able to satisfy every required column; an edit needn't, since the row already
    // has values for the fields this form doesn't show.
    if creating {
        let missing: Vec<&str> = cols
            .iter()
            .filter(|c| matches!(c, Column::Field { required: true, read_only: false, .. }))
            .map(render::name_of)
            .filter(|name| !renders(only, omit, name))
            .collect();
        if !missing.is_empty() {
            return Err(Error::BadRequest(format!(
                "crud::ui({slug}): creating needs {}, which this form doesn't show — add {} to \
                 .fields(), or edit an existing row. A column `default` doesn't help: it pre-fills \
                 the input, so the field still has to be rendered for the value to be sent",
                missing.join(", "),
                if missing.len() == 1 { "it" } else { "them" }
            )));
        }
    }
    Ok(())
}

/// The CSV header the import placeholder shows — the columns an import would read.
fn csv_header(cols: &[Column]) -> String {
    cols.iter()
        .filter(|c| !matches!(c, Column::Field { write_only: true, .. }))
        .map(render::name_of)
        .collect::<Vec<_>>()
        .join(",")
}

fn render_err(e: askama::Error) -> Error {
    Error::Backend(e.to_string())
}
