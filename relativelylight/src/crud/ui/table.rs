//! [`Table`] — one entity on screen: toolbar, rows, bulk actions, pager, and whichever dialog the
//! URL asks for (create, edit, read-only detail, CSV import).

use super::render::{self, Cell, Chip, HeadV, PageLink, Pager, RowV};
use super::state::{Mode, ViewState};
use super::widgets::{self, FieldV, Opt, Widget};
use super::{
    apply, authorize, banner, check_fields, check_sort, check_widgets, csrf_token, csv_header,
    is_filterable, render_err, renders, Fmt, Outcome, RowClass, Surface,
};
use crate::authz::Operation;
use crate::crud::engine::{Column, Engine, Error, ListQuery, Result};
use crate::time::Tz;
use askama::Template;
use http::HeaderMap;
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Template)]
#[template(path = "table.html")]
struct TableTmpl {
    dom_id: String,
    title: String,
    description: String,
    search: bool,
    pagination: bool,
    editable: bool,
    confirm: bool,
    /// Whether rows offer a View action (and therefore whether the actions column exists for a
    /// caller who can't write).
    detail: bool,
    csv: bool,
    q: String,
    csrf: String,
    span: usize,
    keep: Vec<(String, String)>,
    per_page_options: Vec<PageLink>,
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

/// One labelled value in the detail view.
struct DetailV {
    label: String,
    value: Cell,
}

#[derive(Template)]
#[template(path = "detail.html")]
struct DetailTmpl {
    title: String,
    cancel_href: String,
    /// Empty when this caller may not write, so a reader is offered no button they'd be refused.
    edit_href: String,
    fields: Vec<DetailV>,
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
pub(super) struct FilterSpec {
    pub(super) name: String,
    pub(super) fixed: Option<String>,
    /// Offered by [`Admin::filter`](super::Admin::filter) to every table it lists, rather than by this table itself — so a
    /// table with no such column skips it instead of refusing to render.
    pub(super) shared: bool,
}

/// A table for one registered entity, rendered as an HTML fragment for the app's shell.
#[derive(Clone)]
pub struct Table<'a> {
    pub(super) engine: &'a Engine,
    pub(super) slug: String,
    dom_id: Option<String>,
    pub(super) title: Option<String>,
    description: Option<String>,
    search: bool,
    pagination: bool,
    per_page: u64,
    per_page_choices: Vec<u64>,
    per_page_max: u64,
    read_only: bool,
    confirm: bool,
    picker_threshold: u64,
    fields: Vec<String>,
    omit: Vec<String>,
    columns: Vec<String>,
    formatters: Vec<(String, Fmt)>,
    row_class: Option<RowClass>,
    detail: bool,
    pub(super) filters: Vec<FilterSpec>,
    sort: Vec<(String, bool)>,
}

impl<'a> Table<'a> {
    /// The default [`per_page_max`](Table::per_page_max): the largest page a table will fetch
    /// however large a `?per_page=` asks for.
    ///
    /// 500 rather than something rounder, because of what a row *costs*: the SeaORM backend
    /// resolves relations per row, so a page of `N` rows with `R` relation columns is on the order
    /// of `N × R` queries. At 500 that is a page a server can answer; at 10,000 a single typed URL
    /// would be tens of thousands of them. Raise it for tables with no relations, or once relation
    /// reads are batched (`docs/TODO.md`).
    pub const DEFAULT_PER_PAGE_MAX: u64 = 500;

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
            per_page_choices: vec![10, 30, 100, 250],
            per_page_max: Self::DEFAULT_PER_PAGE_MAX,
            read_only: false,
            confirm: true,
            picker_threshold: 20,
            fields: Vec::new(),
            omit: Vec::new(),
            columns: Vec::new(),
            formatters: Vec::new(),
            row_class: None,
            detail: true,
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
    /// Rows per page, until the URL says otherwise. Default 30.
    pub fn per_page(mut self, n: u64) -> Self {
        self.per_page = n;
        self
    }

    /// The sizes the toolbar offers. Default `[10, 30, 100, 250]`; the configured
    /// [`per_page`](Table::per_page) is added if it isn't among them, so the control can always
    /// show the size in force. **Empty hides the control** — the URL still works.
    pub fn per_page_choices<I: IntoIterator<Item = u64>>(mut self, sizes: I) -> Self {
        self.per_page_choices = sizes.into_iter().filter(|n| *n > 0).collect();
        self
    }

    /// The largest page this table will fetch, however large a `?per_page=` asks for. Default
    /// **10,000**.
    ///
    /// The URL is user input: `?per_page=100000000` is a cheap way to make a server read a whole
    /// table into memory, resolve every row's relations, and render the lot — so the number is
    /// clamped rather than trusted. Raise it for a console that really does page in thousands
    /// (knowing its own schema); lower it in front of a wide table. It does not touch CSV export,
    /// which is explicitly unpaginated and asked for one view at a time. See [`DEFAULT_PER_PAGE_MAX`](Table::DEFAULT_PER_PAGE_MAX).
    pub fn per_page_max(mut self, n: u64) -> Self {
        self.per_page_max = n.max(1);
        self
    }
    /// Read-only table: no Create/Edit/Delete and no dialog. Default: false.
    pub fn read_only(mut self, on: bool) -> Self {
        self.read_only = on;
        self
    }
    /// Offer a **View** action per row, opening a read-only dialog (`?show=<id>`) with every
    /// published column. Default: on.
    ///
    /// It is the only way to see what a form doesn't: a generated id, a hook-stamped `created_at`,
    /// a long text column the table shows a corner of — and the only row view a caller who may not
    /// write gets at all. Turn it off for a table that already shows everything it has.
    pub fn detail(mut self, on: bool) -> Self {
        self.detail = on;
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
    /// and this crate no longer has one — see `docs/MIGRATION-0.3.md` §A6.4.)
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
        let per_page_options = self.per_page_options(&state);
        let (controls, chips) = self.filter_views(&cols, &state).await?;

        let dialog = match (state.mode(), editable) {
            (Mode::List, _) => String::new(),
            // A read-only row is a *read*: a caller who may not write still gets it.
            (Mode::Show(id), _) => self.detail_dialog(&cols, id, &state, &tz, editable).await?,
            (_, false) => String::new(),
            (Mode::Import, true) => self.import_dialog(&cols, &state, &csrf)?,
            (mode, true) => self.dialog(&cols, mode, &state, &tz, &csrf).await?,
        };
        TableTmpl {
            dom_id: self.dom_id.clone().unwrap_or_else(|| format!("rl-{}", self.slug)),
            title: self.title.clone().unwrap_or_else(|| self.slug.clone()),
            description: self.description.clone().unwrap_or_default(),
            search: self.search,
            pagination: self.pagination,
            editable,
            confirm: self.confirm,
            csv: cfg!(feature = "csv"),
            q: state.q.clone(),
            span: shown.len() + usize::from(editable) + usize::from(editable || self.detail),
            keep: self.keep(&state),
            per_page_options,
            controls,
            chips,
            heads: render::heads(&shown, &state),
            rows: render::rows(
                &page,
                &shown,
                &self.formatters,
                self.row_class.as_ref(),
                &state,
                &tz,
                self.detail,
            ),
            detail: self.detail,
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
        apply(&surface, &cols, headers, client_ip, body, &state).await
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

    /// The URL state as this table will actually act on it: pinned filters forced on, the default
    /// sort applied when the URL asks for none, and the page size clamped.
    ///
    /// Clamping *here* rather than only where the query is built matters, because every link the
    /// page renders is built from this state: otherwise a `?per_page=100000000` would be refused by
    /// the query and then faithfully copied into every pager link, sort header and redirect.
    fn effective_state(&self, state: &ViewState, cols: &[Column]) -> Result<ViewState> {
        let mut out = state.clone();
        out.per_page = out.per_page.min(self.per_page_max);
        if out.sort.is_empty() {
            out.sort = self.sort.clone();
        }
        // Only filters this entity *has* a column for. An `Admin` shared filter travels in the URL
        // from table to table — that is the point of it — so most tables meet one naming a column
        // they don't have, and passing it to the backend would refuse the whole listing. Dropping
        // it here is the other half of `applicable_filters` dropping the control.
        out.filters.retain(|(name, _)| is_filterable(cols, name));
        for f in self.applicable_filters(cols)? {
            if let Some(value) = f.fixed {
                out.filters.retain(|(n, _)| *n != f.name);
                out.filters.push((f.name, value));
            }
        }
        Ok(out)
    }

    fn list_query(&self, state: &ViewState) -> ListQuery {
        let mut q = state.to_list_query(self.per_page);
        q.per_page = q.per_page.min(self.per_page_max);
        q
    }

    /// The page sizes offered beside the pager, as links — no form, no script, and the one in
    /// force is text rather than a link to where you already are. Empty when the table was
    /// configured with no choices, or when pagination is off.
    fn per_page_options(&self, state: &ViewState) -> Vec<PageLink> {
        if !self.pagination || self.per_page_choices.is_empty() {
            return Vec::new();
        }
        let in_force = self.list_query(state).per_page;
        let mut sizes = self.per_page_choices.clone();
        for extra in [self.per_page, in_force] {
            if !sizes.contains(&extra) {
                sizes.push(extra);
            }
        }
        sizes.retain(|n| *n <= self.per_page_max);
        sizes.sort_unstable();
        sizes.dedup();
        sizes
            .into_iter()
            .map(|n| PageLink {
                label: n.to_string(),
                href: state.href_per_page(n),
                active: n == in_force,
                disabled: false,
            })
            .collect()
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

        // A filter can reach a table without the table declaring a control for it — an `Admin`
        // shared one, or a hand-written URL. It still narrows what is on screen, so it still needs
        // a chip: a filtered table that looked unfiltered is how someone concludes their rows are
        // gone. (`effective_state` has already dropped the ones this entity can't honour.)
        let declared: Vec<&str> = self.filters.iter().map(|f| f.name.as_str()).collect();
        let undeclared = state.filters.iter().filter(|(n, _)| !declared.contains(&n.as_str()));
        for (name, value) in undeclared {
            if value.is_empty() {
                continue;
            }
            let col = cols.iter().find(|c| render::name_of(c) == name);
            let shown = match col {
                Some(Column::Relation { target, .. }) => self.label_of(target, value).await?,
                _ => value.clone(),
            };
            chips.push(Chip {
                label: col.map(render::label_of).unwrap_or_else(|| name.clone()),
                value: shown,
                clear_href: Some(state.href_filter(name, "")),
            });
        }

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

    /// One row, read-only: every published column, rendered by the same code as the table's cells.
    async fn detail_dialog(
        &self,
        cols: &[Column],
        id: &str,
        state: &ViewState,
        tz: &Tz,
        editable: bool,
    ) -> Result<String> {
        // `render_for` has already authorized `Read` for this caller (every non-list mode does),
        // with their real headers — there is nothing left to check here.
        let row = self.engine.get(&self.slug, id).await?;
        let fields = cols
            .iter()
            // A write-only column has nothing to show — the backend never returns one — so it
            // would be a row of blank beside "Password", inviting the reader to wonder.
            .filter(|c| !matches!(c, Column::Field { write_only: true, .. }))
            .map(|c| DetailV {
                label: render::label_of(c),
                value: render::cell(
                    c,
                    &row,
                    self.formatters.iter().find(|(n, _)| n == render::name_of(c)).map(|(_, f)| f),
                    tz,
                ),
            })
            .collect();
        DetailTmpl {
            title: format!("{} #{id}", self.title.clone().unwrap_or_else(|| self.slug.clone())),
            cancel_href: state.href_list(),
            edit_href: if editable { state.href_edit(id) } else { String::new() },
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

