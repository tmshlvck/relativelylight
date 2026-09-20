//! The **URL is the state**: page, sort keys, filters, the search term, which entity is active and
//! which row is being edited all live in the query string, and nowhere else.
//!
//! One consequence is worth stating: every view is linkable. A filtered, sorted, paginated table is a
//! URL you can bookmark, mail to a colleague, or put in a runbook. The previous design kept the same
//! information in three places (Alpine component fields, `localStorage`, and a URL fragment), which is
//! three chances to disagree.
//!
//! The vocabulary is the one the old JSON API parsed, so an app's existing links keep meaning what they
//! meant: `page`, `per_page`, `q`, `filter[name]`, `sort=a,b:desc`, `ids`, `all` — plus `entity`, `new`
//! and `edit` for the UI's own navigation, and `format=csv`.

use crate::crud::engine::{ListQuery, ValidationErrors};
use crate::urlform;
use std::collections::BTreeMap;

/// What the write that redirected here did — rendered once, as an alert above the table.
///
/// Deletes and imports report; a create or an update doesn't, because the redirect already lands on
/// the row that changed (`#row-7`) and an alert on every save is noise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Done {
    /// Rows removed by a per-row, selected, or "all matching" delete.
    Deleted(u64),
    /// A CSV import that applied: rows created, rows updated.
    Imported { created: u64, updated: u64 },
}

impl Done {
    /// `deleted:17` / `imported:120,3` — short, readable in a URL, and nothing an app has to build
    /// by hand (the components emit it).
    fn parse(value: &str) -> Option<Done> {
        let (kind, rest) = value.split_once(':')?;
        let number = |s: &str| s.parse::<u64>().ok();
        match kind {
            "deleted" => Some(Done::Deleted(number(rest)?)),
            "imported" => {
                let (created, updated) = rest.split_once(',')?;
                Some(Done::Imported { created: number(created)?, updated: number(updated)? })
            }
            _ => None,
        }
    }

    pub(crate) fn query(self) -> String {
        match self {
            Done::Deleted(n) => format!("deleted:{n}"),
            Done::Imported { created, updated } => format!("imported:{created},{updated}"),
        }
    }

    /// The sentence shown in the alert.
    pub(crate) fn message(self) -> String {
        let records = |n: u64| if n == 1 { "record".to_string() } else { "records".to_string() };
        match self {
            Done::Deleted(n) => format!("{n} {} deleted.", records(n)),
            Done::Imported { created, updated: 0 } => {
                format!("{created} {} added from CSV.", records(created))
            }
            Done::Imported { created: 0, updated } => {
                format!("{updated} {} updated from CSV.", records(updated))
            }
            Done::Imported { created, updated } => format!(
                "{created} {} added and {updated} updated from CSV.",
                records(created)
            ),
        }
    }
}

/// What the page is showing: the list, or the list with a dialog open on top of it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum Mode {
    #[default]
    List,
    New,
    Edit(String),
    /// The CSV import dialog (`?import=1`). Like the others, it is a URL — so it survives a
    /// refresh, and a rejected import can re-render it with the report in place.
    Import,
}

/// Everything a [`Table`](super::Table) / [`Admin`](super::Admin) render needs from the request URL.
///
/// Parse it once per request with [`from_query`](ViewState::from_query) and hand it to `render_for`.
/// [`Default`] is page 1, unsorted, unfiltered — so a page that ignores the URL still works.
#[derive(Debug, Default, Clone)]
pub struct ViewState {
    /// Which entity an [`Admin`](super::Admin) is showing (`None` = its first).
    pub entity: Option<String>,
    /// 1-based; `0` means "unset" and renders page 1.
    pub page: u64,
    /// Overrides the component's own `per_page` when non-zero.
    pub per_page: u64,
    /// Free-text search across the entity's text columns.
    pub q: String,
    /// Sort keys, in precedence order: `(column, descending)`.
    pub sort: Vec<(String, bool)>,
    /// Exact-match filters, `(column-or-relation, value)`.
    pub filters: Vec<(String, String)>,
    pub mode: Mode,
    /// `?format=csv` — the app's read handler exports instead of rendering (see `Table::csv`).
    pub csv: bool,
    /// `?saved=1` — a standalone [`Form`](super::Form) shows its saved message. Set by the redirect
    /// that form's own `submit` returns, so the message survives the POST→303→GET.
    pub saved: bool,
    /// `?done=…` — what the write that redirected here actually did, reported once above the table.
    /// It rides in the URL because a `303` is all there is between the write and the page that
    /// reports it, and a flash kept in the session would be wrong the moment a second tab exists.
    pub done: Option<Done>,
    /// Set by `submit` when a write was rejected: the messages, and what the operator had typed, so
    /// the dialog can re-render with both in place instead of losing the input.
    pub(crate) rejected: Option<ValidationErrors>,
    pub(crate) posted: BTreeMap<String, Vec<String>>,
}

impl ViewState {
    /// Parse a query string (with or without a leading `?`). Unknown keys are ignored, so an app may
    /// keep its own parameters in the same URL.
    pub fn from_query(query: &str) -> Self {
        let mut s = Self::default();
        for (key, value) in urlform::pairs(query.trim_start_matches('?')) {
            match bracketed(&key, "filter") {
                Some(name) => s.filters.push((name.to_string(), value)),
                None => match key.as_str() {
                    "entity" => s.entity = Some(value),
                    "page" => s.page = value.parse().unwrap_or(0),
                    "per_page" => s.per_page = value.parse().unwrap_or(0),
                    "q" => s.q = value,
                    "sort" => s.sort = parse_sort(&value),
                    "new" => s.mode = Mode::New,
                    "edit" => s.mode = Mode::Edit(value),
                    "import" => s.mode = Mode::Import,
                    "format" => s.csv = value == "csv",
                    "saved" => s.saved = true,
                    "done" => s.done = Done::parse(&value),
                    _ => {}
                },
            }
        }
        s
    }

    /// The same, from a request URI — the usual call in a handler.
    pub fn from_uri(uri: &http::Uri) -> Self {
        Self::from_query(uri.query().unwrap_or(""))
    }

    /// The **list** state as a query string, no leading `?`: everything except the dialog (`new` /
    /// `edit` / `import`), `format`, and the one-shot `imported` report — so it is also the URL a
    /// finished write returns to.
    pub fn to_query(&self) -> String {
        urlform::query(&self.pairs())
    }

    fn pairs(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        if let Some(e) = &self.entity {
            out.push(("entity".into(), e.clone()));
        }
        for (name, value) in &self.filters {
            out.push((format!("filter[{name}]"), value.clone()));
        }
        if !self.q.is_empty() {
            out.push(("q".into(), self.q.clone()));
        }
        if !self.sort.is_empty() {
            out.push(("sort".into(), fmt_sort(&self.sort)));
        }
        if self.per_page > 0 {
            out.push(("per_page".into(), self.per_page.to_string()));
        }
        if self.page > 1 {
            out.push(("page".into(), self.page.to_string()));
        }
        out
    }

    /// A relative link to this state with `changes` applied — `?entity=post&page=2`. Always begins
    /// with `?`, so it resolves against whatever path the app serves the component on and the library
    /// never needs to know that path.
    fn href(&self, changes: &[(&str, &str)]) -> String {
        let mut pairs = self.pairs();
        for (key, value) in changes {
            pairs.retain(|(k, _)| k != key);
            if !value.is_empty() {
                pairs.push((key.to_string(), value.to_string()));
            }
        }
        format!("?{}", urlform::query(&pairs))
    }

    pub(crate) fn href_list(&self) -> String {
        self.href(&[])
    }
    pub(crate) fn href_page(&self, page: u64) -> String {
        self.href(&[("page", &page.to_string())])
    }
    pub(crate) fn href_entity(&self, slug: &str) -> String {
        // A different entity keeps the shared filters (that is the point of `Admin::filter`) but not
        // the page or the search term, which meant something about the table being left behind.
        let mut s = self.clone();
        s.page = 0;
        s.q = String::new();
        s.sort.clear();
        s.href(&[("entity", slug)])
    }
    pub(crate) fn href_new(&self) -> String {
        self.href(&[("new", "1")])
    }
    pub(crate) fn href_import(&self) -> String {
        self.href(&[("import", "1")])
    }
    /// This view with the import report cleared — where the alert's dismiss link points.
    pub(crate) fn href_dismiss(&self) -> String {
        self.href_list()
    }
    pub(crate) fn href_edit(&self, id: &str) -> String {
        self.href(&[("edit", id)])
    }
    pub(crate) fn href_csv(&self) -> String {
        self.href(&[("format", "csv")])
    }
    pub(crate) fn href_filter(&self, name: &str, value: &str) -> String {
        let mut pairs = self.pairs();
        pairs.retain(|(k, _)| k != &format!("filter[{name}]") && k != "page");
        if !value.is_empty() {
            pairs.push((format!("filter[{name}]"), value.to_string()));
        }
        format!("?{}", urlform::query(&pairs))
    }

    /// The link a sortable header points at. Clicking cycles ascending → descending → unsorted on
    /// that column alone; `add` appends it as a secondary key instead, which is what the old
    /// shift-click did undiscoverably.
    pub(crate) fn href_sort(&self, column: &str, add: bool) -> String {
        let mut keys = if add { self.sort.clone() } else { Vec::new() };
        match self.sort.iter().position(|(c, _)| c == column) {
            // ascending → descending; already descending → drop it
            Some(i) if self.sort[i].1 => {
                keys.retain(|(c, _)| c != column);
            }
            Some(_) => {
                keys.retain(|(c, _)| c != column);
                keys.push((column.to_string(), true));
            }
            None => keys.push((column.to_string(), false)),
        }
        self.href(&[("sort", &fmt_sort(&keys)), ("page", "")])
    }

    /// Fold this view into a backend query. `per_page` is the component's default, used unless the URL
    /// overrides it.
    pub fn to_list_query(&self, per_page: u64) -> ListQuery {
        let mut q = ListQuery::default();
        if !self.q.is_empty() {
            q.search.push((None, self.q.clone()));
        }
        q.eq = self.filters.clone();
        q.sort = self.sort.clone();
        q.page = self.page;
        q.per_page = if self.per_page > 0 { self.per_page } else { per_page };
        q
    }

    /// Re-render this view with a rejected write's messages and typed values in place.
    pub(crate) fn with_rejection(
        &self,
        errors: ValidationErrors,
        posted: BTreeMap<String, Vec<String>>,
        mode: Mode,
    ) -> Self {
        Self { rejected: Some(errors), posted, mode, ..self.clone() }
    }

    /// What the page is showing — the list, or a dialog over it.
    pub fn mode(&self) -> &Mode {
        &self.mode
    }

    pub(crate) fn field_error(&self, name: &str) -> Option<&str> {
        self.rejected.as_ref()?.fields.get(name).map(String::as_str)
    }
    pub(crate) fn row_errors(&self) -> &[String] {
        match &self.rejected {
            Some(v) => &v.errors,
            None => &[],
        }
    }

    /// Field messages naming a column the form **didn't render**, as `column: message`.
    ///
    /// Without this they would be invisible: the operator gets a refused form with nothing marked
    /// and no way to tell why. It happens whenever a rule fires on a column outside the form's
    /// field list — a `NOT NULL` the model fills by hook, a validator on a hidden column, a
    /// database constraint named after a column the admin doesn't show — so the banner is where
    /// they belong, beside the cross-field messages.
    pub(crate) fn orphan_errors(&self, rendered: &[String]) -> Vec<String> {
        let Some(rejected) = &self.rejected else { return Vec::new() };
        rejected
            .fields
            .iter()
            .filter(|(name, _)| !rendered.iter().any(|r| r == *name))
            .map(|(name, message)| format!("{name}: {message}"))
            .collect()
    }
    /// What the operator had typed for `name`, after a rejection (empty before one).
    pub(crate) fn posted(&self, name: &str) -> Option<&[String]> {
        self.posted.get(name).map(Vec::as_slice)
    }
}

/// `name[inner]` → `Some(inner)`. Brackets can't occur in a column name — those come from Rust
/// identifiers — so `filter[…]` can never collide with one, however an app names its columns. That is
/// the whole reason for the spelling: the bare reserved words (`page`, `sort`, `entity`, …) *would*
/// shadow a column, and a plain `?<col>=` has no way to say otherwise.
fn bracketed<'a>(key: &'a str, name: &str) -> Option<&'a str> {
    key.strip_prefix(name)?.strip_prefix('[')?.strip_suffix(']')
}

fn parse_sort(value: &str) -> Vec<(String, bool)> {
    value
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|part| match part.split_once(':') {
            Some((c, dir)) => (c.to_string(), dir == "desc"),
            None => (part.to_string(), false),
        })
        .collect()
}

fn fmt_sort(keys: &[(String, bool)]) -> String {
    keys.iter()
        .map(|(c, desc)| if *desc { format!("{c}:desc") } else { c.clone() })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_finished_write_reports_itself_once() {
        for (query, done, message) in [
            ("done=deleted:1", Done::Deleted(1), "1 record deleted."),
            ("done=deleted:17", Done::Deleted(17), "17 records deleted."),
            (
                "done=imported:123,0",
                Done::Imported { created: 123, updated: 0 },
                "123 records added from CSV.",
            ),
            (
                "done=imported:120,3",
                Done::Imported { created: 120, updated: 3 },
                "120 records added and 3 updated from CSV.",
            ),
            (
                "done=imported:0,4",
                Done::Imported { created: 0, updated: 4 },
                "4 records updated from CSV.",
            ),
        ] {
            let s = ViewState::from_query(query);
            assert_eq!(s.done, Some(done), "{query}");
            assert_eq!(done.message(), message);
            assert_eq!(format!("done={}", done.query()), query, "round-trips through the URL");
            assert!(!s.to_query().contains("done"), "reported once, not on every later click");
        }
        assert_eq!(ViewState::from_query("done=nonsense").done, None, "an unreadable report is none");
        assert_eq!(ViewState::from_query("done=deleted:x").done, None);
    }

    #[test]
    fn a_url_round_trips_through_the_state() {
        let url = "entity=post&filter[author]=7&q=hello+world&sort=title,views:desc&page=3";
        let s = ViewState::from_query(url);
        assert_eq!(s.entity.as_deref(), Some("post"));
        assert_eq!(s.filters, vec![("author".to_string(), "7".to_string())]);
        assert_eq!(s.q, "hello world");
        assert_eq!(s.sort, vec![("title".into(), false), ("views".into(), true)]);
        assert_eq!(s.page, 3);
        // Re-parsing what we render gives the same state back.
        let again = ViewState::from_query(&s.to_query());
        assert_eq!(again.filters, s.filters);
        assert_eq!(again.sort, s.sort);
        assert_eq!(again.q, s.q);
        assert_eq!(again.page, s.page);
    }

    #[test]
    fn the_dialog_is_not_carried_back_into_the_list_url() {
        for (url, mode) in [
            ("page=2&edit=7", Mode::Edit("7".into())),
            ("page=2&new=1", Mode::New),
            ("page=2&import=1", Mode::Import),
        ] {
            let s = ViewState::from_query(url);
            assert_eq!(s.mode, mode);
            let back = s.to_query();
            assert!(!back.contains("edit") && !back.contains("new") && !back.contains("import"),
                    "a finished write returns to the list: {back}");
            assert!(back.contains("page=2"), "but keeps where you were");
        }
    }

    #[test]
    fn a_header_link_cycles_asc_desc_off() {
        let none = ViewState::default();
        assert_eq!(none.href_sort("title", false), "?sort=title");
        let asc = ViewState::from_query("sort=title");
        assert_eq!(asc.href_sort("title", false), "?sort=title%3Adesc");
        let desc = ViewState::from_query("sort=title:desc");
        assert_eq!(desc.href_sort("title", false), "?");
    }

    #[test]
    fn a_secondary_key_is_appended_not_replaced() {
        let s = ViewState::from_query("sort=author");
        assert_eq!(s.href_sort("title", true), "?sort=author%2Ctitle");
        assert_eq!(s.href_sort("title", false), "?sort=title", "without `add` it replaces");
    }

    #[test]
    fn paging_resets_when_the_filter_changes_but_not_when_the_page_does() {
        let s = ViewState::from_query("filter[zone]=1&page=5");
        assert!(!s.href_filter("zone", "2").contains("page"), "a new filter starts at page 1");
        assert!(s.href_page(6).contains("page=6"));
    }

    #[test]
    fn switching_entity_keeps_the_shared_filter_and_drops_the_rest() {
        let s = ViewState::from_query("entity=post&filter[author]=7&q=x&page=4&sort=title");
        let href = s.href_entity("tag");
        assert!(href.contains("entity=tag") && href.contains("filter%5Bauthor%5D=7"), "{href}");
        assert!(!href.contains("q=") && !href.contains("page") && !href.contains("sort"), "{href}");
    }

    #[test]
    fn the_list_query_carries_search_filters_and_sort() {
        let q = ViewState::from_query("q=a&filter[zone]=3&sort=name:desc&page=2").to_list_query(30);
        assert_eq!(q.search, vec![(None, "a".to_string())]);
        assert_eq!(q.eq, vec![("zone".to_string(), "3".to_string())]);
        assert_eq!(q.sort, vec![("name".to_string(), true)]);
        assert_eq!((q.page, q.per_page), (2, 30));
        assert_eq!(ViewState::from_query("per_page=5").to_list_query(30).per_page, 5, "URL wins");
    }
}
