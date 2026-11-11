//! Turning `Vec<Column>` × [`Page`] into the pieces a template prints: cells, rows, sortable headers,
//! filter chips and a pager.
//!
//! One `match` per cell over [`Column`], so a new variant or [`LogicalType`] is a compile error in
//! exactly the places that must handle it.

use super::state::ViewState;
use super::Fmt;
use crate::crud::engine::{Cardinality, Column, LogicalType, Page};
use crate::time::Tz;
use serde_json::Value;

/// One table cell, as a *shape* rather than as HTML — so the template escapes the text and only
/// [`Raw`](Cell::Raw) (a `format` closure's output) is inserted verbatim. That keeps the entire
/// raw-HTML surface of this crate to one template branch, which is a thing a reviewer can check.
pub(crate) enum Cell {
    Text(String),
    Bool(Option<bool>),
    Badges(Vec<String>),
    /// A relation whose rows the caller may read ([`Links`]): each label a link to its row —
    /// plain text for a to-one, badges for a to-many.
    Links { links: Vec<LinkV>, badges: bool },
    Raw(String),
}

/// One linked row in a [`Cell::Links`]. `view` is the picker page that shows it in a dialog (what
/// `crud::ui::JS` opens); `href` is where the link goes without the script: the app's own page for
/// the target (`Crud::view_path`), else that same picker page. `key` (`target:id`) is how the
/// script finds every link to a row whose label an edit just changed. An empty `href` is no link:
/// the "+3 more" at the end of a cut list.
pub(crate) struct LinkV {
    pub label: String,
    pub href: String,
    pub view: String,
    pub key: String,
}

/// Which of one entity's relations link to their rows, for one caller: those whose target they may
/// read, when the relation says so (`MetaRelation::links`) or else `Crud::picker_view` does.
/// Resolved once per render, so a page of rows asks each target's gate once, not once per row.
#[derive(Default)]
pub(crate) struct Links(Vec<Linked>);

/// One relation that links: the picker page for its rows, and the app's own page for them if any.
struct Linked {
    relation: String,
    target: String,
    picker: String,
    page: Option<String>,
}

impl Links {
    pub(crate) async fn resolve(
        engine: &crate::crud::engine::Engine,
        slug: &str,
        cols: &[Column],
        headers: &http::HeaderMap,
    ) -> Links {
        let mut out = Vec::new();
        let mut readable: Vec<(String, bool)> = Vec::new();
        for col in cols {
            let Column::Relation { name, target, links, .. } = col else { continue };
            // The relation's own choice, else the app's.
            let Some(path) = engine.picker_view_path(*links) else { continue };
            let ok = match readable.iter().find(|(t, _)| t == target) {
                Some((_, ok)) => *ok,
                None => {
                    let ok = engine.permits(target, crate::authz::Operation::Read, headers).await;
                    readable.push((target.clone(), ok));
                    ok
                }
            };
            if ok {
                out.push(Linked {
                    relation: name.clone(),
                    target: target.clone(),
                    picker: super::picker::pick_href(path, slug, name, None),
                    page: engine.view_path(target).map(str::to_string),
                });
            }
        }
        Links(out)
    }

    /// `col`'s cell as links, or `None` when it doesn't link (not a relation, or not readable).
    fn cell(&self, col: &Column, raw: Option<&Value>) -> Option<Cell> {
        let Column::Relation { name, cardinality, .. } = col else { return None };
        let l = self.0.iter().find(|l| l.relation == *name)?;
        let link = |item: &Value| -> LinkV {
            if let Some(n) = item.get("more").and_then(Value::as_u64) {
                let label = format!("+{n} more");
                return LinkV { label, href: String::new(), view: String::new(), key: String::new() };
            }
            let id = text(item.get("id"));
            let view = crate::urlform::fill_id(&format!("{}&show={{id}}", l.picker), &id);
            LinkV {
                label: text(item.get("label")),
                href: match &l.page {
                    Some(page) => crate::urlform::fill_id(page, &id),
                    None => view.clone(),
                },
                key: format!("{}:{id}", l.target),
                view,
            }
        };
        Some(match cardinality {
            Cardinality::ToOne => Cell::Links {
                links: raw.filter(|v| !v.is_null()).map(|v| vec![link(v)]).unwrap_or_default(),
                badges: false,
            },
            Cardinality::ToMany => Cell::Links {
                links: raw.and_then(Value::as_array).map(|a| a.iter().map(link).collect()).unwrap_or_default(),
                badges: true,
            },
        })
    }
}

pub(crate) struct RowV {
    pub id: String,
    /// The row's display label — what a [`Picker`](super::Picker) hands back as the chosen badge.
    pub label: String,
    pub edit_href: String,
    /// Empty when the table offers no detail view.
    pub show_href: String,
    pub cells: Vec<Cell>,
    /// From [`Table::row_class`](super::Table::row_class); empty unless one is configured.
    pub class: String,
}

pub(crate) struct HeadV {
    pub label: String,
    /// `Some(href)` when the column is sortable — the header is a link that cycles asc → desc → off.
    pub sort_href: Option<String>,
    /// The "+" affordance: add this column as a secondary key. `None` unless something is sorted
    /// already, so the control appears exactly when it means anything.
    pub add_href: Option<String>,
    /// `▲` / `▼`, with a rank digit when more than one key is active.
    pub mark: String,
    pub aria: &'static str,
}

pub(crate) struct Chip {
    pub label: String,
    pub value: String,
    /// `None` for a pinned (`fixed_filter`) or shared filter — it isn't this table's to clear.
    pub clear_href: Option<String>,
}

pub(crate) struct PageLink {
    pub label: String,
    pub href: String,
    pub active: bool,
    pub disabled: bool,
}

pub(crate) struct Pager {
    pub total: u64,
    pub page: u64,
    pub pages: u64,
    pub links: Vec<PageLink>,
}

pub(crate) use crate::crud::text::text;

/// How `col` shows a stored `value`: its option label (`MetaField::option_labels`), else the
/// value itself. Display only — what is posted, linked and exported stays `value`.
pub(crate) fn option_label<'a>(col: &'a Column, value: &'a str) -> &'a str {
    match col {
        Column::Field { option_labels, .. } => {
            option_labels.iter().find(|(v, _)| v == value).map_or(value, |(_, l)| l.as_str())
        }
        Column::Relation { .. } => value,
    }
}

/// One cell of one row. A `format` closure wins over everything; then a relation's [`Links`].
pub(crate) fn cell(col: &Column, row: &Value, fmt: Option<&Fmt>, tz: &Tz, links: Option<&Links>) -> Cell {
    let name = name_of(col);
    let raw = row.get(name);
    if let Some(f) = fmt {
        return Cell::Raw(f(raw.unwrap_or(&Value::Null), row));
    }
    if let Some(cell) = links.and_then(|l| l.cell(col, raw)) {
        return cell;
    }
    match col {
        Column::Field { logical_type: LogicalType::Bool, .. } => {
            Cell::Bool(raw.and_then(Value::as_bool))
        }
        // An int column flagged `datetime` holds Unix seconds: render it in the caller's zone.
        Column::Field { display: Some(d), .. } if d.is_datetime() => match raw.and_then(Value::as_i64)
        {
            Some(secs) => Cell::Text(tz.format(secs)),
            None => Cell::Text(String::new()),
        },
        Column::Field { .. } => Cell::Text(option_label(col, &text(raw)).to_string()),
        // The backend already resolved relations to `{id, label}` — there is nothing to fetch.
        Column::Relation { cardinality: Cardinality::ToOne, .. } => {
            Cell::Text(text(raw.and_then(|r| r.get("label"))))
        }
        Column::Relation { .. } => Cell::Badges(
            raw.and_then(Value::as_array)
                .map(|a| a.iter().map(badge).collect())
                .unwrap_or_default(),
        ),
    }
}

/// A to-many link's badge; the backend ends a cut list with `{"more": n}`.
fn badge(link: &Value) -> String {
    match link.get("more").and_then(Value::as_u64) {
        Some(n) => format!("+{n} more"),
        None => text(link.get("label")),
    }
}

pub(crate) fn name_of(col: &Column) -> &str {
    match col {
        Column::Field { name, .. } | Column::Relation { name, .. } => name,
    }
}

pub(crate) fn label_of(col: &Column) -> String {
    match col {
        Column::Field { name, label, .. } | Column::Relation { name, label, .. } => {
            label.clone().unwrap_or_else(|| name.clone())
        }
    }
}

pub(crate) fn sortable(col: &Column) -> bool {
    match col {
        Column::Field { sortable, .. } | Column::Relation { sortable, .. } => *sortable,
    }
}

/// Every row of the page, with its edit link — and its View link from `show`, if it has one.
#[allow(clippy::too_many_arguments)] // one page's context, passed straight through
pub(crate) fn rows(
    page: &Page,
    cols: &[Column],
    fmts: &[(String, Fmt)],
    row_class: Option<&super::RowClass>,
    state: &ViewState,
    tz: &Tz,
    show: Option<&dyn Fn(&str) -> String>,
    links: Option<&Links>,
) -> Vec<RowV> {
    page.data
        .iter()
        .map(|item| {
            let id = text(Some(&item.id));
            let row = item.row.clone().unwrap_or(Value::Null);
            RowV {
                edit_href: state.href_edit(&id),
                show_href: show.map(|f| f(&id)).unwrap_or_default(),
                class: row_class.map(|f| f(&row)).unwrap_or_default(),
                cells: cols
                    .iter()
                    .map(|c| {
                        let fmt = fmts.iter().find(|(n, _)| n == name_of(c)).map(|(_, f)| f);
                        cell(c, &row, fmt, tz, links)
                    })
                    .collect(),
                label: item.label.clone(),
                id,
            }
        })
        .collect()
}

/// The header row: a link per sortable column, plus the sort marks.
pub(crate) fn heads(cols: &[Column], state: &ViewState) -> Vec<HeadV> {
    let multi = state.sort.len() > 1;
    let sorted_already = !state.sort.is_empty();
    cols.iter()
        .map(|c| {
            let name = name_of(c);
            let rank = state.sort.iter().position(|(col, _)| col == name);
            let desc = rank.map(|i| state.sort[i].1).unwrap_or(false);
            HeadV {
                label: label_of(c),
                sort_href: sortable(c).then(|| state.href_sort(name, false)),
                add_href: (sortable(c) && sorted_already && rank.is_none())
                    .then(|| state.href_sort(name, true)),
                mark: match (rank, multi) {
                    (None, _) => String::new(),
                    (Some(_), false) => (if desc { "▼" } else { "▲" }).to_string(),
                    (Some(i), true) => format!("{}{}", if desc { "▼" } else { "▲" }, i + 1),
                },
                aria: match (rank.is_some(), desc) {
                    (false, _) => "none",
                    (true, false) => "ascending",
                    (true, true) => "descending",
                },
            }
        })
        .collect()
}

/// `First « 3 4 [5] 6 7 » Last`, or nothing at all when there is only one page.
///
/// A window of ±2 around the current page, and `«`/`»` that step by a **tenth of the table**, so a
/// 90-page listing isn't navigated one page at a time — and on a short one the step is 1, which makes
/// them plain previous/next.
pub(crate) fn pager(page: &Page, state: &ViewState) -> Pager {
    let per_page = page.per_page.max(1);
    let pages = page.total.div_ceil(per_page).max(1);
    let current = page.page.clamp(1, pages);
    let jump = (pages / 10).max(1);
    let mut links = Vec::new();
    let mut push = |label: &str, target: u64, active: bool, disabled: bool| {
        links.push(PageLink {
            label: label.to_string(),
            href: state.href_page(target.clamp(1, pages)),
            active,
            disabled,
        });
    };
    if pages > 1 {
        push("First", 1, false, current == 1);
        push("«", current.saturating_sub(jump), false, current == 1);
        let from = current.saturating_sub(2).max(1);
        for p in from..=(from + 4).min(pages) {
            push(&p.to_string(), p, p == current, false);
        }
        push("»", current + jump, false, current == pages);
        push("Last", pages, false, current == pages);
    }
    Pager { total: page.total, page: current, pages, links }
}
