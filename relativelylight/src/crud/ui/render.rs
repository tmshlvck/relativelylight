//! Turning `Vec<Column>` × [`Page`] into the pieces a template prints: cells, rows, sortable headers,
//! filter chips and a pager.
//!
//! All of this used to be JavaScript dispatching on strings (`c.kind === "relation"`,
//! `c.type === "Bool"`). Here it is one `match` per cell over a Rust enum, so a new [`Column`] variant
//! or [`LogicalType`] is a compile error in exactly the places that must handle it.

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
    Raw(String),
}

pub(crate) struct RowV {
    pub id: String,
    pub edit_href: String,
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

/// A JSON scalar as display text. `null` is blank rather than "null": an empty cell reads as "nothing
/// here", which is what it means.
pub(crate) fn text(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// One cell of one row.
pub(crate) fn cell(col: &Column, row: &Value, fmt: Option<&Fmt>, tz: &Tz) -> Cell {
    let name = name_of(col);
    let raw = row.get(name);
    if let Some(f) = fmt {
        return Cell::Raw(f(raw.unwrap_or(&Value::Null), row));
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
        Column::Field { .. } => Cell::Text(text(raw)),
        // The backend already resolved relations to `{id, label}` — there is nothing to fetch.
        Column::Relation { cardinality: Cardinality::ToOne, .. } => {
            Cell::Text(text(raw.and_then(|r| r.get("label"))))
        }
        Column::Relation { .. } => Cell::Badges(
            raw.and_then(Value::as_array)
                .map(|a| a.iter().map(|l| text(l.get("label"))).collect())
                .unwrap_or_default(),
        ),
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

/// Every row of the page, with its edit link.
pub(crate) fn rows(
    page: &Page,
    cols: &[Column],
    fmts: &[(String, Fmt)],
    row_class: Option<&super::RowClass>,
    state: &ViewState,
    tz: &Tz,
) -> Vec<RowV> {
    page.data
        .iter()
        .map(|item| {
            let id = text(Some(&item.id));
            let row = item.row.clone().unwrap_or(Value::Null);
            RowV {
                edit_href: state.href_edit(&id),
                class: row_class.map(|f| f(&row)).unwrap_or_default(),
                cells: cols
                    .iter()
                    .map(|c| {
                        let fmt = fmts.iter().find(|(n, _)| n == name_of(c)).map(|(_, f)| f);
                        cell(c, &row, fmt, tz)
                    })
                    .collect(),
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
