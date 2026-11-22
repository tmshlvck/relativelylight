//! Turning `Vec<Column>` × [`Page`] into the pieces a template prints: cells, rows, sortable headers,
//! filter chips and a pager.
//!
//! One `match` per cell over [`Column`], so a new variant or [`LogicalType`] is a compile error in
//! exactly the places that must handle it.

use super::state::ViewState;
use crate::crud::{Cardinality, Column, LogicalType, Page, Fmt, FmtCtx};
use http::HeaderMap;
use crate::time::Tz;
use serde_json::Value;

/// One table cell, as a *shape* rather than as HTML — so the template escapes the text and only
/// [`Raw`](Cell::Raw) (a field's formatter's output) is inserted verbatim. That keeps the entire
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
/// `crud::JS` opens); `href` is where the link goes without the script: the app's own page for
/// the target (`MetaModel::view_path`), else that same picker page. `key` (`target:id`) is how the
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
        engine: &crate::crud::Engine,
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
                    page: engine.meta(target).ok().and_then(|m| m.view_path),
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
    /// From `MetaModel::row_class`; empty unless one is configured.
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

/// The rows of `target` that `ids` name, in the order of `ids`: each id with its row's label, or
/// `None` when no row has it. One lookup for the lot — `pk_in` is an exact primary-key match, so
/// this reads at most as many rows as there are ids. Ungated: the caller decides who may see
/// labels.
pub(crate) async fn lookup(
    engine: &crate::crud::Engine,
    target: &str,
    ids: &[String],
) -> crate::crud::Result<Vec<(String, Option<String>)>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let q = crate::crud::ListQuery { pk_in: ids.to_vec(), all: true, ..Default::default() };
    let found = match engine.list(target, &q, true).await {
        Ok(page) => page.data,
        // `BadRequest`: an id that can't even be a key of the target (text for an integer key).
        Err(crate::crud::Error::BadRequest(_)) => Vec::new(),
        Err(e) => return Err(e),
    };
    Ok(ids
        .iter()
        .map(|id| {
            let label = found.iter().find(|it| text(Some(&it.id)) == *id).map(|it| it.label.clone());
            (id.clone(), label)
        })
        .collect())
}

/// One row's label ([`lookup`]), or `id` itself when no row has it.
pub(crate) async fn label(engine: &crate::crud::Engine, target: &str, id: &str) -> crate::crud::Result<String> {
    let found = lookup(engine, target, &[id.to_string()]).await?;
    Ok(found.into_iter().next().and_then(|(_, label)| label).unwrap_or_else(|| id.to_string()))
}

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

/// One cell of one row. A field's formatter (`fmt`, with the request it renders for) wins over
/// everything; then a relation's [`Links`].
pub(crate) fn cell(
    col: &Column,
    row: &Value,
    fmt: Option<(&Fmt, &HeaderMap)>,
    tz: &Tz,
    links: Option<&Links>,
) -> Cell {
    let name = col.name();
    let raw = row.get(name);
    if let Some((f, headers)) = fmt {
        return Cell::Raw(f.call(&FmtCtx::new(raw.unwrap_or(&Value::Null), row, headers)));
    }
    if let Some(cell) = links.and_then(|l| l.cell(col, raw)) {
        return cell;
    }
    match col {
        Column::Field { logical_type: LogicalType::Bool, .. } => {
            Cell::Bool(raw.and_then(Value::as_bool))
        }
        // An int column flagged `datetime` holds Unix seconds: render it in the caller's zone.
        Column::Field { .. } if col.is_datetime() => {
            Cell::Text(raw.and_then(Value::as_i64).map(|secs| tz.format(secs)).unwrap_or_default())
        }
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

/// The field's formatter for a table's cells (`MetaField::format_cell`).
pub(crate) fn format_cell(col: &Column) -> Option<&Fmt> {
    match col {
        Column::Field { format_cell, .. } => format_cell.as_ref(),
        Column::Relation { .. } => None,
    }
}

/// The field's formatter where one row is shown (`MetaField::format_view`).
pub(crate) fn format_view(col: &Column) -> Option<&Fmt> {
    match col {
        Column::Field { format_view, .. } => format_view.as_ref(),
        Column::Relation { .. } => None,
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

/// What dresses a page's rows beyond their values. [`Default`] is none of it: every value plain,
/// no class, no View link, no relation links — a picker's list, where a click chooses the row and
/// a link in a cell would leave the form.
#[derive(Default)]
pub(crate) struct Decor<'a> {
    /// The request the fields' `format_cell` and the entity's `row_class` render for; `None`
    /// shows every value plain and classes no row.
    pub formatted: Option<&'a HeaderMap>,
    pub row_class: Option<&'a crate::crud::RowClass>,
    /// Each row's View link, from its id.
    pub show: Option<&'a dyn Fn(&str) -> String>,
    pub links: Option<&'a Links>,
}

/// Every row of the page, with its edit link, dressed as `decor` says.
pub(crate) fn rows(page: &Page, cols: &[Column], state: &ViewState, tz: &Tz, decor: &Decor) -> Vec<RowV> {
    page.data
        .iter()
        .map(|item| {
            let id = text(Some(&item.id));
            let row = item.row.clone().unwrap_or(Value::Null);
            RowV {
                edit_href: state.href_edit(&id),
                show_href: decor.show.map(|f| f(&id)).unwrap_or_default(),
                class: decor
                    .row_class
                    .zip(decor.formatted)
                    .and_then(|(f, h)| f.call(&crate::crud::RowCtx::new(&row, h)))
                    .unwrap_or_default(),
                cells: cols
                    .iter()
                    .map(|c| {
                        let fmt = decor.formatted.and_then(|h| format_cell(c).map(|f| (f, h)));
                        cell(c, &row, fmt, tz, decor.links)
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
            let name = c.name();
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
