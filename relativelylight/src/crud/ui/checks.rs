//! The render-time refusals, shared by every surface. A control that silently did nothing is the
//! bug found in production rather than in review, so a misconfiguration is an error naming the
//! column instead.

use super::render;
use super::state::ViewState;
use super::widgets::{self, FieldV};
use crate::crud::engine::{Column, Error, Result};

/// What goes in a form's banner: the cross-field messages, plus any field message naming a column
/// this form doesn't show — which would otherwise be a rejection with nothing marked.
pub(crate) fn banner(state: &ViewState, fields: &[FieldV]) -> Vec<String> {
    let rendered: Vec<String> = fields.iter().map(|f| f.name.clone()).collect();
    let mut out = state.row_errors().to_vec();
    out.extend(state.orphan_errors(&rendered));
    out
}

pub(crate) fn renders(only: &[String], omit: &[String], name: &str) -> bool {
    let included = only.is_empty() || only.iter().any(|n| n == name);
    included && !omit.iter().any(|n| n == name)
}

/// Whether `name` is something this entity can be filtered by: any published field, or a to-one
/// relation (whose FK the backend resolves).
pub(crate) fn is_filterable(cols: &[Column], name: &str) -> bool {
    cols.iter().any(|c| match c {
        Column::Field { name: n, .. } => n == name,
        Column::Relation { name: n, fk_column, .. } => n == name && fk_column.is_some(),
    })
}

/// Refuse a default sort the backend would reject, naming the column — a table that silently ignored
/// `.sort("zone")` would look like it worked.
pub(crate) fn check_sort(slug: &str, cols: &[Column], sort: &[(String, bool)]) -> Result<()> {
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
pub(crate) fn check_widgets(slug: &str, cols: &[Column]) -> Result<()> {
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
pub(crate) fn check_fields(
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
pub(crate) fn csv_header(cols: &[Column]) -> String {
    cols.iter()
        .filter(|c| !matches!(c, Column::Field { write_only: true, .. }))
        .map(render::name_of)
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn render_err(e: askama::Error) -> Error {
    Error::Backend(e.to_string())
}
