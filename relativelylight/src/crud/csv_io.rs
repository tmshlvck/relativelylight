//! `relativelylight::crud::csv_io` — CSV import/export for the admin UI (feature `csv`).
//!
//! CSV is the one exchange format the UI can't render, so it lives here as a thin layer over the
//! backend-agnostic [`Engine`]: export reads via [`Engine::list`], import writes via
//! [`Engine::write_batch`] — so every row goes through the same coerce/validate/hook pipeline as a
//! form does. It reads the same typed `&[Column]` the renderer does, which is what keeps a file's
//! columns and a screen's columns the same set.
//!
//! **A file matches the screen.** The caller's [`Tz`] is applied to datetime columns, so an exported
//! timestamp reads the way the cell above it did, and re-importing that file means what it says. That
//! was impossible while the export was an API endpoint with no idea what zone the browser had chosen.
//!
//! Shape (round-trippable — export then re-import):
//! - Header row = column names (write-only fields omitted).
//! - Field → the scalar value; a `datetime` field → `YYYY-MM-DD HH:MM` in the caller's zone.
//!   To-one relation → the target **id** (blank if none). To-many → ids joined with `|` (`1|3`).
//! - On import, a row carrying a primary-key value **updates** that row; a blank/absent PK
//!   **creates** one. Read-only columns (the PK aside, inverse relations) are ignored.

use crate::crud::engine::{Cardinality, Column, Engine, Error, ListQuery, LogicalType, Result};
use crate::time::Tz;
use serde::Serialize;
use serde_json::{json, Map, Value};

/// Summary of an import run. All-or-nothing: either every row applied, or `errors` says why none did.
#[derive(Debug, Default, Serialize)]
pub struct ImportReport {
    pub created: usize,
    pub updated: usize,
    pub failed: usize,
    pub errors: Vec<ImportError>,
}

#[derive(Debug, Serialize)]
pub struct ImportError {
    /// 1-based line in the CSV (the header is line 1, so data rows start at 2).
    pub row: usize,
    pub message: String,
}

fn be<E: std::fmt::Display>(e: E) -> Error {
    Error::Backend(e.to_string())
}

/// The columns a file carries: everything except write-only ones, which have nothing to export and
/// would import a secret in clear text.
fn exported(cols: &[Column]) -> Vec<&Column> {
    cols.iter().filter(|c| !matches!(c, Column::Field { write_only: true, .. })).collect()
}

fn name_of(col: &Column) -> &str {
    match col {
        Column::Field { name, .. } | Column::Relation { name, .. } => name,
    }
}

fn is_datetime(col: &Column) -> bool {
    matches!(col, Column::Field { display: Some(d), .. } if d.is_datetime())
}

/// Export every row matching `q` (search / filters / sort apply; pagination is lifted) as CSV text.
pub async fn export(
    engine: &Engine,
    slug: &str,
    cols: &[Column],
    q: &ListQuery,
    tz: &Tz,
) -> Result<String> {
    let cols = exported(cols);
    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record(cols.iter().map(|c| name_of(c))).map_err(be)?;

    let mut all = q.clone();
    all.all = true; // the full (filtered) set, unpaginated
    for item in engine.list(slug, &all, false).await?.data {
        let row = item.row.unwrap_or(Value::Null);
        let record: Vec<String> = cols.iter().map(|c| cell(&row, c, tz)).collect();
        wtr.write_record(&record).map_err(be)?;
    }
    String::from_utf8(wtr.into_inner().map_err(be)?).map_err(be)
}

/// One CSV cell, from an assembled row (relations arrive as `{id, label}`).
fn cell(row: &Value, col: &Column, tz: &Tz) -> String {
    let raw = row.get(name_of(col));
    match col {
        Column::Relation { cardinality: Cardinality::ToMany, .. } => raw
            .and_then(Value::as_array)
            .map(|items| {
                items.iter().filter_map(|i| i.get("id")).map(scalar).collect::<Vec<_>>().join("|")
            })
            .unwrap_or_default(),
        Column::Relation { .. } => raw.and_then(|r| r.get("id")).map(scalar).unwrap_or_default(),
        _ if is_datetime(col) => raw.and_then(Value::as_i64).map(|s| tz.format(s)).unwrap_or_default(),
        _ => raw.map(scalar).unwrap_or_default(),
    }
}

/// A JSON scalar as a cell (`null` → empty, a string without its quotes).
fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Import CSV text: create/update one row per record, as **one unit**.
///
/// One backend transaction for the whole file ([`Engine::write_batch`]), so a file that fails on line
/// 40 leaves the first 39 rows unapplied rather than half-importing a spreadsheet. Validation runs
/// across every row before the transaction opens, so a file with four bad cells reports all four in
/// one pass instead of one per re-upload.
pub async fn import(
    engine: &Engine,
    slug: &str,
    cols: &[Column],
    text: &str,
    tz: &Tz,
) -> Result<ImportReport> {
    let pk = engine.pk(slug)?;
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(text.as_bytes());
    let headers = rdr.headers().map_err(be)?.clone();
    let mut report = ImportReport::default();

    // Parse every record first: the import is all-or-nothing, so there is nothing to half-apply while
    // collecting these.
    let mut rows: Vec<(Option<String>, Value)> = Vec::new();
    for (i, record) in rdr.records().enumerate() {
        match record {
            Ok(record) => rows.push(body(&headers, &record, cols, &pk, tz)),
            Err(e) => {
                report.failed += 1;
                report.errors.push(ImportError { row: i + 2, message: e.to_string() });
            }
        }
    }
    if report.failed > 0 {
        return Ok(report); // unparseable CSV: say so, write nothing
    }

    match engine.write_batch(slug, rows).await {
        Ok(applied) => {
            report.created = applied.created as usize;
            report.updated = applied.updated as usize;
        }
        Err(Error::BatchRejected(bad)) => {
            report.failed = bad.len();
            report.errors.extend(
                bad.into_iter().map(|(i, e)| ImportError { row: i + 2, message: e.one_line() }),
            );
        }
        Err(e) => return Err(e),
    }
    Ok(report)
}

/// One CSV record → a write body, plus the primary key if the file carried one.
fn body(
    headers: &csv::StringRecord,
    record: &csv::StringRecord,
    cols: &[Column],
    pk: &str,
    tz: &Tz,
) -> (Option<String>, Value) {
    let mut out = Map::new();
    let mut key = None;
    for (header, raw) in headers.iter().zip(record.iter()) {
        if header == pk {
            if !raw.is_empty() {
                key = Some(raw.to_string());
            }
            continue; // the PK itself is never written into the body
        }
        let Some(col) = cols.iter().find(|c| name_of(c) == header) else { continue };
        match col {
            Column::Relation { read_only: true, .. } | Column::Field { read_only: true, .. } => {}
            Column::Relation { cardinality: Cardinality::ToMany, .. } => {
                let ids: Vec<Value> = raw
                    .split('|')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(id_value)
                    .collect();
                out.insert(header.to_string(), Value::Array(ids));
            }
            Column::Relation { .. } => {
                out.insert(
                    header.to_string(),
                    if raw.is_empty() { Value::Null } else { id_value(raw) },
                );
            }
            Column::Field { logical_type, .. } => {
                if let Some(v) = scalar_value(*logical_type, is_datetime(col), raw.trim(), tz) {
                    out.insert(header.to_string(), v);
                }
            }
        }
    }
    (key, Value::Object(out))
}

/// Coerce a cell by its column's logical type. `None` = omit the field (an empty numeric cell, where
/// sending `0` would be inventing a value).
fn scalar_value(lt: LogicalType, datetime: bool, cell: &str, tz: &Tz) -> Option<Value> {
    if datetime {
        // Written in the caller's zone by `export`, so read back in it too.
        return match cell.is_empty() {
            true => Some(Value::Null),
            false => Some(tz.parse(cell).map(|s| json!(s)).unwrap_or_else(|| json!(cell))),
        };
    }
    match lt {
        LogicalType::Int => (!cell.is_empty())
            .then(|| cell.parse::<i64>().map(|n| json!(n)).unwrap_or_else(|_| json!(cell))),
        LogicalType::Float => (!cell.is_empty())
            .then(|| cell.parse::<f64>().map(|n| json!(n)).unwrap_or_else(|_| json!(cell))),
        LogicalType::Bool => (!cell.is_empty())
            .then(|| json!(matches!(cell.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "y" | "t"))),
        // Text / Uuid / Date / … — the string as-is (including "") so field validators can run.
        _ => Some(json!(cell)),
    }
}

/// A relation target id: numeric when possible (our PKs), else the raw string.
fn id_value(s: &str) -> Value {
    match s.trim().parse::<i64>() {
        Ok(n) => json!(n),
        Err(_) => json!(s.trim()),
    }
}
