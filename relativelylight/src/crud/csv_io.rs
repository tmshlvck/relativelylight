//! `relativelylight::crud::csv_io` — CSV import/export over the JSON API (feature `csv`).
//!
//! CSV is the one exchange format the JSON API doesn't cover, so it lives here as a thin layer over
//! the backend-agnostic `Engine`: export reads via `Engine::list`, import writes via
//! `Engine::create`/`update` — so every row goes through the same coerce/validate pipeline as the
//! HTTP API. Columns and their kinds come from `Engine::meta_one`, so this is ORM-neutral too.
//!
//! Shape (round-trippable — export then re-import):
//! - Header row = column names (write-only fields omitted).
//! - Fields → the scalar value. To-one relation → the target **id** (blank if none).
//!   To-many / N:M relation → the target ids joined with `|` (e.g. `1|3`).
//! - On import, a row carrying a primary-key value **updates** that row; a row with a blank/absent
//!   PK **creates** one. Read-only columns (PK, inverse relations) are ignored on import.

use crate::crud::engine::{Engine, Error, ListQuery, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};

/// Summary of an import run (best-effort: each row is applied independently; failures are collected).
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

/// Render a JSON scalar as a CSV cell (objects/arrays shouldn't occur here; `null` → empty).
fn cell_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// The entity's columns (from metadata), as parsed JSON objects.
fn columns(engine: &Engine, slug: &str) -> Result<Vec<Value>> {
    let meta = engine.meta_one(slug)?;
    Ok(meta
        .get("columns")
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default())
}

/// Export all rows matching `q` (search / filters / sort apply; pagination is lifted) as CSV text.
pub async fn export(engine: &Engine, slug: &str, q: &ListQuery) -> Result<String> {
    let cols = columns(engine, slug)?;
    let exported: Vec<&Value> = cols
        .iter()
        .filter(|c| c.get("write_only").and_then(|b| b.as_bool()) != Some(true))
        .collect();

    let mut wtr = csv::Writer::from_writer(vec![]);
    let headers: Vec<&str> = exported.iter().map(|c| c["name"].as_str().unwrap_or("")).collect();
    wtr.write_record(&headers).map_err(be)?;

    let mut qq = q.clone();
    qq.all = true; // export the full (filtered) set, unpaginated
    let listing = engine.list(slug, &qq, false).await?;
    let empty = vec![];
    let data = listing.get("data").and_then(|d| d.as_array()).unwrap_or(&empty);
    for item in data {
        let row = item.get("row").cloned().unwrap_or(Value::Null);
        let rec: Vec<String> = exported.iter().map(|c| export_cell(&row, c)).collect();
        wtr.write_record(&rec).map_err(be)?;
    }

    let bytes = wtr.into_inner().map_err(be)?;
    String::from_utf8(bytes).map_err(be)
}

/// One CSV cell for a column, read from an assembled row (relations are `{id,label,url}` shaped).
fn export_cell(row: &Value, col: &Value) -> String {
    let name = col["name"].as_str().unwrap_or("");
    let v = row.get(name);
    match col["kind"].as_str() {
        Some("relation") => match col["cardinality"].as_str() {
            Some("ToMany") => v
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|l| l.get("id"))
                        .map(cell_str)
                        .collect::<Vec<_>>()
                        .join("|")
                })
                .unwrap_or_default(),
            _ => v.and_then(|o| o.get("id")).map(cell_str).unwrap_or_default(),
        },
        _ => v.map(cell_str).unwrap_or_default(),
    }
}

/// Import CSV text: create/update one row per record, returning a per-row report (best-effort).
pub async fn import(engine: &Engine, slug: &str, text: &str) -> Result<ImportReport> {
    let cols = columns(engine, slug)?;
    let by_name: Map<String, Value> = cols
        .iter()
        .filter_map(|c| c.get("name").and_then(|n| n.as_str()).map(|n| (n.to_string(), c.clone())))
        .collect();
    let meta = engine.meta_one(slug)?;
    let pk: Vec<String> = meta
        .get("primary_key")
        .and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(text.as_bytes());
    let headers = rdr.headers().map_err(be)?.clone();
    let mut report = ImportReport::default();

    for (i, result) in rdr.records().enumerate() {
        let row_no = i + 2; // header is line 1; first data record is line 2
        let rec = match result {
            Ok(r) => r,
            Err(e) => {
                report.failed += 1;
                report.errors.push(ImportError { row: row_no, message: e.to_string() });
                continue;
            }
        };
        let (body, pk_val) = build_body(&headers, &rec, &by_name, &pk);
        let body = Value::Object(body);
        // A PK value routes to update; its absence routes to create.
        let outcome = match &pk_val {
            Some(id) => engine.update(slug, id, &body).await.map(|_| false),
            None => engine.create(slug, &body).await.map(|_| true),
        };
        match outcome {
            Ok(true) => report.created += 1,
            Ok(false) => report.updated += 1,
            Err(e) => {
                report.failed += 1;
                report.errors.push(ImportError { row: row_no, message: err_msg(e) });
            }
        }
    }
    Ok(report)
}

/// Build a create/update JSON body from one CSV record; also extract a PK value if the CSV carries one.
fn build_body(
    headers: &csv::StringRecord,
    rec: &csv::StringRecord,
    by_name: &Map<String, Value>,
    pk: &[String],
) -> (Map<String, Value>, Option<String>) {
    let mut body = Map::new();
    let mut pk_val = None;
    for (h, cell) in headers.iter().zip(rec.iter()) {
        if pk.iter().any(|p| p == h) {
            if !cell.is_empty() {
                pk_val = Some(cell.to_string());
            }
            continue; // the PK itself is never written into the body
        }
        let Some(col) = by_name.get(h) else { continue };
        if col.get("read_only").and_then(|b| b.as_bool()) == Some(true) {
            continue; // inverse relations, generated columns, …
        }
        match col.get("kind").and_then(|k| k.as_str()) {
            Some("relation") => {
                if col.get("cardinality").and_then(|c| c.as_str()) == Some("ToMany") {
                    let ids: Vec<Value> = cell
                        .split('|')
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(parse_id)
                        .collect();
                    body.insert(h.to_string(), Value::Array(ids));
                } else {
                    body.insert(h.to_string(), if cell.is_empty() { Value::Null } else { parse_id(cell) });
                }
            }
            _ => {
                let ty = col.get("type").and_then(|t| t.as_str()).unwrap_or("Text");
                if let Some(v) = csv_to_json(ty, cell) {
                    body.insert(h.to_string(), v);
                }
            }
        }
    }
    (body, pk_val)
}

/// Parse a relation target id: numeric when possible (our PKs), else the raw string.
fn parse_id(s: &str) -> Value {
    match s.parse::<i64>() {
        Ok(n) => json!(n),
        Err(_) => json!(s),
    }
}

/// Coerce a CSV string to JSON by the column's logical type. `None` = omit (empty numeric/bool cell).
fn csv_to_json(ty: &str, cell: &str) -> Option<Value> {
    let cell = cell.trim();
    match ty {
        "Int" => (!cell.is_empty()).then(|| cell.parse::<i64>().map(|n| json!(n)).unwrap_or(json!(cell))),
        "Float" => (!cell.is_empty()).then(|| cell.parse::<f64>().map(|n| json!(n)).unwrap_or(json!(cell))),
        "Bool" => (!cell.is_empty())
            .then(|| json!(matches!(cell.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "y" | "t"))),
        // Text / Uuid / Date / … — send the string as-is (incl. "") so field validators can run.
        _ => Some(json!(cell)),
    }
}

/// Flatten an engine error into a one-line message for the row report.
fn err_msg(e: Error) -> String {
    match e {
        Error::Validation(v) => {
            let mut parts: Vec<String> = v.fields.iter().map(|(k, m)| format!("{k}: {m}")).collect();
            parts.extend(v.errors);
            if parts.is_empty() {
                "validation failed".into()
            } else {
                parts.join("; ")
            }
        }
        other => other.to_string(),
    }
}
