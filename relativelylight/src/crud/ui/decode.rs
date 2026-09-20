//! A posted form body → the JSON write body the engine takes.
//!
//! This is `payload()` from `_form_core.html`, in Rust and now in one place. The rules it encodes are
//! the ones a browser form makes unavoidable, and each of them used to be duplicated between the JS
//! that built the payload and the server that validated it:
//!
//! - **empty is not always the same as nothing.** On a nullable column an empty input means `null`; on
//!   a NOT NULL text column it means the empty string; on a number it means "don't send this field at
//!   all", so the database default applies instead of a type error.
//! - **an unchecked checkbox sends nothing**, so a rendered `Bool` that is absent is `false` — which is
//!   why the decoder walks the *columns* and consults the body, never the other way round.
//! - **a write-only column left blank keeps its current value** (that is how "leave blank to keep the
//!   password" works), so it is omitted rather than written as empty.
//!
//! Only columns the form actually rendered are read. A crafted POST naming a hidden, read-only or
//! unrendered column is ignored — the form's field list is part of its contract, not just its layout.
//!
//! Bodies arrive in two shapes and are read the same way: `application/x-www-form-urlencoded` for
//! every ordinary form, and `multipart/form-data` when one carries a file (the CSV import). The
//! token that authorises the write is a field either way, so nothing downstream has to care which
//! it was.

use crate::crud::engine::{Cardinality, Column, Error, LogicalType};
use crate::time::Tz;
use crate::urlform;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// A parsed form body, keeping repeated keys (checkbox groups, multi-selects, `ids=1&ids=2`) and,
/// for a multipart post, any uploaded file alongside them.
pub(crate) struct Posted {
    fields: Vec<(String, String)>,
    /// `(field name, bytes)` per file part. A picker the operator left alone still arrives — as a
    /// part with a filename and no bytes — which is how [`file`](Posted::file) tells "no file
    /// chosen" from a file that happened to be empty.
    files: Vec<(String, Vec<u8>)>,
}

impl Posted {
    /// Read a posted body, choosing by content type. A multipart body that can't be parsed is a
    /// `400` naming the problem rather than a silently empty form.
    pub(crate) fn read(headers: &http::HeaderMap, body: &[u8]) -> Result<Self, Error> {
        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let Some(boundary) = crate::multipart::boundary(content_type) else {
            // The ordinary case: everything the UI renders except the import dialog.
            return Ok(Posted {
                fields: urlform::pairs(&String::from_utf8_lossy(body)),
                files: Vec::new(),
            });
        };
        let mut fields = Vec::new();
        let mut files = Vec::new();
        for part in crate::multipart::parse(body, &boundary)
            .map_err(|why| Error::BadRequest(format!("crud::ui: {why}")))?
        {
            match part.filename {
                Some(_) => files.push((part.name, part.body)),
                // A text field: browsers post these in the document's encoding, which for a page we
                // rendered is UTF-8.
                None => fields.push((part.name, String::from_utf8_lossy(&part.body).into_owned())),
            }
        }
        Ok(Posted { fields, files })
    }

    pub(crate) fn one(&self, key: &str) -> Option<&str> {
        self.fields.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub(crate) fn all(&self, key: &str) -> Vec<&str> {
        self.fields.iter().filter(|(k, _)| k == key).map(|(_, v)| v.as_str()).collect()
    }

    pub(crate) fn has(&self, key: &str) -> bool {
        self.fields.iter().any(|(k, _)| k == key)
    }

    /// The bytes of an uploaded file, or `None` when the picker was left alone (or its file was
    /// empty, which for an import means the same thing: there is nothing to apply).
    pub(crate) fn file(&self, key: &str) -> Option<&[u8]> {
        self.files
            .iter()
            .find(|(k, bytes)| k == key && !bytes.is_empty())
            .map(|(_, bytes)| bytes.as_slice())
    }

    /// Everything that was typed, for re-rendering a rejected form with the input still in it.
    pub(crate) fn values(&self) -> BTreeMap<String, Vec<String>> {
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (k, v) in &self.fields {
            out.entry(k.clone()).or_default().push(v.clone());
        }
        out
    }
}

/// Build the create/update body. `rendered` is the form's field predicate.
pub(crate) fn to_write_body(
    cols: &[Column],
    rendered: &(dyn Fn(&str) -> bool + Send + Sync),
    posted: &Posted,
    tz: &Tz,
) -> Value {
    let mut body = Map::new();
    for col in cols.iter().filter(|c| super::widgets::writable(c)) {
        let name = super::render::name_of(col);
        if !rendered(name) {
            continue;
        }
        match col {
            Column::Relation { cardinality: Cardinality::ToMany, .. } => {
                let ids: Vec<Value> =
                    posted.all(name).into_iter().filter(|s| !s.is_empty()).map(id_value).collect();
                body.insert(name.to_string(), Value::Array(ids));
            }
            Column::Relation { .. } => {
                let raw = posted.one(name).unwrap_or("").trim();
                body.insert(
                    name.to_string(),
                    if raw.is_empty() { Value::Null } else { id_value(raw) },
                );
            }
            Column::Field { logical_type: LogicalType::Bool, .. } => {
                // Absent = unchecked. (A nullable Bool is edited as two states, not three: a
                // switch that could also be "unset" is a control nobody reads correctly.)
                body.insert(name.to_string(), json!(posted.has(name)));
            }
            Column::Field { logical_type, nullable, write_only, display, .. } => {
                let raw = posted.one(name).unwrap_or("");
                if *write_only && raw.is_empty() {
                    continue; // keep the stored value
                }
                let datetime = matches!(display, Some(d) if d.is_datetime());
                if raw.trim().is_empty() {
                    match (nullable, logical_type, datetime) {
                        (true, ..) => body.insert(name.to_string(), Value::Null),
                        // Not nullable and no value typed: let the column's own default decide,
                        // rather than sending `0` or `""` and calling it the operator's choice.
                        (false, LogicalType::Int | LogicalType::Float, _) | (false, _, true) => {
                            continue
                        }
                        (false, ..) => body.insert(name.to_string(), json!("")),
                    };
                    continue;
                }
                let value = match (datetime, logical_type) {
                    // A datetime-local reading is wall-clock time in the caller's zone.
                    (true, _) => tz.parse(raw).map(|s| json!(s)).unwrap_or_else(|| json!(raw)),
                    (_, LogicalType::Int) => {
                        raw.trim().parse::<i64>().map(|n| json!(n)).unwrap_or_else(|_| json!(raw))
                    }
                    (_, LogicalType::Float) => {
                        raw.trim().parse::<f64>().map(|n| json!(n)).unwrap_or_else(|_| json!(raw))
                    }
                    (_, LogicalType::Json) => {
                        serde_json::from_str(raw).unwrap_or_else(|_| json!(raw))
                    }
                    _ => json!(raw),
                };
                body.insert(name.to_string(), value);
            }
        }
    }
    Value::Object(body)
}

/// A relation target id: numeric when it looks numeric (the common case), else the string — a slug or
/// UUID primary key travels unchanged.
fn id_value(s: &str) -> Value {
    match s.trim().parse::<i64>() {
        Ok(n) => json!(n),
        Err(_) => json!(s.trim()),
    }
}
