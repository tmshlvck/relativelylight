//! Text ↔ typed value, for one column: what a form input or a CSV cell means as a write value, and
//! what a stored value is as text.
//!
//! A form ([`ui`](super::ui)) and a CSV file ([`csv_io`](super::csv_io)) are both typed text, so both
//! read it through here — which is what stops them disagreeing about what an empty cell means, or
//! whether `07` in an integer column is a number. What *differs* between them stays with them: a
//! checkbox posts presence rather than text, a file carries a to-many as `1|3`, a form only reads the
//! columns it rendered.
//!
//! This is the UI's half of a value's way in. The engine's half follows on every surface — coercion,
//! [`blank_is_null`](super::seaorm::MetaField::blank_is_null), validators, then
//! [`on_write`](super::seaorm::MetaField::on_write) — so a rule that belongs to the column, not to
//! typed text, lives there instead.

use super::engine::{Column, LogicalType};
use crate::time::Tz;
use serde_json::{json, Value};

/// A stored scalar as text: `null` is blank rather than "null" — an empty cell reads as "nothing
/// here", which is what it means — a string loses its quotes, anything else prints as JSON.
pub(crate) fn text(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// A relation target id: numeric when it looks numeric (the common case), else the trimmed string —
/// a slug or UUID primary key travels unchanged.
pub(crate) fn id_value(s: &str) -> Value {
    match s.trim().parse::<i64>() {
        Ok(n) => json!(n),
        Err(_) => json!(s.trim()),
    }
}

/// A to-one relation's typed id: blank unlinks it.
pub(crate) fn to_one(raw: &str) -> Value {
    match raw.trim() {
        "" => Value::Null,
        id => id_value(id),
    }
}

/// What `raw`, one typed value for a scalar column, means as a write value. `None` leaves the field
/// out of the body.
///
/// - **A write-only column left blank keeps its stored value** — "leave blank to keep the password".
/// - **Blank on a text-ish column** (`Text`, `Uuid`, `Date`, `DateTime`) is `""`, and the engine
///   turns that into `NULL` on a nullable column unless `blank_is_null` is off: one rule, kept where
///   every surface meets it.
/// - **Blank on anything else** — a number, a bool, an enum, JSON, an integer `datetime` — is `NULL`
///   when the column is nullable, else omitted, so the column's own default applies on create rather
///   than an invented `0`, and an update leaves it alone.
/// - A `datetime` column is wall-clock time in `tz`.
/// - `Int` / `Float` / `Json` are parsed; what doesn't parse is sent as the string, so the engine's
///   coercion names the field and the problem rather than this guessing.
/// - `Bool` reads `true` / `1` / `yes` / `y` / `t`, any case. (A form's checkbox posts presence, not
///   text, and never gets here.)
pub(crate) fn field_value(col: &Column, raw: &str, tz: &Tz) -> Option<Value> {
    let Column::Field { logical_type, nullable, write_only, display, .. } = col else {
        return None;
    };
    let datetime = matches!(display, Some(d) if d.is_datetime());
    let cell = raw.trim();
    if cell.is_empty() {
        if *write_only {
            return None;
        }
        let textish = matches!(
            logical_type,
            LogicalType::Text | LogicalType::Uuid | LogicalType::Date | LogicalType::DateTime
        );
        return match (textish && !datetime, nullable) {
            (true, _) => Some(json!("")),
            (false, true) => Some(Value::Null),
            (false, false) => None,
        };
    }
    Some(match (datetime, logical_type) {
        (true, _) => tz.parse(cell).map(|s| json!(s)).unwrap_or_else(|| json!(cell)),
        (_, LogicalType::Int) => cell.parse::<i64>().map(|n| json!(n)).unwrap_or_else(|_| json!(cell)),
        (_, LogicalType::Float) => cell.parse::<f64>().map(|n| json!(n)).unwrap_or_else(|_| json!(cell)),
        (_, LogicalType::Json) => serde_json::from_str(raw).unwrap_or_else(|_| json!(raw)),
        (_, LogicalType::Bool) => {
            json!(matches!(cell.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "y" | "t"))
        }
        // Text, as typed — surrounding spaces included; trimming is a validator's call, not ours.
        _ => json!(raw),
    })
}
