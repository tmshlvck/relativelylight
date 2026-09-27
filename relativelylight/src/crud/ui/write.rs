//! The write path every surface shares: CSRF check, gate, apply, audit, and where to go next. One
//! function, which is why the negative cases only have to be tested once (`crud::gate_tests`).

use super::decode::{self, Posted};
use super::render;
use super::state::{Done, Mode, ViewState};
use super::Outcome;
use crate::authz::{Decision, Operation};
use crate::crud::engine::{Column, Engine, Error, ListQuery, Result, ValidationErrors};
use crate::time::Tz;
use http::HeaderMap;
use serde_json::Value;
use std::net::IpAddr;

/// What `write` needs to know about the surface a body was posted from.
pub(crate) struct Surface<'a> {
    pub(crate) engine: &'a Engine,
    pub(crate) slug: &'a str,
    /// Which columns the form rendered — a crafted body naming another one is ignored.
    pub(crate) renders: &'a (dyn Fn(&str) -> bool + Send + Sync),
    /// The view's own query, so a bulk delete can only ever hit the rows on screen.
    pub(crate) query: ListQuery,
}

/// CSRF check → gate → apply → audit → where to go next. One function for every write the UI does,
/// which is why the negative cases only have to be tested once (`crud::gate_tests`).
pub(crate) async fn apply(
    s: &Surface<'_>,
    cols: &[Column],
    headers: &HeaderMap,
    client_ip: IpAddr,
    body: &[u8],
    state: &ViewState,
) -> Result<Outcome> {
    let posted = Posted::read(headers, body)?;
    let op = Op::of(&posted)?;
    if !s.engine.csrf_ok(headers, posted.one("_csrf")) {
        return Err(Error::Csrf);
    }
    authorize(s.engine, op.operation(), s.slug, headers).await?;

    let tz = Tz::from_headers(headers);
    let mut anchor = String::new();
    let mut done: Option<Done> = None;
    // Every row a delete removed, whichever of the three delete paths it took — see
    // `observe::WriteEvent::before_rows`. Empty for anything that is not a delete.
    let mut gone: Vec<Value> = Vec::new();
    let (before, after, key) = match &op {
        Op::Create | Op::Update => {
            let id = posted.one("_id").unwrap_or("").to_string();
            let write_body = decode::to_write_body(cols, s.renders, &posted, &tz);
            let mode = if matches!(op, Op::Create) {
                Mode::New
            } else {
                Mode::Edit(id.clone())
            };
            let outcome = match &op {
                Op::Create => s.engine.create(s.slug, &write_body).await.map(|row| (None, row)),
                _ => {
                    let before = s.engine.get(s.slug, &id).await.ok();
                    s.engine.update(s.slug, &id, &write_body).await.map(|row| (before, row))
                }
            };
            match outcome {
                Ok((before, row)) => {
                    anchor = render::text(row.get(&s.engine.pk(s.slug)?));
                    (before, Some(row), Some(anchor.clone()))
                }
                // The one error that isn't an error: re-render the dialog with the messages and the
                // operator's input still in it.
                Err(Error::Validation(errors)) => {
                    return Ok(Outcome::Invalid(state.with_rejection(
                        errors,
                        posted.values(),
                        mode,
                    )))
                }
                Err(e) => return Err(e),
            }
        }
        Op::DeleteOne(id) => {
            let row = s.engine.delete(s.slug, id).await?;
            done = Some(Done::Deleted(1));
            // Also as `before_rows`, so an observer reads one field for every delete.
            gone = vec![row.clone()];
            (Some(row), None, Some(id.clone()))
        }
        Op::DeleteSelected => {
            let ids: Vec<String> = posted.all("ids").iter().map(|s| s.to_string()).collect();
            if ids.is_empty() {
                return Ok(Outcome::Done(format!("?{}", state.to_query())));
            }
            let mut q = s.query.clone();
            q.pk_in = ids;
            gone = s.engine.delete_where(s.slug, &q).await?;
            done = Some(Done::Deleted(gone.len() as u64));
            (None, Some(serde_json::json!({ "deleted": gone.len() })), None)
        }
        Op::DeleteAll => {
            let mut q = s.query.clone();
            q.all = true; // this view's filters still apply — the button says "matching"
            gone = s.engine.delete_where(s.slug, &q).await?;
            done = Some(Done::Deleted(gone.len() as u64));
            (None, Some(serde_json::json!({ "deleted": gone.len() })), None)
        }
        Op::Import => {
            // The file the operator chose, read as bytes on the server — or, if they pasted
            // instead, the textarea. Either way it is the same import from here on.
            let text = match posted.file("file") {
                Some(bytes) => match csv_text(bytes) {
                    Ok(text) => text,
                    Err(why) => {
                        let mut errors = ValidationErrors::new();
                        errors.general(why);
                        return Ok(Outcome::Invalid(state.with_rejection(
                            errors,
                            posted.values(),
                            Mode::Import,
                        )));
                    }
                },
                None => posted.one("csv").unwrap_or("").to_string(),
            };
            let report = import_csv(s, cols, &text, &tz).await?;
            // The import is all-or-nothing, so a file with bad rows applied *nothing* — say so, in
            // the dialog, with the text still in it. Redirecting to an unchanged list would look
            // like the import had worked.
            if let Some(errors) = import_rejection(&report) {
                // Put the rows back in the dialog's box, however they arrived, so the operator can
                // fix a cell instead of re-picking a file they can no longer see.
                let mut values = posted.values();
                values.insert("csv".to_string(), vec![text]);
                return Ok(Outcome::Invalid(state.with_rejection(errors, values, Mode::Import)));
            }
            done = Some(Done::Imported {
                created: report.get("created").and_then(Value::as_u64).unwrap_or(0),
                updated: report.get("updated").and_then(Value::as_u64).unwrap_or(0),
            });
            (None, Some(report), None)
        }
    };
    notify(s.engine, op.operation(), s.slug, key.as_deref(), before.as_ref(), after.as_ref(), &gone, headers, client_ip)
        .await;

    // Back to the list the write came from: the view's own query, plus either a one-shot report of
    // what happened or an anchor onto the row that changed.
    let mut target = format!("?{}", state.to_query());
    if let Some(done) = done {
        let separator = if target.ends_with('?') { "" } else { "&" };
        target.push_str(&format!("{separator}done={}", done.query()));
    }
    if !anchor.is_empty() {
        target.push_str(&format!("#row-{anchor}"));
    }
    Ok(Outcome::Done(target))
}

/// An uploaded file's bytes as CSV text: a UTF-8 BOM (what a spreadsheet writes) is dropped, and
/// anything that isn't UTF-8 is refused by name rather than imported as mojibake — the operator
/// can't see the file before it applies, so a wrong guess would reach the database unnoticed.
fn csv_text(bytes: &[u8]) -> std::result::Result<String, String> {
    let bytes = bytes.strip_prefix("\u{feff}".as_bytes()).unwrap_or(bytes);
    String::from_utf8(bytes.to_vec()).map_err(|e| {
        format!(
            "That file isn't valid UTF-8 (byte {}). Re-save it as UTF-8 — a spreadsheet calls this \
             \"CSV UTF-8\" — or paste the rows below.",
            e.utf8_error().valid_up_to()
        )
    })
}

/// A CSV import's per-row failures as messages for the dialog's banner, or `None` if it applied.
/// Each carries the 1-based line, so a spreadsheet is fixed once rather than per re-upload.
fn import_rejection(report: &Value) -> Option<ValidationErrors> {
    let failed = report.get("failed").and_then(Value::as_u64).unwrap_or(0);
    if failed == 0 {
        return None;
    }
    let mut errors = ValidationErrors::new();
    errors.general(format!("{failed} row(s) rejected — nothing was imported."));
    for e in report.get("errors").and_then(Value::as_array).into_iter().flatten() {
        let row = e.get("row").and_then(Value::as_u64).unwrap_or(0);
        let message = e.get("message").and_then(Value::as_str).unwrap_or("invalid");
        errors.general(format!("line {row}: {message}"));
    }
    Some(errors)
}

#[cfg(feature = "csv")]
async fn import_csv(s: &Surface<'_>, cols: &[Column], text: &str, tz: &Tz) -> Result<Value> {
    let report = crate::crud::csv_io::import(s.engine, s.slug, cols, text, tz).await?;
    serde_json::to_value(&report).map_err(|e| Error::Backend(e.to_string()))
}

#[cfg(not(feature = "csv"))]
async fn import_csv(_s: &Surface<'_>, _cols: &[Column], _text: &str, _tz: &Tz) -> Result<Value> {
    Err(Error::BadRequest("CSV import needs the `csv` feature".into()))
}

/// The operations a posted body can ask for. `_del=<id>` is its own key rather than an `_op` value
/// because a `<button>` submits one name/value pair, and a per-row delete needs to say which row.
enum Op {
    Create,
    Update,
    DeleteOne(String),
    DeleteSelected,
    DeleteAll,
    Import,
}

impl Op {
    fn of(posted: &Posted) -> Result<Op> {
        if let Some(id) = posted.one("_del") {
            return Ok(Op::DeleteOne(id.to_string()));
        }
        match posted.one("_op").unwrap_or("") {
            "create" => Ok(Op::Create),
            "update" => Ok(Op::Update),
            "delete_selected" => Ok(Op::DeleteSelected),
            "delete_all" => Ok(Op::DeleteAll),
            "import" => Ok(Op::Import),
            other => Err(Error::BadRequest(format!("crud::ui: unknown form operation '{other}'"))),
        }
    }

    fn operation(&self) -> Operation {
        match self {
            Op::Create | Op::Import => Operation::Create,
            Op::Update => Operation::Update,
            Op::DeleteOne(_) | Op::DeleteSelected | Op::DeleteAll => Operation::Delete,
        }
    }
}

/// Consult the model's gate and map the decision to `401`/`403`.
pub(crate) async fn authorize(
    engine: &Engine,
    op: Operation,
    slug: &str,
    headers: &HeaderMap,
) -> Result<()> {
    match engine.decide(slug, op, headers).await {
        Decision::Allow => Ok(()),
        Decision::NeedsLogin => Err(Error::Unauthorized),
        Decision::Denied => Err(Error::Forbidden),
    }
}

#[allow(clippy::too_many_arguments)]
async fn notify(
    engine: &Engine,
    op: Operation,
    entity: &str,
    key: Option<&str>,
    before: Option<&Value>,
    after: Option<&Value>,
    before_rows: &[Value],
    headers: &HeaderMap,
    client_ip: IpAddr,
) {
    engine
        .observe(crate::observe::WriteEvent {
            source: "autocrud",
            op,
            entity,
            key: key.map(str::to_string),
            before: before.cloned(),
            after: after.cloned(),
            before_rows,
            headers,
            client_ip,
        })
        .await;
}

/// The hidden `_csrf` value, or empty when this engine enforces no token. The **cookie** must already
/// exist — `auth`'s login issues it; an app without `auth` calls `Csrf::ensure` when rendering the
/// page (see `docs/AUTH.md` §7).
#[cfg(feature = "csrf")]
pub(crate) fn csrf_token(engine: &Engine, headers: &HeaderMap) -> String {
    engine.csrf().and_then(|c| c.token(headers)).unwrap_or_default()
}

#[cfg(not(feature = "csrf"))]
pub(crate) fn csrf_token(_engine: &Engine, _headers: &HeaderMap) -> String {
    String::new()
}

