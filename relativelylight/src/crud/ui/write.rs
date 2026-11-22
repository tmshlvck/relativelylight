//! The write path every surface shares: CSRF check, what the surface offers, gate, apply, audit,
//! and where to go next. One function, which is why the negative cases only have to be tested
//! once (`crud::gate_tests`).

use super::decode::{self, Posted};
use super::render;
use super::state::{Done, Mode, ViewState};
use super::Outcome;
use crate::authz::{Decision, Operation};
use crate::crud::{Cardinality, Column, Engine, Error, ListQuery, Result, ValidationErrors};
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
    /// The view's pins: `Table::fixed_filter` values every create, update and import writes, and
    /// `Table::fixed_in` sets each one must hold a value in. An update or delete of one row is
    /// refused unless the row is inside them — the other half of the form not rendering them.
    pub(crate) pins: crate::crud::text::Pins,
    /// The writes this surface offers. Anything else is refused before the gate is asked: a
    /// control the page doesn't draw must not be reachable by posting its name.
    pub(crate) writes: Writes,
}

/// Which writes a surface accepts. The gate still decides each one; this only narrows it.
#[derive(Clone, Copy)]
pub(crate) struct Writes {
    pub(crate) create: bool,
    pub(crate) update: bool,
    pub(crate) delete: bool,
    /// Delete selected and delete all matching.
    pub(crate) bulk_delete: bool,
    pub(crate) import: bool,
}

/// CSRF check → offered here? → gate → apply → audit → where to go next. One function for every
/// write the UI does, which is why the negative cases only have to be tested once
/// (`crud::gate_tests`).
pub(crate) async fn apply(
    s: &Surface<'_>,
    cols: &[Column],
    headers: &HeaderMap,
    client_ip: IpAddr,
    posted: &Posted,
    state: &ViewState,
) -> Result<Outcome> {
    let op = Op::of(posted)?;
    if !s.engine.csrf_ok(headers, posted.one("_csrf")) {
        return Err(Error::Csrf);
    }
    if !op.offered(&s.writes) {
        return Err(Error::Forbidden);
    }
    authorize(s.engine, op.operation(), s.slug, headers).await?;

    let tz = Tz::from_headers(headers);
    // The one error that isn't an error: re-render the dialog with the messages and the operator's
    // input still in it.
    let reject = |errors: ValidationErrors, mode: Mode| {
        Ok(Outcome::Invalid(state.with_rejection(errors, posted.values(), mode)))
    };
    let applied = match &op {
        Op::Create | Op::Update => {
            let creating = matches!(op, Op::Create);
            let id = posted.one("_id").unwrap_or("").to_string();
            let mode = if creating { Mode::New } else { Mode::Edit(id.clone()) };
            match save(s, cols, posted, &tz, creating, &id).await {
                Err(Error::Validation(errors)) => return reject(errors, mode),
                other => other?,
            }
        }
        Op::DeleteOne(id) => {
            in_view(s.engine, s.slug, &s.pins, id).await?;
            let row = s.engine.delete(s.slug, id).await?;
            Applied {
                // Also as `gone`, so an observer reads one field for every delete.
                gone: vec![row.clone()],
                before: Some(row),
                after: None,
                key: Some(id.clone()),
                done: Some(Done::Deleted(1)),
            }
        }
        Op::DeleteSelected | Op::DeleteAll => {
            let mut q = s.query.clone();
            if matches!(op, Op::DeleteAll) {
                q.all = true; // this view's filters still apply — the button says "matching"
            } else {
                q.pk_in = posted.all("ids").iter().map(|s| s.to_string()).collect();
                if q.pk_in.is_empty() {
                    return Ok(Outcome::Done(format!("?{}", state.to_query())));
                }
            }
            let gone = s.engine.delete_where(s.slug, &q).await?;
            Applied {
                before: None,
                after: Some(serde_json::json!({ "deleted": gone.len() })),
                key: None,
                done: Some(Done::Deleted(gone.len() as u64)),
                gone,
            }
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
                        return reject(errors, Mode::Import);
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
            Applied {
                done: Some(Done::Imported {
                    created: report.get("created").and_then(Value::as_u64).unwrap_or(0),
                    updated: report.get("updated").and_then(Value::as_u64).unwrap_or(0),
                }),
                before: None,
                after: Some(report),
                key: None,
                gone: Vec::new(),
            }
        }
    };
    s.engine
        .observe(crate::observe::WriteEvent {
            source: "autocrud",
            op: op.operation(),
            entity: s.slug,
            key: applied.key.clone(),
            before: applied.before,
            after: applied.after,
            before_rows: &applied.gone,
            actor: None, // the gate resolved the caller; `crud` never names one
            headers,
            client_ip,
        })
        .await;

    // Back to the list the write came from: the view's own query, plus either a one-shot report of
    // what happened or an anchor onto the row that changed.
    let mut target = format!("?{}", state.to_query());
    if let Some(done) = applied.done {
        let separator = if target.ends_with('?') { "" } else { "&" };
        target.push_str(&format!("{separator}done={}", done.query()));
    }
    // A saved row is still on the list; a deleted one isn't.
    let saved = applied.key.filter(|k| matches!(op, Op::Create | Op::Update) && !k.is_empty());
    if let Some(key) = saved {
        target.push_str(&format!("#row-{key}"));
    }
    Ok(Outcome::Done(target))
}

/// What a write did: for the observer, and for the redirect back to the list.
struct Applied {
    before: Option<Value>,
    after: Option<Value>,
    /// Every row a delete removed, whichever of the three delete paths it took — see
    /// `observe::WriteEvent::before_rows`. Empty for anything that is not a delete.
    gone: Vec<Value>,
    /// The row written or deleted; a saved one is also the anchor the redirect scrolls to.
    key: Option<String>,
    done: Option<Done>,
}

/// A create (`creating`) or an update of row `id`, from the posted form. A refusal beside the
/// fields — a value outside a set pin, a relation naming no row, the engine's own validation — is
/// `Err(Error::Validation)`, which [`apply`] turns into the re-rendered dialog.
async fn save(
    s: &Surface<'_>,
    cols: &[Column],
    posted: &Posted,
    tz: &Tz,
    creating: bool,
    id: &str,
) -> Result<Applied> {
    let mut write_body = decode::to_write_body(cols, s.renders, posted, tz);
    if !creating {
        // The edit form doesn't render a create-only field; whatever was posted for one is
        // dropped rather than refused, so a stale or hand-made form still saves the rest.
        if let Some(body) = write_body.as_object_mut() {
            for c in cols {
                if let Column::Field { name, create_only: true, .. } = c {
                    body.remove(name);
                }
            }
        }
    }
    s.pins.apply(&mut write_body, cols, tz);
    if !creating {
        in_view(s.engine, s.slug, &s.pins, id).await?;
    }
    // A set pin refuses a value outside it the way a validator would: beside the field, with the
    // operator's input kept. Checked before the backend sees the body, so a write that would move
    // a row out of the view never happens.
    let outside = s.pins.refusals(&write_body, cols, creating);
    if !outside.is_empty() {
        let mut errors = ValidationErrors::new();
        for (name, message) in outside {
            errors.field(&name, message);
        }
        return Err(Error::Validation(errors));
    }
    let unknown = unknown_references(s.engine, cols, &write_body, posted).await?;
    if !unknown.is_empty() {
        return Err(Error::Validation(unknown));
    }
    let (before, row) = match creating {
        true => (None, s.engine.create(s.slug, &write_body).await?),
        false => {
            let before = s.engine.get(s.slug, id).await.ok();
            (before, s.engine.update(s.slug, id, &write_body).await?)
        }
    };
    let key = render::text(row.get(&s.engine.pk(s.slug)?));
    Ok(Applied { before, after: Some(row), gone: Vec::new(), key: Some(key), done: None })
}

/// Refuse a row a view's pins leave out — a `404`, as the row isn't there as far as this view is
/// concerned: a one-row write, or `?edit=`/`?show=` with another parent's id.
pub(crate) async fn in_view(
    engine: &Engine,
    slug: &str,
    pins: &crate::crud::text::Pins,
    id: &str,
) -> Result<()> {
    match engine.outside(slug, pins, &[id.to_string()]).await?.is_empty() {
        true => Ok(()),
        false => Err(Error::NotFound),
    }
}

/// A relation value that names no row of its target, as a field error rather than whatever the
/// database makes of a dangling foreign key — which, without foreign-key enforcement (SQLite's
/// default), is a row pointing at nothing. A picker posts its selection as hidden inputs, and those
/// are as editable as any typed id, so both cardinalities are checked.
async fn unknown_references(
    engine: &Engine,
    cols: &[Column],
    body: &Value,
    posted: &Posted,
) -> Result<ValidationErrors> {
    let mut errors = ValidationErrors::new();
    for col in cols {
        let Column::Relation { name, target, cardinality, .. } = col else { continue };
        let ids: Vec<String> = match (cardinality, body.get(name)) {
            (_, None | Some(Value::Null)) => continue,
            (Cardinality::ToMany, Some(Value::Array(items))) => {
                items.iter().map(|v| render::text(Some(v))).collect()
            }
            (_, Some(one)) => vec![render::text(Some(one))],
        };
        if ids.is_empty() {
            continue;
        }
        let missing: Vec<String> = render::lookup(engine, target, &ids)
            .await?
            .into_iter()
            .filter_map(|(id, label)| label.is_none().then_some(id))
            .collect();
        if !missing.is_empty() {
            // A to-one says what was typed; a to-many names the ids, since nothing was typed.
            let shown = match cardinality {
                Cardinality::ToOne => posted.one(name).unwrap_or("").trim().to_string(),
                Cardinality::ToMany => missing.join("', '"),
            };
            errors.field(name, format!("no {target} matches '{shown}'"));
        }
    }
    Ok(errors)
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

async fn import_csv(s: &Surface<'_>, cols: &[Column], text: &str, tz: &Tz) -> Result<Value> {
    let report = crate::crud::csv_io::import_pinned(s.engine, s.slug, cols, text, tz, &s.pins).await?;
    serde_json::to_value(&report).map_err(|e| Error::Backend(e.to_string()))
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
            other => Err(Error::BadRequest(format!("crud: unknown form operation '{other}'"))),
        }
    }

    fn offered(&self, w: &Writes) -> bool {
        match self {
            Op::Create => w.create,
            Op::Update => w.update,
            Op::DeleteOne(_) => w.delete,
            Op::DeleteSelected | Op::DeleteAll => w.bulk_delete,
            Op::Import => w.import,
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

/// The hidden `_csrf` value, or empty when this engine enforces no token. The **cookie** must already
/// exist — `auth`'s login issues it; an app without `auth` calls `Csrf::ensure` when rendering the
/// page (see `docs/AUTH.md` §7).
pub(crate) fn csrf_token(engine: &Engine, headers: &HeaderMap) -> String {
    engine.csrf().and_then(|c| c.token(headers)).unwrap_or_default()
}

