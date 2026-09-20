//! Backend-agnostic core: the `Accessor` seam, the contract types, and the `Engine` that composes
//! accessors into one registry.
//!
//! The engine is deliberately thin: it holds the registry of entities, consults each model's
//! authorization gate, and forwards data to and from accessors. Every backend (SeaORM today; memory /
//! no-SQL / filesystem later) hands it **finished rows** — already projected (visible fields,
//! transforms applied) with relations embedded as `{id, label}`. All the heavy lifting lives in the
//! backend, and all rendering lives in [`crud::ui`](crate::crud::ui).
//!
//! Everything here is **typed and in-process**: there is no JSON/metadata API any more, so
//! `Vec<Column>` + [`Page`] go straight from the accessor to the renderer without a wire format in
//! between (see `docs/MIGRATION-0.3.md`). An app that wants to publish its own JSON API writes the handlers and calls
//! these same methods.

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

// ===================== Errors =====================

/// Structured validation errors: field-keyed + cross-field/general messages. **`#[non_exhaustive]`** —
/// build one with [`ValidationErrors::new`], which was always the intended path.
#[derive(Debug, Default, Clone, Serialize)]
#[non_exhaustive]
pub struct ValidationErrors {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

impl ValidationErrors {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn field(&mut self, name: impl Into<String>, msg: impl Into<String>) {
        self.fields.insert(name.into(), msg.into());
    }
    pub fn general(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
    }
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.errors.is_empty()
    }
}

/// An engine failure, as the HTTP layer renders it. **`#[non_exhaustive]`**: variants do get added
/// (`Csrf` was, this cycle), so a `match` on this in your code wants a `_` arm and then won't break when
/// the next one arrives.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Backend(String),
    NotFound,
    ReadOnly,
    BadRequest(String),
    Validation(ValidationErrors),
    /// A database constraint (unique / foreign-key) rejected the write → 409.
    Conflict(String),
    /// The operation needs a logged-in user but the request is anonymous → 401.
    Unauthorized,
    /// Authenticated but not permitted → 403.
    Forbidden,
    /// A cookie-authenticated write without a valid CSRF token → 403 (see [`crate::csrf`]).
    Csrf,
    /// A batch write ([`Accessor::write_batch`]) was rejected and **nothing was applied** — the offending
    /// rows by index, so a CSV import can point at lines. Carries the errors themselves rather than
    /// rendered strings, so the caller chooses how to show them ([`Error::one_line`]). → 422.
    BatchRejected(Vec<(usize, Error)>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Backend(e) => write!(f, "backend error: {e}"),
            Error::NotFound => write!(f, "not found"),
            Error::ReadOnly => write!(f, "read-only"),
            Error::BadRequest(m) => write!(f, "bad request: {m}"),
            Error::Validation(_) => write!(f, "validation failed"),
            Error::Conflict(m) => write!(f, "conflict: {m}"),
            Error::Unauthorized => write!(f, "unauthorized"),
            Error::Forbidden => write!(f, "forbidden"),
            Error::Csrf => write!(f, "csrf token missing or invalid"),
            Error::BatchRejected(rows) => write!(f, "{} row(s) rejected; nothing applied", rows.len()),
        }
    }
}

impl Error {
    /// This error as **one line**, flattening a [`Validation`](Error::Validation)'s field messages into
    /// `field: message; field: message`. `Display` says only "validation failed", which is useless in a
    /// per-row report where the whole point is which cell is wrong.
    pub fn one_line(&self) -> String {
        match self {
            Error::Validation(v) => {
                let mut parts: Vec<String> =
                    v.fields.iter().map(|(k, m)| format!("{k}: {m}")).collect();
                parts.extend(v.errors.iter().cloned());
                if parts.is_empty() {
                    "validation failed".into()
                } else {
                    parts.join("; ")
                }
            }
            other => other.to_string(),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

// ===================== Contract types =====================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicalType {
    Int,
    Float,
    Bool,
    Text,
    Date,
    DateTime,
    Uuid,
    Json,
    Enum,
    Other,
}

/// Optional presentation hint overriding how the UI renders a field (the default is derived from the
/// [`LogicalType`]). The stored value, validation, and OpenAPI schema are unaffected — only the admin
/// table cell and the **form input** change.
///
/// Set it through the [`MetaField`](crate::crud::seaorm::MetaField) helpers rather than by hand:
/// `.datetime()`, `.textarea(rows)`, `.radio()`, `.range(min, max, step)`, `.email()`, `.url()`.
///
/// Every variant but [`DateTime`](FieldDisplay::DateTime) affects **only the form input** — a cell keeps
/// rendering the plain value, because a table row is not a place for a slider.
///
/// A widget that can't render its column is a **render-time error naming the field** (a `Radio` with no
/// `options`, a `Range` on text, a `Textarea` on a number) rather than a silently different input — see
/// [`fits`](FieldDisplay::fits).
///
/// **`#[non_exhaustive]`**, for the same reason as [`LogicalType`]: more of these are likely (currency,
/// percentage, colour, …), and an out-of-crate `match` shouldn't break when one arrives.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum FieldDisplay {
    /// An integer column holding **Unix seconds (UTC)**: the cell shows a readable UTC datetime and
    /// the form offers a datetime picker (edited in UTC), storing back the integer seconds.
    DateTime,
    /// A multi-line `<textarea>` of `rows` rows, for prose — the one override almost every app wants.
    Textarea { rows: u16 },
    /// A radio group over the column's `options`, instead of a `<select>`: better for a handful of
    /// choices where seeing them all at once matters. Requires a non-empty `options`.
    Radio,
    /// A slider over a numeric column. `step` may be fractional for a `Float`.
    Range { min: f64, max: f64, step: f64 },
    /// `<input type="email">` — the browser's own validation and the right mobile keyboard. Pair it with
    /// [`validate::email`](crate::validate::email), which is the check that actually runs server-side.
    Email,
    /// `<input type="url">`, as [`Email`](FieldDisplay::Email) but for links.
    Url,
}

impl FieldDisplay {
    /// The wire tag published in `display`.
    pub fn tag(self) -> &'static str {
        match self {
            FieldDisplay::DateTime => "datetime",
            FieldDisplay::Textarea { .. } => "textarea",
            FieldDisplay::Radio => "radio",
            FieldDisplay::Range { .. } => "range",
            FieldDisplay::Email => "email",
            FieldDisplay::Url => "url",
        }
    }

    /// Whether this is the integer-Unix-seconds datetime override — asked often enough by the
    /// renderer and the form decoder to be worth a name.
    pub fn is_datetime(self) -> bool {
        matches!(self, FieldDisplay::DateTime)
    }

    /// Whether this widget can render a column of `lt` (given whether it has a closed option set).
    /// `Err` carries the reason, for a render-time error that names the field instead of quietly
    /// falling back to a different input.
    pub fn fits(self, lt: LogicalType, has_options: bool) -> std::result::Result<(), String> {
        let textish = matches!(lt, LogicalType::Text | LogicalType::Json | LogicalType::Other);
        match self {
            // The picker reads the value as integer seconds, so a string column would arrive as NaN.
            FieldDisplay::DateTime if !matches!(lt, LogicalType::Int) => {
                Err("`datetime` needs an integer column holding Unix seconds".into())
            }
            FieldDisplay::Textarea { .. } | FieldDisplay::Email | FieldDisplay::Url if !textish => {
                Err(format!("`{}` needs a text column, not {lt:?}", self.tag()))
            }
            FieldDisplay::Radio if !has_options => {
                Err("`radio` needs `options` — there is nothing to list".into())
            }
            FieldDisplay::Range { .. } if !matches!(lt, LogicalType::Int | LogicalType::Float) => {
                Err(format!("`range` needs a numeric column, not {lt:?}"))
            }
            FieldDisplay::Range { min, max, .. } if min >= max => {
                Err(format!("`range` needs min < max (got {min} and {max})"))
            }
            _ => Ok(()),
        }
    }
}

impl LogicalType {
    pub fn is_text(self) -> bool {
        matches!(self, LogicalType::Text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cardinality {
    ToOne,
    ToMany,
}

/// One entry in an entity's published shape — a scalar field or a relation — **backend-agnostic**.
/// The [`Accessor`] produces these and [`crud::ui`](crate::crud::ui) renders tables and forms straight
/// from them: one `match` per cell and per form input, checked by the compiler.
///
/// (A to-many relation is not a database column, but it *is* one of these entries.) Note this is the
/// shape the engine **reports**; the thing you *configure* is
/// [`MetaField`](crate::crud::seaorm::MetaField), which is a different direction despite the family
/// resemblance the old name `ColumnMeta` implied.
///
/// **`#[non_exhaustive]` covers new *variants*, not new *fields*.** A non-exhaustive enum *variant*
/// cannot be constructed from another crate at all, which would make [`Accessor`] unimplementable
/// outside this one; since producing these values is that trait's whole job, the variants stay open. So
/// adding a field here is a source break for an out-of-crate `Accessor` or an exhaustive `match` — which
/// is acceptable because the seam is no longer a stability promise (see [`Accessor`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Column {
    Field {
        name: String,
        logical_type: LogicalType,
        read_only: bool,
        write_only: bool,
        /// Whether the column accepts SQL NULL. Drives the UI's "empty means nothing here" handling
        /// (an empty input on a nullable column is sent as `null`, not `""`) and the schema's type
        /// union.
        nullable: bool,
        /// Whether a create must carry this field — NOT NULL, no default, writable. The engine enforces
        /// it (a `422` naming the field, rather than the database's `500`), the form marks it, and OpenAPI
        /// lists it in the create schema's `required`. See
        /// [`MetaField::required`](crate::crud::seaorm::MetaField::required).
        required: bool,
        /// The allowed values when this column is an enumeration, else empty. Drives a `<select>` in the
        /// form, `enum` in the OpenAPI schema, and a membership check on write. See
        /// [`MetaField::options`](crate::crud::seaorm::MetaField::options).
        options: Vec<String>,
        label: Option<String>,
        description: Option<String>,
        default: Option<Value>,
        /// Presentation override (e.g. render an int-seconds column as a datetime).
        display: Option<FieldDisplay>,
        /// Whether `?sort=<name>` is accepted. False for `Json`/`Other`, whose ordering the database
        /// would happily invent but nobody could predict.
        sortable: bool,
    },
    Relation {
        name: String,
        /// The target entity's **slug** (the backend resolves the table→slug mapping).
        target: String,
        cardinality: Cardinality,
        /// For an owned to-one, the FK column on this entity (informational; for the UI/OpenAPI).
        fk_column: Option<String>,
        read_only: bool,
        label: Option<String>,
        description: Option<String>,
        /// Whether `?sort=<name>` is accepted — i.e. whether the label shown in the cell can be
        /// expressed as an `ORDER BY` on the target. True only for a to-one that owns its FK *and*
        /// whose target has a known label column (see
        /// [`MetaModel::label_column`](crate::crud::seaorm::MetaModel::label_column)). A to-many has
        /// many labels per row, so there is no ordering to give.
        sortable: bool,
    },
}

/// A list / bulk-delete query. **`#[non_exhaustive]`** — start from
/// [`Default`](ListQuery::default) and assign what you need, so a field added later (a cursor, say)
/// doesn't break you.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct ListQuery {
    /// Search: `Some(col)` filters a column with LIKE, `None` is full-text across text columns.
    pub search: Vec<(Option<String>, String)>,
    /// Exact-match filters `column == value`.
    pub eq: Vec<(String, String)>,
    /// Restrict to these primary-key values (`pk IN (...)`) — e.g. "delete selected".
    pub pk_in: Vec<String>,
    /// Sort keys `(column, descending)`.
    pub sort: Vec<(String, bool)>,
    pub page: u64,
    pub per_page: u64,
    /// Operate on the whole matching set: on `list` return every row unpaginated; on a bulk delete
    /// permit wiping the (unfiltered) table.
    pub all: bool,
}

/// One row in a listing: its id, display label, and (unless terse) the finished row object.
///
/// **`#[non_exhaustive]` plus a constructor**, because an [`Accessor`] outside this crate has to be able
/// to produce one — marking it non-exhaustive without [`RowItem::new`] would make the seam
/// unimplementable, which is the opposite of the point.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RowItem {
    pub id: Value,
    pub label: String,
    pub row: Option<Value>,
}

impl RowItem {
    /// A listing row: primary key, display label, and the finished row — `None` when the caller asked
    /// for a terse listing (a relation picker, which needs only id + label).
    pub fn new(id: Value, label: String, row: Option<Value>) -> Self {
        Self { id, label, row }
    }
}

/// One page of a listing. **`#[non_exhaustive]`** with a constructor, for the same reason as
/// [`RowItem`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Page {
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
    pub data: Vec<RowItem>,
}

impl Page {
    /// `total` counts every *matching* row, not the rows in `data`, so a client can size a pager.
    pub fn new(total: u64, page: u64, per_page: u64, data: Vec<RowItem>) -> Self {
        Self { total, page, per_page, data }
    }
}

// ===================== Shared helpers =====================

/// Type-check a JSON value against a logical type; returns normalized JSON or an error string.
pub fn coerce(lt: LogicalType, v: &Value) -> std::result::Result<Value, String> {
    if v.is_null() {
        return Ok(Value::Null);
    }
    let ok = match lt {
        LogicalType::Int => v.is_i64() || v.is_u64(),
        LogicalType::Float => v.is_number(),
        LogicalType::Bool => v.is_boolean(),
        LogicalType::Text | LogicalType::Uuid | LogicalType::Date | LogicalType::DateTime => {
            v.is_string()
        }
        LogicalType::Json | LogicalType::Enum | LogicalType::Other => true,
    };
    if ok {
        Ok(v.clone())
    } else {
        Err(format!("expected {lt:?}"))
    }
}

/// Normalize a name into a URL-safe snake_case slug: `BlogPost` → `blog_post`.
pub fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_alnum_lower = false;
    for ch in s.chars() {
        if ch.is_ascii_uppercase() {
            if prev_alnum_lower {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            prev_alnum_lower = false;
        } else if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_alnum_lower = true;
        } else {
            if prev_alnum_lower {
                out.push('_');
            }
            prev_alnum_lower = false;
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        s.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Default row label: first present conventional field, else PK.
pub fn default_label(v: &Value) -> String {
    for key in ["name", "title", "username", "bio", "label"] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            return s.to_string();
        }
    }
    match v.get("id") {
        Some(id) => format!("#{id}"),
        None => v.to_string(),
    }
}

/// URL-safe key string for a JSON scalar.
pub(crate) fn value_key(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

// ===================== The Accessor seam =====================

/// The meeting point between a backend (SeaORM / memory / no-SQL / …) and the generic engine.
/// One instance per entity; owns its own handle, so this interface names no ORM types. Every data
/// method returns **finished rows**: already projected (visible fields, `on_read` applied) with
/// relations resolved to `{id, label}` — the engine forwards them as-is.
///
/// **Not a stability promise.** Its real job is *type erasure*: `Arc<dyn Accessor>` lets one registry
/// hold entities of different Rust types (`SeaAccessor<E>` is generic over the entity), which is why the
/// trait exists even with a single backend. Implement it out-of-crate if you like, but expect it — and
/// [`Column`] — to gain methods and fields in any release.
#[async_trait]
pub trait Accessor: Send + Sync {
    fn slug(&self) -> &str;
    /// The (single) primary-key field name.
    fn pk(&self) -> String;
    /// Backend-agnostic column metadata (fields + relations).
    fn columns(&self) -> Vec<Column>;

    /// A page of rows. `terse` returns only `{id, label}` per item (e.g. relation pickers);
    /// otherwise each item also carries the finished `row`. `ListQuery::all` returns every match.
    async fn list(&self, q: &ListQuery, terse: bool) -> Result<Page>;
    async fn get(&self, pk: &str) -> Result<Option<Value>>;
    async fn create(&self, body: &Value) -> Result<Value>;
    async fn update(&self, pk: &str, body: &Value) -> Result<Option<Value>>;
    /// Delete one row; returns the finished deleted record (or `None` if it didn't exist).
    async fn delete(&self, pk: &str) -> Result<Option<Value>>;
    /// Delete every row matching the query in one set-based operation; returns the count.
    async fn delete_many(&self, q: &ListQuery) -> Result<u64>;

    /// Apply many writes as **one unit**: `Some(pk)` updates that row, `None` creates. Returns what was
    /// applied, or [`Error::BatchRejected`] naming every row that stopped it — in which case **nothing**
    /// was applied.
    ///
    /// This is what makes a CSV import all-or-nothing (`csv_io::import`), and it exists as its own method
    /// because a transaction lives *below* this seam: the engine can't open one, and calling `create` in a
    /// loop can't be atomic however carefully it's done. The finished row is deliberately **not** returned
    /// for each write — resolving relations reads through the connection pool, which would need a second
    /// connection while the batch's transaction holds the first, deadlocking a single-connection pool (an
    /// in-memory SQLite, say). Nothing that imports needs those values anyway.
    ///
    /// **The default implementation is not atomic** — it applies rows one at a time via
    /// [`create`](Accessor::create) / [`update`](Accessor::update) and stops at the first failure, so
    /// earlier rows stay applied. A backend with transactions should override it; the SeaORM one does.
    async fn write_batch(&self, rows: Vec<(Option<String>, Value)>) -> Result<BatchApplied> {
        let mut applied = BatchApplied::default();
        for (i, (pk, body)) in rows.iter().enumerate() {
            let outcome = match pk {
                Some(pk) => self.update(pk, body).await.map(|_| false),
                None => self.create(body).await.map(|_| true),
            };
            match outcome {
                Ok(true) => applied.created += 1,
                Ok(false) => applied.updated += 1,
                Err(e) => return Err(Error::BatchRejected(vec![(i, e)])),
            }
        }
        Ok(applied)
    }
}

/// What a [`write_batch`](Accessor::write_batch) applied. **`#[non_exhaustive]`** — use
/// [`BatchApplied::default`] and add to the counts, as the default `write_batch` does.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BatchApplied {
    pub created: u64,
    pub updated: u64,
}

// ===================== The Engine =====================

pub struct Engine {
    accessors: BTreeMap<String, Arc<dyn Accessor>>,
    /// The authorization gate for each model, keyed by slug (set at registration; `Open` = ungated).
    authz: BTreeMap<String, Arc<dyn crate::authz::Authz>>,
    /// Optional audit sink; fired after each committed write (see [`crate::observe`]).
    observer: Option<Arc<dyn crate::observe::WriteObserver>>,
    /// Optional CSRF checker; when set, every write must carry a valid token (see [`crate::csrf`]).
    #[cfg(feature = "csrf")]
    csrf: Option<crate::csrf::Csrf>,
}

impl Engine {
    /// An empty registry. There is no mount path: a [`crud::ui`](crate::crud::ui) component renders
    /// links relative to whatever URL the app serves it on, so nothing here needs to know that URL.
    pub fn new() -> Self {
        Self {
            accessors: BTreeMap::new(),
            authz: BTreeMap::new(),
            observer: None,
            #[cfg(feature = "csrf")]
            csrf: None,
        }
    }

    /// Register an audit sink fired after each committed write (create/update/delete). See
    /// [`crate::observe`]. Usually set via `Crud::on_write`.
    pub fn set_observer(&mut self, observer: Arc<dyn crate::observe::WriteObserver>) {
        self.observer = Some(observer);
    }

    /// Require a valid CSRF token on every write through this engine — see [`crate::csrf`]. Pass the
    /// app's checker (`auth.csrf()`) so the API and the auth forms share one token cookie. Usually set
    /// via `Crud::csrf`.
    #[cfg(feature = "csrf")]
    pub fn set_csrf(&mut self, csrf: crate::csrf::Csrf) {
        self.csrf = Some(csrf);
    }

    /// Whether this request satisfies the CSRF check (always `true` when CSRF isn't configured).
    /// `form_token` is the `_csrf` field of a posted form — the carrier the UI's own forms use.
    #[cfg(all(feature = "ui", feature = "csrf"))]
    pub(crate) fn csrf_ok(&self, headers: &::http::HeaderMap, form_token: Option<&str>) -> bool {
        match &self.csrf {
            Some(csrf) => csrf.verify(headers, form_token),
            None => true,
        }
    }

    #[cfg(all(feature = "ui", not(feature = "csrf")))]
    pub(crate) fn csrf_ok(&self, _h: &::http::HeaderMap, _form_token: Option<&str>) -> bool {
        true
    }

    /// The CSRF checker this engine enforces, if any — the UI renders its hidden `_csrf` input from it.
    #[cfg(all(feature = "ui", feature = "csrf"))]
    pub(crate) fn csrf(&self) -> Option<&crate::csrf::Csrf> {
        self.csrf.as_ref()
    }

    /// Hand a committed write to the audit sink, if the app registered one. Called by
    /// [`crud::ui`](crate::crud::ui) after each write it applies.
    #[cfg(feature = "ui")]
    pub(crate) async fn observe(&self, event: crate::observe::WriteEvent<'_>) {
        if let Some(observer) = self.observer.as_ref() {
            observer.on_write(&event).await;
        }
    }

    /// The gate governing `slug` (or `None` for an unregistered slug).
    fn authz_for(&self, slug: &str) -> Option<&Arc<dyn crate::authz::Authz>> {
        self.authz.get(slug)
    }

    /// The model's gate [`Decision`](crate::authz::Decision) for `op` on this request — an unregistered
    /// slug is `Denied`. Use this over [`permits`](Engine::permits) when the difference between
    /// "log in" and "not for you" matters: `crud::ui::Form` maps it to `401` vs `403` rather than
    /// rendering a form the caller could never submit.
    pub async fn decide(
        &self,
        slug: &str,
        op: crate::authz::Operation,
        headers: &::http::HeaderMap,
    ) -> crate::authz::Decision {
        match self.authz_for(slug) {
            Some(gate) => gate.authorize(op, headers).await,
            None => crate::authz::Decision::Denied,
        }
    }

    /// Whether the model's gate would allow `op` for this request. Used by the UI to hide write
    /// controls the caller isn't permitted; the API is the actual enforcement point.
    pub async fn permits(
        &self,
        slug: &str,
        op: crate::authz::Operation,
        headers: &::http::HeaderMap,
    ) -> bool {
        matches!(self.decide(slug, op, headers).await, crate::authz::Decision::Allow)
    }

    /// Register an accessor and its authorization gate. Panics on a duplicate slug.
    pub fn add(&mut self, acc: Arc<dyn Accessor>, gate: Arc<dyn crate::authz::Authz>) {
        let slug = acc.slug().to_string();
        if self.accessors.contains_key(&slug) {
            panic!("relativelylight: duplicate slug '{slug}' — set a distinct MetaModel.slug");
        }
        self.authz.insert(slug.clone(), gate);
        self.accessors.insert(slug, acc);
    }

    /// Every registered slug, in registration order.
    pub fn tables(&self) -> Vec<String> {
        self.accessors.keys().cloned().collect()
    }
    fn accessor(&self, slug: &str) -> Result<&Arc<dyn Accessor>> {
        self.accessors.get(slug).ok_or(Error::NotFound)
    }

    /// Typed column metadata for one entity (fields + relations) — what the UI renders from.
    pub fn columns(&self, slug: &str) -> Result<Vec<Column>> {
        Ok(self.accessor(slug)?.columns())
    }

    /// The entity's (single) primary-key field name.
    pub fn pk(&self, slug: &str) -> Result<String> {
        Ok(self.accessor(slug)?.pk())
    }

    // ---- Data (pure forwarding; the backend produces finished rows) ----

    /// One page of rows. `terse` items carry only `id` + `label` (relation pickers and filter
    /// controls); otherwise each item also carries the finished row.
    pub async fn list(&self, slug: &str, q: &ListQuery, terse: bool) -> Result<Page> {
        self.accessor(slug)?.list(q, terse).await
    }

    pub async fn get(&self, slug: &str, pk: &str) -> Result<Value> {
        self.accessor(slug)?.get(pk).await?.ok_or(Error::NotFound)
    }

    pub async fn create(&self, slug: &str, body: &Value) -> Result<Value> {
        self.accessor(slug)?.create(body).await
    }

    pub async fn update(&self, slug: &str, pk: &str, body: &Value) -> Result<Value> {
        self.accessor(slug)?.update(pk, body).await?.ok_or(Error::NotFound)
    }

    pub async fn delete(&self, slug: &str, pk: &str) -> Result<Value> {
        self.accessor(slug)?.delete(pk).await?.ok_or(Error::NotFound)
    }

    /// Apply many writes to one entity as a single unit — see [`Accessor::write_batch`]. Used by CSV
    /// import to make a file all-or-nothing.
    pub async fn write_batch(
        &self,
        slug: &str,
        rows: Vec<(Option<String>, Value)>,
    ) -> Result<BatchApplied> {
        self.accessor(slug)?.write_batch(rows).await
    }

    /// Bulk delete, returning how many rows went. Refuses to wipe the whole (unfiltered) table
    /// unless `q.all` — the flag the UI's "Delete all (N)" button sets and its "Delete selected"
    /// button does not.
    pub async fn delete_where(&self, slug: &str, q: &ListQuery) -> Result<u64> {
        let has_filter = !q.search.is_empty() || !q.eq.is_empty() || !q.pk_in.is_empty();
        if !has_filter && !q.all {
            return Err(Error::BadRequest(
                "refusing to delete every row; say all=true to confirm".into(),
            ));
        }
        self.accessor(slug)?.delete_many(q).await
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

// ===================== HTTP error mapping (feature `axum`) =====================

/// How an engine failure becomes a response, for an app that wants to hand one straight back.
/// Plain text, deliberately: this crate serves HTML pages now, and a page-level error belongs in the
/// app's own shell (see [`crud::ui`](crate::crud::ui), whose `submit` returns the `Error` for exactly
/// that reason).
#[cfg(feature = "axum")]
impl axum::response::IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode as S;
        let code = match &self {
            Error::NotFound => S::NOT_FOUND,
            Error::ReadOnly => S::METHOD_NOT_ALLOWED,
            Error::BadRequest(_) => S::BAD_REQUEST,
            Error::Conflict(_) => S::CONFLICT,
            Error::Validation(_) | Error::BatchRejected(_) => S::UNPROCESSABLE_ENTITY,
            Error::Unauthorized => S::UNAUTHORIZED,
            Error::Forbidden | Error::Csrf => S::FORBIDDEN,
            Error::Backend(_) => S::INTERNAL_SERVER_ERROR,
        };
        (code, self.one_line()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::slugify;
    #[test]
    fn slugify_normalizes() {
        assert_eq!(slugify("post"), "post");
        assert_eq!(slugify("post_tag"), "post_tag");
        assert_eq!(slugify("BlogPost"), "blog_post");
        assert_eq!(slugify("authorId"), "author_id");
        assert_eq!(slugify("My Table!"), "my_table");
    }
}
