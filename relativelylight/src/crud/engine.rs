//! Backend-agnostic core: the `Accessor` seam, the contract types, and the `Engine` that composes
//! accessors into the CRUD + metadata API — plus the axum HTTP surface (feature `axum`).
//!
//! The engine is deliberately thin: it holds the registry of entities, owns URLs / metadata (for
//! OpenAPI and the UI), forwards data to and from accessors, does the generic JSON↔CSV transform
//! (feature `csv`), and wires routes. Every backend (SeaORM today; memory / no-SQL / filesystem
//! later) hands the engine **finished JSON** — rows already projected (visible fields, transforms
//! applied) with relations embedded as `{id, label}`. All the heavy lifting lives in the backend.

use async_trait::async_trait;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

// ===================== Errors =====================

/// Structured validation errors: field-keyed + cross-field/general messages.
#[derive(Debug, Default, Serialize)]
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

#[derive(Debug)]
pub enum Error {
    Backend(String),
    NotFound,
    ReadOnly,
    BadRequest(String),
    Validation(ValidationErrors),
    /// The operation needs a logged-in user but the request is anonymous → 401.
    Unauthorized,
    /// Authenticated but not permitted → 403.
    Forbidden,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Backend(e) => write!(f, "backend error: {e}"),
            Error::NotFound => write!(f, "not found"),
            Error::ReadOnly => write!(f, "read-only"),
            Error::BadRequest(m) => write!(f, "bad request: {m}"),
            Error::Validation(_) => write!(f, "validation failed"),
            Error::Unauthorized => write!(f, "unauthorized"),
            Error::Forbidden => write!(f, "forbidden"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

// ===================== Contract types =====================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

impl LogicalType {
    pub fn is_text(self) -> bool {
        matches!(self, LogicalType::Text)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Cardinality {
    ToOne,
    ToMany,
}

/// One ordered column of an entity — a scalar field or a relation — as **backend-agnostic
/// metadata**. The `Accessor` produces these; the `Engine` renders them into `_meta` JSON (adding
/// URLs) and OpenAPI, and the UI uses them to build tables and forms. Relations carry no resolution
/// mechanics anymore — the backend resolves them and embeds `{id, label}` into the row.
pub enum ColumnMeta {
    Field {
        name: String,
        logical_type: LogicalType,
        read_only: bool,
        write_only: bool,
        label: Option<String>,
        description: Option<String>,
        default: Option<Value>,
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
    },
}

#[derive(Debug, Default, Clone)]
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
pub struct RowItem {
    pub id: Value,
    pub label: String,
    pub row: Option<Value>,
}

pub struct Page {
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
    pub data: Vec<RowItem>,
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
/// method returns **finished JSON**: rows already projected (visible fields, `on_read` applied) with
/// relations resolved to `{id, label}` — the engine forwards them as-is.
#[async_trait]
pub trait Accessor: Send + Sync {
    fn slug(&self) -> &str;
    /// The (single) primary-key field name.
    fn pk(&self) -> String;
    /// Backend-agnostic column metadata (fields + relations).
    fn columns(&self) -> Vec<ColumnMeta>;

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
}

// ===================== The Engine =====================

pub struct Engine {
    base_path: String,
    accessors: BTreeMap<String, Arc<dyn Accessor>>,
    /// The authorization gate for each model, keyed by slug (set at registration; `Open` = ungated).
    authz: BTreeMap<String, Arc<dyn crate::authz::Authz>>,
}

impl Engine {
    pub fn new(base_path: impl Into<String>) -> Self {
        let mut base_path = base_path.into();
        while base_path.ends_with('/') {
            base_path.pop();
        }
        if !base_path.is_empty() && !base_path.starts_with('/') {
            base_path.insert(0, '/');
        }
        Self {
            base_path,
            accessors: BTreeMap::new(),
            authz: BTreeMap::new(),
        }
    }

    /// The gate governing `slug` (or `None` for an unregistered slug).
    fn authz_for(&self, slug: &str) -> Option<&Arc<dyn crate::authz::Authz>> {
        self.authz.get(slug)
    }

    /// Whether the model's gate would allow `op` for this request. Used by the UI to hide write
    /// controls the caller isn't permitted; the API is the actual enforcement point.
    pub async fn permits(
        &self,
        slug: &str,
        op: crate::authz::Operation,
        headers: &::http::HeaderMap,
    ) -> bool {
        match self.authz_for(slug) {
            Some(gate) => matches!(gate.authorize(op, headers).await, crate::authz::Decision::Allow),
            None => false,
        }
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

    pub fn base_path(&self) -> &str {
        &self.base_path
    }
    pub fn tables(&self) -> Vec<String> {
        self.accessors.keys().cloned().collect()
    }
    fn accessor(&self, slug: &str) -> Result<&Arc<dyn Accessor>> {
        self.accessors.get(slug).ok_or(Error::NotFound)
    }

    pub fn entity_url(&self, slug: &str) -> String {
        format!("{}/{}", self.base_path, slug)
    }

    // ---- Metadata ----

    /// Catalog of registered entities (for a frontend). Not routed by default.
    pub fn meta_all(&self) -> Value {
        let entities: Vec<Value> = self
            .accessors
            .keys()
            .map(|s| json!({ "entity": s, "url": self.entity_url(s) }))
            .collect();
        json!({ "entities": entities })
    }

    pub fn meta_one(&self, slug: &str) -> Result<Value> {
        let acc = self.accessor(slug)?;
        let columns: Vec<Value> = acc.columns().into_iter().map(|e| self.column_json(e)).collect();
        Ok(json!({
            "entity": slug,
            "url": self.entity_url(slug),
            "primary_key": [acc.pk()],
            "columns": columns,
        }))
    }

    /// Typed column metadata for one entity (fields + relations) — for schema / OpenAPI generation.
    pub fn columns(&self, slug: &str) -> Result<Vec<ColumnMeta>> {
        Ok(self.accessor(slug)?.columns())
    }

    fn column_json(&self, e: ColumnMeta) -> Value {
        match e {
            ColumnMeta::Field {
                name,
                logical_type,
                read_only,
                write_only,
                label,
                description,
                default,
            } => {
                let mut o = json!({
                    "kind": "field", "name": name, "type": logical_type,
                    "read_only": read_only, "write_only": write_only,
                });
                if let Some(l) = label {
                    o["label"] = json!(l);
                }
                if let Some(d) = description {
                    o["description"] = json!(d);
                }
                if let Some(dv) = default {
                    o["default"] = dv;
                }
                o
            }
            ColumnMeta::Relation {
                name,
                target,
                cardinality,
                fk_column,
                read_only,
                label,
                description,
            } => {
                // `list_url` lets a form picker search the target in terse mode:
                //   GET {list_url}?q=…&view=terse  → [{id,label}]. No per-row item link is emitted
                //   — the table shows relation labels/badges, not links into the JSON API.
                let mut o = json!({
                    "kind": "relation", "name": name, "target": target,
                    "cardinality": cardinality, "read_only": read_only,
                    "list_url": self.entity_url(&target),
                });
                if let Some(fk) = fk_column {
                    o["fk_column"] = json!(fk);
                }
                if let Some(l) = label {
                    o["label"] = json!(l);
                }
                if let Some(d) = description {
                    o["description"] = json!(d);
                }
                o
            }
        }
    }

    // ---- Data (pure forwarding; the backend produces finished JSON) ----

    /// List rows. Each item is `{ id, label, row? }`; `terse` (and the backend) omit `row`.
    pub async fn list(&self, slug: &str, q: &ListQuery, terse: bool) -> Result<Value> {
        let page = self.accessor(slug)?.list(q, terse).await?;
        let data: Vec<Value> = page
            .data
            .into_iter()
            .map(|it| {
                let mut o = json!({ "id": it.id, "label": it.label });
                if let Some(row) = it.row {
                    o["row"] = row;
                }
                o
            })
            .collect();
        Ok(json!({
            "total": page.total, "page": page.page, "per_page": page.per_page, "data": data,
        }))
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

    /// Bulk delete matching rows. Refuses to wipe the whole (unfiltered) table unless `q.all`.
    pub async fn delete_where(&self, slug: &str, q: &ListQuery) -> Result<Value> {
        let has_filter = !q.search.is_empty() || !q.eq.is_empty() || !q.pk_in.is_empty();
        if !has_filter && !q.all {
            return Err(Error::BadRequest(
                "refusing to delete every row; pass ?all=true to confirm".into(),
            ));
        }
        let deleted = self.accessor(slug)?.delete_many(q).await?;
        Ok(json!({ "deleted": deleted }))
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

// ===================== Axum HTTP surface (feature `axum`) =====================

#[cfg(feature = "axum")]
mod http {
    use super::{Engine, Error, ListQuery};
    use axum::extract::{Path, Query, State};
    use axum::http::HeaderMap;
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use axum::{Json, Router};
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::sync::Arc;

    impl IntoResponse for Error {
        fn into_response(self) -> Response {
            match self {
                Error::NotFound => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))),
                Error::ReadOnly => (
                    StatusCode::METHOD_NOT_ALLOWED,
                    Json(json!({ "error": "read-only" })),
                ),
                Error::BadRequest(m) => (StatusCode::BAD_REQUEST, Json(json!({ "error": m }))),
                Error::Backend(e) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e })))
                }
                Error::Validation(v) => {
                    let mut body = serde_json::to_value(&v).unwrap_or_else(|_| json!({}));
                    body["error"] = json!("validation failed");
                    (StatusCode::UNPROCESSABLE_ENTITY, Json(body))
                }
                Error::Unauthorized => {
                    (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" })))
                }
                Error::Forbidden => (StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden" }))),
            }
            .into_response()
        }
    }

    type St = State<Arc<Engine>>;

    use crate::authz::{Decision, Operation};

    /// Consult the model's gate: resolve the caller from the request headers and map the
    /// [`Decision`](crate::authz::Decision) to `401`/`403`. An unregistered model has no gate — let
    /// the handler proceed and return its own `404`.
    async fn authorize(e: &Engine, op: Operation, model: &str, headers: &HeaderMap) -> Result<(), Error> {
        let Some(gate) = e.authz_for(model) else {
            return Ok(());
        };
        match gate.authorize(op, headers).await {
            Decision::Allow => Ok(()),
            Decision::NeedsLogin => Err(Error::Unauthorized),
            Decision::Denied => Err(Error::Forbidden),
        }
    }

    impl Engine {
        /// Build the axum router for the registered entities, mounted under `base_path`.
        pub fn router(self: Arc<Self>) -> Router {
            let base = self.base_path.clone();
            #[allow(unused_mut)]
            let mut inner = Router::new()
                .route("/{entity}", get(list).post(create).delete(delete_many))
                .route("/{entity}/{pk}", get(get_one).patch(update).delete(delete_one));
            #[cfg(feature = "csv")]
            {
                inner = inner.route("/{entity}/_import", axum::routing::post(import));
            }
            let inner = inner.with_state(self);
            if base.is_empty() {
                inner
            } else {
                Router::new().nest(&base, inner)
            }
        }
    }

    fn parse_list_query(params: HashMap<String, String>) -> ListQuery {
        let mut q = ListQuery::default();
        for (key, value) in params {
            match key.as_str() {
                "page" => q.page = value.parse().unwrap_or(0),
                "per_page" => q.per_page = value.parse().unwrap_or(0),
                "view" => {}   // rendering mode, handled by the handler
                "format" => {} // response format (e.g. csv), handled by the handler
                "all" => q.all = value == "true",
                "ids" => {
                    q.pk_in = value.split(',').filter(|s| !s.is_empty()).map(String::from).collect()
                }
                "q" => q.search.push((None, value)),
                "sort" => {
                    for part in value.split(',').filter(|s| !s.is_empty()) {
                        match part.split_once(':') {
                            Some((c, "desc")) => q.sort.push((c.to_string(), true)),
                            Some((c, _)) => q.sort.push((c.to_string(), false)),
                            None => q.sort.push((part.to_string(), false)),
                        }
                    }
                }
                _ => q.search.push((Some(key), value)),
            }
        }
        q
    }

    async fn list(
        State(e): St,
        headers: HeaderMap,
        Path(entity): Path<String>,
        Query(params): Query<HashMap<String, String>>,
    ) -> std::result::Result<Response, Error> {
        authorize(&e, Operation::List, &entity, &headers).await?;
        #[cfg(feature = "csv")]
        if params.get("format").map(|v| v == "csv").unwrap_or(false) {
            let body = crate::crud::csv_io::export(&e, &entity, &parse_list_query(params)).await?;
            let disposition = format!("attachment; filename=\"{entity}.csv\"");
            return Ok((
                [
                    (axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                    (axum::http::header::CONTENT_DISPOSITION, disposition),
                ],
                body,
            )
                .into_response());
        }
        let terse = params.get("view").map(|v| v == "terse").unwrap_or(false);
        Ok(Json(e.list(&entity, &parse_list_query(params), terse).await?).into_response())
    }

    async fn get_one(
        State(e): St,
        headers: HeaderMap,
        Path((entity, pk)): Path<(String, String)>,
    ) -> std::result::Result<Json<Value>, Error> {
        authorize(&e, Operation::Read, &entity, &headers).await?;
        Ok(Json(e.get(&entity, &pk).await?))
    }

    async fn create(
        State(e): St,
        headers: HeaderMap,
        Path(entity): Path<String>,
        Json(body): Json<Value>,
    ) -> std::result::Result<(StatusCode, Json<Value>), Error> {
        authorize(&e, Operation::Create, &entity, &headers).await?;
        Ok((StatusCode::CREATED, Json(e.create(&entity, &body).await?)))
    }

    async fn update(
        State(e): St,
        headers: HeaderMap,
        Path((entity, pk)): Path<(String, String)>,
        Json(body): Json<Value>,
    ) -> std::result::Result<Json<Value>, Error> {
        authorize(&e, Operation::Update, &entity, &headers).await?;
        Ok(Json(e.update(&entity, &pk, &body).await?))
    }

    async fn delete_one(
        State(e): St,
        headers: HeaderMap,
        Path((entity, pk)): Path<(String, String)>,
    ) -> std::result::Result<Json<Value>, Error> {
        authorize(&e, Operation::Delete, &entity, &headers).await?;
        Ok(Json(e.delete(&entity, &pk).await?))
    }

    /// `DELETE /{entity}?<filters>` — bulk delete. `?all=true` permits wiping the whole table.
    async fn delete_many(
        State(e): St,
        headers: HeaderMap,
        Path(entity): Path<String>,
        Query(params): Query<HashMap<String, String>>,
    ) -> std::result::Result<Json<Value>, Error> {
        authorize(&e, Operation::Delete, &entity, &headers).await?;
        Ok(Json(e.delete_where(&entity, &parse_list_query(params)).await?))
    }

    /// `POST /{entity}/_import` — body is CSV text; returns an `ImportReport` as JSON.
    #[cfg(feature = "csv")]
    async fn import(
        State(e): St,
        headers: HeaderMap,
        Path(entity): Path<String>,
        body: String,
    ) -> std::result::Result<Json<Value>, Error> {
        authorize(&e, Operation::Create, &entity, &headers).await?;
        let report = crate::crud::csv_io::import(&e, &entity, &body).await?;
        Ok(Json(serde_json::to_value(report).unwrap_or_else(|_| json!({}))))
    }
}
