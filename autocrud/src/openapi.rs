//! Runtime OpenAPI generation (feature `openapi`). Our routes are per-entity and known only at
//! runtime, so we build the document from the `Engine` with utoipa's builder API rather than derive.
//!
//! Per entity we register two component schemas — the **read record** (`{slug}`) and the **write
//! body** (`{slug}_write`) — derived from the column metadata (logical types + relations), and the
//! operations reference them so the spec (and Swagger UI) describes the actual payloads.

use crate::engine::{Cardinality, ColumnMeta, Engine, LogicalType};
use utoipa::openapi::content::{Content, ContentBuilder};
use utoipa::openapi::path::{
    HttpMethod, OperationBuilder, ParameterBuilder, ParameterIn, PathItem, PathsBuilder,
};
use utoipa::openapi::request_body::{RequestBody, RequestBodyBuilder};
use utoipa::openapi::schema::{ArrayBuilder, ComponentsBuilder, ObjectBuilder, Ref};
use utoipa::openapi::{
    InfoBuilder, OpenApi, OpenApiBuilder, RefOr, Required, ResponseBuilder, Responses,
    ResponsesBuilder, Schema,
};
use utoipa::PartialSchema;

// ---- small schema helpers ----

fn str_schema() -> RefOr<Schema> {
    String::schema()
}

/// JSON Schema for a scalar field, by logical type.
fn scalar(ty: LogicalType) -> RefOr<Schema> {
    match ty {
        LogicalType::Int => i64::schema(),
        LogicalType::Float => f64::schema(),
        LogicalType::Bool => bool::schema(),
        LogicalType::Json => RefOr::T(Schema::Object(ObjectBuilder::new().build())), // any
        // Text / Uuid / Date / DateTime / Enum / Other → string
        _ => String::schema(),
    }
}

/// A relation link object `{ id, label }`.
fn link() -> RefOr<Schema> {
    RefOr::T(Schema::Object(
        ObjectBuilder::new()
            .property("id", i64::schema())
            .property("label", String::schema())
            .build(),
    ))
}

fn array_of(items: RefOr<Schema>) -> RefOr<Schema> {
    RefOr::T(Schema::Array(ArrayBuilder::new().items(items).build()))
}

fn schema_ref(name: impl Into<String>) -> RefOr<Schema> {
    RefOr::Ref(Ref::from_schema_name(name))
}

/// The read record: every readable column (write-only fields omitted); relations as `{id,label}`.
fn record_schema(cols: &[ColumnMeta]) -> RefOr<Schema> {
    let mut o = ObjectBuilder::new();
    for c in cols {
        match c {
            ColumnMeta::Field { name, logical_type, write_only, .. } => {
                if !write_only {
                    o = o.property(name, scalar(*logical_type));
                }
            }
            ColumnMeta::Relation { name, cardinality, .. } => {
                o = o.property(
                    name,
                    match cardinality {
                        Cardinality::ToOne => link(),
                        Cardinality::ToMany => array_of(link()),
                    },
                );
            }
        }
    }
    RefOr::T(Schema::Object(o.build()))
}

/// The write body: writable columns; relations by id (`id` / `[id, …]`).
fn write_schema(cols: &[ColumnMeta]) -> RefOr<Schema> {
    let mut o = ObjectBuilder::new();
    for c in cols {
        match c {
            ColumnMeta::Field { name, logical_type, read_only, .. } => {
                if !read_only {
                    o = o.property(name, scalar(*logical_type));
                }
            }
            ColumnMeta::Relation { name, cardinality, read_only, .. } => {
                if !read_only {
                    o = o.property(
                        name,
                        match cardinality {
                            Cardinality::ToOne => i64::schema(),
                            Cardinality::ToMany => array_of(i64::schema()),
                        },
                    );
                }
            }
        }
    }
    RefOr::T(Schema::Object(o.build()))
}

/// The list envelope: `{ total, page, per_page, data: [{ id, label, row: <record> }] }`.
fn page_schema(slug: &str) -> RefOr<Schema> {
    let item = ObjectBuilder::new()
        .property("id", i64::schema())
        .property("label", String::schema())
        .property("row", schema_ref(slug))
        .build();
    RefOr::T(Schema::Object(
        ObjectBuilder::new()
            .property("total", i64::schema())
            .property("page", i64::schema())
            .property("per_page", i64::schema())
            .property("data", array_of(RefOr::T(Schema::Object(item))))
            .build(),
    ))
}

fn deleted_schema() -> RefOr<Schema> {
    RefOr::T(Schema::Object(
        ObjectBuilder::new().property("deleted", i64::schema()).build(),
    ))
}

// ---- request/response wrappers ----

fn json_content(schema: RefOr<Schema>) -> Content {
    ContentBuilder::new().schema(Some(schema)).build()
}

fn json_body(schema: RefOr<Schema>) -> RequestBody {
    RequestBodyBuilder::new().content("application/json", json_content(schema)).build()
}

fn json_response(code: &str, desc: &str, schema: RefOr<Schema>) -> Responses {
    ResponsesBuilder::new()
        .response(
            code,
            ResponseBuilder::new()
                .description(desc)
                .content("application/json", json_content(schema))
                .build(),
        )
        .build()
}

fn query(name: &str) -> utoipa::openapi::path::Parameter {
    ParameterBuilder::new()
        .name(name)
        .parameter_in(ParameterIn::Query)
        .required(Required::False)
        .schema(Some(str_schema()))
        .build()
}

fn id_param() -> utoipa::openapi::path::Parameter {
    ParameterBuilder::new()
        .name("id")
        .parameter_in(ParameterIn::Path)
        .required(Required::True)
        .schema(Some(str_schema()))
        .build()
}

/// Build an OpenAPI document describing the registered entities' CRUD endpoints + payload schemas.
pub fn build(engine: &Engine, title: &str) -> OpenApi {
    let mut paths = PathsBuilder::new();
    let mut components = ComponentsBuilder::new();

    for slug in engine.tables() {
        let cols = engine.columns(&slug).unwrap_or_default();
        let write_name = format!("{slug}_write");
        components = components
            .schema(slug.clone(), record_schema(&cols))
            .schema(write_name.clone(), write_schema(&cols));

        let list = engine.entity_url(&slug);
        let item = format!("{list}/{{id}}");

        let list_op = OperationBuilder::new()
            .tag(slug.clone())
            .summary(Some(format!("List {slug}")))
            .parameter(query("q"))
            .parameter(query("sort"))
            .parameter(query("page"))
            .parameter(query("per_page"))
            .parameter(query("view"))
            .parameter(query("all"))
            .parameter(query("format"))
            .responses(json_response("200", "A page of rows", page_schema(&slug)))
            .build();
        let create_op = OperationBuilder::new()
            .tag(slug.clone())
            .summary(Some(format!("Create {slug}")))
            .request_body(Some(json_body(schema_ref(&write_name))))
            .responses(json_response("201", "Created row", schema_ref(&slug)))
            .build();
        let delete_many_op = OperationBuilder::new()
            .tag(slug.clone())
            .summary(Some(format!("Bulk delete {slug}")))
            .parameter(query("q"))
            .parameter(query("ids"))
            .parameter(query("all"))
            .responses(json_response("200", "Number of rows deleted", deleted_schema()))
            .build();
        let get_op = OperationBuilder::new()
            .tag(slug.clone())
            .summary(Some(format!("Get {slug}")))
            .parameter(id_param())
            .responses(json_response("200", "The row", schema_ref(&slug)))
            .build();
        let patch_op = OperationBuilder::new()
            .tag(slug.clone())
            .summary(Some(format!("Update {slug}")))
            .parameter(id_param())
            .request_body(Some(json_body(schema_ref(&write_name))))
            .responses(json_response("200", "Updated row", schema_ref(&slug)))
            .build();
        let delete_op = OperationBuilder::new()
            .tag(slug.clone())
            .summary(Some(format!("Delete {slug}")))
            .parameter(id_param())
            .responses(json_response("200", "Deleted row", schema_ref(&slug)))
            .build();

        paths = paths
            .path(list.clone(), PathItem::new(HttpMethod::Get, list_op))
            .path(list.clone(), PathItem::new(HttpMethod::Post, create_op))
            .path(list, PathItem::new(HttpMethod::Delete, delete_many_op))
            .path(item.clone(), PathItem::new(HttpMethod::Get, get_op))
            .path(item.clone(), PathItem::new(HttpMethod::Patch, patch_op))
            .path(item, PathItem::new(HttpMethod::Delete, delete_op));
    }

    OpenApiBuilder::new()
        .info(InfoBuilder::new().title(title).version("0.1.0").build())
        .paths(paths.build())
        .components(Some(components.build()))
        .build()
}

/// Pretty-printed OpenAPI JSON for the registered entities.
pub fn json(engine: &Engine, title: &str) -> String {
    build(engine, title)
        .to_pretty_json()
        .unwrap_or_else(|e| format!("{{\"error\":\"openapi: {e}\"}}"))
}
