//! Runtime OpenAPI generation (feature `openapi`). Our routes are per-entity and known only at
//! runtime, so we build the document from the `Engine` with utoipa's builder API rather than derive.

use crate::engine::Engine;
use utoipa::openapi::path::{
    HttpMethod, OperationBuilder, ParameterBuilder, ParameterIn, PathItem, PathsBuilder,
};
use utoipa::openapi::schema::{ObjectBuilder, Type};
use utoipa::openapi::{
    InfoBuilder, OpenApi, OpenApiBuilder, RefOr, Required, ResponseBuilder, Responses,
    ResponsesBuilder, Schema,
};

fn str_schema() -> RefOr<Schema> {
    ObjectBuilder::new().schema_type(Type::String).build().into()
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

fn one(code: &str, desc: &str) -> Responses {
    ResponsesBuilder::new()
        .response(code, ResponseBuilder::new().description(desc).build())
        .build()
}

/// Build an OpenAPI document describing the registered entities' CRUD endpoints.
pub fn build(engine: &Engine, title: &str) -> OpenApi {
    let mut paths = PathsBuilder::new();

    for slug in engine.tables() {
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
            .responses(one("200", "A page of rows (or CSV when format=csv)"))
            .build();
        let create_op = OperationBuilder::new()
            .tag(slug.clone())
            .summary(Some(format!("Create {slug}")))
            .responses(one("201", "Created row"))
            .build();
        let delete_many_op = OperationBuilder::new()
            .tag(slug.clone())
            .summary(Some(format!("Bulk delete {slug}")))
            .parameter(query("q"))
            .parameter(query("ids"))
            .parameter(query("all"))
            .responses(one("200", "{ deleted: N }"))
            .build();
        let get_op = OperationBuilder::new()
            .tag(slug.clone())
            .summary(Some(format!("Get {slug}")))
            .parameter(id_param())
            .responses(one("200", "The row"))
            .build();
        let patch_op = OperationBuilder::new()
            .tag(slug.clone())
            .summary(Some(format!("Update {slug}")))
            .parameter(id_param())
            .responses(one("200", "Updated row"))
            .build();
        let delete_op = OperationBuilder::new()
            .tag(slug.clone())
            .summary(Some(format!("Delete {slug}")))
            .parameter(id_param())
            .responses(one("200", "Deleted row"))
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
        .build()
}

/// Pretty-printed OpenAPI JSON for the registered entities.
pub fn json(engine: &Engine, title: &str) -> String {
    build(engine, title)
        .to_pretty_json()
        .unwrap_or_else(|e| format!("{{\"error\":\"openapi: {e}\"}}"))
}
