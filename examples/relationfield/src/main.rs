//! relationfield example — the relation picker in a form the app writes itself.
//!
//! `crud::ui::Form` edits one row of one entity. This page's form edits none: "give these tags to
//! every post by this author". It is plain HTML with two `crud::ui::RelationField`s in it — the same
//! input `Form`, `Table` and `Admin` render for a relation, from the same code: a `<select>` while
//! the target is small, and past `picker_threshold` (50; the seeded model has 56 authors and 56
//! tags) the selection as badges and a 🔍 button opening the picker dialog over the target's table.
//!
//! What the app supplies, and all it supplies:
//!
//! - **one definition per field** ([`author_field`], [`tags_field`]), used by both handlers — the GET
//!   renders it, the POST reads it back with `RelationField::read`, which also checks every posted
//!   id is a real row (the picker's hidden inputs are as editable as a typed id);
//! - the **write**, its own: here one `Engine::write_batch`, so the whole retag commits or none of
//!   it does — after asking the `post` gate whether this caller may update posts at all;
//! - the picker's **plumbing**, as for a `Form`: `Crud::picker_path("/pick")`, a `GET /pick` serving
//!   `crud::ui::Picker` in a bare shell, and `crud::ui::JS` in the page shell.
//!
//! Below the form a read-only `Table` pinned to the chosen author shows the result.
//!
//! Try:  open http://127.0.0.1:3000/ · pick an author and two tags · Apply · then try "Replace".
//! Set `.picker_threshold(100)` on a field and it is a plain `<select>` — the handlers don't change.

use askama::Template;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use model::{author, post, tag};
use relativelylight::authz::{Decision, Open, Operation};
use relativelylight::crud::engine::{Engine, Error, ListQuery};
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::{Picker, RelationField, Table, ViewState, CSS, JS};
use sea_orm::IdenStatic; // `post::Column::Title.as_str()` — a column name the compiler checks
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = model::setup().await?;

    let mut author_mm = MetaModel::new(author::Entity);
    let mut post_mm = MetaModel::new(post::Entity);
    let mut tag_mm = MetaModel::new(tag::Entity);
    post_mm.relate(&tag_mm);
    tag_mm.relate(&post_mm);
    author_mm.label_column(author::Column::Name.as_str());

    let mut crud = Crud::new(db);
    crud.register(author_mm, Open);
    crud.register(post_mm, Open);
    crud.register(tag_mm, Open);
    // Where the picker is served — the `/pick` route below. Without it a relation past the
    // threshold stays a `<select>` of every row, which still works.
    crud.picker_path("/pick");
    let engine = Arc::new(crud.into_engine());

    let router = Router::new()
        .route("/", get(page).post(apply))
        .route("/author/{id}", get(author_page))
        .route("/pick", get(pick))
        .with_state(engine)
        // Mandatory for every app on this crate (see relativelylight::middleware), though nothing on
        // these pages writes through the library's own handlers.
        .layer(axum::middleware::from_fn_with_state(
            relativelylight::middleware::TrustProxy(false),
            relativelylight::middleware::resolve_real_ip,
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("relationfield on  http://127.0.0.1:3000/");
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

// ---- the two fields: one definition each, for both handlers ----

/// The posts' `author` relation — a to-one, so a radio per row in the picker.
fn author_field(engine: &Engine) -> RelationField<'_> {
    RelationField::new(engine, "post", "author").label("Author").required(true)
}

/// The posts' `tag` relation — a to-many, a checkbox per row. Named `tags` in this form; the picker
/// still browses `post.tag`.
fn tags_field(engine: &Engine) -> RelationField<'_> {
    RelationField::new(engine, "post", "tag")
        .name("tags")
        .label("Tags")
        .help("Add: every post keeps its tags and gains these. Replace: these become its only tags.")
}

// ---- the page ----

#[derive(Template)]
#[template(path = "shell.html")]
struct Shell {
    css: &'static str,
    js: &'static str,
    author_field: String,
    tags_field: String,
    modes: Vec<ModeOpt>,
    posts: String,
    applied: u64,
}

struct ModeOpt {
    value: &'static str,
    label: &'static str,
    checked: bool,
}

/// What the form shows: the chosen ids, the mode, and why it came back, if it did.
#[derive(Default)]
struct Draft {
    author: Vec<String>,
    tags: Vec<String>,
    mode: String,
    author_error: String,
    tags_error: String,
}

async fn page(State(engine): State<Arc<Engine>>, headers: HeaderMap, uri: Uri) -> Response {
    show(&engine, &headers, &uri, Draft::default(), 0).await
}

/// After a retag: the form with that author still chosen, and their posts below it.
async fn author_page(
    State(engine): State<Arc<Engine>>,
    headers: HeaderMap,
    uri: Uri,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let applied = q.get("applied").and_then(|n| n.parse().ok()).unwrap_or(0);
    show(&engine, &headers, &uri, Draft { author: vec![id], ..Draft::default() }, applied).await
}

async fn show(engine: &Engine, headers: &HeaderMap, uri: &Uri, d: Draft, applied: u64) -> Response {
    let author = author_field(engine).selected(&d.author).error(d.author_error);
    let tags = tags_field(engine).selected(&d.tags).error(d.tags_error);
    // A read-only table of the chosen author's posts — pinned, so it can't be mistaken for every
    // post. Its own links (`?page=2`, `?sort=`) are relative, which is why the author is in the path.
    let posts = match d.author.first() {
        Some(id) => {
            let table = Table::new(engine, "post")
                .title("Their posts")
                .read_only(true)
                .search(false)
                .per_page(10)
                .fixed_filter("author", id.as_str())
                .columns([post::Column::Title.as_str(), "tag"])
                .sort(post::Column::Title.as_str());
            table.render_for(headers, &ViewState::from_uri(uri)).await
        }
        None => Ok(String::new()),
    };
    let (author, tags, posts) = match (author.render_for(headers).await, tags.render_for(headers).await, posts) {
        (Ok(a), Ok(t), Ok(p)) => (a, t, p),
        (Err(e), ..) | (_, Err(e), _) | (.., Err(e)) => return e.into_response(),
    };
    let mode = if d.mode == "replace" { "replace" } else { "add" };
    let modes = [("add", "Add these tags"), ("replace", "Replace their tags with these")]
        .into_iter()
        .map(|(value, label)| ModeOpt { value, label, checked: value == mode })
        .collect();
    let shell = Shell { css: CSS, js: JS, author_field: author, tags_field: tags, modes, posts, applied };
    match shell.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ---- the write: the app's own ----

async fn apply(State(engine): State<Arc<Engine>>, headers: HeaderMap, uri: Uri, body: Bytes) -> Response {
    // Reading the fields writes nothing and asks no gate; this does. `Engine` itself is ungated — it
    // is the typed core the library's own handlers gate in front of — so a handler that writes
    // through it asks first. (`Open` here, so this always allows; a gated app gets 401/403.)
    match engine.decide("post", Operation::Update, &headers).await {
        Decision::Allow => {}
        Decision::NeedsLogin => return Error::Unauthorized.into_response(),
        Decision::Denied => return Error::Forbidden.into_response(),
    }
    // The one plain field: two fixed values, so no decoding to speak of.
    let replace = body.split(|b| *b == b'&').any(|kv| kv == b"mode=replace");
    let mut d = Draft { mode: if replace { "replace" } else { "add" }.into(), ..Draft::default() };
    // `read` hands back the posted ids once each is a row of the target, or a message saying which
    // isn't — put under the field it belongs to. `posted` is the same ids unchecked, so a rejected
    // form comes back with the operator's choice still in it.
    let author = author_field(&engine);
    let tags = tags_field(&engine);
    match (author.posted(&headers, &body), tags.posted(&headers, &body)) {
        (Ok(a), Ok(t)) => (d.author, d.tags) = (a, t),
        (Err(e), _) | (_, Err(e)) => return e.into_response(),
    }
    match author.read(&headers, &body).await {
        Ok(ids) if ids.is_empty() => d.author_error = "Choose an author.".into(),
        Ok(_) => {}
        Err(Error::Validation(v)) => d.author_error = v.fields.into_values().collect(),
        Err(e) => return e.into_response(),
    }
    match tags.read(&headers, &body).await {
        Ok(ids) if ids.is_empty() && d.mode != "replace" => d.tags_error = "Choose a tag to add.".into(),
        Ok(_) => {}
        Err(Error::Validation(v)) => d.tags_error = v.fields.into_values().collect(),
        Err(e) => return e.into_response(),
    }
    if !d.author_error.is_empty() || !d.tags_error.is_empty() {
        let mut page = show(&engine, &headers, &uri, d, 0).await;
        *page.status_mut() = StatusCode::UNPROCESSABLE_ENTITY;
        return page;
    }

    // Every post by that author, with its current tags (`terse: false` — the finished rows).
    let author_id = d.author[0].clone();
    let mut q = ListQuery::default();
    q.eq.push(("author".into(), author_id.clone())); // the relation's name, as in `?filter[author]=`
    q.all = true;
    let posts = match engine.list("post", &q, false).await {
        Ok(page) => page.data,
        Err(e) => return e.into_response(),
    };
    let writes = posts
        .iter()
        .map(|p| {
            let mut ids: Vec<String> = match d.mode.as_str() {
                "replace" => Vec::new(),
                _ => current_tags(p.row.as_ref()),
            };
            for t in &d.tags {
                if !ids.contains(t) {
                    ids.push(t.clone());
                }
            }
            // A to-many is written as the full set of ids; only `tag` is in the body, so nothing
            // else about the post changes.
            let ids: Vec<Value> = ids.iter().map(|id| id.parse::<i64>().map_or(json!(id), Value::from)).collect();
            (Some(id_text(&p.id)), json!({ "tag": ids }))
        })
        .collect();
    // One transaction: every post is retagged, or — if any write fails — none is.
    match engine.write_batch("post", writes).await {
        Ok(done) => Redirect::to(&format!("/author/{author_id}?applied={}", done.updated)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// The tag ids a finished post row links to — its `tag` is `[{id, label}, …]`.
fn current_tags(row: Option<&Value>) -> Vec<String> {
    row.and_then(|r| r["tag"].as_array())
        .map(|tags| tags.iter().map(|t| id_text(&t["id"])).collect())
        .unwrap_or_default()
}

fn id_text(v: &Value) -> String {
    v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())
}

// ---- the picker's page ----

#[derive(Template)]
#[template(path = "bare.html")]
struct Bare {
    body: String,
    css: &'static str,
}

/// The page inside the picker dialog: the target's own table with a radio or a checkbox per row,
/// in a bare shell (it is inside an iframe). Shared by both fields — the URL says which relation.
async fn pick(State(engine): State<Arc<Engine>>, headers: HeaderMap, uri: Uri) -> Response {
    let state = ViewState::from_uri(&uri);
    match Picker::new(&engine).render_for(&headers, &state).await {
        Ok(body) => match (Bare { body, css: CSS }).render() {
            Ok(html) => Html(html).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        Err(e) => e.into_response(),
    }
}
