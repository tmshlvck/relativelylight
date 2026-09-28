//! blobthumbnailer example — **thumbnails as app code**, over a library that has no thumbnailer.
//!
//! `blob` ships no `Thumbnailer` and no variant table, on purpose: sizes, formats and quality are
//! policy, and the crate cannot know what an app wants. This example is the whole of what that costs
//! — `src/thumbs.rs`, about eighty lines — and it shows why the trade is a good one.
//!
//! **A thumbnail here is an ordinary document.** It gets its own handle, its own version chain, and
//! a row in the app's own `picture` table pointing at both. Which means it is listed, read, deleted
//! and garbage collected by exactly the same machinery as everything else. There is no second
//! storage concept to reason about, and no "does a variant keep its source alive" question — the
//! kind of question that is easy to get wrong and hard to notice.
//!
//! What to look at:
//!
//! - **`/`** — upload an image; a thumbnail is generated and stored as a second document, and the
//!   listing shows both, with the `Viewer`'s `thumbnail_url` pointing at it.
//! - **Delete** — removes the picture row and *both* handles, then collects. One deletion path.
//! - **stdout** — the audit trail. A thumbnail's creation is an ordinary `Create`, indistinguishable
//!   from any other document, which is the point.
//!
//! Try:  cargo run -p blobthumbnailer-example   →   http://127.0.0.1:3000/

mod thumbs;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use relativelylight::authz::Open;
use relativelylight::blob::ui::{to_inline_response, to_response, Receiver, UploadForm, Viewer};
use relativelylight::blob::{self, BlobStore, FsBackend, HandleId, WriteContext};
use relativelylight::crud::ui::esc_str;
use relativelylight::middleware::RealIp;
use relativelylight::observe::{WriteEvent, WriteObserver};
use sea_orm::entity::prelude::*;
use sea_orm::{ActiveModelTrait, Database, Schema, Set};
use std::net::SocketAddr;
use std::sync::Arc;

/// The app's own table: a picture, and the thumbnail generated for it. **Two handles**, because a
/// thumbnail is a document like any other — not a variant hanging off the first one.
mod picture {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "picture")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
        pub caption: String,
        /// → `blob_handle.id` — the full-size image.
        pub handle_id: Uuid,
        /// → `blob_handle.id` — the generated thumbnail. `None` when the upload wasn't a decodable
        /// image, which is an ordinary outcome rather than a failure.
        pub thumb_handle_id: Option<Uuid>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

#[derive(Clone)]
struct App {
    db: DatabaseConnection,
    store: Arc<BlobStore<FsBackend>>,
}

struct Log;

#[async_trait::async_trait]
impl WriteObserver for Log {
    async fn on_write(&self, ev: &WriteEvent<'_>) {
        println!(
            "[audit] {:?} {} v{} from {}",
            ev.op,
            ev.entity,
            ev.version.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            ev.client_ip
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::connect("sqlite::memory:").await?;
    blob::migrate(&db).await?;
    let backend = sea_orm::DatabaseBackend::Sqlite;
    let schema = Schema::new(backend);
    let mut stmt = schema.create_table_from_entity(picture::Entity);
    stmt.if_not_exists();
    db.execute(backend.build(&stmt)).await?;

    let root = std::env::temp_dir().join(format!("rl-thumb-example-{}", std::process::id()));
    let fs = FsBackend::new(&root);
    fs.init().await?;
    println!("blob storage: {}", root.display());

    let store = Arc::new(BlobStore::new(fs, db.clone()).on_write(Arc::new(Log)));
    let app = App { db, store };

    let router = Router::new()
        .route("/", get(index).post(upload))
        .route("/picture/{id}/full", get(full))
        .route("/picture/{id}/thumb", get(thumb))
        .route("/picture/{id}/delete", post(delete))
        .with_state(app)
        .layer(axum::middleware::from_fn_with_state(
            relativelylight::middleware::TrustProxy(false),
            relativelylight::middleware::resolve_real_ip,
        ));

    println!("listening on http://127.0.0.1:3000");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

async fn index(State(app): State<App>) -> Response {
    let rows = picture::Entity::find().all(&app.db).await.unwrap_or_default();
    let mut body = String::from("<h1 class=\"h4 mb-3\">Pictures</h1>");

    for p in &rows {
        let Ok(head) = app.store.head(HandleId(p.handle_id)).await else { continue };
        let full = format!("/picture/{}/full", p.id);
        let mut v = Viewer::new(&head, &full).download_url(format!("{full}?download=1"));
        // The thumbnail is a second document; its URL is just another of the app's routes.
        if p.thumb_handle_id.is_some() {
            v = v.thumbnail_url(format!("/picture/{}/thumb", p.id));
        }
        body.push_str(&format!(
            "<div class=\"card my-3\"><div class=\"card-body\">\
             <h2 class=\"h6\">{}</h2>{}\
             <form method=\"post\" action=\"/picture/{}/delete\" class=\"mt-2\">\
             <button class=\"btn btn-sm btn-outline-danger\">Delete picture and thumbnail</button>\
             </form></div></div>",
            esc_str(&p.caption),
            v.render(),
            p.id
        ));
    }

    body.push_str(&format!(
        "<div class=\"card\"><div class=\"card-body\"><h2 class=\"h6\">Add a picture</h2>{}</div></div>",
        UploadForm::new("/").accept("image/*").label("Image").render()
    ));
    shell(&body)
}

async fn upload(State(app): State<App>, headers: HeaderMap, RealIp(ip): RealIp, body: Body) -> Response {
    let upload = match Receiver::new(&*app.store)
        .receive(&headers, body, WriteContext::from(&headers, ip))
        .await
    {
        Ok(u) => u,
        Err(e) => return (e.status(), e.to_string()).into_response(),
    };

    // Generate the thumbnail as its own document. If the upload wasn't a decodable image this is
    // `None`, and the picture simply has no thumbnail — not an error.
    let thumb = thumbs::make(&app.store, upload.handle, 240).await.ok().flatten();

    let _ = picture::ActiveModel {
        caption: Set(upload.filename.clone()),
        handle_id: Set(upload.handle.uuid()),
        thumb_handle_id: Set(thumb.map(|h| h.uuid())),
        ..Default::default()
    }
    .insert(&app.db)
    .await;

    Redirect::to("/").into_response()
}

async fn full(State(app): State<App>, Path(id): Path<i32>, headers: HeaderMap, RealIp(ip): RealIp, uri: Uri) -> Response {
    serve(&app, id, false, &headers, ip, uri.query().unwrap_or("").contains("download=1")).await
}

async fn thumb(State(app): State<App>, Path(id): Path<i32>, headers: HeaderMap, RealIp(ip): RealIp) -> Response {
    serve(&app, id, true, &headers, ip, false).await
}

async fn serve(
    app: &App,
    id: i32,
    want_thumb: bool,
    headers: &HeaderMap,
    ip: std::net::IpAddr,
    attach: bool,
) -> Response {
    // Ungated on purpose: this example is about thumbnails, not authorization. `examples/blob` is
    // the one that shows ownership and gating (BLOBSTORE.md §9).
    let _ = Open;
    let Ok(Some(p)) = picture::Entity::find_by_id(id).one(&app.db).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let handle = if want_thumb { p.thumb_handle_id } else { Some(p.handle_id) };
    let Some(handle) = handle else { return StatusCode::NOT_FOUND.into_response() };
    let Ok(head) = app.store.head(HandleId(handle)).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match app.store.read(head.id, WriteContext::from(headers, ip)).await {
        Ok(s) if attach => to_response(s),
        Ok(s) => to_inline_response(s),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// One deletion path for both documents — the simplification this example exists to demonstrate.
async fn delete(State(app): State<App>, Path(id): Path<i32>, headers: HeaderMap, RealIp(ip): RealIp) -> Response {
    let Ok(Some(p)) = picture::Entity::find_by_id(id).one(&app.db).await else {
        return Redirect::to("/").into_response();
    };
    let ctx = WriteContext::from(&headers, ip);
    let _ = picture::Entity::delete_by_id(id).exec(&app.db).await;
    let _ = app.store.delete_handle(HandleId(p.handle_id), ctx).await;
    if let Some(t) = p.thumb_handle_id {
        let _ = app.store.delete_handle(HandleId(t), ctx).await;
    }
    // Nothing references those bytes now. Collection is the app's to schedule; here it is immediate
    // so the effect is visible.
    match app.store.collect_garbage().await {
        Ok(r) => println!("[gc] {} unreferenced blob(s) deleted", r.deleted.len()),
        Err(e) => eprintln!("[gc] failed: {e}"),
    }
    Redirect::to("/").into_response()
}

fn shell(body: &str) -> Response {
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <title>Thumbnails</title>\
         <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css\" rel=\"stylesheet\">\
         <style>{}</style></head>\
         <body class=\"bg-body-tertiary\"><main class=\"container my-4\">{body}</main></body></html>",
        relativelylight::crud::ui::CSS
    ))
    .into_response()
}
