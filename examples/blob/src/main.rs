//! blob example — **content-addressed file storage with a version chain**, and the ownership
//! pattern the module deliberately doesn't ship (`docs/BLOBSTORE.md` §9).
//!
//! The library stores documents; it stores no *owner*. This example is the other half: a
//! `ticket_document` link table carrying `owner_user_id` as a real foreign key onto `auth_user`, one
//! gate over that table, and download routes addressed by **ticket and attachment** rather than by
//! handle — so authorization is a plain gated query on the app's own row and a handle id never
//! appears in a URL.
//!
//! What to look at:
//!
//! - **`/ticket/1`** — attachments rendered by `blob::ui::Viewer` (always a URL, never inlined
//!   bytes), an upload form, and the version history of each document.
//! - **Upload** — `blob::ui::Receiver` streams the posted file from the socket into the store. The
//!   CSRF token is required *before* the file part, which is what makes a streaming upload
//!   CSRF-checkable at all; `UploadForm` renders it first for exactly that reason.
//! - **Replace a file** — a new *version* of the same document. The attachment's id never changes,
//!   so nothing in `ticket_document` is rewritten. That is the whole argument for the handle.
//! - **Delete** — the only way content goes: delete the document, and the next collection frees
//!   whatever bytes no other document still holds. There is deliberately no way to hollow out one
//!   version; the chain is append-only.
//! - **`/admin`** — the blob tables as ordinary CRUD models, with `blob_version` read-only because
//!   an editable immutable chain isn't one.
//! - **`/documents`** — `blob::ui::Browser`: every document, searchable, drilling into its version
//!   chain, with the gated `Actions` (consistency check / garbage collection) beneath it.
//! - **stdout** — one line per committed write *and read*, from a `WriteObserver`. A download is an
//!   auditable event here, not just a write.
//!
//! Two logins: `admin` / `password` (may write anything) and `editor` / `password` (may write only
//! what they own).
//!
//! Try:  cargo run -p blob-example   →   http://127.0.0.1:3000/

mod model;

use askama::Template;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use model::{ticket, ticket_document};
use relativelylight::auth::{self, Auth, Identity, UserReadGroupWrite};
use relativelylight::authz::{Authz, Decision};
use relativelylight::blob::ui::{Actions, BrowseState, Browser, Portal, Receiver, Routes, UploadForm};
use relativelylight::blob::{self, BlobStore, FsBackend, HandleId, WriteContext};
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::{esc_str, Admin, Outcome, ViewState, CSS};
use relativelylight::middleware::RealIp;
use relativelylight::observe::{WriteEvent, WriteObserver};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, Set,
};
use std::net::SocketAddr;
use std::sync::Arc;

const ADMIN_GROUP: &str = "admin";

#[derive(Template)]
#[template(path = "shell.html")]
struct Shell {
    title: String,
    user: String,
    body: String,
    css: String,
}

fn page(title: &str, who: Option<&Identity>, body: String) -> Response {
    let html = Shell {
        title: title.into(),
        user: who.map(|w| w.username.clone()).unwrap_or_default(),
        body,
        css: CSS.to_string(),
    }
    .render()
    .unwrap_or_else(|e| format!("<pre>{e}</pre>"));
    Html(html).into_response()
}

#[derive(Clone)]
struct App {
    db: DatabaseConnection,
    auth: Auth,
    store: Arc<BlobStore<FsBackend>>,
    /// Where the **admin** panel serves content from. Store-wide gated, which is why nothing
    /// user-facing uses it: ticket attachments go through `/ticket/{id}/attachment/{n}`, whose
    /// authorization is a query on the app's own row (BLOBSTORE.md §9.2).
    admin_routes: Routes,
    engine: Arc<relativelylight::crud::engine::Engine>,
    /// The gate over `ticket_document`: logged-in users read, the admin group writes. Per *model*,
    /// which is exactly why the link table is per document kind — see `model.rs`.
    docs_gate: Arc<dyn Authz>,
}

/// Wraps another gate and refuses every mutation, whoever is asking. The blob tables are a record:
/// `BlobStore` is the only thing that may write one, so the console lists and searches them and
/// nothing more.
struct ReadOnly<G: Authz>(G);

#[async_trait::async_trait]
impl<G: Authz> Authz for ReadOnly<G> {
    async fn authorize(
        &self,
        op: relativelylight::authz::Operation,
        headers: &HeaderMap,
    ) -> Decision {
        if op.is_write() {
            return Decision::Denied;
        }
        self.0.authorize(op, headers).await
    }
}

/// One line per committed write **and per served read**. `blob` fires `Operation::Read` from
/// `BlobStore::read`, so a download is in the trail beside the upload that created it.
struct Log;

#[async_trait::async_trait]
impl WriteObserver for Log {
    async fn on_write(&self, ev: &WriteEvent<'_>) {
        let version = ev.version.map(|v| format!(" v{v}")).unwrap_or_default();
        println!(
            "[audit] {:<6} {:?} {}{} key={} from {}",
            ev.source,
            ev.op,
            ev.entity,
            version,
            ev.key.as_deref().unwrap_or("-"),
            ev.client_ip
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fresh in-memory database and a scratch directory, seeded on every start.
    let db = Database::connect("sqlite::memory:").await?;
    auth::migrate(&db).await?;
    blob::migrate(&db).await?;
    model::migrate(&db).await?;

    let root = std::env::temp_dir().join(format!("rl-blob-example-{}", std::process::id()));
    let backend = FsBackend::new(&root);
    // Once, at startup: a misconfigured path should fail here, not on the first upload.
    backend.init().await?;
    println!("blob storage: {}", root.display());

    let auth = Auth::new(db.clone(), Default::default())
        .admin_group(ADMIN_GROUP)
        .secure_cookies(false) // local http
        .login_shell(login_shell)
        .on_write(Arc::new(Log));

    auth::make_admin(&db, ADMIN_GROUP, "admin", "password").await?;
    if auth::create_user(&db, "editor", "password").await.is_ok() {
        auth::add_to_group(&db, "editor", "staff").await?;
    }

    let store = Arc::new(
        BlobStore::new(backend, db.clone())
            .max_bytes(256 * 1024 * 1024)
            .on_write(Arc::new(Log)),
    );

    seed(&db, &store).await?;

    // The admin console: the blob tables as ordinary models.
    let docs_gate: Arc<dyn Authz> =
        Arc::new(UserReadGroupWrite::new(&auth, [ADMIN_GROUP.to_string()]));
    // `Arc<dyn Authz>` so one gate instance can guard several models (the blanket impl forwards).
    //
    // **Read-only, not merely read-only *fields*.** Marking every column `read_only` stops a form
    // rewriting a row, but the console would still offer "+ New" and "Delete selected" — and a
    // version created or removed outside `BlobStore` is a chain with a hole in it. The gate is the
    // place to say so, because it is what the engine actually enforces. Writing one is four lines,
    // which is the point of `authz::Authz` being a trait rather than a fixed set of presets.
    let admin_only: Arc<dyn Authz> = Arc::new(ReadOnly(
        relativelylight::auth::GroupReadWrite::new(&auth, [ADMIN_GROUP.to_string()]),
    ));

    let mut crud = Crud::new(db.clone());
    crud.csrf(auth.csrf());

    let mut handles = MetaModel::new(blob::entity::handle::Entity);
    handles.label_column("id");
    let mut versions = MetaModel::new(blob::entity::version::Entity);
    // Immutable by design: an editable version chain is not a chain (BLOBSTORE.md §5.3).
    for f in [
        "id", "handle_id", "seq", "prev_version_id", "blob_id", "filename", "mime_declared",
        "created_by", "created_at",
    ] {
        versions.field(f).read_only = true;
    }
    let mut content = MetaModel::new(blob::entity::content::Entity);
    for f in ["id", "size_bytes", "mime_sniffed", "created_at", "verified_at"] {
        content.field(f).read_only = true;
    }

    crud.register(MetaModel::new(ticket::Entity), docs_gate.clone());
    crud.register(MetaModel::new(ticket_document::Entity), docs_gate.clone());
    crud.register(handles, admin_only.clone());
    crud.register(versions, admin_only.clone());
    crud.register(content, admin_only.clone());
    let engine = Arc::new(crud.into_engine());

    let admin_routes = Routes::new("/admin/blob");
    let app = App {
        db: db.clone(),
        auth: auth.clone(),
        store: store.clone(),
        engine,
        docs_gate,
        admin_routes: admin_routes.clone(),
    };

    let router = Router::new()
        .route("/", get(index))
        .route("/ticket/{id}", get(show_ticket))
        .route("/ticket/{id}/upload", post(upload))
        .route("/ticket/{tid}/attachment/{did}", get(download))
        .route("/ticket/{tid}/attachment/{did}/v/{seq}", get(download_version))
        .route("/ticket/{tid}/attachment/{did}/replace", post(replace))
        .route("/admin", get(admin_get).post(admin_post))
        .route("/documents", get(browse_get).post(browse_post))
        .with_state(app)
        // The crate's own content router, mounted for the **admin** surface only and gated to the
        // admin group. Everything a normal user touches is routed by its owning ticket instead.
        .nest(
            "/admin/blob",
            admin_routes.router(
                store,
                relativelylight::auth::GroupReadWrite::new(&auth, [ADMIN_GROUP.to_string()]),
            ),
        )
        // `auth.routes()` carries no state of its own, so merge it after ours is bound.
        .merge(auth.routes())
        .layer(axum::middleware::from_fn_with_state(
            relativelylight::middleware::TrustProxy(false),
            relativelylight::middleware::resolve_real_ip,
        ));

    println!("listening on http://127.0.0.1:3000  (admin/password, editor/password)");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

// ===================== pages =====================

async fn index(State(app): State<App>, headers: HeaderMap) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let tickets = ticket::Entity::find().order_by_asc(ticket::Column::Id).all(&app.db).await.unwrap_or_default();

    let mut body = String::from("<h1 class=\"h4 mb-3\">Tickets</h1><div class=\"list-group\">");
    for t in tickets {
        let n = ticket_document::Entity::find()
            .filter(ticket_document::Column::TicketId.eq(t.id))
            .all(&app.db)
            .await
            .map(|v| v.len())
            .unwrap_or(0);
        body.push_str(&format!(
            "<a class=\"list-group-item list-group-item-action d-flex justify-content-between\" href=\"/ticket/{}\">\
             <span>#{} {}</span><span class=\"badge text-bg-secondary\">{n} attachment(s)</span></a>",
            t.id, t.id, esc_str(&t.subject)
        ));
    }
    body.push_str("</div><p class=\"mt-3\"><a href=\"/documents\">Blob store</a> · <a href=\"/admin\">Admin console</a></p>");
    page("Tickets", Some(&who), body)
}

async fn show_ticket(
    State(app): State<App>,
    Path(id): Path<i32>,
    headers: HeaderMap,
) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let Ok(Some(t)) = ticket::Entity::find_by_id(id).one(&app.db).await else {
        return (StatusCode::NOT_FOUND, "no such ticket").into_response();
    };
        let docs = ticket_document::Entity::find()
        .filter(ticket_document::Column::TicketId.eq(id))
        .order_by_asc(ticket_document::Column::Id)
        .all(&app.db)
        .await
        .unwrap_or_default();

    let mut body = format!(
        "<h1 class=\"h4\">#{} {}</h1><p class=\"text-body-secondary\">{}</p>",
        t.id,
        esc_str(&t.subject),
        esc_str(&t.status)
    );

    for d in &docs {
        let handle = HandleId(d.handle_id);
        let owner = auth::user::Entity::find_by_id(d.owner_user_id)
            .one(&app.db)
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
            .unwrap_or_else(|| "?".into());

        // One component for the whole attachment: current version, history, and the form that adds
        // the next one. Its URLs name the *ticket and attachment*, never the handle — so
        // authorization stays a gated query on our own row (BLOBSTORE.md §9.2) and the admin
        // router mounted at /admin/blob is not involved.
        let base = format!("/ticket/{}/attachment/{}", t.id, d.id);
        let portal = Portal::new(&*app.store, handle, app.docs_gate.clone())
            .view_url(format!("{base}/v/{{version}}"))
            .versions(true)
            .upload_form(
                UploadForm::new(format!("{base}/replace"))
                    .as_new_version()
                    .csrf(app.auth.csrf().token(&headers).unwrap_or_default()),
            )
            .render_for(&headers)
            .await
            .unwrap_or_else(|_| "<em>not allowed</em>".into());

        body.push_str(&format!(
            "<div class=\"card my-3\"><div class=\"card-body\">\
             <div class=\"d-flex justify-content-between\">\
             <span class=\"badge text-bg-light\">{}</span>\
             <small class=\"text-body-secondary\">owner: {}</small></div>\
             {portal}</div></div>",
            esc_str(&d.role),
            esc_str(&owner),
        ));
    }

    body.push_str(&format!(
        "<div class=\"card my-3\"><div class=\"card-body\"><h2 class=\"h6\">Attach a document</h2>{}</div></div>\
         <p><a href=\"/\">&larr; all tickets</a></p>",
        // Creating a document is the *app's* act — it has to record ownership — so this form is
        // standalone rather than something `Portal` offers.
        UploadForm::new(format!("/ticket/{}/upload", t.id))
            .max_bytes(256 * 1024 * 1024)
            .csrf(app.auth.csrf().token(&headers).unwrap_or_default())
            .render()
    ));

    page(&format!("Ticket #{}", t.id), Some(&who), body)
}

// ===================== writes =====================

async fn upload(
    State(app): State<App>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    RealIp(ip): RealIp,
    body: Body,
) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    if app.docs_gate.authorize(relativelylight::authz::Operation::Create, &headers).await
        != Decision::Allow
    {
        return (StatusCode::FORBIDDEN, "not allowed to attach documents").into_response();
    }

    // `Body`, not `Bytes`: the file streams from the socket into the store and never assembles in
    // memory, and axum's 2 MB `DefaultBodyLimit` doesn't apply to a streamed body.
    let ctx = WriteContext::from(&headers, ip);
    let csrf = app.auth.csrf();
    let upload = match Receiver::new(&*app.store)
        .by(Some(who.username.clone()))
        .csrf(&csrf)
        .receive(&headers, body, ctx)
        .await
    {
        Ok(u) => u,
        Err(e) => return (e.status(), e.to_string()).into_response(),
    };

    // Only now does the app's own row appear — with the owner it could not have stored in `blob`.
    let _ = ticket_document::ActiveModel {
        ticket_id: Set(id),
        handle_id: Set(upload.handle.uuid()),
        owner_user_id: Set(user_id(&who)),
        role: Set("attachment".into()),
        ..Default::default()
    }
    .insert(&app.db)
    .await;

    Redirect::to(&format!("/ticket/{id}")).into_response()
}

async fn replace(
    State(app): State<App>,
    Path((tid, did)): Path<(i32, i32)>,
    headers: HeaderMap,
    RealIp(ip): RealIp,
    body: Body,
) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let Some(doc) = find_doc(&app, tid, did).await else {
        return (StatusCode::NOT_FOUND, "no such attachment").into_response();
    };
    if !may_write(&app, &who, &doc, &headers).await {
        return (StatusCode::FORBIDDEN, "not your document").into_response();
    }

    // A new **version** of the same handle: `ticket_document.handle_id` is untouched, which is the
    // whole argument for a stable handle.
    let csrf = app.auth.csrf();
    match Receiver::new(&*app.store)
        .as_version_of(HandleId(doc.handle_id))
        .by(Some(who.username.clone()))
        .csrf(&csrf)
        .receive(&headers, body, WriteContext::from(&headers, ip))
        .await
    {
        Ok(_) => Redirect::to(&format!("/ticket/{tid}")).into_response(),
        Err(e) => (e.status(), e.to_string()).into_response(),
    }
}

// ===================== downloads =====================

/// **Routed by the owning document, never by the handle** (BLOBSTORE.md §9.2). Authorization is a
/// gated query on the app's own row; a handle id never appears in a URL, so it never has to be
/// treated as a secret.
async fn download(
    State(app): State<App>,
    Path((tid, did)): Path<(i32, i32)>,
    headers: HeaderMap,
    RealIp(ip): RealIp,
    uri: Uri,
) -> Response {
    // One handler, two dispositions. `?download=1` is the second URL the viewer's download button
    // points at; without it the content is served inline so an <img>/<embed> can display it.
    let attach = uri.query().unwrap_or("").contains("download=1");
    serve(app, tid, did, None, headers, ip, attach).await
}

/// The same, for one specific version — proof the chain is real and old versions stay readable.
///
/// Addressed by **version id**, which is what `Portal`'s `{version}` placeholder substitutes. The
/// id alone would be enough to find the row, but the route still checks it belongs to *this*
/// attachment's handle: the authorization we just did was about the ticket, so a version from some
/// other document must not be reachable through it.
async fn download_version(
    State(app): State<App>,
    Path((tid, did, version)): Path<(i32, i32, i64)>,
    headers: HeaderMap,
    RealIp(ip): RealIp,
    uri: Uri,
) -> Response {
    let attach = uri.query().unwrap_or("").contains("download=1");
    serve(app, tid, did, Some(version.into()), headers, ip, attach).await
}

async fn serve(
    app: App,
    tid: i32,
    did: i32,
    want: Option<blob::VersionId>,
    headers: HeaderMap,
    ip: std::net::IpAddr,
    attach: bool,
) -> Response {
    if app.auth.identify(&headers).await.is_none() {
        return Redirect::to(app.auth.login_path()).into_response();
    }
    if app.docs_gate.authorize(relativelylight::authz::Operation::Read, &headers).await
        != Decision::Allow
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(doc) = find_doc(&app, tid, did).await else {
        return (StatusCode::NOT_FOUND, "no such attachment").into_response();
    };

    let handle = HandleId(doc.handle_id);
    let version = match want {
        None => app.store.head(handle).await,
        Some(id) => app.store.versions(handle).await.and_then(|vs| {
            vs.into_iter()
                .find(|v| v.id == id)
                .ok_or_else(|| blob::BlobError::NotFound(format!("version {id} of this attachment")))
        }),
    };
    let Ok(version) = version else {
        return (StatusCode::NOT_FOUND, "no such version").into_response();
    };

    // `read` verifies the digest in full before handing back a stream, and fires the audit event.
    match app.store.read(version.id, WriteContext::from(&headers, ip)).await {
        Ok(h) if attach => blob::ui::to_response(h),
        // Inline, so the viewer's <img>/<embed> display — but only for the allowlisted types; an
        // SVG comes back as an attachment however it was uploaded.
        Ok(h) => blob::ui::to_inline_response(h),
        Err(blob::BlobError::Corrupt { .. }) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "stored content failed its digest check")
                .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ===================== admin =====================

fn panel(app: &App) -> Admin<'_> {
    Admin::new(&app.engine)
        .title("Admin")
        .entity("ticket")
        .entity("ticket_document")
        .entity("blob_handle")
        .entity("blob_version")
        .entity("blob")
        .separator()
        .link("Blob store", "/documents")
}

async fn admin_get(State(app): State<App>, headers: HeaderMap, uri: Uri) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let state = ViewState::from_uri(&uri);
    match panel(&app).render_for(&headers, &state).await {
        Ok(html) => page("Admin", Some(&who), html),
        Err(e) => e.into_response(), // crud::Error maps itself to 401/403/409/…
    }
}

async fn admin_post(
    State(app): State<App>,
    headers: HeaderMap,
    RealIp(ip): RealIp,
    uri: Uri,
    body: axum::body::Bytes,
) -> Response {
    let state = ViewState::from_uri(&uri);
    match panel(&app).submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        Ok(Outcome::Invalid(state)) => {
            let who = app.auth.identify(&headers).await;
            match panel(&app).render_for(&headers, &state).await {
                Ok(html) => page("Admin", who.as_ref(), html),
                Err(e) => e.into_response(),
            }
        }
        Err(e) => e.into_response(), // crud::Error maps itself to 401/403/409/…
    }
}

/// The store browser: every document, searchable, drilling into one's version chain — with the
/// maintenance controls beneath it rather than on a page of their own.
async fn browse_get(State(app): State<App>, headers: HeaderMap, uri: Uri) -> Response {
    let who = app.auth.identify(&headers).await;
    if who.is_none() {
        return Redirect::to(app.auth.login_path()).into_response();
    }
    match render_browser(&app, &headers, &BrowseState::from_uri(&uri), None).await {
        Ok(html) => page("Blob store", who.as_ref(), html),
        Err(Decision::NeedsLogin) => Redirect::to(app.auth.login_path()).into_response(),
        Err(_) => (StatusCode::FORBIDDEN, "admins only").into_response(),
    }
}

async fn browse_post(
    State(app): State<App>,
    headers: HeaderMap,
    RealIp(ip): RealIp,
    uri: Uri,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    if !app.auth.csrf().verify(&headers, form.get("_csrf").map(String::as_str)) {
        return (StatusCode::FORBIDDEN, "bad CSRF token").into_response();
    }
    let who = app.auth.identify(&headers).await;
    // One entry point for the whole panel — the browser dispatches `delete`, `check` and `collect`
    // and gates each, so this handler doesn't have to get that right three times.
    let gate = relativelylight::auth::GroupReadWrite::new(&app.auth, [ADMIN_GROUP.to_string()]);
    let outcome = match browser(&app, &headers, gate)
        .submit(&headers, &form, WriteContext::from(&headers, ip))
        .await
    {
        Ok(o) => o,
        Err(Decision::NeedsLogin) => return Redirect::to(app.auth.login_path()).into_response(),
        Err(_) => return (StatusCode::FORBIDDEN, "admins only").into_response(),
    };
    match render_browser(&app, &headers, &BrowseState::from_uri(&uri), Some(outcome)).await {
        Ok(html) => page("Blob store", who.as_ref(), html),
        Err(_) => (StatusCode::FORBIDDEN, "admins only").into_response(),
    }
}

/// The panel: a browser with the maintenance menu attached, both on the same admin gate.
fn browser<'a>(
    app: &'a App,
    headers: &HeaderMap,
    gate: relativelylight::auth::GroupReadWrite,
) -> Browser<'a, FsBackend> {
    let token = app.auth.csrf().token(headers).unwrap_or_default();
    let actions_gate =
        relativelylight::auth::GroupReadWrite::new(&app.auth, [ADMIN_GROUP.to_string()]);
    Browser::new(&*app.store, gate)
        // The component links versions at a route *the app* owns; it invents none of its own.
        .routes(&app.admin_routes)
        .actions(Actions::new(&*app.store, actions_gate).csrf(token))
}

async fn render_browser(
    app: &App,
    headers: &HeaderMap,
    state: &BrowseState,
    outcome: Option<relativelylight::blob::ui::ActionOutcome>,
) -> Result<String, Decision> {
    let gate = relativelylight::auth::GroupReadWrite::new(&app.auth, [ADMIN_GROUP.to_string()]);
    let panel = browser(app, headers, gate).render_for(headers, state).await?;

    let banner = outcome
        .map(|o| {
            format!(
                "<div class=\"alert {}\">{}</div>",
                if o.alarming { "alert-warning" } else { "alert-success" },
                esc_str(&o.message)
            )
        })
        .unwrap_or_default();

    // The panel renders its own heading and its own maintenance menu.
    Ok(format!("{banner}{panel}<p class=\"mt-3\"><a href=\"/\">&larr; tickets</a></p>"))
}

// ===================== helpers =====================

async fn find_doc(app: &App, tid: i32, did: i32) -> Option<ticket_document::Model> {
    ticket_document::Entity::find_by_id(did)
        .filter(ticket_document::Column::TicketId.eq(tid))
        .one(&app.db)
        .await
        .ok()
        .flatten()
}

/// Ownership in one place: the owner, or the admin group. This is the check the library could not
/// have made for us — it is about a *row in the app's table*, which `blob` has never heard of.
async fn may_write(
    app: &App,
    who: &Identity,
    doc: &ticket_document::Model,
    headers: &HeaderMap,
) -> bool {
    doc.owner_user_id == user_id(who)
        || app.docs_gate.authorize(relativelylight::authz::Operation::Update, headers).await
            == Decision::Allow
}

async fn seed(db: &DatabaseConnection, store: &BlobStore<FsBackend>) -> Result<(), Box<dyn std::error::Error>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    for (subject, status) in [
        ("Printer on floor 2 jams", "open"),
        ("VPN certificate expires next month", "waiting"),
    ] {
        ticket::ActiveModel {
            subject: Set(subject.into()),
            status: Set(status.into()),
            opened_at: Set(now),
            ..Default::default()
        }
        .insert(db)
        .await?;
    }

    // Two seeded attachments, so both `Viewer` branches are visible on first load — and the image
    // one carries **two versions**, which is the demo that matters: upload a replacement and the
    // picture changes while `ticket_document.handle_id` stays exactly as it was.
    let admin = auth::user::Entity::find()
        .filter(auth::user::Column::Username.eq("admin"))
        .one(db)
        .await?
        .expect("seeded admin");

    let diagram = store
        .create(
            &include_bytes!("../assets/diagram-v1.png")[..],
            blob::PutMeta::new("diagram.png").mime("image/png").by("admin"),
            WriteContext::none(),
        )
        .await?;
    store
        .add_version(
            diagram,
            &include_bytes!("../assets/diagram-v2.png")[..],
            blob::PutMeta::new("diagram.png").mime("image/png").by("admin"),
            WriteContext::none(),
        )
        .await?;

    let notes = store
        .create(
            &b"Printer jams on the third sheet. Serial FX-22841. Replaced the pickup roller.\n"[..],
            blob::PutMeta::new("engineer-notes.txt").mime("text/plain").by("admin"),
            WriteContext::none(),
        )
        .await?;

    for (handle, role) in [(diagram, "diagram"), (notes, "notes")] {
        ticket_document::ActiveModel {
            ticket_id: Set(1),
            handle_id: Set(handle.uuid()),
            owner_user_id: Set(admin.id),
            role: Set(role.into()),
            ..Default::default()
        }
        .insert(db)
        .await?;
    }
    Ok(())
}

/// `Identity::id` is the `auth_user` primary key **as a string** (the type is deliberately
/// source-agnostic — an SSO or API-token identity need not have an integer key). Our own column is
/// an `i32` foreign key, so this is the one place the two meet.
fn user_id(who: &Identity) -> i32 {
    who.id.parse().unwrap_or_default()
}

/// The library renders the login *fragment*; the app wraps it. Same shell as every other page here.
fn login_shell(form: &str) -> String {
    let body = format!(
        "<div class=\"card shadow-sm mx-auto\" style=\"max-width:24rem\"><div class=\"card-body\">\
         <h1 class=\"h5 mb-3\">Sign in</h1>{form}\
         <p class=\"text-body-secondary small mt-3 mb-0\">admin / password · editor / password</p>\
         </div></div>"
    );
    Shell { title: "Sign in".into(), user: String::new(), body, css: CSS.to_string() }
        .render()
        .unwrap_or_else(|e| format!("<pre>{e}</pre>"))
}
