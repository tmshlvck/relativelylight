//! examples/files — **files in a directory**: upload, preview, download, delete, thumbnails.
//!
//! The crate contributes four things, and only these: the streaming upload reader (`Upload`), the
//! responses (`to_response`, `to_inline_response`), and the components (`UploadForm`, `Preview`,
//! `Thumbnail`). Everything else is this app's, because it depends on where the files live:
//!
//! - `src/store.rs` — a flat directory: names, listing, no-clobber writes, delete.
//! - `src/thumbs.rs` — thumbnails made on request into a cache keyed by content hash.
//! - this file — the routes, the listing table and the decisions: what a file is called, who may
//!   see it (here: anyone), what a failed upload leaves behind.
//!
//! An app with a database keeps an index table and link tables instead of listing a directory —
//! docs/FILES.md §4.
//!
//! What to look at:
//!
//! - **Upload** — pick several files at once, or (on a phone) take a photo. Give a name, or keep the
//!   uploaded one; a name that is taken becomes `name (2).ext` rather than overwriting.
//! - **The list** — images show a thumbnail, other files a badge. Images and PDFs preview in the
//!   page, and so does text — in full up to 5 MiB, beyond that its first 5 MiB and a download link.
//!   An SVG or HTML file is only ever downloaded.
//! - **stdout** — one line per stored file, with the SHA-256 computed while it streamed, and one per
//!   thumbnail generated (reload the page: none, they come from the cache).
//!
//! ```text
//! cargo run -p files-example                          # http://127.0.0.1:3000
//! FILES_ROOT=/tmp/files THUMB_CACHE=/tmp/thumbs cargo run -p files-example
//! LISTEN=0.0.0.0:3000 cargo run -p files-example     # reachable from a phone: try the camera
//! ```

mod store;
mod thumbs;

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use axum_extra::extract::CookieJar;
use relativelylight::csrf::Csrf;
use relativelylight::files::{
    human_size, sniff_mime, to_inline_response, to_response, url_segment, Download, Part, Preview,
    Thumbnail, Upload, UploadForm, SNIFF_BYTES, TEXT_PREVIEW_MAX,
};
use tokio::io::AsyncReadExt;

use store::Store;

const MAX_BYTES: u64 = 256 * 1024 * 1024;
/// Thumbnails are made at twice the tile's size, so they stay sharp on a high-density screen.
const TILE_PX: u32 = 64;

#[derive(Clone)]
struct App {
    store: Arc<Store>,
    thumbs: Arc<thumbs::Cache>,
    csrf: Csrf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = std::env::temp_dir();
    let root = std::env::var_os("FILES_ROOT").map(Into::into);
    let store = Store::open(root.unwrap_or_else(|| tmp.join("rl-files-example"))).await?;
    let cache = std::env::var_os("THUMB_CACHE").map(Into::into);
    let thumbs = thumbs::Cache::open(
        cache.unwrap_or_else(|| tmp.join("rl-files-example-thumbs")),
        TILE_PX * 2,
    )
    .await?;
    println!("files in {}, thumbnails in {}", store.root().display(), thumbs.dir().display());

    // Without `auth` there is no session, but a form that changes something still needs a CSRF
    // token: the double-submit cookie works on its own. (`secure(false)`: this serves plain http.)
    let app =
        App { store: Arc::new(store), thumbs: Arc::new(thumbs), csrf: Csrf::new().secure(false) };

    // Every route is open here. A real app checks the caller in each handler — for a file attached
    // to an invoice, "may this user see that invoice" — before it opens anything.
    let router = Router::new()
        .route("/", get(index))
        .route("/upload", post(upload))
        .route("/view/{name}", get(view))
        .route("/raw/{name}", get(raw))
        .route("/download/{name}", get(download))
        .route("/thumb/{name}", get(thumbnail))
        .route("/delete/{name}", post(delete))
        .with_state(app);

    // Loopback by default. `LISTEN=0.0.0.0:3000` to reach it from a phone on the same network —
    // which also exposes every route here, unauthenticated, to that network.
    let addr = std::env::var("LISTEN").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("listening on http://{addr}");
    axum::serve(listener, router).await?;
    Ok(())
}

/// The listing is the app's own table; the crate renders the tile in its first column.
async fn index(State(app): State<App>, headers: HeaderMap, jar: CookieJar) -> Response {
    let (token, cookie) = app.csrf.ensure(&headers);
    let jar = match cookie {
        Some(c) => jar.add(c),
        None => jar,
    };
    let entries = match app.store.list().await {
        Ok(e) => e,
        Err(e) => return error(e),
    };
    let mut rows = String::new();
    for e in &entries {
        let seg = url_segment(&e.name);
        // The type the bytes say. An app with an index table stores it at upload instead of reading
        // every file per page view.
        let mime = sniff(&app.store, &e.name).await;
        let mut tile = Thumbnail::new(&e.name).href(format!("/view/{seg}")).px(TILE_PX);
        if thumbs::raster(mime) {
            tile = tile.src(format!("/thumb/{seg}"));
        }
        rows.push_str(&format!(
            "<tr><td style=\"width:1%\">{}</td>\
             <td class=\"text-break\"><a href=\"/view/{seg}\">{}</a>\
             <div class=\"small text-body-secondary\">{} · {mime}</div></td>\
             <td class=\"text-end text-nowrap\"><a class=\"btn btn-sm btn-outline-secondary\" href=\"/download/{seg}\" download>Download</a> \
             <form method=\"post\" action=\"/delete/{seg}\" class=\"d-inline\">\
             <input type=\"hidden\" name=\"_csrf\" value=\"{}\">\
             <button class=\"btn btn-sm btn-outline-danger\">Delete</button></form></td></tr>",
            tile.render(),
            esc(&e.name),
            human_size(e.size),
            esc(&token),
        ));
    }
    let list = if rows.is_empty() {
        "<p class=\"text-body-secondary\">No files yet.</p>".to_owned()
    } else {
        format!("<table class=\"table align-middle\"><tbody>{rows}</tbody></table>")
    };
    let form = UploadForm::new("/upload")
        .csrf(&token)
        .name_field("name", "Save as")
        .multiple()
        .label("Files")
        .max_bytes(MAX_BYTES);
    // One tap on a phone: camera, accept, posted — under the name the phone sends, else `photo.jpg`.
    let photo = UploadForm::photo("/upload", "Take a photo").csrf(&token);
    let body = format!(
        "<h1 class=\"h4 mb-1\">Files</h1>\
         <p class=\"text-body-secondary small mb-4\">{}</p>\
         <div class=\"row g-4\"><div class=\"col-lg-8\">{list}</div>\
         <div class=\"col-lg-4\"><div class=\"mb-3\">{}</div>\
         <div class=\"card\"><div class=\"card-body\">{}</div></div></div></div>",
        esc(&app.store.root().display().to_string()),
        photo.render(),
        form.render()
    );
    (jar, shell(&body)).into_response()
}

/// `POST /upload` — read the form part by part and write each file as it streams in.
///
/// `UploadForm` posts the name field before the files, so the name is known before the first byte
/// of the first file. Each file is committed when it is complete; if a later one is refused, the
/// earlier ones stay — this app's choice. An all-or-nothing app would keep them pending until the
/// end, or write inside a database transaction.
async fn upload(State(app): State<App>, headers: HeaderMap, body: Body) -> Response {
    let mut up = match Upload::new(&headers, body) {
        Ok(up) => up.csrf(&app.csrf).max_bytes(MAX_BYTES),
        Err(e) => return (e.status(), e.to_string()).into_response(),
    };
    let mut save_as: Option<String> = None;
    loop {
        let part = match up.next().await {
            Ok(Some(part)) => part,
            Ok(None) => break,
            Err(e) => return (e.status(), e.to_string()).into_response(),
        };
        let mut file = match part {
            Part::Field(name, value) if name == "name" => {
                save_as = Some(value.trim().to_owned()).filter(|v| !v.is_empty());
                continue;
            }
            Part::Field(..) => continue,
            Part::File(file) => file,
        };
        // The name typed into the form, else the uploaded one; a phone's camera may send none.
        let wanted = match &save_as {
            Some(name) => with_extension_of(name, file.filename()),
            None if file.filename().is_empty() => format!("photo.{}", extension(file.mime())),
            None => file.filename().to_owned(),
        };
        let mut pending = match app.store.create().await {
            Ok(p) => p,
            Err(e) => return error(e),
        };
        let written = async {
            while let Some(chunk) = file.chunk().await.map_err(|e| (e.status(), e.to_string()))? {
                pending
                    .write(&chunk)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            }
            Ok::<_, (StatusCode, String)>(())
        }
        .await;
        if let Err(refused) = written {
            pending.discard().await;
            return refused.into_response();
        }
        match pending.commit(&store::clean(&wanted)).await {
            Ok(stored) => println!(
                "stored {stored:?} ({}, {}, sha256 {})",
                human_size(file.size()),
                file.mime(),
                file.sha256().unwrap_or_default()
            ),
            Err(e) => return error(e),
        }
    }
    if up.files() == 0 {
        return (StatusCode::BAD_REQUEST, "no file was submitted").into_response();
    }
    Redirect::to("/").into_response()
}

/// `GET /view/{name}` — a page with the preview on it.
async fn view(State(app): State<App>, Path(name): Path<String>) -> Response {
    let Some(path) = app.store.path(&name) else { return StatusCode::BAD_REQUEST.into_response() };
    let Ok(meta) = tokio::fs::metadata(&path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let seg = url_segment(&name);
    let mime = sniff(&app.store, &name).await;
    let mut preview = Preview::new(&name, mime, format!("/raw/{seg}"))
        .size(meta.len())
        .download_url(format!("/download/{seg}"));
    // Text goes into the page itself, so the component needs the bytes: read the file, or its first
    // TEXT_PREVIEW_MAX bytes — `Preview` then notes how much of the whole it shows. (To show only the
    // note for a large file, read nothing and pass `&[]`.)
    if mime.starts_with("text/") {
        let mut head = Vec::new();
        if let Ok(f) = tokio::fs::File::open(&path).await {
            let _ = f.take(TEXT_PREVIEW_MAX).read_to_end(&mut head).await;
        }
        preview = preview.text(&head);
    }
    shell(&format!("<p><a href=\"/\">← all files</a></p>{}", preview.render())).into_response()
}

/// `GET /raw/{name}` — the content, inline when its type is safe to render.
async fn raw(State(app): State<App>, Path(name): Path<String>) -> Response {
    match open(&app.store, &name).await {
        Ok(d) => to_inline_response(d),
        Err(status) => status.into_response(),
    }
}

/// `GET /download/{name}` — the content, always as an attachment.
async fn download(State(app): State<App>, Path(name): Path<String>) -> Response {
    match open(&app.store, &name).await {
        Ok(d) => to_response(d),
        Err(status) => status.into_response(),
    }
}

/// `GET /thumb/{name}` — from the cache, or made now and cached.
async fn thumbnail(
    State(app): State<App>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(path) = app.store.path(&name) else { return StatusCode::BAD_REQUEST.into_response() };
    if !thumbs::raster(sniff(&app.store, &name).await) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some((png, hash)) = app.thumbs.get(&path).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let etag = format!("\"{hash}\"");
    if headers.get(header::IF_NONE_MATCH).is_some_and(|v| v.as_bytes() == etag.as_bytes()) {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    let mut res = to_inline_response(Download::from_bytes(png, format!("{name}.png")));
    // Revalidate every time: the URL names the file, not the content, so it may change. With the
    // hash in the URL (an app with an index table) this would be `max-age=31536000, immutable`.
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-cache"));
    res.headers_mut().insert(header::ETAG, HeaderValue::from_str(&etag).expect("hex"));
    res
}

/// `POST /delete/{name}` — a plain form post, so the token is checked here. The thumbnail stays in
/// the cache: it is keyed by content, and another file may have the same.
async fn delete(
    State(app): State<App>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !app.csrf.verify(&headers, form.get("_csrf").map(String::as_str)) {
        return app.csrf.reject();
    }
    match app.store.delete(&name).await {
        Ok(()) => {
            println!("deleted {name:?}");
            Redirect::to("/").into_response()
        }
        Err(e) => error(e),
    }
}

/// A stored file as a `Download`, typed by its bytes.
async fn open(store: &Store, name: &str) -> Result<Download, StatusCode> {
    let path = store.path(name).ok_or(StatusCode::BAD_REQUEST)?;
    let file = tokio::fs::File::open(&path).await.map_err(|_| StatusCode::NOT_FOUND)?;
    let len = file.metadata().await.map_err(|_| StatusCode::NOT_FOUND)?.len();
    Ok(Download::new(file, name, sniff(store, name).await).content_length(len))
}

/// The type the first bytes of a stored file say.
async fn sniff(store: &Store, name: &str) -> &'static str {
    let mut head = Vec::with_capacity(SNIFF_BYTES);
    if let Some(path) = store.path(name) {
        if let Ok(f) = tokio::fs::File::open(path).await {
            let _ = f.take(SNIFF_BYTES as u64).read_to_end(&mut head).await;
        }
    }
    sniff_mime(&head)
}

/// A typed name without an extension keeps the uploaded file's: "invoice" + "scan.pdf" → "invoice.pdf".
fn with_extension_of(name: &str, uploaded: &str) -> String {
    match (name.contains('.'), uploaded.rsplit_once('.')) {
        (false, Some((_, ext))) if !ext.is_empty() => format!("{name}.{ext}"),
        _ => name.to_owned(),
    }
}

fn extension(mime: &str) -> &str {
    match mime {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/webp" => "webp",
        "image/gif" => "gif",
        _ => "bin",
    }
}

fn error(e: std::io::Error) -> Response {
    let status = match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NOT_FOUND,
        std::io::ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, e.to_string()).into_response()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn shell(body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Files</title>\
         <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css\" rel=\"stylesheet\">\
         </head><body class=\"bg-body-tertiary\"><main class=\"container my-4\">{body}</main></body></html>"
    ))
}
