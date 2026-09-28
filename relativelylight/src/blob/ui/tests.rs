//! Tests for `blob-ui`. As in `auth/security_tests.rs`, the negatives are the point and each has a
//! positive control beside it so it can't pass vacuously.
//!
//! - **upload** — the file really does stream (a body larger than any buffer round-trips), and the
//!   CSRF token is required *before* the file part, which is the whole reason this path exists
//!   rather than a buffered one.
//! - **escaping** — every value a document can carry (filename, URL) reaches the page escaped,
//!   tested with `<script>`-bearing data, matching `crud/ui_tests.rs`.
//! - **response** — the inline allowlist, and that a filename cannot inject a header.

use axum::body::Body;
use http::{header, HeaderMap, HeaderValue};

use super::*;
use crate::blob::{BlobStore, FsBackend, PutMeta, VersionInfo, WriteContext};

const BOUNDARY: &str = "----rltestboundary";

async fn store(root: &std::path::Path) -> BlobStore<FsBackend> {
    let backend = FsBackend::new(root);
    backend.init().await.unwrap();
    let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
    crate::blob::migrate(&db).await.unwrap();
    BlobStore::new(backend, db)
}

fn multipart_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&format!("multipart/form-data; boundary={BOUNDARY}")).unwrap(),
    );
    h
}

/// Build a body from `(name, filename, content)` parts, in the order given — which is the whole
/// point for the CSRF tests.
fn body(parts: &[(&str, Option<&str>, &[u8])]) -> Body {
    let mut out = Vec::new();
    for (name, filename, content) in parts {
        out.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        match filename {
            Some(f) => out.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\n\r\n"
                )
                .as_bytes(),
            ),
            None => out.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            ),
        }
        out.extend_from_slice(content);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    Body::from(out)
}

// ===================== Upload =====================

#[tokio::test]
async fn a_posted_file_streams_into_the_store_with_its_other_fields() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path()).await;

    let up = Receiver::new(&store)
        .by(Some("alice".into()))
        .receive(
            &multipart_headers(),
            body(&[
                ("note", None, b"quarterly scan"),
                ("file", Some("report.pdf"), b"%PDF-1.7 body"),
            ]),
            WriteContext::none(),
        )
        .await
        .expect("upload");

    assert_eq!(up.filename, "report.pdf");
    assert_eq!(up.size, 13);
    assert_eq!(up.field("note"), Some("quarterly scan"));

    let head = store.head(up.handle).await.unwrap();
    assert_eq!(head.filename, "report.pdf");
    assert_eq!(head.created_by.as_deref(), Some("alice"));
    assert_eq!(
        head.content.as_ref().unwrap().mime_sniffed,
        "application/pdf",
        "the type is sniffed from the streamed prefix"
    );
}

#[tokio::test]
async fn a_file_bigger_than_any_buffer_arrives_intact() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path()).await;
    let content: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();

    let up = Receiver::new(&store)
        .receive(
            &multipart_headers(),
            body(&[("file", Some("big.bin"), &content)]),
            WriteContext::none(),
        )
        .await
        .expect("upload");

    assert_eq!(up.size, content.len() as u64);
    let read = store
        .read(up.version, WriteContext::none())
        .await
        .unwrap()
        .into_bytes()
        .await
        .unwrap();
    assert_eq!(read, content, "every byte survives the streaming round trip");
}

#[tokio::test]
async fn an_upload_over_the_limit_is_refused_and_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path()).await.max_bytes(64);

    let err = Receiver::new(&store)
        .receive(
            &multipart_headers(),
            body(&[("file", Some("big.bin"), &vec![b'x'; 5000])]),
            WriteContext::none(),
        )
        .await;

    assert!(matches!(err, Err(UploadError::Blob(crate::blob::BlobError::TooLarge { .. }))));
    assert_eq!(err.unwrap_err().status(), http::StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        0,
        "the partial upload was discarded, not left staged"
    );
}

#[tokio::test]
async fn an_oversized_text_field_is_refused_rather_than_buffered_without_limit() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path()).await;

    let err = Receiver::new(&store)
        .max_field_bytes(32)
        .receive(
            &multipart_headers(),
            body(&[("note", None, &vec![b'x'; 1000]), ("file", Some("f.txt"), b"body")]),
            WriteContext::none(),
        )
        .await;

    assert!(matches!(err, Err(UploadError::FieldTooLarge { .. })));
}

#[tokio::test]
async fn a_form_with_no_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path()).await;
    let err = Receiver::new(&store)
        .receive(&multipart_headers(), body(&[("note", None, b"nothing attached")]), WriteContext::none())
        .await;
    assert!(matches!(err, Err(UploadError::NoFile)));
}

#[tokio::test]
async fn a_body_that_is_not_multipart_is_refused_before_anything_is_parsed() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path()).await;
    let err = Receiver::new(&store)
        .receive(&HeaderMap::new(), Body::from("just some bytes"), WriteContext::none())
        .await;
    assert!(matches!(err, Err(UploadError::NotMultipart)));
}

#[tokio::test]
async fn appending_a_version_through_the_form_extends_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path()).await;
    let h = store
        .create(&b"v1"[..], PutMeta::new("doc.txt"), WriteContext::none())
        .await
        .unwrap();

    let up = Receiver::new(&store)
        .as_version_of(h)
        .receive(&multipart_headers(), body(&[("file", Some("doc.txt"), b"v2")]), WriteContext::none())
        .await
        .expect("upload");

    assert_eq!(up.handle, h, "the document keeps its identity");
    assert_eq!(store.versions(h).await.unwrap().len(), 2);
    assert_eq!(store.head(h).await.unwrap().seq, 2);
}

// ===================== CSRF ordering =====================

#[cfg(feature = "csrf")]
mod csrf_order {
    use super::*;
    use crate::csrf::Csrf;

    const TOKEN: &str = "5cbf19b46ff34d0a8de0dcbe12b6b7e2c0c1a5f4b3e2d1c0b9a8978685746352";

    fn headers_with_cookie(csrf: &Csrf) -> HeaderMap {
        let mut h = multipart_headers();
        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{}={TOKEN}", csrf.cookie())).unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn a_token_before_the_file_is_accepted() {
        // The positive control for the two negatives below: the ordering `UploadForm` renders.
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let csrf = Csrf::new();

        let up = Receiver::new(&store)
            .csrf(&csrf)
            .receive(
                &headers_with_cookie(&csrf),
                body(&[("_csrf", None, TOKEN.as_bytes()), ("file", Some("f.txt"), b"body")]),
                WriteContext::none(),
            )
            .await
            .expect("a well-formed post must go through");
        assert_eq!(up.filename, "f.txt");
    }

    #[tokio::test]
    async fn a_token_after_the_file_is_refused_with_nothing_written() {
        // The case a *buffered* parser would happily accept, because it already holds the whole
        // body. A streaming one has to decide before it writes — so a body that puts the file
        // first is refused, which is what closes the gap `crud::ui`'s CSV import still has.
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let csrf = Csrf::new();

        let err = Receiver::new(&store)
            .csrf(&csrf)
            .receive(
                &headers_with_cookie(&csrf),
                body(&[("file", Some("f.txt"), b"body"), ("_csrf", None, TOKEN.as_bytes())]),
                WriteContext::none(),
            )
            .await;

        assert!(matches!(err, Err(UploadError::Csrf)), "a late token must not authorise the write");
        assert_eq!(err.unwrap_err().status(), http::StatusCode::FORBIDDEN);
        assert_eq!(
            std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
            0,
            "and nothing was staged before the refusal"
        );
    }

    #[tokio::test]
    async fn a_wrong_or_missing_token_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let csrf = Csrf::new();

        for parts in [
            vec![("_csrf", None, b"not-the-token".as_slice()), ("file", Some("f.txt"), b"body")],
            vec![("file", Some("f.txt"), b"body".as_slice())], // none at all
        ] {
            let err = Receiver::new(&store)
                .csrf(&csrf)
                .receive(&headers_with_cookie(&csrf), body(&parts), WriteContext::none())
                .await;
            assert!(matches!(err, Err(UploadError::Csrf)), "{parts:?} must be refused");
        }
    }

    #[test]
    fn the_form_renders_the_token_before_the_file_input() {
        // Pins the ordering the streaming check depends on. A browser posts parts in document
        // order, so this *is* the mechanism, not a cosmetic detail.
        let html = UploadForm::new("/upload").csrf(TOKEN).render();
        let csrf_at = html.find("_csrf").expect("a token input");
        let file_at = html.find("type=\"file\"").expect("a file input");
        assert!(csrf_at < file_at, "the token must be posted first:\n{html}");
    }
}

// ===================== Escaping =====================

fn fake_version(filename: &str, mime: &str) -> VersionInfo {
    VersionInfo {
        id: crate::blob::VersionId(1),
        handle: crate::blob::HandleId::new(),
        seq: 1,
        prev: None,
        blob: crate::blob::BlobId::of(b"x"),
        filename: filename.into(),
        mime_declared: mime.into(),
        created_by: None,
        created_at: 0,
        metadata: None,
        content: Some(crate::blob::ContentInfo {
            id: crate::blob::BlobId::of(b"x"),
            size_bytes: 10,
            mime_sniffed: mime.into(),
            created_at: 0,
            verified_at: None,
        }),
    }
}

#[test]
fn a_hostile_filename_or_url_cannot_break_out_of_the_viewer() {
    let evil = "<script>alert(1)</script>\".png";
    for mime in ["image/png", "application/pdf", "application/octet-stream"] {
        let info = fake_version(evil, mime);
        let html = Viewer::new(&info, "/f?a=\"><script>alert(2)</script>").render();
        assert!(!html.contains("<script>"), "{mime} branch leaked a tag:\n{html}");
        assert!(html.contains("&lt;script&gt;"), "{mime} branch should escape it:\n{html}");
    }
}

#[test]
fn the_viewer_never_inlines_stored_bytes_only_urls() {
    // BLOBSTORE.md §10: a hostile MIME can steer *which tag* is rendered and nothing more — and
    // whatever branch it steers into, the content is reached by URL and never written into the page.
    for mime in ["image/svg+xml", "text/html", "image/png", "application/pdf", "application/zip"] {
        let info = fake_version("f", mime);
        let html = Viewer::new(&info, "/download/1").render();
        assert!(html.contains("/download/1"), "{mime} must reference, not embed: {html}");
    }
}

#[test]
fn the_viewer_only_promises_a_preview_the_download_route_will_actually_serve_inline() {
    // `to_inline_response` serves an allowlist inline and downgrades the rest to an attachment, so
    // an <img> pointing at an SVG would be a guaranteed broken-image icon. The two agree.
    let svg = fake_version("logo.svg", "image/svg+xml");
    let html = Viewer::new(&svg, "/v/1").render();
    assert!(!html.contains("<img"), "an SVG gets a link, not an image tag: {html}");
    assert!(!html.contains("Open"), "{html}");

    let png = fake_version("photo.png", "image/png");
    let ok = Viewer::new(&png, "/v/1").render();
    assert!(ok.contains("<img"), "control: an allowlisted type does preview: {ok}");
}

#[test]
fn a_hostile_action_or_label_cannot_break_out_of_the_upload_form() {
    let html = UploadForm::new("/x\"><script>alert(1)</script>")
        .label("<script>alert(2)</script>")
        .accept("\"><script>alert(3)</script>")
        .render();
    assert!(!html.contains("<script>"), "{html}");
}

// ===================== Viewer controls =====================

#[test]
fn a_download_button_appears_only_when_the_app_supplies_a_download_url() {
    // Without one, a button would have to point at the inline URL and would look like a broken
    // download — this crate owns no routes, so it cannot invent the second one.
    let info = fake_version("report.pdf", "application/pdf");
    let plain = Viewer::new(&info, "/v/1").render();
    assert!(!plain.contains("Download"), "no URL, no button:\n{plain}");

    let with = Viewer::new(&info, "/v/1").download_url("/v/1?download=1").render();
    assert!(with.contains("Download"), "{with}");
    assert!(with.contains("href=\"/v/1?download=1\" download"), "{with}");
}

#[test]
fn open_is_a_plain_link_so_the_browsers_own_modifiers_keep_working() {
    // Shift-click for a new window and ctrl/cmd-click for a background tab are free on an <a>, and
    // this crate ships no JavaScript to intercept them. Turning it into a button would lose that.
    let info = fake_version("photo.png", "image/png");
    let html = Viewer::new(&info, "/v/1").render();
    assert!(html.contains("<a class=\"btn btn-sm btn-outline-secondary\" href=\"/v/1\""), "{html}");
    assert!(html.contains("target=\"_blank\""), "{html}");
    assert!(html.contains("rel=\"noopener\""), "{html}");
}

#[test]
fn a_thumbnail_replaces_the_full_image_and_links_to_it() {
    let info = fake_version("photo.png", "image/png");
    let html = Viewer::new(&info, "/v/1").thumbnail_url("/v/1/thumb").render();
    assert!(html.contains("src=\"/v/1/thumb\""), "the thumbnail is what loads: {html}");
    assert!(!html.contains("src=\"/v/1\""), "not the full image: {html}");
    assert!(html.contains("href=\"/v/1\""), "but it still links through: {html}");
}

#[test]
fn a_file_with_no_preview_still_offers_its_controls() {
    let info = fake_version("archive.zip", "application/zip");
    let html = Viewer::new(&info, "/v/1").download_url("/v/1?download=1").render();
    assert!(!html.contains("<img"), "nothing to preview: {html}");
    assert!(!html.contains("Open"), "…and nothing a browser would display inline: {html}");
    assert!(html.contains("Download"), "but it can still be fetched: {html}");
    assert!(html.contains("archive.zip"), "{html}");
}

#[test]
fn a_hostile_thumbnail_or_download_url_cannot_break_out() {
    let info = fake_version("x.png", "image/png");
    let html = Viewer::new(&info, "/v/1")
        .thumbnail_url("\"><script>alert(1)</script>")
        .download_url("\"><script>alert(2)</script>")
        .render();
    assert!(!html.contains("<script>"), "{html}");
}

// ===================== Browser =====================

mod browser {
    use super::*;
    use crate::authz::{Decision, Open};
    use crate::blob::ui::{BrowseState, Browser};

    fn state(query: &str) -> BrowseState {
        BrowseState::from_uri(&format!("/files?{query}").parse::<http::Uri>().unwrap())
    }

    #[tokio::test]
    async fn documents_are_listed_with_their_current_name_and_version_count() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let h = store
            .create(&b"v1"[..], PutMeta::new("contract.pdf").by("alice"), WriteContext::none())
            .await
            .unwrap();
        store
            .add_version(h, &b"v2"[..], PutMeta::new("contract-final.pdf").by("bob"), WriteContext::none())
            .await
            .unwrap();
        store
            .create(&b"x"[..], PutMeta::new("other.txt"), WriteContext::none())
            .await
            .unwrap();

        let html = Browser::new(&store, Open)
            .render_for(&HeaderMap::new(), &state(""))
            .await
            .expect("render");

        assert!(html.contains("contract-final.pdf"), "the *current* name, not the first: {html}");
        assert!(!html.contains(">contract.pdf<"), "the superseded name is not the headline: {html}");
        assert!(html.contains("other.txt"), "{html}");
        assert!(html.contains("bob"), "…and who last changed it: {html}");
    }

    #[tokio::test]
    async fn search_matches_a_name_the_document_used_to_have() {
        // What someone hunting for a file actually remembers is often the old name.
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let h = store
            .create(&b"v1"[..], PutMeta::new("invoice-draft.pdf"), WriteContext::none())
            .await
            .unwrap();
        store
            .relabel(h, PutMeta::new("invoice-final.pdf"), WriteContext::none())
            .await
            .unwrap();
        store.create(&b"z"[..], PutMeta::new("unrelated.txt"), WriteContext::none()).await.unwrap();

        let b = Browser::new(&store, Open);
        let hit = b.render_for(&HeaderMap::new(), &state("q=draft")).await.unwrap();
        assert!(hit.contains("invoice-final.pdf"), "found by its old name: {hit}");
        assert!(!hit.contains("unrelated.txt"), "{hit}");

        let miss = b.render_for(&HeaderMap::new(), &state("q=nothingmatches")).await.unwrap();
        assert!(miss.contains("Nothing matches"), "{miss}");
    }

    #[tokio::test]
    async fn opening_a_document_shows_its_chain_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let h = store
            .create(&b"one"[..], PutMeta::new("a.txt").by("alice"), WriteContext::none())
            .await
            .unwrap();
        store
            .add_version(h, &b"two"[..], PutMeta::new("a.txt").by("bob"), WriteContext::none())
            .await
            .unwrap();

        let html = Browser::new(&store, Open)
            .view_url("/files/{handle}/v/{version}")
            .render_for(&HeaderMap::new(), &state(&format!("open={h}")))
            .await
            .unwrap();

        let v2 = html.find(">2<").expect("version 2 listed");
        let v1 = html.find(">1<").expect("version 1 listed");
        assert!(v2 < v1, "newest first — the current version is what a reader wants: {html}");
        assert!(html.contains(&format!("/files/{h}/v/")), "links through the app's route: {html}");
        assert!(html.contains("all handles"), "and back: {html}");
    }

    #[tokio::test]
    async fn the_browser_is_a_real_enforcement_point() {
        struct Denies;
        #[async_trait::async_trait]
        impl crate::authz::Authz for Denies {
            async fn authorize(
                &self,
                _: crate::authz::Operation,
                _: &HeaderMap,
            ) -> Decision {
                Decision::Denied
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        store.create(&b"secret"[..], PutMeta::new("s.txt"), WriteContext::none()).await.unwrap();

        // Unlike `Viewer`, this lists every document in the store, so rendering *is* the read.
        let denied = Browser::new(&store, Denies).render_for(&HeaderMap::new(), &state("")).await;
        assert_eq!(denied.err(), Some(Decision::Denied));
        assert!(Browser::new(&store, Open)
            .render_for(&HeaderMap::new(), &state(""))
            .await
            .is_ok(), "control: an allowing gate renders");
    }

    #[tokio::test]
    async fn a_hostile_filename_cannot_break_out_of_the_listing() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        store
            .create(
                &b"x"[..],
                PutMeta::new("<script>alert(1)</script>.txt").by("<script>alert(2)</script>"),
                WriteContext::none(),
            )
            .await
            .unwrap();

        let b = Browser::new(&store, Open);
        let list = b.render_for(&HeaderMap::new(), &state("q=script")).await.unwrap();
        assert!(!list.contains("<script>"), "listing: {list}");
        assert!(list.contains("&lt;script&gt;"), "listing should escape: {list}");
    }

    #[test]
    fn the_search_term_survives_paging_and_drilling_in() {
        let s = state("q=annual+report&page=3");
        assert_eq!(s.search.as_deref(), Some("annual report"));
        assert_eq!(s.page, 3);
        assert!(s.open.is_none());
    }
}

#[tokio::test]
async fn the_browser_titles_itself_so_the_page_and_its_actions_cannot_drift_apart() {
    // The heading is the component's, not the app's. Leaving it to the app is how this surface ended
    // up calling itself "Files" while everything underneath it said "document".
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path()).await;
    let b = crate::blob::ui::Browser::new(&store, crate::authz::Open);
    let s = crate::blob::ui::BrowseState::from_uri(&"/x".parse::<http::Uri>().unwrap());

    let html = b.render_for(&HeaderMap::new(), &s).await.unwrap();
    assert!(html.contains("<h1 class=\"h4 mb-3\">Blob store</h1>"), "{html}");

    let renamed = crate::blob::ui::Browser::new(&store, crate::authz::Open)
        .title("Attachments")
        .render_for(&HeaderMap::new(), &s)
        .await
        .unwrap();
    assert!(renamed.contains("Attachments"), "{renamed}");
    assert!(!renamed.contains("Blob store"), "{renamed}");

    let bare = crate::blob::ui::Browser::new(&store, crate::authz::Open)
        .title("")
        .render_for(&HeaderMap::new(), &s)
        .await
        .unwrap();
    assert!(!bare.contains("<h1"), "an empty title renders no heading: {bare}");
}

#[tokio::test]
async fn the_maintenance_buttons_are_named_after_the_calls_they_make() {
    // `check_consistency` and `collect_garbage` — not "Check storage" and "Purge", which is what
    // they said while the API said something else.
    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path()).await;
    let html = crate::blob::ui::Actions::new(&store, crate::authz::Open)
        .render_for(&HeaderMap::new())
        .await
        .expect("render");

    assert!(html.contains("<h2 class=\"h6\">Maintenance</h2>"), "{html}");
    assert!(html.contains("Check consistency"), "{html}");
    assert!(html.contains("Collect garbage"), "{html}");
    assert!(!html.contains("Purge"), "the old name is gone: {html}");
    assert!(!html.contains("Check storage"), "{html}");
}

mod panel {
    use super::*;
    use crate::authz::{Decision, Open};
    use crate::blob::ui::{Actions, BrowseState, Browser};
    use std::collections::HashMap;

    const TOKEN: &str = "5cbf19b46ff34d0a8de0dcbe12b6b7e2c0c1a5f4b3e2d1c0b9a8978685746352";

    fn state(q: &str) -> BrowseState {
        BrowseState::from_uri(&format!("/x?{q}").parse::<http::Uri>().unwrap())
    }

    #[tokio::test]
    async fn maintenance_is_a_menu_on_the_list_and_absent_from_one_handles_page() {
        // The controls act on the whole store. Offering them while a reader is looking at one
        // handle's chain invites the reading that they apply to that handle.
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let h = store.create(&b"x"[..], PutMeta::new("a.txt"), WriteContext::none()).await.unwrap();

        let panel = || {
            Browser::new(&store, Open).actions(Actions::new(&store, Open).csrf(TOKEN))
        };

        let list = panel().render_for(&HeaderMap::new(), &state("")).await.unwrap();
        assert!(list.contains("<details"), "a disclosure menu, not a JS dropdown: {list}");
        assert!(list.contains("Check consistency") && list.contains("Collect garbage"), "{list}");

        let one = panel().render_for(&HeaderMap::new(), &state(&format!("open={h}"))).await.unwrap();
        assert!(!one.contains("Check consistency"), "store-wide controls stay off this page: {one}");
        assert!(!one.contains("Collect garbage"), "{one}");
    }

    #[tokio::test]
    async fn the_panel_speaks_the_schema() {
        // An operator reading this is looking at `blob_handle`, `blob_version` and `blob`, and wants
        // to map what they see onto those tables.
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let h = store.create(&b"x"[..], PutMeta::new("a.txt"), WriteContext::none()).await.unwrap();

        let list = Browser::new(&store, Open).render_for(&HeaderMap::new(), &state("")).await.unwrap();
        for col in ["<th>handle</th>", "<th>filename</th>", "<th class=\"text-end\">versions</th>"] {
            assert!(list.contains(col), "missing {col}:\n{list}");
        }

        let one = Browser::new(&store, Open)
            .render_for(&HeaderMap::new(), &state(&format!("open={h}")))
            .await
            .unwrap();
        for col in ["<th>seq</th>", "<th>blob</th>", "<th>created_by</th>"] {
            assert!(one.contains(col), "missing {col}:\n{one}");
        }
        assert!(one.contains("handle <code>"), "the page names the handle it is showing:\n{one}");
    }

    #[tokio::test]
    async fn a_handle_can_be_deleted_from_the_panel_and_the_gate_is_asked_separately() {
        // There is no other route: a plain CRUD delete on `blob_handle` violates the foreign key
        // once there are two versions.
        struct ReadOnly;
        #[async_trait::async_trait]
        impl crate::authz::Authz for ReadOnly {
            async fn authorize(&self, op: crate::authz::Operation, _: &HeaderMap) -> Decision {
                if op.is_write() { Decision::Denied } else { Decision::Allow }
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let h = store.create(&b"v1"[..], PutMeta::new("a.txt"), WriteContext::none()).await.unwrap();
        store.add_version(h, &b"v2"[..], PutMeta::new("a.txt"), WriteContext::none()).await.unwrap();

        let mut form = HashMap::new();
        form.insert("op".to_string(), "delete".to_string());
        form.insert("handle".to_string(), h.to_string());

        // Reading the store is not permission to empty it.
        let refused = Browser::new(&store, ReadOnly)
            .actions(Actions::new(&store, ReadOnly).csrf(TOKEN))
            .submit(&HeaderMap::new(), &form, WriteContext::none())
            .await;
        assert_eq!(refused.err(), Some(Decision::Denied));
        assert!(store.head(h).await.is_ok(), "still there");

        let done = Browser::new(&store, Open)
            .actions(Actions::new(&store, Open).csrf(TOKEN))
            .submit(&HeaderMap::new(), &form, WriteContext::none())
            .await
            .expect("allowed");
        assert!(!done.alarming, "{}", done.message);
        assert!(store.head(h).await.is_err(), "the handle and its chain are gone");

        // Content is freed by collection, not by the delete — dedup is why.
        assert_eq!(store.collect_garbage().await.unwrap().deleted.len(), 2);
    }

    #[tokio::test]
    async fn the_delete_button_is_omitted_when_the_panel_has_no_write_path() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let h = store.create(&b"x"[..], PutMeta::new("a.txt"), WriteContext::none()).await.unwrap();

        // No `actions`, so no CSRF token, so no button that would be refused on submit.
        let bare = Browser::new(&store, Open)
            .render_for(&HeaderMap::new(), &state(&format!("open={h}")))
            .await
            .unwrap();
        assert!(!bare.contains("Delete this handle"), "{bare}");

        let wired = Browser::new(&store, Open)
            .actions(Actions::new(&store, Open).csrf(TOKEN))
            .render_for(&HeaderMap::new(), &state(&format!("open={h}")))
            .await
            .unwrap();
        assert!(wired.contains("Delete this handle"), "{wired}");
        assert!(wired.contains(TOKEN), "and it carries the token: {wired}");
    }
}

#[tokio::test]
async fn two_handles_created_moments_apart_are_told_apart_in_the_listing() {
    // A UUIDv7 leads with a timestamp, so truncating one produces a column where distinct rows look
    // identical — which is exactly what an 8-character prefix did for two documents uploaded in the
    // same second. Handles are shown in full; only digests, which are uniformly random, are cut.
    use crate::authz::Open;
    use crate::blob::ui::{BrowseState, Browser};

    let dir = tempfile::tempdir().unwrap();
    let store = store(dir.path()).await;
    let a = store.create(&b"one"[..], PutMeta::new("a.txt"), WriteContext::none()).await.unwrap();
    let b = store.create(&b"two"[..], PutMeta::new("b.txt"), WriteContext::none()).await.unwrap();
    assert_eq!(
        a.to_string()[..8],
        b.to_string()[..8],
        "control: their prefixes really do collide, which is the whole point"
    );

    let html = Browser::new(&store, Open)
        .render_for(&HeaderMap::new(), &BrowseState::from_uri(&"/x".parse().unwrap()))
        .await
        .unwrap();
    assert!(html.contains(&a.to_string()), "the full handle is shown: {html}");
    assert!(html.contains(&b.to_string()), "{html}");
}
