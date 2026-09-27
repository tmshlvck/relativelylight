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
        // Set, or `is_erased()` is true and every case below takes the tombstone branch instead of
        // the one it means to test.
        blob: Some(crate::blob::BlobId::of(b"x")),
        filename: filename.into(),
        mime_declared: mime.into(),
        created_by: None,
        created_at: 0,
        purged_at: None,
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
    // BLOBSTORE.md §10: a hostile MIME can steer *which tag* is rendered and nothing more.
    for mime in ["image/svg+xml", "text/html", "image/png"] {
        let info = fake_version("f", mime);
        let html = Viewer::new(&info, "/download/1").render();
        assert!(html.contains("/download/1"), "{mime} must reference, not embed: {html}");
    }
}

#[test]
fn an_erased_version_says_so_rather_than_rendering_nothing() {
    let mut info = fake_version("personal.pdf", "application/pdf");
    info.blob = None;
    info.content = None;
    info.purged_at = Some(1_700_000_000);

    let html = Viewer::new(&info, "/download/1").render();
    assert!(html.contains("personal.pdf"), "the record still names the document: {html}");
    assert!(html.contains("erased"), "{html}");
    assert!(!html.contains("<embed"), "and offers nothing to fetch: {html}");
}

#[test]
fn a_hostile_action_or_label_cannot_break_out_of_the_upload_form() {
    let html = UploadForm::new("/x\"><script>alert(1)</script>")
        .label("<script>alert(2)</script>")
        .accept("\"><script>alert(3)</script>")
        .render();
    assert!(!html.contains("<script>"), "{html}");
}
