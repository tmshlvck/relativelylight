//! Tests for `files`. As in `auth/security_tests.rs`, the negatives are the point and each has a
//! positive control beside it so it can't pass vacuously.
//!
//! - **upload** — files really stream (a body larger than any buffer round-trips), the CSRF token
//!   is required *before* the first file, limits hold while streaming, and once refused an upload
//!   yields nothing more.
//! - **escaping** — every value a component is given reaches the page escaped.
//! - **response** — the inline allowlist, and that a filename cannot inject a header.

use axum::body::Body;
use http::{header, HeaderMap, HeaderValue};

use super::response::content_disposition;
use super::*;

const BOUNDARY: &str = "----rltestboundary";

fn multipart_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&format!("multipart/form-data; boundary={BOUNDARY}")).unwrap(),
    );
    h
}

/// A body from `(name, filename, content)` parts, in the order given — which is the whole point for
/// the CSRF tests.
fn body(parts: &[(&str, Option<&str>, &[u8])]) -> Body {
    Body::from(raw(parts))
}

/// The same, trickling through a 4 KiB pipe as from a slow socket. The parser drains whatever is
/// ready, so an in-memory body arrives as one chunk and a test of what happens *past* the read-ahead
/// would never get past it.
fn slow_body(parts: &[(&str, Option<&str>, &[u8])]) -> Body {
    use tokio::io::AsyncWriteExt;
    let (mut tx, rx) = tokio::io::duplex(4096);
    let bytes = raw(parts);
    tokio::spawn(async move {
        let _ = tx.write_all(&bytes).await; // fails once the reader gives up — expected
    });
    Body::from_stream(tokio_util::io::ReaderStream::with_capacity(rx, 4096))
}

fn raw(parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, filename, content) in parts {
        out.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        let disposition = match filename {
            Some(f) => format!("form-data; name=\"{name}\"; filename=\"{f}\""),
            None => format!("form-data; name=\"{name}\""),
        };
        out.extend_from_slice(format!("Content-Disposition: {disposition}\r\n\r\n").as_bytes());
        out.extend_from_slice(content);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    out
}

/// What an app would have stored: each part in order, a file as its bytes and what was learned.
#[derive(Debug, PartialEq)]
enum Got {
    Field(String, String),
    File { filename: String, mime: &'static str, bytes: Vec<u8>, size: u64, sha256: String },
}

/// Read a whole upload the way an app does. On error, returns what was read before it — the
/// part-written file that the app would then discard is *not* in the list.
async fn read_all(mut up: Upload<'_>) -> (Vec<Got>, Result<(), UploadError>) {
    let mut got = Vec::new();
    loop {
        let part = match up.next().await {
            Ok(Some(p)) => p,
            Ok(None) => return (got, Ok(())),
            Err(e) => return (got, Err(e)),
        };
        match part {
            Part::Field(n, v) => got.push(Got::Field(n, v)),
            Part::File(mut f) => {
                let bytes = match f.bytes().await {
                    Ok(b) => b,
                    Err(e) => return (got, Err(e)),
                };
                got.push(Got::File {
                    filename: f.filename().into(),
                    mime: f.mime(),
                    bytes,
                    size: f.size(),
                    sha256: f.sha256().expect("read to the end").into(),
                });
            }
        }
    }
}

// ===================== Upload =====================

#[tokio::test]
async fn parts_arrive_in_order_with_size_hash_and_type() {
    let headers = multipart_headers();
    let png = b"\x89PNG\r\n\x1a\nrest";
    let up = Upload::new(
        &headers,
        body(&[
            ("name", None, b"holiday"),
            ("file", Some("a.png"), png),
            ("file", Some("b.txt"), b"hello"),
        ]),
    )
    .unwrap();
    let (got, end) = read_all(up).await;
    end.expect("a well-formed post");
    assert_eq!(got[0], Got::Field("name".into(), "holiday".into()), "the name before the files");
    let Got::File { filename, mime, size, .. } = &got[1] else { panic!("{got:?}") };
    assert_eq!((filename.as_str(), *mime, *size), ("a.png", "image/png", 12));
    let Got::File { bytes, sha256, mime, .. } = &got[2] else { panic!("{got:?}") };
    assert_eq!((bytes.as_slice(), *mime), (b"hello".as_slice(), "text/plain"));
    assert_eq!(sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
}

#[tokio::test]
async fn the_type_is_known_before_the_first_chunk_is_read() {
    let headers = multipart_headers();
    let mut up = Upload::new(&headers, body(&[("file", Some("x"), b"%PDF-1.7 ...")])).unwrap();
    let Some(Part::File(f)) = up.next().await.unwrap() else { panic!("a file") };
    assert_eq!(f.mime(), "application/pdf");
    assert_eq!(f.sha256(), None, "not read to the end yet");
}

#[tokio::test]
async fn a_file_bigger_than_any_buffer_arrives_intact() {
    let headers = multipart_headers();
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    let up = Upload::new(&headers, body(&[("file", Some("big.bin"), &big)])).unwrap();
    let (got, end) = read_all(up).await;
    end.unwrap();
    let Got::File { bytes, size, .. } = &got[0] else { panic!() };
    assert_eq!(*size, big.len() as u64);
    assert!(bytes == &big, "every chunk, the read-ahead included, in order");
}

#[tokio::test]
async fn a_file_dropped_unread_is_skipped_and_the_next_part_still_arrives() {
    let headers = multipart_headers();
    let mut up = Upload::new(
        &headers,
        body(&[("file", Some("a.bin"), &[7u8; 5000]), ("after", None, b"yes")]),
    )
    .unwrap();
    assert!(matches!(up.next().await.unwrap(), Some(Part::File(_))));
    match up.next().await.unwrap() {
        Some(Part::Field(n, v)) => assert_eq!((n.as_str(), v.as_str()), ("after", "yes")),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn an_empty_picker_beside_a_used_one_is_skipped() {
    // The picker-plus-camera form posts both inputs; the unused one is an empty, unnamed part.
    let headers = multipart_headers();
    let up = Upload::new(
        &headers,
        body(&[("file", Some(""), b""), ("file", Some("photo.jpg"), b"\xff\xd8\xffjpeg")]),
    )
    .unwrap();
    let (got, end) = read_all(up).await;
    end.unwrap();
    assert_eq!(got.len(), 1);
    assert!(matches!(&got[0], Got::File { mime: "image/jpeg", .. }));

    let mut up = Upload::new(&headers, body(&[("file", Some(""), b"")])).unwrap();
    assert!(up.next().await.unwrap().is_none());
    assert_eq!(up.files(), 0, "only empty pickers is no file at all");
}

#[tokio::test]
async fn limits_hold_while_streaming_and_end_the_upload() {
    let headers = multipart_headers();
    // Positive control: exactly at the limit is fine.
    let up = Upload::new(&headers, body(&[("file", Some("a"), b"12345")])).unwrap().max_bytes(5);
    assert!(read_all(up).await.1.is_ok());

    // The first file fits; the second is over, and is refused while being read.
    let mut up = Upload::new(
        &headers,
        body(&[("file", Some("a"), b"12345"), ("file", Some("b"), &[b'x'; 3000])]),
    )
    .unwrap()
    .max_bytes(5);
    let Some(Part::File(mut a)) = up.next().await.unwrap() else { panic!() };
    assert_eq!(a.bytes().await.unwrap(), b"12345");
    drop(a);
    // Over the limit within the read-ahead, so the part is refused before the app sees it.
    let err = up.next().await.unwrap_err();
    assert!(matches!(err, UploadError::TooLarge { limit: 5 }), "{err:?}");
    assert_eq!(err.status(), http::StatusCode::PAYLOAD_TOO_LARGE);
    assert!(matches!(up.next().await, Err(UploadError::Finished)), "nothing after a refusal");

    // Past the read-ahead, the refusal comes from `chunk`, and still ends the upload.
    let big = vec![b'x'; 200_000];
    let mut up =
        Upload::new(&headers, slow_body(&[("file", Some("a"), &big), ("after", None, b"1")]))
            .unwrap()
            .max_bytes(100_000);
    let Some(Part::File(mut f)) = up.next().await.unwrap() else { panic!() };
    assert!(matches!(f.bytes().await, Err(UploadError::TooLarge { .. })));
    drop(f);
    assert!(matches!(up.next().await, Err(UploadError::Finished)));

    let up = Upload::new(&headers, body(&[("file", Some("a"), b"1"), ("file", Some("b"), b"2")]))
        .unwrap()
        .max_files(1);
    let (got, end) = read_all(up).await;
    assert_eq!(got.len(), 1);
    assert!(matches!(end, Err(UploadError::TooManyFiles { limit: 1 })));

    let up = Upload::new(&headers, body(&[("note", None, b"12345"), ("file", Some("a"), b"1")]))
        .unwrap()
        .max_field_bytes(4);
    let (got, end) = read_all(up).await;
    assert!(got.is_empty());
    assert!(matches!(end, Err(UploadError::FieldTooLarge { .. })));
}

#[tokio::test]
async fn a_file_in_another_field_or_a_body_that_is_not_multipart_is_refused() {
    let headers = multipart_headers();
    let up = Upload::new(&headers, body(&[("avatar", Some("a.png"), b"x")])).unwrap();
    assert!(matches!(read_all(up).await.1, Err(UploadError::Malformed(_))));
    let up = Upload::new(&headers, body(&[("avatar", Some("a.png"), b"x")]))
        .unwrap()
        .file_field("avatar");
    assert!(read_all(up).await.1.is_ok(), "positive control");

    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/x-www-form-urlencoded"));
    let err = Upload::new(&h, Body::from("file=x")).unwrap_err();
    assert!(matches!(err, UploadError::NotMultipart));
    assert_eq!(err.status(), http::StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

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
    async fn a_token_before_the_files_is_accepted() {
        // The positive control for the negatives below: the ordering `UploadForm` renders.
        let csrf = Csrf::new();
        let headers = headers_with_cookie(&csrf);
        let up = Upload::new(
            &headers,
            body(&[("_csrf", None, TOKEN.as_bytes()), ("file", Some("f.txt"), b"body")]),
        )
        .unwrap()
        .csrf(&csrf);
        let (got, end) = read_all(up).await;
        end.expect("a well-formed post must go through");
        assert!(matches!(&got[1], Got::File { filename, .. } if filename == "f.txt"));
    }

    #[tokio::test]
    async fn a_token_after_a_file_is_refused_before_the_app_sees_a_byte() {
        // A buffered parser would accept this, because it already holds the whole body. A
        // streaming one has to decide before the app writes — so a file first is refused.
        let csrf = Csrf::new();
        let headers = headers_with_cookie(&csrf);
        let up = Upload::new(
            &headers,
            body(&[("file", Some("f.txt"), b"body"), ("_csrf", None, TOKEN.as_bytes())]),
        )
        .unwrap()
        .csrf(&csrf);
        let (got, end) = read_all(up).await;
        assert!(got.is_empty(), "no file was handed out");
        let err = end.unwrap_err();
        assert!(matches!(err, UploadError::Csrf), "a late token must not authorise the write");
        assert_eq!(err.status(), http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_wrong_or_missing_token_is_refused() {
        let csrf = Csrf::new();
        let headers = headers_with_cookie(&csrf);
        for parts in [
            vec![("_csrf", None, b"not-the-token".as_slice()), ("file", Some("f.txt"), b"body")],
            vec![("file", Some("f.txt"), b"body".as_slice())],
        ] {
            let up = Upload::new(&headers, body(&parts)).unwrap().csrf(&csrf);
            let (got, end) = read_all(up).await;
            assert!(!got.iter().any(|g| matches!(g, Got::File { .. })), "{parts:?}");
            assert!(matches!(end, Err(UploadError::Csrf)), "{parts:?} must be refused");
        }
    }

    #[test]
    fn the_form_renders_the_token_then_the_name_then_the_files() {
        // Pins the ordering the streaming check depends on: a browser posts parts in document order.
        let html = UploadForm::new("/upload")
            .csrf(TOKEN)
            .name_field("name", "Name")
            .camera("Photo")
            .render();
        let csrf_at = html.find("_csrf").expect("a token input");
        let name_at = html.find("name=\"name\"").expect("a name input");
        let file_at = html.find("type=\"file\"").expect("a file input");
        assert!(csrf_at < name_at && name_at < file_at, "token, name, files:\n{html}");
    }

    #[test]
    fn the_photo_button_renders_the_token_before_its_file() {
        let html = UploadForm::photo("/upload", "Take a photo").csrf(TOKEN).render();
        let csrf_at = html.find("_csrf").expect("a token input");
        let file_at = html.find("type=\"file\"").expect("a file input");
        assert!(csrf_at < file_at, "{html}");
        assert!(html.contains("capture=\"environment\"") && html.contains("this.form.submit()"));
        assert!(!html.contains("type=\"submit\""), "no button to press after the camera: {html}");
    }
}

// ===================== Rendering =====================

#[test]
fn nothing_a_component_is_given_breaks_out_of_it() {
    let evil = "\"><script>alert(1)</script>";
    let html = [
        Preview::new(evil, "image/png", evil).size(1).download_url(evil).render(),
        Thumbnail::new(evil).src(evil).href(evil).render(),
        Thumbnail::new(format!("{evil}.pdf")).render(),
        UploadForm::new(evil).accept(evil).label(evil).submit(evil).csrf(evil).render(),
        UploadForm::photo(evil, evil).csrf(evil).render(),
    ];
    for h in html {
        assert!(!h.contains("<script>"), "{h}");
        assert!(h.contains("&lt;script&gt;") || h.contains("&quot;"), "positive control: {h}");
    }
}

#[test]
fn the_preview_embeds_only_urls_never_bytes() {
    let html = Preview::new("a.png", "image/png", "/v/a.png").render();
    assert!(html.contains("<img src=\"/v/a.png\""));
    let pdf = Preview::new("a.pdf", "application/pdf", "/v/a.pdf").render();
    assert!(pdf.contains("<embed src=\"/v/a.pdf\""));
    let none = Preview::new("a.png", "image/png", "/v/a.png").links_only().render();
    assert!(!none.contains("<img"));
}

#[test]
fn open_is_offered_only_for_what_the_response_will_serve_inline() {
    let png = Preview::new("a.png", "image/png", "/v").render();
    assert!(png.contains(">open</a>"), "positive control");
    for mime in ["image/svg+xml", "text/html", "application/octet-stream", ""] {
        let html = Preview::new("x", mime, "/v").download_url("/d").render();
        assert!(!html.contains(">open</a>"), "{mime}");
        assert!(html.contains(">download</a>"), "{mime}");
    }
}

#[test]
fn a_thumbnail_is_an_image_when_given_one_and_a_same_sized_badge_otherwise() {
    let img = Thumbnail::new("photo.jpg").src("/t/1").href("/v/1").px(80).render();
    assert!(img.contains("<img src=\"/t/1\"") && img.contains("width=\"80\""), "{img}");
    assert!(img.starts_with("<a href=\"/v/1\""), "{img}");
    let badge = Thumbnail::new("scan.pdf").px(80).render();
    assert!(!badge.contains("<img") && badge.contains(">PDF</span>"), "{badge}");
    assert!(badge.contains("width:80px;height:80px"), "{badge}");
    for (name, label) in [(".bashrc", "FILE"), ("README", "FILE"), ("a.verylong", "FILE")] {
        assert!(Thumbnail::new(name).render().contains(&format!(">{label}</span>")), "{name}");
    }
}

#[test]
fn a_url_segment_cannot_change_the_route() {
    assert_eq!(url_segment("a b/../c?d#e%"), "a%20b%2F..%2Fc%3Fd%23e%25");
    assert_eq!(url_segment("plain-name_1.txt"), "plain-name_1.txt");
}

// ===================== Response =====================

#[tokio::test]
async fn only_allowlisted_types_render_inline() {
    let png = to_inline_response(Download::from_bytes(b"\x89PNG\r\n\x1a\nxx".to_vec(), "a.png"));
    assert!(png.headers()[header::CONTENT_DISPOSITION].to_str().unwrap().starts_with("inline"));
    assert_eq!(png.headers()[header::CONTENT_TYPE], "image/png");
    assert_eq!(png.headers()[header::CONTENT_LENGTH], "10");

    let svg = to_inline_response(Download::from_bytes(b"<svg onload=alert(1)>".to_vec(), "e.svg"));
    assert!(
        svg.headers()[header::CONTENT_DISPOSITION].to_str().unwrap().starts_with("attachment"),
        "an SVG is downloaded, never rendered"
    );
    assert_eq!(svg.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");

    // A reader with a declared type: the app's claim is held to the same allowlist.
    let html = to_inline_response(Download::new(&b"<b>hi</b>"[..], "x.html", "text/html"));
    assert!(html.headers()[header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .starts_with("attachment"));

    let body = axum::body::to_bytes(png.into_body(), usize::MAX).await.unwrap();
    assert_eq!(&body[..], b"\x89PNG\r\n\x1a\nxx");
}

#[test]
fn a_filename_cannot_inject_a_header_escape_its_quotes_or_carry_a_path() {
    let got = content_disposition("in\r\nX-Evil: yes\r\n\"; filename=\"real.exe", false);
    assert!(!got.contains('\r') && !got.contains('\n'), "{got}");
    assert_eq!(got.matches('"').count(), 2, "{got}");
    assert!(!content_disposition("../../etc/passwd", false).contains('/'));
    let got = content_disposition("Übersicht.pdf", false);
    assert!(got.contains("filename*=UTF-8''%C3%9Cbersicht.pdf"), "{got}");
    assert!(content_disposition("", false).contains("\"download\""));
}

#[test]
fn sniffing_recognises_the_common_types_and_defaults_to_download() {
    assert_eq!(sniff_mime(b"%PDF-1.7"), "application/pdf");
    assert_eq!(sniff_mime(b"plain words"), "text/plain");
    assert_eq!(
        sniff_mime("é".as_bytes().split_at(1).0),
        "text/plain",
        "a prefix cut mid-character"
    );
    assert_eq!(sniff_mime(b"\x00\x01\x02\xff"), "application/octet-stream");
    assert_eq!(sniff_mime(b""), "application/octet-stream");
}
