//! Turning a verified [`ContentStream`] into an HTTP reply — BLOBSTORE.md §5.4.
//!
//! **Not a route.** The app's own handler authorises the request, calls
//! [`BlobStore::read`](crate::blob::BlobStore::read), and calls one of these to build the response.
//! A library-owned download route could do none of the three things that matter: verify the digest,
//! decide whether *this* caller may see *this* document, and emit whatever the app's compliance
//! regime wants emitted (BLOBSTORE.md §9.2 — route by the owning document, never by the handle).

use axum::body::Body;
use axum::response::Response;
use http::header;
use tokio_util::io::ReaderStream;

use crate::blob::ContentStream;

/// Types safe to render in the browser without becoming script. Everything else is downloaded.
///
/// An allowlist rather than a denylist, because the failure mode is XSS: `image/svg+xml` is an
/// image to a user and a scriptable document to a browser, and `text/html` needs no explanation.
/// Sniffed content types are advisory (BLOBSTORE.md §10), so the question this answers isn't "what
/// is this file" but "what is safe to *say* it is while asking a browser to render it".
const INLINE_SAFE: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "application/pdf",
    // Safe *because* of the `nosniff` header below: told `text/plain` and forbidden to sniff, a
    // browser renders the bytes as text even if they happen to be HTML source. Without `nosniff`
    // this line would be an XSS hole.
    "text/plain",
];

/// A download: `Content-Disposition: attachment`, so nothing renders in the browsing context.
///
/// The right default. Prefer it unless a page needs to *display* the content, in which case
/// [`to_inline_response`] is the considered version.
pub fn to_response(handle: ContentStream) -> Response {
    build(handle, false)
}

/// For content a page displays — an `<img src>` or an `<embed src>` from
/// [`Viewer`](super::Viewer).
///
/// Serves inline **only** for the types in this module's allowlist; anything else silently becomes
/// an attachment rather than being rendered. So a hostile SVG uploaded as `image/svg+xml` is
/// downloaded, not executed, even though the viewer asked for it inline — the decision is made here
/// where the `Content-Type` is actually set, not where the tag was chosen.
pub fn to_inline_response(handle: ContentStream) -> Response {
    build(handle, true)
}

fn build(handle: ContentStream, want_inline: bool) -> Response {
    let info = handle.info.clone();
    let mime = info
        .content
        .as_ref()
        .map(|c| c.mime_sniffed.clone())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "application/octet-stream".into());

    let inline = want_inline && INLINE_SAFE.contains(&mime.as_str());
    let disposition = content_disposition(&info.filename, inline);

    let len = info.content.as_ref().map(|c| c.size_bytes).unwrap_or(0);
    let body = Body::from_stream(ReaderStream::new(handle.into_reader()));

    let mut res = Response::builder()
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, len)
        .header(header::CONTENT_DISPOSITION, disposition)
        // The content type above is derived from the bytes, but it is still a guess. Telling the
        // browser not to second-guess it stops a file that sniffs as `text/plain` being re-read as
        // HTML because it happens to start with a tag.
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");

    if inline {
        // Belt and braces for the inline path: even an allowlisted type renders with no script, no
        // plugins and no ability to be framed into someone else's page.
        res = res.header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; img-src 'self' data:; object-src 'self'; sandbox",
        );
    }

    res.body(body).expect("response builder: static headers")
}

/// A `Content-Disposition` value that can't inject a header or smuggle a path.
///
/// Three separate hazards, all real:
/// - **Header injection.** A filename containing CR or LF would end the header and begin another.
/// - **Quote escaping.** A `"` would close the quoted string early and let the rest be read as
///   parameters.
/// - **Path traversal on the client.** Some clients have historically honoured directory separators
///   in a suggested filename.
///
/// Non-ASCII names are additionally given the RFC 6266 / RFC 5987 `filename*` form, since the plain
/// parameter has no defined encoding — so "Übersicht.pdf" arrives intact rather than mangled.
fn content_disposition(filename: &str, inline: bool) -> String {
    let kind = if inline { "inline" } else { "attachment" };

    let safe: String = filename
        .chars()
        .map(|c| match c {
            '"' | '\\' | '/' | '\r' | '\n' | '\0' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    let ascii: String = safe.chars().map(|c| if c.is_ascii() { c } else { '_' }).collect();
    let ascii = if ascii.trim().is_empty() { "download".to_string() } else { ascii };

    if safe.is_ascii() {
        format!("{kind}; filename=\"{ascii}\"")
    } else {
        format!("{kind}; filename=\"{ascii}\"; filename*=UTF-8''{}", percent_encode(&safe))
    }
}

/// RFC 5987 `ext-value` encoding: attr-char stays, everything else is percent-escaped.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'!' | b'#' | b'$' | b'&' | b'+' | b'-'
            | b'.' | b'^' | b'_' | b'`' | b'|' | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_filename_cannot_inject_a_header_or_escape_its_quotes() {
        let evil = "in\r\nX-Evil: yes\r\n\"; filename=\"real.exe";
        let got = content_disposition(evil, false);
        assert!(!got.contains('\r') && !got.contains('\n'), "no CR/LF survives: {got}");
        assert_eq!(got.matches('"').count(), 2, "exactly one quoted value: {got}");
    }

    #[test]
    fn a_filename_cannot_carry_a_path() {
        let got = content_disposition("../../etc/passwd", false);
        assert!(!got.contains('/'), "{got}");
    }

    #[test]
    fn a_non_ascii_filename_gets_both_forms() {
        let got = content_disposition("Übersicht.pdf", false);
        assert!(got.contains("filename=\"_bersicht.pdf\""), "an ASCII fallback: {got}");
        assert!(got.contains("filename*=UTF-8''%C3%9Cbersicht.pdf"), "and the real one: {got}");
    }

    #[test]
    fn an_empty_or_unnameable_filename_still_produces_something_usable() {
        assert!(content_disposition("", false).contains("\"download\""));
        assert!(content_disposition("///", false).contains("\"___\""));
    }

    #[test]
    fn only_allowlisted_types_are_offered_inline() {
        // The point of the list: an SVG is an image to a person and a script host to a browser.
        assert!(!INLINE_SAFE.contains(&"image/svg+xml"));
        assert!(!INLINE_SAFE.contains(&"text/html"));
        assert!(INLINE_SAFE.contains(&"image/png"));
    }
}
