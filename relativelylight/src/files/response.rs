//! Turning any byte stream into an HTTP reply — FILES.md §2.
//!
//! **Not a route.** The app's handler authorises the request, opens the bytes from wherever they
//! live (a file or an object store via [`Download::new`], a database column via
//! [`Download::from_bytes`]), and calls one of these to build the response. The security decision
//! — what may render inline — is made here, where the `Content-Type` is actually set.

use std::pin::Pin;

use axum::body::Body;
use axum::response::Response;
use http::header;
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;

use super::sniff::sniff_mime;

/// Types safe to render in the browser without becoming script. Everything else is downloaded.
///
/// An allowlist rather than a denylist, because the failure mode is XSS: `image/svg+xml` is an
/// image to a user and a scriptable document to a browser, and `text/html` needs no explanation.
pub(crate) const INLINE_SAFE: &[&str] = &[
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

/// Bytes to send, with the name and type to send them under.
pub struct Download {
    reader: Pin<Box<dyn AsyncRead + Send>>,
    filename: String,
    mime: String,
    len: Option<u64>,
}

impl Download {
    /// `mime` should be what the **bytes** say ([`sniff_mime`]), not what an uploader claimed: it
    /// decides whether [`to_inline_response`] renders the content.
    pub fn new(
        reader: impl AsyncRead + Send + 'static,
        filename: impl Into<String>,
        mime: impl Into<String>,
    ) -> Self {
        Self { reader: Box::pin(reader), filename: filename.into(), mime: mime.into(), len: None }
    }

    /// Content held in memory — a file stored in a database column. The type is sniffed.
    pub fn from_bytes(bytes: Vec<u8>, filename: impl Into<String>) -> Self {
        let mime = sniff_mime(&bytes);
        let len = bytes.len() as u64;
        Self::new(std::io::Cursor::new(bytes), filename, mime).content_length(len)
    }

    /// Sets `Content-Length`, so a browser can show progress. Omitted, the body is chunked.
    pub fn content_length(mut self, n: u64) -> Self {
        self.len = Some(n);
        self
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }

    pub fn mime(&self) -> &str {
        &self.mime
    }
}

/// A download: `Content-Disposition: attachment`, so nothing renders in the browsing context.
pub fn to_response(d: Download) -> Response {
    build(d, false)
}

/// For content a page displays — an `<img src>` or an `<embed src>` from
/// [`Preview`](super::Preview) or a [`Thumbnail`](super::Thumbnail).
///
/// Serves inline **only** for the types in this module's allowlist; anything else silently becomes
/// an attachment. So a hostile SVG is downloaded, not executed, even though a page asked for it
/// inline.
pub fn to_inline_response(d: Download) -> Response {
    build(d, true)
}

fn build(d: Download, want_inline: bool) -> Response {
    let mime = if d.mime.is_empty() { "application/octet-stream".to_owned() } else { d.mime };
    let inline = want_inline && INLINE_SAFE.contains(&mime.as_str());
    let mut res = Response::builder()
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_DISPOSITION, content_disposition(&d.filename, inline))
        // The type is derived from the bytes, but it is still a guess. Telling the browser not to
        // second-guess it stops a file that sniffs as `text/plain` being re-read as HTML.
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    if let Some(n) = d.len {
        res = res.header(header::CONTENT_LENGTH, n);
    }
    if inline {
        // Belt and braces for the inline path: even an allowlisted type renders with no script, no
        // plugins and no ability to be framed into someone else's page.
        res = res.header(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; img-src 'self' data:; object-src 'self'; sandbox",
        );
    }
    res.body(Body::from_stream(ReaderStream::new(d.reader)))
        .expect("response builder: valid headers")
}

/// A `Content-Disposition` value that can't inject a header or smuggle a path.
///
/// - **Header injection.** A filename containing CR or LF would end the header and begin another.
/// - **Quote escaping.** A `"` would close the quoted string early.
/// - **Path traversal on the client.** Some clients have honoured directory separators in a
///   suggested filename.
///
/// Non-ASCII names also get the RFC 6266 / RFC 5987 `filename*` form, since the plain parameter has
/// no defined encoding — so "Übersicht.pdf" arrives intact.
pub(crate) fn content_disposition(filename: &str, inline: bool) -> String {
    let kind = if inline { "inline" } else { "attachment" };
    let safe: String = filename
        .chars()
        .map(|c| match c {
            '"' | '\\' | '/' => '_',
            c if c.is_control() => '_',
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
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'&'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
