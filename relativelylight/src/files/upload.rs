//! Reading a posted `multipart/form-data` upload, one part at a time — FILES.md §1.
//!
//! **The crate parses, the app stores.** [`Upload::next`] yields the form's parts in the order the
//! browser sent them: text fields as values, files as a [`FilePart`] the app pulls chunks from and
//! writes wherever it keeps files — a directory, a database column, an object store. Nothing is
//! buffered beyond one chunk (and the first [`SNIFF_BYTES`] of each file), which matters twice over:
//!
//! - It is the only shape that honours [`Upload::max_bytes`] as a *policy* limit. A handler taking
//!   axum's `Bytes` or `Multipart` buffers the whole request first, so a 500 MiB scan is 500 MiB
//!   resident before the app sees it — and it must raise `DefaultBodyLimit` (2 MB) to get that far.
//!   A handler taking `Body`, as [`Upload::new`] does, is subject to neither.
//! - **It closes the CSRF gap** a buffered parser leaves open. A streaming parser has to decide
//!   *before* the app writes, so [`Upload::csrf`] requires the token to arrive **before** the first
//!   file part, and [`UploadForm`](super::UploadForm) renders the hidden input first for exactly that
//!   reason. A body that puts a file first is refused before the app sees a byte of it.
//!
//! The same document order puts the form's other fields — a "save as" name — ahead of the files, so
//! the app knows where a file goes before it starts writing it.
//!
//! **A refused upload is the app's to clean up.** When a limit is hit or the client hangs up halfway
//! through a file, [`FilePart::chunk`] returns the error and the app discards what it wrote of that
//! file — and of earlier ones, if the post is all-or-nothing. Write to a temporary name or inside a
//! transaction, and commit after the last part. Parsing itself is [`multer`](https://docs.rs/multer),
//! the parser axum's own extractor uses.

use std::collections::VecDeque;

use axum::body::{Body, Bytes};
use http::HeaderMap;
use sha2::{Digest, Sha256};

use super::sniff::{sniff_mime, SNIFF_BYTES};

/// Why an upload was refused. After an error the [`Upload`] is finished: further calls return
/// [`UploadError::Finished`].
#[derive(Debug)]
#[non_exhaustive]
pub enum UploadError {
    /// The request wasn't `multipart/form-data`, or carried no usable boundary.
    NotMultipart,
    /// Malformed multipart framing, or the client hung up mid-upload.
    Malformed(String),
    /// The token was missing, wrong, or **arrived after a file part**. See the module docs.
    Csrf,
    /// A text field exceeded [`Upload::max_field_bytes`].
    FieldTooLarge { name: String, limit: usize },
    /// A file exceeded [`Upload::max_bytes`]; detected while streaming.
    TooLarge { limit: u64 },
    /// More file parts than [`Upload::max_files`].
    TooManyFiles { limit: usize },
    /// The upload already failed; it yields nothing more.
    Finished,
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UploadError::NotMultipart => f.write_str("not a multipart/form-data upload"),
            UploadError::Malformed(m) => write!(f, "malformed upload: {m}"),
            UploadError::Csrf => f.write_str("missing, invalid, or late CSRF token"),
            UploadError::FieldTooLarge { name, limit } => {
                write!(f, "form field {name:?} is over the {limit}-byte limit")
            }
            UploadError::TooLarge { limit } => write!(f, "a file is over the {limit}-byte limit"),
            UploadError::TooManyFiles { limit } => write!(f, "more than {limit} files"),
            UploadError::Finished => f.write_str("the upload already failed"),
        }
    }
}

impl std::error::Error for UploadError {}

impl UploadError {
    /// The status an app should answer with, if it has no opinion of its own.
    pub fn status(&self) -> http::StatusCode {
        match self {
            UploadError::NotMultipart => http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            UploadError::Csrf => http::StatusCode::FORBIDDEN,
            UploadError::TooLarge { .. }
            | UploadError::FieldTooLarge { .. }
            | UploadError::TooManyFiles { .. } => http::StatusCode::PAYLOAD_TOO_LARGE,
            _ => http::StatusCode::BAD_REQUEST,
        }
    }
}

/// One part of the form, as [`Upload::next`] yields it.
#[derive(Debug)]
pub enum Part<'u> {
    /// A text field: its name and value, at most [`Upload::max_field_bytes`] long.
    Field(String, String),
    /// A file. Read it to the end, or drop it to skip the rest of it.
    File(FilePart<'u>),
}

/// A posted form being read, streaming.
///
/// ```no_run
/// # use relativelylight::files::{Part, Upload};
/// # async fn h(csrf: &relativelylight::csrf::Csrf, headers: http::HeaderMap,
/// #     body: axum::body::Body) -> Result<(), Box<dyn std::error::Error>> {
/// let mut up = Upload::new(&headers, body)?.csrf(csrf).max_bytes(64 << 20);
/// let mut save_as = None;
/// while let Some(part) = up.next().await? {
///     match part {
///         Part::Field(name, value) if name == "name" => save_as = Some(value),
///         Part::Field(..) => {}
///         Part::File(mut f) => {
///             // f.filename(), f.mime() — known before the first byte is written
///             while let Some(chunk) = f.chunk().await? {
///                 // write `chunk` wherever this app keeps files
///             }
///             let (size, sha256) = (f.size(), f.sha256().unwrap());
///         }
///     }
/// }
/// # Ok(()) }
/// ```
pub struct Upload<'a> {
    parts: multer::Multipart<'static>,
    // The request the token is checked against; unread without `csrf`, kept so the type is the same.
    #[cfg_attr(not(feature = "csrf"), allow(dead_code))]
    headers: &'a HeaderMap,
    state: State,
    file_field: String,
    max_field_bytes: usize,
    max_files: usize,
    #[cfg(feature = "csrf")]
    csrf: Option<&'a crate::csrf::Csrf>,
}

/// What a [`FilePart`] reports back to its [`Upload`].
struct State {
    max_bytes: u64,
    files: usize,
    csrf_ok: bool,
    failed: bool,
}

impl std::fmt::Debug for Upload<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Upload").field("files", &self.state.files).finish_non_exhaustive()
    }
}

impl<'a> Upload<'a> {
    /// Takes `Body` rather than a buffering extractor on purpose — see the module docs. Refuses a
    /// request that isn't `multipart/form-data` before reading any of it.
    pub fn new(headers: &'a HeaderMap, body: Body) -> Result<Self, UploadError> {
        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let boundary =
            multer::parse_boundary(content_type).map_err(|_| UploadError::NotMultipart)?;
        Ok(Self {
            parts: multer::Multipart::new(body.into_data_stream(), boundary),
            headers,
            state: State { max_bytes: 512 * 1024 * 1024, files: 0, csrf_ok: true, failed: false },
            file_field: "file".into(),
            max_field_bytes: 64 * 1024,
            max_files: 32,
            #[cfg(feature = "csrf")]
            csrf: None,
        })
    }

    /// Which field carries files. Default `"file"`, matching [`UploadForm`](super::UploadForm). A
    /// file posted under another name is refused as [`UploadError::Malformed`].
    pub fn file_field(mut self, name: impl Into<String>) -> Self {
        self.file_field = name.into();
        self
    }

    /// Cap on each file, enforced while streaming. Default 512 MiB.
    pub fn max_bytes(mut self, n: u64) -> Self {
        self.state.max_bytes = n;
        self
    }

    /// Cap on the number of files in one post. Default 32.
    pub fn max_files(mut self, n: usize) -> Self {
        self.max_files = n;
        self
    }

    /// Cap on each text field. Default 64 KiB — a field in a form this crate renders is a few
    /// hundred bytes; anything larger is a bug or an attempt to make the server buffer.
    pub fn max_field_bytes(mut self, n: usize) -> Self {
        self.max_field_bytes = n;
        self
    }

    /// Require a valid `_csrf` field **before** the first file part. Pass `auth.csrf()`, or your
    /// own [`Csrf`](crate::csrf::Csrf).
    #[cfg(feature = "csrf")]
    pub fn csrf(mut self, csrf: &'a crate::csrf::Csrf) -> Self {
        self.csrf = Some(csrf);
        self.state.csrf_ok = false;
        self
    }

    /// How many files have been yielded so far — `0` at the end means an empty picker.
    pub fn files(&self) -> usize {
        self.state.files
    }

    /// The next part, or `None` after the last. Borrows the upload, so a [`FilePart`] is read or
    /// dropped before the next part is asked for.
    pub async fn next(&mut self) -> Result<Option<Part<'_>>, UploadError> {
        if self.state.failed {
            return Err(UploadError::Finished);
        }
        match self.advance().await {
            Ok(Some(Advance::Field(name, value))) => Ok(Some(Part::Field(name, value))),
            Ok(Some(Advance::File(inner, mime))) => {
                Ok(Some(Part::File(FilePart { inner, mime, sha256: None, state: &mut self.state })))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                self.state.failed = true;
                Err(e)
            }
        }
    }

    async fn advance(&mut self) -> Result<Option<Advance>, UploadError> {
        loop {
            let Some(mut part) = self.parts.next_field().await.map_err(malformed)? else {
                return Ok(None);
            };
            let name = part.name().unwrap_or_default().to_owned();
            let Some(filename) = part.file_name().map(str::to_owned) else {
                // A text field: bounded, collected, and (for `_csrf`) checked immediately.
                let mut buf = Vec::new();
                while let Some(chunk) = part.chunk().await.map_err(malformed)? {
                    if buf.len() + chunk.len() > self.max_field_bytes {
                        return Err(UploadError::FieldTooLarge {
                            name,
                            limit: self.max_field_bytes,
                        });
                    }
                    buf.extend_from_slice(&chunk);
                }
                let value = String::from_utf8_lossy(&buf).into_owned();
                #[cfg(feature = "csrf")]
                if name == "_csrf" {
                    if let Some(c) = self.csrf {
                        if !c.verify(self.headers, Some(&value)) {
                            return Err(UploadError::Csrf);
                        }
                        self.state.csrf_ok = true;
                    }
                }
                return Ok(Some(Advance::Field(name, value)));
            };

            // A file part. Everything above this line ran before the app saw a byte of it.
            if !self.state.csrf_ok {
                // Deliberately not "check it afterwards": by then the app has written, which is
                // the whole thing CSRF is meant to prevent.
                return Err(UploadError::Csrf);
            }
            if name != self.file_field {
                return Err(UploadError::Malformed(format!("a file in field {name:?}")));
            }
            let mime_declared = part.content_type().map(|m| m.to_string()).unwrap_or_default();

            // Read ahead far enough to sniff, so `mime()` is known before the app writes anything.
            let mut file = Pending {
                field: part,
                filename,
                mime_declared,
                head: VecDeque::new(),
                size: 0,
                hasher: Sha256::new(),
                ended: false,
            };
            let mut sniffed = Vec::with_capacity(SNIFF_BYTES);
            while sniffed.len() < SNIFF_BYTES {
                match file.pull(self.state.max_bytes).await? {
                    Some(chunk) => {
                        let take = (SNIFF_BYTES - sniffed.len()).min(chunk.len());
                        sniffed.extend_from_slice(&chunk[..take]);
                        file.head.push_back(chunk);
                    }
                    None => break,
                }
            }
            // An `<input type=file>` left empty still posts a part: no filename, no bytes. A form
            // with a picker *and* a camera input sends one of these whenever only one is used.
            if file.filename.is_empty() && file.size == 0 {
                continue;
            }
            if self.state.files >= self.max_files {
                return Err(UploadError::TooManyFiles { limit: self.max_files });
            }
            self.state.files += 1;
            return Ok(Some(Advance::File(Box::new(file), sniff_mime(&sniffed))));
        }
    }
}

enum Advance {
    Field(String, String),
    File(Box<Pending>, &'static str),
}

/// A file part before it is handed out: the read-ahead and the running size and hash.
struct Pending {
    field: multer::Field<'static>,
    filename: String,
    mime_declared: String,
    head: VecDeque<Bytes>,
    size: u64,
    hasher: Sha256,
    ended: bool,
}

impl Pending {
    /// The next chunk off the wire, counted and hashed.
    async fn pull(&mut self, max_bytes: u64) -> Result<Option<Bytes>, UploadError> {
        if self.ended {
            return Ok(None);
        }
        match self.field.chunk().await.map_err(malformed)? {
            Some(chunk) => {
                self.size += chunk.len() as u64;
                if self.size > max_bytes {
                    return Err(UploadError::TooLarge { limit: max_bytes });
                }
                self.hasher.update(&chunk);
                Ok(Some(chunk))
            }
            None => {
                self.ended = true;
                Ok(None)
            }
        }
    }
}

/// One posted file, read by the app chunk by chunk.
pub struct FilePart<'u> {
    inner: Box<Pending>,
    mime: &'static str,
    sha256: Option<String>,
    state: &'u mut State,
}

impl std::fmt::Debug for FilePart<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FilePart")
            .field("filename", &self.inner.filename)
            .field("mime", &self.mime)
            .field("size", &self.inner.size)
            .finish_non_exhaustive()
    }
}

impl FilePart<'_> {
    /// The filename **as the browser sent it** — untrusted, possibly empty (a camera capture on
    /// some phones). Make your own name from it; never a path.
    pub fn filename(&self) -> &str {
        &self.inner.filename
    }

    /// The type the browser claimed. Advisory: compare it with [`mime`](Self::mime).
    pub fn declared_mime(&self) -> &str {
        &self.inner.mime_declared
    }

    /// The type the bytes say ([`sniff_mime`]), from the first [`SNIFF_BYTES`] — known before the
    /// first [`chunk`](Self::chunk), so the app can refuse a type without writing anything.
    pub fn mime(&self) -> &'static str {
        self.mime
    }

    /// The next chunk, or `None` at the end of the file. A limit hit or a broken connection is an
    /// error here, and the upload yields nothing after it — discard what you wrote of this file.
    pub async fn chunk(&mut self) -> Result<Option<Bytes>, UploadError> {
        if let Some(chunk) = self.inner.head.pop_front() {
            return Ok(Some(chunk));
        }
        if self.sha256.is_some() {
            return Ok(None);
        }
        match self.inner.pull(self.state.max_bytes).await {
            Ok(Some(chunk)) => Ok(Some(chunk)),
            Ok(None) => {
                self.sha256 = Some(hex(&self.inner.hasher.clone().finalize()));
                Ok(None)
            }
            Err(e) => {
                self.state.failed = true;
                Err(e)
            }
        }
    }

    /// The rest of the file in memory — for a file headed for a database column. [`Upload::max_bytes`]
    /// is then also the memory bound: set it to what the column should hold.
    pub async fn bytes(&mut self) -> Result<Vec<u8>, UploadError> {
        let mut out = Vec::new();
        while let Some(chunk) = self.chunk().await? {
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Bytes read so far; the file's size once [`chunk`](Self::chunk) has returned `None`.
    pub fn size(&self) -> u64 {
        self.inner.size
    }

    /// Lowercase hex SHA-256 of the content, computed while it streamed — `Some` once the file has
    /// been read to the end. The checksum for your index table, at no extra read.
    pub fn sha256(&self) -> Option<&str> {
        self.sha256.as_deref()
    }
}

fn malformed(e: multer::Error) -> UploadError {
    UploadError::Malformed(e.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
