//! Streaming `multipart/form-data` upload — BLOBSTORE.md §5.3.
//!
//! The posted file goes **straight from the socket into the store**, one chunk at a time, and is
//! never assembled in memory. That matters twice over:
//!
//! - It is the only shape that honours [`BlobStore::max_bytes`](crate::blob::BlobStore::max_bytes)
//!   as a *policy* limit. A handler taking axum's `Bytes` or `Multipart` buffers the whole request
//!   first, so a 500 MiB scan is 500 MiB resident before `blob` is even called — and it must raise
//!   `DefaultBodyLimit` (2 MB) to get that far. A handler taking `Body`, as
//!   [`Receiver::receive`] does, is subject to neither.
//! - **It closes the CSRF gap** that `crud::ui`'s CSV import still lives with. A buffered parser
//!   can check the token whenever it likes because it already holds the body; a streaming one has
//!   to decide *before* it starts writing. So this one requires the token to arrive **before** the
//!   file part, and [`UploadForm`](super::UploadForm) renders the hidden input first for exactly
//!   that reason. A body that puts the file first is refused without a byte of it being stored.
//!
//! Parsing itself is [`multer`](https://docs.rs/multer) — the crate axum's own extractor uses, and
//! the one `crate::multipart`'s docs already named as the answer when streaming was needed. A
//! hand-written parser here would be security-sensitive code with no upside.

use std::collections::HashMap;

use axum::body::Body;
use http::HeaderMap;

use crate::blob::{BlobBackend, BlobError, BlobStore, HandleId, PutMeta, VersionId, WriteContext};

/// What a posted upload form produced.
#[derive(Clone, Debug)]
pub struct Upload {
    /// The document. New for a fresh upload; the one you named for a new version.
    pub handle: HandleId,
    pub version: VersionId,
    pub filename: String,
    pub size: u64,
    /// The form's other text fields, by name. A repeated name keeps its last value.
    pub fields: HashMap<String, String>,
}

impl Upload {
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }
}

/// Why an upload was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum UploadError {
    /// The request wasn't `multipart/form-data`, or carried no usable boundary.
    NotMultipart,
    /// Malformed multipart framing.
    Malformed(String),
    /// No part matched the configured file field, or it carried no filename — an empty file picker.
    NoFile,
    /// The token was missing, wrong, or **arrived after the file part**. See the module docs: a
    /// streaming parser has to decide before it writes anything.
    Csrf,
    /// A non-file field exceeded [`Receiver::max_field_bytes`]. A text field in a form this crate
    /// renders is a few hundred bytes; anything larger is either a bug or an attempt to make the
    /// server buffer without limit.
    FieldTooLarge {
        name: String,
        limit: usize,
    },
    Blob(BlobError),
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UploadError::NotMultipart => f.write_str("not a multipart/form-data upload"),
            UploadError::Malformed(m) => write!(f, "malformed upload: {m}"),
            UploadError::NoFile => f.write_str("no file was submitted"),
            UploadError::Csrf => f.write_str("missing, invalid, or late CSRF token"),
            UploadError::FieldTooLarge { name, limit } => {
                write!(f, "form field {name:?} is over the {limit}-byte limit")
            }
            UploadError::Blob(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for UploadError {}

impl From<BlobError> for UploadError {
    fn from(e: BlobError) -> Self {
        UploadError::Blob(e)
    }
}

impl UploadError {
    /// The status an app should answer with, if it has no opinion of its own.
    pub fn status(&self) -> http::StatusCode {
        match self {
            UploadError::Csrf => http::StatusCode::FORBIDDEN,
            UploadError::Blob(BlobError::TooLarge { .. }) | UploadError::FieldTooLarge { .. } => {
                http::StatusCode::PAYLOAD_TOO_LARGE
            }
            UploadError::Blob(BlobError::Db(_) | BlobError::Backend(_)) => {
                http::StatusCode::INTERNAL_SERVER_ERROR
            }
            _ => http::StatusCode::BAD_REQUEST,
        }
    }
}

enum Target {
    NewHandle,
    Version(HandleId),
}

/// Reads one posted upload form into the store, streaming.
///
/// ```no_run
/// # use relativelylight::blob::{BlobStore, WriteContext};
/// # use relativelylight::blob::ui::Receiver;
/// # async fn h(store: &BlobStore, headers: http::HeaderMap, body: axum::body::Body)
/// #     -> Result<(), Box<dyn std::error::Error>> {
/// let upload = Receiver::new(store)
///     .by(Some("alice".into()))
///     .receive(&headers, body, WriteContext::none())
///     .await?;
/// // `upload.handle` is what your own document table stores (BLOBSTORE.md §9).
/// # Ok(()) }
/// ```
pub struct Receiver<'a, B: BlobBackend = crate::blob::FsBackend> {
    store: &'a BlobStore<B>,
    file_field: String,
    max_field_bytes: usize,
    created_by: Option<String>,
    target: Target,
    #[cfg(feature = "csrf")]
    csrf: Option<&'a crate::csrf::Csrf>,
}

impl<'a, B: BlobBackend> Receiver<'a, B> {
    pub fn new(store: &'a BlobStore<B>) -> Self {
        Self {
            store,
            file_field: "file".into(),
            max_field_bytes: 64 * 1024,
            created_by: None,
            target: Target::NewHandle,
            #[cfg(feature = "csrf")]
            csrf: None,
        }
    }

    /// Which part carries the file. Default `"file"`, matching [`UploadForm`](super::UploadForm).
    pub fn file_field(mut self, name: impl Into<String>) -> Self {
        self.file_field = name.into();
        self
    }

    /// Cap on each non-file field. Default 64 KiB.
    pub fn max_field_bytes(mut self, n: usize) -> Self {
        self.max_field_bytes = n;
        self
    }

    /// The uploader's display identity, recorded as a snapshot on the version (BLOBSTORE.md §3.3).
    /// An app running `auth` passes `who.username`.
    pub fn by(mut self, who: Option<String>) -> Self {
        self.created_by = who;
        self
    }

    /// Append to an existing document instead of creating one.
    pub fn as_version_of(mut self, handle: HandleId) -> Self {
        self.target = Target::Version(handle);
        self
    }

    /// Require a valid `_csrf` field, **before** the file part. Pass `auth.csrf()`.
    #[cfg(feature = "csrf")]
    pub fn csrf(mut self, csrf: &'a crate::csrf::Csrf) -> Self {
        self.csrf = Some(csrf);
        self
    }

    /// Stream the body into the store.
    ///
    /// Takes `Body` rather than a buffering extractor on purpose — see the module docs. Nothing is
    /// committed unless the whole upload arrives: a client that hangs up mid-file, an oversized
    /// one, and a late CSRF token all leave no index row and no staged file.
    pub async fn receive(
        self,
        headers: &HeaderMap,
        body: Body,
        ctx: WriteContext<'_>,
    ) -> Result<Upload, UploadError> {
        let content_type = headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let boundary =
            crate::multipart::boundary(content_type).ok_or(UploadError::NotMultipart)?;

        let mut parts = multer::Multipart::new(body.into_data_stream(), boundary);
        let mut fields: HashMap<String, String> = HashMap::new();
        let mut done: Option<Upload> = None;

        #[cfg(feature = "csrf")]
        let mut csrf_ok = self.csrf.is_none();
        #[cfg(not(feature = "csrf"))]
        let csrf_ok = true;

        while let Some(mut field) =
            parts.next_field().await.map_err(|e| UploadError::Malformed(e.to_string()))?
        {
            let name = field.name().unwrap_or_default().to_owned();
            let filename = field.file_name().map(str::to_owned);
            let mime = field.content_type().map(|m| m.to_string()).unwrap_or_default();

            let is_file = name == self.file_field && filename.is_some();
            if !is_file {
                // A text field: bounded, collected, and (for `_csrf`) checked immediately.
                let mut buf = Vec::new();
                while let Some(chunk) =
                    field.chunk().await.map_err(|e| UploadError::Malformed(e.to_string()))?
                {
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
                        if !c.verify(headers, Some(&value)) {
                            return Err(UploadError::Csrf);
                        }
                        csrf_ok = true;
                    }
                }

                fields.insert(name, value);
                continue;
            }

            // The file part. Everything above this line ran before a single byte was stored.
            if !csrf_ok {
                // Deliberately not "check it afterwards": by then the write has happened, which is
                // the whole thing CSRF is meant to prevent.
                return Err(UploadError::Csrf);
            }
            if done.is_some() {
                return Err(UploadError::Malformed("more than one file part".into()));
            }

            let filename = filename.unwrap_or_default();
            let mut ingest = self.store.ingest().await?;
            loop {
                match field.chunk().await {
                    Ok(Some(chunk)) => ingest.write_chunk(&chunk).await?,
                    Ok(None) => break,
                    Err(e) => {
                        // A client that hangs up mid-upload: discard the staged bytes rather than
                        // leaving them for `fsck`.
                        ingest.abort().await;
                        return Err(UploadError::Malformed(e.to_string()));
                    }
                }
            }

            let size = ingest.size();
            let meta = PutMeta {
                filename: filename.clone(),
                mime_declared: mime,
                created_by: self.created_by.clone(),
                metadata: None,
            };
            let (handle, version) = match self.target {
                Target::NewHandle => {
                    let h = ingest.commit_new(meta, ctx).await?;
                    let v = self.store.head(h).await?.id;
                    (h, v)
                }
                Target::Version(h) => (h, ingest.commit_version(h, meta, ctx).await?),
            };
            done = Some(Upload { handle, version, filename, size, fields: HashMap::new() });
        }

        let mut upload = done.ok_or(UploadError::NoFile)?;
        upload.fields = fields;
        Ok(upload)
    }
}
