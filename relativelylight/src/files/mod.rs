//! Files on a page: upload, preview, thumbnail, serve — **storage is the app's**. Feature `files`.
//!
//! The guide is **[docs/FILES.md](../../../docs/FILES.md)**; this is the orientation.
//!
//! Where the bytes live, what they are called, who may see them and how they are listed is the
//! app's (FILES.md §4). Nothing here reads, writes, lists or deletes a file.
//!
//! | Piece | What it does |
//! |---|---|
//! | [`Upload`](crate::files::Upload) | reads a posted `multipart/form-data` body part by part: the app pulls each file's chunks and writes them wherever it likes; CSRF-checked before the first file, size-capped while streaming, hashed and sniffed on the way |
//! | [`Download`](crate::files::Download), [`to_response`](crate::files::to_response), [`to_inline_response`](crate::files::to_inline_response) | any byte stream as an HTTP reply, inline only for an allowlist of types |
//! | [`UploadForm`](crate::files::UploadForm), [`Preview`](crate::files::Preview), [`Thumbnail`](crate::files::Thumbnail) | Bootstrap fragments from plain values the app passes in |
//! | [`sniff_mime`](crate::files::sniff_mime), [`human_size`](crate::files::human_size), [`url_segment`](crate::files::url_segment), [`TEXT_PREVIEW_MAX`](crate::files::TEXT_PREVIEW_MAX) | small helpers |
//!
//! # The smallest thing that works
//!
//! ```no_run
//! # async fn f(headers: http::HeaderMap, body: axum::body::Body) -> Result<(), Box<dyn std::error::Error>> {
//! use relativelylight::files::{Part, Upload};
//! use tokio::io::AsyncWriteExt;
//!
//! let mut up = Upload::new(&headers, body)?;
//! while let Some(part) = up.next().await? {
//!     if let Part::File(mut f) = part {
//!         let mut out = tokio::fs::File::create("/tmp/upload.part").await?;  // your storage
//!         while let Some(chunk) = f.chunk().await? {
//!             out.write_all(&chunk).await?;
//!         }
//!         // f.filename(), f.mime(), f.size(), f.sha256() go into your own table.
//!     }
//! }
//! # Ok(()) }
//! ```

mod render;
mod response;
mod sniff;
mod upload;

#[cfg(test)]
mod tests;

pub use render::{url_segment, Preview, Thumbnail, UploadForm, TEXT_PREVIEW_MAX};
pub use response::{to_inline_response, to_response, Download};
pub use sniff::{human_size, sniff_mime, SNIFF_BYTES};
pub use upload::{FilePart, Part, Upload, UploadError};
