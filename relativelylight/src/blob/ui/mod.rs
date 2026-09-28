//! Server-rendered components for `blob` — BLOBSTORE.md §5. Feature `blob-ui`.
//!
//! HTML *fragments* and a response builder, never whole pages and never a route: your app owns the
//! `<html>`, the layout, the URLs, and the authorization. Same discipline as `crud::ui`.
//!
//! | Piece | What it is |
//! |---|---|
//! | [`Receiver`] | streams a posted `multipart/form-data` upload straight into the store |
//! | [`UploadForm`] | the form that posts to it |
//! | [`Viewer`] | renders one version — always as a URL, never inlining stored bytes |
//! | [`to_response`] / [`to_inline_response`] | a verified [`ContentStream`](crate::blob::BlobHandle) as an HTTP reply |
//! | [`Browser`] | a searchable list of documents, drilling into one's version chain |
//! | [`Actions`] | the gated store-wide maintenance controls (consistency check / garbage collection) |
//!
//! Two things here are less obvious than they look, and both are in the sub-module docs rather than
//! here: why the upload path requires the CSRF token to arrive *before* the file part
//! ([`upload`](self::upload)), and why `Viewer` and `UploadForm` take no gate while `Actions` does
//! ([`render`](self::render)).

mod browse;
mod render;
mod response;
mod upload;

#[cfg(test)]
mod tests;

pub use browse::{BrowseState, Browser};
pub use render::{human_size, ActionOutcome, Actions, UploadForm, Viewer};
pub use response::{to_inline_response, to_response};
pub use upload::{Receiver, Upload, UploadError};
