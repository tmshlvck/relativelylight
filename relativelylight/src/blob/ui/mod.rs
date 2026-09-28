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
//! | [`to_response`] / [`to_inline_response`] | a verified [`ContentStream`](crate::blob::ContentStream) as an HTTP reply |
//! | [`Portal`] | one document: current version, optional history, optional upload |
//! | [`Routes`] | an optional gated router serving content, plus the URLs that reach it |
//! | [`Browser`] | the admin panel: a searchable list of handles, drilling into one's versions |
//! | [`Actions`] | the gated store-wide maintenance controls (consistency check / garbage collection) |
//!
//! Three things here are less obvious than they look, and each is documented where it lives: why
//! the upload path requires the CSRF token to arrive *before* the file part ([`Receiver`]); why
//! [`Viewer`] and [`UploadForm`] take no gate while [`Browser`], [`Portal`] and [`Actions`] do; and
//! when it is safe to mount [`Routes`] at all, which is the one thing here that can quietly undo an
//! app's own authorization.

mod browse;
mod portal;
mod render;
mod routes;
mod response;
mod upload;

#[cfg(test)]
mod tests;

pub use browse::{BrowseState, Browser};
pub use portal::Portal;
pub use routes::Routes;
pub use render::{human_size, ActionOutcome, Actions, UploadForm, Viewer};
pub use response::{to_inline_response, to_response};
pub use upload::{Receiver, Upload, UploadError};
