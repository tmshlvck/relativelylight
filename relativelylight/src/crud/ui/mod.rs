//! The admin UI (re-exported at `relativelylight::crud`), rendered on the server as plain HTML.
//!
//! Three components, one implementation:
//!
//! - [`Table`] — one entity: search, sortable headers, filters, a pager, CSV, bulk delete, and a
//!   create/edit `<dialog>`.
//! - [`Form`] — the same form standalone, for an app's own pages.
//! - [`Admin`] — a side panel over many `Table`s.
//!
//! Plus [`Picker`], the page inside the dialog that edits a relation too large for a `<select>`.
//!
//! All of them are **fragments**: the app owns `<html>`, the Bootstrap 5 stylesheet, and the layout.
//! There is no JavaScript framework and no JSON in between — the URL is the state ([`ViewState`]),
//! writes are `POST` → `303` → `GET`, and the dialog is a native `<dialog open>`. Include [`CSS`]
//! once per page for the few rules Bootstrap doesn't cover, and [`JS`] where a picker is served.
//!
//! # Two handlers per surface
//!
//! Reads stay the app's route, so the app keeps owning its own shell, its own auth redirect and its
//! own error pages. Writes post back to that same URL, and the library does the work:
//!
//! ```ignore
//! use relativelylight::crud::{Admin, Outcome, ViewState};
//!
//! fn panel(engine: &Engine) -> Admin<'_> {          // one definition, used by both handlers
//!     Admin::new(engine).title("Admin").entity("post").entity("tag")
//! }
//!
//! let app = Router::new().route("/admin", get(show).post(save));
//!
//! async fn show(headers: HeaderMap, uri: Uri, State(app): State<Arc<App>>) -> Response {
//!     let state = ViewState::from_uri(&uri);
//!     let frag = panel(&app.engine).render_for(&headers, &state).await?;
//!     Html(my_shell(frag)).into_response()
//! }
//!
//! async fn save(headers: HeaderMap, uri: Uri, RealIp(ip): RealIp, State(app): State<Arc<App>>,
//!               body: String) -> Response {
//!     let state = ViewState::from_uri(&uri);
//!     match panel(&app.engine).submit(&headers, ip, &body, &state).await? {
//!         // Relative, so it lands back on this same page — the library never learns its path.
//!         Outcome::Done(to) => Redirect::to(&to).into_response(),
//!         // Rejected: re-render with the messages and the typed values in place.
//!         Outcome::Invalid(state) => {
//!             let frag = panel(&app.engine).render_for(&headers, &state).await?;
//!             (StatusCode::UNPROCESSABLE_ENTITY, Html(my_shell(frag))).into_response()
//!         }
//!     }
//! }
//! ```

mod admin;
mod checks;
mod decode;
mod field;
mod form;
mod picker;
mod render;
mod state;
mod table;
mod widgets;
mod write;

pub use admin::Admin;
pub use field::RelationField;
pub use form::Form;
pub use picker::Picker;
pub use state::{Done, Mode, ViewState};
pub use table::Table;

pub(crate) use checks::{
    banner, check_fields, check_initial, check_sort, check_widgets, csv_header, is_filterable,
    range_kind, render_err, renders, RangeKind,
};
pub(crate) use write::{apply, authorize, csrf_token, Surface, Writes};


/// The stylesheet the components need beyond Bootstrap 5 (mostly `<dialog>`).
/// Inline it once in your shell: `<style>{{ relativelylight::crud::CSS }}</style>`.
pub const CSS: &str = include_str!("../../../assets/rl.css");

/// The components' script: it makes the dialogs real modals (Esc closes them) and drives the relation
/// picker. Include it once per page with a table or a form, as
/// `<script>{{ relativelylight::crud::JS }}</script>` or served from a file of your own (a strict
/// CSP). Everything works without it, only plainer: a dialog is a page section, and a large
/// relation shows its selection and saves it unchanged but can't be edited.
pub const JS: &str = include_str!("../../../assets/rl.js");

/// What a [`submit`](Table::submit) did. (`Invalid` is large; it's returned once per request, so it
/// isn't boxed.)
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Outcome {
    /// Applied. Redirect to this **relative** URL (`?entity=post&page=2#row-7`), which is the list
    /// the write came from, scrolled to the row that changed.
    Done(String),
    /// Refused by validation. Re-render the surface with this state: the dialog reopens with the
    /// messages beside the fields and the operator's input still in them. Answer `422`.
    Invalid(ViewState),
}
