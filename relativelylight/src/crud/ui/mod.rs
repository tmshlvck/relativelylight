//! `relativelylight::crud::ui` — the admin UI, rendered on the server as plain HTML.
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
//! use relativelylight::crud::ui::{Admin, Outcome, ViewState};
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
    banner, check_fields, check_sort, check_widgets, csv_header, is_filterable, render_err, renders,
};
pub(crate) use write::{apply, authorize, csrf_token, Surface, Writes};

use serde_json::Value;
use std::sync::Arc;

/// The stylesheet the components need beyond Bootstrap 5 (mostly `<dialog>`).
/// Inline it once in your shell: `<style>{{ relativelylight::crud::ui::CSS }}</style>`.
pub const CSS: &str = include_str!("../../../assets/rl.css");

/// The relation picker's script — the one script the components ship. Include it once per page
/// that renders a form, as `<script>{{ relativelylight::crud::ui::JS }}</script>` or served from a
/// file of your own (a strict CSP). It is needed only once `Crud::picker_path` is set; without it a
/// large relation still shows its selection and saves it unchanged, it just can't be edited.
pub const JS: &str = include_str!("../../../assets/rl.js");

/// A custom renderer, `(value, row) -> HTML`, as [`Table::format_cell`] and [`Table::format_view`]
/// store it. Its output is inserted **verbatim**.
pub(crate) type Fmt = Arc<dyn Fn(&Value, &Value) -> String + Send + Sync>;

/// Escape a JSON scalar for HTML — what a [`Table::format_cell`] / [`Table::format_view`] closure
/// wraps its values in. A `String` loses its quotes; anything else prints as JSON.
///
/// ```ignore
/// .format_cell("title", |v, row| format!(r#"<a href="/post/{}">{}</a>"#, esc(&row["id"]), esc(v)))
/// ```
pub fn esc(value: &Value) -> String {
    esc_str(&render::text(Some(value)))
}

/// A ready-made renderer that shortens a value to its first `chars` characters plus `…`, with the
/// whole of it in the `title` tooltip — for [`Table::format_cell`], so the listing shows a corner of
/// a long text and the View dialog all of it. Escapes the value; a value that fits is shown as is.
///
/// ```ignore
/// Table::new(&engine, "post").format_cell("body", truncate(60))
/// ```
pub fn truncate(chars: usize) -> impl Fn(&Value, &Value) -> String + Send + Sync + 'static {
    move |v, _| {
        let s = render::text(Some(v));
        match s.char_indices().nth(chars) {
            None => esc_str(&s),
            Some((cut, _)) => {
                format!(r#"<span title="{}">{}…</span>"#, esc_str(&s), esc_str(s[..cut].trim_end()))
            }
        }
    }
}

/// Escape a string for inclusion in HTML text or a quoted attribute.
pub fn esc_str(s: &str) -> String {
    crate::html::esc(s)
}

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

/// A per-row CSS class, `(row) -> class`, as [`Table::row_class`] stores it.
pub(crate) type RowClass = Arc<dyn Fn(&Value) -> String + Send + Sync>;
