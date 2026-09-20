//! `relativelylight::crud::ui` — the admin UI, rendered on the server as plain HTML.
//!
//! Three components, one implementation:
//!
//! - [`Table`] — one entity: search, sortable headers, filters, a pager, CSV, bulk delete, and a
//!   create/edit `<dialog>`.
//! - [`Form`] — the same form standalone, for an app's own pages.
//! - [`Admin`] — a side panel over many `Table`s.
//!
//! All three are **fragments**: the app owns `<html>`, the Bootstrap 5 stylesheet, and the layout.
//! There is no JavaScript framework, no JSON in between, and no client-side state — the URL is the
//! state ([`ViewState`]), writes are `POST` → `303` → `GET`, and the dialog is a native
//! `<dialog open>`. Include [`CSS`] once per page for the few rules Bootstrap doesn't cover.
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
mod form;
mod render;
mod state;
mod table;
mod widgets;
mod write;

pub use admin::Admin;
pub use form::Form;
pub use state::{Done, Mode, ViewState};
pub use table::Table;

pub(crate) use checks::{
    banner, check_fields, check_sort, check_widgets, csv_header, is_filterable, render_err, renders,
};
pub(crate) use write::{apply, authorize, csrf_token, Surface};

use serde_json::Value;
use std::sync::Arc;

/// The stylesheet the components need beyond Bootstrap 5 (about thirty lines, mostly `<dialog>`).
/// Inline it once in your shell: `<style>{{ relativelylight::crud::ui::CSS }}</style>`.
pub const CSS: &str = include_str!("../../../assets/rl.css");

/// A custom cell renderer: `(value, row) -> HTML`, as [`Table::format`] stores it. Its output is
/// inserted **verbatim**, so escape anything that came from the database with [`esc`].
///
/// `pub(crate)`: `format` takes an `impl Fn`, so no public signature names this, and an exported
/// alias nobody can need is API kept forever for nothing.
pub(crate) type Fmt = Arc<dyn Fn(&Value, &Value) -> String + Send + Sync>;

/// Escape a JSON scalar for inclusion in HTML — what a [`Table::format`] closure wraps its values in.
/// A `String` loses its quotes; anything else prints as JSON.
///
/// ```ignore
/// .format("title", |v, row| format!(r#"<a href="/post/{}">{}</a>"#, esc(&row["id"]), esc(v)))
/// ```
pub fn esc(value: &Value) -> String {
    esc_str(&render::text(Some(value)))
}

/// Escape a string for inclusion in HTML text or a quoted attribute.
pub fn esc_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// What a [`submit`](Table::submit) did.
///
/// (`Invalid` makes this 240 bytes where `Done` needs 24. Boxing it would save a one-per-request
/// stack move and cost every caller a `*state` deref in the match arm they write most often — not a
/// trade worth making for a value returned once per HTTP write.)
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

/// A per-row CSS class: `(row) -> class`, as [`Table::row_class`] stores it. `pub(crate)` for the
/// same reason as [`Fmt`].
pub(crate) type RowClass = Arc<dyn Fn(&Value) -> String + Send + Sync>;
