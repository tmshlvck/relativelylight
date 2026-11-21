//! A field's display formatters: [`MetaField::format_cell`](super::seaorm::MetaField::format_cell)
//! and [`format_view`](super::seaorm::MetaField::format_view), what each is handed ([`FmtCtx`]), and
//! the helpers they are written with ([`esc`], [`esc_str`], [`truncate`]).
//!
//! **A formatter's output is HTML, inserted into the page verbatim.** That is what it is for — a
//! link, a badge, a `<pre>` — and it is also the one way this crate's pages can carry a script an
//! attacker stored: every value a formatter takes from the row goes through [`esc`] (or
//! [`esc_str`]) before it reaches the string it returns. A formatter that writes
//! `format!("<b>{}</b>", ctx.value())` is a stored XSS.
//!
//! ```ignore
//! use relativelylight::crud::fmt::{esc, truncate};
//!
//! workorder.field("number").format_view(|cx| format!(
//!     r#"<a href="/work-orders/{}" target="_top">{}</a> →"#,
//!     esc(&cx.row()["id"]), esc(cx.value()),
//! ));
//! post.field("body").format_cell(truncate(60));
//! ```

use http::HeaderMap;
use serde_json::Value;
use std::sync::Arc;

/// What a formatter is handed: the value, its row, and the request it renders for.
/// **`#[non_exhaustive]`** — a member may be added without breaking a closure.
#[non_exhaustive]
pub struct FmtCtx<'a> {
    value: &'a Value,
    row: &'a Value,
    headers: &'a HeaderMap,
}

impl<'a> FmtCtx<'a> {
    /// For an app that renders a row itself and calls a [`Fmt`] the model carries
    /// (`Column::Field::format_view`).
    pub fn new(value: &'a Value, row: &'a Value, headers: &'a HeaderMap) -> Self {
        Self { value, row, headers }
    }
    /// The field's value as every read returns it (after `on_read`); `null` when absent.
    pub fn value(&self) -> &'a Value {
        self.value
    }
    /// The whole row, as read: `row()["id"]` is the key a link needs while the formatter shows
    /// another column. A relation is `{id, label}` (a to-many, a list of them).
    pub fn row(&self) -> &'a Value {
        self.row
    }
    /// The request's headers, for what depends on the viewer — the timezone first:
    /// `Tz::from_headers(cx.headers())`.
    pub fn headers(&self) -> &'a HeaderMap {
        self.headers
    }
}

/// A display formatter, `(&FmtCtx) -> HTML`, as [`MetaField`](super::seaorm::MetaField) stores it
/// and [`Column::Field`](super::Column::Field) reports it. Its output is inserted **verbatim**.
#[derive(Clone)]
pub struct Fmt(Arc<dyn Fn(&FmtCtx) -> String + Send + Sync>);

impl Fmt {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(&FmtCtx) -> String + Send + Sync + 'static,
    {
        Self(Arc::new(f))
    }
    /// Run it. The result is HTML: insert it as is.
    pub fn call(&self, cx: &FmtCtx) -> String {
        (self.0)(cx)
    }
}

impl std::fmt::Debug for Fmt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fmt(..)")
    }
}

/// A stored scalar as text: `null` is blank rather than "null", a string loses its quotes,
/// anything else prints as JSON.
pub(crate) fn text(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// Escape a JSON scalar for HTML text or a quoted attribute — what a formatter wraps every value
/// in. A `String` loses its quotes, `null` is blank, anything else prints as JSON.
pub fn esc(value: &Value) -> String {
    esc_str(&text(Some(value)))
}

/// Escape a string for HTML text or a quoted attribute.
pub fn esc_str(s: &str) -> String {
    crate::html::esc(s)
}

/// A ready-made formatter that shortens a value to its first `chars` characters plus `…`, with the
/// whole of it in the `title` tooltip — for [`format_cell`](super::seaorm::MetaField::format_cell),
/// so a listing shows a corner of a long text and the View dialog all of it. Escapes the value; a
/// value that fits is shown as is.
///
/// ```ignore
/// post.field("body").format_cell(truncate(60));
/// ```
pub fn truncate(chars: usize) -> impl Fn(&FmtCtx) -> String + Clone + Send + Sync + 'static {
    move |cx| {
        let s = text(Some(cx.value()));
        match s.char_indices().nth(chars) {
            None => esc_str(&s),
            Some((cut, _)) => {
                format!(r#"<span title="{}">{}…</span>"#, esc_str(&s), esc_str(s[..cut].trim_end()))
            }
        }
    }
}
