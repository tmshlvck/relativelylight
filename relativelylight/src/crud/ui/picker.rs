//! [`Picker`] — the page inside the dialog that edits a relation too large for a `<select>`.

use super::state::ViewState;
use super::{render, Table};
use crate::crud::engine::{Cardinality, Column, Engine, Error, Result};
use http::HeaderMap;

/// The target's own table, with a radio (to-one) or a checkbox (to-many) per row — what a relation
/// field opens when its target has more rows than `picker_threshold`.
///
/// The crate adds no route: serve this from one `GET` handler of your own, on the path you gave
/// `Crud::picker_path`, wrapped in a **bare** shell (no navigation; Bootstrap and [`CSS`](super::CSS)).
/// The page that opened the dialog reads its inputs directly, so this page needs no script.
///
/// ```ignore
/// // .route("/pick", get(pick))
/// async fn pick(State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri) -> Response {
///     let state = ViewState::from_uri(&uri);
///     match Picker::new(&app.engine).render_for(&headers, &state).await {
///         Ok(html) => Html(bare_shell(&html)).into_response(),
///         Err(e) => e.into_response(),
///     }
/// }
/// ```
///
/// The URL names the **relation** (`?pick=post.tag`), never the target, so only a real relation
/// can be browsed, and the rows are a `Table` render of the target: refused (`401`/`403`) when the
/// caller may not list it, whatever they may do to the source.
pub struct Picker<'a> {
    engine: &'a Engine,
    per_page: u64,
}

impl<'a> Picker<'a> {
    pub fn new(engine: &'a Engine) -> Self {
        Self { engine, per_page: 10 }
    }

    /// Rows per page in the dialog. Default 10.
    pub fn per_page(mut self, n: u64) -> Self {
        self.per_page = n.max(1);
        self
    }

    /// Render the picker for the relation `?pick=` names. `400` if it names none, or no relation
    /// of that entity.
    pub async fn render_for(&self, headers: &HeaderMap, state: &ViewState) -> Result<String> {
        let Some((slug, relation)) = &state.pick else {
            return Err(Error::BadRequest("crud::ui::Picker: no ?pick=<entity>.<relation>".into()));
        };
        let cols = self.engine.columns(slug)?;
        let found = cols.iter().find(|c| render::name_of(c) == relation);
        let Some(Column::Relation { target, cardinality, .. }) = found else {
            return Err(Error::BadRequest(format!(
                "crud::ui::Picker: {slug} has no relation '{relation}'"
            )));
        };
        Table::new(self.engine, target.clone())
            .per_page(self.per_page)
            .render_pick(headers, state, *cardinality == Cardinality::ToMany)
            .await
    }
}
