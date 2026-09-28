//! [`Browser`] — list the documents in a store, search them, open one to see its version chain.
//!
//! The counterpart to registering `blob_handle` in an ordinary CRUD console, and it exists because
//! the generic table cannot do the one thing a document list is *for*: show the current filename.
//! That lives on `blob_version`, and `blob_handle.head_version_id` carries no declared foreign key
//! (the table cycle — see [`entity::handle`](crate::blob::entity::handle)), so `crud` has nothing to
//! join on. [`BlobStore::browse`](crate::blob::BlobStore::browse) follows the pointer instead.
//!
//! **Gated**, unlike [`Viewer`](super::Viewer): this lists every document in the store regardless of
//! who owns them, so rendering it *is* a read and the gate is where the check goes.

use std::sync::Arc;

use http::HeaderMap;

use crate::authz::{Authz, Decision, Operation};
use crate::blob::{BlobBackend, BlobStore, BrowseQuery, HandleId};
use crate::crud::ui::esc_str;

use super::render::human_size;

/// Where the browser is, read out of the query string — the URL is the state, as everywhere else in
/// this crate, so every view is a link and the component needs no route of its own.
#[derive(Clone, Debug, Default)]
pub struct BrowseState {
    pub search: Option<String>,
    pub page: u64,
    /// The document whose versions are open, if any.
    pub open: Option<HandleId>,
}

impl BrowseState {
    /// Parse `?q=…&page=…&open=…` off a request URI.
    pub fn from_uri(uri: &http::Uri) -> Self {
        let mut out = BrowseState { page: 1, ..Default::default() };
        for (k, v) in form_pairs(uri.query().unwrap_or("")) {
            match k.as_str() {
                "q" => out.search = Some(v),
                "page" => out.page = v.parse().unwrap_or(1).max(1),
                "open" => out.open = v.parse().ok(),
                _ => {}
            }
        }
        out
    }

    fn href(&self, page: u64, open: Option<HandleId>) -> String {
        let mut parts = Vec::new();
        if let Some(q) = self.search.as_deref().filter(|q| !q.is_empty()) {
            parts.push(format!("q={}", urlencode(q)));
        }
        if page > 1 {
            parts.push(format!("page={page}"));
        }
        if let Some(h) = open {
            parts.push(format!("open={h}"));
        }
        if parts.is_empty() { "?".into() } else { format!("?{}", parts.join("&")) }
    }
}

fn form_pairs(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((urldecode(k), urldecode(v)))
        })
        .collect()
}

fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A searchable list of documents, drilling into one document's version chain.
pub struct Browser<'a, B: BlobBackend> {
    store: &'a BlobStore<B>,
    gate: Arc<dyn Authz>,
    per_page: u64,
    title: Option<String>,
    /// `{handle}` / `{version}` placeholders, so the component can link to the app's own routes
    /// without inventing any (§2).
    view_url: Option<String>,
}

impl<'a, B: BlobBackend> Browser<'a, B> {
    pub fn new(store: &'a BlobStore<B>, gate: impl Authz + 'static) -> Self {
        Self { store, gate: Arc::new(gate), per_page: 25, title: Some("Documents".into()), view_url: None }
    }

    pub fn per_page(mut self, n: u64) -> Self {
        self.per_page = n.max(1);
        self
    }

    /// The heading above the list. Defaults to `"Documents"`; pass `""` for none.
    ///
    /// **"Documents", not "Files" or "Blobs"** — a handle *is* a document, and that is the word this
    /// module uses for it throughout. "Blob" is implementation vocabulary (so is "row"), and "files"
    /// invites the assumption that one upload is one thing, which the version chain is precisely a
    /// denial of.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// A template for linking a version at the app's own download route — `{handle}` and
    /// `{version}` are substituted, e.g. `"/files/{handle}/v/{version}"`.
    ///
    /// Omit it and the listing names documents without linking to their content: this crate owns no
    /// routes, and a link it invented would 404.
    pub fn view_url(mut self, template: impl Into<String>) -> Self {
        self.view_url = Some(template.into());
        self
    }

    /// Render the list, or one document's versions. `Err(Decision)` is the gate's answer.
    pub async fn render_for(
        &self,
        headers: &HeaderMap,
        state: &BrowseState,
    ) -> Result<String, Decision> {
        match self.gate.authorize(Operation::List, headers).await {
            Decision::Allow => {}
            other => return Err(other),
        }
        match state.open {
            Some(h) => Ok(self.render_versions(h, state).await),
            None => Ok(self.render_list(state).await),
        }
    }

    async fn render_list(&self, state: &BrowseState) -> String {
        let page = state.page.max(1);
        let q = BrowseQuery {
            search: state.search.as_deref(),
            offset: (page - 1) * self.per_page,
            limit: self.per_page,
        };
        let Ok(found) = self.store.browse(&q).await else {
            return "<div class=\"alert alert-danger\">Could not list documents.</div>".into();
        };

        let term = state.search.as_deref().unwrap_or("");
        let mut out = self.heading();
        out.push_str(&format!(
            "<form method=\"get\" class=\"mb-3 d-flex gap-2\">\
             <input class=\"form-control\" type=\"search\" name=\"q\" value=\"{}\" \
             placeholder=\"Search filenames…\">\
             <button class=\"btn btn-outline-secondary\" type=\"submit\">Search</button></form>",
            esc_str(term)
        ));

        if found.documents.is_empty() {
            out.push_str(
                "<p class=\"text-body-secondary\">No documents match.</p>",
            );
            return out;
        }

        out.push_str(
            "<table class=\"table table-sm align-middle\"><thead><tr>\
             <th>Document</th><th>Type</th><th class=\"text-end\">Size</th>\
             <th class=\"text-end\">Versions</th><th>Last change by</th></tr></thead><tbody>",
        );
        for d in &found.documents {
            let (name, mime, size, by) = match &d.head {
                Some(v) => (
                    esc_str(&v.filename),
                    esc_str(v.content.as_ref().map(|c| c.mime_sniffed.as_str()).unwrap_or("—")),
                    human_size(v.size_bytes()),
                    esc_str(v.created_by.as_deref().unwrap_or("—")),
                ),
                // A handle with no versions is drift, not a document. Say so rather than showing a
                // blank row that looks like a rendering bug.
                None => (
                    "<em class=\"text-danger\">no versions</em>".to_string(),
                    "—".into(),
                    "—".into(),
                    "—".into(),
                ),
            };
            out.push_str(&format!(
                "<tr><td><a href=\"{}\">{name}</a></td><td><small>{mime}</small></td>\
                 <td class=\"text-end\">{size}</td><td class=\"text-end\">{}</td>\
                 <td><small>{by}</small></td></tr>",
                esc_str(&state.href(page, Some(d.handle))),
                d.versions
            ));
        }
        out.push_str("</tbody></table>");
        out.push_str(&self.pager(state, page, found.total));
        out
    }

    async fn render_versions(&self, handle: HandleId, state: &BrowseState) -> String {
        let Ok(chain) = self.store.versions(handle).await else {
            return "<div class=\"alert alert-danger\">No such document.</div>".into();
        };
        let back = esc_str(&state.href(state.page.max(1), None));
        let title = chain
            .last()
            .map(|v| esc_str(&v.filename))
            .unwrap_or_else(|| "(no versions)".into());

        let mut out = format!(
            "{}<p class=\"mb-2\"><a href=\"{back}\">&larr; all documents</a></p>\
             <h2 class=\"h5\">{title}</h2>\
             <p class=\"text-body-secondary small\">Document {handle}</p>\
             <table class=\"table table-sm align-middle\"><thead><tr>\
             <th>#</th><th>Filename</th><th class=\"text-end\">Size</th><th>By</th>\
             <th>Content</th></tr></thead><tbody>",
            self.heading()
        );
        // Newest first: the current version is what a reader is usually looking for.
        for v in chain.iter().rev() {
            let link = match &self.view_url {
                Some(t) => {
                    let url = t
                        .replace("{handle}", &handle.to_string())
                        .replace("{version}", &v.id.to_string());
                    format!("<a href=\"{}\" target=\"_blank\" rel=\"noopener\">open</a>", esc_str(&url))
                }
                None => "—".to_string(),
            };
            out.push_str(&format!(
                "<tr{}><td>{}</td><td>{}</td><td class=\"text-end\">{}</td><td><small>{}</small></td>\
                 <td>{link}</td></tr>",
                if v.id == chain.last().map(|l| l.id).unwrap_or(v.id) {
                    " class=\"table-active\""
                } else {
                    ""
                },
                v.seq,
                esc_str(&v.filename),
                human_size(v.size_bytes()),
                esc_str(v.created_by.as_deref().unwrap_or("—")),
            ));
        }
        out.push_str("</tbody></table>");
        out
    }

    fn heading(&self) -> String {
        match self.title.as_deref().filter(|t| !t.is_empty()) {
            Some(t) => format!("<h1 class=\"h4 mb-3\">{}</h1>", esc_str(t)),
            None => String::new(),
        }
    }

    fn pager(&self, state: &BrowseState, page: u64, total: u64) -> String {
        let pages = total.div_ceil(self.per_page).max(1);
        if pages == 1 {
            return format!("<p class=\"text-body-secondary small\">{total} document(s).</p>");
        }
        let mut out = String::from("<nav><ul class=\"pagination pagination-sm\">");
        for p in 1..=pages {
            let active = if p == page { " active" } else { "" };
            out.push_str(&format!(
                "<li class=\"page-item{active}\"><a class=\"page-link\" href=\"{}\">{p}</a></li>",
                esc_str(&state.href(p, None))
            ));
        }
        out.push_str("</ul></nav>");
        out
    }
}
