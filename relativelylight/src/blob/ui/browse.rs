//! [`Browser`] — list the documents in a store, search them, open one to see its version chain.
//!
//! The counterpart to registering `blob_handle` in an ordinary CRUD console, and it exists because
//! the generic table cannot do the one thing a document list is *for*: show the current filename.
//! That lives on `blob_version`, and `blob_handle.head_version_id` carries no declared foreign key
//! (the table cycle — see [`entity::handle`](crate::blob::entity::handle)), so `crud` has nothing to
//! join on. [`BlobStore::browse`](crate::blob::BlobStore::browse) follows the pointer instead.
//!
//! **Gated**, unlike [`Viewer`](super::Viewer): this lists everything in the store regardless of who
//! owns it, so rendering it *is* a read and the gate is where the check goes.
//!
//! **It speaks the schema, on purpose.** Columns are `handle`, `seq`, `blob`, not "document" and
//! "file". This is an operator's surface: the person reading it is looking at `blob_handle`,
//! `blob_version` and `blob`, and wants to map what they see onto those tables — a truncated digest
//! in a column is how you notice two documents share content. An *end-user* attachment list wants
//! the opposite vocabulary, and that is what [`Viewer`](super::Viewer) is for.

use std::sync::Arc;

use http::HeaderMap;

use crate::authz::{Authz, Decision, Operation};
use crate::blob::{BlobBackend, BlobStore, BrowseQuery, HandleId, WriteContext};
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
    actions: Option<super::Actions<'a, B>>,
    serving: Option<super::Routes>,
    display: bool,
    /// `{handle}` / `{version}` placeholders, so the component can link to the app's own routes
    /// without inventing any (§2).
    view_url: Option<String>,
}

impl<'a, B: BlobBackend> Browser<'a, B> {
    pub fn new(store: &'a BlobStore<B>, gate: impl Authz + 'static) -> Self {
        Self { store, gate: Arc::new(gate), per_page: 25, title: Some("Blob store".into()), view_url: None, actions: None, serving: None, display: true }
    }

    pub fn per_page(mut self, n: u64) -> Self {
        self.per_page = n.max(1);
        self
    }

    /// The heading above the list. Defaults to `"Blob store"`; pass `""` for none.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Attach the maintenance controls, rendered as a disclosure menu beside the search box.
    ///
    /// Shown **only on the list view** — the controls act on the whole store, so offering them while
    /// a reader is looking at one handle's chain invites the reading that they apply to that handle.
    ///
    /// A `<details>` element, not a Bootstrap dropdown: those need Bootstrap's JavaScript bundle,
    /// and this crate ships none. Same reason `crud::ui` uses `<dialog>` for its editor.
    pub fn actions(mut self, actions: super::Actions<'a, B>) -> Self {
        self.actions = Some(actions.title(""));
        self
    }

    /// Whether a handle's page embeds its current version when the browser can render it.
    ///
    /// `true` by default. It is one document per page, so the cost the argument against previews
    /// usually rests on — a *list* of twenty embedded PDFs — does not apply here; seeing what a
    /// handle actually holds is most of why an operator opened it.
    pub fn display(mut self, on: bool) -> Self {
        self.display = on;
        self
    }

    /// Where content is served — normally the same [`Routes`](super::Routes) the app mounted.
    pub fn routes(mut self, routes: &super::Routes) -> Self {
        self.serving = Some(routes.clone());
        self
    }

    /// A template for linking a version at the app's **own** download route — `{handle}` and
    /// `{version}` are substituted, e.g. `"/invoice/{handle}/v/{version}"`. Use this instead of
    /// [`routes`](Self::routes) when authorization is per-document.
    ///
    /// With neither, the listing names handles without linking to their content: this crate owns no
    /// routes unless you mount some, and a link it invented would 404.
    pub fn view_url(mut self, template: impl Into<String>) -> Self {
        self.view_url = Some(template.into());
        self
    }

    /// Handle a posted control — the whole panel's one write entry point.
    ///
    /// Dispatches on the `op` field: `delete` removes the handle named by `handle`, `check` and
    /// `collect` go to the attached [`Actions`](super::Actions). One handler for the page, rather
    /// than the app having to route each control separately and get the gating right three times.
    ///
    /// The caller checks CSRF before calling (the rendered forms carry the token given to
    /// [`csrf`](super::Actions::csrf)).
    pub async fn submit(
        &self,
        headers: &HeaderMap,
        form: &std::collections::HashMap<String, String>,
        ctx: WriteContext<'_>,
    ) -> Result<super::ActionOutcome, Decision> {
        let op = form.get("op").map(String::as_str).unwrap_or("");
        if op == "delete" {
            // Gated separately from the listing: reading the store is not permission to empty it.
            match self.gate.authorize(Operation::Delete, headers).await {
                Decision::Allow => {}
                other => return Err(other),
            }
            let Some(handle) = form.get("handle").and_then(|h| h.parse::<HandleId>().ok()) else {
                return Ok(super::ActionOutcome {
                    message: "No handle given.".into(),
                    alarming: true,
                });
            };
            return Ok(match self.store.delete_handle(handle, ctx).await {
                Ok(()) => super::ActionOutcome {
                    message: format!(
                        "Handle {handle} and its versions deleted. Its content is freed by the \
                         next collection, unless another handle still holds it."
                    ),
                    alarming: false,
                },
                Err(e) => super::ActionOutcome {
                    message: format!("Delete failed: {e}"),
                    alarming: true,
                },
            });
        }
        match &self.actions {
            Some(a) => a.submit(headers, op, form.contains_key("deep")).await,
            None => Ok(super::ActionOutcome {
                message: format!("Unknown action {op:?}."),
                alarming: true,
            }),
        }
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
            None => Ok(self.render_list(headers, state).await),
        }
    }

    async fn render_list(&self, headers: &HeaderMap, state: &BrowseState) -> String {
        let page = state.page.max(1);
        let q = BrowseQuery {
            search: state.search.as_deref(),
            offset: (page - 1) * self.per_page,
            limit: self.per_page,
        };
        let Ok(found) = self.store.browse(&q).await else {
            return "<div class=\"alert alert-danger\">Could not list the store.</div>".into();
        };

        let mut out = self.heading(None);
        out.push_str(&format!(
            "<form method=\"get\" class=\"mb-3 d-flex gap-2 align-items-start\">\
             <input class=\"form-control\" type=\"search\" name=\"q\" value=\"{}\" \
             placeholder=\"Search filenames…\">\
             <button class=\"btn btn-outline-secondary\" type=\"submit\">Search</button>{}</form>",
            esc_str(state.search.as_deref().unwrap_or("")),
            self.actions_menu(headers).await
        ));

        if found.documents.is_empty() {
            out.push_str("<p class=\"text-body-secondary\">Nothing matches.</p>");
            return out;
        }

        out.push_str(
            "<table class=\"table table-sm align-middle\"><thead><tr>\
             <th>handle</th><th>filename</th><th>type</th><th class=\"text-end\">size</th>\
             <th class=\"text-end\">versions</th><th>last change by</th></tr></thead><tbody>",
        );
        for d in &found.documents {
            let (name, mime, size, by) = match &d.head {
                Some(v) => (
                    esc_str(&v.filename),
                    esc_str(v.content.as_ref().map(|c| c.mime_sniffed.as_str()).unwrap_or("—")),
                    human_size(v.size_bytes()),
                    esc_str(v.created_by.as_deref().unwrap_or("—")),
                ),
                // A handle with no versions is drift, not a row to render blankly.
                None => (
                    "<em class=\"text-danger\">no versions</em>".to_string(),
                    "—".into(),
                    "—".into(),
                    "—".into(),
                ),
            };
            out.push_str(&format!(
                "<tr><td><a href=\"{}\"><code class=\"small\">{}</code></a></td><td>{name}</td>\
                 <td><small>{mime}</small></td><td class=\"text-end\">{size}</td>\
                 <td class=\"text-end\">{}</td><td><small>{by}</small></td></tr>",
                esc_str(&state.href(page, Some(d.handle))),
                esc_str(&d.handle.to_string()),
                d.versions
            ));
        }
        out.push_str("</tbody></table>");
        out.push_str(&self.pager(state, page, found.total));
        out
    }

    async fn render_versions(&self, handle: HandleId, state: &BrowseState) -> String {
        let Ok(chain) = self.store.versions(handle).await else {
            return "<div class=\"alert alert-danger\">No such handle.</div>".into();
        };
        let back = esc_str(&state.href(state.page.max(1), None));

        let mut out = format!(
            "{}<p class=\"mb-3\"><a href=\"{back}\">&larr; all handles</a></p>",
            self.heading(Some(&handle.to_string()))
        );

        // Reuse the viewer for the current version rather than re-implementing a preview.
        if let Some(head) = chain.last() {
            if let Some((view, download)) = self.urls_for(handle, head.id) {
                let mut v = super::Viewer::new(head, view).download_url(download);
                if !self.display {
                    v = v.suppress_preview();
                }
                out.push_str(&format!("<div class=\"mb-3\">{}</div>", v.render()));
            }
        }

        out.push_str(
            "<table class=\"table table-sm align-middle\"><thead><tr>\
             <th>seq</th><th>blob</th><th>filename</th><th>declared type</th>\
             <th class=\"text-end\">size</th><th>created_by</th><th>created_at (UTC)</th>\
             <th></th></tr></thead><tbody>",
        );
        let head_id = chain.last().map(|l| l.id);
        // Newest first: the current version is what a reader is usually looking for.
        for v in chain.iter().rev() {
            let link = match self.urls_for(handle, v.id) {
                Some((view, download)) => format!(
                    "<a href=\"{}\" target=\"_blank\" rel=\"noopener\">open</a> · \
                     <a href=\"{}\" download>download</a>",
                    esc_str(&view),
                    esc_str(&download)
                ),
                None => "—".to_string(),
            };
            out.push_str(&format!(
                "<tr{}><td>{}</td><td><code>{}</code></td><td>{}</td><td><small>{}</small></td>\
                 <td class=\"text-end\">{}</td><td><small>{}</small></td>\
                 <td><small>{}</small></td><td>{link}</td></tr>",
                if Some(v.id) == head_id { " class=\"table-active\"" } else { "" },
                v.seq,
                esc_str(&short_digest(v.blob.as_str())),
                esc_str(&v.filename),
                esc_str(&v.mime_declared),
                human_size(v.size_bytes()),
                esc_str(v.created_by.as_deref().unwrap_or("—")),
                esc_str(&utc(v.created_at)),
            ));
        }
        out.push_str("</tbody></table>");
        out.push_str(&self.delete_control(handle));
        out
    }

    /// Deleting a handle is the **only** way to remove a document, and there is no other route to it
    /// in a console: a plain CRUD delete on `blob_handle` fails with a foreign-key violation once
    /// there are two versions, because the cascade removes them in no order and
    /// `prev_version_id` is `Restrict`.
    ///
    /// Offered on one handle's page rather than the list, so it always names what it will remove.
    fn delete_control(&self, handle: HandleId) -> String {
        let Some(csrf) = self.actions.as_ref().and_then(|a| a.csrf_token()) else {
            // No token means the app has not wired this panel's write path; render nothing rather
            // than a button that will be refused.
            return String::new();
        };
        format!(
            "<form method=\"post\" class=\"mt-3\">\
             <input type=\"hidden\" name=\"_csrf\" value=\"{}\">\
             <input type=\"hidden\" name=\"op\" value=\"delete\">\
             <input type=\"hidden\" name=\"handle\" value=\"{}\">\
             <button class=\"btn btn-sm btn-outline-danger\">Delete this handle and all its versions</button>\
             <div class=\"form-text\">The content is freed by the next collection, unless another \
             handle still holds it.</div></form>",
            esc_str(&csrf),
            esc_str(&handle.to_string())
        )
    }

    /// The maintenance menu, or nothing. A `<details>` disclosure, because a Bootstrap dropdown
    /// would need Bootstrap's JavaScript and this crate ships none.
    async fn actions_menu(&self, headers: &HeaderMap) -> String {
        let Some(actions) = &self.actions else { return String::new() };
        let Ok(controls) = actions.render_for(headers).await else {
            // The gate refused the *actions*, not the listing. Show the list without them rather
            // than failing the page: they are two different permissions.
            return String::new();
        };
        format!(
            "<details class=\"position-relative ms-auto\">\
             <summary class=\"btn btn-outline-secondary\">Maintenance</summary>\
             <div class=\"position-absolute end-0 mt-1 p-3 bg-body border rounded shadow\" \
             style=\"z-index:20;min-width:30rem\">{controls}</div></details>"
        )
    }


    /// `(view, download)` for one version, from whichever the app configured.
    fn urls_for(
        &self,
        handle: HandleId,
        version: crate::blob::VersionId,
    ) -> Option<(String, String)> {
        if let Some(r) = &self.serving {
            return Some((r.view(version), r.download(version)));
        }
        let t = self.view_url.as_ref()?;
        let view = t
            .replace("{handle}", &handle.to_string())
            .replace("{version}", &version.to_string());
        let download = format!("{view}?download=1");
        Some((view, download))
    }

    fn heading(&self, handle: Option<&str>) -> String {
        let Some(t) = self.title.as_deref().filter(|t| !t.is_empty()) else { return String::new() };
        match handle {
            Some(h) => format!(
                "<h1 class=\"h4 mb-1\">{}</h1>\
                 <p class=\"text-body-secondary small mb-2\">handle <code>{}</code></p>",
                esc_str(t),
                esc_str(h)
            ),
            None => format!("<h1 class=\"h4 mb-3\">{}</h1>", esc_str(t)),
        }
    }

    fn pager(&self, state: &BrowseState, page: u64, total: u64) -> String {
        let pages = total.div_ceil(self.per_page).max(1);
        if pages == 1 {
            return format!("<p class=\"text-body-secondary small\">{total} handle(s).</p>");
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

/// First twelve characters of a **digest** — enough to recognise and to spot two versions sharing
/// content, short enough to sit in a column.
///
/// Only for digests, which are uniformly random. A `HandleId` is a UUIDv7, whose leading bits are a
/// *timestamp*: two handles created in the same millisecond share their prefix, so truncating one
/// produces a column where distinct rows look identical. Handles are shown in full.
fn short_digest(id: &str) -> String {
    id.chars().take(12).collect()
}

/// A UTC timestamp an operator can read. The admin surface is deliberately not timezone-aware: an
/// operator comparing this against a log wants the same clock the store writes with.
fn utc(epoch: i64) -> String {
    crate::time::Tz::named("UTC").format(epoch)
}
