//! [`Portal`] — one document, everything you can do with it.
//!
//! The component an app puts on a page that *has* an attachment: show the current version, open it,
//! download it, optionally list every version, optionally upload a new one.
//!
//! **One component, not two.** A "current version only" view and a "with history" view differ by a
//! table, so they are [`versions(bool)`](Portal::versions) rather than two types that would have to
//! be kept looking alike by hand.
//!
//! ```no_run
//! # use relativelylight::blob::{BlobStore, HandleId};
//! # use relativelylight::blob::ui::{Portal, Routes};
//! # use relativelylight::authz::Open;
//! # async fn f(store: &BlobStore, handle: HandleId, headers: &http::HeaderMap) {
//! let routes = Routes::new("/blob");
//! let html = Portal::new(store, handle, Open)
//!     .routes(&routes)          // where content is served
//!     .versions(true)           // …and its history
//!     .upload("/doc/7/replace") // …and a form to add the next one
//!     .render_for(headers)
//!     .await;
//! # }
//! ```

use std::sync::Arc;

use http::HeaderMap;

use crate::authz::{Authz, Decision, Operation};
use crate::blob::{BlobBackend, BlobStore, HandleId, VersionInfo};
use crate::crud::ui::esc_str;

use super::render::human_size;
use super::{Routes, UploadForm, Viewer};

/// One document: its current version, optionally its history, optionally a way to add to it.
pub struct Portal<'a, B: BlobBackend> {
    store: &'a BlobStore<B>,
    handle: HandleId,
    gate: Arc<dyn Authz>,
    routes: Option<&'a Routes>,
    view_url: Option<String>,
    versions: bool,
    display: bool,
    upload: Option<UploadForm>,
    title: Option<String>,
}

impl<'a, B: BlobBackend> Portal<'a, B> {
    pub fn new(store: &'a BlobStore<B>, handle: HandleId, gate: impl Authz + 'static) -> Self {
        Self {
            store,
            handle,
            gate: Arc::new(gate),
            routes: None,
            view_url: None,
            versions: false,
            display: true,
            upload: None,
            title: None,
        }
    }

    /// Where content is served. Without it the portal names the document but links to nothing —
    /// this crate owns no routes unless you mount [`Routes`].
    ///
    /// For per-document authorization, don't mount `Routes`: use [`view_url`](Self::view_url).
    pub fn routes(mut self, routes: &'a Routes) -> Self {
        self.routes = Some(routes);
        self
    }

    /// A template for the app's **own** content route — `{version}` is substituted, e.g.
    /// `"/invoice/42/attachment/{version}"`. The download URL is the same with `?download=1`.
    ///
    /// This is the per-document case, and the one BLOBSTORE.md §9.2 recommends: the route names the
    /// owning record, so authorization is a gated query on it and a handle never appears in a URL.
    pub fn view_url(mut self, template: impl Into<String>) -> Self {
        self.view_url = Some(template.into());
        self
    }

    /// Show the version history under the current version. `false` (the default) is the
    /// "this is the attachment" view; `true` adds the table with open/download per version.
    pub fn versions(mut self, on: bool) -> Self {
        self.versions = on;
        self
    }

    /// Whether to *embed* content the browser can render — an `<img>` or an `<embed>`.
    ///
    /// `true` by default, which is what an app page wants. An admin listing usually wants `false`:
    /// the operator is auditing what is stored, not reading it, and twenty embedded PDFs make a
    /// page that takes a minute to load.
    pub fn display(mut self, on: bool) -> Self {
        self.display = on;
        self
    }

    /// Offer an upload that becomes the **next version** of this document.
    ///
    /// `action` is your own POST route, which should call
    /// [`Receiver::as_version_of`](super::Receiver::as_version_of) with this handle. Creating a
    /// *new* document is a different act with a different target, so it is a standalone
    /// [`UploadForm`](super::UploadForm) on the app's own page rather than something offered here.
    pub fn upload(mut self, action: impl Into<String>) -> Self {
        self.upload = Some(UploadForm::new(action).as_new_version());
        self
    }

    /// Replace the upload form with one you configured yourself (CSRF token, `accept`, labels).
    pub fn upload_form(mut self, form: UploadForm) -> Self {
        self.upload = Some(form);
        self
    }

    /// A heading above it all. None by default — the page usually has its own.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Render, or refuse. `Err(Decision)` is the gate's answer, for the caller to map to
    /// `401`/`403`.
    ///
    /// Gated because it **reads the store**: it fetches the version chain, so rendering is the read
    /// and this is where the check goes. (Contrast [`Viewer`](super::Viewer), which is handed a
    /// `VersionInfo` the caller already holds and does no I/O.)
    pub async fn render_for(&self, headers: &HeaderMap) -> Result<String, Decision> {
        match self.gate.authorize(Operation::Read, headers).await {
            Decision::Allow => {}
            other => return Err(other),
        }

        let Ok(chain) = self.store.versions(self.handle).await else {
            return Ok("<div class=\"alert alert-danger\">No such document.</div>".into());
        };
        let Some(head) = chain.last() else {
            return Ok("<div class=\"alert alert-warning\">This document has no versions.</div>"
                .into());
        };

        let mut out = match self.title.as_deref().filter(|t| !t.is_empty()) {
            Some(t) => format!("<h2 class=\"h6\">{}</h2>", esc_str(t)),
            None => String::new(),
        };
        out.push_str(&self.current(head));
        if self.versions {
            out.push_str(&self.history(&chain));
        }
        if let Some(form) = &self.upload {
            out.push_str(&format!("<div class=\"mt-3\">{}</div>", form.render()));
        }
        Ok(out)
    }

    /// The current version, through [`Viewer`] — so a portal and a bare viewer cannot drift apart
    /// in how they present the same thing.
    fn current(&self, head: &VersionInfo) -> String {
        let Some((view, download)) = self.urls_for(head.id) else {
            return format!(
                "<p class=\"text-body-secondary\">{} <small>({})</small></p>",
                esc_str(&head.filename),
                human_size(head.size_bytes())
            );
        };
        let mut v = Viewer::new(head, view).download_url(download);
        if !self.display {
            v = v.suppress_preview();
        }
        v.render()
    }

    /// `(view, download)` from whichever the caller configured — the mounted router, or the app's
    /// own route.
    fn urls_for(&self, version: crate::blob::VersionId) -> Option<(String, String)> {
        if let Some(r) = self.routes {
            return Some((r.view(version), r.download(version)));
        }
        let view = self.view_url.as_ref()?.replace("{version}", &version.to_string());
        let download = format!("{view}?download=1");
        Some((view, download))
    }

    /// The history: newest first, each row openable and downloadable.
    ///
    /// A `<details>` so it is out of the way on a page whose subject is the document, not its
    /// history — and so it needs no JavaScript, like everything else here.
    fn history(&self, chain: &[VersionInfo]) -> String {
        let mut rows = String::new();
        let head_id = chain.last().map(|v| v.id);
        for v in chain.iter().rev() {
            let links = match self.urls_for(v.id) {
                Some((view, download)) => format!(
                    "<a href=\"{}\" target=\"_blank\" rel=\"noopener\">open</a> · \
                     <a href=\"{}\" download>download</a>",
                    esc_str(&view),
                    esc_str(&download)
                ),
                None => "—".to_string(),
            };
            rows.push_str(&format!(
                "<tr{}><td>{}</td><td>{}</td><td class=\"text-end pe-4\">{}</td>\
                 <td><small>{}</small></td><td>{links}</td></tr>",
                if Some(v.id) == head_id { " class=\"table-active\"" } else { "" },
                v.seq,
                esc_str(&v.filename),
                human_size(v.size_bytes()),
                esc_str(v.created_by.as_deref().unwrap_or("—")),
            ));
        }
        format!(
            "<details class=\"mt-3\"><summary class=\"small\">{} version(s)</summary>\
             <table class=\"table table-sm align-middle mt-2\"><thead><tr>\
             <th>seq</th><th>filename</th><th class=\"text-end pe-4\">size</th>\
             <th>created by</th><th></th>\
             </tr></thead><tbody>{rows}</tbody></table></details>",
            chain.len()
        )
    }
}
