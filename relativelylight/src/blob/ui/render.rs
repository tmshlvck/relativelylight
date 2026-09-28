//! The rendered fragments: [`Viewer`], [`UploadForm`], [`Actions`] — BLOBSTORE.md §5.
//!
//! Bootstrap 5 HTML fragments, never whole pages, exactly like `crud::ui`: your app owns the
//! `<html>`, the stylesheet and the layout.
//!
//! **Which of these takes a gate, and why the answer differs** (BLOBSTORE.md §5.1). `Viewer` and
//! `UploadForm` take none: they are formatting functions over data the caller already holds, doing
//! no I/O, rendered inside a page the app has already gated, and posting to a route the app also
//! gates. `Actions` takes one, because it is global and destructive — it sweeps and deletes across
//! every document in the store regardless of who owns them.
//!
//! This diverges from `crud::ui`'s rule that `render_for` *is* the read enforcement point, and the
//! divergence is deliberate rather than an oversight: `Table`/`Form`/`Admin` **query the database
//! while rendering**, so for them rendering is the read and gating it is the only place the check
//! can go. `Viewer` doesn't read anything.

use std::sync::Arc;

use http::HeaderMap;

use crate::authz::{Authz, Decision, Operation};
use crate::blob::{BlobBackend, BlobStore, CheckOptions, VerifyOptions, VersionInfo};
use crate::crud::ui::esc_str;

/// Renders one version for a page — **always by reference, never by value**.
///
/// Every branch emits a URL the browser fetches separately; no branch ever writes stored bytes into
/// the current document. That is the enforcement of BLOBSTORE.md §10's "MIME is advisory, never
/// trusted for dispatch", not merely a description of it: a maliciously-crafted type steers *which
/// tag* appears and nothing else, and what the browser then does is decided by the `Content-Type`
/// the download route sets (see [`to_inline_response`](super::to_inline_response), which keeps its
/// own allowlist).
pub struct Viewer<'a> {
    info: &'a VersionInfo,
    url: String,
    download_url: Option<String>,
    thumbnail_url: Option<String>,
}

impl<'a> Viewer<'a> {
    /// `view_url` is where the content is served **inline** — the `src` of the `<img>`/`<embed>`,
    /// and what the "Open" link points at.
    pub fn new(info: &'a VersionInfo, view_url: impl Into<String>) -> Self {
        Self {
            info,
            url: view_url.into(),
            download_url: None,
            thumbnail_url: None,
        }
    }

    /// Where the content is served as an **attachment**, for the download button.
    ///
    /// A second URL rather than a flag, because the two responses differ in a header this crate
    /// does not get to set — the app owns its routes (§2). In practice it is the same handler with
    /// `?download=1`, answering with [`to_response`](super::to_response) instead of
    /// [`to_inline_response`](super::to_inline_response).
    ///
    /// Without it the download button is omitted rather than pointing somewhere that would render
    /// inline and look like a broken download.
    pub fn download_url(mut self, url: impl Into<String>) -> Self {
        self.download_url = Some(url.into());
        self
    }

    /// A generated variant to show in place of the full image — see
    /// [`Thumbnailer`](crate::blob::Thumbnailer) and `BlobStore::variant`.
    ///
    /// When set, the thumbnail is what renders, wrapped in a link to the full view. A listing of
    /// twenty documents then costs twenty thumbnails rather than twenty full-size images, which is
    /// the entire reason variants exist.
    pub fn thumbnail_url(mut self, url: impl Into<String>) -> Self {
        self.thumbnail_url = Some(url.into());
        self
    }

    /// An HTML fragment. Synchronous — it reads the [`VersionInfo`] it was given and nothing else.
    pub fn render(&self) -> String {
        let url = esc_str(&self.url);
        let name = esc_str(&self.info.filename);

        let mime = self.info.content.as_ref().map(|c| c.mime_sniffed.as_str()).unwrap_or("");
        let size = human_size(self.info.size_bytes());

        // What the browser will actually *render* — which is not the same as what looks like an
        // image. `to_inline_response` serves only an allowlist inline and downgrades everything else
        // to an attachment, so an `<img>` pointing at an SVG is a guaranteed broken-image icon. The
        // two sides agree on purpose: the security decision lives at the response, and the viewer
        // declines to promise something the response will refuse.
        let displayable = matches!(
            mime,
            "image/png" | "image/jpeg" | "image/gif" | "image/webp" | "application/pdf"
        );

        let preview = match (&self.thumbnail_url, mime) {
            // A thumbnail always wins: it is smaller, and clicking through is the full view anyway.
            (Some(t), _) => format!(
                "<a href=\"{url}\" target=\"_blank\" rel=\"noopener\">\
                 <img src=\"{}\" alt=\"{name}\" class=\"rounded border\" loading=\"lazy\"></a>",
                esc_str(t)
            ),
            (None, m) if displayable && m != "application/pdf" => {
                format!("<img src=\"{url}\" alt=\"{name}\" class=\"img-fluid rounded border\" loading=\"lazy\">")
            }
            (None, "application/pdf") => format!(
                "<div class=\"ratio ratio-4x3\"><embed src=\"{url}\" type=\"application/pdf\"></div>"
            ),
            // Anything else has no preview — the filename and the controls below are the whole of it.
            _ => String::new(),
        };

        format!(
            "<div class=\"rl-blob-viewer\">{preview}{}</div>",
            self.controls(&url, &name, &size, displayable)
        )
    }

    /// The row under the preview: what it is, and what you can do with it.
    ///
    /// **Open** is a plain `<a>` with `target="_blank"`, which means the browser's own modifiers
    /// keep working — shift for a new window, ctrl/cmd for a background tab. This crate ships no
    /// JavaScript, so there is nothing to intercept them; that behaviour is free and must not be
    /// taken away by turning the link into a button.
    fn controls(&self, url: &str, name: &str, size: &str, displayable: bool) -> String {
        // The filename is always a link, so content is reachable even with no preview and no
        // download URL — a name with nothing behind it is a dead end, and this crate's whole
        // discipline is that every branch here is a URL the browser fetches separately.
        let mut out = format!(
            "<div class=\"d-flex align-items-center gap-2 flex-wrap mt-2\">\
             <span class=\"me-auto text-truncate\"><a href=\"{url}\">{name}</a> \
             <small class=\"text-body-secondary\">({size})</small></span>"
        );
        if displayable {
            out.push_str(&format!(
                "<a class=\"btn btn-sm btn-outline-secondary\" href=\"{url}\" \
                 target=\"_blank\" rel=\"noopener\">Open</a>"
            ));
        }
        if let Some(d) = &self.download_url {
            // `download` is a hint; the route's Content-Disposition is what actually decides.
            out.push_str(&format!(
                "<a class=\"btn btn-sm btn-primary\" href=\"{}\" download>Download</a>",
                esc_str(d)
            ));
        }
        out.push_str("</div>");
        out
    }
}

/// The upload form — a plain `<form enctype="multipart/form-data">` with a file input.
///
/// The hidden `_csrf` input is rendered **first, before the file input**, and that ordering is
/// load-bearing rather than cosmetic: [`Receiver`](super::Receiver) streams the body straight into
/// the store, so it has to validate the token before it starts writing, which it can only do if the
/// token arrives first. A browser posts parts in document order, so rendering it first is what makes
/// the check possible at all.
pub struct UploadForm {
    action: String,
    accept: Option<String>,
    label: String,
    submit: String,
    csrf_token: Option<String>,
    max_bytes: Option<u64>,
}

impl UploadForm {
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            accept: None,
            label: "File".into(),
            submit: "Upload".into(),
            csrf_token: None,
            max_bytes: None,
        }
    }

    /// The `accept` attribute — a **hint to the file picker**, not enforcement. Anything can still
    /// be posted; check the type server-side if it matters.
    pub fn accept(mut self, patterns: impl Into<String>) -> Self {
        self.accept = Some(patterns.into());
        self
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    pub fn submit(mut self, text: impl Into<String>) -> Self {
        self.submit = text.into();
        self
    }

    /// The token to embed. Get it from `auth.csrf().ensure(&headers)` (or `.token(&headers)`) when
    /// rendering the page.
    pub fn csrf(mut self, token: impl Into<String>) -> Self {
        self.csrf_token = Some(token.into());
        self
    }

    /// Shown to the user as a size hint. Purely informational — the limit that *bites* is
    /// [`BlobStore::max_bytes`](crate::blob::BlobStore::max_bytes), server-side.
    pub fn max_bytes(mut self, n: u64) -> Self {
        self.max_bytes = Some(n);
        self
    }

    pub fn render(&self) -> String {
        let action = esc_str(&self.action);
        let label = esc_str(&self.label);
        let submit = esc_str(&self.submit);
        let accept = self
            .accept
            .as_ref()
            .map(|a| format!(" accept=\"{}\"", esc_str(a)))
            .unwrap_or_default();
        let hint = self
            .max_bytes
            .map(|n| {
                format!(
                    "<div class=\"form-text\">Up to {} per file.</div>",
                    human_size(n as i64)
                )
            })
            .unwrap_or_default();
        // First, deliberately — see the type docs.
        let csrf = self
            .csrf_token
            .as_ref()
            .map(|t| format!("<input type=\"hidden\" name=\"_csrf\" value=\"{}\">", esc_str(t)))
            .unwrap_or_default();

        format!(
            "<form method=\"post\" enctype=\"multipart/form-data\" action=\"{action}\">\
             {csrf}\
             <div class=\"mb-2\"><label class=\"form-label\" for=\"rl-blob-file\">{label}</label>\
             <input class=\"form-control\" type=\"file\" id=\"rl-blob-file\" name=\"file\"{accept} required>\
             {hint}</div>\
             <button class=\"btn btn-primary\" type=\"submit\">{submit}</button>\
             </form>"
        )
    }
}

/// How many blobs a **deep** check re-hashes in one run. See `Actions::submit`.
const DEEP_CHECK_BLOBS: u64 = 500;

/// The store-wide maintenance controls: consistency checking and garbage collection
/// (BLOBSTORE.md §5.3).
///
/// What the generic CRUD console can't express — these aren't row operations and aren't
/// `MetaModel`-shaped. **Gated**, because every button acts across the whole store.
pub struct Actions<'a, B: BlobBackend> {
    store: &'a BlobStore<B>,
    gate: Arc<dyn Authz>,
    csrf_token: Option<String>,
    title: Option<String>,
}

/// What an [`Actions`] button did, for the app to render.
#[derive(Clone, Debug)]
pub struct ActionOutcome {
    pub message: String,
    /// `true` when something was found that wants a human — a missing blob, a corrupt one, a head
    /// pointing at nothing. Render it as a warning rather than a success.
    pub alarming: bool,
}

impl<'a, B: BlobBackend> Actions<'a, B> {
    pub fn new(store: &'a BlobStore<B>, gate: impl Authz + 'static) -> Self {
        Self { store, gate: Arc::new(gate), csrf_token: None, title: Some("Maintenance".into()) }
    }

    pub fn csrf(mut self, token: impl Into<String>) -> Self {
        self.csrf_token = Some(token.into());
        self
    }

    /// The heading above the controls. Defaults to `"Maintenance"`; pass `""` for none.
    ///
    /// Rendered by the component rather than left to the app, so the button labels and the heading
    /// they sit under cannot drift apart — which is how the surface ended up calling itself one
    /// thing while its actions were named another.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    pub(super) fn csrf_token(&self) -> Option<String> {
        self.csrf_token.clone()
    }

    /// Render the buttons, or refuse. `Err(Decision)` is the gate's answer for the caller to map to
    /// `401`/`403` — this is a real enforcement point, not a way to hide buttons.
    pub async fn render_for(&self, headers: &HeaderMap) -> Result<String, Decision> {
        match self.gate.authorize(Operation::List, headers).await {
            Decision::Allow => {}
            other => return Err(other),
        }
        let csrf = self
            .csrf_token
            .as_ref()
            .map(|t| format!("<input type=\"hidden\" name=\"_csrf\" value=\"{}\">", esc_str(t)))
            .unwrap_or_default();

        // Two controls, not three. `check_consistency` and `verify` answer the same question at two
        // depths —
        // "is the stored content still what the index says" — and differ only in cost: one stats
        // each blob, the other re-hashes every byte. That is a checkbox, the way `fsck -c` has
        // always been. Collection stays separate: *is it still wanted* is a different question, and
        // it is the only one that deletes.
        let heading = match self.title.as_deref().filter(|t| !t.is_empty()) {
            Some(t) => format!("<h2 class=\"h6\">{}</h2>", esc_str(t)),
            None => String::new(),
        };
        Ok(format!(
            "<div class=\"rl-blob-actions\">{heading}\
             <form method=\"post\" class=\"mb-3\">{csrf}\
             <input type=\"hidden\" name=\"op\" value=\"check\">\
             <div class=\"d-flex align-items-center gap-2\">\
             <button class=\"btn btn-outline-secondary\" type=\"submit\">Check consistency</button>\
             <div class=\"form-check\">\
             <input class=\"form-check-input\" type=\"checkbox\" id=\"rl-blob-deep\" name=\"deep\" value=\"1\">\
             <label class=\"form-check-label\" for=\"rl-blob-deep\">deep</label></div></div>\
             <div class=\"form-text\">Reconcile the index against storage: content the index expects \
             and cannot find, and stored bytes it has never heard of. <strong>Deep</strong> also \
             re-hashes the least recently checked content to catch silent corruption &mdash; slower, \
             since it reads every byte of what it checks, so it covers a bounded batch per run.\
             </div></form>\
             <form method=\"post\" class=\"mb-3\">{csrf}\
             <input type=\"hidden\" name=\"op\" value=\"collect\">\
             <button class=\"btn btn-outline-danger\" type=\"submit\">Collect garbage</button>\
             <div class=\"form-text\">Delete stored content that no version points at any more. \
             Documents are never touched &mdash; this cannot decide that one is unwanted, only that \
             some bytes are unreachable.</div></form></div>"
        ))
    }

    /// Run one button. `op` is the posted `op` field; `deep` comes from the checkbox. The caller
    /// checks CSRF (or passes the body through the [`csrf::enforce`](crate::csrf::enforce) layer)
    /// before calling.
    pub async fn submit(
        &self,
        headers: &HeaderMap,
        op: &str,
        deep: bool,
    ) -> Result<ActionOutcome, Decision> {
        // Gate on the *write* operation for anything destructive: a caller who may look at the page
        // is not thereby allowed to collect it.
        let needed = if op == "collect" { Operation::Delete } else { Operation::Read };
        match self.gate.authorize(needed, headers).await {
            Decision::Allow => {}
            other => return Err(other),
        }

        let outcome = match op {
            "check" => self.check(deep).await,
            "collect" => match self.store.collect_garbage().await {
                Ok(r) => {
                    let n = r.deleted.len();
                    ActionOutcome {
                        alarming: false,
                        message: format!(
                            "{n} unreferenced blob{} deleted.",
                            if n == 1 { "" } else { "s" }
                        ),
                    }
                }
                Err(e) => ActionOutcome { message: format!("Collection failed: {e}"), alarming: true },
            },
            other => ActionOutcome { message: format!("Unknown action {other:?}."), alarming: true },
        };
        Ok(outcome)
    }

    async fn check(&self, deep: bool) -> ActionOutcome {
        let found = match self.store.check_consistency(CheckOptions::default()).await {
            Ok(r) => r,
            Err(e) => return ActionOutcome { message: format!("Check failed: {e}"), alarming: true },
        };

        let mut parts = Vec::new();
        let mut alarming = !found.missing.is_empty() || !found.dangling_heads.is_empty();

        // The alarming findings first, and only when there are any — a report that leads with four
        // zeroes buries the one number that matters.
        if !found.missing.is_empty() {
            parts.push(format!("{} blob(s) MISSING from storage", found.missing.len()));
        }
        if !found.dangling_heads.is_empty() {
            parts.push(format!(
                "{} document(s) whose current version is missing",
                found.dangling_heads.len()
            ));
        }
        if !found.orphan_handles.is_empty() {
            parts.push(format!("{} document(s) with no versions", found.orphan_handles.len()));
        }
        if !found.orphaned.is_empty() {
            parts.push(format!(
                "{} collectable orphan(s) in storage (harmless: the residue of interrupted uploads)",
                found.orphaned.len()
            ));
        }
        if found.orphans_too_young > 0 {
            parts.push(format!("{} orphan(s) too recent to judge", found.orphans_too_young));
        }

        if deep {
            // Bounded, not exhaustive. `verify` reads **every byte** of what it checks, so an
            // unbounded sweep behind a web button is a request that never returns on a large store.
            // Incremental is also how `verify` is meant to be used: run it repeatedly and it
            // converges on full coverage, oldest-checked first.
            match self.store.verify(VerifyOptions { oldest: Some(DEEP_CHECK_BLOBS) }).await {
                Ok(v) => {
                    if !v.corrupt.is_empty() {
                        alarming = true;
                        parts.push(format!("{} blob(s) CORRUPT", v.corrupt.len()));
                    }
                    parts.push(format!(
                        "{} blob(s) re-hashed (the {} least recently checked)",
                        v.checked, DEEP_CHECK_BLOBS
                    ));
                }
                Err(e) => {
                    alarming = true;
                    parts.push(format!("deep check failed: {e}"));
                }
            }
        }

        let message = if parts.is_empty() {
            "Everything checks out.".to_string()
        } else {
            parts.join("; ") + "."
        };
        ActionOutcome { message, alarming }
    }
}

/// Bytes as something a person reads. Binary units, because that is what a file manager shows.
pub fn human_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut n = bytes as f64;
    let mut i = 0;
    while n >= 1024.0 && i < UNITS.len() - 1 {
        n /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{n:.1} {}", UNITS[i])
    }
}
