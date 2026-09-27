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
use crate::blob::{BlobBackend, BlobStore, FsckOptions, VersionInfo};
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
    tz: Option<&'a crate::time::Tz>,
}

impl<'a> Viewer<'a> {
    pub fn new(info: &'a VersionInfo, download_url: impl Into<String>) -> Self {
        Self { info, url: download_url.into(), tz: None }
    }

    /// Render the erasure date in the caller's zone (`docs/TIME.md`). Without this it is UTC —
    /// correct, just not local. `Tz::from_headers(&headers)` is the usual argument.
    pub fn tz(mut self, tz: &'a crate::time::Tz) -> Self {
        self.tz = Some(tz);
        self
    }

    /// An HTML fragment. Synchronous — it reads the [`VersionInfo`] it was given and nothing else.
    pub fn render(&self) -> String {
        let url = esc_str(&self.url);
        let name = esc_str(&self.info.filename);

        if self.info.is_erased() {
            // The §4.8 case: the record survives its content, and saying so is the point. A blank
            // space here would read as "there was never anything", which is the opposite.
            let utc;
            let zone = match self.tz {
                Some(z) => z,
                None => {
                    utc = crate::time::Tz::named("UTC");
                    &utc
                }
            };
            let when = self
                .info
                .purged_at
                .map(|t| format!(" on {}", esc_str(&zone.format(t))))
                .unwrap_or_default();
            return format!(
                "<div class=\"border rounded p-3 text-body-secondary bg-body-tertiary\">\
                 <strong>{name}</strong><br>\
                 <small>Content was erased{when}. The version record is retained.</small></div>"
            );
        }

        let mime = self.info.content.as_ref().map(|c| c.mime_sniffed.as_str()).unwrap_or("");
        let size = human_size(self.info.size_bytes());

        if mime.starts_with("image/") {
            format!("<img src=\"{url}\" alt=\"{name}\" class=\"img-fluid rounded border\">")
        } else if mime == "application/pdf" {
            format!(
                "<div class=\"ratio ratio-4x3\"><embed src=\"{url}\" type=\"application/pdf\"></div>\
                 <p class=\"mt-2 mb-0\"><a href=\"{url}\">{name}</a> <small class=\"text-body-secondary\">({size})</small></p>"
            )
        } else {
            format!(
                "<a href=\"{url}\">{name}</a> <small class=\"text-body-secondary\">({size})</small>"
            )
        }
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

/// The store-wide maintenance page: `verify`, `fsck`, `purge` (BLOBSTORE.md §5.3).
///
/// What the generic CRUD console can't express — these aren't row operations and aren't
/// `MetaModel`-shaped. **Gated**, because every button acts across the whole store.
pub struct Actions<'a, B: BlobBackend> {
    store: &'a BlobStore<B>,
    gate: Arc<dyn Authz>,
    csrf_token: Option<String>,
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
        Self { store, gate: Arc::new(gate), csrf_token: None }
    }

    pub fn csrf(mut self, token: impl Into<String>) -> Self {
        self.csrf_token = Some(token.into());
        self
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

        let button = |op: &str, label: &str, style: &str, help: &str| {
            format!(
                "<form method=\"post\" class=\"mb-3\">{csrf}\
                 <input type=\"hidden\" name=\"op\" value=\"{op}\">\
                 <button class=\"btn {style}\" type=\"submit\">{label}</button>\
                 <div class=\"form-text\">{help}</div></form>"
            )
        };

        Ok(format!(
            "<div class=\"rl-blob-actions\">{}{}{}</div>",
            button(
                "verify",
                "Verify content",
                "btn-outline-secondary",
                "Re-hash stored content and report anything that no longer matches its digest. \
                 Incremental: the least recently checked first."
            ),
            button(
                "fsck",
                "Check the index",
                "btn-outline-secondary",
                "Reconcile the index against storage. A missing blob is data loss; an orphan is \
                 the normal residue of an interrupted upload and is only reported, never deleted."
            ),
            button(
                "purge",
                "Purge unreferenced content",
                "btn-outline-danger",
                "Delete stored content that no version and no variant points at any more. \
                 Documents are never touched."
            ),
        ))
    }

    /// Run one button. `op` is the posted `op` field; the caller checks CSRF (or passes the token
    /// through the [`csrf::enforce`](crate::csrf::enforce) layer) before calling.
    pub async fn submit(
        &self,
        headers: &HeaderMap,
        op: &str,
    ) -> Result<ActionOutcome, Decision> {
        // Gate on the *write* operation: these change the store, and a caller who may look at the
        // page is not thereby allowed to purge it.
        let needed = if op == "purge" { Operation::Delete } else { Operation::Read };
        match self.gate.authorize(needed, headers).await {
            Decision::Allow => {}
            other => return Err(other),
        }

        let outcome = match op {
            "verify" => match self.store.verify(Default::default()).await {
                Ok(r) => ActionOutcome {
                    alarming: !r.corrupt.is_empty() || !r.missing.is_empty(),
                    message: format!(
                        "Verified {} blobs: {} corrupt, {} missing.",
                        r.checked,
                        r.corrupt.len(),
                        r.missing.len()
                    ),
                },
                Err(e) => ActionOutcome { message: format!("Verify failed: {e}"), alarming: true },
            },
            "fsck" => match self.store.fsck(FsckOptions::default(), None).await {
                Ok(r) => ActionOutcome {
                    alarming: !r.missing.is_empty() || !r.dangling_heads.is_empty(),
                    message: format!(
                        "{} missing, {} orphaned, {} too recent to judge, {} empty documents, \
                         {} broken current-version pointers.",
                        r.missing.len(),
                        r.orphaned.len(),
                        r.orphans_too_young,
                        r.orphan_handles.len(),
                        r.dangling_heads.len()
                    ),
                },
                Err(e) => ActionOutcome { message: format!("Check failed: {e}"), alarming: true },
            },
            "purge" => match self.store.purge(None).await {
                Ok(r) => ActionOutcome {
                    alarming: false,
                    message: {
                        let n = r.content_deleted.len();
                        format!("{n} unreferenced blob{} deleted.", if n == 1 { "" } else { "s" })
                    },
                },
                Err(e) => ActionOutcome { message: format!("Purge failed: {e}"), alarming: true },
            },
            other => ActionOutcome { message: format!("Unknown action {other:?}."), alarming: true },
        };
        Ok(outcome)
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
