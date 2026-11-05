//! The rendered fragments: [`UploadForm`], [`Preview`], [`Thumbnail`] — FILES.md §3.
//!
//! Bootstrap 5 HTML fragments, never whole pages, like `crud::ui`: the app owns the `<html>`, the
//! stylesheet and the layout — and any listing, which is a table or a grid of its own design with
//! these inside it. They take plain values the app already has (a name, a type, a URL), so they do
//! no I/O and take no gate: the page that renders them is gated, and so are the URLs they point at.
//!
//! **By reference, except text the app hands over.** An image or a PDF is a URL the browser fetches
//! separately; what the browser then does is decided by the response
//! ([`to_inline_response`](super::to_inline_response) keeps its own allowlist). The one branch that
//! writes stored bytes into the page is [`Preview::text`], and only with bytes the app passed in: they
//! are decoded as UTF-8 and **escaped** into a `<pre>`, so `text/html` shows as its source. A hostile
//! content type steers which tag appears and nothing else.

use crate::html::esc;

use super::response::INLINE_SAFE;
use super::sniff::human_size;

/// The most of a text file [`Preview::text`] puts into a page: 5 MiB. Read at most this much
/// (`file.take(TEXT_PREVIEW_MAX)`); a file larger than that shows its beginning and a note.
pub const TEXT_PREVIEW_MAX: u64 = 5 * 1024 * 1024;

/// `text/plain`, `text/csv; charset=utf-8`, `Text/Markdown`, … — any `text/*`.
fn is_text(mime: &str) -> bool {
    let essence = mime.split(';').next().unwrap_or_default().trim();
    essence.len() > 5 && essence[..5].eq_ignore_ascii_case("text/")
}

/// One file shown in full: the image, the PDF, the text, or just its name — with "open" and
/// "download" links.
///
/// `url` serves the content **inline** (an app route ending in
/// [`to_inline_response`](super::to_inline_response)); `mime` is the type the **bytes** say, since it
/// picks the tag and whether "open" is offered.
///
/// ```
/// # use relativelylight::files::Preview;
/// let html = Preview::new("scan.pdf", "application/pdf", "/files/scan.pdf")
///     .size(48_213)
///     .download_url("/files/scan.pdf?download")
///     .render();
/// ```
///
/// A `text/*` file shows in a `<pre>` when the app passes its content with [`text`](Self::text).
pub struct Preview {
    name: String,
    mime: String,
    url: String,
    size: Option<u64>,
    download_url: Option<String>,
    embed: bool,
    text: Option<Vec<u8>>,
}

impl Preview {
    pub fn new(name: impl Into<String>, mime: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mime: mime.into(),
            url: url.into(),
            size: None,
            download_url: None,
            embed: true,
            text: None,
        }
    }

    pub fn size(mut self, bytes: u64) -> Self {
        self.size = Some(bytes);
        self
    }

    /// Where the content is served as an attachment. Without it, no download link is shown.
    pub fn download_url(mut self, url: impl Into<String>) -> Self {
        self.download_url = Some(url.into());
        self
    }

    /// Name, size and links only — no embedded image, PDF or text, whatever the type.
    pub fn links_only(mut self) -> Self {
        self.embed = false;
        self
    }

    /// The content of a `text/*` file, or its beginning, shown in a scrolling `<pre>` — decoded as
    /// UTF-8 (anything else becomes `�`) and escaped. Ignored for any other type.
    ///
    /// Pass the whole file when it fits in [`TEXT_PREVIEW_MAX`], and at most that much otherwise; the
    /// component never shows more. When [`size`](Self::size) says the file is larger than what was
    /// passed, the excerpt ends with a note — "the first 5.0 MiB of 12.3 MiB" — and a download link.
    /// Pass nothing (`&[]`) for a large file to show the note alone:
    ///
    /// ```
    /// # use relativelylight::files::{Preview, TEXT_PREVIEW_MAX};
    /// # let (size, head) = (40 << 20, Vec::<u8>::new());
    /// // `head`: the first TEXT_PREVIEW_MAX bytes, read with `file.take(TEXT_PREVIEW_MAX)`.
    /// let full = Preview::new("notes.txt", "text/plain", "/raw/notes.txt").size(size).text(&head);
    /// let note = Preview::new("dump.log", "text/plain", "/raw/dump.log").size(size).text(&[]);
    /// ```
    ///
    /// The link goes to [`download_url`](Self::download_url), or to `url` without one.
    pub fn text(mut self, content: &[u8]) -> Self {
        let n = content.len().min(TEXT_PREVIEW_MAX as usize);
        self.text = Some(content[..n].to_vec());
        self
    }

    /// The `<pre>` and, when it shows less than the whole file, the note under it.
    fn render_text(&self, bytes: &[u8]) -> String {
        let total = self.size.unwrap_or(0).max(bytes.len() as u64);
        let whole = bytes.len() as u64 == total;
        let link = format!(
            "<a href=\"{}\"{}>download</a>",
            esc(self.download_url.as_deref().unwrap_or(&self.url)),
            if self.download_url.is_some() { " download" } else { "" }
        );
        let note = |text: String| format!("<p class=\"small text-body-secondary mb-0\">{text}</p>");
        if bytes.is_empty() && !whole {
            return note(format!(
                "{} is too large to display here; please {link} it.",
                human_size(total)
            ));
        }
        // An excerpt was cut at an arbitrary byte: drop a character left incomplete at the end
        // rather than show it as `�`.
        let bytes = match std::str::from_utf8(bytes) {
            Err(e) if !whole && e.error_len().is_none() => &bytes[..e.valid_up_to()],
            _ => bytes,
        };
        let pre = format!(
            "<pre class=\"rl-file-text border rounded bg-body-tertiary p-2 mb-1 overflow-auto\" \
             style=\"max-height: 70vh\">{}</pre>",
            esc(&String::from_utf8_lossy(bytes))
        );
        match whole {
            true => pre,
            false => pre + &note(format!(
                "Showing the first {} of {}; {link} the whole file.",
                human_size(bytes.len() as u64),
                human_size(total)
            )),
        }
    }

    pub fn render(&self) -> String {
        let url = esc(&self.url);
        let name = esc(&self.name);
        let preview = match self.mime.as_str() {
            _ if !self.embed => String::new(),
            // `img-fluid` scales a wide image down and leaves a narrow one at its natural size.
            "image/png" | "image/jpeg" | "image/gif" | "image/webp" => format!(
                "<img src=\"{url}\" alt=\"{name}\" class=\"img-fluid rounded border\" loading=\"lazy\">"
            ),
            "application/pdf" => format!(
                "<div class=\"ratio ratio-4x3\"><embed src=\"{url}\" type=\"application/pdf\"></div>"
            ),
            // Only what the app handed over: the component does no I/O.
            m if is_text(m) => self.text.as_deref().map(|t| self.render_text(t)).unwrap_or_default(),
            _ => String::new(),
        };
        let size = self
            .size
            .map(|n| format!(" <small class=\"text-body-secondary\">({})</small>", human_size(n)))
            .unwrap_or_default();
        // **Links for GET.** "open" only for what the response would actually render inline, so a
        // page never offers to open what the browser would download instead.
        let mut links = Vec::new();
        if INLINE_SAFE.contains(&self.mime.as_str()) {
            links.push(format!("<a href=\"{url}\" target=\"_blank\" rel=\"noopener\">open</a>"));
        }
        if let Some(d) = &self.download_url {
            // `download` is a hint; the route's Content-Disposition is what actually decides.
            links.push(format!("<a href=\"{}\" download>download</a>", esc(d)));
        }
        let links = if links.is_empty() {
            String::new()
        } else {
            format!("<span class=\"flex-shrink-0 ms-1\">· {}</span>", links.join(" · "))
        };
        // The name truncates; the links never do — a flex row with a shrinkable name and an
        // unshrinkable tail wraps instead of clipping "download" on a narrow screen.
        format!(
            "<div class=\"rl-file-preview\">{preview}\
             <div class=\"mt-2 d-flex align-items-baseline flex-wrap\">\
             <span class=\"text-truncate\">{name}{size}</span>{links}</div></div>"
        )
    }
}

/// A square tile for one file: its thumbnail image, or — for a file without one — a badge with the
/// file's extension. Links to `href` when given. For a listing the app lays out itself.
///
/// The crate makes no thumbnails: `src` is the app's URL for one (FILES.md §4 and `examples/files`
/// generate them on the fly into a cache). Leave it unset for a type that has none, and the tile shows
/// "PDF", "ZIP", … instead, at the same size, so a mixed grid stays aligned.
///
/// ```
/// # use relativelylight::files::Thumbnail;
/// let tile = Thumbnail::new("photo.jpg").src("/thumb/photo.jpg").href("/view/photo.jpg").render();
/// let badge = Thumbnail::new("scan.pdf").href("/view/scan.pdf").render();
/// ```
pub struct Thumbnail {
    name: String,
    src: Option<String>,
    href: Option<String>,
    px: u32,
}

impl Thumbnail {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), src: None, href: None, px: 64 }
    }

    /// The thumbnail image's URL. Unset, the tile is a badge.
    pub fn src(mut self, url: impl Into<String>) -> Self {
        self.src = Some(url.into());
        self
    }

    /// Where clicking the tile goes — the file's view page, typically.
    pub fn href(mut self, url: impl Into<String>) -> Self {
        self.href = Some(url.into());
        self
    }

    /// The tile's edge in CSS pixels. Default 64. The image is cropped to the square
    /// (`object-fit: cover`), so a thumbnail made at twice this size stays sharp on a phone.
    pub fn px(mut self, px: u32) -> Self {
        self.px = px;
        self
    }

    pub fn render(&self) -> String {
        let px = self.px;
        let name = esc(&self.name);
        let tile = match &self.src {
            Some(src) => format!(
                "<img src=\"{}\" alt=\"{name}\" title=\"{name}\" width=\"{px}\" height=\"{px}\" \
                 loading=\"lazy\" class=\"rounded border\" style=\"object-fit:cover\">",
                esc(src)
            ),
            None => format!(
                "<span title=\"{name}\" class=\"d-inline-flex align-items-center justify-content-center \
                 rounded border bg-body-secondary text-body-secondary small fw-semibold\" \
                 style=\"width:{px}px;height:{px}px\">{}</span>",
                esc(&badge(&self.name))
            ),
        };
        match &self.href {
            Some(href) => {
                format!(
                    "<a href=\"{}\" class=\"rl-file-thumb d-inline-block\">{tile}</a>",
                    esc(href)
                )
            }
            None => format!("<span class=\"rl-file-thumb d-inline-block\">{tile}</span>"),
        }
    }
}

/// "scan.pdf" → "PDF". An extension of one to four letters or digits, else "FILE" — the badge is a
/// label, not a type decision, so the name is a good enough source.
fn badge(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext))
            if !stem.is_empty()
                && (1..=4).contains(&ext.len())
                && ext.bytes().all(|b| b.is_ascii_alphanumeric()) =>
        {
            ext.to_ascii_uppercase()
        }
        _ => "FILE".into(),
    }
}

/// Percent-encode a file name for one URL path segment: everything but the RFC 3986 unreserved
/// characters is escaped, so `/`, `?`, `#` and `%` in a name can't change which route a link hits.
pub fn url_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The upload form — a plain `<form enctype="multipart/form-data">`.
///
/// The hidden `_csrf` input is rendered **first**, and that ordering is load-bearing:
/// [`Upload`](super::Upload) streams the body, so it must validate the token before the app starts
/// writing, which it can only do if the token arrives first. A browser posts parts in document order —
/// which is also why the name field comes before the file inputs.
pub struct UploadForm {
    action: String,
    accept: Option<String>,
    label: String,
    submit: String,
    csrf_token: Option<String>,
    max_bytes: Option<u64>,
    multiple: bool,
    camera: Option<String>,
    name_field: Option<(String, String)>,
    photo: bool,
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
            multiple: false,
            camera: None,
            name_field: None,
            photo: false,
        }
    }

    /// A single **take a photo** button instead of a form: it opens a phone's camera (an image picker
    /// on a desktop) and posts the picture as soon as it is accepted. `label` is the button's text.
    ///
    /// The post is one inline `onchange="this.form.submit()"`; without JavaScript the picture is
    /// taken but not sent. The token still goes first; [`csrf`](Self::csrf) applies, while the
    /// name field, picker, label and submit text don't — the app names the file.
    pub fn photo(action: impl Into<String>, label: impl Into<String>) -> Self {
        Self { photo: true, camera: Some(label.into()), ..Self::new(action) }
    }

    /// The `accept` attribute — a **hint to the file picker**, not enforcement.
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

    /// The token to embed — `auth.csrf().ensure(&headers)` (or your own `Csrf`) when rendering.
    pub fn csrf(mut self, token: impl Into<String>) -> Self {
        self.csrf_token = Some(token.into());
        self
    }

    /// Shown as a size hint. The limit that bites is [`Upload::max_bytes`](super::Upload::max_bytes).
    pub fn max_bytes(mut self, n: u64) -> Self {
        self.max_bytes = Some(n);
        self
    }

    /// Let the picker select several files at once.
    pub fn multiple(mut self) -> Self {
        self.multiple = true;
        self
    }

    /// A second input that opens the **camera** on a phone (`capture="environment"`); on a desktop
    /// it is an ordinary image picker. Posts to the same field as the picker, so the
    /// [`Upload`](super::Upload) needs nothing extra; whichever input is left empty is skipped.
    pub fn camera(mut self, label: impl Into<String>) -> Self {
        self.camera = Some(label.into());
        self
    }

    /// A text field for the name to store the file under — `field` is its form name. Left blank,
    /// the app keeps the uploaded name. It arrives as a [`Part::Field`](super::Part::Field) before the
    /// files.
    pub fn name_field(mut self, field: impl Into<String>, label: impl Into<String>) -> Self {
        self.name_field = Some((field.into(), label.into()));
        self
    }

    pub fn render(&self) -> String {
        let action = esc(&self.action);
        // Several forms on one page must not share input ids: a label would focus the wrong input.
        let id = format!("rl-file-{:x}", {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            self.action.hash(&mut h);
            h.finish()
        });
        // First, deliberately — see the type docs.
        let csrf = self
            .csrf_token
            .as_ref()
            .map(|t| format!("<input type=\"hidden\" name=\"_csrf\" value=\"{}\">", esc(t)))
            .unwrap_or_default();
        if self.photo {
            // A label styled as the button opens the hidden input; `visually-hidden` rather than
            // `hidden`, which some mobile browsers won't open from a label.
            return format!(
                "<form method=\"post\" enctype=\"multipart/form-data\" action=\"{action}\">{csrf}\
                 <label class=\"btn btn-primary\">{}<input class=\"visually-hidden\" type=\"file\" \
                 name=\"file\" accept=\"image/*\" capture=\"environment\" required \
                 onchange=\"this.form.submit()\"></label></form>",
                esc(self.camera.as_deref().unwrap_or_default())
            );
        }
        let name = self
            .name_field
            .as_ref()
            .map(|(field, label)| {
                format!(
                    "<div class=\"mb-2\"><label class=\"form-label\" for=\"{id}-name\">{}</label>\
                     <input class=\"form-control\" type=\"text\" id=\"{id}-name\" name=\"{}\" \
                     placeholder=\"keep the uploaded name\"></div>",
                    esc(label),
                    esc(field)
                )
            })
            .unwrap_or_default();
        let accept =
            self.accept.as_ref().map(|a| format!(" accept=\"{}\"", esc(a))).unwrap_or_default();
        let multiple = if self.multiple { " multiple" } else { "" };
        // With a camera input either one may be the one used, so neither can be `required`.
        let required = if self.camera.is_some() { "" } else { " required" };
        let camera = self
            .camera
            .as_ref()
            .map(|label| {
                format!(
                    "<label class=\"form-label mt-2\" for=\"{id}-camera\">{}</label>\
                     <input class=\"form-control\" type=\"file\" id=\"{id}-camera\" name=\"file\" \
                     accept=\"image/*\" capture=\"environment\">",
                    esc(label)
                )
            })
            .unwrap_or_default();
        let hint = self
            .max_bytes
            .map(|n| format!("<div class=\"form-text\">Up to {} per file.</div>", human_size(n)))
            .unwrap_or_default();
        format!(
            "<form method=\"post\" enctype=\"multipart/form-data\" action=\"{action}\">{csrf}{name}\
             <label class=\"form-label\" for=\"{id}\">{}</label>\
             <input class=\"form-control\" type=\"file\" id=\"{id}\" name=\"file\"{accept}{multiple}{required}>\
             {camera}{hint}\
             <button class=\"btn btn-primary mt-3\" type=\"submit\">{}</button></form>",
            esc(&self.label),
            esc(&self.submit)
        )
    }
}
