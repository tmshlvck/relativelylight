//! `relativelylight::time` — timezone-aware **presentation** of timestamps.
//!
//! The contract across relativelylight is: the database and every API speak **integer Unix seconds,
//! UTC**. Timezones exist only for display, and only in the browser. This module ships the frontend
//! pieces that make that work — it holds no Rust-side time logic and has no dependency on the CRUD
//! engine (a plain, non-`crud` page can use it too):
//!
//! - [`JS`] — a self-contained script exposing `window.RLTime` (UTC / browser-local / named-zone
//!   formatting, an explicit UTC formatter, a "local (UTC)" helper, and DST-correct
//!   `datetime-local` ⇆ Unix-seconds conversion), an Alpine `$store.tz` selection, and the
//!   `rlTzPicker()` component. Include it **once** in your shell, before Alpine.js.
//! - [`TzPicker`] — a Bootstrap dropdown (UTC / browser-local / a curated IANA zone list) bound to
//!   `$store.tz`.
//!
//! [`crud::ui::Table`](crate::crud::ui::Table) datetime columns (fields flagged
//! [`MetaField::datetime`](crate::crud::MetaField::datetime)) follow the `$store.tz` selection when
//! [`JS`] is loaded, and fall back to UTC when it isn't. The app chooses the timezone policy via an
//! optional `window.RL_TZ` global. Full guide: [`docs/TIME.md`](https://github.com/tmshlvck/relativelylight/blob/main/docs/TIME.md).
//!
//! ```ignore
//! // in your shell template, before Alpine:
//! //   <script>window.RL_TZ = { mode: 'utc', persist: 'local', withUtc: true };</script>
//! //   <script>{{ time_js|safe }}</script>          // pass relativelylight::time::JS
//! //   ... and in the navbar:  {{ tz_picker|safe }}  // pass TzPicker::new().render()
//! use relativelylight::time::{JS, TzPicker};
//! let time_js = JS;
//! let tz_picker = TzPicker::new().render();
//! ```

/// The timezone JavaScript (`window.RLTime` + Alpine `$store.tz` + the `rlTzPicker()` component).
/// Include it once in your page shell as a plain (non-deferred) `<script>` **before** Alpine.js, so
/// the store registers in time. It's a static asset, hence a `const`. See the [module docs](self).
pub const JS: &str = include_str!("../assets/rl-time.js");

/// A ready-made Bootstrap timezone-picker dropdown bound to the `$store.tz` selection from [`JS`]:
/// **UTC**, **Local (browser)**, then a curated list of IANA zones covering every UTC offset. Drop
/// its [`render`](TzPicker::render) output into your shell (e.g. the navbar); requires [`JS`] loaded.
///
/// The zone list itself is configured at runtime via `window.RL_TZ.zones`; this component controls
/// only the markup. ```ignore
/// let html = relativelylight::time::TzPicker::new().align_end(true).render();
/// ```
pub struct TzPicker {
    align_end: bool,
}

impl TzPicker {
    /// A picker with the default layout (menu right-aligned under the toggle).
    pub fn new() -> Self {
        Self { align_end: true }
    }

    /// Right-align the dropdown menu under its toggle (`dropdown-menu-end`). Default `true`; set
    /// `false` to left-align (e.g. when the picker sits on the left of the navbar).
    pub fn align_end(mut self, on: bool) -> Self {
        self.align_end = on;
        self
    }

    /// Render the picker as an HTML fragment (Alpine `x-data="rlTzPicker()"`).
    pub fn render(&self) -> String {
        include_str!("../assets/rl-tz-picker.html")
            .replace("%%ALIGN%%", if self.align_end { "dropdown-menu-end" } else { "" })
    }
}

impl Default for TzPicker {
    fn default() -> Self {
        Self::new()
    }
}
