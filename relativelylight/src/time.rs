//! `relativelylight::time` — timezone-aware **presentation** of timestamps (feature `tz`).
//!
//! The contract across relativelylight is: the database speaks **integer Unix seconds, UTC**.
//! Timezones exist only for display — but the *formatting happens on the server*, which is what lets a
//! CSV export match what is on screen and a `<datetime-local>` input round-trip through the zone the
//! operator is actually working in.
//!
//! The selection rides in a cookie ([`COOKIE`](crate::time::COOKIE)), so every render of every page agrees about it:
//!
//! - [`Tz`](crate::time::Tz) — the zone for one request, read from the caller's headers ([`Tz::from_headers`](crate::time::Tz::from_headers)), used to
//!   [`format`](crate::time::Tz::format) an epoch for a cell and to [`parse`](crate::time::Tz::parse) a form input back.
//! - [`TzPicker`](crate::time::TzPicker) — a plain `<form>` of zones; posting it sets the cookie. No JavaScript, no store.
//!
//! An unknown or unset zone is **UTC**, and so is a zone the host's tz database doesn't have: a
//! timestamp shown in the wrong zone is worse than one labelled UTC.
//!
//! ```ignore
//! let tz = relativelylight::time::Tz::from_headers(&headers);   // in a page handler
//! let picker = relativelylight::time::TzPicker::new().render(&tz);  // drop into your navbar
//! ```
//!
//! Full guide: [`docs/TIME.md`](https://github.com/tmshlvck/relativelylight/blob/main/docs/TIME.md).

use jiff::civil;
use jiff::tz::TimeZone;
use jiff::Timestamp;

/// The cookie carrying the selected IANA zone name (empty or absent = UTC).
pub const COOKIE: &str = "rl_tz";

/// The zone one request renders in. Cheap to clone and pass down.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Tz(Option<String>);

impl Tz {
    /// UTC — the default, and the fallback for anything unrecognised.
    pub const UTC: Tz = Tz(None);

    /// A named IANA zone (`"Europe/Prague"`). Falls back to UTC if the host has no such zone, so this
    /// never fails and never renders a wrong time.
    pub fn named(zone: &str) -> Tz {
        match TimeZone::get(zone) {
            Ok(_) => Tz(Some(zone.to_string())),
            Err(_) => Tz::UTC,
        }
    }

    /// Whether the host's tz database knows this name — what [`TzPicker::zones`] screens a
    /// configured list with. `"UTC"` is always known.
    pub fn known(zone: &str) -> bool {
        zone == "UTC" || TimeZone::get(zone).is_ok()
    }

    /// The zone this request asked for, from the [`COOKIE`] cookie.
    pub fn from_headers(headers: &http::HeaderMap) -> Tz {
        let Some(cookies) = headers.get(http::header::COOKIE).and_then(|v| v.to_str().ok()) else {
            return Tz::UTC;
        };
        cookies
            .split(';')
            .filter_map(|c| c.trim().split_once('='))
            .find(|(k, _)| *k == COOKIE)
            .map(|(_, v)| Tz::named(&crate::urlform::decode(v)))
            .unwrap_or(Tz::UTC)
    }

    /// The zone's name, as shown to the user and stored in the cookie.
    pub fn name(&self) -> &str {
        self.0.as_deref().unwrap_or("UTC")
    }

    fn zone(&self) -> TimeZone {
        match &self.0 {
            Some(name) => TimeZone::get(name).unwrap_or(TimeZone::UTC),
            None => TimeZone::UTC,
        }
    }

    /// Unix seconds → `YYYY-MM-DD HH:MM` in this zone, for a table cell. Out-of-range input renders
    /// as the raw number rather than a panic or a silently wrong date.
    pub fn format(&self, epoch: i64) -> String {
        match self.civil(epoch) {
            Some(dt) => format!(
                "{:04}-{:02}-{:02} {:02}:{:02}",
                dt.year(),
                dt.month(),
                dt.day(),
                dt.hour(),
                dt.minute()
            ),
            None => epoch.to_string(),
        }
    }

    /// Unix seconds → the `YYYY-MM-DDTHH:MM` an `<input type="datetime-local">` wants.
    pub fn format_input(&self, epoch: i64) -> String {
        match self.civil(epoch) {
            Some(dt) => format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}",
                dt.year(),
                dt.month(),
                dt.day(),
                dt.hour(),
                dt.minute()
            ),
            None => String::new(),
        }
    }

    /// What an `<input type="datetime-local">` posted (`YYYY-MM-DDTHH:MM[:SS]`) → Unix seconds,
    /// interpreting the wall-clock reading **in this zone**. `None` if it isn't a datetime.
    ///
    /// DST is the reason this is the server's job: 02:30 on a spring-forward night doesn't exist, and
    /// 01:30 on a fall-back night happens twice. Both resolve the way `jiff` resolves them (the
    /// "compatible" strategy: after the gap, before the fold) rather than by accident.
    pub fn parse(&self, input: &str) -> Option<i64> {
        let (date, time) = input.trim().split_once(['T', ' '])?;
        let mut d = date.split('-');
        let (y, m, dd) = (d.next()?, d.next()?, d.next()?);
        let mut t = time.split(':');
        let (h, mi) = (t.next()?, t.next()?);
        let sec = t.next().unwrap_or("0");
        let dt = civil::date(y.parse().ok()?, m.parse().ok()?, dd.parse().ok()?)
            .at(h.parse().ok()?, mi.parse().ok()?, sec.parse().unwrap_or(0), 0);
        Some(dt.to_zoned(self.zone()).ok()?.timestamp().as_second())
    }

    /// This selection as a `Set-Cookie` value, for the handler behind a [`TzPicker`]. A year, path
    /// `/`, `SameSite=Lax` — a display preference, so nothing is `HttpOnly` or `Secure`-only about it.
    pub fn cookie(&self) -> String {
        format!(
            "{COOKIE}={}; Path=/; Max-Age=31536000; SameSite=Lax",
            crate::urlform::encode(self.name())
        )
    }

    fn civil(&self, epoch: i64) -> Option<civil::DateTime> {
        Some(Timestamp::from_second(epoch).ok()?.to_zoned(self.zone()).datetime())
    }
}

/// A zone picker: a `<select>` and a submit button in a plain `<form>` that posts `tz` and `back` to
/// a route of yours. The handler is four lines — set [`Tz::cookie`] and redirect to `back`:
///
/// ```ignore
/// async fn set_tz(Form(f): Form<HashMap<String, String>>) -> Response {
///     let tz = Tz::named(f.get("tz").map(String::as_str).unwrap_or("UTC"));
///     let back = f.get("back").cloned().unwrap_or_else(|| "/".into());
///     ([(header::SET_COOKIE, tz.cookie())], Redirect::to(&back)).into_response()
/// }
/// ```
///
/// It stays the app's route on purpose: this crate contributes no roots, and a cookie has to be set
/// by a response, which a fragment renderer never gets to write.
///
/// The zone list is deliberately short — one representative per common offset — and replaceable with
/// [`zones`](TzPicker::zones). A 400-entry IANA list is a worse picker, not a better one.
pub struct TzPicker {
    zones: Vec<String>,
    unknown: Vec<String>,
    label: String,
    action: String,
}

/// The zones **no** list in this module offers: the Russian Federation and Belarus.
///
/// Taken from the IANA database's own country table (`zone1970.tab`), so it is the tzdb's assignment
/// rather than a judgement of ours — including `Europe/Simferopol`, which that table lists under
/// `RU,UA`. An application that wants any of these offers them explicitly through
/// [`TzPicker::zones`]; nothing here stops it. What this list governs is what the crate *ships*.
pub const EXCLUDED: &[&str] = &[
    "Asia/Anadyr",
    "Asia/Barnaul",
    "Asia/Chita",
    "Asia/Irkutsk",
    "Asia/Kamchatka",
    "Asia/Khandyga",
    "Asia/Krasnoyarsk",
    "Asia/Magadan",
    "Asia/Novokuznetsk",
    "Asia/Novosibirsk",
    "Asia/Omsk",
    "Asia/Sakhalin",
    "Asia/Srednekolymsk",
    "Asia/Tomsk",
    "Asia/Ust-Nera",
    "Asia/Vladivostok",
    "Asia/Yakutsk",
    "Asia/Yekaterinburg",
    "Europe/Astrakhan",
    "Europe/Kaliningrad",
    "Europe/Kirov",
    "Europe/Minsk",
    "Europe/Moscow",
    "Europe/Samara",
    "Europe/Saratov",
    "Europe/Simferopol",
    "Europe/Ulyanovsk",
    "Europe/Volgograd",
];

/// Europe's zones, west to east — every distinct set of rules the IANA database carries for the
/// continent, minus [`EXCLUDED`].
///
/// These are the **canonical** names. Modern tzdb merges countries that have kept the same rules
/// since 1970, so `Europe/Amsterdam`, `Europe/Oslo`, `Europe/Stockholm` and a dozen others are links
/// rather than entries here — they resolve perfectly well if an app lists them
/// ([`Tz::named`] accepts any name the host knows), they would just be duplicates in a menu.
pub const ZONES_EUROPE: &[&str] = &[
    "Atlantic/Azores",
    "Atlantic/Canary",
    "Atlantic/Faroe",
    "Atlantic/Madeira",
    "Europe/Dublin",
    "Europe/Lisbon",
    "Europe/London",
    "Europe/Andorra",
    "Europe/Belgrade",
    "Europe/Berlin",
    "Europe/Brussels",
    "Europe/Budapest",
    "Europe/Gibraltar",
    "Europe/Madrid",
    "Europe/Malta",
    "Europe/Paris",
    "Europe/Prague",
    "Europe/Rome",
    "Europe/Tirane",
    "Europe/Vienna",
    "Europe/Warsaw",
    "Europe/Zurich",
    "Europe/Athens",
    "Europe/Bucharest",
    "Europe/Chisinau",
    "Europe/Helsinki",
    "Europe/Kyiv",
    "Europe/Riga",
    "Europe/Sofia",
    "Europe/Tallinn",
    "Europe/Vilnius",
    "Europe/Istanbul",
];

/// The United States, east to west — one zone per distinct offset, rather than the database's full
/// set (which carries a dozen Indiana, Kentucky and North Dakota entries that differ only in their
/// DST history).
pub const ZONES_US: &[&str] = &[
    "America/Puerto_Rico",
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Phoenix",
    "America/Los_Angeles",
    "America/Anchorage",
    "America/Adak",
    "Pacific/Honolulu",
];

/// The default offered list: `UTC`, then [`ZONES_EUROPE`], then [`ZONES_US`].
pub fn zones_default() -> Vec<String> {
    std::iter::once("UTC")
        .chain(ZONES_EUROPE.iter().copied())
        .chain(ZONES_US.iter().copied())
        .map(String::from)
        .collect()
}

/// **Every** zone the host's tz database knows, minus [`EXCLUDED`] — sorted, with `UTC` first.
///
/// Read from the database at runtime rather than hardcoded, so it can't drift from the host and
/// needs no maintenance here. Non-geographic entries are left out: `Etc/*`, the legacy POSIX names
/// (`EST5EDT`, `W-SU`, …), and the `SystemV`/`US`/`Canada`/`posix`/`right` trees, none of which
/// belongs in a menu a person reads. Links **are** kept, so someone looking for `Europe/Amsterdam`
/// finds it rather than having to know it means `Europe/Brussels`.
///
/// Expect ~450 entries on a current tzdb — long enough that [`zones_default`] is the better default,
/// and this is the alternative for a deployment that really does span the world.
pub fn zones_all() -> Vec<String> {
    const AREAS: &[&str] = &[
        "Africa/",
        "America/",
        "Antarctica/",
        "Arctic/",
        "Asia/",
        "Atlantic/",
        "Australia/",
        "Europe/",
        "Indian/",
        "Pacific/",
    ];
    let mut out: Vec<String> = jiff::tz::db()
        .available()
        .map(|name| name.to_string())
        .filter(|name| AREAS.iter().any(|a| name.starts_with(a)))
        .filter(|name| !is_excluded(name))
        .collect();
    out.sort();
    out.dedup();
    out.insert(0, "UTC".to_string());
    out
}

/// Whether this zone is one the crate's own lists leave out — see [`EXCLUDED`]. Apply it to your own
/// configured list if you want the same policy there:
/// `cfg.zones.retain(|z| !relativelylight::time::is_excluded(z))`.
pub fn is_excluded(zone: &str) -> bool {
    EXCLUDED.contains(&zone)
}

impl TzPicker {
    /// A picker offering [`zones_default`] — UTC, Europe, the United States.
    pub fn new() -> Self {
        Self {
            zones: zones_default(),
            unknown: Vec::new(),
            label: "Timezone".into(),
            action: "/tz".into(),
        }
    }

    /// Where the picker posts. Default `/tz`.
    pub fn action(mut self, path: impl Into<String>) -> Self {
        self.action = path.into();
        self
    }

    /// Replace the offered zones — the usual call when the list comes from configuration:
    ///
    /// ```ignore
    /// // cfg.timezones: Vec<String>, read from YAML / JSON / a settings table at startup
    /// let picker = TzPicker::new().zones(cfg.timezones);
    /// if !picker.unknown_zones().is_empty() {
    ///     tracing::warn!(ignored = ?picker.unknown_zones(), "unknown timezone names in config");
    /// }
    /// ```
    ///
    /// Names the host's tz database doesn't know are **dropped**, not offered: an `<option>` that
    /// silently means UTC is exactly the kind of control that looks like it works. They are kept in
    /// [`unknown_zones`](TzPicker::unknown_zones) so a typo in configuration can be reported — or
    /// made fatal — at startup rather than discovered by an operator whose zone is missing.
    ///
    /// The list is offered **as given**: order is yours, and so is policy. If you want the crate's
    /// own exclusions applied to your list too, filter it with [`is_excluded`].
    pub fn zones<I, S>(mut self, zones: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let (known, unknown): (Vec<String>, Vec<String>) =
            zones.into_iter().map(Into::into).partition(|z| Tz::known(z));
        self.zones = known;
        self.unknown = unknown;
        self
    }

    /// Offer [`zones_all`] — every zone the host knows, minus [`EXCLUDED`].
    pub fn all_zones(self) -> Self {
        self.zones(zones_all())
    }

    /// Configured names that were dropped because the host's tz database doesn't know them. Empty
    /// unless [`zones`](TzPicker::zones) was given something unrecognised.
    pub fn unknown_zones(&self) -> &[String] {
        &self.unknown
    }

    /// The visible label beside the control. Default `Timezone`.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Render the picker with `current` preselected, returning to `back` (the page the user is on)
    /// after the cookie is set.
    pub fn render(&self, current: &Tz, back: &str) -> String {
        // The offered list must be able to represent where the user actually is. If a configured
        // list leaves out their zone (or UTC), a `<select>` would show *no* selected option — the
        // browser then displays the first one, and the next submit silently moves them to it.
        let mut offered: Vec<&str> = self.zones.iter().map(String::as_str).collect();
        for needed in [current.name(), "UTC"] {
            if !offered.contains(&needed) {
                offered.insert(0, needed);
            }
        }
        let options: String = offered
            .iter()
            .map(|z| {
                let sel = if *z == current.name() { " selected" } else { "" };
                let z = html_escape(z);
                format!(r#"<option value="{z}"{sel}>{z}</option>"#)
            })
            .collect();
        format!(
            r#"<form method="post" action="{action}" class="d-flex align-items-center gap-1" title="{label}">
<input type="hidden" name="back" value="{back}">
<select class="form-select form-select-sm w-auto" name="tz" aria-label="{label}">{options}</select>
<button class="btn btn-outline-secondary btn-sm" type="submit">Set</button>
</form>"#,
            action = html_escape(&self.action),
            back = html_escape(back),
            label = html_escape(&self.label),
        )
    }
}

impl Default for TzPicker {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal text/attribute escaping — the module renders its own small fragment, so it can't lean on
/// the template engine's autoescaping the way [`crud::ui`](crate::crud::ui) does.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_is_the_fallback_for_anything_unrecognised() {
        assert_eq!(Tz::named("Mars/Olympus"), Tz::UTC);
        assert_eq!(Tz::from_headers(&http::HeaderMap::new()), Tz::UTC);
        assert_eq!(Tz::UTC.name(), "UTC");
    }

    #[test]
    fn the_cookie_selects_the_zone() {
        let mut h = http::HeaderMap::new();
        h.insert(http::header::COOKIE, "a=1; rl_tz=Europe%2FPrague; b=2".parse().unwrap());
        assert_eq!(Tz::from_headers(&h).name(), "Europe/Prague");
    }

    #[test]
    fn formats_one_instant_in_two_zones() {
        let epoch = 1_733_050_800; // 2024-12-01 11:00 UTC
        assert_eq!(Tz::UTC.format(epoch), "2024-12-01 11:00");
        assert_eq!(Tz::named("Europe/Prague").format(epoch), "2024-12-01 12:00");
        assert_eq!(Tz::named("Asia/Tokyo").format(epoch), "2024-12-01 20:00");
    }

    #[test]
    fn a_form_input_round_trips_through_its_zone() {
        let tz = Tz::named("Europe/Prague");
        let epoch = tz.parse("2024-12-01T12:00").expect("parses");
        assert_eq!(epoch, 1_733_050_800);
        assert_eq!(tz.format_input(epoch), "2024-12-01T12:00");
        assert_eq!(tz.parse("2024-12-01T12:00:30"), Some(epoch + 30), "seconds are accepted");
        assert_eq!(tz.parse("not a date"), None);
    }

    #[test]
    fn the_cookie_round_trips_through_a_request() {
        let set = Tz::named("Europe/Prague").cookie();
        assert!(set.starts_with("rl_tz=Europe%2FPrague;"), "{set}");
        let mut h = http::HeaderMap::new();
        let value = set.split(';').next().unwrap();
        h.insert(http::header::COOKIE, value.parse().unwrap());
        assert_eq!(Tz::from_headers(&h), Tz::named("Europe/Prague"));
    }

    #[test]
    fn the_shipped_lists_carry_no_russian_or_belarusian_zone() {
        // The requirement this module is configured for: nothing the crate *offers* may include one.
        for zone in ZONES_EUROPE.iter().chain(ZONES_US).copied() {
            assert!(!is_excluded(zone), "{zone} is excluded but shipped in a default list");
        }
        for zone in zones_default().iter().chain(zones_all().iter()) {
            assert!(!is_excluded(zone), "{zone} reached an offered list");
        }
        assert!(EXCLUDED.contains(&"Europe/Moscow") && EXCLUDED.contains(&"Europe/Minsk"));
        assert!(!zones_all().iter().any(|z| z.starts_with("Etc/")), "no non-geographic entries");
    }

    #[test]
    fn every_shipped_zone_name_is_one_the_host_actually_has() {
        // A name we ship that the database doesn't know would render as an option meaning UTC.
        for zone in zones_default() {
            assert!(Tz::known(&zone), "{zone} is not in the host tz database");
            assert_eq!(Tz::named(&zone).name(), zone, "{zone} must not fall back");
        }
    }

    #[test]
    fn the_complete_list_is_complete_enough_and_sorted() {
        let all = zones_all();
        assert_eq!(all[0], "UTC", "UTC first");
        assert!(all.len() > 200, "expected the host's full database, got {}", all.len());
        assert!(all.iter().any(|z| z == "Asia/Tokyo") && all.iter().any(|z| z == "Africa/Cairo"));
        assert!(all[1..].windows(2).all(|w| w[0] <= w[1]), "sorted");
        assert!(all.iter().all(|z| z == "UTC" || z.contains('/')));
    }

    #[test]
    fn a_configured_list_is_taken_as_given_and_typos_are_reported_not_offered() {
        // The shape an app configures from YAML / JSON / a settings table.
        let configured = vec![
            "Europe/Prague".to_string(),
            "Atlantis/Poseidon".to_string(), // a typo, or a zone this host lacks
            "America/New_York".to_string(),
        ];
        let picker = TzPicker::new().zones(configured);
        assert_eq!(picker.unknown_zones(), ["Atlantis/Poseidon"]);

        let html = picker.render(&Tz::named("Europe/Prague"), "/");
        assert!(html.contains(r#"<option value="Europe/Prague" selected>"#), "{html}");
        assert!(html.contains(r#"<option value="America/New_York">"#));
        assert!(!html.contains("Atlantis"), "an option that would mean UTC is not offered: {html}");
        // Order is the app's: Prague before New_York, as configured (UTC is prepended, see below).
        let prague = html.find("Europe/Prague").unwrap();
        let ny = html.find("America/New_York").unwrap();
        assert!(prague < ny, "the configured order is kept");
    }

    #[test]
    fn the_menu_can_always_represent_where_the_user_is() {
        // A configured list that omits the user's zone would otherwise show no selected option —
        // the browser displays the first, and the next submit silently moves them to it.
        let picker = TzPicker::new().zones(["America/New_York"]);
        let html = picker.render(&Tz::named("Asia/Tokyo"), "/");
        assert!(html.contains(r#"<option value="Asia/Tokyo" selected>"#), "{html}");
        assert!(html.contains(r#"<option value="UTC">"#), "and UTC is always reachable");
        assert_eq!(html.matches("selected").count(), 1);
    }

    #[test]
    fn the_picker_marks_the_current_zone_and_carries_the_page_back() {
        let html = TzPicker::new().action("/tz").render(&Tz::named("Asia/Tokyo"), "/admin?entity=post");
        assert!(html.contains(r#"<option value="Asia/Tokyo" selected>"#), "{html}");
        assert!(html.contains(r#"value="/admin?entity=post""#));
        assert!(html.contains(r#"action="/tz""#));
    }

    /// The case the `time` example exists to show, now checkable without a browser: the same wall
    /// clock either side of a DST change is a different number of UTC seconds, and one hour is not
    /// 3600 seconds apart in civil time.
    #[test]
    fn dst_is_handled_by_the_zone_not_by_an_offset() {
        let tz = Tz::named("Europe/Prague");
        let before = tz.parse("2024-03-31T01:30").expect("winter");
        let after = tz.parse("2024-03-31T03:30").expect("summer");
        assert_eq!(after - before, 3600, "02:00–03:00 does not exist that night");
        // A reading inside the gap resolves forward rather than being rejected or shifted an hour back.
        assert_eq!(tz.parse("2024-03-31T02:30"), Some(before + 3600));
    }
}
