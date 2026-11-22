//! `relativelylight::time` — timezone-aware **presentation** of timestamps.
//!
//! The contract across relativelylight is: an **instant** is stored as **integer Unix seconds, UTC**
//! (a calendar date is a native `DATE`, which has no zone; `docs/TIME.md` §1).
//! Timezones exist only for display — but the *formatting happens on the server*, which is what lets a
//! CSV export match what is on screen and a `<datetime-local>` input round-trip through the zone the
//! operator is actually working in.
//!
//! The selection rides in a cookie ([`COOKIE`](crate::time::COOKIE)), so every render of every page agrees about it:
//!
//! - [`Tz`](crate::time::Tz) — the zone for one request, read from the caller's headers ([`Tz::from_headers`](crate::time::Tz::from_headers)), used to
//!   [`format`](crate::time::Tz::format) an epoch for a cell and to [`parse`](crate::time::Tz::parse) a form input back.
//! - [`picker`](crate::time::picker) — a type-to-search list of zones; [`JS`](crate::time::JS), inlined
//!   in every page, sets the cookie from it, and from the browser's own zone on a first visit.
//!
//! An unknown or unset zone is **UTC**, and so is a zone the host's tz database doesn't have: a
//! timestamp shown in the wrong zone is worse than one labelled UTC.
//!
//! ```ignore
//! let tz = relativelylight::time::Tz::from_headers(&headers);   // in a page handler
//! let picker = relativelylight::time::picker(&tz);  // drop into your navbar
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

    /// A calendar date (`YYYY-MM-DD`, what an `<input type="date">` posts) → its first and last second
    /// **in this zone** (a range's "to" day is inclusive). `None` if it isn't exactly a date.
    pub fn day_bounds(&self, input: &str) -> Option<(i64, i64)> {
        (input.trim().len() == 10).then(|| self.period(input)).flatten()
    }

    /// The period a date-time prefix names, in this zone: `2026`, `2026-03`, `2026-03-05`,
    /// `2026-03-05 14` or `2026-03-05 14:30` (a `T` for the space too) → its first and last second.
    /// `None` for anything else. A DST change makes a day or hour as long as it really is.
    pub fn period(&self, input: &str) -> Option<(i64, i64)> {
        let s = input.trim();
        let num = |range: std::ops::Range<usize>| -> Option<i64> {
            let part = s.get(range)?;
            part.bytes().all(|b| b.is_ascii_digit()).then(|| part.parse().ok()).flatten()
        };
        let sep = |i: usize, ok: &[u8]| s.as_bytes().get(i).is_some_and(|b| ok.contains(b));
        let y = i16::try_from(num(0..4)?).ok()?;
        let (start, next) = match s.len() {
            4 => {
                let d = civil::date(y, 1, 1);
                (d.at(0, 0, 0, 0), d.checked_add(jiff::Span::new().years(1)).ok()?.at(0, 0, 0, 0))
            }
            7 if sep(4, b"-") => {
                let d = civil::Date::new(y, num(5..7)? as i8, 1).ok()?;
                (d.at(0, 0, 0, 0), d.checked_add(jiff::Span::new().months(1)).ok()?.at(0, 0, 0, 0))
            }
            10 | 13 | 16 if sep(4, b"-") && sep(7, b"-") => {
                let d = civil::Date::new(y, num(5..7)? as i8, num(8..10)? as i8).ok()?;
                let (h, unit) = match s.len() {
                    10 => (0, jiff::Span::new().days(1)),
                    _ if sep(10, b" T") => (num(11..13)?, jiff::Span::new().hours(1)),
                    _ => return None,
                };
                let (mi, unit) = match s.len() {
                    16 if sep(13, b":") => (num(14..16)?, jiff::Span::new().minutes(1)),
                    16 => return None,
                    _ => (0, unit),
                };
                let t = civil::Time::new(h as i8, mi as i8, 0, 0).ok()?;
                let at = d.to_datetime(t);
                (at, at.checked_add(unit).ok()?)
            }
            _ => return None,
        };
        let second = |dt: civil::DateTime| Some(dt.to_zoned(self.zone()).ok()?.timestamp().as_second());
        Some((second(start)?, second(next)? - 1))
    }

    /// This zone as a `Set-Cookie` value, for an app that sets the zone itself (one it stores per user,
    /// at sign-in). A year, path `/`, `SameSite=Lax`, as [`JS`] sets it: a display preference, so
    /// nothing is `HttpOnly` or `Secure`-only about it.
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

/// The timezone picker's script, and the first visit's default: **inline it once in every page's
/// shell**, as `crud::JS`, or the picker does nothing (`docs/TIME.md`).
///
/// With no [`COOKIE`] yet, it sets the browser's own zone and reloads once, so a first visit renders
/// in local time from the second page on. A [`picker`] then sets the cookie from what is chosen and
/// reloads: no route, no handler.
pub const JS: &str = include_str!("../assets/rl-tz.js");

/// The picker's entry that means "the browser's own zone".
const BROWSER: &str = "Browser timezone";

/// The picker's list, built once: `UTC`, "Browser timezone", then every zone name the host's database
/// knows, sorted (old and new names both, as it has them: `Europe/Kiev` beside `Europe/Kyiv`).
fn options() -> &'static str {
    static OPTIONS: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    OPTIONS.get_or_init(|| {
        let mut names: Vec<String> =
            jiff::tz::db().available().map(|n| n.to_string()).filter(|n| n != "UTC").collect();
        names.sort();
        ["UTC", BROWSER]
            .into_iter()
            .map(String::from)
            .chain(names)
            .map(|z| format!(r#"<option value="{}">"#, crate::html::esc(&z)))
            .collect()
    })
}

/// The timezone picker showing `current`: a text input over the list of every zone, which a browser
/// searches as you type, led by `UTC` and "Browser timezone". Choosing sets the [`COOKIE`] in the
/// browser and reloads ([`JS`]); a name that isn't in the list means UTC. Put it where you like: a
/// navbar, a profile card.
///
/// ```ignore
/// let html = relativelylight::time::picker(&Tz::from_headers(&headers));
/// ```
pub fn picker(current: &Tz) -> String {
    // Two pickers on one page each need their own list.
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let id = format!("rl-tz-{}", N.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    format!(
        r#"<span class="rl-tz" data-rl-tz data-rl-tz-browser="{BROWSER}"><input class="form-control form-control-sm" style="width:14rem" list="{id}" value="{current}" aria-label="Timezone" title="Timezone" autocomplete="off" spellcheck="false"><datalist id="{id}">{options}</datalist></span>"#,
        current = crate::html::esc(current.name()),
        options = options(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_day_runs_from_its_first_second_to_its_last_in_the_zone() {
        let prague = Tz::named("Europe/Prague");
        // 1 November 2026 in Prague (CET, UTC+1) starts at 23:00 UTC the evening before.
        assert_eq!(prague.day_bounds("2026-11-01"), Some((1_793_487_600, 1_793_487_600 + 86_400 - 1)));
        assert_eq!(Tz::UTC.day_bounds("2026-11-01"), Some((1_793_491_200, 1_793_491_200 + 86_400 - 1)));
        // The spring-forward day is 23 hours long, and the bounds say so.
        let (first, last) = prague.day_bounds("2026-03-29").unwrap();
        assert_eq!((first, last), (1_774_738_800, 1_774_821_600 - 1));
        assert_eq!(last - first + 1, 23 * 3600);
        for bad in ["", "2026-02-30", "yesterday", "2026-11-01T10:00"] {
            assert_eq!(prague.day_bounds(bad), None, "{bad:?} is not a date");
        }
    }

    #[test]
    fn a_date_time_prefix_names_a_period_in_the_zone() {
        let tz = Tz::named("Europe/Prague");
        let at = |s: &str| tz.parse(s).unwrap(); // a wall-clock reading → Unix seconds
        assert_eq!(tz.period("2026"), Some((at("2026-01-01T00:00"), at("2027-01-01T00:00") - 1)));
        assert_eq!(tz.period("2026-03"), Some((at("2026-03-01T00:00"), at("2026-04-01T00:00") - 1)));
        assert_eq!(tz.period("2026-03-05"), Some((at("2026-03-05T00:00"), at("2026-03-06T00:00") - 1)));
        assert_eq!(tz.period("2026-03-05 14"), Some((at("2026-03-05T14:00"), at("2026-03-05T15:00") - 1)));
        assert_eq!(tz.period("2026-03-05T14:30"), Some((at("2026-03-05T14:30"), at("2026-03-05T14:31") - 1)));
        // The DST day is 23 hours long.
        let (a, b) = tz.period("2026-03-29").unwrap();
        assert_eq!(b - a + 1, 23 * 3600);
        for no in ["", "20", "2026-3", "2026-13", "2026-02-30", "2026/03/05", "2026-03-05 1", "2026-03-05 14:3", "abc", "12026"] {
            assert_eq!(tz.period(no), None, "{no:?}");
        }
        assert_eq!(tz.day_bounds("2026-03-05"), tz.period("2026-03-05"));
        assert_eq!(tz.day_bounds("2026-03"), None, "a range bound is a whole date");
    }

    #[test]
    fn with_no_cookie_the_picker_shows_utc() {
        let tz = Tz::from_headers(&http::HeaderMap::new());
        assert_eq!(tz, Tz::UTC, "no cookie is UTC");
        let html = picker(&tz);
        assert!(html.contains(r#"value="UTC" aria-label="Timezone""#), "{html}");
    }

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
    fn the_picker_offers_utc_the_browser_and_every_zone_the_host_knows() {
        let html = picker(&Tz::named("Asia/Tokyo"));
        assert!(html.contains(r#"value="Asia/Tokyo" aria-label="Timezone""#), "shows the current zone: {html}");
        assert!(html.contains(&format!(r#"data-rl-tz-browser="{BROWSER}""#)), "tells the script its entry");
        assert!(JS.contains(&format!("'{COOKIE}'")), "the script sets the cookie the server reads");
        let first = html.find(r#"<option value="UTC">"#).unwrap();
        let browser = html.find(&format!(r#"<option value="{BROWSER}">"#)).unwrap();
        let rest = html.find(r#"<option value="Africa/"#).unwrap();
        assert!(first < browser && browser < rest, "UTC, then the browser's zone, then the rest");
        assert_eq!(html.matches(r#"<option value="UTC">"#).count(), 1, "UTC once");
        // The host's names, old and new both (Kyiv and its former name), sorted.
        assert!(html.contains(r#"<option value="Europe/Kyiv">"#) && html.contains(r#"<option value="Asia/Tokyo">"#));
        let names: Vec<&str> = options().split(r#"<option value=""#).skip(3).map(|o| &o[..o.len() - 2]).collect();
        assert!(names.len() > 300, "the host's whole database, got {}", names.len());
        assert!(names.windows(2).all(|w| w[0] < w[1]), "sorted, no duplicates");
    }

    #[test]
    fn two_pickers_on_one_page_have_their_own_lists() {
        let (a, b) = (picker(&Tz::UTC), picker(&Tz::UTC));
        let id = |h: &str| h.split(r#"list=""#).nth(1).unwrap().split('"').next().unwrap().to_string();
        assert_ne!(id(&a), id(&b));
        assert!(a.contains(&format!(r#"<datalist id="{}">"#, id(&a))));
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
