# Time & timezones

How relativelylight stores, renders and reads back timestamps — and where an app plugs in.

Feature **`tz`** (implied by `ui`). One dependency: [`jiff`](https://docs.rs/jiff), for the IANA
timezone database.

- [1. Storage model](#1-storage-model)
- [2. The zone for one request: `Tz`](#2-the-zone-for-one-request-tz)
- [3. The picker, and its four-line handler](#3-the-picker-and-its-four-line-handler)
- [4. What follows the zone](#4-what-follows-the-zone)
- [5. DST, and why the server does this](#5-dst-and-why-the-server-does-this)
- [6. Choosing a policy](#6-choosing-a-policy)
- [7. Reference: the flow for one datetime column](#7-reference-the-flow-for-one-datetime-column)

---

## 1. Storage model

**The database column is an integer: Unix seconds, UTC.** Nothing else in the crate stores a local
time, an offset, or a zone name beside a timestamp. A timezone is a *presentation* choice, and it is
made per request.

Declare such a column with [`MetaField::datetime`](CRUD.md#widget-overrides--picking-the-form-input-per-field):

```rust
post_mm.field("published_at").datetime();   // an i64 column holding Unix seconds
```

That is the whole model-side configuration. The column then renders as a readable datetime in a table
cell, as a `<input type="datetime-local">` in a form, and as a readable datetime in a CSV export — all
three in the caller's zone, all three on the server.

## 2. The zone for one request: `Tz`

The selected zone rides in a cookie (`rl_tz`, the constant [`time::COOKIE`]), so every render of every
page in a session agrees about it. A handler reads it from the request:

```rust
use relativelylight::time::Tz;

let tz = Tz::from_headers(&headers);   // the cookie's zone, or UTC
tz.name();                             // "Europe/Prague" | "UTC"
tz.format(1_733_050_800);              // "2024-12-01 12:00"   (a table cell)
tz.format_input(1_733_050_800);        // "2024-12-01T12:00"   (a datetime-local value)
tz.parse("2024-12-01T12:00");          // Some(1_733_050_800)  (what the form posted)
```

`Tz::UTC` is the default and the fallback: an unset cookie, an unparseable one, or a zone the host's
tz database doesn't have all render UTC. **A timestamp shown in the wrong zone is worse than one
labelled UTC**, so there is no guessing and no partial failure.

The `crud::ui` components do this for you — `render_for` takes the headers, so cells and inputs are
already in the caller's zone. You need `Tz` directly only on your own pages.

## 3. The picker, and its four-line handler

[`TzPicker`] renders a `<select>` of zones in a plain form that posts `tz` and `back` to a route of
yours. Setting a cookie needs a *response*, which a fragment renderer never gets to write — so this
stays your route, like everything else in this crate:

```rust
// in your shell, e.g. the navbar:
let picker = TzPicker::new().render(&Tz::from_headers(&headers), current_url);

// the route it posts to:
async fn set_tz(Form(fields): Form<HashMap<String, String>>) -> Response {
    let tz = Tz::named(fields.get("tz").map(String::as_str).unwrap_or("UTC"));
    let back = fields.get("back").cloned().unwrap_or_else(|| "/".into());
    ([(header::SET_COOKIE, tz.cookie())], Redirect::to(&back)).into_response()
}
```

`back` is the page the user was on, so setting a zone doesn't lose the table they were looking at, and
`action(path)` changes where the form posts (default `/tz`).

**Where you put it is entirely yours**, because it is a fragment and nothing about it is positional:

- **In the navbar** (what the examples do) — one `TzPicker` rendered by the shell on every page, with
  `back` set to the current URL, so a zone can be changed from wherever the operator noticed the
  problem. This is the right default for a console whose whole job is reading timestamps.
- **On the profile page** — either in your own `/settings` page, or appended to the library's profile
  page with [`Auth::profile_extra`](AUTH.md) (the hook hands you the caller's identity and the
  request's CSRF token, and the picker's own form is plain HTML). Better when the zone is a rarely
  changed personal preference rather than a working control.
- **Both**, or neither: nothing in the library reads the picker. It only reads the **cookie**, via
  `Tz::from_headers` in your handler. A page with no picker anywhere still renders in whatever zone
  the cookie says, and an app that gets the zone from somewhere else entirely — a column on its own
  user table, a query parameter, an org-wide setting — just passes a different `Tz` and never calls
  `TzPicker` at all.

One thing to keep consistent: the cookie is set by *your* route, so if you render the picker in two
places, point both at the same `action` — otherwise you maintain two handlers that must agree about
the cookie's attributes.

### Which zones are offered

| | |
|---|---|
| `TzPicker::new()` | the default: **UTC, Europe, the United States** — [`zones_default`], 42 entries |
| `.all_zones()` | **everything the host's database knows**, minus the exclusions below — [`zones_all`], ~450 entries |
| `.zones(list)` | exactly what you pass, in your order — the usual case |

The third is what a deployment normally does: read a list of IANA names from YAML, JSON or a settings
table at startup and hand it over.

```rust
// cfg.timezones: Vec<String>
let picker = TzPicker::new().zones(cfg.timezones);
if !picker.unknown_zones().is_empty() {                       // check once, at boot
    tracing::warn!(ignored = ?picker.unknown_zones(), "unknown timezone names in config");
}
```

A name the host's database doesn't know is **dropped rather than offered**, and kept in
`unknown_zones()` — an `<option>` that silently means UTC is exactly the kind of control that looks
like it works, and a typo in configuration should be a line in your startup log, not a zone an
operator can't find. Everything else is yours: the order is the order you gave, and no name you list
is second-guessed.

Two things the picker guarantees whatever you configure: **UTC is always reachable**, and **the
caller's current zone is always in the menu** (prepended if your list omits it). Without that second
one, a `<select>` with no selected option displays its first entry — and the next submit would move
the user to it.

### The exclusions

The crate's own lists — [`zones_default`] and [`zones_all`] — leave out the **Russian Federation and
Belarus**: the 28 zones the IANA database's own country table (`zone1970.tab`) assigns to `RU` or
`BY`, `Europe/Simferopol` among them (that table lists it as `RU,UA`). They are available as
[`time::EXCLUDED`], and `is_excluded(zone)` tests one name.

This governs what the crate *ships*, not what your app may offer: `zones(…)` takes your list as
given. Apply the same policy to a configured list with one line if you want it:

```rust
cfg.timezones.retain(|z| !relativelylight::time::is_excluded(z));
```

[`zones_default`]: https://docs.rs/relativelylight/latest/relativelylight/time/fn.zones_default.html
[`zones_all`]: https://docs.rs/relativelylight/latest/relativelylight/time/fn.zones_all.html
[`time::EXCLUDED`]: https://docs.rs/relativelylight/latest/relativelylight/time/constant.EXCLUDED.html

`Tz::cookie()` is a `Set-Cookie` value: path `/`, a year, `SameSite=Lax`, and deliberately neither
`HttpOnly` nor `Secure`-only — it is a display preference, not a credential.

## 4. What follows the zone

Everything the crate renders from a `datetime` column:

| Surface | In the caller's zone |
|---|---|
| a table cell | `2024-12-01 12:00` |
| a form input (`datetime-local`) | pre-filled with the same wall-clock reading, and read back through the zone |
| the form's help text | "Times are Europe/Prague." — so the reading is never ambiguous |
| **a CSV export** | `2024-12-01 12:00`, and re-importing that file means what it says |

The CSV row is the one worth pausing on. While the zone was known only to the browser, an export
*could not* agree with the screen: the server had no idea what the user was looking at, so files came
out in UTC and someone reconciled them by hand. That is the concrete reason this work moved to the
server, and `docs/CRUD.md` § CSV describes the round-trip.

## 5. DST, and why the server does this

A wall-clock reading is not always a unique instant:

- **A gap** (spring forward): `2024-03-31T02:30` does not exist in `Europe/Prague`. `Tz::parse`
  resolves it *forward*, to 03:30 — `jiff`'s "compatible" strategy — rather than rejecting the input
  or silently shifting it an hour back.
- **A fold** (fall back): `2024-11-03T01:30` happens twice in `America/New_York`. The reading before
  the fold is taken.

Both are decided once, in one place, by a library with the IANA rules — not by whichever browser
happened to submit the form. The cases are unit tests (`time.rs`), which is itself an argument for the
move: the same behaviour in JavaScript could only be checked by driving a browser.

Offsets are never stored, so a zone whose rules change (and they do, by political decision) reinterprets
the stored integers correctly on the next render. That is the whole reason the column is UTC seconds.

## 6. Choosing a policy

The cookie is the mechanism; the policy is yours.

- **Nothing at all.** Don't render a picker. Everything is UTC, labelled UTC. Correct, and right for an
  operations console whose logs are UTC too.
- **Let the user choose** (the usual). Render `TzPicker` and the four-line handler. The choice persists
  for a year and costs no storage.
- **Seed it from the browser once.** If you want a first-visit default without asking, three lines of
  JavaScript can set the cookie from `Intl.DateTimeFormat().resolvedOptions().timeZone` and reload.
  This crate ships no such script on purpose: it is three lines, it is the app's policy, and every app
  wants a slightly different trigger.
- **Store it per user.** Read your own `user.timezone` column in your page handler and pass
  `Tz::named(&user.timezone)` where you would have passed `Tz::from_headers(&headers)`; set the cookie
  at login so the library's components agree. The crate keeps no per-user state of its own.
- **Follow the server's zone.** `Tz::named(&std::env::var("TZ")?)`, if matching syslog matters more than
  matching the operator.

Note what is *not* here any more: `window.RL_TZ`, `window.RLTime`, the Alpine `$store.tz` store, and
the `time::JS` bundle. A policy that used to be four JavaScript options is now which `Tz` your handler
passes.

## 7. Reference: the flow for one datetime column

```
  database            i64 Unix seconds, UTC          1733050800
      │
      │  Engine::list / get                          (unchanged, untouched)
      ▼
  Tz::from_headers(&headers)   ──►  "Europe/Prague"  (the rl_tz cookie, else UTC)
      │
      ├─ table cell      Tz::format        ──►  "2024-12-01 12:00"
      ├─ form input      Tz::format_input  ──►  "2024-12-01T12:00"
      └─ CSV cell        Tz::format        ──►  "2024-12-01 12:00"
                                                     │
  browser posts the form                             │  "2024-12-01T12:00"
      │                                              ▼
      └─ ui::decode  ──►  Tz::parse  ──►  1733050800  ──►  the same i64 column
```

Runnable: `cargo run -p crud-example`, then open **`/event`** and pick a zone in the navbar. That
table's rows sit either side of both 2026 DST transitions, so a zone that observes DST shows the
January rows an hour off the June ones — from identical stored integers. Editing `Happens at` reads
your typed wall-clock time back in that zone, and **Export CSV** produces a file that says what the
screen says. `examples/adminpanel` wires the same picker into a login-gated app.

[`time::COOKIE`]: https://docs.rs/relativelylight/latest/relativelylight/time/constant.COOKIE.html
[`TzPicker`]: https://docs.rs/relativelylight/latest/relativelylight/time/struct.TzPicker.html
