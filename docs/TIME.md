# Time & timezones

How relativelylight stores, renders and reads back timestamps — and where an app plugs in.

Feature **`tz`** (implied by `ui`). One dependency: [`jiff`](https://docs.rs/jiff), for the IANA
timezone database.

- [1. Storage model](#1-storage-model)
- [2. The zone for one request: `Tz`](#2-the-zone-for-one-request-tz)
- [3. The picker, and the first visit](#3-the-picker-and-the-first-visit)
- [4. What follows the zone](#4-what-follows-the-zone)
- [5. DST, and why the server does this](#5-dst-and-why-the-server-does-this)
- [6. Choosing a policy](#6-choosing-a-policy)
- [7. Reference: the flow for one datetime column](#7-reference-the-flow-for-one-datetime-column)

---

## 1. Storage model

**Pick a column's type by what the value means.** There is one way for each kind:

| The value is | Column | Model field | Zone |
|---|---|---|---|
| **an instant**: something happened, or will, at a moment (`created_at`, `expires_at`) | an integer, **Unix seconds, UTC** (`BIGINT`), marked `.datetime()` | `ChronoUnixTimestamp` (or `i64`) | shown, typed and exported in the viewer's zone |
| **a calendar date**: a day with no time (a date of supply, a `valid_until`) | a native `DATE` | `Date` (`chrono::NaiveDate`) | none: the same day for every viewer |
| a time of day | not supported for writing; nothing has needed one yet | — | — |
| a native `DateTime` / `Timestamp` / `TimestampWithTimeZone` / `Time` | **read-only**: shown as stored and sorted, never written | — | none |

Nothing in the crate stores a local time, an offset or a zone name beside a value. A timezone is a
*presentation* choice, made per request (§2).

### Instants: integer seconds

An instant is an integer because an integer is the same thing on SQLite and PostgreSQL: it compares,
sorts and does arithmetic (`expires_at <= now`, `+ 86_400`) as an integer, in the same SQL, on an
ordinary index. Storing no offset means a zone whose rules change reinterprets the stored integers
correctly on the next render (§5). Declare the column with
[`MetaField::datetime`](CRUD.md#widget-overrides--picking-the-form-input-per-field):

```rust
#[sea_orm(table_name = "post")]
pub struct Model {
    // …
    pub published_at: Option<ChronoUnixTimestamp>,   // BIGINT in the database
}

post_mm.field("published_at").datetime();
```

That is the whole model-side configuration. The column then renders as a readable datetime in a table
cell, as a `<input type="datetime-local">` in a form, and as a readable datetime in a CSV export — all
three in the caller's zone, all three on the server.

`ChronoUnixTimestamp` (SeaORM's `sea_orm::prelude`) is a `DateTime<Utc>` in Rust and a `BIGINT` of
seconds in the database: date arithmetic in Rust without hand-rolled `i64` maths, and nothing changes
in the schema or for the crate, which reads it as the integer it is. It serializes as that integer
through SeaORM's `serde` feature, which the `crud` feature turns on. Use seconds, not
`ChronoUnixTimestampMillis`: `.datetime()` reads seconds. A plain `i64` field works the same.

### Calendar dates: a native `DATE`

A date is a native `DATE` column, a `Date` (`chrono::NaiveDate`) field: `YYYY-MM-DD` text on SQLite,
`date` on PostgreSQL. Its input is `<input type="date">`, and it reads the same for every viewer, in
every zone.

**Never store a date as midnight-UTC seconds.** Rendered in the viewer's zone, an instant at 00:00 UTC
is the previous day anywhere west of UTC, so a date of supply would show a day early in New York.

The crate accepts a date on every surface (the form, CSV, `Engine`, filters and ranges) only as
exactly `YYYY-MM-DD`, a real day: `2026-1-5`, `5.11.2026`, `2026-02-30` and a date with a time are
the field's error `expected a date, YYYY-MM-DD`. It binds a date as a date, so PostgreSQL compares
`date` with `date`, and a filter value that is no date matches no rows.

### Native date-times: read-only

A native `DateTime`, `Timestamp`, `TimestampWithTimeZone` or `Time` column is introspected
**read-only**. The crate shows it as stored and sorts it; it has no range control, and the engine
refuses a write to it, even if you mark the field writable, with a message pointing here. Writing one would mean deciding what a `datetime-local` value
means for a zoned column; store an instant as integer seconds instead, or fill the column in a hook.
Not recommended for new columns.

### Naming, and the raw database

- **Name an instant `…_at`** (`created_at`, `sent_at`), not `…_ts`: the suffix says what the value
  means. A `DATE` column describes itself in `\d`.
- **Comment an integer instant** for whoever reads the raw database, in the migration:
  `COMMENT ON COLUMN invoice.sent_at IS 'Unix seconds, UTC';` (PostgreSQL; SQLite has no column
  comments). SeaORM's `#[sea_orm(comment = "…")]` does not reach `COMMENT ON COLUMN` when the
  table is created from the entity, so write it yourself.
- **Anyone writing outside the models** (raw SQL, an import script, another app) keeps the same
  contract: a date is exactly `YYYY-MM-DD`, an instant is integer seconds. PostgreSQL refuses
  anything else in a `date` column; **SQLite doesn't**, and a row holding `5.11.2026` then sorts and
  range-filters wrong, with no error anywhere.

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

## 3. The picker, and the first visit

**[`time::JS`] goes in every page's shell**, once, like `crud::ui::JS`. It does two things:

- **A first visit takes the browser's zone.** With no `rl_tz` cookie, it sets the browser's own zone
  and reloads once, so from the second page on everything renders in local time. A zone chosen later
  is never overwritten. Without JavaScript the cookie never appears, and pages render in UTC.
- **It drives the picker.** Choosing a zone sets the cookie in the browser and reloads: there is no
  route of yours behind it.

[`time::picker`] renders the picker: a text input over a list of every zone the server's timezone database
knows, which browsers search as you type. **UTC** and **Browser timezone** lead the list. A name that
isn't in it means UTC.

```rust
// in your shell: the picker wherever you want it, and the script at the end of <body>
let picker = relativelylight::time::picker(&Tz::from_headers(&headers));
// <script>{relativelylight::time::JS}</script>
```

The list holds the database's names as they are, old and new side by side (`Europe/Kiev` and
`Europe/Kyiv`); either renders right. Some browsers report a zone by its old name, which the server
accepts as it is.

**Where you put the picker is yours**, because it is a fragment:

- **In the navbar** — rendered by the shell on every page, so a zone can be changed from wherever the
  operator noticed. Right for a console whose whole job is reading timestamps. `examples/crud` and
  `examples/adminpanel` do this, and the library's own pages carry it too: [`Auth::login_shell`](AUTH.md)
  and `Auth::profile_shell` are handed the request, so the shell reads the cookie as for any page.
- **On the profile page** — a card of [`Auth::profile_extra`](AUTH.md), for a rarely changed personal
  preference. `examples/auth` does this:

  ```rust
  let auth = Auth::new(db, lockout).profile_extra(|s: ProfileSection| async move {
      auth::profile_card("Timezone", &time::picker(&Tz::from_headers(&s.headers)))
  });
  ```

**Every page shows the zone its times are in.** A navbar picker does that by itself. With the picker
elsewhere, say so on each page, as `examples/auth`'s footer does ("Times are shown in Europe/Prague").
A form's help text names it too (§4).

The zone is a cookie, so it belongs to the **browser**, not the account: two machines in two stations
each keep their own. An app that wants a zone per user stores it itself (§6).

## 4. What follows the zone

Everything the crate renders from a `datetime` column:

| Surface | In the caller's zone |
|---|---|
| a table cell | `2024-12-01 12:00` |
| a form input (`datetime-local`) | pre-filled with the same wall-clock reading, and read back through the zone |
| the form's help text | "Times are Europe/Prague." — so the reading is never ambiguous |
| **a CSV export** | `2024-12-01 12:00`, and re-importing that file means what it says |
| the search box | `2024-12` finds the instants in that month there ([CRUD.md → Search](CRUD.md#search)) |

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

- **Local time, chosen in the browser** (the usual): [`time::JS`] on every page and a picker somewhere.
  A first visit gets the browser's zone; a choice lasts a year and costs no storage.
- **UTC only.** Leave out both: every page renders UTC, labelled UTC. Right for an operations console
  whose logs are UTC too.
- **Store it per user.** Read your own `user.timezone` column in your page handler and pass
  `Tz::named(&user.timezone)` where you would have passed `Tz::from_headers(&headers)`, and set the
  cookie at login with `Tz::cookie()` (a `Set-Cookie` value: path `/`, a year, `SameSite=Lax`) so the
  library's components agree. The crate keeps no per-user state of its own.
- **Follow the server's zone.** `Tz::named(&std::env::var("TZ")?)`, if matching syslog matters more than
  matching the operator.

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

Runnable: `cargo run -p crud-example`, then open **`/event`**: it renders in your browser's zone, and
the navbar picks another. That
table's rows sit either side of both 2026 DST transitions, so a zone that observes DST shows the
January rows an hour off the June ones — from identical stored integers. Editing `Happens at` reads
your typed wall-clock time back in that zone, and **Export CSV** produces a file that says what the
screen says. `examples/adminpanel` wires the same picker into a login-gated app, and `examples/auth`
puts it on the profile page and names the zone in its footer.

[`time::COOKIE`]: https://docs.rs/relativelylight/latest/relativelylight/time/constant.COOKIE.html
[`time::picker`]: https://docs.rs/relativelylight/latest/relativelylight/time/fn.picker.html
[`time::JS`]: https://docs.rs/relativelylight/latest/relativelylight/time/constant.JS.html
