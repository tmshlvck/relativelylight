# Time & timezones

relativelylight's rule for time is one sentence: **the database and every API speak integer Unix
seconds in UTC; timezones exist only for display, and only in the browser.** This keeps the backend
unambiguous (no offsets, no DST folds, trivial comparisons and indexing) while letting the UI show
times in UTC, the viewer's local zone, or a chosen zone.

This document covers the display/conversion functions you call from your pages, the timezone
selection ("store") and how to choose a policy, the picker component, and the (optional) backend
hooks — so you can support a single UTC app, a browser-local app, or a full multi-timezone app
(e.g. civil aviation) without changing the data model.

---

## 1. Storage model (unchanged)

- Store timestamps as **integer columns holding Unix seconds, UTC** (`i64` — keep it 64-bit for
  Y2038). Do **not** use zoned/`DateTime`-with-offset column types for wall-clock instants.
- The CRUD JSON API and your own APIs send/receive these as **JSON integers**. No strings, no
  server-side timezone handling.
- Flag such a column for datetime rendering with
  [`MetaField::datetime()`](CRUD.md#metafield) — it sets `display: "datetime"` in the column
  metadata. Storage, validation, and the OpenAPI schema stay integer; only the UI changes.

Everything below is **frontend**. The server stays UTC-only.

---

## 2. The JavaScript: `time::JS`

`relativelylight::time::JS` is a self-contained script (`assets/rl-time.js`). Include it
**once** in your page shell, as a plain (non-deferred) `<script>` **before** Alpine.js so its store
registers in time:

```html
<script>window.RL_TZ = { mode: 'utc', persist: 'local', withUtc: true };</script>
<script>{{ time_js|safe }}</script>   <!-- pass relativelylight::time::JS into your template -->
<script defer src="…/alpinejs@3…"></script>
```

It exposes three things.

### 2a. `window.RLTime` — pure functions (usable on any page, Alpine or not)

All take a timezone *selection* `sel = { mode, zone }` (see §3); `mode` is `'utc' | 'browser' |
'zone'` and `zone` is an IANA id used when `mode === 'zone'`.

| Function | Purpose |
|---|---|
| `RLTime.fmt(sec, sel)` | `"YYYY-MM-DD HH:MM:SS <TZ>"` in the selected zone. Blank for `null`/`0`. |
| `RLTime.fmtUtc(sec)` | **Always UTC**, regardless of the selection — for the "always show UTC" case. |
| `RLTime.fmtWithUtc(sec, sel)` | Selected-zone time **with the UTC instant in parentheses**: `2026-07-21 23:00:00 GMT+2 (2026-07-21 21:00:00 UTC)`. Drops the parenthetical when the selection already is UTC. |
| `RLTime.toInput(sec, sel)` | Unix seconds → naive `"YYYY-MM-DDTHH:MM:SS"` wall-clock in the zone, for `<input type="datetime-local">`. |
| `RLTime.fromInput(str, sel)` | datetime-local string (a wall-clock in the zone) → Unix seconds UTC. **DST-correct** (two-pass offset resolution). Empty → `null`. |
| `RLTime.resolveZone(sel)` | Selection → concrete IANA id (`'browser'` → `Intl…resolvedOptions().timeZone`, else `'UTC'`). |
| `RLTime.offsetMinutes(zone, sec)` | Zone's UTC offset (minutes) at an instant. |
| `RLTime.ZONES` | The curated zone list (see §4). |

Formatting uses `Intl.DateTimeFormat`, so DST and offsets are handled by the platform. Note the zone
label comes from `Intl` `timeZoneName: 'short'`, which on most engines renders as `GMT+2` rather
than `CEST`; that's cosmetic. Parse-back for a **named** zone does the standard two-pass offset
computation; the `'utc'` and `'browser'` paths are exact and free.

Use these directly in your own templates, e.g. a detail page:

```html
<span x-text="RLTime.fmtWithUtc(flight.etd, $store.tz.sel())"></span>
```

### 2b. `$store.tz` — the current selection (Alpine store, reactive)

| Member | Meaning |
|---|---|
| `$store.tz.mode` / `.zone` | Current selection (reactive — read them in bindings and the UI re-renders on change). |
| `$store.tz.withUtc` | Whether cells should use `fmtWithUtc` (from `RL_TZ.withUtc`). |
| `$store.tz.sel()` | `{ mode, zone }` snapshot to pass to `RLTime.*`. |
| `$store.tz.effective()` | The resolved IANA id / `'UTC'`. |
| `$store.tz.set(mode, zone)` | Change the selection; persists (per `RL_TZ.persist`) and fires `RL_TZ.onChange`. |

`Table` datetime columns already read `$store.tz` internally, so cells and the form picker follow the
selection automatically once `time::JS` is loaded. Without `time::JS`, `Table` falls back to plain UTC.

### 2c. `window.rlTzPicker()` — the picker component (see §4)

---

## 3. Choosing a timezone policy (`window.RL_TZ`)

Set `window.RL_TZ` **before** `time::JS` runs. All fields optional:

```js
window.RL_TZ = {
  mode: 'utc' | 'browser' | 'zone',   // initial selection (default 'utc')
  zone: 'Europe/Prague',              // used when mode === 'zone'
  persist: 'session' | 'local' | null,// remember the picker choice (default: don't)
  withUtc: false,                     // table cells use fmtWithUtc ("local (UTC)") when true
  zones: [ { id, label }, … ],        // override the curated zone list
  onChange: function (sel) { … },     // called after every change (hook for a profile API, §5)
};
```

relativelylight deliberately **does not** store a timezone on `auth_user` or model a user profile —
the policy is yours. The five common shapes, all supported by the same store:

- **(a) Hardcoded UTC.** Do nothing (or `mode:'utc'`), and don't include the picker. Cells/forms are
  UTC. This is teleddns-server today.
- **(b) Browser-local.** `RL_TZ = { mode: 'browser' }`. The platform resolves the viewer's zone and
  handles its DST for free. Optionally still include the picker so users can switch.
- **(c) User-configured, ephemeral per session.** Include the picker with `persist: 'session'` (or
  `null` for per-page). Nothing is stored server-side.
- **(d) User-configured, stored in your app.** Include the picker, and in `onChange` `PUT` the
  selection to *your* endpoint (your model, your column). On page load, read it back and either set
  `RL_TZ.mode/zone` from a server-rendered value or call `$store.tz.set(...)` after load.
- **(e) Server-defined timezone.** Fetch your endpoint (e.g. `GET /api/settings/timezone`) and call
  `$store.tz.set('zone', tz)` on load; optionally hide the picker to force it. Useful when the UI
  should match the server's/syslog's zone.

Policies compose: e.g. default to the server zone (e) but let users override and remember it (d).

---

## 4. The picker component

`relativelylight::time::TzPicker` (rendering `assets/rl-tz-picker.html`) is a Bootstrap dropdown
bound to `$store.tz`: **UTC**, **Local (browser)**, then a curated list of IANA zones covering every
UTC offset from −12 to +14 (one representative each — `Europe/Prague`, `Asia/Tokyo`, …). Drop it into
your shell (needs `time::JS` loaded):

```html
{{ tz_picker|safe }}   <!-- pass relativelylight::time::TzPicker::new().render() into your template -->
```

Replace/extend the list with `RL_TZ.zones` (an array of `{ id, label }`). The component
(`window.rlTzPicker()`) is just a thin wrapper over `$store.tz` — you can build your own dropdown/
typeahead against the store instead.

---

## 5. Backend hooks (optional — usually none needed)

relativelylight provides **no** timezone endpoints, on purpose: most apps need none. When you want
policy (d) or (e), you own the endpoints and wire them via `onChange` (write) and a load-time fetch +
`$store.tz.set()` (read). Keep them tiny — a single string (`"UTC"`, `"browser"`, or an IANA id):

```js
// (d) persist to a profile API
window.RL_TZ = {
  mode: initialFromServer.mode, zone: initialFromServer.zone,
  onChange: (sel) => fetch('/api/me/timezone', {
    method: 'PUT', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(sel),
  }),
};
// (e) adopt the server's zone on load
fetch('/api/settings/timezone').then(r => r.json()).then(tz =>
  Alpine.store('tz').set('zone', tz));
```

If a future need is common enough, a small opt-in helper (a settings endpoint + a nullable `timezone`
column your app adds to its own user model) could live in the app layer — but it stays **out** of the
`auth_user` table and the library core.

The **`examples/time`** app is a runnable version of exactly this: a single-table page that on load
adopts `GET /api/settings/timezone` (server zone) then a `GET /api/me/timezone` "stored preference",
and `PUT`s every user change to the console (`onChange`). A `__rlApplying` flag suppresses the `PUT`
during load-time adoption so the app doesn't echo its own values back.

---

## 6. Reference: the flow for one datetime column

1. Column is `i64` Unix-seconds UTC; marked `MetaField::datetime()`.
2. API sends it as an integer (e.g. `1784668744`).
3. `Table` cell: `RLTime.fmt`/`fmtWithUtc(sec, $store.tz.sel())` → readable string in the selected
   zone (reactive to the picker).
4. Edit form: `RLTime.toInput` fills a `datetime-local` with the zone's wall-clock; on save
   `RLTime.fromInput` converts back to integer UTC seconds. The row's `created_at` etc. are never
   affected by display zone.

Examples:
- **`examples/adminpanel`** — the picker in the navbar over a full admin: `RL_TZ` + `time::JS`,
  read-only auth timestamps, and an editable `post.published_at`.
- **`examples/time`** — the minimal single-table version plus the optional backend hooks (server-TZ
  adoption + a fake per-user TZ endpoint, logging the round-trip to the console).
