# `relativelylight::chart` — server-rendered SVG charts — DRAFT SPEC

Status: **not implemented, and not yet agreed.** Written against a downstream dashboard
(teleddns-server) that already runs a crude version of this by hand, so §§2–5 describe a shape that
has been used rather than one imagined. §8 argues about whether to build it at all, and does not
assume yes.

## 1. Purpose & scope

A back-office has a dashboard, a dashboard has three or four small charts, and today the only
options are a JavaScript charting library — a CDN script on a page that holds an admin session, or
200 KB vendored — or hand-rolled SVG per app. Neither is right for the shape of chart a back-office
actually shows: a handful of series, tens to low hundreds of points, drawn once per page load from
data the server already has in memory.

This module renders that chart to an SVG fragment, server-side, in the same idiom as
[`crud::ui`](CRUD.md): typed builders, a `render()` that returns HTML, no JavaScript, no client
state, and **render-time refusals** rather than a picture that silently misleads.

**In scope**

- **Bar charts** — categorical, one value per bar, optional value labels.
- **Line charts** — one or more series over a shared, ordered x-axis; dots optional.
- **Scatter plots** — one or more series of unordered `(x, y)` points.
- Numeric and **time** axes, the latter formatted through [`time::Tz`](TIME.md) so a chart agrees
  with every other timestamp on the page.
- A colour legend, shared across series.
- Light and dark themes from one render.

**Out of scope, deliberately**

- **Interaction of any kind**: no tooltips, no hover, no zoom, no pan, no click-to-toggle. These need
  a client runtime, and the moment one exists the argument for this module collapses — use a
  charting library instead. See §8.
- Pie and donut charts. They are hard to read and easy to mislead with; a bar chart is the honest
  form of the same data.
- Stacked and 100 %-stacked variants, at least in v1.
- Real-time streaming, animation, transitions.
- Thousands of points. §6 gives the ceiling and what happens above it.

## 2. Design tenets

1. **A chart that cannot be drawn honestly is refused, not approximated.** The crate already works
   this way — an unsortable `sort`, a widget that cannot render its column ([CRUD.md § Refusals, not
   surprises](CRUD.md)). A chart with 400 category labels in 700 px does not get a smear of
   overlapping text; it gets an `Err` naming the problem.
2. **One shared y-axis per chart.** Multiple y-axes invite the reader to compare two series that are
   not comparable. An app that wants per-series scales renders *several charts* — small multiples —
   which this module makes cheap, and which is what the downstream dashboard ended up doing by hand
   after a shared axis made its quiet series unreadable.
3. **The server already has the data.** No `<script>`, no JSON blob in the page, no endpoint. The
   fragment is complete when it leaves the handler.
4. **Themes are the page's business.** Axes, gridlines and text use `currentColor` with opacity, so
   they follow the surrounding Bootstrap colour mode; only series colours are fixed, from a palette
   picked to be legible on both.
5. **Text metrics are estimated, and that is a documented limitation** — not a bug to be chased. See
   §6.

## 3. Rust API

One entry type, three constructors, a builder each.

```rust
use relativelylight::chart::{Chart, Series, Axis, Palette};

// ---- bars -------------------------------------------------------------
let svg: String = Chart::bars([("A", 12.0), ("B", 7.0), ("C", 19.0)])
    .y(Axis::new().label("writes"))
    .value_labels(true)          // print the number on/above each bar
    .size(720, 200)
    .render()?;

// ---- lines ------------------------------------------------------------
let svg = Chart::xy()
    .series(Series::line("DDNS", &ddns_points))
    .series(Series::line("API", &api_points).dots(true))
    .x(Axis::time(&tz).label("last 6 hours"))
    .y(Axis::new().label("writes / 5 min").min(0.0))
    .legend(true)
    .render()?;

// ---- scatter ----------------------------------------------------------
let svg = Chart::xy()
    .series(Series::scatter("latency", &points))
    .x(Axis::new().label("zone size (records)"))
    .y(Axis::new().label("push seconds"))
    .render()?;
```

`render()` returns `Result<String, chart::Error>`; the string is an `<svg>` element and nothing else,
so it drops into a template beside anything.

### 3.1 `Chart`

| Builder | Effect |
|---|---|
| `Chart::bars(impl IntoIterator<Item = (impl Into<String>, f64)>)` | categorical bars |
| `Chart::xy()` | an empty line/scatter chart; add `series` |
| `.series(Series)` | add a series (xy only); repeatable |
| `.x(Axis)` / `.y(Axis)` | axis configuration |
| `.size(w, h)` | user-space size; the SVG still scales to its container via `viewBox`. Default `720 × 200` |
| `.legend(bool)` | show the colour legend (default: on when more than one series) |
| `.palette(Palette)` | series colours (default: `Palette::default()`, 8 entries, theme-safe) |
| `.value_labels(bool)` | bars only: print each value |
| `.title(&str)` | `<title>` — the accessible name, and a browser tooltip for free |
| `.describe(&str)` | `<desc>` — the long text for a screen reader |
| `.empty_message(&str)` | what to draw when there is no data at all (default: "no data") |

### 3.2 `Series`

```rust
Series::line(name, &[(f64, f64)])      // connected, x-ordered
Series::scatter(name, &[(f64, f64)])   // dots, unordered
```

| Builder | Effect |
|---|---|
| `.dots(bool)` | line only: also mark each point (default off) |
| `.area(bool)` | line only: fill to the baseline at 18 % opacity (default off) |
| `.colour(&str)` | override the palette for this series |
| `.width(f32)` | stroke width in user units (default `1.5`) |
| `.dashed(bool)` | dashed stroke — the honest way to separate two series that overlap (§5.3) |

A `line` series is **sorted by x at render time**, and duplicate x values are an error
(`Error::DuplicateX`) rather than a line that doubles back on itself.

### 3.3 `Axis`

| Builder | Effect |
|---|---|
| `Axis::new()` | a numeric axis, auto-scaled to the data |
| `Axis::time(&Tz)` | x values are Unix seconds; ticks are wall-clock, formatted in that zone |
| `.label(&str)` | the axis caption |
| `.min(f64)` / `.max(f64)` | pin an end. **`y.min(0.0)` is worth making a habit** — a bar chart or a count chart whose y-axis does not start at zero exaggerates every difference on it |
| `.ticks(usize)` | *target* tick count (default 5); the "nice number" search picks the nearest pleasant interval, so the result may be 4 or 6 |
| `.format(impl Fn(f64) -> String)` | tick label rendering — bytes, percentages, durations |
| `.grid(bool)` | gridlines at the ticks (default: on for y, off for x) |

### 3.4 Errors

`chart::Error` is `IntoResponse` like `crud::Error`, but an app will normally handle it itself
because a failed chart should not fail a page.

| Variant | When |
|---|---|
| `NoSeries` | `Chart::xy()` with nothing added |
| `DuplicateX(name, x)` | a line series has two points at one x |
| `NonFinite(name)` | NaN or infinity in the data |
| `TooManyCategories { got, max }` | bar labels cannot fit the width (§6) |
| `TooManyPoints { got, max }` | past the render ceiling (§6) |

Empty data is **not** an error: a chart with zero points renders axes and `empty_message`, because a
dashboard panel that vanishes when a number goes to zero is worse than one that says "no data".

## 4. Output

```html
<svg viewBox="0 0 720 200" width="100%" height="200" role="img" aria-labelledby="c1t c1d"
     preserveAspectRatio="xMidYMid meet" class="rl-chart">
  <title id="c1t">Writes per 5 minutes</title>
  <desc id="c1d">Four series over six hours; peak 11.</desc>
  <g class="rl-chart-grid">…</g>
  <g class="rl-chart-axes">…</g>
  <g class="rl-chart-series" data-series="DDNS">…</g>
  …
</svg>
```

- **`viewBox` + `width="100%"`** so it fills its container with no measurement and no resize handler.
- **`vector-effect="non-scaling-stroke"`** on every stroke, so lines keep their width after the
  browser scales the box.
- **`currentColor`** for axes, gridlines and text; series colours are explicit.
- Class hooks (`rl-chart-*`) so an app can restyle without forking the renderer.
- No `<style>`, no `<script>`, no external references: the fragment is safe to inline anywhere,
  including inside a CSP that forbids both.

## 5. The parts that are actually hard

Not the drawing. The drawing is a hundred lines. These are the reason this is a module rather than a
snippet.

### 5.1 Nice tick intervals

Given a range of `0 … 4237`, ticks belong at `0, 1000, 2000, 3000, 4000` — not at `0 … 4237` in five
equal steps. The standard answer is Heckbert's *nice numbers* (round the raw interval to the nearest
1, 2, 2.5 or 5 × 10ⁿ). Thirty lines, and it has to survive: a zero-width range, an all-zero series, a
single point, negative values, and ranges spanning many orders of magnitude.

**Time ticks are a different algorithm** — the pleasant intervals are 1/5/15/30 s, 1/5/15/30 min,
1/3/6/12 h, 1 day, 1 week — and they must be *aligned* to the boundary (a tick at 14:00, not 14:03),
which needs the timezone, which is why `Axis::time` takes a `Tz`.

### 5.2 Text width, which SVG will not tell you

Laying out a y-axis needs the width of the widest tick label *before* rendering, to size the left
margin. SVG has no measurement and the server has no font metrics. Everyone solves this by
estimating — roughly `0.6 em` per character for a proportional sans — and everyone is sometimes
wrong: a long label overflows or a margin is too generous.

This is **the** structural limitation of server-side charts, and the one honest answer is to bound
the problem: estimate, then refuse when the estimate says the labels cannot fit (§6). A client-side
library measures for real, and that is a genuine advantage it has.

X-axis labels have the same problem plus collision: 72 time labels do not fit in 700 px, so ticks
must be thinned to the largest count whose estimated widths do not overlap.

### 5.3 Overlapping series — a recorded decision, not a feature

The obvious request is to nudge coincident points or lines apart so both are visible. **This module
will not do that for lines.** Moving a line changes the value it depicts; a reader has no way to know
the chart is lying and no way to know by how much. Two lines at the same value should be separated by
*rendering*, not by geometry:

- `.dashed(true)` on one of them — the overlap is then visible as an alternating stroke;
- partial opacity, which the palette already applies to areas;
- or, if the series genuinely need separate scales, **two charts**, per tenet 2.

For **scatter** plots, jitter is a legitimate and long-established technique for showing density in
discrete data — but it must be opt-in and named for what it is: `.jitter(f64)` on a scatter series,
documented as "displaces points by up to ±n user units to reveal overlap; the chart is then not
readable for individual values". Never a default.

### 5.4 Degenerate data

Each needs a decided answer, and each is a test: no points; one point (no range — pick a unit
interval around it); all y identical (a flat line at mid-height, not a divide-by-zero); all zero;
negative values with `min(0.0)` pinned; one series empty among several.

## 6. Limits

Server-side rendering costs bytes in the HTML, not client CPU. The ceilings are about legibility
first and page weight second.

| | Limit | Above it |
|---|---|---|
| Points per series | **2 000** | `Error::TooManyPoints` — aggregate first; a 700 px chart has ~700 columns of pixels |
| Series | **12** | refused; a legend past a dozen entries is a table |
| Bar categories | width-dependent, ~40 at 720 px | `Error::TooManyCategories`, naming the width it would need |

A 4-series, 72-point line chart is about **6 KB** of SVG — the size of a small image, and it
compresses well. The same chart through Chart.js is ~200 KB of library plus the data.

## 7. Worked example — the teleddns dashboard

The chart this spec was extracted from. Today it is ~90 lines of bespoke Rust plus 40 of template in
the app; here it is the same picture, as small multiples, with axes it currently lacks:

```rust
let mut panels = Vec::new();
for (name, values) in activity_series {
    let points: Vec<(f64, f64)> =
        values.iter().enumerate().map(|(i, v)| (bucket_time(i) as f64, *v as f64)).collect();
    panels.push(
        Chart::xy()
            .series(Series::line(name, &points).area(true))
            .x(Axis::time(&tz).ticks(6))
            .y(Axis::new().min(0.0).ticks(3).label("per 5 min"))
            .size(720, 40)
            .title(&format!("{name}: writes per 5 minutes"))
            .render()?,
    );
}
```

One chart per surface, each on its own scale — tenet 2 — which is exactly what that dashboard
arrived at independently.

## 8. Is this worth building?

The honest argument, both ways. **No conclusion is assumed; this section exists to be disagreed
with.**

### For

- **It is the only option that fits the crate's thesis.** 0.3 removed the JSON API and the JavaScript
  framework on the grounds that a back-office does not need a client runtime. Recommending Chart.js
  for the dashboard reintroduces one through the side door.
- **No third-party script on an authenticated page.** A CDN charting library executes with the
  operator's session; Subresource Integrity mitigates that but does not remove the dependency, and an
  admin console on a management network may have no egress at all.
- **It prints.** SVG survives print-to-PDF and email; `<canvas>` frequently does not.
- **The data is already on the server.** Shipping it to the browser to be drawn is a round trip of
  numbers that were in hand.
- **The scope above is genuinely small.** Three chart types, no interaction, hard ceilings.

### Against

- **Tooltips are the feature people actually want from a chart**, and they cannot be had without a
  client runtime. Every "can you make it show the value on hover?" is unanswerable, forever. That is
  a real product ceiling, not a v1 gap.
- **Text metrics (§5.2) cannot be solved properly server-side.** The design copes by refusing, which
  means some legitimate charts are refused.
- **It is not small in the way the drawing is small.** Realistically **600–900 lines** plus a test
  suite, in a crate whose pitch is that it is small. Nice ticks, time ticks, label thinning, legend
  layout, degenerate data and the refusals are most of it; the polylines are a morning.
- **Charting is a bottomless backlog.** Log scales, stacking, annotations, error bars, dual ranges,
  thresholds — each individually reasonable, and there is no natural line where "just one more" stops.
- **The alternative is 20 lines.** A CDN tag with SRI and a JSON literal in the page, and you get
  tooltips, legends and zoom for free.

### Recommendation

**Build it only if the no-JavaScript property is a requirement rather than a preference.** For
`relativelylight` it plausibly is — that is the whole premise of 0.3 — and if so, the scope in §1 is
defensible *because* it is narrow and refuses rather than degrades.

If the answer is anything softer than that, the better move is:

1. Keep the app-side SVG where it is (it is 90 lines and it works), and
2. Let apps that want interaction reach for Chart.js from a CDN with SRI, documented in
   [APP.md](APP.md) as the supported way to add a chart — a *viewer*, like Swagger UI, not a
   framework the pages are built from.

The middle path worth considering if the appetite is small: **ship `bars` only.** It is a third of the
work (one categorical axis, no time ticks, no legend, no overlap problem), it is the chart a
back-office reaches for most — counts by category — and it defers every hard decision in §5 except
nice ticks. If `bars` proves useful and `xy` is still wanted afterwards, that is evidence rather than
a guess.

## 9. Open questions

- Should `Chart` render to a `String`, or to an askama-friendly type implementing `Display`? The rest
  of `ui` returns `String`; consistency says `String`.
- Is `Palette` shared with anything else, or chart-local? Nothing else in the crate colours anything.
- Do small multiples deserve a `Grid` helper that renders N charts with one shared x-axis and one
  legend, or is a `for` loop in the app enough? The teleddns dashboard suggests a loop is enough.
- Feature name and gating: `chart`, implying nothing, usable without `ui`?
- Does anything want a **table fallback** rendered beside the chart for screen readers, or is
  `<title>` + `<desc>` + the app's own table (as teleddns already does) sufficient?

## 10. Reading

- Heckbert, *Nice Numbers for Graph Labels*, Graphics Gems (1990) — the tick algorithm in §5.1.
- [CRUD.md § Refusals, not surprises](CRUD.md) — the precedent for tenet 1.
- [TIME.md](TIME.md) — `Tz`, which `Axis::time` formats through.
