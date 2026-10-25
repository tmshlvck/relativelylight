# Relation picker — scratchpad

**Status:** working notes for the next change, not documentation. Nothing links here on purpose; once
the picker ships, its behaviour moves into [CRUD.md](CRUD.md) and this file is deleted.

## The problem

A relation input is a `<select>` (to-one) or `<select multiple>` (to-many) of every target row. That
stops working somewhere past a few dozen rows: nobody scrolls 10 000 options, and the page ships them
all. Above `picker_threshold`, a to-one today becomes a typed-id text box, which asks the operator for
a number they don't know. A to-many has no large form at all.

## The design

**At or below the threshold** (default 20, per `Table`/`Form`): unchanged. A to-one is a `<select>`
and a to-many a multi-select, with every target row as an option.

**Above it**, the field shows:

- the current selection, read-only: one label (to-one) or badges (to-many) in a box that scrolls past a
  fixed height, so 100+ chosen rows still fit;
- one hidden input per chosen id, named after the field, so the form posts the selection exactly as a
  `<select>` would and the decoder doesn't change;
- a magnifier button (inline SVG, `aria-label` and `title` "Edit selection") that opens the dialog.

The field shows the **whole** selection, however large. A chosen row the form left out would be
unlinked by saving it (the bug fixed in `5ff4883`).

**The dialog** is a `<dialog>` holding an `<iframe>` of the target's own table in pick mode, served by
an app route (below). The table brings search, sort and paging. Its links are relative, so they move the
iframe and leave the form alone. Each row has a radio (to-one) or a checkbox (to-many). The dialog's
header, which is parent-page DOM and not part of the iframe, shows the working selection as removable
chips. That is how you remove a row without finding it again on page 40, and how a to-one is cleared.
The footer has **OK** and **Cancel**.

**One script, both cardinalities:**

1. Open: copy the field's selection into a working set (`Map<id, label>`) held by the parent page.
2. Each iframe page load asks the parent for the set over `postMessage`, then ticks the rows in it.
   A toggle sends add/remove back. For a to-one, a pick replaces the set, so it is a set capped at one,
   and that cap is the only difference.
3. **OK** rebuilds the field's badges and hidden inputs from the set (labels set with `textContent`, so
   there is nothing to escape). **Cancel** drops the set; the server-rendered field was never touched.

An empty to-many needs no marker input. The decoder already reads a rendered to-many that posts
nothing as the empty set (`ui/decode.rs`, the `ToMany` branch).

**Without JavaScript**, the field still shows the selection and posts it back unchanged, so a save never
loses a link. The selection can't be changed. The button is hidden until the script runs.

**Security:**

- The pick-mode table is a `Table` render, so it goes through the **target's** read gate. Note that
  today's `<select>` options list target labels *without* that check. Close this gap for the small
  case too, rather than copying it.
- The write path checks every posted id. A to-one already does (`unknown_references` in
  `ui/write.rs`). A to-many needs the same check, because hidden inputs are as editable as a typed id.
- `postMessage` checks `event.origin` against its own origin and `event.source` against the dialog's
  iframe.

## Rust API changes

The components keep their builders and their two handlers. What changes:

| Change | Kind | Notes |
|---|---|---|
| `ui::Picker` | new component | `Picker::new(engine).render_for(&headers, &state) -> Result<String>`. Reads `?pick=post.tag` (source slug, relation name), resolves the relation's target, renders the target `Table` in pick mode. 400 if the relation is unknown. The target's read gate gives 401/403. |
| one app route for it | app wiring | The crate adds no routes, so the app mounts `get(pick)`. The handler wraps the fragment in a **bare** shell of its own: no nav bar, with Bootstrap, `CSS` and `JS`. This is the only new handler, and it is GET-only. |
| `Crud::picker_path("/pick")` | new setting | Declared once, beside `csrf`, so `Table`, `Form` and `Admin` all render the iframe `src` from it. Every href stays relative except this one. |
| `ui::JS` | new const | The picker script, which the app includes once in **both** shells, the same way as `CSS`. A const rather than an inline `<script>`, so an app with a CSP can serve it from a file. |
| `ViewState` | new field | `pick: Option<(String, String)>`, parsed from `?pick=`. The picker's own page, search and sort are ordinary keys, because the iframe has its own URL. |
| `picker_threshold(n)` | changed meaning | Now applies to **to-many** too: above it, the badges and the dialog. The setting stays; the behaviour changes, and gets a CHANGELOG entry. |
| `Widget::Reference` | removed (internal) | Replaced by a `Picked { chosen: Vec<Opt>, many: bool, src }` widget. Not public. |
| `ui/write.rs` | internal | The posted-id check extends to to-many. |

**If `picker_path` is unset**, a relation above the threshold falls back to the full `<select>`, not to an
error. The threshold depends on data, so an error there would break a working page when a table grows.
That fallback is today's to-many behaviour, now applied to to-one as well.

`Admin` needs nothing of its own: its tables render through the same widget code. Its picker handler is
the same `Picker` on its own path.

Example wiring (`examples/crud`):

```rust
crud.picker_path("/pick");
// …
.route("/pick", get(pick))

async fn pick(State(app): State<Arc<App>>, headers: HeaderMap, uri: Uri) -> Response {
    let state = ViewState::from_uri(&uri);
    match Picker::new(&app.engine).render_for(&headers, &state).await {
        Ok(html) => Html(bare_shell(&html)).into_response(), // the app's own <html>, no nav
        Err(e) => e.into_response(),
    }
}
```

## Tests

- `ui_tests.rs`, in the existing style:
  - below/above the threshold for each cardinality;
  - the whole selection is rendered, past any page size;
  - the hidden inputs decode;
  - escaping of badge and chip labels;
  - the picker is refused by the target's read gate (with a positive control);
  - an unknown to-many id is a field error;
  - an unset `picker_path` falls back to a `<select>`.
- Playwright, against `examples/crud` with enough tags and authors to cross the threshold:
  - choose a value, search then choose, page then choose;
  - Cancel leaves the field as it was;
  - a chip removes a row;
  - a save keeps an unchanged selection.

## Open

- **The threshold default.** 20 or 50?
- **The dialog on a phone.** Make it full-screen below a breakpoint?
- **The datalist tier** (`git stash`, "datalist tier"): drop it. The picker covers the case it was a
  shortcut for.
- **Later, separately:** split `Table` into smaller pieces (`List`, `Search`, `FilterSelect`, the write
  actions) with `Table`/`Admin` as thin presets over them, so each control owns its `<form>` and a
  setting can't mean two things. That is not part of this change.
