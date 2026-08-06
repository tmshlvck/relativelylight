# Sorting by relation label + predefined relation filters

> **Status: implemented and shipped for 0.2.1.** This file is kept as the design record — the analysis
> of *why* the shape is what it is (the bracket namespace, the label probe, the primary-key tiebreaker)
> is the part worth having later. See `CHANGELOG.md` § Unreleased for what landed and
> [docs/CRUD.md](docs/CRUD.md) for how to use it. Decisions taken against §5: bracket spelling
> `filter[…]` / `search[…]` spelled out rather than `f[…]`; bare `?<col>=` on a non-text column **(b)
> rejected** with a plain 400; label column **auto-detected** by probing `row_label`, with
> `label_column` as the explicit form; the ordering fix taken; `teleddns-server` wired in the same pass.

Analysis and implementation plan for two requests from the downstream `teleddns-server` console:

1. **Sort the RR tables by most columns, including the `zone` column** — which is a to-one relation, so
   what's wanted is a sort by the *relation-derived label* (the string actually shown in the cell), not
   by the FK id.
2. **Pre-defined filters by zone on the RR tables** — an operator normally works inside one zone and
   wants to see and edit only the records of a given type belonging to it.

Status: **neither works today**; both are cheap; the FK-filter path also uncovers a real bug worth
fixing on its own merits. File/line references are against `main` at `aef834a` (v0.2.0).

---

## 1. Sorting

### 1a. What exists

The **API** sorts, the **UI** does not.

- `?sort=views:desc,title` is parsed in `parse_list_query` (`relativelylight/src/crud/engine.rs:920`)
  into `ListQuery::sort: Vec<(String, bool)>` (`engine.rs:307`), multi-key, `:desc` suffix optional.
- The SeaORM backend applies it at `relativelylight/src/crud/seaorm.rs:1143`:

  ```rust
  for (name, desc) in &q.sort {
      let c = column::<E>(name)
          .ok_or_else(|| Error::BadRequest(format!("unknown column: {name}")))?;
      sel = sel.order_by(c, if *desc { Order::Desc } else { Order::Asc });
  }
  ```

  `column::<E>()` (`seaorm.rs:356`) resolves a **real column of this entity**, case-insensitively.
  Anything else is a 400. It is whitelisted and safe, but strictly per-entity-column.
- The admin table has **no sorting at all**: headers are static text
  (`relativelylight/templates/table.html:55-57`) and `load()` sends only `page` / `per_page` / `q`
  (`table.html:200-212`). CSV export (`table.html:333`) likewise carries only `q`.

So even sorting an RR table by `name`, `ttl` or `value` — plain columns — needs the UI half built. That
part is small, but it is not free today.

### 1b. Why the relation label can't be sorted on

The label is computed **in Rust, after the rows are fetched**:

- listing rows: `let label = (self.model.row_label)(&raw);` — `seaorm.rs:916`
- relation cells: `resolve()` (`seaorm.rs:943`) reads the FK, fetches the target row, and calls
  `link()` → `t.label_of(raw)` → `(self.model.row_label)(raw)` (`seaorm.rs:1025`)
- `RowLabel = Box<dyn Fn(&Value) -> String + Send + Sync>` (`seaorm.rs:40`), defaulting to
  `default_label` which probes `name` / `title` / `username` / `bio` / `label` and falls back to `#id`
  (`engine.rs:405`).

An arbitrary Rust closure over a JSON row is not expressible as SQL, and the ordering happens in the
database before those closures ever run. Downstream, `zone`'s label is exactly such a closure —
`teleddns-server/src/web.rs:142`:

```rust
z.row_label = Box::new(|row| row["origin"].as_str().unwrap_or_default().to_string());
```

Sorting the RR list by that label means `ORDER BY zone.origin`, which needs (a) a join and (b) the
library knowing that `origin` is the label column. Neither exists.

### 1c. Proposed design — declare the label column, join, order

**Declare it.** Add to `MetaModel`:

```rust
/// The single column the row label is read from. Sets `row_label` to read that column *and*
/// records the name, so a relation pointing here becomes sortable in SQL.
pub fn label_column(&mut self, col: &str) -> &mut Self
```

Downstream this *replaces* the closure they already write — one line, not an extra one:

```rust
z.label_column("origin");   // instead of z.row_label = Box::new(|row| …);
```

A model that keeps a hand-written closure (two columns concatenated, a formatted value) simply has no
declared label column, reports `sortable: false` for relations pointing at it, and 400s an attempt.
Guessing an SQL expression for an opaque closure would produce an order nobody can predict; refusing is
the honest answer. `MetaModel::new` may additionally *auto-detect* the default case: if `row_label` was
never overridden, `default_label`'s probe order is deterministic, so the first of
`name`/`title`/`username`/`bio`/`label` that exists **as a column** is the effective label column and
can be recorded at construction. That makes most models sortable-by-relation with no code at all.

**Join it.** `MetaRelation` already carries everything the join needs — `target` (table),
`from_col`, `to_col`, `owns_fk`, `cardinality` (`seaorm.rs:833-855`, built by `introspect_relations`).
So for `?sort=zone`:

```sql
SELECT rr.* FROM rr_a rr
LEFT JOIN zone ON rr.zone_id = zone.id
ORDER BY zone.origin ASC
```

built with a `sea_query` join on the target table plus `order_by` on a qualified `Expr::col`. No typed
relation handle is needed, so it works for any `E` the generic accessor is instantiated with.

**Pagination survives it.** A to-one join cannot multiply rows (the FK points at a unique key), and
SeaORM's paginator counts through a wrapped subquery, so `total` stays correct. The join must be added
to the `list` query only — `delete_many` (`seaorm.rs:1277`) never sorts.

**Scope: to-one owning the FK only.** For an inverse to-many or an N:M, a row has *many* labels; an
order would need a correlated `MIN(label)` subquery per row and the semantics are arguable ("sort the
posts by their tags" — which tag?). Those report `sortable: false` and 400 on an explicit attempt.
That covers `zone` on every RR table, which is the actual request.

**Metadata.** `Column::Field` / `Column::Relation` (`engine.rs:238-292`) gain a `sortable: bool` so the
UI knows which headers are clickable, and OpenAPI can describe the allowed `sort` values.

### 1d. UI

- `<th>` becomes a button for `sortable` columns: click cycles asc → desc → off, with a ▲/▼ indicator;
  shift-click appends a secondary key (the API already takes a list).
- `Table` holds `sort` state, sends it from `load()`, `exportUrl()` (so a CSV export matches what's on
  screen), and resets to page 1 on change.
- `Table::sort("zone")` / `.sort_desc("ttl")` sets the initial order.

### 1e. Pagination is not deterministic today, and sorting makes that visible

`list` applies only `q.sort` and nothing else (`seaorm.rs:1142-1147`) — there is no fallback `ORDER BY`.
An unordered `LIMIT`/`OFFSET` scan has no guaranteed row order, so paging a table can in principle
repeat a row on page 2 that already appeared on page 1, and skip another entirely. Today this is mostly
masked: a simple SQLite scan comes back in rowid order.

Adding clickable headers removes the mask, because the natural thing to sort an RR table by is a
**low-cardinality** column. `ORDER BY ttl` over ten thousand records that nearly all share `ttl = 3600`
leaves the database free to return the ties in any order it likes, and it need not pick the same order
for the query that fetches page 1 and the query that fetches page 2. Rows then genuinely duplicate and
vanish between pages.

The fix is one line and belongs in this change: **always append the primary key as the final sort key**,
after whatever the caller asked for. The PK is unique, so it makes every ordering total and every page
boundary stable, and it costs nothing when the caller already sorted by a unique column.

Two smaller ordering choices come with it:

- **NULLs.** SQLite sorts `NULL` first on `ASC`; PostgreSQL sorts it last. A row with no `zone` would
  therefore land at a different end of the list depending on the backend. Proposal: emit an explicit
  `NULLS LAST` (SeaORM's `order_by_with_nulls`) so the two agree.
- **Collation.** Text ordering follows the database's collation — SQLite's `BINARY` puts `Zone` before
  `alpha`, PostgreSQL follows the locale. Proposal: leave it to the database and document it. Wrapping
  the sort key in `LOWER()` would make it uniform but defeats the index, which on a large RR table is
  the wrong trade. (Downstream this is moot: `origin` is lowercased on write —
  `teleddns-server/src/web.rs:133`.)

### 1f. Effort

Roughly a day: `label_column` + auto-detect + `sortable` metadata (½), join + order-by + backend tests
(½), clickable headers + state + export (½), docs/example (½).

---

## 2. Pre-defined filters

### 2a. What exists — and the bug

**Exact-match filtering is not reachable over HTTP at all, and the fallback is wrong.**

`ListQuery::eq` exists (`engine.rs:303`) and the backend implements it correctly, converting the string
to the column's DB type (`seaorm.rs:892-896`):

```rust
for (name, val) in &q.eq {
    let c = column::<E>(name)…;
    cond = cond.add(c.eq(str_to_db(c.def().get_column_type(), val)));
}
```

…but **nothing ever populates it**. `parse_list_query`'s catch-all arm sends every unrecognized
parameter to `search` instead (`engine.rs:929`):

```rust
_ => q.search.push((Some(key), value)),
```

and `build_condition` turns that into a substring match (`seaorm.rs:874-880`):

```rust
Some(name) => { let c = column::<E>(name)…; cond = cond.add(c.contains(pat)); }
```

Consequences today:

- `GET /api/v1/rr_a?zone_id=3` is `zone_id LIKE '%3%'` — it also matches zones **13, 30, 103, 313**.
- On PostgreSQL, `LIKE` against an `integer` column is a **type error**, so the same request 500s
  rather than answering wrongly. It only "works" on SQLite because of its loose typing.

`ListQuery::eq` is therefore reachable only by a Rust caller building a `ListQuery` by hand. This is a
bug independent of the feature request.

The UI has no filter concept either: no state, and nothing in `load()`, `exportUrl()` or
`deleteAllMatching()` (`table.html:200`, `333`, `242`).

### 2b. Query-parameter namespace — is bare `?<col>=<val>` safe?

**No. It is already unsafe, and it should not be extended.** The reserved set is matched *before* the
catch-all, in `parse_list_query` (`engine.rs:910-930`):

| Reserved key | Meaning |
|---|---|
| `page`, `per_page` | pagination |
| `q` | full-text search |
| `sort` | ordering |
| `ids` | `pk IN (…)` |
| `all` | unpaginated / permit whole-table delete |
| `view` | `terse` |
| `format` | `csv` |

An entity with a column named any of those is **silently shadowed today**: a CMS with a `page` column,
a media table with a `format` column, a report with a `sort` or `all` column. `?format=csv` on such a
table returns CSV instead of filtering; `?page=3` paginates instead of matching. It fails quietly, and
the column names involved are not exotic. Worse, `column::<E>()` matches **case-insensitively**
(`seaorm.rs:357`), so `Format`, `ALL` and `Sort` collide too.

The teleddns RR tables happen to be clear (`name`, `ttl`, `value`, `priority`, `weight`, `port`,
`flags`, `tag`, `algorithm`, …) but that is luck, not a guarantee — and the library is generic.

So the filter keys need their own namespace. Three candidate spellings were considered.

Note first that a word prefix is not broken by the *nesting* case — a column genuinely named
`fltr_zone` would be addressed as `?fltr_fltr_zone=`, which is ugly but unambiguous. The problem runs
the other way: as long as the legacy bare `?<col>=<val>` form survives, `?fltr_zone=x` is ambiguous
between "substring-search the column `fltr_zone`" and "filter the column `zone`", and the parser must
silently pick one. A separator that **cannot occur in the names being matched** removes the ambiguity
by construction rather than by convention:

- Relation names are derived from Rust enum variants — `format!("{r:?}").to_lowercase()`
  (`seaorm.rs:843`) — so they are always identifiers: `[a-z0-9_]+`.
- Column names come from SeaORM's `IdenStatic::as_str()`, in practice the Rust field name or a
  `#[sea_orm(column_name = "…")]` override — an SQL identifier, which contains a dot or a bracket only
  if it is quoted everywhere, which nothing else in this crate supports anyway.

#### Candidate A — dot prefix, `?f.zone=7`

Collision-proof, terse, extends to `f.ttl.gt=300` later.

#### Candidate B — value-encoded, `?f=zone=example.com&f=ttl=3600`

Fixed parameter names, so no namespace question can ever arise. But:

- **It does not work with the current extractor.** The list handler takes
  `Query<HashMap<String, String>>` (`engine.rs:939`), and a `HashMap` silently keeps only the last of a
  repeated key. Verified against the pinned `serde_urlencoded` 0.7.1: `f=a&f=b&x=1` deserializes to
  `{"x": "1", "f": "b"}` — the first filter is dropped without an error. Supporting repeated keys means
  switching to `Query<Vec<(String, String)>>` (which does preserve order and duplicates — also verified).
  That change is small and worth making regardless (see below), but it is a prerequisite here, not a
  detail.
- Toggling one filter client-side becomes "rebuild the whole `f` list" instead of one `set`/`delete` on
  one key — and a per-filter toggle is exactly what the Admin-wide zone selector does.
- It nests a second mini-grammar inside a value, where the query string already provides one. Escaping
  then becomes *our* problem: a filter value containing `&`, `+` or `%` has to be encoded by hand
  correctly on both sides, instead of `URLSearchParams` doing it. Splitting on the first `=` handles the
  inner separator (`f=zone%3Dexample.com` decodes to `("f", "zone=example.com")`), but every other
  metacharacter is a new opportunity to get it subtly wrong.
- Harder to read in a log, harder to hand-write with `curl`.
- No OpenAPI benefit: it is still a free-form string as far as the schema is concerned.

#### Candidate C — bracket form, `?f[zone]=7` ← **recommended**

Same collision-proof guarantee as the dot, plus one thing neither other candidate has: **it is the only
spelling OpenAPI 3.1 can describe natively.** `ParameterStyle::DeepObject` exists in the pinned utoipa
5.5.0 (`utoipa-5.5.0/src/openapi/path.rs:869`, with `ParameterBuilder::style()` at `:795`) and renders
exactly as `f[zone]=7`. Declaring one `f` parameter with `style: deepObject` and an object schema means
the Swagger UI this project already ships at `/docs` renders a real filter input, instead of the
convention living only in prose that a generated client cannot see.

```
GET /api/v1/rr_a?f[zone]=7&sort=name         # every A record in zone 7, by name
GET /api/v1/rr_a?f[ttl]=3600
```

- Provably free of collisions with column and relation names, forever, whatever an app calls its
  columns — no reserved-word list to maintain, and no future feature that can steal a name back.
- Familiar: the same convention as JSON:API, Rails and PHP, so it reads as intentional rather than
  bespoke.
- Maps 1:1 onto the front-end's `URLSearchParams`: `p.set("f[zone]", id)` to apply,
  `p.delete("f[zone]")` to clear. That *is* the Admin shared-filter toggle.
- Nests for operators later without another namespace decision: `f[ttl][gt]=300`, `f[name][in]=a,b,c`.
- Percent-encoded brackets (`f%5Bzone%5D=7`) are decoded by `serde_urlencoded` before the key is
  matched, so a client that escapes them still works.
- Symmetrically, `?s[<col>]=<term>` becomes the explicit spelling of the existing substring search, so
  `q` (all text columns) and `s[name]` (one column) are stated rather than inferred.
- An unknown name inside `f[…]` / `s[…]` is a 400, not a silently ignored parameter.

**Relation names are accepted, not just columns.** `f[zone]=7` on an RR table matches the relation
`zone`, resolves to its FK column `zone_id`, and emits `zone_id = 7`. That is what the UI sends, and it
keeps the caller in the vocabulary the `_meta` document publishes rather than requiring them to know
the FK column name.

**Companion fix: repeated keys.** Independently of which candidate wins, `Query<HashMap<String, String>>`
means `?name=a&name=b` today silently drops one condition, even though `ListQuery::search` is a `Vec`
built to hold several. Switching the two list handlers to `Query<Vec<(String, String)>>` fixes that and
costs a few lines.

**The bare form.** Keep `?<col>=<val>` working as the substring search it is today, documented as the
legacy spelling of `s[<col>]`. On a **non-text** column, where it is broken in both directions today
(wrong matches on SQLite, a 500 on PostgreSQL), there are three defensible options — see §4 and
decision 2 in §5.

### 2c. UI

- **`Table::filter("zone")`** — a filter control in the toolbar next to the search box. It reuses the
  existing relation-picker machinery verbatim: `fetchOptions` (`_form_core.html:103`) already fetches
  one threshold-sized terse page and picks a plain `<select>` below `picker_threshold` or a
  search→select combobox above it (`_form_core.html:110-128`). A zone list of any size is handled with
  no new code. Selecting a value sets `f[zone]` and reloads at page 1; clearing removes it.
- The filter must be threaded through **`load()`, `exportUrl()` and `deleteAllMatching()`** — so a CSV
  export matches what is on screen and "Delete all matching" means *this zone*, not the whole table.
  That last one is the reason to do this in the library rather than by hand downstream: a filter the
  bulk-delete path forgets is a foot-gun with real consequences.
- **`Table::fixed_filter("zone", id)`** — the same restriction, applied server-side at render and not
  user-changeable, for a per-zone page (`/zone/{id}/records`). Note this is a **UI convenience, not an
  authorization boundary**: the API remains queryable for other zones by anyone the model's gate
  admits. Per-zone *authorization* stays the app's `Authz` implementation.
- **Admin-wide shared filter** — `Admin::filter("zone")`: pick a zone once in the side panel and every
  registered table that has a `zone` relation filters to it; tables without one ignore it. An Alpine
  store, the same shape as the existing `$store.tz` used by `TzPicker`
  (`relativelylight/assets/rl-time.js:196`), with the selection persisted in `localStorage` and
  reflected in the URL hash so a filtered view can be bookmarked and shared. **With 15+ RR tables in
  teleddns this is the part that makes the feature usable** — a per-table dropdown would mean
  re-selecting the zone on every type switch.
- **Create-form prefill** — when a filter is active on a relation, the create modal pre-selects that
  value for the FK. Adding a record to the zone you are looking at should not require picking it again.
  It only *pre-selects*: the dropdown still offers every zone, because "I filtered the list" is not
  "I may only ever create here".

### 2c-i. Behaviour details worth settling

- **A filter must never be invisible.** A filtered table that looks like an unfiltered one is how a user
  concludes their records were deleted. Both `filter` and `fixed_filter` render a visible chip
  (`zone: example.com. ✕`, without the ✕ when fixed), and the empty state says "No rows *in this zone*"
  rather than "No rows".
- **Persistence.** Proposal: the URL hash is authoritative, so a filtered view can be pasted to a
  colleague; `localStorage` seeds it when the hash is absent. Both are visible in the chip above, which
  is what makes a filter restored from a previous session safe rather than baffling.
- **Empty value = `IS NULL`.** `?f[zone]=` matches rows whose FK is null ("records with no zone"), which
  the `eq` path cannot otherwise express. Clearing the filter in the UI *deletes* the key rather than
  sending it empty, so the two cases stay distinct.
- **Single value for now.** `f[zone]=1&f[zone]=2` (or a comma list) meaning `IN (…)` is left for the
  operator grammar; the repeated-key extractor fix makes it possible later without another decision.
- **The bulk-delete guard already covers this.** `has_filter` counts `q.eq` (`engine.rs:771`), so a
  filtered "Delete all matching" deletes only the filtered set and does not require `?all=true` — while
  an unfiltered one still does.

### 2d. Effort

- API: `f[…]` / `s[…]` parsing, repeated-key extractor fix, relation-name → FK resolution, 400 on
  unknown name, OpenAPI `deepObject` parameters, backend tests — ~½ day.
- `Table::filter` / `fixed_filter` + threading through load/export/bulk-delete — ~1 day.
- `Admin::filter` shared store + URL hash + create prefill — ~1 day.
- Docs, example, `CHANGELOG.md` — ~½ day.

---

## 3. Implementation plan (ordered)

Each step is independently shippable and leaves the tree green.

1. **Filter parsing** — `engine.rs`: `f[<name>]` → `ListQuery::eq`, `s[<name>]` → `search`, unknown
   name → 400; switch the list and bulk-delete handlers to `Query<Vec<(String, String)>>` so repeated
   keys survive; declare `f` / `s` as `deepObject` parameters. *Files:* `crud/engine.rs`,
   `crud/openapi.rs`.
2. **Relation-name filters** — `seaorm.rs`: resolve an `eq` key that names a to-one relation to its FK
   column before `column::<E>()`. *Files:* `crud/seaorm.rs` (`build_condition`).
3. **`label_column` + auto-detect** — `MetaModel::label_column`, recorded on the model and exposed
   through the registry so a *pointing* entity can read the target's label column. *Files:*
   `crud/seaorm.rs`.
4. **`sortable` metadata** — on `Column::Field` (always true) and `Column::Relation` (true iff to-one,
   owns the FK, and the target has a label column). *Files:* `crud/engine.rs`, `crud/seaorm.rs`,
   `crud/openapi.rs`.
5. **Relation sort** — join + qualified `order_by` in `list`; 400 for a non-sortable relation. *Files:*
   `crud/seaorm.rs`.
6. **Table sorting UI** — clickable headers, sort state, `Table::sort()`, export URL. *Files:*
   `crud/ui.rs`, `templates/table.html`.
7. **Table filter UI** — `Table::filter` / `fixed_filter`, reusing the picker; thread through load,
   export and bulk delete. *Files:* `crud/ui.rs`, `templates/table.html`, `templates/_form_core.html`.
8. **Admin shared filter** — `Admin::filter`, Alpine store, URL hash, create-form prefill. *Files:*
   `crud/ui.rs`, `templates/admin.html`, `templates/table.html`.
9. **Docs + example + changelog** — `docs/CRUD.md` (query-param table at §"Query params", the Web UI
   section, and a note on `label_column` under `MetaModel`); extend `examples/crud` with a sorted,
   zone-filtered table over the existing `post`/`author` model; `CHANGELOG.md` under `## Unreleased`,
   with the bare-`<col>=` change listed first as the breaking item (if option (b) or (c) in §4 is
   taken) with its upgrade step.

### Tests

- `crud/` backend tests: `f.<rel>` produces `fk = value` and not a `LIKE`; `f.` on an unknown name is
  400; sort-by-relation orders by the target's label column and paginates with the right `total`;
  sort-by-a-to-many-relation is 400; a filtered `DELETE /{entity}` deletes only matching rows.
- `crud/ui_tests.rs`: a `Table` with a filter renders the control and the fixed filter reaches the data
  URL; sortable headers render only for sortable columns.
- A regression test pinning the substring-vs-exact behaviour per column type, so the bare-`<col>=` fix
  cannot silently revert.

---

## 4. Compatibility — what actually breaks

There is **no private channel between the admin UI and the engine**. `ui::Table`'s JavaScript calls the
same public `GET /{entity}` route that `docs/CRUD.md` documents and `crud::openapi` publishes
(`table.html:206` → `engine.rs:935`). So "we're only changing our own front-end" does not hold: every
query-parameter decision here is a public API decision, and a script or a native API client downstream
could be relying on the current behaviour.

That said, the blast radius is small and mostly zero:

| Change | Breaking? |
|---|---|
| `f[…]` / `s[…]` filters | **No** — purely additive; new parameter names that are a 400 today |
| Sorting by a relation label | **No** — additive; `?sort=zone` is a 400 today |
| `sortable` in `_meta` | **No** — an added field; existing consumers ignore it |
| `Query<Vec<(String,String)>>` | **No** — same wire format; strictly more input survives parsing |
| `MetaModel::label_column` | **No** — new method; `row_label` keeps working |
| `Table::filter` / `Admin::filter` | **No** — new builder methods, default off |
| Bare `?<col>=<val>` on a **text** column | **No** — unchanged `LIKE '%val%'` |
| Bare `?<col>=<val>` on a **non-text** column | **Yes, technically** — see below |

The last row is the only one, and it is a documented parameter whose current behaviour is unusable:
wrong matches on SQLite (`?zone_id=3` also matches 13, 30, 103) and a 500 on PostgreSQL (`LIKE` against
an `integer`). Options, in increasing order of boldness:

- **(a) Freeze it.** Leave bare `<col>=` exactly as it is, route everything new through `f[…]` / `s[…]`.
  Zero break; the PostgreSQL 500 stays.
- **(b) Reject it.** On a non-text column, 400 with a message pointing at `f[<col>]`. Turns a wrong
  answer or a 500 into a clear error — arguably a bug fix, still a status-code change.
- **(c) Fix it.** On a non-text column, exact match. Most useful, and what a caller writing `?zone_id=3`
  meant; a real behaviour change to a documented parameter.

Any of (b) or (c) is a `CHANGELOG.md` entry under `## Unreleased`, listed first as the breaking item
with its upgrade step, and a **minor** bump to `0.3.0` per the pre-1.0 policy. Given v0.2.0 shipped five
days ago and `teleddns-server` is the one known consumer, (c) is cheap to take now and expensive to
take later.

## 5. Decisions

### Settled

- **Bracket filter spelling** — `f[zone]=7`, collision-proof *and* declarable as OpenAPI `deepObject`.
- **Relation sorting is to-one-owning-the-FK only**; to-many and N:M report `sortable: false` and 400.
- **`MetaModel::label_column`** is how a target declares the column its label comes from.
- **`Table::filter` / `fixed_filter` + an `Admin`-wide shared selector**, threaded through list, CSV
  export and bulk delete.
- **Release as `0.2.1`.** One caveat, flagged once and then dropped: `CHANGELOG.md`'s own policy says a
  behaviour break bumps the *minor* pre-1.0. That is only in play for decision 1 below — pick (a) and
  0.2.1 is unambiguously right, since everything else here is additive.

### Still open

1. **Bare `?<col>=<val>` on non-text columns** — freeze (a), reject with a pointer to `f[<col>]` (b), or
   make it exact (c), per §4. (a) is the only option that is purely additive and so the natural fit for
   a patch release; (c) is the one that fixes the PostgreSQL 500.
2. **Label column: auto-detect or explicit?** Recording `default_label`'s first matching column
   automatically makes most models sortable-by-relation with no code at all; requiring an explicit
   `label_column` call is more predictable but means a one-liner in every downstream model.
3. **`f[…]` or `filter[…]`?** Terse in a URL versus consistent with the crate's spelled-out style
   (`per_page`). Same for `s[…]` / `search[…]`. Purely cosmetic, but permanent.
4. **The deterministic-order fix (§1e)** — appending the PK as a final sort key changes the row order
   existing callers see for an unsorted list. It is a correctness fix and I would take it, but it is the
   one other thing in this change that an outside observer could notice.
5. **Scope of the pass** — does `teleddns-server` get wired up in the same sitting (`z.row_label` →
   `z.label_column("origin")`, `Admin::filter("zone")` across the RR tables), or does this land in
   `relativelylight` first and the console follow separately?
6. **One release or two?** The API half (§3 steps 1-5) is independently useful and unblocks anyone
   scripting against the JSON API; the UI half (steps 6-8) is the bulk of the work.

### Taken as defaults unless you say otherwise

`NULLS LAST` on both backends; collation left to the database; a click cycles asc → desc → off with
shift-click for a secondary key; empty `f[zone]=` means `IS NULL`; no `filterable` flag in `_meta`
(every column and to-one relation is filterable, so the flag would be noise); `examples/crud` demos
per-table sort + filter and `examples/adminpanel` demos the Admin-wide zone selector.

## 6. Explicitly out of scope

- Sorting or filtering by an inverse to-many / N:M relation (needs an aggregate; ambiguous semantics).
- Filter *operators* (`gt`, `in`, `is_null`) — the `f[<name>][<op>]` grammar is left room for, not built.
- Free-text filter expressions or a query DSL.
- Per-zone **authorization**. `fixed_filter` restricts a view, not access; scoping who may read or
  write which zone remains the app's `Authz` implementation.
