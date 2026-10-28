# Upgrading from 0.3 to 0.4

0.4 moves to SeaORM 2.0, splits the cell formatter in two, and makes the form and CSV import read
blank values the same way. Most steps are compile errors; the ones that aren't are marked
**(silent)**. [CHANGELOG.md](../CHANGELOG.md) has the full list.

## 1. Dependencies

```toml
relativelylight = { version = "0.4", features = ["ui", "csv", "auth"] }
sea-orm = { version = "2.0", features = ["macros", "with-json"] }
```

Your entities and `DatabaseConnection` go straight into `MetaModel::new`, `Crud::new` and `Auth::new`,
so the build must have one SeaORM, not two. 1.x-style `DeriveEntityModel` entities compile unchanged.

## 2. SeaORM 2.0 in your own code

The 2.0 breaks this crate hit, and their fixes:

| 1.1 | 2.0 |
|---|---|
| `db.execute(backend.build(&stmt))` | `db.execute(&stmt)` |
| `db.execute(Statement::from_string(..))` | `db.execute_raw(stmt)` |
| `Expr::col(c).eq(v)` with `Expr` methods | the same calls, with `sea_query::ExprTrait` imported |
| `Insert::do_nothing()` / `.on_conflict(OnConflict::..do_nothing())` | `.on_conflict_do_nothing()` or `.on_conflict_do_nothing_on([cols])` |
| `TableRef::Table(name)`, `Iden::unquoted() -> String` | `TableRef::Table(name, alias)`, `unquoted() -> &str` |

Import `ExprTrait` in the **narrowest scope** that needs it. It is implemented for everything
`Into<Expr>`, `serde_json::Value` included, so a module-wide import turns `value.is_null()` into the
trait's method, which returns an `Expr` instead of a `bool`.

## 3. `Table::format` → `format_cell` / `format_view`

`format` rendered both the table cell and the View dialog. Now there is one renderer per place, and
neither falls back to the other:

```rust
// 0.3
table.format("title", link)
// 0.4 — the same in both places
table.format_cell("title", link).format_view("title", link)
// 0.4 — short in the listing, whole in View
table.format_cell("body", crud::ui::truncate(60))
```

A column without `format_view` is shown in View by its default rendering.

## 4. `on_read` / `on_write` are a codec, not a mask (silent)

The edit form is filled from `on_read`'s output, so a hook that masks a value (`"••••1234"`) gets the
mask saved back on the next edit. If yours masks or decorates:

- display-only changes move to `format_cell` / `format_view`;
- secrets use `MetaField::write_only` (or `MetaField::password()`).

A hook pair that really is a codec (store digits, show `+420 123 456 789`) is fine as it is, as long as
`on_write(on_read(x)) == x`. See [CRUD.md → A column's way in and out](CRUD.md#a-columns-way-in-and-out).

## 5. Blank inputs and blank CSV cells (silent)

The form and the CSV import now read typed text through one function, so they agree:

| Input | 0.3 | 0.4 |
|---|---|---|
| Form: blank nullable **text** | sent `null` | sends `""`; the engine's `blank_is_null` decides (default: `NULL`) |
| Form: blank NOT NULL database enum | sent `""` (failed the options check) | omitted |
| CSV: blank nullable number / bool / enum / JSON | left the value unchanged | clears it to `NULL` |
| CSV: JSON cell | stored as a string | parsed |
| CSV: text cell | trimmed | taken as written |

Upgrade: a CSV workflow that relied on blank cells leaving values alone must fill them in. A text
column that needs trimming gets a validator or normalizer ([DATAINPUT.md](DATAINPUT.md)).

## 6. The timezone route

Use `TzPicker::submitted`, which only follows a local `back` path. The 0.3 docs' handler redirected
to whatever `back` was posted:

```rust
async fn set_tz(Form(f): Form<HashMap<String, String>>) -> Response {
    let (cookie, back) = TzPicker::submitted(f.get("tz"), f.get("back"));
    ([(header::SET_COOKIE, cookie)], Redirect::to(&back)).into_response()
}
```

## 7. Relations in forms (silent)

- **`picker_threshold` is 50 (was 20) and covers to-many relations too.** Past it, a relation is
  edited in the picker dialog if you serve one, and otherwise stays a `<select>` of every row. The
  typed-id text input a large to-one used to fall back to is gone. To get the picker: set
  `Crud::picker_path("/pick")`, serve `Picker::render_for` from a `GET` on that path in a bare
  shell, and include `crud::ui::JS` in your page shell ([CRUD.md → Picker](CRUD.md#picker--choosing-from-a-large-relation)).
- **A relation's options answer to the target's gate.** A caller who may not `List` the target sees
  the current selection read-only. Grant that read where users picked from a table they couldn't
  otherwise see.
- **A filter control is always a `<select>`.** If a filter's menu is too long to use, drop it or pin
  it with `fixed_filter`.

## 8. Table toolbar

"Delete all N matching" and the CSV export/import moved into a ⋮ "Table operations" menu, and the
rows' form has the id `{dom_id}-rows` (`rl-post-rows`). Only your own CSS or browser tests notice.

## 9. Write controls (silent)

- **A read-only table refuses posted writes** (`403`), and a `Form` refuses anything but a create or
  an update. Before, both hid the controls but applied whatever the gate allowed.
- **Each control asks the gate about its own operation**: Edit appears for a caller allowed `Update`
  even without `Create`, and the deletes disappear for one refused `Delete`.

Nothing to change unless something of yours posted to a read-only table.

## 10. A cut to-many list (silent)

An inverse to-many (an author's posts) past 100 links now ends with `{"more": n}`. If your code
reads that array from `Engine::get` or `Engine::list`, skip elements without an `id`. N:M lists are
never cut.

## 11. `auth` foreign keys, if your database predates 0.3.2

Since 0.3.2, `auth_session`, `auth_totp_recovery` and `auth_user_group` reference `auth_user` (and
`auth_group`) with `ON DELETE CASCADE`. `auth::migrate` doesn't alter existing tables, so an older
database keeps working without them; deleting a user then leaves their sessions and codes behind, and
fails with `409` while they belong to a group. To add them, first delete orphaned rows
(`DELETE FROM auth_session WHERE user_id NOT IN (SELECT id FROM auth_user)`, the same for
`auth_totp_recovery`), then:

- **PostgreSQL / MySQL:** `ALTER TABLE … ADD CONSTRAINT … FOREIGN KEY (user_id) REFERENCES
  auth_user(id) ON DELETE CASCADE` per table; on `auth_user_group`, drop and re-add both existing keys.
- **SQLite** can't alter a constraint: rebuild each table by
  [its documented procedure](https://sqlite.org/lang_altertable.html#otheralter) (create the new shape
  from `auth::table_create_statements` under a temporary name, copy the rows, drop, rename, with
  `PRAGMA foreign_keys=OFF` around it).

## New in 0.4, nothing to change

- `Table::create` / `edit` / `delete` / `bulk_delete` / `import` / `export(bool)`: one switch per
  action, each refused on submit when off.
- `Table::detail_href("/post/{id}")`: View opens a page of your own instead of the dialog.
- `crud::ui::truncate(n)`: a ready-made `format_cell` renderer.
- `crud::ui::RelationField`: the relation input (select or picker) for a form you write yourself.
