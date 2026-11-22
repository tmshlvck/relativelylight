# Upgrading from 0.4 to 0.5

**0.5 is not released yet**; this file collects the steps as they land on `main`.
[CHANGELOG.md](../CHANGELOG.md) has the full list.

## 1. `Auth`'s page callbacks get the request

`Auth::login_shell`, `Auth::profile_shell`, `Auth::csrf_rejection` and `Csrf::on_reject` are now
handed the request's `http::request::Parts`, and `Csrf::reject` takes it. Each is a compile error
until you add the argument:

| 0.4 | 0.5 |
|---|---|
| `.login_shell(\|form\| …)` | `.login_shell(\|form, req\| …)` |
| `.profile_shell(\|frag, who\| …)` | `.profile_shell(\|frag, who, req\| …)` |
| `.csrf_rejection(\|\| …)` / `.on_reject(\|\| …)` | `.csrf_rejection(\|req\| …)` / `.on_reject(\|req\| …)` |
| `csrf.reject()` | `csrf.reject(&parts)`: extract `parts: http::request::Parts` in the handler in place of `HeaderMap`, and read `parts.headers` |

A function passed by name (`.login_shell(login_shell)`) gains a `req: &Parts` parameter. Ignore it
(`_req`) to keep 0.4's pages, or use it to render the chrome the rest of your app renders, such as
the timezone picker ([TIME.md §3](TIME.md#3-the-picker-and-the-first-visit)). A shell that rendered a
reduced navbar because it had no request can now render the full one.

## 2. Optional: API keys move into `auth`

Nothing breaks: `auth_api_key` is a new table and the feature is off until you call
`Auth::api_keys`. `auth::migrate` creates the table. With your own migrations, add a step when you
start using keys:

```rust
m.create_table(relativelylight::auth::api_key::table_create_statement(m.get_database_backend())).await?;
```

**An app that kept its own key table** (teleddns's `api_key`, the same shape) can move onto the
crate's and delete its resolver and profile card ([AUTH.md §5k](AUTH.md#5k-api-keys)). Existing keys
keep working: the stored hash is the SHA-256 hex of the raw key, as before.

1. Migrate the rows: `ALTER TABLE api_key RENAME TO auth_api_key`, then add
   `created_at BIGINT NOT NULL DEFAULT 0` (or create `auth_api_key` and copy the rows over). The
   other columns (`user_id`, `name`, `hashed_key`, `prefix`, `expires_at`, `last_used_at`,
   `disabled`) have the same names and types.
2. Configure `Auth::api_keys(ApiKeys::new("tddns_"))` with the prefix your keys already carry, and
   drop your `profile_extra` card and its mint and revoke routes. The label field's hint is now
   neutral ("what will use it, e.g. a script"); `.name_placeholder("router at home")` keeps yours.
3. In each machine endpoint, call `auth.identify_key(token, ip)` in place of your own lookup. It
   brakes on `auth.ip_lockout()`, so remove your own failure recording for keys, or a bad key counts
   twice. Build your principal from the returned `identity` (groups by name) and `key_id`.
4. In the accounts panel, register `auth::api_key::meta_model()` in place of your own `MetaModel`.

## 3. New `auth` columns and tables

**Required, whatever features you use, before the upgraded crate runs.**

- `auth_user` gains `passkey_handle` (§5l), `password_changed_at` and `must_change_password` (§5m).
- `auth_session` gains `method`, `passkey_class` and `reauth_until` (an SSO account's confirmation,
  §5h).
- Two new tables: `auth_passkey` and `auth_webauthn_challenge`.

Every read of an account selects the new columns, and every write of a password sets two of them,
so an unmigrated database can neither sign anyone in nor create an account. `auth::migrate` creates
the two tables but never alters one: an app that relies on it alone still needs the columns added.

The crate ships the statements, in `auth::upgrade`:

```rust
use relativelylight::auth::upgrade;

// inside a MigrationTrait::up(&self, m: &SchemaManager)
for stmt in upgrade::table_create_statements(m.get_database_backend()) {
    m.create_table(stmt).await?;
}
for stmt in upgrade::table_alter_statements() {
    m.alter_table(stmt).await?;
}
for stmt in upgrade::index_create_statements() {
    m.create_index(stmt).await?;   // the handle's uniqueness: SQLite can't add a UNIQUE column
}
```

As SQL:

```sql
ALTER TABLE auth_user ADD COLUMN passkey_handle varchar NULL;
CREATE UNIQUE INDEX "idx-auth_user-passkey_handle" ON auth_user (passkey_handle);
ALTER TABLE auth_user ADD COLUMN password_changed_at bigint NULL;
ALTER TABLE auth_user ADD COLUMN must_change_password boolean NOT NULL DEFAULT FALSE;
ALTER TABLE auth_session ADD COLUMN method varchar NOT NULL DEFAULT '';
ALTER TABLE auth_session ADD COLUMN passkey_class varchar NULL;
ALTER TABLE auth_session ADD COLUMN reauth_until bigint NULL;
-- and the two tables, from upgrade::table_create_statements
```

**Code that builds the rows itself.** `auth::user::Model` gains `passkey_handle`,
`password_changed_at` and `must_change_password`, and `auth::session::Model` gains `method`,
`passkey_class` and `reauth_until`. A struct literal of either no longer compiles. Build an `ActiveModel` with
`..Default::default()` instead, as the crate's helpers do. A test that inserts a session row should
set `method` (`session::Method::Password.as_str()`), or it reads as a pre-upgrade row.

**After the upgrade:**
- Sessions from before the step keep working. Their `method` is empty, which counts as `Simple`.
- A password from before has no `password_changed_at`; a maximum age counts it from `created_at`.
- **Accounts panel:** the new columns need the rules §8's models apply (`passkey_handle` hidden,
  `must_change_password` read-only).

## 4. MSRV 1.89

The minimum Rust version is **1.89** (was 1.88), for `webauthn-rs` 0.6, the passkeys dependency. It
applies with or without the `passkeys` feature: `rustup update`, and raise `rust-version` in your
own `Cargo.toml` if you pin one.

## 5. The profile page is a grid of cards

`/profile` is now a grid of cards: one column on a phone, two on a wide screen, with one message at
the top. Two things change for an app:

- **`profile_extra`'s hook returns cards.** Wrap what it returned in `auth::profile_card(title, body)`,
  one call per card, and concatenate them. A bare `<hr><h2>…` would sit in the grid as a stray column.
- **`profile_shell` wraps a grid.** Give the fragment a wide column (say `max-width: 72rem`), not
  the narrow card that suited the old single column.

## 6. `Auth::reauthenticate` is replaced by `reauthenticate_with`

`Auth::reauthenticate(&who, password, code)` is gone. It took a password and a TOTP code only, so it
couldn't confirm an account that signs in with a passkey and has no password.
`Auth::reauthenticate_with(&who, &ReauthInput)` takes any factor the account has.

| 0.4 | 0.5 |
|---|---|
| form fields `current_password`, `totp_code` you render yourself | `auth.reauth_fields(&who, "Confirm it's you.").await` inside the form; it offers only the factors the account has, a passkey included |
| `struct MyForm { current_password: String, totp_code: String, … }` | `struct MyForm { #[serde(flatten)] reauth: auth::ReauthInput, … }` |
| `auth.reauthenticate(&who, &f.current_password, &f.totp_code).await` | `auth.reauthenticate_with(&who, &f.reauth).await` |
| no form (a CLI, a test): `auth.reauthenticate(&who, pw, code)` | `auth.reauthenticate_with(&who, &ReauthInput::password_or_code(pw, code))` |

A section on the profile page gets the same inputs in `ProfileSection::reauth_fields`.

## 7. Behaviour you will notice

Nothing to change in code for these, but they change what users see.

- **A password written for someone asks them to choose their own** (AUTH.md §5m). Any write that
  sets `auth_user.password_hash` without setting `must_change_password` flags the account. That
  covers an accounts-panel edit, an app's own form and a manager's reset at `/profile/{id}`. The
  owner then lands on `/profile` after signing in, with a notice, and can still use the app.
  - `create_user`, `set_password`, `make_admin` and `reset_admin_access` don't flag.
  - **If your app sets passwords for users itself and doesn't want this**, set
    `must_change_password` to `false` in the same write.
- **The API-key label hint is neutral**: "what will use it, e.g. a script", where it was "router at
  home". Set your own with `ApiKeys::name_placeholder` ([AUTH.md §5k](AUTH.md#5k-api-keys)).
- **The search box finds more** ([CRUD.md → Search](CRUD.md#search)): numbers, dates, choice labels,
  instants by period and relations by their labels, case-insensitive on PostgreSQL too. A table
  whose search should stay narrow opts fields or relations out with `searchable = false`. A table
  with nothing to search now matches no row for a term.
- **SSO accounts confirm at their provider before a sensitive change** (AUTH.md §5h), where they
  used to pass re-authentication unchallenged. That covers a manager's reset or 2FA removal, adding
  a factor on `/profile`, and every route of yours behind `reauthenticate_with`. The confirm block
  (`reauth_fields`, and the library's own pages) shows a **Confirm with …** link; after the round
  trip the next action passes, once. Nothing changes in code, but `Sso::routes()` must be mounted
  for it, as it already is for SSO sign-in.
- **SSO accounts may enrol TOTP** on `/profile`. Once one has, the TOTP step follows the identity
  provider's callback. This is what `Auth::sso_level(Level::Simple)` relies on to require it (§5m).
  A site that never sets that still lets SSO users opt in.
- **The login page** shows "or" and "Sign in with a passkey" under the form when passkeys are on.
  Draw your SSO buttons under them; they no longer need a divider of their own.
- **A list no longer shows write-only columns.** A password's column was always blank there; it is
  gone from the table as it already was from the View dialog and CSV. The form still takes it.

## 8. The accounts panel comes from `auth`'s `meta_model()`s

A panel configured by hand still compiles, but it is no longer the way: it lets an operator change
someone's password **without signing them out**, which the manager's reset at `/profile/{id}` does,
and it misses the rules for the new columns (§3).
The library's models make the panel set only an account's **first** password, and link each account
to its credentials page for everything after ([AUTH.md §5j](AUTH.md#the-accounts-panel)).

| 0.4 (by hand) | 0.5 |
|---|---|
| `MetaModel::new(auth::user::Entity)` + `.password()`, the policy validator, hidden TOTP columns, read-only stamps, `relate(&group)` | `auth::user::meta_model(&auth)` (the policy comes from `Auth`) |
| `MetaModel::new(auth::group::Entity)` + read-only stamps, `relate(&user)` | `auth::group::meta_model()` |
| `MetaModel::new(auth::lockout::username_entity::Entity)` / `ip_entity` + read-only counters | `auth::lockout::username_meta_model()` / `ip_meta_model()`, shown with `Table::create(false).edit(false)` |
| a `format_cell` linking the id to `/profile/{id}` | nothing: `auth::user::meta_model` links it ([§13](#13-display-formatters-move-to-the-field-the-picker-threshold-to-the-relation)) |
| — | `auth::passkey::meta_model()`, shown with `Table::read_only(true)` |

Drop the hand-written configuration with it: the hook-maintained columns, the hidden ones and the
username check are all in the model. A table that trimmed its columns with `Table::columns` to hide
the password's blank cell no longer needs to (§7).

## 9. `crud::Column::Field` gains `create_only`

Only for an app with its **own `Accessor`** (or code that builds a `Column::Field` literal or
matches one without `..`): add `create_only: false`, or `true` for a column a create sets and an
update must not (`MetaField::create_only`, [CRUD.md](CRUD.md#metafield)).

## 10. A standalone `Form` writes only what it is

`Form::submit` used to take the operation and the row from the posted body, so a `Form::new` accepted
an update and an `.edit(id)` form a create, or an update of another `_id`. Now `Form::new` only
creates and `.edit(id)` only updates `id`: anything else is `403` (the other operation) or `400`
(another row).

A handler that submits with the same builder it rendered with needs no change. One that renders
`.edit(id)` but submits through a plain `Form::new` (one `POST` handler shared by create and edit,
say) now gets `403` for every save. Build the form for the `POST` as for the `GET`:

```rust
// before: one handler for both, the body chose
Form::new(&engine, "post").submit(&headers, ip, &body, &state).await
// after: the route says which
let form = match id { Some(id) => Form::new(&engine, "post").edit(id), None => Form::new(&engine, "post") };
form.submit(&headers, ip, &body, &state).await
```

See [CRUD.md → `Form`](CRUD.md#form--a-standalone-createedit-form).

## 11. Time values: one column type per kind

0.5 settles which column a time value takes ([TIME.md §1](TIME.md#1-storage-model)): an **instant**
is integer Unix seconds with `.datetime()`, a **calendar date** a native `DATE`. Go through your
columns by what each value means.

- **Instants already in integer columns: nothing to do.** Optionally change the field type from `i64`
  to `ChronoUnixTimestamp` to get a `DateTime<Utc>` in Rust. The column, the stored values and the
  `.datetime()` configuration stay as they are:

  ```rust
  pub sent_at: Option<ChronoUnixTimestamp>,   // was Option<i64>
  ```

  Your own code then builds the value with `ChronoUnixTimestamp::from(dt)` and reads `.0`. The
  crate turns on SeaORM's `serde`, which the wrapper needs to serialize as its integer.
- **A date stored as midnight seconds** (a `valid_until`, a date of supply) moves to a `DATE` column
  and a `Date` field. Shown in a viewer's zone, midnight UTC is the previous day west of UTC. This is
  a schema change with a data conversion, e.g. on PostgreSQL:

  ```sql
  ALTER TABLE license ALTER COLUMN valid_until TYPE date
    USING (to_timestamp(valid_until) AT TIME ZONE 'UTC')::date;
  ```

  On SQLite, rebuild the table, or add the new column and fill it with
  `date(valid_until, 'unixepoch')`. Any code that wrote the seconds now writes a `Date`.
- **A native timestamp column you edited through the CRUD** is now read-only. Such a write never
  saved, so nothing that worked breaks, but its input is gone. Move the value to integer seconds
  (an instant) or `DATE` (a day), or fill the column in a hook.
- **A blank date input is now `NULL`** (or not sent, on a non-nullable column) rather than `""`.
- **Anything that writes the database without the models** (raw SQL, import scripts) writes a date
  as exactly `YYYY-MM-DD` and an instant as integer seconds. SQLite stores anything you give it,
  and a row in another format sorts and filters wrong without an error.

## 12. The timezone picker is a script

The timezone picker no longer posts a form to a handler of yours: [`time::JS`](TIME.md#3-the-picker-and-the-first-visit)
sets the zone cookie in the browser and reloads. Its list is every zone the server's database knows,
led by UTC and "Browser timezone", and a first visit takes the browser's own zone.

1. **Inline `time::JS` in every page's shell**, once, as `crud::JS`:
   `<script>{relativelylight::time::JS}</script>`. Without it the picker does nothing.
2. **Remove your timezone route and handler** (`TzPicker::submitted` is gone).
3. **Render it with the function:** `TzPicker` is gone, `time::picker(&tz)` replaces
   `TzPicker::new().render(&tz, back)`, with no return path and no `.action(…)` or `.label(…)`.
4. **Drop zone lists** (`.zones(…)`, `.all_zones()`, `unknown_zones()`, `zones_default()`,
   `zones_all()`, `Tz::known`) and the exclusions (`time::EXCLUDED`, `is_excluded`): the list is now always the
   full database. Nothing replaces a configured list.
5. **If the picker isn't on every page, name the zone** on each page, in a footer say: times are
   otherwise ambiguous ([TIME.md §3](TIME.md#3-the-picker-and-the-first-visit)).

`Tz::from_headers` reads the same `rl_tz` cookie as before, so a zone users already chose stays.

## 13. Display formatters move to the field, the picker threshold to the relation

**Formatters.** `Table::format_cell` / `format_view` are gone; declare the same closures once on the
field, and every table of the entity uses them, along with the dialog a relation's link opens
([CRUD.md → Display formatters](CRUD.md#display-formatters--how-a-field-is-shown)). The closure takes
one `&FmtCtx` instead of `(value, row)`:

```rust
// 0.4
use relativelylight::crud::ui::{esc, truncate};
Table::new(&engine, "post")
    .format_cell("title", |v, row| format!(r#"<a href="/post/{}">{}</a>"#, esc(&row["id"]), esc(v)))
    .format_cell("body", truncate(60))

// 0.5
use relativelylight::crud::{esc, truncate};
post.field("title").format_cell(|cx| {
    format!(r#"<a href="/post/{}" target="_top">{}</a>"#, esc(&cx.row()["id"]), esc(cx.value()))
});
post.field("body").format_cell(truncate(60));
```

1. **Move each `format_cell` / `format_view` to the field** it names, on the `MetaModel` before
   `register`: `(v, row)` becomes `cx`, with `cx.value()` and `cx.row()`. The same closure passed to
   both is still how one rendering serves the cells and View.
2. **Import `esc`, `esc_str` and `truncate` from `crud::`** (0.5 has no `crud::ui` path).
3. **Add `target="_top"` to a link a `format_view` draws**: it now also renders in the linked
   row's dialog, an `<iframe>`, where a plain link would load the page inside the dialog.
4. **Two tables that formatted one column differently** now share one formatter: keep the one the
   entity should show everywhere. A link to the row's own Edit dialog (`?edit={id}`) is better
   dropped: the row's Edit already does it.
5. **The accounts panel:** drop `auth::user::credentials_link` and the `format_cell` /
   `format_view` on `auth_user`'s id; `auth::user::meta_model` sets them.

**Picker threshold.** `Table::picker_threshold`, `Form::picker_threshold` and
`RelationField::picker_threshold` are gone. Set the app-wide one on `Crud`, and a relation's own on
its model:

```rust
crud.picker_threshold(100);                           // every relation (default 50)
workorder.relation("aircraft").picker_threshold(200); // this one
```

**An app with its own `Accessor`** (or a `Column` literal, or a match without `..`): add
`format_cell: None, format_view: None` to `Column::Field` and `picker_threshold: None` to
`Column::Relation`.

## 14. Entity-wide settings move to the model

Four settings that describe an entity, not one screen, are now declared on its `MetaModel`
([CRUD.md → The entity as a whole](CRUD.md#entity-wide-settings)):

| 0.4 | 0.5 |
|---|---|
| `Table::detail_href("/post/{id}")` (`Admin`: `entity_with("post", \|t\| t.detail_href(…))`) | `post.view_path("/post/{id}")` |
| `crud.view_path("post", "/post/{id}")` | `post.view_path("/post/{id}")` |
| `crud.picker_create_except(["user"])` | `user.picker_create(false)` |
| `Picker::new(&e).create_fields("airline", ["name", "hq"])` | `airline.picker_create_fields(["name", "hq"])` |
| `Table::row_class(\|row\| … -> String)` | `invoice.row_class(\|cx\| … -> Option<String>)` |

```rust
// 0.4
crud.view_path("post", "/post/{id}");
crud.picker_create_except(["user"]);
Table::new(&engine, "invoice")
    .detail_href("/invoice/{id}")
    .row_class(|row| match row["status"].as_str() {
        Some("overdue") => "table-danger".into(),
        _ => String::new(),
    })

// 0.5, on the models before `register`
post.view_path("/post/{id}");
invoice.view_path("/invoice/{id}");
user.picker_create(false);
invoice.row_class(|cx| match cx.row()["status"].as_str() {
    Some("overdue") => Some("table-danger".into()),
    _ => None,
});
```

1. **`detail_href` and `view_path` become one `MetaModel::view_path`.** If you set both for an
   entity, keep one; it now drives every table's View *and* a relation link's `href`.
2. **Drop a `view_path` that pointed at a table's own `?show=`** (`"/admin/post?show={id}"`, a
   no-script fallback for relation links): on the model it turns that table's built-in View off.
   Without it, a link's no-script `href` is the picker's page for the row.
3. **`picker_create_except([...])`**: call `picker_create(false)` on each listed target's model. A
   misspelt slug used to be ignored; a model can't be misspelt.
4. **`Picker::create_fields(target, names)`**: move the list to the target's model. An unknown
   name now **panics at startup** instead of failing the render.
5. **`row_class`**: move it to the model, so every table of the entity (`Admin` included) uses it.
   The closure takes `&RowCtx` (`cx.row()`, `cx.headers()`) and returns `Option<String>`: `None`
   where it returned `String::new()`. A table that wanted a class the others don't should say it
   with data instead, or render its own rows.
6. **An app with its own `Accessor`** reports these by overriding `Accessor::meta` (default: none).
   `Engine::set_view_path` and `Engine::set_picker_create_except` are gone with the `Crud` methods.

## 15. Only `sso`, `passkeys` and `files` are features

The engine, its admin UI, CSV, timezones, `auth`, the regex and base64 validators, CSRF and the axum
plumbing are always compiled ([why](DESIGN.md#principles)). The features `crud`, `ui`, `csv`, `tz`,
`auth`, `axum`, `csrf`, `validate-regex` and `validate-base64` are gone; there are no default
features. Cargo refuses a feature that doesn't exist, so a manifest naming one fails to build until it
is updated:

```toml
# 0.4
relativelylight = { version = "0.4", features = ["crud", "axum", "ui", "csv", "auth", "sso", "validate-base64"] }
relativelylight = { version = "0.4", default-features = false, features = ["files", "csrf"] }

# 0.5
relativelylight = { version = "0.5", features = ["sso"] }
relativelylight = { version = "0.5", features = ["files"] }
```

1. **Keep only `"sso"`, `"passkeys"` and `"files"`** in `features`; remove every other name.
2. **Drop `default-features = false`**: there is nothing to turn off. A build that used it to leave
   out the admin (`auth` alone, `files` alone) now compiles the whole crate; it uses what it calls
   and nothing else changes.
3. **Code behind `#[cfg(feature = "csv")]`** or similar in your app, keyed to this crate's features,
   is now always on: remove the attribute and any fallback branch.
4. Nothing changes in the API: the CSV import and export are drawn whenever `Table::import` /
   `Table::export` are on, as they were with `csv`, and the API-key page shows times in the caller's
   zone, as it did with `tz`.

## 16. Import everything from `crud::`

`crud`'s submodules are private; every public item is re-exported at `relativelylight::crud`. A path
through a submodule no longer resolves, so each `use` changes, with no change to the items themselves:

```rust
// 0.4
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::{Admin, Outcome, Table, ViewState, CSS, JS};
use relativelylight::crud::engine::{Engine, ListQuery};
use relativelylight::crud::fmt::esc;

// 0.5
use relativelylight::crud::{esc, Admin, Crud, Engine, ListQuery, MetaModel, Outcome, Table, ViewState, CSS, JS};
```

| 0.4 | 0.5 |
|---|---|
| `crud::seaorm::X`, `crud::engine::X`, `crud::ui::X`, `crud::fmt::X` | `crud::X` |
| `crud::csv_io::export` / `import` | `crud::export_csv` / `import_csv` |
| `crud::csv_io::{ImportReport, ImportError}` | `crud::{ImportReport, ImportError}` |
| `{{ relativelylight::crud::ui::CSS }}` in a template | `{{ relativelylight::crud::CSS }}` (and `JS`) |

A search and replace of `crud::seaorm::`, `crud::engine::`, `crud::ui::` and `crud::fmt::` with `crud::`
does it; then merge the `use` lines the compiler calls duplicates.
