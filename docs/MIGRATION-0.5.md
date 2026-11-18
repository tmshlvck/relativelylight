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
the timezone picker ([TIME.md §3](TIME.md#3-the-picker-and-its-handler)). A shell that rendered a
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
   drop your `profile_extra` card and its mint and revoke routes.
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
| a `format_cell` linking the id to `/profile/{id}` | `auth::user::credentials_link(auth.profile_path())` |
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
  `crud` feature turns on SeaORM's `serde`, which the wrapper needs to serialize as its integer.
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

## 12. `TzPicker` posts to `/_rl/tz`

`TzPicker`'s form posts to **`/_rl/tz`** by default, where it posted to `/tz`. An app that mounts its
timezone handler at `/tz` and doesn't call `.action(…)` would have the picker post to a path nothing
serves. Do one of:

```rust
.route("/_rl/tz", post(set_tz))                      // move the handler to the new default
TzPicker::new().action("/tz")                        // or keep `/tz`, said explicitly
```

An app that already calls `.action(…)` needs nothing. The handler itself is unchanged.

Why: the timezone form's target and the relation picker's route are plumbing, not pages, so the
examples keep them under one prefix, `/_rl/` (`Crud::picker_path("/_rl/pick")`), and the default
follows. Your relation picker's route stays where you mounted it; the crate has no default for it
([APP.md → Your URL namespace](APP.md#your-url-namespace)).
