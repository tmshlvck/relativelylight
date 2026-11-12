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

## 3. New `auth` columns for passkeys

**Required, passkeys or not, before the upgraded crate runs.** `auth_user` gains `passkey_handle`,
`auth_session` gains `method` and `passkey_class`, and there are two new tables, `auth_passkey` and
`auth_webauthn_challenge`. Every read of an account selects the new column, so an unmigrated
database refuses every login. `auth::migrate` creates the two tables but never alters one: an app
that relies on it alone still needs the columns added.

The crate ships the statements:

```rust
use relativelylight::auth::passkey;

// inside a MigrationTrait::up(&self, m: &SchemaManager)
for stmt in passkey::table_create_statements(m.get_database_backend()) {
    m.create_table(stmt).await?;
}
for stmt in passkey::table_alter_statements() {
    m.alter_table(stmt).await?;
}
for stmt in passkey::index_create_statements() {
    m.create_index(stmt).await?;   // the handle's uniqueness: SQLite can't add a UNIQUE column
}
```

As SQL:

```sql
ALTER TABLE auth_user ADD COLUMN passkey_handle varchar NULL;
CREATE UNIQUE INDEX "idx-auth_user-passkey_handle" ON auth_user (passkey_handle);
ALTER TABLE auth_session ADD COLUMN method varchar NOT NULL DEFAULT '';
ALTER TABLE auth_session ADD COLUMN passkey_class varchar NULL;
-- and the two tables, from passkey::table_create_statements
```

Sessions from before the step keep working; their `method` is empty. In an accounts panel, hide
`passkey_handle` with the TOTP columns: the user's authenticators hold it, so an edited one orphans
every passkey on the account.
