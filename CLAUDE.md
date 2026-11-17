# relativelylight

A web back-office toolkit for Rust. From SeaORM entities it generates a **server-rendered CRUD
admin** and **authentication/authorization**, with no per-model code. It is a library composed *into*
an app: the app keeps its axum router and page shell; the crate contributes HTML fragments and the
write path behind them. There is no JSON API and no JavaScript framework — rendering is Rust matching
on typed columns, writes are posted forms (`POST` → `303` → `GET`).

Start with [README.md](README.md) (features, quick start, examples) and [docs/APP.md](docs/APP.md)
(a whole app). The reference guides are [docs/CRUD.md](docs/CRUD.md), [docs/AUTH.md](docs/AUTH.md)
(its security reasoning in [docs/AUTH-SECURITY.md](docs/AUTH-SECURITY.md)),
[docs/TIME.md](docs/TIME.md), [docs/DATAINPUT.md](docs/DATAINPUT.md) and
[docs/FILES.md](docs/FILES.md); upgrading is [docs/MIGRATION-0.5.md](docs/MIGRATION-0.5.md) (unreleased) and
[docs/MIGRATION-0.4.md](docs/MIGRATION-0.4.md);
the design is [docs/DESIGN.md](docs/DESIGN.md) and open work [docs/TODO.md](docs/TODO.md).

**One way to do each thing** ([DESIGN.md principle 9](docs/DESIGN.md#principles)), in the code and
in the docs: before adding a second way, or a second explanation, find the first and extend it.

## Things that are easy to get wrong

- **`middleware::resolve_real_ip` is mandatory and outermost** (the last `.layer`). The login routes
  and the crud write handlers answer `500` without the `RealIp` it inserts. Behind a CDN, write your
  own middleware inserting `RealIp`; there is no hook, on purpose.
- **`render_for` / `submit` are the enforcement points**, not decoration: `Engine` itself is ungated,
  so a handler that calls `Engine::get` directly must call `Engine::decide` first.
- **The URL is the state.** `ViewState` parses page, sort, filters, search, entity and the open
  dialog; every href the crate renders is relative (`?page=2`), so it needs no route of its own.
- **Display vs storage.** `Table::format_cell` / `format_view` are display only (their output is
  inserted verbatim — escape with `crud::ui::esc`). `MetaField::on_read` / `on_write` are a storage
  codec, an inverse pair that also fills the edit form — never a place to mask a value
  ([CRUD.md → A column's way in and out](docs/CRUD.md#a-columns-way-in-and-out)).
- **The form and CSV read typed text through one function** (`crud::text`); the engine then applies
  `blank_is_null`, `required`, `options`, validators and `on_write` on every surface.
- **The password policy covers typed input only** (not the seeders and break-glass helpers).
  `auth::user::meta_model(&auth)` carries `Auth`'s policy into the panel's password field; an app's
  own password form must call it too, or that form is the way around it.
- **Register `auth_*` tables only through their `meta_model()`** (`user`, `group`, `api_key`,
  `passkey`, `lockout::{username,ip}_meta_model`): they hide the secrets, pin owners and keep the
  hook-maintained columns read-only. Never register `auth_totp_recovery` (every row is a credential
  hash). The panel holds account data; changing someone's credentials is `/profile/{id}`'s alone.
- **An API key never opens the UI.** `Auth::identify` reads only the session cookie; keys are checked
  only by `Auth::identify_key`, called by the machine endpoints that take one. Keep it that way: a gate
  or page that accepted a key would let a credential that skips 2FA into the UI
  ([AUTH.md §5k](docs/AUTH.md#5k-api-keys)).
- **Lockout counters are shared**: an app checking credentials itself uses `auth.username_lockout()` /
  `auth.ip_lockout()`, not a second limiter. `identify_key` already counts a bad key on the address
  counter; an app must not count it again. Pruning (`auth.prune()`) is scheduled by the app; the
  crate spawns no tasks and writes nothing to stdout or stderr.
- **A session below `Auth::min_level` is restricted**: `identify` returns `None` and only the caller's
  own `/profile` serves it. Keep it that way for anything new: an API key minted, a manager action or
  an app section reached from a restricted session would carry the account past the policy.
- **`must_change_password` is set by the `auth_user` row hook** whenever a write sets `password_hash`
  without setting it; a new helper that writes the owner's own password sets it to `false`
  explicitly ([AUTH.md §5m](docs/AUTH.md#5m-the-sign-in-policy-and-password-change-required)).
- **Configure `Auth` fully before `Sso::new(&auth)`** clones it.
- Entities need a single-column primary key and single-column to-one FKs; N:M junction tables are
  never registered (`post.relate(&tag)` declares N:M).

## Working on the library

A Cargo workspace: the crate is `relativelylight/` (`crud/` with `ui/` as the renderer, `auth/`,
`files/`, `authz.rs`, `observe.rs`, `time.rs`, `validate.rs`; Askama templates in `templates/`; CSS and
the picker's script in `assets/`), with runnable examples in `examples/` sharing `examples/model`.
Deps: SeaORM 2.0, axum 0.8, askama 0.16, jiff 0.2, totp-rs 6, argon2 0.6, webauthn-rs 0.6. MSRV 1.89
(webauthn-rs).

```bash
cargo build --all-features && cargo test --all-features && cargo clippy --all-features --all-targets
```

**`--all-features` is not enough.** It can't catch a feature that forgets to enable what it uses, or
a helper that is dead code in a narrower build. Before a release, check the matrix for **warnings**
as well as errors:

```bash
for f in "" crud axum csrf tz csv auth auth,sso passkeys crud,ui crud,ui,csv files files,csrf; do
  cargo build -p relativelylight --no-default-features ${f:+--features $f} 2>&1 \
    | grep -E "^(error|warning: )" | grep -v "the following packages"
done
cargo build --workspace      # the examples pin their own narrow feature sets
```

Don't run `rustfmt` over the whole repo; format only what you touch.

**Security behaviour is tested by rejection**, over in-memory SQLite: `auth/security_tests.rs`,
`auth/sso_tests.rs` (a fake IdP), `auth/passkey_tests.rs` (a software authenticator),
`crud/gate_tests.rs`; also `crud/ui_tests.rs` (escaping, form decoding), `crud/transform_tests.rs` (a
value's way through form, CSV and codec) and `files/tests.rs`. What each covers is listed in
[AUTH-SECURITY.md → Tests](docs/AUTH-SECURITY.md#tests--the-negative-paths). Touching login,
sessions, 2FA, API keys, passkeys, the profile pages, a gate or the upload path means extending them,
with a positive control so the negatives can't pass vacuously.

**The docs are part of the change, and each fact has one home.**

- Update the guide that owns the behaviour, and the doc comments.
- Demonstrate user-facing features in an example (a new one goes in the root `Cargo.toml` `members`
  and the README's example list).
- A new module or feature: the table in `docs/DESIGN.md`, a pointer in `README.md`; move shipped items
  out of `docs/TODO.md`.
- Anything a user would notice gets a `CHANGELOG.md` entry under `## Unreleased` in the same change,
  breaking items first with the upgrade step — and, for a breaking change, a step in the current
  `docs/MIGRATION-x.y.md`.
- Each document has one job, and a fact lives in the one whose job it is; the others link to it:
  `DESIGN.md` the design and its decisions (why), `AUTH-SECURITY.md` the security reasoning, the
  guides what ships and how to use it, `APP.md` one whole app built from them, `TODO.md` open work
  and future ideas (the only place), `MIGRATION-x.y.md` upgrade steps. `README.md` is the starting
  point; this file is orientation. A guide's "why" is a `[why]` link, not a copy.

**Releasing:** run the feature matrix above, rename `## Unreleased` to `## [x.y.z] — YYYY-MM-DD`
with its compare link (keep an empty `## Unreleased` above it), bump `relativelylight/Cargo.toml`,
commit `Release vx.y.z`, tag, push `main` and the tag, then `cargo publish -p relativelylight` from
the clean tagged tree. Pre-1.0, a behaviour break bumps the minor.
