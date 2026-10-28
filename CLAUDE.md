# relativelylight

A web back-office toolkit for Rust. From SeaORM entities it generates a **server-rendered CRUD
admin** and **authentication/authorization**, with no per-model code. It is a library composed *into*
an app: the app keeps its axum router and page shell; the crate contributes HTML fragments and the
write path behind them. There is no JSON API and no JavaScript framework — rendering is Rust matching
on typed columns, writes are posted forms (`POST` → `303` → `GET`).

Start with [README.md](README.md) (features, quick start, examples) and [docs/APP.md](docs/APP.md)
(a whole app). The reference guides are [docs/CRUD.md](docs/CRUD.md), [docs/AUTH.md](docs/AUTH.md),
[docs/TIME.md](docs/TIME.md), [docs/DATAINPUT.md](docs/DATAINPUT.md) and
[docs/BLOBSTORE.md](docs/BLOBSTORE.md); upgrading is [docs/MIGRATION-0.4.md](docs/MIGRATION-0.4.md);
the design is [docs/DESIGN.md](docs/DESIGN.md) and open work [docs/TODO.md](docs/TODO.md).

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
- **The password policy covers typed input only.** Wire the same policy into an admin form's password
  field too, or that form is the way around it (`examples/adminpanel`).
- **Never register `auth_totp_recovery` in an admin panel** (every row is a credential hash), and hide
  `auth_user.totp_last_step`.
- **Lockout counters are shared**: an app checking credentials itself uses `auth.username_lockout()` /
  `auth.ip_lockout()`, not a second limiter. Pruning (`auth.prune()`) is scheduled by the app; the
  crate spawns no tasks and writes nothing to stdout or stderr.
- **Configure `Auth` fully before `Sso::new(&auth)`** clones it.
- Entities need a single-column primary key and single-column to-one FKs; N:M junction tables are
  never registered (`post.relate(&tag)` declares N:M).

## Working on the library

A Cargo workspace: the crate is `relativelylight/` (`crud/` with `ui/` as the renderer, `auth/`,
`blob/`, `authz.rs`, `observe.rs`, `time.rs`, `validate.rs`; Askama templates in `templates/`; CSS and
the picker's script in `assets/`), with runnable examples in `examples/` sharing `examples/model`.
Deps: SeaORM 2.0, axum 0.8, askama 0.13, jiff 0.2, totp-rs 5.7.

```bash
cargo build --all-features && cargo test --all-features && cargo clippy --all-features --all-targets
```

**`--all-features` is not enough.** It can't catch a feature that forgets to enable what it uses, or
a helper that is dead code in a narrower build. Before a release, check the matrix for **warnings**
as well as errors:

```bash
for f in "" crud axum csrf tz csv auth auth,sso crud,ui crud,ui,csv blob blob-ui; do
  cargo build -p relativelylight --no-default-features ${f:+--features $f} 2>&1 \
    | grep -E "^(error|warning: )" | grep -v "the following packages"
done
cargo build --workspace      # the examples pin their own narrow feature sets
```

Don't run `rustfmt` over the whole repo; format only what you touch.

**Security behaviour is tested by rejection.** `auth/security_tests.rs`, `auth/sso_tests.rs` (a fake
IdP) and `crud/gate_tests.rs` assert the negative cases over in-memory SQLite: bad credentials,
unusable sessions, replayed codes, non-manager profile writes, each gate's decision, refused reads,
CSRF on every write. `crud/ui_tests.rs` covers escaping and form decoding; `crud/transform_tests.rs`
covers a value's way through form, CSV and the codec against a real database. Touching login, sessions,
2FA, the profile pages or a gate means extending them, with a positive control so the negatives can't
pass vacuously ([AUTH.md §9](docs/AUTH.md#9-tests--the-negative-paths)).

**The docs are part of the change.**

- Update the guide that owns the behaviour, and the doc comments.
- Demonstrate user-facing features in an example (a new one goes in the root `Cargo.toml` `members`
  and the README's example list).
- A new module or feature: the table in `docs/DESIGN.md`, a pointer in `README.md`; move shipped items
  out of `docs/TODO.md`.
- Anything a user would notice gets a `CHANGELOG.md` entry under `## Unreleased` in the same change,
  breaking items first with the upgrade step — and, for a breaking change, a step in the current
  `docs/MIGRATION-x.y.md`.
- `DESIGN.md` holds the design and its decisions, `TODO.md` is the only place for open work and
  future ideas, the guides describe what ships. `README.md` is the starting point; this file is
  orientation. Cross-link rather than copy.

**Releasing:** rename `## Unreleased` to `## [x.y.z] — YYYY-MM-DD` with its compare link, bump
`relativelylight/Cargo.toml`, commit `Release vx.y.z`, tag, push the tag. Pre-1.0, a behaviour break
bumps the minor.
