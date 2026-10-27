# Data input validation — `relativelylight::validate`

Reusable field validators and normalizers. They are **typed predicates** on the natural Rust type
(`fn(&str) -> Result<(), String>`, or a factory returning `impl Fn(i64) -> Result<(), String>`), not
`serde_json::Value` closures, so the **same** check runs in the CRUD write path and in a hand-written
handler that holds a `&str` from a query string.

```rust
use relativelylight::validate;

// In the CRUD write path: MetaField sugar over the `validate::field` adapters.
a.field("value").validate_str(validate::ipv4);
mx.field("priority").validate_int(validate::int_range(0, 65535));
mx.field("target").validate_str(validate::all_of(vec![Box::new(validate::non_empty), Box::new(validate::fqdn)]));

// In your own handler: call the predicate directly.
validate::ipv4(&myip).map_err(ApiError::Validation)?;
```

The module is always compiled and std-only at its core. Two opt-in features reuse crates already in
the dependency tree:

| Feature | Gates |
|---|---|
| `validate-regex` | `regex_match` |
| `validate-base64` | `base64`, `base64_url` |

`url`, `idna` and `email_address` are deliberately avoided: the pragmatic `email` and `url` checks catch
typos, which is what field validation is for. Use `regex_match` or your own handler for anything stricter.

## Validators

Each returns `Ok(())` or `Err(message)`. Factories (`int_range`, `one_of`, …) bake their parameters in
once.

### Numbers

| Validator | Signature | Semantics |
|---|---|---|
| `int_range` | `fn(min: i64, max: i64) -> impl Fn(i64) -> Result<(),String>` | inclusive bounds. `int_min`/`int_max` convenience wrappers use `i64::MIN`/`MAX` for the open side. |
| `float_range` | `fn(min: f64, max: f64) -> impl Fn(f64) -> Result<(),String>` | inclusive; rejects `NaN`. |
| `port` | `fn(i64) -> Result<(),String>` | `1..=65535` (0 rejected — it is never a usable service port). A named special-case of `int_range` because it recurs constantly. |

### Network

All parse via `std::net` — no dependency, fully correct, and canonicalizing (rejects `1.2.3.a`,
`::g`, leading-zero ambiguities per Rust's parser).

| Validator | Signature | Accepts |
|---|---|---|
| `ipv4` | `fn(&str) -> Result<(),String>` | dotted-quad only (`std::net::Ipv4Addr`). |
| `ipv6` | `fn(&str) -> Result<(),String>` | `std::net::Ipv6Addr` (incl. compressed / v4-mapped). |
| `ip` | `fn(&str) -> Result<(),String>` | either family (`IpAddr`). |
| `ipv4_network` | `fn(&str) -> Result<(),String>` | `a.b.c.d/len`, `len` `0..=32`. |
| `ipv6_network` | `fn(&str) -> Result<(),String>` | `addr/len`, `len` `0..=128`. |
| `ip_network` | `fn(&str) -> Result<(),String>` | either. |

`*_network` accept host bits set (`10.0.0.1/8`); the address and prefix are checked, not that the
address is the network's first.

### Strings

| Validator | Signature | Semantics |
|---|---|---|
| `non_empty` | `fn(&str) -> Result<(),String>` | rejects empty **and** whitespace-only. |
| `length` | `fn(min: usize, max: usize) -> impl Fn(&str) -> Result<(),String>` | counts **Unicode scalar values** (`chars().count()`), not bytes — the count a user sees. A `length_bytes` variant exists for byte-bounded columns (DNS labels ≤ 63 **octets**). |
| `one_of` | `fn(&'static [&'static str]) -> impl Fn(&str) -> Result<(),String>` | membership; case-sensitive. `one_of_ci` for ASCII-case-insensitive (CAA `tag`: `issue`/`issuewild`/`iodef`). Message lists the allowed set. |
| `hex` | `fn(&str) -> Result<(),String>` | `[0-9a-fA-F]+`, even length. `hex_len(n)` factory pins an exact **byte** length (DS digest, SSHFP fingerprint). |
| `regex_match` | `fn(&str) -> impl Fn(&str) -> Result<(),String>` *(feature `validate-regex`)* | compiles once (panics at construction on a bad pattern — it is developer input, not user input); the escape hatch for anything not covered. |
| `email` | `fn(&str) -> Result<(),String>` | pragmatic `local@domain` check (one `@`, non-whitespace non-empty local, hostname-shaped domain with a dot). Std-only (reuses `hostname`). **Not** RFC 5322. |
| `url` | `fn(&str) -> Result<(),String>` | scheme + `://` + authority, restricted to `http`/`https` by default; `url_scheme(&[..])` factory to widen. Hand-rolled, std-only. |
| `base64` | `fn(&str) -> Result<(),String>` *(feature `validate-base64`)* | standard alphabet, valid padding (DNSKEY `public_key`). `base64_url` variant. |
| `uuid` | `fn(&str) -> Result<(),String>` | 8-4-4-4-12 hex; std-only, no `uuid` crate needed. |

### Passwords

| Validator | Signature | Semantics |
|---|---|---|
| `password` | `fn(PasswordPolicy) -> impl Fn(&str) -> Result<(),String>` | a [`PasswordPolicy`] as a string predicate, for the crud write path. **Wrap in `optional`** where blank has a meaning (it does on `MetaField::password()`: blank on create = no password, blank on edit = keep current). |
| `PasswordPolicy::check` | `fn(&self, &str, &[&str]) -> Result<(),String>` | the policy itself; the second argument is context words to reject as substrings (`auth` passes the account's username, which a single-field validator can't know). |

`PasswordPolicy` is **length-first with composition rules off**, per NIST SP 800-63B: screen for length
and against known-bad values, and don't require character-class mixtures — users satisfy `upper + digit +
special` with `Password1!`, so the rule costs usability and buys a search space every cracking ruleset
already covers. The flags exist for audits that insist (`legacy_composition()`); no other preset sets them.

| preset | length | screening | composition |
|---|---|---|---|
| `nist_minimum()` | ≥ 8 | common values, patterns, context words | — |
| `recommended()` *(`Default`)* | ≥ 12 | same | — |
| `legacy_composition()` | ≥ 12 | same | upper + lower + digit + symbol |

`from_level(1|2|3)` maps a config integer onto them (anything else → `recommended()`, so a typo doesn't
weaken the policy). Every preset also imposes a **maximum** length — a bound is a security control, since
the value reaches argon2 and hashing an unbounded input burns CPU per request — rejects control
characters, and rejects patterns (one repeated character, or any run of six consecutive characters).
Everything printable is otherwise allowed, including spaces and emoji, and nothing is truncated. The
built-in common-value list is a **floor, not a breach corpus**: matched whole (after folding, stripping a
digit/symbol tail, and undoubling), so `Password1!` and `passwordpassword` are caught while `abc`/`user`
don't reject every passphrase containing them. Real breach screening means a corpus or HIBP's k-anonymity
API — app-level, so not built in; add words via `blocklist` or replace the check.

`auth` applies this to `/profile` and a manager's reset by default and can be opted out of two ways — see
[AUTH.md §5g](AUTH.md), which also explains why both this surface *and* the admin form need wiring.

### Host and DNS names

ASCII only: validate an internationalized name in its `xn--` form.

| Validator | Signature | Semantics |
|---|---|---|
| `hostname` | `fn(&str) -> Result<(),String>` | one or more **strict LDH** labels, each `1..=63` chars (letters/digits/hyphen), no leading/trailing hyphen; total ≤ 253. No trailing dot. |
| `fqdn` | `fn(&str) -> Result<(),String>` | `hostname` rules **plus** a required trailing dot (an absolute name) — matches how DNS rdata targets are stored. The bare root `"."` is accepted. |
| `dns_name` | `fn(&str) -> Result<(),String>` | lenient owner/label form: `hostname` rules **plus** leading-underscore labels (`_dmarc`, `_acme-challenge`), an optional leading `*` wildcard label, and an optional trailing dot. |

## Combinators

| Combinator | Signature | Semantics |
|---|---|---|
| `all_of` | `fn(Vec<StrPredicate>) -> impl Fn(&str)->...` | run in order, return the **first** failure. (The common case: `all_of(vec![Box::new(non_empty), Box::new(fqdn)])`.) |
| `optional` | `fn(StrPredicate) -> impl Fn(&str)->...` | empty string passes; otherwise delegate to `f`. For nullable/blank-allowed columns. |
| `each` | `fn(char, StrPredicate) -> impl Fn(&str)->...` | split on the separator, validate every element with `f` (comma-separated ACLs). Reports the offending element's index. |

`StrPredicate = Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>`. Numeric fields carry one
range check, so there are no `i64` combinators.

## Normalizers

Some cleanups should accept and canonicalize rather than reject: trimming, lower-casing a hostname,
making an FQDN absolute, the canonical form of an IPv6 address. `validate::normalize` has `trim`,
`lowercase`, `ensure_trailing_dot` and `canonical_ip`; wire one into the write path with
`validate::field::str_transform`:

```rust
ns.field("target").on_write = Some(validate::field::str_transform(validate::normalize::ensure_trailing_dot));
```

`on_write` runs after the validators, so validate the raw shape and then canonicalize. A normalizer
must be **idempotent**: `on_write` is one half of a storage codec, and an unchanged edit form posts the
stored value back through it ([CRUD.md → A column's way in and out](CRUD.md#a-columns-way-in-and-out)).

## Messages

A message is short, field-local and stable (`"not a valid IPv4 address"`, `"must be between 0 and
65535"`) and never names the field: the caller owns the key. In `crud` it becomes the field's error
beside the input; a hand-written handler maps it into its own response.

The `field` adapters (`str_field`, `int_field`) let `null` pass — nullability is the column's concern —
and report a value of the wrong JSON type as `expected a string` / `expected an integer`, which coercion
normally catches first.
