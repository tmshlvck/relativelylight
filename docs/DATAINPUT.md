# Data input validation

relativelylight already has the *seam* for validation — every `MetaField` carries an optional
`validate: Option<Fn(&Value) -> Result<(), String>>` hook, run in the write pipeline between coerce
and transform (see [CRUD.md § Validation & transforms](CRUD.md#validation--transforms)). What it
lacks is a **standard library of validators** to plug into that seam. Today every app hand-rolls
"is this a valid IPv4 address" as a one-off closure, or — more often — skips it, so malformed data
(`1.2.3.a` in an A record) is written unchecked.

This document specifies `relativelylight::validate`: a small, dependency-light module of reusable
field validators (and a few normalizers), designed so the **same** check runs in the auto-CRUD write
path *and* in an app's hand-written endpoints. It is a design proposal — nothing here is built yet.

---

## 1. Goals & the one design decision

**Goals**

- A curated set of the validators every back-office needs (numbers-in-range, network addresses,
  email/URL, enums, lengths, regex), plus combinators to compose them.
- **Write once, use on every surface.** relativelylight generates the CRUD API and admin, but apps
  also expose hand-written endpoints (teleddns-server has three: DDNS, a native JSON API, and a
  Cloudflare facade). The identical validator must be callable from a `MetaField.validate` closure
  *and* directly from app code, so the rule lives in one place.
- Dependency-light and feature-gated: pulling in `validate` must not force `regex`/`url`/`idna` on
  an app that only wants `ipv4`.
- Stable, human-readable messages that each surface can wrap into its own error envelope.

**The one decision everything follows from:** validators are **typed predicates on the natural Rust
type**, not `Value` closures.

The crud hook wants `Fn(&Value) -> Result<(), String>`. That shape is not *unusable* off the CRUD
path — a `Value`-map handler (teleddns-server's native API pulls each field out of a
`Map<String, Value>` per-field, so it could call a `Fn(&Value)` directly). The problem is that
`Fn(&Value)` is the wrong **lowest common denominator**, for two reasons:

- **DDNS has no `Value` at all** — it reads `HashMap<String, String>` query params (`myip=…`). To run
  a `Fn(&Value)` there you would wrap `Value::String(myip.clone())`: an allocation and a whole
  `serde_json` dependency for what is fundamentally a string check. A `fn(&str)` is callable from
  *every* surface; only crud (the genuinely `Value`-based one) then needs an adapter. Adapt toward the
  richer type, not away from it.
- **`Validator` is a *holder*, not a validator.** `Box<dyn Fn(&Value) -> …>` is just the shape of the
  slot on `MetaField`; the library ships zero validators in it. So "reuse the crud `Validator`" is a
  category error — there is nothing to reuse until you write the function. The reusable unit *is* a
  named function; the only question is its signature, and `&str`/`i64` wins on the point above.

So the canonical form is:

```rust
pub fn ipv4(s: &str) -> Result<(), String>;
pub fn int_range(min: i64, max: i64) -> impl Fn(i64) -> Result<(), String>;
```

and crud gets **thin adapters** that lift a typed predicate into a `MetaField` `Validator`:

```rust
// relativelylight::validate::field  — crud adapters
pub fn str_field(f: impl Fn(&str) -> Result<(), String> + Send + Sync + 'static) -> Validator;
pub fn int_field(f: impl Fn(i64)  -> Result<(), String> + Send + Sync + 'static) -> Validator;
```

The adapter reads the coerced `Value` (a `String`/number by the time `validate` runs — see the
pipeline in CRUD.md), pulls out the typed payload, and calls the predicate. A `null`/absent field is
the field's own concern (nullability), so the adapters treat "wrong JSON type here" as an internal
`expected string`-style message; coercion has normally already caught it.

This is why the module lives at the **crate root** (`relativelylight::validate`), not under `crud`:
the predicates have no dependency on crud, and the hand-written-API use case is first-class. Only the
`validate::field` submodule (the adapters) references `crud::Validator`, and it is compiled only with
the `crud` feature.

---

## 2. Module layout

```
relativelylight::validate
├─ (root)         typed predicates + predicate factories + combinators
├─ ::field        crud adapters: typed predicate → crud::seaorm::Validator   (feature = "crud")
└─ (re-exports)   crud::ValidationErrors stays where it is; validate does not own row validation
```

Feature flags (all off by default; `validate` itself is always compiled — it is std-only at the
core):

| Feature | Pulls in | Gates |
|---|---|---|
| — (always) | `std::net` only | `ipv4`, `ipv6`, `ip`, `*_network`, `int_range`/`int_min`/`int_max`, `float_range`, `port`, `length`/`length_bytes`, `non_empty`, `one_of`/`one_of_ci`, `hex`/`hex_len`, `hostname`, `fqdn`, `dns_name`, `email`, `url`/`url_scheme`, `uuid`, the combinators, and `normalize::*` |
| `validate-regex` | `regex` (already an optional dep) | `regex_match` (the escape hatch) |
| `validate-base64` | `base64` (already an optional dep) | `base64`, `base64_url` |

`email` turned out **std-only** — its domain half reuses `hostname`, so it needs no regex; only the
generic `regex_match` escape hatch is gated behind `validate-regex`.

`regex` and `base64` are **already** optional dependencies in `Cargo.toml` (currently only enabled by
`sso`). The new features just make them available to `validate` too, so no new crates enter the tree.
Deliberately **avoided**: `url`, `idna`, `email_address` — see § 6.

---

## 3. The validators

Signatures are the canonical typed predicates. Each returns `Ok(())` or `Err(message)`. Factories
(`int_range`, `one_of`, …) return a closure so parameters are baked in once.

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

`*_network` parse the address and prefix length themselves (std has no CIDR type). An **option**:
also offer a `*_host_in_network` strict variant that rejects host bits set (i.e. requires the network
address); most DNS/ACL uses want the lax form, so lax is the default and strict is a separate name,
never a flag.

### Strings

| Validator | Signature | Semantics |
|---|---|---|
| `non_empty` | `fn(&str) -> Result<(),String>` | rejects empty **and** whitespace-only. |
| `length` | `fn(min: usize, max: usize) -> impl Fn(&str) -> Result<(),String>` | counts **Unicode scalar values** (`chars().count()`), not bytes — the count a user sees. A `length_bytes` variant exists for byte-bounded columns (DNS labels ≤ 63 **octets**). |
| `one_of` | `fn(&'static [&'static str]) -> impl Fn(&str) -> Result<(),String>` | membership; case-sensitive. `one_of_ci` for ASCII-case-insensitive (CAA `tag`: `issue`/`issuewild`/`iodef`). Message lists the allowed set. |
| `hex` | `fn(&str) -> Result<(),String>` | `[0-9a-fA-F]+`, even length. `hex_len(n)` factory pins an exact **byte** length (DS digest, SSHFP fingerprint). |
| `regex_match` | `fn(&str) -> impl Fn(&str) -> Result<(),String>` *(feature `validate-regex`)* | compiles once (panics at construction on a bad pattern — it is developer input, not user input); the escape hatch for anything not covered. |
| `email` | `fn(&str) -> Result<(),String>` | pragmatic `local@domain` check (one `@`, non-whitespace non-empty local, hostname-shaped domain with a dot). Std-only (reuses `hostname`). **Not** RFC 5322 — see § 6. |
| `url` | `fn(&str) -> Result<(),String>` | scheme + `://` + authority, restricted to `http`/`https` by default; `url_scheme(&[..])` factory to widen. Hand-rolled, std-only (see § 6). |
| `base64` | `fn(&str) -> Result<(),String>` *(feature `validate-base64`)* | standard alphabet, valid padding (DNSKEY `public_key`). `base64_url` variant. |
| `uuid` | `fn(&str) -> Result<(),String>` | 8-4-4-4-12 hex; std-only, no `uuid` crate needed. |

### DNS-shaped (domain-specific but unavoidable in a DNS control plane)

Kept in the general module because "is this a hostname" recurs well beyond DNS apps, and because
teleddns-server needs them for the `value` side of NS/CNAME/MX/PTR/SRV.

| Validator | Signature | Semantics |
|---|---|---|
| `hostname` | `fn(&str) -> Result<(),String>` | one or more **strict LDH** labels, each `1..=63` chars (letters/digits/hyphen), no leading/trailing hyphen; total ≤ 253. No trailing dot. |
| `fqdn` | `fn(&str) -> Result<(),String>` | `hostname` rules **plus** a required trailing dot (an absolute name) — matches how DNS rdata targets are stored. The bare root `"."` is accepted. |
| `dns_name` | `fn(&str) -> Result<(),String>` | lenient owner/label form: `hostname` rules **plus** leading-underscore labels (`_dmarc`, `_acme-challenge`), an optional leading `*` wildcard label, and an optional trailing dot. |

---

## 4. Combinators

Predicates compose so a field can carry several rules with one message pipeline:

| Combinator | Signature | Semantics |
|---|---|---|
| `all_of` | `fn(Vec<StrPredicate>) -> impl Fn(&str)->...` | run in order, return the **first** failure. (The common case: `all_of(vec![Box::new(non_empty), Box::new(fqdn)])`.) |
| `optional` | `fn(StrPredicate) -> impl Fn(&str)->...` | empty string passes; otherwise delegate to `f`. For nullable/blank-allowed columns. |
| `each` | `fn(char, StrPredicate) -> impl Fn(&str)->...` | split on the separator, validate every element with `f` (comma-separated ACLs). Reports the offending element's index. |

`StrPredicate = Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>`. The combinators are
**string-shaped**: numeric fields carry a single range check (`int_range`/`port`), which does not need
composing, so no `i64` combinators are provided.

---

## 5. Validate vs. normalize

A recurring confusion worth settling in the API: some "cleanups" are **normalizers**, not validators,
and belong in the existing `on_write` (`WriteTransform`) hook, not `validate`:

- lower-casing a hostname,
- trimming surrounding whitespace,
- appending a trailing dot to make an FQDN absolute,
- collapsing an IPv6 address to canonical form.

Doing these as validators (reject non-canonical input) is user-hostile; doing them as transforms
(accept and canonicalize) is kind. So the module ships a parallel, smaller set of **normalizers**
under `validate::normalize` returning the transformed value:

```rust
pub mod normalize {
    pub fn trim(s: &str) -> String;
    pub fn lowercase(s: &str) -> String;
    pub fn ensure_trailing_dot(s: &str) -> String;      // FQDN
    pub fn canonical_ip(s: &str) -> String;             // via std parse, best-effort
}
// crud adapter mirrors validate::field:
pub fn field::str_transform(f: impl Fn(&str)->String + ...) -> WriteTransform;
```

Pipeline order is already **coerce → validate → transform** (CRUD.md), so normalize-after-validate is
the natural fit: validate the raw shape, then canonicalize. (Where an app wants "accept sloppy, store
clean" it can skip the strict validator and rely on the normalizer alone.)

---

## 6. Dependency policy (why some are hand-rolled)

The design leans on `std::net` and hand-rolled character checks to keep `validate` installable
without a dependency wall:

- **IP / network / UUID / hex / hostname / port / lengths / ranges / enums** — zero deps. `std::net`
  is authoritative for addresses; the rest are trivial character predicates.
- **`email`, `regex_match`** — behind `validate-regex`, reusing the `regex` crate the tree already
  has for SSO. Full RFC 5322 email validation is a famous rabbit hole and almost never what an app
  wants; the pragmatic `local@domain` check catches typos, which is the real goal. Apps needing more
  use `regex_match` with their own pattern.
- **`url`** — hand-rolled scheme/authority check rather than the `url` crate (a heavy transitive
  tree) because field validation only needs "is this a well-formed http(s) URL", not full WHATWG
  parsing/normalization. If an app needs true URL parsing it should do it in its handler.
- **`base64`** — behind `validate-base64`, reusing the existing optional `base64` dep.

If real demand appears for RFC-grade email/URL, add opt-in features (`validate-email` → `email_address`,
`validate-url` → `url`) later without changing the default surface.

---

## 7. Integration

### 7a. Auto-CRUD (admin + generated API) — the adapter

```rust
use relativelylight::validate::{self, field};

let mut a = MetaModel::new(rr::a::Entity);
a.field("value").validate = Some(field::str_field(validate::ipv4));
a.field("ttl").validate   = Some(field::int_field(validate::int_range(0, 2_147_483_647)));

let mut mx = MetaModel::new(rr::mx::Entity);
mx.field("priority").validate = Some(field::int_field(validate::int_range(0, 65535)));
mx.field("value").validate    = Some(field::str_field(
    validate::all_of(vec![Box::new(validate::non_empty), Box::new(validate::fqdn)])));
```

**Ergonomics add (optional but recommended):** a `MetaField::validate(f)` *builder method* taking a
typed predicate directly, so callers skip the `field::*_field` wrapping and the `Some(Box::new(...))`
ceremony that the current examples show:

```rust
a.field("value").validate_str(validate::ipv4);          // sugar over field::str_field
mx.field("priority").validate_int(validate::int_range(0, 65535));
```

This is backward compatible — the public `pub validate` field stays; the methods just set it.

### 7b. Hand-written endpoints — the same predicate, no crud

This is the payoff. teleddns-server's native API pulls each field out of a `Map<String, Value>` and
validates it before building the row; it calls the predicate directly on the extracted `&str`/`i64`
and maps the message into its `{ "error": … }` envelope:

```rust
// record_view.rs, `write_record` — replacing the inline `dns::is_ipv4` check
let value = rstr(obj, "value")?;                                 // String out of the Value map
validate::ipv4(&value).map_err(|m| ApiError::Validation(m))?;
let ttl = obj.get("ttl").and_then(|v| v.as_i64()).unwrap_or(default_ttl as i64);
validate::int_range(0, i32::MAX as i64)(ttl).map_err(|m| ApiError::Validation(m))?;
```

DDNS reads its `myip=…` as a `&str` query param (no JSON) and calls the identical `validate::ipv4`;
the CF facade wraps the same calls into the CF envelope. One rule, three surfaces, plus the admin —
exactly the "one authorization model, three surfaces" discipline teleddns already follows, now for
input validation.

**These predicates already exist in teleddns**, hand-rolled in its `dns` module —
`dns::is_ipv4`/`is_ipv6`/`is_valid_name` are `fn(&str) -> bool`, called today by both DDNS and the
native API. This module absorbs them (adding the error message the `bool` form can't carry), so
adopting `validate` in teleddns is a **delete-and-redirect** — retire the local `dns::is_*` helpers
and point every call site at `relativelylight::validate` — not net-new code. That the app already
reached for typed `&str` predicates is the strongest evidence the canonical shape is right.

### 7c. Reference consumer — teleddns-server RR field map

Concrete target for the first consumer, to validate the API against real needs (one table per RR
type; shared `(label, ttl)`):

| Type | Field → validator |
|---|---|
| A | `value → ipv4`; `ttl → int_range(0, i32::MAX)` |
| AAAA | `value → ipv6` |
| NS / CNAME / PTR | `value → fqdn` |
| MX | `priority → int_range(0,65535)`; `value → fqdn` |
| SRV | `priority/weight → int_range(0,65535)`; `port → port`; `value → fqdn` |
| CAA | `flag → int_range(0,255)`; `tag → one_of_ci(["issue","issuewild","iodef"])`; `value → non_empty` |
| SSHFP | `algorithm → int_range(0,4)`; `hash_type → int_range(0,2)`; `fingerprint → hex` |
| TLSA | `cert_usage/selector/matching_type → int_range(0,3\|1\|2)`; `cert_data → hex` |
| DNSKEY | `flags → int_range(0,65535)`; `protocol → one_of(["3"])`; `algorithm → int_range(0,255)`; `public_key → base64` |
| DS | `key_tag → int_range(0,65535)`; `algorithm → int_range(0,255)`; `digest_type → int_range(0,4)`; `digest → hex` |
| NAPTR | `order/preference → int_range(0,65535)`; `replacement → fqdn`; others → `length` bounds |
| `label` (all) | `all_of([length_bytes(0,63), hostname_rel])` or `one_of(["@"])`-tolerant label check |

(Exact numeric ceilings per RFC are the consumer's call; the table shows the *shape*.)

---

## 8. Errors & messages

- Predicates return `Err(String)` — a short, human-readable, **field-local** message
  (`"not a valid IPv4 address"`, `"must be between 0 and 65535"`). No field name inside the message;
  the caller owns the field key.
- In crud, the adapter's `Err` becomes a `ValidationErrors.fields[name]` entry → the existing **422**
  `{ "error": "validation failed", "fields": { … } }` (CRUD.md § Validation). No change to the engine.
- In hand-written handlers, the app maps the message into whatever envelope that surface uses.
- Messages are **stable strings** (documented, not machine codes). If structured codes are ever
  needed, that is an additive `ErrKind` enum later — out of scope now.

---

## 9. Testing

- Unit tests per predicate: a table of accept/reject cases, especially the adversarial ones
  (`1.2.3.a`, `1.2.3.4.5`, `::g`, `256.1.1.1`, leading-zero octets, `/33`, empty, whitespace,
  trailing-dot presence/absence, non-ASCII in hostnames, odd-length hex, unpadded base64).
- Adapter tests: `field::str_field(ipv4)` on a `Value::String`, and behaviour on a non-string Value.
- A doc-test on the combinator example so the README snippet can't rot.

---

## 10. Decisions & remaining questions

Resolved while implementing:

1. **Builder sugar shipped.** `MetaField::validate_str` / `validate_int` are in — they wrap the
   `field::*` adapters, so the ergonomic path is `field("value").validate_str(validate::ipv4)`.
2. **`hostname` strictness settled by two names**, not a flag: a strict-LDH `hostname` (+ `fqdn` for
   the absolute form) and a lenient `dns_name` (leading `_`, `*` wildcard, optional trailing dot).
3. **`email` is std-only** (its domain half reuses `hostname`); only `regex_match` is gated behind
   `validate-regex`.

Still open:

4. **IDNA / Unicode hostnames:** currently ASCII-only (validate the `xn--` form as plain LDH). A
   `validate-idna` feature accepting U-labels could come later if demand appears.
5. **`each` separator semantics** for quoted TXT segments — left out of scope; TXT is freeform.
6. **A short § in CRUD.md** cross-linking to this doc from the "Validation & transforms" section is
   not yet added (this doc + the `lib.rs` module entry are).

---

## 11. Status & rollout

- **Done (in `relativelylight`, `main`):** `src/validate.rs` — all predicates in §3, the `all_of` /
  `optional` / `each` combinators, `normalize::*`, and the `field` adapters (crud-gated); the
  `validate-regex` / `validate-base64` features (reusing existing deps); the `MetaField::validate_str`
  / `validate_int` sugar; the `lib.rs` module entry; unit tests (13, incl. adversarial cases + the
  crud-adapter + feature-gated tests). `cargo test`/`clippy --all-features` clean; builds with and
  without the `crud` feature.
- **Next — tag a release:** cut a `relativelylight` version so teleddns-server can bump its pin.
- **Next — first consumer (teleddns-server):** wire the § 7c map across the RR entities and all three
  hand-written surfaces, retiring the local `dns::is_*` helpers (delete-and-redirect) — closing the
  `1.2.3.a` gap on every path.
- **Later:** grow the set from real demand (IDNA, RFC email/URL, MAC, country/language codes) as
  opt-in features — never bloating the std-only default.
