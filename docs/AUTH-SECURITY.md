# `relativelylight::auth` — the security reasoning

[AUTH.md](AUTH.md) says what each part of `auth` does and how to use it. This file says why it
behaves that way: what each rule defends against, what it deliberately doesn't, and why a choice
went the way it did. The sections follow AUTH.md's order and each links back to the part it explains.
The module-level decisions are in [DESIGN.md → auth](DESIGN.md#auth).

## Sessions and cookies

Explains [AUTH.md §5f](AUTH.md#5f-session-lifetime--revocation).

**The idle clock is the one that bounds a stolen cookie.** Without it, an attacker who lifts a cookie
has the full absolute window, whether or not the victim ever comes back.

**`last_seen_at` is refreshed lazily** (only when more than a minute stale) because `identify` is
called once per gated model: an `Admin` page with five tables resolves the caller five times, so an
eager refresh would turn one page render into five writes.

**`Auth::identify` never changes a session id**, so it stays a cheap call that needs no response to
write into. Everything that changes an id happens inside a POST handler that already owns its
response.

**Rotation on privilege gain.** Login mints a new server-generated id, and confirming the second
factor mints another and deletes the half-authenticated one. So a session cookie an attacker planted
in the victim's browser (cookie-tossing, an XSS) is never elevated by the victim's own login.

**A password change signs out everything else.** The commonest reason to change a password is "I
think someone else is in my account", and a session that outlives the credential that created it
defeats exactly that. The caller's own previous id is deleted too, since it is one of the values that
might have been copied.

## The admin helpers

Explains [AUTH.md §5 → Admin helpers](AUTH.md#admin-helpers--who-may-re-open-an-account).

The three helpers have deliberately different blast radii, so a routine password reset can never
restore login capability by accident.

- **`set_password` is a reset, not an upsert**, so a typo can't silently become a new login.
- **`reset_admin_access` refuses an SSO account.** Grafting a local password onto it would quietly
  take the account out of the identity provider's hands, and out of its group reconciliation.

## TOTP

Explains [AUTH.md §5a](AUTH.md#5a-totp-two-factor-authentication).

**The replay guard (RFC 6238 §5.2).** A code is valid for its own 30-second step *and* the two
neighbours (±1 skew for clock drift), so without a guard the same six digits work for about 90
seconds. Requiring a strictly greater step than the last accepted one makes each code usable exactly
once.

- **Enrolment spends a step too**, or the code that confirmed setup would still work at `/login/totp`
  afterwards.
- **Turning 2FA off clears the guard** in the same write that clears the secret. A stale ceiling
  would silently refuse the first codes of a re-enrolment.
- **A replayed code gets the same message as a wrong one.** "Already used" would confirm to someone
  holding a captured code that they hold a real one. It counts against the account's lockout budget
  like any other failure.
- **What it covers.** It stops a spent code being reused by someone who also has the password (a
  shoulder-surf, a screen share). It does nothing against real-time phishing, where a proxy relays
  the code once; that needs a phishing-resistant factor such as a passkey
  ([AUTH.md §5l](AUTH.md#5l-passkeys-feature-passkeys)).

**A blank secret counts as no secret.** Treating `Some("")` as "2FA on" would demand a login code no
authenticator can produce — an account locked out of its own login — and an empty text input in an
admin form is exactly how that value appears. The same holds for a blank `sso_provider`: an admin
form that leaves the column empty writes `""`, and the account it creates must stay an ordinary local
one.

## SSO

Explains [AUTH.md §5b](AUTH.md#5b-sso--openid-connect-feature-sso).

**The username claim is matched case-insensitively** because providers are not consistent about case.
An IdP that switched from `alice@corp` to `Alice@corp` would otherwise miss the existing account and —
with auto-registration on — create a second one: two rows, two group sets, one human. Local password
login still matches exactly, because changing that would be a behaviour break for every existing
account.

**Discovery is cached for an hour** so a sign-in costs no extra round trips and looping on
`/sso/{key}/login` can't flood your provider. An hour is safe for key rotation: providers publish a
new key well before retiring the old one.

### The transaction cookie

**It is not signed, and signing it would not help.** `state`, `nonce` and the PKCE verifier ride in a
`HttpOnly` cookie as base64 JSON, so the `state` check compares two values that both came from that
cookie. Anyone who can **write** a cookie for your host (a sibling-host XSS, cookie-tossing, an
active attacker on plain http) can therefore supply a transaction of their choosing and complete a
login in the victim's browser — *login CSRF*: the victim ends up signed in as the **attacker's**
identity. Note the direction: the attacker gains none of the victim's access; the harm is a victim
who acts inside an account someone else controls.

Signing the cookie would stop forgery and change nothing here, because forgery isn't needed:
`/sso/{key}/login` hands a genuine transaction to whoever asks, so an attacker can plant a validly
signed one of their own. The protection therefore rests on the same assumption as the double-submit
CSRF token ([CSRF](#csrf)) — a cross-site attacker can neither read your cookies nor set one for your
host — which in practice means HTTPS (ideally HSTS), no XSS, and not sharing a registrable domain
with something you don't trust.

### The `rsa` advisory

`cargo audit` reports `rsa` (RUSTSEC-2023-0071, the Marvin attack) in any build with `sso`:
`openidconnect` depends on it to check RS256 ID-token signatures, and no fixed `rsa` release exists.
The attack recovers a **private** key from the timing of decryption or signing. SSO here only
verifies signatures, using the provider's public key, so this crate holds no RSA private key to leak.
That is why ignoring the advisory is safe until `openidconnect` moves to a fixed `rsa`.

## Lockout

Explains [AUTH.md §5e](AUTH.md#5e-lockout-the-brute-force-brake).

**Durable, shared rows**, so a restart or a second replica doesn't hand an attacker a fresh budget.

**A locked key records nothing**, so an attacker cannot push the expiry out by continuing.

**A locked check never looks at the submitted secret.** So a locked account costs no argon2 work, and
the response is identical for a real and a made-up username (no enumeration hint).

**Why each check is or isn't counted:**

| Check | Why |
|---|---|
| `POST /login` | the anonymous guessing surface |
| `POST /login/totp` | still unauthenticated (the session grants nothing until the code is confirmed), and 6 digits are the most guessable secret we hold |
| the app's own checks | same counters, so one account has one budget everywhere |
| `POST /profile` (current password), not limited | the caller is *authenticated*: that's session theft, whose mitigations are short TTLs and re-authentication ([§5h](AUTH.md#5h-re-authentication-before-sensitive-changes)) — and counting it would let a stolen session lock the real user out of logging in |
| `POST /profile/totp` (enrolment code), not limited | authenticated, and the code guessed is the caller's *own* pending secret |
| `POST /profile/{id}` (manager reset), not limited | verifies no secret; gated by group membership instead |
| passkey sign-in, address only | the passkey names no account until it is verified |
| passkey second factor | the same step as a TOTP code |
| `Auth::identify_key`, address only | a key names no account, so the address is all there is to count |

**Configuration is an argument to `Auth::new`**, not a builder call, so there is no way to end up
with an unbraked login by forgetting one.

**Two independent windows.** An address is a coarser subject than an account, so it usually deserves a
different budget. The address budget is far looser than the account one because a locked address
turns away *valid* callers too, which matters when users share one (CGNAT, an office NAT).

**There is no username whitelist.** An account that can never be locked out is an account whose
password can be guessed at forever. The address whitelist exists for the opposite reason — so one
shared address cannot take everyone down with it.

**The app's own checks share these counters.** A second limiter would give an account two budgets,
and an unlock would free only half of them.

**What may be recorded as a failure.** Only a credential that was actually checked and rejected —
never a request with no credential at all, a failed CSRF check, or one turned away *because* it was
locked — or a third party can spend someone else's budget.

**The unlock is a row delete** in an ordinary admin panel: gated, CSRF-checked and audited like any
other write, with no bespoke endpoint, no CLI and no shelling into the host.

**Skipping `prune` is safe.** A dead session never authenticates and an expired lockout row reads as
unlocked and resets itself on the next failure; the rows just accumulate.

**The trade-off.** Someone who knows an account name can keep it locked by failing on purpose. That
is why the lock is short, lifts on its own, and can be cleared from the admin panel; the
alternative, progressive delays, holds a server task open per attempt.

## Password policy

Explains [AUTH.md §5g](AUTH.md#5g-password-strength).

**It governs typed input, not code.** If the policy governed `create_user`, `set_password`,
`make_admin` and `reset_admin_access`, a deployment could be left with no way to set a first
password at all.

## Re-authentication

Explains [AUTH.md §5h](AUTH.md#5h-re-authentication-before-sensitive-changes).

A live session proves that **someone** logged in once. It does not prove that the account's owner is
the one asking now — a stolen cookie *is* a live session. The idle clock bounds how long such a cookie
lasts; re-authentication bounds what it can **do** while it lasts. So the actions that would let an
intruder entrench ask for a factor again, per request.

**Why each route asks:**

| Route | Why |
|---|---|
| `POST /profile/totp/disable` | removing the second factor is step one for an intruder |
| `POST /profile/totp` (enrol) | otherwise they enrol *their own* authenticator — which doesn't just persist access, it **locks the real user out**, since login then wants a code only they can produce |
| `POST /profile/{id}` (reset) | sets a password without knowing the old one; every account it reaches is one the session can then log in as |
| `POST /profile/{id}/totp/disable` | strips a victim's second factor |
| `POST /profile/api-keys` (mint) | a key outlives the session and skips the second factor — a stolen session must not become a permanent credential |
| `POST /profile/passkeys` (add) | a passkey is a new way into the account |
| `POST /profile/password/remove` | it changes how the account signs in |
| `POST /profile` without a password (setting one) | a password is a new way into the account |
| `POST /profile/{id}/passkeys/remove` | strips a victim's passkeys |

**Removals are not re-authenticated** (signing out other sessions, revoking a key, removing a
passkey): each only removes access, and a user racing to evict an intruder shouldn't be slowed down.

**A fresh code is preferred** when the account has 2FA: it proves presence, where a password may have
been filled in by the browser for whoever is sitting there. A code accepted here is **spent**
([TOTP](#totp)), so one captured code can't wave through both a sensitive action and a login.

**An SSO account confirms at its provider.** Passing it for want of a password would make a stolen
session of an SSO administrator worth every account it could reset.

- **Confirm first, then act.** A provider needs a redirect there and back. Replaying a parked `POST`
  on return would need form bodies stored and a replay path through every handler, so instead the
  round trip leaves a **one-use** confirmation on the session, spent by the next sensitive action and
  expiring after five minutes: still per request, not a window.
- **What it proves:** that the browser signs in at the provider **as the session's account**, which
  a stolen session cookie can't. Another account, or one the site doesn't have, confirms nothing
  (and registers nothing). It proves no fresh sign-in, since a provider with its own session returns
  without asking; Google can't be asked to ask (it refuses unknown `prompt` values), so the default
  request is a plain sign-in. `reauth_max_age` makes a provider that re-prompts strict: `max_age`
  and a request for `auth_time`, refused without a recent one.
- **Bound to the session that asked.** The provider's redirect back is cross-site, so the `Strict`
  session cookie doesn't come with it. The `Lax` transaction cookie carries the session's **SHA-256**
  (the id is a credential), found among the confirmed account's sessions. Starting one reads the
  `Strict` cookie, so another site can't start it. The callback, for a sign-in too, leaves by a page
  that navigates itself: a redirect would still be cross-site and arrive without the session.
- **Fail closed:** with no provider routes mounted, an SSO account is refused.

A local account with no factor at all passes: there is nothing to ask, and it can't sign in anyway.

**Not lockout-limited**, for the [lockout](#lockout) reason: the caller is authenticated, so counting
failures here would let a stolen session lock the real user out of logging in. Nor is it needed —
guessing a password is no easier here than at `/login`, and a 6-digit code would take ~10⁶ requests
inside its 90-second window.

**Per request, not a window.** A "you confirmed five minutes ago" grace period would reopen exactly
the window a stolen session needs. An SSO account's confirmation is no such window: it is spent by
the one action it was made for.

## Recovery codes

Explains [AUTH.md §5i](AUTH.md#5i-totp-recovery-codes).

**Why they exist.** Without them, an enrolled user who loses their authenticator can only be let back
in by a manager disabling their 2FA — workable for staff with an IT department, useless for everyone
else, and an availability problem the moment re-authentication means a live session can no longer
simply switch 2FA off.

**Regeneration is re-authenticated**, because a new set is a new way into the account and an intruder
holding a session must not be able to mint one. Issuing a set invalidates the previous one, which is
what makes regeneration the right response to "I think my codes leaked".

**They are destroyed when 2FA is turned off.** They are a way past a second factor, so without one
they would just be a weaker second password — and a later re-enrolment must not inherit a set the
user threw away with their old phone.

**Hashed with SHA-256, not argon2 — deliberately.** Codes are machine-generated with ~49 bits of
entropy (10 characters from a 30-symbol Crockford-style alphabet, so nothing reads as `0`/`1`), which
is exactly the case argon2 is *not* for: no attacker enumerates a 49-bit space however cheap the
hash. What a slow hash would cost is real and paid by the defender — a submitted code must be matched
against the user's whole set, so up to ten argon2 verifications (≈190 MiB transient, most of a second)
on the **unauthenticated** login path, per attempt. A single SHA-256 makes it one indexed equality
lookup: O(1), no comparison loop, and nothing whose duration depends on how far into the set the
match was. The hash is domain-separated by user id, so a row lifted from one account cannot be
replayed against another.

**A recovery code does not satisfy re-authentication.** It gets you *in*; it does not authorise
entrenching. Otherwise one leaked code would be both a login *and* a licence to remove the second
factor it just bypassed — and for re-authentication the password already covers the
lost-authenticator case.

**An empty submission is not counted**, since presenting nothing is not a failed check, and counting
it would let a stray double-submit or a forged post grief the real user's login.

**The entity is never registered in an admin panel:** every row is a hash of a credential, and there
is nothing an operator can usefully do to one that the "generate new codes" button doesn't do
properly.

## Accounts

Explains [AUTH.md §5j](AUTH.md#5j-where-accounts-come-from--there-is-no-registration-page).

**No registration page is a decision, not a gap.** Who may join, what is verified before they do (an
email? an invite? a payment? a manager's approval?), and what an account is worth on arrival are
product questions with no defensible default — a library that answered them would be wrong for most
apps and, in the wrong deployment, wrong in the direction of letting strangers in. Writing signup in
the app is what lets you put an invite token, a rate limit or an email round trip in front of it, and
it keeps that policy visible in your code rather than buried in a library default.

**The accounts panel's rules:**

- **`GroupReadWrite`, reads included.** A list of accounts is not something a logged-in stranger
  should be able to enumerate, and `render_for` is where that is enforced: a non-admin gets `403`,
  not a page with the buttons greyed out.
- **The TOTP columns and `passkey_handle` are hidden.** The secret and the pending secret are
  credentials; `totp_last_step` is the replay guard, and hand-editing it either lets a code be
  replayed or locks the user out of their own authenticator. `passkey_handle` is held by the user's
  authenticators, so an edited one orphans every passkey.
- **`must_change_password` is read-only** for the reason under
  [the sign-in policy](#the-sign-in-policy-and-password-change).

## API keys

Explains [AUTH.md §5k](AUTH.md#5k-api-keys).

**A good key clears no lockout failures:** one valid credential shouldn't refund a spraying address's
budget.

**Minting is re-authenticated** because a key is a credential that outlives the session and skips the
second factor; an intruder holding a session must not be able to turn it into a permanent one.
Revoking only removes access, so it is not, as with signing out other sessions.

**SHA-256, not argon2**, for the [recovery codes'](#recovery-codes) reason, made stronger: a
machine-generated 238-bit secret can't be enumerated however cheap the hash is, and a deterministic
hash makes the lookup one indexed equality match on an unauthenticated path. The prefix makes a
leaked key recognisable (secret scanners, logs).

**In the accounts panel the owner is read-only**, because moving a key to another account would hand
that account's rights to whoever holds it.

## Passkeys

Explains [AUTH.md §5l](AUTH.md#5l-passkeys-feature-passkeys).

**Phishing resistance.** A relaying proxy can pass a TOTP code on, but a passkey is bound to the
site's domain, so there is nothing a fake site can capture.

**A failed passkey sign-in counts against the address only**, because the credential names no account
until it is verified. A failed passkey second factor is the same step as a TOTP code, so it counts
against the account and the address.

**What the code relies on in `webauthn-rs` 0.6** (checked in a spike):
- **Features:** `conditional-ui` for the username-less sign-in, `danger-allow-state-serialisation` to
  keep the ceremony state in our row, `danger-credential-internals` to read the backup flags at
  registration.
- **Lookup:** a sign-in finds the credential by its ID and finishes with
  `finish_discoverable_authentication_v2`. `userHandle` is optional, so it is checked against
  `passkey_handle` only when present.
- **The backup flag:** an assertion whose backup-eligible flag went from true to false is refused.
  False to true is legal in a user's own ceremony (re-auth, the second factor), and the passkey is
  reclassified synced; the username-less sign-in refuses it before checking the signature, so it
  fails like an unknown passkey.
- **Discoverable credentials:** the library's registration discourages one; the options sent to the
  browser require it, since a passkey here signs in without a username. The server's verification
  doesn't depend on that hint.
- **Tests:** the software authenticators of `webauthn-authenticator-rs` answer only for a named
  credential, can't store a discoverable one and always report device-bound. So the tests name the
  credential, relax the discoverable hint, make a synced registration by rewriting the response and
  check a sign-in's class by editing the row. The script is checked in Chromium's virtual
  authenticator.

## The sign-in policy and password change

Explains [AUTH.md §5m](AUTH.md#5m-the-sign-in-policy-and-password-change-required).

**TOTP lifts a method to `Mfa`, never higher**, because `Attested` means an attested passkey, so
"security keys of trusted models only" stays expressible.

**`must_change_password` stays read-only in a panel.** The form posts every editable field, and an
unticked checkbox is an explicit `false`, which the row hook respects: the flag would never be set.

**`password_max_age_days` is off by default** because NIST SP 800-63B advises against periodic
rotation.

## CSRF

Explains [AUTH.md §7](AUTH.md#7-csrf-double-submit-token-feature-csrf).

**The cookie is not `HttpOnly`, and that is safe**, because the token is *not a credential* — it
grants nothing on its own. A same-site client can always satisfy the check (read your own cookie,
echo it); a cross-site attacker cannot, because they can neither read your cookie nor set one for
your host. That asymmetry *is* the protection.

**The check runs first.** On the auth routes it precedes the password comparison and any database
work, so a forged post costs nothing and can't be used as an argon2 amplifier. In the engine it
precedes the gate, so a forged write never reaches a session lookup, let alone the backend.

**`Authorization`-bearing requests are exempt** because an API credential isn't ambient: a
cross-site request can't borrow it, so there's nothing to protect.

**A multipart body is not parsed** by `csrf::enforce`: an upload shouldn't be buffered to find a
token.

**The rejection page is shell-less and static** because a rejected request hasn't proved it came from
your site, so nothing about the caller is rendered and no cookies are set.

**`crud::ui` reads the token from the cookie at request time** rather than baking it into the
fragment, so a fragment rendered before a rotation (or cached) can't go stale.

## Tests — the negative paths

Explains [AUTH.md §9](AUTH.md#9-tests--the-negative-paths).

The rejection paths are pinned by `cargo test --all-features`, which drives the shipped routers over
in-memory SQLite:

- **`auth/security_tests.rs`** — sessions (expired, idle, half-authenticated, deactivated, forged and
  bearer-presented tokens all resolve to anonymous), login, TOTP and its replay guard, recovery codes,
  the profile and manager pages, re-authentication, the password policy, lockout (including the proxy
  flag and the whitelist), session rotation and revocation, CSRF on every unsafe route, the gate
  presets as a matrix of caller × operation, and API keys (unknown, expired, disabled, inactive owner,
  locked address, a key never opening the UI, minting without re-authentication, revoking someone
  else's key).
- **`auth/passkey_tests.rs`** (feature `passkeys`) — every ceremony through the shipped routes with a
  software authenticator: adding needs a session, CSRF and re-authentication; an answer works once
  and only for its account; a synced passkey under a device-bound policy and an untrusted model under
  an attested one are refused; an unknown, garbled or deactivated owner's passkey signs nobody in and
  counts against the address; a locked address gets no challenge; a stricter policy ends open
  sessions; the second factor only when enabled; a passwordless account keeps a way in and must
  confirm with its passkey; managers, audit, and nothing at all with the feature off. The browser
  script is checked in Chromium's virtual authenticator (Playwright).
- The sign-in policy and password change, also in `auth/security_tests.rs`: each method's level; a
  restricted session sees only its profile, can't mint a key or manage anyone, and steps up when it
  adds TOTP; a stricter minimum ends open sessions; an `Attested` minimum without attested passkeys
  is a startup error; who flags a password and who doesn't (through the CRUD engine too); the maximum
  age. `sso_tests.rs` covers `sso_level` and the TOTP step after a callback, `passkey_tests.rs` the
  `Attested` level.
- **`auth/sso_tests.rs`** (feature `sso`) — the OIDC callback against a **fake IdP** on a loopback
  port (real discovery, real RSA signatures): missing or forged state, wrong key, audience, issuer,
  nonce, an expired token, missing claims, auto-registration off, disabled, local and
  other-provider accounts. Re-authentication through the provider: a confirmation is needed, works
  once and expires; it is refused as another account, as an account the site doesn't have (which it
  doesn't register), for a session that ended, and in strict mode without a recent `auth_time`; it
  needs a session to start, and a restricted one can make one.
- **`crud/gate_tests.rs`** — every UI write asks its gate with the right `Operation` and a refused one
  never reaches the backend; CSRF on every write.

Each group has a **positive control** — a correct login, a valid code, an allowing gate — so a change
that breaks everything can't make the negatives pass vacuously.
