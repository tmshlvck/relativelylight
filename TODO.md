# TODO

Backlog for `relativelylight`. See [PRD.md](PRD.md) for the product roadmap and
[docs/AUTH.md](docs/AUTH.md) for the auth design notes these expand on.

## Security hardening (auth)

Highest priority first.

- [ ] **Login attempt limiting.** Rate-limit and/or lock out repeated failed logins — both the
  password step (`POST /login`) and the TOTP step (`POST /login/totp`). Per-username and per-source-IP
  counters with backoff/lockout; a small `rl_login_attempt` table (or an in-memory limiter with a
  pluggable store). Also cap TOTP-enrolment (`POST /profile/totp`) and password-reset attempts. This
  is the main missing brute-force defense today — there is currently **no limit** on attempts.
- [ ] **CSRF protection.** The always-on double-submit token decided in AUTH.md §7 is still not
  implemented; cookie-authenticated unsafe requests (login, password change, 2FA enrol/disable, the
  admin UI `fetch` writes) rely on `SameSite=Strict` alone. Add the `csrf` cookie + `X-CSRF-Token`
  header check; exempt Bearer-authenticated requests.
- [ ] **Re-authenticate before sensitive changes.** Require the current password (or a fresh TOTP
  code) before disabling 2FA, changing the password, or (later) removing a PassKey.
- [ ] **TOTP recovery / backup codes.** One-time recovery codes issued at enrolment, so a user who
  loses their authenticator isn't locked out (today only a manager can disable their 2FA).
- [ ] **TOTP replay guard.** Reject a code that was already used within its 30s window (track the last
  accepted step per user) to prevent replay inside the skew window.
- [ ] **Cross-cutting middleware (AUTH.md §4).** Real-client-IP (trusted-proxy `Forwarded`/
  `X-Forwarded-For` parsing), structured request logging, and a configurable CORS layer. The examples
  have a minimal access log; the library should offer these as opt-in layers.
- [ ] **Session hardening.** Rotate the session id on privilege change (login, 2FA completion),
  optional idle vs. absolute timeout, and "sign out everywhere" (delete a user's sessions).

## Auth features

- [x] **SSO / OIDC** — Google + Okta/corporate, username/claim group mapping, optional
  auto-registration (feature `sso`; see AUTH.md §5b). Remaining: cache provider discovery
  (currently per-request); verify the callback against a live IdP.
- [ ] **PassKeys / WebAuthn** as an additional second factor / passwordless.
- [ ] **App-issued API tokens** — a Bearer identity source resolving the same `Identity`.
- [ ] **Row-level authorization** — per-row read checks / list filters (the gate seeing the row/query).

## crud / engine

- [ ] Second backend behind the `Accessor` seam (in-memory or another ORM).
- [ ] Batch relation reads (avoid N+1 on relation resolution).
- [ ] Composite-PK URL token + `row_key` escape hatch; map constraint violations to **409** (now 500).
- [ ] Richer field metadata (enum `options`, nullable/`required`).
