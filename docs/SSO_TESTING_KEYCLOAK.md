# Testing SSO with Keycloak

A simple deployment and testing guide for SSO: run [Keycloak](https://www.keycloak.org/) in a
container, point [`examples/auth`](../examples/auth/src/main.rs) at it, and try sign-in and
re-authentication through the provider by hand. It is for development and testing, not production:
the container runs Keycloak's development mode, with an in-memory admin and a throw-away realm.

What SSO does and how to configure it is [AUTH.md §5b](AUTH.md#5b-sso--openid-connect-feature-sso);
re-authentication through the provider is [§5h](AUTH.md#5h-re-authentication-before-sensitive-changes).
The automated tests (`auth/sso_tests.rs`) use a fake provider; this guide is the real one.

- [1. Start Keycloak](#1-start-keycloak)
- [2. Create a test realm](#2-create-a-test-realm)
- [3. Run the example](#3-run-the-example)
- [4. What to try](#4-what-to-try)
- [5. Clean up](#5-clean-up)
- [6. Troubleshooting](#6-troubleshooting)

## 1. Start Keycloak

With Docker or Podman:

```bash
docker run -d --rm --name rl-keycloak --network host \
  -e KC_HTTP_HOST=127.0.0.1 -e KC_HTTP_PORT=8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.4 start-dev
```

It is ready when `http://127.0.0.1:8080/realms/master/.well-known/openid-configuration` answers
(the first start takes a minute or two). The admin console is `http://127.0.0.1:8080/admin`.

- **`127.0.0.1` for Keycloak, `localhost` for the app.** A browser's "site" ignores the port, so
  Keycloak on `localhost:8080` and the app on `localhost:3000` would be the same site. Production's
  round trip to the provider is cross-site, which is what the `SameSite=Strict` session cookie has
  to survive; two host names keep that true here.
- **`--network host`** because rootless Podman's port publishing (`-p 127.0.0.1:8080:8080`) doesn't
  work everywhere. With Docker, `-p 127.0.0.1:8080:8080` in place of `--network host` is fine.

**An existing Keycloak** works the same: use its URL below, with an admin of its `master` realm.
The script only creates a realm of its own and touches nothing else.

## 2. Create a test realm

[`examples/auth/keycloak-setup.sh`](../examples/auth/keycloak-setup.sh) does it through Keycloak's
admin API (it needs `curl` and `python3`):

```bash
KC_URL=http://127.0.0.1:8080 KC_ADMIN=admin KC_ADMIN_PASSWORD=admin \
  ./examples/auth/keycloak-setup.sh
```

It creates:

- a realm `rl-sso-test` (`REALM=…` to name another; `RESET=1` deletes and recreates an existing one);
- a confidential client `relativelylight-demo`, redirecting to
  `http://localhost:3000/sso/keycloak/callback` (`APP_URL=…` for another address);
- a `groups` claim in its tokens, and a group `rl-admins`;
- two users with generated passwords: **`sso-admin`**, in `rl-admins`, which the example maps to its
  local admin group, and **`sso-user`**, an ordinary account.

It writes the example's settings, the client secret and both passwords to
`examples/auth/keycloak.local.env` (`OUT=…` for another file). `*.local.env` is git-ignored: the file
holds a secret.

## 3. Run the example

```bash
set -a; . examples/auth/keycloak.local.env; set +a
cargo run -p auth-example
```

Open **http://localhost:3000**: the login page has a **Sign in with Keycloak** button. The settings
the example reads are listed on `sso_providers_from_env` in `examples/auth/src/main.rs`; the env file
sets them all. The local accounts (`admin` / `password`, `alice` / `password`) still work beside SSO.

## 4. What to try

Each step says what you should see. The passwords are in the env file.

1. **Sign in.** Log out if needed, then **Sign in with Keycloak**, as `sso-admin`. You land on the
   dashboard, signed in as `sso-admin`, the account created on first sign-in. **Accounts** (`/admin`)
   opens: `rl-admins` made it a local admin. Signed in as `sso-user` instead, `/admin` is refused.
2. **Re-authenticate through Keycloak.** On **`/profile`**, the API-keys card has a **Confirm with
   Keycloak** button instead of a password field.
   - Create a key without confirming: refused, "Confirm with Keycloak first, then submit again."
   - Click **Confirm with Keycloak**: you go to Keycloak and straight back (it still has your
     session), and the card says "Confirmed with Keycloak".
   - Create a key: it is shown once.
   - Create another: refused again. A confirmation is good for one change, for five minutes.
3. **A manager action.** As `sso-admin`, open `/profile/2` (`alice`). Resetting her password is
   refused until you confirm, then works once.
4. **Strict mode.** Stop the example, uncomment `SSO_OIDC_REAUTH_MAX_AGE` in the env file (60 seconds;
   a few seconds makes it quick to see), and start it again. Sign in, wait longer than that, and
   click **Confirm with Keycloak**: Keycloak now asks for your password ("Please re-authenticate to
   continue") before sending you back confirmed. The request carries `max_age` and asks for
   `auth_time`, which Keycloak honours; Google doesn't (AUTH.md §5b).

## 5. Clean up

```bash
docker stop rl-keycloak               # the container and everything in it (it was started with --rm)
rm examples/auth/keycloak.local.env
```

On an existing Keycloak, delete the `rl-sso-test` realm in the admin console instead (or recreate it
with `RESET=1`).

## 6. Troubleshooting

- **"Invalid parameter: redirect_uri" at Keycloak.** The app's address and the client's redirect
  disagree: `SSO_BASE_URL` in the env file and `APP_URL` given to the script must be the address
  you browse, `http://localhost:3000` by default.
- **"SSO provider unavailable".** The app couldn't fetch `SSO_OIDC_ISSUER`'s discovery document. The
  issuer must be reachable at the same URL from the app and from the browser, and Keycloak must be up.
- **Back on the login page after signing in at Keycloak.** A relativelylight from before 0.5
  redirected from the provider's callback, and the browser didn't send the new `SameSite=Strict`
  session cookie on that cross-site redirect; reloading signed you in. The callback now answers with
  a page that moves on by itself.
- **Keycloak asks to update the account** on first sign-in: the user lacks an e-mail or a name,
  which Keycloak's user profile wants. The script sets them; a user added by hand needs them too.
