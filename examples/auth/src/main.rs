//! examples/auth — the skeleton of an intranet app, with `auth` doing its part. See `docs/AUTH.md`.
//!
//! The shape is the one CLIMB and teleddns have: **one shell** (a navbar with the links this user may
//! follow, their name leading to their profile, and "log out"), and behind it:
//!
//! | Path | Who | What |
//! |---|---|---|
//! | `/login`, `/logout` | anyone | the library's sign-in: password, then TOTP; or a passkey; or SSO |
//! | `/` | signed in | the dashboard: a card per thing this user may open |
//! | `/secret` | signed in | an ordinary protected page; anonymous callers are sent to `/login` |
//! | `/admin` | the admin group | the accounts panel: users, groups, API keys, passkeys, lockouts; anyone else gets 403 |
//! | `/profile` | signed in | the library's profile: password, 2FA, passkeys, API keys, and an app section |
//! | `/api/whoami` | an API key or HTTP Basic | a machine endpoint |
//!
//! Two demo accounts: `admin` / `password` (in the admin group) and `alice` / `password` (not), so
//! both sides of `/admin` can be seen. Also here: the `--set-admin-pw <pw>` break-glass startup path,
//! and an **app-owned credential check** (`/api/whoami`, HTTP Basic) braked with the *same* attempt
//! counters as the login form via `Auth::username_lockout` / `Auth::ip_lockout` — see below.
//!
//! **There is no registration page, and that is deliberate** (`docs/AUTH.md` §5j). An account comes
//! into being one of four ways: an operator creates it (the panel here, or `auth::create_user`), SSO
//! auto-registration creates it on first login, the boot seeder creates it (`auth::make_admin`), or
//! the break-glass CLI does. A public signup page is an application decision — who may join, what is
//! verified, what they are worth on arrival — so an app that wants one writes it, over those same
//! calls or a `crud::ui::Form`.
//!
//!   cargo run -p auth-example                            # serve; log in as admin / password
//!   TRUST_PROXY=1 cargo run -p auth-example               # …behind a proxy: believe X-Forwarded-For
//!   cargo run -p auth-example -- --set-admin-pw s3cret   # break-glass: pw + enable + clear 2FA + group
//!   curl -u admin:password    127.0.0.1:3000/api/whoami  # the app's own credential check
//!   curl -u admin:nope -i     127.0.0.1:3000/api/whoami  # 5 of these → 429, and /login locks too
//!   curl -H "Authorization: Bearer demo_…" 127.0.0.1:3000/api/whoami  # an API key minted on /profile
//!
//! **The sign-in policy** (docs/AUTH.md §5m): `MIN_LEVEL=2` makes a password alone too little — the
//! login lands on /profile, which asks for TOTP or a passkey, and adding one lets you in.
//! `PASSWORD_MAX_AGE_DAYS=30` makes an older password a change due. A password set for someone in the
//! accounts panel asks them to choose their own.
//!
//! **Passkeys** are on: add one on `/profile`, remove your password there if you like, and sign in with
//! "Sign in with a passkey". Browse to **http://localhost:3000**, not 127.0.0.1: a passkey belongs to a
//! domain name, and browsers refuse one for a bare IP address.
//!
//! It also shows the two housekeeping duties the library leaves to the app: it schedules
//! `auth::prune` (expired sessions + expired lockout rows), and it registers the two lockout
//! entities in the panel, so an operator sees who is locked out and clears a row by deleting it.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use relativelylight::auth::api_key::{ApiKeys, KeyError};
use relativelylight::auth::lockout::{IpLockout, Lockout, UsernameLockout};
use relativelylight::auth::passkey::Passkeys;
use relativelylight::middleware::RealIp;
use relativelylight::auth::sso::{Sso, SsoButton, SsoProvider};
use relativelylight::auth::{self, Auth, GroupReadWrite, Identity, Level};
use relativelylight::crud::engine::Engine;
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::{Admin, Outcome, ViewState, CSS};
use relativelylight::validate;
use sea_orm::{
    ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, IdenStatic, QueryFilter,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

// The superadmin group name is the app's choice — a constant here, but it could come from config.
// **Use the one name everywhere**: the gate / `admin_group`, the boot-time seeder, and break-glass
// recovery. If those three ever disagree, an "admin" is created outside the group the gate checks.
const ADMIN_GROUP: &str = "superadmin";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // One permanent connection, deliberately: an in-memory database lives *inside* its connection, and a
    // pool recycles connections (SeaORM defaults to a 30-minute `max_lifetime` and a 10-minute
    // `idle_timeout`) — so retiring it would take `auth_user` with it, and this demo would answer
    // "no such table" half an hour after it started working. A second connection would open its own empty
    // database and be just as bad. A real app points at a file or a server and needs none of this.
    const FOREVER: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);
    let mut opt = ConnectOptions::new("sqlite::memory:".to_owned());
    opt.max_connections(1).min_connections(1).idle_timeout(FOREVER).max_lifetime(FOREVER);
    let db = Database::connect(opt).await?;
    auth::migrate(&db).await?;

    // How an app wires a `--set-admin-pw` CLI flag: **break-glass** admin recovery — create-or-reset
    // the password, re-activate the account, clear its TOTP 2FA, ensure admin-group membership, exit.
    // Operator-run only (it discards an enrolled authenticator); the boot-time seeder below is
    // `make_admin`. (This example's DB is in-memory, so it's a call-site demo; a real app would point
    // at a persistent database.)
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--set-admin-pw") {
        let pw = args.get(i + 1).map(String::as_str).unwrap_or("");
        auth::reset_admin_access(&db, ADMIN_GROUP, "admin", pw).await?;
        println!("admin password set, account enabled, 2FA cleared, added to '{ADMIN_GROUP}'");
        return Ok(());
    }

    // Otherwise seed a demo admin (in the admin group) and serve. `make_admin` is idempotent and
    // leaves an existing account's `is_active` / 2FA alone, so it's safe on every start.
    auth::make_admin(&db, ADMIN_GROUP, "admin", "password").await?;
    // An ordinary account beside it, so `/admin` can be seen refusing someone. A seeder's password, like
    // `make_admin`'s, doesn't ask its owner to change it; one typed in the accounts panel would.
    auth::create_user(&db, "alice", "password").await?;

    // Optional SSO from env (no hard-coded secrets). Decide whether it's configured *before* building
    // `auth`, because the login page shows the SSO buttons — and `auth` must be fully configured
    // before it's cloned (`Sso::new` clones it; a builder call after that would panic).
    let google = std::env::var("SSO_GOOGLE_CLIENT_ID")
        .ok()
        .zip(std::env::var("SSO_GOOGLE_CLIENT_SECRET").ok());
    let sso_buttons = if google.is_some() {
        sso_buttons_html(&[SsoButton { label: "Google".into(), url: "/sso/google/login".into() }])
    } else {
        String::new()
    };

    // The brute-force brake is mandatory — `Auth::new` takes its configuration. Here: 5 failed logins
    // per account and 15 per source address, both for 5 minutes (the library defaults are 10 / 100 per
    // 15 min).
    // `Lockout` is `#[non_exhaustive]`: start from the defaults and set what you mean. The whitelist
    // (an office range, a monitoring probe) is left empty so the demo can lock itself out from localhost;
    // a real app passes `relativelylight::net::parse_nets(&cfg.allow_list)` to `.whitelist(..)`.
    let lockout = Lockout::default().accounts(5, 300).addresses(15, 300);
    let auth_db = db.clone(); // the app's own endpoint checks passwords itself
    let crud_db = db.clone(); // …and the accounts panel writes to the same tables
    let auth = Auth::new(db, lockout)
        .secure_cookies(false) // local http, so no `Secure` attribute
        .admin_group(ADMIN_GROUP)
        // Session clocks left at the library defaults: 7 days absolute, 8 hours idle. Changing your
        // password (or a manager resetting it) signs every other session out; "Sign out other sessions"
        // on /profile does it on demand. See `session_ttl_secs` / `session_idle_secs`.
        .totp_issuer("relativelylight auth demo") // shown in authenticator apps for 2FA
        // The CSRF refusal, in this app's own shell instead of the library's bare page. One closure
        // covers the library's forms *and* `csrf::enforce` on the routes above, because it travels on the
        // `auth.csrf()` handle. Same discipline as the default: no user named, no cookies set, still 403.
        .csrf_rejection(|_req| {
            (
                StatusCode::FORBIDDEN,
                Html(page(
                    "Security check failed",
                    None,
                    r#"<div class="alert alert-danger">That form was stale, or the request didn't come
from this site. Reload the page and try again.</div>
<a class="btn btn-outline-secondary btn-sm" href="/">Start over</a>"#,
                )),
            )
                .into_response()
        })
        // The library's pages in the same shell as ours: the login form as a centered card, the
        // profile with the navbar of a signed-in user.
        .login_shell(move |form, _req| login_page(form, &sso_buttons))
        .profile_shell(|frag, who, _req| profile_page(frag, who))
        // API keys: a card on /profile to mint (re-authenticated, shown once), list and revoke them.
        // `/api/whoami` accepts them; the accounts panel shows everyone's (docs/AUTH.md §5k).
        .api_keys(ApiKeys::new("demo_"))
        // Passkeys: a section on /profile, "Sign in with a passkey" on /login, and a passkey on every
        // confirm-it's-you form. The site is `localhost` on port 3000 — what the browser must show.
        .passkeys(Passkeys::new("localhost", "http://localhost:3000").rp_name("relativelylight auth demo"))
        // The sign-in policy, from the environment so it can be tried: 1 (default) any sign-in,
        // 2 two factors (TOTP, a passkey, or SSO).
        .min_level(match std::env::var("MIN_LEVEL").as_deref() {
            Ok("2") => Level::Mfa,
            _ => Level::Simple,
        })
        .password_max_age_days(std::env::var("PASSWORD_MAX_AGE_DAYS").ok().and_then(|v| v.parse().ok()).unwrap_or(0))
        // The app's own section on the library's profile page — see `webhook_section`.
        .profile_extra(|s| async move { webhook_section(&s) });

    // auth is now fully configured — safe to clone it into the Sso.
    let sso = google.map(|(id, secret)| build_sso(&auth, id, secret));

    // The accounts panel's engine: `auth`'s own tables, registered like anybody else's models.
    let engine = accounts_engine(crud_db, &auth);

    // No middleware: `secret` resolves the session itself via `auth.identify`. The app router carries
    // its own state (the `Auth` handle, the DB, and the shared attempt counters) so handlers can reach
    // them; the login/logout routes bring their own.
    let state = AppState {
        auth: auth.clone(),
        engine,
        db: auth_db,
        // The *same* counters the login form uses, so one account has one budget across both.
        usernames: auth.username_lockout(),
        ips: auth.ip_lockout(),
    };
    // The app's own **unsafe** routes, behind `csrf::enforce` — the layer form of the check, so the
    // handler doesn't call `Csrf::verify` itself. It takes the *same* `auth.csrf()` handle the library's
    // forms use, so one cookie serves both, and it accepts either the `X-CSRF-Token` header (a `fetch`
    // client) or the `_csrf` field of a form post. Kept in its own Router so the layer guards exactly
    // these routes: it refuses every unsafe request without a token, which is not what you want in front
    // of, say, `/api/whoami`.
    let guarded = Router::new()
        // An app-owned **sensitive** action: CSRF-checked by the layer, then identity-checked by
        // `Auth::reauthenticate_with` inside the handler (see `rotate_webhook_secret`).
        .route("/webhook-secret/rotate", post(rotate_webhook_secret))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(auth.csrf(), relativelylight::csrf::enforce));

    let mut app = Router::new()
        .route("/", get(dashboard)) // signed in only; a card per thing this user may open
        .route("/secret", get(secret)) // gated on demand (see `secret`)
        .route("/api/whoami", get(whoami)) // the app's own credential check (see `whoami`)
        // The accounts panel: two handlers on one path, the model named by the path segment. Its
        // gate is `GroupReadWrite`, so a logged-in non-admin gets 403 rather than a list of accounts.
        .route("/admin", get(|| async { Redirect::to("/admin/auth_user") }))
        .route("/admin/{entity}", get(accounts_show).post(accounts_save))
        .with_state(state)
        .merge(guarded)
        .merge(auth.routes()); // /login, /logout, /profile (password + 2FA), /login/totp
    if let Some(sso) = &sso {
        app = app.merge(sso.routes()); // /sso/{provider}/login + /callback
    }
    // Mandatory and outermost: the caller's address, resolved once for the lockout, the audit events
    // and `/api/whoami`. `auth`'s login routes answer 500 without it.
    let app = app
        .layer(axum::middleware::from_fn_with_state(
            relativelylight::middleware::TrustProxy(trust_proxy_from_env()),
            relativelylight::middleware::resolve_real_ip,
        ));

    // Housekeeping is the **app's** job — the library schedules nothing. `Auth::prune` deletes dead
    // sessions (absolute *and* idle expiry — it knows this `Auth`'s configuration, which the free
    // `auth::prune(&db, &lockout)` can't) plus expired lockout rows; run it once at startup and then on
    // whatever loop the app already has. Skipping it is safe, just untidy: a dead session never
    // authenticates and an expired lockout row reads as unlocked.
    let prune_auth = auth.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            match prune_auth.prune().await {
                Ok(0) => {}
                Ok(n) => println!("pruned {n} dead session/lockout rows"),
                Err(e) => eprintln!("prune failed: {e}"),
            }
        }
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("auth playground on http://localhost:3000/   (log in as admin / password; use localhost for passkeys)");
    println!("accounts panel   http://localhost:3000/admin  (admin only; alice / password is refused)");
    if sso.is_some() {
        println!("SSO enabled: 'Sign in with Google' button on the login page");
    }
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

/// `TRUST_PROXY=1` (or `true`) tells the lockout to believe `X-Forwarded-For` — set it when you put a
/// reverse proxy in front of this example, and leave it unset when it listens on the port itself. It is
/// a security boundary, not a convenience: unproxied, the header is attacker-supplied.
fn trust_proxy_from_env() -> bool {
    matches!(std::env::var("TRUST_PROXY").as_deref(), Ok("1") | Ok("true"))
}

/// Build SSO config from env, so the demo needs no hard-coded secrets. Set `SSO_GOOGLE_CLIENT_ID` +
/// `SSO_GOOGLE_CLIENT_SECRET` (and optionally `SSO_BASE_URL`, default `http://127.0.0.1:3000`) to
/// enable a "Sign in with Google" button; unset → SSO disabled. The redirect URL registered with the
/// provider must be `{SSO_BASE_URL}/sso/google/callback`.
fn build_sso(auth: &Auth, client_id: String, client_secret: String) -> Sso {
    let base = std::env::var("SSO_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".into());
    Sso::new(auth)
        // Google carries no usable group claim → map local groups by username. Here: anyone whose
        // email ends in @example.com becomes "staff" (add your own rules / an admin regex).
        .username_group_rule(r"@example\.com$", ["staff"])
        .provider(
            SsoProvider::new(
                "google",
                "Google",
                "https://accounts.google.com",
                client_id,
                client_secret,
                format!("{base}/sso/google/callback"),
            )
            .username_claim("email") // Google's stable human identifier
            .auto_register(true), // create unknown users on first login (demo convenience)
        )
}

/// Render the SSO login buttons, appended under the login form. With passkeys on, the library's
/// fragment already ends in an "or" and the passkey button, so these join that list of alternatives
/// (an app without passkeys would draw its own divider here).
fn sso_buttons_html(buttons: &[SsoButton]) -> String {
    buttons
        .iter()
        .map(|b| {
            format!(
                r#"<a class="btn btn-outline-secondary w-100 mt-2" href="{}">Sign in with {}</a>"#,
                b.url, b.label
            )
        })
        .collect()
}

/// `GET /` — the dashboard. Signed in only, like every page of an intranet app: an anonymous visitor
/// is sent to the login page. A card per thing this user may open, decided by their groups — the same
/// check the navbar and the pages themselves make.
async fn dashboard(State(app): State<AppState>, headers: HeaderMap) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let mut cards = card(
        "Secret page",
        "An ordinary protected page: what any signed-in user may see.",
        "/secret",
        "Open",
    );
    if is_admin(&who) {
        cards += &card(
            "Accounts",
            "Users, groups, everyone's API keys and passkeys, and who is locked out.",
            "/admin",
            "Open the panel",
        );
    }
    cards += &card(
        "Your profile",
        "Password, two-factor authentication, passkeys, API keys, sessions.",
        "/profile",
        "Open your profile",
    );
    cards += &card(
        "The API",
        "<code>curl -H \"Authorization: Bearer demo_…\" localhost:3000/api/whoami</code> with a key \
         from your profile, or <code>curl -u alice:password …</code>.",
        "/profile",
        "Create a key",
    );
    let body = format!(r#"<div class="row g-3">{cards}</div>"#);
    Html(page("Dashboard", Some(&who), &body)).into_response()
}

/// One dashboard card.
fn card(title: &str, text: &str, href: &str, button: &str) -> String {
    format!(
        r#"<div class="col-md-6"><div class="card h-100"><div class="card-body">
<h2 class="h6 card-title">{title}</h2><p class="card-text small text-muted">{text}</p>
<a href="{href}" class="btn btn-sm btn-outline-primary">{button}</a></div></div></div>"#
    )
}

/// Whether `who` may open the accounts panel: the admin group, the one name used everywhere.
fn is_admin(who: &Identity) -> bool {
    who.in_group(ADMIN_GROUP)
}

/// `GET /secret` — an ordinary protected page. The whole of the check is `identify`: no session, or one
/// below the site's sign-in policy, and the caller goes to the login page.
async fn secret(State(app): State<AppState>, headers: HeaderMap) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let groups = match who.groups.is_empty() {
        true => "none".to_string(),
        false => who.groups.join(", "),
    };
    let body = format!(
        r#"<p>Signed in as <b>{name}</b>.</p>
<dl class="row small mb-0">
<dt class="col-sm-3">Groups</dt><dd class="col-sm-9">{groups}</dd>
<dt class="col-sm-3">Sign-in level</dt><dd class="col-sm-9">{level:?} <span class="text-muted">(docs/AUTH.md §5m)</span></dd>
</dl>"#,
        name = who.username,
        level = who.level,
    );
    Html(page("Secret page", Some(&who), &body)).into_response()
}

/// **Extending the library's profile page** — `Auth::profile_extra` appends this below the
/// password/2FA fragment on `/profile` (the caller's own page only; a manager's `/profile/{id}` does
/// not get it). This is where an app puts the things that belong beside "change my password": API
/// webhooks, notification preferences, a data export. (API keys are built in: `Auth::api_keys`.)
///
/// The hook is handed the caller's identity *and this request's CSRF token*, which is what lets the
/// section contain a real `<form>` rather than just text — the app never sees the request, so it
/// could not mint one itself.
fn webhook_section(s: &relativelylight::auth::ProfileSection) -> String {
    format!(
        r#"<hr class="my-4">
<h2 class="h6">Webhook secret</h2>
<p class="small text-muted">Rotating <b>{}</b>'s webhook signing secret is the kind of thing a live session alone
shouldn't be enough for — a stolen cookie <em>is</em> a live session. So the app asks the caller to prove
they are present, with <code>Auth::reauthenticate_with</code>: the same factors the library's own
sensitive pages take (your password, a fresh 2FA code, or your passkey), and the same single-use rule.
The CSRF token and the confirm-it's-you inputs come from the hook; the check happens in the handler.</p>
<form method="post" action="/webhook-secret/rotate" style="max-width:22rem">
  {csrf_input}
  {reauth}
  <button class="btn btn-outline-danger btn-sm" type="submit">Rotate webhook secret</button>
</form>"#,
        s.who.username,
        csrf_input = relativelylight::csrf::Csrf::hidden_input(&s.csrf),
        reauth = s.reauth_fields,
    )
}

/// What an app's own sensitive route submits: the caller's re-authentication — any of their factors,
/// as `ProfileSection::reauth_fields` rendered them. (The CSRF token is checked by the layer.)
#[derive(serde::Deserialize)]
struct RotateForm {
    #[serde(flatten)]
    reauth: auth::ReauthInput,
}

/// `POST /webhook-secret/rotate` — **the showcase for re-authentication before a sensitive change.**
///
/// The pattern to copy, in order:
/// 1. resolve the caller (`identify`); anonymous goes to the login page;
/// 2. **`reauthenticate_with`**, and return its error *before anything happens*, so a refusal is a no-op;
/// 3. only then do the destructive thing.
///
/// Why bother when the caller already has a session? Because a session proves someone logged in once,
/// not that the account's owner is the one asking now. The idle timeout bounds how long a stolen cookie
/// lives; this bounds what it can *do* while it lives. An account with no local factor (an SSO login)
/// passes step 2 — there is nothing to ask it for — which `Auth::can_reauthenticate` reports if you want
/// to say so in your own UI.
async fn rotate_webhook_secret(
    State(app): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RotateForm>,
) -> Response {
    let auth = &app.auth;
    let Some(who) = auth.identify(&headers).await else {
        return Redirect::to(auth.login_path()).into_response();
    };
    if let Err(msg) = auth.reauthenticate_with(&who, &form.reauth).await {
        // 403, and nothing has changed — the old secret is still the secret.
        return (
            StatusCode::FORBIDDEN,
            Html(page(
                "Confirm it's you",
                Some(&who),
                &format!(
                    r#"<div class="alert alert-danger">{msg}</div>
<p class="small text-muted">Nothing was changed.</p>
<a class="btn btn-outline-secondary btn-sm" href="/profile">Back to your profile</a>"#
                ),
            )),
        )
            .into_response();
    }
    // Re-authenticated. A real app would mint and store a secret here; this one only says it would, since
    // the point of the example is the check above.
    Html(page(
        "Webhook secret rotated",
        Some(&who),
        &format!(
            r#"<div class="alert alert-success">Confirmed — a new webhook secret would now be issued for
<b>{}</b>, and the old one revoked.</div>
<a class="btn btn-outline-secondary btn-sm" href="/profile">Back to your profile</a>"#,
            who.username
        ),
    ))
    .into_response()
}

// ── The accounts panel ───────────────────────────────────────────────────────────────────────────
//
// The library has **no registration page** (see the module docs). Somebody has to make the second
// account, and this is that somebody's screen: `auth`'s own tables — accounts, groups, and the two
// lockout counters — registered as ordinary models and rendered by `crud::ui::Admin`. Nothing here
// is special-cased for `auth`; it is the same five calls any other model gets.

/// Register `auth`'s tables and hand back the engine the panel renders from.
///
/// The gate is `GroupReadWrite`: **reads included**, admin group only. An accounts list is not a
/// thing a logged-in stranger should be able to enumerate, and `render_for` is where that is
/// enforced — a non-admin gets 403, not a page with the buttons greyed out.
fn accounts_engine(db: DatabaseConnection, auth: &Auth) -> Arc<Engine> {
    use auth::lockout::{ip_entity::Column as IpCol, username_entity::Column as NameCol};
    use auth::{group::Column as GroupCol, user::Column as UserCol};
    let mut user = MetaModel::new(auth::user::Entity);
    let mut group = MetaModel::new(auth::group::Entity);

    // `.password()` makes `password_hash` a write-only, argon2-hashed "Password" field: plaintext in
    // the form, a hash in the column, never returned in a read. Blank on create = an account with no
    // password (login by password disabled — how you pre-create an SSO-only user); blank on edit =
    // keep the current one, which is what `validate::optional` below preserves.
    user.field(UserCol::PasswordHash.as_str()).password();
    user.field(UserCol::PasswordHash.as_str()).description = Some(
        "Blank on create = no password (SSO-only account). Blank on edit = keep the current one. \
         At least 12 characters, and not a common one."
            .into(),
    );
    // The *same* policy `Auth` applies to /profile, applied to this form too. Wire only one of the
    // two and the other becomes the way around it. (`examples/adminpanel` drives both from a single
    // configurable level; this one takes the recommended default.)
    user.field(UserCol::PasswordHash.as_str())
        .validate_str(validate::optional(Box::new(validate::password(
            validate::PasswordPolicy::recommended(),
        ))));
    // Secrets and machinery: the 2FA columns are managed from /profile, never from a form. Note
    // `totp_last_step` is not a secret but is still hidden — it is the replay guard, and an operator
    // editing it either lets a code be replayed or locks the user out of their own authenticator.
    // `passkey_handle` is the WebAuthn user handle the authenticators hold; an edited one orphans
    // every passkey on the account.
    for f in [
        UserCol::TotpSecret.as_str(),
        UserCol::TotpPending.as_str(),
        UserCol::TotpLastStep.as_str(),
        UserCol::PasskeyHandle.as_str(),
    ] {
        user.field(f).hidden = true;
    }
    // "Password change required" (docs/AUTH.md §5m): the row hook flags an account whenever a password
    // is written for it — this panel's password field included — so the owner is asked for their own.
    // Read-only here, or the form's unticked checkbox would post an explicit `false` with every save.
    user.field(UserCol::MustChangePassword.as_str()).label = Some("Must change password".into());
    user.field(UserCol::MustChangePassword.as_str()).read_only = true;
    user.field(UserCol::PasswordChangedAt.as_str()).label = Some("Password set".into());
    // Lifecycle stamps are the library's to write: show them, formatted in the caller's zone.
    for f in [
        UserCol::CreatedAt.as_str(),
        UserCol::UpdatedAt.as_str(),
        UserCol::LastLoginAt.as_str(),
        UserCol::PasswordChangedAt.as_str(),
    ] {
        user.field(f).read_only = true;
        user.field(f).datetime();
    }
    user.field(UserCol::IsActive.as_str()).default = Some(serde_json::json!(true));
    for f in [GroupCol::CreatedAt.as_str(), GroupCol::UpdatedAt.as_str()] {
        group.field(f).read_only = true;
        group.field(f).datetime();
    }
    // Labels for the relation pickers, and the N:M membership itself. **This is the line that makes
    // the panel able to create a working account**: the gate checks group membership, so a screen
    // that can create a user but not put them in a group can't finish the job. `auth_user_group` is
    // a junction table and is never registered as a model of its own — declaring the relation is how
    // it is reached.
    user.label_column(UserCol::Username.as_str());
    group.label_column(GroupCol::Name.as_str());
    user.relate(&group);
    group.relate(&user);
    user.relation("auth_group").label = Some("Groups".into());
    group.relation("auth_user").label = Some("Members".into());
    user.field(UserCol::Username.as_str()).label = Some("Username".into());
    user.field(UserCol::IsActive.as_str()).label = Some("Active".into());
    user.field(UserCol::IsActive.as_str()).description =
        Some("Unticked = refused at the door, password or SSO alike, session or not.".into());
    user.field(UserCol::LastLoginAt.as_str()).label = Some("Last login".into());
    group.field(GroupCol::Name.as_str()).label = Some("Group".into());

    // The lockout counters. Everything about them is the library's to maintain, so they are
    // read-only — and the unlock is *deleting the row*, which needs no button of its own: it is an
    // ordinary gated, CSRF-checked, audited DELETE.
    let mut locked_names = MetaModel::new(auth::lockout::username_entity::Entity);
    let mut locked_ips = MetaModel::new(auth::lockout::ip_entity::Entity);
    for f in [
        &mut locked_names.field(NameCol::Failures.as_str()),
        &mut locked_ips.field(IpCol::Failures.as_str()),
    ] {
        f.read_only = true;
    }
    for f in [
        &mut locked_names.field(NameCol::LastFailureAt.as_str()),
        &mut locked_ips.field(IpCol::LastFailureAt.as_str()),
    ] {
        f.read_only = true;
        f.datetime();
    }

    let gate = Arc::new(GroupReadWrite::new(auth, [ADMIN_GROUP]));
    let mut crud = Crud::new(db);
    crud.register(user, gate.clone());
    crud.register(group, gate.clone());
    // Everyone's API keys: the hash hidden, the owner pinned, disable/re-date/delete allowed.
    crud.register(auth::api_key::meta_model(), gate.clone());
    // Everyone's passkeys: the credential hidden, the owner pinned; relabel or delete.
    crud.register(auth::passkey::meta_model(), gate.clone());
    crud.register(locked_names, gate.clone());
    crud.register(locked_ips, gate);
    // These writes are cookie-authenticated, so they must carry the double-submit token — the same
    // handle `auth`'s own forms and `csrf::enforce` use, so one cookie serves the whole app.
    crud.csrf(auth.csrf());
    Arc::new(crud.into_engine())
}

/// The panel's shape. Built per request (it borrows the engine), which is also what lets it be
/// rendered *for a caller*.
fn accounts(engine: &Engine) -> Admin<'_> {
    Admin::new(engine)
        .title("Accounts")
        .base("/admin")
        .group("People")
        // `columns` trims the *table*; the dialog still edits every writable column — which is how
        // the write-only password stays out of a list where its cell could only ever be blank.
        .entity_with("auth_user", |t| {
            t.title("Users").columns([
                auth::user::Column::Id.as_str(),
                auth::user::Column::Username.as_str(),
                auth::user::Column::IsActive.as_str(),
                "auth_group", // a relation: no column enum, so the name stays a string
                auth::user::Column::LastLoginAt.as_str(),
            ])
        })
        .entity_with("auth_group", |t| t.title("Groups").columns([
                auth::group::Column::Id.as_str(),
                auth::group::Column::Name.as_str(),
                "auth_user",
            ]))
        // Keys are minted on /profile, where the raw value can be shown once; one made here would
        // have no value anyone could see, so the panel offers no "+ New".
        .entity_with("auth_api_key", |t| t.title("API keys").create(false))
        // A passkey is made by its authenticator, on /profile; there is nothing to create here.
        .entity_with("auth_passkey", |t| t.title("Passkeys").create(false))
        .separator()
        .group("Locked out")
        .entity_with("auth_username_lockout", |t| t.title("By account"))
        .entity_with("auth_ip_lockout", |t| t.title("By address"))
        .separator()
        .group("Elsewhere")
        .link("Dashboard", "/")
        .link("Your profile", "/profile")
}

/// `GET /admin/{entity}` — parse the URL, render the fragment, wrap it in our shell. The path names
/// the model; the query carries the view of it (page, sort, filters, the open dialog).
async fn accounts_show(
    State(app): State<AppState>,
    Path(entity): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let mut state = ViewState::from_uri(&uri);
    state.entity = Some(entity);
    match accounts(&app.engine).render_for(&headers, &state).await {
        Ok(body) => Html(wide_page("Accounts", &who, &body)).into_response(),
        // A signed-in non-admin lands here: the gate refuses the *read*, so there is no panel — a page
        // that says so, in our shell, rather than the library's bare status.
        Err(relativelylight::crud::Error::Forbidden) => admins_only(&who),
        Err(e) => e.into_response(),
    }
}

/// The 403 a signed-in non-admin gets for `/admin`: in the shell, saying why.
fn admins_only(who: &Identity) -> Response {
    let body = format!(
        r#"<div class="alert alert-warning">The accounts panel is for the <b>{ADMIN_GROUP}</b> group, and
<b>{}</b> isn't in it.</div><a class="btn btn-outline-secondary btn-sm" href="/">Back to the dashboard</a>"#,
        who.username
    );
    (StatusCode::FORBIDDEN, Html(page("Admins only", Some(who), &body))).into_response()
}

/// `POST /admin/{entity}` — hand the body to the library and redirect, or re-render with the
/// validation messages and the typed values back in the dialog.
async fn accounts_save(
    State(app): State<AppState>,
    Path(entity): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    RealIp(ip): RealIp,
    body: Bytes,
) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let mut state = ViewState::from_uri(&uri);
    state.entity = Some(entity);
    let panel = accounts(&app.engine);
    match panel.submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        Ok(Outcome::Invalid(state)) => match panel.render_for(&headers, &state).await {
            Ok(body) => {
                (StatusCode::UNPROCESSABLE_ENTITY, Html(wide_page("Accounts", &who, &body))).into_response()
            }
            Err(e) => e.into_response(),
        },
        Err(relativelylight::crud::Error::Forbidden) => admins_only(&who),
        Err(e) => e.into_response(),
    }
}

/// What the app's own routes need: the `Auth` handle, a DB connection, and the shared attempt
/// counters. `Attempts` is cheap to clone, so it lives in the state like any other handle.
#[derive(Clone)]
struct AppState {
    auth: Auth,
    /// The accounts panel reads and writes through this — one `Engine`, built once at startup.
    engine: Arc<Engine>,
    db: DatabaseConnection,
    usernames: UsernameLockout,
    ips: IpLockout,
}

/// `GET /api/whoami` — a machine endpoint taking either credential:
///
/// - an **API key** (`Authorization: Bearer`), minted on /profile. The app reads the header and
///   `Auth::identify_key` verifies it, braking on the library's address counter itself;
/// - **HTTP Basic**, an app-owned check against the same user table. `auth` never sees this, so
///   braking it is the app's job — and it must use the library's counters, not its own, so that:
///
/// - one account has **one** budget: burning it here locks `/login` too, and vice versa;
/// - `Auth::clear_login_attempts` (the operator unlock) frees every surface at once.
///
/// The shape to copy: check `locked` *before* the secret, record only a credential you actually
/// checked and rejected, clear the account on success.
async fn whoami(
    State(app): State<AppState>,
    RealIp(ip): RealIp,
    headers: HeaderMap,
) -> Response {
    // An API key: the owner, with their groups as they are now. A key never opens /profile or the
    // panel — `identify` ignores it — so this route is where it means something.
    if let Some(token) = auth::bearer_token(&headers) {
        return match app.auth.identify_key(token, ip).await {
            Ok(k) => format!(
                "ok: {} (API key {} \"{}\"; groups: {})\n",
                k.identity.username,
                k.key_prefix,
                k.key_name,
                k.identity.groups.join(", ")
            )
            .into_response(),
            Err(KeyError::Invalid) => unauthorized("bad API key"),
            Err(KeyError::Locked(retry)) => (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, retry.to_string())],
                format!("too many failed attempts — retry in {retry}s\n"),
            )
                .into_response(),
            Err(KeyError::Internal) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
    }
    // A request with no credential at all is a plain 401 — never counted, or an anonymous scanner
    // could lock out everyone who shares its address.
    let Some((username, password)) = basic_auth(&headers) else {
        return unauthorized("send HTTP Basic credentials or an API key");
    };
    // No resolution to do and no proxy flag to remember: `RealIp` is the address the middleware already
    // worked out, which is by construction the one `/login` counted against. That's the point of it.
    if let Some(retry) = locked(&app, &username, Some(ip)).await {
        // Refused without looking at the password: no argon2 work, and no hint about the account.
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, retry.to_string())],
            format!("too many failed attempts — retry in {retry}s\n"),
        )
            .into_response();
    }

    let user = auth::user::Entity::find()
        .filter(auth::user::Column::Username.eq(&username))
        .one(&app.db)
        .await
        .ok()
        .flatten()
        // An SSO account's password isn't ours to check, and a 2FA account's password isn't the whole
        // credential — a machine endpoint should hand those users an API key instead.
        .filter(|u| u.is_active && !u.is_sso() && !u.has_totp());
    let ok = user.as_ref().is_some_and(|u| auth::verify_password(&u.password_hash, &password));
    if !ok {
        let by_user = app.usernames.record_failure(&username).await;
        let by_ip = app.ips.record_failure(Some(ip)).await;
        if by_user || by_ip {
            println!("locked out: {username} / {ip} (too many failed checks)");
        }
        return unauthorized("bad credentials");
    }
    app.usernames.clear(&username).await; // a good credential forgets the account's failures
    format!("ok: {username}\n").into_response()
}

/// The longer of the account's and the address's remaining lockout, if either is locked.
async fn locked(app: &AppState, username: &str, ip: Option<IpAddr>) -> Option<i64> {
    let (by_user, by_ip) = (app.usernames.locked(username).await, app.ips.locked(ip).await);
    match (by_user, by_ip) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// The username + password from an `Authorization: Basic` header, if it carries one.
fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    use base64::Engine;
    let raw = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(raw.strip_prefix("Basic ")?).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (u, p) = text.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

fn unauthorized(why: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(axum::http::header::WWW_AUTHENTICATE, "Basic realm=\"api\"")],
        format!("{why}\n"),
    )
        .into_response()
}

// ── The shell ────────────────────────────────────────────────────────────────────────────────────
//
// One shell for every page, the library's included, as CLIMB and teleddns have: a navbar with the
// links this user may follow (decided by their groups, the same check the pages make), their name
// leading to their profile, and "log out". The library renders fragments; the page is ours.

/// The page around everything: the navbar for `who` (or none), `body` in the main column.
fn shell(title: &str, who: Option<&Identity>, body: &str) -> String {
    let mut left = String::new();
    let mut right = String::new();
    match who {
        Some(w) => {
            left += r#"<a class="nav-link" href="/secret">Secret page</a>"#;
            if is_admin(w) {
                left += r#"<a class="nav-link" href="/admin">Accounts</a>"#;
            }
            // `Identity::password_change`: a password someone else set, or an expired one.
            if w.password_change.is_some() {
                right += r#"<a class="badge text-bg-warning text-decoration-none" href="/profile">change your password</a>"#;
            }
            right += &format!(
                r#"<span class="navbar-text"><a href="/profile" class="link-body-emphasis text-decoration-none fw-medium">{}</a>
&middot; <a href="/logout" class="link-secondary text-decoration-none">log out</a></span>"#,
                w.username
            );
        }
        None => right += r#"<a class="nav-link" href="/login">Log in</a>"#,
    }
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title} — auth example</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>{CSS}</style></head>
<body class="bg-body-tertiary d-flex flex-column min-vh-100">
<nav class="navbar bg-body border-bottom px-3 gap-3">
<div class="d-flex align-items-center gap-3"><a class="navbar-brand" href="/">auth example</a>{left}</div>
<div class="d-flex align-items-center gap-3 ms-auto">{right}</div></nav>
<main class="container-fluid py-3 flex-grow-1">{body}</main>
<footer class="border-top py-2 text-center small text-muted">relativelylight · demo accounts
<code>admin</code> and <code>alice</code>, password <code>password</code></footer>
</body></html>"#
    )
}

/// An app page: a heading and `body`, in a readable column.
fn page(title: &str, who: Option<&Identity>, body: &str) -> String {
    shell(
        title,
        who,
        &format!(r#"<div class="mx-auto" style="max-width:48rem"><h1 class="h4 mb-3">{title}</h1>{body}</div>"#),
    )
}

/// A page at full width: the accounts panel's tables.
fn wide_page(title: &str, who: &Identity, body: &str) -> String {
    shell(title, Some(who), body)
}

/// The library's profile fragment in our shell, with the signed-in navbar.
fn profile_page(fragment: &str, who: &Identity) -> String {
    shell(
        "Profile",
        Some(who),
        &format!(
            r#"<div class="card shadow-sm mx-auto" style="max-width:40rem"><div class="card-body">{fragment}</div></div>"#
        ),
    )
}

/// The library's login fragment as a centered card: the form, then the alternatives — the library's
/// "or" and passkey button, and our SSO buttons under them.
fn login_page(form: &str, sso_buttons: &str) -> String {
    shell(
        "Log in",
        None,
        &format!(
            r#"<div class="card shadow-sm mx-auto mt-4" style="max-width:24rem"><div class="card-body">
<h1 class="h5 mb-3">Log in</h1>{form}{sso_buttons}</div></div>"#
        ),
    )
}
