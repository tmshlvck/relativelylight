//! examples/auth — the `auth` module on its own terms. See `docs/AUTH.md`. A public page, a
//! `/secret` page gated by login, `/login` + `/logout`, a configurable admin group, and the
//! **accounts panel** (`/admin`) an operator provisions users from. Also demonstrates the
//! `--set-admin-pw <pw>` break-glass startup path and an **app-owned credential check**
//! (`/api/whoami`, HTTP Basic) braked with the *same* attempt counters as the login form via
//! `Auth::username_lockout` / `Auth::ip_lockout` — see below.
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
use axum_extra::extract::CookieJar;
use relativelylight::auth::lockout::{IpLockout, Lockout, UsernameLockout};
use relativelylight::middleware::RealIp;
use relativelylight::auth::sso::{Sso, SsoButton, SsoProvider};
use relativelylight::auth::{self, Auth, GroupReadWrite, Identity};
use relativelylight::crud::engine::Engine;
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::{Admin, Outcome, ViewState, CSS};
use relativelylight::validate;
use sea_orm::{ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, QueryFilter};
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
        .csrf_rejection(|| {
            (
                StatusCode::FORBIDDEN,
                Html(page(
                    "Security check failed",
                    r#"<div class="alert alert-danger">That form was stale, or the request didn't come
from this site. Reload the page and try again.</div>
<a class="btn btn-outline-secondary btn-sm" href="/">Start over</a>"#,
                )),
            )
                .into_response()
        })
        .login_shell(move |form| bootstrap_login(form, &sso_buttons))
        .profile_shell(bootstrap_profile)
        // The app's own section on the library's profile page — see `api_token_section`.
        .profile_extra(|s| async move { api_token_section(&s) });

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
        // `Auth::reauthenticate` inside the handler (see `rotate_api_token`).
        .route("/api-token/rotate", post(rotate_api_token))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(auth.csrf(), relativelylight::csrf::enforce));

    let mut app = Router::new()
        .route("/", get(public))
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
    // The caller's address is resolved **once**, at the outermost layer, and read from there by
    // `auth`'s lockout, the audit events, this app's own `/api/whoami` and anything it logs — so they all
    // name the same client. This app used to resolve it in three places with two copies of the proxy
    // flag; the layer is what makes that impossible. Mandatory: `auth`'s login routes 500 without it.
    // (No request log here — the crate ships none; `examples/audit` shows the dozen lines.)
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
    println!("auth playground on http://127.0.0.1:3000/   (log in as admin / password)");
    println!("accounts panel   http://127.0.0.1:3000/admin  (admin group only — the library has no sign-up page)");
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

/// Render the SSO login buttons (appended under the password form).
fn sso_buttons_html(buttons: &[SsoButton]) -> String {
    if buttons.is_empty() {
        return String::new();
    }
    let mut s = String::from(r#"<hr class="my-3"><p class="text-muted small mb-2">Or sign in with:</p>"#);
    for b in buttons {
        s.push_str(&format!(
            r#"<a class="btn btn-outline-secondary w-100 mb-2" href="{}">{}</a>"#,
            b.url, b.label
        ));
    }
    s
}

/// Access log: one line per request — source IP, method, URI, and HTTP status.
async fn public() -> Html<String> {
    Html(page(
        "Public page",
        r#"<p><a href="/secret">/secret</a> requires a login · <a href="/login">/login</a></p>
<p><a href="/admin">/admin</a> is the accounts panel — admin group only, reads included. There is no
sign-up page: an operator creates accounts there, or SSO does on first login.</p>
<p class="small text-muted"><code>GET /api/whoami</code> takes HTTP Basic — the app checks it itself,
braked with the same attempt counters as the login form.</p>"#,
    ))
}

// Requires an authenticated user: resolve the session on demand and redirect anonymous visitors to
// the login page. `CookieJar` lets us show the session cookie (a playground affordance — don't
// surface session tokens in real apps).
async fn secret(State(app): State<AppState>, headers: HeaderMap, jar: CookieJar) -> Response {
    let auth = &app.auth;
    let Some(who) = auth.identify(&headers).await else {
        return Redirect::to(auth.login_path()).into_response();
    };
    let name = auth.session_cookie_name();
    let cookie = jar.get(name).map(|c| c.value().to_string()).unwrap_or_default();
    let body = Html(page(
        "Protected page",
        &format!(
            r#"<p>Signed in as <b>{}</b> — groups: [{}].</p>
<p class="small text-muted mb-1">session cookie</p>
<pre class="bg-body-secondary p-2 rounded"><code>{name}={}</code></pre>
<a class="btn btn-primary btn-sm" href="/profile">Profile, 2FA &amp; API token</a>
<a class="btn btn-outline-secondary btn-sm" href="/admin">Accounts</a>
<a class="btn btn-outline-secondary btn-sm" href="/logout">Log out</a>
<p class="small text-muted mt-3 mb-0">The API-token section on <a href="/profile">/profile</a> is this
app's own, rendered into the library's page by <code>Auth::profile_extra</code>.</p>"#,
            who.username,
            who.groups.join(", "),
            cookie,
        ),
    ));
    (jar, body).into_response()
}

/// **Extending the library's profile page** — `Auth::profile_extra` appends this below the
/// password/2FA fragment on `/profile` (the caller's own page only; a manager's `/profile/{id}` does
/// not get it). This is where an app puts the things that belong beside "change my password": API
/// tokens, notification preferences, a data export.
///
/// The hook is handed the caller's identity *and this request's CSRF token*, which is what lets the
/// section contain a real `<form>` rather than just text — the app never sees the request, so it
/// could not mint one itself.
fn api_token_section(s: &relativelylight::auth::ProfileSection) -> String {
    format!(
        r#"<hr class="my-4">
<h2 class="h6">API token</h2>
<p class="small text-muted">Rotating <b>{}</b>'s API token is the kind of thing a live session alone
shouldn't be enough for — a stolen cookie <em>is</em> a live session. So the app asks the caller to prove
they are present, with <code>Auth::reauthenticate</code>: the same factors the library's own sensitive
pages take (your password, or a fresh 2FA code), and the same single-use rule for codes. The CSRF token
comes from the hook; the re-auth happens in the handler.</p>
<form method="post" action="/api-token/rotate">
  {csrf_input}
  <div class="mb-2" style="max-width:22rem">
    <label class="form-label small" for="rot-pw">Your current password</label>
    <input class="form-control form-control-sm" id="rot-pw" name="current_password" type="password"
           autocomplete="current-password">
  </div>
  <div class="mb-2" style="max-width:22rem">
    <label class="form-label small" for="rot-code">…or a code from your authenticator app</label>
    <input class="form-control form-control-sm" id="rot-code" name="totp_code" inputmode="numeric"
           autocomplete="one-time-code" placeholder="123456">
  </div>
  <button class="btn btn-outline-danger btn-sm" type="submit">Rotate API token</button>
</form>"#,
        s.who.username,
        csrf_input = relativelylight::csrf::Csrf::hidden_input(&s.csrf),
    )
}

/// What an app's own sensitive route submits: the caller's re-authentication. (A real one would carry a
/// CSRF token too — `auth.csrf()` — which the library's own forms demonstrate.)
#[derive(serde::Deserialize)]
struct RotateForm {
    #[serde(default)]
    current_password: String,
    #[serde(default)]
    totp_code: String,
}

/// `POST /api-token/rotate` — **the showcase for re-authentication before a sensitive change.**
///
/// The pattern to copy, in order:
/// 1. resolve the caller (`identify`); anonymous goes to the login page;
/// 2. **`reauthenticate`**, and return its error *before anything happens*, so a refusal is a no-op;
/// 3. only then do the destructive thing.
///
/// Why bother when the caller already has a session? Because a session proves someone logged in once,
/// not that the account's owner is the one asking now. The idle timeout bounds how long a stolen cookie
/// lives; this bounds what it can *do* while it lives. An account with no local factor (an SSO login)
/// passes step 2 — there is nothing to ask it for — which `Auth::can_reauthenticate` reports if you want
/// to say so in your own UI.
async fn rotate_api_token(
    State(app): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RotateForm>,
) -> Response {
    let auth = &app.auth;
    let Some(who) = auth.identify(&headers).await else {
        return Redirect::to(auth.login_path()).into_response();
    };
    if let Err(msg) = auth.reauthenticate(&who, &form.current_password, &form.totp_code).await {
        // 403, and nothing has changed — the old token is still the token.
        return (
            StatusCode::FORBIDDEN,
            Html(page(
                "Confirm it's you",
                &format!(
                    r#"<div class="alert alert-danger">{msg}</div>
<p class="small text-muted">Nothing was changed.</p>
<a class="btn btn-outline-secondary btn-sm" href="/secret">Back</a>"#
                ),
            )),
        )
            .into_response();
    }
    // Re-authenticated. A real app would mint and store a token here; this one only says it would, since
    // the point of the example is the check above.
    Html(page(
        "API token rotated",
        &format!(
            r#"<div class="alert alert-success">Confirmed — a new API token would now be issued for
<b>{}</b>, and the old one revoked.</div>
<a class="btn btn-outline-secondary btn-sm" href="/secret">Back</a>"#,
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
    let mut user = MetaModel::new(auth::user::Entity);
    let mut group = MetaModel::new(auth::group::Entity);

    // `.password()` makes `password_hash` a write-only, argon2-hashed "Password" field: plaintext in
    // the form, a hash in the column, never returned in a read. Blank on create = an account with no
    // password (login by password disabled — how you pre-create an SSO-only user); blank on edit =
    // keep the current one, which is what `validate::optional` below preserves.
    user.field("password_hash").password();
    user.field("password_hash").description = Some(
        "Blank on create = no password (SSO-only account). Blank on edit = keep the current one. \
         At least 12 characters, and not a common one."
            .into(),
    );
    // The *same* policy `Auth` applies to /profile, applied to this form too. Wire only one of the
    // two and the other becomes the way around it. (`examples/adminpanel` drives both from a single
    // configurable level; this one takes the recommended default.)
    user.field("password_hash")
        .validate_str(validate::optional(Box::new(validate::password(
            validate::PasswordPolicy::recommended(),
        ))));
    // Secrets and machinery: the 2FA columns are managed from /profile, never from a form. Note
    // `totp_last_step` is not a secret but is still hidden — it is the replay guard, and an operator
    // editing it either lets a code be replayed or locks the user out of their own authenticator.
    for f in ["totp_secret", "totp_pending", "totp_last_step"] {
        user.field(f).hidden = true;
    }
    // Lifecycle stamps are the library's to write: show them, formatted in the caller's zone.
    for f in ["created_at", "updated_at", "last_login_at"] {
        user.field(f).read_only = true;
        user.field(f).datetime();
    }
    user.field("is_active").default = Some(serde_json::json!(true));
    for f in ["created_at", "updated_at"] {
        group.field(f).read_only = true;
        group.field(f).datetime();
    }
    // Labels for the relation pickers, and the N:M membership itself. **This is the line that makes
    // the panel able to create a working account**: the gate checks group membership, so a screen
    // that can create a user but not put them in a group can't finish the job. `auth_user_group` is
    // a junction table and is never registered as a model of its own — declaring the relation is how
    // it is reached.
    user.label_column("username");
    group.label_column("name");
    user.relate(&group);
    group.relate(&user);
    user.relation("auth_group").label = Some("Groups".into());
    group.relation("auth_user").label = Some("Members".into());
    user.field("username").label = Some("Username".into());
    user.field("is_active").label = Some("Active".into());
    user.field("is_active").description =
        Some("Unticked = refused at the door, password or SSO alike, session or not.".into());
    user.field("last_login_at").label = Some("Last login".into());
    group.field("name").label = Some("Group".into());

    // The lockout counters. Everything about them is the library's to maintain, so they are
    // read-only — and the unlock is *deleting the row*, which needs no button of its own: it is an
    // ordinary gated, CSRF-checked, audited DELETE.
    let mut locked_names = MetaModel::new(auth::lockout::username_entity::Entity);
    let mut locked_ips = MetaModel::new(auth::lockout::ip_entity::Entity);
    for f in [&mut locked_names.field("failures"), &mut locked_ips.field("failures")] {
        f.read_only = true;
    }
    for f in [&mut locked_names.field("last_failure_at"), &mut locked_ips.field("last_failure_at")] {
        f.read_only = true;
        f.datetime();
    }

    let gate = Arc::new(GroupReadWrite::new(auth, [ADMIN_GROUP]));
    let mut crud = Crud::new(db);
    crud.register(user, gate.clone());
    crud.register(group, gate.clone());
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
            t.title("Users").columns(["id", "username", "is_active", "auth_group", "last_login_at"])
        })
        .entity_with("auth_group", |t| t.title("Groups").columns(["id", "name", "auth_user"]))
        .separator()
        .group("Locked out")
        .entity_with("auth_username_lockout", |t| t.title("By account"))
        .entity_with("auth_ip_lockout", |t| t.title("By address"))
        .separator()
        .group("Reference")
        .link("Profile & 2FA", "/profile")
        .link("Protected page", "/secret")
        .link("Log out", "/logout")
}

/// `GET /admin/{entity}` — parse the URL, render the fragment, wrap it in our shell. The path names
/// the model; the query carries the view of it (page, sort, filters, the open dialog).
async fn accounts_show(
    State(app): State<AppState>,
    Path(entity): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if app.auth.identify(&headers).await.is_none() {
        return Redirect::to(app.auth.login_path()).into_response();
    }
    let mut state = ViewState::from_uri(&uri);
    state.entity = Some(entity);
    match accounts(&app.engine).render_for(&headers, &state).await {
        Ok(body) => Html(admin_page("Accounts", &body)).into_response(),
        // A logged-in non-admin lands here: the gate refuses the *read*, so there is no page.
        Err(e) => e.into_response(),
    }
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
    if app.auth.identify(&headers).await.is_none() {
        return Redirect::to(app.auth.login_path()).into_response();
    }
    let mut state = ViewState::from_uri(&uri);
    state.entity = Some(entity);
    let panel = accounts(&app.engine);
    match panel.submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        Ok(Outcome::Invalid(state)) => match panel.render_for(&headers, &state).await {
            Ok(body) => {
                (StatusCode::UNPROCESSABLE_ENTITY, Html(admin_page("Accounts", &body))).into_response()
            }
            Err(e) => e.into_response(),
        },
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

/// `GET /api/whoami` — an **app-owned** credential check (HTTP Basic against the same user table),
/// standing in for the API-token endpoint a real app would have. `auth` never sees this request, so
/// braking it is the app's job — and it must use the library's counters, not its own, so that:
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
    // A request with no credential at all is a plain 401 — never counted, or an anonymous scanner
    // could lock out everyone who shares its address.
    let Some((username, password)) = basic_auth(&headers) else {
        return unauthorized("send HTTP Basic credentials");
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
        // credential — a machine endpoint should hand those users an API token instead.
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

/// Bootstrap page wrapper for the app's own pages.
fn page(title: &str, body: &str) -> String {
    shell(title, body, "max-width:40rem")
}

/// The same shell, full width and carrying `crud::ui::CSS` — the forty-odd rules the admin
/// components need beyond Bootstrap (mostly the `<dialog>`). No JavaScript, here or there.
fn admin_page(title: &str, body: &str) -> String {
    shell(title, body, "")
}

fn shell(title: &str, body: &str, width: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>{title}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>{CSS}</style></head>
<body class="bg-body-tertiary"><main class="container py-4" style="{width}">
<h1 class="h4 mb-3">{title}</h1>{body}</main></body></html>"#
    )
}

/// The app's shell for the library's profile/password page. The library hands us the caller's
/// identity so the page can greet them; we wrap the change-password form in our Bootstrap chrome.
fn bootstrap_profile(fragment: &str, who: &Identity) -> String {
    page(
        &format!("Profile — {}", who.username),
        &format!(
            r#"<div class="card shadow-sm"><div class="card-body">{fragment}</div></div>
<a class="d-inline-block mt-3" href="/secret">&larr; Back to /secret</a>"#
        ),
    )
}

/// The app's shell for the library's login form — this is where the app styles it (Bootstrap card).
/// `sso_buttons` is the optional SSO button block appended under the password form.
fn bootstrap_login(form: &str, sso_buttons: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Log in</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>
<body class="bg-body-tertiary"><main class="container" style="max-width:24rem">
<div class="card shadow-sm mt-5"><div class="card-body">
<h1 class="h4 mb-3">Log in</h1>{form}{sso_buttons}</div></div>
<p class="text-center text-muted small mt-2">Demo: <code>admin</code> / <code>password</code></p>
</main></body></html>"#
    )
}
