//! adminpanel example — the `relativelylight::crud::ui::Admin` component, **login-gated** with the
//! `auth` module. Anonymous requests are redirected to `/login`; each model is gated by an `Authz`
//! gate (logged-in users may read; only the admin group may write) and the panel is rendered *per
//! request*, so a reader is offered no write controls and a write they forge is refused anyway. Two
//! demo logins: `admin` / `password` (read-write) and `editor` / `password` (read-only).
//!
//! The whole stack composed by the app: **two handlers** for the panel (`GET /` renders, `POST /`
//! writes), the `auth` routes merged in, one address-resolving layer, an askama shell, a timezone
//! cookie, and the authn/authz gates. (The `crud-example` is the ungated counterpart.)
//!
//! Try:  open http://127.0.0.1:3000/   ·   each model has its own path (/admin/post, /admin/tag)
//!
//!   cargo run -p adminpanel-example -- --set-admin-pw s3cret   # break-glass admin recovery, then exit
//!   TRUST_PROXY=1 cargo run -p adminpanel-example              # behind a proxy: trust X-Forwarded-For

use askama::Template;
use axum::body::Bytes;
use axum::extract::{Form, Path, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use model::{author, post, profile, tag, user};
use relativelylight::auth::{self, Auth, GroupReadWrite, Identity, UserReadGroupWrite};
use relativelylight::crud::engine::Engine;
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::ui::{esc, Admin, Outcome, ViewState, CSS};
use relativelylight::middleware::RealIp;
use relativelylight::time::{Tz, TzPicker};
use relativelylight::validate;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

// The superadmin group (configurable). Its members may write; other logged-in users may only read.
// **One name, used everywhere**: the gates below, `Auth::admin_group`, the boot-time seeder, and
// break-glass recovery. Let those drift apart and you get an "admin" outside the group the gate checks.
const ADMIN_GROUP: &str = "admin";

#[derive(Template)]
#[template(path = "shell.html")]
struct Shell {
    title: String,
    user: String, // signed-in username (empty when anonymous) → navbar link to /profile
    body: String,
    css: &'static str, // the library's few CSS rules (crud::ui::CSS) — no JavaScript anywhere
    tz_picker: String, // the navbar timezone form (time::TzPicker), posting to /tz
}

impl Shell {
    /// `back` is where the timezone picker returns to — the page being rendered, so setting a zone
    /// doesn't lose the table the operator was looking at.
    fn page(title: impl Into<String>, user: impl Into<String>, body: String, headers: &HeaderMap, back: &str) -> Self {
        Self {
            title: title.into(),
            user: user.into(),
            body,
            css: CSS,
            tz_picker: timezones().render(&Tz::from_headers(headers), back),
        }
    }
}

/// The timezone picker this app offers, configured the way a real deployment configures it: a list
/// of IANA names read at startup — here from `RL_TIMEZONES`, in an app from YAML/JSON or a settings
/// table — falling back to the library's default (UTC + Europe + the United States).
///
/// `RL_TIMEZONES=all` offers every zone the host knows; `RL_TIMEZONES=UTC,Europe/Prague,Asia/Tokyo`
/// offers exactly those three. Names the host's database doesn't know are dropped and reported by
/// `check_timezones()` at boot, rather than appearing as options that quietly mean UTC.
fn timezones() -> TzPicker {
    match std::env::var("RL_TIMEZONES").ok().as_deref() {
        None | Some("") => TzPicker::new(),
        Some("all") => TzPicker::new().all_zones(),
        Some(list) => TzPicker::new().zones(list.split(',').map(str::trim).filter(|z| !z.is_empty())),
    }
}

struct App {
    engine: Arc<Engine>,
    auth: Auth,
}

// The admin fragment's structure (nav groups, per-model table config). Built fresh per request so it
// can be rendered *for the caller*. `is_manager` marks callers in the admin group: only they get the
// `GroupReadWrite`-gated Accounts section (the auth users/groups), where each user-id links to its
// password-reset page. Non-managers would get 403 reading those models, so we omit the section for them.
fn build_admin(engine: &Engine, is_manager: bool) -> Admin<'_> {
    let mut admin = Admin::new(engine)
        .title("relativelylight")
        // Each model gets a path of its own: /admin/post, /admin/auth_user. Only the side panel's
        // links change — everything inside a table is relative, so it resolves against whichever
        // path it is being served from.
        .base("/admin")
        // One control in the side-panel, applied to every listed table that has an `author` column —
        // here just `post`, but this is the shape that pays off when an admin lists many tables of the
        // same kind (fifteen per-type DNS record tables, say) and an operator works inside one of them
        // at a time. The choice is remembered and travels in the URL fragment, so it can be linked.
        .filter("author")
        .group("Content")
        .entity_with("post", |t| {
            // A cell renderer is a Rust closure now, and escaping is what `esc` is for: this link
            // opens the row's own edit dialog, which is just a URL.
            t.per_page(10).format("title", |v, row| {
                format!(r#"<a href="?entity=post&amp;edit={}">{}</a>"#, esc(&row["id"]), esc(v))
            })
        })
        .entity("tag")
        .separator()
        .group("People")
        .entity("author")
        .entity_with("user", |t| t.read_only(true))
        .entity("profile");
    if is_manager {
        admin = admin
            .separator()
            .group("Accounts (auth)")
            // Login accounts: create/edit inline (password is the write-only field above); the id
            // links to /profile/{id} for a dedicated password reset. Password never shows in reads.
            .entity_with("auth_user", |t| {
                t.title("Login accounts").format("id", |v, _row| {
                    format!(r#"<a href="/profile/{}" title="Reset password">{}</a>"#, esc(v), esc(v))
                })
            })
            .entity_with("auth_group", |t| t.title("Groups"))
            .entity_with("auth_username_lockout", |t| {
                t.title("Locked accounts").description(
                    "Accounts with recent failed logins. Delete a row to unlock one (the count \
                     clears itself once the lockout expires).",
                )
            })
            .entity_with("auth_ip_lockout", |t| {
                t.title("Locked addresses")
                    .description("Source addresses with recent failed credential checks.")
            });
    }
    admin.separator().group("Reference").link("Profile & 2FA", "/profile").link("Log out", "/logout")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = model::setup().await?;

    // auth: create the auth tables and seed an admin user in the admin group.
    auth::migrate(&db).await?;

    // Who the client is, decided **once** for the whole app and handed to the middleware below. Unset,
    // the socket peer is the client; `TRUST_PROXY=1` believes the proxy's forwarded hop (unproxied, that
    // header is attacker-supplied — hence the flag). Nothing else in this app resolves an address.
    let trust_proxy = matches!(std::env::var("TRUST_PROXY").as_deref(), Ok("1") | Ok("true"));

    // The brute-force brake is mandatory — `Auth::new` takes its configuration: 5 failed logins per
    // account and 15 per source address, both for 5 minutes.
    // Built from the defaults, since `Lockout` is `#[non_exhaustive]` — a struct literal would break the
    // day it grows a knob. Whitelisted addresses (an office range, a monitoring probe) are left empty so
    // the demo can actually lock itself out from localhost; a real app would pass
    // `relativelylight::net::parse_nets(&cfg.allow_list)` to `.whitelist(..)`.
    let lockout = auth::lockout::Lockout::default().accounts(5, 300).addresses(15, 300);

    // How an app wires a `--set-admin-pw` CLI flag: **break-glass** admin recovery for an operator who
    // is locked out — create-or-reset the password, re-activate the account, clear its TOTP 2FA, ensure
    // membership of ADMIN_GROUP (the same constant the gates use), then exit. Destructive by design, so
    // operator-run only; the boot-time seeder is `make_admin`, which leaves `is_active` / 2FA alone.
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--set-admin-pw") {
        let pw = args.get(i + 1).map(String::as_str).unwrap_or("");
        auth::reset_admin_access(&db, ADMIN_GROUP, "admin", pw).await?;
        println!("admin password set, account enabled, 2FA cleared, added to '{ADMIN_GROUP}'");
        return Ok(());
    }

    // Configuration is checked at startup, not discovered by an operator whose zone is missing.
    let picker = timezones();
    if !picker.unknown_zones().is_empty() {
        eprintln!("RL_TIMEZONES: ignoring unknown zone(s): {:?}", picker.unknown_zones());
    }

    auth::make_admin(&db, ADMIN_GROUP, "admin", "password").await?;

    // A second, non-admin user to show the gate at work: `editor` may read everything but write
    // nothing — the panel renders read-only for them (no Create/Edit/Delete) and the API returns 403.
    // Note the asymmetry, which is deliberate: these seeded passwords would be **refused** by the policy
    // configured below if they were typed into a form, but `make_admin` / `create_user` are the app's own
    // code — a seeder, a break-glass CLI — and the policy governs typed input only. If it governed these
    // too, a deployment could be left with no way to set a first password at all.
    auth::create_user(&db, "editor", "password").await?;

    // **One password policy, both surfaces.** Decided here because it is wanted in two places: `Auth`
    // applies it to /profile (self-service and a manager's reset), and the `auth_user` admin form gets
    // the same rule as a field validator further down. Skip either and it becomes the way around the
    // other.
    //
    // Driven by one config value, which is also the opt-out: PASSWORD_LEVEL=0 turns checking off
    // entirely, 1 = NIST's floor (≥ 8 characters), 2 = the library default (≥ 12), 3 = adds the
    // character-class rules an audit sometimes demands (see the docs on why that's offered rather than
    // recommended). An app wanting a rule the policy can't express — a breached-password corpus, a
    // per-group rule — passes its own closure to `Auth::password_check` instead.
    let password_level: u8 =
        std::env::var("PASSWORD_LEVEL").ok().and_then(|s| s.parse().ok()).unwrap_or(2);
    let password_policy = (password_level > 0).then(|| {
        // The app's own name is worth blocking: "adminpanel2024" satisfies every length rule ever
        // written and is the first thing anyone tries against this deployment.
        validate::PasswordPolicy::from_level(password_level).block(["adminpanel", "relativelylight"])
    });

    // authn: on-demand session lookups + login/logout routes, Bootstrap-styled login page. No
    // middleware — gates and page handlers call `auth.identify(&headers)` themselves.
    let auth = Auth::new(db.clone(), lockout)
        .secure_cookies(false) // local http
        .admin_group(ADMIN_GROUP)
        .totp_issuer("relativelylight admin") // shown in authenticator apps for 2FA
        .password_policy(password_policy.clone()) // `None` (level 0) switches the check off
        // Two session clocks: an absolute lifetime, and an idle one that expires a session nobody has
        // used. The idle window is what bounds a stolen cookie — the library's defaults are 7 days and
        // 8 hours; a back-office that lives in a browser tab all day wants roughly this.
        .session_ttl_secs(7 * 24 * 3600)
        .session_idle_secs(8 * 3600)
        .login_shell(login_shell)
        .profile_shell(profile_shell); // the app's chrome around the library's profile page

    // Housekeeping is the app's job — the library schedules nothing. `Auth::prune` clears dead sessions
    // (on either clock) and expired lockout rows; run it at startup and on the app's own loop.
    let prune_auth = auth.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            ticker.tick().await;
            if let Err(e) = prune_auth.prune().await {
                eprintln!("prune failed: {e}");
            }
        }
    });

    let mut author_mm = MetaModel::new(author::Entity);
    // Declaring the label column makes `post`'s `author` header sortable: the engine can turn
    // "order by the label in the cell" into `ORDER BY author.name`. Without it the relation would
    // still render, just without a clickable header.
    author_mm.label_column("name");
    let user_mm = MetaModel::new(user::Entity);
    let profile_mm = MetaModel::new(profile::Entity);
    let mut post_mm = MetaModel::new(post::Entity);
    // A closed set of values on a text column → a dropdown in the form, `enum` in the schema, and a 422
    // for anything else. (An enum column on Postgres/MySQL is introspected and needs no declaration.)
    post_mm.field("status").options =
        vec!["draft".into(), "review".into(), "published".into(), "archived".into()];
    let mut tag_mm = MetaModel::new(tag::Entity);
    post_mm.relate(&tag_mm);
    tag_mm.relate(&post_mm);

    // The auth login accounts + groups, surfaced in the admin. `.password()` turns `password_hash`
    // into a write-only, argon2-hashed "Password" field in one call: plaintext in the form, a hash in
    // the column, never returned in reads. An empty password stores an empty hash — no password can
    // verify against it, so password login is disabled (e.g. for future SSO / PassKey users).
    let mut auth_user_mm = MetaModel::new(auth::user::Entity);
    auth_user_mm.field("password_hash").password();
    auth_user_mm.field("password_hash").description = Some(
        "Optional. Leave blank to create an account with no password (password login disabled). \
         On edit, blank keeps the current password. At least 12 characters, and not a common one."
            .into(),
    );
    // The admin-form half of the policy decided above (the `Auth` half is on the builder). The pipeline
    // is coerce → validate → transform, so this validator sees the **plaintext** the form submitted,
    // before `.password()`'s argon2 hook hashes it. `optional` is what keeps blank meaningful (blank on
    // create = no password / login disabled; blank on edit = keep the current one) — without it, "leave
    // blank to keep the current password" would become a validation error.
    if let Some(policy) = password_policy.clone() {
        auth_user_mm
            .field("password_hash")
            .validate_str(validate::optional(Box::new(validate::password(policy))));
    }
    // The TOTP secret columns are secrets — never expose them in reads/writes/metadata. (2FA is
    // managed from the profile page, not the crud form.)
    auth_user_mm.field("totp_secret").hidden = true;
    auth_user_mm.field("totp_pending").hidden = true;
    // `totp_last_step` is the replay guard (the last 30s step accepted for this account). Not a secret,
    // but nothing an operator should see or edit — the library maintains it, and hand-editing it either
    // lets a code be replayed or locks the user out of their own authenticator for a while.
    auth_user_mm.field("totp_last_step").hidden = true;
    // Note what is *not* registered: `auth::recovery::entity` (the TOTP recovery codes). Every row is a
    // hash of a credential, and there is nothing an operator can usefully do to one — a user who needs a
    // fresh set generates it from /profile, and a user who has lost their authenticator is helped by the
    // "Disable 2FA" button on their manage page, which clears the codes with it. Contrast the two lockout
    // tables below, which *are* registered, because deleting one of those rows is the whole unlock.
    // New accounts are active by default (so a freshly created user with a password can log in).
    auth_user_mm.field("is_active").default = Some(serde_json::json!(true));
    // Lifecycle timestamps are maintained by the library (hooks / login flow) — show, don't edit.
    // Lifecycle stamps: read-only + rendered as timezone-aware datetimes (see .datetime() + the
    // $store.tz picker wired into the shell). They follow the picker's zone; storage stays UTC.
    for f in ["created_at", "updated_at", "last_login_at"] {
        auth_user_mm.field(f).read_only = true;
        auth_user_mm.field(f).datetime();
    }
    let mut auth_group_mm = MetaModel::new(auth::group::Entity);
    for f in ["created_at", "updated_at"] {
        auth_group_mm.field(f).read_only = true;
        auth_group_mm.field(f).datetime();
    }

    // Per-field presentation + validation (drives the labels / help / defaults / errors in the form).
    post_mm.field("title").label = Some("Title".into());
    post_mm.field("title").description = Some("The post headline (required).".into());
    post_mm.field("views").default = Some(serde_json::json!(0));
    post_mm.field("published").label = Some("Published".into());
    post_mm.field("published").default = Some(serde_json::json!(true));
    // Editable datetime → the form renders a timezone-aware <datetime-local> picker (edited in the
    // selected zone, stored as integer Unix-seconds UTC). Empty = unpublished.
    post_mm.field("published_at").label = Some("Published at".into());
    post_mm.field("published_at").description = Some("When the post went live (blank = draft).".into());
    post_mm.field("published_at").datetime();
    post_mm.relation("author").label = Some("Author".into());
    post_mm.relation("tag").label = Some("Tags".into());
    post_mm.field("title").validate = Some(Box::new(|v| {
        if v.as_str().unwrap_or("").trim().is_empty() {
            Err("Title cannot be empty".into())
        } else {
            Ok(())
        }
    }));

    // One gate for the whole panel: any logged-in user may list/read; only the admin group may write.
    // A shared `Arc` (it implements `Authz`) guards every model; each gate resolves the caller from
    // the request itself (via the `auth` handle it holds).
    let gate = Arc::new(UserReadGroupWrite::new(&auth, [ADMIN_GROUP]));
    let mut crud = Crud::new(db.clone());
    crud.register(author_mm, gate.clone());
    crud.register(post_mm, gate.clone());
    crud.register(user_mm, gate.clone());
    crud.register(profile_mm, gate.clone());
    crud.register(tag_mm, gate.clone());
    // The auth accounts/groups are admin-only, read included (the new `GroupReadWrite` preset).
    let admin_gate = Arc::new(GroupReadWrite::new(&auth, [ADMIN_GROUP]));
    crud.register(auth_user_mm, admin_gate.clone());
    crud.register(auth_group_mm, admin_gate.clone());
    // The lockout tables — this is what makes the unlock an ordinary, gated, audited DELETE instead of
    // a bespoke endpoint: an operator sees who is locked out and deletes the row. Counts and
    // timestamps are maintained by the library, so everything is read-only except the delete.
    let mut username_lockout_mm = MetaModel::new(auth::lockout::username_entity::Entity);
    let mut ip_lockout_mm = MetaModel::new(auth::lockout::ip_entity::Entity);
    for mm in [&mut username_lockout_mm.field("failures"), &mut ip_lockout_mm.field("failures")] {
        mm.read_only = true;
    }
    for mm in
        [&mut username_lockout_mm.field("last_failure_at"), &mut ip_lockout_mm.field("last_failure_at")]
    {
        mm.read_only = true;
        mm.datetime();
    }
    crud.register(username_lockout_mm, admin_gate.clone());
    crud.register(ip_lockout_mm, admin_gate.clone());
    // CSRF: these writes are cookie-authenticated, so every posted form must echo the double-submit
    // token. Sharing `auth.csrf()` puts the panel's forms and the login/profile forms on one token
    // cookie; the library renders the hidden `_csrf` input itself. See docs/AUTH.md §7.
    crud.csrf(auth.csrf());

    // One shared engine, rendered from *per request*, so write controls hide for users who can't
    // write — and a forged write is refused by the same gate regardless.
    let engine = Arc::new(crud.into_engine());

    let app = Arc::new(App { engine: engine.clone(), auth: auth.clone() });

    let ui = Router::new()
        // One pair of handlers for every model: the path says which one. Both are login-gated
        // (see `home`). `/` sends you to the first panel.
        .route("/", get(|| async { Redirect::to("/admin/post") }))
        .route("/admin/{entity}", get(home).post(save))
        .route("/tz", post(set_tz))
        .with_state(app);

    // Merge our pages and the login routes. No middleware: each handler/gate does its own on-demand
    // session lookup.
    let app_router = ui
        .merge(auth.routes())
        // No request log: this crate ships none (it writes nothing anywhere). `examples/access_log`
        // is a dozen lines you can copy, in two variants.
        // The caller's address, resolved **once** at the outermost layer: the access log, `auth`'s
        // lockout and the audit events all read that one value, so they can't disagree about who called.
        // `TRUST_PROXY=1` believes the proxy's forwarded hop; unset, the socket peer is the client
        // (unproxied, those headers are attacker-supplied — hence the flag). Mandatory: without this
        // layer `auth`'s login routes answer 500 and say what to add.
        .layer(axum::middleware::from_fn_with_state(
            relativelylight::middleware::TrustProxy(trust_proxy),
            relativelylight::middleware::resolve_real_ip,
        ));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("Admin panel on  http://127.0.0.1:3000/admin/post   (admin/password = read-write · editor/password = read-only)");
    // ConnectInfo gives the middleware the peer socket address for the access log.
    axum::serve(listener, app_router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

// Requires a logged-in user: resolve the session on demand, redirect anonymous visitors to the login
// page, then render the panel *for this caller* — a non-admin gets no Create/Edit/Delete, and the
// gates refuse those operations anyway. No middleware, no extractor.
//
// The whole of the read side is: parse the URL, render the fragment, wrap it in our shell.
async fn home(
    headers: HeaderMap,
    uri: Uri,
    Path(entity): Path<String>,
    State(app): State<Arc<App>>,
) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    // The path names the model; the query carries the view of it (page, sort, filters, dialog).
    let mut state = ViewState::from_uri(&uri);
    state.entity = Some(entity);
    let panel = panel(&app, &who);

    // The toolbar's Export link is `?format=csv` on this same page, so the export is this handler's
    // other answer — and it exports the view on screen, filter, search, sort and timezone included.
    if state.csv {
        return match panel.csv(&headers, &state).await {
            Ok(csv) => (
                [
                    (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                    (header::CONTENT_DISPOSITION, "attachment; filename=\"export.csv\"".to_string()),
                ],
                csv,
            )
                .into_response(),
            Err(e) => e.into_response(),
        };
    }

    match panel.render_for(&headers, &state).await {
        Ok(body) => page(body, &who, &headers, &uri),
        // A gate refusing a read (an `editor` opening an accounts table, say) answers 401/403 here.
        Err(e) => e.into_response(),
    }
}

/// The write side: hand the posted body to the library, then redirect — or, if it was refused,
/// re-render the same panel with the messages and the typed values back in the dialog.
async fn save(
    headers: HeaderMap,
    uri: Uri,
    Path(entity): Path<String>,
    RealIp(ip): RealIp,
    State(app): State<Arc<App>>,
    body: Bytes,
) -> Response {
    let Some(who) = app.auth.identify(&headers).await else {
        return Redirect::to(app.auth.login_path()).into_response();
    };
    let mut state = ViewState::from_uri(&uri);
    state.entity = Some(entity);
    let panel = panel(&app, &who);
    match panel.submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        Ok(Outcome::Invalid(state)) => match panel.render_for(&headers, &state).await {
            Ok(body) => (StatusCode::UNPROCESSABLE_ENTITY, page(body, &who, &headers, &uri)).into_response(),
            Err(e) => e.into_response(),
        },
        Err(e) => e.into_response(),
    }
}

/// The timezone picker's handler: set the cookie, come back to the page it was set from. Timestamps
/// are then formatted server-side in that zone — cells, form inputs and CSV alike.
async fn set_tz(Form(fields): Form<HashMap<String, String>>) -> Response {
    let tz = Tz::named(fields.get("tz").map(String::as_str).unwrap_or("UTC"));
    let back = fields.get("back").cloned().unwrap_or_else(|| "/".into());
    ([(header::SET_COOKIE, tz.cookie())], Redirect::to(&back)).into_response()
}

/// The panel for this caller. Managers (members of the admin group) get the accounts section and the
/// user-id → password-reset links; for anyone else those models would refuse a read, so the section
/// isn't listed at all.
fn panel<'a>(app: &'a App, who: &Identity) -> Admin<'a> {
    build_admin(&app.engine, app.auth.can_manage_others(who))
}

fn page(body: String, who: &Identity, headers: &HeaderMap, uri: &Uri) -> Response {
    let back = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let html = Shell::page("relativelylight", who.username.clone(), body, headers, back)
        .render()
        .unwrap_or_default();
    Html(html).into_response()
}

// The app styles the library's login form: drop it into our shell as a centered card. Anonymous, so
// the navbar shows no user link.
fn login_shell(form: &str) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto" style="max-width:24rem"><div class="card-body">
<h1 class="h5 mb-3">Log in</h1>{form}
<p class="text-muted small mt-2 mb-0">Demo: <code>admin</code> / <code>password</code></p>
</div></div>"#
    );
    Shell::page("Log in", "", body, &HeaderMap::new(), "/").render().unwrap_or_default()
}

// The app styles the library's profile/password page the same way. The library hands us the caller's
// identity, so the navbar shows their username (and Log out) just like the admin page.
fn profile_shell(fragment: &str, who: &Identity) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto" style="max-width:32rem"><div class="card-body">{fragment}
<a class="d-inline-block mt-3" href="/">&larr; Back to admin</a></div></div>"#
    );
    Shell::page("Profile", who.username.clone(), body, &HeaderMap::new(), "/profile")
        .render()
        .unwrap_or_default()
}
