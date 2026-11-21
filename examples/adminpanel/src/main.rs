//! adminpanel example — the `relativelylight::crud::ui::Admin` component, **login-gated** with the
//! `auth` module. Anonymous requests are redirected to `/login`; each model is gated by an `Authz`
//! gate (logged-in users may read; only the admin group may write) and the panel is rendered *per
//! request*, so a reader is offered no write controls and a write they forge is refused anyway. Two
//! demo logins: `admin` / `password` (read-write) and `editor` / `password` (read-only).
//!
//! The whole stack composed by the app: **two handlers** for the panel (`GET /` renders, `POST /`
//! writes), the `auth` routes merged in, one address-resolving layer, an askama shell, a timezone
//! cookie, and the authn/authz gates. (The `crud-example` is the ungated counterpart.) A relation
//! field's "+ New" creates a missing author or tag in a dialog over the form, for the admin only.
//!
//! Try:  open http://127.0.0.1:3000/   ·   each model has its own path (/admin/post, /admin/tag)
//!
//!   cargo run -p adminpanel-example -- --set-admin-pw s3cret   # break-glass admin recovery, then exit
//!   TRUST_PROXY=1 cargo run -p adminpanel-example              # behind a proxy: trust X-Forwarded-For

use askama::Template;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use model::{author, post, profile, tag, user};
use relativelylight::auth::{self, Auth, GroupReadWrite, Identity, UserReadGroupWrite};
use relativelylight::crud::engine::Engine;
use relativelylight::crud::seaorm::{Crud, MetaModel};
use relativelylight::crud::fmt::truncate;
use relativelylight::crud::ui::{Admin, Outcome, Picker, ViewState, CSS, JS};
use relativelylight::middleware::RealIp;
use relativelylight::time::{picker, Tz};
use relativelylight::validate;
use sea_orm::IdenStatic; // `post::Column::Title.as_str()` — a column name the compiler checks
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
    /// The account should choose a new password (`Identity::password_change`): a badge by the name.
    /// The general "notifications" design (a bell) is open work; this is the one notice there is.
    password_due: bool,
    body: String,
    css: &'static str, // the library's few CSS rules (crud::ui::CSS)
    js: &'static str,  // crud::ui::JS: modal dialogs with Esc, and the relation dialogs
    tz_picker: String, // the navbar timezone picker (time::picker)
    tz_js: &'static str, // time::JS: sets the zone cookie from the picker, and the browser's on a first visit
}

/// The page inside the relation picker's dialog: no navbar, the same stylesheet and colour mode.
#[derive(Template)]
#[template(path = "bare.html")]
struct Bare {
    body: String,
    css: &'static str,
}

/// A picker page (the list, a form, a row) in the bare shell, or the library's error.
fn bare(status: StatusCode, page: relativelylight::crud::engine::Result<String>) -> Response {
    match page.map(|body| Bare { body, css: CSS }.render()) {
        Ok(Ok(html)) => (status, Html(html)).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        Err(e) => e.into_response(),
    }
}

impl Shell {
    fn page(title: impl Into<String>, user: impl Into<String>, body: String, headers: &HeaderMap) -> Self {
        Self {
            title: title.into(),
            user: user.into(),
            password_due: false,
            body,
            css: CSS,
            js: JS,
            tz_picker: picker(&Tz::from_headers(headers)),
            tz_js: relativelylight::time::JS,
        }
    }
}

impl Shell {
    /// The shell for `who`: their name in the navbar, and the badge if a password change is due.
    fn for_user(mut self, who: &Identity) -> Self {
        self.password_due = who.password_change.is_some();
        self
    }
}

struct App {
    engine: Arc<Engine>,
    auth: Auth,
    /// The accounts tables' gate: it decides who may read them, so it also decides who sees them.
    accounts: Arc<GroupReadWrite>,
}

// The admin fragment's structure (nav groups, per-model table config). Built fresh per request so it
// can be rendered *for the caller*. `is_manager` says the accounts tables' gate admits the caller:
// only then is the Accounts section listed (anyone else would get 403 reading it). Each user-id links
// to its credentials page.
fn build_admin<'a>(engine: &'a Engine, is_manager: bool) -> Admin<'a> {
    let mut admin = Admin::new(engine)
        .title("relativelylight")
        // Each model gets a path of its own: /admin/post, /admin/auth_user. Only the side panel's
        // links change — everything inside a table is relative, so it resolves against whichever
        // path it is being served from.
        .base("/admin")
        // One control in the side-panel, applied to every listed table that has an `author` column —
        // here just `post`, but this is the shape that pays off when an admin lists many tables of the
        // same kind (fifteen per-type DNS record tables, say) and an operator works inside one of them
        // at a time. The choice travels in the query string, so it can be linked.
        .filter("author")
        .group("Content")
        .entity_with("post", |t| t.per_page(10))
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
            // Login accounts: create/edit inline (password is the write-only field above). The id
            // links to the account's credentials page, `/profile/{id}` (password reset, 2FA off,
            // passkeys removed): `auth::user::meta_model` declares that link, so every table of
            // accounts has it. Password never shows in reads.
            .entity_with("auth_user", |t| t.title("Login accounts"))
            .entity_with("auth_group", |t| t.title("Groups"))
            .entity_with("auth_username_lockout", |t| {
                t.title("Locked accounts").create(false).edit(false).description(
                    "Accounts with recent failed logins. Delete a row to unlock one (the count \
                     clears itself once the lockout expires).",
                )
            })
            .entity_with("auth_ip_lockout", |t| {
                t.title("Locked addresses")
                    .create(false)
                    .edit(false)
                    .description("Source addresses with recent failed credential checks.")
            });
    }
    admin
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
    author_mm.label_column(author::Column::Name.as_str());
    let user_mm = MetaModel::new(user::Entity);
    let profile_mm = MetaModel::new(profile::Entity);
    let mut post_mm = MetaModel::new(post::Entity);
    // `post.status` needs no line here: it is a `db_type = "Enum"` ActiveEnum (`post::Status`), so the
    // admin introspects the variants → a dropdown in the form and a 422 for anything else, on SQLite too.
    let mut tag_mm = MetaModel::new(tag::Entity);
    post_mm.relate(&tag_mm);
    tag_mm.relate(&post_mm);

    // The auth login accounts, groups and lockout counters come configured from the library: the
    // secrets hidden, the stamps read-only, the first password write-only, argon2-hashed and screened by
    // the same policy `Auth` was given above, the group membership as an N:M relation. Later passwords,
    // 2FA and passkeys of someone else are their credentials page's (`/profile/{id}`), which the id
    // column links to. Note what is *not* registered: `auth::recovery::entity` (every row is a hash of
    // a credential).
    let auth_user_mm = auth::user::meta_model(&auth);
    let auth_group_mm = auth::group::meta_model();

    // Per-field presentation + validation (drives the labels / help / defaults / errors in the form).
    post_mm.field(post::Column::Title.as_str()).label = Some("Title".into());
    post_mm.field(post::Column::Title.as_str()).description =
        Some("The post headline (required).".into());
    post_mm.field(post::Column::Views.as_str()).default = Some(serde_json::json!(0));
    post_mm.field(post::Column::Published.as_str()).label = Some("Published".into());
    post_mm.field(post::Column::Published.as_str()).default = Some(serde_json::json!(true));
    // Editable datetime → the form renders a timezone-aware <datetime-local> picker (edited in the
    // selected zone, stored as integer Unix-seconds UTC). Empty = unpublished.
    post_mm.field(post::Column::PublishedAt.as_str()).label = Some("Published at".into());
    post_mm.field(post::Column::PublishedAt.as_str()).description =
        Some("When the post went live (blank = draft).".into());
    post_mm.field(post::Column::PublishedAt.as_str()).datetime();
    // The listing shows the start of the body (whole in the tooltip); View shows it all. A display
    // formatter belongs to the field, so every table of posts shows it the same way.
    post_mm.field(post::Column::Body.as_str()).format_cell(truncate(60));
    post_mm.relation("author").label = Some("Author".into());
    post_mm.relation("tag").label = Some("Tags".into());
    post_mm.field(post::Column::Title.as_str()).validate = Some(Box::new(|v| {
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
    // a bespoke endpoint: an operator sees who is locked out and deletes the row.
    crud.register(auth::lockout::username_meta_model(), admin_gate.clone());
    crud.register(auth::lockout::ip_meta_model(), admin_gate.clone());
    // CSRF: these writes are cookie-authenticated, so every posted form must echo the double-submit
    // token. Sharing `auth.csrf()` puts the panel's forms and the login/profile forms on one token
    // cookie; the library renders the hidden `_csrf` input itself. See docs/AUTH.md §7.
    crud.csrf(auth.csrf());
    // A post's author and tags outnumber `picker_threshold` (50), so the form edits them in a dialog
    // over this route. Its rows are the target's own table, so they answer to the target's gate.
    crud.picker_path("/_rl/pick");
    // "+ New" for a relation whose target doesn't have the row yet: a new author made in a dialog
    // over the half-filled post, and chosen in it. The target's gate decides, so the editor
    // (read-only) never sees the button. `user` is shown read-only in the panel (see `build_admin`),
    // so it is never created this way either: a table-level switch is a view's choice, which only
    // the gate or this list carries over to "+ New".
    crud.picker_create(true);
    crud.picker_create_except(["user"]);
    // Each relation's label links to its row, opened in a dialog (with Edit for the admin). Without
    // the script, or in a new tab, the link is the row's View in this panel.
    crud.picker_view(true);
    for slug in ["post", "tag", "author", "user", "profile", "auth_user", "auth_group"] {
        crud.view_path(slug, format!("/admin/{slug}?show={{id}}"));
    }

    // One shared engine, rendered from *per request*, so write controls hide for users who can't
    // write — and a forged write is refused by the same gate regardless.
    let engine = Arc::new(crud.into_engine());

    let app = Arc::new(App { engine: engine.clone(), auth: auth.clone(), accounts: admin_gate });

    let ui = Router::new()
        // One pair of handlers for every model: the path says which one. Both are login-gated
        // (see `home`). `/` sends you to the first panel.
        .route("/", get(|| async { Redirect::to("/admin/post") }))
        .route("/admin/{entity}", get(home).post(save))
        .route("/_rl/pick", get(pick).post(pick_write))
        .with_state(app);

    // Merge our pages and the login routes. No middleware: each handler/gate does its own on-demand
    // session lookup.
    let app_router = ui
        .merge(auth.routes())
        // No request log: this crate ships none (it writes nothing anywhere). `examples/audit`
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
/// The relation picker's page. No login redirect of its own: it renders inside a dialog, and the
/// target's gate answers 401/403 for a caller who may not list it.
async fn pick(headers: HeaderMap, uri: Uri, State(app): State<Arc<App>>) -> Response {
    let state = ViewState::from_uri(&uri);
    bare(StatusCode::OK, Picker::new(&app.engine).render_for(&headers, &state).await)
}

/// The "+ New" dialog's create form posts here: a `303` into the same iframe when saved (the dialog's
/// script then chooses the new row), the form again with its messages when not. Gated and
/// CSRF-checked like the panel's own writes.
async fn pick_write(
    headers: HeaderMap,
    uri: Uri,
    RealIp(ip): RealIp,
    State(app): State<Arc<App>>,
    body: Bytes,
) -> Response {
    let state = ViewState::from_uri(&uri);
    let picker = Picker::new(&app.engine);
    match picker.submit(&headers, ip, &body, &state).await {
        Ok(Outcome::Done(to)) => Redirect::to(&to).into_response(),
        Ok(Outcome::Invalid(state)) => {
            bare(StatusCode::UNPROCESSABLE_ENTITY, picker.render_for(&headers, &state).await)
        }
        Err(e) => e.into_response(),
    }
}

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
        Ok(body) => page(body, &who, &headers),
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
            Ok(body) => (StatusCode::UNPROCESSABLE_ENTITY, page(body, &who, &headers)).into_response(),
            Err(e) => e.into_response(),
        },
        Err(e) => e.into_response(),
    }
}

/// The panel for this caller: the accounts section when the accounts gate admits them — the gate that
/// guards those tables, asked without a second session lookup.
fn panel<'a>(app: &'a App, who: &Identity) -> Admin<'a> {
    build_admin(&app.engine, app.accounts.admits(who))
}

fn page(body: String, who: &Identity, headers: &HeaderMap) -> Response {
    let html = Shell::page("relativelylight", who.username.clone(), body, headers)
        .for_user(who)
        .render()
        .unwrap_or_default();
    Html(html).into_response()
}

// The app styles the library's login form: drop it into our shell as a centered card. Anonymous, so
// the navbar shows no user link. The library hands us the request, so the navbar's timezone picker
// shows the caller's zone here as on every other page.
fn login_shell(form: &str, req: &Parts) -> String {
    let body = format!(
        r#"<div class="card shadow-sm mx-auto" style="max-width:24rem"><div class="card-body">
<h1 class="h5 mb-3">Log in</h1>{form}
<p class="text-muted small mt-2 mb-0">Demo: <code>admin</code> / <code>password</code></p>
</div></div>"#
    );
    Shell::page("Log in", "", body, &req.headers).render().unwrap_or_default()
}

// The app styles the library's profile/password page the same way. The library hands us the caller's
// identity and the request, so the navbar shows their username (and Log out) and their timezone just
// like the admin page — on /profile, /profile/totp and a manager's /profile/{id} alike.
fn profile_shell(fragment: &str, who: &Identity, req: &Parts) -> String {
    // The fragment is a grid of cards (two columns on a wide screen): a wide column, no card around it.
    let body = format!(
        r#"<div class="mx-auto" style="max-width:72rem">{fragment}</div>"#
    );
    Shell::page("Profile", who.username.clone(), body, &req.headers)
        .for_user(who)
        .render()
        .unwrap_or_default()
}

