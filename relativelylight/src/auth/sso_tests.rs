//! SSO callback tests, driven against a **fake identity provider** (feature `sso`).
//!
//! `security_tests.rs` covers what an `sso_provider` account means *locally* — no password login, no
//! profile writes, no manager reset. This module covers the other half: the OIDC callback itself, which
//! is the module's actual trust boundary. Everything it must refuse is refused here, and each rejection
//! is checked the way the rest of the suite checks them — **no session cookie, no session row** — so a
//! handler that answered "no" while quietly signing someone in would fail.
//!
//! **Why a fake IdP and not a live one.** `TODO.md` asked for the callback to be verified against a real
//! provider. A real one can't be driven in CI, can't be asked for an expired token or one signed by the
//! wrong key, and would make the suite depend on someone else's uptime — so the negative cases, which are
//! the whole point, would go untested. Instead a small axum app plays the provider on a loopback port,
//! serving a discovery document, a JWKS, and a token endpoint that mints ID tokens **to order** via
//! [`Recipe`]. The client side is the shipped code: `openidconnect` performs real discovery over real
//! HTTP and verifies real RSA signatures.
//!
//! The one shortcut: the tests read the in-flight transaction out of its own cookie to learn the nonce.
//! That is possible because the cookie is base64 JSON rather than a signed blob — see `docs/AUTH.md` §5b
//! on why that is a documented assumption rather than a defect.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration as ChronoDuration, Utc};
use openidconnect::core::{
    CoreGenderClaim, CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey, CoreSubjectIdentifierType,
};
use openidconnect::{
    AdditionalClaims, Audience, AuthUrl, EmptyAdditionalProviderMetadata, IdToken, IdTokenClaims,
    IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl, PrivateSigningKey, ResponseTypes, StandardClaims,
    SubjectIdentifier, TokenUrl,
};
use rsa::pkcs1::EncodeRsaPrivateKey;
use sea_orm::{Database, DatabaseConnection, EntityTrait, Set};
use serde_json::{json, Map, Value};
use tower::ServiceExt;

use crate::auth::lockout::Lockout;
use crate::auth::sso::{Sso, SsoProvider};
use crate::auth::{migrate, session, user, Auth};

const CLIENT_ID: &str = "test-client";
const PROVIDER: &str = "testidp";

// ===================== Signing keys =====================

/// Two RSA keys, generated **once per test process**: the one the fake IdP publishes in its JWKS, and a
/// second one that it doesn't, for the "signed by a key we don't trust" case. Generated rather than
/// embedded so no private key material lives in the repository (and no secret scanner has to be told
/// about it); 2048 bits keeps the one-off cost small.
fn keys() -> &'static (String, String) {
    static KEYS: OnceLock<(String, String)> = OnceLock::new();
    KEYS.get_or_init(|| (generate_key(), generate_key()))
}

fn generate_key() -> String {
    let mut rng = rand_core::OsRng;
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
    // PKCS#1 (`RSA PRIVATE KEY`), which is what `CoreRsaPrivateSigningKey::from_pem` parses — a PKCS#8
    // (`PRIVATE KEY`) wrapper is rejected on the label alone.
    key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).expect("encode PEM").to_string()
}

fn signing_key(pem: &str) -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(pem, Some(JsonWebKeyId::new("test-key".into())))
        .expect("valid RSA private key")
}

// ===================== The fake IdP =====================

/// Free-form additional claims, so a test can put an arbitrary claim name (the configured username
/// claim, a groups array) into a **properly signed** token — our reader takes them from the verified
/// token's payload, so they have to be really there, not stubbed.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Extra(Map<String, Value>);
impl AdditionalClaims for Extra {}

type TestIdToken =
    IdToken<Extra, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>;
type TestClaims = IdTokenClaims<Extra, CoreGenderClaim>;

/// What the fake IdP should mint on the next token exchange. Every field is a way for a real provider —
/// or an attacker standing in for one — to be wrong.
#[derive(Clone)]
struct Recipe {
    /// The `nonce` to bind in. `None` → omit it entirely; a wrong value stands in for a replayed token.
    nonce: Option<String>,
    /// The `aud`. Anything but the client id must be refused.
    audience: String,
    /// The `iss`. `None` → the fake IdP's real issuer.
    issuer: Option<String>,
    /// Seconds until `exp`; negative mints an already-expired token.
    lifetime_secs: i64,
    /// Sign with the key that is **not** in the published JWKS.
    wrong_key: bool,
    /// `(claim, value)` for the username, e.g. `("preferred_username", "alice")`. `None` → omit it.
    username: Option<(String, String)>,
    /// The `groups` claim, when the test drives group mapping.
    groups: Option<Vec<String>>,
    /// Answer the token endpoint without an `id_token` at all.
    omit_id_token: bool,
}

impl Recipe {
    /// A recipe that produces a valid token for `username` — the baseline each test spoils in one way.
    fn valid(username: &str) -> Self {
        Self {
            nonce: None, // filled in from the transaction cookie
            audience: CLIENT_ID.into(),
            issuer: None,
            lifetime_secs: 300,
            wrong_key: false,
            username: Some(("preferred_username".into(), username.into())),
            groups: None,
            omit_id_token: false,
        }
    }
}

#[derive(Clone)]
struct IdpState {
    issuer: String,
    recipe: Arc<Mutex<Recipe>>,
    /// How many times the discovery document has been fetched — the discovery cache is a claim about
    /// this number, so the test counts it rather than trusting the implementation.
    discovery_hits: Arc<AtomicUsize>,
}

/// Start the fake IdP on a loopback port; returns its state handle (which carries the issuer URL).
async fn start_idp() -> IdpState {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind idp");
    let addr: SocketAddr = listener.local_addr().expect("idp addr");
    let state = IdpState {
        issuer: format!("http://{addr}"),
        recipe: Arc::new(Mutex::new(Recipe::valid("nobody"))),
        discovery_hits: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(idp_discovery))
        .route("/jwks", get(idp_jwks))
        .route("/token", post(idp_token))
        .with_state(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    // The client does real HTTP against this, so it has to be accepting before the first request.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    state
}

async fn idp_discovery(State(idp): State<IdpState>) -> impl IntoResponse {
    idp.discovery_hits.fetch_add(1, Ordering::SeqCst);
    let meta = CoreProviderMetadata::new(
        IssuerUrl::new(idp.issuer.clone()).unwrap(),
        AuthUrl::new(format!("{}/authorize", idp.issuer)).unwrap(),
        JsonWebKeySetUrl::new(format!("{}/jwks", idp.issuer)).unwrap(),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::new(format!("{}/token", idp.issuer)).unwrap()));
    Json(serde_json::to_value(&meta).unwrap())
}

/// Publishes **only** the first key, which is what makes the `wrong_key` recipe fail verification.
async fn idp_jwks() -> impl IntoResponse {
    let jwks = CoreJsonWebKeySet::new(vec![signing_key(&keys().0).as_verification_key()]);
    Json(serde_json::to_value(&jwks).unwrap())
}

async fn idp_token(State(idp): State<IdpState>) -> impl IntoResponse {
    let recipe = idp.recipe.lock().unwrap().clone();
    let mut body = json!({ "access_token": "test-access-token", "token_type": "Bearer", "expires_in": 3600 });
    if recipe.omit_id_token {
        return Json(body);
    }

    let mut extra = Map::new();
    if let Some((claim, value)) = &recipe.username {
        extra.insert(claim.clone(), json!(value));
    }
    if let Some(groups) = &recipe.groups {
        extra.insert("groups".into(), json!(groups));
    }
    let issuer = recipe.issuer.clone().unwrap_or_else(|| idp.issuer.clone());
    let claims = TestClaims::new(
        IssuerUrl::new(issuer).unwrap(),
        vec![Audience::new(recipe.audience.clone())],
        Utc::now() + ChronoDuration::seconds(recipe.lifetime_secs),
        Utc::now(),
        StandardClaims::new(SubjectIdentifier::new("test-subject".into())),
        Extra(extra),
    )
    .set_nonce(recipe.nonce.clone().map(openidconnect::Nonce::new));

    let pem = if recipe.wrong_key { &keys().1 } else { &keys().0 };
    let id_token = TestIdToken::new(
        claims,
        &signing_key(pem),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        None,
    )
    .expect("sign id token");
    let jwt = serde_json::to_value(&id_token).unwrap();
    body["id_token"] = jwt;
    Json(body)
}

// ===================== Our side =====================

/// Our app: `Auth` + `Sso` pointed at the fake IdP, driven with `oneshot` (only the *provider* needs a
/// real socket — the callback's outbound calls are ordinary reqwest traffic).
struct Fx {
    db: DatabaseConnection,
    auth: Auth,
    app: Router,
    idp: IdpState,
}

impl Fx {
    async fn new(auto_register: bool) -> Fx {
        Fx::with(auto_register, |p| p).await
    }

    async fn with(auto_register: bool, tweak: impl FnOnce(SsoProvider) -> SsoProvider) -> Fx {
        let idp = start_idp().await;
        let db = Database::connect("sqlite::memory:").await.expect("sqlite in-memory");
        migrate(&db).await.expect("migrate");
        let auth = Auth::new(db.clone(), Lockout::default()).secure_cookies(false);
        let provider = tweak(
            SsoProvider::new(
                PROVIDER,
                "Test IdP",
                idp.issuer.clone(),
                CLIENT_ID,
                "test-secret",
                "http://localhost/sso/testidp/callback",
            )
            .auto_register(auto_register),
        );
        let sso = Sso::new(&auth)
            .username_group_rule(r"^staff-", ["staff"])
            .provider(provider);
        let app = auth.routes().merge(sso.routes());
        Fx { db, auth, app, idp }
    }

    async fn send(&self, req: Request<Body>) -> Resp {
        let res = self.app.clone().oneshot(req).await.expect("router response");
        let status = res.status();
        let headers = res.headers().clone();
        let body = axum::body::to_bytes(res.into_body(), 1 << 20).await.expect("body");
        Resp { status, headers, body: String::from_utf8_lossy(&body).into_owned() }
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> Resp {
        let mut req = Request::builder().method("GET").uri(path);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        self.send(req.body(Body::empty()).unwrap()).await
    }

    /// Walk the first half of the flow: `GET /sso/{p}/login` and return the transaction cookie it set
    /// plus the `state` and `nonce` inside it.
    async fn begin_login(&self) -> (String, String, String) {
        let res = self.get(&format!("/sso/{PROVIDER}/login"), None).await;
        assert_eq!(res.status, StatusCode::SEE_OTHER, "login must redirect to the provider: {}", res.body);
        let cookie = res.txn_cookie().expect("a transaction cookie");
        let txn = res.txn().expect("a readable transaction");
        let state = txn["csrf"].as_str().expect("csrf in txn").to_string();
        let nonce = txn["nonce"].as_str().expect("nonce in txn").to_string();
        (cookie, state, nonce)
    }

    /// The whole flow with the IdP told to mint `recipe` (its nonce filled in from the transaction).
    async fn login_with(&self, mut recipe: Recipe) -> Resp {
        let (cookie, state, nonce) = self.begin_login().await;
        if recipe.nonce.is_none() {
            recipe.nonce = Some(nonce);
        }
        *self.idp.recipe.lock().unwrap() = recipe;
        self.callback(&format!("code=test-code&state={state}"), Some(&cookie)).await
    }

    async fn callback(&self, query: &str, cookie: Option<&str>) -> Resp {
        self.get(&format!("/sso/{PROVIDER}/callback?{query}"), cookie).await
    }

    async fn row(&self, username: &str) -> Option<user::Model> {
        use sea_orm::{ColumnTrait, QueryFilter};
        user::Entity::find()
            .filter(user::Column::Username.eq(username))
            .one(&self.db)
            .await
            .expect("query")
    }

    async fn session_count(&self) -> usize {
        session::Entity::find().all(&self.db).await.expect("query").len()
    }

    async fn groups_of(&self, username: &str) -> Vec<String> {
        let id = self.row(username).await.expect("user exists").id;
        crate::auth::groups_of(&self.db, id).await
    }

    /// Add a local (password) user, optionally bound to an SSO provider and/or disabled.
    async fn user(&self, username: &str, provider: Option<&str>, active: bool) -> i32 {
        let u = user::ActiveModel {
            username: Set(username.into()),
            password_hash: Set(crate::auth::hash_password("pw")),
            is_active: Set(active),
            sso_provider: Set(provider.map(String::from)),
            ..Default::default()
        };
        use sea_orm::ActiveModelTrait;
        u.insert(&self.db).await.expect("insert user").id
    }

    /// Every rejection must leave the caller anonymous: no session cookie handed out, no row written.
    async fn assert_no_login(&self, res: &Resp, what: &str) {
        assert!(
            res.session_token(self.auth.session_cookie_name()).is_none(),
            "{what}: must not set a session cookie"
        );
        assert_eq!(self.session_count().await, 0, "{what}: must not create a session row");
    }
}

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Resp {
    fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(String::from))
            .collect()
    }

    fn session_token(&self, name: &str) -> Option<String> {
        for c in self.set_cookies() {
            if let Some(rest) = c.strip_prefix(&format!("{name}=")) {
                let value = rest.split(';').next().unwrap_or_default().to_string();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
        None
    }

    fn txn_cookie(&self) -> Option<String> {
        self.set_cookies()
            .into_iter()
            .find(|c| c.starts_with("rl_sso_txn="))
            .map(|c| c.split(';').next().unwrap_or_default().to_string())
    }

    /// The transaction's JSON, decoded straight out of the cookie.
    fn txn(&self) -> Option<Value> {
        let raw = self.txn_cookie()?;
        let value = raw.trim_start_matches("rl_sso_txn=").to_string();
        let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Whether the response *clears* the transaction cookie — a removal renders as an empty value
    /// (`rl_sso_txn=;` …), which is what distinguishes it from the cookie `login` sets.
    fn clears_txn(&self) -> bool {
        self.set_cookies().iter().any(|c| c.starts_with("rl_sso_txn=;"))
    }
}

// ===================== The positive control =====================

#[tokio::test]
async fn a_full_sso_login_signs_in_maps_groups_and_marks_the_account_external() {
    // The control the rejections below are measured against: the real client code, real discovery over
    // HTTP, a real RSA signature — and a session at the end of it.
    let fx = Fx::with(true, |p| p.groups_claim("groups").claim_group_rule("eng", ["editors"])).await;

    let mut recipe = Recipe::valid("staff-alice");
    recipe.groups = Some(vec!["eng".into(), "unmapped".into()]);
    let res = fx.login_with(recipe).await;

    assert_eq!(res.status, StatusCode::SEE_OTHER, "expected a redirect: {}", res.body);
    assert!(res.session_token(fx.auth.session_cookie_name()).is_some(), "a session cookie is set");
    assert_eq!(fx.session_count().await, 1);

    let row = fx.row("staff-alice").await.expect("auto-registered");
    assert_eq!(row.sso_key(), Some(PROVIDER), "the account is marked external");
    assert!(row.password_hash.is_empty(), "and has no local password");
    assert!(row.last_login_at.is_some(), "the login is stamped");

    // Groups are the union of the username rule (^staff- → staff) and the claim rule (eng → editors);
    // an unmapped claim value grants nothing.
    let mut groups = fx.groups_of("staff-alice").await;
    groups.sort();
    assert_eq!(groups, vec!["editors".to_string(), "staff".to_string()]);

    // The transaction is finished, so its cookie goes.
    assert!(res.clears_txn(), "the transaction cookie must be cleared: {:?}", res.set_cookies());
}

// ===================== Transaction / CSRF =====================

#[tokio::test]
async fn a_callback_without_a_transaction_cookie_is_refused() {
    let fx = Fx::new(true).await;
    let (_cookie, state, _nonce) = fx.begin_login().await;
    // The state is right; the cookie proving we issued it is missing.
    let res = fx.callback(&format!("code=test-code&state={state}"), None).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.body.contains("SSO transaction"), "{}", res.body);
    fx.assert_no_login(&res, "no transaction cookie").await;
}

#[tokio::test]
async fn a_state_mismatch_is_refused_and_clears_the_transaction() {
    let fx = Fx::new(true).await;
    let (cookie, state, _nonce) = fx.begin_login().await;

    for (query, what) in [
        (format!("code=test-code&state={}", "b".repeat(state.len())), "a forged state"),
        (format!("code=test-code&state={}", &state[1..]), "a truncated state"),
        ("code=test-code".to_string(), "no state at all"),
        (format!("state={state}"), "no code"),
        (format!("error=access_denied&state={state}"), "the provider reporting an error"),
    ] {
        let res = fx.callback(&query, Some(&cookie)).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{what} must be refused: {}", res.body);
        fx.assert_no_login(&res, what).await;
        // A finished-with transaction must not linger for the rest of its ten minutes.
        assert!(res.clears_txn(), "{what}: must clear the transaction cookie");
    }
}

#[tokio::test]
async fn a_transaction_for_one_provider_cannot_be_completed_at_another() {
    // Two providers, so the callback path and the transaction can disagree. Without the provider check a
    // transaction opened at a permissive IdP could be cashed in at a privileged one.
    let idp = start_idp().await;
    let db = Database::connect("sqlite::memory:").await.expect("sqlite");
    migrate(&db).await.expect("migrate");
    let auth = Auth::new(db.clone(), Lockout::default()).secure_cookies(false);
    let mk = |key: &str| {
        SsoProvider::new(
            key,
            key,
            idp.issuer.clone(),
            CLIENT_ID,
            "test-secret",
            format!("http://localhost/sso/{key}/callback"),
        )
        .auto_register(true)
    };
    let sso = Sso::new(&auth).provider(mk("first")).provider(mk("second"));
    let app = auth.routes().merge(sso.routes());

    let res = app
        .clone()
        .oneshot(Request::builder().uri("/sso/first/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let cookie = res
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("rl_sso_txn="))
        .map(|c| c.split(';').next().unwrap().to_string())
        .expect("txn cookie");
    let txn: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(cookie.trim_start_matches("rl_sso_txn=")).unwrap(),
    )
    .unwrap();
    let state = txn["csrf"].as_str().unwrap();

    // Same cookie, same state — presented at the *other* provider's callback.
    let res = app
        .oneshot(
            Request::builder()
                .uri(format!("/sso/second/callback?code=test-code&state={state}"))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST, "a cross-provider transaction must be refused");
    assert_eq!(session::Entity::find().all(&db).await.unwrap().len(), 0, "no session row");
}

// ===================== ID token verification =====================

#[tokio::test]
async fn an_id_token_that_fails_verification_is_refused() {
    // Each case is a token the provider *did* return over a correct transaction — only the token itself
    // is wrong. These are the assertions that would silently pass if verification were skipped.
    for (spoil, what) in [
        (
            Box::new(|r: &mut Recipe| r.wrong_key = true) as Box<dyn Fn(&mut Recipe)>,
            "signed by a key that isn't in the JWKS",
        ),
        (Box::new(|r: &mut Recipe| r.audience = "someone-else".into()), "issued for another audience"),
        (
            Box::new(|r: &mut Recipe| r.issuer = Some("http://evil.example".into())),
            "issued by another issuer",
        ),
        (Box::new(|r: &mut Recipe| r.lifetime_secs = -60), "expired"),
        (Box::new(|r: &mut Recipe| r.nonce = Some("not-the-nonce".into())), "bound to another nonce"),
        (Box::new(|r: &mut Recipe| r.nonce = Some(String::new())), "carrying an empty nonce"),
        (Box::new(|r: &mut Recipe| r.omit_id_token = true), "absent altogether"),
    ] {
        let fx = Fx::new(true).await;
        let mut recipe = Recipe::valid("alice");
        spoil(&mut recipe);
        // `login_with` only fills the nonce when the recipe left it unset, so the spoiled ones survive.
        let res = fx.login_with(recipe).await;
        assert_eq!(res.status, StatusCode::BAD_GATEWAY, "a token {what} must be refused: {}", res.body);
        fx.assert_no_login(&res, what).await;
        assert!(fx.row("alice").await.is_none(), "{what}: and must not create an account");
    }
}

#[tokio::test]
async fn a_token_without_the_configured_username_claim_is_refused() {
    let fx = Fx::new(true).await;
    let mut recipe = Recipe::valid("alice");
    recipe.username = None;
    let res = fx.login_with(recipe).await;
    assert_eq!(res.status, StatusCode::BAD_GATEWAY);
    assert!(res.body.contains("preferred_username"), "names the missing claim: {}", res.body);
    fx.assert_no_login(&res, "no username claim").await;

    // And a claim whose value can't be an identity key is refused rather than stored.
    for bad in ["", "  ", "has space", "with\ttab"] {
        let fx = Fx::new(true).await;
        let mut recipe = Recipe::valid("alice");
        recipe.username = Some(("preferred_username".into(), bad.into()));
        let res = fx.login_with(recipe).await;
        assert_eq!(res.status, StatusCode::BAD_GATEWAY, "username {bad:?} must be refused: {}", res.body);
        fx.assert_no_login(&res, "invalid username claim").await;
    }
}

// ===================== Account resolution =====================

#[tokio::test]
async fn a_disabled_sso_account_cannot_log_in() {
    // The finding this test was written for: `resolve_user` never looked at `is_active`, so a deactivated
    // account got its groups reconciled, its `last_login_at` stamped and a session row minted. None of it
    // authenticated (`identify` re-checks the flag) — but "disable this account" has to mean the same
    // thing on the SSO door as on the password one, and the audit trail must not record a login that
    // never happened.
    let fx = Fx::new(false).await;
    fx.user("dormant", Some(PROVIDER), false).await;

    let res = fx.login_with(Recipe::valid("dormant")).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "a disabled account must be refused: {}", res.body);
    assert!(res.body.contains("disabled"), "{}", res.body);
    fx.assert_no_login(&res, "disabled account").await;
    assert!(fx.row("dormant").await.unwrap().last_login_at.is_none(), "no login is stamped");

    // Control: re-activating the same account lets the same flow through.
    use sea_orm::ActiveModelTrait;
    let mut am: user::ActiveModel = fx.row("dormant").await.unwrap().into();
    am.is_active = Set(true);
    am.update(&fx.db).await.expect("reactivate");
    let res = fx.login_with(Recipe::valid("dormant")).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    assert!(res.session_token(fx.auth.session_cookie_name()).is_some());
}

#[tokio::test]
async fn a_local_password_account_cannot_be_taken_over_through_sso() {
    // An IdP (or a claim mapping) that yields an existing *local* username must not hand over that
    // account — otherwise anyone who can make the IdP emit a chosen username owns every local login.
    let fx = Fx::new(true).await;
    fx.user("alice", None, true).await;

    let res = fx.login_with(Recipe::valid("alice")).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.body);
    assert!(res.body.contains("local"), "{}", res.body);
    fx.assert_no_login(&res, "local account via SSO").await;
    assert!(fx.row("alice").await.unwrap().sso_key().is_none(), "the account stays local");
}

#[tokio::test]
async fn an_account_bound_to_another_provider_is_refused() {
    let fx = Fx::new(true).await;
    fx.user("federated", Some("otheridp"), true).await;

    let res = fx.login_with(Recipe::valid("federated")).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.body);
    assert!(res.body.contains("different SSO provider"), "{}", res.body);
    fx.assert_no_login(&res, "wrong provider binding").await;
    assert_eq!(fx.row("federated").await.unwrap().sso_key(), Some("otheridp"), "binding unchanged");
}

#[tokio::test]
async fn auto_registration_off_refuses_an_unknown_account() {
    let fx = Fx::new(false).await;
    let res = fx.login_with(Recipe::valid("stranger")).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.body);
    fx.assert_no_login(&res, "auto-register off").await;
    assert!(fx.row("stranger").await.is_none(), "no account is created");

    // Control: with it on, the same login creates the account.
    let fx = Fx::new(true).await;
    let res = fx.login_with(Recipe::valid("stranger")).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    assert!(fx.row("stranger").await.is_some());
}

#[tokio::test]
async fn the_username_claim_is_matched_case_insensitively() {
    // A provider that changes the case of what it emits must not acquire a second account for the same
    // person — two rows, two group sets, one human. The pre-created row wins and keeps its own spelling.
    let fx = Fx::new(true).await;
    fx.user("Alice@Corp.example", Some(PROVIDER), true).await;

    let res = fx.login_with(Recipe::valid("alice@corp.example")).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "the existing account is found: {}", res.body);
    assert!(fx.row("alice@corp.example").await.is_none(), "no lower-cased duplicate is created");
    assert!(fx.row("Alice@Corp.example").await.unwrap().last_login_at.is_some(), "the original logged in");
    assert_eq!(user::Entity::find().all(&fx.db).await.unwrap().len(), 1, "still exactly one account");

    // The same recognition applies to the refusals: a *local* account differing only in case is still
    // identified as local, not auto-registered alongside.
    let fx = Fx::new(true).await;
    fx.user("Bob", None, true).await;
    let res = fx.login_with(Recipe::valid("bob")).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.body);
    assert_eq!(user::Entity::find().all(&fx.db).await.unwrap().len(), 1, "no second Bob");
}

// ===================== Discovery caching =====================

#[tokio::test]
async fn provider_discovery_is_fetched_once_and_then_reused() {
    // Discovery used to run on every request — twice per sign-in — which cost two round-trips, made
    // sign-in fail whenever the provider's endpoint was briefly slow, and let an unauthenticated caller
    // aim a flood of outbound requests at the provider by looping on /login.
    let fx = Fx::new(true).await;
    assert_eq!(fx.idp.discovery_hits.load(Ordering::SeqCst), 0, "nothing fetched yet");

    let res = fx.login_with(Recipe::valid("alice")).await;
    assert_eq!(res.status, StatusCode::SEE_OTHER, "{}", res.body);
    let after_first = fx.idp.discovery_hits.load(Ordering::SeqCst);
    assert_eq!(after_first, 1, "one sign-in (login + callback) fetches the document once");

    // Several more sign-ins add nothing.
    for _ in 0..3 {
        let _ = fx.login_with(Recipe::valid("alice")).await;
    }
    assert_eq!(
        fx.idp.discovery_hits.load(Ordering::SeqCst),
        after_first,
        "the cached document is reused across sign-ins"
    );
}
