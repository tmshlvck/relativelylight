//! Passkeys, tested by rejection (feature `passkeys`). Each ceremony runs through the shipped routes with
//! a **software authenticator** (`webauthn-authenticator-rs`) in place of the browser, so what's under
//! test is the server: challenges, verification, the class policy, the lockout, re-authentication.
//!
//! Two limits of the software authenticators shape a few tests (see `docs/DESIGN.md` → auth): they
//! answer only when the request names a credential, so a username-less sign-in gets the credential put
//! into its options here; and they always report device-bound, so a synced registration is made by
//! rewriting the response, and a sign-in with a synced passkey by editing the stored row. They also
//! can't store a discoverable credential, which the server asks for, so the tests relax that one hint
//! ([`soft`]) before handing a registration to them.

use super::passkey::{self, Class, Passkeys};
use super::*;
use crate::auth::lockout::Lockout;
use axum::body::Body;
use axum::http::{header, Request};
use sea_orm::Database;
use tower::ServiceExt;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_authenticator_rs::softtoken::{SoftToken, AAGUID};
use webauthn_authenticator_rs::{AuthenticatorBackend, WebauthnAuthenticator};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse, Url};
use webauthn_rs_proto::AllowCredentials;

const PW: &str = "correct-horse-battery-staple";
const CSRF: &str = "5cbf19b46ff34d0a8de0dcbe12b6b7e2c0c1a5f4b3e2d1c0b9a8978685746352";
const ORIGIN: &str = "http://localhost:3000";

fn origin() -> Url {
    Url::parse(ORIGIN).unwrap()
}

struct Fx {
    db: DatabaseConnection,
    auth: Auth,
    app: Router,
}

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn session(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|c| {
                let v = c.strip_prefix(&format!("{name}="))?.split(';').next()?;
                (!v.is_empty()).then(|| v.to_string())
            })
    }

    fn location(&self) -> Option<&str> {
        self.headers.get(header::LOCATION)?.to_str().ok()
    }

    /// The passkey ceremony the page asks for: its challenge id and its options (JSON).
    fn ask(&self) -> (String, String) {
        let b = &self.body;
        let c = b
            .find(r#"name="passkey_challenge" value=""#)
            .unwrap_or_else(|| panic!("no challenge: {b}"));
        let rest = &b[c + r#"name="passkey_challenge" value=""#.len()..];
        let challenge = rest[..rest.find('"').unwrap()].to_string();
        let tag = "data-rl-passkey-options>";
        let o = b.find(tag).expect("no options") + tag.len();
        let options = b[o..o + b[o..].find("</script>").unwrap()].to_string();
        (challenge, options)
    }
}

impl Fx {
    async fn new() -> Fx {
        Fx::with(Lockout::default(), |p| p).await
    }

    async fn with(lockout: Lockout, cfg: impl FnOnce(Passkeys) -> Passkeys) -> Fx {
        Fx::build(lockout, Some(cfg(Passkeys::new("localhost", ORIGIN)))).await
    }

    async fn build(lockout: Lockout, passkeys: Option<Passkeys>) -> Fx {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        migrate(&db).await.unwrap();
        let mut auth = Auth::new(db.clone(), lockout).secure_cookies(false);
        if let Some(p) = passkeys {
            auth = auth.passkeys(p);
        }
        let app = auth.routes().layer(axum::middleware::from_fn_with_state(
            crate::middleware::TrustProxy(false),
            crate::middleware::resolve_real_ip,
        ));
        Fx { db, auth, app }
    }

    async fn user(&self, name: &str) -> user::Model {
        create_user(&self.db, name, PW).await.unwrap();
        self.row(name).await
    }

    async fn row(&self, name: &str) -> user::Model {
        user::Entity::find()
            .filter(user::Column::Username.eq(name))
            .one(&self.db)
            .await
            .unwrap()
            .unwrap()
    }

    async fn cookie_for(&self, name: &str) -> String {
        let id = self.row(name).await.id;
        let token = create_session(&self.auth.inner, id, false, session::Method::Password)
            .await
            .unwrap();
        format!("{}={token}", self.auth.session_cookie_name())
    }

    async fn send(&self, mut req: Request<Body>) -> Resp {
        let addr: std::net::SocketAddr = "192.0.2.7:9".parse().unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));
        let res = self.app.clone().oneshot(req).await.unwrap();
        let (status, headers) = (res.status(), res.headers().clone());
        let body = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        Resp {
            status,
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
        }
    }

    /// A browser's post of one of our forms: the CSRF field and cookie, and `cookie` if given.
    async fn post(&self, path: &str, pairs: &[(&str, &str)], cookie: Option<&str>) -> Resp {
        let mut body: Vec<String> = pairs
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect();
        body.push(format!("_csrf={CSRF}"));
        let csrf = format!("{}={CSRF}", self.auth.csrf().cookie());
        let cookie = match cookie {
            Some(c) => format!("{c}; {csrf}"),
            None => csrf,
        };
        let req = Request::post(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, cookie)
            .body(Body::from(body.join("&")))
            .unwrap();
        self.send(req).await
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> Resp {
        let mut req = Request::get(path);
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        self.send(req.body(Body::empty()).unwrap()).await
    }

    async fn identify(&self, token: &str) -> Option<Identity> {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("{}={token}", self.auth.session_cookie_name())
                .parse()
                .unwrap(),
        );
        self.auth.identify(&h).await
    }

    async fn keys(&self) -> Vec<passkey::entity::Model> {
        passkey::entity::Entity::find().all(&self.db).await.unwrap()
    }

    async fn challenges(&self) -> usize {
        passkey::challenge::Entity::find()
            .all(&self.db)
            .await
            .unwrap()
            .len()
    }

    /// Add a passkey to `cookie`'s account through the profile, confirming with the password. Returns
    /// the finishing response.
    async fn enrol(&self, cookie: &str, auth: &mut impl AuthenticatorBackend, label: &str) -> Resp {
        let page = self
            .post(
                "/profile/passkeys",
                &[("name", label), ("current_password", PW)],
                Some(cookie),
            )
            .await;
        assert_eq!(
            page.status,
            StatusCode::OK,
            "the ceremony page: {}",
            page.body
        );
        let (challenge, options) = page.ask();
        let reg = auth
            .do_registration(origin(), soft(&options))
            .expect("the authenticator registers");
        let answer = serde_json::to_string(&reg).unwrap();
        self.post(
            "/profile/passkeys/finish",
            &[
                ("passkey_challenge", &challenge),
                ("passkey_response", &answer),
                ("name", label),
            ],
            Some(cookie),
        )
        .await
    }

    /// Answer the passkey challenge on `page` with `auth`, naming `cred` (the soft authenticators can't
    /// discover one). Returns `(challenge, answer)`.
    fn answer(
        &self,
        page: &Resp,
        auth: &mut impl AuthenticatorBackend,
        cred: &str,
    ) -> (String, String) {
        let (challenge, options) = page.ask();
        let mut rcr: RequestChallengeResponse = serde_json::from_str(&options).unwrap();
        if rcr.public_key.allow_credentials.is_empty() {
            let id = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(cred)
                .unwrap();
            rcr.public_key.allow_credentials = vec![AllowCredentials {
                type_: "public-key".into(),
                id,
                transports: None,
            }];
        }
        let asrt = auth
            .do_authentication(origin(), rcr)
            .expect("the authenticator answers");
        (challenge, serde_json::to_string(&asrt).unwrap())
    }

    /// A full username-less sign-in with `auth`'s passkey `cred`.
    async fn sign_in(&self, auth: &mut impl AuthenticatorBackend, cred: &str) -> Resp {
        let page = self.post("/login/passkey", &[], None).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let (challenge, answer) = self.answer(&page, auth, cred);
        self.post(
            "/login/passkey/finish",
            &[
                ("passkey_challenge", &challenge),
                ("passkey_response", &answer),
            ],
            None,
        )
        .await
    }

    async fn set_class(&self, class: Class) {
        for k in self.keys().await {
            let mut am: passkey::entity::ActiveModel = k.into();
            am.class = Set(class.as_str().into());
            am.update(&self.db).await.unwrap();
        }
    }
}

use base64::Engine as _;

/// Registration options for a software authenticator: the server's, with the discoverable-credential
/// requirement relaxed (they can't store one). Everything the server verifies is unchanged.
fn soft(options: &str) -> CreationChallengeResponse {
    let mut ccr: CreationChallengeResponse = serde_json::from_str(options).unwrap();
    if let Some(sel) = ccr.public_key.authenticator_selection.as_mut() {
        sel.resident_key = Some(webauthn_rs_proto::ResidentKeyRequirement::Discouraged);
        sel.require_resident_key = false;
    }
    ccr
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

// ===================== Enrolment =====================

#[tokio::test]
async fn a_passkey_is_added_and_then_signs_in_alone() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let cookie = fx.cookie_for("alice").await;
    let mut key = SoftPasskey::new(true);

    let res = fx.enrol(&cookie, &mut key, "laptop").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(res.body.contains("Passkey “laptop” added"), "{}", res.body);
    let row = &fx.keys().await[0];
    assert_eq!(
        (row.name.as_str(), row.class()),
        ("laptop", Class::DeviceBound)
    );
    assert!(
        fx.row("alice").await.passkey_handle.is_some(),
        "the account got its user handle"
    );
    let left = passkey::challenge::Entity::find()
        .all(&fx.db)
        .await
        .unwrap();
    assert!(
        left.iter().all(|c| c.purpose != "register"),
        "the registration challenge was spent"
    );
    assert!(
        left.iter().all(|c| c.purpose == "reauth"),
        "only the new page's re-auth challenge is left"
    );

    // Positive control for everything below: a username-less sign-in, the session saying how.
    let res = fx.sign_in(&mut key, &row.credential_id).await;
    assert_eq!(res.location(), Some("/"), "{} {}", res.status, res.body);
    let token = res
        .session(fx.auth.session_cookie_name())
        .expect("a session");
    assert_eq!(
        fx.identify(&token).await.map(|w| w.username),
        Some("alice".into())
    );
    let s = session::Entity::find_by_id(token)
        .one(&fx.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (s.method(), s.passkey_class()),
        (Some(session::Method::Passkey), Some(Class::DeviceBound))
    );
    let used = &fx.keys().await[0];
    assert!(used.last_used_at.is_some());
    assert_ne!(
        used.credential, row.credential,
        "the signature counter is stored"
    );
}

#[tokio::test]
async fn adding_a_passkey_needs_a_session_csrf_and_reauthentication() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    let cookie = fx.cookie_for("alice").await;

    let res = fx
        .post("/profile/passkeys", &[("name", "x")], Some(&cookie))
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "no factor");
    let res = fx
        .post(
            "/profile/passkeys",
            &[("current_password", "wrong")],
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "a wrong password");
    let req = Request::post("/profile/passkeys")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, &cookie)
        .body(Body::from(format!("current_password={PW}")))
        .unwrap();
    assert_eq!(
        fx.send(req).await.status,
        StatusCode::FORBIDDEN,
        "no CSRF token"
    );
    assert!(fx
        .post("/profile/passkeys", &[("current_password", PW)], None)
        .await
        .status
        .is_redirection());
    assert_eq!(
        fx.challenges().await,
        0,
        "none of those created a challenge"
    );

    // Control: the password opens the ceremony — asking for a discoverable credential, since a passkey
    // here signs in without a username (the library's own default discourages one).
    let res = fx
        .post(
            "/profile/passkeys",
            &[("current_password", PW)],
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(fx.challenges().await, 1);
    let (_, options) = res.ask();
    let o: serde_json::Value = serde_json::from_str(&options).unwrap();
    let sel = &o["publicKey"]["authenticatorSelection"];
    assert_eq!(
        (
            sel["residentKey"].as_str(),
            sel["requireResidentKey"].as_bool()
        ),
        (Some("required"), Some(true)),
        "{o}"
    );
    assert_eq!(
        sel["userVerification"].as_str(),
        Some("required"),
        "a passkey verifies the user itself"
    );
}

#[tokio::test]
async fn a_registration_answer_works_once_and_only_for_its_account() {
    let fx = Fx::new().await;
    fx.user("alice").await;
    fx.user("bob").await;
    let alice = fx.cookie_for("alice").await;
    let bob = fx.cookie_for("bob").await;
    let mut key = SoftPasskey::new(true);

    let page = fx
        .post(
            "/profile/passkeys",
            &[("current_password", PW)],
            Some(&alice),
        )
        .await;
    let (challenge, options) = page.ask();
    let reg = key.do_registration(origin(), soft(&options)).unwrap();
    let answer = serde_json::to_string(&reg).unwrap();
    let post = |cookie: String| {
        let (c, a) = (challenge.clone(), answer.clone());
        let fx = &fx;
        async move {
            fx.post(
                "/profile/passkeys/finish",
                &[("passkey_challenge", &c), ("passkey_response", &a)],
                Some(&cookie),
            )
            .await
        }
    };
    let res = post(bob).await;
    assert_eq!(
        res.status,
        StatusCode::BAD_REQUEST,
        "alice's challenge, posted by bob"
    );
    assert!(fx.keys().await.is_empty());
    // Taking it for bob spent it: the real owner must start again. A challenge is single-use.
    let res = post(alice.clone()).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "already taken");
    assert!(fx.keys().await.is_empty());
}

/// Make a soft authenticator's registration look like a synced passkey: backup-eligible and backed up,
/// with the attestation format `none` (a synced passkey never attests).
fn as_synced(reg: &mut webauthn_rs::prelude::RegisterPublicKeyCredential) {
    use serde_cbor_2::Value;
    let raw: &[u8] = reg.response.attestation_object.as_ref();
    let mut v: Value = serde_cbor_2::from_slice(raw).unwrap();
    if let Value::Map(m) = &mut v {
        for (k, val) in m.iter_mut() {
            match (k, val) {
                (Value::Text(k), Value::Bytes(ad)) if k == "authData" => ad[32] |= 0x18,
                (Value::Text(k), val @ Value::Text(_)) if k == "fmt" => {
                    *val = Value::Text("none".into())
                }
                (Value::Text(k), val @ Value::Map(_)) if k == "attStmt" => {
                    *val = Value::Map(Default::default())
                }
                _ => {}
            }
        }
    }
    reg.response.attestation_object = serde_cbor_2::to_vec(&v).unwrap();
}

async fn enrol_synced(fx: &Fx, cookie: &str) -> Resp {
    let mut key = SoftPasskey::new(true);
    let page = fx
        .post(
            "/profile/passkeys",
            &[("current_password", PW)],
            Some(cookie),
        )
        .await;
    let (challenge, options) = page.ask();
    let mut reg = key.do_registration(origin(), soft(&options)).unwrap();
    as_synced(&mut reg);
    let answer = serde_json::to_string(&reg).unwrap();
    fx.post(
        "/profile/passkeys/finish",
        &[
            ("passkey_challenge", &challenge),
            ("passkey_response", &answer),
        ],
        Some(cookie),
    )
    .await
}

#[tokio::test]
async fn a_device_bound_policy_refuses_a_synced_passkey() {
    // Control: with the default policy a synced passkey is accepted, and classed as synced.
    let fx = Fx::new().await;
    fx.user("alice").await;
    let res = enrol_synced(&fx, &fx.cookie_for("alice").await).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert_eq!(fx.keys().await[0].class(), Class::Synced);

    let fx = Fx::with(Lockout::default(), |p| p.require(Class::DeviceBound)).await;
    fx.user("alice").await;
    let res = enrol_synced(&fx, &fx.cookie_for("alice").await).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(res.body.contains("syncs between devices"), "{}", res.body);
    assert!(fx.keys().await.is_empty(), "nothing stored");
}

fn ca_pem(ca: &crypto_glue::x509::Certificate) -> Vec<u8> {
    use crypto_glue::traits::{EncodePem, LineEndingPem};
    ca.to_pem(LineEndingPem::LF).unwrap().into_bytes()
}

#[tokio::test]
async fn an_attested_policy_takes_only_a_trusted_model() {
    let (mut token, ca) = SoftToken::new(true).unwrap();
    let pem = ca_pem(&ca);
    let fx = Fx::with(Lockout::default(), |p| {
        p.require(Class::Attested)
            .attestation_ca(&pem, &AAGUID.to_string(), "soft token")
    })
    .await;
    fx.user("alice").await;
    let cookie = fx.cookie_for("alice").await;

    // A token attested by another CA is refused…
    let (mut stranger, _) = SoftToken::new(true).unwrap();
    let res = fx.enrol(&cookie, &mut stranger, "other").await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.body);
    assert!(fx.keys().await.is_empty());

    // …and the trusted one is stored as attested, with its model, and signs in.
    let res = fx.enrol(&cookie, &mut token, "yubikey").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    let row = fx.keys().await.remove(0);
    assert_eq!(row.class(), Class::Attested);
    assert_eq!(row.aaguid.as_deref(), Some(AAGUID.to_string().as_str()));
    let res = fx.sign_in(&mut token, &row.credential_id).await;
    assert_eq!(res.location(), Some("/"), "{} {}", res.status, res.body);
}

#[test]
#[should_panic(expected = "needs at least one attestation_ca")]
fn an_attested_policy_without_a_ca_is_a_startup_error() {
    let db = sea_orm::DatabaseConnection::default();
    let _ = Auth::new(db, Lockout::default())
        .passkeys(Passkeys::new("localhost", ORIGIN).require(Class::Attested));
}

// ===================== Sign-in =====================

async fn alice_with_key(fx: &Fx) -> (SoftPasskey, String) {
    fx.user("alice").await;
    let cookie = fx.cookie_for("alice").await;
    let mut key = SoftPasskey::new(true);
    assert_eq!(
        fx.enrol(&cookie, &mut key, "k").await.status,
        StatusCode::OK
    );
    let cred = fx.keys().await[0].credential_id.clone();
    (key, cred)
}

#[tokio::test]
async fn an_unusable_passkey_signs_nobody_in() {
    let fx = Fx::new().await;
    let (mut key, cred) = alice_with_key(&fx).await;
    let ip_failures = |fx: &Fx| {
        let db = fx.db.clone();
        async move {
            lockout::ip_entity::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .first()
                .map(|r| r.failures)
                .unwrap_or(0)
        }
    };

    // A stranger's passkey: a valid signature over a credential this site doesn't know.
    let mut stranger = SoftPasskey::new(true);
    let mut other = fx_with_key_elsewhere(&mut stranger).await;
    let res = fx.sign_in(&mut stranger, &other.remove(0)).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.body);
    assert!(res.session(fx.auth.session_cookie_name()).is_none());
    assert_eq!(ip_failures(&fx).await, 1, "counted against the address");

    // A garbled answer.
    let page = fx.post("/login/passkey", &[], None).await;
    let (challenge, _) = page.ask();
    let res = fx
        .post(
            "/login/passkey/finish",
            &[
                ("passkey_challenge", &challenge),
                ("passkey_response", "{}"),
            ],
            None,
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(ip_failures(&fx).await, 2);

    // An unknown or spent challenge checks nothing and counts nothing.
    let res = fx
        .post(
            "/login/passkey/finish",
            &[("passkey_challenge", "nope"), ("passkey_response", "{}")],
            None,
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(ip_failures(&fx).await, 2);

    // A deactivated owner.
    let mut am: user::ActiveModel = fx.row("alice").await.into();
    am.is_active = Set(false);
    am.update(&fx.db).await.unwrap();
    let res = fx.sign_in(&mut key, &cred).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.body);
}

/// A passkey registered at another site with the same origin, so its signatures are good but the
/// credential is unknown here. Returns its credential ids.
async fn fx_with_key_elsewhere(key: &mut SoftPasskey) -> Vec<String> {
    let other = Fx::new().await;
    other.user("mallory").await;
    let cookie = other.cookie_for("mallory").await;
    assert_eq!(other.enrol(&cookie, key, "m").await.status, StatusCode::OK);
    other
        .keys()
        .await
        .into_iter()
        .map(|k| k.credential_id)
        .collect()
}

#[tokio::test]
async fn a_sign_in_answer_works_once() {
    let fx = Fx::new().await;
    let (mut key, cred) = alice_with_key(&fx).await;
    let page = fx.post("/login/passkey", &[], None).await;
    let (challenge, answer) = fx.answer(&page, &mut key, &cred);
    let fields = [
        ("passkey_challenge", challenge.as_str()),
        ("passkey_response", answer.as_str()),
    ];
    let first = fx.post("/login/passkey/finish", &fields, None).await;
    assert_eq!(
        first.location(),
        Some("/"),
        "control: the first submission signs in"
    );
    let again = fx.post("/login/passkey/finish", &fields, None).await;
    assert_eq!(
        again.status,
        StatusCode::BAD_REQUEST,
        "a replay finds no challenge"
    );
    assert!(again.session(fx.auth.session_cookie_name()).is_none());
}

#[tokio::test]
async fn a_locked_address_gets_no_challenge_and_no_sign_in() {
    let fx = Fx::with(Lockout::default().addresses(2, 900), |p| p).await;
    let (mut key, cred) = alice_with_key(&fx).await;
    let page = fx.post("/login/passkey", &[], None).await;
    let (challenge, answer) = fx.answer(&page, &mut key, &cred);
    for _ in 0..2 {
        let p = fx.post("/login/passkey", &[], None).await;
        let (c, _) = p.ask();
        fx.post(
            "/login/passkey/finish",
            &[("passkey_challenge", &c), ("passkey_response", "{}")],
            None,
        )
        .await;
    }
    let before = fx.challenges().await;
    assert_eq!(
        fx.post("/login/passkey", &[], None).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        fx.challenges().await,
        before,
        "a locked address writes no challenge"
    );
    let res = fx
        .post(
            "/login/passkey/finish",
            &[
                ("passkey_challenge", &challenge),
                ("passkey_response", &answer),
            ],
            None,
        )
        .await;
    assert_eq!(
        res.status,
        StatusCode::TOO_MANY_REQUESTS,
        "even a good answer waits"
    );
}

#[tokio::test]
async fn a_stricter_policy_refuses_a_weaker_passkey_and_its_sessions() {
    let fx = Fx::with(Lockout::default(), |p| p.require(Class::DeviceBound)).await;
    let (mut key, cred) = alice_with_key(&fx).await;
    let res = fx.sign_in(&mut key, &cred).await;
    let token = res
        .session(fx.auth.session_cookie_name())
        .expect("control: signed in");
    assert!(fx.identify(&token).await.is_some());

    // The stored class drops below the policy (what a synced passkey, or a stricter policy, looks like).
    fx.set_class(Class::Synced).await;
    let mut am: session::ActiveModel = session::Entity::find_by_id(token.clone())
        .one(&fx.db)
        .await
        .unwrap()
        .unwrap()
        .into();
    am.passkey_class = Set(Some("synced".into()));
    am.update(&fx.db).await.unwrap();
    assert!(
        fx.identify(&token).await.is_none(),
        "the open session no longer counts"
    );
    let res = fx.sign_in(&mut key, &cred).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.body);
}

#[tokio::test]
async fn a_passkey_then_totp_when_the_account_has_totp() {
    let fx = Fx::new().await;
    let (mut key, cred) = alice_with_key(&fx).await;
    let secret = totp::generate_secret();
    let mut am: user::ActiveModel = fx.row("alice").await.into();
    am.totp_secret = Set(Some(secret.clone()));
    am.update(&fx.db).await.unwrap();

    let res = fx.sign_in(&mut key, &cred).await;
    assert_eq!(
        res.location(),
        Some("/login/totp"),
        "the passkey is the first step only"
    );
    let pending = res.session(fx.auth.session_cookie_name()).unwrap();
    assert!(fx.identify(&pending).await.is_none(), "half-authenticated");
    let cookie = format!("{}={pending}", fx.auth.session_cookie_name());
    let page = fx.get("/login/totp", Some(&cookie)).await;
    assert!(
        !page.body.contains("passkey_challenge"),
        "a passkey can't be its own second factor"
    );

    let res = fx
        .post(
            "/login/totp",
            &[("code", &totp::current_code(&secret))],
            Some(&cookie),
        )
        .await;
    let full = res.session(fx.auth.session_cookie_name()).expect("rotated");
    let s = session::Entity::find_by_id(full.clone())
        .one(&fx.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.method(), Some(session::Method::PasskeyTotp));
    assert_eq!(
        s.passkey_class(),
        Some(Class::DeviceBound),
        "the class carries over"
    );
    assert!(fx.identify(&full).await.is_some());
}

#[tokio::test]
async fn a_passkey_is_a_second_factor_only_when_enabled() {
    // Off (the default): the password alone signs in, as it always has.
    let fx = Fx::new().await;
    alice_with_key(&fx).await;
    let res = fx
        .post("/login", &[("username", "alice"), ("password", PW)], None)
        .await;
    assert_eq!(res.location(), Some("/"));

    // On: the password leads to the passkey step.
    let fx = Fx::with(Lockout::default().accounts(2, 900), |p| {
        p.second_factor(true)
    })
    .await;
    let (mut key, cred) = alice_with_key(&fx).await;
    let res = fx
        .post("/login", &[("username", "alice"), ("password", PW)], None)
        .await;
    assert_eq!(res.location(), Some("/login/totp"));
    let pending = res.session(fx.auth.session_cookie_name()).unwrap();
    let cookie = format!("{}={pending}", fx.auth.session_cookie_name());
    assert!(fx.identify(&pending).await.is_none());

    // A wrong answer is a failed check against the account.
    let page = fx.get("/login/totp", Some(&cookie)).await;
    let (challenge, _) = page.ask();
    let res = fx
        .post(
            "/login/totp/passkey",
            &[
                ("passkey_challenge", &challenge),
                ("passkey_response", "{}"),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    let row = lockout::username_entity::Entity::find_by_id("alice".to_string())
        .one(&fx.db)
        .await
        .unwrap();
    assert_eq!(row.map(|r| r.failures), Some(1));

    // An expired or unknown challenge checks nothing, so it counts nothing.
    let page = fx.get("/login/totp", Some(&cookie)).await;
    let (_, answer) = fx.answer(&page, &mut key, &cred);
    let fields = [("passkey_challenge", "gone"), ("passkey_response", answer.as_str())];
    let res = fx.post("/login/totp/passkey", &fields, Some(&cookie)).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    let row = lockout::username_entity::Entity::find_by_id("alice".to_string()).one(&fx.db).await.unwrap();
    assert_eq!(row.map(|r| r.failures), Some(1), "still one");

    // Control: the passkey finishes it.
    let page = fx.get("/login/totp", Some(&cookie)).await;
    let (challenge, answer) = fx.answer(&page, &mut key, &cred);
    let res = fx
        .post(
            "/login/totp/passkey",
            &[
                ("passkey_challenge", &challenge),
                ("passkey_response", &answer),
            ],
            Some(&cookie),
        )
        .await;
    let full = res.session(fx.auth.session_cookie_name()).expect("rotated");
    let s = session::Entity::find_by_id(full.clone())
        .one(&fx.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.method(), Some(session::Method::PasswordPasskey));
    assert!(fx.identify(&full).await.is_some());
}

// ===================== The password, and re-authentication =====================

/// Remove alice's password through the profile, confirming with the passkey.
async fn go_passwordless(fx: &Fx, key: &mut SoftPasskey, cred: &str, cookie: &str) -> Resp {
    let page = fx.get("/profile", Some(cookie)).await;
    let (challenge, answer) = fx.answer(&page, key, cred);
    fx.post(
        "/profile/password/remove",
        &[
            ("passkey_challenge", &challenge),
            ("passkey_response", &answer),
        ],
        Some(cookie),
    )
    .await
}

#[tokio::test]
async fn the_password_goes_only_with_a_passkey_and_a_confirmation() {
    let fx = Fx::new().await;
    fx.user("bob").await;
    let bob = fx.cookie_for("bob").await;
    let res = fx
        .post(
            "/profile/password/remove",
            &[("current_password", PW)],
            Some(&bob),
        )
        .await;
    assert_eq!(res.status, StatusCode::CONFLICT, "no passkey, no removal");

    let (mut key, cred) = alice_with_key(&fx).await;
    let alice = fx.cookie_for("alice").await;
    let res = fx.post("/profile/password/remove", &[], Some(&alice)).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "not confirmed");
    assert!(!fx.row("alice").await.password_hash.is_empty());

    let res = go_passwordless(&fx, &mut key, &cred, &alice).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(fx.row("alice").await.password_hash.is_empty());
    let res = fx
        .post("/login", &[("username", "alice"), ("password", PW)], None)
        .await;
    assert_eq!(
        res.status,
        StatusCode::UNAUTHORIZED,
        "the old password is gone"
    );
    assert_eq!(
        fx.sign_in(&mut key, &cred).await.location(),
        Some("/"),
        "the passkey still signs in"
    );
}

#[tokio::test]
async fn a_passwordless_account_keeps_a_way_in_and_must_confirm_with_its_passkey() {
    let fx = Fx::new().await;
    let (mut key, cred) = alice_with_key(&fx).await;
    let cookie = fx.cookie_for("alice").await;
    let res = go_passwordless(&fx, &mut key, &cred, &cookie).await;
    let cookie = format!(
        "{}={}",
        fx.auth.session_cookie_name(),
        res.session(fx.auth.session_cookie_name())
            .expect("resessioned")
    );

    // The last passkey of an account with no password can't go.
    let id = fx.keys().await[0].id;
    let res = fx
        .post(
            &format!("/profile/passkeys/{id}/remove"),
            &[],
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    assert_eq!(fx.keys().await.len(), 1);

    // Re-authentication no longer passes with nothing (it did, for an account with no password).
    let res = fx
        .post("/profile/sessions/revoke", &[], Some(&cookie))
        .await;
    assert_eq!(
        res.status,
        StatusCode::OK,
        "control: an unconfirmed action still works"
    );
    let who = fx
        .auth
        .identify(&{
            let mut h = HeaderMap::new();
            h.insert(header::COOKIE, cookie.parse().unwrap());
            h
        })
        .await
        .unwrap();
    assert!(
        fx.auth.reauthenticate(&who, "", "").await.is_err(),
        "nothing is not a factor"
    );
    assert!(
        fx.auth.reauthenticate(&who, PW, "").await.is_err(),
        "nor is a password it doesn't have"
    );
    let fields = fx.auth.reauth_fields(&who, "Confirm").await;
    assert!(
        fields.contains("data-rl-passkey") && !fields.contains("current_password"),
        "{fields}"
    );

    // Setting a password needs the passkey; then the last passkey may go.
    let page = fx.get("/profile", Some(&cookie)).await;
    let (challenge, answer) = fx.answer(&page, &mut key, &cred);
    let new_pw = "trombone-hedgehog-marmalade";
    let res = fx
        .post(
            "/profile",
            &[
                ("new_password", new_pw),
                ("confirm_password", new_pw),
                ("passkey_challenge", &challenge),
                ("passkey_response", &answer),
            ],
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(verify_password(
        &fx.row("alice").await.password_hash,
        new_pw
    ));
    let cookie = format!(
        "{}={}",
        fx.auth.session_cookie_name(),
        res.session(fx.auth.session_cookie_name())
            .expect("resessioned")
    );
    let res = fx
        .post(
            &format!("/profile/passkeys/{id}/remove"),
            &[],
            Some(&cookie),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(fx.keys().await.is_empty());
}

#[tokio::test]
async fn a_passkey_confirms_a_sensitive_action_for_its_own_account_only() {
    let fx = Fx::new().await;
    let (mut key, cred) = alice_with_key(&fx).await;
    fx.user("bob").await;
    let alice = fx.cookie_for("alice").await;
    let bob = fx.cookie_for("bob").await;
    // Bob has no passkey, so a challenge rendered for alice is all there is to try.
    let page = fx.get("/profile", Some(&alice)).await;
    let (challenge, answer) = fx.answer(&page, &mut key, &cred);
    let res = fx.post("/profile/api-keys", &[], Some(&bob)).await;
    assert!(
        res.status.is_client_error(),
        "api keys are off here; any refusal will do"
    );
    let res = fx
        .post(
            "/profile/password/remove",
            &[
                ("passkey_challenge", &challenge),
                ("passkey_response", &answer),
            ],
            Some(&bob),
        )
        .await;
    assert_ne!(
        res.status,
        StatusCode::OK,
        "bob can't use alice's confirmation"
    );
    assert!(!fx.row("bob").await.password_hash.is_empty());

    // The app-facing pair, with a passkey: control first, then a garbled answer.
    let who = Identity::new(fx.row("alice").await.id.to_string(), "alice", vec![]);
    let fields = fx.auth.reauth_fields(&who, "Confirm").await;
    let page = Resp {
        status: StatusCode::OK,
        headers: HeaderMap::new(),
        body: fields,
    };
    let (challenge, answer) = fx.answer(&page, &mut key, &cred);
    let mut proof = ReauthInput {
        passkey_challenge: challenge,
        passkey_response: answer,
        ..ReauthInput::default()
    };
    assert!(fx.auth.reauthenticate_with(&who, &proof).await.is_ok());
    assert!(
        fx.auth.reauthenticate_with(&who, &proof).await.is_err(),
        "spent"
    );
    proof.passkey_response = "{}".into();
    assert!(fx.auth.reauthenticate_with(&who, &proof).await.is_err());
}

// ===================== Managers, audit, switching it off =====================

#[tokio::test]
async fn a_manager_removes_someones_passkeys_with_their_own_confirmation() {
    let fx = Fx::new().await;
    let (_key, _cred) = alice_with_key(&fx).await;
    let alice_id = fx.row("alice").await.id;
    fx.user("mallory").await;
    create_user(&fx.db, "root", PW).await.unwrap();
    add_to_group(&fx.db, "root", "admin").await.unwrap();
    let path = format!("/profile/{alice_id}/passkeys/remove");

    let res = fx
        .post(
            &path,
            &[("current_password", PW)],
            Some(&fx.cookie_for("mallory").await),
        )
        .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "not a manager");
    let root = fx.cookie_for("root").await;
    let res = fx.post(&path, &[], Some(&root)).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "not confirmed");
    assert_eq!(fx.keys().await.len(), 1);

    let res = fx
        .post(&path, &[("current_password", PW)], Some(&root))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.body);
    assert!(fx.keys().await.is_empty());
}

#[derive(Default)]
struct Seen(std::sync::Mutex<Vec<String>>);

#[async_trait::async_trait]
impl crate::observe::WriteObserver for Seen {
    async fn on_write(&self, ev: &crate::observe::WriteEvent<'_>) {
        let line = format!("{:?} {} {:?} {:?}", ev.op, ev.entity, ev.before, ev.after);
        self.0.lock().unwrap().push(line);
    }
}

#[tokio::test]
async fn adding_and_removing_a_passkey_are_audited_without_the_credential() {
    let seen = Arc::new(Seen::default());
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migrate(&db).await.unwrap();
    let auth = Auth::new(db.clone(), Lockout::default())
        .secure_cookies(false)
        .on_write(seen.clone())
        .passkeys(Passkeys::new("localhost", ORIGIN));
    let app = auth.routes().layer(axum::middleware::from_fn_with_state(
        crate::middleware::TrustProxy(false),
        crate::middleware::resolve_real_ip,
    ));
    let fx = Fx { db, auth, app };
    fx.user("alice").await;
    let cookie = fx.cookie_for("alice").await;
    let mut key = SoftPasskey::new(true);
    fx.enrol(&cookie, &mut key, "laptop").await;
    fx.enrol(&cookie, &mut SoftPasskey::new(true), "phone")
        .await;
    let row = fx.keys().await.remove(0);
    fx.post(
        &format!("/profile/passkeys/{}/remove", row.id),
        &[],
        Some(&cookie),
    )
    .await;

    let lines = seen.0.lock().unwrap().clone();
    let ours: Vec<_> = lines
        .iter()
        .filter(|l| l.contains("auth_passkey"))
        .collect();
    assert_eq!(ours.len(), 3, "{lines:?}");
    assert!(
        ours[0].starts_with("Create") && ours[2].starts_with("Delete"),
        "{ours:?}"
    );
    for l in ours {
        assert!(l.contains("device-bound"), "describes the passkey: {l}");
        assert!(
            !l.contains(&row.credential_id) && !l.contains("cred_id"),
            "never the credential: {l}"
        );
    }
}

#[tokio::test]
async fn without_passkeys_there_is_no_button_section_or_route() {
    let fx = Fx::build(Lockout::default(), None).await;
    fx.user("alice").await;
    let cookie = fx.cookie_for("alice").await;
    assert!(!fx.get("/login", None).await.body.contains("/login/passkey"));
    assert!(!fx
        .get("/profile", Some(&cookie))
        .await
        .body
        .contains("Passkeys"));
    assert!(fx
        .post("/login/passkey", &[], None)
        .await
        .status
        .is_client_error());
    assert_eq!(fx.challenges().await, 0);

    // Control: on, they are there.
    let fx = Fx::new().await;
    fx.user("alice").await;
    let cookie = fx.cookie_for("alice").await;
    assert!(fx.get("/login", None).await.body.contains("/login/passkey"));
    assert!(fx
        .get("/profile", Some(&cookie))
        .await
        .body
        .contains("Passkeys"));
    assert_eq!(
        fx.get("/auth/passkey.js", None).await.status,
        StatusCode::OK
    );
}
