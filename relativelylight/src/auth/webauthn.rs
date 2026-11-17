//! **Passkeys**: the configuration, the WebAuthn ceremonies and the routes (feature `passkeys`). See
//! `docs/AUTH.md` §5l and `docs/DESIGN.md` → auth.
//!
//! Every ceremony has the same shape, and it is a posted form, not a JSON API:
//!
//! 1. a handler creates a **challenge row** (`passkey::challenge`) holding the library's state, and
//!    renders the options into the page (`pages::PasskeyAsk`);
//! 2. the script (`assets/rl-passkey.js`, served at `/auth/passkey.js`) runs the browser ceremony,
//!    puts the answer in a hidden field and submits the form;
//! 3. the handler **takes** the row — deleting it, so an answer can't be replayed — and verifies.
//!
//! The row is created only when someone asks: on a click for a sign-in, on rendering a page for a
//! signed-in user. Anonymous page views write nothing.

use super::pages::{self, PasskeyAsk, ReauthView};
use super::{passkey, session, user, Auth, Inner};
use crate::middleware::RealIp;
use axum::extract::{Form, Path, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine as _;
use passkey::{challenge, entity, Class};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use webauthn_rs::prelude::{
    AttestationCaList, AttestationCaListBuilder, AttestationMetadata, AttestedPasskey,
    AttestedPasskeyRegistration, AuthenticationResult, Credential, DiscoverableAuthentication,
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Uuid, Webauthn, WebauthnBuilder,
};
use webauthn_rs_proto::ResidentKeyRequirement;

/// How long a challenge lives: long enough to find a security key in a drawer.
const CHALLENGE_SECS: i64 = 300;

// ===================== Configuration =====================

/// Passkeys for an app, switched on with [`Auth::passkeys`]. The policy is **app-wide**.
///
/// ```ignore
/// use relativelylight::auth::passkey::{Class, Passkeys};
///
/// let auth = Auth::new(db, lockout).passkeys(
///     Passkeys::new("example.com", "https://example.com")
///         .rp_name("Example")
///         .require(Class::DeviceBound),
/// );
/// ```
///
/// `#[non_exhaustive]`: built with [`Passkeys::new`] and the builders.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Passkeys {
    rp_id: String,
    origins: Vec<Url>,
    rp_name: Option<String>,
    require: Class,
    second_factor: bool,
    cas: Vec<(Vec<u8>, Uuid, String)>,
}

impl Passkeys {
    /// Passkeys for the site `rp_id` (the registrable domain: `example.com`, or `localhost`), served
    /// at `origin` (`https://example.com`, with the port if not the default). A credential is bound to
    /// `rp_id` for good, so choose the domain the site will keep.
    ///
    /// # Panics
    ///
    /// If `origin` is not a URL. It is configuration, so a bad one is a startup error.
    pub fn new(rp_id: impl Into<String>, origin: &str) -> Self {
        let origin = Url::parse(origin).unwrap_or_else(|e| {
            panic!("relativelylight: passkey origin {origin:?} is not a URL: {e}")
        });
        Self {
            rp_id: rp_id.into(),
            origins: vec![origin],
            rp_name: None,
            require: Class::Synced,
            second_factor: false,
            cas: Vec::new(),
        }
    }

    /// The site's name, as authenticators show it. Default: the `rp_id`.
    pub fn rp_name(mut self, name: impl Into<String>) -> Self {
        self.rp_name = Some(name.into());
        self
    }

    /// Another origin the site is served from (a second hostname under the same `rp_id`).
    ///
    /// # Panics
    ///
    /// If `origin` is not a URL.
    pub fn origin(mut self, origin: &str) -> Self {
        let url = Url::parse(origin).unwrap_or_else(|e| {
            panic!("relativelylight: passkey origin {origin:?} is not a URL: {e}")
        });
        self.origins.push(url);
        self
    }

    /// The lowest [`Class`] of passkey accepted, at enrolment and at every use. Default
    /// [`Class::Synced`]: any passkey. [`Class::Attested`] needs at least one
    /// [`attestation_ca`](Passkeys::attestation_ca).
    pub fn require(mut self, class: Class) -> Self {
        self.require = class;
        self
    }

    /// Whether a passkey may also be the **second factor** after a password, beside TOTP. Default
    /// `false`: a passkey is a way to sign in on its own, and the password sign-in asks for TOTP only.
    pub fn second_factor(mut self, on: bool) -> Self {
        self.second_factor = on;
        self
    }

    /// Trust authenticators whose attestation chains to this CA (PEM) and report this model
    /// (`aaguid`). Needed for [`Class::Attested`]; `description` names the model in logs.
    ///
    /// # Panics
    ///
    /// If `aaguid` is not a UUID.
    pub fn attestation_ca(mut self, pem: &[u8], aaguid: &str, description: &str) -> Self {
        let aaguid = Uuid::parse_str(aaguid)
            .unwrap_or_else(|e| panic!("relativelylight: AAGUID {aaguid:?} is not a UUID: {e}"));
        self.cas
            .push((pem.to_vec(), aaguid, description.to_string()));
        self
    }
}

/// The configuration, built: what `Inner` holds.
pub(super) struct Runtime {
    wa: Webauthn,
    require: Class,
    second_factor: bool,
    cas: Option<AttestationCaList>,
}

impl Runtime {
    fn build(cfg: Passkeys) -> Self {
        let first = &cfg.origins[0];
        let mut b = WebauthnBuilder::new(&cfg.rp_id, first).unwrap_or_else(|e| {
            panic!(
                "relativelylight: passkeys for {:?} at {first}: {e:?}",
                cfg.rp_id
            )
        });
        for o in &cfg.origins[1..] {
            b = b.append_allowed_origin(o);
        }
        if let Some(name) = &cfg.rp_name {
            b = b.rp_name(name);
        }
        let wa = b
            .build()
            .unwrap_or_else(|e| panic!("relativelylight: passkeys: {e:?}"));
        let cas = match cfg.cas.is_empty() {
            true => None,
            false => {
                let mut list = AttestationCaListBuilder::new();
                for (pem, aaguid, desc) in &cfg.cas {
                    list.insert_device_pem(pem, *aaguid, desc.clone(), Default::default())
                        .unwrap_or_else(|e| {
                            panic!("relativelylight: attestation CA for {desc:?} is not a PEM certificate: {e:?}")
                        });
                }
                Some(list.build())
            }
        };
        assert!(
            cfg.require < Class::Attested || cas.is_some(),
            "relativelylight: Passkeys::require(Class::Attested) needs at least one attestation_ca"
        );
        Self {
            wa,
            require: cfg.require,
            second_factor: cfg.second_factor,
            cas,
        }
    }

    /// Whether a passkey may be the second factor after a password.
    pub(super) fn second_factor(&self) -> bool {
        self.second_factor
    }

    /// The lowest class the policy accepts.
    pub(super) fn require(&self) -> Class {
        self.require
    }
}

impl Auth {
    /// Turn on **passkeys**: the passkeys section on `/profile`, "Sign in with a passkey" on `/login`,
    /// a passkey on every confirm-it's-you form, and (with
    /// [`second_factor`](Passkeys::second_factor)) a passkey after a password. See `docs/AUTH.md` §5l.
    ///
    /// # Panics
    ///
    /// On a configuration that can't work: [`Class::Attested`] with no CA, an unusable origin. Call it
    /// before the `Auth` is cloned, like the other builders.
    pub fn passkeys(mut self, cfg: Passkeys) -> Self {
        Arc::get_mut(&mut self.inner).unwrap().passkeys = Some(Arc::new(Runtime::build(cfg)));
        self
    }
}

// ===================== Stored state =====================

/// What a challenge is for. A row taken for one purpose is refused for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Purpose {
    Register,
    Login,
    SecondFactor,
    Reauth,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Purpose::Register => "register",
            Purpose::Login => "login",
            Purpose::SecondFactor => "second-factor",
            Purpose::Reauth => "reauth",
        }
    }
}

/// A stored credential: the library's own type, which says whether it was attested.
#[derive(Serialize, Deserialize)]
enum Stored {
    Passkey(Passkey),
    Attested(AttestedPasskey),
}

impl Stored {
    fn passkey(&self) -> Passkey {
        match self {
            Stored::Passkey(p) => p.clone(),
            Stored::Attested(a) => Passkey::from(a),
        }
    }

    fn update(&mut self, res: &AuthenticationResult) {
        match self {
            Stored::Passkey(p) => {
                p.update_credential(res);
            }
            Stored::Attested(a) => {
                a.update_credential(res);
            }
        }
    }

    fn json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// A registration in progress.
#[derive(Serialize, Deserialize)]
enum RegState {
    Plain(PasskeyRegistration),
    Attested(AttestedPasskeyRegistration),
}

/// A registration challenge's row: the state, and the WebAuthn user handle it was made with. The handle
/// is saved on the account only when a passkey is added, so rendering the profile writes nothing to it.
#[derive(Serialize, Deserialize)]
struct Registration {
    handle: Uuid,
    state: RegState,
}

/// A credential ID as stored: base64url without padding.
fn cred_id(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Store a ceremony's state; returns the challenge id the page carries.
async fn put(
    inner: &Inner,
    purpose: Purpose,
    user_id: Option<i32>,
    state: &impl Serialize,
) -> Result<String, DbErr> {
    let id = super::new_token();
    challenge::ActiveModel {
        id: Set(id.clone()),
        purpose: Set(purpose.as_str().into()),
        user_id: Set(user_id),
        state: Set(serde_json::to_string(state).unwrap_or_default()),
        expires_at: Set(super::now_secs() + CHALLENGE_SECS),
    }
    .insert(&inner.db)
    .await?;
    Ok(id)
}

/// Take a challenge: it must exist, be for `purpose` and `user_id`, and be unexpired. It is deleted
/// whatever the outcome, and only the request whose delete removed it gets the state — so two
/// submissions of one answer can't both be verified.
async fn take<T: for<'de> Deserialize<'de>>(
    inner: &Inner,
    id: &str,
    purpose: Purpose,
    user_id: Option<i32>,
) -> Option<T> {
    if id.is_empty() {
        return None;
    }
    let row = challenge::Entity::find_by_id(id.to_string())
        .one(&inner.db)
        .await
        .ok()??;
    let gone = challenge::Entity::delete_many()
        .filter(challenge::Column::Id.eq(id))
        .exec(&inner.db)
        .await
        .ok()?
        .rows_affected;
    if gone != 1
        || row.purpose != purpose.as_str()
        || row.user_id != user_id
        || row.expires_at < super::now_secs()
    {
        return None;
    }
    serde_json::from_str(&row.state).ok()
}

/// The options for the browser, made safe to embed, with their challenge id.
fn ask(challenge: String, options: &impl Serialize) -> PasskeyAsk {
    let json = serde_json::to_string(options).unwrap_or_default();
    PasskeyAsk {
        challenge,
        options: pages::script_json(&json),
    }
}

/// A passkey row's credential, parsed.
fn stored(row: &entity::Model) -> Option<Stored> {
    serde_json::from_str(&row.credential).ok()
}

// ===================== Ceremonies =====================

/// Why a user's passkey answer was refused: the message to show, and whether anything was checked
/// (an expired challenge checks nothing, so a lockout must not count it).
pub(super) struct Refusal {
    pub message: String,
    pub checked: bool,
}

impl Refusal {
    fn checked(message: &str) -> Self {
        Self {
            message: message.to_string(),
            checked: true,
        }
    }
}

/// Why a sign-in with a passkey failed — each answered differently.
enum LoginFail {
    /// No usable credential or a bad signature: counted against the address.
    Invalid,
    /// The challenge is gone or expired: nothing was checked.
    Expired,
    /// A real credential the policy no longer accepts.
    Policy,
    /// The database failed.
    Internal(DbErr),
}

impl Runtime {
    /// A challenge for `user` to answer with one of their passkeys, for `purpose`; `None` when they have
    /// none (or it can't be created — the page then simply offers no passkey).
    pub(super) async fn ask_user(
        &self,
        inner: &Inner,
        user: &user::Model,
        purpose: Purpose,
    ) -> Option<PasskeyAsk> {
        let rows = passkey::list(&inner.db, user.id).await.ok()?;
        let creds: Vec<Passkey> = rows
            .iter()
            .filter(|r| r.class() >= self.require)
            .filter_map(stored)
            .map(|s| s.passkey())
            .collect();
        if creds.is_empty() {
            return None;
        }
        let (rcr, state) = self.wa.start_passkey_authentication(&creds).ok()?;
        let id = put(inner, purpose, Some(user.id), &state).await.ok()?;
        Some(ask(id, &rcr))
    }

    /// Verify `user`'s answer to a challenge from [`ask_user`](Runtime::ask_user), and record the use.
    /// `Err` is a message fit to show; nothing is counted here (the caller decides).
    pub(super) async fn verify_user(
        &self,
        inner: &Inner,
        user: &user::Model,
        purpose: Purpose,
        challenge_id: &str,
        response: &str,
    ) -> Result<entity::Model, Refusal> {
        let refused = || Refusal::checked("Your passkey didn't confirm it's you. Try again.");
        let Ok(cred) = serde_json::from_str::<PublicKeyCredential>(response) else {
            return Err(refused());
        };
        let Some(state) =
            take::<PasskeyAuthentication>(inner, challenge_id, purpose, Some(user.id)).await
        else {
            // Nothing was checked: a lockout must not count this.
            let message = "That confirmation expired. Try again.".to_string();
            return Err(Refusal {
                message,
                checked: false,
            });
        };
        let Ok(res) = self.wa.finish_passkey_authentication(&cred, &state) else {
            return Err(refused());
        };
        let row = entity::Entity::find()
            .filter(entity::Column::CredentialId.eq(cred_id(res.cred_id().as_slice())))
            .filter(entity::Column::UserId.eq(user.id))
            .one(&inner.db)
            .await
            .ok()
            .flatten()
            .ok_or_else(refused)?;
        let row = self
            .after_use(inner, row, &res)
            .await
            .map_err(|_| refused())?;
        if row.class() < self.require {
            return Err(Refusal::checked(&policy_message(self.require)));
        }
        Ok(row)
    }

    /// Record a successful use: the counter, the backup flags, and the class — a credential whose
    /// backup-eligible flag has turned on is synced from now on.
    async fn after_use(
        &self,
        inner: &Inner,
        row: entity::Model,
        res: &AuthenticationResult,
    ) -> Result<entity::Model, DbErr> {
        let mut cred = stored(&row).ok_or_else(|| DbErr::Custom("unreadable passkey".into()))?;
        cred.update(res);
        let class = match res.backup_eligible() {
            true => Class::Synced,
            false => row.class(),
        };
        let mut am: entity::ActiveModel = row.into();
        am.credential = Set(cred.json());
        am.backup_eligible = Set(res.backup_eligible());
        am.backup_state = Set(res.backup_state());
        am.class = Set(class.as_str().into());
        am.last_used_at = Set(Some(super::now_secs()));
        am.update(&inner.db).await
    }

    /// Start registering a passkey for `user`: a challenge, with their existing passkeys excluded so an
    /// authenticator can't register twice. An account with no WebAuthn user handle yet gets a new one,
    /// kept in the challenge and saved with the passkey.
    async fn begin_registration(
        &self,
        inner: &Inner,
        user: &user::Model,
    ) -> Result<PasskeyAsk, String> {
        let failed = |_| "Could not start adding a passkey.".to_string();
        let handle = user
            .passkey_handle
            .as_deref()
            .and_then(|h| Uuid::parse_str(h).ok())
            .unwrap_or_else(Uuid::new_v4);
        let exclude: Vec<_> = passkey::list(&inner.db, user.id)
            .await
            .map_err(failed)?
            .iter()
            .filter_map(stored)
            .map(|s| s.passkey().cred_id().clone())
            .collect();
        let name = &user.username;
        let (mut ccr, state) = match (&self.cas, self.require) {
            (Some(cas), Class::Attested) => {
                let (ccr, st) = self
                    .wa
                    .start_attested_passkey_registration(
                        handle,
                        name,
                        name,
                        Some(exclude),
                        cas.clone(),
                        None,
                    )
                    .map_err(|_| "Could not start adding a passkey.".to_string())?;
                (ccr, RegState::Attested(st))
            }
            _ => {
                let (ccr, st) = self
                    .wa
                    .start_passkey_registration(handle, name, name, Some(exclude))
                    .map_err(|_| "Could not start adding a passkey.".to_string())?;
                (ccr, RegState::Plain(st))
            }
        };
        // A **discoverable** credential, or it can't sign in without a username — which is how a passkey
        // signs in here. The library asks authenticators to discourage one (phones and laptops make one
        // anyway; a security key obeys). Verification doesn't depend on this hint, so asking for it in
        // the browser's options is enough.
        if let Some(sel) = ccr.public_key.authenticator_selection.as_mut() {
            sel.resident_key = Some(ResidentKeyRequirement::Required);
            sel.require_resident_key = true;
        }
        let row = Registration { handle, state };
        let id = put(inner, Purpose::Register, Some(user.id), &row)
            .await
            .map_err(failed)?;
        Ok(ask(id, &ccr))
    }

    /// Finish registering: verify, classify, check the policy, store.
    async fn finish_registration(
        &self,
        inner: &Inner,
        user: &user::Model,
        challenge_id: &str,
        response: &str,
        name: &str,
    ) -> Result<entity::Model, String> {
        let refused = "The passkey could not be added. Try again.";
        let Some(Registration { handle, state }) =
            take::<Registration>(inner, challenge_id, Purpose::Register, Some(user.id)).await
        else {
            return Err("Adding the passkey took too long. Reload the page and try again.".into());
        };
        // The account's handle is the one the challenge was made with, or none yet — then it becomes
        // this one. Anything else is a challenge from before another passkey was added.
        let ours = user
            .passkey_handle
            .as_deref()
            .and_then(|h| Uuid::parse_str(h).ok());
        if ours.is_some_and(|h| h != handle) {
            return Err("Adding the passkey took too long. Reload the page and try again.".into());
        }
        let Ok(reg) = serde_json::from_str::<RegisterPublicKeyCredential>(response) else {
            return Err(refused.into());
        };
        let (cred, stored, class, aaguid) = match state {
            RegState::Plain(st) => {
                let pk = self
                    .wa
                    .finish_passkey_registration(&reg, &st)
                    .map_err(|_| refused.to_string())?;
                let c: Credential = pk.clone().into();
                let class = match c.backup_eligible {
                    true => Class::Synced,
                    false => Class::DeviceBound,
                };
                (c, Stored::Passkey(pk), class, None)
            }
            RegState::Attested(st) => {
                let apk = self.wa.finish_attested_passkey_registration(&reg, &st).map_err(|_| {
                    "This authenticator is not one this site accepts: it must prove its make and model."
                        .to_string()
                })?;
                let aaguid = match &apk.attestation().metadata {
                    AttestationMetadata::Packed { aaguid }
                    | AttestationMetadata::Tpm { aaguid, .. } => Some(aaguid.to_string()),
                    _ => None,
                };
                let c: Credential = apk.clone().into();
                (c, Stored::Attested(apk), Class::Attested, aaguid)
            }
        };
        if class < self.require {
            return Err(match self.require {
                Class::DeviceBound => {
                    "That passkey syncs between devices. This site needs one that stays \
                    on a single device, such as a security key."
                        .into()
                }
                _ => policy_message(self.require),
            });
        }
        let row = entity::ActiveModel {
            user_id: Set(user.id),
            name: Set(name.to_string()),
            credential_id: Set(cred_id(cred.cred_id.as_slice())),
            credential: Set(stored.json()),
            class: Set(class.as_str().into()),
            aaguid: Set(aaguid),
            backup_eligible: Set(cred.backup_eligible),
            backup_state: Set(cred.backup_state),
            created_at: Set(super::now_secs()),
            last_used_at: Set(None),
            ..Default::default()
        }
        .insert(&inner.db)
        .await
        .map_err(|_| "That passkey is already registered.".to_string())?;
        if ours.is_none() {
            let mut am: user::ActiveModel = user.clone().into();
            am.passkey_handle = Set(Some(handle.to_string()));
            am.update(&inner.db)
                .await
                .map_err(|_| "Could not add the passkey.".to_string())?;
        }
        Ok(row)
    }

    /// Start a sign-in with a passkey: a username-less challenge, any passkey of this site's.
    async fn begin_login(&self, inner: &Inner) -> Result<PasskeyAsk, DbErr> {
        let (rcr, state) = self
            .wa
            .start_discoverable_authentication()
            .map_err(|e| DbErr::Custom(format!("{e:?}")))?;
        let id = put(inner, Purpose::Login, None, &state).await?;
        Ok(ask(id, &rcr))
    }

    /// Finish a sign-in with a passkey: the credential names the account.
    async fn finish_login(
        &self,
        inner: &Inner,
        challenge_id: &str,
        response: &str,
    ) -> Result<(user::Model, entity::Model), LoginFail> {
        let Some(state) =
            take::<DiscoverableAuthentication>(inner, challenge_id, Purpose::Login, None).await
        else {
            return Err(LoginFail::Expired);
        };
        let Ok(cred) = serde_json::from_str::<PublicKeyCredential>(response) else {
            return Err(LoginFail::Invalid);
        };
        let row = entity::Entity::find()
            .filter(entity::Column::CredentialId.eq(cred_id(cred.raw_id.as_slice())))
            .one(&inner.db)
            .await
            .map_err(LoginFail::Internal)?
            .ok_or(LoginFail::Invalid)?;
        let account = user::Entity::find_by_id(row.user_id)
            .one(&inner.db)
            .await
            .map_err(LoginFail::Internal)?
            .filter(|u| u.is_active && !u.is_sso())
            .ok_or(LoginFail::Invalid)?;
        // The user handle is optional in an answer; when present it must be this account's.
        if let Some(h) = &cred.response.user_handle {
            let ours = account
                .passkey_handle
                .as_deref()
                .and_then(|h| Uuid::parse_str(h).ok());
            if ours.map(|u| u.as_bytes().to_vec()) != Some(h.as_slice().to_vec()) {
                return Err(LoginFail::Invalid);
            }
        }
        // The class is checked after the signature, not before: until then nothing proves the caller
        // holds this passkey, and a refusal that named the policy would describe someone else's.
        let s = stored(&row).ok_or(LoginFail::Invalid)?;
        let res = match &s {
            Stored::Passkey(p) => self
                .wa
                .finish_discoverable_authentication_v2(&cred, state, p),
            Stored::Attested(a) => self
                .wa
                .finish_discoverable_authentication_v2(&cred, state, a),
        }
        .map_err(|_| LoginFail::Invalid)?;
        let row = self
            .after_use(inner, row, &res)
            .await
            .map_err(LoginFail::Internal)?;
        if row.class() < self.require {
            return Err(LoginFail::Policy);
        }
        Ok((account, row))
    }

    /// The passkeys card of the caller's own profile page.
    pub(super) async fn card_html(
        &self,
        inner: &Inner,
        user: &user::Model,
        reauth: &ReauthView,
        csrf: &str,
        headers: &HeaderMap,
    ) -> String {
        // The "Add a passkey" form carries its registration challenge, so its button runs the
        // browser's prompt on the spot: no page in between.
        let register = self.begin_registration(inner, user).await.ok();
        let (zone, fmt) = super::api_key::clock(headers);
        let rows: Vec<pages::PasskeyRow> = passkey::list(&inner.db, user.id)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|k| pages::PasskeyRow {
                id: k.id,
                accepted: k.class() >= self.require,
                class: class_label(k.class()),
                created: fmt(k.created_at),
                used: k.last_used_at.map(&fmt).unwrap_or_else(|| "never".into()),
                name: k.name,
            })
            .collect();
        let view = pages::PasskeysCard {
            rows: &rows,
            zone: &zone,
            has_password: !user.password_hash.is_empty(),
            requirement: requirement_label(self.require),
            reauth,
            register: register.as_ref(),
            csrf,
        };
        pages::passkeys_card_html(&view)
    }
}

fn class_label(c: Class) -> &'static str {
    match c {
        Class::Synced => "synced",
        Class::DeviceBound => "this device only",
        Class::Attested => "attested hardware",
    }
}

fn requirement_label(c: Class) -> Option<&'static str> {
    match c {
        Class::Synced => None,
        Class::DeviceBound => {
            Some("This site accepts passkeys that stay on one device, such as a security key.")
        }
        Class::Attested => Some("This site accepts only security keys of the models it trusts."),
    }
}

fn policy_message(require: Class) -> String {
    match require {
        Class::Synced => "That passkey is not accepted here.".into(),
        Class::DeviceBound => {
            "That passkey syncs between devices, and this site now needs one that stays on a \
            single device. Ask an administrator."
                .into()
        }
        Class::Attested => {
            "That passkey is not a security key of a model this site trusts. Ask an administrator."
                .into()
        }
    }
}

// ===================== Routes =====================

/// The body of a passkey sign-in: the challenge and the browser's answer.
#[derive(Deserialize)]
pub(super) struct CeremonyForm {
    #[serde(default)]
    passkey_challenge: String,
    #[serde(default)]
    passkey_response: String,
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

/// "Add a passkey": its label, the caller's re-authentication, and the browser's answer to the
/// registration challenge the form carried.
#[derive(Deserialize)]
pub(super) struct AddForm {
    #[serde(default)]
    name: String,
    #[serde(flatten)]
    reauth: super::ReauthInput,
    #[serde(default)]
    register_challenge: String,
    #[serde(default)]
    register_response: String,
    #[serde(default, rename = "_csrf")]
    csrf: Option<String>,
}

use super::CsrfOnlyForm as CsrfForm;

fn runtime(inner: &Inner) -> Option<Arc<Runtime>> {
    inner.passkeys.clone()
}

/// Whether the request asked for JSON — the passkey script on the login page does, to open the prompt
/// on the user's click instead of on a second page.
fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"))
}

/// The login page again, with a message and a status.
fn login_again(
    inner: &Inner,
    req: &Parts,
    jar: CookieJar,
    status: StatusCode,
    msg: &str,
) -> Response {
    let (token, jar) = super::csrf_token(inner, &req.headers, jar);
    let form = pages::login_form_html(Some(msg), &token, true);
    (status, jar, Html((inner.login_shell)(&form, req))).into_response()
}

/// `POST /login/passkey` — the user asked to sign in with a passkey: a fresh challenge, and the page
/// that runs it. Refused while the address is locked out, so a locked address can't write rows.
pub(super) async fn login_begin(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp,
    jar: CookieJar,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !inner.csrf().verify(&req.headers, form.csrf.as_deref()) {
        return super::csrf_rejected(&inner, &req);
    }
    let Some(rt) = runtime(&inner) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(retry) = inner.ips.locked(Some(client_ip)).await {
        let (token, jar) = super::csrf_token(&inner, &req.headers, jar);
        let form = pages::login_form_html(Some(&super::lockout_message(retry)), &token, true);
        return super::too_many_attempts(retry, jar, Html((inner.login_shell)(&form, &req)));
    }
    let ask = match rt.begin_login(&inner).await {
        Ok(a) => a,
        Err(e) => {
            inner
                .report("auth-login", "passkey challenge", &e, client_ip)
                .await;
            return login_again(
                &inner,
                &req,
                jar,
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not start a passkey sign-in.",
            );
        }
    };
    // The script on the login page asks for JSON so the prompt opens on the same click: the challenge
    // and its options, and where to post the answer. Everything else about the sign-in is unchanged —
    // the answer is still a posted form, and a browser without the script gets the page below.
    if wants_json(&req.headers) {
        let options: serde_json::Value = serde_json::from_str(&ask.options).unwrap_or_default();
        let body = serde_json::json!({
            "challenge": ask.challenge,
            "options": options,
            "action": "/login/passkey/finish",
        });
        return (
            [(header::CACHE_CONTROL, "no-store")],
            [(header::CONTENT_TYPE, "application/json")],
            body.to_string(),
        )
            .into_response();
    }
    let (token, jar) = super::csrf_token(&inner, &req.headers, jar);
    let page = pages::passkey_ceremony_html(&pages::Ceremony {
        cancel: &inner.login_path,
        ask: &ask,
        csrf: &token,
    });
    (jar, Html((inner.login_shell)(&page, &req))).into_response()
}

/// `POST /login/passkey/finish` — verify the answer and sign the account in: fully, or to the TOTP step
/// when the account has TOTP. A rejected passkey counts against the address; an expired challenge
/// counts nothing (nothing was checked).
pub(super) async fn login_finish(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp,
    jar: CookieJar,
    Form(form): Form<CeremonyForm>,
) -> Response {
    if !inner.csrf().verify(&req.headers, form.csrf.as_deref()) {
        return super::csrf_rejected(&inner, &req);
    }
    let Some(rt) = runtime(&inner) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(retry) = inner.ips.locked(Some(client_ip)).await {
        let (token, jar) = super::csrf_token(&inner, &req.headers, jar);
        let form = pages::login_form_html(Some(&super::lockout_message(retry)), &token, true);
        return super::too_many_attempts(retry, jar, Html((inner.login_shell)(&form, &req)));
    }
    let (account, row) = match rt
        .finish_login(&inner, &form.passkey_challenge, &form.passkey_response)
        .await
    {
        Ok(v) => v,
        Err(LoginFail::Invalid) => {
            inner.ips.record_failure(Some(client_ip)).await;
            let msg = "That passkey didn't sign you in.";
            return login_again(&inner, &req, jar, StatusCode::UNAUTHORIZED, msg);
        }
        Err(LoginFail::Expired) => {
            let msg = "The sign-in took too long. Try again.";
            return login_again(&inner, &req, jar, StatusCode::BAD_REQUEST, msg);
        }
        Err(LoginFail::Policy) => {
            return login_again(
                &inner,
                &req,
                jar,
                StatusCode::FORBIDDEN,
                &policy_message(rt.require()),
            );
        }
        Err(LoginFail::Internal(e)) => {
            inner
                .report("auth-login", "passkey sign-in", &e, client_ip)
                .await;
            let msg = "That passkey didn't sign you in.";
            return login_again(&inner, &req, jar, StatusCode::UNAUTHORIZED, msg);
        }
    };
    let needs_totp = account.has_totp();
    let method = session::Method::Passkey;
    let token = match super::create_session_class(
        &inner,
        account.id,
        needs_totp,
        method,
        Some(row.class()),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            inner
                .report("auth-login", "session create", &e, client_ip)
                .await;
            let msg = "That passkey didn't sign you in.";
            return login_again(&inner, &req, jar, StatusCode::INTERNAL_SERVER_ERROR, msg);
        }
    };
    let (_, csrf_cookie) = inner.csrf().issue();
    let jar = jar
        .add(super::session_cookie(&inner, token))
        .add(csrf_cookie);
    if needs_totp {
        return (jar, Redirect::to("/login/totp")).into_response();
    }
    super::stamp_login(&inner.db, account.id, None).await;
    let to = inner
        .landing(&account, session::Method::Passkey, Some(row.class()))
        .to_string();
    (jar, Redirect::to(&to)).into_response()
}

/// `POST /login/totp/passkey` — the passkey as the **second factor** after a password: the same brakes
/// as a TOTP code (the account and the address).
pub(super) async fn second_factor_finish(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp,
    jar: CookieJar,
    Form(form): Form<CeremonyForm>,
) -> Response {
    let headers = &req.headers;
    if !inner.csrf().verify(headers, form.csrf.as_deref()) {
        return super::csrf_rejected(&inner, &req);
    }
    let Some(rt) = runtime(&inner) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some((pending, account)) = super::pending_totp_user(&inner, headers).await else {
        return Redirect::to(&inner.login_path).into_response();
    };
    // Only after a password, and only where passkeys are a second factor.
    if !rt.second_factor() || pending.method() != Some(session::Method::Password) {
        return Redirect::to("/login/totp").into_response();
    }
    if let Some(retry) = inner.locked_out(&account.username, client_ip).await {
        let (token, jar) = super::csrf_token(&inner, headers, jar);
        let msg = super::lockout_message(retry);
        let page =
            super::second_step_page(&inner, &pending, &account, Some(&msg), &token, &req).await;
        return super::too_many_attempts(retry, jar, page);
    }
    let purpose = Purpose::SecondFactor;
    let row = match rt
        .verify_user(
            &inner,
            &account,
            purpose,
            &form.passkey_challenge,
            &form.passkey_response,
        )
        .await
    {
        Ok(row) => row,
        Err(refusal) => {
            if refusal.checked {
                inner.record_failure(&account.username, client_ip).await;
            }
            let (token, jar) = super::csrf_token(&inner, headers, jar);
            let msg = Some(refusal.message.as_str());
            let page = super::second_step_page(&inner, &pending, &account, msg, &token, &req).await;
            return (StatusCode::UNAUTHORIZED, jar, page).into_response();
        }
    };
    let method = session::Method::PasswordPasskey;
    let to = inner
        .landing(&account, method, Some(row.class()))
        .to_string();
    let Some(token) = super::rotate_session(&inner, pending, method, Some(row.class())).await
    else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "session error").into_response();
    };
    super::stamp_login(&inner.db, account.id, None).await;
    inner.usernames.clear(&account.username).await;
    let (_, csrf_cookie) = inner.csrf().issue();
    let jar = jar
        .add(super::session_cookie(&inner, token))
        .add(csrf_cookie);
    (jar, Redirect::to(&to)).into_response()
}

/// `POST /profile/passkeys` — add a passkey, in one post: the label, the caller's re-authentication (a
/// passkey is a new way into the account), and the browser's answer to the registration challenge the
/// profile page carried. The script fills that answer in; without it there is none, and the page says
/// adding a passkey needs JavaScript.
pub(super) async fn add(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp,
    jar: CookieJar,
    Form(form): Form<AddForm>,
) -> Response {
    let Some(rt) = runtime(&inner) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (who, user, csrf) = match super::self_post(&inner, &req, form.csrf.as_deref()).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    if user.is_sso() {
        return Redirect::to(&inner.profile_path).into_response(); // SSO: the IdP's factors
    }
    let refuse = |status: StatusCode, msg: String| {
        let (inner, who, user, csrf, req) = (&inner, &who, &user, &csrf, &req);
        async move { super::profile_reply(inner, (who, user, csrf, req), status, Err(&msg)).await }
    };
    if let Err(msg) = inner.reauth(&user, &form.reauth).await {
        return refuse(StatusCode::FORBIDDEN, msg).await;
    }
    if form.register_response.trim().is_empty() {
        // The page's script fills the answer in. None means no script ran: JavaScript is off, or the
        // browser holds an older copy of the script than this page needs.
        let msg = "The browser sent no passkey. Reload the page and try again; adding a passkey \
                   needs JavaScript."
            .to_string();
        return refuse(StatusCode::BAD_REQUEST, msg).await;
    }
    let name = match form.name.trim() {
        "" => "passkey".to_string(),
        _ => match super::api_key::clean_name(&form.name) {
            Ok(n) => n,
            Err(msg) => return refuse(StatusCode::BAD_REQUEST, msg.to_string()).await,
        },
    };
    let (challenge, answer) = (&form.register_challenge, &form.register_response);
    let row = match rt
        .finish_registration(&inner, &user, challenge, answer, &name)
        .await
    {
        Ok(row) => row,
        Err(msg) => return refuse(StatusCode::BAD_REQUEST, msg).await,
    };
    inner
        .notify_event(super::Event {
            source: "auth-profile",
            op: crate::authz::Operation::Create,
            actor: &who.username,
            entity: "auth_passkey",
            key: Some(row.id.to_string()),
            before: None,
            after: Some(describe(&row)),
            headers: &req.headers,
            client_ip,
        })
        .await;
    // The session just proved the passkey: it steps up (§5m), so a restricted session becomes usable.
    let factor = super::Factor::Passkey(row.class());
    let (jar, csrf) = super::step_up(&inner, &req.headers, jar, csrf, factor).await;
    let who = super::refreshed(&inner, &req, &jar, who).await;
    let user = super::target_user(&inner, &who.id).await.unwrap_or(user);
    let msg = format!("Passkey “{}” added.", row.name);
    let page =
        super::profile_reply(&inner, (&who, &user, &csrf, &req), StatusCode::OK, Ok(&msg)).await;
    (jar, page).into_response()
}

/// `POST /profile/passkeys/{id}/remove` — the caller removes one of their own passkeys. Not
/// re-authenticated: it only removes access. Refused for the last passkey of an account with no
/// password, which would leave it no way in.
pub(super) async fn remove(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp,
    Path(id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    let (who, user, csrf) = match super::self_post(&inner, &req, form.csrf.as_deref()).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    let row = match id.parse::<i32>() {
        Ok(id) => entity::Entity::find_by_id(id)
            .filter(entity::Column::UserId.eq(user.id))
            .one(&inner.db)
            .await
            .ok()
            .flatten(),
        Err(_) => None,
    };
    let Some(row) = row else {
        return super::profile_reply(
            &inner,
            (&who, &user, &csrf, &req),
            StatusCode::NOT_FOUND,
            Err("No such passkey."),
        )
        .await;
    };
    if user.password_hash.is_empty() && passkey::count(&inner.db, user.id).await <= 1 {
        let msg = "This is your only way to sign in. Set a password first, or add another passkey.";
        return super::profile_reply(
            &inner,
            (&who, &user, &csrf, &req),
            StatusCode::CONFLICT,
            Err(msg),
        )
        .await;
    }
    let gone = entity::Entity::delete_many()
        .filter(entity::Column::Id.eq(row.id))
        .filter(entity::Column::UserId.eq(user.id))
        .exec(&inner.db)
        .await
        .map(|r| r.rows_affected)
        .unwrap_or(0);
    if gone == 1 {
        inner
            .notify_event(super::Event {
                source: "auth-profile",
                op: crate::authz::Operation::Delete,
                actor: &who.username,
                entity: "auth_passkey",
                key: Some(row.id.to_string()),
                before: Some(describe(&row)),
                after: None,
                headers: &req.headers,
                client_ip,
            })
            .await;
    }
    let msg = format!("Passkey “{}” removed.", row.name);
    super::profile_reply(&inner, (&who, &user, &csrf, &req), StatusCode::OK, Ok(&msg)).await
}

/// `POST /profile/password/remove` — an account with a passkey drops its password, re-authenticated. Its
/// other sessions are signed out: they may have been opened with the password that no longer exists.
pub(super) async fn password_remove(
    State(inner): State<Arc<Inner>>,
    req: Parts,
    RealIp(client_ip): RealIp,
    jar: CookieJar,
    Form(form): Form<AddForm>,
) -> Response {
    if runtime(&inner).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let (who, user, csrf) = match super::self_post(&inner, &req, form.csrf.as_deref()).await {
        Ok(v) => v,
        Err(res) => return res,
    };
    if user.password_hash.is_empty() || user.is_sso() {
        return Redirect::to(&inner.profile_path).into_response();
    }
    if passkey::count(&inner.db, user.id).await == 0 {
        let msg = "Add a passkey first: without a password it is your way to sign in.";
        return super::profile_reply(
            &inner,
            (&who, &user, &csrf, &req),
            StatusCode::CONFLICT,
            Err(msg),
        )
        .await;
    }
    if let Err(msg) = inner.reauth(&user, &form.reauth).await {
        return super::profile_reply(
            &inner,
            (&who, &user, &csrf, &req),
            StatusCode::FORBIDDEN,
            Err(&msg),
        )
        .await;
    }
    let mut am: user::ActiveModel = user.clone().into();
    am.password_hash = Set(String::new());
    am.must_change_password = Set(false);
    let user = match am.update(&inner.db).await {
        Ok(u) => u,
        Err(e) => {
            inner
                .report("auth-profile", "password removal", &e, client_ip)
                .await;
            let (status, msg) = (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not remove the password.",
            );
            return super::profile_reply(&inner, (&who, &user, &csrf, &req), status, Err(msg))
                .await;
        }
    };
    let method = super::current_session(&inner, &req.headers)
        .await
        .and_then(|s| s.method())
        .unwrap_or(session::Method::Passkey);
    let (jar, csrf) = match super::resession(&inner, user.id, method).await {
        Some(token) => {
            let (csrf, csrf_cookie) = inner.csrf().issue();
            (
                jar.add(super::session_cookie(&inner, token))
                    .add(csrf_cookie),
                csrf,
            )
        }
        None => (jar, csrf),
    };
    inner
        .notify(
            "auth-profile",
            &who.username,
            "auth_user",
            Some(who.id.clone()),
            serde_json::json!({ "password_removed": true, "sessions_revoked": true }),
            &req.headers,
            client_ip,
        )
        .await;
    let msg = "Your password is removed: you sign in with a passkey. Other sessions have been signed out.";
    (
        jar,
        super::profile_reply(&inner, (&who, &user, &csrf, &req), StatusCode::OK, Ok(msg)).await,
    )
        .into_response()
}

/// `GET /auth/passkey.js` — the one script passkeys need, as a file so a strict CSP can allow it.
///
/// Revalidated on every use (`no-cache` with an `ETag` of its content): a page and its script change
/// together on an upgrade, and a browser holding the old script against a new page would post a form
/// the old script doesn't know how to fill. An unchanged script costs a `304`.
pub(super) async fn script(headers: HeaderMap) -> Response {
    let etag = script_etag();
    let fresh = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag));
    if fresh {
        return (StatusCode::NOT_MODIFIED, [(header::ETAG, etag.to_string())]).into_response();
    }
    (
        [
            (
                header::CONTENT_TYPE,
                "text/javascript; charset=utf-8".to_string(),
            ),
            (header::CACHE_CONTROL, "no-cache".to_string()),
            (header::ETAG, etag.to_string()),
        ],
        SCRIPT,
    )
        .into_response()
}

/// The script's `ETag`: a hash of its content, computed once.
fn script_etag() -> &'static str {
    static ETAG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ETAG.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let hex: String = Sha256::digest(SCRIPT.as_bytes())
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("\"{hex}\"")
    })
}

/// The passkey script — `assets/rl-passkey.js`.
pub(super) const SCRIPT: &str = include_str!("../../assets/rl-passkey.js");

/// A passkey as the audit trail sees it: label, class, model. Never the credential.
fn describe(row: &entity::Model) -> serde_json::Value {
    serde_json::json!({
        "user_id": row.user_id,
        "name": row.name,
        "class": row.class,
        "aaguid": row.aaguid,
    })
}

/// The routes, merged into `Auth::routes()` when passkeys are on.
pub(super) fn routes(router: axum::Router<Arc<Inner>>) -> axum::Router<Arc<Inner>> {
    use axum::routing::{get, post};
    router
        .route("/auth/passkey.js", get(script))
        .route("/login/passkey", post(login_begin))
        .route("/login/passkey/finish", post(login_finish))
        .route("/login/totp/passkey", post(second_factor_finish))
        .route("/profile/passkeys", post(add))
        .route("/profile/passkeys/{id}/remove", post(remove))
        .route("/profile/password/remove", post(password_remove))
}
