//! SSO / OpenID Connect (feature `sso`). Sign users in through an external identity provider
//! (Google, Okta, or any OIDC-compliant corporate IdP) via the Authorization Code flow with PKCE,
//! then map them onto local `auth_user` rows + group memberships.
//!
//! **Group mapping.** A login's local groups are the **union** of two rule tables:
//! - a **global username-pattern table** — `regexp → [groups]` — applied to the resolved username.
//!   This is the fallback for providers that carry no usable group/role claim (e.g. plain Google
//!   OIDC), where all you have to key off is the email/username.
//! - a **per-provider claim table** — `claim-value → [groups]` — applied to each value of the
//!   provider's configured groups claim (e.g. Okta / a corporate IdP that emits group names).
//!
//! On every login the resulting set is **reconciled** onto the user: groups in the set are added,
//! groups the user has but the set doesn't are removed. SSO accounts' groups are therefore fully
//! managed by these rules (don't hand-assign groups to an SSO user — they'll be stripped next login).
//!
//! **Accounts.** An SSO login resolves to an `auth_user` whose `sso_provider` marks it external (no
//! local password / 2FA). With **auto-registration** on for a provider, an unknown user is created on
//! first login; with it off, an admin must pre-create the user and set its `sso_provider` first, else
//! the login is refused. See `docs/AUTH.md`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    reqwest, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use regex::Regex;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use crate::auth::{session_cookie, user, Auth};

const TXN_COOKIE: &str = "rl_sso_txn"; // short-lived cookie carrying the in-flight login transaction

/// One OIDC provider the app offers (Google, Okta, a corporate IdP …). Secrets and the group-claim
/// table are configured at app start.
#[derive(Clone)]
pub struct SsoProvider {
    pub(crate) key: String,   // URL segment + `sso_provider` value, e.g. "google"
    pub(crate) label: String, // button label on the login page, e.g. "Google"
    pub(crate) issuer: String, // OIDC issuer URL (used for discovery)
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) redirect_url: String,
    pub(crate) scopes: Vec<String>,
    /// Claim whose value becomes the local username (default `"preferred_username"`; Google → `"email"`).
    pub(crate) username_claim: String,
    /// Claim holding the provider's group/role values, if any (e.g. `"groups"`). `None` → no claim table.
    pub(crate) groups_claim: Option<String>,
    /// `claim-value → [groups]` table (union'd with the global username table).
    pub(crate) claim_rules: HashMap<String, Vec<String>>,
    /// Create unknown users on first login (typical for a corporate IdP). Off → admin must pre-create.
    pub(crate) auto_register: bool,
}

impl SsoProvider {
    /// A provider keyed by `key` (the `/sso/{key}/…` URL segment and the account's `sso_provider`
    /// value). `issuer` is the OIDC issuer for discovery; `redirect_url` must match what's registered
    /// with the provider and point at `{base_path}/{key}/callback`.
    pub fn new(
        key: impl Into<String>,
        label: impl Into<String>,
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_url: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            issuer: issuer.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_url: redirect_url.into(),
            // `openid` is added automatically by the OIDC flow — don't list it here (avoids a dup).
            scopes: vec!["email".into(), "profile".into()],
            username_claim: "preferred_username".into(),
            groups_claim: None,
            claim_rules: HashMap::new(),
            auto_register: false,
        }
    }

    /// Replace the extra requested scopes (default `email profile`). The `openid` scope is always
    /// added by the OIDC flow, so you don't list it here.
    pub fn scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).filter(|s| s != "openid").collect();
        self
    }

    /// The claim to use as the local username (default `"preferred_username"`; use `"email"` for Google).
    pub fn username_claim(mut self, claim: impl Into<String>) -> Self {
        self.username_claim = claim.into();
        self
    }

    /// The claim holding the provider's group/role values (e.g. `"groups"`), to drive the claim table.
    pub fn groups_claim(mut self, claim: impl Into<String>) -> Self {
        self.groups_claim = Some(claim.into());
        self
    }

    /// Add a `claim-value → groups` rule: when the groups claim contains `value`, grant `groups`.
    pub fn claim_group_rule<I, S>(mut self, value: impl Into<String>, groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.claim_rules.insert(value.into(), groups.into_iter().map(Into::into).collect());
        self
    }

    /// Create unknown users on first login (default off). Off: an admin must pre-create the user and
    /// set its `sso_provider` to this key before they can sign in.
    pub fn auto_register(mut self, on: bool) -> Self {
        self.auto_register = on;
        self
    }
}

/// SSO configuration: the global username→group rules plus the registered providers. Built at app
/// start from an [`Auth`] handle (it creates sessions and users, and reconciles groups); merge
/// [`routes`](Sso::routes) into your router and link the login page to `{base_path}/{key}/login`.
#[derive(Clone)]
pub struct Sso {
    pub(crate) auth: Auth,
    pub(crate) base_path: String,
    /// Global `username-regexp → [groups]` table (union'd with each provider's claim table).
    pub(crate) username_rules: Vec<(Regex, Vec<String>)>,
    pub(crate) providers: Vec<SsoProvider>,
}

impl Sso {
    pub fn new(auth: &Auth) -> Self {
        Self { auth: auth.clone(), base_path: "/sso".into(), username_rules: Vec::new(), providers: Vec::new() }
    }

    /// Route prefix for the SSO endpoints (default `"/sso"` → `/sso/{key}/login`, `/sso/{key}/callback`).
    pub fn base_path(mut self, path: impl Into<String>) -> Self {
        self.base_path = path.into();
        self
    }

    /// Add a global `username-pattern → groups` rule. `pattern` is a regular expression matched
    /// against the resolved username (anchor it with `^…$` for an exact match). **Panics at startup on
    /// an invalid regex** — this is config, so fail fast.
    pub fn username_group_rule<I, S>(mut self, pattern: &str, groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let re = Regex::new(pattern)
            .unwrap_or_else(|e| panic!("invalid SSO username regex {pattern:?}: {e}"));
        self.username_rules.push((re, groups.into_iter().map(Into::into).collect()));
        self
    }

    /// Register a provider.
    pub fn provider(mut self, provider: SsoProvider) -> Self {
        self.providers.push(provider);
        self
    }

    /// One login button per registered provider — `(label, url)` — to render on your login page.
    /// The URL is `{base_path}/{key}/login`.
    pub fn buttons(&self) -> Vec<SsoButton> {
        let base = self.base_path.trim_end_matches('/');
        self.providers
            .iter()
            .map(|p| SsoButton { label: p.label.clone(), url: format!("{base}/{}/login", p.key) })
            .collect()
    }

    /// The SSO routes to merge into your router: `GET {base_path}/{key}/login` (redirect to the
    /// provider) and `GET {base_path}/{key}/callback` (exchange the code, map the user, sign in).
    pub fn routes(&self) -> Router {
        let base = self.base_path.trim_end_matches('/').to_string();
        Router::new()
            .route(&format!("{base}/{{provider}}/login"), get(login))
            .route(&format!("{base}/{{provider}}/callback"), get(callback))
            .with_state(Arc::new(self.clone()))
    }

    pub(crate) fn find_provider(&self, key: &str) -> Option<&SsoProvider> {
        self.providers.iter().find(|p| p.key == key)
    }

    /// The groups a login should have: the union of the global username-pattern matches and the
    /// provider's claim-table matches over `claim_values` (the provider's groups claim, empty if none).
    pub(crate) fn resolve_groups(
        &self,
        provider: &SsoProvider,
        username: &str,
        claim_values: &[String],
    ) -> BTreeSet<String> {
        resolve_groups(&self.username_rules, &provider.claim_rules, username, claim_values)
    }
}

/// Pure group resolution: union of (username-pattern matches) and (claim-value matches).
pub(crate) fn resolve_groups(
    username_rules: &[(Regex, Vec<String>)],
    claim_rules: &HashMap<String, Vec<String>>,
    username: &str,
    claim_values: &[String],
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (re, groups) in username_rules {
        if re.is_match(username) {
            out.extend(groups.iter().cloned());
        }
    }
    for value in claim_values {
        if let Some(groups) = claim_rules.get(value) {
            out.extend(groups.iter().cloned());
        }
    }
    out
}

/// Which groups to add / remove to make `current` equal `desired` (for on-login reconciliation).
pub(crate) fn group_diff(
    current: &BTreeSet<String>,
    desired: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    let to_add = desired.difference(current).cloned().collect();
    let to_remove = current.difference(desired).cloned().collect();
    (to_add, to_remove)
}

// ===================== OIDC flow (Authorization Code + PKCE) =====================

/// A login button for the app's login page.
pub struct SsoButton {
    pub label: String,
    pub url: String,
}

/// The in-flight login transaction, carried in a short-lived cookie between `login` and `callback`.
#[derive(Serialize, Deserialize)]
struct Txn {
    provider: String,
    csrf: String,  // expected `state` on return
    nonce: String, // bound into the ID token
    pkce: String,  // PKCE code verifier
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Discover the provider metadata + parse the redirect URL + build an HTTP client. (The OIDC client
/// itself is constructed inline in each handler — openidconnect's endpoint typestate can't be named
/// through a `fn` return.)
async fn discover(p: &SsoProvider) -> Result<(CoreProviderMetadata, RedirectUrl, reqwest::Client), String> {
    let http = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none()) // never follow redirects (SSRF hardening)
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let issuer = IssuerUrl::new(p.issuer.clone()).map_err(|e| format!("issuer url: {e}"))?;
    let meta = CoreProviderMetadata::discover_async(issuer, &http)
        .await
        .map_err(|e| format!("discovery: {e}"))?;
    let redirect = RedirectUrl::new(p.redirect_url.clone()).map_err(|e| format!("redirect url: {e}"))?;
    Ok((meta, redirect, http))
}

/// `GET {base}/{provider}/login` — redirect to the provider's authorization endpoint (PKCE + nonce +
/// CSRF state), stashing the transaction in a short-lived cookie.
async fn login(State(sso): State<Arc<Sso>>, Path(provider): Path<String>, jar: CookieJar) -> Response {
    let Some(p) = sso.find_provider(&provider) else {
        return (StatusCode::NOT_FOUND, "unknown SSO provider").into_response();
    };
    let (meta, redirect, _http) = match discover(p).await {
        Ok(x) => x,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("SSO provider unavailable: {e}")).into_response(),
    };
    let client = CoreClient::from_provider_metadata(
        meta,
        ClientId::new(p.client_id.clone()),
        Some(ClientSecret::new(p.client_secret.clone())),
    )
    .set_redirect_uri(redirect);
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut req = client.authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );
    for s in &p.scopes {
        req = req.add_scope(Scope::new(s.clone()));
    }
    let (auth_url, csrf, nonce) = req.set_pkce_challenge(challenge).url();

    let txn = Txn {
        provider: p.key.clone(),
        csrf: csrf.secret().clone(),
        nonce: nonce.secret().clone(),
        pkce: verifier.secret().clone(),
    };
    let jar = jar.add(txn_cookie(&sso, &txn));
    (jar, Redirect::to(auth_url.as_str())).into_response()
}

/// `GET {base}/{provider}/callback` — validate state, exchange the code, verify the ID token, map the
/// user, reconcile groups, and start a session.
async fn callback(
    State(sso): State<Arc<Sso>>,
    Path(provider): Path<String>,
    jar: CookieJar,
    Query(q): Query<CallbackQuery>,
) -> Response {
    if let Some(err) = q.error {
        return (StatusCode::BAD_REQUEST, format!("SSO error from provider: {err}")).into_response();
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return (StatusCode::BAD_REQUEST, "missing code/state").into_response();
    };
    let Some(txn) = read_txn(&sso, &jar) else {
        return (StatusCode::BAD_REQUEST, "no or invalid SSO transaction").into_response();
    };
    // CSRF: the returned state must match what we issued, for the same provider.
    if txn.provider != provider || txn.csrf != state {
        return (StatusCode::BAD_REQUEST, "SSO state mismatch").into_response();
    }
    let Some(p) = sso.find_provider(&provider) else {
        return (StatusCode::NOT_FOUND, "unknown SSO provider").into_response();
    };
    let clear = jar.clone().remove(Cookie::build(TXN_COOKIE).path("/").build());

    let (meta, redirect, http) = match discover(p).await {
        Ok(x) => x,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("SSO provider unavailable: {e}")).into_response(),
    };
    let client = CoreClient::from_provider_metadata(
        meta,
        ClientId::new(p.client_id.clone()),
        Some(ClientSecret::new(p.client_secret.clone())),
    )
    .set_redirect_uri(redirect);
    // Exchange the authorization code (PKCE) for tokens.
    let token = match client.exchange_code(AuthorizationCode::new(code)) {
        Ok(r) => match r.set_pkce_verifier(PkceCodeVerifier::new(txn.pkce)).request_async(&http).await {
            Ok(t) => t,
            Err(e) => return (StatusCode::BAD_GATEWAY, format!("token exchange failed: {e}")).into_response(),
        },
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("token request: {e}")).into_response(),
    };
    let Some(id_token) = token.id_token() else {
        return (StatusCode::BAD_GATEWAY, "provider returned no ID token").into_response();
    };
    // SECURITY: verify signature, issuer, audience, expiry, and the nonce we bound.
    let verifier = client.id_token_verifier();
    if let Err(e) = id_token.claims(&verifier, &Nonce::new(txn.nonce)) {
        return (StatusCode::BAD_GATEWAY, format!("ID token verification failed: {e}")).into_response();
    }
    // The token is verified; read the (already-authenticated) payload for the configured claims.
    let Some(payload) = id_token_payload(id_token) else {
        return (StatusCode::BAD_GATEWAY, "could not read ID token claims").into_response();
    };
    let Some(username) = payload.get(&p.username_claim).and_then(|v| v.as_str()) else {
        return (StatusCode::BAD_GATEWAY, format!("ID token has no '{}' claim", p.username_claim)).into_response();
    };
    let claim_values = p
        .groups_claim
        .as_ref()
        .and_then(|gc| payload.get(gc))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>())
        .unwrap_or_default();

    let db = &sso.auth.inner.db;
    let user = match resolve_user(db, p, username).await {
        Ok(u) => u,
        Err((code, msg)) => return (code, clear, msg).into_response(),
    };
    let desired = sso.resolve_groups(p, username, &claim_values);
    reconcile_groups(db, &user.username, user.id, &desired).await;
    super::stamp_last_login(db, user.id).await;

    // SSO accounts have no local 2FA, so this is a full session immediately.
    let Some(token) = super::create_session(&sso.auth.inner, user.id, false).await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, clear, "session error").into_response();
    };
    let jar = clear.add(session_cookie(&sso.auth.inner, token));
    (jar, Redirect::to("/")).into_response()
}

/// Find the SSO user for `username`, honoring the provider binding and auto-registration policy.
async fn resolve_user(
    db: &sea_orm::DatabaseConnection,
    p: &SsoProvider,
    username: &str,
) -> Result<user::Model, (StatusCode, String)> {
    let existing = user::Entity::find()
        .filter(user::Column::Username.eq(username))
        .one(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if let Some(u) = existing {
        return match u.sso_provider.as_deref() {
            Some(key) if key == p.key => Ok(u),
            Some(_) => Err((StatusCode::FORBIDDEN, "account is bound to a different SSO provider".into())),
            None => Err((StatusCode::FORBIDDEN, "this is a local (password) account, not SSO".into())),
        };
    }
    if !p.auto_register {
        return Err((StatusCode::FORBIDDEN, "no such SSO account — an admin must create it first".into()));
    }
    user::ActiveModel {
        username: Set(username.to_string()),
        password_hash: Set(String::new()), // no password → no local login
        is_active: Set(true),
        sso_provider: Set(Some(p.key.clone())),
        ..Default::default()
    }
    .insert(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// Make the user's group memberships exactly `desired` (add missing, remove extras).
async fn reconcile_groups(
    db: &sea_orm::DatabaseConnection,
    username: &str,
    user_id: i32,
    desired: &BTreeSet<String>,
) {
    let current: BTreeSet<String> = super::groups_of(db, user_id).await.into_iter().collect();
    let (add, remove) = group_diff(&current, desired);
    for g in add {
        let _ = super::add_to_group(db, username, &g).await;
    }
    for g in remove {
        let _ = super::remove_from_group(db, username, &g).await;
    }
}

/// The verified ID token's payload as JSON (to read the configured username / groups claims). The
/// token's signature + nonce were already checked by `id_token.claims(...)`; here we just decode the
/// same token's payload segment.
fn id_token_payload(id_token: &openidconnect::core::CoreIdToken) -> Option<serde_json::Value> {
    let jwt = serde_json::to_value(id_token).ok()?; // IdToken serializes to the compact JWT string
    let jwt = jwt.as_str()?;
    let payload = jwt.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Build the short-lived transaction cookie (base64 JSON; HttpOnly; SameSite=Lax so it survives the
/// top-level redirect back from the provider).
fn txn_cookie(sso: &Sso, txn: &Txn) -> Cookie<'static> {
    let json = serde_json::to_vec(txn).unwrap_or_default();
    let value = URL_SAFE_NO_PAD.encode(json);
    Cookie::build((TXN_COOKIE, value))
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .secure(sso.auth.inner.secure_cookies)
        .max_age(time::Duration::minutes(10))
        .build()
}

fn read_txn(_sso: &Sso, jar: &CookieJar) -> Option<Txn> {
    let raw = jar.get(TXN_COOKIE)?.value().to_string();
    let bytes = URL_SAFE_NO_PAD.decode(raw).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Vec<(Regex, Vec<String>)> {
        vec![
            (Regex::new(r"@example\.com$").unwrap(), vec!["staff".into()]),
            (Regex::new(r"^admin@").unwrap(), vec!["admin".into()]),
        ]
    }

    #[test]
    fn username_rules_union() {
        let claim_rules = HashMap::new();
        // Matches both @example.com and ^admin@ → union {staff, admin}.
        let g = resolve_groups(&rules(), &claim_rules, "admin@example.com", &[]);
        assert_eq!(g, BTreeSet::from(["admin".to_string(), "staff".to_string()]));
        // Matches only the domain rule.
        let g = resolve_groups(&rules(), &claim_rules, "bob@example.com", &[]);
        assert_eq!(g, BTreeSet::from(["staff".to_string()]));
        // Matches nothing.
        let g = resolve_groups(&rules(), &claim_rules, "bob@other.org", &[]);
        assert!(g.is_empty());
    }

    #[test]
    fn claim_rules_union_with_username_rules() {
        let mut claim_rules = HashMap::new();
        claim_rules.insert("eng-admins".to_string(), vec!["admin".to_string()]);
        claim_rules.insert("eng".to_string(), vec!["editors".to_string()]);
        // Domain rule (staff) unions with two matched claim values (admin, editors); "other" ignored.
        let g = resolve_groups(
            &rules(),
            &claim_rules,
            "dev@example.com",
            &["eng".into(), "eng-admins".into(), "other".into()],
        );
        assert_eq!(
            g,
            BTreeSet::from(["admin".to_string(), "editors".to_string(), "staff".to_string()])
        );
    }

    #[test]
    fn diff_adds_and_removes() {
        let current = BTreeSet::from(["staff".to_string(), "old".to_string()]);
        let desired = BTreeSet::from(["staff".to_string(), "admin".to_string()]);
        let (add, remove) = group_diff(&current, &desired);
        assert_eq!(add, vec!["admin".to_string()]); // in desired, not current
        assert_eq!(remove, vec!["old".to_string()]); // in current, not desired
    }
}
