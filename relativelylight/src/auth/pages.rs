//! The HTML `auth` serves: Askama templates in `templates/auth/`, which escape every value they
//! insert. Each page is a fragment with Bootstrap-friendly class hooks and no page chrome; the app's
//! [`Auth::login_shell`](super::Auth::login_shell) / [`profile_shell`](super::Auth::profile_shell)
//! wraps and styles it.

use super::{api_key, recovery, totp, Identity};
use axum::http::request::Parts;
use askama::Template;

/// Askama renders into a `String` and these templates insert only `&str`s and integers, so this
/// cannot fail in practice; an empty body is the safe answer if it ever did.
fn render(t: impl Template) -> String {
    t.render().unwrap_or_default()
}

/// The confirm-it's-you block's inputs (`_macros.html` → `reauth`): which factors the account has to
/// offer. Built per render by `Inner::reauth_view`, which also creates the passkey challenge.
pub(super) struct ReauthView {
    pub has_password: bool,
    pub totp_on: bool,
    pub passkey: Option<PasskeyAsk>,
}

impl ReauthView {
    /// No factor at all — the SSO case, and the safe stand-in when a page has no account to ask about.
    pub fn none() -> Self {
        Self { has_password: false, totp_on: false, passkey: None }
    }
}

/// A passkey ceremony a page asks for: the challenge row's id and the options for the browser, as JSON
/// already made safe to sit inside a `<script>` element ([`script_json`]).
pub(super) struct PasskeyAsk {
    pub challenge: String,
    pub options: String,
}

/// JSON made safe for a `<script type="application/json">` element: `<`, `>` and `&` become `\u` escapes,
/// so no value can close the element or open a comment. `JSON.parse` reads them back unchanged.
#[cfg_attr(not(feature = "passkeys"), allow(dead_code))]
pub(super) fn script_json(json: &str) -> String {
    json.replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026")
}

#[derive(Template)]
#[template(path = "auth/shell.html")]
struct Shell<'a> {
    title: &'a str,
    body: &'a str,
}

/// The page around the login fragment when the app sets no `login_shell`: a minimal document.
pub(super) fn default_login_shell(form: &str, _req: &Parts) -> String {
    render(Shell { title: "Log in", body: form })
}

/// The page around the profile fragment when the app sets no `profile_shell`.
pub(super) fn default_profile_shell(fragment: &str, _who: &Identity, _req: &Parts) -> String {
    render(Shell { title: "Profile", body: fragment })
}

#[derive(Template)]
#[template(path = "auth/csrf_rejected.html")]
struct CsrfRejected<'a> {
    login: &'a str,
}

/// The bare `403` for a missing or wrong CSRF token.
pub(super) fn csrf_rejected_html(login: &str) -> String {
    render(CsrfRejected { login })
}

#[derive(Template)]
#[template(path = "auth/login.html")]
struct Login<'a> {
    error: Option<&'a str>,
    success: Option<&'a str>,
    csrf: &'a str,
    passkeys: bool,
}

/// The login form; `passkeys` adds the "Sign in with a passkey" button.
pub(super) fn login_form_html(error: Option<&str>, csrf: &str, passkeys: bool) -> String {
    render(Login { error, success: None, csrf, passkeys })
}

#[derive(Template)]
#[template(path = "auth/totp_login.html")]
struct TotpLogin<'a> {
    error: Option<&'a str>,
    success: Option<&'a str>,
    csrf: &'a str,
    totp_on: bool,
    passkey: Option<&'a PasskeyAsk>,
}

/// The second step of a login, at `/login/totp`: the TOTP code when the account has TOTP, and its
/// passkey when one is asked for.
pub(super) fn totp_login_html(
    error: Option<&str>,
    csrf: &str,
    totp_on: bool,
    passkey: Option<&PasskeyAsk>,
) -> String {
    render(TotpLogin { error, success: None, csrf, totp_on, passkey })
}

#[derive(Template)]
#[template(path = "auth/totp_setup.html")]
struct TotpSetup<'a> {
    qr: &'a str,
    url: &'a str,
    reauth: &'a ReauthView,
    error: Option<&'a str>,
    success: Option<&'a str>,
    csrf: &'a str,
}

/// 2FA enrolment: the QR image, the `otpauth://` URL as text, and a code to confirm it.
pub(super) fn totp_setup_html(
    prov: &totp::Provisioning,
    reauth: &ReauthView,
    error: Option<&str>,
    csrf: &str,
) -> String {
    render(TotpSetup { qr: &prov.qr_data_uri, url: &prov.url, reauth, error, success: None, csrf })
}

#[derive(Template)]
#[template(path = "auth/profile.html")]
struct Profile<'a> {
    username: &'a str,
    has_password: bool,
    reauth: &'a ReauthView,
    totp_on: bool,
    recovery_left: Option<u64>,
    error: Option<&'a str>,
    success: Option<&'a str>,
    csrf: &'a str,
}

/// The self-service profile: change password, the 2FA state, recovery codes (with 2FA on) and
/// signing out other sessions.
#[allow(clippy::too_many_arguments)]
pub(super) fn change_form_html(
    who: &Identity,
    has_password: bool,
    reauth: &ReauthView,
    totp_on: bool,
    recovery_left: Option<u64>,
    error: Option<&str>,
    success: Option<&str>,
    csrf: &str,
) -> String {
    let username = &who.username;
    render(Profile { username, has_password, reauth, totp_on, recovery_left, error, success, csrf })
}

#[derive(Template)]
#[template(path = "auth/reset.html")]
struct Reset<'a> {
    id: &'a str,
    username: &'a str,
    totp_on: bool,
    has_password: bool,
    passkeys: u64,
    /// The **manager's** factors — they confirm with their own, never the target's.
    reauth: &'a ReauthView,
    error: Option<&'a str>,
    success: Option<&'a str>,
    csrf: &'a str,
}

/// A manager's view of another account: set its password without the current one, and disable its
/// 2FA (a manager can't set one up for someone else).
/// What a manager's page shows about the account being managed.
pub(super) struct Target<'a> {
    pub id: &'a str,
    pub username: &'a str,
    pub totp_on: bool,
    pub has_password: bool,
    pub passkeys: u64,
}

pub(super) fn reset_form_html(
    t: &Target<'_>,
    reauth: &ReauthView,
    error: Option<&str>,
    success: Option<&str>,
    csrf: &str,
) -> String {
    render(Reset {
        id: t.id,
        username: t.username,
        totp_on: t.totp_on,
        has_password: t.has_password,
        passkeys: t.passkeys,
        reauth,
        error,
        success,
        csrf,
    })
}

#[derive(Template)]
#[template(path = "auth/reauth_fields.html")]
struct ReauthFields<'a> {
    reauth: &'a ReauthView,
    hint: &'a str,
}

/// The confirm-it's-you block alone, for an app's own form (`Auth::reauth_fields`).
pub(super) fn reauth_fields_html(reauth: &ReauthView, hint: &str) -> String {
    render(ReauthFields { reauth, hint })
}

/// One passkey in the profile's passkeys section, formatted.
#[cfg(feature = "passkeys")]
pub(super) struct PasskeyRow {
    pub id: i32,
    pub name: String,
    pub class: &'static str,
    /// Whether the policy accepts it now; one it doesn't is listed so the user can remove it.
    pub accepted: bool,
    pub created: String,
    pub used: String,
}

/// The passkeys section of the caller's own profile.
#[cfg(feature = "passkeys")]
#[derive(Template)]
#[template(path = "auth/passkeys.html")]
pub(super) struct PasskeysCard<'a> {
    pub rows: &'a [PasskeyRow],
    pub zone: &'a str,
    pub has_password: bool,
    pub requirement: Option<&'a str>,
    pub reauth: &'a ReauthView,
    pub error: Option<&'a str>,
    pub success: Option<&'a str>,
    pub csrf: &'a str,
}

#[cfg(feature = "passkeys")]
pub(super) fn passkeys_card_html(card: &PasskeysCard<'_>) -> String {
    card.render().unwrap_or_default()
}

/// A page whose one job is a passkey ceremony: the options, the button that starts it, and the form
/// the script submits.
#[cfg(feature = "passkeys")]
#[derive(Template)]
#[template(path = "auth/passkey_ceremony.html")]
pub(super) struct Ceremony<'a> {
    pub title: &'a str,
    pub lead: &'a str,
    pub action: &'a str,
    /// `get` (sign in, confirm) or `create` (add a passkey).
    pub mode: &'a str,
    pub button: &'a str,
    pub cancel: &'a str,
    /// Extra fields the post carries (the new passkey's label).
    pub hidden: &'a [(&'a str, &'a str)],
    pub ask: &'a PasskeyAsk,
    pub csrf: &'a str,
}

#[cfg(feature = "passkeys")]
pub(super) fn passkey_ceremony_html(c: &Ceremony<'_>) -> String {
    c.render().unwrap_or_default()
}

#[derive(Template)]
#[template(path = "auth/recovery_codes.html")]
struct RecoveryCodes<'a> {
    codes: Vec<String>,
    headline: &'a str,
}

/// The one showing of a freshly issued set.
pub(super) fn recovery_codes_html(codes: &[String], headline: &str) -> String {
    render(RecoveryCodes { codes: codes.iter().map(|c| recovery::display(c)).collect(), headline })
}

#[derive(Template)]
#[template(path = "auth/api_keys.html")]
struct ApiKeys<'a> {
    card: &'a api_key::Card,
    reauth: &'a ReauthView,
    error: Option<&'a str>,
    success: Option<&'a str>,
    csrf: &'a str,
}

/// The API-key card on the caller's own profile: their keys, a revoke button each, and the mint form,
/// which re-authenticates when the account has a factor to ask for.
pub(super) fn api_keys_html(
    card: &api_key::Card,
    reauth: &ReauthView,
    error: Option<&str>,
    success: Option<&str>,
    csrf: &str,
) -> String {
    render(ApiKeys { card, reauth, error, success, csrf })
}

#[derive(Template)]
#[template(path = "auth/api_key_minted.html")]
struct ApiKeyMinted<'a> {
    name: &'a str,
    raw: &'a str,
}

/// The one showing of a freshly minted key.
pub(super) fn api_key_minted_html(name: &str, raw: &str) -> String {
    render(ApiKeyMinted { name, raw })
}

#[derive(Template)]
#[template(path = "auth/sso.html")]
struct Sso<'a> {
    managed: bool,
    username: &'a str,
    provider: &'a str,
}

/// A manager's view of an SSO account: a notice in place of the reset form.
pub(super) fn sso_managed_html(username: &str, provider: &str) -> String {
    render(Sso { managed: true, username, provider })
}

/// The owner's profile of an SSO account: a read-only notice.
pub(super) fn sso_profile_html(who: &Identity, provider: &str) -> String {
    render(Sso { managed: false, username: &who.username, provider })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every value a page shows is escaped. The positive control is that the value is there at
    /// all, escaped — a page that dropped it would pass the negative check vacuously.
    #[test]
    fn every_value_a_page_shows_is_escaped() {
        let bad = r#"<script>x</script>""#;
        let who = Identity { id: bad.into(), username: bad.into(), groups: vec![] };
        let prov = totp::Provisioning { url: bad.into(), qr_data_uri: bad.into() };
        let row = || api_key::Row {
            id: 1,
            name: bad.into(),
            prefix: bad.into(),
            created: bad.into(),
            expires: bad.into(),
            expired: true,
            used: bad.into(),
            disabled: true,
        };
        let card = api_key::Card { rows: vec![row()], zone: bad.into() };
        let none = ReauthView::none();
        let target = Target { id: bad, username: bad, totp_on: true, has_password: false, passkeys: 2 };
        let pages = [
            login_form_html(Some(bad), bad, true),
            totp_login_html(Some(bad), bad, true, None),
            totp_setup_html(&prov, &none, Some(bad), bad),
            change_form_html(&who, true, &none, true, Some(2), Some(bad), None, bad),
            change_form_html(&who, false, &none, false, None, None, Some(bad), bad),
            reset_form_html(&target, &none, Some(bad), None, bad),
            recovery_codes_html(&[], bad),
            sso_managed_html(bad, bad),
            sso_profile_html(&who, bad),
            csrf_rejected_html(bad),
            api_keys_html(&card, &none, Some(bad), None, bad),
            api_keys_html(&card, &none, None, Some(bad), bad),
            api_key_minted_html(bad, bad),
        ];
        for html in pages {
            assert!(!html.contains("<script>") && !html.contains("\"\""), "unescaped: {html}");
            assert!(html.contains("&#60;script&#62;x&#60;/script&#62;&#34;"), "not shown: {html}");
        }
    }
}
