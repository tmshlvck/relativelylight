//! The HTML `auth` serves: Askama templates in `templates/auth/`, which escape every value they
//! insert. Each page is a fragment with Bootstrap-friendly class hooks and no page chrome; the app's
//! [`Auth::login_shell`](super::Auth::login_shell) / [`profile_shell`](super::Auth::profile_shell)
//! wraps and styles it.

use super::{recovery, totp, Identity};
use askama::Template;

/// Askama renders into a `String` and these templates insert only `&str`s and integers, so this
/// cannot fail in practice; an empty body is the safe answer if it ever did.
fn render(t: impl Template) -> String {
    t.render().unwrap_or_default()
}

#[derive(Template)]
#[template(path = "auth/shell.html")]
struct Shell<'a> {
    title: &'a str,
    body: &'a str,
}

/// The page around the login fragment when the app sets no `login_shell`: a minimal document.
pub(super) fn default_login_shell(form: &str) -> String {
    render(Shell { title: "Log in", body: form })
}

/// The page around the profile fragment when the app sets no `profile_shell`.
pub(super) fn default_profile_shell(fragment: &str, _who: &Identity) -> String {
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
}

pub(super) fn login_form_html(error: Option<&str>, csrf: &str) -> String {
    render(Login { error, success: None, csrf })
}

#[derive(Template)]
#[template(path = "auth/totp_login.html")]
struct TotpLogin<'a> {
    error: Option<&'a str>,
    success: Option<&'a str>,
    csrf: &'a str,
}

/// The second step of a login, at `/login/totp`, after a correct password.
pub(super) fn totp_login_html(error: Option<&str>, csrf: &str) -> String {
    render(TotpLogin { error, success: None, csrf })
}

#[derive(Template)]
#[template(path = "auth/totp_setup.html")]
struct TotpSetup<'a> {
    qr: &'a str,
    url: &'a str,
    totp_on: bool,
    error: Option<&'a str>,
    success: Option<&'a str>,
    csrf: &'a str,
}

/// 2FA enrolment: the QR image, the `otpauth://` URL as text, and a code to confirm it.
pub(super) fn totp_setup_html(
    prov: &totp::Provisioning,
    totp_on: bool,
    error: Option<&str>,
    csrf: &str,
) -> String {
    render(TotpSetup { qr: &prov.qr_data_uri, url: &prov.url, totp_on, error, success: None, csrf })
}

#[derive(Template)]
#[template(path = "auth/profile.html")]
struct Profile<'a> {
    username: &'a str,
    totp_on: bool,
    recovery_left: Option<u64>,
    error: Option<&'a str>,
    success: Option<&'a str>,
    csrf: &'a str,
}

/// The self-service profile: change password, the 2FA state, recovery codes (with 2FA on) and
/// signing out other sessions.
pub(super) fn change_form_html(
    who: &Identity,
    totp_on: bool,
    recovery_left: Option<u64>,
    error: Option<&str>,
    success: Option<&str>,
    csrf: &str,
) -> String {
    render(Profile { username: &who.username, totp_on, recovery_left, error, success, csrf })
}

#[derive(Template)]
#[template(path = "auth/reset.html")]
struct Reset<'a> {
    id: &'a str,
    username: &'a str,
    totp_on: bool,
    manager_totp_on: bool,
    error: Option<&'a str>,
    success: Option<&'a str>,
    csrf: &'a str,
}

/// A manager's view of another account: set its password without the current one, and disable its
/// 2FA (a manager can't set one up for someone else).
pub(super) fn reset_form_html(
    id: &str,
    username: &str,
    totp_on: bool,
    manager_totp_on: bool,
    error: Option<&str>,
    success: Option<&str>,
    csrf: &str,
) -> String {
    render(Reset { id, username, totp_on, manager_totp_on, error, success, csrf })
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
        let pages = [
            login_form_html(Some(bad), bad),
            totp_login_html(Some(bad), bad),
            totp_setup_html(&prov, true, Some(bad), bad),
            change_form_html(&who, true, Some(2), Some(bad), None, bad),
            change_form_html(&who, false, None, None, Some(bad), bad),
            reset_form_html(bad, bad, true, true, Some(bad), None, bad),
            recovery_codes_html(&[], bad),
            sso_managed_html(bad, bad),
            sso_profile_html(&who, bad),
            csrf_rejected_html(bad),
        ];
        for html in pages {
            assert!(!html.contains("<script>") && !html.contains("\"\""), "unescaped: {html}");
            assert!(html.contains("&#60;script&#62;x&#60;/script&#62;&#34;"), "not shown: {html}");
        }
    }
}
