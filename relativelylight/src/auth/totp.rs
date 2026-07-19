//! TOTP (RFC 6238) helpers over [`totp-rs`](https://docs.rs/totp-rs): generate a secret, build the
//! `otpauth://` provisioning URL + QR image for enrolment, and verify a submitted code. Secrets are
//! stored as base32 strings (`auth_user.totp_secret` / `totp_pending`); the parameters (SHA1, 6 digits,
//! 30s step, ±1 skew) are the widely-compatible defaults every authenticator app supports.

use totp_rs::{Algorithm, Secret, TOTP};

const DIGITS: usize = 6;
const SKEW: u8 = 1; // accept the adjacent 30s windows too (clock drift)
const STEP: u64 = 30;

/// Build a `TOTP` for the given account from a stored base32 secret (`None` if the secret is invalid).
fn build(issuer: &str, account: &str, secret_b32: &str) -> Option<TOTP> {
    let bytes = Secret::Encoded(secret_b32.to_string()).to_bytes().ok()?;
    TOTP::new(Algorithm::SHA1, DIGITS, SKEW, STEP, bytes, Some(issuer.to_string()), account.to_string())
        .ok()
}

/// A freshly generated base32 secret, ready to store as `totp_pending` and show for enrolment.
pub(crate) fn generate_secret() -> String {
    // `Secret::generate_secret` is cryptographically random (feature `gen_secret`).
    Secret::generate_secret().to_encoded().to_string()
}

/// Whether `code` is valid for `secret_b32` right now (issuer/account don't affect the code, but a
/// well-formed `TOTP` is needed to check). Whitespace in the code is ignored.
pub(crate) fn verify(secret_b32: &str, code: &str) -> bool {
    match build("rl", "rl", secret_b32) {
        Some(totp) => totp.check_current(code.trim()).unwrap_or(false),
        None => false,
    }
}

/// Enrolment material for a pending secret: the `otpauth://` URL (shown as text) and a QR code as a
/// `data:image/png;base64,…` URI (shown as an `<img>`). `None` if the secret or QR can't be built.
pub(crate) struct Provisioning {
    pub url: String,
    pub qr_data_uri: String,
}

pub(crate) fn provisioning(issuer: &str, account: &str, secret_b32: &str) -> Option<Provisioning> {
    let totp = build(issuer, account, secret_b32)?;
    let url = totp.get_url();
    let qr = totp.get_qr_base64().ok()?;
    Some(Provisioning { url, qr_data_uri: format!("data:image/png;base64,{qr}") })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_secret_verifies_its_own_current_code() {
        let secret = generate_secret();
        let totp = build("relativelylight", "alice", &secret).unwrap();
        let code = totp.generate_current().unwrap();
        assert!(verify(&secret, &code));
        assert!(verify(&secret, &format!("  {code} "))); // whitespace ignored
        assert!(!verify(&secret, "000000"));
        assert!(!verify(&secret, "not-a-code"));
        assert!(!verify("not-base32!!", &code)); // bad secret → never verifies
    }

    #[test]
    fn provisioning_has_url_and_qr() {
        let secret = generate_secret();
        let p = provisioning("relativelylight", "alice", &secret).unwrap();
        assert!(p.url.starts_with("otpauth://totp/"));
        assert!(p.url.contains("relativelylight"));
        assert!(p.qr_data_uri.starts_with("data:image/png;base64,"));
    }
}
