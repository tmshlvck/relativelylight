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

/// The **step** `code` matched for `secret_b32` right now, or `None` if it matched nothing
/// (issuer/account don't affect the code, but a well-formed `TOTP` is needed to check). Whitespace in
/// the code is ignored.
///
/// Returning the step rather than a bool is what makes the replay guard possible: the caller records it
/// on the account and refuses anything that doesn't *advance* it
/// ([`user::Model::totp_step_ok`](crate::auth::user::Model::totp_step_ok)). `totp-rs`' own `check` /
/// `check_current` apply the ±[`SKEW`] window internally and answer yes/no, so they can't say *which*
/// of the three acceptable codes was presented — hence the explicit loop over candidate steps here.
///
/// Candidates are tried newest-first, so if two adjacent steps somehow yield the same six digits (a
/// ~1-in-10⁶ coincidence) the guard advances as far as it legitimately can.
pub(crate) fn verify_step(secret_b32: &str, code: &str) -> Option<i64> {
    let totp = build("rl", "rl", secret_b32)?;
    let code = code.trim();
    let base = (now_secs() / STEP) as i64;
    let skew = SKEW as i64;
    (base - skew..=base + skew)
        .rev()
        .find(|&step| crate::csrf::ct_eq(totp.generate(step as u64 * STEP).as_bytes(), code.as_bytes()))
}

/// Whether `code` is valid for `secret_b32` right now, ignoring the step (used where there is no
/// account to record a step against — the enrolment check re-reads it via [`verify_step`]).
#[cfg(test)]
pub(crate) fn verify(secret_b32: &str, code: &str) -> bool {
    verify_step(secret_b32, code).is_some()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Enrolment material for a pending secret: the `otpauth://` URL (shown as text) and a QR code as a
/// `data:image/png;base64,…` URI (shown as an `<img>`). `None` if the secret or QR can't be built.
pub(crate) struct Provisioning {
    pub url: String,
    pub qr_data_uri: String,
}

/// The code an authenticator app would show for `secret_b32` right now — test-only, so the auth
/// tests can drive the real TOTP paths (and prove the negative cases aren't vacuous).
#[cfg(test)]
pub(crate) fn current_code(secret_b32: &str) -> String {
    build("rl", "rl", secret_b32).and_then(|t| t.generate_current().ok()).expect("valid secret")
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
    fn the_matched_step_is_the_current_one_and_neighbours_are_accepted() {
        // The replay guard is only as good as this: the step returned must be the one the code belongs
        // to, or a spent code could be recorded under a step that doesn't block its reuse.
        let secret = generate_secret();
        let totp = build("relativelylight", "alice", &secret).unwrap();
        let now = now_secs();
        let base = (now / STEP) as i64;

        assert_eq!(verify_step(&secret, &totp.generate(now)), Some(base), "the current step");
        // Clock drift in both directions is still accepted (SKEW = 1), each under its own step.
        for offset in [-1i64, 1] {
            let step = base + offset;
            let code = totp.generate(step as u64 * STEP);
            assert_eq!(verify_step(&secret, &code), Some(step), "step {offset:+} must match itself");
        }
        // Two steps out is outside the window, and nonsense matches nothing.
        for step in [base - 2, base + 2] {
            assert_eq!(verify_step(&secret, &totp.generate(step as u64 * STEP)), None, "outside skew");
        }
        assert_eq!(verify_step(&secret, "000000"), None);
        assert_eq!(verify_step("not-base32!!", &totp.generate(now)), None, "bad secret");
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
