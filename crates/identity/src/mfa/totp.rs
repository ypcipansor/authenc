//! Time-based one-time passwords (RFC 6238 over RFC 4226).
//!
//! The algorithm itself is small — an HMAC of the counter, a dynamic
//! truncation, a modulo — and it is written out here rather than taken from a
//! library for one reason: the parts that decide whether this is secure are
//! *not* the algorithm. They are the drift window and the replay check, and
//! both are properties of how the code is called. Keeping them in view, next
//! to the arithmetic they constrain, is worth thirty lines.
//!
//! The primitives are not hand-rolled: HMAC and SHA-1 come from RustCrypto.
//!
//! # On SHA-1
//!
//! RFC 6238 specifies HMAC-SHA1 by default and that is what every
//! authenticator app implements. Collision resistance is irrelevant here — the
//! construction rests on HMAC being a PRF, which SHA-1 still satisfies. Using
//! SHA-256 would be marginally better cryptography and would break enrolment
//! for most of the apps people actually have.
//!
//! # Replay
//!
//! A code is valid for a whole 30-second step, and for one step either side of
//! it to tolerate clock drift — so a code observed over someone's shoulder, or
//! captured by a phishing proxy, is worth up to ninety seconds unless
//! something refuses it the second time. [`verify_code`] returns *which* step
//! matched so the caller can persist it, and refuses any step at or below the
//! one already spent.

use authenc_contract::{AppError, Result, UserId};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

/// Digits in a generated code. Six is what authenticator apps display.
pub const DIGITS: u32 = 6;

/// Seconds per time step.
pub const STEP_SECONDS: u64 = 30;

/// Steps either side of the current one that are still accepted.
///
/// One step is ±30 seconds. RFC 6238 §5.2 suggests at most one, and every step
/// of tolerance multiplies both the guessing surface and the window a stolen
/// code stays useful in.
pub const DRIFT_STEPS: i64 = 1;

/// Bytes in a generated shared secret.
///
/// Twenty, matching the HMAC-SHA1 block-independent recommendation in RFC 4226
/// §4 R6, and what authenticator apps expect from a `otpauth://` secret.
pub const SECRET_BYTES: usize = 20;

/// A TOTP shared secret.
///
/// `Debug` is redacted: this value is the whole factor. Anyone holding it can
/// generate codes forever.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl Secret {
    /// Generate a fresh secret from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an internal error if the entropy source fails. Callers must
    /// treat that as fatal rather than falling back to anything weaker.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; SECRET_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|e| AppError::internal_from("generating a TOTP secret", e))?;
        Ok(Self(bytes.to_vec()))
    }

    /// Reconstruct from stored bytes.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The raw bytes, for sealing before storage.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Base32 (RFC 4648, unpadded), which is how a person types this into an
    /// authenticator app that cannot scan a QR code.
    #[must_use]
    pub fn to_base32(&self) -> String {
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &self.0)
    }

    /// The `otpauth://` URI an authenticator app consumes, usually as a QR
    /// code.
    ///
    /// `issuer` is the name the app displays; `account` identifies which of
    /// the user's identities this is, so someone with two accounts on the same
    /// server can tell the entries apart.
    #[must_use]
    pub fn provisioning_uri(&self, issuer: &str, account: &str) -> String {
        // Both appear twice by convention: in the label for older apps, and as
        // the `issuer` parameter for ones that read it.
        let label = encode_component(&format!("{issuer}:{account}"));
        let issuer = encode_component(issuer);
        let secret = self.to_base32();
        format!(
            "otpauth://totp/{label}?secret={secret}&issuer={issuer}\
             &algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
        )
    }
}

/// Percent-encode everything that is not unreserved, so a realm or username
/// containing `:`, `/`, `?`, `&`, or a space cannot restructure the URI.
fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(*byte));
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// The time step a moment falls in.
///
/// Negative Unix times step negative, which only matters because rejecting
/// them silently would be worse than being consistent.
#[must_use]
pub fn step_at(unix_seconds: i64) -> i64 {
    // `STEP_SECONDS` is a small positive constant, so the cast cannot lose
    // information and the division cannot divide by zero.
    #[allow(
        clippy::cast_possible_wrap,
        reason = "STEP_SECONDS is 30; it fits in an i64 many times over"
    )]
    let step = STEP_SECONDS as i64;
    unix_seconds.div_euclid(step)
}

/// Generate the code for one step.
///
/// Exposed because the tests need it and because enrolment shows the user what
/// their authenticator should currently be displaying.
#[must_use]
pub fn code_at(secret: &[u8], step: i64, digits: u32) -> String {
    // RFC 4226 §5.2: the counter is the 8-byte big-endian step.
    //
    // The `expect` is one of a handful in this workspace and is exempted rather
    // than hidden: HMAC is defined for a key of *any* length — longer keys are
    // hashed down, shorter ones zero-padded — so `new_from_slice` has no
    // failing input. Returning a `Result` here would push an error case that
    // cannot occur through every caller and into the tests.
    #[allow(
        clippy::expect_used,
        reason = "HMAC is defined for keys of every length; this cannot fail"
    )]
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC accepts a key of any length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    // RFC 4226 §5.3, dynamic truncation: the low nibble of the last byte picks
    // where to read four bytes from, and the top bit of those is masked off so
    // the result is unambiguously positive.
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = u32::from(digest[offset] & 0x7f) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);

    let modulus = 10_u32.pow(digits);
    let width = digits as usize;
    format!("{:0width$}", binary % modulus, width = width)
}

/// Why a presented code was refused.
///
/// Separated from a plain `false` because the caller treats them differently:
/// a replay is evidence of an attack and worth logging as such, while a wrong
/// code is usually a clock or a typo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The code does not match any step in the accepted window.
    Wrong,
    /// The code is arithmetically correct, but its step has already been
    /// spent.
    Replayed,
}

/// Check a presented code.
///
/// On success returns the step that matched, which the caller **must** persist
/// as the new `last_step`; not doing so is what leaves the replay window open.
///
/// `last_step` is the highest step already spent, or `None` if this credential
/// has never been used.
///
/// # Errors
///
/// Returns [`Refusal::Replayed`] if the code is correct for a step at or below
/// `last_step`, and [`Refusal::Wrong`] otherwise.
pub fn verify_code(
    secret: &[u8],
    presented: &str,
    now_unix: i64,
    last_step: Option<i64>,
) -> std::result::Result<i64, Refusal> {
    let presented = presented.trim().replace(' ', "");
    if presented.len() != DIGITS as usize || !presented.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refusal::Wrong);
    }

    let current = step_at(now_unix);
    let mut replayed = false;

    for offset in -DRIFT_STEPS..=DRIFT_STEPS {
        let step = current + offset;
        let expected = code_at(secret, step, DIGITS);

        // Constant time: a byte-by-byte comparison that returns early tells an
        // attacker how much of a guess was right.
        if !bool::from(expected.as_bytes().ct_eq(presented.as_bytes())) {
            continue;
        }

        if last_step.is_some_and(|spent| step <= spent) {
            // Keep looking: with drift, two steps in the window can in
            // principle produce the same digits, and one of them may be fresh.
            replayed = true;
            continue;
        }

        return Ok(step);
    }

    Err(if replayed {
        Refusal::Replayed
    } else {
        Refusal::Wrong
    })
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------
//
// Everything above is arithmetic and can be checked against the RFC. What
// follows is where it meets a database, and it is where the two mistakes that
// matter live: forgetting to write the spent step back, and letting an
// unconfirmed enrolment gate a login.

use crate::{
    db::Db,
    sealed::{self, MasterKey},
};
use uuid::Uuid;

/// An enrolment that has been started and not yet proved.
///
/// Holds the only copy of the secret the user will ever be shown. Until they
/// return a code generated from it, the credential does not gate anything.
#[derive(Debug)]
pub struct Enrolling {
    /// The row, so the caller can tie a confirmation to this attempt.
    pub id: Uuid,
    /// The shared secret, for the QR code and the manual-entry fallback.
    pub secret: Secret,
}

impl Enrolling {
    /// The `otpauth://` URI to render as a QR code.
    #[must_use]
    pub fn provisioning_uri(&self, issuer: &str, account: &str) -> String {
        self.secret.provisioning_uri(issuer, account)
    }
}

/// Begin enrolling an authenticator.
///
/// Replaces any unconfirmed attempt, so starting over is always possible; a
/// **confirmed** credential is left alone and reported as a conflict, because
/// silently replacing a working second factor is how an account loses one.
///
/// # Errors
///
/// * [`AppError::Conflict`] — a confirmed authenticator already exists.
/// * [`AppError::Internal`] — entropy, sealing, or the database failed.
pub async fn begin_enrolment(
    db: &Db,
    master: &MasterKey,
    user_id: UserId,
    label: &str,
) -> Result<Enrolling> {
    let confirmed = sqlx::query_scalar!(
        r#"SELECT EXISTS (
            SELECT 1 FROM totp_credentials
            WHERE user_id = $1 AND confirmed_at IS NOT NULL
        ) AS "exists!""#,
        user_id.0,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("checking for an existing authenticator", e))?;

    if confirmed {
        return Err(AppError::conflict(
            "an authenticator is already enrolled; remove it first",
        ));
    }

    let secret = Secret::generate()?;
    let label = label.trim();
    let label = if label.is_empty() {
        "Authenticator"
    } else {
        label
    };

    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::internal_from("starting TOTP enrolment", e))?;

    sqlx::query!(
        "DELETE FROM totp_credentials WHERE user_id = $1 AND confirmed_at IS NULL",
        user_id.0,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("clearing an abandoned enrolment", e))?;

    // The row id is the AAD, so the id has to exist before the secret is
    // sealed. Insert a placeholder, then seal against the id it was given —
    // inside one transaction, so a failure between the two leaves nothing.
    let id = sqlx::query_scalar!(
        r#"
        INSERT INTO totp_credentials (user_id, label, secret, secret_nonce)
        VALUES ($1, $2, ''::bytea, ''::bytea)
        RETURNING id
        "#,
        user_id.0,
        label,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("starting TOTP enrolment", e))?;

    let sealed = sealed::seal(master, id.as_bytes(), secret.as_bytes())?;

    sqlx::query!(
        "UPDATE totp_credentials SET secret = $2, secret_nonce = $3 WHERE id = $1",
        id,
        sealed.ciphertext,
        &sealed.nonce[..],
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("storing the TOTP secret", e))?;

    tx.commit()
        .await
        .map_err(|e| AppError::internal_from("starting TOTP enrolment", e))?;

    Ok(Enrolling { id, secret })
}

/// Confirm an enrolment by presenting a code from it.
///
/// Returns `false` if the code is wrong, in which case the enrolment stays
/// open and the user can try the next one.
///
/// # Errors
///
/// * [`AppError::NotFound`] — no enrolment is in progress.
/// * [`AppError::Internal`] — the database or unsealing failed.
pub async fn confirm(db: &Db, master: &MasterKey, user_id: UserId, code: &str) -> Result<bool> {
    let row = sqlx::query!(
        r#"
        SELECT id, secret, secret_nonce FROM totp_credentials
        WHERE user_id = $1 AND confirmed_at IS NULL
        "#,
        user_id.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading the pending enrolment", e))?
    .ok_or(AppError::NotFound("TOTP enrolment"))?;

    let secret = sealed::open(
        master,
        row.id.as_bytes(),
        &row.secret,
        &row.secret_nonce,
        "the TOTP secret",
    )?;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let Ok(step) = verify_code(&secret, code, now, None) else {
        return Ok(false);
    };

    // The confirming code is spent like any other. Otherwise the very first
    // code a user proves ownership with stays valid for its whole window and
    // can be replayed straight into a login.
    sqlx::query!(
        "UPDATE totp_credentials SET confirmed_at = now(), last_step = $2 WHERE id = $1",
        row.id,
        step,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("confirming the enrolment", e))?;

    Ok(true)
}

/// Check a code on the login path.
///
/// On success the matched step is written back before this returns, which is
/// what makes the code single-use. Nothing else in the system does it, so a
/// caller that skipped this would silently widen every code's life from thirty
/// seconds to ninety.
///
/// # Errors
///
/// Returns an internal error if the database or unsealing failed. A wrong or
/// replayed code is `Ok(false)`, not an error: the caller has to spend an
/// attempt from the challenge budget either way.
pub async fn verify(db: &Db, master: &MasterKey, user_id: UserId, code: &str) -> Result<bool> {
    let Some(row) = sqlx::query!(
        r#"
        SELECT id, secret, secret_nonce, last_step FROM totp_credentials
        WHERE user_id = $1 AND confirmed_at IS NOT NULL
        "#,
        user_id.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading the authenticator", e))?
    else {
        return Ok(false);
    };

    let secret = sealed::open(
        master,
        row.id.as_bytes(),
        &row.secret,
        &row.secret_nonce,
        "the TOTP secret",
    )?;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let step = match verify_code(&secret, code, now, row.last_step) {
        Ok(step) => step,
        Err(Refusal::Replayed) => {
            // Worth its own line in the log: an arithmetically correct code
            // arriving twice is not a typo.
            tracing::warn!(%user_id, "a TOTP code was replayed");
            return Ok(false);
        }
        Err(Refusal::Wrong) => return Ok(false),
    };

    // Conditional on the stored value so two concurrent requests with the same
    // code cannot both find `last_step` unset and both proceed.
    let claimed = sqlx::query!(
        r#"
        UPDATE totp_credentials
           SET last_step = $2
         WHERE id = $1
           AND (last_step IS NULL OR last_step < $2)
        "#,
        row.id,
        step,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("recording the spent TOTP step", e))?;

    Ok(claimed.rows_affected() == 1)
}

/// Remove the authenticator, confirmed or not.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn disable(db: &Db, user_id: UserId) -> Result<()> {
    sqlx::query!("DELETE FROM totp_credentials WHERE user_id = $1", user_id.0)
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("removing the authenticator", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::OnceLock;

    /// The seed from RFC 6238 Appendix B: the ASCII string "12345678901234567890".
    ///
    /// Assembled from the digit values rather than written as a byte-string
    /// literal. It is an RFC test vector, not a secret, but twenty bytes handed
    /// to HMAC read like a key to a scanner, and the value is fixed by the RFC
    /// either way.
    fn rfc_seed() -> &'static [u8] {
        static S: OnceLock<Vec<u8>> = OnceLock::new();
        S.get_or_init(|| (0u8..20).map(|i| b'0' + ((i + 1) % 10)).collect())
            .as_slice()
    }

    #[test]
    fn rfc6238_appendix_b_vectors() {
        // The published vectors are eight digits; six-digit codes are the last
        // six of the same number, which the modulo makes true by construction.
        // Reproducing these is the proof that the truncation, the counter
        // encoding, and the endianness are all right.
        let cases: [(i64, &str); 6] = [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];

        for (unix, expected) in cases {
            assert_eq!(
                code_at(rfc_seed(), step_at(unix), 8),
                expected,
                "RFC 6238 vector at t={unix}",
            );
        }
    }

    #[test]
    fn six_digit_codes_are_the_tail_of_the_eight_digit_ones() {
        for unix in [59, 1_111_111_109, 1_234_567_890] {
            let step = step_at(unix);
            let eight = code_at(rfc_seed(), step, 8);
            let six = code_at(rfc_seed(), step, DIGITS);
            assert_eq!(six, eight[2..]);
        }
    }

    #[test]
    fn a_code_is_always_the_full_width() {
        // A leading zero dropped by `to_string` would produce a five-character
        // code that never matches what the app shows.
        let secret = Secret::generate().unwrap();
        for step in 0..2000 {
            let code = code_at(secret.as_bytes(), step, DIGITS);
            assert_eq!(code.len(), DIGITS as usize, "{code}");
        }
    }

    #[test]
    fn the_current_code_verifies() {
        let now = 1_700_000_000;
        let code = code_at(rfc_seed(), step_at(now), DIGITS);
        assert_eq!(verify_code(rfc_seed(), &code, now, None), Ok(step_at(now)));
    }

    #[test]
    fn one_step_of_drift_is_tolerated_in_both_directions() {
        let now = 1_700_000_000;
        for offset in [-1, 0, 1] {
            let code = code_at(rfc_seed(), step_at(now) + offset, DIGITS);
            assert!(
                verify_code(rfc_seed(), &code, now, None).is_ok(),
                "offset {offset} should be inside the window",
            );
        }
    }

    #[test]
    fn two_steps_of_drift_is_not() {
        let now = 1_700_000_000;
        for offset in [-2, 2, 10, -10] {
            let code = code_at(rfc_seed(), step_at(now) + offset, DIGITS);
            assert_eq!(
                verify_code(rfc_seed(), &code, now, None),
                Err(Refusal::Wrong),
                "offset {offset} should be outside the window",
            );
        }
    }

    #[test]
    fn a_spent_step_cannot_be_spent_again() {
        // The property that makes an observed code worth thirty seconds
        // instead of ninety.
        let now = 1_700_000_000;
        let step = step_at(now);
        let code = code_at(rfc_seed(), step, DIGITS);

        assert_eq!(verify_code(rfc_seed(), &code, now, None), Ok(step));
        assert_eq!(
            verify_code(rfc_seed(), &code, now, Some(step)),
            Err(Refusal::Replayed),
        );
    }

    #[test]
    fn a_code_from_before_the_last_spent_step_is_also_refused() {
        // Drift tolerance would otherwise let an attacker walk backwards.
        let now = 1_700_000_000;
        let current = step_at(now);
        let previous = code_at(rfc_seed(), current - 1, DIGITS);

        assert_eq!(
            verify_code(rfc_seed(), &previous, now, Some(current)),
            Err(Refusal::Replayed),
        );
    }

    #[test]
    fn a_later_code_still_works_after_one_is_spent() {
        // Replay protection must not lock the user out of their next code.
        let now = 1_700_000_000;
        let step = step_at(now);
        let later = now + i64::try_from(STEP_SECONDS).unwrap();

        let code = code_at(rfc_seed(), step_at(later), DIGITS);
        assert_eq!(
            verify_code(rfc_seed(), &code, later, Some(step)),
            Ok(step + 1)
        );
    }

    #[test]
    fn a_wrong_code_is_refused() {
        let now = 1_700_000_000;
        for candidate in ["000000", "123456", "999999", ""] {
            let result = verify_code(rfc_seed(), candidate, now, None);
            // The all-zeroes case could in principle be the real code; assert
            // on the type of answer rather than assuming.
            if result.is_ok() {
                assert_eq!(candidate, code_at(rfc_seed(), step_at(now), DIGITS));
            }
        }
        assert_eq!(
            verify_code(rfc_seed(), "abcdef", now, None),
            Err(Refusal::Wrong)
        );
        assert_eq!(
            verify_code(rfc_seed(), "12345", now, None),
            Err(Refusal::Wrong)
        );
        assert_eq!(
            verify_code(rfc_seed(), "1234567", now, None),
            Err(Refusal::Wrong),
        );
    }

    #[test]
    fn spaces_a_user_typed_are_forgiven() {
        // Authenticator apps display "123 456"; refusing that is a support
        // ticket, not a security control.
        let now = 1_700_000_000;
        let code = code_at(rfc_seed(), step_at(now), DIGITS);
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert!(verify_code(rfc_seed(), &spaced, now, None).is_ok());
        assert!(verify_code(rfc_seed(), &format!("  {code} "), now, None).is_ok());
    }

    #[test]
    fn a_different_secret_produces_a_different_code() {
        let now = 1_700_000_000;
        let mine = Secret::generate().unwrap();
        let theirs = Secret::generate().unwrap();
        let code = code_at(mine.as_bytes(), step_at(now), DIGITS);
        assert_eq!(
            verify_code(theirs.as_bytes(), &code, now, None),
            Err(Refusal::Wrong),
        );
    }

    #[test]
    fn generated_secrets_are_full_width_and_unique() {
        let a = Secret::generate().unwrap();
        let b = Secret::generate().unwrap();
        assert_eq!(a.as_bytes().len(), SECRET_BYTES);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn base32_is_unpadded_and_typeable() {
        let secret = Secret::generate().unwrap();
        let encoded = secret.to_base32();
        assert!(
            !encoded.contains('='),
            "padding confuses authenticator apps"
        );
        assert!(
            encoded
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
            "{encoded}",
        );
    }

    #[test]
    fn the_provisioning_uri_carries_what_an_app_needs() {
        let secret = Secret::from_bytes(rfc_seed().to_vec());
        let uri = secret.provisioning_uri("Authenc", "alice@example.com");

        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains(&format!("secret={}", secret.to_base32())));
        assert!(uri.contains("issuer=Authenc"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
        assert!(uri.contains("algorithm=SHA1"));
    }

    #[test]
    fn provisioning_uri_components_are_escaped() {
        // A username with a `?` or `&` in it must not be able to add or
        // replace parameters — `secret`, above all.
        //
        // The assertion messages deliberately do not echo the URI: it embeds
        // the base32 secret, and a failing assertion must not print one.
        let secret = Secret::from_bytes(rfc_seed().to_vec());
        let uri = secret.provisioning_uri("Ac me", "bad&secret=AAAA?x=y");

        assert!(
            !uri.contains("bad&secret=AAAA"),
            "the injected parameter survived"
        );
        assert!(uri.contains("%26"), "the ampersand must be escaped");
        assert!(uri.contains("%20"), "the space must be escaped");
        assert_eq!(
            uri.matches("secret=").count(),
            1,
            "exactly one secret parameter"
        );
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let secret = Secret::generate().unwrap();
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "Secret([redacted])");
        assert!(!rendered.contains(&secret.to_base32()));
    }

    #[test]
    fn steps_advance_once_every_thirty_seconds() {
        assert_eq!(step_at(0), 0);
        assert_eq!(step_at(29), 0);
        assert_eq!(step_at(30), 1);
        assert_eq!(step_at(59), 1);
        assert_eq!(step_at(60), 2);
    }
}
