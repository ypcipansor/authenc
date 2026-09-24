//! Authorization codes and PKCE.
//!
//! A code is a bearer credential that travels through the user's browser and
//! lands in a redirect URI, which means it is routinely written to browser
//! history, referrer headers, and proxy logs. Three things keep that from
//! being fatal, and all three are enforced here rather than left to the
//! endpoint:
//!
//! * **Single use.** Redemption is one atomic `UPDATE … WHERE used_at IS
//!   NULL`, so two concurrent redemptions cannot both succeed.
//! * **Bound to the client.** The claim is scoped by `client_id`, so a
//!   different client presenting a stolen code neither redeems it nor burns
//!   it.
//! * **Bound to the requester, by PKCE.** The code alone is useless without
//!   the verifier whose hash was pinned when the code was issued (RFC 7636).
//!
//! Replay is *detected*, not merely refused: [`redeem`] reports
//! [`Redemption::Replayed`] carrying the family whose tokens must be revoked.
//! A code presented twice means it leaked, and the tokens already minted from
//! it are in the same danger as the code was.

use authenc_contract::{AppError, RealmId, Result, UserId};
use authenc_identity::{Db, SecretToken, token::constant_time_eq};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{client::ClientKey, error::OAuthError};

/// How long an authorization code stays redeemable.
///
/// RFC 6749 §4.1.2 puts the maximum at ten minutes and recommends one. A code
/// is redeemed by a back-channel call that happens within a second of the
/// redirect, so a minute is generous.
pub const CODE_LIFETIME: Duration = Duration::minutes(1);

/// The only challenge method this server accepts.
///
/// `plain` is deliberately absent. It puts the verifier in the same
/// authorization request the challenge travels in, so an attacker who can read
/// one can read the other, which is the thing PKCE exists to prevent.
pub const CHALLENGE_METHOD: &str = "S256";

/// A PKCE challenge as presented in the authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge(String);

impl Challenge {
    /// Accept a `code_challenge`/`code_challenge_method` pair.
    ///
    /// # Errors
    ///
    /// Returns `invalid_request` if the method is not `S256` or the challenge
    /// is not a plausible base64url-encoded SHA-256 digest.
    pub fn new(value: &str, method: Option<&str>) -> std::result::Result<Self, OAuthError> {
        match method {
            // RFC 7636 §4.3 defaults an absent method to `plain`, which this
            // server does not implement, so an absent method is an error
            // rather than a silent downgrade.
            Some(CHALLENGE_METHOD) => {}
            Some(other) => {
                return Err(OAuthError::invalid_request(format!(
                    "code_challenge_method '{other}' is not supported; use S256"
                )));
            }
            None => {
                return Err(OAuthError::invalid_request(
                    "code_challenge_method is required and must be S256",
                ));
            }
        }

        // A SHA-256 digest is 32 bytes, which is 43 base64url characters.
        if value.len() != 43 || !value.chars().all(is_base64url) {
            return Err(OAuthError::invalid_request(
                "code_challenge must be the base64url-encoded SHA-256 of the verifier",
            ));
        }

        Ok(Self(value.to_owned()))
    }

    /// The encoded challenge.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether a verifier hashes to this challenge.
    ///
    /// # Errors
    ///
    /// Returns `invalid_grant` if the verifier is outside the length or
    /// character set RFC 7636 §4.1 defines, or does not match.
    pub fn verify(&self, verifier: &str) -> std::result::Result<(), OAuthError> {
        if !(43..=128).contains(&verifier.len()) || !verifier.chars().all(is_verifier_char) {
            return Err(OAuthError::invalid_grant(
                "code_verifier must be 43 to 128 unreserved characters",
            ));
        }

        let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        if constant_time_eq(computed.as_bytes(), self.0.as_bytes()) {
            Ok(())
        } else {
            Err(OAuthError::invalid_grant("code_verifier does not match"))
        }
    }
}

const fn is_base64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_')
}

// RFC 7636 §4.1: ALPHA / DIGIT / "-" / "." / "_" / "~".
const fn is_verifier_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~')
}

/// What an authorization code is issued for.
#[derive(Debug, Clone)]
pub struct NewCode<'a> {
    /// The client the code is bound to.
    pub client: ClientKey,
    /// The realm.
    pub realm_id: RealmId,
    /// The user who approved it.
    pub user_id: UserId,
    /// The exact redirect URI the authorization request named.
    pub redirect_uri: &'a str,
    /// Scopes the user granted.
    pub scopes: &'a [String],
    /// `nonce` to echo into the ID token.
    pub nonce: Option<&'a str>,
    /// PKCE challenge, required for public clients.
    pub challenge: Option<&'a Challenge>,
    /// How the session that approved this authenticated, in RFC 8176 terms.
    ///
    /// A snapshot, not a lookup. By the time the code is redeemed the session
    /// may be gone, and what the account has enrolled *now* is not what was
    /// presented *then*.
    pub authenticated_with: &'a [String],
}

/// Issue an authorization code.
///
/// # Errors
///
/// Returns an internal error if entropy or the database fails.
pub async fn issue(db: &Db, new: NewCode<'_>) -> Result<SecretToken> {
    let code =
        SecretToken::generate().map_err(|e| AppError::internal_from("generating auth code", e))?;

    sqlx::query!(
        r#"
        INSERT INTO authorization_codes
            (client_id, user_id, realm_id, code_hash, redirect_uri, scopes,
             nonce, code_challenge, code_challenge_method, expires_at,
             authenticated_with)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
        new.client.0,
        new.user_id.0,
        new.realm_id.0,
        code.hash(),
        new.redirect_uri,
        new.scopes,
        new.nonce,
        new.challenge.map(Challenge::as_str),
        new.challenge.map(|_| CHALLENGE_METHOD),
        OffsetDateTime::now_utc() + CODE_LIFETIME,
        new.authenticated_with,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("storing auth code", e))?;

    Ok(code)
}

/// What a redeemed code authorises.
#[derive(Debug, Clone)]
pub struct Authorization {
    /// The code's own id. Used as the refresh-token family id, which is what
    /// lets a replayed code revoke exactly the tokens it produced.
    pub id: Uuid,
    /// The realm.
    pub realm_id: RealmId,
    /// The user.
    pub user_id: UserId,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// The `nonce` to echo into the ID token.
    pub nonce: Option<String>,
    /// How the session that approved this authenticated.
    pub authenticated_with: Vec<String>,
}

/// The outcome of presenting a code.
#[derive(Debug)]
pub enum Redemption {
    /// A live code, now spent.
    Granted(Box<Authorization>),
    /// A code that had already been spent. The caller must revoke this family
    /// and refuse the request.
    Replayed {
        /// The family whose tokens were minted from this code.
        family_id: Uuid,
    },
}

/// Redeem a code.
///
/// The claim is scoped to the client, so presenting another client's code is
/// a plain "no such grant" and does not consume it. Everything after the claim
/// — expiry, redirect URI, PKCE — can only be satisfied by the party that made
/// the authorization request, so failing those checks *after* spending the code
/// is correct: RFC 6749 §4.1.2 requires the code to be invalidated on any
/// failed redemption attempt.
///
/// # Errors
///
/// Returns `invalid_grant` for an unknown, expired, or mismatched code, and
/// `server_error` if the database fails.
pub async fn redeem(
    db: &Db,
    presented: &SecretToken,
    client: ClientKey,
    redirect_uri: &str,
    verifier: Option<&str>,
) -> std::result::Result<Redemption, OAuthError> {
    let claimed = sqlx::query!(
        r#"
        UPDATE authorization_codes
        SET used_at = now()
        WHERE code_hash = $1 AND client_id = $2 AND used_at IS NULL
        RETURNING id, realm_id, user_id, redirect_uri, scopes, nonce,
                  code_challenge, expires_at, authenticated_with
        "#,
        presented.hash(),
        client.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("redeeming auth code", e))?;

    let Some(row) = claimed else {
        // Nothing claimed. Either the code never existed, it belongs to
        // another client, or it has already been spent — and that last case is
        // the one worth acting on.
        let spent = sqlx::query!(
            "SELECT id FROM authorization_codes \
             WHERE code_hash = $1 AND client_id = $2 AND used_at IS NOT NULL",
            presented.hash(),
            client.0,
        )
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::internal_from("checking for code replay", e))?;

        return match spent {
            Some(spent) => {
                tracing::warn!(
                    code_id = %spent.id,
                    "authorization code presented twice; revoking the tokens it minted",
                );
                Ok(Redemption::Replayed {
                    family_id: spent.id,
                })
            }
            None => Err(OAuthError::invalid_grant(
                "authorization code is invalid or has expired",
            )),
        };
    };

    if row.expires_at <= OffsetDateTime::now_utc() {
        return Err(OAuthError::invalid_grant("authorization code has expired"));
    }

    // RFC 6749 §4.1.3: the redirect URI presented at the token endpoint must
    // be identical to the one the code was issued against.
    if row.redirect_uri != redirect_uri {
        return Err(OAuthError::invalid_grant(
            "redirect_uri does not match the authorization request",
        ));
    }

    match (row.code_challenge.as_deref(), verifier) {
        (Some(challenge), Some(verifier)) => {
            Challenge(challenge.to_owned()).verify(verifier)?;
        }
        (Some(_), None) => {
            return Err(OAuthError::invalid_grant(
                "code_verifier is required for this authorization",
            ));
        }
        // A verifier for a code issued without a challenge is a downgrade
        // attempt: accepting it would let an attacker who intercepted the code
        // supply any verifier they like.
        (None, Some(_)) => {
            return Err(OAuthError::invalid_grant(
                "this authorization was issued without PKCE",
            ));
        }
        (None, None) => {}
    }

    Ok(Redemption::Granted(Box::new(Authorization {
        id: row.id,
        realm_id: RealmId(row.realm_id),
        user_id: UserId(row.user_id),
        scopes: row.scopes,
        nonce: row.nonce,
        authenticated_with: row.authenticated_with,
    })))
}

/// Delete codes that can no longer be redeemed.
///
/// Spent codes are kept for one lifetime past expiry so replay stays
/// detectable for as long as a replay could plausibly arrive.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn purge_expired(db: &Db) -> Result<u64> {
    let removed = sqlx::query!(
        "DELETE FROM authorization_codes WHERE expires_at < now() - INTERVAL '1 hour'",
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("purging auth codes", e))?
    .rows_affected();

    Ok(removed)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "a failed setup step should fail the test"
)]
mod tests {
    use super::*;
    use crate::test_support;

    /// The `amr` of an ordinary password login, which is what these fixtures
    /// stand in for. The MFA variants are exercised in `authenc-identity`.
    ///
    /// A `static` rather than a function: the structs below borrow it, and a
    /// freshly built `Vec` would not outlive the expression that borrows it.
    static PWD: std::sync::LazyLock<Vec<String>> =
        std::sync::LazyLock::new(|| vec!["pwd".to_owned()]);
    use crate::client::{self, NewClient};
    use authenc_identity::{PasswordHasher, realm, user::NewUser};

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }

    fn challenge_for(verifier: &str) -> Challenge {
        let encoded = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Challenge::new(&encoded, Some(CHALLENGE_METHOD)).unwrap()
    }

    struct Fixture {
        realm_id: RealmId,
        user_id: UserId,
        client: ClientKey,
    }

    async fn fixture(db: &Db) -> Fixture {
        let hasher = PasswordHasher::new();
        let realm = realm::create(db, "master", "Master").await.unwrap();
        let user = authenc_identity::user::create(
            db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "ada",
                email: "ada@example.com",
                password: test_support::password(),
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap();

        let uris = owned(&["https://app.example.com/callback"]);
        let registered = client::register(
            db,
            &hasher,
            NewClient {
                realm_id: realm.id,
                client_id: Some("spa"),
                name: "SPA",
                is_public: true,
                redirect_uris: &uris,
                grant_types: &[],
                scopes: &[],
                require_consent: false,
            },
        )
        .await
        .unwrap();

        Fixture {
            realm_id: realm.id,
            user_id: user.id,
            client: registered.client.key,
        }
    }

    async fn issue_for(db: &Db, f: &Fixture, challenge: Option<&Challenge>) -> SecretToken {
        let scopes = owned(&["openid"]);
        issue(
            db,
            NewCode {
                authenticated_with: &PWD,
                client: f.client,
                realm_id: f.realm_id,
                user_id: f.user_id,
                redirect_uri: "https://app.example.com/callback",
                scopes: &scopes,
                nonce: Some("n-0S6_WzA2Mj"),
                challenge,
            },
        )
        .await
        .unwrap()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_code_redeems_once_and_carries_what_was_authorised(db: Db) {
        let f = fixture(&db).await;
        let challenge = challenge_for(VERIFIER);
        let code = issue_for(&db, &f, Some(&challenge)).await;

        let redeemed = redeem(
            &db,
            &code,
            f.client,
            "https://app.example.com/callback",
            Some(VERIFIER),
        )
        .await
        .unwrap();

        let Redemption::Granted(auth) = redeemed else {
            panic!("first redemption should be granted");
        };
        assert_eq!(auth.user_id, f.user_id);
        assert_eq!(auth.scopes, owned(&["openid"]));
        assert_eq!(auth.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn presenting_a_code_twice_is_reported_as_replay_not_merely_refused(db: Db) {
        // The difference matters: a refusal leaves the tokens the first
        // redemption minted alive in the thief's hands.
        let f = fixture(&db).await;
        let challenge = challenge_for(VERIFIER);
        let code = issue_for(&db, &f, Some(&challenge)).await;

        let first = redeem(
            &db,
            &code,
            f.client,
            "https://app.example.com/callback",
            Some(VERIFIER),
        )
        .await
        .unwrap();
        let Redemption::Granted(auth) = first else {
            panic!("first redemption should be granted");
        };

        let second = redeem(
            &db,
            &code,
            f.client,
            "https://app.example.com/callback",
            Some(VERIFIER),
        )
        .await
        .unwrap();

        match second {
            Redemption::Replayed { family_id } => assert_eq!(
                family_id, auth.id,
                "the reported family must be the one this code minted",
            ),
            Redemption::Granted(_) => panic!("a spent code must never grant twice"),
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_stolen_code_is_useless_without_the_verifier(db: Db) {
        let f = fixture(&db).await;
        let challenge = challenge_for(VERIFIER);
        let code = issue_for(&db, &f, Some(&challenge)).await;

        let error = redeem(
            &db,
            &code,
            f.client,
            "https://app.example.com/callback",
            Some("Xy9tOEcJvVXBpN5hqLmZrTfKdWgQsAuIeYoP1234567"),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, crate::error::OAuthErrorCode::InvalidGrant);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn omitting_the_verifier_does_not_bypass_pkce(db: Db) {
        let f = fixture(&db).await;
        let challenge = challenge_for(VERIFIER);
        let code = issue_for(&db, &f, Some(&challenge)).await;

        let error = redeem(
            &db,
            &code,
            f.client,
            "https://app.example.com/callback",
            None,
        )
        .await
        .unwrap_err();
        assert!(error.description.contains("code_verifier"), "{error}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn another_clients_code_is_neither_redeemed_nor_burned(db: Db) {
        let f = fixture(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://other.example.com/callback"]);
        let other = client::register(
            &db,
            &hasher,
            NewClient {
                realm_id: f.realm_id,
                client_id: Some("other"),
                name: "Other",
                is_public: true,
                redirect_uris: &uris,
                grant_types: &[],
                scopes: &[],
                require_consent: false,
            },
        )
        .await
        .unwrap();

        let challenge = challenge_for(VERIFIER);
        let code = issue_for(&db, &f, Some(&challenge)).await;

        let error = redeem(
            &db,
            &code,
            other.client.key,
            "https://app.example.com/callback",
            Some(VERIFIER),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, crate::error::OAuthErrorCode::InvalidGrant);

        // The rightful client must still be able to use it: otherwise anyone
        // who learns a code can deny service by presenting it as someone else.
        assert!(matches!(
            redeem(
                &db,
                &code,
                f.client,
                "https://app.example.com/callback",
                Some(VERIFIER),
            )
            .await
            .unwrap(),
            Redemption::Granted(_),
        ));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_redirect_uri_must_match_the_authorization_request(db: Db) {
        let f = fixture(&db).await;
        let challenge = challenge_for(VERIFIER);
        let code = issue_for(&db, &f, Some(&challenge)).await;

        let error = redeem(
            &db,
            &code,
            f.client,
            "https://app.example.com/callback2",
            Some(VERIFIER),
        )
        .await
        .unwrap_err();
        assert!(error.description.contains("redirect_uri"), "{error}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_expired_code_is_refused(db: Db) {
        let f = fixture(&db).await;
        let code = issue_for(&db, &f, None).await;

        sqlx::query!(
            "UPDATE authorization_codes SET expires_at = now() - INTERVAL '1 second' \
             WHERE code_hash = $1",
            code.hash(),
        )
        .execute(&db)
        .await
        .unwrap();

        let error = redeem(
            &db,
            &code,
            f.client,
            "https://app.example.com/callback",
            None,
        )
        .await
        .unwrap_err();
        assert!(error.description.contains("expired"), "{error}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_verifier_cannot_be_supplied_for_a_code_issued_without_a_challenge(db: Db) {
        // Otherwise an intercepted code could be redeemed with any verifier at
        // all, which is PKCE's whole failure mode.
        let f = fixture(&db).await;
        let code = issue_for(&db, &f, None).await;

        let error = redeem(
            &db,
            &code,
            f.client,
            "https://app.example.com/callback",
            Some(VERIFIER),
        )
        .await
        .unwrap_err();
        assert!(error.description.contains("without PKCE"), "{error}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_code_itself_is_never_stored(db: Db) {
        let f = fixture(&db).await;
        let code = issue_for(&db, &f, None).await;

        let stored: Vec<u8> =
            sqlx::query_scalar!("SELECT code_hash FROM authorization_codes LIMIT 1")
                .fetch_one(&db)
                .await
                .unwrap();

        assert_eq!(stored, code.hash());
        assert!(!stored.starts_with(code.expose().as_bytes()));
    }

    #[test]
    fn only_s256_is_accepted_as_a_challenge_method() {
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()));

        assert!(Challenge::new(&digest, Some("S256")).is_ok());
        // `plain` puts the verifier in the same message as the challenge.
        assert!(Challenge::new(VERIFIER, Some("plain")).is_err());
        // RFC 7636 defaults an absent method to `plain`, so absent is refused.
        assert!(Challenge::new(&digest, None).is_err());
    }

    #[test]
    fn a_challenge_that_is_not_a_sha256_digest_is_refused() {
        assert!(Challenge::new("too-short", Some("S256")).is_err());
        assert!(Challenge::new(&"a".repeat(43), Some("S256")).is_ok());
        assert!(Challenge::new(&"a".repeat(44), Some("S256")).is_err());
        assert!(Challenge::new(&format!("{}+", "a".repeat(42)), Some("S256")).is_err());
    }

    #[test]
    fn a_verifier_outside_the_specified_length_is_refused() {
        let challenge = challenge_for(VERIFIER);
        assert!(challenge.verify(VERIFIER).is_ok());

        // Too short to carry the entropy PKCE assumes.
        assert!(challenge_for("short").verify("short").is_err());
        // Too long.
        let long = "a".repeat(129);
        assert!(challenge_for(&long).verify(&long).is_err());
    }
}
