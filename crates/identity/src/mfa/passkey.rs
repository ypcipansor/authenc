//! WebAuthn passkeys.
//!
//! # Why this is a thin wrapper and not an implementation
//!
//! Verifying a WebAuthn assertion means parsing CBOR, decoding COSE keys,
//! checking an X.509 chain for attested credentials, and verifying a signature
//! under whichever of several algorithms the authenticator chose — over a
//! message that has to be reassembled byte-for-byte from the client data hash
//! and the authenticator data. Every one of those is a place to be subtly
//! wrong in a way that still returns `true`.
//!
//! The previous tree wrote its own. `verify_registration` and
//! `verify_authentication` both ended in `Ok(true)`, having read none of their
//! arguments. That is the honest outcome of trying to do this by hand under
//! time pressure, and it is why the work here is confined to *storing* things
//! correctly and letting `webauthn-rs` decide whether a signature is good.
//!
//! # What this module is responsible for
//!
//! Three things the library cannot do for us, each of which breaks the scheme
//! if it is done carelessly:
//!
//! 1. **The challenge must live on the server.** A challenge the client
//!    chooses, or one handed back to it in a cookie it can replay, is not a
//!    challenge. Ceremony state goes in a table, keyed by an opaque token,
//!    single-use and expiring.
//! 2. **The signature counter must be written back.** `webauthn-rs` compares
//!    the counter in the assertion against the one in the stored credential
//!    and refuses a regression — but only against what we last saved. Not
//!    persisting the new value turns the whole anti-cloning mechanism into
//!    decoration.
//! 3. **The credential must belong to the user being authenticated.** The
//!    library checks the assertion against the credentials we put in the
//!    ceremony; we check that the credential it names is still one of this
//!    user's, so a key deleted mid-ceremony cannot complete a login.

use authenc_contract::{AppError, Result, UserId, model::User};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{
        CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
        PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url,
    },
};

use crate::{db::Db, token::SecretToken};

/// How long a ceremony may stay open.
///
/// Long enough to find a security key in a drawer, short enough that a
/// challenge left behind on a shared machine has expired before anyone could
/// use it.
pub const CEREMONY_LIFETIME: Duration = Duration::minutes(5);

/// The relying party: who is asking, and from where.
///
/// Both halves are load-bearing and neither may be guessed from the request.
/// The RP ID scopes which origins an authenticator will answer, and the origin
/// is compared against the one the browser reports — so taking either from a
/// `Host` header would let whoever controls that header redirect the ceremony
/// to a site they own.
pub struct RelyingParty {
    inner: Webauthn,
}

impl std::fmt::Debug for RelyingParty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelyingParty")
    }
}

impl RelyingParty {
    /// Build from the configured public origin.
    ///
    /// `origin` is the exact origin the console is served from; `name` is what
    /// the authenticator shows the user when it asks them to confirm.
    ///
    /// # Errors
    ///
    /// Returns a validation error if the origin is not a URL, has no host, or
    /// does not agree with the derived RP ID.
    pub fn new(origin: &str, name: &str) -> Result<Self> {
        let url = Url::parse(origin)
            .map_err(|_| AppError::validation(format!("{origin} is not a valid URL")))?;

        // The RP ID is the origin's host, always. Deriving it rather than
        // configuring it separately removes the failure where the two disagree
        // and every ceremony is rejected by the browser with a message that
        // does not say why.
        let rp_id = url
            .host_str()
            .ok_or_else(|| AppError::validation(format!("{origin} has no host")))?
            .to_owned();

        let inner = WebauthnBuilder::new(&rp_id, &url)
            .map_err(|e| AppError::internal_from("configuring WebAuthn", e))?
            .rp_name(name)
            .build()
            .map_err(|e| AppError::internal_from("configuring WebAuthn", e))?;

        Ok(Self { inner })
    }
}

/// A registered passkey, as the account page sees it.
///
/// Carries no key material: what the console needs is which keys exist and
/// when they were last used, and a public key in a JSON response is a
/// fingerprint that follows the user across sites.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Registered {
    /// Stable identifier, for renaming and removal.
    pub id: Uuid,
    /// What the user called it.
    pub label: String,
    /// When it was registered.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it was last used to sign in, if ever.
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
}

/// What kind of ceremony a stored state belongs to.
///
/// Recorded so a registration state can never be fed to the authentication
/// finisher or the other way round.
const REGISTRATION: &str = "registration";
const AUTHENTICATION: &str = "authentication";

/// Begin registering a new passkey.
///
/// Returns the challenge for the browser and the opaque token that identifies
/// this ceremony, which the caller sends back with the finished credential.
///
/// # Errors
///
/// Returns an internal error if the ceremony cannot be started or stored.
pub async fn begin_registration(
    db: &Db,
    rp: &RelyingParty,
    user: &User,
) -> Result<(CreationChallengeResponse, SecretToken)> {
    // Excluding what is already registered is what stops one authenticator
    // being enrolled twice — which would otherwise produce two rows whose
    // counters advance independently and neither of which ever looks stale.
    let existing = credentials_for(db, user.id).await?;
    let exclude = existing
        .iter()
        .map(|(_, passkey)| passkey.cred_id().clone())
        .collect::<Vec<_>>();

    let (challenge, state) = rp
        .inner
        .start_passkey_registration(
            user.id.0,
            &user.username,
            &user.display_name(),
            Some(exclude),
        )
        .map_err(|e| AppError::internal_from("starting passkey registration", e))?;

    let token = store_ceremony(db, Some(user.id), REGISTRATION, &state).await?;
    Ok((challenge, token))
}

/// Finish registering a passkey.
///
/// # Errors
///
/// * [`AppError::Unauthenticated`] — the ceremony is unknown, expired, spent,
///   or the credential does not verify against its challenge.
/// * [`AppError::Conflict`] — this authenticator is already registered.
/// * [`AppError::Internal`] — the database failed.
pub async fn finish_registration(
    db: &Db,
    rp: &RelyingParty,
    user_id: UserId,
    token: &SecretToken,
    label: &str,
    credential: &RegisterPublicKeyCredential,
) -> Result<Registered> {
    let state: PasskeyRegistration = claim_ceremony(db, token, REGISTRATION, Some(user_id)).await?;

    let passkey = rp
        .inner
        .finish_passkey_registration(credential, &state)
        .map_err(|error| {
            // Logged, never returned: the reason a ceremony failed tells an
            // attacker which of their assumptions was wrong.
            tracing::warn!(%error, %user_id, "passkey registration did not verify");
            AppError::Unauthenticated
        })?;

    let label = label.trim();
    let label = if label.is_empty() { "Passkey" } else { label };

    let credential_id = passkey.cred_id().as_ref().to_vec();
    let encoded = serde_json::to_value(&passkey)
        .map_err(|e| AppError::internal_from("encoding a passkey", e))?;

    let row = sqlx::query!(
        r#"
        INSERT INTO passkeys (user_id, credential_id, label, credential)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (credential_id) DO NOTHING
        RETURNING id, label, created_at, last_used_at
        "#,
        user_id.0,
        credential_id,
        label,
        encoded,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("storing a passkey", e))?;

    // `DO NOTHING` returning no row means the credential id is already taken —
    // by this user or another. Either way the answer is the same, and it does
    // not say which, because that would confirm whether a given authenticator
    // is registered to somebody else.
    let row = row.ok_or_else(|| AppError::conflict("this passkey is already registered"))?;

    Ok(Registered {
        id: row.id,
        label: row.label,
        created_at: row.created_at,
        last_used_at: row.last_used_at,
    })
}

/// Begin authenticating with a passkey.
///
/// # Errors
///
/// * [`AppError::NotFound`] — the user has no passkeys to offer.
/// * [`AppError::Internal`] — the ceremony could not be started or stored.
pub async fn begin_authentication(
    db: &Db,
    rp: &RelyingParty,
    user_id: UserId,
) -> Result<(RequestChallengeResponse, SecretToken)> {
    let credentials = credentials_for(db, user_id).await?;
    if credentials.is_empty() {
        return Err(AppError::NotFound("passkey"));
    }

    let passkeys = credentials
        .into_iter()
        .map(|(_, passkey)| passkey)
        .collect::<Vec<_>>();

    let (challenge, state) = rp
        .inner
        .start_passkey_authentication(&passkeys)
        .map_err(|e| AppError::internal_from("starting passkey authentication", e))?;

    let token = store_ceremony(db, Some(user_id), AUTHENTICATION, &state).await?;
    Ok((challenge, token))
}

/// Finish authenticating with a passkey.
///
/// On success the credential's signature counter is written back before this
/// returns, because the counter only defends against a cloned authenticator
/// for as long as it is persisted.
///
/// # Errors
///
/// Returns [`AppError::Unauthenticated`] if the ceremony is unknown, expired,
/// spent, the assertion does not verify, or the credential it names is not one
/// of this user's.
pub async fn finish_authentication(
    db: &Db,
    rp: &RelyingParty,
    user_id: UserId,
    token: &SecretToken,
    credential: &PublicKeyCredential,
) -> Result<()> {
    let state: PasskeyAuthentication =
        claim_ceremony(db, token, AUTHENTICATION, Some(user_id)).await?;

    let outcome = rp
        .inner
        .finish_passkey_authentication(credential, &state)
        .map_err(|error| {
            tracing::warn!(%error, %user_id, "passkey assertion did not verify");
            AppError::Unauthenticated
        })?;

    let credential_id = outcome.cred_id().as_ref().to_vec();

    // Re-read rather than trusting the ceremony: a passkey removed while the
    // ceremony was open must not still complete a login.
    let stored = sqlx::query!(
        r#"
        SELECT id, credential FROM passkeys
        WHERE user_id = $1 AND credential_id = $2
        "#,
        user_id.0,
        credential_id,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading a passkey", e))?
    .ok_or(AppError::Unauthenticated)?;

    let mut passkey: Passkey = serde_json::from_value(stored.credential)
        .map_err(|e| AppError::internal_from("decoding a stored passkey", e))?;

    // `update_credential` folds in the new counter and backup state. `Some(true)`
    // means something changed and has to be saved; `None` would mean the
    // credential ids disagree, which the lookup above has already ruled out.
    let changed = passkey.update_credential(&outcome).unwrap_or(false);

    let encoded = if changed {
        Some(
            serde_json::to_value(&passkey)
                .map_err(|e| AppError::internal_from("encoding a passkey", e))?,
        )
    } else {
        None
    };

    sqlx::query!(
        r#"
        UPDATE passkeys
           SET last_used_at = now(),
               credential = COALESCE($2, credential)
         WHERE id = $1
        "#,
        stored.id,
        encoded,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("recording passkey use", e))?;

    Ok(())
}

/// This user's passkeys, for the account page.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn list(db: &Db, user_id: UserId) -> Result<Vec<Registered>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, label, created_at, last_used_at
          FROM passkeys
         WHERE user_id = $1
         ORDER BY created_at
        "#,
        user_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing passkeys", e))?;

    Ok(rows
        .into_iter()
        .map(|row| Registered {
            id: row.id,
            label: row.label,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
        })
        .collect())
}

/// Rename a passkey.
///
/// # Errors
///
/// Returns [`AppError::NotFound`] if it is not this user's.
pub async fn rename(db: &Db, user_id: UserId, id: Uuid, label: &str) -> Result<()> {
    let label = label.trim();
    if label.is_empty() {
        return Err(AppError::field("label", "must not be empty"));
    }

    let result = sqlx::query!(
        "UPDATE passkeys SET label = $3 WHERE id = $1 AND user_id = $2",
        id,
        user_id.0,
        label,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("renaming a passkey", e))?;

    if result.rows_affected() == 0 {
        // Scoped by user: someone else's passkey is reported missing, not
        // forbidden, so its existence is not confirmed.
        return Err(AppError::NotFound("passkey"));
    }
    Ok(())
}

/// Remove a passkey.
///
/// # Errors
///
/// Returns [`AppError::NotFound`] if it is not this user's.
pub async fn remove(db: &Db, user_id: UserId, id: Uuid) -> Result<()> {
    let result = sqlx::query!(
        "DELETE FROM passkeys WHERE id = $1 AND user_id = $2",
        id,
        user_id.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("removing a passkey", e))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("passkey"));
    }
    Ok(())
}

/// Delete ceremonies that are past their expiry, for `authenc purge`.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn purge_expired(db: &Db) -> Result<u64> {
    let result = sqlx::query!("DELETE FROM webauthn_ceremonies WHERE expires_at < now()")
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("purging WebAuthn ceremonies", e))?;

    Ok(result.rows_affected())
}

/// This user's stored credentials, decoded.
async fn credentials_for(db: &Db, user_id: UserId) -> Result<Vec<(Uuid, Passkey)>> {
    let rows = sqlx::query!(
        "SELECT id, credential FROM passkeys WHERE user_id = $1 ORDER BY created_at",
        user_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("loading passkeys", e))?;

    rows.into_iter()
        .map(|row| {
            serde_json::from_value(row.credential)
                .map(|passkey| (row.id, passkey))
                .map_err(|e| AppError::internal_from("decoding a stored passkey", e))
        })
        .collect()
}

/// Persist ceremony state and return the token that identifies it.
async fn store_ceremony<S: serde::Serialize>(
    db: &Db,
    user_id: Option<UserId>,
    kind: &str,
    state: &S,
) -> Result<SecretToken> {
    let token = SecretToken::generate()
        .map_err(|e| AppError::internal_from("generating a ceremony token", e))?;
    let encoded = serde_json::to_value(state)
        .map_err(|e| AppError::internal_from("encoding ceremony state", e))?;

    sqlx::query!(
        r#"
        INSERT INTO webauthn_ceremonies (user_id, kind, token_hash, state, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        user_id.map(|id| id.0),
        kind,
        token.hash(),
        encoded,
        OffsetDateTime::now_utc() + CEREMONY_LIFETIME,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("storing ceremony state", e))?;

    Ok(token)
}

/// Spend a ceremony and return its state.
///
/// The claim is atomic and matches on the kind and the user as well as the
/// token, so a registration state cannot finish an authentication and one
/// user's ceremony cannot be completed by another.
///
/// The user match is exact, `NULL` included — there is deliberately no
/// "unspecified matches anything" case. Every caller today names its user, and
/// a wildcard branch that nothing uses is the one an argument eventually
/// arrives as `None` through.
async fn claim_ceremony<S: serde::de::DeserializeOwned>(
    db: &Db,
    token: &SecretToken,
    kind: &str,
    user_id: Option<UserId>,
) -> Result<S> {
    let row = sqlx::query!(
        r#"
        UPDATE webauthn_ceremonies
           SET consumed_at = now()
         WHERE token_hash = $1
           AND kind = $2
           AND user_id IS NOT DISTINCT FROM $3
           AND consumed_at IS NULL
           AND expires_at > now()
        RETURNING state
        "#,
        token.hash(),
        kind,
        user_id.map(|id| id.0),
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("claiming ceremony state", e))?
    .ok_or(AppError::Unauthenticated)?;

    serde_json::from_value(row.state)
        .map_err(|e| AppError::internal_from("decoding ceremony state", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use crate::{
        password::PasswordHasher,
        realm,
        user::{self, NewUser},
    };

    async fn fixture(db: &Db) -> User {
        let hasher = PasswordHasher::new();
        let realm = realm::create(db, "acme", "Acme").await.unwrap();
        user::create(
            db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "alice",
                email: "alice@example.com",
                password: test_support::password(),
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap()
    }

    fn relying_party() -> RelyingParty {
        RelyingParty::new("https://auth.example.com", "Authenc").unwrap()
    }

    #[test]
    fn the_rp_id_is_derived_from_the_origin() {
        // Configuring them separately is how they end up disagreeing, at which
        // point every browser refuses the ceremony without saying why.
        assert!(RelyingParty::new("https://auth.example.com", "Authenc").is_ok());
        assert!(RelyingParty::new("http://localhost:3000", "Authenc").is_ok());
    }

    #[test]
    fn an_origin_without_a_host_is_refused() {
        assert!(RelyingParty::new("not a url", "Authenc").is_err());
        assert!(RelyingParty::new("", "Authenc").is_err());
        // A path is not an origin; `file:` has no host to be an RP ID.
        assert!(RelyingParty::new("file:///tmp", "Authenc").is_err());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_registration_ceremony_is_stored_server_side(db: Db) {
        // The challenge must not be anything the client chose or can replay.
        let user = fixture(&db).await;
        let (challenge, token) = begin_registration(&db, &relying_party(), &user)
            .await
            .unwrap();

        assert!(!challenge.public_key.challenge.as_ref().is_empty());

        let stored: (Vec<u8>, String) =
            sqlx::query_as("SELECT token_hash, kind FROM webauthn_ceremonies")
                .fetch_one(&db)
                .await
                .unwrap();

        assert_eq!(stored.0, token.hash());
        assert_ne!(stored.0, token.expose().as_bytes());
        assert_eq!(stored.1, REGISTRATION);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_ceremony_can_only_be_claimed_once(db: Db) {
        let user = fixture(&db).await;
        let (_, token) = begin_registration(&db, &relying_party(), &user)
            .await
            .unwrap();

        assert!(
            claim_ceremony::<PasskeyRegistration>(&db, &token, REGISTRATION, Some(user.id))
                .await
                .is_ok(),
        );
        assert!(
            claim_ceremony::<PasskeyRegistration>(&db, &token, REGISTRATION, Some(user.id))
                .await
                .is_err(),
            "a replayed ceremony token must not work",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_registration_state_cannot_finish_an_authentication(db: Db) {
        // Two ceremonies, two meanings. Mixing them is how a challenge issued
        // for one purpose gets spent on another.
        let user = fixture(&db).await;
        let (_, token) = begin_registration(&db, &relying_party(), &user)
            .await
            .unwrap();

        assert!(
            claim_ceremony::<PasskeyAuthentication>(&db, &token, AUTHENTICATION, Some(user.id))
                .await
                .is_err(),
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn another_users_ceremony_cannot_be_claimed(db: Db) {
        let alice = fixture(&db).await;
        let hasher = PasswordHasher::new();
        let bob = user::create(
            &db,
            &hasher,
            NewUser {
                realm_id: alice.realm_id,
                username: "bob",
                email: "bob@example.com",
                password: test_support::password(),
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap();

        let (_, token) = begin_registration(&db, &relying_party(), &alice)
            .await
            .unwrap();

        assert!(
            claim_ceremony::<PasskeyRegistration>(&db, &token, REGISTRATION, Some(bob.id))
                .await
                .is_err(),
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_expired_ceremony_cannot_be_claimed(db: Db) {
        let user = fixture(&db).await;
        let (_, token) = begin_registration(&db, &relying_party(), &user)
            .await
            .unwrap();

        sqlx::query("UPDATE webauthn_ceremonies SET expires_at = now() - interval '1 second'")
            .execute(&db)
            .await
            .unwrap();

        assert!(
            claim_ceremony::<PasskeyRegistration>(&db, &token, REGISTRATION, Some(user.id))
                .await
                .is_err(),
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_forged_credential_does_not_register(db: Db) {
        // The library decides this, which is the point of using it — but the
        // wiring has to actually hand it the credential and honour the answer.
        let user = fixture(&db).await;
        let rp = relying_party();
        let (_, token) = begin_registration(&db, &rp, &user).await.unwrap();

        let forged: RegisterPublicKeyCredential = serde_json::from_str(
            r#"{
                "id": "AAAA",
                "rawId": "AAAA",
                "type": "public-key",
                "response": {
                    "attestationObject": "AAAA",
                    "clientDataJSON": "AAAA"
                }
            }"#,
        )
        .unwrap();

        let error = finish_registration(&db, &rp, user.id, &token, "Forged", &forged)
            .await
            .unwrap_err();
        assert_eq!(error.status(), 401);

        assert!(list(&db, user.id).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn authentication_needs_a_registered_key(db: Db) {
        let user = fixture(&db).await;
        let error = begin_authentication(&db, &relying_party(), user.id)
            .await
            .unwrap_err();
        assert_eq!(error.status(), 404);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn purging_removes_only_expired_ceremonies(db: Db) {
        let user = fixture(&db).await;
        begin_registration(&db, &relying_party(), &user)
            .await
            .unwrap();
        let (_, live) = begin_registration(&db, &relying_party(), &user)
            .await
            .unwrap();

        sqlx::query(
            "UPDATE webauthn_ceremonies SET expires_at = now() - interval '1 hour' \
             WHERE token_hash <> $1",
        )
        .bind(live.hash())
        .execute(&db)
        .await
        .unwrap();

        assert_eq!(purge_expired(&db).await.unwrap(), 1);
        assert!(
            claim_ceremony::<PasskeyRegistration>(&db, &live, REGISTRATION, Some(user.id))
                .await
                .is_ok(),
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn renaming_and_removing_are_scoped_to_the_owner(db: Db) {
        let user = fixture(&db).await;
        let stranger = Uuid::new_v4();

        // 404 rather than 403: a passkey that is not yours is one you cannot
        // learn the existence of.
        assert_eq!(
            rename(&db, user.id, stranger, "Mine")
                .await
                .unwrap_err()
                .status(),
            404,
        );
        assert_eq!(
            remove(&db, user.id, stranger).await.unwrap_err().status(),
            404,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_blank_label_is_refused(db: Db) {
        let user = fixture(&db).await;
        assert_eq!(
            rename(&db, user.id, Uuid::new_v4(), "   ")
                .await
                .unwrap_err()
                .status(),
            400,
        );
    }
}
