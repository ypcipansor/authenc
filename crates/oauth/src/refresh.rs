//! Refresh tokens, with rotation and reuse detection.
//!
//! A refresh token is long-lived and, unlike an access token, is worth
//! stealing: it mints new access tokens for as long as it lives. The defence
//! is rotation with **detection**, as OAuth 2.1 §4.14.2 and RFC 9700 §4.14
//! describe.
//!
//! Every token is spent on first use and replaced. A spent token is not
//! deleted — it is marked, and it points at its successor. So when a spent
//! token turns up again, that is not an error to shrug at: either the
//! legitimate client is retrying a request whose response it never saw, or the
//! token leaked and someone else got there first. The two are indistinguishable
//! from here, so the whole family is revoked and both parties have to
//! re-authenticate. That is the conservative reading, and it is the one the
//! specification asks for.
//!
//! The family id is the authorization code's own id, so a replayed *code* and
//! a replayed *token* revoke exactly the same set.

use authenc_contract::{AppError, RealmId, Result, UserId, event::Action};
use authenc_identity::{Db, SecretToken};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{client::ClientKey, error::OAuthError};

/// How long a refresh token lives before it must be re-authorised.
pub const REFRESH_TOKEN_LIFETIME: Duration = Duration::days(14);

/// A newly minted refresh token.
#[derive(Debug)]
pub struct Minted {
    /// The token to hand to the client. Only its hash is stored.
    pub token: SecretToken,
    /// The family it belongs to.
    pub family_id: Uuid,
    /// When it stops working.
    pub expires_at: OffsetDateTime,
}

/// What a token is minted for.
#[derive(Debug, Clone)]
pub struct Mint<'a> {
    /// The client that will present it.
    pub client: ClientKey,
    /// The realm.
    pub realm_id: RealmId,
    /// The user it speaks for.
    pub user_id: UserId,
    /// Scopes it may refresh.
    pub scopes: &'a [String],
    /// How the session behind it authenticated, carried forward so ID tokens
    /// minted days later still describe the sign-in that actually happened.
    pub authenticated_with: &'a [String],
    /// The family. Successors keep the family of the token they replace.
    pub family_id: Uuid,
}

/// Mint a refresh token.
///
/// # Errors
///
/// Returns an internal error if entropy or the database fails.
pub async fn mint(db: &Db, new: Mint<'_>) -> Result<Minted> {
    let token = SecretToken::generate()
        .map_err(|e| AppError::internal_from("generating refresh token", e))?;
    let expires_at = OffsetDateTime::now_utc() + REFRESH_TOKEN_LIFETIME;

    sqlx::query!(
        r#"
        INSERT INTO refresh_tokens
            (client_id, user_id, realm_id, token_hash, scopes, family_id,
             expires_at, authenticated_with)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
        new.client.0,
        new.user_id.0,
        new.realm_id.0,
        token.hash(),
        new.scopes,
        new.family_id,
        expires_at,
        new.authenticated_with,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("storing refresh token", e))?;

    Ok(Minted {
        token,
        family_id: new.family_id,
        expires_at,
    })
}

/// What a rotation produced.
#[derive(Debug)]
pub struct Rotated {
    /// The replacement token.
    pub token: SecretToken,
    /// The realm.
    pub realm_id: RealmId,
    /// The user.
    pub user_id: UserId,
    /// Scopes carried forward.
    pub scopes: Vec<String>,
    /// How the original sign-in happened, carried forward unchanged.
    pub authenticated_with: Vec<String>,
    /// The family, unchanged.
    pub family_id: Uuid,
}

/// Spend a refresh token and issue its successor.
///
/// # Errors
///
/// Returns `invalid_grant` if the token is unknown, expired, revoked, or
/// already spent. In the last case the whole family is revoked first, so an
/// access token minted from a stolen refresh token stops being renewable
/// immediately.
pub async fn rotate(
    db: &Db,
    presented: &SecretToken,
    client: ClientKey,
) -> std::result::Result<Rotated, OAuthError> {
    let claimed = sqlx::query!(
        r#"
        UPDATE refresh_tokens
        SET used_at = now()
        WHERE token_hash = $1
          AND client_id = $2
          AND used_at IS NULL
          AND revoked_at IS NULL
          AND expires_at > now()
        RETURNING id, realm_id, user_id, scopes, family_id, authenticated_with
        "#,
        presented.hash(),
        client.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("rotating refresh token", e))?;

    let Some(row) = claimed else {
        detect_reuse(db, presented, client).await?;
        return Err(OAuthError::invalid_grant(
            "refresh token is invalid or has expired",
        ));
    };

    let successor = mint(
        db,
        Mint {
            client,
            realm_id: RealmId(row.realm_id),
            user_id: UserId(row.user_id),
            scopes: &row.scopes,
            // Carried, never recomputed: this token may be days old, and what
            // the account has enrolled now is not what was presented then.
            authenticated_with: &row.authenticated_with,
            family_id: row.family_id,
        },
    )
    .await?;

    // Link predecessor to successor so the chain can be walked when
    // investigating an incident.
    sqlx::query!(
        "UPDATE refresh_tokens SET replaced_by = \
         (SELECT id FROM refresh_tokens WHERE token_hash = $2) WHERE id = $1",
        row.id,
        successor.token.hash(),
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("linking rotated refresh token", e))?;

    Ok(Rotated {
        token: successor.token,
        realm_id: RealmId(row.realm_id),
        user_id: UserId(row.user_id),
        scopes: row.scopes,
        authenticated_with: row.authenticated_with,
        family_id: row.family_id,
    })
}

/// If the presented token was already spent, revoke its whole family.
async fn detect_reuse(
    db: &Db,
    presented: &SecretToken,
    client: ClientKey,
) -> std::result::Result<(), OAuthError> {
    let spent = sqlx::query!(
        "SELECT family_id, realm_id, user_id FROM refresh_tokens \
         WHERE token_hash = $1 AND client_id = $2 AND used_at IS NOT NULL",
        presented.hash(),
        client.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("checking for refresh token reuse", e))?;

    if let Some(spent) = spent {
        let revoked = revoke_family(db, spent.family_id).await?;
        tracing::warn!(
            family_id = %spent.family_id,
            revoked,
            "refresh token reuse detected; revoked the family",
        );

        // The single most important line the audit log carries. A spent
        // refresh token coming back means one of the two holders is not the
        // user — and the log line above goes wherever logs go, which is not
        // where an operator looks up "what happened to this account?".
        authenc_identity::audit::observe(
            db,
            authenc_identity::audit::Entry::failure(Action::RefreshTokenReuseDetected)
                .in_realm(RealmId(spent.realm_id))
                .by_id(UserId(spent.user_id))
                .to("refresh_family", &spent.family_id.to_string())
                .detail(serde_json::json!({ "revoked": revoked })),
        )
        .await;
    }

    Ok(())
}

/// Revoke every token in a family.
///
/// # Errors
///
/// Returns an internal error if the update fails.
pub async fn revoke_family(db: &Db, family_id: Uuid) -> Result<u64> {
    let affected = sqlx::query!(
        "UPDATE refresh_tokens SET revoked_at = now() \
         WHERE family_id = $1 AND revoked_at IS NULL",
        family_id,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("revoking refresh token family", e))?
    .rows_affected();

    Ok(affected)
}

/// Revoke a single token, as RFC 7009 asks.
///
/// Returns whether anything was revoked. The endpoint answers 200 either way —
/// RFC 7009 §2.2 is explicit that an unknown token is a successful revocation —
/// but the caller may want to log the difference.
///
/// # Errors
///
/// Returns an internal error if the update fails.
pub async fn revoke(db: &Db, presented: &SecretToken, client: ClientKey) -> Result<bool> {
    let affected = sqlx::query!(
        "UPDATE refresh_tokens SET revoked_at = now() \
         WHERE token_hash = $1 AND client_id = $2 AND revoked_at IS NULL",
        presented.hash(),
        client.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("revoking refresh token", e))?
    .rows_affected();

    Ok(affected > 0)
}

/// Revoke every refresh token a user holds, across all clients.
///
/// Called when an account is disabled or its password is reset — otherwise a
/// stolen session's refresh tokens outlive the recovery that was supposed to
/// end it.
///
/// # Errors
///
/// Returns an internal error if the update fails.
pub async fn revoke_all_for_user(db: &Db, user_id: UserId) -> Result<u64> {
    let affected = sqlx::query!(
        "UPDATE refresh_tokens SET revoked_at = now() \
         WHERE user_id = $1 AND revoked_at IS NULL",
        user_id.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("revoking user refresh tokens", e))?
    .rows_affected();

    Ok(affected)
}

/// What a live refresh token authorises, for introspection.
#[derive(Debug, Clone)]
pub struct Introspected {
    /// The user.
    pub user_id: UserId,
    /// The realm.
    pub realm_id: RealmId,
    /// Scopes.
    pub scopes: Vec<String>,
    /// Expiry.
    pub expires_at: OffsetDateTime,
}

/// Look up a refresh token without spending it.
///
/// # Errors
///
/// Returns an internal error if the query fails. An unknown, spent, revoked,
/// or expired token is `Ok(None)` — "not active" is an answer, not a failure.
pub async fn introspect(
    db: &Db,
    presented: &SecretToken,
    client: ClientKey,
) -> Result<Option<Introspected>> {
    let row = sqlx::query!(
        r#"
        SELECT user_id, realm_id, scopes, expires_at
        FROM refresh_tokens
        WHERE token_hash = $1
          AND client_id = $2
          AND used_at IS NULL
          AND revoked_at IS NULL
          AND expires_at > now()
        "#,
        presented.hash(),
        client.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("introspecting refresh token", e))?;

    Ok(row.map(|row| Introspected {
        user_id: UserId(row.user_id),
        realm_id: RealmId(row.realm_id),
        scopes: row.scopes,
        expires_at: row.expires_at,
    }))
}

/// Delete tokens that can no longer be used.
///
/// Spent and revoked tokens are kept until expiry so reuse stays detectable
/// for the whole window in which a stolen token could be presented.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn purge_expired(db: &Db) -> Result<u64> {
    let removed = sqlx::query!("DELETE FROM refresh_tokens WHERE expires_at < now()")
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("purging refresh tokens", e))?
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

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
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

    async fn first_token(db: &Db, f: &Fixture) -> Minted {
        let scopes = owned(&["openid", "offline_access"]);
        mint(
            db,
            Mint {
                authenticated_with: &PWD,
                client: f.client,
                realm_id: f.realm_id,
                user_id: f.user_id,
                scopes: &scopes,
                family_id: Uuid::new_v4(),
            },
        )
        .await
        .unwrap()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rotation_returns_a_new_token_and_keeps_the_family(db: Db) {
        let f = fixture(&db).await;
        let first = first_token(&db, &f).await;

        let rotated = rotate(&db, &first.token, f.client).await.unwrap();

        assert_ne!(rotated.token.expose(), first.token.expose());
        assert_eq!(rotated.family_id, first.family_id);
        assert_eq!(rotated.user_id, f.user_id);
        assert_eq!(rotated.scopes, owned(&["openid", "offline_access"]));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_spent_token_stops_working_the_moment_it_is_rotated(db: Db) {
        let f = fixture(&db).await;
        let first = first_token(&db, &f).await;
        rotate(&db, &first.token, f.client).await.unwrap();

        assert!(rotate(&db, &first.token, f.client).await.is_err());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn reusing_a_spent_token_revokes_the_whole_family(db: Db) {
        // This is the property the whole design exists for: a thief who
        // rotates first must not leave the victim with a working token, and
        // vice versa.
        let f = fixture(&db).await;
        let first = first_token(&db, &f).await;

        let second = rotate(&db, &first.token, f.client).await.unwrap();
        // The successor works, right up until the replay.
        assert!(
            introspect(&db, &second.token, f.client)
                .await
                .unwrap()
                .is_some()
        );

        // Someone presents the already-spent predecessor.
        assert!(rotate(&db, &first.token, f.client).await.is_err());

        // Now nothing in the family works, including the successor that was
        // fine a moment ago.
        assert!(
            introspect(&db, &second.token, f.client)
                .await
                .unwrap()
                .is_none()
        );
        assert!(rotate(&db, &second.token, f.client).await.is_err());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn one_familys_compromise_does_not_touch_another(db: Db) {
        let f = fixture(&db).await;
        let compromised = first_token(&db, &f).await;
        let unrelated = first_token(&db, &f).await;

        rotate(&db, &compromised.token, f.client).await.unwrap();
        assert!(rotate(&db, &compromised.token, f.client).await.is_err());

        assert!(
            introspect(&db, &unrelated.token, f.client)
                .await
                .unwrap()
                .is_some(),
            "an unrelated authorization must survive",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn another_clients_token_cannot_be_rotated(db: Db) {
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

        let first = first_token(&db, &f).await;
        assert!(rotate(&db, &first.token, other.client.key).await.is_err());

        // And it must not have been burned by the attempt.
        assert!(rotate(&db, &first.token, f.client).await.is_ok());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_expired_token_is_refused(db: Db) {
        let f = fixture(&db).await;
        let first = first_token(&db, &f).await;

        sqlx::query!(
            "UPDATE refresh_tokens SET expires_at = now() - INTERVAL '1 second' \
             WHERE token_hash = $1",
            first.token.hash(),
        )
        .execute(&db)
        .await
        .unwrap();

        assert!(rotate(&db, &first.token, f.client).await.is_err());
        assert!(
            introspect(&db, &first.token, f.client)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn revoking_a_token_is_idempotent_and_reports_the_difference(db: Db) {
        let f = fixture(&db).await;
        let first = first_token(&db, &f).await;

        assert!(revoke(&db, &first.token, f.client).await.unwrap());
        assert!(!revoke(&db, &first.token, f.client).await.unwrap());
        assert!(rotate(&db, &first.token, f.client).await.is_err());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn disabling_an_account_can_revoke_every_token_it_holds(db: Db) {
        let f = fixture(&db).await;
        let a = first_token(&db, &f).await;
        let b = first_token(&db, &f).await;

        assert_eq!(revoke_all_for_user(&db, f.user_id).await.unwrap(), 2);
        assert!(introspect(&db, &a.token, f.client).await.unwrap().is_none());
        assert!(introspect(&db, &b.token, f.client).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_token_itself_is_never_stored(db: Db) {
        let f = fixture(&db).await;
        let first = first_token(&db, &f).await;

        let stored: Vec<u8> = sqlx::query_scalar!("SELECT token_hash FROM refresh_tokens LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap();

        assert_eq!(stored, first.token.hash());
        assert!(!stored.starts_with(first.token.expose().as_bytes()));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rotation_records_which_token_replaced_which(db: Db) {
        // Not cosmetic: it is what turns "a family was revoked" into an
        // investigable chain.
        let f = fixture(&db).await;
        let first = first_token(&db, &f).await;
        let second = rotate(&db, &first.token, f.client).await.unwrap();

        let replaced: Option<Uuid> = sqlx::query_scalar!(
            "SELECT replaced_by FROM refresh_tokens WHERE token_hash = $1",
            first.token.hash(),
        )
        .fetch_one(&db)
        .await
        .unwrap();

        let successor: Uuid = sqlx::query_scalar!(
            r#"SELECT id AS "id!" FROM refresh_tokens WHERE token_hash = $1"#,
            second.token.hash(),
        )
        .fetch_one(&db)
        .await
        .unwrap();

        assert_eq!(replaced, Some(successor));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn purging_removes_only_what_can_no_longer_be_used(db: Db) {
        let f = fixture(&db).await;
        let live = first_token(&db, &f).await;
        let stale = first_token(&db, &f).await;

        sqlx::query!(
            "UPDATE refresh_tokens SET expires_at = now() - INTERVAL '1 day' \
             WHERE token_hash = $1",
            stale.token.hash(),
        )
        .execute(&db)
        .await
        .unwrap();

        assert_eq!(purge_expired(&db).await.unwrap(), 1);
        assert!(
            introspect(&db, &live.token, f.client)
                .await
                .unwrap()
                .is_some()
        );
    }
}
