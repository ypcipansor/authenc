//! Recorded consent.
//!
//! A user is asked once per client, and asked again the moment the client
//! wants more than last time. That second half is the part that is easy to
//! drop: storing "this user approved this client" without storing *what* they
//! approved lets a client quietly widen its scopes after the first approval.
//! The granted scopes are therefore stored and compared on every request.

use authenc_contract::{AppError, Result, UserId};
use authenc_identity::Db;
use time::OffsetDateTime;

use crate::client::ClientKey;

/// What a user has approved for one client.
#[derive(Debug, Clone)]
pub struct Grant {
    /// The scopes approved.
    pub scopes: Vec<String>,
    /// When they were approved.
    pub granted_at: OffsetDateTime,
}

/// The consent a user has on record for a client, if any.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn granted(db: &Db, user_id: UserId, client: ClientKey) -> Result<Option<Grant>> {
    let row = sqlx::query!(
        "SELECT scopes, granted_at FROM oauth_consents WHERE user_id = $1 AND client_id = $2",
        user_id.0,
        client.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading consent", e))?;

    Ok(row.map(|row| Grant {
        scopes: row.scopes,
        granted_at: row.granted_at,
    }))
}

/// Whether the request can proceed without asking.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn is_satisfied(
    db: &Db,
    user_id: UserId,
    client: ClientKey,
    requested: &[String],
) -> Result<bool> {
    Ok(granted(db, user_id, client)
        .await?
        .is_some_and(|grant| crate::scope::covers(&grant.scopes, requested)))
}

/// Record an approval.
///
/// Approving a narrower set than before does not shrink the record: the union
/// is stored, because the user has approved each of those scopes at some point
/// and re-prompting for one they already granted is noise. Withdrawal is
/// [`revoke`], which is explicit.
///
/// # Errors
///
/// Returns an internal error if the write fails.
pub async fn record(db: &Db, user_id: UserId, client: ClientKey, scopes: &[String]) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO oauth_consents (user_id, client_id, scopes)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, client_id) DO UPDATE
        SET scopes = ARRAY(
                SELECT DISTINCT unnest(oauth_consents.scopes || EXCLUDED.scopes)
            ),
            granted_at = now()
        "#,
        user_id.0,
        client.0,
        scopes,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("recording consent", e))?;

    Ok(())
}

/// Withdraw consent for one client.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn revoke(db: &Db, user_id: UserId, client: ClientKey) -> Result<bool> {
    let affected = sqlx::query!(
        "DELETE FROM oauth_consents WHERE user_id = $1 AND client_id = $2",
        user_id.0,
        client.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("revoking consent", e))?
    .rows_affected();

    Ok(affected > 0)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "a failed setup step should fail the test"
)]
mod tests {
    use super::*;
    use crate::client::{self, NewClient};
    use crate::test_support;
    use authenc_identity::{PasswordHasher, realm, user::NewUser};

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }

    async fn fixture(db: &Db) -> (UserId, ClientKey) {
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
                client_id: Some("app"),
                name: "App",
                is_public: true,
                redirect_uris: &uris,
                grant_types: &[],
                scopes: &[],
                require_consent: true,
            },
        )
        .await
        .unwrap();

        (user.id, registered.client.key)
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn nothing_is_satisfied_before_anything_is_approved(db: Db) {
        let (user, client) = fixture(&db).await;
        assert!(granted(&db, user, client).await.unwrap().is_none());
        assert!(
            !is_satisfied(&db, user, client, &owned(&["openid"]))
                .await
                .unwrap()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn approving_a_set_satisfies_that_set_and_any_subset(db: Db) {
        let (user, client) = fixture(&db).await;
        record(&db, user, client, &owned(&["openid", "profile"]))
            .await
            .unwrap();

        assert!(
            is_satisfied(&db, user, client, &owned(&["openid"]))
                .await
                .unwrap()
        );
        assert!(
            is_satisfied(&db, user, client, &owned(&["profile", "openid"]))
                .await
                .unwrap()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_client_cannot_quietly_widen_what_it_was_approved_for(db: Db) {
        // The reason the scopes are stored at all rather than a bare
        // "approved" flag.
        let (user, client) = fixture(&db).await;
        record(&db, user, client, &owned(&["openid"]))
            .await
            .unwrap();

        assert!(
            !is_satisfied(&db, user, client, &owned(&["openid", "email"]))
                .await
                .unwrap(),
            "asking for more than was approved must prompt again",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_second_approval_adds_to_the_record_rather_than_replacing_it(db: Db) {
        let (user, client) = fixture(&db).await;
        record(&db, user, client, &owned(&["openid"]))
            .await
            .unwrap();
        record(&db, user, client, &owned(&["email"])).await.unwrap();

        let mut scopes = granted(&db, user, client).await.unwrap().unwrap().scopes;
        scopes.sort();
        assert_eq!(scopes, owned(&["email", "openid"]));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn withdrawing_consent_makes_the_next_request_prompt_again(db: Db) {
        let (user, client) = fixture(&db).await;
        record(&db, user, client, &owned(&["openid"]))
            .await
            .unwrap();

        assert!(revoke(&db, user, client).await.unwrap());
        assert!(!revoke(&db, user, client).await.unwrap());
        assert!(
            !is_satisfied(&db, user, client, &owned(&["openid"]))
                .await
                .unwrap()
        );
    }
}
