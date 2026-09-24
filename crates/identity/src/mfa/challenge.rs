//! A password that was correct, and is not yet a session.
//!
//! This is the state between the two halves of a login. It is deliberately its
//! own table and its own type rather than a flag on `sessions`, because a flag
//! is something every reader has to remember to check and a separate type is
//! something the compiler checks for them. Nothing that resolves a session
//! cookie can be handed one of these.
//!
//! Three properties matter:
//!
//! * **Short.** Five minutes is long enough to fetch a phone and short enough
//!   that a challenge left open on a shared machine is worthless.
//! * **Budgeted.** A six-digit code is one in a million per guess, which is
//!   only strong if the number of guesses is small. The challenge dies at five
//!   wrong answers, and the user starts again from the password.
//! * **Single use.** Claimed atomically, so the same challenge cannot open two
//!   sessions.

use authenc_contract::{AppError, RealmId, Result, UserId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{db::Db, session::Origin, token::SecretToken};

/// How long a pending login survives.
pub const LIFETIME: Duration = Duration::minutes(5);

/// Wrong second factors before the challenge is abandoned.
pub const MAX_ATTEMPTS: i32 = 5;

/// A login waiting on its second factor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Stable identifier.
    pub id: Uuid,
    /// Who is trying to sign in.
    pub user_id: UserId,
    /// Which realm they authenticated against.
    pub realm_id: RealmId,
    /// How the first factor was satisfied, so `amr` can say which.
    pub first_factor: super::FirstFactor,
    /// Wrong answers so far.
    pub attempts: i32,
    /// When this stops being usable.
    pub expires_at: OffsetDateTime,
}

/// A newly created challenge, with the token that identifies it.
#[derive(Debug)]
pub struct Issued {
    /// The stored challenge.
    pub pending: Pending,
    /// The handle for the client, available exactly once.
    ///
    /// Travels in an `HttpOnly` cookie for the same reason the session token
    /// does: page script has no business holding a credential, even a
    /// five-minute one.
    pub token: SecretToken,
}

/// Open a challenge for a user whose password was correct.
///
/// # Errors
///
/// Returns an internal error if entropy or the insert fails.
pub async fn issue(
    db: &Db,
    user_id: UserId,
    realm_id: RealmId,
    first_factor: super::FirstFactor,
    origin: Origin<'_>,
) -> Result<Issued> {
    let token = SecretToken::generate()
        .map_err(|e| AppError::internal_from("generating an MFA challenge token", e))?;
    let expires_at = OffsetDateTime::now_utc() + LIFETIME;

    let row = sqlx::query!(
        r#"
        INSERT INTO mfa_challenges
            (user_id, realm_id, token_hash, user_agent, ip_address, expires_at,
             first_factor)
        VALUES ($1, $2, $3, $4, $5::text::inet, $6, $7)
        RETURNING id
        "#,
        user_id.0,
        realm_id.0,
        token.hash(),
        origin.user_agent,
        origin.ip_address.map(|ip| ip.to_string()),
        expires_at,
        first_factor.as_str(),
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("creating an MFA challenge", e))?;

    Ok(Issued {
        pending: Pending {
            id: row.id,
            user_id,
            realm_id,
            first_factor,
            attempts: 0,
            expires_at,
        },
        token,
    })
}

/// Resolve a token to its challenge.
///
/// Returns `None` when the token matches nothing, has expired, has already
/// been spent, or has run out of attempts — all four are the same answer to
/// the caller: start again.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn lookup(db: &Db, token: &SecretToken) -> Result<Option<Pending>> {
    let row = sqlx::query!(
        r#"
        SELECT id, user_id, realm_id, attempts, expires_at, first_factor
          FROM mfa_challenges
         WHERE token_hash = $1
           AND consumed_at IS NULL
           AND expires_at > now()
           AND attempts < $2
        "#,
        token.hash(),
        MAX_ATTEMPTS,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("looking up an MFA challenge", e))?;

    row.map(|row| {
        Ok(Pending {
            id: row.id,
            user_id: UserId(row.user_id),
            realm_id: RealmId(row.realm_id),
            first_factor: super::FirstFactor::parse(&row.first_factor)?,
            attempts: row.attempts,
            expires_at: row.expires_at,
        })
    })
    .transpose()
}

/// Record a wrong second factor, returning how many have now been made.
///
/// # Errors
///
/// Returns an internal error if the update fails.
pub async fn record_failure(db: &Db, id: Uuid) -> Result<i32> {
    let row = sqlx::query!(
        r#"
        UPDATE mfa_challenges
           SET attempts = attempts + 1
         WHERE id = $1
        RETURNING attempts
        "#,
        id,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("recording an MFA failure", e))?;

    Ok(row.attempts)
}

/// Spend a challenge.
///
/// Returns `false` if it was already spent, which is what stops two concurrent
/// requests from turning one correct code into two sessions.
///
/// # Errors
///
/// Returns an internal error if the update fails.
pub async fn consume(db: &Db, id: Uuid) -> Result<bool> {
    let result = sqlx::query!(
        r#"
        UPDATE mfa_challenges
           SET consumed_at = now()
         WHERE id = $1 AND consumed_at IS NULL
        "#,
        id,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("consuming an MFA challenge", e))?;

    Ok(result.rows_affected() == 1)
}

/// Delete challenges that are past their expiry, for `authenc purge`.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn purge_expired(db: &Db) -> Result<u64> {
    let result = sqlx::query!("DELETE FROM mfa_challenges WHERE expires_at < now()")
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("purging MFA challenges", e))?;

    Ok(result.rows_affected())
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
    use authenc_contract::model::User;

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

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_issued_challenge_resolves(db: Db) {
        let user = fixture(&db).await;
        let issued = issue(
            &db,
            user.id,
            user.realm_id,
            crate::mfa::FirstFactor::Password,
            Origin::default(),
        )
        .await
        .unwrap();

        let found = lookup(&db, &issued.token).await.unwrap().unwrap();
        assert_eq!(found.id, issued.pending.id);
        assert_eq!(found.user_id, user.id);
        assert_eq!(found.attempts, 0);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_token_resolves_to_nothing(db: Db) {
        fixture(&db).await;
        let stranger = SecretToken::generate().unwrap();
        assert!(lookup(&db, &stranger).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_spent_challenge_cannot_be_spent_again(db: Db) {
        let user = fixture(&db).await;
        let issued = issue(
            &db,
            user.id,
            user.realm_id,
            crate::mfa::FirstFactor::Password,
            Origin::default(),
        )
        .await
        .unwrap();

        assert!(consume(&db, issued.pending.id).await.unwrap());
        assert!(
            !consume(&db, issued.pending.id).await.unwrap(),
            "one challenge must not open two sessions",
        );
        assert!(lookup(&db, &issued.token).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_attempt_budget_kills_the_challenge(db: Db) {
        // A six-digit code is only strong because the number of guesses is
        // small. This is the thing that keeps it small.
        let user = fixture(&db).await;
        let issued = issue(
            &db,
            user.id,
            user.realm_id,
            crate::mfa::FirstFactor::Password,
            Origin::default(),
        )
        .await
        .unwrap();

        for expected in 1..=MAX_ATTEMPTS {
            assert_eq!(
                record_failure(&db, issued.pending.id).await.unwrap(),
                expected
            );
        }

        assert!(
            lookup(&db, &issued.token).await.unwrap().is_none(),
            "the challenge must be dead once the budget is spent",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_challenge_survives_up_to_the_budget(db: Db) {
        let user = fixture(&db).await;
        let issued = issue(
            &db,
            user.id,
            user.realm_id,
            crate::mfa::FirstFactor::Password,
            Origin::default(),
        )
        .await
        .unwrap();

        for _ in 1..MAX_ATTEMPTS {
            record_failure(&db, issued.pending.id).await.unwrap();
        }

        // One wrong code away from the limit is still a usable challenge: a
        // typo must not cost the user their password entry.
        assert!(lookup(&db, &issued.token).await.unwrap().is_some());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_expired_challenge_is_gone(db: Db) {
        let user = fixture(&db).await;
        let issued = issue(
            &db,
            user.id,
            user.realm_id,
            crate::mfa::FirstFactor::Password,
            Origin::default(),
        )
        .await
        .unwrap();

        sqlx::query("UPDATE mfa_challenges SET expires_at = now() - interval '1 second'")
            .execute(&db)
            .await
            .unwrap();

        assert!(lookup(&db, &issued.token).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn purging_removes_only_expired_challenges(db: Db) {
        let user = fixture(&db).await;
        let live = issue(
            &db,
            user.id,
            user.realm_id,
            crate::mfa::FirstFactor::Password,
            Origin::default(),
        )
        .await
        .unwrap();
        let stale = issue(
            &db,
            user.id,
            user.realm_id,
            crate::mfa::FirstFactor::Password,
            Origin::default(),
        )
        .await
        .unwrap();

        sqlx::query(
            "UPDATE mfa_challenges SET expires_at = now() - interval '1 hour' WHERE id = $1",
        )
        .bind(stale.pending.id)
        .execute(&db)
        .await
        .unwrap();

        assert_eq!(purge_expired(&db).await.unwrap(), 1);
        assert!(lookup(&db, &live.token).await.unwrap().is_some());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_token_is_not_recoverable_from_the_database(db: Db) {
        let user = fixture(&db).await;
        let issued = issue(
            &db,
            user.id,
            user.realm_id,
            crate::mfa::FirstFactor::Password,
            Origin::default(),
        )
        .await
        .unwrap();

        let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM mfa_challenges")
            .fetch_one(&db)
            .await
            .unwrap();

        assert_ne!(stored, issued.token.expose().as_bytes());
        assert_eq!(stored, issued.token.hash());
    }
}
