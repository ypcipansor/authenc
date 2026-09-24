//! Sessions.
//!
//! The browser holds an opaque token in a cookie it cannot read from
//! JavaScript. The server holds everything else here, and only a hash of the
//! token, so a database disclosure does not hand over live sessions.

use authenc_contract::{AppError, RealmId, Result, SessionId, UserId};
use time::{Duration, OffsetDateTime};

use crate::{
    db::Db,
    token::{SecretToken, constant_time_eq},
};

/// How long a session lives without being refreshed.
pub const LIFETIME: Duration = Duration::days(14);

/// A session as the server sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Stable identifier.
    pub id: SessionId,
    /// Who the session belongs to.
    pub user_id: UserId,
    /// Which realm they authenticated against.
    pub realm_id: RealmId,
    /// When the session stops being valid.
    pub expires_at: OffsetDateTime,
    /// How this session was authenticated, in RFC 8176 `amr` terms.
    ///
    /// Recorded when the session is created rather than inferred later from
    /// what the account has enrolled, which would be wrong for every session
    /// opened before a factor was added. Not yet surfaced in ID tokens; see
    /// the note in `migrations/0004_mfa.sql`.
    pub authenticated_with: Vec<String>,
    /// Secret used for the CSRF check, bound to this session.
    csrf_secret: Vec<u8>,
}

impl Session {
    /// The CSRF token to hand this session's client.
    #[must_use]
    pub fn csrf_token(&self) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode(&self.csrf_secret)
    }

    /// Whether a client-supplied CSRF token belongs to *this* session.
    ///
    /// Compared in constant time. Binding to the session is the point: the
    /// previous implementation accepted any string of 32 characters or more,
    /// with no server-side state at all, so a token from anywhere validated
    /// everywhere.
    #[must_use]
    pub fn csrf_token_matches(&self, presented: &str) -> bool {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(presented) else {
            return false;
        };
        constant_time_eq(&decoded, &self.csrf_secret)
    }
}

/// A newly created session, together with the token to send to the client.
#[derive(Debug)]
pub struct Issued {
    /// The stored session.
    pub session: Session,
    /// The token for the cookie. Available exactly once — it is not recoverable
    /// from the database afterwards.
    pub token: SecretToken,
}

/// Where a session was created from, for the audit trail and for the user's
/// own "active sessions" list.
#[derive(Debug, Clone, Copy, Default)]
pub struct Origin<'a> {
    /// `User-Agent` header, if present.
    pub user_agent: Option<&'a str>,
    /// Client address, if known.
    pub ip_address: Option<std::net::IpAddr>,
}

/// Create a session for a user.
///
/// # Errors
///
/// Returns an internal error if entropy is unavailable or the insert fails.
pub async fn create(
    db: &Db,
    user_id: UserId,
    realm_id: RealmId,
    authenticated_with: Vec<String>,
    origin: Origin<'_>,
) -> Result<Issued> {
    let token = SecretToken::generate()
        .map_err(|e| AppError::internal_from("generating session token", e))?;
    let csrf_secret = crate::token::random_bytes::<32>()
        .map_err(|e| AppError::internal_from("generating CSRF secret", e))?;
    let expires_at = OffsetDateTime::now_utc() + LIFETIME;

    let row = sqlx::query!(
        r#"
        INSERT INTO sessions
            (user_id, realm_id, token_hash, csrf_secret, user_agent, ip_address,
             expires_at, authenticated_with)
        VALUES ($1, $2, $3, $4, $5, $6::text::inet, $7, $8)
        RETURNING id
        "#,
        user_id.0,
        realm_id.0,
        token.hash(),
        &csrf_secret[..],
        origin.user_agent,
        origin.ip_address.map(|ip| ip.to_string()),
        expires_at,
        &authenticated_with,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("creating session", e))?;

    Ok(Issued {
        session: Session {
            id: SessionId(row.id),
            user_id,
            realm_id,
            expires_at,
            authenticated_with,
            csrf_secret: csrf_secret.to_vec(),
        },
        token,
    })
}

/// Resolve a client token to a live session, refreshing its last-seen time.
///
/// Returns `Ok(None)` for an unknown or expired token — an absent session is
/// not an error, it is the normal state of an anonymous request.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn lookup(db: &Db, token: &SecretToken) -> Result<Option<Session>> {
    let row = sqlx::query!(
        r#"
        UPDATE sessions
        SET last_seen_at = now()
        WHERE token_hash = $1 AND expires_at > now()
        RETURNING id, user_id, realm_id, csrf_secret, expires_at, authenticated_with
        "#,
        token.hash(),
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("looking up session", e))?;

    Ok(row.map(|row| Session {
        id: SessionId(row.id),
        user_id: UserId(row.user_id),
        realm_id: RealmId(row.realm_id),
        expires_at: row.expires_at,
        authenticated_with: row.authenticated_with,
        csrf_secret: row.csrf_secret,
    }))
}

/// Delete a session. Used by logout.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn revoke(db: &Db, token: &SecretToken) -> Result<()> {
    sqlx::query!("DELETE FROM sessions WHERE token_hash = $1", token.hash())
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("revoking session", e))?;
    Ok(())
}

/// Delete every session belonging to a user.
///
/// Used after a password change, so that stealing a password no longer implies
/// keeping access once the owner recovers the account.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn revoke_all_for_user(db: &Db, user_id: UserId) -> Result<u64> {
    let result = sqlx::query!("DELETE FROM sessions WHERE user_id = $1", user_id.0)
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("revoking user sessions", e))?;
    Ok(result.rows_affected())
}

/// Remove expired sessions. Intended for a periodic job.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn purge_expired(db: &Db) -> Result<u64> {
    let result = sqlx::query!("DELETE FROM sessions WHERE expires_at <= now()")
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("purging expired sessions", e))?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    /// The `amr` of an ordinary password login, which is what these tests are
    /// about; the MFA variants are covered in `crate::mfa`.
    fn pwd() -> Vec<String> {
        vec![crate::mfa::AMR_PASSWORD.to_owned()]
    }
    use crate::{
        password::PasswordHasher,
        realm,
        user::{self, NewUser},
    };

    async fn a_user(db: &Db) -> (UserId, RealmId) {
        let hasher = PasswordHasher::new();
        let realm = realm::create(db, "acme", "Acme").await.unwrap();
        let user = user::create(
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
        .unwrap();
        (user.id, realm.id)
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_issued_token_resolves_to_its_session(db: Db) {
        let (user_id, realm_id) = a_user(&db).await;
        let issued = create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();

        let found = lookup(&db, &issued.token).await.unwrap().unwrap();
        assert_eq!(found.id, issued.session.id);
        assert_eq!(found.user_id, user_id);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn only_the_hash_is_stored(db: Db) {
        let (user_id, realm_id) = a_user(&db).await;
        let issued = create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();

        // The plaintext token must not appear anywhere in the row.
        let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM sessions")
            .fetch_one(&db)
            .await
            .unwrap();

        assert_eq!(stored, issued.token.hash());
        assert_ne!(stored, issued.token.expose().as_bytes());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_token_resolves_to_nothing(db: Db) {
        let (user_id, realm_id) = a_user(&db).await;
        create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();

        let other = SecretToken::generate().unwrap();
        assert!(lookup(&db, &other).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_expired_session_does_not_resolve(db: Db) {
        let (user_id, realm_id) = a_user(&db).await;
        let issued = create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();

        sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 second'")
            .execute(&db)
            .await
            .unwrap();

        assert!(
            lookup(&db, &issued.token).await.unwrap().is_none(),
            "expiry must be enforced on lookup, not merely recorded",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_revoked_session_stops_resolving(db: Db) {
        let (user_id, realm_id) = a_user(&db).await;
        let issued = create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();

        revoke(&db, &issued.token).await.unwrap();
        assert!(lookup(&db, &issued.token).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn revoking_all_sessions_logs_every_device_out(db: Db) {
        let (user_id, realm_id) = a_user(&db).await;
        let first = create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();
        let second = create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();

        assert_eq!(revoke_all_for_user(&db, user_id).await.unwrap(), 2);
        assert!(lookup(&db, &first.token).await.unwrap().is_none());
        assert!(lookup(&db, &second.token).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn csrf_tokens_are_bound_to_their_session(db: Db) {
        let (user_id, realm_id) = a_user(&db).await;
        let a = create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();
        let b = create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();

        assert!(a.session.csrf_token_matches(&a.session.csrf_token()));

        // The property the previous implementation lacked entirely: a token
        // minted for one session must not validate against another, even for
        // the same user.
        assert!(
            !a.session.csrf_token_matches(&b.session.csrf_token()),
            "a CSRF token must not be transferable between sessions",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn csrf_rejects_garbage_without_panicking(db: Db) {
        let (user_id, realm_id) = a_user(&db).await;
        let issued = create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();

        for bad in ["", "!!!not base64!!!", "AAAA", &"x".repeat(1000)] {
            assert!(!issued.session.csrf_token_matches(bad), "accepted {bad:?}");
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_csrf_secret_survives_a_round_trip_through_the_database(db: Db) {
        let (user_id, realm_id) = a_user(&db).await;
        let issued = create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();

        let reloaded = lookup(&db, &issued.token).await.unwrap().unwrap();
        assert!(reloaded.csrf_token_matches(&issued.session.csrf_token()));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn purging_removes_only_expired_sessions(db: Db) {
        let (user_id, realm_id) = a_user(&db).await;
        let live = create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();
        let stale = create(&db, user_id, realm_id, pwd(), Origin::default())
            .await
            .unwrap();

        sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 day' WHERE id = $1")
            .bind(stale.session.id.0)
            .execute(&db)
            .await
            .unwrap();

        assert_eq!(purge_expired(&db).await.unwrap(), 1);
        assert!(lookup(&db, &live.token).await.unwrap().is_some());
    }
}
