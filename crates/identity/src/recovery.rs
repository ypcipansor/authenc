//! Password reset and email verification.
//!
//! Both flows share a shape, and both are easy to get subtly wrong:
//!
//! * **Requesting a reset never reveals whether the address exists.** The
//!   caller gets the same answer either way; only the mail differs, and only
//!   the real owner sees that.
//! * **A token is single-use.** Redemption is one atomic `UPDATE … WHERE
//!   used_at IS NULL`, so two concurrent requests cannot both succeed.
//! * **A completed reset revokes every session** for that user. Otherwise an
//!   attacker who took the password keeps their access after the owner
//!   recovers the account.
//! * **A completed reset clears the failure history**, so the lockout an
//!   attack caused does not keep the rightful owner out.

use authenc_contract::{AppError, RealmId, Result, UserId};
use time::{Duration, OffsetDateTime};

use crate::{
    db::Db,
    mail::{Mailer, Message},
    password::PasswordHasher,
    session,
    token::SecretToken,
    user,
};

/// How long a password-reset link is valid.
pub const RESET_LIFETIME: Duration = Duration::hours(1);
/// How long an email-verification link is valid.
pub const VERIFICATION_LIFETIME: Duration = Duration::hours(24);

/// Begin a password reset.
///
/// Returns `Ok(())` whether or not the address matched an account. That is the
/// point: the response must not tell a caller which addresses are registered.
///
/// # Errors
///
/// Returns an internal error if the database or the mailer fails.
pub async fn request_password_reset(
    db: &Db,
    mailer: &dyn Mailer,
    realm_id: RealmId,
    email: &str,
    reset_url_base: &str,
) -> Result<()> {
    let Some(user_id) = user::id_by_email(db, realm_id, email).await? else {
        // Deliberately silent. Logged at debug so an operator can still see
        // what happened when investigating.
        tracing::debug!("password reset requested for an unknown address");
        return Ok(());
    };

    let secret = SecretToken::generate()
        .map_err(|e| AppError::internal_from("generating reset token", e))?;
    let expires_at = OffsetDateTime::now_utc() + RESET_LIFETIME;

    sqlx::query!(
        "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        user_id.0,
        secret.hash(),
        expires_at,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("storing reset token", e))?;

    let link = format!("{reset_url_base}?token={}", secret.expose());
    mailer
        .send(Message {
            to: email.to_owned(),
            subject: "Reset your password".to_owned(),
            body: format!(
                "Use this link within the next hour to choose a new password:\n\n{link}\n\n\
                 If you did not ask for this, you can ignore this message — \
                 your password has not changed.",
            ),
        })
        .await?;

    Ok(())
}

/// Complete a password reset.
///
/// # Errors
///
/// * [`AppError::Unauthenticated`] — the token is unknown, expired, or already
///   used. One error for all three, so a caller cannot probe which.
/// * A field error if the new password fails policy.
/// * An internal error if a write fails.
pub async fn complete_password_reset(
    db: &Db,
    hasher: &PasswordHasher,
    presented: &SecretToken,
    new_password: &str,
) -> Result<UserId> {
    // Check the password before spending the token: a policy failure should
    // leave the link usable so the user can simply try a better password.
    authenc_contract::validate::password(new_password)?;

    let row = sqlx::query!(
        r#"
        UPDATE password_reset_tokens
        SET used_at = now()
        WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
        RETURNING user_id
        "#,
        presented.hash(),
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("redeeming reset token", e))?
    .ok_or(AppError::Unauthenticated)?;

    let user_id = UserId(row.user_id);

    user::set_password(db, hasher, user_id, new_password).await?;

    // Everything that follows is what makes the reset a recovery rather than
    // just a password change.
    let revoked = session::revoke_all_for_user(db, user_id).await?;
    let user = user::by_id(db, user_id).await?;
    crate::login::clear_failures(db, user.realm_id, &user.username).await?;
    crate::login::clear_failures(db, user.realm_id, &user.email).await?;

    tracing::info!(%user_id, revoked, "password reset completed");
    Ok(user_id)
}

/// Begin email verification for a user's current address.
///
/// # Errors
///
/// Returns an internal error if the database or the mailer fails.
pub async fn request_email_verification(
    db: &Db,
    mailer: &dyn Mailer,
    user_id: UserId,
    verify_url_base: &str,
) -> Result<()> {
    let user = user::by_id(db, user_id).await?;
    if user.email_verified {
        tracing::debug!(%user_id, "email already verified; not sending");
        return Ok(());
    }

    let secret = SecretToken::generate()
        .map_err(|e| AppError::internal_from("generating verification token", e))?;
    let expires_at = OffsetDateTime::now_utc() + VERIFICATION_LIFETIME;

    sqlx::query!(
        r#"
        INSERT INTO email_verification_tokens (user_id, email, token_hash, expires_at)
        VALUES ($1, $2, $3, $4)
        "#,
        user_id.0,
        user.email,
        secret.hash(),
        expires_at,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("storing verification token", e))?;

    let link = format!("{verify_url_base}?token={}", secret.expose());
    mailer
        .send(Message {
            to: user.email.clone(),
            subject: "Confirm your email address".to_owned(),
            body: format!("Confirm this address within the next 24 hours:\n\n{link}"),
        })
        .await?;

    Ok(())
}

/// Complete email verification.
///
/// # Errors
///
/// * [`AppError::Unauthenticated`] — unknown, expired, or already-used token.
/// * An internal error if a write fails.
pub async fn complete_email_verification(db: &Db, presented: &SecretToken) -> Result<UserId> {
    let row = sqlx::query!(
        r#"
        UPDATE email_verification_tokens
        SET used_at = now()
        WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
        RETURNING user_id, email
        "#,
        presented.hash(),
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("redeeming verification token", e))?
    .ok_or(AppError::Unauthenticated)?;

    // Only mark verified if the address still matches the one the link was
    // issued for. Changing the address mid-flight must not let an old link
    // verify the new one.
    let updated = sqlx::query!(
        r#"
        UPDATE users
        SET email_verified = true, updated_at = now()
        WHERE id = $1 AND lower(email) = lower($2)
        "#,
        row.user_id,
        row.email,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("marking email verified", e))?;

    if updated.rows_affected() == 0 {
        tracing::info!("verification link no longer matches the account's address");
        return Err(AppError::Unauthenticated);
    }

    Ok(UserId(row.user_id))
}

/// Delete spent and expired recovery tokens. Intended for a periodic job.
///
/// # Errors
///
/// Returns an internal error if a delete fails.
pub async fn purge_expired(db: &Db) -> Result<u64> {
    let resets = sqlx::query!(
        "DELETE FROM password_reset_tokens WHERE expires_at <= now() OR used_at IS NOT NULL",
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("purging reset tokens", e))?;

    let verifications = sqlx::query!(
        "DELETE FROM email_verification_tokens WHERE expires_at <= now() OR used_at IS NOT NULL",
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("purging verification tokens", e))?;

    Ok(resets.rows_affected() + verifications.rows_affected())
}

/// Extract the `token` query parameter from a reset or verification link.
///
/// Present so the browser side has one implementation to call rather than
/// parsing URLs by hand. The previous console read the token with
/// `use_params`, which reads *path* parameters, on a route that had no path
/// segment — so it was always `None` and email verification could never
/// complete.
#[must_use]
pub fn token_from_query(query: &str) -> Option<SecretToken> {
    query
        .trim_start_matches('?')
        .split('&')
        .find_map(|pair| pair.strip_prefix("token="))
        .filter(|value| !value.is_empty())
        .map(SecretToken::from_client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use crate::{
        login::{self, Attempt},
        mail::CapturingMailer,
        realm,
        session::Origin,
        user::NewUser,
    };

    async fn fixture(db: &Db) -> (PasswordHasher, RealmId, UserId) {
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
        (hasher, realm.id, user.id)
    }

    fn link_token(mailer: &CapturingMailer) -> SecretToken {
        let body = mailer.sent().first().expect("a mail was sent").body.clone();
        let query = body.split("?token=").nth(1).expect("link has a token");
        let value = query.split_whitespace().next().expect("token is non-empty");
        SecretToken::from_client(value)
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_reset_link_lets_the_user_choose_a_new_password(db: Db) {
        let (hasher, realm_id, _) = fixture(&db).await;
        let mailer = CapturingMailer::new();

        request_password_reset(
            &db,
            &mailer,
            realm_id,
            "alice@example.com",
            "https://x/reset",
        )
        .await
        .unwrap();

        complete_password_reset(
            &db,
            &hasher,
            &link_token(&mailer),
            test_support::reset_password(),
        )
        .await
        .unwrap();

        let attempt = |password: &'static str| Attempt {
            realm: "acme",
            identifier: "alice",
            password,
            origin: Origin::default(),
        };

        assert!(
            login::authenticate(&db, &hasher, attempt(test_support::reset_password()))
                .await
                .is_ok()
        );
        assert!(
            login::authenticate(&db, &hasher, attempt(test_support::password()))
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn requesting_a_reset_for_an_unknown_address_looks_identical(db: Db) {
        let (_, realm_id, _) = fixture(&db).await;
        let mailer = CapturingMailer::new();

        // Same `Ok(())` for both, so the caller learns nothing.
        request_password_reset(
            &db,
            &mailer,
            realm_id,
            "nobody@example.com",
            "https://x/reset",
        )
        .await
        .unwrap();

        assert!(
            mailer.sent().is_empty(),
            "no mail to a non-existent address"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_reset_token_works_only_once(db: Db) {
        let (hasher, realm_id, _) = fixture(&db).await;
        let mailer = CapturingMailer::new();

        request_password_reset(
            &db,
            &mailer,
            realm_id,
            "alice@example.com",
            "https://x/reset",
        )
        .await
        .unwrap();
        let token = link_token(&mailer);

        complete_password_reset(&db, &hasher, &token, test_support::reset_password())
            .await
            .unwrap();

        let error =
            complete_password_reset(&db, &hasher, &token, &test_support::another_password())
                .await
                .unwrap_err();
        assert_eq!(error.status(), 401, "a spent link must not work again");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_expired_reset_token_is_refused(db: Db) {
        let (hasher, realm_id, _) = fixture(&db).await;
        let mailer = CapturingMailer::new();

        request_password_reset(
            &db,
            &mailer,
            realm_id,
            "alice@example.com",
            "https://x/reset",
        )
        .await
        .unwrap();
        sqlx::query("UPDATE password_reset_tokens SET expires_at = now() - interval '1 second'")
            .execute(&db)
            .await
            .unwrap();

        let error = complete_password_reset(
            &db,
            &hasher,
            &link_token(&mailer),
            test_support::reset_password(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status(), 401);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_reset_token_is_refused(db: Db) {
        let (hasher, _, _) = fixture(&db).await;
        let error = complete_password_reset(
            &db,
            &hasher,
            &SecretToken::generate().unwrap(),
            test_support::reset_password(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status(), 401);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_weak_new_password_leaves_the_link_usable(db: Db) {
        let (hasher, realm_id, _) = fixture(&db).await;
        let mailer = CapturingMailer::new();

        request_password_reset(
            &db,
            &mailer,
            realm_id,
            "alice@example.com",
            "https://x/reset",
        )
        .await
        .unwrap();
        let token = link_token(&mailer);

        assert_eq!(
            complete_password_reset(&db, &hasher, &token, &test_support::short_password())
                .await
                .unwrap_err()
                .status(),
            400,
        );

        // The token must not have been spent by the rejected attempt.
        assert!(
            complete_password_reset(&db, &hasher, &token, test_support::reset_password())
                .await
                .is_ok(),
            "a policy failure must not burn the reset link",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn completing_a_reset_logs_every_session_out(db: Db) {
        let (hasher, realm_id, user_id) = fixture(&db).await;
        let mailer = CapturingMailer::new();

        let existing = session::create(
            &db,
            user_id,
            realm_id,
            vec!["pwd".to_owned()],
            Origin::default(),
        )
        .await
        .unwrap();

        request_password_reset(
            &db,
            &mailer,
            realm_id,
            "alice@example.com",
            "https://x/reset",
        )
        .await
        .unwrap();
        complete_password_reset(
            &db,
            &hasher,
            &link_token(&mailer),
            test_support::reset_password(),
        )
        .await
        .unwrap();

        assert!(
            session::lookup(&db, &existing.token)
                .await
                .unwrap()
                .is_none(),
            "an attacker holding a session must lose it when the owner recovers",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn completing_a_reset_lifts_the_lockout_the_attack_caused(db: Db) {
        let (hasher, realm_id, _) = fixture(&db).await;
        let mailer = CapturingMailer::new();

        for _ in 0..=login::MAX_ATTEMPTS_PER_IDENTIFIER {
            let _ = login::authenticate(
                &db,
                &hasher,
                Attempt {
                    realm: "acme",
                    identifier: "alice",
                    password: &test_support::wrong_password(),
                    origin: Origin::default(),
                },
            )
            .await;
        }

        request_password_reset(
            &db,
            &mailer,
            realm_id,
            "alice@example.com",
            "https://x/reset",
        )
        .await
        .unwrap();
        complete_password_reset(
            &db,
            &hasher,
            &link_token(&mailer),
            test_support::reset_password(),
        )
        .await
        .unwrap();

        assert!(
            login::authenticate(
                &db,
                &hasher,
                Attempt {
                    realm: "acme",
                    identifier: "alice",
                    password: test_support::reset_password(),
                    origin: Origin::default(),
                },
            )
            .await
            .is_ok(),
            "the rightful owner must not stay locked out after recovering",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_verification_link_marks_the_address_proven(db: Db) {
        let (_, _, user_id) = fixture(&db).await;
        let mailer = CapturingMailer::new();

        assert!(!user::by_id(&db, user_id).await.unwrap().email_verified);

        request_email_verification(&db, &mailer, user_id, "https://x/verify")
            .await
            .unwrap();
        complete_email_verification(&db, &link_token(&mailer))
            .await
            .unwrap();

        assert!(user::by_id(&db, user_id).await.unwrap().email_verified);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_verification_token_works_only_once(db: Db) {
        let (_, _, user_id) = fixture(&db).await;
        let mailer = CapturingMailer::new();

        request_email_verification(&db, &mailer, user_id, "https://x/verify")
            .await
            .unwrap();
        let token = link_token(&mailer);

        complete_email_verification(&db, &token).await.unwrap();
        assert_eq!(
            complete_email_verification(&db, &token)
                .await
                .unwrap_err()
                .status(),
            401,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_link_cannot_verify_an_address_changed_after_it_was_sent(db: Db) {
        let (_, _, user_id) = fixture(&db).await;
        let mailer = CapturingMailer::new();

        request_email_verification(&db, &mailer, user_id, "https://x/verify")
            .await
            .unwrap();

        // The user changes their address before clicking the old link.
        sqlx::query("UPDATE users SET email = 'elsewhere@example.com' WHERE id = $1")
            .bind(user_id.0)
            .execute(&db)
            .await
            .unwrap();

        assert_eq!(
            complete_email_verification(&db, &link_token(&mailer))
                .await
                .unwrap_err()
                .status(),
            401,
        );
        assert!(!user::by_id(&db, user_id).await.unwrap().email_verified);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn purging_removes_spent_and_expired_tokens(db: Db) {
        let (hasher, realm_id, _) = fixture(&db).await;
        let mailer = CapturingMailer::new();

        request_password_reset(
            &db,
            &mailer,
            realm_id,
            "alice@example.com",
            "https://x/reset",
        )
        .await
        .unwrap();
        complete_password_reset(
            &db,
            &hasher,
            &link_token(&mailer),
            test_support::reset_password(),
        )
        .await
        .unwrap();

        assert_eq!(purge_expired(&db).await.unwrap(), 1);
    }

    #[test]
    fn a_token_is_read_out_of_the_query_string() {
        // The defect this replaces: the previous console used `use_params`,
        // which reads path parameters, so the token was always absent.
        assert_eq!(
            token_from_query("?token=abc123").map(|t| t.expose().to_owned()),
            Some("abc123".to_owned()),
        );
        assert_eq!(
            token_from_query("x=1&token=abc123&y=2").map(|t| t.expose().to_owned()),
            Some("abc123".to_owned()),
        );
        assert!(token_from_query("").is_none());
        assert!(token_from_query("?token=").is_none());
        assert!(token_from_query("?other=abc").is_none());
    }
}
