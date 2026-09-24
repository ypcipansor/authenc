//! Authenticating a user.
//!
//! This is the one place a password is checked, and the shape of the function
//! is most of the security. Three properties are load-bearing:
//!
//! 1. **A wrong password and an unknown user are indistinguishable** — same
//!    error, and the same amount of work, because skipping the hash when the
//!    user does not exist turns response time into a user-enumeration oracle.
//! 2. **Lockout is checked before the password is**, so a locked account costs
//!    an attacker a database lookup rather than an Argon2 verification.
//! 3. **Every attempt is recorded**, successful or not, because that record is
//!    both the lockout input and the answer to "was this account attacked?".
//!
//! A fourth property arrived with second factors, and it is the reason
//! [`authenticate`] returns an [`Outcome`] rather than a session: when a user
//! has one enrolled, **a correct password does not open a session**. It opens
//! a [`challenge::Pending`], which is a different type in a different table
//! that no session lookup can resolve. The alternative — issue the session,
//! then ask for the code — makes "was the second factor checked?" a property
//! of the login page rather than of the system, and a page is a thing one can
//! forget to write.

use std::net::IpAddr;

// Deliberately only `Action`: this module has its own `Outcome`, meaning "what
// the password bought", and the audit crate's means "did it work". Importing
// both would make every use of the word ambiguous to a reader even where the
// compiler could tell them apart. `Entry::success`/`failure` carry the other
// one.
use authenc_contract::{AppError, RealmId, Result, UserId, event::Action, model::User};
use time::{Duration, OffsetDateTime};

use crate::{
    audit::{self, Entry},
    db::Db,
    mfa::{self, Factor, challenge, recovery, totp},
    organization,
    password::PasswordHasher,
    sealed::MasterKey,
    session::{self, Issued, Origin},
    token::SecretToken,
    user,
};

/// Failed attempts against one identifier before it is locked.
pub const MAX_ATTEMPTS_PER_IDENTIFIER: i64 = 5;
/// Failed attempts from one address before it is locked, across all accounts.
///
/// Higher than the per-identifier limit because a shared NAT address is a
/// normal thing, but low enough to make credential stuffing expensive.
pub const MAX_ATTEMPTS_PER_ADDRESS: i64 = 30;
/// How far back failed attempts are counted, and therefore how long a lockout
/// lasts once attempts stop.
pub const WINDOW: Duration = Duration::minutes(15);

/// What the caller supplies to authenticate someone.
#[derive(Debug, Clone, Copy)]
pub struct Attempt<'a> {
    /// Realm slug.
    pub realm: &'a str,
    /// Username or email.
    pub identifier: &'a str,
    /// Submitted password.
    pub password: &'a str,
    /// Where the request came from.
    pub origin: Origin<'a>,
}

/// A completed authentication: the user is signed in.
#[derive(Debug)]
pub struct Authenticated {
    /// The user who authenticated.
    pub user: User,
    /// Their new session, and the token for the cookie.
    pub session: Issued,
}

/// What a correct password bought.
///
/// Deliberately an enum with no `Deref` and no `unwrap`-shaped accessor: the
/// caller has to name which case it is handling, and there is no way to reach
/// a session out of the pending one.
#[derive(Debug)]
pub enum Outcome {
    /// No second factor enrolled. The session exists and the cookie can be set.
    Complete(Box<Authenticated>),
    /// A second factor is enrolled. **Nobody is signed in yet.**
    SecondFactorRequired(Box<Challenged>),
}

/// A login waiting on its second factor.
#[derive(Debug)]
pub struct Challenged {
    /// Who is signing in. Needed to render the prompt; carries no authority.
    pub user: User,
    /// The pending challenge and the token that identifies it.
    pub issued: challenge::Issued,
    /// What this user could present.
    pub factors: Vec<Factor>,
}

/// Check a password, and either open a session or demand a second factor.
///
/// # Errors
///
/// * [`AppError::Unauthenticated`] — wrong credentials, unknown user, disabled
///   user, or disabled realm. Deliberately the same error for all of them.
/// * [`AppError::RateLimited`] — too many recent failures for this identifier
///   or from this address.
/// * [`AppError::Internal`] — the database or the hasher failed.
pub async fn authenticate(
    db: &Db,
    hasher: &PasswordHasher,
    attempt: Attempt<'_>,
) -> Result<Outcome> {
    let realm = crate::realm::by_name(db, attempt.realm)
        .await
        .map_err(|error| match error.status() {
            // Do not confirm which realms exist to an unauthenticated caller.
            404 => AppError::Unauthenticated,
            _ => error,
        })?;

    if !realm.enabled {
        return Err(AppError::Unauthenticated);
    }

    if is_locked(db, realm.id, attempt.identifier, attempt.origin.ip_address).await? {
        // Recorded so that an attacker hammering a locked account still shows
        // up in the attempt history.
        record(
            db,
            realm.id,
            attempt.identifier,
            None,
            attempt.origin,
            false,
        )
        .await?;

        audit::observe(
            db,
            Entry::failure(Action::LoginLockedOut)
                .in_realm(realm.id)
                .by_name(attempt.identifier)
                .from(attempt.origin),
        )
        .await;

        return Err(AppError::RateLimited);
    }

    let found = user::credentialed_by_identifier(db, realm.id, attempt.identifier).await?;

    // Verify against a real hash whether or not the user exists, so the timing
    // of the two cases matches. `DUMMY_PHC` is a hash of a random string; it
    // can never verify.
    let (user, phc) = match &found {
        Some(credentialed) => (
            Some(&credentialed.user),
            credentialed.phc.as_deref().unwrap_or(DUMMY_PHC),
        ),
        None => (None, DUMMY_PHC),
    };

    let password_ok = hasher.verify(attempt.password, phc).unwrap_or(false);
    let enabled = user.is_some_and(|u| u.enabled);

    if !password_ok || !enabled {
        record(
            db,
            realm.id,
            attempt.identifier,
            user.map(|u| u.id),
            attempt.origin,
            false,
        )
        .await?;

        // Recorded with the identifier as typed, not resolved to a user: the
        // interesting case is exactly the one where no such account exists,
        // and a record naming nobody would hide the probing worth seeing.
        audit::observe(
            db,
            Entry::failure(Action::LoginFailed)
                .in_realm(realm.id)
                .from(attempt.origin),
        )
        .await;

        return Err(AppError::Unauthenticated);
    }

    let user = user.cloned().ok_or(AppError::Unauthenticated)?;

    // A suspended organisation stops its members signing in. Checked after the
    // password, not before, so the answer does not differ by timing between a
    // suspended account and a wrong password — and reported as the same
    // `Unauthenticated` for the same reason.
    if organization::blocks_sign_in(db, user.id).await? {
        record(
            db,
            realm.id,
            attempt.identifier,
            Some(user.id),
            attempt.origin,
            false,
        )
        .await?;

        audit::observe(
            db,
            Entry::failure(Action::LoginFailed)
                .in_realm(realm.id)
                .by(user.id, &user.username)
                .from(attempt.origin)
                .detail(serde_json::json!({ "reason": "organization_suspended" })),
        )
        .await;

        return Err(AppError::Unauthenticated);
    }

    // Take the opportunity to upgrade a hash made under weaker parameters.
    if hasher.needs_rehash(phc)
        && let Err(error) = user::set_password(db, hasher, user.id, attempt.password).await
    {
        // Not fatal: the user authenticated correctly, and failing the login
        // over a background upgrade would be worse than leaving the old hash.
        tracing::warn!(%error, user_id = %user.id, "failed to upgrade password hash");
    }

    record(
        db,
        realm.id,
        attempt.identifier,
        Some(user.id),
        attempt.origin,
        true,
    )
    .await?;

    // The branch that matters. Note what is *not* here: no session is created
    // before the enrolment is known, so there is no window in which a
    // half-authenticated caller holds a usable cookie.
    let enrolment = mfa::enrolment(db, user.id).await?;
    if enrolment.is_required() {
        let issued = challenge::issue(
            db,
            user.id,
            realm.id,
            mfa::FirstFactor::Password,
            attempt.origin,
        )
        .await?;

        audit::observe(
            db,
            Entry::success(Action::SecondFactorRequired)
                .in_realm(realm.id)
                .by(user.id, &user.username)
                .from(attempt.origin),
        )
        .await;

        return Ok(Outcome::SecondFactorRequired(Box::new(Challenged {
            user,
            issued,
            factors: enrolment.available(),
        })));
    }

    let session = session::create(
        db,
        user.id,
        realm.id,
        mfa::amr_for(mfa::FirstFactor::Password, None),
        attempt.origin,
    )
    .await?;

    audit::observe(
        db,
        Entry::success(Action::LoginSucceeded)
            .in_realm(realm.id)
            .by(user.id, &user.username)
            .from(attempt.origin),
    )
    .await;

    Ok(Outcome::Complete(Box::new(Authenticated { user, session })))
}

/// A second factor a caller is offering.
#[derive(Debug, Clone, Copy)]
pub enum Proof<'a> {
    /// A code from an authenticator app.
    Totp(&'a str),
    /// One of the codes issued when the factor was enrolled.
    RecoveryCode(&'a str),
}

impl Proof<'_> {
    const fn factor(self) -> Factor {
        match self {
            Self::Totp(_) => Factor::Totp,
            Self::RecoveryCode(_) => Factor::RecoveryCode,
        }
    }
}

/// Complete a login by presenting a second factor.
///
/// The challenge is spent whether or not the proof is good — a correct one
/// opens exactly one session, and a wrong one costs an attempt from a budget
/// that runs out. That budget is the only thing standing between a six-digit
/// code and an attacker with a script.
///
/// # Errors
///
/// * [`AppError::Unauthenticated`] — the challenge is unknown, expired, spent,
///   out of attempts, or the proof did not verify.
/// * [`AppError::Internal`] — the database failed.
pub async fn second_factor(
    db: &Db,
    master: &MasterKey,
    token: &SecretToken,
    proof: Proof<'_>,
    origin: Origin<'_>,
) -> Result<Authenticated> {
    let pending = challenge::lookup(db, token)
        .await?
        .ok_or(AppError::Unauthenticated)?;

    let accepted = match proof {
        Proof::Totp(code) => totp::verify(db, master, pending.user_id, code).await?,
        Proof::RecoveryCode(code) => recovery::claim(db, pending.user_id, code).await?,
    };

    if !accepted {
        challenge::record_failure(db, pending.id).await?;

        audit::observe(
            db,
            Entry::failure(Action::SecondFactorFailed)
                .in_realm(pending.realm_id)
                .from(origin)
                .detail(serde_json::json!({ "factor": proof.factor() })),
        )
        .await;

        return Err(AppError::Unauthenticated);
    }

    open_session(db, &pending, proof.factor(), origin).await
}

/// Turn a satisfied challenge into a session.
///
/// Shared by every second factor, including the passkey path in
/// [`crate::mfa::passkey`], so that "the challenge is spent exactly once" and
/// "the session records which factor was used" cannot be true on one route and
/// false on another.
///
/// # Errors
///
/// Returns [`AppError::Unauthenticated`] if the challenge was already spent.
pub async fn open_session(
    db: &Db,
    pending: &challenge::Pending,
    factor: Factor,
    origin: Origin<'_>,
) -> Result<Authenticated> {
    // Atomic: two requests racing with the same correct code produce one
    // session, not two.
    if !challenge::consume(db, pending.id).await? {
        return Err(AppError::Unauthenticated);
    }

    let user = user::by_id(db, pending.user_id).await?;
    let session = session::create(
        db,
        pending.user_id,
        pending.realm_id,
        mfa::amr_for(pending.first_factor, Some(factor)),
        origin,
    )
    .await?;

    audit::observe(
        db,
        Entry::success(Action::SecondFactorSucceeded)
            .in_realm(pending.realm_id)
            .by(user.id, &user.username)
            .from(origin)
            .detail(serde_json::json!({ "factor": factor })),
    )
    .await;

    // A recovery code is worth its own line: it means the user could not use
    // their usual factor, which is either a lost phone or somebody else.
    if factor == Factor::RecoveryCode {
        audit::observe(
            db,
            Entry::success(Action::RecoveryCodeUsed)
                .in_realm(pending.realm_id)
                .by(user.id, &user.username)
                .from(origin),
        )
        .await;
    }

    Ok(Authenticated { user, session })
}

/// An Argon2id hash of a value no one knows, used to equalise the timing of
/// the "no such user" path with the "wrong password" path.
const DUMMY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1\
$c29tZXNhbHRzb21lc2FsdA$Yl5rN0zCJKcCwvB5PLQVOCB6BE6cN4RQtvSHnKqLQBg";

/// Whether this identifier or address currently exceeds the failure budget.
async fn is_locked(
    db: &Db,
    realm_id: RealmId,
    identifier: &str,
    ip: Option<IpAddr>,
) -> Result<bool> {
    let since = OffsetDateTime::now_utc() - WINDOW;

    let by_identifier = sqlx::query_scalar!(
        r#"
        SELECT count(*) AS "count!"
        FROM login_attempts
        WHERE realm_id = $1
          AND lower(identifier) = lower($2)
          AND NOT successful
          AND attempted_at > $3
        "#,
        realm_id.0,
        identifier,
        since,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("counting failed attempts", e))?;

    if by_identifier >= MAX_ATTEMPTS_PER_IDENTIFIER {
        return Ok(true);
    }

    let Some(ip) = ip else {
        return Ok(false);
    };

    let by_address = sqlx::query_scalar!(
        r#"
        SELECT count(*) AS "count!"
        FROM login_attempts
        WHERE ip_address = $1::text::inet
          AND NOT successful
          AND attempted_at > $2
        "#,
        ip.to_string(),
        since,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("counting failed attempts by address", e))?;

    Ok(by_address >= MAX_ATTEMPTS_PER_ADDRESS)
}

/// Record an attempt.
async fn record(
    db: &Db,
    realm_id: RealmId,
    identifier: &str,
    user_id: Option<UserId>,
    origin: Origin<'_>,
    successful: bool,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO login_attempts (realm_id, identifier, user_id, ip_address, successful)
        VALUES ($1, $2, $3, $4::text::inet, $5)
        "#,
        realm_id.0,
        identifier,
        user_id.map(|id| id.0),
        origin.ip_address.map(|ip| ip.to_string()),
        successful,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("recording login attempt", e))?;

    Ok(())
}

/// Clear the failure history for an identifier — used after a successful
/// password reset, so a locked-out owner is not kept out by the attack that
/// prompted the reset.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn clear_failures(db: &Db, realm_id: RealmId, identifier: &str) -> Result<()> {
    sqlx::query!(
        r#"
        DELETE FROM login_attempts
        WHERE realm_id = $1 AND lower(identifier) = lower($2) AND NOT successful
        "#,
        realm_id.0,
        identifier,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("clearing login failures", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use crate::{
        realm,
        user::{self, NewUser},
    };

    async fn fixture(db: &Db) -> (PasswordHasher, User) {
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
        (hasher, user)
    }

    /// Unwrap a login that should not have needed a second factor.
    ///
    /// A function rather than a method, deliberately: reaching a session out of
    /// an [`Outcome`] should be something a caller writes down, not something
    /// that happens by accident.
    #[track_caller]
    fn completed(outcome: Outcome) -> Authenticated {
        match outcome {
            Outcome::Complete(authenticated) => *authenticated,
            Outcome::SecondFactorRequired(_) => {
                panic!("expected a completed login, got a second-factor challenge")
            }
        }
    }

    #[track_caller]
    fn challenged(outcome: Outcome) -> Challenged {
        match outcome {
            Outcome::SecondFactorRequired(challenged) => *challenged,
            Outcome::Complete(_) => panic!("expected a second-factor challenge"),
        }
    }

    fn attempt<'a>(identifier: &'a str, password: &'a str) -> Attempt<'a> {
        Attempt {
            realm: "acme",
            identifier,
            password,
            origin: Origin::default(),
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn correct_credentials_open_a_session(db: Db) {
        let (hasher, user) = fixture(&db).await;

        let result = completed(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );

        assert_eq!(result.user.id, user.id);
        let resolved = session::lookup(&db, &result.session.token)
            .await
            .unwrap()
            .expect("the issued token must resolve");
        assert_eq!(resolved.user_id, user.id);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_email_address_works_as_the_identifier(db: Db) {
        let (hasher, _) = fixture(&db).await;
        assert!(
            authenticate(
                &db,
                &hasher,
                attempt("ALICE@example.com", test_support::password())
            )
            .await
            .is_ok()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_wrong_password_and_an_unknown_user_are_indistinguishable(db: Db) {
        let (hasher, _) = fixture(&db).await;

        let wrong_password = authenticate(
            &db,
            &hasher,
            attempt("alice", &test_support::wrong_password()),
        )
        .await
        .unwrap_err();
        let unknown_user = authenticate(&db, &hasher, attempt("nobody", test_support::password()))
            .await
            .unwrap_err();

        // Same status and same message: anything else lets a caller enumerate
        // which accounts exist.
        assert_eq!(wrong_password.status(), 401);
        assert_eq!(unknown_user.status(), 401);
        assert_eq!(wrong_password.to_string(), unknown_user.to_string());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_realm_does_not_reveal_itself(db: Db) {
        let (hasher, _) = fixture(&db).await;

        let error = authenticate(
            &db,
            &hasher,
            Attempt {
                realm: "no-such-realm",
                identifier: "alice",
                password: test_support::password(),
                origin: Origin::default(),
            },
        )
        .await
        .unwrap_err();

        // 401, not 404: a 404 would confirm which realms exist.
        assert_eq!(error.status(), 401);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_disabled_user_cannot_authenticate(db: Db) {
        let (hasher, user) = fixture(&db).await;
        sqlx::query("UPDATE users SET enabled = false WHERE id = $1")
            .bind(user.id.0)
            .execute(&db)
            .await
            .unwrap();

        let error = authenticate(&db, &hasher, attempt("alice", test_support::password()))
            .await
            .unwrap_err();
        assert_eq!(error.status(), 401);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_disabled_realm_blocks_authentication(db: Db) {
        let (hasher, _) = fixture(&db).await;
        sqlx::query("UPDATE realms SET enabled = false")
            .execute(&db)
            .await
            .unwrap();

        let error = authenticate(&db, &hasher, attempt("alice", test_support::password()))
            .await
            .unwrap_err();
        assert_eq!(error.status(), 401);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn repeated_failures_lock_the_account(db: Db) {
        let (hasher, _) = fixture(&db).await;

        for _ in 0..MAX_ATTEMPTS_PER_IDENTIFIER {
            let error = authenticate(
                &db,
                &hasher,
                attempt("alice", &test_support::wrong_password()),
            )
            .await
            .unwrap_err();
            assert_eq!(error.status(), 401);
        }

        let error = authenticate(
            &db,
            &hasher,
            attempt("alice", &test_support::wrong_password()),
        )
        .await
        .unwrap_err();
        assert_eq!(error.status(), 429, "should be locked by now");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn lockout_holds_even_against_the_correct_password(db: Db) {
        let (hasher, _) = fixture(&db).await;

        for _ in 0..MAX_ATTEMPTS_PER_IDENTIFIER {
            let _ = authenticate(
                &db,
                &hasher,
                attempt("alice", &test_support::wrong_password()),
            )
            .await;
        }

        // The whole point: an attacker who guesses correctly on attempt six
        // must still be turned away.
        let error = authenticate(&db, &hasher, attempt("alice", test_support::password()))
            .await
            .unwrap_err();
        assert_eq!(error.status(), 429);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn lockout_is_scoped_to_the_identifier_attacked(db: Db) {
        let (hasher, _) = fixture(&db).await;
        let realm = realm::by_name(&db, "acme").await.unwrap();
        user::create(
            &db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "bob",
                email: "bob@example.com",
                password: test_support::password(),
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap();

        for _ in 0..=MAX_ATTEMPTS_PER_IDENTIFIER {
            let _ = authenticate(
                &db,
                &hasher,
                attempt("alice", &test_support::wrong_password()),
            )
            .await;
        }

        // Attacking one account must not lock everyone else out.
        assert!(
            authenticate(&db, &hasher, attempt("bob", test_support::password()))
                .await
                .is_ok()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn failures_outside_the_window_do_not_count(db: Db) {
        let (hasher, _) = fixture(&db).await;

        for _ in 0..=MAX_ATTEMPTS_PER_IDENTIFIER {
            let _ = authenticate(
                &db,
                &hasher,
                attempt("alice", &test_support::wrong_password()),
            )
            .await;
        }
        assert_eq!(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap_err()
                .status(),
            429,
        );

        // Age the attempts past the window; the lock must lift on its own.
        sqlx::query("UPDATE login_attempts SET attempted_at = now() - interval '1 hour'")
            .execute(&db)
            .await
            .unwrap();

        assert!(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .is_ok(),
            "lockout must expire without an administrator",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn every_attempt_is_recorded(db: Db) {
        let (hasher, _) = fixture(&db).await;

        let _ = authenticate(
            &db,
            &hasher,
            attempt("alice", &test_support::wrong_password()),
        )
        .await;
        authenticate(&db, &hasher, attempt("alice", test_support::password()))
            .await
            .unwrap();

        let (failures, successes): (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE NOT successful), \
                    count(*) FILTER (WHERE successful) FROM login_attempts",
        )
        .fetch_one(&db)
        .await
        .unwrap();

        assert_eq!(failures, 1);
        assert_eq!(successes, 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn clearing_failures_lifts_a_lockout(db: Db) {
        let (hasher, _) = fixture(&db).await;
        let realm = realm::by_name(&db, "acme").await.unwrap();

        for _ in 0..=MAX_ATTEMPTS_PER_IDENTIFIER {
            let _ = authenticate(
                &db,
                &hasher,
                attempt("alice", &test_support::wrong_password()),
            )
            .await;
        }

        clear_failures(&db, realm.id, "alice").await.unwrap();

        assert!(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .is_ok(),
            "a password reset must let the rightful owner back in",
        );
    }

    // -----------------------------------------------------------------------
    // Second factors
    // -----------------------------------------------------------------------

    fn master() -> MasterKey {
        MasterKey::generate().unwrap()
    }

    /// Enrol a working authenticator and return its secret.
    ///
    /// Confirmation deliberately uses the **previous** step's code, which the
    /// drift window accepts. Confirming spends whichever step it matched, so
    /// enrolling with the current code would leave the current code already
    /// spent — correct behaviour, and a poor starting point for a test about
    /// signing in. `the_confirming_code_cannot_then_sign_you_in` covers that
    /// property directly.
    async fn enrol_totp(db: &Db, master: &MasterKey, user_id: UserId) -> totp::Secret {
        let enrolling = totp::begin_enrolment(db, master, user_id, "Phone")
            .await
            .unwrap();
        let secret = enrolling.secret.clone();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let code = totp::code_at(secret.as_bytes(), totp::step_at(now) - 1, totp::DIGITS);
        assert!(totp::confirm(db, master, user_id, &code).await.unwrap());
        secret
    }

    fn current_code(secret: &totp::Secret) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        totp::code_at(secret.as_bytes(), totp::step_at(now), totp::DIGITS)
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_correct_password_alone_opens_no_session_when_a_factor_is_enrolled(db: Db) {
        // The single most important test in this file. If this ever passes a
        // session back, every route that reads the session cookie is reachable
        // with a password alone and the second factor is decoration.
        let (hasher, user) = fixture(&db).await;
        let master = master();
        enrol_totp(&db, &master, user.id).await;

        let outcome = authenticate(&db, &hasher, attempt("alice", test_support::password()))
            .await
            .unwrap();
        let challenged = challenged(outcome);

        assert_eq!(challenged.user.id, user.id);
        assert_eq!(challenged.factors, vec![Factor::Totp]);

        // And nothing that resolves a session cookie will accept the handle
        // this login produced.
        assert!(
            session::lookup(&db, &challenged.issued.token)
                .await
                .unwrap()
                .is_none(),
            "an MFA challenge token must not resolve as a session",
        );

        let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(sessions, 0, "no session may exist yet");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_correct_code_completes_the_login(db: Db) {
        let (hasher, user) = fixture(&db).await;
        let master = master();
        let secret = enrol_totp(&db, &master, user.id).await;

        let challenged = challenged(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );

        let authenticated = second_factor(
            &db,
            &master,
            &challenged.issued.token,
            Proof::Totp(&current_code(&secret)),
            Origin::default(),
        )
        .await
        .unwrap();

        assert_eq!(authenticated.user.id, user.id);
        let resolved = session::lookup(&db, &authenticated.session.token)
            .await
            .unwrap()
            .expect("the session must resolve");
        assert_eq!(resolved.user_id, user.id);
        assert_eq!(resolved.authenticated_with, vec!["pwd", "otp", "mfa"]);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_confirming_code_cannot_then_sign_you_in(db: Db) {
        // Confirming an enrolment is a use of the code, so it spends its step
        // like any other. Otherwise the code a user reads out once during setup
        // stays live for its whole window and can be replayed straight into a
        // session.
        let (hasher, user) = fixture(&db).await;
        let master = master();

        let enrolling = totp::begin_enrolment(&db, &master, user.id, "Phone")
            .await
            .unwrap();
        let secret = enrolling.secret.clone();
        let code = current_code(&secret);
        assert!(totp::confirm(&db, &master, user.id, &code).await.unwrap());

        let challenged = challenged(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );

        assert_eq!(
            second_factor(
                &db,
                &master,
                &challenged.issued.token,
                Proof::Totp(&code),
                Origin::default(),
            )
            .await
            .unwrap_err()
            .status(),
            401,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_code_cannot_be_spent_twice(db: Db) {
        // Two challenges, one code. The second must fail even though the code
        // is still inside its time window.
        let (hasher, user) = fixture(&db).await;
        let master = master();
        let secret = enrol_totp(&db, &master, user.id).await;
        let code = current_code(&secret);

        let first = challenged(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );
        assert!(
            second_factor(
                &db,
                &master,
                &first.issued.token,
                Proof::Totp(&code),
                Origin::default(),
            )
            .await
            .is_ok()
        );

        let second = challenged(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );
        assert_eq!(
            second_factor(
                &db,
                &master,
                &second.issued.token,
                Proof::Totp(&code),
                Origin::default(),
            )
            .await
            .unwrap_err()
            .status(),
            401,
            "a replayed code must not open a second session",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn one_challenge_opens_at_most_one_session(db: Db) {
        let (hasher, user) = fixture(&db).await;
        let master = master();
        let secret = enrol_totp(&db, &master, user.id).await;

        let challenged = challenged(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );
        let code = current_code(&secret);

        assert!(
            second_factor(
                &db,
                &master,
                &challenged.issued.token,
                Proof::Totp(&code),
                Origin::default(),
            )
            .await
            .is_ok()
        );
        assert!(
            second_factor(
                &db,
                &master,
                &challenged.issued.token,
                Proof::Totp(&code),
                Origin::default(),
            )
            .await
            .is_err(),
            "the challenge must be spent",
        );

        let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(sessions, 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn wrong_codes_exhaust_the_challenge(db: Db) {
        // What keeps a six-digit code out of reach of a script.
        let (hasher, user) = fixture(&db).await;
        let master = master();
        let secret = enrol_totp(&db, &master, user.id).await;

        let challenged = challenged(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );

        for _ in 0..challenge::MAX_ATTEMPTS {
            assert!(
                second_factor(
                    &db,
                    &master,
                    &challenged.issued.token,
                    Proof::Totp("000000"),
                    Origin::default(),
                )
                .await
                .is_err()
            );
        }

        // Even the right code cannot rescue a spent budget.
        assert!(
            second_factor(
                &db,
                &master,
                &challenged.issued.token,
                Proof::Totp(&current_code(&secret)),
                Origin::default(),
            )
            .await
            .is_err(),
            "the challenge must be dead once the budget is gone",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_challenge_token_is_refused(db: Db) {
        let (_, user) = fixture(&db).await;
        let master = master();
        enrol_totp(&db, &master, user.id).await;

        let invented = SecretToken::generate().unwrap();
        assert_eq!(
            second_factor(
                &db,
                &master,
                &invented,
                Proof::Totp("000000"),
                Origin::default(),
            )
            .await
            .unwrap_err()
            .status(),
            401,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_recovery_code_also_completes_the_login(db: Db) {
        let (hasher, user) = fixture(&db).await;
        let master = master();
        enrol_totp(&db, &master, user.id).await;
        let codes = recovery::generate(&db, user.id).await.unwrap();

        let challenged = challenged(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );

        let authenticated = second_factor(
            &db,
            &master,
            &challenged.issued.token,
            Proof::RecoveryCode(&codes.expose()[0]),
            Origin::default(),
        )
        .await
        .unwrap();

        let resolved = session::lookup(&db, &authenticated.session.token)
            .await
            .unwrap()
            .unwrap();
        // `mfa` is asserted, but no method is named: see `mfa::Factor::amr`.
        assert_eq!(resolved.authenticated_with, vec!["pwd", "mfa"]);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unconfirmed_enrolment_does_not_gate_a_login(db: Db) {
        // Someone who started enrolling and closed the tab must still be able
        // to sign in, or the feature locks people out of their own accounts.
        let (hasher, user) = fixture(&db).await;
        let master = master();
        totp::begin_enrolment(&db, &master, user.id, "Phone")
            .await
            .unwrap();

        let authenticated = completed(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );
        assert_eq!(authenticated.user.id, user.id);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn recovery_codes_alone_do_not_demand_a_second_factor(db: Db) {
        // Generating codes without an authenticator must not turn MFA on.
        let (hasher, user) = fixture(&db).await;
        recovery::generate(&db, user.id).await.unwrap();

        assert!(matches!(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
            Outcome::Complete(_),
        ));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_password_only_session_says_so(db: Db) {
        let (hasher, _) = fixture(&db).await;
        let authenticated = completed(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );
        let resolved = session::lookup(&db, &authenticated.session.token)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved.authenticated_with, vec!["pwd"]);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn another_users_code_does_not_satisfy_this_challenge(db: Db) {
        let (hasher, alice) = fixture(&db).await;
        let master = master();
        let realm = realm::by_name(&db, "acme").await.unwrap();
        let bob = user::create(
            &db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "bob",
                email: "bob@example.com",
                password: test_support::password(),
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap();

        enrol_totp(&db, &master, alice.id).await;
        let bobs_secret = enrol_totp(&db, &master, bob.id).await;

        let alices = challenged(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );

        assert_eq!(
            second_factor(
                &db,
                &master,
                &alices.issued.token,
                Proof::Totp(&current_code(&bobs_secret)),
                Origin::default(),
            )
            .await
            .unwrap_err()
            .status(),
            401,
        );
    }

    // -----------------------------------------------------------------------
    // The audit trail
    // -----------------------------------------------------------------------
    //
    // Wiring a recorder in is easy to get almost right — an event written with
    // the wrong realm, or only on the success path, looks fine until the log is
    // needed. These assert what actually lands.

    async fn recorded(db: &Db, realm_id: RealmId) -> Vec<Action> {
        audit::list(db, realm_id, audit::Filter::default(), 50, 0)
            .await
            .unwrap()
            .into_iter()
            .map(|event| event.action)
            .collect()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_successful_password_login_is_recorded(db: Db) {
        let (hasher, user) = fixture(&db).await;
        authenticate(&db, &hasher, attempt("alice", test_support::password()))
            .await
            .unwrap();

        let events = audit::list(&db, user.realm_id, audit::Filter::default(), 50, 0)
            .await
            .unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, Action::LoginSucceeded);
        assert_eq!(events[0].actor_id, Some(user.id));
        assert_eq!(events[0].actor_name.as_deref(), Some("alice"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_failed_login_is_recorded_even_for_an_account_that_does_not_exist(db: Db) {
        // The case the log exists for. A record only written when the account
        // resolves would be blind to exactly the probing worth seeing.
        let (hasher, user) = fixture(&db).await;
        let _ = authenticate(
            &db,
            &hasher,
            attempt("nobody", &test_support::wrong_password()),
        )
        .await;

        assert_eq!(
            recorded(&db, user.realm_id).await,
            vec![Action::LoginFailed]
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_lockout_is_recorded_as_its_own_event(db: Db) {
        // Distinct from a failed password: a lockout firing is a signal, and a
        // wrong password is Tuesday.
        let (hasher, user) = fixture(&db).await;
        for _ in 0..=MAX_ATTEMPTS_PER_IDENTIFIER {
            let _ = authenticate(
                &db,
                &hasher,
                attempt("alice", &test_support::wrong_password()),
            )
            .await;
        }

        let actions = recorded(&db, user.realm_id).await;
        assert!(actions.contains(&Action::LoginLockedOut), "{actions:?}");
        assert!(
            Action::LoginLockedOut.is_security_signal(),
            "and it must be marked as one",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_two_steps_of_an_mfa_login_are_both_recorded(db: Db) {
        let (hasher, user) = fixture(&db).await;
        let master = master();
        let secret = enrol_totp(&db, &master, user.id).await;

        let challenged = challenged(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );
        second_factor(
            &db,
            &master,
            &challenged.issued.token,
            Proof::Totp(&current_code(&secret)),
            Origin::default(),
        )
        .await
        .unwrap();

        let actions = recorded(&db, user.realm_id).await;
        assert!(
            actions.contains(&Action::SecondFactorRequired),
            "{actions:?}"
        );
        assert!(
            actions.contains(&Action::SecondFactorSucceeded),
            "{actions:?}"
        );
        // And *not* a password-only success: no session was opened at step one.
        assert!(!actions.contains(&Action::LoginSucceeded), "{actions:?}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_wrong_second_factor_is_recorded(db: Db) {
        let (hasher, user) = fixture(&db).await;
        let master = master();
        enrol_totp(&db, &master, user.id).await;

        let challenged = challenged(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );
        let _ = second_factor(
            &db,
            &master,
            &challenged.issued.token,
            Proof::Totp("000000"),
            Origin::default(),
        )
        .await;

        assert!(
            recorded(&db, user.realm_id)
                .await
                .contains(&Action::SecondFactorFailed),
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn using_a_recovery_code_says_so_in_the_trail(db: Db) {
        // Worth its own line: it means the usual factor was unavailable, which
        // is either a lost phone or somebody else.
        let (hasher, user) = fixture(&db).await;
        let master = master();
        enrol_totp(&db, &master, user.id).await;
        let codes = recovery::generate(&db, user.id).await.unwrap();

        let challenged = challenged(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );
        second_factor(
            &db,
            &master,
            &challenged.issued.token,
            Proof::RecoveryCode(&codes.expose()[0]),
            Origin::default(),
        )
        .await
        .unwrap();

        let actions = recorded(&db, user.realm_id).await;
        assert!(actions.contains(&Action::RecoveryCodeUsed), "{actions:?}");
        assert!(
            actions.contains(&Action::SecondFactorSucceeded),
            "{actions:?}"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_trail_records_where_a_login_came_from(db: Db) {
        let (hasher, user) = fixture(&db).await;
        authenticate(
            &db,
            &hasher,
            Attempt {
                realm: "acme",
                identifier: "alice",
                password: test_support::password(),
                origin: Origin {
                    user_agent: Some("Mozilla/5.0"),
                    ip_address: Some("198.51.100.4".parse().unwrap()),
                },
            },
        )
        .await
        .unwrap();

        let events = audit::list(&db, user.realm_id, audit::Filter::default(), 50, 0)
            .await
            .unwrap();

        assert_eq!(events[0].ip_address.as_deref(), Some("198.51.100.4"));
        assert_eq!(events[0].user_agent.as_deref(), Some("Mozilla/5.0"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn no_recorded_event_ever_contains_a_credential(db: Db) {
        // There is no automated guard on `detail`; this is the closest thing
        // to one for the paths this module owns.
        let (hasher, user) = fixture(&db).await;
        let master = master();
        let secret = enrol_totp(&db, &master, user.id).await;

        let challenged = challenged(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .unwrap(),
        );
        let code = current_code(&secret);
        second_factor(
            &db,
            &master,
            &challenged.issued.token,
            Proof::Totp(&code),
            Origin::default(),
        )
        .await
        .unwrap();
        let _ = authenticate(
            &db,
            &hasher,
            attempt("alice", &test_support::another_password()),
        )
        .await;

        let rows: Vec<String> =
            sqlx::query_scalar("SELECT detail::text || coalesce(target, '') FROM audit_events")
                .fetch_all(&db)
                .await
                .unwrap();
        let all = rows.join(" ");

        for secret in [
            test_support::password(),
            &test_support::another_password(),
            code.as_str(),
            challenged.issued.token.expose(),
        ] {
            assert!(!all.contains(secret), "a credential reached the audit log");
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_suspended_organisation_stops_its_members_signing_in(db: Db) {
        // Suspending a customer is only real if authentication honours it.
        use crate::organization::{self, MemberRole};

        let (hasher, user) = fixture(&db).await;
        let org = organization::create(&db, user.realm_id, "widgets", "Widgets")
            .await
            .unwrap();
        organization::set_member(&db, org.id, user.id, MemberRole::Owner)
            .await
            .unwrap();

        assert!(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .is_ok(),
        );

        organization::set_enabled(&db, org.id, false).await.unwrap();

        let error = authenticate(&db, &hasher, attempt("alice", test_support::password()))
            .await
            .unwrap_err();
        // The same 401 a wrong password gets: which of the two it was is not
        // something an unauthenticated caller may learn.
        assert_eq!(error.status(), 401);

        organization::set_enabled(&db, org.id, true).await.unwrap();
        assert!(
            authenticate(&db, &hasher, attempt("alice", test_support::password()))
                .await
                .is_ok(),
            "restoring the organisation must restore its people",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_suspended_sign_in_is_recorded_with_its_reason(db: Db) {
        use crate::organization::{self, MemberRole};

        let (hasher, user) = fixture(&db).await;
        let org = organization::create(&db, user.realm_id, "widgets", "Widgets")
            .await
            .unwrap();
        organization::set_member(&db, org.id, user.id, MemberRole::Owner)
            .await
            .unwrap();
        organization::set_enabled(&db, org.id, false).await.unwrap();

        let _ = authenticate(&db, &hasher, attempt("alice", test_support::password())).await;

        // The client is told nothing, but an operator asking "why can this
        // person not sign in?" must not have to guess.
        let detail: serde_json::Value = sqlx::query_scalar(
            "SELECT detail FROM audit_events WHERE action = 'login.failed' LIMIT 1",
        )
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(detail["reason"], "organization_suspended");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_dummy_hash_can_never_verify(db: Db) {
        // If this ever returned true, an unknown username would authenticate.
        let (hasher, _) = fixture(&db).await;
        let empty = String::new();
        for candidate in [
            empty.as_str(),
            test_support::password(),
            &test_support::another_password(),
        ] {
            assert!(
                !hasher.verify(candidate, DUMMY_PHC).unwrap(),
                "a candidate verified against the dummy hash",
            );
        }
    }
}
