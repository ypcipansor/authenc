//! Recovery codes: the way back in when the phone is gone.
//!
//! # Why these are hashed with SHA-256 and passwords are not
//!
//! A password is chosen by a person, so it comes from a distribution an
//! attacker can enumerate, and the only defence is to make each guess
//! expensive — hence Argon2id. A code here is 80 bits straight from the OS
//! CSPRNG. There is no dictionary, so there is nothing for a work factor to
//! slow down, and the cost would land in the wrong place anyway: verification
//! has to find *which* of ten codes was presented, and ten Argon2
//! verifications at 19 MiB each would put roughly a second of work on the
//! login path.
//!
//! Hashing by SHA-256 also makes the lookup a single indexed query rather than
//! a scan, which is what keeps the timing of "unknown code" and "known code"
//! from differing by the number of codes the account has left.
//!
//! # Single use
//!
//! Claimed with one atomic `UPDATE … WHERE used_at IS NULL`. Reading the row
//! and then marking it used lets two concurrent requests both pass — the same
//! race that authorization codes are claimed against in `authenc-oauth`.

use authenc_contract::{AppError, Result, UserId};
use sha2::{Digest, Sha256};

use crate::db::Db;

/// How many codes an account gets.
pub const COUNT: usize = 10;

/// Bytes of entropy per code. Ten bytes is 80 bits, which is far past
/// guessable and still short enough to write down.
const CODE_BYTES: usize = 10;

/// The alphabet codes are rendered in.
///
/// Base32 without `0`, `1`, `8`, `I`, `L`, `O`, `S`, `U` would be friendlier
/// still, but a non-standard alphabet means writing an encoder and a decoder
/// and getting both right. RFC 4648 base32 is already unambiguous about the
/// pairs that matter — it has no lowercase, no `0`, and no `1`.
const GROUP: usize = 4;

/// A freshly generated set of codes, in the only form they will ever exist in
/// outside the caller.
///
/// `Debug` is redacted: each of these is a live credential that bypasses the
/// user's authenticator.
#[derive(Clone)]
pub struct Generated(Vec<String>);

impl std::fmt::Debug for Generated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Generated({} codes, [redacted])", self.0.len())
    }
}

impl Generated {
    /// The codes, to show the user exactly once.
    #[must_use]
    pub fn expose(&self) -> &[String] {
        &self.0
    }
}

/// Normalise a code as a person might have typed it: any case, with or without
/// the separators it was displayed with.
fn normalise(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// The stored hash for a code.
fn hash(code: &str) -> Vec<u8> {
    Sha256::digest(normalise(code).as_bytes()).to_vec()
}

/// Render a code with separators, so it can be read aloud and typed back.
fn group(raw: &str) -> String {
    raw.as_bytes()
        .chunks(GROUP)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Replace this user's recovery codes with a fresh set.
///
/// Every existing code — used or not — is deleted first. Regenerating is what
/// a user does when they think the old list leaked, and leaving the old ones
/// valid would make the operation useless.
///
/// # Errors
///
/// Returns an internal error if entropy or the database fails.
pub async fn generate(db: &Db, user_id: UserId) -> Result<Generated> {
    let mut codes = Vec::with_capacity(COUNT);
    let mut hashes = Vec::with_capacity(COUNT);

    for _ in 0..COUNT {
        let mut bytes = [0u8; CODE_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|e| AppError::internal_from("generating a recovery code", e))?;
        let raw = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes);
        hashes.push(hash(&raw));
        codes.push(group(&raw));
    }

    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::internal_from("storing recovery codes", e))?;

    sqlx::query!("DELETE FROM recovery_codes WHERE user_id = $1", user_id.0)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::internal_from("clearing old recovery codes", e))?;

    sqlx::query!(
        r#"
        INSERT INTO recovery_codes (user_id, code_hash)
        SELECT $1, hash FROM unnest($2::bytea[]) AS hash
        "#,
        user_id.0,
        &hashes,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("storing recovery codes", e))?;

    tx.commit()
        .await
        .map_err(|e| AppError::internal_from("storing recovery codes", e))?;

    Ok(Generated(codes))
}

/// Spend a recovery code.
///
/// Returns `true` if the code belonged to this user and had not been used.
/// The claim is atomic, so two requests presenting the same code cannot both
/// succeed.
///
/// # Errors
///
/// Returns an internal error if the update fails.
pub async fn claim(db: &Db, user_id: UserId, presented: &str) -> Result<bool> {
    let result = sqlx::query!(
        r#"
        UPDATE recovery_codes
           SET used_at = now()
         WHERE user_id = $1
           AND code_hash = $2
           AND used_at IS NULL
        "#,
        user_id.0,
        hash(presented),
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("claiming a recovery code", e))?;

    Ok(result.rows_affected() == 1)
}

/// How many codes this user has left.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn remaining(db: &Db, user_id: UserId) -> Result<i64> {
    sqlx::query_scalar!(
        r#"
        SELECT count(*) AS "count!" FROM recovery_codes
        WHERE user_id = $1 AND used_at IS NULL
        "#,
        user_id.0,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("counting recovery codes", e))
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

    #[test]
    fn separators_and_case_do_not_change_a_code() {
        // Whatever the user types, as long as the characters are right.
        let canonical = hash("ABCD-EFGH-IJKL-MNOP");
        assert_eq!(hash("abcdefghijklmnop"), canonical);
        assert_eq!(hash("ABCD EFGH IJKL MNOP"), canonical);
        assert_eq!(hash("abcd-efgh-ijkl-mnop"), canonical);
        assert_ne!(hash("ABCD-EFGH-IJKL-MNOQ"), canonical);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_generated_code_works_once(db: Db) {
        let user = fixture(&db).await;
        let codes = generate(&db, user.id).await.unwrap();
        let first = codes.expose()[0].clone();

        assert!(claim(&db, user.id, &first).await.unwrap());
        assert!(
            !claim(&db, user.id, &first).await.unwrap(),
            "a spent code must not work twice",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_full_set_is_issued(db: Db) {
        let user = fixture(&db).await;
        let codes = generate(&db, user.id).await.unwrap();

        assert_eq!(codes.expose().len(), COUNT);
        assert_eq!(remaining(&db, user.id).await.unwrap(), COUNT as i64);

        let unique: std::collections::HashSet<_> = codes.expose().iter().collect();
        assert_eq!(unique.len(), COUNT, "two codes came out the same");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn spending_one_leaves_the_rest(db: Db) {
        let user = fixture(&db).await;
        let codes = generate(&db, user.id).await.unwrap();

        assert!(claim(&db, user.id, &codes.expose()[3]).await.unwrap());
        assert_eq!(remaining(&db, user.id).await.unwrap(), COUNT as i64 - 1);
        assert!(claim(&db, user.id, &codes.expose()[4]).await.unwrap());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn regenerating_invalidates_every_old_code(db: Db) {
        // The point of regenerating is that the old list stopped being secret.
        let user = fixture(&db).await;
        let old = generate(&db, user.id).await.unwrap();
        let new = generate(&db, user.id).await.unwrap();

        for code in old.expose() {
            assert!(!claim(&db, user.id, code).await.unwrap(), "{code} survived");
        }
        assert!(claim(&db, user.id, &new.expose()[0]).await.unwrap());
        assert_eq!(remaining(&db, user.id).await.unwrap(), COUNT as i64 - 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn another_users_code_does_not_work(db: Db) {
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

        let alices = generate(&db, alice.id).await.unwrap();
        generate(&db, bob.id).await.unwrap();

        assert!(
            !claim(&db, bob.id, &alices.expose()[0]).await.unwrap(),
            "a code must only work for the account it was issued to",
        );
        // And it must still work for its owner: the failed attempt above must
        // not have spent it.
        assert!(claim(&db, alice.id, &alices.expose()[0]).await.unwrap());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_invented_code_is_refused(db: Db) {
        let user = fixture(&db).await;
        generate(&db, user.id).await.unwrap();

        for candidate in ["", "AAAA-AAAA-AAAA-AAAA", "not a code", "0000"] {
            assert!(
                !claim(&db, user.id, candidate).await.unwrap(),
                "{candidate}"
            );
        }
        assert_eq!(remaining(&db, user.id).await.unwrap(), COUNT as i64);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn codes_carry_their_full_entropy(db: Db) {
        let user = fixture(&db).await;
        let codes = generate(&db, user.id).await.unwrap();

        for code in codes.expose() {
            let bare = normalise(code);
            // 10 bytes in unpadded base32 is 16 characters.
            assert_eq!(bare.len(), 16, "{code}");
            assert!(
                bare.bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
                "{code}",
            );
            assert!(code.contains('-'), "{code} should be grouped for reading");
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_codes_are_not_recoverable_from_the_database(db: Db) {
        // Only hashes are stored, so a disclosure yields nothing usable.
        let user = fixture(&db).await;
        let codes = generate(&db, user.id).await.unwrap();

        let stored: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT code_hash FROM recovery_codes WHERE user_id = $1")
                .bind(user.id.0)
                .fetch_all(&db)
                .await
                .unwrap();

        for code in codes.expose() {
            let bare = normalise(code);
            assert!(
                !stored.iter().any(|row| row == bare.as_bytes()),
                "{code} was stored in the clear",
            );
        }
    }

    #[test]
    fn debug_never_prints_a_code() {
        let generated = Generated(vec!["ABCD-EFGH".to_owned()]);
        let rendered = format!("{generated:?}");
        assert!(!rendered.contains("ABCD"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
    }
}
