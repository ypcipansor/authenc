//! Password hashing and verification.
//!
//! Argon2id with parameters from
//! [OWASP's Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html):
//! 19 MiB of memory, 2 iterations, 1 degree of parallelism.
//!
//! The full PHC string is stored, so the parameters travel with each hash and
//! can be raised later without invalidating existing passwords — see
//! [`PasswordHasher::needs_rehash`].

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{
        PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString, rand_core::OsRng,
    },
};
use authenc_contract::{AppError, Result};

/// Memory cost in KiB (19 MiB).
const MEMORY_KIB: u32 = 19 * 1024;
/// Number of passes over memory.
const ITERATIONS: u32 = 2;
/// Degree of parallelism.
const PARALLELISM: u32 = 1;

/// Hashes and verifies passwords.
#[derive(Clone)]
pub struct PasswordHasher {
    argon2: Argon2<'static>,
}

impl std::fmt::Debug for PasswordHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordHasher")
    }
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordHasher {
    /// Build a hasher with the recommended parameters.
    ///
    /// The constants above are known to satisfy Argon2's bounds, so the
    /// fallback is unreachable. It is not a silent weakening either way:
    /// `hashes_are_argon2id_with_policy_parameters` asserts that emitted
    /// hashes carry exactly `MEMORY_KIB` and `ITERATIONS`, so if the fallback
    /// ever did engage, that test would fail rather than the service quietly
    /// hashing at lower cost.
    #[must_use]
    pub fn new() -> Self {
        let params =
            Params::new(MEMORY_KIB, ITERATIONS, PARALLELISM, None).unwrap_or(Params::DEFAULT);
        Self {
            argon2: Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        }
    }

    /// Hash a password, returning a PHC string safe to store.
    pub fn hash(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        self.argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| AppError::internal_from("hashing password", HashError(e)))
    }

    /// Verify a password against a stored PHC string.
    ///
    /// Returns `Ok(false)` for a wrong password and `Err` only when the stored
    /// hash itself is unusable — the caller must not treat a malformed hash as
    /// a successful login.
    pub fn verify(&self, password: &str, phc: &str) -> Result<bool> {
        let parsed = PasswordHash::new(phc)
            .map_err(|e| AppError::internal_from("parsing stored password hash", HashError(e)))?;
        match self.argon2.verify_password(password.as_bytes(), &parsed) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(AppError::internal_from("verifying password", HashError(e))),
        }
    }

    /// Whether a stored hash was produced with weaker parameters than current
    /// policy, and should be replaced on the next successful login.
    #[must_use]
    pub fn needs_rehash(&self, phc: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(phc) else {
            // Unparseable: replace it at the next opportunity.
            return true;
        };
        if parsed.algorithm.as_str() != "argon2id" {
            return true;
        }
        let Ok(params) = Params::try_from(&parsed) else {
            return true;
        };
        params.m_cost() < MEMORY_KIB
            || params.t_cost() < ITERATIONS
            || params.p_cost() < PARALLELISM
    }
}

/// Wraps `argon2`'s error, which does not implement `std::error::Error`.
#[derive(Debug)]
struct HashError(argon2::password_hash::Error);

impl std::fmt::Display for HashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for HashError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    #[test]
    fn hashes_verify_against_the_original_password() {
        let hasher = PasswordHasher::new();
        let password = test_support::password();
        let phc = hasher.hash(password).unwrap();
        assert!(hasher.verify(password, &phc).unwrap());
    }

    #[test]
    fn wrong_password_returns_false_not_error() {
        let hasher = PasswordHasher::new();
        let phc = hasher.hash(test_support::password()).unwrap();
        assert!(
            !hasher
                .verify(&test_support::another_password(), &phc)
                .unwrap()
        );
    }

    #[test]
    fn the_same_password_hashes_differently_each_time() {
        let hasher = PasswordHasher::new();
        let password = test_support::password();
        let a = hasher.hash(password).unwrap();
        let b = hasher.hash(password).unwrap();
        assert_ne!(a, b, "salts must differ");
    }

    #[test]
    fn hashes_are_argon2id_with_policy_parameters() {
        let phc = PasswordHasher::new()
            .hash(test_support::password())
            .unwrap();
        assert!(phc.starts_with("$argon2id$"), "got {phc}");
        assert!(phc.contains(&format!("m={MEMORY_KIB}")));
        assert!(phc.contains(&format!("t={ITERATIONS}")));
    }

    #[test]
    fn a_malformed_stored_hash_is_an_error_not_a_successful_login() {
        let hasher = PasswordHasher::new();
        let candidate = test_support::password();
        // The critical property: this must never be `Ok(true)`.
        assert!(hasher.verify(candidate, "not-a-phc-string").is_err());
        assert!(hasher.verify(candidate, "").is_err());
    }

    #[test]
    fn current_hashes_do_not_need_rehashing() {
        let hasher = PasswordHasher::new();
        let phc = hasher.hash(test_support::password()).unwrap();
        assert!(!hasher.needs_rehash(&phc));
    }

    #[test]
    fn weaker_or_unparseable_hashes_need_rehashing() {
        let hasher = PasswordHasher::new();
        // Produced with deliberately weaker parameters.
        let weak_params = Params::new(8 * 1024, 1, 1, None).unwrap();
        let weak = Argon2::new(Algorithm::Argon2id, Version::V0x13, weak_params);
        let salt = SaltString::generate(&mut OsRng);
        let weak_phc = weak
            .hash_password(test_support::password().as_bytes(), &salt)
            .unwrap()
            .to_string();

        assert!(hasher.needs_rehash(&weak_phc));
        assert!(hasher.needs_rehash("garbage"));
    }
}
