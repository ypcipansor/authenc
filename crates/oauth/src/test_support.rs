//! Generated credentials for tests.
//!
//! See `authenc_identity::test_support` for the reasoning: a fixture password
//! is generated at runtime rather than written as a literal, so the protocol
//! tests do not look like they embed a credential. Compiled only under
//! `cfg(test)`.

use std::sync::OnceLock;

/// A password that satisfies the policy, generated from the OS CSPRNG.
#[must_use]
pub fn password() -> &'static str {
    static P: OnceLock<String> = OnceLock::new();
    P.get_or_init(|| uuid::Uuid::new_v4().to_string()).as_str()
}
