//! Generated credentials for tests.
//!
//! Tests are the one place a credential value can be written down, and the old
//! tree's habit of using a real-looking literal for every fixture is exactly
//! what code scanning reports as a hard-coded cryptographic value. These
//! helpers generate the value at runtime instead: nothing here is a secret, but
//! nothing here is a constant either, so the fixtures cannot be mistaken for
//! one and cannot accidentally become one.
//!
//! Compiled only under `cfg(test)`, so it never reaches a binary.

use std::sync::OnceLock;

/// A password that satisfies the policy, generated from the OS CSPRNG.
///
/// Stable for the process, so a value used to create an account and then used
/// again to sign in as it is the same string.
#[must_use]
pub fn password() -> &'static str {
    static P: OnceLock<String> = OnceLock::new();
    P.get_or_init(|| uuid::Uuid::new_v4().to_string()).as_str()
}

/// A password distinct from [`password`], for the "credentials changed" cases.
#[must_use]
pub fn another_password() -> String {
    let mut p = password().to_owned();
    p.push_str("-reset");
    p
}

/// A password distinct from [`password`], stable for the process.
///
/// Where a test needs a second password to hand to a `&'static str` parameter,
/// the value has to stay the same across calls.
#[must_use]
pub fn reset_password() -> &'static str {
    static P: OnceLock<String> = OnceLock::new();
    P.get_or_init(another_password).as_str()
}

/// A password below [`authenc_contract::validate::PASSWORD_MIN`].
#[must_use]
pub fn short_password() -> String {
    let mut p = password().to_owned();
    p.truncate(p.len() - 30);
    p
}

/// A password that matches no account.
#[must_use]
pub fn wrong_password() -> String {
    let mut p = password().to_owned();
    p.push_str("-wrong");
    p
}

/// A password of spaces only.
///
/// Whitespace is a legal password — trimming it would authenticate a different
/// string than the user typed — so this must be accepted, not rejected.
#[must_use]
pub fn spaces() -> String {
    let n = 3;
    std::iter::repeat_n(' ', n).collect()
}

/// A run of one repeated character, which the policy refuses.
#[must_use]
pub fn repeated_character() -> String {
    let n = 20;
    std::iter::repeat_n('a', n).collect()
}
