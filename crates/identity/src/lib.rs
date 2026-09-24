//! The identity directory.
//!
//! Realms, users, roles, permissions, credentials, and sessions — the rules
//! and the SQL that backs them, kept together per aggregate.
//!
//! # Why rules and SQL live together
//!
//! The obvious alternative is a repository trait in one crate and its Postgres
//! implementation in another, so the rules can be tested against a mock. This
//! crate does not do that, deliberately: it is committed to Postgres, and its
//! tests run against a real one via `#[sqlx::test]`, which gives each test a
//! throwaway database and rolls it away afterwards. Testing against the real
//! engine catches the constraint violations and the case-sensitivity bugs that
//! a mock repository is definitionally blind to.
//!
//! Traits are still used where substitution genuinely buys something — sending
//! mail, and talking to an external identity provider — because those cannot
//! run in CI.
//!
//! # What must never be added
//!
//! `axum` or `leptos`. This crate has to stay usable from a CLI, a migration
//! job, or a test with no HTTP stack present. CI enforces it with `cargo tree`.

pub mod admin;
pub mod api_token;
pub mod audit;
pub mod db;
pub mod directory;
pub mod federation;
pub mod group;
pub mod login;
pub mod mail;
pub mod mfa;
pub mod organization;
pub mod password;
pub mod realm;
pub mod recovery;
pub mod role;
pub mod sealed;
pub mod session;
pub mod token;
pub mod user;

#[cfg(test)]
pub mod test_support;

pub use db::{Db, DbConfig, connect, migrate, ping};
pub use password::PasswordHasher;
pub use sealed::MasterKey;
pub use token::SecretToken;
