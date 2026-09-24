//! OAuth 2.0 and OpenID Connect.
//!
//! The protocol layer: signing keys, tokens, clients, authorization codes, and
//! refresh-token rotation. It knows nothing about HTTP — the endpoints live in
//! `authenc-server` — so every rule here is testable without a request.
//!
//! The previous tree had two OIDC implementations. The 857-line one, which had
//! the correct discovery path and a real login form, was dead code; the
//! 406-line one that was actually mounted issued a valid signed token for
//! `demo_user` to anyone who asked, with no credentials, no code validation,
//! and no client authentication.
//!
//! # Layout
//!
//! * [`admin`] — actor-checked administration of clients
//! * [`keyring`] — persistent, rotatable Ed25519 keys, encrypted at rest
//! * [`token`] — signing and verifying JWTs
//! * [`client`] — registration, redirect-URI allow-list, client authentication
//! * [`code`] — authorization codes and PKCE
//! * [`refresh`] — refresh-token rotation with reuse detection
//! * [`consent`] — what each user has approved for each client
//! * [`grant`] — turning an authorization into a token response
//! * [`scope`] — parsing and narrowing scope requests
//! * [`social`] — the client side: signing in with an account held elsewhere
//! * [`discovery`] — the provider metadata document
//! * [`error`] — the protocol's own error bodies, distinct from [`AppError`]
//!
//! [`AppError`]: authenc_contract::AppError

pub mod admin;
pub mod client;
pub mod code;
pub mod consent;
pub mod discovery;
pub mod error;
pub mod grant;
pub mod keyring;
pub mod refresh;
pub mod scope;
pub mod social;
pub mod token;

#[cfg(test)]
pub mod test_support;

pub use client::Client;
pub use error::{OAuthError, OAuthErrorCode};
pub use keyring::MasterKey;
