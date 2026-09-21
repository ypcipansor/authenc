# Security Policy

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/analisaperlengkapan/authenc/security/advisories/new).
Please do not open a public issue for a vulnerability.

Include what you can: affected version or commit, reproduction steps, and the
impact you believe it has. A proof of concept helps but is not required.

Expect an acknowledgement within three working days and an assessment within
ten. If a fix is warranted we will agree disclosure timing with you.

## Supported versions

This project is pre-1.0 and under active development. Only `main` receives
security fixes.

## Current status

**This software has not had an independent security review.** Authentication,
multi-factor authentication, the audit log, and the OAuth 2.0 / OpenID Connect
provider work and are tested. Do not deploy it as a production identity
provider. [ROADMAP.md](ROADMAP.md) states precisely what is implemented,
including the parts of the specifications that are deliberately not
implemented.

The tree before August 2026 (tag `archive/pre-refactor`) contains authentication
bypasses — authenticators that returned success without verifying anything,
unauthenticated test endpoints in the production router, and an ephemeral
per-process JWT signing key. It is retained for history only. Do not deploy it,
and do not copy code from it.

## Security properties this codebase maintains

These are invariants, enforced by tests and review. A change that breaks one is
a bug regardless of what else it does.

- **Credentials never reach the browser as bearer tokens.** Sessions are an
  opaque identifier in an `HttpOnly`, `Secure`, `SameSite` cookie. Nothing
  readable by JavaScript authenticates a request.
- **Only hashes are stored.** Passwords use Argon2id at OWASP parameters, with
  the full PHC string retained so parameters can be raised per user on next
  login. Session tokens are stored hashed.
- **Internal error detail never leaves the server.** `AppError::Internal`
  collapses to a fixed message for the client; the real one is logged.
- **Secrets are redacted in logs.** Configuration secrets use a newtype whose
  `Debug` output is redacted and whose buffer is zeroed on drop. Authorization
  and Cookie headers are marked sensitive before tracing sees them.
- **No test or debug route is ever registered in the production router.** Seed
  data belongs in the CLI and in test fixtures.
- **A verification function never returns success without verifying.** If it is
  not implemented, it does not exist.
- **Authorisation is decided in the use case**, from an `Actor`, not by
  matching a URL prefix in middleware.
- **CORS comes from configuration** and never allows `*`; the production
  profile refuses to start if it is set to `*`, if the public URL is not
  HTTPS, if HSTS is off, or if the development database credentials are still
  in place.

- **A password alone never opens a session for an account with a second
  factor.** Not by policy — by type. `login::authenticate` returns a challenge
  in its own table, which no session lookup resolves, so the check cannot be
  skipped by a caller that forgot to make it.
- **A one-time code is spent when it is used.** The matched TOTP time step and
  each recovery code are recorded at the moment they succeed, by an atomic
  write. Replay is refused, not merely unlikely.
- **A WebAuthn challenge is chosen and held by the server**, single-use and
  expiring, and the relying-party id comes from configuration rather than from
  a request header.
- **A signature counter that goes backwards is refused**, and the new value is
  persisted on every assertion — a counter that is checked but never written
  back defends against nothing.

## Supply chain

`cargo-deny` and `cargo-audit` run on every pull request and weekly on a
schedule. `Cargo.lock` is committed and builds use `--locked`, so what CI
tested is what ships.

One dependency needs saying out loud: `webauthn-rs 0.5` links against OpenSSL,
which `deny.toml` otherwise bans outright. It is admitted through a single
narrow wrapper exception, because the alternatives were writing WebAuthn
verification by hand — which is what the previous tree did, and its verifier
returned `Ok(true)` without reading its argument — or depending on a
pre-release. The exception carries its own exit condition: `webauthn-rs 0.6`
replaces OpenSSL with pure Rust, and when it is released the exception comes
out.
