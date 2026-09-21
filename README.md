# Authenc

Identity and access management, built as one Rust workspace: a Leptos
server-rendered frontend and an Axum backend over PostgreSQL.

> **Status: foundation, authentication, multi-factor authentication, the audit
> log, and the OAuth/OIDC provider.** This repository was rebuilt from
> scratch in August 2026. What is documented below is implemented and tested;
> everything else is in [ROADMAP.md](ROADMAP.md) and is not claimed to exist.
> It has not had an independent security review — see [SECURITY.md](SECURITY.md).

## Screenshots

Every page the application serves, captured from a running instance with
`just screenshots` and checked by `just screenshot-check`. The pages that need
a live token — a password-reset link, a confirmation link — are captured with a
token the running server minted, not one written into the database, so what is
shown is what the request path produces.

### Sign in, and the pages around it

<table>
<tr>
<td width="50%"><img src="docs/screenshots/home.png" alt="Home page: the service name, a one-line description, and a server status panel reporting version 0.1.0 and a connected database."><br><b>Home</b> — server status, rendered server-side.</td>
<td width="50%"><img src="docs/screenshots/login.png" alt="Sign-in form with realm, username or email, and password fields, a Sign in button, and a divider above a Continue with GitHub button."><br><b>Sign in</b> — realm, identifier, password, and any configured social provider.</td>
</tr>
<tr>
<td><img src="docs/screenshots/login-error.png" alt="The sign-in form showing the message: That realm, username, or password did not match an account."><br><b>A failed sign-in</b> — one message for a wrong password and an unknown user alike, so the page does not say which accounts exist.</td>
<td><img src="docs/screenshots/forgot-password.png" alt="Reset your password form with a realm field, an email field, and a Send reset link button."><br><b>Reset request</b> — never reveals whether the address is registered.</td>
</tr>
<tr>
<td><img src="docs/screenshots/forgot-password-sent.png" alt="A confirmation panel reading: If that address belongs to an account, a reset link is on its way. The link is valid for one hour."><br><b>Reset requested</b> — the same confirmation whatever was typed.</td>
<td><img src="docs/screenshots/reset-password-form.png" alt="Choose a new password, with new password and confirm password fields and a Set password button."><br><b>Choose a new password</b> — reached with a real single-use token.</td>
</tr>
<tr>
<td><img src="docs/screenshots/reset-password.png" alt="Choose a new password page reporting: This link is missing its token. Request a new one from the reset page."><br><b>A spent or missing reset link</b> — the token is single-use, so the second visit says so rather than reusing it.</td>
<td><img src="docs/screenshots/verify-email-confirmed.png" alt="Confirm your email page reading: Your email address is confirmed, with a Sign in link."><br><b>Email confirmed</b> — reached with a real single-use token.</td>
</tr>
<tr>
<td><img src="docs/screenshots/verify-email.png" alt="Confirm your email page reporting: This link is missing its token."><br><b>A spent confirmation link</b> — the same page, without a usable token.</td>
<td><img src="docs/screenshots/not-found.png" alt="Not found page reading: That page does not exist, with a Back to the start link."><br><b>Not found</b> — served with a real HTTP 404, not a 200 with a friendly body.</td>
</tr>
</table>

### The account area

<table>
<tr>
<td width="50%"><img src="docs/screenshots/security.png" alt="Security page listing two-step verification, an authenticator app panel marked Not enrolled, and a passkeys panel with no passkeys registered."><br><b>Security</b> — the second factors enrolled on this account.</td>
<td width="50%"><img src="docs/screenshots/security-enrol.png" alt="The authenticator app panel after starting enrolment: an instruction line, the shared secret in monospace, a code field, and a Confirm button."><br><b>Enrolling an authenticator</b> — the secret is issued by the server; the code is checked against it.</td>
</tr>
<tr>
<td colspan="2"><img src="docs/screenshots/consent.png" alt="Approve access page: Web Console wants access to your account admin, followed by a bulleted list of the scopes requested, with Allow and Deny buttons."><br><b>Consent</b> — the scopes are listed individually and the approved set is what gets recorded. The form posts without JavaScript.</td>
</tr>
</table>

### The admin console

<table>
<tr>
<td width="50%"><img src="docs/screenshots/admin-overview.png" alt="Overview page naming the signed-in administrator and listing the permissions they hold, such as realm:read."><br><b>Overview</b> — the permissions in force, resolved from the database.</td>
<td width="50%"><img src="docs/screenshots/admin-users.png" alt="Users page: an Add a user form above a table of five accounts with enabled state, first and last name, and per-row actions."><br><b>Users</b> — creation and the accounts that exist.</td>
</tr>
<tr>
<td><img src="docs/screenshots/admin-users-filled.png" alt="The same Users page with the Add a user form filled in with a username, email, and password."><br><b>Adding a user</b> — the form as it looks mid-entry.</td>
<td><img src="docs/screenshots/admin-groups.png" alt="Groups page: a note that a member of a group holds its ancestors' roles, a create form, and a table of the engineering group and its two children."><br><b>Groups</b> — a tree, with inheritance running upward.</td>
</tr>
<tr>
<td><img src="docs/screenshots/admin-roles.png" alt="Roles page listing the admin, auditor, and support roles with their descriptions."><br><b>Roles</b> — each role's description, and what it grants.</td>
<td><img src="docs/screenshots/admin-organizations.png" alt="Organisations page: a note that suspending stops members signing in, and a table listing the Acme Corporation organisation."><br><b>Organisations</b> — a tenant boundary inside the realm.</td>
</tr>
<tr>
<td><img src="docs/screenshots/admin-providers.png" alt="Social login page explaining that each provider is configured per realm, with a table listing a GitHub provider."><br><b>Social login</b> — providers per realm, with the client secret sealed at rest.</td>
<td><img src="docs/screenshots/admin-clients.png" alt="OAuth clients page: a register-a-client form, a note that the secret is shown once, and a table listing the Web Console public client."><br><b>OAuth clients</b> — redirect URIs matched exactly; a public client holds no secret.</td>
</tr>
<tr>
<td colspan="2"><img src="docs/screenshots/admin-audit.png" alt="Audit page: namespace and refusals-only filters above a table of events with when, action, who, what, from, and outcome columns, with refused attempts marked."><br><b>Audit</b> — who did what, from where, and whether it worked. Reuse of a spent refresh token is recorded as the evidence it is.</td>
</tr>
</table>

## Why it is built this way

One language across the whole stack means the type that a Leptos view renders
is the same type an Axum handler returns, checked by the compiler. Validation
rules in `crates/contract` run identically in the browser and on the server, so
they cannot drift. Server functions replace a hand-written API client entirely.

## Getting started

Requires Rust 1.94, Docker (for PostgreSQL), and
[`just`](https://github.com/casey/just).

```bash
git clone https://github.com/analisaperlengkapan/authenc.git
cd authenc
just setup    # toolchain, tools, database, migrations
read -r -s AUTHENC_SEED_PASSWORD && export AUTHENC_SEED_PASSWORD   # not echoed
just seed admin@example.com
just dev      # http://localhost:3000/login, then /admin
```

`just setup` copies `.env.example` to `.env`. Every setting is documented
there.

`just seed` creates a realm named `master` and an administrator in it. It takes
the password from `AUTHENC_SEED_PASSWORD` and never as an argument: an argument
is visible in the process list, and `just seed … 'password'` would leave the
password in the shell history no matter what the child process does with its own
environment. Reading it with `read -r -s` keeps it out of both.

Without `just`:

```bash
rustup target add wasm32-unknown-unknown
cargo install cargo-leptos sqlx-cli --locked
docker compose up -d postgres
cp .env.example .env
sqlx migrate run --source migrations
cargo leptos watch
```

## Layout

```
crates/contract   entities, DTOs, AppError, validation   — wasm + native
crates/identity   realms, users, roles, credentials      — native
crates/oauth      OAuth 2.0 / OpenID Connect provider    — native
crates/web        Leptos pages, components, server fns   — wasm + native
crates/server     composition root, HTTP stack, CLI      — native
migrations/       sqlx migrations, applied at startup
docs/             architecture, security model, deployment
e2e/              demo data, screenshot capture, screenshot checks
```

Dependencies run one way: `contract ← identity ← oauth ← server` and
`contract ← web ← server`. Neither `identity` nor `oauth` may depend on `axum`
or `leptos`, which is what lets every protocol rule be tested without an HTTP
stack. CI fails the build if a crate reaches across a layer, so the structure
is enforced rather than merely intended.

## What works today

| | |
|---|---|
| Server-rendered pages with hydration | `cargo leptos build` produces the wasm bundle; CI asserts it exists |
| Server functions | `/api/sfn/*`, executing against PostgreSQL |
| Migrations | applied by `sqlx::migrate!()` at startup |
| Password hashing | Argon2id at OWASP parameters, with per-user rehash on policy change |
| Configuration | layered defaults → TOML → env, validated once, secrets redacted in logs |
| Health probes | `/health/live` and `/health/ready`, answering different questions |
| Middleware | request id, tracing, panic capture, timeout, body limit, CORS from config, security headers |
| Error responses | RFC 9457 `application/problem+json`, internal detail never leaked |
| Sessions | opaque token in an `HttpOnly`, `SameSite=Lax` cookie; only its hash is stored |
| Login and logout | server functions, with the login page rendered server-side |
| Brute-force protection | per-identifier and per-address lockout over a rolling window |
| User enumeration resistance | wrong password and unknown user return the identical response |
| CSRF | `/api/v1`: token bound to the session, compared in constant time. `/api/sfn`: `Sec-Fetch-Site`/`Origin`, because the Leptos client sends no header of ours |
| RBAC groundwork | roles resolved from the database at the point of use, never from a token |
| Password reset | single-use expiring link; completing it revokes every session and lifts the lockout |
| Email verification | single-use expiring link; a link cannot verify an address changed after it was sent |
| Mail | SMTP via lettre, or a logging transport for development that production refuses to start with |
| Admin console | server-rendered pages for users, roles, groups, organisations, providers, clients, and the audit trail, with a session guard that redirects on the server |
| RBAC | typed permissions checked in the use case, resolved from the database per request |
| REST API | `/api/v1` for automation, with an OpenAPI document at `/api/v1/openapi.json` |
| Tenant isolation | an actor cannot read or change anything in another realm, and gets 404 rather than 403 |
| OpenID Connect discovery | `/.well-known/openid-configuration` — with hyphens, so standard clients find it |
| Authorization code + PKCE | `S256` only, mandatory for public clients; a code is single-use and client-bound |
| Refresh token rotation | reuse is detected, not merely refused: a replayed token revokes its whole family |
| Signing keys | persistent, rotatable, AES-GCM-encrypted at rest; retired keys keep verifying until their deadline |
| Client registry | Argon2-hashed secrets, exact-match redirect URIs, `client_secret_basic`/`_post`/`none` |
| Introspection and revocation | RFC 7662 and RFC 7009, under client authentication, not a bearer token |
| UserInfo | claims filtered by granted scope; a disabled account stops working immediately |
| Consent | a server-rendered form that works without JavaScript, recording *which* scopes were approved |
| Dynamic client registration | RFC 7591, off unless switched on |
| Client administration | `/api/v1/clients` and a console page; secret rotation shows the new secret once |
| Two-step sign-in | a correct password returns a *challenge*, not a session, when a factor is enrolled — a different type, in a different table |
| TOTP | RFC 6238, checked against the RFC's own test vectors; a code is single-use, so an observed one expires in 30s rather than 90 |
| Recovery codes | ten per account, 80 bits each, single-use; issued the moment an authenticator is confirmed |
| Passkeys | WebAuthn via `webauthn-rs`; the challenge stays on the server and the signature counter is written back after every assertion |
| Audit log | one event model, `Action::ALL` is the complete list; every authentication path and every administrative change records |
| `amr` in ID tokens | snapshotted at sign-in and carried through code and refresh, so a relying party can tell a password from a passkey |
| Audit access | its own `audit:read` permission — listing users does not confer reading everyone's movements |
| Audit retention | opt-in via `authenc purge --audit-older-than DAYS`; nothing trims the log on a schedule nobody chose |
| Audit API | `/api/v1/audit` and `/api/v1/audit.csv`; a bad filter is refused, and the CSV neutralises spreadsheet formulas |
| Groups | a hierarchy per realm; permissions resolve through it, so a member of a child holds its ancestors' roles |
| Group safety | cycles refused by a database trigger; inheritance runs upward only, so nesting is never an escalation |
| Organisations | a tenant boundary inside a realm: suspendable, joined by invitation, with owner/admin/member roles |
| Suspension | disabling an organisation stops its members signing in — unless they belong to another that is still enabled |
| Invitations | single-use expiring links, hash-only at rest, recording who actually accepted rather than only who was invited |
| Group and org API | `/api/v1/groups` and `/api/v1/organizations`; an invitation token is returned once and never listed back |
| Social login | Google, GitHub, Microsoft, Facebook, Apple, or any OIDC provider; per realm, client secret sealed at rest |
| Account identity | the upstream `sub`, never the email — an address can be reassigned, and at several providers the holder can change it |
| Account adoption | off by default; needs the operator's opt-in *and* the upstream's own `email_verified` for that sign-in |
| Social login and MFA | a federated sign-in returns the same challenge a password does, so adding a provider is not a way around an enrolled factor |
| Login CSRF | `state` is bound to a `SameSite=Lax` cookie as well as the URL; the server-side row alone does not stop it |
| GitHub addresses | read from `/user/emails`, not the profile — the profile address is typed in by the account holder and never checked |
| LDAP / Active Directory | search then bind as the entry's own DN; the distinguished name is the identity, not the login name |
| LDAP safety | an empty password is refused before it is sent (an empty bind is an *anonymous* bind, and succeeds); the login is escaped per RFC 4515 |
| API tokens | `Authorization: Bearer` for `/api/v1`, so automation does not have to hold somebody's password |
| Token authority | never more than its maker had, and narrowed at every request to what the bound account holds *now* |
| Token revocation | immediate; disabling the account kills its tokens without anybody remembering to revoke them |
| CLI | `authenc seed`, `migrate`, `purge`, `generate-master-key`, `rotate-keys`, `register-client` — no test endpoints in the router |

Social login and LDAP are **tested against a mock provider and a scripted
directory, not real ones.** No
provider's credentials can run in CI, so `oauth::social::Transport` is a trait
and the tests exercise the rules that are ours: the state binding, PKCE, the
`nonce`/`iss`/`aud`/`exp` checks, and each provider's claim mapping. What has
not been exercised is a live Google, GitHub, OpenLDAP, or Active Directory
response.

## Development

```bash
just check     # fmt + clippy (both targets) + tests + layer boundaries
just test      # tests only
just build     # release build with the optimised wasm bundle
```

Two things to know before your first change:

- **Never use `--all-features`.** Leptos' `hydrate` and `ssr` features are
  mutually exclusive. Build native with `--features ssr`, wasm with
  `--features hydrate`.
- **After changing any SQL, run `just sqlx-prepare`** and commit `.sqlx/`. CI
  builds without a database and relies on that metadata.

Database tests use `#[sqlx::test]`, which gives each test its own throwaway
database. They need PostgreSQL running; they do not mock it.

### Regenerating the screenshots

```bash
just db-up          # PostgreSQL
just demo-data      # invented, idempotent rows for the console pages to render
just serve          # in one terminal; logs to /tmp/authenc-server.log
# in another: the capture reads the same secret the seed used
just screenshots
just screenshot-check
```

`just screenshots` needs a server whose output is going to
`/tmp/authenc-server.log`, because it reads the password-reset link out of the
development mailer's log rather than inserting a token row directly. Capturing
the page the real request produced is the point.

It signs in with `DEMO_PASSWORD`, or with `AUTHENC_SEED_PASSWORD` if that is
already exported from the seed, so one value covers both. There is deliberately
no default: a published one would be a working administrator password for anyone
following these steps. The capture reads it without echoing it, and signs in
through the form, so the session cookie is the one the application issues.

Node 20 or newer is required (see `e2e/screenshots/package-lock.json`). The
first run installs Playwright's Chromium build and the packages pinned in the
lockfile (`npm ci`), so a clean machine works once it can reach the registry;
later runs are cache hits.

`screenshot-check` re-reads the files on disk and fails on a blank, white, or
content-free image, an image the report does not name, a report entry that
recorded a problem or a status other than the one it expected, and a report
entry with no image. `capture.mjs` checks the page as it captured it, and fails
on a page that logged a JavaScript error, rendered the application's own error
copy, overflowed horizontally, clipped a control, answered with an unexpected
HTTP status, or never reached the interaction it was aiming for. A screenshot
that looks fine in a directory listing is exactly the failure both exist to
catch. A capture that fails any page writes nothing into `docs/screenshots/`;
the previous set stays in place and the failed run is left in a temporary
directory to inspect.

## Documentation

- [AGENTS.md](AGENTS.md) — conventions and invariants, for humans and coding agents
- [docs/architecture.md](docs/architecture.md) — why the crates are cut this way
- [docs/security-model.md](docs/security-model.md) — sessions, CSRF, secrets
- [docs/deployment.md](docs/deployment.md) — Docker and configuration
- [ROADMAP.md](ROADMAP.md) — what is not built yet
- [SECURITY.md](SECURITY.md) — reporting a vulnerability
- [CONTRIBUTING.md](CONTRIBUTING.md)

## History

The tree before August 2026 is preserved at the tag `archive/pre-refactor`. It
did not compile, its CI had failed 926 consecutive runs, and several of its
authenticators returned success without verifying anything. It was replaced
rather than repaired. [ROADMAP.md](ROADMAP.md) records which of its advertised
features are genuinely planned.

## Licence

[Apache-2.0](LICENSE).
