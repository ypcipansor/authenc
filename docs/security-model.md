# Security model

What this system assumes, what it guarantees, and what it does not. Statements
here are backed by tests; where something is not yet built, this file says so
rather than describing an intention as a property.

## Status

Stages 1 to 8 of the rebuild. Passwords, sessions, CSRF, brute-force lockout,
credential recovery, authorisation, tenant isolation, configuration, transport
headers, error handling, multi-factor authentication, the audit log, groups,
organisations, federation, and the OAuth 2.0 / OpenID Connect provider are in
place and tested. [ROADMAP.md](../ROADMAP.md) lists the parts of each
specification that are deliberately not implemented.

## Threat model

Assumed capable of:

- reading anything the browser can read, via injected script (XSS)
- making a browser issue authenticated cross-site requests (CSRF)
- reading the database, if it leaks
- reading logs, metrics, and crash dumps
- replaying a captured request

Out of scope: a compromised server host, a malicious administrator, and
side-channel attacks against the hardware.

## Credentials

**Passwords** are hashed with Argon2id at OWASP parameters — 19 MiB, 2
iterations, 1 lane — and stored as a full PHC string, so the parameters travel
with each hash. `PasswordHasher::needs_rehash` detects hashes made under weaker
settings so they can be upgraded on the user's next successful login without a
mass reset.

A malformed stored hash is an **error**, never a successful verification. This
has a test of its own (`a_malformed_stored_hash_is_an_error_not_a_successful_login`)
because the failure mode it guards against — a verifier returning success when
it could not actually check — is exactly what the previous tree shipped in
`verify_authentication()`, `UsernamePasswordAuthenticator`, and
`OTPAuthenticator`.

**Usernames and emails are unique per realm, compared case-insensitively**,
enforced by a functional unique index in the schema. Treating `Alice` and
`alice` as separate accounts is an account-takeover route during password
reset.

## Sessions

- The browser holds an **opaque token** in a cookie: `HttpOnly`,
  `SameSite=Lax`, `Path=/`. Nothing readable by JavaScript authenticates a
  request, so an injected script has nothing to steal. The previous console
  kept a JWT in `localStorage`. Under the production profile the cookie is
  additionally `Secure` and `__Host-` prefixed, binding it to exactly one
  origin so a sibling subdomain cannot overwrite it. Development uses a plain
  name because a browser will not store a `Secure` cookie over plain HTTP.
- The server stores only a **SHA-256 hash** of the token, so a database
  disclosure yields hashes rather than live sessions. A test asserts the
  plaintext never appears in the row.
- Expiry is enforced **on lookup**, not merely recorded, and logging out
  deletes the server-side row as well as the cookie — clearing only the cookie
  would leave a working session for anyone who captured the value.

## CSRF

There are two request surfaces, and they are gated differently. Safe methods
are exempt on both.

**`/api/v1` — the token.** Derived from a per-session secret and compared in
**constant time**; a token minted for one session does not validate against
another, and a test asserts exactly that. The previous implementation checked
only that the submitted value was at least 32 characters long, with no
server-side state, no HMAC, and no session binding, so any string of the right
length worked everywhere.

**`/api/sfn` — the origin.** Server functions are invoked by the Leptos client,
which sends no header of ours, so a token requirement there would refuse the
console itself. What is checked instead is `Sec-Fetch-Site`, falling back to
`Origin`: a browser sets both and page script can forge neither, and a browser
always sends `Origin` on a cross-origin POST. A request carrying neither header
is not a browser and so cannot be a forged one; it passes through to whatever
authenticates it. The gate has to cover `log_in` as well as the administrative
functions, which is the other reason it is not a session-bound token — at that
point there is no session to bind one to.

This closes the case `SameSite=Lax` does not. A cross-*site* POST already
arrives without the session cookie; a *subdomain somebody else controls* is
same-site, and would otherwise be trusted.

Neither gate is `SameSite=Lax` on its own, and that distinction was earned: the
origin check was written and unit-tested during Stage 2 and **called from
nowhere**, so until Stage 7 the server-function surface had no CSRF gate at
all. A `curl` carrying a session cookie and no token deleted a group. The tests
that now cover it send the forged request and assert the refusal, rather than
testing the helper in isolation.

## Resisting brute force and enumeration

- **A wrong password and an unknown user produce the identical response** —
  same status, same body. The password is verified against a real Argon2 hash
  even when no such user exists, so response time does not distinguish the two
  either. An unknown *realm* returns 401 rather than 404, so realm names cannot
  be probed.
- **Lockout is checked before the password is**, so a locked account costs an
  attacker a database lookup rather than an Argon2 verification. It is scoped
  per identifier and per address over a rolling window, holds even against the
  correct password, lifts on its own once attempts stop, and does not lock out
  other accounts.
- **Every attempt is recorded**, successful or not — that record is both the
  lockout input and the answer to "was this account attacked?".
- The client address comes from the transport connection only.
  `X-Forwarded-For` is deliberately not consulted; the previous code trusted it
  unconditionally, letting any client choose the address it was judged by.

## Credential recovery

Reset and verification links carry 256 bits from the OS CSPRNG; only the
SHA-256 hash is stored. Redemption is a single atomic
`UPDATE … WHERE used_at IS NULL AND expires_at > now()`, so a link cannot be
spent twice even under concurrent requests, and unknown, expired, and
already-used tokens all produce the same 401.

Requesting a reset returns an identical response for a registered address, an
unregistered one, and an unknown realm — only the mail differs, and only the
real owner sees it.

Completing a reset **revokes every session** for that user, so an attacker who
took the password loses their access the moment the owner recovers, and
**clears the failure history**, so the lockout the attack caused does not keep
the owner out. A password that fails policy is rejected *before* the token is
spent, so a weak first guess does not burn the link.

A verification link records the address it was issued for. If the account's
address changes before the link is used, the link is refused rather than
confirming the new address.

## Authorisation

Permissions are an enum, so a typo is a compile error and `Permission::ALL` is
the complete, reviewable list of what this system can authorise. Every use case
calls `Actor::require` before doing anything; there is no middleware deciding
access by URL prefix, so a function cannot lose its check by being mounted on
the wrong router. The REST handlers apply no authorisation of their own — one
that forgot would still be refused by the use case beneath it.

Permissions are resolved from `role_permissions` rows on each request. Holding
a role *named* `admin` grants nothing by itself, and a test asserts that: the
previous code branched on `roles.contains("admin")`, so the string **was** the
authorisation — while the tokens it issued carried `roles: None`, meaning no
token it produced could satisfy the check at all.

An unrecognised permission name in the database is ignored with a warning,
never guessed into something else: a row left behind by a rename must neither
lock everyone out nor silently escalate.

**Tenant isolation** is checked separately from permissions, and always after
them. Reaching into another realm returns 404, not 403, because confirming that
a resource exists in another tenant is itself a disclosure.

A disabled account fails authentication on the next request even if its session
row still exists, and disabling a user revokes their sessions immediately
rather than waiting for expiry. An actor cannot disable or delete its own
account.

## OAuth 2.0 and OpenID Connect

**Signing keys** live in the database, encrypted with AES-GCM under a
key-encryption key from configuration that never reaches the database. The
`kid` is bound in as associated data, so a ciphertext moved onto another key's
row fails to decrypt rather than signing as the wrong key. A realm has one
active key; retired keys keep verifying, and keep appearing in JWKS, until
their deadline, so rotation does not invalidate tokens still in flight. The
production profile refuses to start on the development key.

**Token verification** checks issuer, audience, expiry, not-before, and key id.
The algorithm is fixed at EdDSA and never read from the token header, so
algorithm-confusion does not apply. The UserInfo endpoint is the one place that
does not pin an audience — it is presented a token minted for whichever client
the user authorised — and it uses a separately named entry point
(`verify_any_audience`) so that omission is a decision rather than an oversight.

**Client authentication** accepts `client_secret_basic`, `client_secret_post`,
and `none` (public clients, PKCE only), and refuses a request presenting
credentials in more than one place. Secrets are 256-bit random values hashed
with Argon2; an unknown client and a wrong secret produce the same code, status,
and message, so the endpoint does not enumerate which clients exist.

**Redirect URIs** are an exact-match allow-list. Prefix and wildcard matching
are not offered, because both are routinely bypassed —
`https://good.example.com.attacker.test/` has the registered prefix. An unknown
client or an unregistered URI is reported at the authorization endpoint and
**never** by redirecting; there is no address we have reason to trust.

**Authorization codes** are single-use, live for one minute, and are claimed by
one atomic `UPDATE … WHERE used_at IS NULL` scoped to the client — so another
client presenting a stolen code neither redeems it nor burns it. PKCE S256 is
mandatory for public clients; `plain` is not implemented and is not advertised.

**Refresh tokens** rotate on every use, and reuse is *detected*, not merely
refused. Every token minted from one authorization shares a family id — the
authorization code's own id — so presenting a spent token revokes the whole
family. A replayed authorization code revokes exactly the same set. The
conservative reading is deliberate: from the server, a client retrying a lost
response and a thief racing the owner are indistinguishable, so both lose
access rather than one of them being an undetected thief.

**Consent** stores which scopes were approved, not merely that approval
happened, so a client cannot quietly widen its scopes after the first
approval. The approval form carries the session-bound CSRF token.

**Account state is re-checked on every use.** A signed access token stays
cryptographically valid until it expires; disabling an account stops UserInfo
and the refresh grant immediately rather than fifteen minutes later.

**Dynamic client registration is off by default.** Open registration lets
anyone create a client whose redirect URI they control, which is a phishing
page wearing the operator's own domain.

## Operational tasks

`authenc seed`, `migrate`, `purge`, `generate-master-key`, `rotate-keys`, and
`register-client` are CLI subcommands. Nothing equivalent exists as an
unauthenticated HTTP endpoint. The previous router served
`/oauth2/token/test`, `/oauth2/consent/test`, and `/api/v1/auth/test-login`
unauthenticated in production, granting consent for a hardcoded user id, and a
test asserts none of those paths exists.

The two commands that mint a credential — `generate-master-key` and
`register-client` — write it to stdout and nowhere else, so it can be piped
into a secret store without passing through the log.

## Secrets

Configuration secrets use the `Secret` newtype: `Debug` renders
`Secret([redacted])`, and the buffer is zeroed on drop. A test asserts that
formatting the whole `Config` does not reveal the database password, because a
config struct reaches logs and panic messages.

`Authorization` and `Cookie` request headers are marked sensitive before the
tracing layer sees them.

## Error disclosure

`AppError::Internal` carries context for the log and collapses to
`"An internal error occurred."` on the wire. Two tests assert that a connection
string embedded in an internal error does not appear in the response body.
Validation errors keep their detail, including the offending field name,
because the caller needs it and it reveals nothing.

## Transport

Every response carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
and `Cross-Origin-Opener-Policy: same-origin`.

HSTS is emitted **only when configured on**, and the production profile refuses
to start without it. The previous server emitted HSTS unconditionally while
serving plain HTTP and never implementing TLS at all.

CORS comes from configuration. An empty allow-list means same-origin only,
which is the default. `*` is rejected under the production profile. A test
asserts that an unlisted origin is not reflected.

## Availability

The release profile uses `panic = "unwind"` with `CatchPanicLayer`, so a panic
in one request becomes a 500 for that request. Under `panic = "abort"` — which
this project previously shipped — any panic in any handler killed the whole
process, turning a single malformed request into a denial of service.

Requests are bounded by a timeout and a body-size limit, both configured.

Readiness returns **503**, not 500, when the database is unreachable, so an
orchestrator removes the instance from rotation instead of restarting it.
Liveness deliberately touches no dependency.

## Not yet addressed

General per-endpoint rate limiting is not implemented; only the login path is
protected, by the lockout above. The previous implementation was a
process-local counter keyed per IP *and path*, so the effective budget was the
configured limit multiplied by the number of paths, and it coordinated across
no instances. A replacement will be shared-state and keyed on the identity
being attacked.

No independent security review has been performed.
