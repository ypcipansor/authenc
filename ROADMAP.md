# Roadmap

What exists, what is coming, and what was removed. The point of this file is
that nothing is claimed to work until it does — the previous `TODO.md` listed
Docker, Helm charts, and an OpenAPI specification as complete when none of
those files existed in the repository.

## Delivered

### Stage 1 — Foundation

Workspace of four crates with CI-enforced layer boundaries. Leptos 0.8 SSR with
hydration via `cargo-leptos`. SQLx with migrations applied at startup and
compile-time-checked queries. Layered configuration, validated once, with
secrets redacted in logs. Axum middleware: request id, tracing, panic capture,
timeout, body limit, configured CORS, security headers. RFC 9457 error
responses. Health and readiness probes. Argon2id password hashing. Docker
image, compose stack, CI across format, lint (both targets), tests against a
real PostgreSQL, layer boundaries, wasm bundle, and MSRV.

### Stage 2 — Authentication

Sessions as an opaque token in an `HttpOnly`, `SameSite=Lax` cookie, with only
its hash stored. CSRF token bound to the session and compared in constant time
for `/api/v1`, and a `Sec-Fetch-Site`/`Origin` check for `/api/sfn`, where the
Leptos client sends no header of ours. (The origin check was written here and
mounted nowhere until Stage 7 — see `docs/security-model.md`.) Brute-force lockout per identifier and
per address over a rolling window, which holds even against the correct
password and lifts on its own. Login, logout, and current-user server
functions; a server-rendered login page. A `CurrentUser` extractor that
resolves roles from the database. An `authenc` CLI with `seed`, `migrate`, and
`purge`, so no test endpoint has to exist in the router.

### Stage 3a — Credential recovery

Password reset and email verification, both as single-use expiring links whose
hash alone is stored. Completing a reset revokes every session for that user
and clears the failure history, so an attacker loses their access and the
rightful owner is not kept out by the lockout the attack caused. A verification
link cannot confirm an address that changed after it was sent. Requesting a
reset returns an identical response for a known address, an unknown address,
and an unknown realm.

Mail goes over SMTP through `lettre`, or to the log in development — a
transport the production profile refuses to start with.

### Stage 3b — Administration and RBAC

Typed permissions (`Permission::ALL` is the complete list) checked by
`Actor::require` inside each use case, never by URL prefix. Permissions are
resolved from `role_permissions` rows per request; holding a role *named*
`admin` grants nothing by itself. Write implies read. An actor cannot reach
another realm, and is told 404 rather than 403 so the other tenant's existence
is not confirmed.

A REST `/api/v1` surface for automation, documented by an OpenAPI document at
`/api/v1/openapi.json`, sitting on the same use cases the console will use.

### Stage 3c — Admin console

Server-rendered pages at `/admin` for the overview, users, and roles, backed by
server functions. An unauthenticated visitor is redirected **by the server**
before any console markup is produced. Actions the viewer lacks permission for
are hidden — using the same rule the server enforces, with a test asserting the
two agree — and a test also asserts that hiding is only a hint: calling the
server function directly is still refused.

A `DataTable` primitive replaces the table chrome the previous console
copy-pasted across eight pages, using keyed `<For>` so a refetch touches only
the rows that changed rather than rebuilding the whole `<tbody>`.

### Stage 4a — Signing keys and tokens

`crates/oauth` with two pieces in place and tested:

**Signing keys** are persistent, rotatable, and encrypted at rest with a
key-encryption key that never reaches the database. A realm has exactly one
active key that signs, plus retired keys that keep verifying — and keep
appearing in JWKS — until their deadline, so rotation does not invalidate
tokens still in flight. The previous build generated its keypair with
`Lazy::new(|| SigningKey::generate(&mut OsRng))`.

**Tokens** are Ed25519 JWTs whose verification checks issuer, audience, expiry,
not-before, and key id. The algorithm is fixed and never read from the header,
so `alg: none` confusion cannot apply. The previous verifier checked the
signature and `exp` and nothing else.

### Stage 4b — The protocol endpoints

Discovery at `/.well-known/openid-configuration` — with hyphens, so a standard
client can find it — plus JWKS, the authorization-code flow with PKCE S256,
refresh-token rotation with reuse detection, introspection and revocation under
client authentication, UserInfo, a consent screen, and dynamic client
registration (RFC 7591, off by default).

The rules live in `crates/oauth` and are tested without an HTTP stack; a
separate suite in `crates/server/tests/oidc.rs` drives a full
authorize → redeem → UserInfo → refresh → rotate exchange over the assembled
router, so a rule that exists but is not reachable through the endpoints fails
a test.

Deliberate limits, stated rather than implied:

- **`plain` PKCE is not implemented.** It puts the verifier in the same message
  as the challenge; discovery advertises `S256` only.
- **The implicit and hybrid flows are not implemented.** `response_type=code`
  is the only one offered, as OAuth 2.1 recommends.
- **`client_credentials` is not implemented.** Machine-to-machine access is
  stage 8; discovery does not claim otherwise.
- **A client may only introspect its own tokens.** RFC 7662 permits a broader
  policy; this one is narrower on purpose.
- **Dynamic registration is off unless `oauth.allow_dynamic_registration` is
  set**, because open registration lets anyone create a client whose redirect
  URI they control — a phishing page wearing the operator's domain.

### Stage 4c — Client administration

Two typed permissions — `client:read` and `client:write` — and
`authenc_oauth::admin`, which checks them the same way
`authenc_identity::admin` does: an `Actor` per call, and a client in another
realm reported as 404 rather than 403.

Both surfaces sit on it. `/api/v1/clients` for automation, with `GET`, `POST`,
`PATCH`, `DELETE`, and `POST …/secret`; a `/admin/clients` console page for
people. The REST surface returns a `ClientView` rather than the internal type,
so the row's database id and realm id stay ours — an internal identifier in a
public response becomes a compatibility obligation the moment someone stores it.

Secret rotation is the operation this stage exists for. Before it, replacing a
leaked client secret meant shell access to the server. A rotated secret is shown
**once**, because that is the only moment it exists outside the caller: the
database holds an Argon2 hash and nothing else. Tokens the client already holds
keep working — what stops is authenticating with the old secret — which is what
makes it usable during an incident rather than only at setup.

### Stage 5 — Multi-factor authentication

The shape is the security. `login::authenticate` returns an `Outcome`, not a
session: when a second factor is enrolled, a correct password produces a
`challenge::Pending` — a different type, in a different table, that no session
lookup can resolve. The alternative, issuing the session and *then* asking for
a code, makes "was the second factor checked?" a property of the login page
rather than of the system, and a page is a thing one can forget to write.

**TOTP** is RFC 6238, written out rather than taken from a library, because the
parts that decide whether it is secure are the drift window and the replay
check — both properties of how it is called. The arithmetic is checked against
the RFC 6238 Appendix B vectors; HMAC and SHA-1 come from RustCrypto. A code is
single-use: the matched time step is persisted, so an observed code is worth
thirty seconds rather than the ninety the drift window would otherwise allow.
Secrets are AES-256-GCM sealed under the master key, with the row's id as
associated data.

**Recovery codes** carry 80 bits from the CSPRNG, so they are hashed with
SHA-256 for the same reason session tokens are, and claimed with one atomic
`UPDATE`. Ten are issued at the moment an authenticator is confirmed, because
turning on a second factor without a way past a lost phone is how an account
becomes unrecoverable.

**Passkeys** go through `webauthn-rs`. What this repository is responsible for
is the three things a library cannot do for it: keeping the challenge on the
server, writing the signature counter back after every assertion, and checking
that the credential named still belongs to the user being authenticated.

Deliberate limits, stated rather than implied:

- **Recovery codes do not count as an enrolled factor.** They are a way past a
  lost one. If they counted, generating them would silently turn on MFA for an
  account with no authenticator and lock the user out at the next login.
- **A session records how it was authenticated (`amr`), and ID tokens carry
  it.** The value is snapshotted onto the authorization code and then onto the
  refresh family, rather than recomputed at issuance; access tokens carry none.
  See Stage 6 for why.
- **`webauthn-rs 0.5` pulls in OpenSSL**, which `deny.toml` otherwise bans. It
  is admitted through one narrow wrapper exception with the reasoning and the
  exit condition written down there: 0.6 drops OpenSSL for pure Rust and exists
  only as a pre-release, and a pre-release deciding who someone is was the
  worse trade.
- **The passkey ceremony is driven by ~40 lines of self-hosted JavaScript.**
  `navigator.credentials` is a browser API; calling it through `web-sys` would
  add bindings for no gain. Nothing security-relevant happens there — every
  value it produces is verified server-side against a challenge the server
  chose and stored.

## Delivered, continued

Each stage leaves the repository compiling, linted, and tested.

### Stage 6 — Audit and events

**Delivered.** One event model in `contract::event` — `Action::ALL` is
the complete list of what this system can record, so a renamed variant is a
compile error rather than a silent gap. Events go to `audit_events` in
PostgreSQL, queryable by action, namespace prefix, outcome, actor, and time
range, scoped to a realm. Every authentication path records: password
success and failure, lockout, both steps of an MFA login, a wrong second
factor, a recovery code being spent — and refresh-token reuse, which is the
single most important line the log carries.

Two decisions worth knowing about:

- **`actor_name` and `target` are denormalised strings, not joins.** An audit
  record has to outlive the rows it names; a foreign key that nulls on delete
  answers "somebody did something to something".
- **A failed audit write does not fail the operation it was recording.**
  `observe` swallows it into a loud `tracing::error!`. The strict alternative
  turns any audit-table problem into a total authentication outage. This is a
  real gap — a dropped write is not detectable from the audit log itself — and
  it is written down in the module rather than discovered later.

Retention is opt-in: `authenc purge --audit-older-than DAYS`. Nothing trims the
log on a schedule nobody chose.

Administrative and OAuth changes record too: users created and deleted, roles
granted and revoked, clients registered, changed, deleted, and their secrets
rotated. Reading the trail needs its own permission, `audit:read` — the log
names every account in the realm and where each of them signed in from, so
being allowed to list users is not the same as being allowed to read everyone's
movements. There is deliberately no `audit:write`.

The console has an `/admin/audit` page: filtered by namespace and by refusals,
paged, with the actions that are evidence of an attack marked as such using the
same rule the contract defines, so the console and anything else reading the log
agree on what counts.

ID tokens carry `amr`. The value is snapshotted onto the authorization code and
then onto the refresh family, rather than recomputed at issuance — by the time a
refresh mints an ID token days later the session may be gone, and what the
account has enrolled *now* is not what was presented *then*. Access tokens
deliberately carry none: they describe an authorisation, and putting `amr` there
would invite a resource server to make an authentication decision from an
authorisation credential. An unknown `amr` is absent rather than an empty array,
because an empty array asserts "no methods were used" and silence does not.

`/api/v1/audit` serves the trail for automation, filtered the same way the
console filters it, and `/api/v1/audit.csv` exports a page of it. An
unparseable filter is a 400 rather than a silently ignored parameter — a caller
asking for `outcome=failed` and receiving every event would draw exactly the
wrong conclusion. The CSV neutralises leading `=`, `+`, `-`, and `@`, because
an audit log holds attacker-supplied strings (a user agent is whatever the
client sent) and the export exists to be opened in a spreadsheet, where such a
cell is a formula.

Stage 6 is complete.

### Stage 7 — Groups

A hierarchy of groups within a realm, each carrying role grants, with
membership. What makes it access control rather than an org chart is that
`user::permissions` resolves *through* the tree: a member of
`/engineering/backend` holds the roles granted to `backend` and to
`engineering` above it, and that union is what every `Actor` is built from.

Inheritance runs upward only, from a group to its ancestors. Adding a child
group therefore cannot widen what its parent's members can do — nesting is
never a privilege escalation, and a test asserts the downward direction stays
closed.

Cycles are refused by a database trigger rather than by Rust. A cycle is not
merely invalid data: every ancestry walk over it is a query that does not
terminate, and one runs on every authorised request. The rule belongs where
nothing can route around it.

Granting a role to a group needs **both** `group:write` and `role:write`.
Granting to a group hands the role to every member and descendant at once; if
`group:write` alone sufficed it would be a strictly more powerful way to assign
roles than `role:write`, and the weaker permission would be the one worth
having.

**Organisations** are a tenant boundary *inside* a realm, and the question
worth answering before adding the table was what one does that a group does
not. Three things: it can be **suspended**, which stops its members signing in
without touching a user row; people **join by invitation** through a link sent
to an address; and membership carries a **role inside the organisation** —
owner, admin, member — which says who runs the customer's account and confers
nothing over the realm.

The suspension rule is more careful than "any disabled organisation blocks
you". Someone in no organisation is unaffected; someone whose only
organisation is suspended is blocked; someone in two, one still enabled, is
**not** blocked — a consultant working with two customers must not lose their
account when one of them is suspended.

An invitation is a single-use expiring link whose hash alone is stored, claimed
atomically so one link admits one person. The accepting account is recorded
separately from the invited address: a link forwarded to somebody else and
accepted by them cannot be prevented — possession of it *is* the proof — but it
is visible afterwards, and a row storing only the invited address would hide it.

An organisation must keep at least one owner, and an admin cannot act on an
owner. Otherwise an admin could evict every owner and take the organisation,
which is the only reason the two roles differ.

`/api/v1/organizations` covers the lot: create, suspend, delete, membership,
and invitations. The invitation token is returned **once**, at creation, and
never by the listing — an endpoint that could hand one back would let anyone
who may read the list join as anyone who was invited.

The console has a page for each. The group tree is rendered flat and indented
rather than as a collapsible tree: the server already returns it ordered by
path, so indentation reproduces the hierarchy exactly, and a flat list is what
makes the roles and member counts comparable down a column — which is what an
administrator opens the page to compare. Roles are shown as *directly granted*,
never as inherited: the child inherits for authorisation, but listing the
parent's roles against the child would misreport what somebody actually set.

Groups and organisations use typed identifiers (`GroupId`, `OrganizationId`,
`InvitationId`) like every other aggregate, so an invitation id cannot be
passed where an organisation id is expected. That is not hypothetical: the
first draft of `revoke_organization_invitation` took two bare `Uuid`s, and the
compiler had nothing to say about the order.

Domain-based auto-join is deliberately absent: it is only safe once a domain
has been *proved*, and DNS verification is not built, so claiming one would be
a feature that looks like a control and is not.

Stage 7 is complete.

### Stage 8 — Federation

Social login (Google, GitHub, Microsoft, Facebook, Apple) with account linking,
and LDAP/Active Directory bind plus synchronisation with just-in-time
provisioning.

**Machine-to-machine API tokens are built.** `/api/v1` was authenticated by
the same session cookie the console uses, so an automated client had to sign in
as a person and echo a CSRF token — which meant a Terraform provider held
somebody's password and the audit trail recorded their name for everything it
did.

A token is bound to an account, because something has to be answerable for it
and a service account is a user: realm isolation, disabled accounts, and
suspended organisations then apply without being restated. Its authority is
checked twice. At creation, against the maker's own permissions, so a token
cannot be an escalation. At *use*, as the **intersection** of its grant and
what the account holds now — so losing a role narrows every token that account
owns, immediately, without anybody remembering they exist. A token that kept
what it was granted reproduces exactly the failure offboarding is supposed to
prevent.

It skips CSRF, deliberately. CSRF exists because a browser attaches a cookie to
a request the user did not intend; a token is attached by the client that holds
it. The test for that asserts a state-changing request **succeeds**, because
asserting a refusal would have passed whether or not the check was skipped.

Building it surfaced a defect in Stage 3: `role::set_permissions` only ever
inserted, so `PUT /api/v1/roles/{id}/permissions` — documented as "the complete
set; anything absent is removed" — returned 200 for a withdrawal and kept the
permission. Withdrawing one is the operation an incident needs, and it was the
one that did not work. Now fixed, with tests, and three tests fail if the
deletion is removed again.

**Social login is built.** A provider is configured per realm with its own
client id and secret — the secret AES-256-GCM sealed under the master key, the
endpoints stored rather than derived so a provider that moves one needs no
release. `kind` selects only the *claim mapping*, which is the part that
genuinely differs.

Three decisions carry the weight:

* **The upstream `sub` is the identity, never the email.** An address can be
  reassigned, and at several providers the account holder can change it.
* **Adopting an existing local account is off by default**, and needs both the
  operator's `link_by_verified_email` and the upstream's own `email_verified`
  for that particular sign-in — the policy and the evidence. Left on for a
  provider that asserts addresses it has not checked, it hands over whichever
  local account matches.
* **A federated sign-in does not bypass MFA.** It returns the same
  `login::Outcome` as a password one. That required `mfa::amr_for` to stop
  hardcoding `pwd`: a Google sign-in was about to tell relying parties this
  server had verified a password it never saw.

The callback binds `state` to a `SameSite=Lax` cookie as well as the URL,
because the server-side row alone does not stop login CSRF — an attacker holds
a valid unspent state of their own and only needs the victim's browser to
finish it. `nonce`, `iss`, `aud`, and `exp` are checked on the ID token; the
signature is not, and `oauth::social` says why (OIDC Core §3.1.3.7 point 6) and
what would make that stop being true.

GitHub needed its own note in the code: `/user` returns the *public profile*
address, which the account holder types in and GitHub does not check, so the
verified set comes from a second call to `/user/emails`. Its subject is the
numeric `id`, never `login`, which a user can change and free for somebody else.

**Tested against a mock provider, not a real one.** No provider's credentials
can run in CI, so `Transport` is a trait and the tests exercise the rules that
are ours. What has *not* been exercised is a real Google or GitHub response;
`README.md` says so too rather than calling this "tested".

**LDAP and Active Directory are built**, as a user source: search for the
person, bind as their DN with the submitted password, then resolve to a local
account by DN or create one.

Three rules carry it, and each is a way LDAP authentication is routinely got
wrong. They are pure functions so they can be tested without a directory, and
removing any of the first two turns a test red.

* **An empty password never reaches the directory.** A simple bind with an
  empty password is an *anonymous* bind, and a directory answers it with
  success — so a server that forwards one has authenticated nobody as
  somebody. `Credentials::new` is the only way to reach the bind, which makes
  the check unskippable rather than remembered.
* **The login is escaped into the filter** per RFC 4515. `*)(uid=*`
  substituted raw closes the intended clause and opens a match-anything one,
  and whoever the directory returns first gets in.
* **Exactly one result, or nothing.** Two matches means the filter does not
  identify a person, and "pick the first" picks whoever the directory happened
  to return.

The DN is the identity, not the login name: a `uid` can be reassigned when
somebody leaves, and a directory handing `jsmith` to a new starter would
otherwise hand them the previous holder's account and its roles. It is stored
case-normalised, so two spellings of one identity do not become two accounts.

`ldap3` with `tls-rustls-ring` — not `tls-native` (OpenSSL, which `deny.toml`
bans) and not `tls-rustls-aws-lc-rs` (the C and assembly crypto stack this
workspace already declined once).

**Tested against a scripted directory, not a real one**, for the same reason as
social login: no directory's credentials can run in CI, and standing up
OpenLDAP for these tests would exercise `ldap3` rather than the rules above.
What has not been exercised is a live OpenLDAP or Active Directory response.

## Not built

Stated plainly, because each of these is advertised by a specification this
repository claims to implement:

- **`plain` PKCE** — `S256` only; see Stage 4b for why.
- **The implicit and hybrid flows** — `response_type=code` only.
- **`client_credentials`** — machine-to-machine access is through a bound
  account's API token instead.
- **ID token signature verification at the social provider** — the claim
  checks are done, the signature is not; `oauth::social` records why and what
  would change it.
- **DNS ownership verification for organisations** — an organisation can be
  created but its domain cannot be proved; see Stage 7.
- **Anything in the Removed table below** — those subsystems are gone and are
  not planned.

## Removed, and why

These subsystems existed in the previous tree as code that returned invented
data. They were deleted rather than carried forward; each is a project in its
own right, and none is currently planned. All of it remains at the tag
`archive/pre-refactor`.

| Subsystem | What it actually did |
|---|---|
| SAML 2.0 | Three overlapping implementations; signature validation documented in its own comments as "simplified" |
| OID4VC / SD-JWT | Credential proofs were `format!("mock-proof-{}", uuid)` |
| Post-quantum cryptography | Key types present, never reachable from any request path |
| Clustering / Raft | Consensus was comments: `// we'd send vote requests to peers` |
| FIPS mode | A boolean field; attested to nothing |
| Kubernetes operator | Built against a Kubernetes version that is end-of-life |
| Compliance engine (GDPR/HIPAA/SOC 2) | Produced verdicts without reading any data source |
| Zero-trust risk scoring | Scored on `X-Forwarded-For`, trusted unconditionally |
| SPI plugin framework | Two competing versions; its username/password and OTP authenticators returned `success: true` for any input |
| Secret vault | The PKCS#12 backend's `set_secret()` logged a warning and returned `Ok` without storing anything |

If you need one of these, open an issue describing the use case. It will be
built properly or not at all.
