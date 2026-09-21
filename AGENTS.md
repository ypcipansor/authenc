# AGENTS.md

Instructions for coding agents working in this repository. Everything here is
checkable — if a statement below stops being true, the statement is the bug.

## What this is

Authenc is an identity and access management server: a Leptos SSR frontend and
an Axum backend in one Rust workspace, over PostgreSQL via SQLx.

The repository was rebuilt from scratch in August 2026. The previous tree —
about 164,000 lines — did not compile, had failed CI on 926 consecutive runs,
and shipped authenticators that returned `success: true` without checking
anything. It is preserved in git history and at the tag `archive/pre-refactor`.
**Do not copy code from it.** If you need a feature it appeared to have, check
`ROADMAP.md`, then write it properly.

## Workspace map

| Crate | Path | Holds | Compiles to |
|---|---|---|---|
| `authenc-contract` | `crates/contract` | Entities, DTOs, `AppError`, validation | wasm **and** native |
| `authenc-identity` | `crates/identity` | Realms, users, roles, credentials, sessions — rules and SQL | native |
| `authenc-oauth` | `crates/oauth` | Signing keys, tokens, clients, codes, refresh rotation, consent, discovery | native |
| `authenc-web` | `crates/web` | Leptos pages, components, `#[server]` functions, hydrate entry | wasm **and** native |
| `authenc-server` | `crates/server` | Composition root, HTTP stack, CLI | native |

Dependencies run one way: `contract ← identity ← oauth ← server`, and
`contract ← web ← server` (with `web` reaching `identity` and `oauth` only
behind `ssr`). `server` is the only crate that wires things together.

`identity` and `oauth` must stay free of `axum` and `leptos`. That is what
lets every protocol rule be tested without an HTTP stack, and CI fails the
build if a dependency creeps in.

## Commands

```bash
just setup        # database + toolchain, first time
just dev          # cargo leptos watch — serves on :3000 with hot reload
just check        # fmt + clippy (both targets) + tests. Run before every commit.
just build        # cargo leptos build --release. Run before pushing a page change.
just test         # tests only
just migrate      # apply pending migrations
just sqlx-prepare # regenerate .sqlx offline data after changing any query
just demo-data    # invented, idempotent rows for the console pages
just screenshots  # capture every page into docs/screenshots/ (needs `just serve`)
just screenshot-check  # re-read those PNGs and fail on a blank or white one
```

`just check` deliberately stops short of the release wasm build, which takes
around ten minutes. That gap is real and has bitten once: a page whose `view!`
nested a `<Suspense>` around a `<Card>` around a form overflowed the trait
solver's depth limit in the **release** wasm build while compiling cleanly in
debug, so `just check` was green and CI was not. If you touched anything under
`crates/web/src/pages`, run `just build` before pushing. (The crate now sets
`recursion_limit = "256"`; prefer splitting a page into components over raising
it again.)

Without `just`, read `justfile` — it is short and every recipe is a plain
command.

### The build depends on a tool that is not in this repository

`cargo leptos build` shells out to a standalone `tailwindcss` binary to compile
the stylesheet. It resolves that binary **from `PATH` first**, and only
downloads a pinned copy when `PATH` has none — so whichever `tailwindcss` a
machine happens to have is the one that builds the CSS, and a broken entry by
that name fails the build with nothing but `No such file or directory` from
`cargo-leptos`'s `sync.rs`, long after the Rust compile has succeeded. That is
what it looks like; the message names neither Tailwind nor the file.

CI and the Dockerfile therefore install v4.2.1 explicitly and put it first on
`PATH`, and CI asserts the output carries Tailwind's banner rather than merely
being non-empty. If you change the pinned version, change it in both
`.github/workflows/ci.yml` and `Dockerfile`, and check it still matches what
`cargo-leptos` expects (`VersionConfig::Tailwind` in its source).

## Rules that CI enforces

1. **Never `--all-features`.** `hydrate` and `ssr` are mutually exclusive;
   enabling both makes `leptos` fail to compile. Build native with
   `--features ssr` and wasm with `--features hydrate`.
2. **Layer boundaries.** `authenc-contract` must not depend on `axum`, `sqlx`,
   or `leptos`. `authenc-identity` and `authenc-oauth` must not depend on
   `axum` or `leptos`. The `boundaries` CI job runs `cargo tree` and fails if
   they do.
3. **`Cargo.lock` is committed.** Build with `--locked`. `deny.toml` sets
   `yanked = "deny"`, so a dependency yanked upstream turns `cargo-audit` and
   `cargo-deny` red on every branch at once without any diff causing it — the
   fix is `cargo update -p <crate>` and a committed lockfile, not an ignore.
4. **Clippy is `-D warnings`**, with `unwrap`/`expect`/`panic` warned in crate
   code and allowed in tests (see `clippy.toml`).

## Rules that reviewers enforce

These are the failure modes the previous tree actually shipped. Each one is a
real defect that was in `main`.

- **Never return a success value from a function that did not check anything.**
  `verify_authentication()` returning `Ok(true)` is worse than `todo!()`,
  because nothing fails loudly. If it is not implemented, do not add the
  function.
- **Never add a test-only or unauthenticated route to the production router.**
  The old tree served `/oauth2/token/test` and `/oauth2/consent/test` with no
  auth, granting consent for a hardcoded user id. Seed data belongs in the CLI
  and in `#[sqlx::test]` fixtures.
- **Never store a bearer token where JavaScript can read it.** Sessions are an
  opaque id in an `HttpOnly` cookie. The old console kept a JWT in
  `localStorage`.
- **Never log a secret.** Config secrets use the `Secret` newtype, whose
  `Debug` is redacted. Authorization and Cookie headers are marked sensitive in
  the middleware stack.
- **Never let an internal error message reach a client.** `AppError::Internal`
  collapses to a fixed string in `public_detail()`; the real message is logged.
- **Authorise in the use case, not in a URL prefix.** Take an `Actor` and check
  it. The old code gated on path prefixes, so a route registered on the wrong
  router silently lost its access control.
- **A test that skips when the database is missing must fail or be
  `#[ignore]`d — never `return` quietly.** 68 old tests reported success while
  asserting nothing, in a CI job that had no database.
- **Never redirect a failed authorization to an unvalidated URI.** At the
  OAuth authorization endpoint, the client and the `redirect_uri` are settled
  first; until both check out there is nowhere an error may be sent, and it is
  reported on the spot. The old endpoint bounced the browser to whatever
  `redirect_uri` the caller supplied.
- **Never match a redirect URI by prefix.** Exact string comparison only.
  `https://good.example.com.attacker.test/` passes a prefix check.
- **Anything single-use is claimed by one atomic `UPDATE … WHERE used_at IS
  NULL`.** Read-then-write lets two concurrent redemptions both succeed. This
  applies to recovery tokens, authorization codes, and refresh tokens alike.
- **Detect replay, do not merely refuse it.** A spent authorization code or
  refresh token presented again means it leaked; revoke the family it minted
  rather than returning an error and leaving those tokens alive.
- **A half-finished login is a different type, not a flagged session.** When a
  second factor is enrolled, `login::authenticate` returns
  `Outcome::SecondFactorRequired`, whose token lives in `mfa_challenges` and
  resolves nowhere else. Never add a "pending" or "mfa_verified" column to
  `sessions`: a flag is something every reader has to remember to check, and a
  separate type is something the compiler checks for them.
- **A one-time code is not one-time until the spent step is written back.**
  `totp::verify` returns the matched step precisely so the caller must persist
  it. Dropping that write costs nothing visible and silently triples the window
  an observed code stays usable.
- **A WebAuthn challenge lives on the server.** Ceremony state goes in
  `webauthn_ceremonies`, keyed by an opaque token, single-use and expiring. A
  challenge the client holds and returns is not a challenge, whatever it is
  named.
- **Derive the WebAuthn relying party from configuration, never from a request
  header.** `Host` is attacker-controlled; an RP ID taken from it points the
  ceremony at an origin somebody else owns.
- **A contract type has one name on the wire, and it is the stored one.**
  `Permission` and `Action` serialise via `as_str()` with hand-written impls,
  not `#[serde(rename_all)]`. A derived spelling is a *second* name for the same
  thing: `whoami` said `user:read` while the enum said `user_read`, and only one
  of the two parsed back. If you add such an enum, round-trip every variant in a
  test.
- **Every aggregate id is its own type.** `GroupId`, `OrganizationId`,
  `InvitationId`, `UserId` and the rest live in `contract::id`; a bare `Uuid`
  in a signature is a defect. Adjacent parameters of the same primitive type
  are silently swappable, and `revoke_organization_invitation(db, actor, uuid,
  uuid)` compiled happily with its two arguments the wrong way round. The
  conversion belongs at the edges: `.0` when binding to SQL, `Id(row.id)` when
  reading back, and the HTTP layer keeps taking `Path<Uuid>` because `utoipa`
  cannot describe the newtype.
- **Inheritance in the group tree runs upward, never downward.** A member of a
  child holds its ancestors' roles; a member of a parent does not hold its
  children's. The other direction would make adding a nested group a privilege
  escalation for everyone above it.
- **A rule whose violation hangs a request belongs in the database.** Group
  cycles are refused by a trigger, not by Rust, because an ancestry walk over a
  cycle does not terminate and one runs on every authorised request.
- **Every REST request body sets `deny_unknown_fields`.** Serde drops unknown
  fields by default, so a caller's invented or mistyped parameter produced a
  2xx and an action that did not do what they asked.
- **The two API surfaces have two different CSRF gates, and both must run.**
  `/api/v1` requires the session-bound token in `x-csrf-token`; `/api/sfn`
  cannot, because the Leptos client sends no header of ours, so it is gated on
  `Sec-Fetch-Site`/`Origin` instead. Neither gate is `SameSite=Lax` on its own.
- **A use case with no caller is a feature that does not exist.** Auditing for
  public functions never referenced outside their own file found
  `accept_organization_invitation`: written, tested, and reachable from no
  endpoint, so a link could be issued and never redeemed while `README.md`
  said invitations worked. The same sweep found three helpers implying
  protections nobody used. Before claiming a feature, follow it from the HTTP
  surface to the database and back.
- **A security check is not mounted until a test proves it refuses something.**
  `is_same_origin` was written, unit-tested, and called from nowhere; the
  server-function surface had no CSRF gate at all, and a `curl` with a session
  cookie and no token deleted a group. Worse, the first fix *looked* mounted:
  a guard on a `/api/sfn/{*path}` route registered in `http.rs` never ran,
  because `leptos_routes_with_context` registers the concrete server-function
  paths itself and a concrete path beats a wildcard. Write the test that sends
  the forged request, and watch it fail before the fix.
- **Server functions return `ServerFnError`, and the status must be set.**
  Leptos reports every server-function failure as 500 unless something calls
  `to_server_fn_error`. `require_session` and `require_actor` therefore return
  an already-converted error — but anywhere else, a bare `?` on an `AppError`
  goes through a blanket conversion that loses the status, and a 401 arrives as
  a 500. Tests should assert the status, not merely that the call failed.

## Writing tests

- Unit tests live beside the code in `#[cfg(test)] mod tests`.
- Database tests use `#[sqlx::test(migrations = "../../migrations")]`, which
  provisions a throwaway database per test and drops it afterwards. Use a real
  database; do not mock the repository layer.
- Name tests for the property they prove
  (`a_malformed_stored_hash_is_an_error_not_a_successful_login`), not for the
  function they call.
- A test must fail if the behaviour it describes is removed. Deleting the
  implementation and re-running is a cheap way to check.

## SQL

Queries are checked at compile time against the real schema. After adding or
changing one, run `just sqlx-prepare` and commit the `.sqlx/` change, otherwise
CI — which builds without a database — will fail.

Then run `just offline`, which compiles the workspace the way CI does. The
`--all-targets` in it is the whole point: a per-crate `cargo check` builds the
library and nothing else, so a query that lives in an *integration test* can be
absent from `.sqlx` and still look fine locally. That is not hypothetical — a
`cargo sqlx prepare` interrupted by a full disk committed a `.sqlx` missing one
test's query, four per-crate offline checks passed, and CI failed.

Migrations are additive and never edited once merged. Add a new file in
`migrations/`.

## Style

- Comments explain *why*, and are worth writing when the reason is not obvious
  from the code. Do not narrate what the next line does.
- Reference a defect by what it was, not by issue number.
- Match the surrounding code's naming and structure.
- Public items need doc comments; `missing_docs` is a warning at workspace
  level.

## Commits and pull requests

- Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`,
  `chore:`.
- Run `just check` before committing.
- Say what you did *not* do. A partial change described accurately is useful; a
  partial change described as complete is not.
