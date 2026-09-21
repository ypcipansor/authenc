# e2e

Fixtures and tooling for looking at the running application.

| File | Purpose |
|---|---|
| `demo-data.sql` | Invented rows so the console pages have something to render. Idempotent. |
| `token-fixtures.sql` | Re-arms the single-use email-verification token. |
| `capture-screenshots.sh` | Mints a real reset token, then runs the capture. |
| `screenshots/capture.mjs` | Drives a browser through every page and validates each one. |
| `check-screenshots.py` | Re-reads the PNGs on disk and rejects blank or white ones. |

Run it all with `just screenshots && just screenshot-check`; see the README for
the prerequisites.

## Prerequisites

- A running server on `:3000` with the development mailer, its output going to
  `$SERVER_LOG` (default `/tmp/authenc-server.log`). The capture reads the
  password-reset token out of that log; without it, there is nothing to shoot.
- `DEMO_PASSWORD` exported, and equal to the password the administrator was
  seeded with. `AUTHENC_SEED_PASSWORD` is accepted in its place, so the value
  the seed used does not have to be exported twice. There is no default — a
  default would be a published administrator password.
- Node **20 or newer**, matching the `engines` constraint in
  `screenshots/package-lock.json`; the capture runs Playwright, which requires
  it.
- Network access for the first `npm ci` and `npx playwright install chromium`.
  A machine that has neither the packages nor the browser installed will fetch
  both; later runs are cache hits.

`just screenshots` runs `npm ci` from the committed lockfile and installs the
Chromium build Playwright expects, so it works from a clean checkout without
any prior setup beyond Node and the running server.

`demo-data.sql` is not a migration and is not applied at startup. Nothing here
runs in CI, and none of it belongs in a production database.
