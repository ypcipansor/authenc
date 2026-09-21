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

`demo-data.sql` is not a migration and is not applied at startup. Nothing here
runs in CI, and none of it belongs in a production database.
