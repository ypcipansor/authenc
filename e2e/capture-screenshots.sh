#!/usr/bin/env bash
#
# Capture every frontend page into docs/screenshots/.
#
# Run through `just screenshots`. It expects the server to be running with the
# development mailer, because the password-reset token is read out of the log
# exactly as a person would read it out of their inbox — the alternative,
# inserting a token row directly, would capture a page that the real request
# path might not produce.
#
# The verification token is a fixture because the address it verifies is one.
#
# `DEMO_PASSWORD` is required and has no default. A published default would be
# a working administrator password for any instance somebody stood up with
# these steps, and the point of the capture is only to sign in — never to
# suggest the credentials somebody should run with. `AUTHENC_SEED_PASSWORD` is
# accepted in its place so the password the seed used is the password the
# capture uses, without asking for the same value twice.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
DEMO_REALM="${DEMO_REALM:-master}"
DEMO_USER="${DEMO_USER:-admin}"
SERVER_LOG="${SERVER_LOG:-/tmp/authenc-server.log}"
PSQL="${PSQL:-docker exec -i authenc-postgres-1 psql -U postgres -d authenc}"

# One exported secret drives both `just seed` and the capture.
DEMO_PASSWORD="${DEMO_PASSWORD:-${AUTHENC_SEED_PASSWORD:-}}"

if [ -z "${DEMO_PASSWORD:-}" ]; then
    echo "DEMO_PASSWORD is not set. The capture signs in with it, so it is required." >&2
    echo >&2
    echo "There is deliberately no default: a published one would be a working" >&2
    echo "administrator password. Use the password you seeded the administrator with." >&2
    echo "Read it without echoing it, or into the environment directly:" >&2
    echo >&2
    echo "  read -r -s -p 'Demo password: ' DEMO_PASSWORD && export DEMO_PASSWORD" >&2
    echo "  just screenshots" >&2
    echo >&2
    echo "AUTHENC_SEED_PASSWORD is accepted in its place, so the value the seed" >&2
    echo "used does not have to be exported a second time." >&2
    exit 1
fi

echo "==> re-arming the single-use fixtures"
$PSQL -q < "$HERE/token-fixtures.sql"

echo "==> requesting a password reset, to mint a real reset token"
curl -sf -X POST "$BASE_URL/api/sfn/password-reset" \
  -H 'Content-Type: application/json' \
  -H "Origin: $BASE_URL" -H 'Sec-Fetch-Site: same-origin' \
  -d "{\"realm\":\"$DEMO_REALM\",\"email\":\"admin@example.com\"}" \
  -o /dev/null
sleep 1

RESET_TOKEN="$(grep -o 'reset-password?token=[A-Za-z0-9_-]*' "$SERVER_LOG" \
  | tail -1 | cut -d= -f2 || true)"

if [ -z "${RESET_TOKEN:-}" ]; then
  echo "no reset token found in $SERVER_LOG." >&2
  echo "Start the server with its output going there: just serve > $SERVER_LOG 2>&1" >&2
  exit 1
fi

echo "==> capturing pages"
cd "$HERE/screenshots"
# `npm ci`, not `npm install`: the lockfile is committed, and a capture run
# should install exactly what the lockfile pins rather than resolve fresh.
npm ci --no-audit --no-fund
# A clean machine has Node but not the browser binary. `npx playwright install`
# is idempotent, so a machine that already has it pays only a version check.
npx playwright install chromium
RESET_TOKEN="$RESET_TOKEN" \
VERIFY_TOKEN="verifytoken123" \
BASE_URL="$BASE_URL" \
DEMO_REALM="$DEMO_REALM" \
DEMO_USER="$DEMO_USER" \
DEMO_PASSWORD="$DEMO_PASSWORD" \
  node capture.mjs
