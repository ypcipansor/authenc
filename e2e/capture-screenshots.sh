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
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
DEMO_REALM="${DEMO_REALM:-master}"
DEMO_USER="${DEMO_USER:-admin}"
DEMO_PASSWORD="${DEMO_PASSWORD:-correct horse battery staple}"
SERVER_LOG="${SERVER_LOG:-/tmp/authenc-server.log}"
PSQL="${PSQL:-docker exec -i authenc-postgres-1 psql -U postgres -d authenc}"

JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

echo "==> re-arming the verification token"
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
npm install --silent --no-audit --no-fund
RESET_TOKEN="$RESET_TOKEN" \
VERIFY_TOKEN="verifytoken123" \
BASE_URL="$BASE_URL" \
DEMO_REALM="$DEMO_REALM" \
DEMO_USER="$DEMO_USER" \
DEMO_PASSWORD="$DEMO_PASSWORD" \
  node capture.mjs
