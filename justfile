# Task runner. `just --list` shows everything.
#
# Every recipe is a plain command, so you can run them by hand if you would
# rather not install `just` (cargo install just).

set dotenv-load := true

default:
    @just --list

# First-time setup: toolchain targets, tools, and a database.
setup:
    rustup target add wasm32-unknown-unknown
    cargo install cargo-leptos --locked
    cargo install sqlx-cli --no-default-features --features rustls,postgres --locked
    @test -f .env || cp .env.example .env
    just db-up
    just migrate

# Start PostgreSQL (and MailHog) via compose.
db-up:
    docker compose up -d postgres

# Stop the compose stack.
db-down:
    docker compose down

# Apply pending migrations.
migrate:
    sqlx migrate run --source migrations

# Create a realm and an administrator in it, then print nothing else.
#   just seed admin@example.com 'a long passphrase you will remember'
#
# The password travels in the environment rather than as an argument, which the
# CLI asks for: an argument is visible in the process list and in shell history.
seed email password:
    AUTHENC_SEED_PASSWORD={{quote(password)}} cargo run -p authenc-server --bin authenc -- seed --email {{quote(email)}}

# Create a new migration file.
migration name:
    sqlx migrate add --source migrations {{name}}

# Regenerate the offline query metadata that lets CI build without a database.
# Run this after adding or changing any sqlx query, and commit `.sqlx/`.
sqlx-prepare:
    cargo sqlx prepare --workspace -- --all-targets --features ssr

# Run the app with hot reload on http://localhost:3000.
dev:
    cargo leptos watch

# Production build: server binary plus the optimised wasm bundle.
build:
    cargo leptos build --release

# Everything CI checks, in the order CI checks it.
check: fmt-check lint test boundaries offline

# Compile everything the way CI does: no database, `.sqlx` only.
#
# `--all-targets` is the point. A per-crate `cargo check` compiles the library
# and nothing else, so a query that lives in an integration test can be missing
# from `.sqlx` and still look fine locally — which is exactly how a broken
# offline build reached CI once.
offline:
    SQLX_OFFLINE=true cargo check --workspace --all-targets --features ssr --locked

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

# Clippy on both halves. Never `--all-features`: `hydrate` and `ssr` cannot
# both be on.
lint:
    cargo clippy --workspace --all-targets --features ssr --locked -- -D warnings
    cargo clippy -p authenc-web --no-default-features --features hydrate \
        --target wasm32-unknown-unknown --locked -- -D warnings

test:
    cargo test --workspace --locked

# Fail if a crate has picked up a dependency its layer forbids.
boundaries:
    #!/usr/bin/env bash
    set -euo pipefail
    fail() { echo "boundary violation: $1"; exit 1; }
    tree_has() { cargo tree -p "$1" --edges normal --prefix none 2>/dev/null | awk '{print $1}' | grep -qx "$2"; }
    for forbidden in axum sqlx leptos; do
        tree_has authenc-contract "$forbidden" && fail "authenc-contract depends on $forbidden"
    done
    for crate in authenc-identity authenc-oauth; do
        for forbidden in axum leptos; do
            tree_has "$crate" "$forbidden" && fail "$crate depends on $forbidden"
        done
    done
    echo "layer boundaries hold"

# Register an OAuth client and print its secret once.
#   just register-client web 'Example App' https://app.example.com/callback
register-client client_id name redirect_uri:
    cargo run -p authenc-server --bin authenc -- register-client \
        --client-id {{client_id}} --name {{quote(name)}} --redirect-uri {{redirect_uri}}

# Print a fresh key-encryption key for AUTHENC_OAUTH__MASTER_KEY.
master-key:
    cargo run -p authenc-server --bin authenc -- generate-master-key

# Delete everything that has expired, across every store.
purge:
    cargo run -p authenc-server --bin authenc -- purge

# Purge, and trim the audit log to a retention window. Retention is opt-in:
# an audit log that trims itself on a schedule nobody chose is one that will
# be empty when it is needed.
purge-audit days="365":
    cargo run -p authenc-server --bin authenc -- purge --audit-older-than {{days}}

# Supply-chain checks.
audit:
    cargo deny check
    cargo audit

# Load the demo data the screenshots and the console pages are shown with.
# Invented, idempotent, and safe to re-run.
demo-data:
    #!/usr/bin/env bash
    set -euo pipefail
    docker exec -i authenc-postgres-1 psql -v ON_ERROR_STOP=1 -U postgres -d authenc \
        < e2e/demo-data.sql

# Run the server with its output captured, so `just screenshots` can read the
# development mailer's reset link back out of it.
serve:
    cargo run -p authenc-server --bin authenc -- serve 2>&1 | tee /tmp/authenc-server.log

# Capture every frontend page into docs/screenshots/.
# Needs a running server (see `just serve`) and the demo data (`just demo-data`).
screenshots:
    bash e2e/capture-screenshots.sh

# Re-read docs/screenshots/ and fail on a blank, white, or content-free image.
screenshot-check:
    python3 e2e/check-screenshots.py
