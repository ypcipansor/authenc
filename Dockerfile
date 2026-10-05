# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
FROM rust:1.99-bookworm AS builder

# `webauthn-rs-core` links against OpenSSL. It is the one C dependency in the
# tree and the one exception in `deny.toml`; see the note there for why it is
# admitted and when it comes out.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown

# Pinned, and installed before the source is copied, so the layer caches.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-leptos --locked

# The CSS compiler, pinned to the version cargo-leptos expects. cargo-leptos
# would otherwise fetch it itself, in the middle of the build, from whatever
# the latest release happens to be — and it resolves `tailwindcss` from PATH
# before it considers downloading, so an unexpected entry there decides which
# compiler builds the stylesheet. Installing it here settles both.
ARG TAILWIND_VERSION=v4.2.1
RUN curl -fsSL --retry 3 -o /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-x64" \
    && chmod +x /usr/local/bin/tailwindcss \
    && tailwindcss --help >/dev/null

WORKDIR /build

COPY Cargo.toml Cargo.lock rust-toolchain.toml clippy.toml ./
COPY crates ./crates
COPY migrations ./migrations
COPY .sqlx ./.sqlx

# Build against the committed query metadata: no database is reachable here.
ENV SQLX_OFFLINE=true

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo leptos build --release \
    && mkdir -p /out \
    && cp target/release/authenc /out/authenc \
    && cp -r target/site /out/site

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged: nothing this process does needs root.
RUN useradd --system --create-home --uid 10001 authenc
USER authenc
WORKDIR /app

COPY --from=builder --chown=authenc:authenc /out/authenc /app/authenc
COPY --from=builder --chown=authenc:authenc /out/site /app/site

ENV LEPTOS_OUTPUT_NAME=authenc \
    LEPTOS_SITE_ROOT=/app/site \
    LEPTOS_SITE_PKG_DIR=pkg \
    AUTHENC_SERVER__HOST=0.0.0.0 \
    AUTHENC_SERVER__PORT=3000 \
    AUTHENC_TELEMETRY__JSON=true

EXPOSE 3000

# Readiness, not liveness: this must fail while the database is down.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:3000/health/ready || exit 1

ENTRYPOINT ["/app/authenc"]
