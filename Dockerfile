# ── Stage 1: Build ────────────────────────────────────────────────────
FROM rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
# Patched pg-embed, resolved through [patch.crates-io] in Cargo.toml.
COPY third_party/ third_party/
# Stub out the GUI crate so the workspace compiles without Node/Tauri deps.
COPY gui/src-tauri/Cargo.toml gui/src-tauri/Cargo.toml
RUN mkdir -p gui/src-tauri/src && echo "fn main(){}" > gui/src-tauri/src/main.rs

# Builds the IronVise server, the guard worker, and the
# offline verifier. Cargo's release `strip = true` drops the symbol table and
# leaves debug info, so GNU strip runs on every shipped binary. The copies in
# /out are the only builder files the runtime stage is allowed to see.
RUN cargo build --release -p ectoledger --no-default-features --features sandbox \
    && strip --strip-unneeded \
           target/release/ironvise \
           target/release/guard-worker \
           target/release/verify-cert \
    && mkdir -p /out \
    && cp target/release/ironvise \
          target/release/guard-worker \
          target/release/verify-cert \
          /out/

# ── Stage 2: Runtime rootfs ──────────────────────────────────────────
# The server links rustls (aws-lc, static), not libssl, and nothing in the
# image calls the curl binary. ca-certificates is the trust store rustls reads.
# The stage platform is already the build target; pinning it again is a
# redundant-platform lint.
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man /usr/share/info /usr/share/locale

# guard-worker sits next to the server: guard_process.rs resolves it as a
# sibling, so GUARD_REQUIRED=true fails closed if that file is missing.
# verify-cert is the offline verifier the documentation tells readers to run.
COPY --from=builder /out/ /usr/local/bin/

# Fail the build if a builder artifact (toolchain, cargo target, a downloaded
# PostgreSQL archive) landed in this rootfs. The shipped binaries are the only
# files that are allowed to be large.
RUN set -eu; \
    find / -xdev -type f -size +16M ! -path '/usr/local/bin/*' > /tmp/unexpected-large; \
    if [ -s /tmp/unexpected-large ]; then \
        echo "runtime rootfs contains files that are not the shipped binaries:"; \
        cat /tmp/unexpected-large; \
        exit 1; \
    fi; \
    rm -f /tmp/unexpected-large

# ── Stage 3: Flattened image ─────────────────────────────────────────
# `docker buildx --load` on the native architecture was keeping a builder
# layer in the image size (the rust:bookworm toolchain layer is ~170 MiB;
# the compiler layer next to it is ~194 MiB). The emulated architecture's
# export did not, so arm64 reported ~209 MB and amd64 ~51 MB while the three
# binaries were ~35 MB either way. Copying the runtime rootfs onto scratch
# makes one layer and drops every parent, on both architectures.
FROM scratch
COPY --from=runtime / /

LABEL org.opencontainers.image.source="https://github.com/EctoSpace/IronVise"
LABEL org.opencontainers.image.url="https://ectospace.com/IronVise"
LABEL org.opencontainers.image.description="IronVise - Cryptographic accountability for AI agents"
# BUSL-1.1, matching the workspace and the root LICENSE. The SDKs under sdk/
# are separately Apache-2.0 and are not in this image.
LABEL org.opencontainers.image.licenses="BUSL-1.1"
LABEL org.opencontainers.image.vendor="EctoSpace"

# ── DEMO-ORIENTED DEFAULTS - NOT a production configuration ────────────────
# This image ships insecure-by-design defaults so `docker run` works with no
# setup: the semantic guard is off, dev mode accepts default DB credentials,
# and the dashboard binds to every interface (the Bearer token is then the
# only access control). The server logs a WARN banner at startup whenever it
# is in this state.
#
# For a hardened deployment override all three (see docs/getting-started/running-securely.md):
#   -e GUARD_REQUIRED=true -e ECTO_DEV_MODE=false -e ECTO_BIND_HOST=127.0.0.1
ENV RUST_LOG=info \
    ECTO_BIND_HOST=0.0.0.0 \
    ECTO_BIND_PORT=3000 \
    ECTO_DEV_MODE=true \
    GUARD_REQUIRED=false

EXPOSE 3000
# Exec form needs no shell or curl. `ironvise health` reads GET /api/status.
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
  CMD ["ironvise", "health"]
ENTRYPOINT ["ironvise"]
CMD ["serve"]
