# syntax=docker/dockerfile:1
#
# Builds and runs the `fhe-service` HTTP service (see CLAUDE.md's "Cloud Run
# Deployment" section -- Cloud Run routes to container port 8080). This used
# to build and ship `nine65_v7_demo`, a CLI demo binary with no HTTP server
# at all, so the shipped image could never have served the deployed service.
#
# The previous "pre-copy manifests, then COPY crates crates" block provided
# no actual caching: nothing ran between the manifest-only copy and the full
# source copy that would have used just the manifests, so every build
# re-fetched every dependency from scratch. Real fetch/build caching here
# uses BuildKit cache mounts on the cargo registry and target dir instead --
# it does not need a hand-maintained list of every workspace member's
# manifest (this repo's `members = ["crates/*"]` glob currently covers a
# dozen crates, several with multiple explicit [[bin]] targets, so keeping
# that list in lockstep by hand is its own source of silent drift).
FROM rust:slim AS builder

WORKDIR /app

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --locked -p fhe-service \
    && cp target/release/fhe-service /app/fhe-service-bin


FROM debian:bookworm-slim AS runtime

WORKDIR /app

# Minimal runtime dependencies.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root for safety.
RUN useradd --create-home --shell /usr/sbin/nologin appuser
USER appuser

# Copy the built binary from the builder stage.
COPY --from=builder /app/fhe-service-bin /usr/local/bin/fhe-service

# Cloud Run's configured container port is 8080 (CLAUDE.md); the process
# must bind 0.0.0.0, not its loopback default, to accept traffic routed to
# the container's external interface.
ENV FHE_SERVICE_HOST=0.0.0.0
ENV FHE_SERVICE_PORT=8080
EXPOSE 8080

# The service fails closed without these -- see crates/fhe-service/src/auth.rs
# and crates/fhe-service/src/handlers.rs. Set at deploy time, not baked in:
#   FHE_API_TOKEN       internal token stamped onto authenticated requests
#   FHE_TENANT_TOKENS   "tenant-a=secret-a;tenant-b=secret-b" per-tenant map
ENTRYPOINT ["/usr/local/bin/fhe-service"]
