FROM rust:slim AS builder

WORKDIR /app

# 1) Pre-copy manifests to maximize Docker layer caching.
COPY Cargo.toml Cargo.lock ./
COPY crates/mana/Cargo.toml crates/mana/Cargo.toml
COPY crates/nine65/Cargo.toml crates/nine65/Cargo.toml
COPY crates/unhal/Cargo.toml crates/unhal/Cargo.toml

# 2) Copy sources and build the demo binary.
COPY crates crates

RUN cargo build --release -p nine65 --bin fhe_demo


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
COPY --from=builder /app/target/release/fhe_demo /usr/local/bin/fhe_demo

ENTRYPOINT ["/usr/local/bin/fhe_demo"]
CMD ["--help"]

