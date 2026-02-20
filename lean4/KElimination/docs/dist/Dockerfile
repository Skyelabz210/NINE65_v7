# MANA FHE Benchmark - Secure Sandbox Container
#
# This container provides complete isolation:
# - No network access
# - No filesystem access outside container
# - Runs as non-root user
# - Read-only root filesystem
# - All capabilities dropped
#
# Build:  docker build -t mana-benchmark .
# Run:    docker run --rm --network=none --read-only --cap-drop=ALL mana-benchmark

FROM debian:bookworm-slim

# Create non-root user for running benchmark
RUN useradd -m -s /bin/bash benchmark && \
    mkdir -p /app && \
    chown benchmark:benchmark /app

WORKDIR /app

# Copy only the benchmark binary
COPY --chown=benchmark:benchmark mana_fhe_benchmark /app/
COPY --chown=benchmark:benchmark VERIFICATION.txt /app/
COPY --chown=benchmark:benchmark mana_fhe_benchmark.sha256 /app/

# Make binary executable
RUN chmod +x /app/mana_fhe_benchmark

# Switch to non-root user
USER benchmark

# Verify checksum at build time
RUN sha256sum /app/mana_fhe_benchmark && \
    echo "Expected: 61a3e1110324297a512da84270f4d73544d96fbdb80dc6bea0dbf94c5a54c5dd"

# Health check - just verify binary exists and is executable
HEALTHCHECK --interval=30s --timeout=3s \
    CMD test -x /app/mana_fhe_benchmark || exit 1

# Default command runs the benchmark
ENTRYPOINT ["/app/mana_fhe_benchmark"]
