# Contributing to NINE65 v5

Thank you for your interest in contributing to NINE65, a bootstrap-free Fully Homomorphic Encryption system built on exact integer arithmetic.

NINE65 is proprietary software. All contributions require prior written authorization from the copyright holder. By submitting a contribution, you agree that your work becomes the property of the project under the existing license terms.

---

## Getting Started

### Prerequisites

- Rust stable toolchain (edition 2021)
- Rust nightly toolchain (for fuzz testing only)
- Coq 8.18+ (for formal proofs)
- Lean 4.x with Mathlib (for Lean4 proofs)

### Building

```bash
cargo build --release --workspace        # Build all crates
cargo test --workspace --release          # Run all tests
cargo test -p nine65 --lib --release      # Core crate only
```

### Workspace Crates

| Crate | Path | Purpose |
|-------|------|---------|
| `nine65` | `crates/nine65/` | Core FHE: arithmetic, ring operations, security, entropy, keys, noise, params |
| `clockwork-core` | `crates/clockwork-core/` | Formal-spec RNS arithmetic: bound tracking, GRO timing, key lifecycle |
| `mana` | `crates/mana/` | FHE stream accelerator (lane-parallel via Rayon) |
| `nexgen_rational` | `crates/nexgen_rational/` | Exact i128 rational arithmetic (zero dependencies) |
| `unhal` | `crates/unhal/` | Hardware abstraction layer |

---

## Development Standards

### Integer-Only Mandate

NINE65 enforces a strict **no floating-point at runtime** policy. All cryptographic runtime paths, hot loops, and public APIs must avoid `f32`/`f64`. The only exception is the circuit compiler (`crates/nine65/src/compiler.rs`), which uses `f64` exclusively for offline/static noise analysis.

**Rationale**: Floating-point rounding compounds across FHE operations. Integer-only arithmetic guarantees deterministic, reproducible results across all platforms. Static analysis can use `f64` because it does not execute in production.

#### Integer Representation Conventions

| Concept | Type | Scale | Example |
|---------|------|-------|---------|
| Noise budget | `u64` millibits | 1000 = 1 bit | `31500` = 31.5 bits |
| Ratios | `u32` permille | 1000 = 1.0 | `28500` = 28.5 |
| Error sigma | `u32` millibits | 1000 = 1.0 | `3200` = sigma 3.2 |
| Trig values | Q15 fixed-point LUT | >> 15 | 256-entry cos/sin table |

Reference `crates/nine65/src/arithmetic/integer_math.rs` for utility functions.

```rust
// WRONG (runtime)
let noise_bits: f64 = 31.5;

// CORRECT (runtime)
let noise_millibits: u64 = 31_500;

// Allowed (compiler.rs static analysis)
let noise_bits: f64 = 31.5;
```

---

## Code Quality

All of the following must pass before submitting:

```bash
cargo test --workspace --release
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
grep -rn "f64\|f32" crates/ --include="*.rs"   # runtime must be clean; compiler.rs is the sole exception
```

- Use `thiserror` for error types.
- Sensitive data types must derive `Zeroize` and use `subtle` crate for constant-time comparisons.

---

## Feature Flags

| Flag | Purpose | Production? |
|------|---------|-------------|
| `ntt_fft` (default) | Number Theoretic Transform | Yes |
| `parallel` (default) | Rayon parallelism | Yes |
| `accelerated` | Links mana/unhal | Yes |
| `allow_insecure` | Test-only configs | **Never** |
| `exact_rational` | NexGen rational bridge | Yes |
| `clockwork` | Clockwork-Core integration | Yes |
| `deterministic_rng` | Reproducible RNG | Testing only |
| `serde` | Serialization support | Yes |

---

## Testing

```bash
cargo test --workspace --release                    # Full suite
cargo test -p nine65 security::tests -- --nocapture # Security tests
cargo +nightly fuzz run fuzz_encrypt_decrypt         # Fuzz testing
```

Depth benchmarks (ignored by default): `cargo test -p nine65 --lib --release -- --include-ignored --nocapture`

Add fuzz targets for new public API surfaces or serialization formats.

---

## Formal Proofs

Changes to proven algorithms require updated proofs.

- **Coq** (`proofs/coq/`, Coq 8.18+): 14 verified proofs
- **Lean4** (`lean4/KElimination/`, Lean 4.x + Mathlib)

---

## Pull Request Process

1. Branch from `main` with descriptive name
2. Follow all standards above
3. Validate: `cargo fmt && cargo clippy && cargo test --workspace --release`
4. Prefix commits: `fix:`, `feat:`, `refactor:`, `test:`, `proof:`, `docs:`
5. Open PR with description and validation confirmation

---

## License

NINE65 is proprietary software. All rights reserved. See [LICENSE](LICENSE).
