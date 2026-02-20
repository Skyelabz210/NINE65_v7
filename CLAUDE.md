# NINE65 v7 "Bootstrap Complete" - Claude Code Guide

## Build & Test

```bash
cargo build --release --workspace        # Build all 7 crates (nine65, clockwork-core, exact_transcendentals, nexgen_rational, fhe-service, mana, unhal)
cargo test --workspace --release          # Run all tests
cargo test -p nine65 --lib --release      # Core crate only
cargo test -p nine65 security::tests -- --nocapture  # Security tests
```

## Workspace Crates

| Crate | Path | Purpose |
|-------|------|---------|
| `nine65` | `crates/nine65/` | Core FHE: arithmetic, ring, ops, security, entropy, keys, noise, params (621 tests) |
| `clockwork-core` | `crates/clockwork-core/` | Formal-spec RNS arithmetic: bound tracking, GRO timing, key lifecycle, Garner, integrity (46 tests) |
| `exact_transcendentals` | `crates/exact_transcendentals/` | Exact transcendental functions via integer CORDIC (143 tests) |
| `nexgen_rational` | `crates/nexgen_rational/` | Exact i128 rational arithmetic, zero-dep (95 tests) |
| `fhe-service` | `crates/fhe-service/` | FHE session management and serialization (22 tests) |
| `mana` | `crates/mana/` | FHE stream accelerator, lane-parallel via Rayon (30 tests) |
| `unhal` | `crates/unhal/` | Hardware abstraction layer (10 tests) |

## Key Paths

- **Secure configs**: `crates/nine65/src/params/secure_configs.rs` - `SecureConfig::secure_128()`, `secure_192()`, `secure_256()`
- **Test configs**: Require `--features allow_insecure` flag
- **K-Elimination**: `crates/nine65/src/arithmetic/k_elimination.rs`
- **GSO-FHE**: `crates/nine65/src/ops/gso_fhe.rs` - Depth operations with Clockwork Bootstrap
- **Three-Lock Bootstrap**: `crates/nine65/src/bootstrap/` - Protected re-encryption with conjunction security (Shannon mask + RLWE outer + Clockwork)
- **NTT**: `crates/nine65/src/arithmetic/ntt.rs`
- **Security estimator**: `crates/nine65/src/params/security_estimator.rs`
- **CT primitives**: `crates/nine65/src/security/secret_data.rs`
- **Rational bridge**: `crates/nine65/src/arithmetic/rational_bridge.rs` (requires `exact_rational` feature)
- **Exact noise**: `crates/nine65/src/noise/exact_noise.rs` (requires `exact_rational` feature)
- **Exact delta**: `crates/nine65/src/params/exact_params.rs` (requires `exact_rational` feature)
- **Bound tracking**: `crates/nine65/src/arithmetic/bounded_rns.rs` (requires `clockwork` feature)
- **GRO timing gate**: `crates/nine65/src/security/gro_gate.rs` (requires `clockwork` feature)
- **Key lifecycle**: `crates/nine65/src/security/key_manager.rs` (requires `clockwork` feature)
- **Limb integrity**: `crates/nine65/src/security/integrity.rs` (requires `clockwork` feature)
- **Shadow entropy monitor**: `crates/nine65/src/entropy/shadow_entropy_monitor.rs` (adaptive tests require `adaptive-threading` feature)
- **Integer math utilities**: `crates/nine65/src/arithmetic/integer_math.rs` - log2, sqrt, format, trig LUT
- **Garner reconstruction**: `crates/clockwork-core/src/garner.rs` (cross-validates K-Elimination)
- **Coq proofs**: `proofs/coq/*.v` (14 proofs, requires Coq 8.18+)
- **Lean4 proofs**: `lean4/KElimination/` (4 proofs, requires Lean 4.x + Mathlib)

## Feature Flags

- `shadow-entropy` - Enable CRT shadow entropy harvester (needed for some benchmarks)
- `allow_insecure` - Enable test/light configs (NOT for production)
- `accelerated` - Link mana/unhal crates into nine65
- `v2` - Enable ntt_fft + wassan noise bundle
- `serde` - Serialization support (JSON + bincode)
- `deterministic_rng` - Reproducible testing via rand_chacha
- `exact_rational` - Enable NexGen rational bridge (exact noise tracking, BFV delta)
- `clockwork` - Enable Clockwork-Core integration (bound tracking, GRO timing, key lifecycle, integrity)
- `adaptive-threading` - Enable entropy-based adaptive thread count (depends on `shadow-entropy`)
- `slow_tests` - Enable expensive tests
- Defaults: `ntt_fft`, `parallel` (Rayon)

## Scripts

- `scripts/generate_performance_baseline.sh` - Generates dated performance baseline in `docs/`
- `scripts/generate_security_baseline.sh` - Generates lattice estimator baseline in `docs/`

## Depth Benchmarks (ignored by default, run with --include-ignored)

```bash
cargo test -p nine65 --lib --release \
  ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 \
  -- --include-ignored --nocapture
```

## Fuzz Testing (requires nightly)

```bash
cargo +nightly fuzz run fuzz_encrypt_decrypt
cargo +nightly fuzz run fuzz_k_elimination
```

## Conventions

- Integer-only: No floating-point anywhere (zero f32/f64 in all crates)
- Workspace uses resolver = "2"
- Release profile: LTO fat, codegen-units=1, panic=abort
- Proprietary license

## Integer-Only Representations

All values formerly expressed as floats now use exact integer representations:

| Concept | Type | Scale | Example |
|---------|------|-------|---------|
| Noise budget (bits) | `u64` millibits | 1000 = 1 bit | `31500` = 31.5 bits |
| Ratios (N/logQ, hit rate) | `u32` permille | 1000 = 1.0 | `28500` = 28.5 |
| Error sigma | `u32` millibits | 1000 = 1.0 | `3200` = σ=3.2 |
| Timing display | `Duration::as_nanos()/as_micros()` | native | integer division |
| Trig (basin placement) | Q15 fixed-point LUT | `>> 15` | 256-entry cos/sin table |
| Statistics (chi-squared) | `×1000` scaled | 1000 = 1.0 | `chi_sq_x1000 < 50_000` |

**Key utilities** in `crates/nine65/src/arithmetic/integer_math.rs`:
- `integer_log2(x)` / `integer_log2_u128(x)` - floor(log2) via `leading_zeros()`
- `integer_sqrt(n)` - floor(sqrt) via Babylonian method
- `format_millibits(mb)` - display `31500` as `"31.500"`
- `format_ops(ops)` - display `1_234_567_890` as `"1G"`
- `fixed_cos_sin(angle_idx)` - Q15 cos/sin lookup from 256-entry table
- `COS_SIN_TABLE` / `GOLDEN_ANGLE_Q30` - precomputed constants

**Exemption**: `compiler.rs` retains `#![allow(clippy::float_arithmetic)]` — it is a compile-time analysis tool, not runtime computation.
