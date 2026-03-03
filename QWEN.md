# NINE65 v7 — Project Context for Qwen Code

## Project Overview

**NINE65 v7 "Bootstrap Complete"** is a proprietary, unlimited-depth Fully Homomorphic Encryption (FHE) system built on the QMNF (Quantized Modular Number Field) architecture. Written entirely in Rust with **zero floating-point arithmetic** across all cryptographic runtime paths.

### Key Achievement

First FHE system with **fully verified bootstrap roundtrip** across all three paths:
| Path | Method | Status |
|------|--------|--------|
| **Circular Bootstrap** | `bootstrap()` — boot_sk = lift(work_sk) | Verified exact |
| **Non-Circular (KSK)** | `bootstrap_with_ksk()` — independent boot_sk, gadget key switch | Verified exact |
| **Auto-Bootstrap** | `AutoBootstrapEvaluator::mul_auto()` — auto-trigger on noise threshold | Verified 10+ chained muls |

This enables **truly unlimited-depth FHE computation** with deterministic, bit-identical results across all platforms.

---

## Repository Structure

```
NINE65_v7/
├── crates/
│   ├── nine65/                    # Core FHE library (599+ tests)
│   │   └── src/
│   │       ├── arithmetic/        # RNS, K-Elimination, NTT, Montgomery, Barrett
│   │       ├── ops/
│   │       │   ├── rns_fhe.rs           # BFV ops (encrypt, mul, decrypt)
│   │       │   ├── bootstrap.rs         # Clockwork Bootstrap (3 paths)
│   │       │   ├── auto_bootstrap.rs    # AutoBootstrapEvaluator
│   │       │   └── gso_fhe.rs           # GSO depth management
│   │       ├── entropy/           # CRT Shadow + CSPRNG (ShadowHarvester)
│   │       ├── security/          # CT primitives, GRO gates, secret_data.rs
│   │       ├── keys/              # Key generation (BSK, KSK, eval keys)
│   │       ├── noise/             # Noise budget tracking (millibits)
│   │       └── params/            # Secure configs + security estimator
│   ├── clockwork-core/            # Formal-spec RNS (Garner, GRO, bounds)
│   ├── exact_transcendentals/     # Exact CORDIC transcendentals (143 tests)
│   ├── nexgen_rational/           # Exact i128 rational arithmetic (95 tests)
│   ├── fhe-service/               # Session management + /decrypt endpoint
│   ├── mana/                      # FHE stream accelerator (lane-parallel)
│   └── unhal/                     # Hardware abstraction layer
├── proofs/coq/                    # 14 machine-checked Coq proofs
├── lean4/KElimination/            # 4 Lean4 formalizations
├── scripts/                       # Quality gates (claim registry, no_floats, etc.)
├── docs/                          # Security proofs, benchmarks, compliance
└── state/                         # State management
```

---

## Workspace Crates

| Crate | Purpose | Tests |
|-------|---------|-------|
| `nine65` | Core FHE: arithmetic, ring, ops, security, entropy, keys, noise, params | 599+ |
| `clockwork-core` | Formal-spec RNS: bound tracking, GRO timing, Garner, integrity | 46 |
| `exact_transcendentals` | Exact transcendental functions via integer CORDIC | 143 |
| `nexgen_rational` | Exact i128 rational arithmetic, zero-dep | 95 |
| `fhe-service` | FHE session management and serialization | 22 |
| `mana` | FHE stream accelerator, lane-parallel pipeline engine | 30 |
| `unhal` | Hardware abstraction layer | 10 |

---

## Building and Running

### Build Commands

```bash
# Build all crates (release)
cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm

# Build core crate only
cargo build --release -p nine65
```

### Test Commands

```bash
# Run all tests
cargo test --release --workspace --exclude nine65-python --exclude nine65-wasm

# Core FHE tests only
cargo test -p nine65 --lib --release

# Bootstrap-specific tests
cargo test -p nine65 --lib --release -- bootstrap
cargo test -p nine65 --test bootstrap_integration --release
cargo test -p nine65 --test bootstrap_parameter_exploration --release

# Security tests
cargo test -p nine65 security::tests -- --nocapture

# Depth benchmarks (secure_128)
cargo test -p nine65 --lib --release \
  ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 \
  -- --nocapture
```

### Quality Gates

```bash
# All quality checks
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace --release

# Verify integer-only runtime (no f32/f64 in cryptographic paths)
./scripts/check_no_floats_runtime.sh

# Verify claim registry consistency
./scripts/check_claim_registry.sh
```

---

## Feature Flags

| Flag | Description | Production? |
|------|-------------|-------------|
| `ntt_fft` (default) | FFT-based NTT (O(N log N)) | Yes |
| `parallel` | Opt-in Rayon parallelism | Yes |
| `accelerated` | MANA + UNHAL integration (recommended) | Yes |
| `clockwork` | GRO timing gates, bound tracking, key lifecycle | Yes |
| `exact_rational` | NexGen rational bridge (exact noise, BFV delta) | Yes |
| `exact_transcendentals_backend` | Integer CORDIC/AGM backend | Yes |
| `shadow-entropy` | CRT shadow entropy harvester | Yes |
| `adaptive-threading` | Entropy-based adaptive threads | Yes |
| `deterministic_rng` | Reproducible RNG for testing | Testing only |
| `allow_insecure` | Test-only configs (blocked in release) | **NEVER** |
| `debug_dual_mul` | Verbose debug for DualRNS | Debug only |
| `slow_tests` | Gates long-running tests | Testing only |
| `benchmarks` | Enables timing benchmarks | Benchmarking |

---

## Security Configurations

### Production-Safe Parameters

| Config | n | log2(q) | Classical | Quantum | Hybrid |
|--------|---|---------|-----------|---------|--------|
| `secure_128` | 4096 | 90 | 129 | 86 | 129 |
| `secure_192` | 16384 | 147 | 374 | 213 | 318 |
| `secure_256` | 16384 | 177 | 311 | 177 | 264 |

### Usage Example

```rust
use nine65::params::secure_configs::SecureConfig;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::entropy::ShadowHarvester;

// Setup with production-safe config
let config = SecureConfig::secure_128().into_config();
let ctx = RNSFHEContext::try_new(&config).expect("Context");
let boot = ClockworkBootstrap::new(&config).expect("Bootstrap");
let mut rng = ShadowHarvester::from_os_seed();

// Generate keys
let keys = ctx.generate_keys_dual_full(&mut rng);
let boot_keys = boot.generate_keys(&keys.secret_key, &mut rng).expect("KeyGen");

// Encrypt and compute
let ct_a = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
let ct_b = ctx.encrypt_dual(7, &keys.public_key, &mut rng);
let ct_prod = ctx.mul_dual_public(&ct_a, &ct_b, &keys.eval_key).expect("mul");

// Bootstrap refreshes noise -> enables unlimited depth
let ct_fresh = boot.bootstrap(&ct_prod, &boot_keys.bsk, &boot_keys.ksk)
    .expect("bootstrap");

// Continue computing on refreshed ciphertext
let ct_c = ctx.encrypt_dual(3, &keys.public_key, &mut rng);
let ct_result = ctx.mul_dual_public(&ct_fresh, &ct_c, &keys.eval_key)
    .expect("mul after boot");
let result = ctx.decrypt_dual(&ct_result, &keys.secret_key);
assert_eq!(result, 42 * 7 * 3);
```

### Auto-Bootstrap (Unlimited Depth)

```rust
use nine65::ops::auto_bootstrap::AutoBootstrapEvaluator;

let mut evaluator = AutoBootstrapEvaluator::new(
    &ctx, &boot, &boot_keys.bsk, &boot_keys.ksk, &keys.eval_key, &config,
);

// Chain arbitrary multiplications - bootstrap fires automatically
let ct_x = ctx.encrypt_dual(2, &keys.public_key, &mut rng);
let mut ct = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
for _ in 0..20 {
    ct = evaluator.mul_auto(&ct, &ct_x).expect("unlimited depth");
}
// Result is exact: 2^20 mod t
```

---

## Development Conventions

### Integer-Only Mandate

**NINE65 enforces a strict no floating-point at runtime policy.** All cryptographic runtime paths, hot loops, and public APIs must avoid `f32`/`f64`.

**Exception**: `compiler.rs` uses `f64` exclusively for **offline/static noise analysis** (does not execute in production).

#### Integer Representation Conventions

| Concept | Type | Scale | Example |
|---------|------|-------|---------|
| Noise budget | `u64` millibits | 1000 = 1 bit | `31500` = 31.5 bits |
| Ratios | `u32` permille | 1000 = 1.0 | `28500` = 28.5 |
| Error sigma | `u32` millibits | 1000 = 1.0 | `3200` = sigma 3.2 |
| Trig values | Q15 fixed-point LUT | >> 15 | 256-entry cos/sin table |

```rust
// WRONG (runtime)
let noise_bits: f64 = 31.5;

// CORRECT (runtime)
let noise_millibits: u64 = 31_500;

// Allowed (compiler.rs static analysis only)
let noise_bits: f64 = 31.5;
```

### Code Quality Requirements

All of the following must pass before committing:

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace --release
```

- Use `thiserror` for error types (`Nine65Error`, `Nine65Result`)
- Sensitive data must derive `Zeroize` and use `subtle` crate for constant-time operations
- All security-sensitive paths must be constant-time (see `security/secret_data.rs`)

### Commit Message Prefixes

| Prefix | Purpose |
|--------|---------|
| `fix:` | Bug fixes |
| `feat:` | New features |
| `refactor:` | Code restructuring |
| `test:` | Test additions/fixes |
| `proof:` | Formal proof updates |
| `docs:` | Documentation changes |
| `security:` | Security hardening |

---

## Formal Verification

### Coq Proofs (14)

K-Elimination, GSO-FHE, CRT Shadow Entropy, Order Finding, MQ-ReLU, Integer Softmax, Montgomery, Mobius, Cyclotomic Phase, Pade Engine, Exact Coefficient, State Compression, Side-Channel Resistance, Encrypted Quantum.

```bash
cd proofs/coq && coqc *.v  # Requires Coq 8.18+
```

### Lean4 Proofs (4)

K-Elimination, Core Definitions, Shadow Entropy, Modular Arithmetic.

```bash
cd lean4/KElimination && lake build  # Requires Lean 4.x + Mathlib
```

---

## Performance Benchmarks

Performance baselines from internal release builds on CPU. No GPU required.

### FHE Operations (secure_128 / secure_192)

| Operation | secure_128 | secure_192 |
|-----------|------------|------------|
| Encrypt | 23.56ms | 61.59ms |
| Add | 0.83ms | 2.10ms |
| Mul | 152.13ms | 459.02ms |
| Decrypt | 11.06ms | 29.00ms |

### Depth (Symmetric Mode)

| Config | Depth | Total | Avg/mul |
|--------|-------|-------|---------|
| secure_128 | 50 | 6.29s | 125.81ms |
| secure_192 | 50 | 10.10s | 201.91ms |

### RNS Arithmetic (4-lane)

| Op | Time | Throughput |
|----|------|------------|
| ADD | 65.7ns | 15.2M/s |
| MUL | 95.6ns | 10.5M/s |

---

## Security Considerations

### Production Safety

- Only `secure_128`, `secure_192`, `secure_256` configs are validated for production
- `allow_insecure` feature **must never** be enabled in release builds
- All Context constructors assert production-safe configs via `assert_production_safe_fhe_config()`

### Side-Channel Hardening

- Constant-time primitives in `security/secret_data.rs`
- Use `subtle` crate for constant-time comparisons
- Montgomery multiplication and K-Elimination paths are branchless

### fhe-service Decryption Oracle Warning

The `fhe-service` crate exposes a `/decrypt` endpoint which is a **decryption oracle**. Do not expose to untrusted clients. Deploy behind authentication (mTLS, API key) restricted to authorized enclave operators only.

---

## License

Proprietary. All rights reserved. See `LICENSE`.

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `README.md` | Project overview, quick start, architecture |
| `CONTRIBUTING.md` | Contribution guidelines and development standards |
| `CLAUDE.md` | Alternative project context file |
| `SECURITY.md` | Security policy and vulnerability reporting |
| `Cargo.toml` | Workspace configuration |
| `crates/nine65/src/lib.rs` | Core crate root with prelude module |
| `crates/nine65/src/ops/rns_fhe.rs` | DualRNS FHE operations (recommended for ct×ct) |
| `crates/nine65/src/ops/bootstrap.rs` | Clockwork Bootstrap implementation |
| `crates/nine65/src/ops/auto_bootstrap.rs` | Auto-triggered bootstrap |
| `docs/LATTICE_ESTIMATOR_BASELINE_2026-02-25.md` | Security baseline |
| `docs/BOOTSTRAP_CORRECTNESS_CONTRACT.md` | Bootstrap correctness specification |

---

*NINE65 v7 "Bootstrap Complete" — Built on QMNF architecture by Acidlabz210*
