# NINE65 v7 "Bootstrap Complete"
## Unlimited-Depth FHE with Verified Clockwork Bootstrap

<div align="center">

**First FHE system with fully verified bootstrap roundtrip: circular, non-circular (KSK), and auto-triggered unlimited-depth chains**

[![Tests](https://img.shields.io/badge/tests-689%20passing-brightgreen)]()
[![Bootstrap](https://img.shields.io/badge/bootstrap-verified%20roundtrip-success)]()
[![Proofs](https://img.shields.io/badge/formal%20proofs-Coq%20%2B%20Lean4-blue)]()
[![Security](https://img.shields.io/badge/security-128--256%20bit-green)]()
[![Build](https://img.shields.io/badge/build-passing-success)]()

[What's New](#whats-new-in-v7) | [Quick Start](#quick-start) | [Architecture](#architecture) | [Benchmarks](#performance-benchmarks) | [Security](#post-quantum-security)

</div>

---

## What's New in v7

### Bootstrap-Complete: All Three Paths Verified

v7 achieves what no prior version could: **every bootstrap path produces exact plaintext recovery**, enabling truly unlimited-depth FHE computation.

| Path | Description | Status |
|------|-------------|--------|
| **Circular Bootstrap** | `bootstrap()` - boot_sk = lift(work_sk) | Verified exact |
| **Non-Circular (KSK)** | `bootstrap_with_ksk()` - independent boot_sk, gadget key switch | Verified exact |
| **Auto-Bootstrap** | `AutoBootstrapEvaluator::mul_auto()` - automatic trigger on noise threshold | Verified 10+ chained muls |

### Key Fixes (v6 -> v7)

1. **Key Switch Modswitch Fix**: `key_switch()` was performing simple residue reduction (`x mod Q_work`) instead of proper RNS modswitch (`round(x * Q_work / Q_boot)`). This destroyed the delta-m encoding for non-circular bootstrap. Fixed by separating key switch (stays in boot space) from modswitch (proper prime-drop scaling).

2. **Anchor Limb Recomputation**: `modswitch_boot_to_work()` zeroed K-Elimination anchor limbs, causing subsequent multiplications to produce garbage (K-Elimination rescale needs valid anchors). Fixed by CRT-reconstructing each coefficient from work main primes and reducing mod each anchor prime.

3. **CRT Gadget Decomposition**: `key_switch()` decomposed only from the first RNS limb (~30 bits) instead of CRT-reconstructing the full ~120-bit coefficient before base-B decomposition. Fixed with Garner's iterative CRT reconstruction across all boot prime limbs.

### New Regression Tests

| Test | What It Verifies |
|------|------------------|
| `test_circular_bootstrap_roundtrip` | 7 messages through circular bootstrap |
| `test_ksk_bootstrap_roundtrip` | 7 messages through non-circular KSK bootstrap |
| `test_mul_then_bootstrap_then_mul` | multiply -> bootstrap -> multiply chain |
| `test_auto_bootstrap_chained_muls` | 10 chained muls with auto-triggered bootstrap (2^11 = 2048) |

---

## Executive Summary

| Metric | NINE65 v7 |
|--------|-----------|
| **Max Depth** | Unlimited (auto-bootstrap) |
| **Bootstrap Paths** | 3 (circular, KSK, auto) |
| **Bootstrap Cost** | Trivial (depth-1 Clockwork) |
| **Security Levels** | 128, 192, 256 bit |
| **Test Coverage** | 689+ tests passing |
| **Formal Proofs** | 14 Coq + 4 Lean4 |
| **Platform** | CPU only, deterministic |
| **Arithmetic** | Integer-only (zero floats) |
| **Post-Quantum** | LWE-based (lattice verified) |

---

## Quick Start

```rust
use nine65::params::secure_configs::SecureConfig;
use nine65::ops::rns_fhe::RNSFHEContext;
use nine65::ops::bootstrap::ClockworkBootstrap;
use nine65::entropy::ShadowHarvester;

// Setup
let config = SecureConfig::secure_128().into_config();
let ctx = RNSFHEContext::try_new(&config).expect("Context");
let boot = ClockworkBootstrap::new(&config).expect("Bootstrap");
let mut rng = ShadowHarvester::from_os_seed();

// Keys
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

### Non-Circular Security (KSK Path)

```rust
// Independent boot key (no circular security assumption)
let boot_keys_ksk = boot.generate_keys_with_ksk(&keys.secret_key, &mut rng)
    .expect("KSK keygen");

let ct = ctx.encrypt_dual(42, &keys.public_key, &mut rng);
let ct_refreshed = boot.bootstrap_with_ksk(
    &ct, &boot_keys_ksk.bsk, &boot_keys_ksk.ksk
).expect("KSK bootstrap");
assert_eq!(ctx.decrypt_dual(&ct_refreshed, &keys.secret_key), 42);
```

---

## Architecture

```
NINE65_v7/
├── crates/
│   ├── nine65/              # Core FHE (689+ tests)
│   │   └── src/
│   │       ├── arithmetic/  # RNS, K-Elimination, NTT, Montgomery
│   │       ├── ops/
│   │       │   ├── rns_fhe.rs        # BFV operations (encrypt, mul, decrypt)
│   │       │   ├── bootstrap.rs      # Clockwork Bootstrap (3 paths)
│   │       │   ├── auto_bootstrap.rs # AutoBootstrapEvaluator
│   │       │   └── gso_fhe.rs        # GSO depth management
│   │       ├── entropy/     # CRT Shadow + CSPRNG
│   │       ├── security/    # CT primitives, GRO gates
│   │       ├── keys/        # Key generation (BSK, KSK, eval keys)
│   │       ├── noise/       # Noise budget tracking (millibits)
│   │       └── params/      # Secure configs + security estimator
│   ├── clockwork-core/      # Formal-spec RNS (Garner, GRO, bounds)
│   ├── exact_transcendentals/  # Exact CORDIC transcendentals
│   ├── nexgen_rational/     # Exact i128 rational arithmetic
│   ├── fhe-service/         # Session management
│   ├── mana/                # Lane-parallel accelerator
│   └── unhal/               # Hardware abstraction
├── proofs/coq/              # 14 machine-checked Coq proofs
├── lean4/KElimination/      # 4 Lean4 formalizations
├── scripts/                 # Quality gates
└── docs/                    # Security proofs, benchmarks, compliance
```

### Workspace Crates

| Crate | Purpose | Tests |
|-------|---------|-------|
| `nine65` | Core FHE: arithmetic, ring, ops, security, entropy, keys, noise, params | 599+ |
| `clockwork-core` | Formal-spec RNS: bound tracking, GRO timing, Garner, integrity | 46 |
| `exact_transcendentals` | Exact transcendental functions via integer CORDIC | 143 |
| `nexgen_rational` | Exact i128 rational arithmetic, zero-dep | 95 |
| `fhe-service` | FHE session management and serialization | 22 |
| `mana` | FHE stream accelerator, lane-parallel via Rayon | 30 |
| `unhal` | Hardware abstraction layer | 10 |

---

## Build and Test

```bash
# Build all crates (release)
cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm

# Run all tests
cargo test --release --workspace --exclude nine65-python --exclude nine65-wasm

# Core FHE tests only
cargo test -p nine65 --lib --release

# Bootstrap-specific tests
cargo test -p nine65 --lib --release -- bootstrap
cargo test -p nine65 --test bootstrap_integration --release
cargo test -p nine65 --test bootstrap_parameter_exploration --release

# Depth benchmarks
cargo test -p nine65 --lib --release \
  ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 \
  -- --nocapture

# Security tests
cargo test -p nine65 security::tests -- --nocapture
```

### Feature Flags

| Feature | Description |
|---------|-------------|
| `ntt_fft` (default) | FFT-based NTT |
| `parallel` (default) | Rayon parallelism |
| `clockwork` | GRO timing gates, bound tracking, key lifecycle, integrity |
| `exact_rational` | NexGen rational bridge (exact noise, BFV delta) |
| `shadow-entropy` | CRT shadow entropy harvester |
| `adaptive-threading` | Entropy-based adaptive threads (requires `shadow-entropy`) |
| `accelerated` | MANA + UNHAL integration |
| `deterministic_rng` | Reproducible testing |
| `allow_insecure` | Test-only configs (blocked in release) |

---

## Performance Benchmarks

Performance baselines from internal release builds on CPU. No GPU required.

### FHE Operations (secure_128 / secure_192)

| Operation | secure_128 | secure_192 |
|-----------|------------|------------|
| Encrypt | 23.56ms | 61.59ms |
| Add | 0.83ms | 2.10ms |
| Mul (K-Elim rescale) | 152.13ms | 459.02ms |
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

## Post-Quantum Security

NINE65 targets post-quantum security through LWE-based cryptography.

### Lattice Estimator Baseline

| Config | n | log2(q) | min attack log2(rop) |
|--------|---|---------|----------------------|
| `secure_128` | 4096 | 89.08 | 129 |
| `secure_192` | 8192 | 145.08 | 159 |
| `secure_256` | 16384 | 203.38 | 226 |

### Security Hardening

- **Constant-time operations**: Montgomery, K-Elimination, NTT
- **Compile-time parameter enforcement**: Test configs blocked in release
- **Runtime validation**: HE Standard compliance, orbital safety checks
- **GRO timing gates**: On keygen and decrypt paths
- **Noise budget monitoring**: Integer-only millibits precision

---

## Formal Verification

### Coq Proofs (14)

K-Elimination, GSO-FHE, CRT Shadow Entropy, Order Finding, MQ-ReLU, Integer Softmax, Montgomery, Mobius, Cyclotomic Phase, Pade Engine, Exact Coefficient, State Compression, Side-Channel Resistance, Encrypted Quantum.

### Lean4 Proofs (4)

K-Elimination, Core Definitions, Shadow Entropy, Modular Arithmetic.

```bash
# Verify Coq proofs (requires Coq 8.18+)
cd proofs/coq && coqc *.v

# Verify Lean4 proofs (requires Lean 4.x + Mathlib)
cd lean4/KElimination && lake build
```

---

## Technical Foundation

Built on the QMNF (Quantized Modular Number Field) architecture:

1. **Integer-only arithmetic**: Zero f64/f32 across all workspace crates
2. **Stacked CRT**: Two-layer exact arithmetic (fast CRTBigInt + unlimited HCVLangBigInt)
3. **Fused Piggyback Division**: 40x faster RNS division via anchor-first computation
4. **K-Elimination**: Exact division in RNS without floating-point
5. **Deterministic execution**: Bit-identical results across all platforms

---

## License

Proprietary. See `LICENSE`.

---

*NINE65 v7 "Bootstrap Complete" - Unlimited-Depth FHE with Verified Clockwork Bootstrap*
*Built on QMNF architecture by Acidlabz210*
