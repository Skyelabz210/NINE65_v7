# NINE65 Architecture

**Version**: 5.0 (module/layer map below predates Clockwork bootstrap, CRAM, and the MANA/UNHAL accelerator pipeline)
**Status**: Pre-production (deployment not recommended yet)
**Security Rating**: Provisional (see RedShirt assessment)

> **Staleness notice (2026-08-19):** this document was last fully rewritten
> 2026-01-24 ("Version 5.0") and describes the pre-bootstrap, pre-CRAM
> codebase. It predates the Clockwork bootstrap paths (circular, KSK,
> auto-triggered), the CRAM residue-native architecture, `clockwork-core`,
> `fhe-service`, `nine65-wasm`, and the MANA/UNHAL accelerator surfaces —
> none of that is reflected in the layer diagram or module tables below.
> **CLAUDE.md is the current, maintained architecture reference; treat this
> file as historical unless a specific section has been spot-corrected**, as
> a handful below have been (2026-08-19 truth pass) to remove claims that were
> actively wrong rather than merely outdated.

## Overview

NINE65 was originally a bootstrap-free FHE library built on the BFV scheme with novel components including K-Elimination for exact RNS division and GSO-FHE for gravitational swarm noise optimization. The current codebase adds real Clockwork bootstrap (circular, KSK-separated, and auto-triggered paths) on top of this foundation — see CLAUDE.md's "Bootstrap Paths" section. GSO-FHE remains one depth-management path among several, not the whole story.

**Deployment note**: Production deployment is not recommended until timing side-channel mitigations and parameter baselines are fully reconciled (see docs/REDSHIRT_SECURITY_ASSESSMENT.md). Minimum recommended configuration for evaluation is `SecureConfig::secure_192()`.

---

## Layer Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                             │
│  FHENeuralEvaluator, BatchEncoder, TrackedEvaluator             │
│  High-level APIs for ML inference and batch processing          │
├─────────────────────────────────────────────────────────────────┤
│                    FHE OPERATIONS LAYER                          │
│  BFVEvaluator, RNSFHEContext, GSOFHEContext                     │
│  Homomorphic add/sub/mul, noise tracking, K-Elimination         │
├─────────────────────────────────────────────────────────────────┤
│                    CRYPTOGRAPHIC LAYER                           │
│  BFVEncryptor, BFVDecryptor, KeySet                             │
│  Encryption, decryption, key generation                         │
├─────────────────────────────────────────────────────────────────┤
│                    ARITHMETIC LAYER                              │
│  NTTEngine, Montgomery, KElimination, RNSContext                │
│  Number-theoretic transforms, modular arithmetic, RNS ops       │
├─────────────────────────────────────────────────────────────────┤
│                    ENTROPY LAYER                                 │
│  ShadowHarvester, SecureRng, WassanNoiseField                   │
│  Deterministic testing RNG, OS CSPRNG, noise generation         │
├─────────────────────────────────────────────────────────────────┤
│                    SECURITY LAYER                                │
│  SecretData, SecretPoly, LWEParams, SecurityEstimate            │
│  Constant-time markers, security estimation, zeroization        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module Structure

### Core Modules (`src/`)

| Module | Purpose | Key Types |
|--------|---------|-----------|
| `arithmetic/` | Low-level math operations | `NTTEngine`, `KElimination`, `RNSContext` |
| `entropy/` | Random number generation | `ShadowHarvester`, `SecureRng` |
| `keys/` | Key generation and management | `SecretKey`, `PublicKey`, `EvaluationKey` |
| `ops/` | FHE operations | `BFVEvaluator`, `RNSFHEContext`, `Ciphertext` |
| `params/` | Configuration presets | `FHEConfig`, `SecureConfig` |
| `ring/` | Polynomial ring operations | `RingPolynomial`, `PolynomialPool` |
| `noise/` | Noise budget tracking | `NoiseBudget`, `NoiseEstimator` |
| `security/` | Security primitives | `SecretData`, `LWEParams` |
| `compiler.rs` | FHE circuit compiler | `FHECompiler`, `CompiledCircuit` |

### Arithmetic Submodules (`arithmetic/`)

| File | Component | Speedup |
|------|------------|---------|
| `k_elimination.rs` | Exact RNS division | 40x vs MRC |
| `order_finding.rs` | Non-circular BSGS | Novel |
| `ntt.rs` | Constant-time NTT | CT variants |
| `montgomery.rs` | Persistent Montgomery | 50-100x |
| `rns.rs` | Dual-track RNS | K-Elim enabled |

### Operations Submodules (`ops/`)

| File | Purpose |
|------|---------|
| `encrypt.rs` | BFV encrypt/decrypt |
| `homomorphic.rs` | Add/sub/mul/negate |
| `rns_fhe.rs` | RNS-based FHE with K-Elimination |
| `gso_fhe.rs` | GSO noise optimization |
| `rns_mul.rs` | Tensor product multiplication |
| `galois.rs` | Rotation operations |
| `batch.rs` | SIMD-style batching |
| `neural.rs` | Neural network layers |

---

## Key Components

> Every "Coq Proof" pointer below refers to the legacy `proofs/coq/` tree.
> Per CLAUDE.md, that tree is a **v2-era exploration predating the move to
> Lean, is not maintained, and is NOT the verification basis** — several
> files there do not compile and several contain `Admitted` lemmas. Lean 4
> (`lean4/KElimination/`, `lake build`: 0 errors, 0 `sorry`) is the current
> formalization of record. Do not cite the Coq references below as
> machine-checked.

### 1. K-Elimination Component
**Location**: `arithmetic/k_elimination.rs`

Provides exact RNS division with O(k) complexity vs O(k^2) for MRC.

```
Given V in dual-codex (α, β):
  V = vα (mod αcap)
  V = vβ (mod βcap)

Recover V exactly:
  k = (vβ - vα) × αcap_inv (mod βcap)
  V = vα + k × αcap
```

**Legacy Coq proof (not verification basis, see note above)**: `proofs/coq/KElimination.v`.
Current formalization of record: `lean4/KElimination/KElimination.lean`.

### 2. GSO-FHE Component
**Location**: `ops/gso_fhe.rs`

Gravitational Swarm Optimization: one depth-management path (noise collapse
without a level-consuming bootstrap), not the only one — Clockwork bootstrap
(circular, KSK-separated, auto-triggered) is the other, see CLAUDE.md.

- Adaptive noise collapse at configurable thresholds
- Depth reached is config- and chain-shape-dependent, not a fixed number.
  The "400x speedup for deep circuits" and "depth-50+" figures previously
  stated here were not backed by any asserting test or entry in
  `docs/CLAIM_REGISTRY.csv` and have been removed rather than restated with
  a number that could go stale the same way. For current, CI-asserted depth
  evidence see CLAUDE.md's "Bootstrap Paths" / depth-benchmark sections and
  `crates/nine65/tests/time_crystal_verification.rs::symmetric_depth_is_unbounded`
  (asserts a 128-level floor, `secure_128`, symmetric mul-by-fresh-operand,
  no bootstrap) and
  `crates/nine65/tests/depth_and_noise.rs::depth_and_noise_curve_deep_chain`
  (asserts a 32-level regression floor). `benchmark_symmetric_max_depth_secure_128`/
  `_192` in `gso_fhe.rs` are timing benchmarks only — they do not decrypt or
  assert correctness, so they establish throughput, not a verified depth.

**Legacy Coq proof (not verification basis, see note above)**: `proofs/coq/GSOFHE.v`.

### 3. Persistent Montgomery Component
**Location**: `arithmetic/montgomery.rs`

Keep values in Montgomery form across operations:
- 3n conversions vs 2 per operation
- 50-100x speedup for operation chains

**Legacy Coq proof (not verification basis, see note above)**: `proofs/coq/MontgomeryPersistent.v`.
The Lean counterpart, `lean4/KElimination/KElimination/Montgomery.lean`, is
the sound coverage — the Coq `MontgomeryContext.v` tree contains a theorem
(`montgomery_sub_correct`) with a known counterexample and must not be cited
as correct.

### 4. Shadow Entropy
**Location**: `entropy/shadow.rs`

CRT-based deterministic RNG for reproducible testing:
- Zero-cost randomness from modular quotients
- Deterministic across platforms
- OS CSPRNG fallback for production

---

## Security Architecture

### Constant-Time Enforcement

```rust
// Type-safe secret data marking
pub trait SecretData: Sized + Zeroize {}

// Forces CT operations
pub struct SecretPoly { coeffs: Vec<u64>, q: u64 }
impl SecretData for SecretPoly {}
```

### Key Security Features

| Feature | Implementation |
|---------|----------------|
| Zeroization | `ZeroizeOnDrop` on all secret types |
| CT NTT | `ntt_ct()`, `intt_ct()` variants |
| CT Montgomery | All ops have CT versions |
| Noise tracking | `TrackedEvaluator` with budget checks |
| Serde validation | `from_*_validated()` methods |

### Parameter Security

> The `light()`/`he_standard_128()`/`standard_128()` rows below are historical
> (2026-01-24) and not re-verified in this pass — they are test-only/insecure
> configs gated behind `allow_insecure` regardless. The three `SecureConfig::`
> rows are corrected to CLAUDE.md's "Security Configs" table, screened
> 2026-08-22 by `params::secure_configs::tests::screened_levels_for_named_configs`
> against the tuples actually in `secure_configs.rs` (Core-SVP model; these are
> an in-tree deterministic screen, not an independent lattice-security
> certificate — see CLAUDE.md for the caveat). The previous revision of this
> table (secure_128 129-bit / 116-bit MATZOV, secure_192 318-bit,
> secure_256 264-bit) cited `docs/LATTICE_ESTIMATOR_BASELINE_2026-02-25.md`,
> which CLAUDE.md flags as stale for exactly this table: that baseline's
> `secure_128` row was computed at `n=4096`, not the shipped `n=8192`, and its
> 192/256 rows use a floor-sum `log2(q)` approximation rather than the exact
> bit length the constructor gates on. `secure_128`'s figure below further
> reflects the 2026-08-26 re-cut (`docs/OPEN_WORK_2026-08-26.md` §A3): the
> constructor now builds the same four-prime chain as `secure_128_deep`,
> not the three-prime chain CLAUDE.md's own screening pass measured 259/233
> for. See `README.md`'s "Verified Capability" section for the currently
> synchronized numbers.

| Config | N | Claimed | Core-SVP (2026-08-22 screen) | Status |
|--------|---|---------|--------|--------|
| `light()` | 1024 | 80-bit | 36-bit (2026-01-24, not re-verified) | TEST ONLY (gated) |
| `he_standard_128()` | 2048 | 128-bit | 56-bit (2026-01-24, not re-verified) | TEST ONLY (gated) |
| `standard_128()` | 4096 | 128-bit | 96-bit (2026-01-24, not re-verified) | MARGINAL |
| `SecureConfig::secure_128()` | 8192 | 128-bit | 196-bit | MEETS (Core-SVP); 176-bit under MATZOV |
| `SecureConfig::secure_192()` | 16384 | 192-bit | 320-bit | EXCEEDS |
| `SecureConfig::secure_256()` | 16384 | 256-bit | 267-bit | MEETS (Core-SVP); 240-bit under MATZOV, 16 bits short of the 256-bit name |

---

## Data Flow

### Encryption Pipeline
```
plaintext → encode(Δ·m) → sample noise → pk·(a, -a·s+e) → ciphertext
```

### Homomorphic Multiplication
```
ct1 × ct2 → tensor product → RNS decomposition → K-Elimination rescale → ct_result
```

### K-Elimination Rescale
```
(c0_main, c0_anchor) → exact_divide(divisor) → (c0'_main, c0'_anchor)
```

---

## Thread Safety

| Type | Send | Sync | Notes |
|------|------|------|-------|
| `NTTEngine` | ✓ | ✓ | Immutable after construction |
| `ShadowHarvester` | ✓ | ✗ | Mutable state, use per-thread |
| `SecretKey` | ✓ | ✓ | Immutable, zeroized on drop |
| `RNSFHEContext` | ✓ | ✓ | Stateless operations |

---

## Build Configuration

### Features

| Feature | Default | Purpose |
|---------|---------|---------|
| `ntt_fft` | ✓ (legacy alias; the FFT path is now unconditionally active) | Use FFT-based NTT |
| `parallel` | ✗ (opt-in) | Rayon-based parallelism for MANA's legacy stream-level API (`ParallelStream`). MANA is the canonical accelerator, recommended over rayon; the production hot path (nine65 → UNHAL `Accelerator::run_lanes` → MANA `mana::executor`) uses a dependency-free, deterministic scoped-thread lane executor with bit-identical output regardless of thread count, and does not require or use this feature. |
| `accelerated` | ✓ (part of the default feature set) | Pulls in the `mana`/`unhal` crates for MANA/UNHAL acceleration |
| `serde` | ✗ | Serialization support |
| `allow_insecure` | ✗ | Enable insecure test configs |

### Recommended Production Build
```bash
cargo build --release -p nine65 --features serde
```

---

## Testing

### Test Categories

| Category | Command | Purpose |
|----------|---------|---------|
| Unit tests | `cargo test -p nine65 --lib` | Module correctness |
| Timing tests | `cargo test -- --ignored` | CT verification |
| Fuzz tests | `cargo +nightly fuzz run` | Edge cases |
| Coq proofs | `coqc proofs/coq/*.v` | Formal verification |

### Coverage
```bash
cargo tarpaulin -p nine65 --out Html
```

---

## Performance Targets

| Operation | Target | Typical |
|-----------|--------|---------|
| NTT (N=4096) | <500μs | ~200μs |
| Encrypt | <5ms | ~3ms |
| Decrypt | <2ms | ~1.5ms |
| Add | <100μs | ~50μs |
| Mul (RNS) | <20ms | ~15ms |
| K-Elimination | <1μs | ~500ns |

---

## External Dependencies

| Crate | Purpose | Version |
|-------|---------|---------|
| `zeroize` | Secure memory clearing | 1.7+ |
| `subtle` | Constant-time primitives | 2.5+ |
| `sha2` | Hashing for entropy | 0.10+ |
| `rayon` | Opt-in parallelism behind the `parallel` feature (off by default); not used by the production accelerator hot path — see `mana`/`unhal` below | 1.10+ |
| `getrandom` | OS CSPRNG | 0.2+ |
| `mana` / `unhal` | Canonical FHE accelerator pipeline (nine65 → UNHAL decides → MANA executes); MANA is a dependency-free, deterministic scoped-thread lane executor | workspace |

---

## Related Documents

- `../CLAUDE.md` - the current, maintained architecture and build reference; authoritative over this file wherever they disagree
- `SECURITY_GAP_ANALYSIS.md` - Security assessment and roadmap
- `RETIRED_MECHANISMS.md` - modulus switching and the noise budget/ladder, retired; authoritative on what NINE65 no longer implements
- `proofs/coq/` - legacy, unmaintained Coq exploration predating the move to Lean; not the verification basis (several files do not compile; several contain `Admitted`)
- `lean4/KElimination/` - Lean 4 formalization of record (`lake build`: 0 errors, 0 `sorry`)

---

*Full rewrite: 2026-01-24. Truth-pass spot corrections (accelerator description, parameter table, Coq/Lean status, unsourced depth/speedup figures): 2026-08-19 — see the staleness notice at the top of this file.*
