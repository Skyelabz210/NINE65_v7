# NINE65 Architecture

**Version**: 5.0
**Status**: Pre-production (deployment not recommended yet)
**Security Rating**: Provisional (see RedShirt assessment)

---

## Overview

NINE65 is a bootstrap-free Fully Homomorphic Encryption (FHE) library built on the BFV scheme with novel components including K-Elimination for exact RNS division and GSO-FHE for gravitational swarm noise optimization.

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

**Coq Proof**: `proofs/coq/KElimination.v`

### 2. GSO-FHE Component
**Location**: `ops/gso_fhe.rs`

Gravitational Swarm Optimization for noise management without bootstrapping.

- Adaptive noise collapse at configurable thresholds
- Depth-50+ circuits without bootstrap overhead
- 400x speedup for deep circuits

**Coq Proof**: `proofs/coq/GSOFHE.v`

### 3. Persistent Montgomery Component
**Location**: `arithmetic/montgomery.rs`

Keep values in Montgomery form across operations:
- 3n conversions vs 2 per operation
- 50-100x speedup for operation chains

**Coq Proof**: `proofs/coq/MontgomeryPersistent.v`

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

| Config | N | Claimed | Actual | Status |
|--------|---|---------|--------|--------|
| `light_insecure()` | 1024 | 80-bit | 36-bit | TEST ONLY (gated) |
| `he_standard_128_insecure()` | 2048 | 128-bit | 56-bit | TEST ONLY (gated) |
| `standard_128()` | 4096 | 128-bit | 96-bit | MARGINAL |
| `SecureConfig::secure_128()` | 4096 | 128-bit | 128-bit | MARGINAL (not recommended) |
| `SecureConfig::secure_192()` | 8192 | 192-bit | 176-bit | RECOMMENDED |
| `SecureConfig::secure_256()` | 16384 | 256-bit | 268-bit | MAXIMUM |

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
| `ntt_fft` | ✓ | Use FFT-based NTT |
| `parallel` | ✓ | Enable Rayon parallelism |
| `accelerated` | ✓ | MANA/UNHAL acceleration |
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
| `rayon` | Parallelism | 1.10+ |
| `getrandom` | OS CSPRNG | 0.2+ |

---

## Related Documents

- `SECURITY_GAP_ANALYSIS.md` - Security assessment and roadmap
- `proofs/coq/` - Formal Coq proofs for all components
- `lean4/KElimination/` - Lean 4 proofs

---

*Last updated: 2026-01-24*
