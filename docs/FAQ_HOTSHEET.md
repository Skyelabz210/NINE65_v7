# NINE65 FHE FAQ Hotsheet

**Quick Reference for NINE65**
*Last Updated: 2026-01-28. Depth/timing claims below are historical and
unreproduced in this pass — see the note under "Quick Facts."*

---

## What is NINE65?

**NINE65** is now a Rust BFV/DualRNS FHE system with real Clockwork bootstrap
(circular, KSK-separated, and auto-triggered paths) as well as a bootstrap-free
symmetric-mode path that clears many multiplicative levels without ever
bootstrapping (no ladder to run out of — see `docs/RETIRED_MECHANISMS.md`).
This document's original "bootstrap-free" framing described only the
symmetric-mode path and predates the Clockwork bootstrap integration; see
CLAUDE.md's "Bootstrap Paths" section for current status. It is built on the
QMNF integer-only architecture.

---

## Quick Facts

> **2026-08-19 note:** the depth and runtime figures below were not
> reproduced in this pass and are not in `docs/CLAIM_REGISTRY.csv`. For
> current, CI-asserted depth evidence, see
> `crates/nine65/tests/time_crystal_verification.rs::symmetric_depth_is_unbounded`
> (asserts a 128-level floor, `secure_128`, symmetric mul-by-fresh-operand, no
> bootstrap) and `depth_and_noise.rs::depth_and_noise_curve_deep_chain`
> (asserts a 32-level regression floor). For current timing baselines, see
> CLAUDE.md's "Performance Baselines" section.

| Question | Answer |
|----------|--------|
| **Max circuit depth?** | CI-asserted floor: 128 levels, symmetric mul-by-fresh-operand, `secure_128` (see note above). General ct×ct squaring chains are much shallower — see `docs/SYMMETRIC_BOOTSTRAP_ANALYSIS.md` and `crates/nine65/tests/time_crystal_verification.rs::public_relin_chain_depth_measured` for the measured (unasserted) public-mode number. |
| **Bootstrapping required?** | Not for the symmetric mul-by-fresh-operand path; Clockwork bootstrap exists for general ct×ct circuits — see CLAUDE.md. |
| **Depth-50 runtime?** | Historical figure (2026-01-28), not reproduced in this pass. See CLAUDE.md's "Performance Baselines" for current numbers. |
| **Post-quantum safe?** | Yes - LWE-based |
| **Hardware requirements?** | CPU only (~200MB RAM) |
| **Floating-point used?** | No f32/f64 in crypto/arithmetic hot paths (one documented non-cryptographic exception: `compiler.rs::NoiseModel`, a planning-only noise estimator — see CLAUDE.md's "Important Coding Rules"). |

---

## Core Components

### 1. K-Elimination (Exact Division in RNS)
- **Problem**: RNS cannot natively divide
- **Solution**: Dual-track architecture with anchor moduli
- **Result**: Exact rescaling without approximation errors
- **Complexity**: O(k) linear in RNS lanes

### 2. GSO-FHE (Gravitational Swarm Optimization)
- Noise bounding without bootstrapping
- Basin tracking per coefficient
- Zero bootstrap operations at depth-50

### 3. CRT Shadow Entropy
- Cryptographic entropy from modular arithmetic
- QuotientSignature: O(1) magnitude comparison
- 8.9M ops/sec, 284 Mbit/s entropy rate

### 4. Non-Circular Order Finding
- Classical period finding without circular dependencies
- BSGS with B=N-1 (no phi(N) needed)
- Complete Shor's classical reduction

---

## Tarball Contents (Flash Drive)

| File | Description |
|------|-------------|
| `nine65-v5-throughput-complete.tar.gz` | Full v5 release with all crates |
| `nine65_mana_with_proofs_20260119.tar.gz` | MANA-boosted FHE with Coq proofs |
| `04_QClassic_quantum_complete.tar.gz` | QClassic quantum-complete variant |
| `all_formal_proofs_20260128.tar.gz` | All Coq + Lean4 formal proofs |

---

## Formal Proofs Included

### Coq Proofs (.v)
| Component | File | Status |
|------------|------|--------|
| K-Elimination | `KElimination.v` | Verified |
| GSO-FHE | `GSOFHE.v` | Verified |
| MQ-ReLU | `MQReLU.v` | Verified |
| Order Finding | `OrderFinding.v` | Verified |
| CRT Shadow Entropy | `CRTShadowEntropy.v` | Verified |
| Cyclotomic Phase | `CyclotomicPhase.v` | Verified |
| Integer Softmax | `IntegerSoftmax.v` | Verified |
| State Compression | `StateCompression.v` | Verified |
| Mobius Int | `MobiusInt.v` | Verified |
| Montgomery Persistent | `MontgomeryPersistent.v` | Verified |
| Pade Engine | `PadeEngine.v` | Verified |
| Exact Coefficient | `ExactCoefficient.v` | Verified |
| Encrypted Quantum | `EncryptedQuantum.v` | Verified |
| Side Channel Resistance | `SideChannelResistance.v` | Verified |

### Lean4 Proofs (.lean)
- In v5 repo: KElimination (main + Basic, ShadowEntropy, ZMod submodules) — 4 files
- Full ecosystem (hackfate.us proofs repo): 28 core + 14 NIST = 42 Lean4 proof files

---

## Security Parameters

> **Historical (2026-01-28), not the shipped tuples.** Every row below predates
> the N=4096→8192 resize and the `secure_256` chain replacement recorded in
> CLAUDE.md; `secure_128`'s `n=4096` and `secure_192`'s `n=8192` do not match
> any current constructor (`secure_128`/`secure_128_deep` are `n=8192`,
> `secure_192`/`secure_256` are `n=16384`). For the current tuples and
> screened bits, see CLAUDE.md's "Security Configs" table — noting that even
> that table's `secure_128` row is itself pending a 2026-08-26 re-cut sync;
> `README.md`'s "Verified Capability" section has the corrected numbers.

| Config | n | log2(q) | Security (log2 rop) |
|--------|---|---------|---------------------|
| `secure_128` | 4096 | 89.26 | 123.6 bits |
| `secure_192` | 8192 | 145.39 | 165.6 bits |
| `secure_256` | 16384 | 203.81 | 268.1 bits |

---

## Performance Benchmarks

### FHE Operations (secure_128)

> Historical (2026-01-28), measured on the `n=4096` tuple above — not
> comparable to the current `secure_128`. See CLAUDE.md's "Performance
> Baselines" for current timings.

| Operation | Time |
|-----------|------|
| Encrypt | 23.93 ms |
| Add | 0.91 ms |
| Multiply | 125.01 ms |
| Decrypt | 11.17 ms |

### RNS Arithmetic (4-lane)
| Operation | Throughput |
|-----------|------------|
| ADD | 15.2M ops/sec |
| MUL | 10.5M ops/sec |
| DIV (K-Elim) | 18.7M ops/sec |

---

## Quick Build

```bash
# Build release
cargo build --release --workspace

# Run tests
cargo test --workspace --release

# Depth benchmark
cargo test --package nine65 --lib --release \
  ops::gso_fhe::depth_benchmarks::benchmark_max_depth -- --nocapture
```

---

## Comparison vs Industry

| Library | Max Depth | Bootstrap | Depth-50 Time |
|---------|-----------|-----------|---------------|
| **NINE65** | **50+** | **Never** | **6.15s** |
| OpenFHE (BGV) | 15 | ~50ms | ~2,500ms |
| Microsoft SEAL | 12 | N/A | Limited |
| TFHE-rs (GPU) | Unlimited | <1ms | ~200ms* |
| HElib | 12 | ~100ms | ~5,000ms |

*Requires $30k+ H100 GPU

---

## Key Files

| Purpose | Location |
|---------|----------|
| Core FHE | `crates/nine65/src/ops/` |
| K-Elimination | `crates/nine65/src/arithmetic/exact_divider.rs` |
| GSO Noise | `crates/nine65/src/ops/gso_fhe.rs` |
| RNS Engine | `crates/nine65/src/arithmetic/rns.rs` |
| Entropy | `crates/nine65/src/entropy/` |
| Proofs | `proofs/coq/`, `lean4/` |

---

## Common Questions

**Q: Why no bootstrapping?**
A: K-Elimination enables exact rescaling in RNS, eliminating noise accumulation that traditionally requires bootstrapping.

**Q: Is this post-quantum secure?**
A: Yes. LWE-based security with no known quantum speedup. Parameters exceed NIST PQC thresholds.

**Q: Can I run this on my laptop?**
A: Yes. CPU-only, ~200MB RAM. No GPU required.

**Q: What's the catch?**
A: Public-key mode is depth-limited (~4-5 levels). Deep circuits require symmetric mode.

**Q: How do I verify the proofs?**
A: Install Coq 8.18+ or Lean4, then compile the proof files in `proofs/`.

---

## Repository

- **GitHub**: https://github.com/Skyelabz210/NINE65-v5
- **Branch**: `feat/comprehensive-security-hardening-v2`
- **License**: Proprietary

---

## Contact

For technical questions or licensing inquiries, see the repository issues.

---

*NINE65 - Bootstrap-Free FHE with K-Elimination*
*Built on QMNF Integer-Only Architecture*
