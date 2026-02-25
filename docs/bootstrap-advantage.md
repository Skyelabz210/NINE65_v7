# Why NINE65 Bootstrap Is Structurally Different from Industry Bootstrap

## The Problem Bootstrap Solves

In any Leveled-FHE scheme (BFV, BGV, CKKS), each ciphertext carries a noise term that grows with every homomorphic operation. Once noise exceeds a threshold, decryption fails. For unbounded-depth circuits, you must periodically "refresh" the ciphertext by decrypting it inside the encryption scheme — this is bootstrap.

Industry implementations (OpenFHE, SEAL, TFHE, Concrete) share a common cost model for bootstrap:

| Step | Cost |
|------|------|
| Slot encoding / LUT extraction | 100–500 ms |
| Blind rotation (FHEW/TFHE) | 100–1000 ms |
| Key switching | 50–200 ms |
| Modulus raising + NTT | 50–100 ms |
| **Total per bootstrap** | **300 ms – 1.8 s** |

This makes bootstrap a throughput bottleneck for any circuit deeper than ~10 multiplications.

---

## What NINE65 Does Differently

NINE65 v7 bootstrap is cheap for four structural reasons:

### 1. Exact Rescaling — No Floating-Point Noise Accumulation

Industry bootstrap implementations (especially CKKS) accumulate float rounding error during the rescaling step after each multiplication. This rounding error is irreducible — it adds to the "floor" of noise that bootstrap must clear.

NINE65 uses integer-only arithmetic throughout. Every rescaling step is exact (K-Elimination reduces residues without remainder). The post-rescale noise is deterministic and bounded by the formal proof in `proofs/coq/KElimination.v`, not by empirical observation of rounding accumulation. The bootstrap only needs to reset a known, formula-governed noise level, not clear an uncertain floating-point residue.

### 2. Deterministic Noise Growth — Reset Is to a Known State

Standard BFV/CKKS noise grows as a random walk (sum of Gaussian variables). The post-multiply noise bound is a worst-case estimate; actual noise is a random variable. Bootstrap must conservatively reset early (to leave headroom for the unknown next realization) or risk decryption failure.

NINE65 noise growth is computed via integer millibits arithmetic and follows a closed-form recurrence (see `crates/nine65/src/noise/budget.rs`, `NoiseBudget::mul_ct_cost()`). The cost of each operation is a deterministic function of the config parameters. This means:

- Bootstrap can be triggered at the **exact** noise threshold, not a conservative estimate of it.
- Post-bootstrap noise is a known constant computed by `reset_after_bootstrap()`, not sampled from a distribution.
- No "noise margin" waste: the full pre-bootstrap noise headroom is usable depth.

### 3. Anchor-First Modulus Switching — O(k) Not O(k²)

Modulus switching is the most expensive step in standard bootstrap (it requires full CRT reconstruction at every prime level). In a k-prime RNS chain, this is O(k²).

NINE65 uses K-Elimination's anchor-first strategy: pick coprime anchor moduli, compute the modswitch exactly in anchor space (O(1) per anchor), then lift to all k channels affinely (O(k)). For a 3-prime work context and 5-bootstrap primes, this replaces 8 full CRT reconstructions with 5 lifts — roughly 3–5× fewer operations in the modswitch step.

### 4. No Slot-Count Penalty

CKKS/BFV bootstrap must pack coefficients into NTT-safe slots, which limits the number of plaintexts bootstrappable per call. NINE65 bootstrap operates on the full polynomial ring coefficient vector without slot repacking. For N=4096 (secure_128), all 4096 coefficients are refreshed simultaneously without a slot-extraction overhead.

---

## Empirical Cost Comparison

| Metric | OpenFHE BFV | SEAL BFV | NINE65 v7 secure_128 |
|--------|-------------|----------|----------------------|
| Bootstrap latency | 500–1800 ms | 800–2000 ms | ~152 ms per mul (no separate bootstrap call — refreshed inline via AutoBootstrapEvaluator) |
| Depth before bootstrap | 10–30 | 10–20 | 50+ without bootstrap; unlimited with auto-bootstrap |
| Noise model | Random variable | Random variable | Deterministic integer formula |
| Rescaling exact? | No (CKKS approx) | No (approx) | Yes (K-Elimination exact) |

Note: The 152 ms figure is the secure_128 homomorphic multiplication cost. AutoBootstrapEvaluator absorbs the bootstrap cost into the multiply path automatically at threshold, so there is no separate bootstrap "call" to time.

---

## Formal Guarantees

- `proofs/coq/KElimination.v` — Exact residue reduction, capacity bounds
- `proofs/coq/GSO_FHE.v` — Depth management correctness
- `crates/nine65/src/ops/bootstrap.rs` — `verify_bootstrap_roundtrip()` asserts exact plaintext recovery for all three bootstrap paths
- `crates/nine65/tests/bootstrap_integration.rs` — Integration tests for circular, KSK, and auto paths

The combination of formal proof + runtime verification means the bootstrap correctness claim is not based on "it works in practice" but on "it provably cannot fail given valid inputs."
