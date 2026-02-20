# NINE65 Security Proofs

**Version**: Post-December 2025 Refactor
**Last Updated**: December 29, 2025
**Status**: Work in Progress

---

## 1. Architecture Overview

NINE65 provides TWO security modes:

| Mode | API | Security Model | Circuit Depth |
|------|-----|----------------|---------------|
| **Symmetric** | `mul_dual_symmetric(ct1, ct2, sk)` | Single-party (holder of sk) | Deep (50+ muls tested) |
| **Public** | `mul_dual_public(ct1, ct2, evk)` | Multi-party IND-CPA | Shallow by default; deeper with smaller decomposition base (public_deep/with_base) |

### Key Insight
The symmetric mode achieves deep circuits because it uses `s²` directly for relinearization,
adding ZERO relinearization noise. This is not a bug - it's a feature for single-party
computation where the same entity encrypts, computes, and decrypts.

The public mode uses standard BFV-style evaluation keys, which add noise per operation.

---

## 2. Encryption Security (Both Modes)

### 2.1 RLWE-Based Key Generation

**Secret Key**: `s ← {-1, 0, 1}^N` (ternary distribution)

**Public Key**:
```
a ← R_q (uniform random)
e ← CBD(η) (centered binomial distribution)
pk = (pk0, pk1) = (-a·s - e, a)
```

**Security Claim**: The public key is computationally indistinguishable from uniform
random under the Ring-LWE assumption with parameters (N, q, χ).

**Proof Sketch**:
1. The pair (a, a·s + e) is RLWE sample with secret s and error e
2. By RLWE hardness, this is indistinguishable from (a, u) where u is uniform
3. Therefore (a, -a·s - e) is indistinguishable from (a, -u)
4. The public key reveals no information about s

### 2.2 Encryption

**Encryption of message m**:
```
u ← {-1, 0, 1}^N
e1, e2 ← CBD(η)
c0 = pk0·u + e1 + m·Δ
c1 = pk1·u + e2
```

**Security Claim**: Fresh ciphertexts are IND-CPA secure under RLWE.

**Proof Sketch**:
1. Decryption: c0 + c1·s = (pk0·u + e1 + m·Δ) + (pk1·u + e2)·s
                        = (-a·s - e)·u + e1 + m·Δ + a·u·s + e2·s
                        = m·Δ + noise (where noise = -e·u + e1 + e2·s)
2. The ciphertext (c0, c1) is computationally indistinguishable from uniform
   under RLWE, as it's constructed from RLWE samples plus message encoding

---

## 3. K-Elimination Security Analysis

### 3.1 What K-Elimination Does

K-Elimination provides exact integer reconstruction from dual RNS representation:

```
Given: v_main (mod M), v_anchor (mod A) where gcd(M, A) = 1
Compute: k = (v_anchor - v_main) · M^{-1} (mod A)
Reconstruct: V_exact = v_main + k · M
```

### 3.2 Security Claim

**Claim**: K-Elimination does NOT weaken RLWE security.

**Justification**:
1. K-Elimination operates on ciphertext coefficients, not plaintexts
2. The anchor residues are deterministic functions of main residues
3. No secret key material is used in K-Elimination
4. The reconstruction is a mathematical identity, not a cryptographic operation

### 3.3 What K-Elimination is NOT

K-Elimination is NOT:
- A noise reduction technique (it doesn't reduce RLWE noise)
- A bootstrapping alternative (it doesn't refresh noise budget)
- A security mechanism (it's a correctness mechanism)

K-Elimination enables:
- Exact rescaling (no floating-point rounding errors)
- Deterministic computation (reproducible results)
- Deep circuits in symmetric mode (by avoiding rescaling noise)

---

## 4. Symmetric Mode Security

### 4.1 Security Model

**Assumption**: Single party holds all keys (sk, pk, evk not used)

**Threat Model**:
- Adversary can observe ciphertexts
- Adversary cannot access secret key or computation intermediates
- No multi-party computation

### 4.2 Relinearization

```rust
// Symmetric relinearization (uses sk directly)
s² = s · s
c0' = e0 + e2 · s²
c1' = e1
```

**Security**: Same as fresh encryption - the result is a valid RLWE ciphertext.

**Noise**: ZERO additional noise from relinearization (exact s² computation).

### 4.3 Why This Works for Deep Circuits

In standard FHE with eval keys, each relinearization adds noise:
```
noise_relin ≈ N · B · σ²  (where B = decomposition base)
```

In symmetric mode:
```
noise_relin = 0  (exact s² computation)
```

This is why symmetric mode achieves 50+ multiplication depth while public mode
is limited to shallow circuits without larger parameters.

---

## 5. Public Mode Security

### 5.1 Security Model

**Standard FHE Model**:
- Key holder generates (sk, pk, evk)
- Key holder distributes (pk, evk) to computing party
- Computing party can encrypt and compute
- Only key holder can decrypt

### 5.2 Evaluation Key Generation

```
For i = 0 to num_digits:
    a_i ← R_q
    e_i ← CBD(η)
    power_i = base^i
    rlk0_i = -a_i·s - e_i + power_i · s²
    rlk1_i = a_i
```

**Security Claim**: Evaluation keys are IND-CPA secure under RLWE.

**Proof Sketch**:
1. Each rlk component is an RLWE encryption of power_i · s²
2. The RLWE samples hide s² from the computing party
3. Computing party can use evk to relinearize but cannot extract s²

### 5.3 Public Relinearization

```rust
// Public relinearization (uses evk, NOT sk)
for i in 0..num_digits:
    digit_i = extract_digit(e2, i, base)
    c0 += digit_i · rlk0_i
    c1 += digit_i · rlk1_i
```

**Correctness**:
```
sum_i(digit_i · rlk0_i) + s · sum_i(digit_i · rlk1_i)
≈ sum_i(digit_i · power_i · s²) + noise
= e2 · s² + noise
```

**Noise Growth**:
```
noise_relin ≈ num_digits · N · base · σ²
```

This noise accumulates with each multiplication, limiting circuit depth.

---

## 6. Parameters and Security Levels

### 6.1 Current Parameters (light_rns_exact)

```
N = 1024
Primes: [998244353, 985661441] (≈60-bit Q)
t = 65537
η = 3 (CBD parameter)
```

### 6.2 Security Estimate

Using the LWE estimator formula (rough):
```
security_bits ≈ N / log2(q) · constant
             ≈ 1024 / 60 · 10
             ≈ 170 bits (rough estimate)
```

**For precise estimates, use the Lattice Estimator.**

### 6.3 HE Standard Compliance

| N | Max log2(q) for 128-bit | Our log2(q) | Status |
|---|-------------------------|-------------|--------|
| 1024 | 27 | ~60 | EXCEEDS (use N≥2048 for 128-bit claims) |
| 2048 | 54 | ~60 | COMPLIANT |
| 4096 | 109 | ~60 | COMPLIANT |

---

## 7. Centered Representative Invariant

### 7.1 The Fix (December 2025)

**Problem**: When crossing between main and anchor RNS systems, values could
be interpreted differently (positive vs negative representation).

**Solution**: Center values around Q/2 before conversion:
```rust
let v_centered = if v > q_half { v - q } else { v };
```

### 7.2 Security Implication

**None** - this is a correctness fix, not a security change. The centered
representative is a deterministic function of the residues and does not
leak any additional information.

---

## 8. Formal Verification Requirements

For production deployment, the following proofs should be formalized:

### 8.1 Required (Informal Proofs Complete)

1. **RLWE Reduction**: Breaking NINE65 ⟹ Solving RLWE(N, q, χ)
2. **K-Elimination Soundness**: Exact reconstruction for V < M × A
3. **Evaluation Key Security**: evk does not leak s²
4. **Lean 4 formalization of K-Elimination**: completed (lean4/KElimination)

### 8.2 Recommended (Future Work)

1. Independent security audit
2. NIST-style known answer tests

---

## 9. Known Limitations

### 9.1 Public Mode Circuit Depth

Depth-1 circuits are reliable across configs; depth > 1 depends on parameters and
decomposition base. Baseline measurements show depth 4-5 for standard_128/high_192
with smaller bases; light_rns_exact depth-2 still fails (see docs/PUBLIC_MODE_DEPTH_BASELINE_2026-01-27.md).

**Root Cause Analysis (December 2025, Updated December 30)**:

Public mode uses BFV-style relinearization with evaluation keys. The depth-2 failure
mechanism was investigated in detail and involves the interaction between K-Elimination
and accumulated tensor product noise.

**Detailed Trace (light_rns_exact parameters)**:

| Stage | K value (coeff 0) | Phase error | Status |
|-------|-------------------|-------------|--------|
| Depth-1 (ct_6) | k ≈ 10^9 (small) | ~10^12 | ✓ OK |
| Depth-1 (ct_20) | k ≈ 10^9 (small) | ~10^12 | ✓ OK |
| Depth-2 tensor (d0, d1, d2) | k ≈ 10^9 to 10^28 | ~10^17 | Tensor scale Δ² |
| Depth-2 post-relin | k ≈ 10^28 (for some terms) | ~10^17 | Still OK at Δ² scale |
| Depth-2 post-rescale | — | ~10^13 to 10^15 | EXCEEDS Δ/2 |

**Why K Values Become Large (k ≈ A)**:

After depth-1 rescale, c1 coefficients can represent small negative noise values. In the
K-Elimination representation, negative values require k ≈ A - ε where ε is small:

```
For coefficient c = -|c| where |c| < M:
  v_main = M - |c| (positive representation)
  v_anchor = a_i - (|c| mod a_i)
  k_i = ((v_anchor - v_main mod a_i) × M⁻¹) mod a_i ≈ a_i - 1

Via CRT: k ≈ A - 1 (for small |c|)
```

When depth-1 outputs enter depth-2 tensor products, the multiplied c1 coefficients produce
tensor values with k values proportional to the product of input k values, giving k ≈ A.

**Why Rescale Fails with Large k**:

The rescale formula uses k mod Δ trick:
```
round((v_m + k×M) / Δ) ≡ round((v_m + (k mod Δ)×M) / Δ) (mod M)
```

For k ≈ A with SignedK interpretation:
- k_signed.magnitude = A - k ≈ ε (small, but can be ~10^8)
- k_contrib = ε × M ≈ 10^8 × 10^18 = 10^26
- scaled k_contrib = 10^26 / Δ ≈ 10^26 / 10^13 = 10^13

This k contribution (10^13) **exceeds the threshold Δ/2 ≈ 7.5×10^12**.

**Key Finding**: The K-Elimination is working correctly. The large k values accurately
represent tensor product coefficients that have accumulated noise from depth-1 operations.
The issue is that this accumulated noise exceeds the decryption threshold for depth-2.

**Measured Behavior**:

| Metric | Depth-1 | Depth-2 |
|--------|---------|---------|
| Symmetric result | 6 ✓ | 120 ✓ |
| Public result | 6 ✓ | 18-412 (varies with seed) |
| Public phase error | ~10^12 (within Δ/2) | ~10^13 to 10^15 (exceeds Δ/2) |
| K-Elimination invariant | Maintained ✓ | Maintained ✓ |

**Solutions for Deeper Public Mode**:
1. **Modulus switching**: Drop primes after each multiplication to reduce noise relative to Q
2. **Larger parameters**: Use N=4096 with more primes for larger noise budget
3. **Bootstrapping**: Refresh ciphertext noise periodically
4. **Use symmetric mode**: For single-party computation (works to 50+ depth)

### 9.2 Key Zeroization

**CRITICAL**: Secret keys (RNSSecretKey, DualRNSSecretKey) are zeroized on drop via `zeroize` (derive-based).
```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DualRNSSecretKey {
    pub s: DualRNSPoly,
}
```

### 9.3 Randomness Quality

Shadow Entropy is acceptable for error sampling but OS CSPRNG
should be used for key generation in production.

---

## 10. Summary

| Claim | Status | Notes |
|-------|--------|-------|
| Encryption is IND-CPA under RLWE | Proven (informal) | Standard RLWE argument |
| K-Elimination doesn't weaken security | Justified | Operates on ciphertexts only |
| Symmetric mode: deep circuits | Verified (50+ muls) | Zero relinearization noise |
| Public mode: depth-1 reliable | Verified | Standard BFV relinearization |
| Public mode: depth 4-5 baseline | Measured | standard_128/high_192 (see baseline doc) |
| Public mode: deep circuits | NOT YET | Needs larger params or bootstrapping |

**Bottom Line**: NINE65 provides standard RLWE security with an innovative
K-Elimination exact rescaling mechanism. The symmetric mode enables deep
circuits for single-party computation; the public mode provides standard
FHE security for multi-party scenarios.
