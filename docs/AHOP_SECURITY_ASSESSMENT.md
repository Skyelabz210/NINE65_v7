# AHOP (F_{p²} Quantum Simulation) Security Assessment

**Date**: January 2026
**Classification**: Security Research
**Status**: CRITICAL VULNERABILITIES IDENTIFIED

---

## Executive Summary

The AHOP (Axiomatic Holographic Operator-state Projection) implementation provides mathematically sound quantum simulation over F_{p²}, but contains **critical side-channel vulnerabilities** that render it unsuitable for cryptographic applications without significant hardening.

### Severity Summary

| Severity | Count | Description |
|----------|-------|-------------|
| **HIGH** | 3 | Timing leaks, probability measurement exposure |
| **MEDIUM** | 5 | Prime validation, cache timing, algebraic structure |
| **LOW** | 2 | Conditional branches, speculative execution |

---

## Critical Vulnerabilities

### 1. Timing-Based Oracle Leakage (HIGH)

**File**: `crates/nine65/src/ahop/grover.rs:37-39`

```rust
pub fn apply_oracle(&self, state: &mut StateVector) {
    state.amplitudes[self.target] = state.amplitudes[self.target].neg();
}
```

**Attack Vector**: Array indexing reveals target state via cache timing:
- L1 cache hit: ~4 cycles
- L3 cache hit: ~40 cycles
- Main memory: ~200+ cycles

**Impact**: Target index can be recovered through cache timing analysis.

**Mitigation**: Implement constant-time permutation or oblivious access.

---

### 2. Variable-Time Modular Inverse (HIGH)

**File**: `crates/nine65/src/ahop/mod.rs` (mod_pow function)

```rust
fn mod_pow(base: u64, exp: u64, m: u64) -> u64 {
    while exp > 0 {
        if exp & 1 == 1 {  // BRANCH LEAK
            result = (result * base) % m;
        }
        exp >>= 1;
        base = (base * base) % m;
    }
}
```

**Attack**: Binary exponentiation leaks exponent bits through:
- Hamming weight analysis
- Branch prediction timing
- Differential power analysis (hardware)

**Impact**: Called every Grover iteration - timing measurements accumulate.

**Mitigation**: Use Montgomery ladder or constant-time exponentiation.

---

### 3. Probability Measurement Leakage (HIGH)

**File**: `crates/nine65/src/ahop/mod.rs:279-283`

```rust
pub fn probability(&self, k: usize) -> f64 {
    let weight_k = self.amplitudes[k].norm_squared() as f64;
    let total = self.total_weight() as f64;
    weight_k / total
}
```

**Attack**: Probability peaks directly reveal target states:
```
target = argmax(P(k)) across all k
```

**Impact**: Algorithm design fundamentally exposes target through measurement.

**Mitigation**: Secure multi-party computation for target-hiding applications.

---

### 4. Weak Prime Validation (MEDIUM)

**Issue**: Only checks `p % 4 == 3`, not primality:

```rust
assert!(p % 4 == 3, "Prime must satisfy p ≡ 3 (mod 4)");
// Missing: is_prime(p) check
```

**Attack**: Composite p causes field operations to become non-deterministic.

**Mitigation**: Add mandatory primality test before F_{p²} construction.

---

### 5. Cache-Timing via Target List (MEDIUM)

**File**: `crates/nine65/src/ahop/grover_full.rs:414-424`

```rust
for &t in &self.targets {
    phases[t] = Fp2::new(self.p - 1, 0, self.p);  // Store leaks index
}
```

**Attack**: Cache line evictions during oracle construction reveal target count and indices.

**Mitigation**: Oblivious oracle construction with constant memory access pattern.

---

### 6. Hardcoded Primes (MEDIUM)

**Issue**: Primes reused across all sessions from constant arrays.

**Attack**: Timing measurements from one run apply to another.

**Mitigation**: Runtime prime generation per session.

---

## Vulnerability Summary Table

| Vulnerability | Type | Severity | File Location |
|---------------|------|----------|---------------|
| Oracle index access | Timing | HIGH | grover.rs:37-39 |
| Fermat's mod_pow | Timing | HIGH | mod.rs |
| Probability measurement | Information | HIGH | mod.rs:279-283 |
| Modular reduction | Timing | MEDIUM | mod.rs:111-115 |
| Conditional negation | Speculative | MEDIUM-LOW | mod.rs:69-76 |
| Extended GCD timing | Timing | MEDIUM | grover_full.rs:53-74 |
| Prime validation | Algorithmic | MEDIUM | grover_full.rs:400 |
| Cache-timing (oracle) | Timing | MEDIUM | grover_full.rs:414-424 |
| F_{p²} norm leak | Algebraic | MEDIUM | mod.rs |
| Hardcoded primes | Cryptanalytic | MEDIUM | params/primes.rs |

---

## Recommendations

### Immediate Actions (CRITICAL)

1. **Replace Fermat's Little Theorem with constant-time exponentiation**
2. **Validate all primes before F_{p²} construction** (is_prime + p ≡ 3 mod 4)
3. **Use constant-time oracle implementation** with oblivious memory access

### Medium-Term Actions (HIGH PRIORITY)

4. **Implement masked arithmetic for amplitudes**
5. **Deploy runtime prime generation**
6. **Add timing randomization (blinding)**

### Architectural Changes (LONG-TERM)

7. **Move to MPC for target-secret applications**
8. **Implement verifiable random functions for amplitudes**
9. **Consider ORAM + differential privacy for secure search**

---

## Security Rating

**Current Status**: UNSUITABLE FOR CRYPTOGRAPHIC USE WITHOUT MODIFICATION

**Suitable For**:
- Academic quantum algorithm simulation
- Mathematical correctness testing
- Educational demonstrations

**NOT Suitable For**:
- Cryptographic applications requiring secret targets
- Side-channel resistant search
- Adversarial environments with timing/power measurement capability

---

## Comparison to FHE Security

| Component | FHE (RNS) | AHOP | Assessment |
|-----------|-----------|------|------------|
| CPAD Resistance | PASS | N/A | FHE secure |
| Timing Side-Channels | PARTIAL | FAIL | AHOP needs hardening |
| Prime Validation | PASS | FAIL | AHOP needs validation |
| Noise Margin Exposure | PROTECTED | N/A | FHE private API |
| Target Secrecy | N/A | FAIL | AHOP leaks by design |

---

*Report generated by RedShirt Security Testing Framework*
*NINE65/MANA FHE Security Research*
