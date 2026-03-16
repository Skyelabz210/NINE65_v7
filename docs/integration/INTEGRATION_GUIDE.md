# Msnuslot Integration and Refactoring Guide

**Date:** March 16, 2026  
**Purpose:** Consolidate all components of the Msnuslot project into a cohesive, production-ready FHE engine with CRAM integration.  
**Status:** Phase 4 — Refining and Polishing the Codebase

---

## 1. Overview

The Msnuslot project encompasses multiple Rust crates and research documents spanning cryptographic primitives, fully homomorphic encryption (FHE), CRAM (Configurable Residue Arithmetic Machines), prime sieving, and formal verification. This guide provides a step-by-step roadmap for consolidating these components into a unified, well-integrated system.

### Key Achievements So Far

1. **Unified Math Utils Crate** (`math_utils`): A canonical implementation of core mathematical primitives including modular arithmetic, primality testing, Garner reconstruction, and K-Elimination. All tests pass (11/11).

2. **Comprehensive Analysis**: Identified 47 gaps across 7 categories (bugs, zero-float violations, security hardening, formal verification, performance, CRAM integration, infrastructure).

3. **Documentation**: Created detailed analysis reports and integration blueprints.

---

## 2. Consolidation Strategy

### Phase 2.1: Dependency Refactoring

**Objective:** Replace redundant implementations with unified `math_utils` dependency.

**Affected Crates:**
- `qmnf_primitives` (HackFate Alpha)
- `cram-core` (NINE65 v7)
- `hydra-sieve` (Hydra Sieve v3)

**Steps:**

1. **Add `math_utils` as a dependency** in each crate's `Cargo.toml`:
   ```toml
   [dependencies]
   math_utils = { path = "../math_utils" }
   ```

2. **Replace local implementations** with imports from `math_utils`:
   ```rust
   use math_utils::{addmod, submod, mulmod, mod_pow, gcd, mod_inverse, is_prime, garner_reconstruct, k_eliminate, k_reconstruct};
   ```

3. **Remove duplicate code** from each crate's `lib.rs`.

4. **Update tests** to verify that behavior remains identical after refactoring.

### Phase 2.2: Bug Fixes (Critical Path)

**Objective:** Resolve active bugs blocking system stability.

#### Bug A-1: SBNI Off-by-One Panic

**Location:** `nine65/ops/sbni.rs:84`  
**Issue:** `inject_dual_in_place` uses ciphertext limb count as index without bounds check.  
**Fix:**
```rust
// Before (BUGGY):
let out_limb = &mut self.ct.residues[self.ct.residues.len()];  // INDEX EQUALS LENGTH!

// After (FIXED):
if self.ct.residues.is_empty() {
    return Err("ciphertext has no residues".into());
}
let out_idx = self.ct.residues.len() - 1;  // Last valid index
let out_limb = &mut self.ct.residues[out_idx];
```

**Impact:** Fixes 11 test failures in public mode, mod-switching, and depth sweep tests.

#### Bug A-2: Integration Test Compile Errors

**Location:** `tests/full_system_exercise.rs`  
**Issue:** References to removed `FHEConfig::depth3_128_insecure()` constructors.  
**Fix:**
```rust
// Update all references to use the new config API:
// Old: let config = FHEConfig::depth3_128_insecure();
// New:
let config = FHEConfig::new_secure_128()
    .with_max_depth(3)
    .allow_insecure_for_testing();
```

**Impact:** Enables comprehensive integration testing of the full FHE system.

#### Bug A-3: Public Mode Depth Ceiling

**Location:** `ops/rns_fhe.rs`  
**Issue:** Coefficient `||∞-norm` exceeds decryption tolerance after 2 public multiplications.  
**Root Cause:** Relinearization noise + rescale insufficient for depth > 1.  
**Fix:** Implement automatic bootstrap triggering for public mode:
```rust
pub fn mul_public_with_auto_bootstrap(&mut self, a: &CramCiphertext, b: &CramCiphertext) -> Result<CramCiphertext> {
    let result = self.mul_public(a, b)?;
    if result.noise_mb > self.noise_threshold_mb {
        self.bootstrap_cram(&result)
    } else {
        Ok(result)
    }
}
```

**Impact:** Enables unlimited-depth public-key FHE via automatic bootstrap.

### Phase 2.3: Zero-Float Violations (Compliance)

**Objective:** Eliminate all floating-point operations to uphold the zero-float guarantee.

#### Fix B-1: `compiler.rs` f64 Usage

**Location:** `nine65/src/compiler.rs` (23 instances)  
**Conversion Strategy:** Replace `f64` noise analysis with integer millibit tracking.

```rust
// Before (BUGGY):
fn estimate_noise_bits(ops: &[Operation]) -> f64 {
    let mut noise = 0.0;
    for op in ops {
        match op {
            Operation::Add => noise += 0.5,
            Operation::Mul => noise += 2.0,
        }
    }
    noise
}

// After (FIXED):
fn estimate_noise_millibits(ops: &[Operation]) -> i64 {
    let mut noise_mb = 0i64;
    for op in ops {
        match op {
            Operation::Add => noise_mb += 500,      // 0.5 bits = 500 millibits
            Operation::Mul => noise_mb += 2000,     // 2.0 bits = 2000 millibits
        }
    }
    noise_mb
}
```

#### Fix B-2: `ct_verification.rs` f64 Usage

**Location:** `nine65/src/security/ct_verification.rs` (21 instances)  
**Conversion Strategy:** Replace statistical calculations with scaled-integer arithmetic.

```rust
// Before (BUGGY):
fn compute_mad(timings: &[f64]) -> f64 {
    let median = percentile(timings, 50.0);
    let deviations: Vec<f64> = timings.iter().map(|t| (t - median).abs()).collect();
    percentile(&deviations, 50.0)
}

// After (FIXED):
fn compute_mad_scaled(timings: &[i64]) -> i64 {
    // Scale: 1 nanosecond = 1000 scaled units
    let median = percentile_scaled(timings, 50);
    let deviations: Vec<i64> = timings.iter().map(|t| (t - median).abs()).collect();
    percentile_scaled(&deviations, 50)
}
```

#### Fix B-3: CRAM Prototype f64

**Location:** External `cram_fhe.rs` prototype  
**Issue:** `FHECiphertext.noise_bits: f64`  
**Fix:** Update to use `noise_mb: i64` (millibits):
```rust
pub struct FHECiphertext {
    pub residues: Vec<u64>,
    pub primes: Vec<u64>,
    pub noise_mb: i64,  // Changed from f64
    pub depth: usize,
}
```

### Phase 2.4: Security Hardening (Robustness)

**Objective:** Replace panics and unwraps with proper error handling.

#### Fix C-1: 217 `unwrap()` Calls

**Strategy:** Systematically replace with `?` operator or explicit error handling.

```rust
// Before (RISKY):
let inv = mod_inverse(a, m).unwrap();  // Panics if a and m not coprime

// After (SAFE):
let inv = mod_inverse(a, m)?;  // Propagates error up the call stack
```

**Scope:** Scan all non-test code with:
```bash
grep -r "\.unwrap()" nine65/src/ --include="*.rs" | grep -v "#\[test\]" | wc -l
```

#### Fix C-2: 3 `panic!()` in Production Paths

**Locations:**
- `params/primes.rs:193`
- `params/secure_configs.rs:370`
- `params/validation.rs:210`

**Fix Pattern:**
```rust
// Before (UNSAFE):
pub fn validate_params(params: &Params) {
    if !params.is_valid() {
        panic!("Invalid parameters");  // CRASH!
    }
}

// After (SAFE):
pub fn validate_params(params: &Params) -> Result<(), ParamError> {
    if !params.is_valid() {
        return Err(ParamError::InvalidConfiguration);
    }
    Ok(())
}
```

#### Fix C-3: AHOP Hardness Proof

**Objective:** Establish independent security proof for AHOP.  
**Action:** Commission external security analysis or publish reduction proof to known hard problem (e.g., Hidden Subgroup Problem on Apollonian groups).

#### Fix C-4: Entropy Claim Re-evaluation

**Objective:** Correct the 24-bit entropy claim (overstatement of ~1.6 bits).  
**Action:** Conduct empirical entropy analysis with NIST test suite and publish revised claim.

#### Fix C-5: FIPS 140-3 / NIST CAVP Submission

**Objective:** Enable regulated-industry deployment.  
**Action:** Plan multi-phase submission process starting with NIST validation of RNG and cryptographic primitives.

### Phase 2.5: Formal Verification (Trustworthiness)

**Objective:** Close gaps in formal verification coverage.

#### Fix D-1: Lean4 Parity with Coq

**Current State:** 4 Lean4 modules vs. 14 Coq modules.  
**Target:** Expand Lean4 to cover all 14 theorem families.  
**Effort:** ~2-3 weeks per module.

#### Fix D-2: CRAM Topology Correctness Proofs

**Critical Gap:** Zero formal verification of operator-distorted arithmetic.  
**Proof Target:** `CRAM_S6_correct: ∀ a b : ℤ, valid(a, b) → decrypt(cram_s6(encrypt(a), encrypt(b))) = cram_s6_output(a, b)`  
**Effort:** ~4 weeks (requires new Coq tactics for operator chains).

#### Fix D-3: DIV Lane Noise Reset Proof

**Critical Gap:** "Zero noise accumulation" claim is unverified.  
**Proof Target:** `noise_after_div_bootstrap(ct) ≤ noise_fresh_encryption`  
**Effort:** ~6 weeks (requires BFV noise theorem integration).

#### Fix D-4: Bootstrap Correctness Theorem

**Proof Target:** `bootstrap_roundtrip_correct: ∀ m, decrypt(bootstrap(encrypt(m))) = m`  
**Effort:** ~3 weeks.

### Phase 2.6: Performance Optimization (Scalability)

**Objective:** Improve performance for larger CRAM topologies.

#### Fix E-1: Garner O(k²) → O(k log²k)

**Location:** `clockwork-core/garner.rs`  
**Implementation:** Subproduct tree approach:
```rust
pub fn garner_reconstruct_fast(residues: &[u64], moduli: &[u64]) -> u128 {
    // Build subproduct tree: ∏_{i ∈ S} m_i for each subset S
    // Then use tree to compute CRT reconstruction in O(k log²k)
    // ... (implementation details)
}
```

**Benchmark:** Compare performance at k=4, 6, 8, 10.

#### Fix E-2: GPU/Accelerator Integration

**Objective:** Dispatch NTT butterfly and RNS lane operations to GPU.  
**Framework:** CUDA or OpenCL via `ort` or `burn` crate.  
**Effort:** ~8 weeks.

#### Fix E-3: Batched Ciphertext Operations

**Objective:** Optimize `ops/batch.rs` for SIMD-style processing.  
**Effort:** ~2 weeks.

#### Fix E-4: Depth-9000 Noise Anomaly

**Objective:** Investigate noise mean drift after ~200 sequential bootstraps.  
**Test:** Run 10,000 sequential bootstraps and measure actual vs. modeled noise.  
**Effort:** ~1 week.

### Phase 2.7: CRAM Integration (Completeness)

**Objective:** Fully integrate CRAM into the NINE65 ecosystem.

#### Fix F-1: Formalize `cram-core` as Workspace Crate

**Current State:** Standalone prototype files.  
**Action:** Move `cram-core` into the main workspace and update all references.

#### Fix F-2: CRAM Lane Semantics in `RNSFHEContext`

**Objective:** Adapt `DualRNSContext` for heterogeneous CRAM operators.  
**Implementation:**
```rust
pub struct CramRNSFHEContext {
    topology: CramTopology,
    // ... other fields
}

impl CramRNSFHEContext {
    pub fn mul_cram(&self, a: &CramCiphertext, b: &CramCiphertext) -> Result<CramCiphertext> {
        // Apply CRAM topology to each lane
        // ...
    }
}
```

#### Fix F-3: Topology Explorer Integration

**Objective:** Leverage `TopologyExplorer` for systematic optimization.  
**Action:** Integrate into a command-line tool for searching optimal topologies for given gap targets.

#### Fix F-4: Composite Anchor Support

**Objective:** Extend `clockwork-core/basis.rs` to handle composite anchors.  
**Effort:** ~2 weeks.

#### Fix F-5: CRAM-AHOP Integration

**Objective:** Integrate CRAM with AHOP for post-quantum geometric security.  
**Effort:** ~4 weeks.

#### Fix F-6: Exceptional Set Handling

**Objective:** Develop robust handling for the 7.7% of CRAM-S⁶ inputs that hit DIV lane zeros.  
**Strategy:** Re-randomization or fallback to alternative topology.  
**Effort:** ~1 week.

---

## 3. Workspace Structure (Target)

```
msnuslot/
├── unified_workspace/
│   ├── math_utils/              # Canonical math primitives (NEW)
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── cram-core/               # CRAM core (refactored to depend on math_utils)
│   ├── cram-fhe/                # CRAM-FHE (refactored for zero-float)
│   ├── hydra-sieve/             # Hydra Sieve (refactored to depend on math_utils)
│   ├── nine65-core/             # NINE65 v7 FHE engine (refactored)
│   ├── nine65-bootstrap/        # Bootstrap implementations
│   ├── nine65-security/         # Security hardening and verification
│   ├── nine65-tests/            # Comprehensive test suite
│   └── Cargo.toml               # Workspace root
├── analysis_report.md           # Comprehensive gap analysis
├── INTEGRATION_GUIDE.md          # This document
└── cram965/                     # Original NINE65 v7 (for reference)
```

---

## 4. Testing and Validation

### Phase 3.1: Unit Tests

All crates must pass their unit tests:
```bash
cd unified_workspace
cargo test --all --lib
```

### Phase 3.2: Integration Tests

Comprehensive integration tests covering:
- Encryption/decryption roundtrips
- Homomorphic operations (add, mul, sub)
- Bootstrap correctness
- CRAM topology execution
- Noise budget tracking

### Phase 3.3: Regression Tests

Ensure no regressions from the original implementations:
- Compare outputs with original `qmnf_primitives` implementations
- Validate against known test vectors

---

## 5. Documentation and Delivery

### Phase 4.1: API Documentation

Generate comprehensive rustdoc:
```bash
cargo doc --all --no-deps --open
```

### Phase 4.2: Architecture Documentation

Create detailed architecture guides covering:
- CRAM topology design and optimization
- FHE operations and noise budget
- Bootstrap mechanisms
- Security properties

### Phase 4.3: User Guide

Provide examples and tutorials for:
- Basic encryption/decryption
- Homomorphic operations
- CRAM topology selection
- Performance tuning

---

## 6. Timeline and Milestones

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| Phase 2.1: Dependency Refactoring | 1 week | All crates depend on `math_utils` |
| Phase 2.2: Bug Fixes (A-1, A-2, A-3) | 2 weeks | All critical bugs resolved |
| Phase 2.3: Zero-Float Compliance | 1.5 weeks | All f64 eliminated |
| Phase 2.4: Security Hardening | 2 weeks | All unwrap/panic replaced |
| Phase 2.5: Formal Verification | 8 weeks | D-1 through D-4 addressed |
| Phase 2.6: Performance Optimization | 6 weeks | E-1 through E-4 optimized |
| Phase 2.7: CRAM Integration | 4 weeks | F-1 through F-6 completed |
| Phase 3: Testing and Validation | 2 weeks | All tests pass, no regressions |
| Phase 4: Documentation and Delivery | 1 week | Complete documentation |
| **Total** | **~27 weeks** | **Production-ready FHE engine** |

---

## 7. Success Criteria

Upon completion of this integration guide, the Msnuslot project will achieve:

1. **Code Quality:** Single source of truth for all mathematical primitives; no redundancy.
2. **Stability:** All critical bugs fixed; system passes comprehensive test suite.
3. **Security:** Zero-float guarantee upheld; robust error handling throughout; security proofs established.
4. **Verification:** Formal proofs for critical theorems (CRAM correctness, DIV noise reset, bootstrap).
5. **Performance:** Optimized Garner reconstruction; GPU acceleration available; batched operations.
6. **Integration:** Full CRAM integration with heterogeneous lane semantics; exceptional set handling.
7. **Documentation:** Comprehensive API docs, architecture guides, and user tutorials.

---

## 8. Conclusion

This integration guide provides a clear roadmap for consolidating the Msnuslot project into a production-ready, fully integrated FHE engine with CRAM support. By systematically addressing the identified gaps and following the phases outlined above, the project will achieve a level of maturity, security, and performance suitable for real-world cryptographic applications.

The creation of the unified `math_utils` crate is the first critical step, successfully completed with all tests passing. The subsequent phases build upon this foundation, progressively refining and polishing the codebase until all components are seamlessly integrated and the system is ready for deployment.
