# TODO - NINE65 v5 Gap Analysis Action Items

**Last Updated**: 2026-01-26
**Analysis Sources**: Frontier Validation Architect, RedTeam Analyst, RedShirt Cryptanalysis

---

## P0 - CRITICAL (Production Blockers)

### CRITICAL-001: Fix u64 Truncation in Encoding ✅ FIXED
- [x] **File**: `crates/nine65/src/ops/rns_fhe.rs:1620`
- [x] **Status**: Already fixed - `to_main_rns_u128()` and `to_anchor_rns_u128()` methods compute residues directly from u128
- [x] **Verified**: 2026-01-25

### CRITICAL-002: Fix/Deprecate PRODUCTION_PRIMES_60BIT ✅ FIXED
- [x] **File**: `crates/nine65/src/params/production.rs:9-33`
- [x] **Status**: Added `#[deprecated]` attribute with clear warning
- [x] **Added**: `VERIFIED_PRIMES_51BIT` array with 5 validated primes
- [x] **Verified**: 2026-01-25

---

## P1 - HIGH Priority (1-2 Weeks)

### HIGH-001: Add Anchor Capacity Validation ✅ FIXED
- [x] **File**: `crates/nine65/src/arithmetic/rns.rs:628-734`
- [x] **Status**: Added assertion in `extract_k_rns_level()` that 4+ main primes require 4+ anchor primes
- [x] **Verified**: 2026-01-25

### HIGH-002: Add Edge Case Tests ✅ FIXED
- [x] **Test**: Large k values (80+ bits) for 4-prime CRT
- [x] **Test**: Signed-k boundary (A/2 ± 1)
- [x] **Test**: Anchor capacity insufficient assertion
- [x] **Test**: u128 overflow boundary in CRT reconstruction
- [x] **Verified**: 2026-01-25

### HIGH-003: Integrate Noise Budget into FHE Operations ✅ FIXED
- [x] **File**: `crates/nine65/src/ops/rns_fhe.rs`
- [x] Added `mul_dual_public_tracked()` with noise budget tracking
- [x] Added `mul_dual_public_deep_tracked()` with modulus switch
- [x] Added `add_dual_tracked()` for tracked addition
- [x] Added `rescale_cost()` and `multiplication_cycle_cost()` to NoiseBudget
- [x] **Verified**: 2026-01-25

### HIGH-004: Extend Coq Proofs for 4-Prime CRT ✅ FIXED
- [x] **File**: `proofs/coq/KElimination.v`
- [x] Proved `k_elimination_4prime_sound` theorem (via CRT uniqueness)
- [x] Proved `signed_k_positive` and `signed_k_negative` (SignedK interpretation)
- [x] Proved `m_level_inv_exists` and `k_elimination_level_sound` (level-aware M⁻¹)
- [x] Added `incremental_crt_step` for 4-prime reconstruction
- [x] **Verified**: 2026-01-26

### HIGH-SEC: Convert Security Estimator to Integer Arithmetic ✅ FIXED
- [x] **File**: `crates/nine65/src/params/security_estimator.rs`
- [x] Removed `use std::f64::consts::PI` and all f64 operations
- [x] Converted to millibits precision (1000 = 1 bit)
- [x] Changed `bkz_iterations` from f64 to u64
- [x] Changed `SecretDistribution::Gaussian(f64)` to `Gaussian(u32)` (milliunits)
- [x] All calculations now use integer arithmetic
- [x] **Verified**: 2026-01-26

---

## P2 - MEDIUM Priority (1 Month)

### MEDIUM-001: Replace Saturation with Checked Arithmetic ✅ FIXED
- [x] **File**: `crates/nine65/src/arithmetic/rns.rs`
- [x] Replaced `saturating_mul` with `checked_mul` + panic in:
  - Line 128: `to_int_partial()` CRT reconstruction
  - Line 647: `extract_k_rns_level()` M_level product
  - Line 724: 4-prime CRT reconstruction
- [x] **Verified**: 2026-01-26

### MEDIUM-002: Replace Production unwrap() Calls ✅ N/A
- [x] **Status**: All unwrap() calls are in test code (after `#[cfg(test)]`)
- [x] Production code has zero unwrap() calls
- [x] **Verified**: 2026-01-26

### MEDIUM-003: Add Missing light_rns_exact Warnings ✅ FIXED
- [x] **File**: `crates/nine65/src/params/mod.rs:224`
- [x] Added `#[deprecated(since = "5.0.0", note = "INSECURE: ~80-bit security")]`
- [x] **Verified**: 2026-01-26

### MEDIUM-004: Improve Noise Budget Precision ✅ VALIDATED
- [x] **File**: `crates/nine65/src/noise/budget.rs`
- [x] Analysis: Millibits (1000/bit) is sufficient for all practical circuits
  - Depth 100: max cumulative error = 50 millibits = 0.05 bits (0.14% relative)
  - Microbits would add overhead with negligible benefit
- [x] Added precision analysis documentation to module
- [x] Added `test_deep_circuit_precision` validation test
- [x] **Verified**: 2026-01-26

### MEDIUM-005: Complete SideChannelResistance.v Proofs ✅ FIXED
- [x] **File**: `proofs/coq/SideChannelResistance.v`
- [x] Added Barrett reduction constant-time proof (6 operations)
- [x] Added modulus switch rounding constant-time proof (3 operations/coeff)
- [x] Updated SideChannelSecure record with barrett_ct and modswitch_ct
- [x] Compiles axiom-free: "Closed under the global context"
- [x] **Verified**: 2026-01-26

### MEDIUM-006: Add Anchor Prime N-Compatibility Check ✅ FIXED
- [x] **File**: `crates/nine65/src/arithmetic/rns.rs:402`
- [x] Added assertion: `(p-1) % 2n == 0` for NTT compatibility
- [x] **Verified**: 2026-01-26

---

## Known Limitations (Tests Ignored)

- [ ] Public-mode deep diagnostics/slow sweeps (4 ignored unit tests; keep ignored unless explicitly requested)
  - rns_fhe::test_mul_dual_public_mode_deep
  - rns_fhe::test_public_mode_depth_sweep
  - rns_fhe::test_mul_dual_debug (verbose)
  - rns_fhe::test_mul_dual_anchor_consistency_trace (verbose)
- [ ] Tree multiplication deep test is gated by feature
  - rns_fhe::test_tree_mul_deep_passes (requires `--features slow_tests`)
- [ ] ProductionConfig128 full RNS chain
  - Requires big-integer Q or RNS-only (u128 product overflows for 7×30-bit primes)
- [ ] Doc-tests remain ignored (40 total) because examples are `ignore`d by design
  - Most require secure RNG, long-running keygen, or feature flags

---

## Recent Fixes (Completed)

- [x] Modulus switching tests now run on depth2_128
- [x] Anchor consistency tests now use assert_main_anchor_consistent/check_poly_consistency
- [x] NTT residue debug test now uses per-prime consistency checks
- [x] Anchor-track exact poly mul fallback (naive cyclic convolution) for non-NTT anchor modulus
- [x] Production 128-bit test enabled using 51-bit NTT-friendly prime + noise budget tracking
- [x] 4-prime incremental CRT reconstruction for large k values
- [x] Level-aware signed-k interpretation matching anchor prime count
- [x] Timing/CT regression tests moved to criterion benches (`benches/timing.rs`)
- [x] ops/rns_mul tests enabled using native DualRNS encryption + trivial ciphertext path for K-Elim validation

---

## Cryptographic Security Status

**Validated via RedShirt Cryptanalysis (2026-01-25)**:

| Config | Classical | Quantum | Status |
|--------|-----------|---------|--------|
| QMNF-Light (n=1024, logq=30) | 92 bits | 83 bits | INSECURE |
| standard_128 (n=4096, logq=30) | 516 bits | 453 bits | SECURE |
| high_192 (n=8192, logq=30) | 600 bits | 530 bits | SECURE |

**Post-Quantum**: Shor's algorithm does NOT apply (Ring-LWE ≠ discrete log)

---

## Formal Verification Coverage

| Proof File | Component | Status |
|------------|------------|--------|
| KElimination.v | K-Elimination core + 4-Prime CRT | Complete |
| GSOFHE.v | Bootstrap-free noise | Complete |
| MontgomeryPersistent.v | Persistent Montgomery | Complete |
| SideChannelResistance.v | Constant-time ops | Complete |
| 10 other modules | Various | Complete |

**Total**: 5,103 LOC formal proofs (updated 2026-01-26)

---

## Progress Tracking

- **Total Tasks**: 22
- **Critical (P0)**: 2/2 ✅
- **High (P1)**: 6/6 ✅
- **Medium (P2)**: 6/6 ✅ (All MEDIUM tasks complete!)
- **Known Limitations**: 3
- **Completed**: 18
