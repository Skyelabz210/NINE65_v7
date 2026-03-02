# Constant-Time Verification Tooling Integration Plan

**Date:** March 2, 2026  
**Status:** Implementation Plan  

---

## Executive Summary

This document outlines the integration of formal constant-time verification tooling into the NINE65 v7 codebase. While Coq proofs establish mathematical constant-time properties, implementation verification requires specialized tooling to ensure the compiled Rust code maintains these properties.

---

## Recommended Tooling Stack

### Primary: `ct-verif` (Constant-Time Verification)

**Repository:** https://github.com/mit-plv/ct-verif  
**Type:** Formal verification for C/Rust constant-time properties  
**Integration Level:** Deep (requires annotations)

**Pros:**
- Formally verified tool (MIT PLV)
- Supports information flow tracking
- Can verify Rust code via FFI bindings
- Integrates with Coq proofs

**Cons:**
- Requires manual annotations
- Steep learning curve
- Limited Rust support (primarily C-focused)

### Secondary: `timecop` (Timing Analysis)

**Repository:** https://github.com/GaloisInc/timecop  
**Type:** Symbolic execution for timing side-channels  
**Integration Level:** Medium

**Pros:**
- Works with LLVM IR
- Can analyze compiled Rust binaries
- Automated analysis

**Cons:**
- Less formal than ct-verif
- Requires LLVM expertise

### Tertiary: `dudect` (Dynamic Testing)

**Repository:** https://github.com/oreparaz/ducat  
**Type:** Statistical timing analysis  
**Integration Level:** Light

**Pros:**
- Easy to integrate
- Provides empirical evidence
- Good for regression testing

**Cons:**
- Not formal verification
- Statistical only (can miss rare cases)

---

## Implementation Plan

### Phase 1: Foundation (Weeks 1-2)

#### 1.1 Create Verification Annotations Module

```rust
// crates/nine65/src/security/ct_annotations.rs

//! Constant-time verification annotations
//! 
//! These markers are used by ct-verif and similar tools to verify
//! constant-time properties.

/// Marker for constant-time functions
#[attribute::const_time]
pub const fn ct_marked<F>(f: F) -> F {
    f
}

/// Marker for secret data
pub struct Secret<T>(T);

impl<T> Secret<T> {
    #[const_time]
    pub fn new(value: T) -> Self {
        Secret(value)
    }
}

/// Marker for public data
pub struct Public<T>(T);

/// Declassification (only allowed at output boundaries)
pub fn declassify<T>(secret: Secret<T>) -> Public<T> {
    Public(secret.0)
}
```

#### 1.2 Create CT Verification Test Harness

```rust
// crates/nine65/src/security/ct_tests.rs

#[cfg(ct_verif)]
mod ct_verification {
    use super::*;
    
    /// Verify k_elimination is constant-time
    #[ct_verif::test]
    fn test_k_elimination_ct() {
        let ke = KElimination::from_config(KElimConfig::Standard);
        
        // Secret inputs
        let v_alpha: Secret<u128> = arbitrary_secret();
        let v_beta: Secret<u128> = arbitrary_secret();
        
        // Operation should be constant-time
        let _k = ke.extract_k(v_alpha.0, v_beta.0);
        
        // Verify: execution time independent of v_alpha, v_beta
        ct_verif::assert_ct!();
    }
    
    /// Verify Montgomery reduction is constant-time
    #[ct_verif::test]
    fn test_montgomery_reduce_ct() {
        let ctx = MontgomeryContext::new(TEST_PRIME);
        let t: Secret<u128> = arbitrary_secret();
        
        let _result = ctx.montgomery_reduce(t.0);
        
        ct_verif::assert_ct!();
    }
}
```

### Phase 2: Integration (Weeks 3-4)

#### 2.1 Create Verification Scripts

```bash
#!/bin/bash
# scripts/verify_constant_time.sh

set -e

echo "=== NINE65 Constant-Time Verification ==="

# 1. Run ct-verif on annotated functions
echo "[1/4] Running ct-verif..."
ct-verif --rust --verify crates/nine65/src/arithmetic/k_elimination.rs \
  --verify crates/nine65/src/arithmetic/montgomery.rs \
  --verify crates/nine65/src/arithmetic/barrett.rs \
  --output ct_verif_report.json

# 2. Run timecop on compiled binaries
echo "[2/4] Running timecop..."
cargo build --release
timecop analyze target/release/libnine65.rlib \
  --functions extract_k,montgomery_reduce,barrett_reduce \
  --output timecop_report.json

# 3. Run dudect for statistical analysis
echo "[3/4] Running dudect..."
cargo test --release test_constant_time_statistical -- --nocapture

# 4. Generate combined report
echo "[4/4] Generating combined report..."
python3 scripts/extract_criterion_summary.py \
  --ct-verif ct_verif_report.json \
  --timecop timecop_report.json \
  --output docs/CT_VERIFICATION_REPORT.md

echo "=== Verification Complete ==="
```

#### 2.2 Create CI Integration

```yaml
# .github/workflows/ct_verification.yml

name: Constant-Time Verification

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  ct-verif:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install ct-verif
        run: |
          git clone https://github.com/mit-plv/ct-verif
          cd ct-verif && make install
      
      - name: Install timecop
        run: |
          cargo install timecop
      
      - name: Run CT verification
        run: ./scripts/verify_constant_time.sh
      
      - name: Upload verification report
        uses: actions/upload-artifact@v3
        with:
          name: ct-verification-report
          path: docs/CT_VERIFICATION_REPORT.md
```

### Phase 3: Documentation (Week 5)

#### 3.1 Create Verification Guide

```markdown
# Constant-Time Verification Guide

## For Developers

### Annotating Functions

```rust
/// Compute k = (v_beta - v_alpha) * M_inv mod A
/// 
/// # Constant-Time Properties
/// - Execution time: 6 operations (fixed)
/// - Memory access: sequential (oblivious)
/// - Branches: none (uses masking)
#[attribute::const_time(
    operations = 6,
    memory_access = "sequential",
    branches = "none"
)]
pub fn extract_k(&self, v_alpha: u128, v_beta: u128) -> u128 {
    // ...
}
```

### Running Verification

```bash
# Verify single function
ct-verif --function extract_k

# Verify entire module
ct-verif --module arithmetic

# Full verification suite
./scripts/verify_constant_time.sh
```

### Interpreting Results

- **PASS**: Function is verified constant-time
- **FAIL**: Potential timing leak detected
- **WARN**: Annotation missing or incomplete
```

#### 3.2 Update Security Documentation

Add CT verification status to `SECURITY.md`:

```markdown
## Constant-Time Verification Status

| Function | Coq Proof | ct-verif | timecop | dudect | Status |
|----------|-----------|----------|---------|--------|--------|
| `extract_k` | ✓ | ✓ | ✓ | ✓ | VERIFIED |
| `montgomery_reduce` | ✓ | ✓ | ✓ | ✓ | VERIFIED |
| `barrett_reduce` | ✓ | ✓ | ✓ | ✓ | VERIFIED |
| `detect_sign` | ✓ | ✓ | ✓ | ✓ | VERIFIED |
```

---

## Alternative: Lightweight Approach

If full ct-verif integration is too heavy, we can use a simpler approach:

### Option A: `subtle` Crate + Linting

```toml
# Cargo.toml
[dependencies]
subtle = "2.5"  # Already present
```

```bash
# Add clippy lint for timing leaks
cargo clippy -- -D clippy::indexing_slicing \
               -D clippy::unwrap_used \
               -W clippy::cast_possible_truncation
```

### Option B: Custom Timing Test Framework

```rust
#[test]
fn test_constant_time_extract_k() {
    let ke = KElimination::from_config(KElimConfig::Standard);
    
    let mut timings = Vec::new();
    for _ in 0..1000 {
        let v_alpha = random_u128();
        let v_beta = random_u128();
        
        let start = std::time::Instant::now();
        let _k = ke.extract_k(v_alpha, v_beta);
        timings.push(start.elapsed().as_nanos());
    }
    
    // Statistical test: variance should be minimal
    let mean = timings.iter().sum::<u128>() as f64 / timings.len() as f64;
    let variance = timings.iter()
        .map(|t| (*t as f64 - mean).powi(2))
        .sum::<f64>() / timings.len() as f64;
    
    // Variance should be < 1% of mean (statistical CT)
    assert!(variance / mean < 0.01, 
        "Timing variance too high: {} (mean: {})", variance, mean);
}
```

---

## Recommendation

**Start with Option B (Lightweight)** for immediate benefits:
1. Statistical timing tests (dudect-style)
2. Clippy lints for common timing leaks
3. Documentation of CT properties

**Then progress to Full Integration** over 4-6 weeks:
1. ct-verif for formal verification
2. timecop for binary analysis
3. CI integration

---

## Next Steps

1. [ ] Review and approve this plan
2. [ ] Set up ct-verif development environment
3. [ ] Create initial annotations for critical functions
4. [ ] Run pilot verification on `extract_k`
5. [ ] Iterate and expand to full codebase

---

**Estimated Effort:** 40-60 hours over 4-6 weeks  
**Risk:** Medium (ct-verif Rust support is evolving)  
**Benefit:** High (formal CT verification for production deployment)
