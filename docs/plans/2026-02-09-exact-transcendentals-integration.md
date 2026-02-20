# Exact Transcendentals Integration Plan — Continuation

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Date**: 2026-02-09
**Goal**: Complete the integration of exact_transcendentals into NINE65 v5 — fix the one remaining test failure, sync diverged source from the standalone repo, expand the backend bridge, and wire transcendentals into the FHE pipeline.

**Context**: The initial integration (commits `2deade6`, `73d6b7f`) copied the exact_transcendentals crate into `crates/exact_transcendentals/` and created `transcendental_backend.rs` with a Q30-based CORDIC bridge. The crate's own 143 tests pass, but the nine65 integration has one failing test and several incomplete connections.

**What exists already**:
- `crates/exact_transcendentals/` — workspace crate, 10 modules, 143 tests passing
- `crates/nine65/src/arithmetic/transcendental_backend.rs` — Q30 CORDIC/Hyperbolic bridge (sin, cos, exp, ln)
- Feature flag `exact_transcendentals_backend` in nine65's Cargo.toml (correctly wired)
- Pre-integration baseline captured in `docs/baselines/pre_exact_transcendentals_20260209_092437Z/`
- Standalone repo at `/home/acid/Projects/exact_transcendentals/` has uncommitted diverged changes (now **behind** the NINE65 copy by ~968 lines)

**What needs to happen**:
1. Fix the Pade engine off-by-one test failure
2. Sync standalone repo back from NINE65 canonical copy
3. Expand transcendental_backend with missing functions (atan, sqrt, pi, AGM)
4. Wire transcendentals into GSO-FHE depth pipeline
5. Add cross-validation tests between Pade fallback and CORDIC backend
6. Update CLAUDE.md and BLUEPRINT.md

**Tech Stack**: Rust 2021, i64/i128 scaled integers, Q30 fixed-point (2^30), feature-gated optional dependency.

---

## Task 1: Fix Pade engine off-by-one test failure

**Problem**: `test_pade_engine_zero_identities` in `crates/nine65/tests/formalization_invariants.rs:47` fails:
```
assertion `left == right` failed
  left: 1000000001
 right: 1000000000
```
`engine.cos_integer(0)` returns `PADE_SCALE + 1` instead of `PADE_SCALE`. This is a rounding error in the Pade cos(0) computation.

**Files:**
- Investigate: `crates/nine65/src/arithmetic/mod.rs` (find `PadeEngine` and `cos_integer`)
- Fix: The Pade engine's `cos_integer(0)` method

**Step 1: Locate the PadeEngine implementation**

Search for `PadeEngine` in `crates/nine65/src/arithmetic/` and read `cos_integer` method.

**Step 2: Diagnose the off-by-one**

`cos(0) = 1` exactly. At PADE_SCALE = 10^9, the result should be exactly 1_000_000_000. The +1 means the Pade [4/4] or [6/6] approximant has a rounding artifact at x=0. Likely cause: integer division truncation producing `(num + den/2) / den` instead of `num / den` when num/den is already exact.

**Step 3: Fix — ensure cos(0) returns PADE_SCALE exactly**

Add an early-return check: `if x == 0 { return PADE_SCALE; }` for cos, and verify the other identity functions (exp(0)=SCALE, sin(0)=0, tanh(0)=0, sigmoid(0)=SCALE/2) still hold.

**Step 4: Verify fix**

Run: `cargo test -p nine65 --test formalization_invariants --release`
Expected: 4/4 tests pass (including `test_pade_engine_zero_identities`).

**Step 5: Run full suite to check for regressions**

Run: `cargo test -p nine65 --lib --release`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add crates/nine65/src/arithmetic/...
git commit -m "fix: Pade cos(0) off-by-one — return exact PADE_SCALE at zero"
```

---

## Task 2: Sync standalone repo from NINE65 canonical copy

**Problem**: The standalone repo at `/home/acid/Projects/exact_transcendentals/` has uncommitted local changes and is 968 lines behind the NINE65 canonical copy. The NINE65 copy received audit fixes, truth perturber tests, and integration adapters. The standalone repo should be updated to match.

**Files:**
- Source: `crates/exact_transcendentals/src/*.rs` (NINE65 canonical)
- Target: `/home/acid/Projects/exact_transcendentals/src/*.rs` (standalone)

**Step 1: Verify the NINE65 copy is the authoritative version**

Run: `cargo test -p exact_transcendentals --release`
Expected: 143 tests pass.

**Step 2: Copy source files from NINE65 to standalone**

```bash
cp /home/acid/Projects/NINE65/v5/crates/exact_transcendentals/src/*.rs \
   /home/acid/Projects/exact_transcendentals/src/
```

**Step 3: Verify standalone still builds and tests pass**

```bash
cd /home/acid/Projects/exact_transcendentals
cargo test --release
```
Expected: 143+ tests pass.

**Step 4: Commit in standalone repo**

```bash
cd /home/acid/Projects/exact_transcendentals
git add src/
git commit -m "sync: pull canonical source from NINE65/v5 integration (2026-02-09)"
```

**Note**: This task does NOT push. The user should decide when to push the standalone repo.

---

## Task 3: Expand transcendental_backend with missing functions

**Problem**: `transcendental_backend.rs` currently only bridges 4 functions (sin, cos, exp, ln). The exact_transcendentals crate provides many more: atan, atan2, sqrt, pi, AGM-based ln, binary splitting exp, continued fraction constants. The backend should expose the most useful ones.

**Files:**
- Modify: `crates/nine65/src/arithmetic/transcendental_backend.rs`

**Step 1: Write failing tests for new functions**

Add to the `#[cfg(all(test, feature = "exact_transcendentals_backend"))]` block:

```rust
#[test]
fn test_exact_atan_at_one() {
    // atan(1) = pi/4 ≈ 0.7854
    let scale = 1_000_000_000i128;
    let result = try_atan_integer_exact(scale, scale).expect("should succeed");
    // pi/4 * 10^9 ≈ 785_398_163
    assert!((result - 785_398_163).abs() < 5_000_000, "atan(1) off: {result}");
}

#[test]
fn test_exact_sqrt_at_four() {
    // sqrt(4) = 2
    let scale = 1_000_000_000i128;
    let result = try_sqrt_integer_exact(4 * scale, scale).expect("should succeed");
    assert!((result - 2 * scale).abs() < 2_000_000, "sqrt(4) off: {result}");
}

#[test]
fn test_exact_pi_constant() {
    let scale = 1_000_000_000i128;
    let result = try_pi_integer_exact(scale).expect("should succeed");
    // pi * 10^9 ≈ 3_141_592_653
    assert!((result - 3_141_592_653).abs() < 5_000_000, "pi off: {result}");
}
```

**Step 2: Implement the new bridge functions**

Add to `ExactTranscendentalBackend`:

```rust
pub fn atan_integer(&self, x: i128, scale: i128) -> Option<i128> {
    let x_q30 = to_q30(x, scale)?;
    from_q30(self.circular.atan(x_q30), scale)
}

pub fn sqrt_integer(&self, x: i128, scale: i128) -> Option<i128> {
    if x < 0 { return None; }
    let x_q30 = to_q30(x, scale)?;
    if x_q30 < 0 { return None; }
    // Use exact_transcendentals::sqrt::isqrt_newton for the Q30 value
    let sqrt_q30 = exact_transcendentals::sqrt::isqrt_newton_q30(x_q30);
    from_q30(sqrt_q30, scale)
}
```

Add public `try_*` wrapper functions following the existing pattern.

Add `try_pi_integer_exact(scale)` that returns pi at the given scale using the AGM or binary splitting pi computation from `exact_transcendentals::agm::compute_pi_q62()` downscaled to caller scale.

**Step 3: Run tests**

Run: `cargo test -p nine65 --lib --release --features exact_transcendentals_backend -- transcendental_backend`
Expected: All new + existing tests pass.

**Step 4: Commit**

```bash
git add crates/nine65/src/arithmetic/transcendental_backend.rs
git commit -m "feat: expand transcendental_backend with atan, sqrt, pi bridges"
```

---

## Task 4: Wire transcendentals into GSO-FHE noise pipeline

**Problem**: GSO-FHE's depth computations in `ops/gso_fhe.rs` use integer-only Q15 LUT trig (256-entry table in `integer_math.rs`). When `exact_transcendentals_backend` is enabled, the noise evolution model can optionally use CORDIC for higher-precision noise estimates, improving depth predictions.

**Files:**
- Modify: `crates/nine65/src/ops/gso_fhe.rs` (add optional CORDIC noise path)
- Modify: `crates/nine65/src/noise/mod.rs` (add exact transcendental noise helper)

**Step 1: Write a test showing the benefit**

```rust
#[cfg(all(test, feature = "exact_transcendentals_backend"))]
#[test]
fn test_noise_estimate_with_exact_transcendentals() {
    // Compare noise estimate at depth 10 between LUT and CORDIC paths
    // CORDIC should give a tighter bound (smaller noise estimate)
    let lut_noise = estimate_noise_growth_lut(10, 16);
    let cordic_noise = estimate_noise_growth_cordic(10, 16);
    assert!(cordic_noise <= lut_noise,
        "CORDIC noise {cordic_noise} should be <= LUT noise {lut_noise}");
}
```

**Step 2: Implement the CORDIC noise path**

Add a feature-gated helper that uses `try_exp_integer_exact` for exponential noise growth estimation instead of the LUT-based `exp_integer_lut`. This gives 30-bit precision instead of 15-bit for the noise growth factor.

**Step 3: Verify no regression without the feature**

Run: `cargo test -p nine65 --lib --release -- ops::gso_fhe`
Expected: All existing tests pass (CORDIC path is feature-gated).

**Step 4: Verify with the feature**

Run: `cargo test -p nine65 --lib --release --features exact_transcendentals_backend -- ops::gso_fhe`
Expected: All tests pass including new CORDIC noise test.

**Step 5: Commit**

```bash
git add crates/nine65/src/ops/gso_fhe.rs crates/nine65/src/noise/
git commit -m "feat: optional CORDIC noise estimation in GSO-FHE depth pipeline"
```

---

## Task 5: Cross-validation tests — Pade vs CORDIC backend

**Problem**: NINE65 has two transcendental computation paths: the built-in Pade approximant engine and the exact_transcendentals CORDIC backend. These should agree within known error bounds for correctness.

**Files:**
- Create: `crates/nine65/tests/transcendental_cross_validation.rs`

**Step 1: Write cross-validation tests**

```rust
//! Cross-validation between Pade and CORDIC transcendental backends.
//!
//! Both paths should agree within their respective error bounds.

#![cfg(feature = "exact_transcendentals_backend")]

use nine65::arithmetic::{PadeEngine, PADE_SCALE};
use nine65::arithmetic::transcendental_backend::*;

#[test]
fn cross_validate_exp_at_origin_neighborhood() {
    let engine = PadeEngine::default();
    let scale = PADE_SCALE as i128;

    // Test exp at x = 0, 0.1, 0.5, 1.0 (scaled)
    let test_points = [0, scale / 10, scale / 2, scale];

    for &x in &test_points {
        let pade_result = engine.exp_integer(x as i64) as i128;
        if let Some(cordic_result) = try_exp_integer_exact(x, scale) {
            let diff = (pade_result - cordic_result).abs();
            let tolerance = scale / 100; // 1% tolerance
            assert!(diff < tolerance,
                "exp({x}/{scale}): Pade={pade_result}, CORDIC={cordic_result}, diff={diff}");
        }
    }
}

#[test]
fn cross_validate_sin_cos_pythagorean() {
    let scale = PADE_SCALE as i128;

    // For several angles, verify sin^2 + cos^2 ≈ scale^2
    let angles = [0, scale / 6, scale / 4, scale / 3, scale / 2];

    for &theta in &angles {
        if let (Some(s), Some(c)) = (
            try_sin_integer_exact(theta, scale),
            try_cos_integer_exact(theta, scale),
        ) {
            let sum_sq = s * s + c * c;
            let expected = scale * scale;
            let error = (sum_sq - expected).abs();
            let tolerance = expected / 1000; // 0.1% tolerance
            assert!(error < tolerance,
                "Pythagorean at theta={theta}: sin^2+cos^2={sum_sq}, expected={expected}, err={error}");
        }
    }
}

#[test]
fn cross_validate_ln_exp_roundtrip() {
    let scale = 1_000_000_000i128;

    // ln(exp(x)) should ≈ x for small x
    let test_points = [scale / 10, scale / 4, scale / 2];

    for &x in &test_points {
        if let Some(exp_x) = try_exp_integer_exact(x, scale) {
            if let Some(ln_exp_x) = try_ln_integer_exact(exp_x, scale) {
                let diff = (ln_exp_x - x).abs();
                let tolerance = scale / 50; // 2% tolerance
                assert!(diff < tolerance,
                    "ln(exp({x}/{scale})): got {ln_exp_x}, expected {x}, diff={diff}");
            }
        }
    }
}
```

**Step 2: Run cross-validation**

Run: `cargo test -p nine65 --test transcendental_cross_validation --release --features exact_transcendentals_backend`
Expected: All 3 tests pass.

**Step 3: Commit**

```bash
git add crates/nine65/tests/transcendental_cross_validation.rs
git commit -m "test: cross-validation between Pade and CORDIC transcendental paths"
```

---

## Task 6: Update documentation

**Files:**
- Modify: `CLAUDE.md` (add exact_transcendentals to crate table and feature flags)
- Modify: `crates/exact_transcendentals/BLUEPRINT.md` (update integration status)

**Step 1: Update CLAUDE.md**

Add `exact_transcendentals` to the Workspace Crates table:
```
| `exact_transcendentals` | `crates/exact_transcendentals/` | Exact integer-only transcendentals: CORDIC, AGM, binary splitting, CF (143 tests) |
```

Add to Feature Flags section:
```
- `exact_transcendentals_backend` - CORDIC/AGM exact backend for transcendental ops
```

Add to Key Paths section:
```
- **Transcendental backend**: `crates/nine65/src/arithmetic/transcendental_backend.rs` (requires `exact_transcendentals_backend` feature)
```

**Step 2: Update BLUEPRINT.md integration status**

In `crates/exact_transcendentals/BLUEPRINT.md`, update the QMNF Integration Points table:

| QMNF Component | Integration Status |
|-----------------|-------------------|
| K-Elimination | Integrated via rational_bridge |
| CRTBigInt | Integrated (crt.rs, 580 lines) |
| Montgomery Persistence | CORDIC compatible |
| Cyclotomic Phase | Extends trig to FHE ring |
| Shadow Entropy | Randomized algorithm variants |
| **NINE65 Backend** | **Integrated (transcendental_backend.rs)** |
| **GSO-FHE Noise** | **Integrated (CORDIC noise estimation)** |

**Step 3: Commit**

```bash
git add CLAUDE.md crates/exact_transcendentals/BLUEPRINT.md
git commit -m "docs: update CLAUDE.md and BLUEPRINT.md for exact transcendentals integration"
```

---

## Dependency Graph

```
Task 1 (fix Pade off-by-one)
     ↓
Task 2 (sync standalone repo) ← independent, can run after Task 1

Task 3 (expand backend) ← depends on Task 1 (needs green suite)
     ↓
Task 4 (GSO-FHE wiring) ← depends on Task 3 (uses new bridge functions)
     ↓
Task 5 (cross-validation) ← depends on Task 3 (tests expanded API)
     ↓
Task 6 (documentation) ← depends on Tasks 3-5 (documents final state)
```

**Parallelizable**: Tasks 1 and 2 can run concurrently. Tasks 4 and 5 can run concurrently after Task 3.

---

## Future Work (not in this plan)

- **Lean4 proof coverage**: Separate plan at `crates/exact_transcendentals/docs/plans/2026-02-08-full-proof-coverage-design.md`
- **Arbitrary-precision backend**: Enable `--features arbitrary-precision` in exact_transcendentals for CRTBigInt-backed computations within NINE65
- **SIMD CORDIC via Mana**: Route CORDIC iterations through the Mana lane-parallel accelerator
- **Benchmark suite**: Compare Pade vs CORDIC latency at various precision levels
- **Formal cross-proof**: Coq proof that CORDIC and Pade agree within bounded error for the FHE-relevant domain
