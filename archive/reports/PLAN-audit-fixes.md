# Implementation Plan: Audit Findings #1 & #3

## Context
Manus AI audit identified 3 issues. #2 (U256 overflow) is fixed and committed.
Remaining: #1 Public Mode Depth, #3 Float Violations.

## Branch: `fix/audit-public-depth-and-float-purge`

---

## Task 1: Public Mode — Automatic Modulus Switching (TDD)

**Goal:** Make `mul_dual_public` automatically apply modulus switching when
the ciphertext has enough levels, matching `mul_dual_public_deep` behavior
as the default path.

**Files:** `crates/nine65/src/ops/rns_fhe.rs`

### Steps

1.1 **RED:** Write test `test_mul_dual_public_auto_mod_switch_depth2` that
    performs depth-2 public multiplication using `mul_dual_public` (not
    `_deep`) and expects correct decryption. Currently this should FAIL
    because `mul_dual_public` lacks automatic modulus switching.

1.2 **Verify RED:** Run test, confirm it fails with decryption error.

1.3 **GREEN:** Modify `mul_dual_public` (line ~2206) to apply
    `mod_switch_ct_down` after rescale when `ct.level >= 3` (enough primes
    to drop one). This mirrors what `mul_dual_public_deep` already does.

1.4 **Verify GREEN:** Run test, confirm depth-2 now decrypts correctly.

1.5 **RED:** Write test `test_mul_dual_public_depth3_chain` that chains
    3 multiplications through `mul_dual_public` and expects correct result.

1.6 **GREEN:** If depth-3 fails, tune: use smaller decomposition base or
    add level-aware eval key adaptation. The mechanisms already exist in
    `mod_switch_eval_key_to_level` (line 2265).

1.7 **Verify GREEN:** Full RNS test suite passes.

1.8 **REFACTOR:** Remove `mul_dual_public_deep` if it's now redundant, or
    deprecate it with a doc comment pointing to the automatic path.

---

## Task 2: Float Purge — avatar.rs (TDD)

**Goal:** Remove all 15 f64 violations from `avatar.rs`.

**File:** `avatar.rs` (project root)

### Steps

2.1 **RED:** Write test `test_avatar_accuracy_integer` that creates an
    Avatar, runs classifications, and checks accuracy as `u32` permille
    (1000 = 100%). Currently fails because `accuracy()` returns f64.

2.2 **GREEN:** Convert `accuracy()` to return `u32` permille:
    `self.correct_count * 1000 / self.classification_count`

2.3 Convert parameter API (lines 70-79): Change `preference_weight: f64`
    etc. to `i64` (pre-scaled by ENTROPY_SCALE). Update callers.

2.4 Replace `(i as f64 * 0.2).sin()` synthetic data (line 417) with
    Q15 fixed-point LUT from `integer_math.rs::fixed_cos_sin()`.

2.5 Convert `global_accuracy()` (line 519) to return `u32` permille.

2.6 **Verify GREEN:** `cargo test` on affected module passes.

---

## Task 3: Float Purge — pipeline.rs (TDD)

**Goal:** Remove all 6 f64 violations from `pipeline.rs`.

**File:** `pipeline.rs` (project root)

### Steps

3.1 **RED:** Write test `test_pipeline_metrics_integer` checking
    `success_rate()` and `human_rate()` return `u32` permille.

3.2 **GREEN:** Convert:
    - `success_rate()` → `u32` permille
    - `human_rate()` → `u32` permille
    - `avg_latency_ms: f64` → `u64` (nanoseconds or microseconds)
    - `accuracy()` → `u32` permille

3.3 **Verify GREEN:** Full workspace test suite passes.

---

## Verification

After all tasks:
```bash
cargo test -p nine65 -p clockwork-core -p nexgen_rational -p mana -p unhal --release
grep -rn "f64\|f32" --include="*.rs" crates/nine65/src/ avatar.rs pipeline.rs \
  | grep -v compiler.rs | grep -v "//\|///\|#\[doc"
```

Expected: zero non-exempt float violations, all tests pass.

## Batch Plan

- **Batch 1:** Task 1 (Public Mode — most complex, highest impact)
- **Batch 2:** Tasks 2 & 3 in parallel (Float Purge — independent files)
