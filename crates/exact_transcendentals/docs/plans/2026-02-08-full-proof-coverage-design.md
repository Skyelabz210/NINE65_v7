# Full Proof Coverage Design — Exact Transcendentals Lean4 Formalization

**Date**: 2026-02-08
**Goal**: Eliminate all `sorry` statements. Every theorem machine-verified in full generality.
**Constraint**: No compromises — rewrite definitions if needed, but prove everything.

---

## Current State (Post Round 1)

| Metric | Value |
|--------|-------|
| Files | 7 Lean files |
| Definitions | ~30 |
| Proofs verified (no sorry) | 14 |
| Proofs with sorry | 18 |
| Compilation errors | 2 files broken (Isqrt, Agm) |
| Missing modules | 2 (BinaryGcd, ScaledInt) |
| Vacuous theorems | 1 (L010 proves `True`) |

## Design Decisions

1. **Full proof coverage** — zero sorry, full generality
2. **No compromises** — rewrite definitions for tractability
3. **Add Mathlib dependency** — unlocks powerful tactics + existing BinaryGCD proof
4. **Two-definition pattern** — `_impl` (Rust-faithful) + `_spec` (proof-friendly) + bridge theorem
5. **Rust cross-validation** — `#eval!` assertions matching `cargo test` outputs
6. **Full ScaledInt type** — retrofit CORDIC/AGM with computational scaled integer type
7. **Port existing BinaryGCD** — from `/home/acid/Projects/qmnf-formalization-swarm/14_BinaryGCD.lean`

---

## Phase 1: Infrastructure (prerequisite)

### 1a. Add Mathlib to lakefile.toml

```toml
[dependencies]
mathlib = { git = "https://github.com/leanprover-community/mathlib4", rev = "..." }
```

### 1b. Fix Isqrt.lean compilation

- Remove `isqrtDigitByDigit` (broken HShiftRight Nat Int, unterminated Int recursion)
- Remove `isqrtBinary` (redundant)
- Remove all custom bitwise operators (`<<<`, `>>>`, `&&&`, `|||`) and helpers (`Nat.shiftLeft`, `Nat.bitAnd`, `Nat.binaryOr`)
- Fix `isPerfectSquare_char`: use `isPerfectSquare n = true ↔ ...` with proper Bool/Prop bridge
- Target: ~80 lines: `isqrtNewton`, `isPerfectSquare`, theorems

### 1c. Fix Agm.lean compilation

- Delete duplicate `isqrtNat` definition (import from Isqrt)
- Move `agmStepRepeated` definition above `agm_converges` theorem
- Replace `Nat.natAbs` with plain `Nat` subtraction

### 1d. Replace Basic.lean

Replace placeholder `def hello := "world"` with foundation module:
- Integer-only axiom documentation
- SCALE constants (2^30, 2^62)
- Shared utility definitions

### 1e. Port BinaryGcd.lean

Port from `/home/acid/Projects/qmnf-formalization-swarm/14_BinaryGCD.lean`:
- `binaryGCD` definition
- `binaryGCD_correct` theorem (proven via well-founded induction)
- Extended GCD with Bezout identity
- Adapt namespace from `QMNF.BinaryGCD` to `ExactTranscendentals`

### 1f. Create ScaledInt.lean

Full computational type:
- `ScaledInt` structure with `value : Int`, `scale_bits : Nat`
- Arithmetic: `add`, `sub`, `mul` (with rescaling), `shr`, `neg`
- Constructors: `mk`, `zero`, `one`
- Conversion: `toRational : ScaledInt → ExactRational`
- Invariant theorem: operations preserve scaling

### 1g. Fix #eval everywhere

Change all `#eval` to `#eval!` (sorry-dependent evaluation blocked in Lean 4.27+).

### Gate: `lake build` passes with zero errors

---

## Phase 2: Rust Cross-Validation

### 2a. Extract Rust test vectors

```bash
cd /home/acid/Projects/exact_transcendentals
cargo test -- --nocapture 2>&1
```

### 2b. Create CrossCheck.lean

Embed Rust outputs as `#eval!` assertions:

```lean
-- CORDIC
#eval! assert! (cordicSincos_impl 0 32 == (1073741824, 0))
#eval! assert! (cordicSincos_impl 843314857 32 == ...)

-- isqrt
#eval! assert! (isqrtNewton 0 == 0)
#eval! assert! (isqrtNewton 100 == 10)
#eval! assert! (isqrtNewton 1000000 == 1000)

-- Pell
#eval! assert! (pellFundamental_impl 2 == some (3, 2))
#eval! assert! (pellFundamental_impl 61 == some (1766319049, 226153980))
```

### Gate: All assertions match Rust outputs

---

## Phase 3: Definition Restructuring

### 3a. CORDIC: Replace foldl with explicit recursion

```lean
-- _impl: matches Rust (foldl)
def cordicIter_impl (angle : Int) (n : Nat) : CordicState :=
  (List.range n).foldl (fun st i => cordicStep st i) (SCALE, 0, angle)

-- _spec: proof-friendly (structural recursion on Nat)
def cordicIter_spec (angle : Int) : Nat → CordicState
  | 0 => (SCALE, 0, angle)
  | n+1 => cordicStep (cordicIter_spec angle n) n

-- Bridge
theorem cordicIter_impl_eq_spec (angle : Int) (n : Nat) :
    cordicIter_impl angle n = cordicIter_spec angle n
```

### 3b. AGM: Explicit pair recursion

```lean
def agmIter_spec (a b : Nat) : Nat → Nat × Nat
  | 0 => (a, b)
  | n+1 => let (a', b') := agmIter_spec a b n; agmStep a' b'
```

### 3c. Binary Splitting: Formal series sum

Define the mathematical series sum and prove `binarySplit` computes it:

```lean
def seriesSum (termA termB termP termQ : Nat → Int) (lo hi : Nat) : Int × Int := ...

theorem binarySplit_correct :
    let st := binarySplit a b termA termB termP termQ
    let (num, den) := seriesSum termA termB termP termQ a b
    st.t * den = num * (st.b * st.q)
```

### 3d. Pell: Factor into period + extraction

```lean
def sqrtCFPeriod (d : Nat) : List Int := ...
def sqrtCFPeriodLength (d : Nat) : Nat := ...
def pellFromPeriod (d : Nat) (period : List Int) : Option (Int × Int) := ...
```

### 3e. Retrofit ScaledInt

Replace raw `Int` with `ScaledInt` in:
- `CordicState` → `ScaledInt × ScaledInt × ScaledInt`
- `cordicStep`, `cordicSincos`
- `agmStep`, `agm`

---

## Phase 4: Wave 1-2 Proofs (Easy + Moderate)

### Wave 1: Trivial with Mathlib (3 proofs)

| Theorem | Technique |
|---------|-----------|
| `equiv_trans` | `mul_left_cancel₀` with `s.den_ne_zero` |
| `reduce_equiv` | `Int.ediv_mul_cancel`, `gcd_dvd_left/right` |
| `isPerfectSquare_char` | Fix Bool↔Prop, `constructor; intro; exact` |

### Wave 2: Moderate with Mathlib (7 proofs)

| Theorem | Technique |
|---------|-----------|
| `isqrtNewton_correctness` | Well-founded induction, `omega` for arithmetic |
| `isqrt_of_square` | Corollary of correctness |
| `isqrt_monotonic` | From correctness bounds |
| `agm_symmetric` | Induction, `Nat.add_comm`, `Nat.mul_comm` |
| `agm_bounds` | AM-GM + induction |
| `cf_determinant_identity` | Induction on n, `ring` for algebra |
| `cordicIter_impl_eq_spec` | Induction, `List.range_succ`, `List.foldl_append` |

---

## Phase 5: Wave 3-4 Proofs (Hard + Deep)

### Wave 3: Hard (5 proofs)

| Theorem | Technique |
|---------|-----------|
| `cordic_convergence` | Induction on n. At step i, d = sign(z) so `\|z'\| = \|z - d·atan_i\| ≤ max(\|z\| - atan_i, atan_i)`. Tail sum bound by induction. |
| `pythagorean_identity` | CORDIC step is pseudo-rotation with det = 1 + 2^{-2i}. Product of dets = 1/K². After gain correction, `\|c²+s²-S²\| ≤ S·2`. Integer truncation bounded per step. |
| `binarySplit_correctness` | Strong induction on `hi - lo`. Combine algebra verified by `ring`. |
| `cf_sqrt_error_bound` | From determinant identity: `p_n² - d·q_n² = (-1)^n · d_n`. Show `d_n ≤ 2·a0` from CF algorithm invariants. |
| `agm_monotone_convergence` | AM-GM: `(a+b)/2 ≥ √(ab) ≥ min(a,b)`. Gap: `a_{n+1} - b_{n+1} ≤ (a_n - b_n)²/(4·b_n)`. |

### Wave 4: Deep (3 proofs)

| Theorem | Technique |
|---------|-----------|
| `cordic_sin_odd` | Induction on n. Negating z_0 flips every decision d. Track: x stays same (cos even), y flips (sin odd). |
| `cordic_cos_even` | Same induction, tracking x. |
| `pell_correctness` | Requires CF periodicity infrastructure (~200 lines). Prove: (a) sqrt(d) CF is periodic, (b) period length is finite, (c) convergent at period boundary satisfies Pell, (d) parity handling. |

---

## Phase 6: Verification

1. `lake build` — zero errors, zero sorry, zero warnings about sorry
2. All `#eval!` assertions in CrossCheck.lean pass
3. Blueprint updated: all nodes → `verified` status
4. Confidence scores recomputed via evidence formula
5. `evidence.lean_compiled = true` for all nodes

---

## File Structure (Final)

```
lean4/
├── lakefile.toml                          # + Mathlib dependency
├── ExactTranscendentals.lean              # Root imports
├── ExactTranscendentals/
│   ├── Basic.lean                         # Foundation: axioms, shared constants
│   ├── ScaledInt.lean                     # D004: Full computational type (NEW)
│   ├── BinaryGcd.lean                     # D001: Ported from qmnf-formalization-swarm
│   ├── Isqrt.lean                         # D003: Fixed (removed broken defs)
│   ├── ExactRational.lean                 # D002: Existing (minor fixes)
│   ├── Cordic.lean                        # D005-D007: Retrofitted with ScaledInt
│   ├── Agm.lean                           # D008: Retrofitted, fixed imports
│   ├── ContinuedFraction.lean             # D009-D010: Refactored Pell
│   ├── BinarySplitting.lean               # D011: Added formal series sum
│   └── CrossCheck.lean                    # Rust cross-validation assertions (NEW)
└── Main.lean
```

---

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Mathlib version incompatibility | Pin to specific Mathlib rev in lakefile |
| Pell existence proof too complex | Factor into ~5 supporting lemmas about CF periodicity |
| ScaledInt retrofit breaks existing proofs | Two-definition pattern preserves both versions |
| Build time increases with Mathlib | One-time cost; subsequent builds are incremental |
| Some `nlinarith` goals may not close | Fall back to manual `calc` chains with explicit steps |

---

## Success Criteria

- [ ] `lake build` passes with zero errors
- [ ] Zero `sorry` in any .lean file
- [ ] All `#eval!` assertions in CrossCheck.lean pass
- [ ] Blueprint nodes all at `verified` status
- [ ] `evidence.lean_compiled = true` for all nodes
- [ ] Every `_impl` definition has a bridge theorem to `_spec`
- [ ] ScaledInt type enforces scale consistency in CORDIC/AGM
