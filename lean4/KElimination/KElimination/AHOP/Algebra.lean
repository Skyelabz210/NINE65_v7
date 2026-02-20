/-
  AHOP Algebraic Foundations

  This file proves that the Apollonian structure works in FINITE FIELDS,
  addressing the critique that "geometric constructions don't translate to ℤ_q".

  KEY INSIGHT: The Descartes Circle Theorem is an ALGEBRAIC identity, not geometric.
  The equation (k₁+k₂+k₃+k₄)² = 2(k₁²+k₂²+k₃²+k₄²) holds in ANY ring where 2 is invertible.

  We prove this WITHOUT any geometric assumptions.

  Date: 2026-02-04
  Status: Ported from SwarmProofs to NINE65 v5
-/

import Mathlib.Data.ZMod.Basic
import Mathlib.Data.Fin.Basic
import Mathlib.Algebra.Ring.Basic
import Mathlib.Tactic

namespace KElimination.AHOP

/-! # Part 1: Descartes Quadratic Form (Pure Algebra) -/

/-- The Descartes quadratic form Q(k) = (∑kᵢ)² - 2∑kᵢ²
    This is a purely algebraic expression that works in any ring. -/
def descartesForm {R : Type*} [Ring R] (k : Fin 4 → R) : R :=
  let sum := k 0 + k 1 + k 2 + k 3
  let sumSquares := k 0 ^ 2 + k 1 ^ 2 + k 2 ^ 2 + k 3 ^ 2
  sum ^ 2 - 2 * sumSquares

/-- Expanded form for computation. -/
theorem descartesForm_expanded {R : Type*} [CommRing R] (k : Fin 4 → R) :
    descartesForm k =
      2 * (k 0 * k 1 + k 0 * k 2 + k 0 * k 3 +
          k 1 * k 2 + k 1 * k 3 + k 2 * k 3) -
      (k 0 ^ 2 + k 1 ^ 2 + k 2 ^ 2 + k 3 ^ 2) := by
  simp [descartesForm]
  ring_nf

/-! # Part 2: Apollonian Quadruples over ℤ_q -/

/-- A quadruple is Apollonian if it satisfies the Descartes relation Q(k) = 0 mod q -/
def IsApollonian {q : ℕ} [Fact (0 < q)] (k : Fin 4 → ZMod q) : Prop :=
  descartesForm k = 0

/-- Example: The zero quadruple is Apollonian. -/
example {q : ℕ} [Fact (0 < q)] :
    IsApollonian (fun _ : Fin 4 => (0 : ZMod q)) := by
  simp [IsApollonian, descartesForm]

/-! # Part 3: Reflection Operators (Algebraic Definition) -/

/-- Reflection S_i replaces kᵢ with 2(k₀+k₁+k₂+k₃) - 3kᵢ
    This is derived from the Descartes relation, keeping Q = 0.

    Actually, the correct formula from Descartes is:
    k'ᵢ = 2(sum of others) - kᵢ = 2(k_j + k_l + k_m) - kᵢ where {j,l,m} = {0,1,2,3} \ {i}

    Equivalently: k'ᵢ = 2(k₀+k₁+k₂+k₃) - 2kᵢ - kᵢ = 2S - 3kᵢ where S = sum of all -/
def reflect {q : ℕ} [Fact (0 < q)] (i : Fin 4) (k : Fin 4 → ZMod q) : Fin 4 → ZMod q :=
  fun j => if j = i then
    let S := k 0 + k 1 + k 2 + k 3
    2 * S - 3 * k i
  else
    k j

/-- Alternative formula using sum of others (equivalent) -/
def reflect' {q : ℕ} [Fact (0 < q)] (i : Fin 4) (k : Fin 4 → ZMod q) : Fin 4 → ZMod q :=
  fun j => if j = i then
    let others_sum := (k 0 + k 1 + k 2 + k 3) - k i
    2 * others_sum - k i
  else
    k j

theorem reflect_eq_reflect' {q : ℕ} [Fact (0 < q)] (i : Fin 4) (k : Fin 4 → ZMod q) :
    reflect i k = reflect' i k := by
  ext j
  simp only [reflect, reflect']
  split_ifs with h
  · ring
  · rfl

/-! # Part 4: Involution Property (S_i ∘ S_i = id) -/

/-- THEOREM: Reflection is an involution: S_i(S_i(k)) = k
    This is pure algebra, no geometry needed. -/
theorem reflect_involution {q : ℕ} [Fact (0 < q)] [Fact (q > 2)]
    (i : Fin 4) (k : Fin 4 → ZMod q) :
    reflect i (reflect i k) = k := by
  ext j
  fin_cases i <;> fin_cases j <;> simp [reflect] <;> ring_nf

/-! # Part 5: Descartes Invariant Preservation -/

/-- Helper: Sum of quadruple changes predictably under reflection -/
theorem sum_after_reflect {q : ℕ} [Fact (0 < q)] (i : Fin 4) (k : Fin 4 → ZMod q) :
    let k' := reflect i k
    let S := k 0 + k 1 + k 2 + k 3
    let S' := k' 0 + k' 1 + k' 2 + k' 3
    S' = 3 * S - 4 * k i := by
  -- k'_j = k_j for j ≠ i, and k'_i = 2S - 3k_i
  -- S' = (S - k_i) + (2S - 3k_i) = 3S - 4k_i
  fin_cases i <;> simp [reflect] <;> ring_nf

/-- THEOREM: Reflection preserves the Descartes invariant Q(k) = 0.
    This is the KEY theorem showing AHOP works in ℤ_q. -/
theorem reflect_preserves_apollonian {q : ℕ} [Fact (0 < q)] [Fact (q > 2)]
    (i : Fin 4) (k : Fin 4 → ZMod q) (hk : IsApollonian k) :
    IsApollonian (reflect i k) := by
  -- Reduce to a pure ring identity: Q(reflect i k) = Q(k).
  fin_cases i <;> (
    simp [IsApollonian, descartesForm, reflect] at *
    ring_nf at *
    simpa using hk
  )

/-! # Part 6: Non-Commutativity -/

/-- THEOREM: Reflections are non-commutative: S_i ∘ S_j ≠ S_j ∘ S_i for i ≠ j -/
theorem reflects_noncommutative {q : ℕ} [Fact (0 < q)] [Fact (q ≥ 11)] :
    ∃ (k : Fin 4 → ZMod q),
    reflect 0 (reflect 1 k) ≠ reflect 1 (reflect 0 k) := by
  -- Explicit counterexample: k = (1, 0, 0, 0)
  let k : Fin 4 → ZMod q := fun i => if i = 0 then (1 : ZMod q) else 0
  refine ⟨k, ?_⟩
  intro h
  -- Compare coordinate 0 on both sides
  have h0 := congrArg (fun f => f 0) h
  -- Evaluate both sides at coordinate 0
  have h_left : (reflect 0 (reflect 1 k)) 0 = (3 : ZMod q) := by
    simp [k, reflect]
    ring_nf
  have h_right : (reflect 1 (reflect 0 k)) 0 = (-1 : ZMod q) := by
    simp [k, reflect]
    ring_nf
  have h0' : (3 : ZMod q) = (-1 : ZMod q) := by
    simpa [h_left, h_right] using h0
  -- From 3 = -1, we get 4 = 0
  have h4 : (4 : ZMod q) = 0 := by
    have h := congrArg (fun x => x + 1) h0'
    ring_nf at h
    simpa using h
  -- But q >= 11 cannot divide 4
  have hq_div : q ∣ 4 := (ZMod.natCast_eq_zero_iff 4 q).1 h4
  have hq_le : q ≤ 4 := Nat.le_of_dvd (by decide : 0 < 4) hq_div
  have hq_ge : 11 ≤ q := (Fact.out : q ≥ 11)
  have : 11 ≤ 4 := le_trans hq_ge hq_le
  exact (by decide : ¬ (11 ≤ 4)) this

/-! # Part 7: Group Structure -/

/-- The AHOP group is generated by the four reflections with involution relations -/
inductive AHOPWord
  | empty : AHOPWord
  | cons : Fin 4 → AHOPWord → AHOPWord

/-- Apply a word to a quadruple -/
def applyWord {q : ℕ} [Fact (0 < q)] : AHOPWord → (Fin 4 → ZMod q) → (Fin 4 → ZMod q)
  | AHOPWord.empty, k => k
  | AHOPWord.cons i w, k => reflect i (applyWord w k)

/-- Word application preserves Apollonian property -/
theorem applyWord_preserves_apollonian {q : ℕ} [Fact (0 < q)] [Fact (q > 2)]
    (w : AHOPWord) (k : Fin 4 → ZMod q) (hk : IsApollonian k) :
    IsApollonian (applyWord w k) := by
  induction w with
  | empty => exact hk
  | cons i w ih => exact reflect_preserves_apollonian i _ ih

/-! # Part 8: AHOP Problem Definition -/

/-- The orbit of k under all reflection sequences -/
def orbit {q : ℕ} [Fact (0 < q)] (k : Fin 4 → ZMod q) : Set (Fin 4 → ZMod q) :=
  { k' | ∃ w : AHOPWord, applyWord w k = k' }

/-- AHOP Instance: Given k_start, k_target in same orbit, find the word -/
structure AHOPInstance (q : ℕ) [Fact (0 < q)] where
  k_start : Fin 4 → ZMod q
  k_target : Fin 4 → ZMod q
  h_start_apollonian : IsApollonian k_start
  h_target_apollonian : IsApollonian k_target
  h_in_orbit : k_target ∈ orbit k_start

/-- An AHOP solution is a word that navigates from start to target -/
def AHOPSolution {q : ℕ} [Fact (0 < q)] (inst : AHOPInstance q) :=
  { w : AHOPWord // applyWord w inst.k_start = inst.k_target }

end KElimination.AHOP

/-! # Verification Summary -/

/-
  AHOP/Algebra.lean STATUS:

  PROVEN (no sorry):
  - descartesForm_expanded: Algebraic expansion of Descartes form
  - reflect_eq_reflect': Two formulations are equivalent
  - reflect_involution: S_i ∘ S_i = id (pure algebra)
  - sum_after_reflect: Sum transformation under reflection
  - reflect_preserves_apollonian: Q(k)=0 ⟹ Q(S_i(k))=0 ★ KEY THEOREM ★
  - applyWord_preserves_apollonian: Words preserve Apollonian property
  - reflects_noncommutative: Explicit counterexample (non-commutative)

  SORRY COUNT: 0

  KEY INSIGHT PROVEN:
  The Descartes relation Q(k) = (∑kᵢ)² - 2∑kᵢ² = 0 is ALGEBRAIC.
  Reflection operators preserve this invariant in ANY ring where 2 is invertible.
  This DIRECTLY REFUTES the claim that AHOP "doesn't work in finite fields".

  The mathematics is ring theory, not geometry.
-/
