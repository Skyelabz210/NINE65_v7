/-
  Exact Coefficient Arithmetic

  Dual-Track RNS with Exact Integer Magnitude

  NINE65 v6 "a Clockwork Prime"
  Ported from Coq: proofs/coq/ExactCoefficient.v
-/

import Mathlib.Data.Nat.Basic
import Mathlib.Tactic

namespace KElimination.ExactCoefficient

/-! # Dual-Track Representation

FHE coefficients need:
1. Fast RNS operations (parallel)
2. Exact integer magnitude (for comparison, scaling)

Traditional: Choose one, lose the other.
SOLUTION: Dual-track representation maintains BOTH invariants.
-/

/-- Dual coefficient: RNS residue + exact integer value -/
structure DualCoeff where
  rns : Nat         -- RNS residue
  exact : Nat       -- Exact integer value
  modulus : Nat     -- RNS modulus

/-- Invariant: RNS residue matches exact value mod modulus -/
def dual_invariant (c : DualCoeff) : Prop :=
  c.rns = c.exact % c.modulus

/-! # Operations -/

/-- Dual addition -/
def dual_add (a b : DualCoeff) : DualCoeff :=
  { rns := (a.rns + b.rns) % a.modulus,
    exact := a.exact + b.exact,
    modulus := a.modulus }

/-- Addition preserves dual invariant -/
theorem add_preserves_invariant (a b : DualCoeff)
    (ha : dual_invariant a) (hb : dual_invariant b)
    (hmod : a.modulus = b.modulus) (hpos : a.modulus > 0) :
    dual_invariant (dual_add a b) := by
  unfold dual_invariant at *
  unfold dual_add
  simp only
  rw [ha, hb, hmod]
  exact (Nat.add_mod _ _ _).symm

/-- Dual multiplication -/
def dual_mul (a b : DualCoeff) : DualCoeff :=
  { rns := (a.rns * b.rns) % a.modulus,
    exact := a.exact * b.exact,
    modulus := a.modulus }

/-- Multiplication preserves dual invariant -/
theorem mul_preserves_invariant (a b : DualCoeff)
    (ha : dual_invariant a) (hb : dual_invariant b)
    (hmod : a.modulus = b.modulus) (hpos : a.modulus > 0) :
    dual_invariant (dual_mul a b) := by
  unfold dual_invariant at *
  unfold dual_mul
  simp only
  rw [ha, hb, hmod]
  exact (Nat.mul_mod _ _ _).symm

/-! # Exact Division via K-Elimination -/

/-- Dual division (when divisor divides exact value) -/
def dual_div (a : DualCoeff) (d : Nat) : DualCoeff :=
  { rns := (a.rns * (a.modulus / d)) % a.modulus,
    exact := a.exact / d,
    modulus := a.modulus }

/-- Division is exact when d divides a.exact -/
theorem div_exact (a : DualCoeff) (d : Nat)
    (hd : d > 0) (hdiv : d ∣ a.exact) :
    (dual_div a d).exact * d = a.exact := by
  unfold dual_div
  simp only
  obtain ⟨k, hk⟩ := hdiv
  rw [hk, Nat.mul_div_cancel_left k hd]
  ring

/-! # Reconstruction -/

/-- Exact value is always available -/
def reconstruct (c : DualCoeff) : Nat := c.exact

/-- Reconstruction matches RNS via modulus -/
theorem reconstruct_correct (c : DualCoeff) (hc : dual_invariant c) :
    reconstruct c % c.modulus = c.rns := by
  unfold reconstruct dual_invariant at *
  exact hc.symm

/-! # Range Tracking -/

/-- Ranged coefficient with upper bound -/
structure RangedCoeff where
  dual : DualCoeff
  max_val : Nat

/-- Value is within tracked range -/
def in_range (c : RangedCoeff) : Prop :=
  c.dual.exact ≤ c.max_val

/-- Addition preserves range bounds -/
theorem add_range (a b : RangedCoeff)
    (ha : in_range a) (hb : in_range b)
    (hmod : a.dual.modulus = b.dual.modulus) :
    in_range { dual := dual_add a.dual b.dual,
               max_val := a.max_val + b.max_val } := by
  unfold in_range at *
  unfold dual_add
  simp only
  omega

/-- Multiplication preserves range bounds -/
theorem mul_range (a b : RangedCoeff)
    (ha : in_range a) (hb : in_range b)
    (hmod : a.dual.modulus = b.dual.modulus) :
    in_range { dual := dual_mul a.dual b.dual,
               max_val := a.max_val * b.max_val } := by
  unfold in_range at *
  unfold dual_mul
  simp only
  exact Nat.mul_le_mul ha hb

end KElimination.ExactCoefficient

/-!
## Verification Summary

SORRY COUNT: 0
STATUS: FULLY VERIFIED

Proved:
1. add_preserves_invariant: Addition maintains RNS = exact mod m
2. mul_preserves_invariant: Multiplication maintains invariant
3. div_exact: Division exact when divisible
4. reconstruct_correct: Reconstruction matches RNS
5. add_range: Addition range tracking
6. mul_range: Multiplication range tracking
-/
