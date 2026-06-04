/-
  MobiusInt: Signed Arithmetic via Möbius Bands

  Symmetric Residues for Natural Signed Representation

  NINE65 v6 "a Clockwork Prime"
  Ported from Coq: proofs/coq/MobiusInt.v
-/

import Mathlib.Data.Nat.Basic
import Mathlib.Tactic

namespace KElimination.MobiusInt

/-! # Symmetric Residue Representation

For modulus m, represent values in [-(m-1)/2, (m-1)/2]
The "twist" at m/2 naturally encodes sign.
-/

/-- Symmetric residue: value in [0, m) with sign determined by threshold -/
structure SymmetricResidue where
  value : Nat
  modulus : Nat

/-- Half modulus: the sign threshold -/
def half_modulus (m : Nat) : Nat := m / 2

/-- Is this residue negative? (value > m/2) -/
def is_negative (sr : SymmetricResidue) : Bool :=
  half_modulus sr.modulus < sr.value

/-- Signed magnitude: distance from 0 or m -/
def to_signed_magnitude (sr : SymmetricResidue) : Nat :=
  if is_negative sr then sr.modulus - sr.value
  else sr.value

/-- Magnitude is bounded by half modulus -/
theorem magnitude_bounded (sr : SymmetricResidue)
    (_hm : sr.modulus > 0) (hv : sr.value < sr.modulus) :
    to_signed_magnitude sr ≤ half_modulus sr.modulus := by
  unfold to_signed_magnitude is_negative half_modulus
  split_ifs with h
  · -- Negative: magnitude = m - v, and v > m/2, so m - v ≤ m/2
    simp only [decide_eq_true_eq] at h
    omega
  · -- Positive: magnitude = v ≤ m/2 by ¬(m/2 < v)
    simp only [decide_eq_true_eq] at h
    omega

/-! # Operations -/

/-- Modular addition of symmetric residues -/
def sr_add (a b : SymmetricResidue) : SymmetricResidue :=
  { value := (a.value + b.value) % a.modulus,
    modulus := a.modulus }

/-- Modular negation -/
def sr_neg (a : SymmetricResidue) : SymmetricResidue :=
  { value := (a.modulus - a.value) % a.modulus,
    modulus := a.modulus }

/-- Negation is involutive: neg(neg(a)) = a -/
theorem neg_involutive (a : SymmetricResidue)
    (_hm : a.modulus > 0) (hv : a.value < a.modulus) (hpos : a.value > 0) :
    (sr_neg (sr_neg a)).value = a.value := by
  unfold sr_neg
  simp only
  -- First negation: (m - v) % m = m - v (since 0 < v < m implies 0 < m - v < m)
  have h1 : (a.modulus - a.value) % a.modulus = a.modulus - a.value :=
    Nat.mod_eq_of_lt (by omega)
  rw [h1]
  -- Second negation: (m - (m - v)) % m = v % m = v
  have h2 : a.modulus - (a.modulus - a.value) = a.value := by omega
  rw [h2]
  exact Nat.mod_eq_of_lt hv

/-! # Sign Detection -/

/-- Sign bit: 1 for negative, 0 for non-negative -/
def sign_bit (sr : SymmetricResidue) : Nat :=
  if is_negative sr then 1 else 0

/-- Negation flips the sign bit (when value ≠ 0 and ≠ m/2) -/
theorem sign_consistent_with_neg (a : SymmetricResidue)
    (_hm : a.modulus > 2) (hpos : a.value > 0)
    (hv : a.value < a.modulus) (hneq : a.value ≠ a.modulus / 2) :
    sign_bit (sr_neg a) = 1 - sign_bit a := by
  unfold sign_bit sr_neg is_negative half_modulus
  simp only
  have hmod : (a.modulus - a.value) % a.modulus = a.modulus - a.value :=
    Nat.mod_eq_of_lt (by omega)
  rw [hmod]
  simp only [decide_eq_true_eq]
  split_ifs with h1 h2
  · -- neg is negative and a is negative: contradiction
    -- a.value > m/2 (negative) → m - a.value < m/2 → neg should be positive
    omega
  · -- neg is negative, a is positive: sign flipped correctly
    rfl
  · -- neg is positive, a is negative: sign flipped correctly
    rfl
  · -- neg is positive, a is positive: contradiction
    -- a.value ≤ m/2 and a.value ≠ m/2 → a.value < m/2 → m - a.value > m/2 → neg is negative
    omega

/-! # Multiplication -/

/-- Modular multiplication -/
def sr_mul (a b : SymmetricResidue) : SymmetricResidue :=
  { value := (a.value * b.value) % a.modulus,
    modulus := a.modulus }

/-- Multiplication result is bounded -/
theorem mul_bounded (a b : SymmetricResidue)
    (hm : a.modulus > 0) :
    (sr_mul a b).value < a.modulus := by
  unfold sr_mul
  simp only
  exact Nat.mod_lt _ hm

/-! # Addition Boundedness -/

/-- Addition result is bounded -/
theorem add_bounded (a b : SymmetricResidue)
    (hm : a.modulus > 0) :
    (sr_add a b).value < a.modulus := by
  unfold sr_add
  simp only
  exact Nat.mod_lt _ hm

/-! # Overflow Detection -/

/-- Near boundary detection -/
def near_boundary (sr : SymmetricResidue) (margin : Nat) : Bool :=
  half_modulus sr.modulus < to_signed_magnitude sr + margin

/-- Boundary detection is correct -/
theorem boundary_detection_correct (sr : SymmetricResidue) (margin : Nat)
    (_hm : sr.modulus > 0) (_hv : sr.value < sr.modulus)
    (hnear : near_boundary sr margin = true) :
    to_signed_magnitude sr + margin > half_modulus sr.modulus := by
  unfold near_boundary at hnear
  exact of_decide_eq_true hnear

/-! # Factored Representation for Large Numbers -/

/-- Power of 10 -/
def pow10 : Nat → Nat
  | 0 => 1
  | n + 1 => 10 * pow10 n

/-- pow10 is positive -/
theorem pow10_pos (n : Nat) : pow10 n > 0 := by
  induction n with
  | zero => simp [pow10]
  | succ n ih => simp [pow10]; omega

/-- pow10 is monotone -/
theorem pow10_mono (n m : Nat) (h : n < m) : pow10 n < pow10 m := by
  induction h with
  | refl => simp [pow10]; have := pow10_pos n; omega
  | step _ ih => simp [pow10]; have := pow10_pos m; omega

end KElimination.MobiusInt

/-!
## Verification Summary

SORRY COUNT: 0
STATUS: FULLY VERIFIED

Proved:
1. magnitude_bounded: Signed magnitude ≤ m/2
2. neg_involutive: Double negation = identity
3. sign_consistent_with_neg: Negation flips sign bit
4. mul_bounded: Multiplication stays in range
5. add_bounded: Addition stays in range
6. pow10_pos/mono: Power-of-10 properties
-/
