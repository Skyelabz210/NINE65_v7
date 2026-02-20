/-
  ExactTranscendentals.Basic
  ==========================

  Foundation module for the ExactTranscendentals formalization.
  Establishes shared constants, utility definitions, and documents
  the integer-only axiom that governs the entire library.

  All computations in this project use exact integer arithmetic:
  - Values are represented as v * 2^n (scaled integers)
  - No floating-point types appear in any definition or theorem
  - Only add, subtract, multiply, bit-shift, and exact integer division

  Part of the QMNF ecosystem.
-/

namespace ExactTranscendentals

/-! ## Scale Constants

These are the standard scale factors used across the library.
CORDIC uses 2^30, AGM uses 2^62.
-/

/-- CORDIC scale factor: 2^30 = 1073741824.
    All CORDIC values represent real_value * SCALE_30. -/
def SCALE_30 : Nat := 2^30

/-- AGM / high-precision scale factor: 2^62.
    Used for AGM, binary splitting, and other high-precision computations. -/
def SCALE_62 : Nat := 2^62

/-! ## Utility Definitions -/

/-- Integer absolute difference: |a - b| for natural numbers. -/
def natAbsDiff (a b : Nat) : Nat :=
  if a ≥ b then a - b else b - a

/-- Integer absolute value for Int. -/
def intAbs (x : Int) : Int :=
  if x ≥ 0 then x else -x

/-! ## Basic Properties -/

theorem natAbsDiff_comm (a b : Nat) : natAbsDiff a b = natAbsDiff b a := by
  unfold natAbsDiff
  split <;> split <;> omega

theorem natAbsDiff_self (a : Nat) : natAbsDiff a a = 0 := by
  unfold natAbsDiff
  simp

theorem natAbsDiff_zero_left (a : Nat) : natAbsDiff 0 a = a := by
  unfold natAbsDiff
  by_cases h : a = 0
  · rw [h]
    rw [if_pos (Nat.le_refl 0)]
    simp [Nat.sub_zero]
  · have h_pos : 0 < a := Nat.zero_lt_of_ne_zero h
    rw [if_neg h_pos]
    simp [Nat.sub_zero]

end ExactTranscendentals