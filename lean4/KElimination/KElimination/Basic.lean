/-
  K-Elimination Basic Definitions

  Core definitions without Mathlib dependencies for quick checking.
-/

namespace KElimination.Basic

/-- The overflow count k = floor(X / M) -/
def overflow (X M : Nat) : Nat := X / M

/-- Main residue v_M = X mod M -/
def mainRes (X M : Nat) : Nat := X % M

/-- Anchor residue v_A = X mod A -/
def anchorRes (X A : Nat) : Nat := X % A

/-- Fundamental identity: X = v_M + k * M -/
theorem fundamental (X M : Nat) (hM : M > 0) :
    X = mainRes X M + overflow X M * M := by
  simp [mainRes, overflow]
  omega

/-- Residue is less than modulus -/
theorem res_lt (X M : Nat) (hM : M > 0) : mainRes X M < M := by
  simp [mainRes]
  exact Nat.mod_lt X hM

/-- k range for bounded X -/
theorem overflow_range (X M A : Nat) (hM : M > 0) (hX : X < M * A) :
    overflow X M < A := by
  simp [overflow]
  have h := Nat.div_lt_iff_lt_mul hM
  rw [h]
  exact hX

end KElimination.Basic
