/-
  Shadow Entropy core identities.

  This models the quotient ("shadow") and residue from modular arithmetic,
  aligning with entropy/crt_shadow.rs.
-/

import Mathlib.Data.Nat.Basic
import Mathlib.Data.Nat.Log
import Mathlib.Tactic

namespace KElimination.ShadowEntropy

/-- Shadow (quotient) from a * b divided by m. -/
def shadow (a b m : Nat) : Nat := (a * b) / m

/-- Result (residue) from a * b mod m. -/
def result (a b m : Nat) : Nat := (a * b) % m

/-- Shadow + result reconstructs the original product. -/
theorem shadow_reconstruction (a b m : Nat) :
    a * b = shadow a b m * m + result a b m := by
  simpa [shadow, result] using (Nat.div_add_mod' (a * b) m).symm

/-- Shadow is bounded by the modulus when a,b < m. -/
theorem shadow_bounded (a b m : Nat) (hm : m > 0) (ha : a < m) (hb : b < m) :
    shadow a b m < m := by
  have hprod : a * b < m * m := by
    nlinarith
  exact (Nat.div_lt_iff_lt_mul hm).2 hprod

/-- Quotient range for bounded inputs: if x < m * n then x / m < n. -/
theorem quotient_range (x m n : Nat) (hm : m > 0) (hx : x < m * n) :
    x / m < n := by
  exact (Nat.div_lt_iff_lt_mul hm).2 (by
    simpa [Nat.mul_comm, Nat.mul_left_comm, Nat.mul_assoc] using hx)

/-- Standard division decomposition within bounds. -/
theorem div_mod_decomp (x m n : Nat) (hm : m > 0) (hx : x < m * n) :
    ∃ q r, q < n ∧ r < m ∧ x = q * m + r := by
  refine ⟨x / m, x % m, ?_, Nat.mod_lt _ hm, ?_⟩
  · exact quotient_range x m n hm hx
  · have h := Nat.div_add_mod' x m
    simpa [Nat.mul_comm, Nat.mul_left_comm, Nat.mul_assoc] using h.symm

/-- Entropy bits as log2 of the modulus (model). -/
def shadow_entropy_bits (m : Nat) : Nat := Nat.log2 m

/-- log2(m) is positive for m > 1. -/
theorem shadow_entropy_bits_pos (m : Nat) (hm : 1 < m) :
    0 < shadow_entropy_bits m := by
  have hm0 : m ≠ 0 := by
    exact Nat.ne_of_gt (lt_trans (by decide : 0 < 1) hm)
  have h1 : 1 ≤ Nat.log2 m := by
    exact (Nat.le_log2 hm0).2 (by simpa using hm)
  exact lt_of_lt_of_le (by decide : 0 < 1) h1

end KElimination.ShadowEntropy
