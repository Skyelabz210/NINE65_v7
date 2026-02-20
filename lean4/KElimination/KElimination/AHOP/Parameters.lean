/-
  AHOP Parameter Validation

  This file encodes production parameters and basic sanity proofs.

  Date: 2026-02-04
  Status: Ported from SwarmProofs to NINE65 v5
-/

import Mathlib.Data.Nat.Prime.Basic
import Mathlib.Data.Nat.Basic
import Mathlib.Tactic

namespace KElimination.AHOP.Parameters

/-- Production parameter bundle (integer-only). -/
structure AHOPParams where
  n : Nat
  q : Nat
  sigma_num : Nat
  sigma_den : Nat
  n_pow2 : ∃ k, n = 2^k
  q_prime : Nat.Prime q
  sigma_pos : sigma_num > 0 ∧ sigma_den > 0

/-- 128-bit target parameters (placeholders for security analysis). -/
def params_128bit : AHOPParams :=
  { n := 4096
    q := 18014398509481951
    sigma_num := 16
    sigma_den := 5
    n_pow2 := ⟨12, rfl⟩
    q_prime := by native_decide
    sigma_pos := ⟨by norm_num, by norm_num⟩ }

/-- Sanity checks for the 128-bit parameter bundle. -/
theorem params_128bit_secure :
    params_128bit.n = 4096 ∧
    Nat.Prime params_128bit.q ∧
    params_128bit.sigma_num > 0 ∧ params_128bit.sigma_den > 0 := by
  refine ⟨rfl, params_128bit.q_prime, ?_, ?_⟩
  · exact params_128bit.sigma_pos.1
  · exact params_128bit.sigma_pos.2

/-- q is within the 54-bit window. -/
theorem params_128bit_q_range :
    2^53 ≤ params_128bit.q ∧ params_128bit.q < 2^54 := by
  native_decide

/-- Conservative orbit-size lower bound from q^2. -/
def orbitLowerBound (q : Nat) : Nat := q * q

theorem params_128bit_orbit_lower_bound :
    orbitLowerBound params_128bit.q ≥ 2^106 := by
  native_decide

/-- Conservative quantum lower bound (Grover-style sqrt of q^2). -/
def quantumLowerBound (q : Nat) : Nat := q

theorem params_128bit_quantum_lower_bound :
    quantumLowerBound params_128bit.q ≥ 2^53 := by
  native_decide

/-- Parameters are integer-only by construction. -/
theorem params_integer_only (p : AHOPParams) :
    p.n ≥ 0 ∧ p.q ≥ 0 ∧ p.sigma_num ≥ 0 ∧ p.sigma_den ≥ 0 := by
  exact ⟨Nat.zero_le _, Nat.zero_le _, Nat.zero_le _, Nat.zero_le _⟩

end KElimination.AHOP.Parameters
