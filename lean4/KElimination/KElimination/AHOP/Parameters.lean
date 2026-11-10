/-
  AHOP Parameter Validation

  This file encodes a historical target tuple and arithmetic sanity proofs.
  Numeric labels and estimates are not cryptographic security or orbit-size proofs.

  Date: 2026-02-04
  Status: Ported from SwarmProofs to NINE65 v5
-/

import Mathlib.Data.Nat.Prime.Basic
import Mathlib.Data.Nat.Basic
import Mathlib.Tactic.NormNum
import Mathlib.Tactic.NormNum.Prime
import Mathlib.Tactic.ReduceModChar
import Mathlib.NumberTheory.LucasPrimality

namespace KElimination.AHOP.Parameters

/-! The following Lucas certificates use the existing library theorem and
kernel-checked modular exponentiation, avoiding `native_decide` compiler trust.
They establish primality only, not cryptographic strength. -/

private theorem prime_486391 : Nat.Prime 486391 := by
  apply lucas_primality 486391 (3 : ZMod 486391)
  · reduce_mod_char
  · intro r hr hdiv
    have h2 : Nat.Prime 2 := by norm_num
    have h3 : Nat.Prime 3 := by norm_num
    have h5 : Nat.Prime 5 := by norm_num
    have h31 : Nat.Prime 31 := by norm_num
    have h523 : Nat.Prime 523 := by norm_num
    have hfactor : 486391 - 1 = 2 * 3 * 5 * 31 * 523 := by norm_num
    rw [hfactor] at hdiv
    simp only [hr.dvd_mul,
      Nat.prime_dvd_prime_iff_eq hr h2,
      Nat.prime_dvd_prime_iff_eq hr h3,
      Nat.prime_dvd_prime_iff_eq hr h5,
      Nat.prime_dvd_prime_iff_eq hr h31,
      Nat.prime_dvd_prime_iff_eq hr h523] at hdiv
    simp only [or_assoc] at hdiv
    rcases hdiv with rfl | rfl | rfl | rfl | rfl <;> reduce_mod_char <;> decide

private theorem prime_246912443 : Nat.Prime 246912443 := by
  apply lucas_primality 246912443 (2 : ZMod 246912443)
  · reduce_mod_char
  · intro r hr hdiv
    have h2 : Nat.Prime 2 := by norm_num
    have h7 : Nat.Prime 7 := by norm_num
    have h2239 : Nat.Prime 2239 := by norm_num
    have h7877 : Nat.Prime 7877 := by norm_num
    have hfactor : 246912443 - 1 = 2 * 7 * 2239 * 7877 := by norm_num
    rw [hfactor] at hdiv
    simp only [hr.dvd_mul,
      Nat.prime_dvd_prime_iff_eq hr h2,
      Nat.prime_dvd_prime_iff_eq hr h7,
      Nat.prime_dvd_prime_iff_eq hr h2239,
      Nat.prime_dvd_prime_iff_eq hr h7877] at hdiv
    simp only [or_assoc] at hdiv
    rcases hdiv with rfl | rfl | rfl | rfl <;> reduce_mod_char <;> decide

private theorem prime_18014398509481951 : Nat.Prime 18014398509481951 := by
  apply lucas_primality 18014398509481951 (3 : ZMod 18014398509481951)
  · reduce_mod_char
  · intro r hr hdiv
    have h2 : Nat.Prime 2 := by norm_num
    have h3 : Nat.Prime 3 := by norm_num
    have h5 : Nat.Prime 5 := by norm_num
    have h486391 : Nat.Prime 486391 := prime_486391
    have h246912443 : Nat.Prime 246912443 := prime_246912443
    have hfactor : 18014398509481951 - 1 = 2 * 3 * 5 * 5 * 486391 * 246912443 := by norm_num
    rw [hfactor] at hdiv
    simp only [hr.dvd_mul,
      Nat.prime_dvd_prime_iff_eq hr h2,
      Nat.prime_dvd_prime_iff_eq hr h3,
      Nat.prime_dvd_prime_iff_eq hr h5,
      Nat.prime_dvd_prime_iff_eq hr h486391,
      Nat.prime_dvd_prime_iff_eq hr h246912443] at hdiv
    simp only [or_assoc] at hdiv
    rcases hdiv with rfl | rfl | rfl | rfl | rfl | rfl <;> reduce_mod_char <;> decide

/-- Historical target parameter bundle (integer-only); no security admission. -/
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
    q_prime := prime_18014398509481951
    sigma_pos := ⟨by norm_num, by norm_num⟩ }

/-- Arithmetic sanity checks only. The legacy name does not assert 128-bit security. -/
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
  norm_num [params_128bit]

/-- Numerical estimate only: no theorem here connects `q*q` to an actual orbit. -/
def orbitLowerBound (q : Nat) : Nat := q * q

theorem params_128bit_orbit_lower_bound :
    orbitLowerBound params_128bit.q ≥ 2^106 := by
  norm_num [params_128bit, orbitLowerBound]

/-- Numerical estimate only: not a bound on any quantum algorithm or success probability. -/
def quantumLowerBound (q : Nat) : Nat := q

theorem params_128bit_quantum_lower_bound :
    quantumLowerBound params_128bit.q ≥ 2^53 := by
  norm_num [params_128bit, quantumLowerBound]

/-- Parameters are integer-only by construction. -/
theorem params_integer_only (p : AHOPParams) :
    p.n ≥ 0 ∧ p.q ≥ 0 ∧ p.sigma_num ≥ 0 ∧ p.sigma_den ≥ 0 := by
  exact ⟨Nat.zero_le _, Nat.zero_le _, Nat.zero_le _, Nat.zero_le _⟩

end KElimination.AHOP.Parameters
