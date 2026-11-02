import Std

/-!
# Bounded signed lift for the research native public-refresh producer

This file proves exact integer facts for the producer parameters p=65537,
support H=96, and residual radius 49. It separates the residual rho from the
signed quotient K. These are arithmetic theorems; they do not prove that a Rust
value has the stated producer relation or establish sparse/joint-key security.
-/

namespace KElimination.PublicRefreshNativeLift

/-- Integer summation, retaining the complete signed phase expression. -/
def phaseSum : List Int → Int
  | [] => 0
  | x :: xs => x + phaseSum xs

/-- Negacyclic sign changes and multiplication by a ternary secret preserve
the centered public digit bound. -/
theorem ternary_term_bound (digit secret : Int)
    (hd : -32768 ≤ digit ∧ digit ≤ 32768)
    (hs : secret = -1 ∨ secret = 0 ∨ secret = 1) :
    -32768 ≤ digit * secret ∧ digit * secret ≤ 32768 := by
  rcases hs with hs | hs | hs
  · subst secret
    simp only [Int.mul_neg, Int.mul_one]
    omega
  · subst secret
    simp
  · subst secret
    simp only [Int.mul_one]
    exact hd

theorem phase_sum_bound (terms : List Int)
    (h : ∀ term ∈ terms, -32768 ≤ term ∧ term ≤ 32768) :
    -32768 * (terms.length : Int) ≤ phaseSum terms ∧
      phaseSum terms ≤ 32768 * (terms.length : Int) := by
  induction terms with
  | nil => simp [phaseSum]
  | cons term rest ih =>
    have ht := h term (by simp)
    have hr := ih (by intro x hx; exact h x (by simp [hx]))
    simp only [phaseSum, List.length_cons, Int.natCast_add, Int.natCast_one]
    omega

/-- H=96 nonzero ternary terms plus d0 give D=97*32768=3178496.
Zero secret positions contribute nothing and need not be stored in this list.
-/
theorem native_source_norm (d0 : Int) (terms : List Int)
    (hlen : terms.length = 96)
    (hd0 : -32768 ≤ d0 ∧ d0 ≤ 32768)
    (hterms : ∀ term ∈ terms, -32768 ≤ term ∧ term ≤ 32768) :
    -3178496 ≤ d0 + phaseSum terms ∧ d0 + phaseSum terms ≤ 3178496 := by
  have hsum := phase_sum_bound terms hterms
  rw [hlen] at hsum
  omega

/-- The residual radius 49 and phase norm D imply quotient radius 48.
The residual is not identified with the quotient. -/
theorem signed_quotient_radius (x rho k : Int)
    (hx : -3178496 ≤ x ∧ x ≤ 3178496)
    (hrho : -49 ≤ rho ∧ rho ≤ 49)
    (hphase : x = rho + 65537 * k) :
    -48 ≤ k ∧ k ≤ 48 := by
  omega

/-- Centered p² phase residues determine x uniquely within the source norm. -/
theorem source_phase_lift_unique (x y : Int)
    (hx : -3178496 ≤ x ∧ x ≤ 3178496)
    (hy : -3178496 ≤ y ∧ y ≤ 3178496)
    (hresidue : x % 4295098369 = y % 4295098369) : x = y := by
  omega

/-- The extracted K mod p has exactly one signed representative in [-48,48]. -/
theorem signed_quotient_lift_unique (a b : Int)
    (ha : -48 ≤ a ∧ a ≤ 48) (hb : -48 ≤ b ∧ b ≤ 48)
    (hresidue : a % 65537 = b % 65537) : a = b := by
  omega

/-- The norm/support class reaches K=48 without exceeding any digit bound. -/
theorem quotient_radius_sharp :
    48 + (96 : Int) * 32768 = 65537 * 48 ∧
    -32768 ≤ (48 : Int) ∧ (48 : Int) ≤ 32768 := by
  decide

/-- Shift the entire signed quotient interval into the 97-element query domain. -/
theorem shifted_quotient_domain (k : Int) (hk : -48 ≤ k ∧ k ≤ 48) :
    0 ≤ k + 48 ∧ k + 48 ≤ 96 := by
  omega

/-- For authentic same-source 36/37 residue views of Y in [0,96], the on-demand
query returns the exact sheet, rather than merely a residue of that sheet. -/
theorem pair_query_exact (y : Int) (hy : 0 ≤ y ∧ y ≤ 96) :
    (y % 36 - y % 37) % 37 = y / 36 ∧
    0 ≤ (y % 36 - y % 37) % 37 ∧
    (y % 36 - y % 37) % 37 ≤ 2 := by
  have hnonneg : 0 ≤ y / 36 := by omega
  have htwo : y / 36 ≤ 2 := by omega
  have hdecomp : y % 36 - y % 37 = y / 36 + 37 * (y / 37 - y / 36) := by
    omega
  rw [hdecomp, Int.add_mul_emod_self_left]
  rw [Int.emod_eq_of_lt hnonneg (by omega)]
  exact ⟨rfl, hnonneg, htwo⟩

/-- This materialization is a proof identity; it is not required at runtime. -/
theorem pair_query_materialization (y : Int) (hy : 0 ≤ y ∧ y ≤ 96) :
    y % 36 + 36 * ((y % 36 - y % 37) % 37) = y := by
  have hquery := pair_query_exact y hy
  omega

/-- Direct target-residue emission from the same-source query, without a
persistent winding ledger. Arithmetic equality does not establish provenance.
-/
theorem pair_query_target_residue (y b : Int) (hy : 0 ≤ y ∧ y ≤ 96) :
    (y % 36 % b + (36 % b) * (((y % 36 - y % 37) % 37) % b) - 48 % b) % b =
      (y - 48) % b := by
  have hmaterial := pair_query_materialization y hy
  calc
    _ = ((y % 36 + 36 * ((y % 36 - y % 37) % 37)) % b - 48 % b) % b := by
      rw [Int.add_emod (y % 36) (36 * ((y % 36 - y % 37) % 37)) b,
        Int.mul_emod 36 ((y % 36 - y % 37) % 37) b]
      simp only [Int.add_emod_emod, Int.emod_sub_emod]
    _ = (y % 36 + 36 * ((y % 36 - y % 37) % 37) - 48) % b :=
      (Int.sub_emod _ 48 b).symm
    _ = (y - 48) % b := by rw [hmaterial]

end KElimination.PublicRefreshNativeLift
