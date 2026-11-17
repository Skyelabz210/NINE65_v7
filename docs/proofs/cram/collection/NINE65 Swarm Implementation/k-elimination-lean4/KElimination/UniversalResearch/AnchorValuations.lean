import Std

/-!
Prime-exponent proof of the factorization-free anchor planner.
The bridge from Nat.gcd/Nat.lcm to actual prime valuations is not assumed here:
these are explicit theorems about the exponent recurrence. The accompanying
written argument supplies that standard arithmetic bridge; this module does
not claim a full formal refinement of the Python gcd loop.
-/

namespace KElimination.AnchorValuations

def requiredExponent (d p : Nat) : Nat := if d ≤ p then 0 else d

def saturate (d initial : Nat) : Nat → Nat
  | 0 => initial
  | n + 1 => min d (2 * saturate d initial n)

/-- This is the exact per-prime capacity condition for D | lcm(P,a). -/
theorem exponent_feasible (d p : Nat) : d ≤ max p (requiredExponent d p) := by
  unfold requiredExponent
  split <;> omega

/-- Any sufficient anchor contains the full demanded exponent at a deficient
prime. It contains no required factor at an already-covered prime. -/
theorem exponent_minimal (d p a : Nat) (h : d ≤ max p a) :
    requiredExponent d p ≤ a := by
  unfold requiredExponent
  split <;> omega

theorem missing_exponent_zero_iff (d p : Nat) : d-p=0 ↔ d≤p := by omega

theorem saturation_zero (d n : Nat) : saturate d 0 n = 0 := by
  induction n with
  | zero => rfl
  | succ n ih => simp [saturate, ih]

theorem saturation_bounded (d initial : Nat) (h : initial ≤ d) (n : Nat) :
    saturate d initial n ≤ d := by
  cases n with
  | zero => exact h
  | succ n => exact Nat.min_le_left _ _

theorem saturation_monotone (d initial : Nat) (h : initial ≤ d) (n : Nat) :
    saturate d initial n ≤ saturate d initial (n+1) := by
  have hb := saturation_bounded d initial h n
  simp only [saturate]
  omega

/-- A positive deficient exponent grows by at least one each strict round,
which gives a conservative explicit finite fuel bound. -/
theorem saturation_lower_bound (d initial : Nat) (hpos : 0<initial)
    (hbound : initial ≤ d) (n : Nat) :
    min d (initial+n) ≤ saturate d initial n := by
  induction n with
  | zero => simp [saturate]; omega
  | succ n ih =>
    have hb := saturation_bounded d initial hbound n
    simp only [saturate]
    omega

theorem positive_saturation_reaches_cap (d initial : Nat)
    (hpos : 0<initial) (hbound : initial ≤ d) :
    saturate d initial d = d := by
  have lo := saturation_lower_bound d initial hpos hbound d
  have hi := saturation_bounded d initial hbound d
  omega

theorem missing_saturation_is_required (d p : Nat) :
    saturate d (d-p) d = requiredExponent d p := by
  by_cases h : d ≤ p
  · have hz : d-p=0 := by omega
    rw [hz, saturation_zero]
    simp [requiredExponent, h]
  · rw [positive_saturation_reaches_cap d (d-p) (by omega) (by omega)]
    simp [requiredExponent, h]

theorem saturation_fixed (d a : Nat) (h : a ≤ d) :
    min d (2*a)=a ↔ a=0 ∨ a=d := by omega

/-- Applied pointwise to all prime exponents, the saturated vector is the
least sufficient extra-anchor vector under divisibility. -/
theorem vector_minimal_sufficient {I : Type} (d p : I → Nat) :
    (∀ i, d i ≤ max (p i) (requiredExponent (d i) (p i))) ∧
    (∀ a : I → Nat, (∀ i, d i ≤ max (p i) (a i)) →
      ∀ i, requiredExponent (d i) (p i) ≤ a i) := by
  exact ⟨fun i => exponent_feasible _ _,
    fun a h i => exponent_minimal _ _ _ (h i)⟩

end KElimination.AnchorValuations

#print axioms KElimination.AnchorValuations.exponent_feasible
#print axioms KElimination.AnchorValuations.exponent_minimal
#print axioms KElimination.AnchorValuations.missing_exponent_zero_iff
#print axioms KElimination.AnchorValuations.saturation_zero
#print axioms KElimination.AnchorValuations.saturation_bounded
#print axioms KElimination.AnchorValuations.saturation_monotone
#print axioms KElimination.AnchorValuations.saturation_lower_bound
#print axioms KElimination.AnchorValuations.positive_saturation_reaches_cap
#print axioms KElimination.AnchorValuations.missing_saturation_is_required
#print axioms KElimination.AnchorValuations.saturation_fixed
#print axioms KElimination.AnchorValuations.vector_minimal_sufficient
