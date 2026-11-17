import Mathlib.Data.Nat.Factorization.Basic
import KElimination.UniversalResearch.AnchorValuations

/-!
Actual Nat.gcd/lcm bridge for the factorization-free anchor constructor.
The algorithm uses only division and gcd of public parameters. Factorization
is used in the proof, never as an implementation input.
-/

namespace KElimination.AnchorSaturation

def seed (P D : Nat) : Nat := D / Nat.gcd P D

def iterate (D a : Nat) : Nat → Nat
  | 0 => a
  | n+1 => Nat.gcd D ((iterate D a n) * (iterate D a n))

theorem seed_positive (P D : Nat) (hD : 0<D) : 0<seed P D := by
  unfold seed
  exact Nat.div_pos (Nat.gcd_le_right P hD) (Nat.gcd_pos_of_pos_right P hD)

theorem iterate_positive (D a n : Nat) (hD : 0<D) (ha : 0<a) :
    0<iterate D a n := by
  cases n with
  | zero => exact ha
  | succ n => exact Nat.gcd_pos_of_pos_left _ hD

theorem seed_factorization (P D p : Nat) (hP : P≠0) (hD : D≠0) :
    (seed P D).factorization p = D.factorization p - P.factorization p := by
  unfold seed
  rw [Nat.factorization_div (Nat.gcd_dvd_right P D), Nat.factorization_gcd hP hD]
  simp only [Finsupp.tsub_apply, Finsupp.inf_apply]
  omega

theorem step_factorization (D a p : Nat) (hD : D≠0) (ha : a≠0) :
    (Nat.gcd D (a*a)).factorization p = min (D.factorization p) (2*a.factorization p) := by
  rw [Nat.factorization_gcd hD (Nat.mul_ne_zero ha ha), Nat.factorization_mul ha ha]
  simp only [Finsupp.inf_apply, Finsupp.add_apply]
  omega

theorem iterate_factorization (D a n p : Nat) (hD : 0<D) (ha : 0<a) :
    (iterate D a n).factorization p =
      AnchorValuations.saturate (D.factorization p) (a.factorization p) n := by
  induction n with
  | zero => rfl
  | succ n ih =>
    rw [iterate, step_factorization D _ p hD.ne' (iterate_positive D a n hD ha).ne', ih]
    rfl

theorem saturation_after_bound (d p n : Nat) (h : d≤n) :
    AnchorValuations.saturate d (d-p) n = AnchorValuations.requiredExponent d p := by
  by_cases hdp : d≤p
  · have hz : d-p=0 := by omega
    rw [hz, AnchorValuations.saturation_zero]
    simp [AnchorValuations.requiredExponent, hdp]
  · have lo := AnchorValuations.saturation_lower_bound d (d-p) (by omega) (by omega) n
    have hi := AnchorValuations.saturation_bounded d (d-p) (by omega) n
    simp only [AnchorValuations.requiredExponent, if_neg hdp]
    omega

theorem anchor_factorization (P D n p : Nat) (hP : 0<P) (hD : 0<D)
    (hfuel : D.factorization p ≤ n) :
    (iterate D (seed P D) n).factorization p =
      AnchorValuations.requiredExponent (D.factorization p) (P.factorization p) := by
  rw [iterate_factorization D (seed P D) n p hD (seed_positive P D hD),
    seed_factorization P D p hP.ne' hD.ne']
  exact saturation_after_bound _ _ _ hfuel

/-- Every positive public demand and old period have a least sufficient extra
anchor. The displayed finite gcd program computes it whenever the public fuel
bounds all demand exponents. No prime factorization is used by that program. -/
theorem iterate_is_least_sufficient (P D n : Nat) (hP : 0<P) (hD : 0<D)
    (hfuel : ∀ p, D.factorization p ≤ n) :
    D ∣ Nat.lcm P (iterate D (seed P D) n) ∧
    ∀ b, D ∣ Nat.lcm P b → iterate D (seed P D) n ∣ b := by
  let a := iterate D (seed P D) n
  have ha : a≠0 := (iterate_positive D (seed P D) n hD (seed_positive P D hD)).ne'
  have haf (p : Nat) : a.factorization p =
      AnchorValuations.requiredExponent (D.factorization p) (P.factorization p) :=
    anchor_factorization P D n p hP hD (hfuel p)
  constructor
  · apply (Nat.factorization_le_iff_dvd hD.ne' (Nat.lcm_ne_zero hP.ne' ha)).mp
    intro p
    rw [Nat.factorization_lcm hP.ne' ha]
    simp only [Finsupp.sup_apply]
    rw [haf]
    exact AnchorValuations.exponent_feasible _ _
  · intro b hb
    by_cases hb0 : b=0
    · subst b
      exact Nat.dvd_zero a
    · apply (Nat.factorization_le_iff_dvd ha hb0).mp
      intro p
      have hd := (Nat.factorization_le_iff_dvd hD.ne' (Nat.lcm_ne_zero hP.ne' hb0)).mpr hb
      have hdp := hd p
      rw [Nat.factorization_lcm hP.ne' hb0] at hdp
      simp only [Finsupp.sup_apply] at hdp
      rw [haf]
      exact AnchorValuations.exponent_minimal _ _ _ hdp

/-- A deliberately conservative concrete fuel bound avoids any factorization
input. Faster early stopping may be used once its fixed-point test succeeds. -/
theorem demand_fuel_is_sufficient (P D : Nat) (hP : 0<P) (hD : 0<D) :
    D ∣ Nat.lcm P (iterate D (seed P D) D) ∧
    ∀ b, D ∣ Nat.lcm P b → iterate D (seed P D) D ∣ b := by
  exact iterate_is_least_sufficient P D D hP hD
    (fun p => Nat.le_of_lt (Nat.factorization_lt p hD.ne'))

theorem demand_fuel_is_fixed (P D : Nat) (hP : 0<P) (hD : 0<D) :
    Nat.gcd D ((iterate D (seed P D) D)*(iterate D (seed P D) D)) =
      iterate D (seed P D) D := by
  have ha := (iterate_positive D (seed P D) D hD (seed_positive P D hD)).ne'
  apply Nat.eq_of_factorization_eq (Nat.gcd_pos_of_pos_left _ hD).ne' ha
  intro p
  rw [step_factorization D _ p hD.ne' ha,
    anchor_factorization P D D p hP hD (Nat.le_of_lt (Nat.factorization_lt p hD.ne'))]
  unfold AnchorValuations.requiredExponent
  split <;> omega

theorem iterate_add (D a n m : Nat) :
    iterate D a (n+m) = iterate D (iterate D a n) m := by
  induction m with
  | zero => rfl
  | succ m ih =>
    change Nat.gcd D ((iterate D a (n+m))*(iterate D a (n+m))) =
      Nat.gcd D ((iterate D (iterate D a n) m)*(iterate D (iterate D a n) m))
    rw [ih]

theorem fixed_point_stays (D a n : Nat) (hfixed : Nat.gcd D (a*a)=a) :
    iterate D a n = a := by
  induction n with
  | zero => rfl
  | succ n ih => simp only [iterate, ih, hfixed]

/-- Stopping at any successful fixed-point test yields the same least anchor
as the conservative demand-fuel program. This validates early stopping at the
mathematical recurrence level, without asserting Python source refinement. -/
theorem early_stop_is_least (P D n : Nat) (hP : 0<P) (hD : 0<D)
    (hfixed : Nat.gcd D ((iterate D (seed P D) n)*(iterate D (seed P D) n)) =
      iterate D (seed P D) n) :
    D ∣ Nat.lcm P (iterate D (seed P D) n) ∧
    ∀ b, D ∣ Nat.lcm P b → iterate D (seed P D) n ∣ b := by
  by_cases hDn : D≤n
  · apply iterate_is_least_sufficient P D n hP hD
    intro p
    exact Nat.le_trans (Nat.le_of_lt (Nat.factorization_lt p hD.ne')) hDn
  · have hsplit : D=n+(D-n) := by omega
    have heq : iterate D (seed P D) D = iterate D (seed P D) n := by
      conv_lhs => arg 3; rw [hsplit]
      rw [iterate_add]
      exact fixed_point_stays D _ (D-n) hfixed
    have hleast := demand_fuel_is_sufficient P D hP hD
    rw [heq] at hleast
    exact hleast

end KElimination.AnchorSaturation

#print axioms KElimination.AnchorSaturation.seed_positive
#print axioms KElimination.AnchorSaturation.iterate_positive
#print axioms KElimination.AnchorSaturation.seed_factorization
#print axioms KElimination.AnchorSaturation.step_factorization
#print axioms KElimination.AnchorSaturation.iterate_factorization
#print axioms KElimination.AnchorSaturation.saturation_after_bound
#print axioms KElimination.AnchorSaturation.anchor_factorization
#print axioms KElimination.AnchorSaturation.iterate_is_least_sufficient
#print axioms KElimination.AnchorSaturation.demand_fuel_is_sufficient
#print axioms KElimination.AnchorSaturation.demand_fuel_is_fixed
#print axioms KElimination.AnchorSaturation.iterate_add
#print axioms KElimination.AnchorSaturation.fixed_point_stays
#print axioms KElimination.AnchorSaturation.early_stop_is_least
