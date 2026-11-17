import Std

/-!
Exact resolution of arbitrary finite collections of positive anchor moduli.
The computed LCM and GCD identify the observation kernel. Repeated, composite,
overlapping and empty anchor lists are allowed; no pairwise coprimality is used.
These are mathematical capacity/kernel theorems, not a fusion implementation.
-/

namespace KElimination.CoupledAnchors

/-- Empty observations impose no restriction: their LCM is one. -/
def anchorLCM : List Nat → Nat
  | [] => 1
  | a :: rest => Nat.lcm a (anchorLCM rest)

def resolution (M : Nat) (anchors : List Nat) : Nat :=
  anchorLCM anchors / Nat.gcd M (anchorLCM anchors)

theorem anchor_lcm_dvd_iff (anchors : List Nat) (n : Nat) :
    anchorLCM anchors ∣ n ↔ ∀ a ∈ anchors, a ∣ n := by
  induction anchors with
  | nil => simp [anchorLCM]
  | cons a rest ih => simp [anchorLCM, Nat.lcm_dvd_iff, ih]

theorem anchor_lcm_pos (anchors : List Nat)
    (hpos : ∀ a ∈ anchors, 0 < a) : 0 < anchorLCM anchors := by
  induction anchors with
  | nil => decide
  | cons a rest ih =>
    exact Nat.lcm_pos (hpos a (by simp))
      (ih (fun b hb => hpos b (by simp [hb])))

theorem nat_reduced_kernel (M A v : Nat) (hA : 0 < A) :
    A ∣ M * v ↔ A / Nat.gcd M A ∣ v := by
  rw [Nat.div_dvd_iff_dvd_mul (Nat.gcd_dvd_right M A)
    (Nat.gcd_pos_of_pos_right M hA)]
  rw [Nat.gcd_comm M A, Nat.dvd_gcd_mul_iff_dvd_mul]

/-- Signed coordinate changes have exactly the same reduced period. -/
theorem int_reduced_kernel (M A : Nat) (delta : Int) (hA : 0 < A) :
    (A : Int) ∣ (M : Int) * delta ↔
      ((A / Nat.gcd M A : Nat) : Int) ∣ delta := by
  simpa only [Int.ofNat_dvd_left, Int.natAbs_mul, Int.natAbs_natCast] using
    nat_reduced_kernel M A delta.natAbs hA

theorem anchor_lcm_int_dvd_iff (anchors : List Nat) (n : Int) :
    (anchorLCM anchors : Int) ∣ n ↔ ∀ a ∈ anchors, (a : Int) ∣ n := by
  simpa only [Int.ofNat_dvd_left] using anchor_lcm_dvd_iff anchors n.natAbs

/-- Complete combined kernel: all anchor differences vanish iff the reduced
LCM divides the coordinate difference. This is necessary and sufficient. -/
theorem combined_kernel (M : Nat) (anchors : List Nat) (delta : Int)
    (hpos : ∀ a ∈ anchors, 0 < a) :
    (∀ a ∈ anchors, (a : Int) ∣ (M : Int) * delta) ↔
      (resolution M anchors : Int) ∣ delta := by
  rw [← anchor_lcm_int_dvd_iff]
  exact int_reduced_kernel M (anchorLCM anchors) delta (anchor_lcm_pos anchors hpos)

theorem resolution_pos (M : Nat) (anchors : List Nat)
    (hpos : ∀ a ∈ anchors, 0 < a) : 0 < resolution M anchors :=
  Nat.div_gcd_pos_of_pos_right M (anchor_lcm_pos anchors hpos)

/-- The full source ambiguity period is exactly the LCM including the main
modulus. Its multiplication by resolution does not overcount shared factors. -/
theorem source_period (M : Nat) (anchors : List Nat) :
    M * resolution M anchors = Nat.lcm M (anchorLCM anchors) := by
  unfold resolution
  rw [← Nat.mul_div_assoc M (Nat.gcd_dvd_right M (anchorLCM anchors))]
  rfl

theorem combined_kernel_two (M A B : Nat) (delta : Int)
    (hA : 0 < A) (hB : 0 < B) :
    ((A : Int) ∣ (M : Int) * delta ∧ (B : Int) ∣ (M : Int) * delta) ↔
      ((Nat.lcm A B / Nat.gcd M (Nat.lcm A B) : Nat) : Int) ∣ delta := by
  simpa [anchorLCM, resolution] using combined_kernel M [A, B] delta
    (by intro a ha; simp at ha
        rcases ha with rfl | rfl <;> assumption)

theorem combined_kernel_as_lcm_of_resolutions
    (M : Nat) (anchors : List Nat) (delta : Int)
    (hpos : ∀ a ∈ anchors, 0 < a) :
    (resolution M anchors : Int) ∣ delta ↔
      (anchorLCM (anchors.map (fun a => a / Nat.gcd M a)) : Int) ∣ delta := by
  rw [← combined_kernel M anchors delta hpos, anchor_lcm_int_dvd_iff]
  constructor
  · intro hall a ha
    obtain ⟨b, hb, rfl⟩ := List.mem_map.mp ha
    exact (int_reduced_kernel M b delta (hpos b hb)).mp (hall b hb)
  · intro hall a ha
    apply (int_reduced_kernel M a delta (hpos a ha)).mpr
    exact hall _ (List.mem_map.mpr ⟨a, ha, rfl⟩)

/-- The coupled resolution law, as an equality of actual computed naturals. -/
theorem resolution_eq_lcm_reduced (M : Nat) (anchors : List Nat)
    (hpos : ∀ a ∈ anchors, 0 < a) :
    resolution M anchors = anchorLCM (anchors.map (fun a => a / Nat.gcd M a)) := by
  apply Nat.dvd_antisymm
  · apply Int.ofNat_dvd.mp
    exact (combined_kernel_as_lcm_of_resolutions M anchors _ hpos).mpr (Int.dvd_refl _)
  · apply Int.ofNat_dvd.mp
    exact (combined_kernel_as_lcm_of_resolutions M anchors _ hpos).mp (Int.dvd_refl _)

/-- Equality of the actual affine source readings has the computed kernel. -/
theorem same_affine_readings_iff (M : Nat) (anchors : List Nat) (r k j : Int)
    (hpos : ∀ a ∈ anchors, 0 < a) :
    (∀ a ∈ anchors, (r + (M : Int) * k) % a = (r + (M : Int) * j) % a) ↔
      (resolution M anchors : Int) ∣ k - j := by
  rw [← combined_kernel M anchors (k - j) hpos]
  apply forall_congr'
  intro a
  apply forall_congr'
  intro _
  rw [Int.emod_eq_emod_iff_emod_sub_eq_zero, ← Int.dvd_iff_emod_eq_zero]
  have heq : r + (M : Int) * k - (r + (M : Int) * j) = (M : Int) * (k - j) := by grind
  rw [heq]

/-- A common half-open signed window of width R makes the coordinate unique.
The bound is on coordinates, and no scalar source is constructed. -/
theorem signed_window_unique (M : Nat) (anchors : List Nat) (r k j lo : Int)
    (hpos : ∀ a ∈ anchors, 0 < a)
    (hklo : lo ≤ k) (hkhi : k < lo + resolution M anchors)
    (hjlo : lo ≤ j) (hjhi : j < lo + resolution M anchors)
    (hread : ∀ a ∈ anchors,
      (r + (M : Int) * k) % a = (r + (M : Int) * j) % a) : k = j := by
  have hdiv := (same_affine_readings_iff M anchors r k j hpos).mp hread
  have hshift : (k - lo) - (j - lo) = k - j := by omega
  have hmod : (k - lo) % resolution M anchors = (j - lo) % resolution M anchors := by
    apply Int.emod_eq_emod_iff_emod_sub_eq_zero.mpr
    rw [hshift]
    exact Int.emod_eq_zero_of_dvd hdiv
  rw [Int.emod_eq_of_lt (by omega) (by omega),
      Int.emod_eq_of_lt (by omega) (by omega)] at hmod
  omega

/-- Exact criterion for a target modulus to ignore a coordinate period.
Necessity compares coordinates R and zero; sufficiency transports divisibility.
This is a statement for all integer coordinates, with a fixed reference. -/
theorem target_period_iff (M R b : Nat) (r : Int) :
    (∀ k j : Int, (R : Int) ∣ k - j →
      (r + (M : Int) * k) % b = (r + (M : Int) * j) % b) ↔
      b ∣ M * R := by
  constructor
  · intro hall
    have hread := hall (R : Int) 0 (by simp)
    have hzero := Int.emod_eq_emod_iff_emod_sub_eq_zero.mp hread
    have hdiff : r + (M : Int) * R - (r + (M : Int) * 0) = (M : Int) * R := by grind
    rw [hdiff] at hzero
    have hdiv := Int.dvd_of_emod_eq_zero hzero
    exact Int.ofNat_dvd.mp (by simpa only [Int.natCast_mul] using hdiv)
  · intro hperiod k j hdelta
    apply Int.emod_eq_emod_iff_emod_sub_eq_zero.mpr
    apply Int.emod_eq_zero_of_dvd
    obtain ⟨v, hv⟩ := hperiod
    obtain ⟨z, hz⟩ := hdelta
    refine ⟨(v : Int) * z, ?_⟩
    have hc : (M : Int) * R = (b : Int) * v := by exact_mod_cast hv
    grind

/-- Direct target recoverability for the exact combined-anchor kernel. -/
theorem combined_target_iff (M b : Nat) (anchors : List Nat) (r : Int)
    (hpos : ∀ a ∈ anchors, 0 < a) :
    (∀ k j : Int,
      (∀ a ∈ anchors, (r + (M : Int) * k) % a = (r + (M : Int) * j) % a) →
      (r + (M : Int) * k) % b = (r + (M : Int) * j) % b) ↔
      b ∣ Nat.lcm M (anchorLCM anchors) := by
  rw [← source_period M anchors, ← target_period_iff M (resolution M anchors) b r]
  constructor
  · intro hall k j hdelta
    exact hall k j ((same_affine_readings_iff M anchors r k j hpos).mpr hdelta)
  · intro hall k j hread
    exact hall k j ((same_affine_readings_iff M anchors r k j hpos).mp hread)

/-- Resolution is itself an invisible positive coordinate change, and every
positive invisible change is at least as large. -/
theorem resolution_minimal (M : Nat) (anchors : List Nat)
    (hpos : ∀ a ∈ anchors, 0 < a) :
    (∀ a ∈ anchors, a ∣ M * resolution M anchors) ∧
    (∀ v : Nat, 0 < v → (∀ a ∈ anchors, a ∣ M * v) → resolution M anchors ≤ v) := by
  constructor
  · intro a ha
    have hk := (combined_kernel M anchors (resolution M anchors) hpos).mpr (Int.dvd_refl _)
    exact Int.ofNat_dvd.mp (by simpa only [Int.natCast_mul] using hk a ha)
  · intro v hv hvanish
    have hk : (resolution M anchors : Int) ∣ (v : Int) := by
      apply (combined_kernel M anchors v hpos).mp
      intro a ha
      exact_mod_cast hvanish a ha
    exact Nat.le_of_dvd hv (Int.ofNat_dvd.mp hk)

/-- Complete equality criterion for actual residue observations. -/
theorem source_readings_iff (anchors : List Nat) (X Y : Int) :
    (∀ a ∈ anchors, X % a = Y % a) ↔ (anchorLCM anchors : Int) ∣ X - Y := by
  rw [anchor_lcm_int_dvd_iff]
  apply forall_congr'
  intro a
  apply forall_congr'
  intro _
  rw [Int.emod_eq_emod_iff_emod_sub_eq_zero, ← Int.dvd_iff_emod_eq_zero]

/-- The main lane plus all anchors distinguish sources exactly modulo MR.
This proves the observation period, beyond the numerical LCM identity. -/
theorem main_and_anchor_readings_iff (M : Nat) (anchors : List Nat) (X Y : Int) :
    (X % M = Y % M ∧ ∀ a ∈ anchors, X % a = Y % a) ↔
      ((M * resolution M anchors : Nat) : Int) ∣ X - Y := by
  rw [source_period]
  simpa [anchorLCM] using source_readings_iff (M :: anchors) X Y

/-- A further anchor whose modulus already divides the existing LCM adds no
resolution. Repeated or dependent lanes are not counted as fresh capacity. -/
theorem dependent_anchor_resolution (M a : Nat) (anchors : List Nat)
    (hdependent : a ∣ anchorLCM anchors) :
    resolution M (a :: anchors) = resolution M anchors := by
  simp only [resolution, anchorLCM, Nat.lcm_eq_right hdependent]

end KElimination.CoupledAnchors

#print axioms KElimination.CoupledAnchors.anchor_lcm_dvd_iff
#print axioms KElimination.CoupledAnchors.anchor_lcm_pos
#print axioms KElimination.CoupledAnchors.nat_reduced_kernel
#print axioms KElimination.CoupledAnchors.int_reduced_kernel
#print axioms KElimination.CoupledAnchors.anchor_lcm_int_dvd_iff
#print axioms KElimination.CoupledAnchors.combined_kernel
#print axioms KElimination.CoupledAnchors.resolution_pos
#print axioms KElimination.CoupledAnchors.source_period
#print axioms KElimination.CoupledAnchors.combined_kernel_two
#print axioms KElimination.CoupledAnchors.combined_kernel_as_lcm_of_resolutions
#print axioms KElimination.CoupledAnchors.resolution_eq_lcm_reduced
#print axioms KElimination.CoupledAnchors.same_affine_readings_iff
#print axioms KElimination.CoupledAnchors.signed_window_unique
#print axioms KElimination.CoupledAnchors.target_period_iff
#print axioms KElimination.CoupledAnchors.combined_target_iff
#print axioms KElimination.CoupledAnchors.resolution_minimal
#print axioms KElimination.CoupledAnchors.source_readings_iff
#print axioms KElimination.CoupledAnchors.main_and_anchor_readings_iff
#print axioms KElimination.CoupledAnchors.dependent_anchor_resolution
