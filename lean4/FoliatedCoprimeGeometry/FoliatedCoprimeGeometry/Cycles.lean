import FoliatedCoprimeGeometry.Cocycle

namespace FoliatedCoprimeGeometry

section CycleClassification

variable {M A : Nat} (hM : 0 < M) (hA : 0 < A)

/-- Exact cycle length `M · (A / gcd(A, τ(c)))`. -/
def cycleLength (c : Fin M → Fin A) : Nat :=
  M * (A / Nat.gcd A (tau hM hA c).val)

/-- The declared cycle length is positive, including the zero-monodromy case. -/
theorem cycleLength_pos (c : Fin M → Fin A) : 0 < cycleLength hM hA c := by
  dsimp [cycleLength]
  exact Nat.mul_pos hM (Nat.div_pos
    (Nat.le_of_dvd hA (Nat.gcd_dvd_left A _))
    (Nat.gcd_pos_of_pos_left _ hA))

/-- Every state returns to itself after `cycleLength c` steps. -/
theorem liftStep_iter_cycleLength (c : Fin M → Fin A) (p : Fin M × Fin A) :
    iter (liftStep hM hA c) (cycleLength hM hA c) p = p := by
  dsimp [cycleLength]
  rw [liftStep_iter_M_mul]
  apply Prod.ext
  · rfl
  · apply Fin.ext
    dsimp only
    let t := (tau hM hA c).val
    let d := Nat.gcd A t
    have hda : d ∣ A := Nat.gcd_dvd_left A t
    have hdt : d ∣ t := Nat.gcd_dvd_right A t
    have hprod : (A / d) * t = A * (t / d) := by
      have ha : d * (A / d) = A := Nat.mul_div_cancel' hda
      have ht : d * (t / d) = t := Nat.mul_div_cancel' hdt
      calc (A / d) * t = (A / d) * (d * (t / d)) := by rw [ht]
        _ = (d * (A / d)) * (t / d) := by rw [← Nat.mul_assoc, Nat.mul_comm (A / d) d]
        _ = A * (t / d) := by rw [ha]
    rw [hprod, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt p.2.isLt]

/-- Minimality: every return time `k` is a multiple of `cycleLength c`. -/
theorem cycleLength_dvd_return (c : Fin M → Fin A) (p : Fin M × Fin A) (k : Nat)
    (hret : iter (liftStep hM hA c) k p = p) :
    cycleLength hM hA c ∣ k := by
  have h1 := congrArg (fun q => q.1.val) hret
  rw [liftStep_iter] at h1
  dsimp only at h1
  have hM_dvd : M ∣ k := by
    have hmod : (p.1.val + k) % M = (p.1.val + 0) % M := by
      rw [Nat.add_zero, Nat.mod_eq_of_lt p.1.isLt]; exact h1
    rw [Nat.add_comm p.1.val k, Nat.add_comm p.1.val 0] at hmod
    have hk0 := mod_eq_of_add_eq hmod
    rw [Nat.zero_mod] at hk0
    exact Nat.dvd_iff_mod_eq_zero.mpr hk0
  obtain ⟨m, rfl⟩ := hM_dvd
  rw [liftStep_iter_M_mul] at hret
  have h2 := congrArg (fun q => q.2.val) hret
  dsimp only at h2
  let t := (tau hM hA c).val
  have hA_dvd : A ∣ m * t := by
    have hmod : (p.2.val + m * t) % A = (p.2.val + 0) % A := by
      rw [Nat.add_zero, Nat.mod_eq_of_lt p.2.isLt]; exact h2
    rw [Nat.add_comm p.2.val (m * t), Nat.add_comm p.2.val 0] at hmod
    have hmt0 := mod_eq_of_add_eq hmod
    rw [Nat.zero_mod] at hmt0
    exact Nat.dvd_iff_mod_eq_zero.mpr hmt0
  let d := Nat.gcd A t
  have hd : 0 < d := Nat.gcd_pos_of_pos_left t hA
  have hda : d ∣ A := Nat.gcd_dvd_left A t
  have hdt : d ∣ t := Nat.gcd_dvd_right A t
  have hdiv_dvd : (A / d) ∣ m * (t / d) := by
    obtain ⟨w, hw⟩ := hA_dvd
    refine ⟨w, ?_⟩
    have ha : d * (A / d) = A := Nat.mul_div_cancel' hda
    have ht : d * (t / d) = t := Nat.mul_div_cancel' hdt
    have hmul : d * (m * (t / d)) = d * ((A / d) * w) := by
      calc d * (m * (t / d)) = m * (d * (t / d)) := by rw [Nat.mul_left_comm]
        _ = m * t := by rw [ht]
        _ = A * w := hw
        _ = (d * (A / d)) * w := by rw [ha]
        _ = d * ((A / d) * w) := Nat.mul_assoc _ _ _
    exact Nat.eq_of_mul_eq_mul_left hd hmul
  have hcop : Nat.gcd (A / d) (t / d) = 1 := gcd_div_coprime hA
  have hAd_dvd_m : (A / d) ∣ m := coprime_dvd_of_dvd_mul hcop hdiv_dvd
  exact Nat.mul_dvd_mul_left M hAd_dvd_m

/-- Canonical representatives `(0, j)` for `j ∈ Fin (gcd(A, τ(c)))`, one per cycle. -/
def cycleRep (c : Fin M → Fin A) (j : Fin (Nat.gcd A (tau hM hA c).val)) :
    Fin M × Fin A :=
  (⟨0, hM⟩,
   ⟨j.val, Nat.lt_of_lt_of_le j.isLt (Nat.le_of_dvd hA (Nat.gcd_dvd_left A _))⟩)

/-- Completeness: every state lies on the forward orbit of some canonical representative. -/
theorem orbit_complete (c : Fin M → Fin A) (p : Fin M × Fin A) :
    ∃ (j : Fin (Nat.gcd A (tau hM hA c).val)) (k : Nat),
      iter (liftStep hM hA c) k (cycleRep hM hA c j) = p := by
  let t := (tau hM hA c).val
  let d := Nat.gcd A t
  have hd : 0 < d := Nat.gcd_pos_of_pos_left t hA
  let q₀ : Fin A :=
    ⟨(p.2.val + (A - psumFrom hM c 0 p.1.val % A)) % A, Nat.mod_lt _ hA⟩
  let j : Fin d := ⟨q₀.val % d, Nat.mod_lt _ hd⟩
  -- Solve `(j + m * t) % A = q₀` using Bézout's identity.
  have hbez := bezout_spec A t
  let x := (bezout A t).1
  let y := (bezout A t).2
  change (A : Int) * x + (t : Int) * y = (d : Int) at hbez
  let s : Nat := q₀.val / d
  let z : Int := y * (s : Int)
  have hA_ne : (A : Int) ≠ 0 := by omega
  have hz_nonneg : 0 ≤ z % (A : Int) := Int.emod_nonneg z hA_ne
  let m : Nat := (z % (A : Int)).toNat
  have hm_cast : (m : Int) = z % (A : Int) := Int.toNat_of_nonneg hz_nonneg
  have hz_div : (A : Int) * (z / (A : Int)) + z % (A : Int) = z := Int.mul_ediv_add_emod z (A : Int)
  have hq0_div : d * s + j.val = q₀.val := Nat.div_add_mod q₀.val d
  have hq0_int : (d : Int) * (s : Int) + (j.val : Int) = (q₀.val : Int) := by
    rw [← Int.natCast_mul, ← Int.natCast_add, hq0_div]
  have hlin : ((j.val + m * t : Nat) : Int) =
      (q₀.val : Int) + (A : Int) * (-(x * (s : Int)) - (z / (A : Int)) * (t : Int)) := by
    have hm_sub : (m : Int) = z - (A : Int) * (z / (A : Int)) := by omega
    have hty : (t : Int) * y = (d : Int) - (A : Int) * x := by omega
    rw [Int.natCast_add, Int.natCast_mul, hm_sub, Int.sub_mul]
    have hzt : z * (t : Int) = (d : Int) * (s : Int) - (A : Int) * (x * (s : Int)) := by
      calc z * (t : Int) = (y * (s : Int)) * (t : Int) := rfl
        _ = ((t : Int) * y) * (s : Int) := by rw [Int.mul_right_comm, Int.mul_comm y]
        _ = ((d : Int) - (A : Int) * x) * (s : Int) := by rw [hty]
        _ = (d : Int) * (s : Int) - ((A : Int) * x) * (s : Int) := Int.sub_mul _ _ _
        _ = (d : Int) * (s : Int) - (A : Int) * (x * (s : Int)) := by rw [Int.mul_assoc]
    rw [hzt, Int.mul_assoc (A : Int) (z / (A : Int)) (t : Int),
        Int.mul_sub (A : Int), Int.mul_neg]
    omega
  have hm_eq : (j.val + m * t) % A = q₀.val := by
    cases hK : (-(x * (s : Int)) - (z / (A : Int)) * (t : Int)) with
    | ofNat k =>
      rw [hK] at hlin
      change ((j.val + m * t : Nat) : Int) = (q₀.val : Int) + (A : Int) * (k : Int) at hlin
      rw [← Int.natCast_mul, ← Int.natCast_add] at hlin
      have hnat : j.val + m * t = q₀.val + A * k := Int.ofNat.inj hlin
      rw [hnat, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt q₀.isLt]
    | negSucc k =>
      have hns : Int.negSucc k = -((k + 1 : Nat) : Int) := by omega
      rw [hK, hns, Int.mul_neg, ← Int.natCast_mul] at hlin
      have hge : A ≤ A * (k + 1) := Nat.le_mul_of_pos_right A (Nat.succ_pos k)
      have hlt : q₀.val < A := q₀.isLt
      omega
  refine ⟨j, M * m + p.1.val, ?_⟩
  rw [iter_add, liftStep_iter_M_mul]
  have hmid : ((⟨0, hM⟩, ⟨(j.val + m * t) % A, Nat.mod_lt _ hA⟩) : Fin M × Fin A) = (⟨0, hM⟩, q₀) := by
    apply Prod.ext
    · rfl
    · exact Fin.ext hm_eq
  dsimp [cycleRep]
  rw [hmid, liftStep_iter]
  apply Prod.ext <;> apply Fin.ext
  · dsimp only; rw [Nat.zero_add, Nat.mod_eq_of_lt p.1.isLt]
  · dsimp only [q₀]
    rw [add_mod_left_drop, nat_mod_cancel hA, Nat.mod_eq_of_lt p.2.isLt]

/-- Disjointness: distinct canonical representatives lie in disjoint orbits. -/
theorem orbit_disjoint (c : Fin M → Fin A)
    (j₁ j₂ : Fin (Nat.gcd A (tau hM hA c).val)) (k : Nat)
    (hreach : iter (liftStep hM hA c) k (cycleRep hM hA c j₁) = cycleRep hM hA c j₂) :
    j₁ = j₂ := by
  have h1 := congrArg (fun q => q.1.val) hreach
  rw [liftStep_iter] at h1
  dsimp [cycleRep] at h1
  rw [Nat.zero_add] at h1
  have hM_dvd : M ∣ k := Nat.dvd_iff_mod_eq_zero.mpr h1
  obtain ⟨m, rfl⟩ := hM_dvd
  rw [liftStep_iter_M_mul] at hreach
  have h2 := congrArg (fun q => q.2.val) hreach
  dsimp [cycleRep] at h2
  let t := (tau hM hA c).val
  let d := Nat.gcd A t
  have hda : d ∣ A := Nat.gcd_dvd_left A t
  have hdt : d ∣ t := Nat.gcd_dvd_right A t
  obtain ⟨qt, hqt⟩ := hdt
  change (j₁.val + m * t) % A = j₂.val at h2
  have hmod_d : j₂.val % d = j₁.val % d := by
    rw [← h2, mod_mod_of_dvd hda, hqt, ← Nat.mul_assoc,
        Nat.mul_comm m d, Nat.mul_assoc, Nat.add_mul_mod_self_left]
  rw [Nat.mod_eq_of_lt j₂.isLt, Nat.mod_eq_of_lt j₁.isLt] at hmod_d
  exact Fin.ext hmod_d.symm

/-- Every multiple of the declared period returns every state. -/
theorem liftStep_iter_cycleLength_mul (c : Fin M → Fin A)
    (p : Fin M × Fin A) (n : Nat) :
    iter (liftStep hM hA c) (cycleLength hM hA c * n) p = p := by
  induction n with
  | zero => rfl
  | succ n ih =>
    rw [Nat.mul_succ, iter_add, ih, liftStep_iter_cycleLength]

/-- An intersection at arbitrary times forces the two representative labels to agree.
This strengthens representative-to-representative disjointness to disjointness of the
entire forward orbits. -/
theorem orbit_intersection (c : Fin M → Fin A)
    (j₁ j₂ : Fin (Nat.gcd A (tau hM hA c).val)) (a b : Nat)
    (hinter : iter (liftStep hM hA c) a (cycleRep hM hA c j₁) =
      iter (liftStep hM hA c) b (cycleRep hM hA c j₂)) :
    j₁ = j₂ := by
  let n := cycleLength hM hA c * a - a
  have hle : a ≤ cycleLength hM hA c * a :=
    Nat.le_mul_of_pos_left a (cycleLength_pos hM hA c)
  have hsteps : a + n = cycleLength hM hA c * a := by dsimp [n]; omega
  have hshift := congrArg (iter (liftStep hM hA c) n) hinter
  rw [← iter_add, ← iter_add, hsteps, liftStep_iter_cycleLength_mul] at hshift
  exact (orbit_disjoint hM hA c j₂ j₁ (b + n) hshift.symm).symm

/-- Exact cycle count identity: `cycleCount · cycleLength = M · A`. -/
theorem cycleCount_mul_cycleLength (c : Fin M → Fin A) :
    Nat.gcd A (tau hM hA c).val * cycleLength hM hA c = M * A := by
  dsimp [cycleLength]
  rw [Nat.mul_left_comm, Nat.mul_div_cancel' (Nat.gcd_dvd_left A _)]

end CycleClassification

/-- The unit-carry cocycle on the `C_30030 → C_2730` cover. -/
def unitCarryCocycle (r : Fin 2730) : Fin 11 :=
  ⟨if r.val = 2729 then 1 else 0, by split <;> omega⟩

theorem unitCarry_psum_lt (k : Nat) (hk : k ≤ 2729) :
    psumFrom (by decide : 0 < 2730) unitCarryCocycle 0 k = 0 := by
  induction k with
  | zero => rfl
  | succ k ih =>
    dsimp [psumFrom, unitCarryCocycle]
    rw [ih (by omega)]
    have hmod : (0 + k) % 2730 = k := by omega
    rw [hmod]
    have hne : k ≠ 2729 := by omega
    simp [hne]

theorem unitCarry_tau :
    tau (by decide : 0 < 2730) (by decide : 0 < 11) unitCarryCocycle = ⟨1, by decide⟩ := by
  apply Fin.ext
  change psumFrom (by decide : 0 < 2730) unitCarryCocycle 0 2730 % 11 = 1
  have hstep : psumFrom (by decide : 0 < 2730) unitCarryCocycle 0 2730 =
      psumFrom (by decide : 0 < 2730) unitCarryCocycle 0 2729 +
      (unitCarryCocycle ⟨(0 + 2729) % 2730, by decide⟩).val :=
        psumFrom.eq_2 (by decide : 0 < 2730) unitCarryCocycle 0 2729
  rw [hstep, unitCarry_psum_lt 2729 (Nat.le_refl 2729)]
  decide

/-- The unit-carry cover has one cycle, of length 30,030. -/
theorem cover_30030_connected :
    Nat.gcd 11 (tau (by decide : 0 < 2730) (by decide : 0 < 11) unitCarryCocycle).val = 1 ∧
    cycleLength (by decide : 0 < 2730) (by decide : 0 < 11) unitCarryCocycle = 30030 := by
  simp only [cycleLength, unitCarry_tau]
  decide

end FoliatedCoprimeGeometry
