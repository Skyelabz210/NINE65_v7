import FoliatedCoprimeGeometry.Basic

/-!
Cocycle lifts of a finite cyclic base and classification by total monodromy.
The coordinate changes here are fiber translations, not arbitrary conjugacies.
This is cohomology of the directed cycle graph (equivalently the successor
action of the integers), not group cohomology of the finite cyclic group.
-/
namespace FoliatedCoprimeGeometry

section CocycleClassification

variable {M A : Nat} (hM : 0 < M) (hA : 0 < A)

/-- Skew-product lift on `Fin M × Fin A` driven by cocycle `c`. -/
def liftStep (c : Fin M → Fin A) (p : Fin M × Fin A) : Fin M × Fin A :=
  (⟨(p.1.val + 1) % M, Nat.mod_lt _ hM⟩,
   ⟨(p.2.val + (c p.1).val) % A, Nat.mod_lt _ hA⟩)

/-- Partial cocycle sum over `k` steps starting at base coordinate `r`. -/
def psumFrom (c : Fin M → Fin A) (r : Nat) : Nat → Nat
  | 0 => 0
  | k + 1 => psumFrom c r k + (c ⟨(r + k) % M, Nat.mod_lt _ hM⟩).val

/-- Total monodromy modulo the fiber cardinality. -/
def tau (c : Fin M → Fin A) : Fin A :=
  ⟨psumFrom hM c 0 M % A, Nat.mod_lt _ hA⟩

theorem psumFrom_split (c : Fin M → Fin A) (r a b : Nat) :
    psumFrom hM c r (a + b) = psumFrom hM c r a + psumFrom hM c (r + a) b := by
  induction b with
  | zero => simp [psumFrom]
  | succ b ih =>
    simp [psumFrom, Nat.add_assoc, ih]

theorem psumFrom_shift_M (c : Fin M → Fin A) (r : Nat) :
    psumFrom hM c (r + 1) M = psumFrom hM c r M := by
  have h1 : psumFrom hM c r (M + 1) =
      psumFrom hM c r M + (c ⟨(r + M) % M, Nat.mod_lt _ hM⟩).val := rfl
  have h2 : psumFrom hM c r (1 + M) =
      psumFrom hM c r 1 + psumFrom hM c (r + 1) M := psumFrom_split hM c r 1 M
  have hcomm : M + 1 = 1 + M := Nat.add_comm M 1
  rw [← hcomm, h1] at h2
  have h1step : psumFrom hM c r 1 = (c ⟨r % M, Nat.mod_lt _ hM⟩).val := by
    simp [psumFrom]
  have hmod : (r + M) % M = r % M := Nat.add_mod_right r M
  have hce : (c ⟨(r + M) % M, Nat.mod_lt _ hM⟩).val =
             (c ⟨r % M, Nat.mod_lt _ hM⟩).val := by
    congr 2; exact Fin.ext hmod
  rw [h1step, hce] at h2
  omega

theorem psumFrom_M_const (c : Fin M → Fin A) (r : Nat) :
    psumFrom hM c r M = psumFrom hM c 0 M := by
  induction r with
  | zero => rfl
  | succ r ih => rw [psumFrom_shift_M, ih]

theorem liftStep_iter (c : Fin M → Fin A) (k : Nat) (p : Fin M × Fin A) :
    iter (liftStep hM hA c) k p =
      (⟨(p.1.val + k) % M, Nat.mod_lt _ hM⟩,
       ⟨(p.2.val + psumFrom hM c p.1.val k) % A, Nat.mod_lt _ hA⟩) := by
  induction k with
  | zero =>
    apply Prod.ext <;> apply Fin.ext
    · dsimp [iter]; exact (Nat.mod_eq_of_lt p.1.isLt).symm
    · dsimp [iter, psumFrom]; exact (Nat.mod_eq_of_lt p.2.isLt).symm
  | succ k ih =>
    rw [iter, ih]
    apply Prod.ext <;> apply Fin.ext
    · dsimp [liftStep]
      rw [add_mod_left_drop, Nat.add_assoc]
    · dsimp [liftStep, psumFrom]
      rw [add_mod_left_drop, Nat.add_assoc]

/-- A full base loop translates every fiber by `tau c`. -/
theorem liftStep_monodromy (c : Fin M → Fin A) (p : Fin M × Fin A) :
    iter (liftStep hM hA c) M p =
      (p.1, ⟨(p.2.val + (tau hM hA c).val) % A, Nat.mod_lt _ hA⟩) := by
  rw [liftStep_iter]
  apply Prod.ext <;> apply Fin.ext
  · dsimp only
    rw [Nat.add_mod_right, Nat.mod_eq_of_lt p.1.isLt]
  · dsimp [tau]
    rw [psumFrom_M_const, add_mod_right_drop]

theorem liftStep_iter_M_mul (c : Fin M → Fin A) (k : Nat) (p : Fin M × Fin A) :
    iter (liftStep hM hA c) (M * k) p =
      (p.1, ⟨(p.2.val + k * (tau hM hA c).val) % A, Nat.mod_lt _ hA⟩) := by
  induction k with
  | zero =>
    apply Prod.ext
    · rfl
    · apply Fin.ext; simp [iter, Nat.mod_eq_of_lt p.2.isLt]
  | succ k ih =>
    rw [Nat.mul_succ, iter_add, ih, liftStep_monodromy]
    apply Prod.ext
    · rfl
    · apply Fin.ext; dsimp only
      rw [add_mod_left_drop, Nat.add_assoc, Nat.succ_mul]

/-- Fiber-translation gauge change. -/
def gauge (φ : Fin M → Fin A) (p : Fin M × Fin A) : Fin M × Fin A :=
  (p.1, ⟨(p.2.val + (φ p.1).val) % A, Nat.mod_lt _ hA⟩)

/-- The explicit inverse fiber translation; no choice of representatives is needed. -/
def gaugeInv (φ : Fin M → Fin A) (p : Fin M × Fin A) : Fin M × Fin A :=
  (p.1, ⟨(p.2.val + (A - (φ p.1).val)) % A, Nat.mod_lt _ hA⟩)

theorem gaugeInv_gauge (φ : Fin M → Fin A) (p : Fin M × Fin A) :
    gaugeInv hA φ (gauge hA φ p) = p := by
  apply Prod.ext
  · rfl
  · apply Fin.ext
    dsimp [gaugeInv, gauge]
    rw [add_mod_left_drop]
    have hb := (φ p.1).isLt
    have he : p.2.val + (φ p.1).val + (A - (φ p.1).val) = p.2.val + A := by omega
    rw [he, Nat.add_mod_right, Nat.mod_eq_of_lt p.2.isLt]

theorem gauge_gaugeInv (φ : Fin M → Fin A) (p : Fin M × Fin A) :
    gauge hA φ (gaugeInv hA φ p) = p := by
  apply Prod.ext
  · rfl
  · apply Fin.ext
    dsimp [gaugeInv, gauge]
    rw [add_mod_left_drop]
    have hb := (φ p.1).isLt
    have he : p.2.val + (A - (φ p.1).val) + (φ p.1).val = p.2.val + A := by omega
    rw [he, Nat.add_mod_right, Nat.mod_eq_of_lt p.2.isLt]

/-- Two cocycles are equivalent if conjugated by a fiber translation. -/
def CocycleEquiv (c₁ c₂ : Fin M → Fin A) : Prop :=
  ∃ φ : Fin M → Fin A, ∀ p : Fin M × Fin A,
    gauge hA φ (liftStep hM hA c₁ p) = liftStep hM hA c₂ (gauge hA φ p)

/-- Total monodromy completely classifies cocycles under fiber translations. -/
theorem cocycle_equiv_iff_tau_eq (c₁ c₂ : Fin M → Fin A) :
    CocycleEquiv hM hA c₁ c₂ ↔ tau hM hA c₁ = tau hM hA c₂ := by
  constructor
  · rintro ⟨φ, hφ⟩
    have hiter := iter_conj (liftStep hM hA c₁) (liftStep hM hA c₂) (gauge hA φ) hφ M
      (⟨0, hM⟩, ⟨0, hA⟩)
    rw [liftStep_monodromy, liftStep_monodromy] at hiter
    have hval := congrArg (fun p => p.2.val) hiter
    dsimp [gauge] at hval
    rw [Nat.zero_add, Nat.mod_eq_of_lt (tau hM hA c₁).isLt,
        Nat.zero_add, Nat.mod_eq_of_lt (φ ⟨0, hM⟩).isLt,
        Nat.add_comm (φ ⟨0, hM⟩).val] at hval
    have hmod := mod_eq_of_add_eq hval
    rw [Nat.mod_eq_of_lt (tau hM hA c₁).isLt, Nat.mod_eq_of_lt (tau hM hA c₂).isLt] at hmod
    exact Fin.ext hmod
  · intro htau
    have htau_val : psumFrom hM c₁ 0 M % A = psumFrom hM c₂ 0 M % A :=
      congrArg Fin.val htau
    let φ : Fin M → Fin A := fun r =>
      ⟨(psumFrom hM c₂ 0 r.val + (A - psumFrom hM c₁ 0 r.val % A)) % A, Nat.mod_lt _ hA⟩
    refine ⟨φ, fun p => ?_⟩
    apply Prod.ext
    · rfl
    · apply Fin.ext
      dsimp [gauge, liftStep, φ]
      rw [add_mod_left_drop, add_mod_right_drop, add_mod_left_drop]
      rw [Nat.add_assoc p.2.val _ (c₂ p.1).val,
          ← add_mod_right_drop p.2.val, add_mod_left_drop, add_mod_right_drop]
      suffices hstep :
          ((c₁ p.1).val + (psumFrom hM c₂ 0 ((p.1.val + 1) % M) +
            (A - psumFrom hM c₁ 0 ((p.1.val + 1) % M) % A))) % A =
          (psumFrom hM c₂ 0 p.1.val + (A - psumFrom hM c₁ 0 p.1.val % A) +
            (c₂ p.1).val) % A by
        rw [Nat.add_assoc, ← add_mod_right_drop p.2.val, hstep,
            add_mod_right_drop]
      have hp1 : psumFrom hM c₁ 0 (p.1.val + 1) = psumFrom hM c₁ 0 p.1.val + (c₁ p.1).val := by
        rw [psumFrom]
        have he : (⟨(0 + p.1.val) % M, Nat.mod_lt _ hM⟩ : Fin M) = p.1 := by
          apply Fin.ext
          simp [Nat.mod_eq_of_lt p.1.isLt]
        rw [he]
      have hp2 : psumFrom hM c₂ 0 (p.1.val + 1) = psumFrom hM c₂ 0 p.1.val + (c₂ p.1).val := by
        rw [psumFrom]
        have he : (⟨(0 + p.1.val) % M, Nat.mod_lt _ hM⟩ : Fin M) = p.1 := by
          apply Fin.ext
          simp [Nat.mod_eq_of_lt p.1.isLt]
        rw [he]
      by_cases hlt : p.1.val + 1 < M
      · have hmod : (p.1.val + 1) % M = p.1.val + 1 := Nat.mod_eq_of_lt hlt
        rw [hmod, hp1, hp2]
        apply mod_eq_of_add_eq (z := psumFrom hM c₁ 0 p.1.val + (c₁ p.1).val)
        have hL : (c₁ p.1).val + (psumFrom hM c₂ 0 p.1.val + (c₂ p.1).val +
            (A - (psumFrom hM c₁ 0 p.1.val + (c₁ p.1).val) % A)) +
            (psumFrom hM c₁ 0 p.1.val + (c₁ p.1).val) =
            ((c₁ p.1).val + psumFrom hM c₂ 0 p.1.val + (c₂ p.1).val) +
            (A - (psumFrom hM c₁ 0 p.1.val + (c₁ p.1).val) % A) +
            (psumFrom hM c₁ 0 p.1.val + (c₁ p.1).val) := by omega
        have hR : psumFrom hM c₂ 0 p.1.val + (A - psumFrom hM c₁ 0 p.1.val % A) +
            (c₂ p.1).val + (psumFrom hM c₁ 0 p.1.val + (c₁ p.1).val) =
            ((c₁ p.1).val + psumFrom hM c₂ 0 p.1.val + (c₂ p.1).val) +
            (A - psumFrom hM c₁ 0 p.1.val % A) + psumFrom hM c₁ 0 p.1.val := by omega
        rw [hL, hR, nat_mod_cancel hA, nat_mod_cancel hA]
      · have heqM : p.1.val + 1 = M := by have := p.1.isLt; omega
        have hmod : (p.1.val + 1) % M = 0 := by rw [heqM, Nat.mod_self]
        rw [hmod]
        simp only [psumFrom, Nat.zero_mod, Nat.sub_zero, Nat.zero_add]
        apply mod_eq_of_add_eq (z := psumFrom hM c₁ 0 p.1.val)
        have hL : (c₁ p.1).val + A + psumFrom hM c₁ 0 p.1.val =
            (psumFrom hM c₁ 0 p.1.val + (c₁ p.1).val) + A := by omega
        have hR : psumFrom hM c₂ 0 p.1.val + (A - psumFrom hM c₁ 0 p.1.val % A) +
            (c₂ p.1).val + psumFrom hM c₁ 0 p.1.val =
            (psumFrom hM c₂ 0 p.1.val + (c₂ p.1).val) +
            (A - psumFrom hM c₁ 0 p.1.val % A) + psumFrom hM c₁ 0 p.1.val := by omega
        rw [hL, hR, Nat.add_mod_right, nat_mod_cancel hA, ← hp1, ← hp2, heqM, htau_val]

end CocycleClassification
end FoliatedCoprimeGeometry
