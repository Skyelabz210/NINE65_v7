import FoliatedCoprimeGeometry.Cover
import FoliatedCoprimeGeometry.Cycles
import FoliatedCoprimeGeometry.Projectors

/-! Integration of the supplied finite theorems. Sheet coordinates are semantic
charts, not a runtime requirement to persist winding. No external package is used. -/
namespace FoliatedCoprimeGeometry

/-- A bundled pair of mutually inverse coordinate maps, using only Lean core. -/
structure CoordinateEquiv (α β : Type) where
  toFun : α → β
  invFun : β → α
  left_inv : ∀ a, invFun (toFun a) = a
  right_inv : ∀ b, toFun (invFun b) = b

def coverEquiv : CoordinateEquiv (Fin 30030) (Fin 2730 × Fin 11) :=
  ⟨toSheet, fromSheet, fromSheet_toSheet, toSheet_fromSheet⟩

def shadowGaugeEquiv : CoordinateEquiv (Fin 2730 × Fin 11) (Fin 2730 × Fin 11) :=
  ⟨shadowToSheet, sheetToShadow, sheetToShadow_shadowToSheet, shadowToSheet_sheetToShadow⟩

def discrepancyEquiv : CoordinateEquiv (Fin 77 × Fin 143) (Pullback × Fin 11) :=
  ⟨psi, psiInv, psiInv_psi, psi_psiInv⟩

/-- The concrete carry chart is exactly the instance of the general lift. -/
theorem sheetStep_eq_liftStep :
    sheetStep = liftStep (by decide : 0 < 2730) (by decide : 0 < 11) unitCarryCocycle := by
  funext p
  rfl

/-- The concrete chart returns after 30030 steps, using the general period theorem. -/
theorem sheetStep_period (p : Fin 2730 × Fin 11) : iter sheetStep 30030 p = p := by
  have h := liftStep_iter_cycleLength (by decide : 0 < 2730) (by decide : 0 < 11)
    unitCarryCocycle p
  rw [cover_30030_connected.2] at h
  rw [sheetStep_eq_liftStep]
  exact h

/-- No smaller positive return is possible for any concrete chart state. -/
theorem sheetStep_return_iff (p : Fin 2730 × Fin 11) (k : Nat) :
    iter sheetStep k p = p ↔ 30030 ∣ k := by
  constructor
  · intro h
    rw [sheetStep_eq_liftStep] at h
    have hd := cycleLength_dvd_return (by decide : 0 < 2730) (by decide : 0 < 11)
      unitCarryCocycle p k h
    rwa [cover_30030_connected.2] at hd
  · rintro ⟨n, rfl⟩
    rw [iter_mul]
    induction n with
    | zero => rfl
    | succ n ih => rw [iter, ih, sheetStep_period]

/-- The raw residue pair also has exact period 30030; winding need not be stored. -/
theorem rawShadowStep_return_iff (p : Fin 2730 × Fin 11) (k : Nat) :
    iter rawShadowStep k p = p ↔ 30030 ∣ k := by
  constructor
  · intro h
    apply (sheetStep_return_iff (shadowToSheet p) k).mp
    rw [← iter_conj rawShadowStep sheetStep shadowToSheet kElim_gauge_conjugacy, h]
  · intro h
    have hs := (sheetStep_return_iff (shadowToSheet p) k).mpr h
    rw [← iter_conj rawShadowStep sheetStep shadowToSheet kElim_gauge_conjugacy] at hs
    have := congrArg sheetToShadow hs
    simpa only [sheetToShadow_shadowToSheet] using this

/-- Heterogeneous operators preserve every compatible pair precisely when they
induce the same map on the shared 11-coordinate. `h` is a function, not assumed
an additive or ring homomorphism. This is coherence, not source authentication. -/
theorem phase_lock_iff_shared_map (f : Fin 77 → Fin 77) (g : Fin 143 → Fin 143) :
    (∀ u v, u.val % 11 = v.val % 11 → (f u).val % 11 = (g v).val % 11) ↔
    ∃ h : Fin 11 → Fin 11,
      (∀ u, (f u).val % 11 = (h ⟨u.val % 11, by omega⟩).val) ∧
      (∀ v, (g v).val % 11 = (h ⟨v.val % 11, by omega⟩).val) := by
  constructor
  · intro hc
    let h : Fin 11 → Fin 11 := fun s =>
      ⟨(f ⟨s.val, by omega⟩).val % 11, by omega⟩
    refine ⟨h, ?_, ?_⟩
    · intro u
      let u₀ : Fin 77 := ⟨u.val % 11, by omega⟩
      let v₀ : Fin 143 := ⟨u.val % 11, by omega⟩
      have ha := hc u v₀ (by dsimp [v₀]; omega)
      have hb := hc u₀ v₀ (by rfl)
      exact ha.trans hb.symm
    · intro v
      let u₀ : Fin 77 := ⟨v.val % 11, by omega⟩
      have hv := hc u₀ v (by dsimp [u₀]; omega)
      exact hv.symm
  · rintro ⟨h, hf, hg⟩ u v huv
    rw [hf, hg]
    exact congrArg Fin.val (congrArg h (Fin.ext huv))

/-- A repair projection discards disagreement unless the discrepancy is retained. -/
theorem projection_collision :
    projU ⟨0, by decide⟩ ⟨0, by decide⟩ = projU ⟨0, by decide⟩ ⟨13, by decide⟩ ∧
    discrepancy ⟨0, by decide⟩ ⟨0, by decide⟩ ≠
      discrepancy ⟨0, by decide⟩ ⟨13, by decide⟩ := by decide

end FoliatedCoprimeGeometry
