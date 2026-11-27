import Lean

/-! Synchronization retractions and reversible discrepancy retention.
Projection alone selects an authoritative reading; retaining the discrepancy
makes the transformation reversible. Neither operation authenticates an input. -/
namespace FoliatedCoprimeGeometry

/-- Compatible observations sharing their residue modulo eleven. -/
def Pullback : Type :=
  { p : Fin 77 × Fin 143 // p.1.val % 11 = p.2.val % 11 }

/-- U-authoritative retraction preserving the other reading modulo thirteen. -/
def projU (u : Fin 77) (v : Fin 143) : Fin 77 × Fin 143 :=
  (u, ⟨(78 * u.val + 66 * v.val) % 143, by omega⟩)

/-- V-authoritative retraction preserving the other reading modulo seven. -/
def projV (u : Fin 77) (v : Fin 143) : Fin 77 × Fin 143 :=
  (⟨(22 * u.val + 56 * v.val) % 77, by omega⟩, v)

def succ77 (u : Fin 77) : Fin 77 := ⟨(u.val + 1) % 77, by omega⟩
def succ143 (v : Fin 143) : Fin 143 := ⟨(v.val + 1) % 143, by omega⟩

theorem projU_mem_pullback (u : Fin 77) (v : Fin 143) :
    (projU u v).1.val % 11 = (projU u v).2.val % 11 := by
  dsimp [projU]; omega

theorem projU_preserves_77 (u : Fin 77) (v : Fin 143) :
    (projU u v).1 = u := rfl

theorem projU_preserves_13 (u : Fin 77) (v : Fin 143) :
    (projU u v).2.val % 13 = v.val % 13 := by
  dsimp [projU]; omega

theorem projU_idempotent (u : Fin 77) (v : Fin 143) :
    projU (projU u v).1 (projU u v).2 = projU u v := by
  apply Prod.ext <;> apply Fin.ext <;> dsimp [projU] <;> omega

theorem projU_fix_pullback (u : Fin 77) (v : Fin 143) (h : u.val % 11 = v.val % 11) :
    projU u v = (u, v) := by
  apply Prod.ext <;> apply Fin.ext <;> dsimp [projU] <;> omega

/-- Unique compatible replacement preserving the thirteen-reading. -/
theorem projU_unique (u : Fin 77) (v w : Fin 143)
    (h11 : w.val % 11 = u.val % 11) (h13 : w.val % 13 = v.val % 13) :
    w = (projU u v).2 := by
  apply Fin.ext; dsimp [projU]; omega

/-- Independence of representatives chosen modulo 77 and 143. -/
theorem projU_well_defined (u₁ u₂ v₁ v₂ : Nat)
    (hu : u₁ % 77 = u₂ % 77) (hv : v₁ % 143 = v₂ % 143) :
    (78 * u₁ + 66 * v₁) % 143 = (78 * u₂ + 66 * v₂) % 143 := by
  omega

theorem projU_comm_succ (u : Fin 77) (v : Fin 143) :
    projU (succ77 u) (succ143 v) = (succ77 (projU u v).1, succ143 (projU u v).2) := by
  apply Prod.ext <;> apply Fin.ext <;> dsimp [projU, succ77, succ143] <;> omega

theorem projV_mem_pullback (u : Fin 77) (v : Fin 143) :
    (projV u v).1.val % 11 = (projV u v).2.val % 11 := by
  dsimp [projV]; omega

theorem projV_preserves_7 (u : Fin 77) (v : Fin 143) :
    (projV u v).1.val % 7 = u.val % 7 := by
  dsimp [projV]; omega

theorem projV_preserves_143 (u : Fin 77) (v : Fin 143) :
    (projV u v).2 = v := rfl

theorem projV_idempotent (u : Fin 77) (v : Fin 143) :
    projV (projV u v).1 (projV u v).2 = projV u v := by
  apply Prod.ext <;> apply Fin.ext <;> dsimp [projV] <;> omega

theorem projV_fix_pullback (u : Fin 77) (v : Fin 143) (h : u.val % 11 = v.val % 11) :
    projV u v = (u, v) := by
  apply Prod.ext <;> apply Fin.ext <;> dsimp [projV] <;> omega

theorem projV_unique (u w : Fin 77) (v : Fin 143)
    (h7 : w.val % 7 = u.val % 7) (h11 : w.val % 11 = v.val % 11) :
    w = (projV u v).1 := by
  apply Fin.ext; dsimp [projV]; omega

theorem projV_well_defined (u₁ u₂ v₁ v₂ : Nat)
    (hu : u₁ % 77 = u₂ % 77) (hv : v₁ % 143 = v₂ % 143) :
    (22 * u₁ + 56 * v₁) % 77 = (22 * u₂ + 56 * v₂) % 77 := by
  omega

theorem projV_comm_succ (u : Fin 77) (v : Fin 143) :
    projV (succ77 u) (succ143 v) = (succ77 (projV u v).1, succ143 (projV u v).2) := by
  apply Prod.ext <;> apply Fin.ext <;> dsimp [projV, succ77, succ143] <;> omega

/-- Signed mismatch `(u-v) mod 11`, encoded without natural-number underflow. -/
def discrepancy (u : Fin 77) (v : Fin 143) : Fin 11 :=
  ⟨(u.val % 11 + 11 - v.val % 11) % 11, by omega⟩

theorem discrepancy_zero_iff (u : Fin 77) (v : Fin 143) :
    discrepancy u v = ⟨0, by decide⟩ ↔ u.val % 11 = v.val % 11 := by
  constructor
  · intro h
    have hv := congrArg Fin.val h
    dsimp [discrepancy] at hv
    omega
  · intro h
    apply Fin.ext
    dsimp [discrepancy]
    omega

/-- Retraction plus discrepancy preserves the entire original pair. -/
def psi (p : Fin 77 × Fin 143) : Pullback × Fin 11 :=
  (⟨projU p.1 p.2, projU_mem_pullback p.1 p.2⟩, discrepancy p.1 p.2)

/-- Inverse uses `65 = -78 mod 143`. -/
def psiInv (q : Pullback × Fin 11) : Fin 77 × Fin 143 :=
  (q.1.val.1, ⟨(q.1.val.2.val + 65 * q.2.val) % 143, by omega⟩)

theorem psiInv_psi (p : Fin 77 × Fin 143) :
    psiInv (psi p) = p := by
  apply Prod.ext <;> apply Fin.ext <;> dsimp [psiInv, psi, projU, discrepancy] <;> omega

theorem psi_psiInv (q : Pullback × Fin 11) :
    psi (psiInv q) = q := by
  rcases q with ⟨⟨⟨u, v'⟩, hpb⟩, δ⟩
  change u.val % 11 = v'.val % 11 at hpb
  apply Prod.ext
  · apply Subtype.ext
    apply Prod.ext <;> apply Fin.ext <;> dsimp [psi, psiInv, projU] at * <;> omega
  · apply Fin.ext
    dsimp [psi, psiInv, discrepancy] at *
    omega

/-- Synchronized successor preserves mismatch; it does not erase mismatch. -/
theorem discrepancy_succ_invariant (u : Fin 77) (v : Fin 143) :
    discrepancy (succ77 u) (succ143 v) = discrepancy u v := by
  apply Fin.ext
  dsimp [discrepancy, succ77, succ143]
  omega

end FoliatedCoprimeGeometry
