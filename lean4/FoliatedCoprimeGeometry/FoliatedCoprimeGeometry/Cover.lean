import FoliatedCoprimeGeometry.Basic

/-! Finite cyclic cover, sheet coordinates and the K-Elimination coordinate change.
These are finite arithmetic/dynamical statements, not claims of analytic branching. -/
namespace FoliatedCoprimeGeometry

def toSheet (x : Fin 30030) : Fin 2730 × Fin 11 :=
  (⟨x.val % 2730, by omega⟩, ⟨x.val / 2730, by omega⟩)

def fromSheet (p : Fin 2730 × Fin 11) : Fin 30030 :=
  ⟨2730 * p.2.val + p.1.val, by omega⟩

theorem toSheet_fromSheet (p : Fin 2730 × Fin 11) :
    toSheet (fromSheet p) = p := by
  apply Prod.ext <;> apply Fin.ext <;> dsimp [toSheet, fromSheet] <;> omega

theorem fromSheet_toSheet (x : Fin 30030) :
    fromSheet (toSheet x) = x := by
  apply Fin.ext; dsimp [toSheet, fromSheet]; omega

def succTotal (x : Fin 30030) : Fin 30030 :=
  ⟨(x.val + 1) % 30030, by omega⟩

/-- Sheet-coordinate successor with a unit carry at the base cut. -/
def sheetStep (p : Fin 2730 × Fin 11) : Fin 2730 × Fin 11 :=
  (⟨(p.1.val + 1) % 2730, by omega⟩,
   ⟨(p.2.val + if p.1.val = 2729 then 1 else 0) % 11, by omega⟩)

theorem toSheet_succTotal (x : Fin 30030) :
    toSheet (succTotal x) = sheetStep (toSheet x) := by
  apply Prod.ext
  · apply Fin.ext; dsimp [toSheet, succTotal, sheetStep]; omega
  · apply Fin.ext; dsimp [toSheet, succTotal, sheetStep]; split <;> omega

theorem iter_succTotal (k : Nat) (x : Fin 30030) :
    iter succTotal k x = ⟨(x.val + k) % 30030, by omega⟩ := by
  induction k with
  | zero => apply Fin.ext; dsimp [iter]; omega
  | succ k ih =>
    rw [iter, ih]
    apply Fin.ext
    dsimp [succTotal]
    omega

/-- A full base loop fixes the base coordinate and advances the sheet by one. -/
theorem sheetStep_monodromy (p : Fin 2730 × Fin 11) :
    iter sheetStep 2730 p = (p.1, ⟨(p.2.val + 1) % 11, by omega⟩) := by
  have hconj := iter_conj succTotal sheetStep toSheet toSheet_succTotal 2730 (fromSheet p)
  rw [toSheet_fromSheet, iter_succTotal] at hconj
  rw [← hconj]
  apply Prod.ext
  · apply Fin.ext; dsimp [toSheet, fromSheet]; omega
  · apply Fin.ext; dsimp [toSheet, fromSheet]; omega

/-- Underflow-free natural-number implementation of the exact sheet query. -/
theorem kElim_exact (x : Fin 30030) :
    x.val / 2730 = (6 * (x.val % 11 + 11 - (x.val % 2730) % 11)) % 11 := by
  omega

/-- Signed-integer form of the same exact sheet query. -/
theorem kElim_int_exact (x : Fin 30030) :
    ((x.val / 2730 : Nat) : Int) =
      (6 * (((x.val % 11 : Nat) : Int) - ((x.val % 2730 : Nat) : Int))) % 11 := by
  omega

/-- Simultaneous successor in the raw base and shadow readings. -/
def rawShadowStep (p : Fin 2730 × Fin 11) : Fin 2730 × Fin 11 :=
  (⟨(p.1.val + 1) % 2730, by omega⟩, ⟨(p.2.val + 1) % 11, by omega⟩)

/-- Coordinate change `(r,s) ↦ (r,6(s-r) mod 11)`. -/
def shadowToSheet (p : Fin 2730 × Fin 11) : Fin 2730 × Fin 11 :=
  (p.1, ⟨(6 * (p.2.val + 11 - p.1.val % 11)) % 11, by omega⟩)

/-- Inverse coordinate change `(r,q) ↦ (r,(2q+r) mod 11)`. -/
def sheetToShadow (p : Fin 2730 × Fin 11) : Fin 2730 × Fin 11 :=
  (p.1, ⟨(2 * p.2.val + p.1.val) % 11, by omega⟩)

theorem shadowToSheet_sheetToShadow (p : Fin 2730 × Fin 11) :
    shadowToSheet (sheetToShadow p) = p := by
  apply Prod.ext <;> apply Fin.ext <;> dsimp [shadowToSheet, sheetToShadow] <;> omega

theorem sheetToShadow_shadowToSheet (p : Fin 2730 × Fin 11) :
    sheetToShadow (shadowToSheet p) = p := by
  apply Prod.ext <;> apply Fin.ext <;> dsimp [shadowToSheet, sheetToShadow] <;> omega

/-- K-Elimination conjugates shadow drift to the single-cut unit-carry dynamics. -/
theorem kElim_gauge_conjugacy (p : Fin 2730 × Fin 11) :
    shadowToSheet (rawShadowStep p) = sheetStep (shadowToSheet p) := by
  apply Prod.ext
  · apply Fin.ext; dsimp [shadowToSheet, rawShadowStep, sheetStep]
  · apply Fin.ext
    dsimp [shadowToSheet, rawShadowStep, sheetStep]
    split
    · rename_i h
      rw [h]
      omega
    · rename_i h
      have hr : p.1.val + 1 < 2730 := by omega
      rw [Nat.mod_eq_of_lt hr]
      omega

end FoliatedCoprimeGeometry
