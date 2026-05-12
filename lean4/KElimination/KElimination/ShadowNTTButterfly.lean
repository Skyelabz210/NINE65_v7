/-
  Shadow NTT Butterfly proofs.

  This file formalizes the algebra behind the shadow-capturing NTT butterfly:
  the butterfly output is the usual invertible Cooley-Tukey map, while the
  shadow is an additional deterministic quotient byproduct.
-/

import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic

namespace KElimination.ShadowNTTButterfly

/-- A Cooley-Tukey butterfly over ZMod q. -/
def butterfly (w u v : ZMod q) : ZMod q × ZMod q :=
  (u + w * v, u - w * v)

/-- The shadowed butterfly returns the same butterfly output plus an extra shadow value. -/
def shadowButterfly (w u v shadow : ZMod q) : (ZMod q × ZMod q) × ZMod q :=
  (butterfly w u v, shadow)

/-- The first projection of a shadowed butterfly is exactly the ordinary butterfly. -/
theorem shadow_projection_eq_butterfly (w u v shadow : ZMod q) :
    (shadowButterfly w u v shadow).1 = butterfly w u v := by
  rfl

/-- Shadow capture is output-independent: changing only the shadow leaves the butterfly output unchanged. -/
theorem shadow_capture_output_independent (w u v s₁ s₂ : ZMod q) :
    (shadowButterfly w u v s₁).1 = (shadowButterfly w u v s₂).1 := by
  rfl

/-- Butterfly coordinates in expanded form. -/
theorem butterfly_fst (w u v : ZMod q) :
    (butterfly w u v).1 = u + w * v := by
  rfl

/-- Butterfly coordinates in expanded form. -/
theorem butterfly_snd (w u v : ZMod q) :
    (butterfly w u v).2 = u - w * v := by
  rfl

/-- If two butterflies with the same nonzero twiddle agree, then twice the upper inputs agree. -/
theorem butterfly_eq_implies_two_u_eq
    (w u v u' v' : ZMod q)
    (h : butterfly w u v = butterfly w u' v') :
    (2 : ZMod q) * u = (2 : ZMod q) * u' := by
  have h1 : u + w * v = u' + w * v' := by
    simpa [butterfly] using congrArg Prod.fst h
  have h2 : u - w * v = u' - w * v' := by
    simpa [butterfly] using congrArg Prod.snd h
  calc
    (2 : ZMod q) * u = (u + w * v) + (u - w * v) := by ring
    _ = (u' + w * v') + (u' - w * v') := by rw [h1, h2]
    _ = (2 : ZMod q) * u' := by ring

/-- If two butterflies with the same twiddle agree, then twice the twiddle-scaled lower inputs agree. -/
theorem butterfly_eq_implies_two_wv_eq
    (w u v u' v' : ZMod q)
    (h : butterfly w u v = butterfly w u' v') :
    (2 : ZMod q) * (w * v) = (2 : ZMod q) * (w * v') := by
  have h1 : u + w * v = u' + w * v' := by
    simpa [butterfly] using congrArg Prod.fst h
  have h2 : u - w * v = u' - w * v' := by
    simpa [butterfly] using congrArg Prod.snd h
  calc
    (2 : ZMod q) * (w * v) = (u + w * v) - (u - w * v) := by ring
    _ = (u' + w * v') - (u' - w * v') := by rw [h1, h2]
    _ = (2 : ZMod q) * (w * v') := by ring

/-- Butterfly injectivity when 2 and the twiddle are nonzero. -/
theorem butterfly_injective
    (w : ZMod q)
    (h2 : (2 : ZMod q) ≠ 0)
    (hw : w ≠ 0) :
    Function.Injective (fun x : ZMod q × ZMod q => butterfly w x.1 x.2) := by
  intro x y h
  rcases x with ⟨u, v⟩
  rcases y with ⟨u', v'⟩
  have hu2 : (2 : ZMod q) * u = (2 : ZMod q) * u' :=
    butterfly_eq_implies_two_u_eq w u v u' v' h
  have hu : u = u' := mul_left_cancel₀ h2 hu2
  have hv2 : (2 : ZMod q) * (w * v) = (2 : ZMod q) * (w * v') :=
    butterfly_eq_implies_two_wv_eq w u v u' v' h
  have hwv : w * v = w * v' := mul_left_cancel₀ h2 hv2
  have hv : v = v' := mul_left_cancel₀ hw hwv
  simp [hu, hv]

/-- Explicit inverse for the butterfly when inv2 is 1/2 and winv is w⁻¹. -/
def butterflyInv (inv2 winv : ZMod q) (y : ZMod q × ZMod q) : ZMod q × ZMod q :=
  (inv2 * (y.1 + y.2), winv * inv2 * (y.1 - y.2))

/-- The explicit inverse is a left inverse under the algebraic inverse hypotheses. -/
theorem butterflyInv_left
    (w inv2 winv u v : ZMod q)
    (h2 : inv2 * (2 : ZMod q) = 1)
    (hw : winv * w = 1) :
    butterflyInv inv2 winv (butterfly w u v) = (u, v) := by
  ext <;> simp [butterflyInv, butterfly]
  · calc
      inv2 * ((u + w * v) + (u - w * v)) = inv2 * ((2 : ZMod q) * u) := by ring
      _ = (inv2 * (2 : ZMod q)) * u := by ring
      _ = u := by rw [h2]; ring
  · calc
      winv * inv2 * ((u + w * v) - (u - w * v)) = winv * inv2 * ((2 : ZMod q) * (w * v)) := by ring
      _ = winv * (inv2 * (2 : ZMod q)) * (w * v) := by ring
      _ = winv * w * v := by rw [h2]; ring
      _ = v := by rw [hw]; ring

/-- The explicit inverse is a right inverse under the algebraic inverse hypotheses. -/
theorem butterflyInv_right
    (w inv2 winv y₁ y₂ : ZMod q)
    (h2 : (2 : ZMod q) * inv2 = 1)
    (hw : w * winv = 1) :
    butterfly w (butterflyInv inv2 winv (y₁, y₂)).1 (butterflyInv inv2 winv (y₁, y₂)).2 = (y₁, y₂) := by
  ext <;> simp [butterflyInv, butterfly]
  · calc
      inv2 * (y₁ + y₂) + w * (winv * inv2 * (y₁ - y₂))
          = inv2 * ((y₁ + y₂) + (y₁ - y₂)) := by rw [show w * (winv * inv2 * (y₁ - y₂)) = inv2 * (y₁ - y₂) by calc
              w * (winv * inv2 * (y₁ - y₂)) = (w * winv) * inv2 * (y₁ - y₂) := by ring
              _ = inv2 * (y₁ - y₂) := by rw [hw]; ring]
        ring
      _ = inv2 * ((2 : ZMod q) * y₁) := by ring
      _ = ((2 : ZMod q) * inv2) * y₁ := by ring
      _ = y₁ := by rw [h2]; ring
  · calc
      inv2 * (y₁ + y₂) - w * (winv * inv2 * (y₁ - y₂))
          = inv2 * ((y₁ + y₂) - (y₁ - y₂)) := by rw [show w * (winv * inv2 * (y₁ - y₂)) = inv2 * (y₁ - y₂) by calc
              w * (winv * inv2 * (y₁ - y₂)) = (w * winv) * inv2 * (y₁ - y₂) := by ring
              _ = inv2 * (y₁ - y₂) := by rw [hw]; ring]
        ring
      _ = inv2 * ((2 : ZMod q) * y₂) := by ring
      _ = ((2 : ZMod q) * inv2) * y₂ := by ring
      _ = y₂ := by rw [h2]; ring

end KElimination.ShadowNTTButterfly
