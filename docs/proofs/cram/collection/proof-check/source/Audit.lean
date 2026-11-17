import KElimination

#print axioms KElimination.key_congruence
#print axioms KElimination.modular_inverse_exists
#print axioms KElimination.kElimination_core
#print axioms KElimination.complexity_improvement
#print axioms Soundness.k_elimination_sound
#print axioms Soundness.k_elimination_complete

-- A proposed abstract kernel, not a claim of implementation refinement.
theorem audit_unit_quotient_recovery {R : Type*} [CommRing R]
    (x r m k u : R) (decomposition : x = r + k * m)
    (inverse : m * u = 1) : (x - r) * u = k := by
  rw [decomposition]
  calc
    (r + k * m - r) * u = k * (m * u) := by ring
    _ = k := by rw [inverse, mul_one]

#print axioms audit_unit_quotient_recovery

-- Concrete rejection of the attachments' natural-subtraction formula.
example : (5 : Nat) / 3 = 1 := by decide
example : (((5 : Nat) % 5 - 5 % 3) * 2) % 5 = 0 := by decide
example : (8 : Nat) / 5 = 1 := by decide
example : (((8 : Nat) % 2 + 2 - 8 % 5) * 1) % 2 = 0 := by decide
