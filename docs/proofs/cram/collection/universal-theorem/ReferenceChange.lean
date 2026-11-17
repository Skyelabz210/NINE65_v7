import UniversalLift

/-!
Changing the affine reference leaves the exact requested result unchanged.
Only the views of the old/new references are needed at runtime. Coordinates
and source values in these statements are mathematical specification variables.
-/

namespace KElimination.ReferenceChange

open Lean.Grind UniversalLift

universe u v w z
variable {G : Type u} {K : Type v} {H : Type w} {T : Type z}
variable [AddCommGroup G] [AddCommGroup K] [AddCommGroup H] [AddCommGroup T]

/-- Moving the reference by i(a) changes its coordinate from k to k-a. -/
theorem shifted_decomposition (embed : AddMap K G) (x r : G) (k a : K)
    (hsource : x = r + embed.apply k) :
    x = (r + embed.apply a) + embed.apply (k - a) := by
  rw [embed.map_sub, AddCommMonoid.add_assoc,
      AddCommMonoid.add_comm (embed.apply a), AddCommGroup.sub_add_cancel]
  exact hsource

/-- The observed difference transforms by subtracting the observed reference
shift. No inverse or source recovery is needed to prove this law. -/
theorem shifted_defect (embed : AddMap K G) (observe : AddMap G H)
    (x r : G) (k a : K) (hsource : x = r + embed.apply k) :
    observe.apply x - observe.apply (r + embed.apply a) =
      (observe.apply x - observe.apply r) - (observe.comp embed).apply a := by
  rw [phase_difference embed observe x (r + embed.apply a) (k - a)
    (shifted_decomposition embed x r k a hsource)]
  rw [(observe.comp embed).map_sub, phase_difference embed observe x r k hsource]

/-- Independent admitted windows may be used before and after changing the
reference. Each readout must satisfy its own concrete decoder law. -/
theorem target_invariant_under_reference_change
    (embed : AddMap K G) (observe : AddMap G H) (target : AddMap G T)
    (oldDomain newDomain : K → Prop) (oldReadout newReadout : H → T)
    (hold : ∀ k, oldDomain k → oldReadout ((observe.comp embed).apply k) =
      target.apply (embed.apply k))
    (hnew : ∀ k, newDomain k → newReadout ((observe.comp embed).apply k) =
      target.apply (embed.apply k))
    (x r : G) (k a : K) (hk : oldDomain k) (hshift : newDomain (k - a))
    (hsource : x = r + embed.apply k) :
    target.apply r + query oldReadout (observe.apply r) (observe.apply x) =
      target.apply (r + embed.apply a) +
        query newReadout (observe.apply (r + embed.apply a)) (observe.apply x) := by
  rw [direct_target_query embed observe target oldDomain oldReadout hold x r k hk hsource]
  rw [direct_target_query embed observe target newDomain newReadout hnew x
    (r + embed.apply a) (k - a) hshift
    (shifted_decomposition embed x r k a hsource)]

end KElimination.ReferenceChange

#print axioms KElimination.ReferenceChange.shifted_decomposition
#print axioms KElimination.ReferenceChange.shifted_defect
#print axioms KElimination.ReferenceChange.target_invariant_under_reference_change
