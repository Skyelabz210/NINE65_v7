import Std

/-! Integral polynomial identities: no field, inverse, odd characteristic or
prime-modulus premise is needed. Actual finite-word execution still needs
the implementation's width and source-binding contract. -/

namespace KElimination.ReflectionInvariant

open Lean.Grind

def reflect {R : Type} [Ring R] (a b c d : R) : R := 2*(b+c+d)-a

def descartes {R : Type} [Ring R] (a b c d : R) : R :=
  2*(a*a+b*b+c*c+d*d)-(a+b+c+d)*(a+b+c+d)

theorem reflection_involution {R : Type} [CommRing R] (a b c d : R) :
    reflect (reflect a b c d) b c d = a := by
  unfold reflect
  grind

theorem reflection_preserves_descartes {R : Type} [CommRing R] (a b c d : R) :
    descartes (reflect a b c d) b c d = descartes a b c d := by
  unfold reflect descartes
  grind

end KElimination.ReflectionInvariant

#print axioms KElimination.ReflectionInvariant.reflection_involution
#print axioms KElimination.ReflectionInvariant.reflection_preserves_descartes
