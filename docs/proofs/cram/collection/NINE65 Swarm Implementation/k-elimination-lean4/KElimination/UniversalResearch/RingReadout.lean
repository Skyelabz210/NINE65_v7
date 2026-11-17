import Std

/-!
Constructive ring specialization of observed-lift elimination.

The readout uses only two supplied observations and a supplied left inverse:
one subtraction and one multiplication in the observation ring. Its result is
the observation of K. Selecting an exact source K requires a separate admitted
domain/decoder theorem. No source X or persistent K is a readout input.

These theorems use Lean's bundled algebra hierarchy. The principal readout and
solution-fiber statements hold even for noncommutative rings; multiplication
order and the side of the inverse are explicit.
-/

namespace KElimination.RingReadout

open Lean.Grind

universe u v w

/-- The two homomorphism laws needed for the readout. Unitality is not needed;
the separate left-inverse certificate is an equation in the observation ring.
-/
structure Observation (R : Type u) (H : Type v) [Ring R] [Ring H] where
  read : R → H
  map_add : ∀ a b, read (a + b) = read a + read b
  map_mul : ∀ a b, read (a * b) = read a * read b

namespace Observation

variable {R : Type u} {H : Type v} [Ring R] [Ring H]

theorem map_zero (h : Observation R H) : h.read 0 = 0 := by
  apply (AddCommGroup.add_right_inj (h.read 0) (h.read 0) 0).mp
  rw [← h.map_add, Semiring.add_zero, Semiring.add_zero]

theorem map_sub (h : Observation R H) (a b : R) :
    h.read (a - b) = h.read a - h.read b := by
  symm
  apply AddCommGroup.sub_eq_iff.mpr
  rw [← h.map_add, AddCommGroup.sub_add_cancel]

theorem map_neg (h : Observation R H) (a : R) :
    h.read (-a) = -(h.read a) := by
  have ha : (0 : R) - a = -a := by
    rw [Ring.sub_eq_add_neg, AddCommMonoid.zero_add]
  rw [← ha, h.map_sub, h.map_zero, Ring.sub_eq_add_neg, AddCommMonoid.zero_add]

end Observation

theorem left_mul_sub {H : Type v} [Ring H] (a b c : H) :
    a * (b - c) = a * b - a * c := by
  rw [Ring.sub_eq_add_neg, Semiring.left_distrib, Ring.mul_neg,
      Ring.sub_eq_add_neg]

/-- This is the complete computational readout; inputs are observations only. -/
def readout {H : Type v} [Ring H] (inverse baseReading sourceReading : H) : H :=
  inverse * (sourceReading - baseReading)

/-- A source decomposition gives an observed phase defect. -/
theorem phase_defect {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : Observation R H) (X r M K : R) (hsource : X = r + M * K) :
    h.read X - h.read r = h.read M * h.read K := by
  rw [hsource, h.map_add, h.map_mul, Semiring.add_comm (h.read r),
      AddCommGroup.add_sub_cancel]

/-- Left cancellation gives the exact observed lift, without commutativity. -/
theorem unit_readout {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : Observation R H) (X r M K : R) (inverse : H)
    (hsource : X = r + M * K) (hunit : inverse * h.read M = 1) :
    readout inverse (h.read r) (h.read X) = h.read K := by
  unfold readout
  rw [phase_defect h X r M K hsource, ← Semiring.mul_assoc, hunit,
      Semiring.one_mul]

/-- When the source is a right multiple, use a right inverse on the right. -/
theorem right_unit_readout {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : Observation R H) (X r M K : R) (inverse : H)
    (hsource : X = r + K * M) (hunit : h.read M * inverse = 1) :
    (h.read X - h.read r) * inverse = h.read K := by
  rw [hsource, h.map_add, h.map_mul, Semiring.add_comm (h.read r),
      AddCommGroup.add_sub_cancel, Semiring.mul_assoc, hunit,
      Semiring.mul_one]

/-- Invisible changes of a source lift: the preimage of the observer kernel
under multiplication by M. In a commutative ring this is the ideal quotient
(ker h : M). This predicate also makes sense in a noncommutative ring.
-/
def LiftNull {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : Observation R H) (M delta : R) : Prop := h.read (M * delta) = 0

/-- All compatible solutions differ from any one solution by LiftNull.
No inverse, primality, coprimality or source range is required for this result.
-/
theorem solution_fiber {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : Observation R H) (r M K₀ : R) (observed : H)
    (hbase : h.read (r + M * K₀) = observed) (K : R) :
    h.read (r + M * K) = observed ↔ LiftNull h M (K - K₀) := by
  unfold LiftNull
  rw [← hbase, h.map_add, h.map_add, h.map_mul, h.map_mul,
      h.map_mul, h.map_sub, left_mul_sub]
  exact (AddCommGroup.add_right_inj _ _ _).trans
    AddCommGroup.sub_eq_zero_iff.symm

/-- The exact recovery criterion is kernel separation on the admitted set. -/
theorem injective_on_iff_lift_null_separates
    {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : Observation R H) (r M : R) (admitted : R → Prop) :
    (∀ a b, admitted a → admitted b →
      h.read (r + M * a) = h.read (r + M * b) → a = b) ↔
    (∀ a b, admitted a → admitted b → LiftNull h M (a - b) → a = b) := by
  constructor
  · intro hinj a b ha hb hnull
    apply hinj a b ha hb
    exact (solution_fiber h r M b (h.read (r + M * b)) rfl a).mpr hnull
  · intro hsep a b ha hb heq
    apply hsep a b ha hb
    exact (solution_fiber h r M b (h.read (r + M * b)) rfl a).mp heq

/-- A left inverse removes the multiplier's ambiguity. Any remaining ambiguity
is exactly the observer kernel, so a source decoder still needs its own range
or separation certificate.
-/
theorem unit_lift_null_iff {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : Observation R H) (M delta : R) (inverse : H)
    (hunit : inverse * h.read M = 1) :
    LiftNull h M delta ↔ h.read delta = 0 := by
  unfold LiftNull
  rw [h.map_mul]
  constructor
  · intro hz
    have hcancel := congrArg (fun value => inverse * value) hz
    change inverse * (h.read M * h.read delta) = inverse * 0 at hcancel
    rw [← Semiring.mul_assoc, hunit, Semiring.one_mul,
        Semiring.mul_zero] at hcancel
    exact hcancel
  · intro hz
    rw [hz, Semiring.mul_zero]

theorem lift_null_zero {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : Observation R H) (M : R) : LiftNull h M 0 := by
  unfold LiftNull
  rw [Semiring.mul_zero, h.map_zero]

theorem lift_null_add {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : Observation R H) (M a b : R)
    (ha : LiftNull h M a) (hb : LiftNull h M b) : LiftNull h M (a + b) := by
  unfold LiftNull at *
  rw [Semiring.left_distrib, h.map_add, ha, hb, Semiring.add_zero]

theorem lift_null_neg {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : Observation R H) (M a : R) (ha : LiftNull h M a) :
    LiftNull h M (-a) := by
  unfold LiftNull at *
  rw [Ring.mul_neg, h.map_neg, ha, AddCommGroup.neg_zero]

/-- The invisible changes form a right ideal even without commutativity. -/
theorem lift_null_mul_right {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : Observation R H) (M a b : R) (ha : LiftNull h M a) :
    LiftNull h M (a * b) := by
  unfold LiftNull at *
  rw [← Semiring.mul_assoc, h.map_mul, ha, Semiring.zero_mul]

/-- In the commutative case, this is also closed under left multiplication. -/
theorem lift_null_mul_left {R : Type u} {H : Type v} [CommRing R] [Ring H]
    (h : Observation R H) (M a b : R) (ha : LiftNull h M a) :
    LiftNull h M (b * a) := by
  rw [CommSemiring.mul_comm b a]
  exact lift_null_mul_right h M a b ha

/-- A target view is produced from target components; no inverse is needed. -/
def project {T : Type w} [Ring T] (base scale lift : T) : T := base + scale * lift

theorem target_projection {R : Type u} {T : Type w} [Ring R] [Ring T]
    (target : Observation R T) (X r M K : R) (hsource : X = r + M * K) :
    project (target.read r) (target.read M) (target.read K) = target.read X := by
  unfold project
  rw [hsource, target.map_add, target.map_mul]

end KElimination.RingReadout

#print axioms KElimination.RingReadout.Observation.map_zero
#print axioms KElimination.RingReadout.Observation.map_sub
#print axioms KElimination.RingReadout.Observation.map_neg
#print axioms KElimination.RingReadout.left_mul_sub
#print axioms KElimination.RingReadout.phase_defect
#print axioms KElimination.RingReadout.unit_readout
#print axioms KElimination.RingReadout.right_unit_readout
#print axioms KElimination.RingReadout.solution_fiber
#print axioms KElimination.RingReadout.injective_on_iff_lift_null_separates
#print axioms KElimination.RingReadout.unit_lift_null_iff
#print axioms KElimination.RingReadout.lift_null_zero
#print axioms KElimination.RingReadout.lift_null_add
#print axioms KElimination.RingReadout.lift_null_neg
#print axioms KElimination.RingReadout.lift_null_mul_right
#print axioms KElimination.RingReadout.lift_null_mul_left
#print axioms KElimination.RingReadout.target_projection
