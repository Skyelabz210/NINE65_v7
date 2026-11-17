import KElimination.UniversalResearch.ExactObservation

/-!
Constructive universal K-Elimination layer over additive groups.

Algebra comes from Lean's bundled standard hierarchy, not project axioms.
The theorem is about observed affine extensions, not a claim that every
domain has an effective inexpensive inverse. Concrete readouts are proved
separately. The computational query accepts only two observations; source x,
chart representative r and lift k occur only as specification variables.
-/

namespace KElimination.UniversalLift

open Lean.Grind

universe u v w z

structure AddMap (A : Type u) (B : Type v)
    [AddCommGroup A] [AddCommGroup B] where
  apply : A → B
  map_add : ∀ a b, apply (a + b) = apply a + apply b

namespace AddMap

variable {A : Type u} {B : Type v} {C : Type w}
variable [AddCommGroup A] [AddCommGroup B] [AddCommGroup C]

theorem map_zero (h : AddMap A B) : h.apply 0 = 0 := by
  apply Eq.symm
  apply (AddCommGroup.add_right_inj (h.apply 0) 0 (h.apply 0)).mp
  simpa only [AddCommMonoid.add_zero] using h.map_add 0 0

theorem map_neg (h : AddMap A B) (a : A) : h.apply (-a) = -h.apply a := by
  apply (AddCommGroup.add_left_inj (h.apply a)).mp
  rw [← h.map_add, AddCommGroup.neg_add_cancel, h.map_zero,
    AddCommGroup.neg_add_cancel]

theorem map_sub (h : AddMap A B) (a b : A) :
    h.apply (a - b) = h.apply a - h.apply b := by
  rw [AddCommGroup.sub_eq_add_neg, h.map_add, h.map_neg,
    AddCommGroup.sub_eq_add_neg]

def comp (g : AddMap B C) (f : AddMap A B) : AddMap A C where
  apply a := g.apply (f.apply a)
  map_add a b := by rw [f.map_add, g.map_add]

/-- The exact ambiguity of an additive observation is its difference kernel. -/
theorem same_reading_iff (h : AddMap A B) (a b : A) :
    h.apply a = h.apply b ↔ h.apply (a - b) = 0 := by
  rw [h.map_sub, AddCommGroup.sub_eq_zero_iff]

end AddMap

variable {G : Type u} {K : Type v} {H : Type w}
variable [AddCommGroup G] [AddCommGroup K] [AddCommGroup H]

/-- Actual runtime function: subtract the chart's observation, then apply a
specified readout. It receives no full source x or persistent lift k. -/
def query {V : Type z} (readout : H → V) (chart source : H) : V :=
  readout (source - chart)

/-- Universal elimination identity: the observed phase difference isolates
the observer's image of the hidden displacement. -/
theorem phase_difference
    (embed : AddMap K G) (observe : AddMap G H)
    (x r : G) (k : K) (hsource : x = r + embed.apply k) :
    observe.apply x - observe.apply r =
      (observe.comp embed).apply k := by
  rw [hsource, observe.map_add]
  change observe.apply r + observe.apply (embed.apply k) - observe.apply r =
    observe.apply (embed.apply k)
  rw [AddCommMonoid.add_comm (observe.apply r), AddCommGroup.add_sub_cancel]

/-- Complete solution fiber, including noninjective and nonunit observers. -/
theorem candidate_iff_kernel
    (embed : AddMap K G) (observe : AddMap G H)
    (x r : G) (k candidate : K) (hsource : x = r + embed.apply k) :
    observe.apply (r + embed.apply candidate) = observe.apply x ↔
      (observe.comp embed).apply (candidate - k) = 0 := by
  rw [hsource, observe.map_add, observe.map_add,
    AddCommGroup.add_right_inj]
  exact (observe.comp embed).same_reading_iff candidate k

/-- Every observed affine fiber has at most one admitted coordinate iff its
kernel contains no nonzero difference of admitted coordinates. -/
theorem separation_iff
    (linear : AddMap K H) (admitted : K → Prop) :
    (∀ a b, admitted a → admitted b →
      linear.apply a = linear.apply b → a = b) ↔
    (∀ a b, admitted a → admitted b →
      linear.apply (a - b) = 0 → a = b) := by
  constructor
  · intro hinj a b ha hb hzero
    exact hinj a b ha hb ((linear.same_reading_iff a b).mpr hzero)
  · intro hker a b ha hb heq
    exact hker a b ha hb ((linear.same_reading_iff a b).mp heq)

/-- Universal exact-query criterion, stronger than requiring full lift recovery.
An arbitrary query of the lift is recoverable iff it is constant on exactly
the ambiguity classes computed by the linear observation kernel.
The existence direction is mathematical and uses Classical.choice through
ExactObservation.recoverable_iff; it is not an efficient decoder constructor.
-/
theorem lift_query_exists_iff
    {V : Type z} (linear : AddMap K H) (admitted : K → Prop) (wanted : K → V) :
    (∃ answer : ExactObservation.Observed
        (fun k : {k : K // admitted k} => linear.apply k.val) → V,
      ∀ k : {k : K // admitted k},
        answer (ExactObservation.reading
          (fun j : {j : K // admitted j} => linear.apply j.val) k) = wanted k.val) ↔
    (∀ a b, admitted a → admitted b →
      linear.apply (a - b) = 0 → wanted a = wanted b) := by
  rw [ExactObservation.recoverable_iff]
  constructor
  · intro h a b ha hb hzero
    exact h ⟨a, ha⟩ ⟨b, hb⟩ ((linear.same_reading_iff a b).mpr hzero)
  · intro h a b heq
    exact h a.val b.val a.property b.property
      ((linear.same_reading_iff a.val b.val).mp heq)

/-- On the whole lift group, exact transport of an additive consumer is
equivalent to kernel inclusion. It may hold even when full lift recovery
does not. The factor is defined only on genuinely observed values. -/
theorem target_factor_exists_iff
    {T : Type z} [AddCommGroup T]
    (linear : AddMap K H) (consumer : AddMap K T) :
    (∃ answer : ExactObservation.Observed linear.apply → T,
      ∀ k, answer (ExactObservation.reading linear.apply k) = consumer.apply k) ↔
    (∀ delta, linear.apply delta = 0 → consumer.apply delta = 0) := by
  rw [ExactObservation.recoverable_iff]
  constructor
  · intro hfiber delta hzero
    have heq : linear.apply delta = linear.apply 0 := by
      rw [linear.map_zero]
      exact hzero
    have htarget := hfiber delta 0 heq
    rw [consumer.map_zero] at htarget
    exact htarget
  · intro hkernel a b heq
    apply (consumer.same_reading_iff a b).mpr
    exact hkernel (a - b) ((linear.same_reading_iff a b).mp heq)

/-- An exact factor on the observation image is unique. This is a statement
about every valid observation, not about arbitrary malformed inputs. -/
theorem target_factor_unique
    {T : Type z} (linear : AddMap K H) (wanted : K → T)
    (first second : ExactObservation.Observed linear.apply → T)
    (hfirst : ∀ k, first (ExactObservation.reading linear.apply k) = wanted k)
    (hsecond : ∀ k, second (ExactObservation.reading linear.apply k) = wanted k) :
    ∀ observed, first observed = second observed := by
  intro observed
  obtain ⟨k, hk⟩ := observed.property
  have hreading : ExactObservation.reading linear.apply k = observed :=
    Subtype.ext hk
  rw [← hreading, hfirst k, hsecond k]

/-- The factor preserves the addition induced on the observation image.
This makes no claim that it extends additively to every element of H. -/
theorem target_factor_additive
    {T : Type z} [AddCommGroup T]
    (linear : AddMap K H) (consumer : AddMap K T)
    (answer : ExactObservation.Observed linear.apply → T)
    (hanswer : ∀ k, answer (ExactObservation.reading linear.apply k) = consumer.apply k)
    (a b : K) :
    answer (ExactObservation.reading linear.apply (a + b)) =
      answer (ExactObservation.reading linear.apply a) +
      answer (ExactObservation.reading linear.apply b) := by
  rw [hanswer (a + b), hanswer a, hanswer b, consumer.map_add]

/-- Once a concrete readout is proved on observed lift coordinates, the same
readout works on authentic source/chart readings. Neither x nor k is a runtime
argument. The ring and integer modules construct particular readouts.
-/
theorem constructive_query_correct
    {V : Type z} (embed : AddMap K G) (observe : AddMap G H)
    (admitted : K → Prop) (wanted : K → V) (readout : H → V)
    (hread : ∀ k, admitted k →
      readout ((observe.comp embed).apply k) = wanted k)
    (x r : G) (k : K) (hk : admitted k)
    (hsource : x = r + embed.apply k) :
    query readout (observe.apply r) (observe.apply x) = wanted k := by
  unfold query
  rw [phase_difference embed observe x r k hsource]
  exact hread k hk

/-- Full lift recovery is a particular query, not a required intermediate
for every consumer. -/
theorem constructive_lift_correct
    (embed : AddMap K G) (observe : AddMap G H)
    (admitted : K → Prop) (readout : H → K)
    (hread : ∀ k, admitted k →
      readout ((observe.comp embed).apply k) = k)
    (x r : G) (k : K) (hk : admitted k)
    (hsource : x = r + embed.apply k) :
    query readout (observe.apply r) (observe.apply x) = k :=
  constructive_query_correct embed observe admitted id readout hread x r k hk hsource

/-- Exact consumer projection can avoid emitting the source itself. The only
base-chart input used by the consumer is its target observation target(r).
-/
theorem target_projection
    {T : Type z} [AddCommGroup T]
    (embed : AddMap K G) (observe : AddMap G H) (target : AddMap G T)
    (admitted : K → Prop) (readout : H → K)
    (hread : ∀ k, admitted k →
      readout ((observe.comp embed).apply k) = k)
    (x r : G) (k : K) (hk : admitted k)
    (hsource : x = r + embed.apply k) :
    target.apply r + target.apply (embed.apply
      (query readout (observe.apply r) (observe.apply x))) = target.apply x := by
  rw [constructive_lift_correct embed observe admitted readout hread x r k hk hsource]
  rw [hsource, target.map_add]

/-- The target may decode only its own displacement image, even when the
full lift is ambiguous. This is often strictly weaker than lift recovery. -/
theorem direct_target_query
    {T : Type z} [AddCommGroup T]
    (embed : AddMap K G) (observe : AddMap G H) (target : AddMap G T)
    (admitted : K → Prop) (readout : H → T)
    (hread : ∀ k, admitted k →
      readout ((observe.comp embed).apply k) = target.apply (embed.apply k))
    (x r : G) (k : K) (hk : admitted k)
    (hsource : x = r + embed.apply k) :
    target.apply r + query readout (observe.apply r) (observe.apply x) =
      target.apply x := by
  rw [constructive_query_correct embed observe admitted
    (fun j => target.apply (embed.apply j)) readout hread x r k hk hsource]
  rw [hsource, target.map_add]

end KElimination.UniversalLift

#print axioms KElimination.UniversalLift.AddMap.map_zero
#print axioms KElimination.UniversalLift.AddMap.map_neg
#print axioms KElimination.UniversalLift.AddMap.map_sub
#print axioms KElimination.UniversalLift.AddMap.same_reading_iff
#print axioms KElimination.UniversalLift.phase_difference
#print axioms KElimination.UniversalLift.candidate_iff_kernel
#print axioms KElimination.UniversalLift.separation_iff
#print axioms KElimination.UniversalLift.lift_query_exists_iff
#print axioms KElimination.UniversalLift.target_factor_exists_iff
#print axioms KElimination.UniversalLift.target_factor_unique
#print axioms KElimination.UniversalLift.target_factor_additive
#print axioms KElimination.UniversalLift.constructive_query_correct
#print axioms KElimination.UniversalLift.constructive_lift_correct
#print axioms KElimination.UniversalLift.target_projection
#print axioms KElimination.UniversalLift.direct_target_query
