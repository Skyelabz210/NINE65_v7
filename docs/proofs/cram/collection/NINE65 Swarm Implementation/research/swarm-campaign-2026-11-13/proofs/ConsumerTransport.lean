import UniversalLift

/-!
Consumer-directed exact transport and dynamical closure.

The source type may be a subtype of the states admitted by a range or other
invariant. A source operation on that subtype must already preserve admission.
The existence of an image decoder is a mathematical assertion, not an efficient
implementation. In particular no hidden source, full winding, or synthetic
residue emitter is introduced as a runtime input.
-/

namespace KElimination.ConsumerTransport

open ExactObservation

universe u v w z t

/-- Several requested outputs need only the intersection of their ambiguities.
This applies to nonlinear queries as well as additive ones. -/
theorem paired_queries_iff
    {X : Type u} {R : Type v} {Y : Type w} {Z : Type z}
    (observe : X → R) (first : X → Y) (second : X → Z) :
    FiberConstant observe (fun x => (first x, second x)) ↔
      FiberConstant observe first ∧ FiberConstant observe second := by
  constructor
  · intro h
    exact ⟨fun x y heq => congrArg Prod.fst (h x y heq),
      fun x y heq => congrArg Prod.snd (h x y heq)⟩
  · rintro ⟨hf, hs⟩ x y heq
    exact Prod.ext (hf x y heq) (hs x y heq)

/-- The bundle can be any indexed family, including a finite compiler demand
set. This is a statement about exactness, not its aggregate computation cost. -/
theorem indexed_queries_iff
    {X : Type u} {R : Type v} {I : Type w} {Y : I → Type z}
    (observe : X → R) (queries : (i : I) → X → Y i) :
    FiberConstant observe (fun x i => queries i x) ↔
      ∀ i, FiberConstant observe (queries i) := by
  constructor
  · intro h i x y heq
    exact congrFun (h x y heq) i
  · intro h x y heq
    funext i
    exact h i x y heq

/-- Deterministic processing of an available query never demands more source
information. It may itself take arbitrarily much work. -/
theorem postprocess_sufficient
    {X : Type u} {R : Type v} {Y : Type w} {Z : Type z}
    (observe : X → R) (query : X → Y) (finish : Y → Z)
    (hquery : FiberConstant observe query) :
    FiberConstant observe (finish ∘ query) := by
  intro x y heq
  exact congrArg finish (hquery x y heq)

/-- For an injective output conversion, exact information demand is unchanged. -/
theorem injective_postprocess_iff
    {X : Type u} {R : Type v} {Y : Type w} {Z : Type z}
    (observe : X → R) (query : X → Y) (finish : Y → Z)
    (hfinish : ∀ a b, finish a = finish b → a = b) :
    FiberConstant observe (finish ∘ query) ↔ FiberConstant observe query := by
  constructor
  · intro h x y heq
    exact hfinish _ _ (h x y heq)
  · exact postprocess_sufficient observe query finish

/-- An observation may be sufficient for a query today without being closed
under a source transition. Stability is precisely the missing condition. -/
def Stable {X : Type u} {R : Type v}
    (observe : X → R) (step : X → X) : Prop :=
  FiberConstant observe (observe ∘ step)

/-- The exact dynamic quotient exists on valid readings iff the transition
preserves observation fibers. Invalid readings have no required extension. -/
theorem quotient_transition_exists_iff
    {X : Type u} {R : Type v} (observe : X → R) (step : X → X) :
    (∃ advance : Observed observe → Observed observe,
      ∀ x, advance (reading observe x) = reading observe (step x)) ↔
    Stable observe step := by
  rw [recoverable_iff]
  constructor
  · intro h x y heq
    exact congrArg Subtype.val (h x y heq)
  · intro h x y heq
    exact Subtype.ext (h x y heq)

/-- The quotient transition is unique wherever the observation is authentic. -/
theorem quotient_transition_unique
    {X : Type u} {R : Type v} (observe : X → R) (step : X → X)
    (advance other : Observed observe → Observed observe)
    (ha : ∀ x, advance (reading observe x) = reading observe (step x))
    (hb : ∀ x, other (reading observe x) = reading observe (step x)) :
    advance = other := by
  funext r
  obtain ⟨x, hx⟩ := r.property
  have hr : reading observe x = r := Subtype.ext hx
  rw [← hr, ha, hb]

/-- A known quotient transition transports every currently available consumer
through that transition, without requiring full-state reconstruction. -/
theorem stable_transports_consumer
    {X : Type u} {R : Type v} {Y : Type w}
    (observe : X → R) (step : X → X) (query : X → Y)
    (hstep : Stable observe step) (hquery : FiberConstant observe query) :
    FiberConstant observe (query ∘ step) := by
  intro x y heq
  exact hquery (step x) (step y) (hstep x y heq)

/-- Stable transitions remain stable when composed in program order. -/
theorem stable_composition
    {X : Type u} {R : Type v} (observe : X → R) (first second : X → X)
    (hfirst : Stable observe first) (hsecond : Stable observe second) :
    Stable observe (second ∘ first) := by
  intro x y heq
  exact hsecond (first x) (first y) (hfirst x y heq)

/-- A list of admitted controls preserves indistinguishability when every
primitive preserves it. The number of primitives is finite but unrestricted. -/
theorem stable_finite_program
    {X : Type u} {R : Type v} {Op : Type w}
    (observe : X → R) (semantic : Op → X → X)
    (hstep : ∀ op, Stable observe (semantic op)) (program : List Op) :
    Stable observe (fun x => program.foldl (fun y op => semantic op y) x) := by
  intro x y heq
  induction program generalizing x y with
  | nil => exact heq
  | cons op rest ih =>
    simp only [List.foldl_cons, Function.comp_apply]
    exact ih (semantic op x) (semantic op y) (hstep op x y heq)

/-- Available outputs remain exact after a stable finite program. This differs
from an arithmetic implementation refinement: stability alone supplies neither
a fast transition algorithm nor an encrypted implementation. -/
theorem finite_program_consumer_sufficient
    {X : Type u} {R : Type v} {Op : Type w} {Y : Type z}
    (observe : X → R) (semantic : Op → X → X)
    (hstep : ∀ op, Stable observe (semantic op)) (program : List Op)
    (query : X → Y) (hquery : FiberConstant observe query) :
    FiberConstant observe
      (fun x => query (program.foldl (fun y op => semantic op y) x)) := by
  exact stable_transports_consumer observe _ query
    (stable_finite_program observe semantic hstep program) hquery

/-- Consumer-specific demand may be strictly weaker than a stable full
observation. A compiler may prove the pullback query directly. -/
theorem terminal_query_exists_iff
    {X : Type u} {R : Type v} {Op : Type w} {Y : Type z}
    (observe : X → R) (semantic : Op → X → X) (program : List Op)
    (query : X → Y) :
    (∃ answer : Observed observe → Y,
      ∀ x, answer (reading observe x) =
        query (program.foldl (fun y op => semantic op y) x)) ↔
    FiberConstant observe
      (fun x => query (program.foldl (fun y op => semantic op y) x)) := by
  exact recoverable_iff observe _

/-- Reversibly changing a reading's representation preserves the dynamic
closure question. Surjective reconstruction of the source is not assumed. -/
theorem stable_under_equivalent_observations
    {X : Type u} {R : Type v} {S : Type w}
    (observe : X → R) (other : X → S) (forward : R → S) (back : S → R)
    (hf : ∀ x, forward (observe x) = other x)
    (hb : ∀ x, back (other x) = observe x) (step : X → X) :
    Stable observe step ↔ Stable other step := by
  constructor
  · intro h x y heq
    have base : observe x = observe y := by rw [← hb x, ← hb y, heq]
    have next := h x y base
    change observe (step x) = observe (step y) at next
    change other (step x) = other (step y)
    rw [← hf (step x), ← hf (step y), next]
  · intro h x y heq
    have base : other x = other y := by rw [← hf x, ← hf y, heq]
    have next := h x y base
    change other (step x) = other (step y) at next
    change observe (step x) = observe (step y)
    rw [← hb (step x), ← hb (step y), next]

open UniversalLift Lean.Grind

/-- The linear dynamical specialization is exact kernel invariance. For a
matrix observer B and transition F, this is F(ker B) contained in ker B.
It is the missing premise for autonomous evolution on observed state. -/
theorem additive_stability_iff_kernel_invariant
    {X : Type u} {R : Type v} [AddCommGroup X] [AddCommGroup R]
    (observe : AddMap X R) (step : AddMap X X) :
    Stable observe.apply step.apply ↔
      ∀ delta, observe.apply delta = 0 → observe.apply (step.apply delta) = 0 := by
  constructor
  · intro h delta hzero
    have hz : observe.apply delta = observe.apply 0 := by
      rw [observe.map_zero]
      exact hzero
    have hnext := h delta 0 hz
    change observe.apply (step.apply delta) = observe.apply (step.apply 0) at hnext
    simpa only [step.map_zero, observe.map_zero] using hnext
  · intro h x y heq
    apply (observe.same_reading_iff _ _).mpr
    rw [← step.map_sub]
    exact h (x - y) ((observe.same_reading_iff x y).mp heq)

/-- Explicit finite counterexample: parity is not an autonomous quotient for
integer halving. Today's exact reading does not entail tomorrow's reading. -/
theorem parity_halving_not_stable :
    ¬ Stable (fun x : Nat => x % 2) (fun x => x / 2) := by
  intro h
  have impossible := h 0 2 (by decide)
  change 0 = 1 at impossible
  contradiction

end KElimination.ConsumerTransport

#print axioms KElimination.ConsumerTransport.paired_queries_iff
#print axioms KElimination.ConsumerTransport.indexed_queries_iff
#print axioms KElimination.ConsumerTransport.postprocess_sufficient
#print axioms KElimination.ConsumerTransport.injective_postprocess_iff
#print axioms KElimination.ConsumerTransport.quotient_transition_exists_iff
#print axioms KElimination.ConsumerTransport.quotient_transition_unique
#print axioms KElimination.ConsumerTransport.stable_transports_consumer
#print axioms KElimination.ConsumerTransport.stable_composition
#print axioms KElimination.ConsumerTransport.stable_finite_program
#print axioms KElimination.ConsumerTransport.finite_program_consumer_sufficient
#print axioms KElimination.ConsumerTransport.terminal_query_exists_iff
#print axioms KElimination.ConsumerTransport.stable_under_equivalent_observations
#print axioms KElimination.ConsumerTransport.additive_stability_iff_kernel_invariant
#print axioms KElimination.ConsumerTransport.parity_halving_not_stable
