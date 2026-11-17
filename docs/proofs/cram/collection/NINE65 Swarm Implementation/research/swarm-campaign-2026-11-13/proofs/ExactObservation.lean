import Std

/-!
Research certificate for the generalized query and composition layer.
These are mathematical specification theorems, not executable residue decoders.
In particular the existence proof uses Classical.choose. A concrete CRAM query
still needs an implemented algorithm, source binding and its refinement proof.
The arbitrary type X may be a subtype of admissible/bounded source states.
-/

namespace KElimination.ExactObservation

universe u v w z

def Observed {X : Type u} {R : Type v} (observe : X → R) :=
  { r : R // ∃ x, observe x = r }

def reading {X : Type u} {R : Type v} (observe : X → R) (x : X) :
    Observed observe := ⟨observe x, x, rfl⟩

def FiberConstant {X : Type u} {R : Type v} {Y : Type w}
    (observe : X → R) (query : X → Y) : Prop :=
  ∀ x y, observe x = observe y → query x = query y

/-- A query is recoverable precisely when it is constant on observation fibers.
No algebraic structure, finiteness or full-state reconstruction is assumed.
The inverse on the image exists mathematically; no efficiency is inferred.
-/
theorem recoverable_iff {X : Type u} {R : Type v} {Y : Type w}
    (observe : X → R) (query : X → Y) :
    (∃ answer : Observed observe → Y,
      ∀ x, answer (reading observe x) = query x) ↔
    FiberConstant observe query := by
  constructor
  · intro h x y hxy
    obtain ⟨answer, ha⟩ := h
    have hr : reading observe x = reading observe y := Subtype.ext hxy
    rw [← ha x, ← ha y, hr]
  · intro h
    refine ⟨fun r => query (Classical.choose r.property), ?_⟩
    intro x
    exact h _ x (Classical.choose_spec (reading observe x).property)

/-- Authentic refinement can only add recoverable queries. -/
theorem refined_observation_suffices
    {X : Type u} {R : Type v} {S : Type z} {Y : Type w}
    (observe : X → R) (finer : X → S) (forget : S → R)
    (query : X → Y) (hsource : ∀ x, forget (finer x) = observe x)
    (hquery : FiberConstant observe query) : FiberConstant finer query := by
  intro x y hxy
  apply hquery
  rw [← hsource x, ← hsource y, hxy]

/-- A collision only rules out a query that separates the colliding states. -/
theorem collision_obstructs_query
    {X : Type u} {R : Type v} {Y : Type w}
    (observe : X → R) (query : X → Y) (x y : X)
    (hobs : observe x = observe y) (hdiff : query x ≠ query y) :
    ¬ FiberConstant observe query := by
  intro h
  exact hdiff (h x y hobs)

/-- This equation is a refinement specification. encode is not a runtime oracle. -/
def Refines {X : Type u} {R : Type v}
    (encode : X → R) (semantic : X → X) (run : R → R) : Prop :=
  ∀ x, run (encode x) = encode (semantic x)

theorem refines_identity {X : Type u} {R : Type v} (encode : X → R) :
    Refines encode id id := by
  intro x
  rfl

theorem refines_composition {X : Type u} {R : Type v}
    (encode : X → R) (f g : X → X) (rf rg : R → R)
    (hf : Refines encode f rf) (hg : Refines encode g rg) :
    Refines encode (g ∘ f) (rg ∘ rf) := by
  intro x
  change rg (rf (encode x)) = encode (g (f x))
  rw [hf x, hg (f x)]

/-- A finite program preserves its encoded semantics when its concrete
primitives refine total semantic primitives on the same admitted source type.
Full source-value identification additionally needs an injective encoding.
Partial/refused operations need an explicit result type or admitted subtype.
This theorem does not supply primitive implementations or range certificates.
-/
theorem finite_program_exact
    {X : Type u} {R : Type v} {Op : Type w}
    (encode : X → R) (semantic : Op → X → X) (run : Op → R → R)
    (hstep : ∀ op, Refines encode (semantic op) (run op))
    (program : List Op) (x : X) :
    program.foldl (fun r op => run op r) (encode x) =
      encode (program.foldl (fun y op => semantic op y) x) := by
  induction program generalizing x with
  | nil => rfl
  | cons op rest ih =>
    simp only [List.foldl_cons]
    rw [hstep op x]
    exact ih (semantic op x)

/-- Injectivity upgrades agreement of encoded outputs to source-value equality.
The injection hypothesis must itself follow from the representation's admitted
domain; a constant/nonfaithful encoding cannot establish this conclusion.
-/
theorem finite_program_identifies_result
    {X : Type u} {R : Type v} {Op : Type w}
    (encode : X → R) (semantic : Op → X → X) (run : Op → R → R)
    (hinj : ∀ a b, encode a = encode b → a = b)
    (hstep : ∀ op, Refines encode (semantic op) (run op))
    (program : List Op) (x y : X)
    (hresult : program.foldl (fun r op => run op r) (encode x) = encode y) :
    program.foldl (fun a op => semantic op a) x = y := by
  apply hinj
  rw [← finite_program_exact encode semantic run hstep program x, hresult]

/-- Frame transfers preserve the common source on every valid encoded state. -/
theorem transduction_composes
    {X : Type u} {A : Type v} {B : Type w} {C : Type z}
    (ea : X → A) (eb : X → B) (ec : X → C)
    (ab : A → B) (bc : B → C)
    (hab : ∀ x, ab (ea x) = eb x) (hbc : ∀ x, bc (eb x) = ec x) :
    ∀ x, bc (ab (ea x)) = ec x := by
  intro x
  rw [hab x, hbc x]

theorem transduction_round_trip
    {X : Type u} {A : Type v} {B : Type w}
    (ea : X → A) (eb : X → B) (ab : A → B) (ba : B → A)
    (hab : ∀ x, ab (ea x) = eb x) (hba : ∀ x, ba (eb x) = ea x) :
    ∀ x, ba (ab (ea x)) = ea x := by
  intro x
  rw [hab x, hba x]

end KElimination.ExactObservation

#print axioms KElimination.ExactObservation.recoverable_iff
#print axioms KElimination.ExactObservation.refined_observation_suffices
#print axioms KElimination.ExactObservation.collision_obstructs_query
#print axioms KElimination.ExactObservation.refines_identity
#print axioms KElimination.ExactObservation.refines_composition
#print axioms KElimination.ExactObservation.finite_program_exact
#print axioms KElimination.ExactObservation.finite_program_identifies_result
#print axioms KElimination.ExactObservation.transduction_composes
#print axioms KElimination.ExactObservation.transduction_round_trip
