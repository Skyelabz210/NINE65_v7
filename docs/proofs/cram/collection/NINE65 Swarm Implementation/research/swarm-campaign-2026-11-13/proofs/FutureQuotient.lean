import ConsumerTransport

/-!
The largest exact identification compatible with every declared future query.
The source may be an admitted subtype. Transitions are total on that subtype.
Theorems concern mathematical observations; no scalar runtime oracle is supplied.
-/

namespace KElimination.FutureQuotient

universe u v w z

def run {X : Type u} {Op : Type v} (step : Op → X → X)
    (program : List Op) (x : X) : X :=
  program.foldl (fun s op => step op s) x

def FutureEq {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (x y : X) : Prop :=
  ∀ program i, query i (run step program x) = query i (run step program y)

def OutputEq {X : Type u} {I : Type w} {Y : Type z}
    (query : I → X → Y) (x y : X) : Prop := ∀ i, query i x = query i y

def Preserved {X : Type u} {Op : Type v} (step : Op → X → X)
    (rel : X → X → Prop) : Prop :=
  ∀ op x y, rel x y → rel (step op x) (step op y)

theorem future_refl {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (x : X) :
    FutureEq step query x x := by intro program i; rfl

theorem future_symm {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (x y : X)
    (h : FutureEq step query x y) : FutureEq step query y x := by
  intro program i
  exact (h program i).symm

theorem future_trans {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (x y z : X)
    (hxy : FutureEq step query x y) (hyz : FutureEq step query y z) :
    FutureEq step query x z := by
  intro program i
  exact (hxy program i).trans (hyz program i)

theorem future_determines_outputs
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (x y : X)
    (h : FutureEq step query x y) : OutputEq query x y := by
  intro i
  exact h [] i

theorem future_preserved
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) :
    Preserved step (FutureEq step query) := by
  intro op x y h program i
  exact h (op :: program) i

/-- Any output-sufficient relation preserved by every operation identifies
only future-equivalent states. No equivalence assumptions are needed here. -/
theorem future_is_coarsest
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (rel : X → X → Prop)
    (houtput : ∀ x y, rel x y → OutputEq query x y)
    (hstep : Preserved step rel) :
    ∀ x y, rel x y → FutureEq step query x y := by
  intro x y h program
  induction program generalizing x y with
  | nil => exact houtput x y h
  | cons op rest ih =>
    exact ih (step op x) (step op y) (hstep op x y h)

def futureSetoid {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) : Setoid X where
  r := FutureEq step query
  iseqv := ⟨future_refl step query, fun h => future_symm step query _ _ h,
    fun h₁ h₂ => future_trans step query _ _ _ h₁ h₂⟩

def quotientQuery {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (i : I) :
    Quotient (futureSetoid step query) → Y :=
  Quotient.lift (query i) (fun x y h => future_determines_outputs step query x y h i)

def quotientStep {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (op : Op) :
    Quotient (futureSetoid step query) → Quotient (futureSetoid step query) :=
  Quotient.lift (fun x => Quotient.mk _ (step op x))
    (fun x y h => Quotient.sound (future_preserved step query op x y h))

theorem quotient_query_correct
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (i : I) (x : X) :
    quotientQuery step query i (Quotient.mk _ x) = query i x := rfl

theorem quotient_step_correct
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (op : Op) (x : X) :
    quotientStep step query op (Quotient.mk _ x) = Quotient.mk _ (step op x) := rfl

theorem quotient_equal_iff_future
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (x y : X) :
    Quotient.mk (futureSetoid step query) x = Quotient.mk _ y ↔ FutureEq step query x y := by
  constructor
  · intro h
    exact Quotient.exact h
  · intro h
    apply Quotient.sound
    exact h

/-- Relational refinement used by the finite public-model partition compiler.
At round n it observes all words of length at most n. -/
def Refined {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) : Nat → X → X → Prop
  | 0, x, y => OutputEq query x y
  | n + 1, x, y => Refined step query n x y ∧
      ∀ op, Refined step query n (step op x) (step op y)

theorem refined_monotone
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (n : Nat) (x y : X) :
    Refined step query (n+1) x y → Refined step query n x y := by
  exact And.left

theorem refined_determines_outputs
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (n : Nat) (x y : X)
    (h : Refined step query n x y) : OutputEq query x y := by
  induction n with
  | zero => exact h
  | succ n ih => exact ih h.1

theorem future_refines_every_round
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (n : Nat) :
    ∀ x y, FutureEq step query x y → Refined step query n x y := by
  induction n with
  | zero => exact future_determines_outputs step query
  | succ n ih =>
    intro x y h
    exact ⟨ih x y h, fun op => ih _ _ (future_preserved step query op x y h)⟩

theorem refined_iff_bounded_future
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (n : Nat) :
    ∀ x y, Refined step query n x y ↔
      ∀ program : List Op, program.length ≤ n →
        ∀ i, query i (run step program x) = query i (run step program y) := by
  induction n with
  | zero =>
    intro x y
    constructor
    · intro h program hlen i
      have hp : program = [] := List.eq_nil_of_length_eq_zero (by omega)
      subst program
      exact h i
    · intro h i
      exact h [] (by simp) i
  | succ n ih =>
    intro x y
    constructor
    · rintro ⟨hold, hnext⟩ program hlen i
      cases program with
      | nil => exact refined_determines_outputs step query n x y hold i
      | cons op rest =>
        exact (ih _ _).mp (hnext op) rest (by simpa using hlen) i
    · intro h
      refine ⟨(ih x y).mpr ?_, fun op => (ih _ _).mpr ?_⟩
      · intro program hlen i
        exact h program (by omega) i
      · intro program hlen i
        exact h (op :: program) (by simpa using hlen) i

/-- A fixed point of the implemented refinement recurrence already computes
the full all-future equivalence; no unbounded word enumeration is needed. -/
theorem fixed_point_is_future_equivalence
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    (step : Op → X → X) (query : I → X → Y) (n : Nat)
    (hfixed : ∀ x y, Refined step query n x y → Refined step query (n+1) x y) :
    ∀ x y, Refined step query n x y ↔ FutureEq step query x y := by
  intro x y
  constructor
  · apply future_is_coarsest step query (Refined step query n)
      (refined_determines_outputs step query n)
    intro op a b hab
    exact (hfixed a b hab).2 op
  · exact future_refines_every_round step query n x y

open UniversalLift Lean.Grind

def Invisible {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    [AddCommGroup X] [AddCommGroup Y]
    (step : Op → AddMap X X) (query : I → AddMap X Y) (delta : X) : Prop :=
  ∀ program i, (query i).apply (run (fun op => (step op).apply) program delta) = 0

theorem additive_run_zero
    {X : Type u} {Op : Type v} [AddCommGroup X]
    (step : Op → AddMap X X) (program : List Op) :
    run (fun op => (step op).apply) program 0 = 0 := by
  induction program with
  | nil => rfl
  | cons op rest ih =>
    change run _ rest ((step op).apply 0) = 0
    rw [(step op).map_zero]
    exact ih

theorem additive_run_add
    {X : Type u} {Op : Type v} [AddCommGroup X]
    (step : Op → AddMap X X) (program : List Op) (x y : X) :
    run (fun op => (step op).apply) program (x+y) =
      run (fun op => (step op).apply) program x +
      run (fun op => (step op).apply) program y := by
  induction program generalizing x y with
  | nil => rfl
  | cons op rest ih =>
    change run _ rest ((step op).apply (x+y)) = _
    rw [(step op).map_add]
    exact ih _ _

theorem additive_run_sub
    {X : Type u} {Op : Type v} [AddCommGroup X]
    (step : Op → AddMap X X) (program : List Op) (x y : X) :
    run (fun op => (step op).apply) program (x-y) =
      run (fun op => (step op).apply) program x -
      run (fun op => (step op).apply) program y := by
  induction program generalizing x y with
  | nil => rfl
  | cons op rest ih =>
    change run _ rest ((step op).apply (x-y)) = _
    rw [(step op).map_sub]
    exact ih _ _

theorem invisible_zero
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    [AddCommGroup X] [AddCommGroup Y]
    (step : Op → AddMap X X) (query : I → AddMap X Y) : Invisible step query 0 := by
  intro program i
  rw [additive_run_zero, (query i).map_zero]

theorem invisible_add
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    [AddCommGroup X] [AddCommGroup Y]
    (step : Op → AddMap X X) (query : I → AddMap X Y) (x y : X)
    (hx : Invisible step query x) (hy : Invisible step query y) :
    Invisible step query (x+y) := by
  intro program i
  rw [additive_run_add, (query i).map_add, hx program i, hy program i]
  exact AddCommMonoid.add_zero 0

theorem invisible_sub
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    [AddCommGroup X] [AddCommGroup Y]
    (step : Op → AddMap X X) (query : I → AddMap X Y) (x y : X)
    (hx : Invisible step query x) (hy : Invisible step query y) :
    Invisible step query (x-y) := by
  intro program i
  rw [additive_run_sub, (query i).map_sub, hx program i, hy program i]
  exact AddCommGroup.sub_self 0

theorem invisible_preserved
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    [AddCommGroup X] [AddCommGroup Y]
    (step : Op → AddMap X X) (query : I → AddMap X Y) (op : Op) (x : X)
    (hx : Invisible step query x) : Invisible step query ((step op).apply x) := by
  intro program i
  exact hx (op :: program) i

theorem invisible_is_largest
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    [AddCommGroup X] [AddCommGroup Y]
    (step : Op → AddMap X X) (query : I → AddMap X Y) (candidate : X → Prop)
    (houtput : ∀ x, candidate x → ∀ i, (query i).apply x = 0)
    (hstep : ∀ op x, candidate x → candidate ((step op).apply x)) :
    ∀ x, candidate x → Invisible step query x := by
  intro x hx program
  induction program generalizing x with
  | nil => exact houtput x hx
  | cons op rest ih => exact ih _ (hstep op x hx)

theorem future_eq_iff_invisible_difference
    {X : Type u} {Op : Type v} {I : Type w} {Y : Type z}
    [AddCommGroup X] [AddCommGroup Y]
    (step : Op → AddMap X X) (query : I → AddMap X Y) (x y : X) :
    FutureEq (fun op => (step op).apply) (fun i => (query i).apply) x y ↔
      Invisible step query (x-y) := by
  constructor
  · intro h program i
    rw [additive_run_sub]
    exact ((query i).same_reading_iff _ _).mp (h program i)
  · intro h program i
    apply ((query i).same_reading_iff _ _).mpr
    rw [← additive_run_sub]
    exact h program i

end KElimination.FutureQuotient

#print axioms KElimination.FutureQuotient.future_refl
#print axioms KElimination.FutureQuotient.future_symm
#print axioms KElimination.FutureQuotient.future_trans
#print axioms KElimination.FutureQuotient.future_determines_outputs
#print axioms KElimination.FutureQuotient.future_preserved
#print axioms KElimination.FutureQuotient.future_is_coarsest
#print axioms KElimination.FutureQuotient.quotient_query_correct
#print axioms KElimination.FutureQuotient.quotient_step_correct
#print axioms KElimination.FutureQuotient.quotient_equal_iff_future
#print axioms KElimination.FutureQuotient.refined_monotone
#print axioms KElimination.FutureQuotient.refined_determines_outputs
#print axioms KElimination.FutureQuotient.future_refines_every_round
#print axioms KElimination.FutureQuotient.refined_iff_bounded_future
#print axioms KElimination.FutureQuotient.fixed_point_is_future_equivalence
#print axioms KElimination.FutureQuotient.additive_run_zero
#print axioms KElimination.FutureQuotient.additive_run_add
#print axioms KElimination.FutureQuotient.additive_run_sub
#print axioms KElimination.FutureQuotient.invisible_zero
#print axioms KElimination.FutureQuotient.invisible_add
#print axioms KElimination.FutureQuotient.invisible_sub
#print axioms KElimination.FutureQuotient.invisible_preserved
#print axioms KElimination.FutureQuotient.invisible_is_largest
#print axioms KElimination.FutureQuotient.future_eq_iff_invisible_difference
