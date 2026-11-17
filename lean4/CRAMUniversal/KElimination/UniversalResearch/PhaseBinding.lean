import KElimination.UniversalResearch.IntegerSpecialization

/-!
# Phase consistency versus source binding

A phase equation checked against a lift derived from that same equation is
an algebraic consistency check, not independent evidence of the readings'
origin. The integer theorem below makes this distinction explicit for the
existing K-Elimination query. An executable finite counterexample mixes the
main reading of 0 with the anchor reading of 1; it passes the phase check,
but its compatible bounded integer is 4, not the claimed source 0.

The positive results use a source-indexed relation and commuting producer and
transition equations. They are conditional composition lemmas, not a claim
that arbitrary Rust producers already satisfy those equations. A concrete
paired-residue translation discharges its own transition equation. All source
values occur in specifications/proofs; the observation update consumes only
the two readings, a translation, and the public moduli. No winding register is
introduced. Source binding here is mathematical, not cryptographic custody.
-/

namespace KElimination.PhaseBinding

open IntegerSpecialization

/-- A congruence check for a supplied candidate lift. -/
def PhaseConsistent (r s M A k : Int) : Prop :=
  (s - r - M * k) % A = 0

/-- For a unit multiplier, checking the query against the equation used to
derive it succeeds on arbitrary readings. No common-source premise occurs.
This is not a statement about checks using independently obtained evidence. -/
theorem query_phase_consistency (r s M A u : Int)
    (hinv : (u * M) % A = 1 % A) :
    PhaseConsistent r s M A (query r s A u) := by
  have hmul : (M * query r s A u) % A = (s - r) % A := by
    rw [query_fused]
    calc
      (M * (((s - r) * u) % A)) % A = (M * ((s - r) * u)) % A := by
        simp only [Int.mul_emod, Int.emod_emod]
      _ = ((u * M) * (s - r)) % A := by
        congr 1
        grind
      _ = (((u * M) % A) * ((s - r) % A)) % A := Int.mul_emod _ _ _
      _ = ((1 % A) * ((s - r) % A)) % A := by rw [hinv]
      _ = (s - r) % A := by rw [← Int.mul_emod]; simp
  unfold PhaseConsistent
  rw [Int.sub_emod, hmul]
  simp

universe u v w x y z o

/-- The reading is bound to this specified source, not merely to some source
in the image of `observe`. The source is a specification parameter. -/
def BoundTo {Source : Type u} {Reading : Type v}
    (observe : Source → Reading) (reading : Reading) (source : Source) : Prop :=
  reading = observe source

/-- A producer obligation to discharge for an actual ingress implementation. -/
def ProducerCorrect {Source : Type u} {Reading : Type v}
    (observe produce : Source → Reading) : Prop :=
  ∀ source, produce source = observe source

/-- A transition obligation to discharge for the actual observation update.
The source and observation types may both change, as in frame transduction. -/
def TransitionCorrect
    {Source : Type u} {NextSource : Type v}
    {Reading : Type w} {NextReading : Type x}
    (observe : Source → Reading) (observeNext : NextSource → NextReading)
    (semantic : Source → NextSource) (advance : Reading → NextReading) : Prop :=
  ∀ source, advance (observe source) = observeNext (semantic source)

/-- Conditional ingress lemma; producer correctness is explicit. -/
theorem producer_establishes_binding
    {Source : Type u} {Reading : Type v}
    (observe produce : Source → Reading)
    (hproducer : ProducerCorrect observe produce) (source : Source) :
    BoundTo observe (produce source) source :=
  hproducer source

/-- A proved observation update preserves binding to the corresponding source
transition. Equal labels without the commuting equation do not suffice. -/
theorem transition_preserves_binding
    {Source : Type u} {NextSource : Type v}
    {Reading : Type w} {NextReading : Type x}
    (observe : Source → Reading) (observeNext : NextSource → NextReading)
    (semantic : Source → NextSource) (advance : Reading → NextReading)
    (hadvance : TransitionCorrect observe observeNext semantic advance)
    (source : Source) (reading : Reading) (hbound : BoundTo observe reading source) :
    BoundTo observeNext (advance reading) (semantic source) := by
  change advance reading = observeNext (semantic source)
  rw [hbound]
  exact hadvance source

theorem identity_transition_correct
    {Source : Type u} {Reading : Type v} (observe : Source → Reading) :
    TransitionCorrect observe observe id id := by
  intro source
  rfl

/-- Verified transitions compose, including changes of frame/source type. -/
theorem transition_correct_composition
    {Source : Type u} {MiddleSource : Type v} {FinalSource : Type w}
    {Reading : Type x} {MiddleReading : Type y} {FinalReading : Type z}
    (observe : Source → Reading) (observeMiddle : MiddleSource → MiddleReading)
    (observeFinal : FinalSource → FinalReading)
    (first : Source → MiddleSource) (second : MiddleSource → FinalSource)
    (advanceFirst : Reading → MiddleReading)
    (advanceSecond : MiddleReading → FinalReading)
    (hfirst : TransitionCorrect observe observeMiddle first advanceFirst)
    (hsecond : TransitionCorrect observeMiddle observeFinal second advanceSecond) :
    TransitionCorrect observe observeFinal (second ∘ first)
      (advanceSecond ∘ advanceFirst) := by
  intro source
  change advanceSecond (advanceFirst (observe source)) =
    observeFinal (second (first source))
  rw [hfirst source, hsecond (first source)]

/-- A finite program preserves source binding if each actual transition
satisfies its commuting equation. This lemma supplies no missing primitive
implementation and makes no termination claim about an unbounded program. -/
theorem finite_program_preserves_binding
    {Source : Type u} {Reading : Type v} {Op : Type o}
    (observe : Source → Reading) (semantic : Op → Source → Source)
    (advance : Op → Reading → Reading)
    (hstep : ∀ op, TransitionCorrect observe observe (semantic op) (advance op))
    (program : List Op) (source : Source) (reading : Reading)
    (hbound : BoundTo observe reading source) :
    BoundTo observe
      (program.foldl (fun state op => advance op state) reading)
      (program.foldl (fun state op => semantic op state) source) := by
  induction program generalizing source reading with
  | nil => exact hbound
  | cons op rest ih =>
    simp only [List.foldl_cons]
    exact ih (semantic op source) (advance op reading)
      (transition_preserves_binding observe observe (semantic op) (advance op)
        (hstep op) source reading hbound)

/-- Paired modular observation. For a production finite frame, the profile
additionally requires positive, nontrivial moduli and its capacity contract. -/
def modularPair (M A source : Int) : Int × Int :=
  (source % M, source % A)

/-- A concrete observation-only update; it does not decode a source or K. -/
def translatePair (M A delta : Int) (reading : Int × Int) : Int × Int :=
  ((reading.1 + delta) % M, (reading.2 + delta) % A)

/-- Both tray updates use the same translation. This actual map discharges
its transition obligation by modular arithmetic, without assuming the result. -/
theorem modular_translate_correct (M A delta : Int) :
    TransitionCorrect (modularPair M A) (modularPair M A)
      (fun source => source + delta) (translatePair M A delta) := by
  intro source
  simp [translatePair, modularPair, Int.add_emod]

theorem modular_translate_preserves_binding (M A delta source : Int)
    (reading : Int × Int) (hbound : BoundTo (modularPair M A) reading source) :
    BoundTo (modularPair M A) (translatePair M A delta reading) (source + delta) :=
  transition_preserves_binding _ _ _ _ (modular_translate_correct M A delta)
    source reading hbound

/-- Main observation from 0, anchor observation from 1: the unit-derived
phase check passes, and the query equals 2. This is a finite exact witness. -/
theorem mixed_sources_pass_phase_check :
    ((0 : Int) % 2 = 0) ∧ ((1 : Int) % 3 = 1) ∧
    query 0 1 3 2 = 2 ∧ PhaseConsistent 0 1 2 3 (query 0 1 3 2) := by
  unfold PhaseConsistent
  decide

/-- The mixed readings do represent a bounded integer: 4 in [0,6).
Existence of a compatible source does not identify the claimed origin. -/
theorem mixed_pair_is_bound_to_four :
    BoundTo (modularPair 2 3) (0, 1) 4 ∧ (0 ≤ (4 : Int) ∧ 4 < 2 * 3) := by
  unfold BoundTo
  decide

theorem mixed_pair_not_bound_to_zero :
    ¬ BoundTo (modularPair 2 3) (0, 1) 0 := by
  unfold BoundTo
  decide

/-- Even with canonical readings and a valid inverse, phase consistency does
not establish binding to the specified source. It certifies another relation. -/
theorem phase_check_not_source_binding :
    ¬ (∀ r s : Int,
      0 ≤ r → r < 2 → 0 ≤ s → s < 3 →
      PhaseConsistent r s 2 3 (query r s 3 2) →
      BoundTo (modularPair 2 3) (r, s) 0) := by
  intro h
  exact mixed_pair_not_bound_to_zero
    (h 0 1 (by decide) (by decide) (by decide) (by decide)
      mixed_sources_pass_phase_check.2.2.2)

end KElimination.PhaseBinding

#print axioms KElimination.PhaseBinding.query_phase_consistency
#print axioms KElimination.PhaseBinding.producer_establishes_binding
#print axioms KElimination.PhaseBinding.transition_preserves_binding
#print axioms KElimination.PhaseBinding.identity_transition_correct
#print axioms KElimination.PhaseBinding.transition_correct_composition
#print axioms KElimination.PhaseBinding.finite_program_preserves_binding
#print axioms KElimination.PhaseBinding.modular_translate_correct
#print axioms KElimination.PhaseBinding.modular_translate_preserves_binding
#print axioms KElimination.PhaseBinding.mixed_sources_pass_phase_check
#print axioms KElimination.PhaseBinding.mixed_pair_is_bound_to_four
#print axioms KElimination.PhaseBinding.mixed_pair_not_bound_to_zero
#print axioms KElimination.PhaseBinding.phase_check_not_source_binding
