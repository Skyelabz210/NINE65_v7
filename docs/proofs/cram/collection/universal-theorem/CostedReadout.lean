import UniversalLift
import RingReadout
import IntegerSpecialization

/-!
A small expression language makes the exact operation-count claim explicit.
Input nodes are two supplied readings and public constants, not a source X or
stored K. A node is one operation of the chosen arithmetic substrate. In a
fixed-width modular implementation this is a modular-operation count; it is
not a bound on bit complexity, input production, or encrypted circuit depth.
-/

namespace KElimination.CostedReadout

open Lean.Grind

universe u v

inductive Expr (H : Type u) where
  | chart : Expr H
  | source : Expr H
  | constant : H → Expr H
  | sub : Expr H → Expr H → Expr H
  | mul : Expr H → Expr H → Expr H

def Expr.eval {H : Type u} (subtract multiply : H → H → H)
    (chart source : H) : Expr H → H
  | .chart => chart
  | .source => source
  | .constant value => value
  | .sub a b => subtract (a.eval subtract multiply chart source)
      (b.eval subtract multiply chart source)
  | .mul a b => multiply (a.eval subtract multiply chart source)
      (b.eval subtract multiply chart source)

def Expr.subtractions {H : Type u} : Expr H → Nat
  | .chart | .source | .constant _ => 0
  | .sub a b => a.subtractions + b.subtractions + 1
  | .mul a b => a.subtractions + b.subtractions

def Expr.multiplications {H : Type u} : Expr H → Nat
  | .chart | .source | .constant _ => 0
  | .sub a b => a.multiplications + b.multiplications
  | .mul a b => a.multiplications + b.multiplications + 1

/-- The entire readout program, independent of the source magnitude. -/
def program {H : Type u} (inverse : H) : Expr H :=
  .mul (.constant inverse) (.sub .source .chart)

theorem program_counts {H : Type u} (inverse : H) :
    (program inverse).subtractions = 1 ∧
    (program inverse).multiplications = 1 := by
  exact ⟨rfl, rfl⟩

theorem program_evaluates_to_readout {H : Type u} [Ring H]
    (inverse chart source : H) :
    (program inverse).eval (· - ·) (· * ·) chart source =
      RingReadout.readout inverse chart source := rfl

theorem program_correct {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : RingReadout.Observation R H) (X r M K : R) (inverse : H)
    (hsource : X = r + M * K) (hunit : inverse * h.read M = 1) :
    (program inverse).eval (· - ·) (· * ·) (h.read r) (h.read X) = h.read K :=
  RingReadout.unit_readout h X r M K inverse hsource hunit

/-- The same program specializes to normalized modular arithmetic gates. -/
theorem modular_program_evaluates_to_query (chart source A inverse : Int) :
    (program inverse).eval (fun a b => (a - b) % A)
      (fun a b => (a * b) % A) chart source =
      IntegerSpecialization.query chart source A inverse := by
  change (inverse * ((source - chart) % A)) % A =
    (((source - chart) % A) * inverse) % A
  rw [Int.mul_comm]

/-- The adjacent-anchor simplification has only a subtraction node. -/
def adjacentProgram {H : Type u} : Expr H := .sub .chart .source

theorem adjacent_program_counts {H : Type u} :
    (adjacentProgram : Expr H).subtractions = 1 ∧
    (adjacentProgram : Expr H).multiplications = 0 := by
  exact ⟨rfl, rfl⟩

theorem adjacent_program_evaluates_to_query (chart source M : Int) :
    (adjacentProgram : Expr Int).eval (fun a b => (a - b) % (M + 1))
      (fun a b => (a * b) % (M + 1)) chart source =
      IntegerSpecialization.query chart source (M + 1) (-1) := by
  change (chart - source) % (M + 1) = _
  exact (IntegerSpecialization.adjacent_query_subtraction chart source M).symm

/-- Multiplication by M is an additive lift map, even in a noncommutative ring. -/
def scaleMap {R : Type u} [Ring R] (M : R) : UniversalLift.AddMap R R where
  apply k := M * k
  map_add a b := Semiring.left_distrib M a b

def observationMap {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : RingReadout.Observation R H) : UniversalLift.AddMap R H where
  apply := h.read
  map_add := h.map_add

/-- The fast ring readout is a constructive instance of the universal theorem.
Its readout obligation is discharged from ring laws and a sided inverse; query
correctness is not assumed as an extra axiom. -/
theorem ring_is_universal_instance
    {R : Type u} {H : Type v} [Ring R] [Ring H]
    (h : RingReadout.Observation R H) (X r M K : R) (inverse : H)
    (hsource : X = r + M * K) (hunit : inverse * h.read M = 1) :
    UniversalLift.query (fun defect => inverse * defect) (h.read r) (h.read X) =
      h.read K := by
  apply UniversalLift.constructive_query_correct (scaleMap M) (observationMap h)
    (fun _ => True) h.read (fun defect => inverse * defect) ?_ X r K trivial hsource
  intro k _
  change inverse * h.read (M * k) = h.read k
  rw [h.map_mul, ← Semiring.mul_assoc, hunit, Semiring.one_mul]

end KElimination.CostedReadout

#print axioms KElimination.CostedReadout.program_counts
#print axioms KElimination.CostedReadout.program_evaluates_to_readout
#print axioms KElimination.CostedReadout.program_correct
#print axioms KElimination.CostedReadout.modular_program_evaluates_to_query
#print axioms KElimination.CostedReadout.adjacent_program_counts
#print axioms KElimination.CostedReadout.adjacent_program_evaluates_to_query
#print axioms KElimination.CostedReadout.ring_is_universal_instance
