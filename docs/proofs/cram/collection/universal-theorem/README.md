# Universal K-Elimination proof candidate

Start with [the theorem and its consequences](../UNIVERSAL_THEOREM.md). This package proves the additive exact-query criterion, constructive ring readout, integer windows/nonunit reduction/direct target transport, and the fast program's operation count. Source values used in proofs are not runtime arguments to the observed-view query.

The fresh clean build passed **130 theorem declarations**, adding **55 closure and StarLift declarations** to the preceding 75-declaration core. No admitted proof or project axiom is present. [verification.json](verification.json) records every source hash and every theorem's transitive axioms; [verification.log](verification.log) contains the compiler output.

| Module | Declarations | Scope |
|---|---:|---|
| [ExactObservation.lean](ExactObservation.lean) | 9 reused | Fiber criterion and finite-operation/transfer composition |
| [UniversalLift.lean](UniversalLift.lean) | 15 | Observed affine identity, full ambiguity, exact target criterion, factor uniqueness/additivity, constructive query interface |
| [RingReadout.lean](RingReadout.lean) | 16 | Actual sided-inverse readout over arbitrary rings, ideal/kernel fibers and target equation |
| [IntegerSpecialization.lean](IntegerSpecialization.lean) | 28 | Actual modular programs, signed/unsigned windows, star/adjacent anchors, nonunit reduction and direct target projection |
| [CostedReadout.lean](CostedReadout.lean) | 7 | Program evaluation, one subtraction/one multiplication, adjacent simplification, ring instance of universal theorem |
| [ReferenceChange.lean](ReferenceChange.lean) | 3 | Affine reference shift and target invariance |
| [CoupledAnchors.lean](CoupledAnchors.lean) | 19 | Exact GCD/LCM resolution, minimality, signed windows and target iff |
| [ResidueAlgorithms.lean](ResidueAlgorithms.lean) | 6 | Executable bounded divmod/GCD and full loop correctness |
| [ResiduePrimitives.lean](ResiduePrimitives.lean) | 14 | Actual paired-state implementation discharging every primitive obligation |
| [StarLift.lean](StarLift.lean) | 13 | Both winding orientations, signed decoding and reduced nonunit negative query |

Counts include supporting lemmas. The set/image existence theorems do not promise an efficient decoder for every structure. The concrete ring and integer programs supply proved constructors. The [mathematical review](MATHEMATICAL_REVIEW.md) gives further written domain specializations, with their formal status distinguished.

## Reproduce

Install the exact toolchain named in `lean-toolchain`. With `lean` available through elan:

```sh
python3 check_proofs.py --lean lean
```

The checker uses a fresh temporary directory, rebuilds every project import, checks the pinned version, rejects admitted/custom assumed declarations, and queries the axioms of every theorem. It uses Python's standard library. Set `ELAN_HOME` if your installation requires it; an absolute Lean executable can be passed through `--lean`.

For normal package builds:

```sh
lake build
lake env lean ClosureSmoke.lean
```

The source imports Lean's bundled algebra classes (`Lean.Grind.AddCommGroup`, `Ring`, `CommRing`). These are supplied algebraic structures and laws, not new project axioms. There is no Mathlib dependency. The standalone success is separate from the earlier public repository's root-build repair.

## Runtime and cost contract

The fast program accepts two authentic readings and a public inverse, and returns the observed coordinate. Within a proved integer window this is the exact quotient. It uses one operation of each kind in the observation ring; the adjacent case uses one subtraction. Producing the inputs, signed decoding, target projection, common-factor removal and implementation-specific arithmetic have explicit additional work. No scalar X or persistent K is supplied to the core query.

The current package is research source and proof evidence. It does not alter the production NINE65 implementation. Integration should establish that the intended producers deliver these readings, that admission/range invariants hold, and that the consumers compute the specific requested observable.

The [continuation report](../CLOSURE_PROOFS.md), [StarLift interpretation](STARLIFT.md) and [independent review](CLOSURE_REVIEW.md) record the new scope. The executable smoke suite passed 1,809 admitted pairs and four controls; see [log](closure-smoke.log).
