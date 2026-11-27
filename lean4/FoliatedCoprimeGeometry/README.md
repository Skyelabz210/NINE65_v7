# Foliated Coprime Geometry — checked finite core

The author's supplied finite-covering formalization is integrated as a standalone
Lean package, with proof-script repairs and explicit composition theorems.
**67 theorem declarations and 97 authored declarations pass a fresh build and
transitive axiom audit on Lean 4.27.0-rc1.** No Mathlib or other external package
is required. The imported `Lean` library ships with that pinned distribution.

All original named theorem statements are retained. There are no `sorry`,
custom axioms, or `native_decide` admissions. The audit reports only Lean's
foundational `propext` and `Quot.sound`; “no external dependencies” does **not**
mean “no foundational axioms.” Generated declarations and imported library
lemmas are not counted as newly authored theorems.

## Build and reproduce

With the pinned official Lean distribution installed and its `bin` on `PATH`:

```sh
cd lean4/FoliatedCoprimeGeometry
lake build
python3 scripts/check_proofs.py
```

Alternatively supply `--lean /absolute/path/to/lean` to the audit. It freezes the
source bytes, compiles every module into a new temporary directory, audits every
authored definition/structure/theorem, and checks that the sources did not change.
It does not reuse this project's `.olean` cache. Bundled Lean libraries are used.

- [Machine-readable evidence](evidence/verification.json): source hashes,
  toolchain, declaration inventory, and each declaration's transitive axioms.
- [Raw build and axiom output](evidence/verification.log).
- [Existing CRAM obligation ledger](../CRAMUniversal/docs/cram/PROOF_OBLIGATIONS.md).

## What is proved

All names below are in `FoliatedCoprimeGeometry`.

| Module | Checked contract | Main exports |
| --- | --- | --- |
| [Basic](FoliatedCoprimeGeometry/Basic.lean) | Iteration, modular cancellation, Bézout and gcd helpers, reusing bundled arithmetic results where available | `iter_add`, `iter_mul`, `iter_conj`, `bezout_spec` |
| [Cover](FoliatedCoprimeGeometry/Cover.lean) | Mutually inverse 30,030-state/sheet coordinates, exact sheet readout, successor intertwining and full-loop monodromy | `kElim_exact`, `sheetStep_monodromy`, `kElim_gauge_conjugacy` |
| [Cocycle](FoliatedCoprimeGeometry/Cocycle.lean) | For every positive M,A and every c : Fin M → Fin A, translation-gauge equivalence iff total monodromy agrees | `cocycle_equiv_iff_tau_eq`, `gaugeInv_gauge`, `gauge_gaugeInv` |
| [Cycles](FoliatedCoprimeGeometry/Cycles.lean) | Positive minimal period M·(A/gcd(A,τ)), complete/disjoint canonical orbit representatives, exact cycle-count identity | `cycleLength_pos`, `cycleLength_dvd_return`, `orbit_complete`, `orbit_intersection`, `cycleCount_mul_cycleLength` |
| [Projectors](FoliatedCoprimeGeometry/Projectors.lean) | Both authority-selecting 77/143 repairs, uniqueness, equivariance, and lossless discrepancy maps | `projU_unique`, `projV_unique`, `psiInv_psi`, `psi_psiInv` |
| [Integration](FoliatedCoprimeGeometry/Integration.lean) | Bundled inverse maps, exact return criterion for both raw residues and sheet coordinates, and the heterogeneous shared-shadow compatibility criterion | `discrepancyEquiv`, `rawShadowStep_return_iff`, `phase_lock_iff_shared_map` |

The general cycle theorems include M=1, A=1 and τ=0. The specified finite cover
has τ=1 and one cycle of length 30,030. `sheetStep_return_iff` proves that a
return time is **exactly** a multiple of 30,030, not merely that 30,030 is a
possible period. `rawShadowStep_return_iff` transfers that fact back to the
actual pair of residue readings.

The supplied header's bijections are now bundled as `CoordinateEquiv`, a small
core-only structure containing maps and both inverse proofs. This avoids adding
an external package solely to obtain the notation `≃`.

## Coordinates, shadow and phase locking

The fixed primary remains `{2,3,5,7,11,13}`. Factoring its period as
`30030 = 2730·11` is a mathematical view; it does not remove or add a primary
lane. With same-source readings `r=X mod 2730`, `s=X mod 11`, the readout is
`q=6(s-r) mod 11`. On `Fin 30030` this is the exact sheet index. A general
unbounded integer source still has only its quotient **class** identified by
this one finite observation; the existing signed universal congruence is not
replaced by the finite representative theorem.

`toSheet`, `fromSheet` and `sheetStep` are semantic coordinate models. They are
not a runtime serialization format or an instruction to persist K. The residue
map `shadowToSheet` derives the requested sheet coordinate from the readings.
A complete raw-state period is proved without introducing a runtime K ledger.

`phase_lock_iff_shared_map` begins the existing P4/P6 transition work: arbitrary
functions on the 77 and 143 views preserve **every compatible pair** iff they
induce a common function on the shared 11-coordinate. It does not require the
functions to be ring homomorphisms or to be the same integer operator. Authentic
source/epoch production is a separate implementation obligation.

The projectors copy the selected authority's shared reading while preserving the
other view's exclusive lane. A projector alone is lossy: `projection_collision`
exhibits two distinct inputs with the same repaired output. `psi` retains the
signed discrepancy and has a proved inverse. Synchronized successor preserves
that discrepancy, so these proofs distinguish coherent evolution from a repair
policy that selects an authority.

## Scope and terminology

- “H¹” here refers to cocycles on the directed base cycle (or the successor
  Z-action), modulo fiber translations. It is not a formalization of finite-group
  cohomology `H¹(C_M, Z/A)`, nor classification under every possible conjugacy.
- The K-Elimination map additionally **scales** the fiber by six. Raw-shadow
  drift has monodromy 2730 mod 11 = 2; sheet carry has monodromy 1. Their affine
  conjugacy is consistent with the translation-only classification: multiplying
  by six sends 2 to 1 modulo 11.
- The code formalizes finite sets, inverse coordinates and discrete dynamics.
  It does not declare a graph/topological covering object, a branched Riemann
  surface, an inverse-limit topology, or a continuum evolution.
- The sheet chart is not an additive isomorphism to the ordinary product-group
  law: carry belongs to its coordinate dynamics. These proofs do not establish
  runtime latency, spontaneous synchronization, prime-distribution claims,
  source authentication, or downstream cryptographic security.

## Repairs and contribution record

The theorem design and supplied formalization came from the user's November 26,
2026 submission. Integration preserved their mathematical statements and repaired
core-tactic compatibility, implicit lemma arguments, Nat/Int casts, nested modular
rewrites, dependent `Fin` equalities, and eager recursive elaboration. Public
helper visibility permits separate files. Bundled library lemmas replace bespoke
proofs of standard gcd facts without introducing Mathlib.

Added results make gauge inverses explicit, prove cycle-length positivity and
arbitrary-orbit disjointness, complete the dual projector API, bundle coordinate
bijections, connect the concrete cover to general periods, and prove the shared
shadow transition criterion. An independent agent reviewed these statements and
the audit; the Lean kernel checked the resulting proofs. This is a formalization
and integration record, not a historical priority assessment.
