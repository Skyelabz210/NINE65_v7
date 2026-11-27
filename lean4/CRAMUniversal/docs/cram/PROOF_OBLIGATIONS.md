# CRAM proof obligations and evidence ledger

Baseline date: 2026-11-17. Authority: [CORE_SPEC.md](CORE_SPEC.md). NINE65 is the intended downstream consumer of this engine; its cryptographic correctness is not part of this closure gate.

## Baseline evidence

The inspected proof baseline is `dd9c6cfb341ad3747f148c336a015e2b80664e87`. The 2026-11-17 maintained audit rebuilt the local targets and checked **223 declarations**, 58 without axioms; the remaining dependencies were confined to `propext`, `Classical.choice`, `Quot.sound`. Lean is `4.27.0-rc1`; mathlib is `3bdc7047b97538f795b725dc0713c28c0f53ed10`. This rebuild reused local compiled dependency artifacts; it was not a from-zero dependency build.

Raw baseline evidence: `/workspace/scratch/cram-lock-2026-11-17/maintained-audit/`. Any subsequent theorem additions must receive a new audit and source manifest. Historical proof counts and copied paper banners do not update themselves.

The integrated 2026-11-17 audit after importing `PhaseBinding` **passed with 235 declarations**, 67 axiom-free, under the same foundational-axiom allowlist and toolchain. Raw output is `/workspace/scratch/cram-lock-2026-11-17/integrated-audit/`. Twelve new theorems establish self-derived phase consistency, an explicit mixed-origin counterexample, conditional source-binding composition, and concrete paired-residue translation. These close those mathematical statements, not unspecified Rust producer obligations. The delivered source snapshot/manifest records the uncommitted additions relative to the baseline.

## Closure map

Owner clarification, 2026-11-17: the primary Safe Basis is fixed and intact. Arbitrary-modulus additions are dependent phase-locked sisters, never independent additions to the primary tray. P1/P4 must prove primary immutability and transfer of each named invariant; P8 must prove compatible sister refinement, including any claimed p-adic inverse system, without imposing a fixed global magnitude ceiling. Earlier carrier-extension and payload-factorization examples are mathematical/reference mechanisms, not a substitute for this architecture. The 235-declaration audit predates these additional obligations; no new formal closure is claimed here.

| ID | Obligation | Existing mathematical evidence | Remaining closure condition |
|---|---|---|---|
| P1 | Representation, Safe Basis and views | `CoupledAnchors.main_and_anchor_readings_iff`, `source_period`, `dependent_anchor_resolution`; bounded `ResiduePrimitives.encode_injective_on_window` | Immutable primary profile, role/family signatures and operator capabilities; S6/S8 mathematical packing equivalence, checked machine-word capacity, explicit signed/rational interfaces. |
| P2 | Universal target-query transport | `ExactObservation.recoverable_iff`; `UniversalLift`; ring/integer instances | Bind each executable readout to its real producer; existence using choice is not an algorithm. |
| P3 | Derived K and resolution | `IntegerSpecialization`, `StarLift`, `CoupledAnchors.combined_kernel`, `combined_target_iff`, `signed_window_unique` | Actual prepared-frame Rust refinement, input canonicality, overflow checks, signed conventions and no persistent derived magnitude. |
| P4 | Authentic sister trays | Source/transition relationships can be expressed using `ExactObservation.Refines`; additional phase-binding module introduced separately | Concrete constructors and transitions, source binding, actual 2/11 phase laws, shared-interface compatibility and transport of each named signature. Shadow-11 and phase-lock-22 references have separate domains. Congruence-only verification is insufficient. |
| P5 | Arithmetic closure | `ResiduePrimitives.ops_correct`, `divmod_correct`, `gcd_correct`; `ResidueAlgorithms` termination/correctness | Signed and rational extensions, optimized division/FPD implementations and dispatch coverage, implementation refinement. Existing constructive division is bounded repeated subtraction, not a fast-division complexity theorem. |
| P6 | Heterogeneous operators | General observation and transition semantics, `ConsumerTransport` | Registered operators, typed domains, lane topology, dependency/confluence proofs and source preservation. |
| P7 | Fifth Operator | `ExactObservation.transduction_composes`, `transduction_round_trip`; `ReferenceChange` | Concrete residue-native transport plus signature/topology/recovery maps and actual inverse obligations. |
| P8 | Capacity/scale changes | Coupled-anchor resolution; `AnchorSaturation.early_stop_is_least` and related finite-termination results | Observation production, pre-overflow admission, real bounds, checked wider arithmetic, frame-change execution and compatible-family construction. |
| P9 | Complete execution | `ExactObservation.finite_program_exact`; `ConsumerTransport.stable_finite_program`; `FutureQuotient` | Public partial-operation machine, success and safe-refusal semantics, changing frames, executable progress with noncircular admission, whole-program termination scope. |
| P10 | Rust and cost refinement | `CostedReadout` specifies expression counts; current Rust provides candidate kernels | Aeneas/Charon extraction and proof of actual code, no trusted substitutes for unsupported primitives, ghost-erasure/serialization/call-path evidence, setup and end-to-end cost accounting. |

The table lists theorem names as local proof locators, not a claim that their hypotheses have been established by current Rust. The root namespaces differ by module; use source declarations and the audit inventory for fully qualified names.

## Current executable gaps (source-observed)

At NINE65 `88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`:

- `cram-core` has no runtime dependencies, but `nine65` currently uses it mainly under optional `architecture-meter`. Engine integration remains to be built.
- `CramState.winding` / `WindingState.cells` are inconsistent with the locked schema. Observed construction is a zero-filled test state; no live winding ledger is inferred merely from the field name.
- Public `CramState` and `ResidueLane` fields permit invariant bypass. `BoundCertificate` bit counts and saturating operations are not proofs of authentic intervals or capacity.
- `anchor::recover_winding` computes an inverse per call; its full present cost is not just the prepared readout's subtraction/multiplication.
- `AnchorWitness::verify` checks a congruence, not source identity or canonicality. Shadow-11 successor verification assumes supplied source/bound evidence. Phase-lock-22 uses a separate domain and increment contract.
- The private `RecumbentCoefficient` type supplies a useful pure arithmetic extraction candidate: trusted ingress, analytic intervals, main/anchor observations and provisioned-lane dropping. Its debug oracle and experimental rank-projection path must be kept separately scoped.

## Execution sequence

1. Keep the architecture lock and source corrections together with this ledger.
2. Define private invariant-bearing primary/sister state types and versioned domain/operation interfaces in the standalone engine package. Make the primary Safe Basis immutable; type the sisters' source/phase dependencies and inherited properties. Preserve legacy source as explicitly scoped history.
3. Reuse the existing mathematical results; prove real observation producers and sister transitions before advertising their downstream queries.
4. Establish an Aeneas/Charon extraction preflight on the actual modular kernel, then extend refinement through preparation, queries, arithmetic and transport. Pin toolchain/translator versions and record their trusted semantics. The existing Lean package remains reproducible; upgrading the refinement package must not silently weaken its mathematical statements.
5. Integrate the public CRAM path and prove soundness plus admitted progress. A correct result conditional on an assumed perfect producer is a component lemma, not machine closure.
6. Only after engine contracts are met, implement NINE65's consumer adapter and discharge its additional obligations in its own program.

## Required negative controls and acceptance

Use independent integer/rational oracles outside production. Exercise adjacent operand reversal, incorrect star inverses, nonunit resolution, repeated/overlapping lanes, signed endpoints, X vs X+MA, malformed residues, wrong frame/source/revision, cross-frame states, overflow, nonintegral division, zero divisor and gcd(0,0). Include self-derived zero phase defects with mixed sources, transduction losses and failed capacity changes that leave state intact.

Audit runtime payload and serialization for K, reconstructed magnitude and alias names; inspect producer dataflow rather than names alone. Distinguish public bounds from values secretly carried as exact bounds. A target selector must not bypass semantics using an assumed certificate. Test mutations that break these premises and verify that checks reject them.

Completion requires compiled proofs without admitted goals/custom project axioms, actual Rust refinement, tested producer-to-consumer integration and accurate cost scopes. Finite benchmarks, proof snippets and a struct named `Certified` cannot substitute for these gates.

## New Torus-Fiber / certified-lift intake

The 2026-11-17 user upload is preserved as a separately hashed evidence packet. Its raw CRT quotient `alpha` is not automatically the source winding `K`. In the supplied alpha-extraction formula, the q2 witness must observe the canonical representative x; substituting a witness of X=x+KM observes alpha-K instead unless an explicit KM correction is made. Benchmark setup and canonical-witness production therefore belong in the admission/cost analysis.

The `certified_lift` crate is a candidate implementation to audit, not an accepted replacement for the engine contract. Its state, bounds, frame binding, supported division semantics and reconstruction paths must pass the same obligations above. The intake report and reproducible findings are indexed from the delivery folder.

Fresh intake outcomes:

- The rich ZIP's 38 checksum entries passed; the older ZIP variants' 27-entry manifests also passed. All ten user attachments are preserved separately.
- The arbitrary-composite Rust default and shared-anchor/witness fixture passed. The supplied exact Python probe passed 1,801,800 canonical cases, 217,800 anchor pairs and 516 witness-boundary cases, with additional high-word and ambiguity checks.
- The benchmark's readout modulus must resolve alpha, not just its independent q2 checker. Its maximal-xi fixture also needs a correct expected rank for small moduli. Both gaps reproduce as preflight rejection; they do not demonstrate wrong accepted reconstructions.
- `certified_lift` passed its 19 original tests. Four independent contract tests (debug and release) demonstrate missing cross-frame binding, short-frame panic, exact scalar tracking through `bound`, and narrow division admission. CL-01 and CL-02 in the detailed review block conformance promotion.
- Preserve prototype strengths as proof targets: concrete producers, signed-bias comparison, pre-alias observation growth, unit-divisor history certificates and redundant-anchor readouts. Their implementations need frame/bound/refusal repairs and refinement proofs.

Next bounded implementation priorities are P1/P4 fixed-primary states, actual sister-tray producers and inherited-invariant preservation, followed by P3/P8 compliant bounds and compatible sister observation growth. An individual finite query's representative interval is not a fixed ceiling on the complete extensible architecture. Keep q2/source-reference and rank-window obligations attached to each alpha kernel; do not infer them from passing the large default fixture.

The full Prime Family read adds explicit P1/P4 obligations from its conditional transfer principle (PDF p. 35): identify the represented property, establish the map/inverse or query-fiber laws, and prove operation preservation. The 77/143 shared-11 fiber product is a written model for dependent views; it does not yet formalize the live sister constructor. Before registering inherited signatures, repair the PDF's nonunit-11 orbit statement, linear-pair offset premise, residue-ring/extension-field distinction, and non-expansion versus pointwise-preservation wording. Proofs must use the corrected predicates, not historical certification labels.

For the fixed coprime carrier base, add a Lean obligation for `alpha_max=floor(sum_i (m_i-1)/m_i)`, attainability of every rank through that maximum, and the resulting exact-rank threshold `q>alpha_max`. S6 has maximum 4, not 5. Under P6, add division-free affine powering via `(p,s)*(q,t)=(pq,s+pt)`; binary exponentiation computes both the power and geometric sum over arbitrary residue rings without assuming `a-1` is a unit. These are written mathematical derivations and future formalization targets, not part of the current 235 declarations.


## Finite-cover integration — 2026-11-26

The [new standalone package](../../../FoliatedCoprimeGeometry/README.md) preserves
the user's supplied finite-cover theorem statements and adds explicit composition
results. Its [fresh receipt](../../../FoliatedCoprimeGeometry/evidence/verification.json)
checks 67 theorems / 97 authored declarations under Lean 4.27.0-rc1, with no
external packages, no admitted proofs, and only `propext` / `Quot.sound` in the
transitive axiom inventory. These counts do not amend the frozen 235-declaration
audit above. Source inspection covered the supplied formalization, this ledger,
and the existing `ConsumerTransport` / `PhaseBinding` contracts at repository
base `64c1c89b191093dc12cf81b87da5fb1a02c46dc1`.

| Obligation | Disposition and freshly checked result | Exact remaining difference |
| --- | --- | --- |
| P1/P3 finite sheet view | SPECIALIZE / INTEGRATE: `coverEquiv`, `kElim_exact`, `shadowGaugeEquiv`; fixed 30030=2730·11 view and on-demand coordinate map | Actual fixed-primary runtime type and serialization; finite semantic coordinate models do not mandate stored K |
| P4 shared 11 compatibility | EXTEND: both projectors preserve exclusive lanes and land in `Pullback`; `phase_lock_iff_shared_map` characterizes all compatible-pair-preserving function pairs | Bind real producers to source/epoch; instantiate other required 2/11 interfaces and named transported signatures |
| P6 successor and heterogeneous transitions | EXTEND: projector equivariance, discrepancy invariance and common shared-map criterion | Register concrete operators against this criterion; arithmetic coherence alone does not establish authenticity or convergence |
| P7 reversible transport | INTEGRATE: `discrepancyEquiv` bundles both inverse laws; `projection_collision` identifies the information a repair would otherwise discard | Choose an authoritative repair policy or retain discrepancy through the actual consumer and serialization path |
| P8/P9 finite dynamics | EXTEND: general positive minimal cycle length, complete/disjoint orbits, and exact return times for concrete raw residues | Compatible infinite-family construction and topology; actual runtime transition refinement; no claim of universal finite-observation magnitude recovery |

Next dependency order: implement and prove actual same-source constructors for
the required sister interfaces; instantiate heterogeneous operator compatibility;
carry the lossless discrepancy contract through consumers; then compose compatible
refinements into the intended inverse system. Existing universal transport,
source-binding and signed congruence proofs remain reusable dependencies. The
finite results above are complete at their stated scope, not reopened as future
proof obligations by the remaining implementation work.
