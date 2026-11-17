# Consumer-directed query transport and dynamical closure

This module adds **14 machine-checked theorem declarations** to the existing
130-declaration universal K-Elimination research packet. Its build checks all
**144 declarations**, including the 130 unchanged prior declarations; those
130 are not counted as new. It was
developed against NINE65 source commit
`88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484` on the local research branch.
The results concern mathematical exactness, with no change to the production
Rust or ciphertext paths.

The new result needed for cross-domain use is a precise **dynamical closure
criterion**. Write `o : X → R` for authentic observations and `F : X → X` for
an admitted source transition. An autonomous transition on *valid readings*
exists exactly when

\[
o(x)=o(y)\;\Longrightarrow\;o(F(x))=o(F(y)).
\]

Thus a representation adequate for today's query need not be adequate for
tomorrow's computation. For additive `B` and `F`, the criterion becomes

\[
F(\ker B)\subseteq\ker B.
\]

This is the same condition used by exact quotient dynamics and linear
observability reductions. It gives CRAM a concrete proof obligation for
reusing an observation frame across an operation, independently of whether
the final consumer needs the whole integer.

## Verified coverage

| New declarations | What they establish |
| --- | --- |
| `paired_queries_iff`, `indexed_queries_iff` | A shared reading serves a bundle exactly iff it serves each member. The index family can be finite or infinite; computation cost is not asserted. |
| `postprocess_sufficient`, `injective_postprocess_iff` | Processing an available result cannot increase its source-information requirement; injective processing preserves that requirement exactly. |
| `quotient_transition_exists_iff`, `quotient_transition_unique` | Fiber stability is necessary and sufficient for a unique transition on the authentic observation image. |
| `stable_transports_consumer` | A stable transition preserves access to every currently recoverable consumer. |
| `stable_composition`, `stable_finite_program`, `finite_program_consumer_sufficient` | Stability and consumer exactness compose through any finite program whose primitives satisfy the stated hypotheses. |
| `terminal_query_exists_iff` | A particular final query can be transported even when full frame stability is unavailable, precisely when its program pullback is constant on initial fibers. |
| `stable_under_equivalent_observations` | Reversibly re-encoding valid readings preserves the dynamic closure question. |
| `additive_stability_iff_kernel_invariant` | Additive dynamic closure is exactly invariance of the observation kernel. |
| `parity_halving_not_stable` | A checked obstruction: 0 and 2 have equal parity, but after integer halving their parities differ. |

Nine new declarations are axiom-free; the remaining five use only the standard
foundations recorded individually in `verification.json`: `propext`,
`Classical.choice`, and/or `Quot.sound`. There are no project axioms or admitted
proofs. `Classical.choice` appears in existence results on the observation
image; these results do **not** construct an efficient residue decoder.

## Interpretation for NINE65

1. A consumer graph may pair several queries and reuse their authentic
   observations. Postprocessing an already recovered query adds no new
   information requirement. It can still add substantial arithmetic cost.
2. Before reusing a frame across a source operation, prove stability or prove
   the exact terminal query criterion. When neither holds, add authentic
   observations before losing the information, narrow the admitted domain,
   or refuse the operation.
3. Frame transduction can carry this closure proof when both encodings agree
   on the common admitted source. It cannot repair missing information.

These proofs do not assume or introduce a persistent scalar K, reconstructed
source integer, synthetic Garner emission, FHE bootstrap, or encrypted
division algorithm. A valid-state subtype can encode a bounded domain, but
every transition on that subtype must actually preserve admission. The
additive specialization uses ambient additive groups; a bounded interval is
usually not an additive subgroup, so its weaker domain-specific criterion is
the general fiber theorem.

## Reproduction

Use the pinned toolchain in `lean-toolchain`:

```sh
python3 check_proofs.py --lean lean
python3 check_negative_controls.py --lean lean
```

The checker compiles all thirteen project modules from source into a fresh
temporary directory, sets `LEAN_PATH` to that directory, and reads no saved
project `.olean` files. Every theorem has a separate `#print axioms` query;
unexpected axioms, admissions, opaque assumptions, warnings, or missing
queries fail the build. `verification.json` records each source SHA-256 and
each theorem's axiom dependencies; `verification.log` records the executed
commands and Lean output.

Four controlled invalid artifacts were refused: an admitted proof, a custom
axiom, a false positive halving-stability claim, and a missing axiom-audit
query. These are checker controls, not runtime benchmarks or encrypted tests.

Eleven modules, from `ExactObservation.lean` through the
`UniversalKElimination.lean` aggregate, are copied unchanged from the existing
local universal proof packet, with provenance in
`dependency-provenance.json`. They include all 130 previously checked
declarations: the fiber criterion, additive and ring transport, actual
integer/nonunit/coupled-anchor specializations, costed readout, residue
divmod/GCD implementations with concrete primitives, and StarLift. The new
theorems are in `ConsumerTransport.lean`; `AllResearch.lean` imports both
packages without modifying the prior aggregate.
