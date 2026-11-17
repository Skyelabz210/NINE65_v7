# Independent review of the cross-pollination packet

Reviewed 12 November 2026 against NINE65 base commit
`88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`. The review covers the two new
public-model implementations, their tests, the 14 new Lean theorem statements
and proofs, the integrated proof metadata, and the three substantive research
reports. It is not a whole-repository code audit, an encrypted execution, or
an independent historical-priority determination. The referenced live task
remains unavailable; its contents were not used.

The follow-up review also covers [the central synthesis](README.md),
[the planner and future-equivalence derivations](PLANNER_PROOFS.md), and
[the integration plan](../../docs/execution/2026-11-12/UNIVERSAL_CROSS_POLLINATION.md).

**Result: no blocking mathematical or implementation error found within this
scope.** The models and deductions support a consumer-directed observation
layer with explicit conditions for continued computation. They do not establish
that all suggested domain adapters are implemented.

## Public anchor planner

The factorization-free anchor construction is correct. Write
`p = v_q(P)` and `d = v_q(D)` for the valuation at any prime q. The initial
anchor `D/gcd(P,D)` has valuation `max(d-p,0)`. Each saturation step
`a <- gcd(D,a*a)` replaces its valuation by `min(d,2*v_q(a))`. Thus covered
primes stay absent, while every deficient prime reaches its full exponent in D.
The process terminates because a strictly increases through divisors of D
until stable. Its limit is exactly

\[
\prod_{q:\,v_q(D)>v_q(P)}q^{v_q(D)},
\]

which divides every sufficient extra anchor and is itself sufficient. This
proves minimality under divisibility, not an unconditional cheapest physical
producer. The separate cost selection solves the specified finite candidate
problem.

The dynamic-programming state `gcd(current_period,D)` is sufficient because
future updates depend only on
`lcm(coverage,gcd(candidate_modulus,D))`. Minimum cost, then minimum count,
then lexicographic names is a valid stable tie order when extending with
later candidates. Each candidate is considered at most once. The stated
state-transition bound excludes big-integer and tuple-management costs and is
correct as phrased.

The query periods are correct on all integers:

- `(a*x+c) mod b` has least positive period `b/gcd(a,b)`, including a=0 and
  negative coefficients.
- `floor(x/d) mod b` has period `d*b` for b>1; b=1 is constant. If a proposed
  period has nonzero remainder modulo d, the quotient increment takes two
  consecutive values, which cannot both vanish modulo b>1. This proves
  necessity as well as sufficiency.
- Bundled queries require the LCM of their periods. Pullback through an
  affine operation cannot increase the source period needed for a linear
  modular query.

The API consumes public moduli, query descriptions and costs only. It does not
manufacture a missing observation, establish producer authenticity, or decode
a secret value. This boundary is essential to its proposed CRAM use.

## Future-query compiler

The finite refinement algorithm is correct for the stated total transition
tables. Initially, states share a class exactly when their demanded outputs
agree. Each iteration refines by every successor class while retaining the
old class. Any output-sufficient stable partition must refine the initial
partition and, inductively, every later one. The fixed point is therefore the
coarsest stable sufficient partition. Every strict iteration adds a class,
giving at most `n - initial_class_count` strict refinements. Canonical class
numbering makes equality of the class tuples a sound fixed-point check.

The generated quotient tables are well-defined at the fixed point. The model
correctly refuses transitions leaving the admitted finite domain. Explicit
state enumeration is research tooling, not a proposed secret-dependent FHE
execution path. A fixed terminal query can need less information than this
all-future-words construction; the reports and Lean module retain that
distinction.

## Independent executed checks

The rerunnable [reviewer oracle](evidence/reviewer_oracles.py) uses different
algorithms from the implementations. [Its JSON result](evidence/reviewer_oracles.json)
records the deterministic seed, exact source hashes and successful checks:

| Independent oracle | Cases | Result |
|---|---:|---|
| Explicit trial factorization versus gcd-saturation anchor construction | 5,000 | PASS |
| Exhaustive candidate subsets versus cost dynamic programming | 1,500 | PASS |
| Pair-graph distinguishability versus partition refinement | 2,000 | PASS |

The pair-graph oracle marks state pairs distinguishable by current outputs,
then closes backwards through transitions. It agrees with the compiler's
final equivalence relation in every generated model. These checks supplement
the written arguments; they are finite checks rather than universal proofs.

Run from the repository root:

```sh
python3 research/universal-cross-pollination/evidence/reviewer_oracles.py
```

## Lean review and evidence reconciliation

All 14 new statements and proof bodies in
[ConsumerTransport.lean](lean/ConsumerTransport.lean) were read. The most
substantive addition is existence and uniqueness of exact quotient dynamics
on valid observations precisely when source transitions preserve observation
fibers; the additive specialization correctly requires kernel invariance.
The consumer, postprocessing, finite-program and equivalent-frame lemmas have
their needed assumptions. The parity/halving counterexample is valid.

The reviewed integrated build report records 144 checked declarations: 130
unchanged prior declarations and 14 new ones. Nine of the new declarations
are axiom-free. The others use only the listed standard foundations. The
review independently recomputed all 13 module hashes in `verification.json`,
recounted its theorem records, checked allowed axiom names, and compared all
11 dependency files byte-for-byte against the prior proof packet. All checks
passed. This review did not count the unchanged dependencies as new work or
substitute metadata checking for the producer's recorded fresh Lean build.

An intermediate README still described the earlier 24-declaration dependency
slice; the proof author corrected it to the final 130-declaration dependency
set and 13 modules before completion. No mathematical result changed.

Existential decoders using classical choice establish exact mathematical
factorization, not an efficient runtime constructor. A bounded-state subtype
must be preserved by its admitted transitions. These limitations are stated
in the reviewed module and documentation.

## Cross-domain and internal connection review

The written deductions in [the arithmetic report](ARITHMETIC_CRYPTO_CONNECTIONS.md),
[the external-domain report](DISPARATE_DOMAIN_CONNECTIONS.md), and
[the repository inventory](INNOVATION_INVENTORY.md) were reviewed. Useful
conditions that must survive any later condensation are:

- **G/H retraction:** the root and derivative-inverse certificates establish
  the residual retraction on the stated supported charts modulo p². A
  weighted nonunit target may satisfy a weaker scalar equation, but a single
  coherent composite-ring interpolation polynomial remains an additional
  construction.
- **Division composition:** nested Euclidean floor drops compose with an
  exact remainder law. Nearest rounding does not inherit that law, as the
  provided counterexample shows. The public 2w-round Euclidean schedule
  suffices for w-bit inputs with a frozen zero branch; ciphertext refinement
  and noise admission remain proposed work.
- **Observation dynamics:** present query sufficiency is weaker than
  transition stability. This matters for MAA reflections, time folding,
  control observability, compressed execution and stochastic lumpability.
- **Replication and provenance:** arithmetic merge must descend through the
  observation relation; addition does not provide deduplication, and modular
  projection does not preserve maximum merge. Shared plaintext roots do not
  justify mixing distinct source phases.
- **Faults and synchronization:** query-specific Hamming distance supplies the
  stated finite error-correction criterion. Graph cycle consistency supplies
  phase realizability, not authenticity. Both require the actual observation
  alphabet/domain.
- **Statistics and the continuum:** deterministic factorization of one query
  differs from statistical sufficiency for a parameter family. Finite
  quotient dynamics and exact interpolation do not alone prove a real
  continuum/PDE limit.

Selected source assertions, including GRO's circular-distance observation and
Triad's finite S8 agreement, were checked against the actual code. The
inventory's corrections distinguish those observations from stronger claims
in module banners. The source bibliography transparently limits each external
citation to retrieved material and identifies independent written deductions;
this review is not a second exhaustive literature search.

The remaining work is concrete: connect the public planner and proof contracts
to authentic producers, implement the proposed adapters, and establish the
corresponding refinement and measured costs. No production path was changed
by this review.

## Central synthesis and universal-property follow-up

The all-future equivalence is correctly stated for total admitted transitions
and every finite operation word, including the empty word. Appending a fixed
first operation proves transition stability. Conversely, induction on word
length shows that every output-preserving stable equivalence is contained in
it. Thus it is the coarsest such equivalence, and in the additive case its
invisible subgroup is the largest transition-invariant subgroup contained in
all consumer kernels. This is a written universal-property argument; the
packet does not count it as a fifteenth new Lean theorem.

The affine StarLift typing is correct: the direct coordinate query
`C(k)=k mod A` can be induced by the ambient map `p(x)=M^(-1)x mod A`
when M is invertible modulo A. The ambient reduction `p(x)=x mod A` instead
induces `C(k)=Mk mod A`. Distinguishing these maps avoids an otherwise real
type/semantic error while retaining both adjacent-modulus formulas.

The planning proofs correctly separate least information periods, least
anchors under divisibility, minimum cost among given producers, and actual
runtime feasibility. An authentic new reading is a required input-producing
capability, not a consequence of the plan. The integration plan retains that
dependency and does not mark its proposed production gates complete.

The follow-up requested three small presentation corrections: explicitly
state additivity of both B and F for kernel invariance; write the saturation
iteration bound with a constant term; and describe exponent 151 rather than
“151 bits of exponent.” All three corrections were applied and verified.
They do not change any implemented algorithm or proved statement. Final reviewed document hashes are recorded in
`evidence/reviewer_scope.json`.
