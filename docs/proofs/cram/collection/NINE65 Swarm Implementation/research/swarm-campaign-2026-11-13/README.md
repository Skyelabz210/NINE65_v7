# CRAM universal discovery and implementation — 13 November 2026

The accepted balanced discovery/build campaign is implemented. Its results are
reviewable code in NINE65, an updated original Lean repository, executable
cross-domain models, source coverage, counterexamples, and a versioned proof
collection. The central design is **compute the required query from authentic
observations, and retain exactly the information needed for future queries**.
K remains an on-demand readout rather than a persistent scalar magnitude ledger.

## What changed

| Contribution | Implemented or established | Evidence |
|---|---|---|
| Future-query universality | Actual quotient output/transition constructors; coarsest sufficient transition-preserved equivalence; finite-refinement fixed-point semantics; largest invisible additive subgroup | [Formal results](proofs/README.md) |
| Least sufficient anchor | For positive P,D, the gcd recurrence computes the divisibility-least a satisfying D divides lcm(P,a), with finite fuel and early stopping | [Nat proof](proofs/mathlib/AnchorSaturation.lean) |
| General ring reflections | Involution and Descartes-polynomial preservation over every commutative ring, including composite residue rings | [Reflection proof](proofs/ReflectionInvariant.lean) |
| Native residue consumers | Producer-owned observations, source/frame/epoch binding, lane add/multiply/square, public demand and producer planning, and an opt-in compiler/UNHAL adapter | [Runtime](runtime-residue/README.md) |
| Encrypted GCD | Fixed-round Euclid plus a direct small-width query circuit; real native N=8192 two-bit executions after the first strategy's recorded refusal | [GCD implementation and evidence](runtime-gcd/README.md) |
| Cross-domain constructions | Composite-module query compiler, exact geometric orientation, actual BBS path-evolution intertwining, Hasse-jet quotient recovery and local precision lifting | [Discovery report](discovery/REPORT.md) |
| Corpus and lineage | 42 uploaded files, 108 extracted artifacts, eight repository inventories, scoped source reads and explicit unavailable context | [Coverage](registry/SOURCE_COVERAGE.md) |

### The general theorem and its constructive returns

For an observation B and query C on an abelian source group, exact additive
transport on the observed image exists exactly when `ker B ⊆ ker C`. The set
version requires the query to be constant on observation fibers. This is the
underlying factorization principle. Its use here is constructive: identify the
specific observation, the required query, the remaining ambiguity, and an
executable decoder or a witness that no decoder exists.

For evolving systems, equality of every requested query after every finite
operation word is the coarsest sufficient equivalence preserved by the declared
operations. The new Lean development constructs its quotient outputs and
transitions. This states a universal *relative-to-queries-and-operations* result;
it does not say any chosen compressed representation is closed under arbitrary
operations. That distinction supplies both a design method and a falsification
test for future CRAM, quantum-family and state-reduction proposals.

For public observed period P and target demand D, the new constructive anchor
result is

```
a₀ = D / gcd(P,D)
aₙ₊₁ = gcd(D,aₙ²).
```

At its fixed point, a is sufficient and divides every other sufficient anchor:
`D | lcm(P,a)` and `D | lcm(P,b) ⇒ a | b`. Positive P,D are required.
The checked proof gives conservative fuel D and proves early stopping correct.
The algorithm needs no factorization input; prime exponents are used in its
proof. The Rust planner uses checked finite-width arithmetic and refuses
overflow; its source-level refinement to Lean is a remaining obligation.

These statements reach beyond a scalar CRT readout. Their algebraic ingredients
have established mathematical antecedents; that alone does not settle the
novelty of the architecture, constructions or integrations. This campaign makes
no historical-priority ruling and compares mechanisms and hypotheses explicitly.

## Actual implementation and validation

The original `k-elimination-lean4` project builds from its pinned sources and
passes an audit of **223 unique theorem declarations**: 27 original root,
three repaired Basic, 144 preserved universal foundation, **36 new standard-
library and 13 new Nat declarations**. Thus **49 are new**, not 223. No custom
project axioms or admitted proofs were used; foundational axioms are listed per
declaration. A second fresh independent build checks the 180-declaration
standalone subset. The full inventory and patch are in
[original-repo-verification.json](proofs/original-repo-verification.json).

The residue runtime passes 29 core tests plus three serial and three accelerated
adapter tests. Its private producer-owned state retains residue lanes and public
bounds. Native operations update those lanes; queries derive K temporarily.
Stale plans, source/frame mismatch, range overflow and excessive public work
budgets refuse explicitly. `residue-query` is opt-in and default features are
unchanged. The general quotient consumer is a variable-time clear reference
algorithm; it is not an encrypted division circuit. The measured clear baseline
is faster on the recorded tiny workload, so no speedup is claimed.

Encrypted GCD uses the existing sealed bit representation, immutable histories
and gate-by-gate preflight. Fixed Euclid runs 2w rounds for public widths 1–8.
The direct strategy compiles the final query for widths 1–4, without inspecting
encrypted inputs. At width two, it reduces the actual DAG from **54 products at
depth 11 to 23 products at depth 2**. The same N=8192/t=3 test tuple that refused
fixed Euclid admits the direct strategy; gcd(3,2), gcd(0,0) and gcd(2,2) pass
49,152 output-coefficient checks. Native one-bit fixed-strategy checks add
16,384. These are arithmetic executions, not a new cryptographic security
validation or proof that larger widths admit.

The rational-pair reference separately tests 1,953 normalizations and 11,025
multiplications with cross-cancellation. It is not an encrypted rational API.
The existing private-feedback encrypted aggregation test passes all eight slots
under its unchanged configuration; the new conservation model is not silently
substituted into that encrypted path.

Independent review executes 95,448 actual GCD DAG cases with a separate
common-divisor oracle and 136,020 public residue-query checks, in addition to
independent domain checks and proof-body review. See
[REVIEW.md](reviews/REVIEW.md), [integrated runtime evidence](evidence/integrated-runtime.json)
and each worker's source-bound logs. Counts describe their stated scopes and
overlap; they should not be summed as independent evidence of universal safety.

## Cross-pollination that can be used next

The graph screens **22 families, 231 unordered pairs and 462 directions**.
Twelve deeper candidates are split evenly among practical returns, frontier
generalizations and internal compositions. Screening is triage, not 231 proofs.
The final [contribution ledger](registry/contributions.jsonl) joins every
candidate's source, assumptions, separate potential/readiness scores, forward
benefit and return benefit to a scoped execution result.

1. **Composite-module compiler:** given a verified public diagonal certificate,
   produce query weights or an explicit kernel collision. This imports normal-
   form methods into query-directed planning and works with nonunit observations.
2. **Exact geometry:** bounded orientation predicates exercise a useful sign
   consumer without reconstructing the full determinant.
3. **BBS dynamics:** for nearest-neighbor integer heights and an explicit empty-
   carrier boundary, linear interpolation commutes with the running maximum,
   hence with the actual Pitman/BBS evolution. General jumps have a recorded
   counterexample. This is continuous space and discrete time, not a PDE limit.
4. **Hasse jets:** at a shared root, the first nonzero multiplier jet restores
   quotient evaluation lost by value-only observations. The unit condition and
   authentic jet-production cost remain explicit.
5. **Local precision:** Hensel correction supplies a step-by-step template for
   higher-order G/H observations; a low-order result does not establish all
   precision levels.
6. **Internal returns:** general-ring reflection invariants, centered theta
   negative-winding queries with wall policies, exact-total normalization, and
   a repaired energy-bound inference. Exact energy preservation alone does not
   imply maximum-coordinate contraction.

Five external documents received bounded primary-source reads, with explicit
scope in [sources.json](discovery/sources.json). Four useful method imports are
listed in [usable_now.jsonl](discovery/usable_now.jsonl). No external source code
was copied into these reference models.

## Ranked continuation backlog

| Priority | Next contribution | Decisive completion condition |
|---|---|---|
| 1 | Rust/Lean refinement for source-bound queries and anchor planning | Prove executable state transitions and checked-width behavior match the mathematical contracts |
| 2 | Wider admitted encrypted GCD | Compare direct, binary and composed circuits under identical inputs/histories; record full noise, memory and time costs |
| 3 | Composite-module public planner | Scalable certificate production plus a verified checker and typed Rust integration |
| 4 | Lean BBS interpolation bridge | Prove real-coordinate running-maximum commutation and explicit finite-tail boundary semantics |
| 5 | Authentic polynomial/jet and higher-order G/H producers | Produce needed observations and prove their precision, provenance and cost |
| 6 | Encrypted rational normalization | Compose admitted sign/GCD/exact-division operations with denominator and capacity certificates |
| 7 | Matched geometry and multi-query benchmarks | Compare complete input-to-output paths, charging observation acquisition and all bit-width costs |

The linked Codex task remains unread because this session exposes no
`read_thread` tool. Its title was not used as evidence. Repository tree
inventory is distinguished from whole-source review, and the uploaded PDFs
have not received a page-by-page formula audit. Private Drive source bodies
remain outside repository-ready artifacts.

## Reproduce and review

`python3 run_all.py` from the discovery directory rebuilds its models,
admission tests, graph and validation. From this campaign directory,
`python3 tools/verify_campaign.py --models --complete` checks coverage, exact models and final evidence;
the proof and Rust READMEs list pinned commands and their individual scopes.
`tools/build_contributions.py` joins final evidence into the coordinator ledger.

Local changes and the separate Lean patch are delivered for review. No public
GitHub push or publication is part of this campaign. The private Drive
[CRAM Proofs folder](https://drive.google.com/drive/folders/1CbC-CoHlIsT-5XNn8O5qHVDBnRW2uYql)
contains the preserved baseline and versioned implementation collection;
[delivery evidence](evidence/drive-delivery.json) records actual upload/readback
status rather than treating a local archive as uploaded.
