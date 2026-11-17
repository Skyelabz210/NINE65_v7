# Producer-bound residue runtime and public query planning

Implemented in `cram-core::query_runtime`, starting from NINE65 research snapshot
`d883d24` (original implementation base `88a7bda`). This is an actual clear
residue producer-to-consumer path. It does not claim an encrypted remainder
producer, FHE correctness, confidentiality or physical constant-time behavior.

## Interface and authority

`AdjacentProducer::new(M, ingress_upper)` fixes a public workload profile and
capacity `M*(M+1)`. Every input admitted through that producer receives the same
upper bound. `ingress` accepts the integer at its declared boundary and retains
only its two residues, local source/frame/epoch IDs and the public upper bound.
The state has private fields, no raw-residue constructor and no Clone/serde
implementation. Debug exposes public metadata only.

`observe` issues a borrowed capability. Its `plan(QuerySpec)` returns a plan
bound to the exact source, frame and epoch. `execute` checks all three before
answering. Mixing equal-valued independently issued sources is refused, and a
plan becomes stale after an update even if the residues do not change. These
are guarantees of the safe local Rust API, not signatures or remote attestation.

`add_assign` and `multiply_assign` perform independent modular lane operations.
Their new bounds are `L+R` and `L*R`, using checked arithmetic. Admission and
epoch checks precede mutation. Bounds are never tightened by inspecting the
actual hidden magnitude. An operation may conservatively refuse even if that
particular pair of inputs would fit.

`square_assign` performs the self-product directly in the same two lanes,
updates the bound to U² and advances the epoch. It neither clones a source
identity nor requires integer re-ingress. Repeated squaring is refused before
mutation when its public capacity/word bound is exhausted.

## Arithmetic refinement argument

Let `r=X mod M`, `a=X mod (M+1)` and `0<=X<=U<M*(M+1)`. The adjacent readout
`k=(r-a) mod (M+1)` equals `floor(X/M)` by the existing checked StarLift theorem.
The runtime derives k temporarily and stores no k field.

For a linear query `(cX+o) mod b`, it evaluates the low and high terms directly
in the target ring: `c*r mod b` and `(c*M mod b)*(k mod b) mod b`, then adds the
offset. It never assembles `r+M*k` as a source integer. The output is the
explicit requested residue projection; requesting a modulus larger than the
admitted range can, intentionally, reveal the whole bounded value at that
output boundary.

For the quotient query `floor(X/d) mod b`, divisor `d=M` uses the adjacent
readout directly. A divisor greater than the public bound returns zero.
Other positive divisors use bounded residue-space repeated subtraction. The
comparison uses the lexicographic pair `(k,r)` against `(floor(d/M), d mod M)`.
Every successful subtraction updates both remainder lanes and increments only
the requested quotient residue modulo b. At most `floor(U/d)` successful
subtractions occur. Euclidean division correctness follows from the invariant
`X=d*q+remainder`, `remainder>=0` and the final `remainder<d`; the oracle integer
appears only in tests. Shared factors between d and the frame require no inverse.
Negative quotient queries negate the final target residue. Invalid divisor zero
is refused.

The generic quotient loop is a reference runtime algorithm, not a competitive
constant-time divider. Its branches and early termination depend on the clear
residue state. Only the bounded adjacent readout itself uses one modular
subtraction. QueryCost counts actual modular helper calls, readouts, comparisons
and iterations; it does not charge public setup, machine reductions, ingress,
memory, bit-width arithmetic or encrypted work.

Plans preflight the public quotient loop bound against a default budget of
1,000,000 steps. `plan_with_budget` permits an explicitly chosen public limit;
the limit is not inferred from the source value. `WorkBudgetExceeded` refuses
an oversized general quotient before execution. Direct adjacent readout and
constant-output routes do not consume this repeated-subtraction budget.

The above induction connects the code's definitions to the existing checked
mathematical primitives, but is a written refinement argument, not a machine-
checked Rust semantics proof. The local source binding remains a separate API
invariant from arithmetic correctness.

## Public planner

`plan_demands` computes LCM observation capacity, exact unrestricted-integer
linear/quotient query periods and the least extra anchor by factorization-free
gcd saturation. `select_producers` optimizes a public candidate catalog by cost,
then count, then sorted ID. It accepts at most 16 candidates and requires the
entire offered catalog's LCM and total cost to fit u64. Conservative overflow
refusal is explicit; it does not search for a smaller representable catalog.

A ProducerCandidate describes the availability contract supplied by a planner
client; it is not an issued reading and cannot construct live SourceState or
Observation authority. Thus a public plan cannot manufacture missing information.

An unconditional period certificate and a bounded source certificate differ.
The runtime's authentic adjacent pair uniquely names the admitted bounded
source, so it can answer target moduli not dividing the frame product. The
unrestricted planner correctly asks for extra information for those same
queries when no interval certificate is supplied. Neither criterion substitutes
for the other.

The implemented frame is an adjacent CLASS-R arithmetic profile, not a claim
to implement all S8 role or NTT/CLASS-F policies. No production dependencies
were added to cram-core.

## Executed verification

`core-tests.json` and `core-tests.log` record the exact command and source hashes.
That first core package run includes 13 existing unit tests, five existing
workload tests and ten new integration tests. The later `adapter-tests.json`
and `core-square.log` add a self-product regression and record the current
29-test core package run. The new tests exercise:

* All 1,332 states through 48 direct linear/adjacent consumers each: 63,936
  output comparisons, including signed coefficients and u64::MAX modulus.
* All 1,332 states through twelve divisors, three target moduli and both signs:
  95,904 quotient-output comparisons, including nonunits and zero quotients.
* All 1,296 pairs in the shared public `[0,35]` profile through addition,
  multiplication and mixed sequences; another 64 small mixed sequences.
* 6,400 period/demand pairs with 160 independently enumerated anchor candidates,
  4,096 signed quotient-period cases and 1,200 catalog optimization cases
  independently checked against all 64 subsets.
* Wrong source/frame, stale epochs with unchanged residues, invalid parameters,
  overflow, alias-capacity boundary, missing observations, atomic refusal and
  runtime operation-count assertions.

The first package run also passed all 28 tests. Its intentionally simple
anchor oracle took about 50 seconds; the final oracle scans only positive
multiples of the base period, preserving the same exhaustive mathematical
check with less test overhead. This timing is test execution evidence, not a
runtime benchmark or a claimed CRAM speedup.

## Matched cost experiment

`query_runtime_cost` first checks every result against a clear integer oracle,
then measures the same 1,332-input, three-query workload three times. It records
producer setup, ingress and planning separately from steady query execution,
and also measures ingress+planning+query and the declared clear integer boundary
baseline. `matched-cost.json` contains all raw nanosecond observations and actual
query operation counts. This is a small transparent cost experiment, with no
RNS/FHE acceleration claim or statistically established timing comparison. It
demonstrates the real cost of the general repeated-subtraction consumer instead
of extrapolating the adjacent readout's one subtraction to an entire algorithm.

## NINE65 compiler and UNHAL adapter

The opt-in `nine65/residue-query` feature exposes
`compiler::residue_query::{plan_information,choose_observation_producers,execute_residue_queries}`.
It leaves default features and cryptographic evaluators unchanged. The adapter
reuses the public planner, obtains a real producer-issued observation, and
preflights every source-bound plan before executing any query. It does not use
the parent compiler's floating-point heuristic noise model.

With `accelerated`, execution calls the actual UNHAL `Accelerator::run_lanes`
entry point and its deterministic MANA backend. Without it, the same plans
execute serially. Output ordering and results agree. Only public query count
and executor configuration select scheduling; the clear general-division
consumer retains its explicitly variable-time semantics.

The dedicated caller tests use 128 queries to exercise the accelerated path,
compare each answer against both direct serial execution and an integer oracle,
refuse wrong frames and invalid/resource-exceeding queries, and demonstrate
the difference between unrestricted demand and bounded observation admission.
`adapter-tests.json` records both feature configurations, exact commands,
nonzero test counts and matching source hashes. Neither route is an encrypted
query-producer claim.
