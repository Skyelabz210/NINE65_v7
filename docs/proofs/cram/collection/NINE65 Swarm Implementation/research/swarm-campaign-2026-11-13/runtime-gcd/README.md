# Consumer-directed encrypted GCD and rational-pair reference

Source base: NINE65 `d883d24` (the preserved research snapshot over
`88a7bdadbf0e1f8fbfdb2b37e9843101b8db3484`). Date: 2026-11-13.
This contribution composes an existing encrypted integer divider into a new
GCD circuit, then uses the final consumer to compile a lower-depth small-word
alternative. It does not implement GCD by modular reciprocal or by decrypting
an operand. Rational normalization below is a separate clear reference.

## Implemented interface and mechanism

`CramMainEvaluator::plan_integer_gcd(a,b)` constructs and admits a public
Boolean DAG. `gcd_integer(a,b)` evaluates it and returns a sealed
`EncryptedUint`; the public CRAM facade exposes the same operation and records
its successful use. Inputs may have unequal widths and the output uses their
maximum. Public width selects `SmallTruthTable` through width 4 and
`FixedEuclid` for widths 5–8. Explicit `*_with_strategy` methods retain both
constructors for reproducible comparisons. A forced table above width 4 receives
`GcdTableWidth`; any GCD width above 8 receives `GcdWidth`. Original division
retains widths 1–64.

The `FixedEuclid` builder uses the existing division DAG as a subcircuit in exactly 2w
Euclidean rounds. Let z be its encrypted denominator-zero predicate and r its
remainder. Every round constructs

```
next_a = select(z, a, b)
next_b = select(z, 0, r)
```

The terminal state `(a,0)` therefore freezes rather than alternating or losing
a. The final first word is the GCD, including gcd(0,0)=0. Common subexpressions,
constant simplifications and dead-gate removal use the same Boolean builder.
The quotient outputs of intermediate division subcircuits are unneeded and
are removed when dead.

`SmallTruthTable` instead compiles only the final target. It enumerates public
candidate bit patterns, computes their GCD using bounded public arithmetic,
and builds disjoint Boolean minterms for the output bits. Runtime evaluates
the same polynomial for every encrypted input. No input decrypts, indexes a
lookup table or controls a branch. The executed division-round count is zero
for this strategy; its compiler's public candidate calculations are not
encrypted Euclidean rounds.

All input bits retain private constructors, key-domain validation and immutable
noise histories. Division and GCD share the original gate-by-gate noise
preflight and ciphertext evaluator; the refactor does not weaken admission or
reset a bound. Source values never select the circuit shape. No live scalar
winding or reconstructed operand is introduced.

## Written correctness argument

For b>0, the divider returns r=a mod b with 0<=r<b, so
`gcd(a,b)=gcd(b,r)`. For b=0 the masked update preserves `(a,0)`. Thus the
invariant holds through every public round, including zero inputs.

If r is positive, examine the next remainder s=b mod r. If r<=b/2 then
s<r<=b/2. Otherwise b/2<r<b, so s=b-r<b/2. If r=0 the terminal state has
already been reached. Consequently the positive second component becomes
less than half its old value every two rounds. Since the original b<2^w,
after 2w rounds the second component is zero. The first component is therefore
the original GCD. This proof applies to zero-extended unequal-width operands.

The Boolean circuit correspondence uses the already tested divider semantics,
the encrypted zero predicate and the exact select equations. Independent
review additionally evaluates the actual composed DAG using a separate common-
divisor oracle. This is written proof and execution evidence, not a new Lean
refinement theorem for the Rust evaluator.

For the direct table, exactly one input-pair minterm is 1 for Boolean inputs.
Each output is the sum of those mutually disjoint minterms whose public GCD
has that bit set. It therefore equals the desired GCD bit over the plaintext
ring. Construction and evaluation size can both grow exponentially in the
combined bit widths, and the small-width cap is essential. Evaluation has the
recorded finite DAG cost; a polynomial expression is not a polynomial-size
complexity guarantee for unbounded truth-table compilation or execution.

## What actually executes, and what refuses

The initial GCD test run executes all one-bit pairs and six two-bit pairs under
an n=8/t=3 research configuration derived from the existing secure_256 modulus
chain. The two-bit cases include gcd(3,2), gcd(2,3), gcd(2,2), both zero operand
orientations and gcd(0,0). Every output polynomial coefficient is checked, not
only the leading plaintext value.

The fixed-Euclid native secure_128-derived n=8192/t=3 configuration executes the one-bit
cases gcd(0,0) and gcd(1,0), checking 16,384 coefficients in total. One-bit GCD
is mathematically OR; this fixed-Euclid native demonstration must not be described as
native execution of general multi-bit Euclid. At n=8 the two-bit fixed experiment
does exercise a nontrivial four-round composed Euclidean circuit.

The fixed-Euclid n=8 profile admits widths 1 and 2. Fixed widths 3–8 refuse its
noise budget. Fixed native n=8192 width 2 refuses both the secure_128-derived
tuple (gate 40) and the larger secure_256-derived research tuple (gate 58). Initial tests that
incorrectly assumed these tuples would admit width 2 failed at preflight; their
logs are retained. The corrected tests explicitly require these refusals.
These are resource/admission boundaries, not observed GCD arithmetic failures.

The direct-target strategy addresses that observed obstruction by reducing
intermediate computation. Under the **same native n=8192/t=3 tuple**, it
admits width 2 with 23 products, product depth 2 and 41,000 remaining millibits.
Actual encrypted gcd(3,2)=1, gcd(0,0)=0 and gcd(2,2)=2 pass every output
coefficient: **49,152 native direct-strategy coefficient checks**, in addition
to 16,384 native fixed-strategy checks. At n=8, four selected cases at each
width1–4 execute successfully with the direct strategy. The final targeted
GCD run passes seven tests in 55.48 seconds, including refusals and history
preservation. This is real producer-to-consumer ciphertext execution, not
only a clear circuit model. Neither modified tuple nor this arithmetic run
establishes a new security admission.

Gate counts are extracted from the actual compiled DAG by `circuit_costs.rs`:

| Width | Euclid rounds | DAG nodes | Ciphertext products | Product depth |
|---:|---:|---:|---:|---:|
| 1 | 2 | 10 | 4 | 3 |
| 2 | 4 | 92 | 54 | 11 |
| 3 | 6 | 636 | 345 | 23 |
| 4 | 8 | 3,962 | 1,750 | 31 |
| 5 | 10 | 1,790 | 1,134 | 319 |
| 6 | 12 | 3,144 | 1,991 | 532 |
| 7 | 14 | 5,054 | 3,198 | 823 |
| 8 | 16 | 7,616 | 4,815 | 1,204 |

The alternate direct-target costs for widths 1–4 are respectively 3, 23, 87, 303
products at product depths 1, 2, 3, 3. Thus width 2 drops from 54 products/depth 11 to
23/depth 2, and width 4 drops from1,750/depth 31 to 303/depth 3. These are counts
from the actual two constructors, not a benchmark or a uniform asymptotic
speedup. Both still require the same authentic encrypted input words.

The width 4/5 discontinuity is inherited from the divider's public small-table
versus restoring-circuit choice. Product count and depth measure different
costs. The table does not include key preparation, ciphertext widths, memory or
elapsed time, and is not a claim that all listed DAGs admit encrypted execution.

## Rational-pair normalization and cross-cancellation

`rational_pair_reference.py` implements a bounded clear model with signed
numerators, positive denominators, canonical zero `(0,1)`, fixed-round GCD,
normalization and cross-cancelled multiplication. It checks capacities and
refuses zero denominators, mismatched widths, noncanonical direct construction
and overflowing results.

For reduced pairs n/d and m/e, put g=gcd(|n|,e), h=gcd(|m|,d). Their product is

```
((n/g)*(m/h)) / ((d/h)*(e/g)).
```

The result is already reduced. Cancellation can avoid intermediate overflow:
`200/3 * 3/200 = 1` fits the same eight-bit pair budget, whereas naive products
are 600. The pair `(1,2)` has a valid meaning even when a future residue frame
contains a modulus-2 lane; it is not an attempted reciprocal of 2 in that lane.

This reference is **not an encrypted rational API or a residue-native
implementation**. Its scalar inputs serve as the executable specification for
future pair adapters. The actual encrypted GCD boundary and its noise limits
must be addressed before encrypted normalization is claimed.

## Return paths and next discriminating experiments

The first useful imported method is fixed-round oblivious compilation of
Euclid, connected to NINE65's already sealed encrypted words. The second is
bounded direct-function compilation: target-query reasoning avoids paying for
intermediate quotient/remainder states when only the final GCD is consumed.
This does not reduce input information or claim a new truth-table theorem;
it provides a tested alternative architecture and an admission comparison.
Next compare binary-GCD or alternative divider circuits beyond the small-table
cap under identical input histories. The new circuit
cannot be described as constant-cost simply because its underlying
K-Elimination readout may require one modular subtraction and multiplication.

Rational cross-cancellation is immediately useful to a bounded exact reference
layer. A future encrypted adapter needs sign, denominator and division
certificates and a complete noise budget; it must not turn the clear reference
into a runtime oracle.

The separate existing private-feedback test passed in 2.20 seconds after
building the current library. It encrypts two eight-slot inputs under the
unchanged secure_128 configuration, adds their ciphertexts, and asserts every
decrypted slot equals `[141,4,7,6,34,4,0,950]`. These values are the expected
public fixture sums verified by the test, not separately printed raw samples.
It exercises existing encrypted aggregation, not a protected phase/anchor
producer. No refresh gate, security setting or public confidentiality claim is
changed by this work.

## Reproduction

With Rust 1.89.0 and the repository's default features:

```
cargo test -p nine65 --lib division::gcd_tests:: --no-fail-fast -- --nocapture
rustc --edition=2021 -O --test research/swarm-campaign-2026-11-13/runtime-gcd/circuit_costs.rs -o /tmp/gcd-circuit-tests
/tmp/gcd-circuit-tests --nocapture
python3 research/swarm-campaign-2026-11-13/runtime-gcd/rational_pair_reference.py
rustc --edition=2021 research/swarm-campaign-2026-11-13/runtime-gcd/circuit_costs.rs -o /tmp/gcd-circuit-costs
/tmp/gcd-circuit-costs
```

The final `evidence/verification.json` identifies the exact commands, source
hashes, individual successful runs and preserved failed admission experiments.
It distinguishes native ciphertext cases, small-ring ciphertext cases, clear
DAG evaluations, semantic round-bound checks and clear rational arithmetic.
