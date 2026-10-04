# Round I proof packet: contracts to reuse

Source: the owner's supplied **CRAM — Formal Proofs, Round I: Individual
Proofs**, tags T1–T16. This packet makes several intended domains more precise
than the earlier monograph. Mathematical decompositions called “carried” here
do not override the owner's explicit implementation requirement to derive K
on demand. The named historical witness counts are not new test results.

| Tags | Reusable contract | Integration obligation |
|---|---|---|
| T1, T9 | Source CRT ring isomorphism and saturation | Preserve the root; keep S6 witness results distinct from current S8 admission |
| T5 | Extended-Euclid unit inversion works on composites | Repair current Rust prime-only inversion; add mod15015 inverse2=7508 alongside the mod9/mod15 regressions |
| T2, T2b | Bounded K recovery and adjacent subtraction | Same-state coordinates, precise source/anchor split and range; derive K on demand |
| T3, T16 | Projection to any positive target, no target inverse and no full-X reconstruction | Bind the lift to live state; preserve source information while attaching dependent views |
| T4 | Lexicographic `(K,r)` order for nonnegative integers with canonical r | Obtain the correct bounded K and canonical r; do not compare unrelated residue coordinates or charge no cost for acquiring them |
| T6 | Coordinatewise add/mul; exact divisible quotient on unit-divisor lanes | Establish divisibility and unit conditions; use a separate valid shared-factor route |
| T7 | Independent coordinate updates commute | Read a consistent input epoch; respect inter-operation dependencies and measure actual scheduling |
| T8, T8b | Exact finite-group periods and parity alternation | Verify group/domain conditions and distinguish exact discrete motion from approximation of a continuous model |
| T10 | Full source state disambiguates colliding partial views | Keep the full root/needed phase information; a partial sister view is not an independent substitute |
| T11, T11b | Order composition and factor extraction under the stated hypotheses | Requires the prime-power factors/order information as inputs; do not infer an efficient general factoring algorithm from this identity |
| T12 | Affine iteration equals a power plus geometric sum | When a-1 is nonunit, compute the sum by pair doubling to retain logarithmic work; a direct N-term sum is linear |
| T13 | Bounded lifted coordinates agree with natural order | A finite implementation needs a range/extension contract; mathematical unbounded K is not unbounded fixed-memory state |
| T14 | Conditional information loss under a deterministic map; injectivity criterion on its source support | Distinguish loss conditional on output from source secrecy conditional on the actual attacker's view |
| T15, T15b | Modular square-root constructions in the declared finite fields | Enforce primality/residuosity and handle zero; the cube map's fourth iterate on F11 units does not make its output a square root of every nonresidue |

The useful exact ordering and projection results can be applied after querying
a provider for the needed coordinates; storing a scalar K between operations
is unnecessary for their mathematical validity. Conversely, eliminating the
stored scalar does not eliminate the information/range preconditions.

## Shadow entropy: a useful bridge with an explicit observer

T14 concerns `H(input | output)`, which precisely quantifies information lost
by observing only a noninjective projection. For uniform X over `[0,L*M)`,
the decomposition `(r=X mod M, K=floor(X/M))` is bijective, and for an observer
who sees only r, `H(K | r)=log2(L)`. This is a meaningful starting point for
an exact hidden-lift/source argument; it is not necessary to discard it merely
because the transformation is deterministic.

H01 must then establish the actual input distribution and observer. If that
observer also knows X or all inputs that determine it, the derived K is known.
If the actual source is a structured NTT product instead of uniform X, its
conditional distribution must be evaluated under that source model. T14's
injectivity test alone does not certify a new independent RLWE error field or
cryptographic RNG.

## Two precise wording/complexity repairs

T5's operational rule is correct: use an inverse routine justified for the
admitted modulus. Its wording “only when m is prime” is stronger than needed:
some composite moduli/operands also satisfy the Fermat-style exponent identity.
It is not a valid general inverse algorithm for arbitrary composites.

T12's logarithmic algorithm need not divide by a-1 at all. Carry a pair
`P_n=a^n`, `S_n=sum(i=0..n-1,a^i)` modulo m and use

```text
P_2n = P_n * P_n
S_2n = S_n * (1 + P_n)
P_(2n+1) = P_2n * a
S_(2n+1) = S_2n + P_2n
```

This works on composite rings, including nonunit a-1, with logarithmically many
stages. S04 can verify this as a concrete supported operator construction.

There is already a division-free repeated-squaring primitive in
`crates/exact_transcendentals/src/arrow_step.rs:83`; an affine map can be
expressed with a homogeneous matrix. Reuse its applicable contract rather than
inventing a prime-only geometric-sum division. Its current dense matrix
multiplication has cubic work in matrix dimension; that is separate from the
logarithmic dependence on the iteration count.

## Evidence discipline

The current Rust Safe Basis/lifted-transduction integration suites passed
14 tests during this revision. They cover composite repacking, overlapping
views, adjacent recovery, arbitrary targets and the wrapped S6-to-S8 case.
The source-bound probe additionally performed42 projection comparisons and
reproduced the composite-inverse defect. These are recorded current checks.

The Round I counts292,851 /55,742 /275,660 /21,315 and named libcram witness
programs remain historical provenance until matching source and logs are
located. Do not add them to today's totals. Matching a theorem title or test
name is not a proof of identical implementation, parameters or domains.

The exact named witness files were not located in the reviewed checkouts.
`docs/cram-corpus/2026-08-12/RECONCILIATION.md` records that the original cramlab
module/full `NS_FIFTH_OPERATOR_PACKET_v2` workspace is not vendored. Recover
that packet in F03 rather than manufacture logs for its named tests.
