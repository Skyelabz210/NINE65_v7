# Dense working key, bounded internal source, and public return

The public input transform now connects an ordinary dense N8192 working key
to the bounded source required by the tropical integer-lift clock. It first
reduces Q119 to Q60 under the original working key, then switches to an
independent balanced weight-96 source at Q60. Refresh returns to the original
dense working key at Q119. This closes the conditional arithmetic gap without
replacing dense work encryption or adding a Safe Basis root.

It does not complete or admit native public bootstrap. The earlier
weight-32/Q119 source candidate is rejected by external attack estimates;
the replacement source is still undergoing assessment. Native encrypted
clock execution, practical latency, joint key security and authenticated
root/history integration remain open.

## Key and modulus boundaries

```text
original dense work key, N8192/Q119
  -> two public modulus drops, SAME dense work key
  -> public raw switch to balanced sparse source, N8192/Q60
  -> encrypted tropical lift clock and affine recovery, outer N16384/Q241
  -> modulus drops under SAME dense outer key to Q119
  -> even/odd return switches under ORIGINAL dense work key, N8192/Q119
  -> useful dense polynomial multiplication
  -> the same public input transform and refresh again.
```

The source modulus is exactly `998244353 * 985661441 = 983930967448092673`.
Source-key encryption samples are published only at that modulus. Return-key
samples under the working key are published at Q119, after outer reduction.
The source sampler selects 96 distinct hidden positions, assigning 48 of
each sign in draw order. Assigning signs by sorted support would describe a
different distribution and is deliberately avoided.

The evaluator receives ciphertext components, public bounds and evaluation
keys. It receives neither source support nor measured phase errors. Client
decryption and clock sheets appear only in independent test assertions.
The one Safe Basis S8 and its 2/11 root authority remain the architecture;
the composite-99 coordinate is a dependent view, not a new root.

## Three secret norms serve different purposes

| Step | Bound used | Reason |
| --- | ---: | --- |
| Input modulus rounding | Dense working norm <=8192 | The key has not switched yet. |
| Source raw-switch error | N8192 times gadget digit sum times eta | Sparsity does not reduce the convolution length of independent key errors. |
| Lift-clock window and integer range | Sparse source norm 96 | The key really has switched before component preprocessing. |
| Derived outer-key errors and outer modulus drops | Dense outer norm <=16384 | Outer encryption still uses its own dense key. |
| Returned polynomial multiplication | Dense working norm <=8192 | Return uses the original working key. |

For source cap `V <= Q60/16`, composite99 and outer degree16384, the actual
source-modulus clock width is `W2=13699 < 16384`. Reusing Q119 as that
denominator would understate the width. Merely relabeling the dense source
gives `W2=815203` and still fails; a real switch is essential.

The public integer ledger reports:

| Quantity | Bound |
| --- | ---: |
| Example incoming working V | Q119/20, 114 bits |
| Prepared source V | 49,206,186,694,551,964, 56 bits |
| Allowed prepared source V | 61,495,685,465,505,792 |
| Maximum transformable working V under this public envelope | 21,806,547,521,815,194,107,121,290,421,657,598 |
| Assembled outer V | 143 bits |
| Returned dense working V | 36,220,549,737,939, 46 bits |
| Following dense polynomial square V | 88 bits |
| Following prepared source V | 9,638,771,482,236, 44 bits |
| Added public source-switch key | 1,572,864 bytes |
| Total stored ciphertext/transform polynomial words | 1,073,217,536 bytes |
| Counted raw switches per native refresh | 444,703,747 |

The following product is transformed before comparison with the source cap.
The returned bound is independent of the admitted incoming V; the public
preflight checks the incoming envelope before execution. Every intermediate
modulus level has its own decoding check. These are mathematical bounds and
word counts, not measured full-native memory or timing results.

## Executed encrypted checks

The native input experiment uses an actual ordinary N8192 working secret
with observed ternary norm5448, public encryption of a dense nonconstant
polynomial, an exact polynomial square, and a substantial phase load. The
public modulus drops and source-key switch preserve all8192 coefficients.
Incoming observed V has114 bits; source observed and producer bounds both
have56 bits. An independent client oracle checks every source clock sheet
and lookup identity, observing sheets -11 through10. It does not execute a
native encrypted clock or allocate its precharge.

The complete encrypted integration uses explicitly insecure workN16,
sourceN16 and outerN32, with an ordinary working secret of norm11 and a
weight2 source. It performs two dependent refresh cycles with the same
precharge, returning to the original dense key, then squares the result.
Both cycles preserve every coefficient: incoming V110bits, prepared source
observed/bound51/51bits and returned observed/bound31/37bits. Carry omission
corrupts eight coefficients across the two cycles. Skipping the source
switch fails under the source key. These controls distinguish a genuine
public transform from a change of labels.

The complete focused harness passes25 tests, including the prior lift,
modulus-return, negative and boundary controls. Four public-analysis suites
pass26 tests. The focused harness links the unchanged Cargo-built library,
with debug assertions and overflow checks enabled. No package-wide build,
hosted Rust CI success or production admission is claimed. No lint ran.

## External sparse-source assessment

The targeted [initial assessment](https://github.com/Skyelabz210/NINE65_v7/actions/runs/39925418189)
uses Sage10.6, exact CBD eta3 errors and unlimited samples, with pinned
[upstream lattice-estimator](https://github.com/malb/lattice-estimator/tree/f31b86fe490ab11abb4a69efa13007583791e10a)
and the independent [rotated sparse-key estimator](https://github.com/jdumezy/sparse-key-estimate/tree/aa2c40d4eee4551e6fba06c55d7432f6918e1597).
Its selected classical reduction model is MATZOV; the quantum lattice cost
model is ADPS16. The latter is not complete quantum hybrid coverage.

For the old balanced weight32/Q119 candidate, completed attack estimates
reach98.46 classical bits and79.11 quantum-lattice-model bits. That is enough
to reject it at target128 despite nine other timed-out searches. Earlier
conditional H32 arithmetic evidence remains historical, not a secure option.

For balanced weight96/Q60, the initial run completes14 finite estimates and
times out on ten, with no worker errors. Its completed minima are221.56
classical bits and204.16 quantum-lattice-model bits.
The [follow-up run](https://github.com/Skyelabz210/NINE65_v7/actions/runs/39928978629)
retains the exact14 completed estimates by hash and retries only the ten
incomplete searches with longer deadlines and diagnostic stack traces.
It finishes22 finite estimates, two timeouts and zero errors. The updated
minima are211.74 classical bits and194.90 quantum-lattice-model bits. Both
remaining timeouts are upstream Arora/Gröbner-basis searches, spending their
deadlines in the upstream generating-series coefficient calculation. All
configured lattice, BKW and rotated searches now finish. The workflow fails
closed because the two algebraic searches are incomplete, not because it
observed a sub128-bit cost for this replacement candidate. These partial
minima still do not certify the source. The initial and resumed reports are
retained separately and unchanged under the evidence directory.

Even a finite result from every configured search would cover only those
models: the rotated estimator's concurrent Hou/Jiang2026/366 limitation,
quantum hybrid coverage, and joint/KDM relations among the source, outer and
working keys must still be addressed. The dense outer screen does not imply
sparse-source security or certify that key cycle.

Exact logs, source hashes, build provenance, native public bounds and raw
assessment reports are under
`artifacts/execution/2026-10-23/source-encapsulation/`. The service's refresh
gate stays closed. The next runtime task is to reduce the measured cost of
the raw switch kernel, then obtain actual native encrypted repeated-refresh
evidence with authenticated key, epoch, history and intact-root admission.
