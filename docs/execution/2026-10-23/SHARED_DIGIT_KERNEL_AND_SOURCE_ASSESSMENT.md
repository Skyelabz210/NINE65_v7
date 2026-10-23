# Exact shared digit transforms and completed configured source searches

The subsequent [batched paired lift](BATCHED_PAIRED_LIFT.md) now constructs
native encrypted Z99/Z121 and an invertible integer (U,D) chart for all8192
coefficients together. Its shared-precharge K-elimination residual has a
49-bit direct bound instead of the57-bit separate-view bound. The encrypted
nonlinear chart map and native repeated bootstrap remain open.

The research raw-switch engine now reuses each small-digit transform across
all main ciphertext primes. Every component of the native N16384/eight-prime
switch agrees bit for bit with the previous main-prime implementation.
An isolated three-repetition benchmark measures a median0.347873seconds
instead of0.930115seconds, a2.674x improvement on this machine. The complete
focused harness passes28 tests, including both repeated encrypted return
constructions and the native dense-key/source transform.

The targeted source assessment also now completes all24 configured searches.
The two previously timed-out algebraic searches finish in about16seconds
using an exact, independently checked recurrence. Their161.34-bit cost is
the new minimum over the configured estimates. This resolves the configured
search timeouts, not the outstanding model coverage or joint key assumptions.
Production public refresh remains closed.

## Exact computational auxiliary field

A raw switch sums negacyclic convolutions of small digit polynomials and
canonical ciphertext-key rows. Let L be the sum of per-digit maximum values,
N the ring degree and qmax the largest main prime. Every signed integer
coefficient in either output component has absolute value at most

`B = N * L * (qmax-1)`.

For the native28-row candidate, B is821210941134733312. The implementation
checks `2B < A` before using the auxiliary modulus
`A=2^64-2^32+1=18446744069414584321`. Checked arithmetic refuses an overflowing
bound. A candidate without that guard falls back to the main-prime kernel.
Centered reduction after the inverse transform therefore recovers the exact
integer convolution before reduction into each main ciphertext prime.

The auxiliary field is deterministic arithmetic applied to already public
key ciphertext rows. It does not publish secret samples in another
ciphertext modulus, modify persistent ciphertext lanes, or add a Safe Basis
root. Distinct cache variants prevent accidentally applying a main-prime
inverse transform to an auxiliary-field row. Client raw-row observations
explicitly undo the correct representation.

The code verifies a complete factorization of A-1 and a Lucas order witness
for7, certifying the field and transform roots. The negacyclic transform
uses an explicit psi twist, with inverse scaling included. Hot multiplication
uses the identities `2^64=2^32-1` and `(2^32-1)*2^32=-1 (mod A)`, with u128
intermediates and canonical reductions. Tests compare boundary and random
products with u128 remainder arithmetic, and negacyclic convolution with an
independent signed schoolbook calculation.

Digit transforms fall from28*8=224 to28. Output inverses remain16, so the
total falls from240 to44 transforms per raw switch. Cached key coefficient
word counts are unchanged; a small shared transform plan is added per
degree. Contexts, metadata and this plan are separate from the historical
stored-key word allowance. No full-native peak memory result is claimed.

## Exact completion of the algebraic searches

The pinned [upstream GB estimator](https://github.com/malb/lattice-estimator/blob/f31b86fe490ab11abb4a69efa13007583791e10a/estimator/gb.py)
first expands the rational series

`F(z) = product((1-z^d)^m)/(1-z)^n`

to precision2n, then scans for its first negative coefficient. The previous
stack traces show it spending both300-second deadlines in that full-series
calculation. The replacement evaluation uses `Q F'=P F`, obtained by exact
logarithmic differentiation. For `F=sum f_k z^k`, `Q(0)=1`, the recurrence is

`k*f_k = sum_i (P_(i-1) - (k-i)*Q_i) * f_(k-i)`.

Only nonzero coefficients of the low-degree P and Q are visited, with exact
integer division at every step. Evaluation stops at the same first negative
coefficient as the original full expansion. The degree of regularity,
binomial cost formula, multiplicities, sample model and attack optimizer
are unchanged. A noninteger input falls back to the original implementation.

Before installation, each hosted worker compares complete cost dictionaries
against the original pinned Sage implementation on18 inputs, including
coincident degrees, absent factors, non-default precision and inconclusive
cutoffs. Independent local tests compare with direct truncated binomial
expansion on48 inputs plus the upstream comparison inputs. The native
bounded-error term stops at degree7; each hosted worker reports546 adapter
calls, including its18 original-upstream comparisons.

The [successful targeted run](https://github.com/Skyelabz210/NINE65_v7/actions/runs/39932572679)
at `dc1393edbe2fe94d53125781f4fa0430c833032c` restores22 exact completed
estimates from the previous immutable report and finishes the remaining two.
The result has24 finite estimates, zero timeouts and zero worker errors.
The minimum is161.33894242424722bits in each selected-model column because
the same classical algebraic attack is included in both. Calling the second
column a complete quantum security estimate would be incorrect. Its lattice
cost model is quantum, while complete quantum hybrid coverage remains absent.
This conservative algebraic estimate also allows unlimited samples and
requests approximately2^82.8 samples; no finite-publication strength credit
is taken.

The primary [Hou/Jiang paper](https://eprint.iacr.org/2026/366) separately
describes enhancements exploiting ring structure. That concurrent variant
is not covered by the pinned rotated estimator. Completion of configured
searches does not establish that missing coverage or the joint/KDM security
of source, outer and working evaluation keys.

## Runtime consequence and next execution step

The isolated native kernel measurement is useful evidence about one switch.
It is not full encrypted-bootstrap timing. The current public circuit still
counts444703747 raw switches per refresh. Applying the representative
0.347873-second kernel time uniformly would project about4.9years serially;
that extrapolation is neither a measured execution nor a general lower bound.
It is enough to reject launching this layout as a practical native run on
this machine. Batching clocks controls resident memory but repeats expansion
and does not remove the quadratic online circuit.

The next algorithmic investigation must remove the per-output repetition:
start from the encrypted source polynomial, compute the public weighted
source sum for all coefficients together, and compile the integer-lift chart
map in batches. A structured coefficient/slot transform or another CRAM
chart construction needs its own complete modulus, polynomial-error and key
storage ledger before encrypted native execution. The earlier generic BSGS
transform's N diagonal operations do not count as a completed solution.
No private support shortcut or small-period alias may replace the actual
native source domain. The one S8 root and dependent composite trays remain
the architecture.

The active execution requirements are therefore: obtain a materially smaller
public lift circuit; finish attack-model and joint-key assessment; connect
authenticated key/domain/epoch/history and intact S8/Root211 capabilities;
then execute the complete native refresh, a useful next operation and another
refresh. The new kernel and completed configured source searches are reusable
parts of that work. They do not satisfy those remaining requirements.

All logs, exact source hashes, the completed raw assessment, build provenance
and scope flags are under
`artifacts/execution/2026-10-23/shared-digit-kernel/`. The focused Rust harness
links the unchanged production library with overflow checks and debug
assertions enabled. The five Python suites pass31 tests; together with the
28 Rust tests,59 local checks pass. No package-wide or hosted Rust CI result
is claimed. No lint or formatting CI gate was re-enabled.
