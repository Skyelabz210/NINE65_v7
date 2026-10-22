# R01: separate plaintext residual from outer ciphertext noise

Updated 2026-10-21. **Partial research result; native refresh remains gated.**
This corrects the key-domain conclusion in commit `7a7f203` and historical
`artifacts/execution/2026-10-21/R01-partial/result.json`. Historical artifacts
remain unchanged. Their claim that dense-key re-encryption replaces the
sparse norm in the earlier rounding error was wrong.

## Inner residual: the secret at rounding matters

For odd Q and base plaintext modulus p, let s_in be the secret **when the
components are scaled**, and m the centered message vector. With an
already-established ideal-grid history bound (including floor encoding):

```text
V >= ||p*(c0+c1*s_in)-Q*m||inf modulo pQ,  2V < Q
a_i = round(p^2*c_i/Q)
w = a0+a1*s_in = p*m+rho modulo p^2
H_in >= ||s_in||_1
||rho|| <= floor(p*V/Q + (H_in+1)*(Q-1)/(2Q)).
```

Indeed, rho equals the scaled input error plus `delta0+delta1*s_in`.
The later outer secret does not multiply these rounding residues.
Distribution-wide H_in=N remains valid for dense ternary keys; H_in=32
requires an actual weight-32 key, not a caller assertion.

The pinned upstream
[`perform_noisy_expansion`](https://github.com/FeanorTheElf/fheanor/blob/2ba00539204cc03816dd258b57fad94904f54d41/src/bfv/bootstrap.rs#L463-L487)
switches to the sparse key before component scaling, then evaluates
`a0+a1*Enc_work(s_sparse)`. The encapsulated key encrypts the sparse secret
as a plaintext under the work key. This confirms the distinct key roles;
it does not certify the native construction or its security.

For Q=348959453350711275087786864768188417 and p=65537, the three existing
V fixtures give dense radii 4096,4096,22310 and sparse radii 16,16,18230 **if
the same V were established after switching**. Sparse rounding does not
remove previous input error or justify carrying a pre-switch V unchanged.

## Modulus switch and noisy key switch

V must be established **after any slots-to-coefficients transform**.
For explicit nearest-component switching Q -> q under the dense secret,
then same-q key switching with unscaled phase perturbation bounded by K:

```text
V_ms = floor(q*V/Q + p*(H_dense+1)*(Q-1)/(2Q))
V_sw = V_ms + p*K
require 2*V_sw < q
B_required = floor(p*V_sw/q + (H_sparse+1)*(q-1)/(2q))
require B_required <= B and 2B < p.
```

Thus the dense norm belongs to the earlier modulus switch and the sparse
norm to the p-squared expansion. This models the stated rounding rule,
not every implementation that calls an operation "modswitch".

For per-lane base-2^b gadget switching with coefficient error support eta:

```text
K <= N*eta*(2^b-1)*sum_i ceil(bitlen(q_i-1)/b).
```

Each gadget key encrypts `g_i*2^(b*j)*s_dense` under s_sparse. The source
CRT idempotents g_i multiply key messages, not sampled errors. Digits come
from individual lanes, matching the native hybrid relinearization layout;
no full-coefficient reconstruction is needed. A cross-key implementation
and sparse-key security certificate are still missing.

With native lanes (998244353,985661441), N=8192, eta=3, H_dense=8192,
H_sparse=32, and either of the first two existing V fixtures:

| Digit bits | Total lane digits | Required radius |
| --- | --- | --- |
| 4 | 16 | 16 |
| 8 | 8 | 16 |
| 10 (current native hybrid base) | 6 | 17 |
| 12 | 6 | 19 |
| 14 | 6 | 27 |
| 16 | 4 | 44 |

At 10 bits, K=150847488. The first refused source V for B=17 is
4480644730138606536169473115611: one less gives radius 17; this value gives
radius 18. That is approximately V/Q=0.0000128400153288, much narrower than
ordinary decryption's V/Q<1/2. Refresh must start within that allowance.
The third fixture fails B=32 at every listed base. No live post-transform
lineage or sparse-key security admission is inferred from these numbers.

## Outer ciphertext correctness: a separate inequality

Let P=p^2, Q_b=P*Delta_b+r_b, and the encapsulated key have phase
`k0+k1*s_out = Delta_b*s_in+e_b` modulo Q_b with ||e_b||inf<=beta.
For the exact centered public lifts a0,a1 used in evaluation:

```text
d0=a1*k0+Delta_b*a0; d1=a1*k1
d0+d1*s_out = Delta_b*w+a1*e_b modulo Q_b
W = ||P*(d0+d1*s_out)-Q_b*centered(w,P)||inf modulo P*Q_b
W <= P*||a1||_1*beta + r_b*(||a0||inf+||a1||inf*H_in)
require 2W < Q_b.
```

The outer secret, encryption masks and sampler contribute to beta according
to the actual key constructor. They do not retroactively change inner rho.
Later transforms and polynomial evaluation must propagate outer error too.

## Nonlinear removal and the derivative connection

The existing bounded polynomial satisfies F(r)=r modulo p^2 and F'(r)=0
modulo p on its support. Integer Taylor expansion gives F(r+p*m)=r, hence
w-F(w)=p*m modulo p^2. Interpret that encryption at plaintext modulus p;
do not invert the nonunit p modulo p^2. The shifted native phase uses
`h+F(x-h)`, as described in
[the original construction](../../PUBLIC_FHE_SOLUTION_2026-09-28.md).

This is a concrete p-adic derivative mechanism, not a proved equivalence
with a tropical/ultradiscrete Jacobian. It does not suppress outer evaluation
noise. The intact Safe Basis root and arbitrary sister views are unchanged;
accurate carry representation alone still preserves input residual.

## Tests and the next construction gap

Ten tests in `scripts/test_digit_radius_oracle.py` cover exhaustive toy
bounds, actual noisy per-lane switching, all 16 dense outer sign patterns at
degree 4, outer-noise failure with unchanged rho, and exact first-refusal
boundaries. Zero, negative and maximum supported residuals are explicit.

The secret-free toy polynomial evaluator checks 60 constant-projection
encryptions (51 at p=17/B=1; nine at p=65537/B=17), each followed by a square.
Nonzero residuals must show strict improvement in actual ideal-grid phase
error, not a counter reset. Wide toy moduli and unrelinearized tensors are
used: this is not SIMD transformation, native refresh or repeat refresh.

Under the existing native five-prime coefficient-projection certificate,
the first polynomial multiply needs 131 error bits against 113 half-scale
bits. A shorter domain alone does not change this first multiplication.
This rejects that circuit/certificate, not every possible refresh.

A separate test-only native diagnostic isolates the next stage on the
five-prime SQUARE_BOOT tuple (Q=154 bits, half-Delta=121 bits). For the
support-valid sample m=32769, the traced coefficient is x=2147614722 and
w=x-h=2147581954=32769*65537+1: its centered low digit is 1, while the
hidden high digit is 32769. The full-size trace residual is 56 bits. The
exact tensor for w(w-1) decrypts correctly but already has a 95-bit residual
before relinearization; after relinearization it remains 95 bits, while the
isolated relinearization difference is only 20 bits. Thus the dominant
observed first-product error is in the tensor/scale-round path, not the hybrid
relinearization key. Shifting that same trace ciphertext to low digits
{-17,-1,0,17} preserves the observed 56-bit input-residual size; both
w(w-1) and w^2 decode correctly at each point and each tensor output has a
95-bit residual. An oracle-only carry-removal control subtracts the known
high component 2147581953, leaving plaintext 1 with the same 56-bit input
residual; its square also decodes correctly with a 95-bit residual. In this
sample, hidden-carry magnitude therefore does not explain the first-product
residual increase. The exact test-only winding control now reconstructs the
centered integer lift `A = c0 + c1*s` and centered mod-Q phase `P`, then
extracts `K = (A-P)/Q` coefficientwise. Expanding `A=P+QK` gives
`t*A^2/Q = t*P^2/Q + 2*t*K*P + t*Q*K^2`; the last term vanishes modulo Q,
and the integer `2*t*K*P` commutes with the scale-round. Against the
phase-only tensor result, the predicted `2*t*K*P` term and the observed
original-vs-phase-only phase difference are both 95 bits. The maximum
coefficient magnitude of K is 7 bits; their unexplained difference is only
14 bits, at coefficient 2992. At the actual native degree N=8192, the
deterministic bound is `(N^2+N+2)/2 = 33558529` (26 bits): round the three
tensor components before multiplying by `1`, `s`, and `s^2`, and include the
phase-only rounding. The test checks this magnitude bound at every
coefficient. This corrects the earlier explanation's incorrect N=4096 and
24-bit worst-case bound; the measured 14-bit mismatch is unchanged. This
quantitatively confirms the component-representation winding as the source of
the extra residual for this sample, not the hidden high digit. It remains a
diagnostic only: extracting P/K or constructing `(phase, 0)` uses the secret
and is not a public or secure evaluation path. The measured multiplication
winding is not asserted to be identical to Phase 1's missing `K`. More
specifically, writing `P = Delta*m + e` and `Q = t*Delta + r` gives
`2*t*K*(Delta*m) = 2*K*m*(Q-r) = -2*K*m*r (mod Q)`. For this sample
`m=1`, `|K|<2^7`, and `r<t<2^33`, so the encoded-message part is below
`2^41`; it cannot account for the 95-bit term. The measured 56-bit input
error instead enters through `2*t*K*e`, the noise-times-winding cross term.
That predicts why one product still fits the 121-bit half-Delta, while another
multiply can push the 95-bit error beyond it. A tray that only changes the
residue view cannot remove that term.

The follow-up applies the oracle correction to the actual relinearized
ciphertext, preserving its c1 exactly. It also tests only the encoded-message
part `-2*r*K` as a control. The expected plaintext is constant one throughout.

| Square output treatment | Error after treatment | Next square error | Next square correct |
| --- | ---: | ---: | --- |
| No correction | 95 bits | 140 bits | No |
| Encoded-message winding term only | 95 bits | 140 bits | No |
| Full oracle `2*t*K*P` correction | 57 bits | 96 bits | Yes |

Squaring the 96-bit result once more without a new correction fails at 141
bits, against the same 121-bit half-Delta. Thus the full correction suffices
to recover one additional multiplication in this sample; one cancellation
does not reset all subsequent noise growth. No ciphertext component is
replaced by a clear phase in this follow-up, but computing the subtracted
correction still requires the test oracle's boot secret. The native test
passes with both the correction controls and the original schedule probes.

A test-only control that wraps each tensor component into its centered main-Q
representative before scale-round instead decodes the same square as 0 with a
122-bit residual, so simple tensor wrapping is not a valid replacement under
the current contract. A balanced four-factor
node then decodes 65537 as 64609,
with 139-bit intended residual against 121-bit half-Delta; at the original
point w^2 is correct at 95 bits, but w^4 is wrong at 140 bits. This is one
deterministic native sample and rejects these tested schedules, not all
possible polynomial circuits. Reproduce with
`NINE65_TRACE_NOISE_DIAGNOSTIC=1 cargo test --locked --offline -j1 -p nine65
--lib contraction_with_oracle_lift_refreshes_boundary_input_and_supports_multiply
-- --nocapture`. The added probe is test-only; production admission remains
unchanged. A plausible next target is a public refresh/state transform that
reduces or cancels the `t*K*P`-dependent noise before another multiplication;
the current sister-tray/composite-modulus tests only provide budgeted views and
do not reset this winding.

The next work is a source-bound sparse switch plus post-transform history
and security assessment, and a reduced/certified outer transform/polynomial
schedule (or separately admitted wider backend). R00's full-history proof
and specialist review remain outstanding. No production gate or acceptance
flag changes; the incorrect dense-key substitution is no longer a blocker.

## Public multiplication correction contract (2026-10-21)

Call this ciphertext-specific winding `K_mul` to distinguish it from the
original Phase-1 component-rounding carry. All products below are negacyclic
polynomial products. For centered ciphertext component lifts `C0,C1` under
the boot secret, define

```text
A = C0 + C1*s_boot
P = center_Qboot(A)
K_mul = (A-P)/Qboot
W_square(C) = 2*t*K_mul*P mod Qboot.
```

A public correction producer would need a ciphertext D with
`D.c0 + D.c1*s_boot = W_square(C) + epsilon (mod Qboot)`, bound to that
same input C, boot key, modulus, and operation. Its independent error
certificate must include epsilon and all work needed to produce D. Subtracting
an oracle-manufactured D with epsilon=0 tests this target; it does not supply
the producer or certify its error.

The current encrypted carry runtime cannot be substituted unchanged. Its
`source_q: i128` and `(remainder,winding)` rows describe the source work sum;
the multiplication winding above uses the 154-bit boot modulus and boot
secret. Its precharged selector/noise implementation also requires
`t=8*N+1=65537`. The sister-tray projections encode canonical integer residues
with the BFV Delta scale in that plaintext ring. D instead needs raw phase
residues under `t=65537^2`, without multiplying W_square by Delta. A residue
view modulo 2 or 11 supplies neither this source conversion nor this encoding
conversion. The required full secret-sum circuit and producer error bound
remain outstanding.

The independent `scripts/refresh_carry_bridge.py` now checks this
multiplication-winding identity, exact component-rounding bound, and
cancellation on 9,450 scalar/degree-two integer cases. It also computes a
conservative next-square budget for the constant-one case above. For a
certified input phase error bound E, `||K_mul||_1 <= N^2/2` gives

```text
E_next <= 2*E + ceil(t*N*E^2/Q) + t*N^2*E + N*r
          + (N^2+N+2)/2 + E_switch + 2.
E_switch = eta*N*(2^10-1)*sum_i ceil(bitlen(q_i)/10).
```

For this native tuple, `E_switch=502824960`. Exact integer binary search
checks both sides of the admission boundary: E at most
6245762953937978686 satisfies `E_next < half-Delta`; the next integer does
not. Every E below 2^62 fits this bound, whereas arbitrary 63-bit errors do
not. This is a target for the **total** certified error after correction,
including the producer's own error; a sampled 57-bit residual is not itself
that public certificate.

The same probe rejects a naive encoding adapter. Multiplying an ideal
Delta-scaled unit with just one unit of phase error by `Delta^-1 mod Q`
produces a 152-bit centered error, already above the 121-bit half-Delta.
Modular inversion alone therefore does not turn the existing noisy
Delta-scaled carry views into a suitably bounded raw-phase correction.

### Encrypted-carry encoding isolation

The native diagnostic now supplies the oracle's `K_mul` through two test-only
key-holder encryption fixtures: a raw phase `K_mul + nu`, and an ordinary
BFV phase `Delta*K_mul + nu`. Each uses a fresh full-width uniform mask and
signed CBD error with eta=3. The carry is still secret-derived; encrypting it
does not provide a public producer or establish security for this key-dependent
message. No production evaluator or admission gate changes.

For the raw encoding, unscaled ring multiplication, relinearization, and
public scaling by `2*t` produce

```text
D_raw = W_square(C) + 2*t*nu*P + 2*t*rho (mod Q),
```

where rho is the relinearization phase error. Since `P=Delta+e`, even one
unit of carry error contributes `-2*r + 2*t*e` modulo Q. Small integer
encryption noise is not automatically small enough after this adapter.

For the Delta encoding, the diagnostic also tries the compensated circuit
`D_comp = 2*t*Mul(C,B) - t^2*Mul(B,B)`. Let the centered component lift of
the carry ciphertext be `B_lift=Delta*K_mul+nu+Q*J`, and set
`V=P+r*K_mul-t*nu`. Before component rounding and relinearization,

```text
D_comp - W_square(C)
  = (t/Q)*(P^2-V^2) + 2*t^2*J*V (mod Q).
```

This is an identity of rational scaled lifts; the final ciphertext has the
separately measured integer-rounding and key-switch errors. The compensation
removes the leading floor-scale bias for an ideal carry, but an encrypted
carry introduces its own component winding J. It cannot be omitted from a
public error certificate. The independent integer probe checks both adapter
identities and exact component-rounding bounds on 56,700 scalar/degree-two
cases, including 3,152 with nonzero J.

Measured on the same native constant-one sample (half-Delta=121 bits):

| Carry / adapter | Correction-target error | Corrected product error | Next square |
| --- | ---: | ---: | --- |
| Raw K, zero error, clear oracle control | 0 bits | 57 bits | Correct, 96 bits |
| Raw K, one-unit error, clear control | 89 bits | 89 bits | Wrong, 128 bits |
| Raw K, fresh uniform mask + sampled CBD | 90 bits | 90 bits | Wrong, 135 bits |
| Delta K, zero error, clear oracle control | 82 bits | 82 bits | Wrong, 127 bits |
| Delta K, fresh uniform mask + sampled CBD | 128 bits | 128 bits, already wrong | Skipped |
| Delta K, compensated clear oracle control | 63 bits | 63 bits | Correct, 109 bits |
| Delta K, compensated fresh mask + sampled CBD | 128 bits | 128 bits, already wrong | Skipped |

For the raw encrypted carry, the sampled input error has magnitude at most
eta=3 (2 bits). Its `2*t*nu*P` contribution is 90 bits **before**
relinearization, while the isolated scaled key-switch difference is 53 bits.
The test additionally checks exact componentwise linearity of the noisy
raw-carry adapter relative to its zero-error control. This independently
isolates carry error amplification from relinearization. Follow-up squares
run for every adapter that preserves the intended plaintext; already-wrong
products are not treated as valid next-square inputs.

Thus this sample supplies a useful positive algebraic control for the
compensated Delta adapter, but neither encrypted-carry adapter meets the
required correction precision. In particular, a standard small-error
encryption of the correct carry is insufficient here. The next public
construction must address its **own encoding, winding, and total phase-error
budget**, or reduce the input error before applying this adapter. Producing
the carry value alone, adding another residue view, or improving only the
hybrid relinearization noise does not close the demonstrated gap. These
controls do not rule out other refresh constructions.

Reproduce the complete opt-in native diagnostic and its dependent tests:

```sh
NINE65_TRACE_NOISE_DIAGNOSTIC=1 cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib contraction_with_oracle_lift_refreshes_boundary_input_and_supports_multiply -- --include-ignored --nocapture
python3 scripts/refresh_carry_bridge.py
```

### Matched carry controls and fused relinearization

The follow-up separates two variables that the preceding encrypted-carry
experiment changed together. Starting from the same Delta-scaled encrypted
carry, it constructs a 2x2 diagnostic matrix: clear/masked representation
versus zero/the same sampled CBD error. The phase-only control preserves the
exact error polynomial; the masked zero-error control preserves c1 exactly
and removes only that error. Both transformations require the test oracle.
In particular, a masked zero-error control is **not** a proposed deployable
encryption scheme.

For identical carry phase and error, changing its component representation
from winding J0 to J1 changes the compensated correction by
`2*t^2*(J1-J0)*V` modulo Q, apart from the independently rounded tensor
components. The Python oracle now checks this matched identity on 28,350
cases in addition to the existing 56,700 adapter cases.

The diagnostic also tests an evaluator-side arithmetic improvement. If
`T_CB=Mul_no_relin(C,B)` and `T_BB=Mul_no_relin(B,B)` are the already
scale-rounded degree-two tensors, combine **all three** components as
`T_D=2*t*T_CB-t^2*T_BB` in the main ring, then relinearize T_D once. This
preserves the compensated tensor phase before key switching. It does not
combine unrounded tensors or claim to remove component-rounding error.

Separate relinearizations have noise `2*t*rho_CB-t^2*rho_BB`; the fused
schedule has one ordinary hybrid-switch error rho_D instead. Under the
existing conservative switch bound 502824960, the separate bound is
9276049498846062186173399040 (93 bits), versus 502824960 (29 bits) for the
fused schedule. This improvement does not cancel `2*t^2*J*V`. Both schedules
and their pre-switch phases are tested on every cell of the matched matrix,
with dependent squares only when the intended plaintext remains correct.

Native matched results (same N=8192 input, same mask, same CBD polynomial):

| Carry representation | Carry error | Pre-switch correction-target error | Separate / fused switch error | Corrected product / next square |
| --- | --- | ---: | ---: | --- |
| Clear | Zero | 63 bits | 0 / 0 bits | Correct at 63 bits / correct at 109 bits |
| Clear | Sampled CBD | 63 bits | 0 / 0 bits | Correct at 63 bits / correct at 109 bits |
| Same full-width mask | Zero | 128 bits | 84 / 20 bits | Already wrong at 128 bits / skipped |
| Same full-width mask | Same sampled CBD | 128 bits | 84 / 20 bits | Already wrong at 128 bits / skipped |

The product/next-square outcomes hold for the pre-switch control and both
relinearization schedules. Thus in this sample the compensated adapter
tolerates the isolated small CBD error, but fails with the mask's component
winding even when its phase error is exactly zero. Its failure is already
present before relinearization. This refines, rather than contradicts, the
preceding raw-encoding finding: the **raw** adapter amplifies small carry
noise; the **compensated Delta** adapter is dominated here by its own carry
winding. Neither a lower-noise carry encryption nor fused relinearization
alone closes the latter gap.

The fused schedule is a measured evaluator-side improvement (84 to 20 bits
of switch error), not a public refresh admission. The next construction
must avoid or publicly account for J and certify the remaining rounding and
switching work; removing J with a secret oracle is not that construction.
As an independent sensitivity check, deliberately omitting `2*t^2*J*V`
from the Python model is rejected on the degree-two witness
`C0=C1=(-2,-2), s=(-1,-1), Q=5, t=3`; the unmodified model passes it.

### Second winding and the scale-round placement

The next native ablation reconstructs J from the actual masked/noisy carry B
using its centered integer component lift, independently of the original K.
Set `V_phase=C-t*B`; its phase is `V=P+r*K-t*nu`. The oracle supplies raw J,
and evaluator-side raw ring multiplication produces `H=2*t^2*J*V` modulo Q.
Subtract H from the fused compensated correction, so the square output is

```text
Y_two = Mul(C,C) - 2*t*Mul(C,B) + t^2*Mul(B,B) + H.
```

With exact J this cancels the second winding, but it still combines three
**already rounded** products. Their rounding errors are multiplied by 1,
2*t and t^2. Against a single-round `(V,0)` square oracle, the deterministic
rounding bound is `R*(t+1)^2+1`, where `R=(N^2+N+2)/2`; allow two ordinary
hybrid-switch bounds as well. This bound is 90 bits on the native tuple.
The `(V,0)` control uses the secret; it is not a public implementation.

A positive independent integer control instead forms the **unwrapped**
component polynomials `F0=C0-t*B0`, `F1=C1-t*B1`, squares their tensor, and
scale-rounds only once before adding H. Its integer lift is `V-t*Q*J`, so
the H cancellation leaves the single-round V square modulo Q, up to the
ordinary component-rounding bound R rather than `R*(t+1)^2`. The Python
probe checks the unwrapped rounding bound and exact integer-lift cancellation
on 56,700 cases, plus 113,400 signed one-unit perturbations of J. An error xi
in raw J changes the output by `2*t^2*xi*V`; a second tray is not automatically
accurate enough merely because its error is a small integer.

This single-round arithmetic cannot be obtained by passing `C-t*B` reduced
modulo Q to the existing multiplication API: that discards the required
unwrapped component lifts. A sufficient tensor operand bound is
`(N/2)*(t+1)^2 = 75562475552672386662400` (77 bits); its scale-round shift
multiplier needs 109 bits. The current kernel and plan accept u64 bounds.
Their existing seven-lane transient catalog has 220 bits, below the required
263-bit capacity. A nine-lane candidate, adding two already-catalogued
NTT-compatible moduli, has 283 bits. Eleven exact residue scale-round
boundary cases pass with that candidate. The reverse base-extension rank
fallback would need 286 bits for `(lanes+1)*A`; the existing U256 capacity
guard must also refuse it. Merely widening the bound type or adding lanes
is insufficient: a certified wider rank fallback is required too. These are **temporary arithmetic
lanes**, not extra ciphertext primes; neither the main Q nor its security
screen changes. A native wide-bound single-round evaluator has not yet been
implemented or admitted, and a public, adequately precise J producer remains
a separate requirement. Sampled native residuals also do not replace the
required public input-error certificate.

Native second-layer measurements on the same masked carry:

| Treatment | Intended output error | Product correct | Dependent square |
| --- | ---: | --- | --- |
| Compensated correction, no J cancellation | 128 bits | No | Skipped |
| Exact raw J oracle cancellation | 78 bits | Yes | Wrong, 122 bits |
| Raw J oracle with one-unit error | 121 bits | Yes | Wrong, 153 bits |
| Raw J with fresh mask and sampled CBD error | 122 bits | No | Skipped |
| Single-round `(V,0)` phase oracle | 57 bits | Yes | Correct, 58 bits |

J has a 7-bit maximum coefficient magnitude. After exact J cancellation,
the output differs from the single-round phase reference by 78 bits, within
the independently checked 90-bit rounding-plus-switch bound. This identifies
amplified rounding as the remaining dominant error in this sample. Exact J
alone does not recover another square: 122-bit intended error exceeds the
121-bit half-Delta. One unit of raw J error nearly consumes that margin on
the corrected product itself; the sampled CBD version already changes the
plaintext. Bit lengths alone are not threshold comparisons: the one-unit
case's 121-bit error still lies below the actual 121-bit half-Delta.

The final row is deliberately a clear-phase oracle with c1=0. Its 58-bit
dependent-square result is **not** a demonstration of a public encrypted
single-round evaluator. The positive unwrapped integer identity, native
rounding isolation, and exact capacity requirements now give an explicit
next implementation target: a wide, jointly scale-rounded tensor with the
existing admission checks retained, followed by a certified public
correction producer. Simply adding another noisy raw carry tray fails these
tested precision controls.
