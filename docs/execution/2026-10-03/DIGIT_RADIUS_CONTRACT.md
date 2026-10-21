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

The next work is a source-bound sparse switch plus post-transform history
and security assessment, and a reduced/certified outer transform/polynomial
schedule (or separately admitted wider backend). R00's full-history proof
and specialist review remain outstanding. No production gate or acceptance
flag changes; the incorrect dense-key substitution is no longer a blocker.
