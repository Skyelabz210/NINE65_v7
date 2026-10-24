# Adjacent quotient Jacobian and the p/(p+1) K-Elimination lift

Date: 2026-10-24. Research only; issue #95 remains open and public refresh
remains fail-closed.

## Quotient pair

Let `p=65,537`, `M=p+1=65,538`, and `T=p^2*M`. Apply exact centered
component quotients to the same `Enc_p(K)` history using divisors `p*M` and
`(p+1)*M`. Write `C` for the first high-T view and `D` for their difference.
The observed plaintext identities are

```text
C = K + p*J
D = J + (K-J)/(p+1)
r = C mod (p+1) = K-J
C mod p = K
```

For `|K|<=8,193` and the public centered component/ternary-key bound
`|J|<=n/2+1`, the residual obeys `|K-J|<=16,386<(p+1)/2`. Therefore `D`
lies strictly inside J's nearest-integer cell. At native degree its minimum
rounding margin is at least 0.249 plaintext units. This obtains the
quotient winding without enumerating ternary support words.

The phase-locked sister views give the adjacent K-Elimination identity

```text
J mod p = (C mod p) - (C mod (p+1)) mod p
        = K - r mod p,
```

because `p+1 == 1 mod p`. Since `|J|<=8,193<p/2`, this residue uniquely
sign-lifts to J. In the experiment, all coefficients of `C mod p`, `D mod p`,
`(C-D) mod p`, and `C mod (p+1)` match their expected values, and the
adjacent residue identity recovers J at both signed endpoints. These are
same-history ciphertext views; their decryption is only the client-side test
observer.

## Lift and correction boundary

The p+1 residual view can be scaled and componentwise divided back toward T,
but that operation does not produce a clean residual. For this tuple, dividing
the p+1 view by `p^2` returns `K+p*J`; its residual from `K-J` is exactly
`(p+1)*J`. The `p^2+1` adjacent-divisor control returns the same result. The
second winding is the original J, not an independently corrected value. This
rules out treating a raw component quotient as a canonical lift.

As a baseline consumer control, if a test supplies a clean `Enc_T(J)`, the
high correction is only

```text
K = C - p*J mod T.
```

The first control supplies that single view through a key-holder oracle. It
recovers every coefficient, rejects a corrupted root view, and remains exact
after the full `M_pJ=16,390*(p+1)` scale. The measured phase-error size is 108
bits before scaling and 138 bits after scaling against a 189-bit Q product.
This confirms the correction arithmetic and its sampled noise margin; it does
not implement the root producer or certify a worst-case bound.

## Inverse-residual K-Elimination

The correction does not need a root-produced `Enc_T(J)` if the one Safe-Basis
root can emit the same-history residual `r=K-J` as a common-T sister view.
Choose a composite output target `T=p*s`, where `s == 1 mod M`. Then
`T == -1 mod M` and

```text
u = (T+1)/M
M*u == 1 mod T
C-r = (K+pJ)-(K-J) = M*J
J = u*(C-r) mod T
K = C-pJ = r+J mod T.
```

This is a linear K-Elimination consumer once the root supplies `Enc_T(r)`.
For the full `M_pJ` downstream scale, the probe chooses
`s=268,574,725=4,098*M+1`, `T=17,601,581,752,325`, and
`u=268,570,627` (29 bits). The plaintext target is just large enough that
`2*M_pJ*8,193<T`; `gcd(T,M)=1`. The residual tray stays the single arbitrary
composite sister `M=p+1`; it does not become another Safe Basis.

At N=512, 8,192, and 16,384, a test-only root oracle supplies `Enc_T(r)` from
the observed same-history `K-J`. The modular inverse recovers every J, the K
correction and `r+J` agree at every coefficient, and the full `M_pJ*K` scale
has zero mismatches. Sampled phase-error sizes are 116, 132, and 162 bits for
J, corrected K, and scaled K against the 189-bit Q product. These are observed
noise results, not a worst-case certificate.

The adjacent scale also exposes an encrypted M-tray view without an oracle:
scaling `Enc_T(C)` by `u` and decoding it under M has zero residue mismatches
at all three degrees. Two attempts to turn that M-encoded ciphertext into
common-T `Enc_T(r)` fail. A raw component quotient by `u` returns C and
reintroduces exactly the first J winding (469/512, 8,033/8,192, and
16,167/16,384 mismatches). Aligning an independently encrypted M view to Q
and dividing by `T*M` has 194–196-bit J error and fails broadly. A two-step
Richardson/K-Elimination combination cancels the ideal fractional term
algebraically, but its noisy quotient views produce 195–197-bit J error and
fail the K/full-scale checks.

## Same-root direct common-T sister tray

The M-only lift failure does not rule out a Safe-Basis tray. If the root's
phase-locked state already represents `C=K+pJ` as remainder/winding `(K,J)`,
then one root can attach `[p,M,T]` and directly project the bounded affine
sheet `K-J` under its common-T encoding. This view is `Enc_T(K-J)` at
emission; it is not an `Enc_M` ciphertext numerically relabelled as `Enc_T`
afterward. The same-root M tray checks the residue identity, while
the T tray supplies C for the inverse-residual consumer.

The focused `one_root_emits_adjacent_residual_at_common_composite_t_and_k_eliminates`
probe uses `N=32`, `p=65,537`, `M=65,538`,
`T=17,601,581,752,325`, and the full `M_pJ` scale. It checks five signed
support cases, including all four `(K,J)` endpoint pairs at `|K|=|J|=8,193`.
The same-root affine projection, modular inverse, both K forms, and full-scale
output decode exactly. The fixture's eta-based noise bounds admit each linear
stage at 17/75/91/121 bits against the 144-bit half-Delta. Wrong-root reuse
and an insufficient residue bound refuse before projection. The full six-test
`one_root` filter passes, including the adjacent-view, paired-chart, and
symbolic scale-Jacobian follow-ups (243.90 seconds).

That follow-up exposed and fixed an unrelated fixture-bound mismatch in the
existing `pJ` projection test: it had assigned the post-transform projected
error envelope to selectors that were direct key-holder precharges. Using
their exact `eta` precharge bound restores a sound projection estimate; the
output remains secret-holder decoded and within the same modeled budget.

This is a terminal-producer integration control, not the live source producer:
the test supplies the possible `(K,J)` support rows and key-holder-precharged
one-hot selectors. It proves that one 2/11 Safe-Basis root and an arbitrary M
sister can feed the common-T consumer. The remaining producer gap is to
derive that phase-locked `(K,J)` state from the actual CRAM ciphertext and
precharged ternary history, then certify the resulting all-coefficient noise
bound. It does not close public refresh.

## Live pair-tree coordinate and exact factor cancellation

The live second-quotient pair tree does not yet supply the `(K,J_q)` state
assumed above. It sums the public centered component residues modulo p with
encrypted output-key pair selectors. Its selected state is
`S_raw=R_raw+p*J_q`. The winding is the correct `J_q`, but `R_raw` differs
from the BFV-decoded K. The same deterministic ciphertexts give:

| Degree | support rows / products | K | raw remainder | raw-minus-K |
|---:|---:|---:|---:|---:|
| 4 | 81 / 81 | 23 | 15,773 | 15,750 |
| 8 | 6,549 / 6,723 | 23 | 13,066 | 13,043 |

The tests independently sum the public component residues with the test
secret, check the root output against that integer sum, and require its
disagreement with the actual BFV quotient ciphertext. Thus directly feeding
this root's `remainder-winding` sheet to the K consumer would correct to the
wrong coordinate. The BFV encoding/phase transition must first be bound to
the same selector history; winding agreement alone is insufficient.

There is an exact budget improvement once two projections share that history.
With **unreduced integer row coefficients**, define
`C_raw=project(R_raw+p*J_q)` and `r_raw=project(R_raw-J_q)`. Then

```text
C_raw-r_raw = (p+1)*project(J_q)
```

holds in every ciphertext component and RNS lane. The tests check this
equality publicly before cancelling `(p+1)` by its inverse modulo each Q
prime. The resulting ciphertext is byte-for-byte equal to the direct winding
projection. Subtracting `p*project(J_q)` is likewise componentwise equal to
the direct raw-remainder projection. The resulting noise bound is that of
the direct projection; treating the inputs as independent and multiplying by
a plaintext modular inverse had needlessly inflated the estimate.

The adjacent high-scale control uses
`S=M_pJ-1=1,074,167,819=79*1481*9181` and
`T_adj=p^2*S=4,613,656,447,419,187,211`, so `T_adj=-1 mod (p+1)`.
At degree 4 the residual/winding/remainder bounds are 81/66/81 bits, and
the high bound/measured error is 111/80 bits within the 126-bit radius.
At degree 8 they are 130/114/130 bits and 160/117 high bits; the high
output is refused by the modeled bound. Both sampled high outputs decode the
raw remainder exactly, and both disagree with the desired BFV value. This
control isolates exact factor cancellation, coordinate normalization, and
remaining support/noise growth; it is not public-bootstrap admission.

Reproduce both degree tests with the `safe_basis_root_projects_second_k_elimination_quotient_winding`
lib-test filter and `allow_insecure,exact_transcendentals_backend`. Both pass.

## Parallel Q-phase sister normalization

A Q-phase coordinate beside the raw component residues fixes the live tree's
wrong-remainder problem. For each candidate ternary secret and coefficient,
let `S=c0+c1*s mod Q` be the original ciphertext phase and
`R=r0+r1*s mod Q` the public centered component residues combined with that
candidate. Exact component division by p gives the quotient phase

```text
q = (S - R) * p^(-1) mod Q
C = round(p^2*q/Q) mod p^2
K = centered(C mod p)
J = centered((C-K)/p mod p)
```

The inverse of p is applied independently in each public Q lane. Rounding the
quotient phase at p² retains the Q-sheet wrap that the small integer `R` sum
alone misses. That was the all-coefficient mismatch: at N=8 coefficient 2
had actual `J=1`, while the raw-residue-only path reported zero. The encrypted
pair selectors still hide which candidate is active; the evaluator processes
public Q residues and candidate labels and does not receive the secret.

For the selected candidate, the normalized state now satisfies `C=K+pJ`
modulo p² and emits residual `r=K-J`. Same-history projections prove
`C-r=(p+1)*Enc(J)` and `C-p*Enc(J)=Enc(K)` in every ciphertext component and
Q lane. An inverse of p+1 in each Q lane cancels the first known factor and
returns the direct J ciphertext exactly. The all-coefficient follow-up checks
the selected K/J, bounded residual tray, both ciphertext identities, and
factor cancellation for every coefficient at N=4 and N=8.

The composite selector branch uses `t_s=65,545`, just above
`M=p+1=65,538`, and output scale `d=268,574,725=4,098*M+1`. The common target
is `T_s=t_s*d=17,603,730,350,125`. Since d is 1 modulo M, 2, and 11, the same
Safe-Basis root attaches `[M,2,11]` and preserves those residues. The p
selector control remains below tray capacity (`M>p`); the composite selector
fits the tray and admits all tested K corrections. Its output is `d*K`, not
the existing `M_pJ*K_lift`, and this remains an exhaustive `3^N` support
search.

| Selector / output | Degree | rows / products | C/r/J/K bounds | K bound / measured / radius | tray bound / measured | all coefficients |
|---|---:|---:|---:|---:|---:|:---:|
| p² / p²M_pJ | 4 | 81 / 81 | 82/81/66/81 | 111/80/126 | — | coefficient 0 |
| p² / p²M_pJ | 8 | 6,561 / 6,723 | 131/130/115/130 | 160/117/126, refused | — | coefficient 0 |
| p / pM_pJ | 4 | 81 / 81 | 66/65/50/65 | 95/47/142 | p+1 refused by capacity | coefficient 0 |
| p / pM_pJ | 8 | 6,561 / 6,723 | 99/98/83/98 | 128/72/142 | p+1 refused by capacity | coefficient 0 |
| 65,545 / T_s | 4 | 81 / 81 | 94/93/78/93 | 93/46/144 | 94/49 | all 4 |
| 65,545 / T_s | 8 | 6,561 / 6,723 | 127/126/111/126 | 126/71/144 | 127/71 | all 8 |

This improves the exact small-degree producer and selector budget, but does
not close public refresh. The candidate state still grows as `3^N`; the
tested ring degrees use `security_bits=0`; signed endpoint, wrong-history,
independent-key, and production-security cases are not covered. Scale d is
not yet joined to the actual `K_lift mod p` sibling, and work-key return,
repeat refresh, and the Issue #95 acceptance ladder remain unimplemented.

## Evidence

`crates/nine65/examples/adjacent_quotient_jacobian.rs` uses three 63-bit RNS
primes, `security_bits=0`, and exact endpoint coefficients `K=+-8,193`.
Results:

| N | `|J|` bound / observed max | adjacent Jacobian mismatches | p/p+1 view mismatches | adjacent K-Elim mismatches | raw p+1-to-T lift mismatches | root-view correction mismatches | scaled K mismatches |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 512 | 257 / 18 | 0/512 | 0/2,048 | 0/512 adjacent K-Elim | 469/512 | 0/512 | 0/512 |
| 8,192 | 4,097 / 89 | 0/8,192 | 0/32,768 | 0/8,192 adjacent K-Elim | 8,033/8,192 | 0/8,192 | 0/8,192 |
| 16,384 | 8,193 / 121 | 0/16,384 | 0/65,536 | 0/16,384 adjacent K-Elim | 16,167/16,384 | 0/16,384 | 0/16,384 |

The public p² scale-wrap cocycle is zero on these deterministic ciphertext
histories at all three degrees, so the raw lift winding is exactly the first J
through every coefficient. This is why the p²+1 quotient agrees with the
p² quotient; it does not create a new winding coordinate.

The raw-lift mismatch is an expected negative control: that path returns C,
not `K-J`. The direct `p*D` correction fails in all coefficients except one
coincidental match at N=16,384. The corrupted-root control fails in every
coefficient. All configurations are unadmitted research fixtures.

Reproduce with:

```sh
cargo run -p nine65 --example adjacent_quotient_jacobian -- 512
cargo run -p nine65 --example adjacent_quotient_jacobian -- 8192
cargo run -p nine65 --example adjacent_quotient_jacobian -- 16384
```

## Remaining producer work

The carry algebra now has a compact input: same-history `K mod p` and
`(K-J) mod (p+1)` yield bounded J through one adjacent K-Elimination step.
The inverse-residual consumer needs the root to emit `Enc_T(K-J)` directly
from the same phase-locked history, with a certified error bound. Its tray
path must preserve the 2/11 Safe-Basis phase lock while allowing the
subsequent composite sister moduli. It must not rely on the key-holder
observer or enumerate all signed J values.

Once that producer is live, join `C-p*Enc_T(J)` to the actual `K_lift`
consumer, then test the work-key return, dependent products, second refresh,
repeat cycle, and admission under production parameters. This probe does not
close those gates.
