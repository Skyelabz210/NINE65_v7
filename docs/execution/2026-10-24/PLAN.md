# Issue #95 public-refresh execution plan

Date: 2026-10-24. Scope: close the public CRAM refresh gap through the
scale-Jacobian and ultradiscrete lift path. Production Phase 1 remains
fail-closed until the complete acceptance ladder passes.

## Verified state

- The second quotient winding now has a live non-enumerative producer under
  its p view. Exact U512 centered CRT arithmetic proves that `J_q` is the
  Q-wrap of the same p-view carry ciphertext in all 1,024 medium slots. The
  old coarse 99 chart loses that wrap (970/1,024 mismatches); a centered
  component chart retains it (zero mismatches). One encrypted high-key
  precharge then recovers `J_q` in all 2,048 medium and 32,768 native outer
  slots. At native size the virtual clock is 2^24, the two-prime Q is 126
  bits, and the observed p-view error is 117 bits. The doubled N=32,768
  ring uses a new ten-prime NTT-compatible anchor set; both its nominal ring
  and the effective N=16,384 embedded-key dimension pass the in-tree 128-bit
  parameter screen.
- The centered chart can use an even embedding of the original high secret
  on two Q lanes shared with the high ciphertext. Splitting its even
  coefficients returns `J_q` under that original secret with zero mismatches
  at medium (1,024) and native (16,384) size. This avoids a separate key
  switch for the p-view experiment. It does not supply a common-high-T
  ciphertext: the returned medium p-view has 119-bit phase error in Q=126
  bits and its first dependent square fails in 1,024/1,024 slots. The
  embedded-key precharge also needs a reviewed key-dependent-message
  security argument before production use.
- A virtual 99/121 chart clock can exceed the ciphertext ring dimension without
  increasing that ring. With source N=8,192, dense ternary support H=8,192,
  outer N=16,384, and numeric clock 2^21, one encrypted source-key precharge
  yields the exact first Phase 1 carry in all 8,192 even slots, with all odd
  slots zero. No support words are enumerated. The two-prime Q=126-bit outer
  tuple passes the in-tree 128-bit screen. The p-view is *correct* but has
  122-bit observed phase error, so this chart alone is not a refresh or
  noise reset. The same construction passes the dense N=512 control.
- The full-bound pJ tray now uses `A=(p+1)/3=21,846`, retaining factors 2 and
  11. Its modulus `M_pJ=A*(p+1)=1,431,743,148` has centered radius
  715,871,573, above the native certified `pJ` bound 536,944,641. The common
  target `T=p^2*M_pJ=6,149,477,659,801,725,612` fits the existing three
  prime Q=189-bit tuple, which still passes the in-tree 128-bit screen.
  Because `A^-1 mod p=3`, the same-history ciphertext-only p-view recovers
  the high-lift carry in all 1,024 medium and 16,384 native slots with
  observed phase errors of 72 and 73 bits respectively. Both meet the Q/16
  input cap for a follow-up chart.
- The lift's remaining carry is functionally necessary. Leaving it in place
  still decodes the Phase 1 plaintext, but the medium/native phase errors are
  178/180 bits and the first dependent square fails in 1,024/1,024 and
  16,384/16,384 slots. A clear test correction restores the correct high
  residual and gives zero square and cube mismatches at both sizes. This
  isolates high-scale encrypted carry correction, rather than pJ tray width
  or plaintext decoding, as the present blocker.
- The same-history `high_delta` directly supplies the bounded `e+B` composite
  view because `M_pJ` divides the Jacobian step. The pJ tray recovers `pJ`;
  the high K-Elimination lift exposes `M_pJ*K_lift`, and the p view plus
  public `A^-1 mod p` recovers every tested `K_lift mod p` coefficient.
- The componentwise p-to-p² quotient is not a direct lift of `K_lift`: it
  returns `K_lift+p*J_q`. Medium N=1,024 and native N=16,384 preserve all p
  residues and observe `max |J_q|=26/116`, under public bounds 513/8,193.
- A research-only live selector/root test corrects a nonzero `J_q` from the
  same ciphertext's component remainders. At N=4, nine precharged two-trit
  words recover `J_q=1`; the modeled/measured winding errors are 66/65 bits,
  the p-scaled correction bound is 82 bits, and the full-T bound is 112 bits.
  Both correction bounds are admitted and the tested coefficient is exact.
- At N=8, the same balanced pair tree recovers `J_q=1`. It produces 6,549
  support rows and performs 6,723 exact selector products. The p² winding
  bound is 114 bits (96 measured); the p-scaled correction bound is 130 bits
  and admitted. Multiplication by `M_pJ` gives a 160-bit bound, above the
  126-bit high-T radius, so admission refuses it. The secret-holder test
  observes 112-bit error and an exact high-T coefficient, but that sample
  does not override the refused bound.
- The research selector projection model now applies a 16x margin to the
  projected selector error. Native N=16,384 `CarryRuntime` and root preflight
  still initialize. Exact multiplication plans at native degree with 9
  transient auxiliary lanes: 283 available bits for 266 required.
- The medium full-bound consumer test still uses a clear carry correction.
  Its corrected residual, carry, Phase 1, square, and next product pass, but
  the raw ciphertext-only high lift fails broadly. Work-key return, a second
  refresh, and repeat-cycle admission remain unimplemented.
- A new adjacent-quotient probe at N=512, 8,192, and 16,384 recovers the
  first hidden winding `J` with zero coefficient mismatches. The same-history
  p and p+1 views give `C mod p=K`, `C mod (p+1)=K-J`, so the adjacent
  K-Elimination residue `(C mod p)-(C mod (p+1)) mod p` sign-lifts J under
  the public `|J|<=8,193<p/2` bound. The maximum observed `|J|` is 121.
- The quotient-pair residual satisfies `D=J+(K-J)/(p+1)` with a public
  nearest-integer margin of at least 0.249 at native degree. A raw component
  quotient from the p+1 residual tray back to T returns `K+pJ`, not `K-J`;
  the p²+1 divisor control is identical. A single clean high-T `Enc(J)` root
  oracle corrects K at all tested coefficients and survives the full `M_pJ`
  scale with measured 108/138-bit phase error against Q=189 bits. The live
  common-T root producer remains absent.
- The inverse-residual consumer is cleaner: with `T=p*s`, `s=1 mod (p+1)`,
  `u=(T+1)/(p+1)`, a common-T same-history residual `r=K-J` gives
  `J=u*(C-r) mod T` and `K=r+J`. A test-only `Enc_T(r)` root control passes
  N=512, 8,192, and 16,384, including full `M_pJ*K` scaling (116/132/162-bit
  sampled phase error against Q=189). The adjacent p+1 residue itself is
  available with zero mismatch, but converting its M-only ciphertext to
  common T recreates J or fails the noise budget; common-T r production
  remains the gate.
- A same-root tray control narrows that gate: if the Safe-Basis state
  represents `C=K+pJ` as `(remainder=K,winding=J)`, the one 2/11 root can
  project its arbitrary `p+1` sister directly as signed `K-J` under common T.
  At N=32, five precharged support rows cover all four `|K|=|J|=8,193`
  endpoint pairs plus zero. The inverse recovers J, both K forms and the full
  `M_pJ*K` output exactly; modeled eta-based errors fit the Q=189 half-Delta.
  The measured modeled bounds are 17/75/91/121 bits against a 144-bit
  half-Delta, and wrong-root and too-small-bound cases refuse. All six
  `one_root` tests pass, including paired-chart and symbolic Jacobian
  follow-ups. The neighboring pJ control now uses the exact eta bound for its
  direct precharges rather than a post-transform envelope. The rows are still
  supplied by the fixture, so this verifies the terminal tray and consumer,
  not production construction of `(K,J)` from the source.
- The live second-quotient root has now been checked against the actual
  BFV quotient ciphertext. Its winding is correct, but its raw remainder is
  15,773/13,066 at N=4/8 while decoded K is 23. It cannot be identified with
  the `(K,J_q)` state needed by the adjacent consumer. Exact same-selector
  factor cancellation does work in every ciphertext component: unreduced
  `C_raw-r_raw=(p+1)*Enc(J_q)` divides back to the direct winding ciphertext.
  The adjacent composite target `T_adj=p^2*(M_pJ-1)` has a 111-bit admitted
  raw-remainder bound at N=4; N=8 needs 160 bits against radius 126 and
  refuses. Both source-driven tests pass with this mismatch as an explicit
  negative control.
- The live Q-phase normalizer now computes the actual component-quotient
  phase for each candidate secret. Per Q lane it forms
  `q=(c0+c1*s-r0-r1*s)/p`, where `r0,r1` are the public centered residues,
  then rounds `q` at p² to recover `C=K+pJ`. This retains the Q-wrap sheet
  missed by the small residue sum alone: at N=8 coefficient 2 has `J=1`,
  while the raw-residue-only candidate gave zero. The selected `(K,J)` and
  exact Q-lane identities `C-r=(p+1)J` and `C-pJ=K` now pass for every
  coefficient at N=4 and N=8. The support remains exhaustive: 81/6,561 rows
  and 81/6,723 selector products.
- The selector-encoding follow-up confirms the capacity and scale tradeoff.
  Encoding selectors at `p` cuts the N=8 normalized root bounds to 99/98/83/98
  bits for C/r/J/K, and the natural `p*M_pJ` output is admitted at 128/142
  bits. Reusing that ciphertext at the original `p^2*M_pJ` target needs
  144/126 bits and is refused. The `p` context also correctly refuses an
  attached `p+1` tray because `p+1 > t`.
- A just-larger composite selector target removes that tray-capacity failure
  without returning to `p^2` selectors. Use `t_s=65,545` (composite,
  `t_s>p+1`) and `d=268,574,725=4,098*(p+1)+1`, with common target
  `T_s=t_s*d=17,603,730,350,125`. The same root attaches `[p+1,2,11]`;
  `d` is 1 modulo `p+1`, 2, and 11, so those views retain their residues.
  `gcd(T_s,p+1)=1`. The live Q-phase normalizer passes at N=4 and N=8 with
  respectively 81/81 and 6,561/6,723 rows/products. N=4 C/r/J/K bounds are
  94/93/78/93 bits; the K output is admitted at 93/144 bits and the tray view
  at 94/144. N=8 bounds are 127/126/111/126 bits; K is admitted at 126/144
  and the tray view at 127/144. `K`, `J`, residual, tray residue, and exact
  factor cancellation pass for all 4/8 coefficients. This target emits `d*K`,
  not the existing `M_pJ*K`, and still enumerates `3^N` candidate words. It is
  an all-coefficient small-degree source producer and selector/encoding-budget
  result, not a native CRAM implementation.

## Gap analysis

The dense virtual clock removes `3^N` support enumeration for both the first
carry readout and the live second winding's p-view. The second chart even
returns under the original secret on two common Q lanes. The remaining
operation is a low-noise, same-history **common-T signed lift** of `J_q` (or
`K_lift-J_q`) that corrects `M_pJ*K_lift` without introducing another hidden
winding. Raw p-to-T quotients produce `K_lift+p*J_q`; the medium returned
p-view square fails in every slot. A decoded carry is therefore insufficient.
The one 2/11 Safe-Basis root and phase-locked composite sisters remain the
intended representation. Production remains fail-closed.

The adjacent p/(p+1) identity is algebraically non-enumerative once its
phase-locked residue views are available: it determines bounded J by
K-Elimination, and the quotient Jacobian identifies the nearest-integer cell.
The native-degree adjacent probe verifies those residue views with a client
observer. The centered chart now emits a scalable encrypted **p-view** of
`J_q`, but not common-T `Enc_T(J_q)` or `Enc_T(K-J_q)`. The small-degree
Q-phase normalizer emits the complete corrected state from the actual
ciphertext only by enumerating `3^N` candidate secret words. The raw
component lift still reproduces `K+pJ`. The inverse-residual formula reduces
the consumer to one same-history common-T `Enc_T(K-J)` sister view. The
same-root tray control shows how to emit that view after `(K,J)` already
exists: attach the arbitrary M sister and project the signed affine sheet
directly under T. M-only-to-T raw quotients and adjacent Richardson
cancellation fail.

The centered chart proves the Q-wrap `J_q` can be read from the actual live
ciphertext without a ternary support tree. The high-encoding conversion is
the next radix carry operation: attach a phase-locked `p+1` sister to the
single 2/11 root and emit the bounded signed `K_lift-J_q` directly under T.
It must preserve the Q-wrap sheet and signed endpoints, and its state/noise
certificate must precede key generation. The N=4/8 selector normalizer
still enumerates complete secret histories and is not a native solution.

The tuned composite target demonstrates a useful representation choice for
M=`p+1`: the selector plaintext modulus must exceed the largest tray residue,
and the output scale must be phase-aligned with that modulus. The exact
quotient-phase formula and composite tray pass every coefficient at N=4 and
N=8, including nonzero second windings, and keep the tested K correction
inside the N=8 modeled noise radius. The central gaps are the common-T
signed-lift producer, alignment with the actual `M_pJ*K_lift` sibling, and
native endpoint, independent-key, and production-security bounds. No result
closes public refresh.

The synced remote branch `research/phase1-carry-transducer` (head
`93d6257`) has a useful 49/2 residue identity for a carry bounded by 48:
`k49=((Y49-w49)*47) mod 49`, `k2=(Y2-w2) mod 2`, and
`K=k49-49*((k49-k2) mod 2)`. Its boundary checks are exact, but the script is
explicitly a clear integer oracle: it does not produce those dense residues
from the same encrypted source history. It is a candidate for the CRAM
composite-tray design, not an encrypted refresh implementation.

## Next steps

1. Consume the source-bound centered `J_q` chart from the original high key.
   Build the single-root `p+1` sister so it emits signed `K_lift-J_q` directly
   in common T; measure exact factor cancellation and refuse any quotient
   that creates a new winding. Prove the full `M_pJ*K_lift` noise bound and
   test signed endpoint and wrong-history controls.
2. Resolve the embedded-key precharge's key-dependent-message assumption or
   supply a certified independent-key return. Bind source key, RNS level,
   scale, history, support bound, and noise to a typed producer certificate.
3. Replace the clear carry correction in the medium and native pJ consumers;
   rerun plaintext, phase error, square, cube, work-key return, second refresh,
   and repeat-product checks before Issue #95 acceptance and production
   admission.

Issue #95 remains open and production refresh remains fail-closed. The linked
scale-Jacobian and ultradiscrete architecture notes contain the derivation and
variable map; this plan records current experimental evidence, not a closure
claim.
