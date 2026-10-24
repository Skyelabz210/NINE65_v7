# Issue #95 public-refresh execution plan

Date: 2026-10-24. Scope: close the public CRAM refresh gap through the
scale-Jacobian and ultradiscrete lift path. Production Phase 1 remains
fail-closed until the complete acceptance ladder passes.

## Verified state

- The same-history `high_delta` directly supplies the bounded `e+B` composite
  view because `M_pJ` divides the Jacobian step. The pJ tray recovers `pJ`;
  the high K-Elimination lift exposes `M_pJ*K_lift`, and the p view plus
  public `A^-1 mod p` recovers every tested `K_lift mod p` coefficient.
- The componentwise p-to-p² quotient is not a direct lift of `K_lift`: it
  returns `K_lift+p*J_q`. The medium N=1,024 experiment preserves all p
  residues and observes `max |J_q|=22` under the public degree bound 513.
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

The adjacent p/(p+1) identity is algebraically non-enumerative once its
phase-locked residue views are available: it determines bounded J by
K-Elimination, and the quotient Jacobian identifies the nearest-integer cell.
The native-degree probe verifies those views with a client-side decryption
observer; it does not emit `Enc(J)` or `Enc(K-J)`. Separately, the live
small-degree Q-phase normalizer emits the corrected state from the actual
ciphertext, but does so by enumerating `3^N` candidate secret words. These are
complementary results, not a scalable encrypted producer. The raw component
lift alone reproduces `K+pJ`. The inverse-residual formula reduces the
consumer to one same-history common-T `Enc_T(K-J)` sister view. The same-root
tray control shows how to emit that view after `(K,J)` already exists: attach
the arbitrary M sister and project the signed affine sheet directly under T.
M-only-to-T raw quotients and adjacent Richardson cancellation fail.

The next producer should start from the actual quotient phase
`q_j=(S_j-R_j)*p^(-1) mod Q`, then realize
`C_j=round(p^2*q_j/Q)=K_j+p*J_j` as a radix carry transducer. Its encrypted
state should retain only the current bounded digit carry and the phase-locked
p and p+1 sister residues. At each digit, combine the three possible ternary
transitions and merge equal states; do not retain complete secret histories.
The transducer must preserve the Q-wrap sheet and signed endpoints, keep the
single 2/11 root, and emit common-T `Enc_T(K-J)` directly. Its state count and
noise must be certified before key generation; if it still grows
exponentially, it is not a solution.

The tuned composite target demonstrates a useful representation choice for
M=`p+1`: the selector plaintext modulus must exceed the largest tray residue,
and the output scale must be phase-aligned with that modulus. The exact
quotient-phase formula and composite tray pass every coefficient at N=4 and
N=8, including nonzero second windings, and keep the tested K correction
inside the N=8 modeled noise radius. The central gaps are the scalable
encrypted producer, alignment with the actual `M_pJ*K_lift` sibling, and
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

1. Preserve the tested `(K,J)` and exact-factor-cancellation invariants while
   replacing the `3^N` support enumeration with a compressed same-history
   producer. Measure support growth before any key generation and refuse if
   the state is not polynomially bounded.
2. Extend the `t_s,d,T_s` branch beyond the all-coefficient N=4/8 checks to
   signed endpoints, wrong-history/corrupted-root negatives, independent keys,
   and production-security parameters. Prove its noise model and choose a
   scale that can be shared with the actual `K_lift mod p` sibling.
3. Connect the live producer to that same-history sibling. Remove the clear
   correction from the medium and native consumers and rerun residual, carry,
   Phase 1, square, next product, return-to-work-key, second-refresh, and
   repeat-product checks.
4. Bind source key, RNS level, scale tuple, history, ternary-key domain, carry
   bound, and propagated noise into a typed producer certificate. Re-run the
   R00-R03 admission checks and complete Issue #95's acceptance ladder.

Issue #95 remains open and production refresh remains fail-closed. The linked
scale-Jacobian and ultradiscrete architecture notes contain the derivation and
variable map; this plan records current experimental evidence, not a closure
claim.
