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
- A parallel Q-phase sister tree now supplies the missing normalization at
  N=4 and N=8. It uses public candidate Q-phase coordinates and the same
  encrypted pair masks to construct a true `(K,J_q)` root. At coefficient
  zero its C matches the actual quotient ciphertext, its residual is K-J_q,
  and its corrected K is exact. Exact component identities retain the
  correlated-factor noise bound. The full high output is admitted at N=4
  (111/126 bits); N=8 is sampled exact but refused (160/126 bits). The new
  tree retains 81/6,561 candidate rows and adds 81/6,723 selector products.
  It is an exhaustive small-degree producer, with a 10,000-candidate preflight
  cap, rather than a native implementation.

## Gap analysis

The new quotient pair provides a non-enumerative route to the first winding:
same-history p and p+1 residues give J by adjacent K-Elimination, and the
quotient Jacobian D identifies its nearest-integer cell. This replaces the
pair-word search for this lift variable. The raw component lift merely
reproduces `K+pJ`. The inverse-residual formula reduces the missing output to
one same-history, bounded common-T `Enc_T(K-J)` sister view. The same-root
tray control shows how to emit it once the state already contains `(K,J)`:
attach the arbitrary M sister and project the signed affine sheet directly
under T. M-only-to-T raw quotients and adjacent Richardson cancellation fail.
The remaining producer work is scalable construction and certification of `(K,J)`
from the actual CRAM source ciphertext and precharged ternary history, while
preserving the 2/11 lock across coefficients. In particular, the current
live quotient tree's raw component remainder is a different coordinate from
BFV-decoded K, despite its correct winding. The parallel Q-phase tree now
supplies this transition on live N=4/8 histories, but its exhaustive support
and high-scale noise do not support native degree. The terminal test's supplied support
rows are not that construction. The consumer result is one step of the public
refresh, not a completed refresh.

The synced remote branch `research/phase1-carry-transducer` (head
`93d6257`) has a useful 49/2 residue identity for a carry bounded by 48:
`k49=((Y49-w49)*47) mod 49`, `k2=(Y2-w2) mod 2`, and
`K=k49-49*((k49-k2) mod 2)`. Its boundary checks are exact, but the script is
explicitly a clear integer oracle: it does not produce those dense residues
from the same encrypted source history. It is a candidate for the CRAM
composite-tray design, not an encrypted refresh implementation.

## Next steps

1. Replace the parallel Q-phase normalizer's exhaustive ternary-word support
   with a compressed same-history state. First test the smaller p selector
   encoding and its exact composite output-scale relation to isolate the
   current p^2 selector budget cost. Preserve the normalized `(K,J)` relation
   against the actual quotient ciphertext; raw remainders must not be
   substituted for K. Project the bounded `K-J` sheet from the one 2/11 root
   directly under common T through the `p+1` composite sister tray. Preserve
   the unreduced row coefficients and certify `C-r=(p+1)*Enc(J)` in every
   ciphertext component before cancelling the known factor in Q. Bind root
   history, scale, and noise before correction. Do not substitute the
   terminal fixture's supplied support rows for this construction.
2. Test the producer at increasing degrees and both signs, including full
   signed boundaries, every output coefficient, every RNS lane, and
   wrong-history/corrupted-root negatives. Require p² correction and full-T
   admission before joining it to the consumer.
3. Connect the live producer to the actual same-history
   `K_lift mod p` sibling. Remove the clear correction from the medium and
   native consumers and rerun the dependent residual, carry, Phase 1, square,
   next product, and return-to-work-key checks.
4. Bind source key, RNS level, scale tuple, history, ternary-key domain, carry
   bound, and propagated noise into a typed producer certificate. Re-run the
   R00-R03 admission checks, second refresh, and repeat product.

Issue #95 remains open and production refresh remains fail-closed. The linked
scale-Jacobian and ultradiscrete architecture notes contain the derivation and
variable map; this plan records current experimental evidence, not a closure
claim.
