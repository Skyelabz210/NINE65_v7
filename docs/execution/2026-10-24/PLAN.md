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

## Gap analysis

The new quotient pair provides a non-enumerative route to the first winding:
same-history p and p+1 residues give J by adjacent K-Elimination, and the
quotient Jacobian D identifies its nearest-integer cell. This replaces the
pair-word search for this lift variable. The raw component lift merely
reproduces `K+pJ`. The inverse-residual formula reduces the missing output to
one same-history, bounded common-T `Enc_T(K-J)` sister view. The remaining
task is a one-root, phase-locked K-Elimination producer for that view, with
the 2/11 Safe-Basis lock and arbitrary composite sister trays. M-only-to-T
raw quotients and adjacent Richardson cancellation both fail; the common-T
tray must be emitted from the same root/history with a certified noise bound.
The oracle correction is evidence for the consumer equation, not a public
refresh.

The synced remote branch `research/phase1-carry-transducer` (head
`93d6257`) has a useful 49/2 residue identity for a carry bounded by 48:
`k49=((Y49-w49)*47) mod 49`, `k2=(Y2-w2) mod 2`, and
`K=k49-49*((k49-k2) mod 2)`. Its boundary checks are exact, but the script is
explicitly a clear integer oracle: it does not produce those dense residues
from the same encrypted source history. It is a candidate for the CRAM
composite-tray design, not an encrypted refresh implementation.

## Next steps

1. Implement the one-root adjacent K-Elimination producer for the
   same-history `(K-J) mod (p+1)` residual. Use the 2/11 Safe-Basis phase lock
   and composite sister trays to emit common-T `Enc_T(K-J)` without
   enumerating all signed J values. Apply `J=(T+1)/(p+1)*(C-r) mod T`, then
   certify root history, scale, and noise before correction.
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
