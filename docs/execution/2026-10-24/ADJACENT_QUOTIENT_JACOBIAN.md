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

If one live root emits a clean `Enc_T(J)`, the high correction is only

```text
K = C - p*J mod T.
```

The research example supplies that single view through a key-holder oracle.
It recovers every coefficient, rejects a corrupted root view, and remains
exact after the full `M_pJ=16,390*(p+1)` scale. The measured phase-error size
is 108 bits before scaling and 138 bits after scaling against a 189-bit Q
product. This confirms the correction arithmetic and its sampled noise
margin; it does not implement the root producer or certify a worst-case bound.

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
The missing operation is a live Safe-Basis producer that consumes those
phase-locked residues and emits `Enc_T(J)` with a certified error bound.
Its tray path must preserve the 2/11 Safe-Basis phase lock while allowing the
subsequent composite sister moduli. It must not rely on the key-holder
observer or enumerate all signed J values.

Once that producer is live, join `C-p*Enc_T(J)` to the actual `K_lift`
consumer, then test the work-key return, dependent products, second refresh,
repeat cycle, and admission under production parameters. This probe does not
close those gates.
