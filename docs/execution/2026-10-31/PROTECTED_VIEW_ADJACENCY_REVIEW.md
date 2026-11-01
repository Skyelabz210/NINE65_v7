# Protected 36/37 views: production versus adjacency consumption

## Implemented restoration query

`PublicRefreshCircuitPlan` now compiles the complete restoration query, with
an explicit `AdjacentLiftRestorationCertificate`. For the certified interval,

```text
Y=K+48, g=Y mod36, a=Y mod37, kappa=(g-a) mod37,
affine + g + 36*kappa - 48 = affine + K = m mod65537.
```

The compiler eliminates the entire remainder round-trip. Runtime consumes the
encrypted K already derived by the source-bound G/H circuit and performs one
addition. It allocates no remainder ciphertexts, shifted-Y ciphertext, or
epoch state. The certificate rejects an aliased 36/37 interval or a signed
interval that is ambiguous in the native field, and charges the sum of the
affine and carry error bounds. Existing source lineage, phase coherence, and
return acceptance checks still surround this operation.

The native plan has **517 error bits before the inverse slot transform and
562 after it, below the 633-bit half-Delta**. Its returned work bound funds
the next square and refresh with residual radius 48, within support 49. Thus
the 667-bit separate sheet-consumer failure below is not a necessary cost of
message restoration. The original encrypted refresh already used direct
`affine+K`; this change makes the query elimination and its capacity/noise
certificate explicit rather than introducing a new bootstrap algorithm.

The new encrypted regression checks all 97 K values against four message
boundaries (388 restorations). All six public circuit tests and the separate
three-cycle encrypted refresh test pass; those executions use small research
fixtures. The native bound is a key-free preflight. The previous full native
execution is not repeated or claimed as new evidence here. The 41 Python
checks and strict library/test Clippy also pass.

This resolves the noise objection for this complete restoration query. An API
that independently returns g, a, or kappa still needs a protected producer;
query fusion does not provide those outputs. CRAM root integration and
joint-key security admission are separate from this algebraic elimination.

## Independent residue queries

The adjacency equation is exact, and compatible encrypted views can be
subtracted cheaply. The proposed replacement does not yet provide the inputs
needed to use it in native public refresh. This review tests the three paths
and implements a cheaper *conditional consumer* as a research prototype.

The relevant native plaintext is `p=65537` and `Y=K+48` lies in **`[0,96]`**.
The 832-bit figure is a lower bound from the current error certificate for
appending a degree-96 field polynomial to the extracted K. It is not measured
blind-rotation noise, and the inspected refresh path has no blind-rotation
LUT interface to replace. The native ciphertext uses the main Q650 worker
primes; 36 and 37 are proposed logical plaintext views, not two of those
ciphertext-modulus limbs. `cram-core` currently has clear `ResidueLane` and
anchor arithmetic, not the proposed `CiphertextLimb::homomorphic_sub` API.

## Path A: valid after compatible views have been produced

If two ciphertexts already encode `g=Y mod36` and `a=Y mod37` **in a common
plaintext ring F_37**, under the same key, scale, and layout, their ordinary
ciphertext subtraction encrypts `(g-a) mod37 = floor(Y/36)`. The encrypted
regression verifies this for all 97 possible Y values. This consumes two
views; it does not generate either view from encrypted Y.

The existing native encoding is F_65537. At `Y=36`, for example, `g=0` and
`a=36`. Native subtraction encrypts `65501`, while the desired sheet is 1.
Changing the modulus written in a helper call does not change the ciphertext
encoding or scale. Nor can a caller subtract unrelated worker limbs: even
equivalent ciphertext representatives modulo Q need not remain equivalent
after reducing their components modulo 37. The exact toy counterexample
`Q=101, t=7, s=1`, ciphertexts `(42,0)` and `(43,100)`, has the same phase
42 and message 3, but component-wise reduction at 37 gives phases 5 and 32.
An encrypted mixed-scale counterexample also uses the same Q and key:
`Enc_t36(20)-Enc_t37(20)`, decoded at t=37, gives 1 although Y=20's sheet
is 0. The scale mismatch alone invalidates that subtraction.

A plaintext-37 coefficient encoding is possible, as used by the small encrypted
test. It is not a drop-in replacement for native slot packing:
`2*32768` does not divide `37-1`, so the current native `SlotEncoding` rejects
that plaintext modulus.

Subtraction has the ideal-grid bound `E_out <= E_g + E_a`. There is no
universal 10–25-bit cost or 600-bit reserve. The known native carry bound has
517 bits; even if both views already had that same bound, the subtraction
would have 518 bits against a 633-bit half-Delta. The missing view-production
cost and any return/consumer operations must still be included.

## A cheaper consumer in the existing native field

For authentic paired views of `Y in [0,96]`, the integer difference d is in
the much smaller set

```text
d = g-a in {-36, -35, 0, 1, 2}.
```

The desired canonical sheets are respectively `1,2,0,1,2`. Over F_65537,
the polynomial

```text
phi(d) = d + d(d-1)(d-2)(12783*d + 19490)
```

has exactly these values. For d=0,1,2 the correction vanishes. For the two
negative inputs, solve
`alpha*d+beta = 37/[d(d-1)(d-2)] mod65537`; this gives the displayed
`alpha=12783, beta=19490`. Factoring it into
`d(d-1)` and `(d-2)(alpha*d+beta)`, followed by their product, uses **three
ciphertext products over two multiplication levels**. No persistent sheet
counter is needed.

The executable prototype in `protected_adjacent_view_tests.rs` evaluates this
consumer on encrypted, client-prepared views for all 97 Y values. It also
checks the native ledger with the explicit hypothesis `E_g,E_a <= E_carry`:

| Stage | Error-bound bit length | Fits native half-Delta? |
| --- | ---: | --- |
| Hypothetical preproduced view, each | 517 | yes |
| Their native-field difference | 518 | yes |
| Degree-4 canonical sheet consumer | 622 | yes |
| Same output through existing slot return | 667 | no |
| Native half-Delta threshold | 633 | threshold |

All comparisons use exact U1024 integers, not just bit lengths. These are
conditional preflight bounds, not an end-to-end protected-view producer.
The five-point precondition is essential: the polynomial is not a generic
modulo-37 map on arbitrary ciphertext values or unbound residue pairs.

## Path B: factorization does not reduce this input domain

The input to each proposed sublookup remains encrypted Y in `[0,96]`.
Exact interpolation gives degree **96** for both `Y mod4` and `Y mod9`,
just as for `Y mod36` and `Y mod37`. The small number of output symbols does
not make these four- or nine-input lookup functions. Consequently the claimed
140–180-bit cost is not established for the existing representation.

The CRT identity is correct modulo 36. It is not an automatically canonical
integer result when evaluated in F_65537. With `Y=2`, the proposed expression
before its final modulo is

```text
9*(2 mod4) + 4*((2*7) mod9) = 18+20 = 38,
38 mod36 = 2,       but 38 mod65537 = 38.
```

Moving that operation to a common plaintext-36 representation, or obtaining
pre-factored protected inputs from a new source producer, would be a separate
encoding/conversion construction. It cannot be inferred from integer CRT.

## Path C: distinguish a relation from an independent witness

For `kappa=(g-a) mod37`, `D=a-g-36*kappa mod37` is zero for every pair g,a.
It cannot validate its own inputs. Even the native interval does not fix
source binding: take g=4 from Y=4 and a=3 from Y=3. The derived kappa=1 gives
zero defect and the numerically valid implied Y=40, although the two supplied
views came from different values.

If the defect reuses the exact ciphertext `kappa=c_g-c_a` in F_37, reducing
`-36` to `+1` makes the entire ciphertext cancel to zero. That zero-noise
result is a tautology. If kappa instead has another valid encryption, a zero
plaintext defect need not have zero error: the encrypted regression adds one
raw phase-error unit to a valid sheet ciphertext and obtains a defect with
plaintext zero and exactly one error unit. General independent inputs incur
their sum/scalar error bounds. Public acceptance of an encrypted zero relation
also needs an admitted verification mechanism, not disclosure of its plaintext.

## Interface and admission consequence

The correct consumer contract requires a producer-bound source identity,
semantic quantity `Y=K+48`, interval, key/context/scale/layout, and input error
bounds. Under a common F_37 encoding, the consumer is subtraction. Under the
current F_65537 encoding, the degree-4 correction above is one conditional
consumer. Neither contract can be constructed merely by assigning the names
36 and 37 to ciphertext worker limbs.

Therefore this change adds checked research consumers and counterexamples,
not a misleading public view-generator wrapper. View production and its full
return/consumption budget remain outstanding for independently returned
remainder/sheet ciphertexts. Native canonical-root preservation is now
[bound to actual producers](CANONICAL_PLAINTEXT_ROOT.md); joint-key security
admission remains separate. A linear arithmetic identity alone does not
establish production admission.

## Reproduction

Run the four tests under
`ops::bounded_digit_circuit::protected_adjacent_view_tests` and
`python3 -m unittest discover -s scripts -p test_public_refresh_lift_refinement.py -v`.
They are included in the research selections of the existing refresh gate
runner. The encrypted fixtures deliberately let the client supply the views;
the evaluator itself only receives ciphertexts. The native check is a key-free
preflight, not a new full native encrypted execution or a security proof.

Validation for this refinement: all four new Rust regressions, all 41 Python
checks in the refresh CI selection, both exact production-boundary tests,
strict library/test Clippy, and formatting checks pass. The production-boundary
tests confirm that unsupported public refresh still fails closed.
