# Precharged Safe Basis: encrypted coordinates and the remaining carry map

Date: 2026-10-20. Baseline: `64d76bb7d56cb4acbdf426d159746da189d99a3e`.

The precharge experiment produces encrypted residues of the actual native
residual phase `S=R0+R1*s` using the existing encrypted-inner-product kernel.
It therefore supplies a concrete producer for the proposed residue evidence.
Recovering the carry from that evidence still needs an encrypted operation.

## Construction tested

The key holder precharges `Enc_{m,Q}(s_work)` for each coordinate modulus m,
under one independent boot secret. Each object is an ordinary main-Q
`RNSCiphertext`; m specifies its **plaintext encoding**, not an added RLWE
modulus. Fresh encryptions of zero supply nonzero encryption noise.

For each public input component the evaluator computes

```text
Ri = centered_Q(t*ci)
ri,m = Ri mod m
Enc_{m,Q}(S mod m) = ri0,m + ri1,m * Enc_{m,Q}(s_work).
```

`MainOnlyBaseExt::project_centered` derives the component residues from public
main-Q input. `evaluate_centered_components` evaluates the encrypted
negacyclic product without receiving either secret. Secret access, decryption
and scalar reconstruction occur only in the test oracle and key-holder setup.

The root coordinate moduli are `{2,3,5,7,11,13,17,19}`. The expanded sister
frame uses the same eight independent factors at higher powers:

```text
{2^17, 3^11, 5^8, 7^6, 11^5, 13^5, 17^4, 19^4}
= {131072,177147,390625,117649,161051,371293,83521,130321}.
```

Reducing each coordinate to its root prime preserves all eight roles. These
plaintext moduli do not need NTT roots: all NTT operations still use the
existing four main-Q primes. This follows the higher-power range option in
[the Safe Basis revision](../2026-10-03/SAFE_BASIS_REVISION.md); it does not
claim acceptance of the unresolved S00 owner phase mechanism.

## Capacity and the specific remaining operation

With `N=8192`, the native Q has 119 bits. The full signed S interval requires
132 bits. The exact products have these sizes:

| Coordinate system | Product bits | Covers the full signed S interval? |
| --- | ---: | --- |
| S8 root alone | 24 | No |
| Q together with independent S8 evidence | 142 | Yes |
| Higher-power sister frame | 139 | Yes |

Earlier conversational estimates of 143 and 140 bits rounded the individual
factor widths upward. These are the exact product bit lengths.

The higher-power frame can represent S across **several encrypted plaintext
coordinates**, even though its total range exceeds Q. It does not require a
single plaintext modulus larger than Q to produce those separate coordinates.
Thus the earlier single-wide-plaintext capacity objection does not exclude
this representation. It remains applicable to combining the entire frame
into one ordinary BFV plaintext at the existing Q.

For the joint Q/S8 route the exact bounded identity is

```text
g = centered_Q(S)
K mod P = ((S mod P) - (g mod P)) * inverse(Q,P) mod P
P = 9699690; |K| <= 4096.
```

S8 therefore holds every signed K uniquely. However, producing `g mod P`
requires the centered representative of the **secret sum**. Applying a
component projector before that sum produces S mod P instead, and substituting
it for g would force the calculated carry to zero. The higher-power route
avoids needing a separate g input, but must evaluate `nearest(S/Q)` on its
encrypted CRT coordinates. The clear canonical-rank/transduction functions
cannot accept ciphertexts as if their plaintext residues were public.

The Rust test also checks linear encrypted CRT assembly of the eight root
coordinates into `Enc_{P,Q}(S mod P)`. Under the shared boot secret, multiply
coordinate p by `inverse(P/p,p)` and sum. Its encoding weight is Q/p rather
than Q/P, supplying the missing P/p factor. The exact-grid error bound is
`E_assembly = sum_p inverse(P/p,p)*E_p`, which also clears the P encoding's
half-scale. The test checks decoded results and measured exact-grid errors
against this bound. Its small P range still
aliases different native carries, so this assembly does not complete refresh.

## Bounds and wire interpretation

For coordinate modulus m, use `|a1_i| <= floor(m/2)`, zero-encryption bound
`beta=eta*(2N+1)`, and remainder `r=Q mod m`. A conservative per-coordinate
error certificate is

```text
E_m = beta*N*floor(m/2) + (N+1)*r + ceil(r/2)
E_m < floor(floor(Q/m)/2).
```

The formula includes even coordinate moduli. Centered input sums have magnitude
at most `(N+1)*floor(m/2)`; replacing the sum by its centered m representative
introduces at most N+1 multiples of m. Each contributes at most r because
`floor(Q/m)*m = Q-r`. The remaining half-grid discrepancy is at most ceil(r/2).
For the native eta=3 tuple all sixteen coordinate bounds pass; the higher-power
frame's smallest bit-length difference between half-scale and error is 52.
These are coordinate-production bounds, not a remaining circuit-depth budget
or a certificate for encrypted carry extraction.

The earlier concern about publishing raw coprime secret-dependent RLWE lanes
does not directly apply to this layout: all ciphertext coefficients remain
wrapped modulo the original Q. Safe-Basis information is encrypted plaintext
under the independent boot secret. This satisfies the **format** part of
WIRE-Q without a new auxiliary wire lane. It does not by itself admit a new
production key family, its lifecycle, or the complete refresh circuit. The
test uses deterministic seeds and test-only constructors and is not a
production precharge-key API.

## Evidence and reproduction

```sh
python3 scripts/safe_basis_precharge_probe.py
cargo test --locked --offline -j1 -p nine65 --lib precharged_safe_basis_ -- --nocapture
```

The clear probe checks 11,250 two-coefficient negacyclic residual cases,
22,500 signed coefficient recoveries (5,520 nonzero carries), and 57,347 native
boundary cases spanning all 8,193 possible carry values. Its Q=5 and Q=17
anchor tests use the coprime subset of S8; their higher-power-frame tests keep
all eight factors. Native Q is coprime to the full root. Negative controls
show Q-only aliasing, S8-only aliasing, frame overflow, insufficient shadow-11
capacity, a stale anchor returning a wrong but in-range carry, and the wrong
substitution of component-derived S residues for g residues.

The encrypted test uses a native `encrypt(7)` at N=8192, distinct work and boot
secrets, 16 plaintext encodings, and 16 coefficient positions including both
ends of the negacyclic ring. Direct schoolbook convolution checks 256 decoded
phase coordinates. Another 16 checks exercise encrypted S8 CRT assembly.
All 272 results check exact-grid error bounds; the 128 higher-power outputs
also reduce to the matching root plaintext coordinate.
These sampled encrypted checks complement the exact parameter bound; they are
not exhaustive over encryption randomness or all native ciphertexts.

A second Rust test uses the actual `MainOnlyBaseExt` kernels on clear
higher-power coordinates. It projects the frame into the main-prime phase
residues, projects those into the centered g mod P, and combines with root
S mod P using inverse(Q,P). All 24,579 cases pass, covering every native K
with g in {-1,0,1}. It never forms the 132-bit S scalar or calls the
`to_u256_level` reconstruction helper. The canonical rank calculations
inside the projectors receive **clear residue values**: this test identifies
the exact bridge to implement under encryption, rather than supplying that
encrypted implementation.

The [probe artifact](../../../artifacts/execution/2026-10-19-carry/safe-basis-precharge.json)
binds the test sources, evaluator, projection kernel, configuration source and
Cargo lockfile by SHA-256. The accompanying encrypted-test log records the
separate Rust runs.

The next required implementation is encrypted CRT rank/quotient evaluation
across the precharged coordinates, with its output encoding and complete
error bound. No test here evaluates that carry circuit; public refresh stays
unadmitted.

The [encrypted carry follow-up](SAFE_BASIS_CARRY_TRANSDUCTION.md) now tests
aligned sister-frame carry decoding and a nonlinear local ternary carry gate
at native ring size. The aligned frame retains the input residual; the local
gate removes it only for its one-trit domain. General encrypted-remainder
composition remains required before public refresh can be admitted.
