# Public lift, polynomial assembly, work-key return and repeat

The research pipeline now executes two dependent refresh/multiply cycles on
an actual encrypted polynomial. This closes the small-context integration
gap left by the single-coefficient phase-clock probes. It does **not**
establish the native public bootstrap goal: production admission remains
false, and the native full-polynomial budget exposes a substantial resource
and noise gap.

Implementation: `crates/nine65/tests/research/public_bootstrap_pipeline.rs`,
a child of the compact-selector integration module. No production API,
refresh gate, S8 root, or external FHE backend is changed.

Later follow-up: [larger outer ring and reduction before the return switch](OUTER_RING_PUBLIC_RETURN.md)
changes that ordering and the outer dimension/modulus. Its conditional native
full-polynomial ledger closes with about1GiB of stored key words; source
security, native execution and production admission remain open. The200GiB
search result below is scoped to this earlier Q149/N8192 construction.

## Residue-only input, without a supplied residual

The input is a real main-Q ciphertext created by public-key encryption and
exact multiplication. Its source period is the existing Q_work119, not a
small chart period. The evaluator receives neither secret key, message,
hidden sheet, centered phase, nor client noise measurement.

For a canonical public ciphertext component C, the existing public rank
projector computes nearest rounding into small targets. The local research
adapter also handles even target T using

```text
floor(Q/2) mod T = ((Q mod (2T))-1)/2,   Q odd.
```

This avoids the inverse of 2 modulo T that the existing odd-target adapter
requires. It preserves the canonical endpoint: a rounded zero is restored to
T when the PUBLIC component is in the upper half. No full canonical wide C
or hidden phase is reconstructed on this path.

With M=2N and odd composite m, compute

```text
A = round(p*C/Q), U = round(M*p*C/Q)
b = round((U-M*A)/m).
```

Odd m gives `round(round(x)/m)=round(x/m)`, so this is the phase clock's
required `round(M*(p*C-Q*A)/(m*Q))`, with no extra double-rounding allowance.
The test compares against a separate wide-integer client calculation at
native-Q endpoints, component-rounding boundaries and random values. Small
Q is also checked exhaustively, including even targets.

The hidden lift is still evaluated by the encrypted composite clock:
`S=Q*K+g`, followed by `A0+A1*s+K mod p`. Negacyclic signs are handled
separately for every output coefficient. Every source selector position,
including encrypted zeros, is processed in a fixed public traversal.

## Full output and actual return

Every coefficient is recovered into a constant ciphertext, rotated into its
output position, and added. These extracted ciphertexts have noise in ALL
coefficients. Assembly therefore charges N times the per-coefficient bound;
treating their errors as disjoint would understate the bound.

For this return experiment the outer tuple is the four existing working
primes plus 1811939329. Q_outer has 149 bits and equals P_special*Q_work
exactly. It replaces the earlier research outer tuple; it does not add a
sixth lane or change the working ciphertext modulus. At native N8192 this
dense outer tuple passes the existing 128-bit parameter screen. That screen
does not certify the sparse source, additional key-dependent material, or
work/boot key cycle.

The key holder precharges a switch from the independent outer secret to the
working secret at Q_outer. After the public key switch, the evaluator drops
the special prime component by component:

```text
r = center_P(C mod P)
round(C/P) mod q_i = (C_i-r)*P^-1 mod q_i.
```

This is residue arithmetic with one small divisor, not a public wide CRT
reconstruction. Both ciphertext components are differentially checked
against independent wide-integer rounding, including endpoints and rounding
boundaries. Truncation is an explicit negative control.

With source norm H and raw return-key bound E_return,

```text
V_return <= ceil((N*V_coefficient + p*E_return)/P)
            + ceil(p*(H+1)/2).
```

The next multiply uses a FULL-POLYNOMIAL envelope. Its message l1 bound is
`N*(p-1)/2`, winding l1 bound `N*(H/2+1)` for even H, and tensor rounding is
charged before combining the terms 1,s,s^2. The probe conservatively uses
H=N for multiplication, even though its working secret has weight2.
Producer bounds, rather than observations, determine whether the next input
can enter the clock window. These remain a research ledger, not the
repository's authenticated production history/capability types.

## Executed dependent tests

The opt-in execution is explicitly insecure N32, p65537, private working
secret weight2 with opposite signs, composite9, packed block8, raw/Galois
radix2bits. The outer key is independent and dense. Its input polynomial is
nonconstant, has every coefficient populated, and exercises negacyclic wrap.

The sequence is public encryption, actual exact square, a public
plaintext-preserving phase load, refresh, return, square, and a second
refresh/return/square using the SAME precharge. All32 coefficients are
checked at each stage against independent schoolbook plaintext convolution.

| Quantity, bits of ideal-grid V | Cycle0 | Cycle1 |
| --- | ---: | ---: |
| Incoming observed V | 110 | 110 |
| Assembled outer observed / bound | 47 / 68 | 47 / 68 |
| Returned observed / bound | 17 / 37 | 16 / 37 |
| Following polynomial product observed / bound | 35 / 63 | 36 / 63 |

The reused key material performs 44,674 raw switches across both cycles.
Removing the carry corrupts22 output coefficients in total. Dropping the
outer modulus without first switching to the work key produces the wrong
polynomial. These checks prevent a constant-message, carry-free, or
same-key shortcut from passing the integration probe.

## Native gap after charging the entire polynomial

`scripts/full_polynomial_bootstrap_budget.py` models the implemented
pipeline, including assembly, the return key, modulus drop and polynomial
multiply. This supersedes using the earlier coefficient/scalar comparison
to infer full-ring repeat closure. Its native source norm32 is still an
UNCERTIFIED assumption, not the default dense source key.

At N8192, composite33, V_source<=Q_work/8, prefix outer Q149:

| Layout | Assembled V bits | Returned V bits | Following product bound bits | Result |
| --- | ---: | ---: | ---: | --- |
| G512, raw/Galois2bits | 122 | 91 | 125 | product decoding bound fails |
| G2048, raw/Galois2bits | 124 | 93 | 127 | product decoding bound fails |
| G1, raw8bits/Galois10bits | 109 | 78 | 112 | conditional arithmetic closure; resource refusal |

The last row is the minimum stored-key candidate in the declared finite
search: raw/Galois radices1..10bits and G powers1..8192. It requires
214,924,001,280 bytes of polynomial words (over200GiB), including its return
key, excluding ordinary keys, metadata and evaluation scratch. Only block
sizes1 or2 pass the conditional arithmetic tests somewhere in this search.
The full polynomial also needs 536,977,409 online raw switches per refresh,
before streamed expansion. No such native key allocation or execution is
attempted. These are refusals of this construction/bound, not impossibility
proofs about CRAM or tropical lifts.

The remaining variables are now separated:

1. Default dense source H8192 still fails the clock window and integer carry
   range. A secure, admitted sparse-source route remains necessary for this
   clock geometry; the test's weight2 is not that route.
2. Packed extraction and multiplication by the dense outer secret amplify
   derived raw-key error. Full coefficient assembly adds another N factor.
   A smaller-memory layout must lower those costs enough to pass the actual
   returned-product bound, not just one coefficient's square.
3. Per-coefficient clocks make full-polynomial online work quadratic in N.
   Passing a noise bound alone cannot establish useful native latency.
4. Sparse-key and joint/circular key security, authenticated key/history
   binding, intact S8/Root211 integration, and a native repeated execution
   remain unproved. None is replaced by the dense parameter screen.

The next construction should be screened against this full-polynomial
closure ledger before allocating native keys. The public bootstrap goal
remains open.

## Reproduction

Run the focused integration harness with `--include-ignored --nocapture`;
the new test filter is `public_bootstrap_pipeline`. All encrypted probes
must include the opt-in tests. Exact compiler flags, unchanged library hash,
executable hash, source manifest and accepted logs are in
`artifacts/execution/2026-10-23/full-polynomial-public-return/`.

`python3 -m unittest discover -s scripts -p 'test_full_polynomial_bootstrap_budget.py' -v`

`python3 scripts/full_polynomial_bootstrap_budget.py`

The focused harness is built directly against the existing Cargo-built
library because the workspace filesystem is at capacity and Cargo also
links unrelated audit binaries. This is not a package-wide Cargo or hosted
CI green claim. Linting is not run; production correctness and security
gates are unchanged.
