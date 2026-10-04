# Public FHE solution route at plaintext modulus 65537

The route is a wider BFV bootstrap with coefficient/slot transforms and
bounded-error digit removal. The earlier full-domain canonical-lift sweep
rejected that particular circuit on NINE65's current modulus chains; it did
not establish that BFV bootstrapping at 65537 is impossible.

The independent executable in
[`research/bfv-bootstrap-reference`](../research/bfv-bootstrap-reference/README.md)
implements the complete public evaluation sequence through the pinned
Fheanor 0.11.9 reference. Native NINE65 public refresh remains disabled.

## Why this construction is different

1. Move plaintext slots into coefficients before the noisy expansion, then move
   the expanded coefficients into slots. Nonlinear digit removal runs on all
   slots simultaneously. The earlier native baseline instead projects and
   evaluates each coefficient separately.
2. Temporarily switch to a weight-32 sparse secret at a small ciphertext modulus.
   Its bounded coefficient-rounding error permits a short digit polynomial.
   The main key remains uniform ternary. Both key domains and their published
   evaluation-key relationships need a separate security assessment.
3. Evaluate a bounded-error digit polynomial at plaintext modulus `p^2`, then
   contract back to `p`. Use a modulus wide enough for the entire circuit and
   another multiplication/refresh cycle.

The complete flow is implemented in the
[reference BFV bootstrap](https://github.com/FeanorTheElf/fheanor/blob/2ba00539204cc03816dd258b57fad94904f54d41/src/bfv/bootstrap.rs),
following [BFV/BGV bootstrapping](https://eprint.iacr.org/2022/1363) and
[bounded-support digit extraction](https://eprint.iacr.org/2024/115).

For `N <= 32768` with power-of-two `N`, `2N` divides `p-1 = 65536`.
Consequently `X^N+1` splits into distinct linear factors modulo `p`: every
plaintext slot is a base-field slot, and thin bootstrapping covers arbitrary
plaintext polynomials. This argument does not extend unchanged to larger `N`.

## An exact low-degree polynomial

The independent integer script
[`bounded_digit_polynomial.py`](../scripts/bounded_digit_polynomial.py)
constructs the following polynomial for any odd prime `p` and `2B < p`:

```text
G(X) = product over r=-B,...,B of (X-r)
H(r) = 1/G'(r) mod p, with degree(H) <= 2B
F(X) = X - G(X)H(X) mod p^2
```

The distinct roots make every `G'(r)` invertible modulo `p`. Interpolate `H`
over the field, lift its coefficients to integers, and calculate `F` modulo
`p^2`. For every integer `m` and supported `r`, integer Taylor expansion gives

```text
F(r) = r mod p^2
F'(r) = 0 mod p
F(r+p*m) = F(r) + p*m*F'(r) = r mod p^2.
```

The script certifies the two finite sets of exact identities. They imply the
claim for every upper digit; they are not a sampled argument. For `p=65537`
and `B=32`, the polynomial has degree 129 and the certificate covers 4,259,905
residues modulo `p^2`. Independent exhaustive small-prime evaluation checks
9,482 cases and verifies rejection after corrupting a coefficient.

For `B=17`, it has degree 69 and the certificate covers 2,293,795 residues;
the same independent test checks 9,482 cases. This tighter setting also passed
the first repeatable encrypted run below.

To fit the native shifted phase `x=p*m+rho+h`, where `h=(p-1)/2`, use
`h+F(x-h)`. **Provided `|rho| <= B <= h`**, this gives the canonical low digit
in `[0,p)`, so subtracting it permits exact contraction. An ordinary low
encoding cannot replace this polynomial lift.

The radius is an essential hypothesis. It must come from a proved bound on
the actual input operation history, transforms, modulus switching and key
switching. A measured small error or a parameter-only allowance cannot supply
that certificate. The script is a public-constant compiler and identity
checker, not an encrypted evaluator and not an admission gate.

## Functional run evidence

The evaluator harness uses fresh random keys per run. Every successful run
includes a fresh ciphertext, homomorphic addition, two squares before the first
refresh, then each refresh followed by a square and a check of every plaintext
coefficient. The noise budgets in these artifacts are measured diagnostics,
not worst-case certificates.

| Ring, modulus and bound | Result |
| --- | --- |
| `N=1024`, requested chain size 820 bits (`log2 Q ≈ 810`), `B=32`, 3 rounds | Failed on the second refresh. The first round was exact but left 67 measured budget bits after its square. [Run log](../artifacts/bootstrap/public_bfv_reference_n1024_b32_run1_2026-09-28.stderr.log) |
| `N=1024`, requested chain size 820 bits (`log2 Q ≈ 810`), `B=17`, 3 rounds | Passed all three refresh-and-square rounds for all 1024 coefficients; measured post-square budgets were 99, 100 and 100 bits. [Results](../artifacts/bootstrap/public_bfv_reference_n1024_b17_q820_run1_2026-09-28.json), [reproduction metadata](../artifacts/bootstrap/public_bfv_reference_n1024_b17_q820_run1_2026-09-28.run.json) |
| `N=1024`, requested chain size 1000 bits (`log2 Q ≈ 990`), `B=32`, 3 rounds | Passed all three rounds for every coefficient; measured post-square budgets were 190, 190 and 191 bits. [Results](../artifacts/bootstrap/public_bfv_reference_n1024_b32_q1000_run1_2026-09-28.json), [reproduction metadata](../artifacts/bootstrap/public_bfv_reference_n1024_b32_q1000_run1_2026-09-28.run.json) |
| `N=8192`, requested chain size 1000 bits (`log2 Q ≈ 990`), `B=32`, 2 rounds | Passed both refresh-and-square rounds for all 8192 coefficients; measured post-square budgets were 157 and 153 bits. Peak resident memory was 1,220 MiB. [Results](../artifacts/bootstrap/public_bfv_reference_n8192_b32_q1000_run1_2026-09-28.json), [reproduction metadata](../artifacts/bootstrap/public_bfv_reference_n8192_b32_q1000_run1_2026-09-28.run.json) |

These runs demonstrate a repeatable public refresh for arbitrary plaintext
polynomials in the tested reference rings. They do not provide an independent
security estimate or a proof that every random key and ciphertext obeys the
selected error bound. No claim of 100% correctness for unbounded Gaussian
samples follows from finite random trials.

The `N=8192`, `log2(Q)≈990` run is only a correctness demonstration and is far
outside standard BFV security guidance for that ring. The Homomorphic Encryption
Standard [v1.1 security tables](https://homomorphicencryption.org/wp-content/uploads/2024/08/Homomorphic-Encryption-Standard-v1.1.pdf)
give `log2(q)≈202` at `N=8192` for their 128-bit ternary post-quantum estimate.
The standard's sparse-secret section explicitly says it has no
recommendations for sparse keys. Our small-modulus weight-32 encapsulation is
therefore unassessed; the measured refresh success cannot be called secure.

`N=32768`, main uniform-ternary secret, and `log2(Q)≈810` is the next
security-sized evaluation point: the standard's corresponding 128-bit
post-quantum estimate allows about 827 bits for that main-key distribution.
All slots remain degree one at this ring size. This is a candidate for a full
attack estimate and large-memory repeat test, not a claim of 128-bit security;
the temporary sparse-key switch, evaluation-key samples, bounded-error route,
and total cost still require joint review.

## Native implementation work required

| Component | Concrete requirement |
| --- | --- |
| Wider arithmetic | Replace the 256-bit canonical-rank and related 512-bit capacity ceilings with proved fixed-work multi-limb capacity; supply enough NTT primes and transient multiplication residues. Increasing a lane-count constant alone is insufficient. |
| SIMD transforms | Implement and independently verify forward/inverse coefficient/slot transforms with public Galois keys over `p` and `p^2`. |
| Error reduction | Implement main-Q-only sparse encapsulation, or another construction with a proved comparable support bound. Bind keys to each exact ring/modulus domain. |
| Encrypted digit removal | Compile the bounded polynomial into an admitted arithmetic circuit, with a bound for every multiplication and relinearization. Feed its certified canonical result to the existing contraction kernel. |
| Repeatability | Establish a public input certificate and prove that refresh restores enough capacity for another supported multiplication and refresh, including the return to the work-key domain. |
| Security and runtime contract | Assess the exact work/sparse parameters and key cycle independently; preserve bounded integer sampling, fixed-work sensitive arithmetic, and the published main-Q-only wire contract. |

Completion requires all of these at an admitted tuple. An external reference
success does not implement the native integer-only path, prove a failure
probability, or justify removing `public_phase1_soundness_gate`.

## Reproduce the identity certificate

```sh
python3 scripts/bounded_digit_polynomial.py --self-test
```

The checked output is
[`bounded_digit_polynomial_2026-09-28.json`](../artifacts/bootstrap/bounded_digit_polynomial_2026-09-28.json).
The tighter bound used in the successful 820-bit run is checked in
[`bounded_digit_polynomial_b17_2026-09-28.json`](../artifacts/bootstrap/bounded_digit_polynomial_b17_2026-09-28.json).
