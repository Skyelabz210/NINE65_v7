# Public BFV Phase 1: an exact route to refresh

Status: arithmetic reference validated; encrypted digit removal and production
refresh are **not implemented**. Public entry points remain fail-closed.

## The construction to implement

Use the BFV recryption decomposition in Geelen and Vercauteren,
[Bootstrapping for BGV and BFV Revisited](https://eprint.iacr.org/2022/1363.pdf),
Equation 9 and Sections 3 and 6. Let `p = t = 65537`, let `P = p^e`, and let
`Q_ell` be the active work modulus. For each public ciphertext component and
coefficient, calculate

```text
a_i = round(P * c_i / Q_ell) mod P.
```

Generate a bootstrap key that encrypts the ternary work secret under a BFV
plaintext ring modulo `P`. In that ring, evaluate the negacyclic inner product

```text
Enc_P(w) = TrivialEnc_P(a_0) + a_1 * Enc_P(s),
w = a_0 + a_1*s mod P.
```

For a valid input, `w` is `p^(e-1)*m + rho mod P`, where `rho` contains the
component-rounding carry and scaled input noise. The bootstrap must then
evaluate **on the encrypted `w`** the coefficient-wise digit-removal function

```text
D(w) = round(w / p^(e-1)) mod p.
```

The output of `D` is encrypted under a fresh modulus with plaintext modulus
`p`; only then can it be switched back to the work basis. This nonlinear step
is what the existing affine `homomorphic_inner_product` cannot perform.

`expanded_plaintext_phase_recovers_scalar_carry` checks the scalar
counterexample for all ternary secrets. The test-only
`expanded_plaintext_phase_recovers_real_ciphertext` checks a fresh `N=8192`
ciphertext at messages `0`, `1`, `7`, and `p-1`. Both tests use the work secret
only as an oracle; they neither implement encrypted digit removal nor establish
noise refresh.

## Bounds and starting parameters

For nearest rounding, each public component contributes at most `1/2` to
`rho`. With ternary secret of Hamming weight `h`, the component contribution
has absolute value at most `(h+1)/2` per coefficient. Scaled input noise and
the mismatch between `floor(Q_ell/p)` and `Q_ell/p` must also fit below the
digit-removal margin `p^(e-1)/2`. This condition needs a checked certificate
at every admitted ciphertext level; `e=3` is a reference starting point, not
an admitted production setting.

For the current `secure_128` tuple, `Q_work` has 90 bits, `P=p^3` has 49 bits,
and the four-prime `Q_boot` has 119 bits. The current bootstrap constructor
budgets **two** multiplicative levels. The digit extraction procedures in
Geelen and Vercauteren have substantially greater depth; their Table 3 gives
`(e-1)*ceil(log2 p) = 34` nonscalar levels for Halevi/Shoup when `e=3` and
`p=65537`, before the coefficient/slot transforms. This is a capacity
comparison, not a proposed secure parameter set. The existing four-prime
chain and `U256`-bounded sampler cannot be reused without a new parameter and
security analysis.

## Implementation boundaries

1. Replace the test-only scalar reconstruction in the `a_i` calculation with
   an exact, level-aware residue procedure and an independently checked
   reference oracle. Keep main and anchor lanes coherent. The existing
   [residue-native bootstrap contract](CRAM_RESIDUE_NATIVE_BOOTSTRAP_SPEC.md)
   forbids materializing a ciphertext coefficient as one integer in production.
2. Add bootstrap key material for plaintext modulus `P`, including all
   evaluation and automorphism keys needed by coefficient/slot transforms and
   digit removal. Encrypt `-1` using a centered representative and account for
   BFV's nonzero `Q_boot mod P` encoding remainder in the noise proof.
3. Implement and test homomorphic digit removal in the expanded plaintext
   ring. A public residue quotient over **unencrypted** lanes does not perform
   the encrypted nonlinear operation. Merely reinterpreting `Enc_P(w)` as a
   `p`-plaintext ciphertext leaves `rho` as noise, so it does not refresh a
   near-boundary input.
4. Choose a new boot chain and ring dimension from an explicit depth, noise,
   key-size, and lattice-security analysis. Extend arithmetic beyond the
   current eight-prime/256-bit limit if that analysis requires it.
5. Admit public calls only after fresh, added, multiplied, relinearized, and
   boundary-noise ciphertexts decrypt exactly for `0`, `1`, `p-1`, and interior
   messages at every supported level. Check that a refreshed ciphertext has
   enough budget for a subsequent public multiplication.

The alternative in Kim, Seo, and Song,
[Simpler and Faster BFV Bootstrapping for Arbitrary Plaintext Modulus from
CKKS](https://eprint.iacr.org/2024/109.pdf), extracts BFV noise and runs a CKKS
bootstrap. It is attractive for large prime `p`, but NINE65 has no CKKS
bootstrap, and the published construction assumes `p` divides the BFV
ciphertext modulus. The current work prime products do not satisfy that
condition. It is a separate architecture project, not a Phase 1 patch.
