# Public BFV Phase 1: an exact route to refresh

Status: residue-native public component preprocessing and the encrypted
expanded-phase inner product are implemented and checked against independent
references. Authentic paired encrypted `t/t^2` views and the conditional
subtraction kernel are also implemented. The current four-prime chain admits
these phase views at `P=t^2`. A public canonical low-digit lift baseline is
implemented with complete noise admission and passes encrypted small-ring
checks; its polynomial multiplication bound refuses the current parameters.
Complete production digit removal remains unadmitted. Public refresh entry points
remain fail-closed. The narrower same-prime obligation is described in
[Same-prime bootstrap phase and contraction](PRIME_POWER_BOOTSTRAP_CONTRACTION.md).

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

## Implemented public component preprocessing

[`CanonicalScaleRound`](../crates/nine65/src/arithmetic/canonical_scale_round.rs)
calculates the component switch without reconstructing a ciphertext
coefficient. For canonical `X in [0,Q)`, odd coprime `P` and `Q`, define

```text
Z = P*X + floor(Q/2),
r = Z mod Q,
Y = floor(Z/Q).
```

The main residues of `r` are obtained lane by lane as
`P*x_i + (q_i-1)/2 mod q_i`. The existing `MainOnlyBaseExt` projects this
canonical remainder into a transient modulus `P`, using its certified rank
and bounded exact fallback. No incoming anchor or canonical `X` is required.
Since `P*X = 0 mod P`, the quotient follows from

```text
Y mod P = (floor(Q/2) mod P - r mod P) * Q^(-1) mod P.
```

`Y` lies in `[0,P]`; the possible endpoint `P` maps to zero exactly as required
by the component switch. This also avoids forming the potentially overflowing
numerator `P*X` in production.

[`ExpandedPhase1Plan`](../crates/nine65/src/ops/expanded_phase1.rs) precomputes
this scaler for the first `level` work primes and a checked `P=t^e`. Its
`prepare` method validates both component shapes and canonical residues,
then returns the public polynomials `a_0,a_1`, `P`, and `P/t`. It does not
return a ciphertext or admit a refresh. Main residues alone determine its
output; serialized anchors are neither read nor changed. The encrypted
expanded stage emits a main-only ciphertext under its boot modulus.

The arithmetic backend currently requires odd `P < 2^63`, `gcd(P,Q)=1`, and
an exact rank accumulator that fits 256 bits. Invalid shapes, overflowing
plaintext powers, non-coprime bases, and insufficient capacity are typed
refusals. A chain containing `t` as a main prime is outside this kernel's
domain and is refused.

The focused [`expanded_phase1` integration
target](../crates/nine65/tests/expanded_phase1.rs) checks every production
prime-chain prefix, rounding boundaries and deterministic random inputs against
an independent 512-bit integer quotient reference. It also compares every
coefficient of both components for the four full-size reference messages,
before evaluating the secret-dependent phase and digit removal only as a test
oracle. Run it with:

```sh
cargo test -p nine65 --features allow_insecure --test expanded_phase1
```

## Implemented encrypted expanded phase

[`ExpandedBootstrapKey`](../crates/nine65/src/keys/expanded_bootstrap.rs)
generates an independent boot key pair and encrypts the ternary work secret.
It validates all work-secret main lanes before drawing key-generation
randomness. A secret coefficient `-1` is encoded as `-Delta_P`, rather than
`(P-1)*Delta_P`; the latter would introduce an avoidable encoding-remainder
error. Production key generation uses the OS CSPRNG. Deterministic sampling is
confined to the existing explicit insecure-test feature.

[`ExpandedPhaseEvaluator`](../crates/nine65/src/ops/expanded_bootstrap.rs)
centers the public component polynomials and evaluates
`TrivialEnc_P(a0) + a1*Enc_P(s_work)` using per-prime negacyclic NTT products.
The evaluator accepts no secret key and reconstructs no ciphertext
coefficient. Its input key and output `RNSCiphertext` contain only main lanes
in the persistent Montgomery representation. The separate key-holder result
retains the boot secret for verification and future key switching.

This stage admits a parameter set only after checking its basis capacity,
encoding scale, worst-case decoding headroom, and both in-tree lattice-cost
screens. These screens are not an external security attestation.

For ternary boot secrets and encryption masks and CBD errors bounded by
`eta`, the coefficient error of `Enc_P(0)` is bounded by

```text
beta = eta*(2N+1).
```

Let `r = Q_boot mod P` and `Delta_P = floor(Q_boot/P)`. Centered `a1` has
L1 norm at most `N*(P-1)/2`. Centering `a0+a1*s_work mod P` introduces a
winding bounded conservatively by `N+1`; since `Delta_P*P = Q_boot-r`, this
contributes encoding error. The evaluator requires

```text
beta*N*(P-1)/2 + (N+1)*r + ceil(r/2) < floor(Delta_P/2).
```

At `N=8192`, `eta=3`, `t=65537`, the actual tested certificates are:

| Expanded plaintext | Boot main primes | Phase error bound, bits | Half-Delta, bits | Inner product |
| --- | ---: | ---: | ---: | --- |
| `t^2` | 4 | 60 | 86 | admitted |
| `t^3` | 4 | 76 | 70 | refused |
| `t^3` | 5 | 76 | 97 | admitted |

The four-prime `t^2` plan also passes `ExactMulPlan` construction: its exact
tensor multiply requires 164 bits of auxiliary capacity and selects six
transient lanes supplying 188 bits. The five-prime `t^3` plan requires 207
bits and selects seven lanes supplying 220 bits. These are arithmetic
capacity certificates; they do not certify a complete digit-removal circuit's
noise or depth. Main and auxiliary bases have separate bounded rank
operations; adding their bit lengths is not the backend's capacity test.

The [`expanded_bootstrap` integration
target](../crates/nine65/tests/expanded_bootstrap.rs) decrypts and independently
checks every coefficient of the encrypted work secret and expanded phase for
`0`, `1`, `7`, and `t-1`, including active levels two, three, and four, plus
public addition and multiplication/relinearization cases. Secret keys and
integer reconstruction appear only in the test oracles. The last digit
removal in those tests is still performed in the clear. The test also checks
malformed keys, public components, incompatible regimes, and the entire
Safe-Basis carry window. Run both focused stages with:

```sh
cargo test -p nine65 --features allow_insecure --test expanded_phase1 --test expanded_bootstrap
```

## Same-prime contraction at t squared

For `P=t^2`, expanded winding `Z=w+K_P*t^2` contributes `K_P*t` after division,
which vanishes modulo `t`. General encrypted `K_P` derivation is therefore
unnecessary for this digit-removal target. Shifting by `h=(t-1)/2` gives
`x=(w+h) mod t^2`, `r=x mod t`, and `D(w)=(x-r)/t mod t`.

`PrimePowerPhaseEvaluator` now evaluates authentic encryptions of `x` modulo
`t^2` and `r` modulo `t`, using two encrypted views of the work secret under
one independent boot secret. Its private paired type binds both views to the
same public phase and key family. Full-ring checks cover fresh/evaluated
inputs and the maximum admitted input-error extremes at levels two through
four. The evaluator never obtains a clear low digit or a secret key.

The ordinary low view is not yet a canonical encryption of `r` in the high
encoding. `PrimePowerDigitRemoval` requires that stronger evidence and then
subtracts, emitting an ordinary plaintext-`t` main ciphertext with a certified
sum of errors. The original boundary contraction check supplies the evidence
through a test-only secret-key oracle. The separate public producer uses
native Galois projection and a canonical-section polynomial, and its small-ring
encrypted tests produce the digit without that oracle. A modular-scalar shortcut using the
ordinary low view fails even on one-unit noise; the focused regression pins
down that failure. The
[same-prime contract](PRIME_POWER_BOOTSTRAP_CONTRACTION.md) records the precise
remaining primitive, numerical bounds, and test scope.

The phase evaluator directly produces an additional `Enc_{t^2}(N^-1*x)`
view from preconditioned public components. A Galois trace then recovers
each constant coefficient without post-scaling ciphertext noise: the current
projection bound falls from 92 bits to 73, below its 86-bit half-scale.
The canonical polynomial `F(X)=X+product_{a=0}^{t-1}(X-a) mod t^2` is exact,
but its first multiply needs a 131-bit bound on the four-prime tuple.
The public factory refuses the route before generating keys. The
[canonical-lift baseline](PRIME_POWER_CANONICAL_LIFT_BASELINE.md) gives the
proof, noise terms, resource counts, and encrypted verification boundaries.

## Bounds and starting parameters

For nearest rounding, each public component contributes at most `1/2` to
`rho`. With ternary secret of Hamming weight `h`, the component contribution
has absolute value at most `(h+1)/2` per coefficient. Scaled input noise and
the mismatch between `floor(Q_ell/p)` and `Q_ell/p` must also fit below the
digit-removal margin `p^(e-1)/2`. This condition needs a checked certificate
at every admitted ciphertext level. The plan's `input_noise_budget()` now
calculates the parameter-derived allowance without inspecting the input.
Let `E` bound error from the **centered** work encoding `Delta_t*m`,
`r_t = Q_ell mod t`, and use the conservative secret-weight bound `h=N`.
The required digit margin is

```text
P/Q_ell * (E + r_t*(t-1)/(2t)) + (N+1)/2 < P/(2t).
```

The largest admissible integer `E` is therefore

```text
floor((P*Q_ell - t*Q_ell*(N+1) - P*r_t*(t-1) - 1)/(2*t*P)).
```

All arithmetic for this allowance uses bounded public metadata. It is not
evidence of an arbitrary input's actual noise; admission still needs a
justified operation-history bound. The current tuple has a positive uniform
allowance at levels two through four and refuses level one. Centering an
ordinarily encrypted message above `t/2` adds the `Q_ell mod t` contribution
to its error bound. A small-ring test checks all ternary secrets and centered
messages at both allowed error extremes and component rounding boundaries.

The current `secure_128` work tuple has **four** primes and a 119-bit product;
the retired three-prime prefix has 90 bits. The legacy `ClockworkBootstrap`
constructor adds one boot prime and budgets **two** multiplicative levels.
The expanded evaluator is a separate stage; it does not call that
constructor or its modulus-drop routine. Its admitted four-prime `t^2`
context can use the current work modulus with a fresh boot secret.

For the digit-extraction algorithms in Geelen and Vercauteren, Table 3 gives
`(e-1)*ceil(log2 p)` nonscalar levels for Halevi/Shoup: 17 at `e=2`, or 34
at `e=3`, for `p=65537`, before coefficient/slot transforms. Neither the
four-prime `t^2` inner-product certificate nor the five-prime `t^3` certificate
admits that complete circuit. `e=3` remains a reference precision choice,
not an admitted production refresh setting.

## Four-prime chain and Safe Basis

The bounded winding of the centered expanded phase satisfies
`K in [-(N+1), N+1]`. At `N=8192` this has 16,387 possible values. Shift by
`N+1` to obtain a canonical nonnegative value. The canonical S6 product
`2*3*5*7*11*13 = 30,030` covers this window, and its disjoint composite
repacking `{6,35,143}` preserves exactly the same capacity. The tests project
every carry in this window to S8 and check both source representations.

This establishes representability after carry derivation. It does not derive
an encrypted carry from `Enc_P(w)`. The existing Safe-Basis lifted-transduction
API consumes authentic `K mod b` evidence; it does not supply that evidence
for the secret-dependent BFV inner product. Its small/composite CLASS-R
carriers also do not replace the CLASS-F primes needed by the NTT.

For `t^2 -> t`, the expanded winding cancels modulo `t`, so its derivation need
not lie on the contraction's critical path. Safe Basis remains available for
validation, general lifted transduction, and consumers whose quotient depends
on winding. It does not provide a canonical high-encoding low digit. Any
encrypted implementation must preserve the
[WIRE-Q boundary](NINE65_CURRENT_STATE_AND_WORK_REQUESTS_2026-09-03.md):
no clear secret-dependent carry or additional coprime secret-dependent lane
may be published. Evaluation-local residue scratch or encrypted carry
material must have a concrete derivation and range contract. The
[Safe-Basis execution packet](CRAM_SAFE_BASIS_LIFTED_TRANSDUCTION_EXECUTION.md)
records the existing repacking and authentic-lift obligations.

## Implementation boundaries

1. **Implemented:** an exact, level-aware public residue procedure for `a_i`,
   a parameter-derived input-error allowance, and independent reference
   checks. The existing
   [residue-native bootstrap contract](CRAM_RESIDUE_NATIVE_BOOTSTRAP_SPEC.md)
   forbids materializing a ciphertext coefficient as one integer in production.
2. **Implemented for the inner product:** non-circular bootstrap key material
   for plaintext modulus `P`, centered secret encoding, the encrypted expanded
   phase, and its worst-case error certificate. Typed native Galois keys now
   support coefficient projection for the public canonical-lift baseline.
   They do not establish admission of a complete transform or refresh circuit.
3. Admit an efficient canonical same-prime low-digit lift, or an equivalent
   homomorphic digit-removal primitive, in the expanded plaintext ring.
   Authentic paired `t/t^2` views, a directly preconditioned projection view,
   and the conditional subtraction kernel are implemented. The public
   polynomial producer passes complete encrypted toy checks, but its
   multiplication certificate refuses the current four-prime tuple.
   A public residue quotient over **unencrypted** lanes does not perform
   the encrypted nonlinear operation. Merely reinterpreting `Enc_P(w)` as a
   `p`-plaintext ciphertext leaves `rho` as noise, so it does not refresh a
   near-boundary input.
4. Admit a complete boot chain and ring dimension from an explicit depth,
   noise, key-size, and lattice-security analysis. Start with the current
   four-prime `t^2` candidate, but extend beyond the current eight-prime/256-bit
   limit if the complete circuit's analysis requires it.
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
