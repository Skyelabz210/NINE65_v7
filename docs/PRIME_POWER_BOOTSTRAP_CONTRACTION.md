# Same-prime bootstrap phase and contraction

Revision: 2026-09-27. The authentic encrypted `t/t^2` phase pair is
implemented. The subtraction kernel is implemented and requires a certified
canonical low-digit lift in the high encoding. A public producer for that
stronger lift is still missing; public refresh remains disabled.

## Which winding can disappear

For `P=t^2`, let `w=Z mod P`, `h=(t-1)/2`, and `x=(w+h) mod P`.
Nearest rounding for odd `t` gives

```text
D(w) = floor((w+h)/t) mod t = floor(x/t).
Z = w + K_P*P  =>  D(Z) = D(w) mod t.
```

The expanded phase's winding `K_P` contributes `K_P*t`, which vanishes
modulo `t`. It need not be recovered on this contraction's critical path.
This does not remove the original BFV component-rounding problem: the
displaced error `rho` in `w=t*m+rho mod t^2` still needs encrypted digit
removal. The original work-modulus carry and the expanded phase's `K_P`
are different quantities.

With `r=x mod t`, the desired quotient is exactly

```text
d = (x-r)/t mod t.
```

This is a same-prime division obligation. A clear shared-factor division
theorem specifies which higher-power residues are needed; it does not by
itself convert a BFV ciphertext's plaintext encoding.

## Authentic paired views

[`PrimePowerPhaseEvaluator`](../crates/nine65/src/ops/prime_power_phase.rs)
uses the existing residue-native `ExpandedPhase1Plan` for the active work
level. It shifts each public `a0` coefficient by `h`, then evaluates

```text
high = Enc_{t^2}((a0+h)+a1*s_work mod t^2)
low  = Enc_t(((a0+h) mod t)+(a1 mod t)*s_work mod t).
```

The additional low-view key encrypts the same ternary work secret under the
same independently generated boot secret and main modulus, using the
plaintext-`t` encoding. The evaluator receives no secret key. It reads no
incoming anchors, constructs no clear secret-dependent digit or winding,
and reconstructs no ciphertext coefficient.

`PrimePowerLiftedPhase` has private fields and no public constructor or
serialization implementation. Its immutable views come from one evaluation
call. A SHA-256 lineage tag binds the prepared public components, source
level, ring and basis to a random boot-key family identifier. The tag is a
provenance check, not a proof about a caller's actual input noise.

The high and low certificates bound their respective errors relative to the
exact `Q/t^2` and `Q/t` grids, including floor-scale and phase-winding error.
On the current four-prime tuple, the high bound is 60 bits against an 86-bit
half-scale, and the low bound is 44 bits against a 102-bit half-scale. These
certify the views, not the missing cross-encoding lift's error or depth.
The work-input allowance is parameter derived; admission of a complete
refresh still needs an authenticated operation-history bound. Level one has
no uniform digit margin and is refused for the current tuple.

## Why an ordinary low-view ciphertext is insufficient

Subtraction requires `Enc_{t^2}(r)` with **canonical** `r in [0,t)`.
An ordinary `Enc_t(r)` has scale `Delta_t`; its decryption phase is only
specified modulo `t`. It is not a ciphertext of the same integer in the
high encoding. Ordinary key switching changes the secret relationship,
not this canonical plaintext-lift contract.
Canonical lifting is not additive: lifting `(t-1)+1=0 mod t` as one value
gives zero, while adding the two canonical lifts gives `t mod t^2`.
The paired views therefore do not yet establish a reduction in the complete
digit-removal circuit's multiplicative depth.

The current four-prime product is

```text
Q         = 348959453350711275087786864768188417
Delta_P   = 81245974683452302344181040
Delta_t   = 5324617442829413538730592867665
Delta_t - t*Delta_P = 49185.
```

The small floor-scale difference does not certify a cross-encoding
conversion. Consider an affine candidate using ordinary floor encodings:

```text
A*(t*Delta_P) = Delta_t mod Q
A*Delta_P + B*Delta_t = 0 mod Q.
```

Both scales are invertible for this tuple. Consequently
`A=Delta_t*(t*Delta_P)^(-1) mod Q` and `B=-t^(-1) mod Q`.
These scalars produce the right ideal noiseless quotient, but amplify
noise through modular inversion. At `x=r=0`, the high phase is zero and a
low phase of one still decrypts to zero. Applying `B` to that harmless
one-unit error decrypts to **1111**. The same failure occurs at `x=r=h`,
the authentic shifted phase for `w=0`, away from a low-digit boundary.
The focused regression checks the noiseless equations and both failures.
Integer division of an error
bound by `t` cannot justify these modular scalar operations.

## The conditional contraction kernel

`CanonicalLowDigitLift` is a separate type whose fields and construction
are private. Its contract requires an encryption of canonical `r` in the
high encoding, tied to the phase's lineage, key family, ring, basis and
certified error bound. There is no production constructor yet. The ordinary
low view cannot be passed to `PrimePowerDigitRemoval::contract` in its place.

Given this stronger evidence, subtraction suffices:

```text
phase(high)  = (Q/t^2)*x + E_H mod Q
phase(digit) = (Q/t^2)*r + E_R mod Q
phase(high-digit) = (Q/t)*d + E_H-E_R mod Q.
```

The kernel subtracts the two main-basis Montgomery ciphertexts and emits an
ordinary `RNSCiphertext` interpreted with plaintext modulus `t`. It performs
no modular inverse, ciphertext multiplication, reconstruction or clear
digit extraction. Its output bound is `|E_H|+|E_R|`, which must be strictly
below `floor(Delta_t/2)`. The public floor-scale difference is reported as
metadata; it is already included in the exact-grid error bounds and must
not be counted twice. Input bounds are checked before addition to prevent
full-width certificate overflow.

The test-only oracle decrypts a phase and encrypts its canonical low digits
to exercise this conditional kernel. That oracle is compiled only under
`cfg(test)` and is **not** a public lift provider, including when
`allow_insecure` is enabled. The checks cover all coefficients for `0`,
`1`, `7`, and `t-1`, malformed lineage/family/residues/bounds, and an input
at its maximum admitted error followed by a public square/relinearization.

## Safe Basis and remaining work

Safe Basis still represents and projects the expanded phase's bounded
winding, serves as a differential validation substrate, and supports
consumers whose result actually depends on winding. It is not required
to derive `K_P` before this particular `t^2 -> t` contraction. The existing
clear `LiftEvidenceProvider` does not supply a homomorphic canonical
low-digit lift.

The next production primitive must convert the authentic low view into
`CanonicalLowDigitLift`, or directly implement an equivalent certified
digit removal. It needs its own noise/depth bound and a concrete evaluation
key relationship. A claim of authentic `t/t^2` provenance alone cannot
replace that primitive. The
[CRAM integration contract](CRAM_INTEGRATION_CONTRACT.md) requires rejection
of shared-factor FHE division until its FPD path is implemented and gated.

Complete refresh also needs actual input-noise admission and the final
output key relationship. Operation-local evidence must respect
[WIRE-Q](NINE65_CURRENT_STATE_AND_WORK_REQUESTS_2026-09-03.md); secret-dependent
coprime or Safe-Basis residues cannot be serialized as auxiliary wire lanes.

Run the focused checks with:

```sh
cargo test -p nine65 --features allow_insecure --test prime_power_phase
cargo test -p nine65 --features allow_insecure --lib contraction_with_oracle_lift
```
