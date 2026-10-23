# Native nonlinear section at the 11 anchor

The native research path now evaluates a nonlinear 11-adic ring section on
the actual K-eliminated chart residue. The accepted N16384 run checks all
16384 coefficients, including a dense perturbation by11H, and verifies a
Witt quotient of Z99 through two encrypted constructions. The section uses
five exact ciphertext products and one Galois switch, with depth4 and no
coefficient/slot transform.

This is a nonlinear step tied to the CRAM chart, not a complete public
bootstrap. The result is a ring section and a Witt digit. Its semantics
differ from the coefficientwise canonical integer lift required by the
existing return consumer. Canonical K extraction, the plaintext65537 return,
repeated native refresh and production admission remain open.

## The Jacobian is now a contraction in an explicit auxiliary ring

Let `R121=(Z/121Z)[Y]/(Y^N+1)`, with native N16384. Since11 is invertible
modulo2N, the Galois map `sigma11: Y -> Y^11` is invertible. Define

`Phi(x) = sigma_(11^-1)(x^11) mod121`.

For the native degree, the inverse Galois exponent is2979 modulo32768.
Fermat's identity on the coefficients gives `Phi(x)=x mod11`. The binomial
expansion of `(x+11H)^11` has every nonconstant perturbation term divisible
by121, so

```text
Phi(x+11H) = Phi(x) mod121
Phi(Phi(x)) = Phi(x) mod121.
```

The directional derivative is divisible by11. This is a different role from
the determinant1 chart Jacobian: the integer chart preserves information,
while this section removes dependence on the upper11-adic plaintext digit.
Ciphertext error still grows during evaluation; no noise certificate is reset.

The operation acts on a whole ring polynomial. Ring Frobenius modulo11 is
corrected by one inverse Galois permutation, which is why this computation
needs no coefficient projection or coefficient/slot bridge. The corrected
permutation is essential and has its own negative control.

The section is multiplicative, and it selects a ring lift determined by the
lower residue. It is not coefficientwise canonical. For example, in the
eight-coefficient ring, the input `1+Y` maps to the coefficient vector

`[78,78,99,77,33,88,44,22] mod121`,

rather than `[1,1,0,0,0,0,0,0]`. Both reduce to `1+Y mod11`. These extra
cross-coefficient multiples of11 are part of the ring section and cannot be
silently discarded or passed as a `CanonicalLowDigitLift`.

## The auxiliary view is initialized from public source components

The source remains N8192/Q60, plaintext65537, balanced weight96 and source
phase capQ60/64. Public residue preprocessing forms the composite99/121
weights. The same integer expression `D=9*Z99-11*Z121` is evaluated in a
dependent plaintext121 view using a key-holder precharge of the same source
polynomial under the outer key. Its error includes the full precharge error,
the actual public polynomial l1 norm and the constant-encoding remainder.

This view represents D modulo121; it does not claim that D's integer
representative fits in121. The client check independently reconstructs D
from the source components and secret for assertions only, then checks every
coefficient of the encrypted residue. The evaluator receives no secret,
clear digit, measured error, winding or plaintext oracle.

The key holder also supplies a coherent plaintext11 precharge under the same
boot key for the later chart identity. No public conversion from an arbitrary
plaintext65537 ciphertext to121 or11 is asserted. Authenticated family and
history binding of these coherent precharges remains an admission requirement.

## Two exact capacity limits are retained and followed through

The initial small-degree Q241 probe fails construction because its canonical
transient auxiliary pool has220bits and needs259. Its explicitly insecure
N2048 fixture uses Q180 instead. The native degree has the existing315-bit
pool, but the Q241 exact plan selects nine lanes; the base-extension rank
fallback needs287bits and is correctly refused by its U256 capacity check.

The accepted native route forms D at Q241 and publicly drops the last outer
prime under the SAME boot secret before evaluating Phi. The remaining
seven-prime product has211bits. The normal exact plan then uses eight
transient auxiliary lanes and passes the existing rank and scale checks.
The canonical catalog, runtime arithmetic library and capacity gates are
unchanged. These transient lanes are numerical workspaces, not additional
Safe Basis roots or published ciphertext lanes.

The public reduction certificate is

`V_next <= ceil(V/P_special) + ceil(121*(N_outer+1)/2)`.

It lowers the chart-input certificate from39 to20bits in the native run.
Source precharge is separately reduced with its own bound for the later
linear views. Prefix key setup truncates both secret and public-key limbs;
it does not reuse an observer-only zero public key for encryption.

## The encrypted quotient has a proved encoding change

Because `x-Phi(x)` is divisible by11 as a polynomial modulo121, the SAME
ciphertext components of that difference represent

`W(x)=(x-Phi(x))/11 mod11`

under plaintext11, the same Q and the same key. This follows from the ideal
encoding grids: `(Q/121)*(11q)=(Q/11)*q`. The V certificate is
`ceil((V_x+V_Phi)/11)`. The producer proves divisibility algebraically; it
does not reconstruct a private digit to justify the reinterpretation.

Adding11H leaves the section message unchanged and adds H to the quotient
modulo11. The native test checks this with a dense H including odd powers.
Directly interpreting the original x ciphertext under plaintext11 fails the
quotient check, so a change of label cannot replace the nonlinear operation.

## The digit is connected to the actual lift chart

The two-view integer chart obeys `Z99=11U+5D`. Multiplicativity and the
section's invariance give

```text
Phi(Z99) = 5^11 * Phi(D) = 27*Phi(D) mod121
W(Z99) = U + 5*W(D) - 2*D mod11.
```

The test verifies every coefficient by both paths: subtracting the scaled
section from a coherent high121 Z99 view and dividing its proved multiple
of11, and evaluating the displayed formula with independently initialized
low11 U/D views and the encrypted W(D). Those two quotient ciphertexts have
the same plaintext; they are not asserted to have identical random errors.
No extra ciphertext power is needed for this chart compatibility step.

The accepted native results are:

| Quantity | Observed / certified V bits |
| --- | ---: |
| D input after the public outer-prime drop | 14 /20 |
| Phi(D) | 95 /159 |
| W(D), plaintext11 | 92 /155 |
| W(Z99), high121 difference path | 97 /160 |
| W(Z99), low11 chart identity path | 94 /158 |

One public section evaluation takes22.470767seconds in the recorded isolated
native probe. It includes the five exact products and Galois switch, while
setup, view preparation, client observations, the perturbation follow-up
and chart-identity follow-up are separate. The complete native test takes
103.70seconds. These are primitive timings, not public-bootstrap latency.

The public planner refuses another section evaluation from the resulting
159-bit bound before ciphertext work. Plaintext idempotence does not permit
resetting that certificate or treating encrypted reapplication as free.

## Remaining consumer requirement

The fixed-polynomial constraints from the preceding three-view analysis
apply to a coefficientwise LUT over plaintext65537. This construction uses
an explicit auxiliary11-adic encoding and produces a ring-valued section
with cross-coefficient carries. It therefore needs its own consumer proof.

The next step is to connect these coherent Witt digits and the retained
chart winding to the canonical integer K in the required output encoding.
The native test does not recover K, produce a refreshed plaintext65537
ciphertext, or return to the working key. A ring section cannot satisfy the
existing canonical-lift token by renaming it. Joint key security, source
attack-model coverage, authenticated key/domain/epoch/history and intact
S8/Root211 integration also remain open. The production refresh gate stays
closed.

The [scale-locked tray follow-up](SCALE_LOCKED_CARRY_TRAY.md) tests
`T=65537*A` and re-decodes the same phase under plaintext65537. This removes
the extra winding caused by componentwise rational rescaling, but leaves the
source chart residual in the output phase: the native A=5632 bound decodes
once and fails the following dense square after key return. The exact missing
operation remains a public canonical residual producer in the high encoding,
with a proved zero response along the carry direction and a finite-difference
certificate across all admitted sheets.

Implementation and exact evidence are in
`crates/nine65/tests/research/frobenius_chart_section.rs` and
`artifacts/execution/2026-10-23/frobenius-chart-section/`. The Python companion
audits the ring identities and public error plan. The focused harness uses
the unchanged Cargo-built library, with debug assertions and overflow checks.
The complete focused Rust harness passes37 tests, and the seven Python
suites pass46, for83 local unit checks. Initial failed capacity experiments
are retained separately from accepted final checks.
No package-wide build, hosted Rust CI result, new external backend, changed
working modulus or lint run is claimed.
