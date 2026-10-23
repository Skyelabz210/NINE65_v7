# Scale-locked carry tray: exact decode, no reset

This follow-up tests whether one composite tray can avoid the hidden winding
from the 120-to-121 component scale conversion. It finds an exact same-phase
re-decode identity and then follows its real phase error through the existing
outer return and next dense multiplication. It is not a refresh construction.

## Same-phase identity

Let the source residual phase satisfy `S=Q_source*K+g`, with source norm96
and `|g|<=Q_source/64`. Choose an even scale `A`, form public component
weights `b_i=round(A*R_i/Q_source)`, and let

```text
z=b_0+b_1*s=A*K+e.
```

The 97 strict component-rounding errors contribute less than48.5, and the
phase contributes at most `A/64`. Thus

```text
|e| < 48.5 + A/64.
```

For `A=5632=2^9*11`, this gives integer `|e|<=136`, while the carry radius is
48. Encrypt `z` with plaintext tray `T=p*A`, `p=65537`. The same ciphertext
components, re-decoded under `p`, produce `round(z/A)=K`. If its integer phase
lift differs by `Q_outer*J`, the output decoder adds `p*J`, which vanishes
modulo `p`. No componentwise rational scaling is used, so this step has no
new `J` shift.

`T=369104384` is below every lane in the existing outer basis. The encrypted
weighted view has a77-bit scaled-error bound under `T`. Its same-phase output
decodes with a236-bit scaled-error bound under a241-bit ciphertext modulus.

## The source residual still consumes the refresh budget

The output's scaled phase error includes approximately

```text
Q_outer * |e|/A
```

This is the scaled error; as a fraction of the output Q grid it is `|e|/A`.
It is the actual chart residual, not only encryption noise. After the
existing special-prime drops and return-key switch, the certificate reaches
113 bits. The following dense square requires155 bits and does not decode
under the119-bit work modulus. The smaller `A=121` tray also decodes the
carry, but its return reaches117 bits and its following square requires159
bits.

So a scale-locked tray removes the *cross-encoding winding* while preserving
the *source chart residual*. It can recover the integer in one decryption and
still fail as a refresh. Those are distinct checks.

## Exact missing operation

To use exact divisibility for contraction, the evaluator needs a public
canonical residual producer in the high encoding:

```text
F_T(A*K+e)=e mod T,
(Enc_T(A*K+e)-Enc_T(e)) / A = Enc_p(K).
```

The first map must erase the carry direction exactly on the admitted domain,
so input `g/Q_source` and the component rounding residue do not pass into the
output phase. A zero Jacobian along that direction is the local contraction
condition, but the finite-difference identity across every admitted sheet
and every boundary still needs proof. A 2/11-locked sister tray can carry the
low residue, but the encrypted lift into the common high encoding is still
required. K-elimination then supplies the exact quotient; it does not by
itself construct `F_T`.

This keeps the tropical variables distinct: `K` is the covering-space sheet,
`e` is the centered torus/chart remainder, and the Jacobian condition removes
the sheet-direction derivative. The 11-adic ring section in
`FROBENIUS_CHART_SECTION.md` has a zero derivative modulo11, but its Witt
quotient is not yet the canonical integer residual above.

The Python tests exhaust every integer carry/residual pair in the certified
rectangle for both candidate trays, check that all tested integer Q-windings
vanish modulo p, and confirm the return-cycle refusal:

```text
python3 scripts/test_scale_locked_carry_tray.py
python3 scripts/scale_locked_carry_tray.py
```

The native encrypted residual producer, all-coefficient carry path, return
history and repeated refresh remain open. Production admission stays closed.
