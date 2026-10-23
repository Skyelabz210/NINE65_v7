# Adjacent 120/121 hidden-carry lift

This tray pair gives a compact exact source-carry identity on the existing S8
Safe Basis. It reduces the source carry to a 120/121 K-Elimination read. The
remaining obstacle is a second, secret-dependent winding created when the
120 plaintext ciphertext is rescaled to the 121 encoding. The path is not a
public refresh yet.

## Source lift

For each centered source component residual `R_i`, publicly compute
`b_i = round(120*R_i/Q_source)`. For one source coefficient, write
`S = R_0 + R_1*s = Q_source*K + g`, with source norm at most 96 and
`|g| <= Q_source/16`. The weighted integer is

```text
z = b_0 + b_1*s = 120*K + e.
```

There are at most 97 component rounding residuals, each strictly below
`Q_source/2`; together they contribute less than 48.5. The phase contributes
at most 7.5, so `|e| < 56` and the integer residual has `|e| <= 55`. The
carry radius is 48. Thus `e` fits the centered 120 tray and `K` fits the
centered 121 anchor. Since `120 = -1 mod 121`,

```text
z mod 120 = e
z mod 121 = e-K
```

and the clear residue difference recovers `K` exactly.

The two public weighted views have 43-bit deterministic error bounds. The
weight maximum is 60 and the public polynomial l1 norm is 491,520. These are
useful low-noise source-view bounds.

## The missing carry in plaintext-scale conversion

The 120 and 121 views use different BFV scales. The new RNS component
primitive computes

```text
y = floor((120*x + floor(121/2))/121) mod q_i
```

from a centered CRT coefficient's main-lane residues and its K-Elimination
remainder modulo 121. It does not materialize the wide coefficient. The
component arithmetic is exact.

Applying that map separately to ciphertext components does not preserve the
decrypted phase by itself. Let `J` be the polynomial winding in the integer
phase `c0 + c1*s` before reduction modulo the ciphertext modulus `Q`. Scaling
both components by `120/121` changes the decoded 121-plaintext message by

```text
120*J mod 121 = -J mod 121.
```

For `J=1`, the recovered carry is off by one, producing phase error `Q` for
the intended message. The converter's coefficient-rounding error is only
about 19 bits, but it cannot bound or remove this separate winding. The next
conversion, from 121 to 65,537, creates the analogous shift `121*J mod
65,537`.

If both scale-conversion windings were zero or corrected, the conditional
ledger would give a 44-bit carry, 46-bit work-key return, 88-bit following
dense product, and 44-bit next source preparation. Those figures are not
valid output bounds until the windings are handled.

## Tests and next step

The Python tests exhaust all 97 carries and 111 residuals in the certified
rectangle, and compare the RNS scale-division formula with signed integer
oracles across the full native outer basis. The Rust unit tests validate the
component-level K-Elimination division on every centered value in a toy CRT
basis and on the native basis shape. They do not test ciphertext-level
plaintext conversion or a native encrypted carry producer.

The next required construction must eliminate or correct the converter
winding without restoring the source error. One route is a direct plaintext
65,537 K output from additional same-encoding sister views; another is to
derive the converter winding through the same precharged 2/11 phase system.
Then execute the complete native path, return it to the work key, and run the
dependent refresh tests. Full-source/joint-key security, authenticated
key/domain/epoch/history, and intact S8/Root211 service admission remain
separate gates. Production remains fail-closed.

The [scale-locked tray follow-up](SCALE_LOCKED_CARRY_TRAY.md) shows a way to
avoid this converter winding by choosing `T=65537*A` and preserving the same
ciphertext phase. That fixes the immediate carry decode but retains the
source residual and fails the following dense square. It does not replace the
canonical-residual producer required above.

Reproduce the arithmetic checks with:

```text
python3 scripts/test_adjacent_120_121_carry_reset.py
python3 scripts/adjacent_120_121_carry_reset.py
```
