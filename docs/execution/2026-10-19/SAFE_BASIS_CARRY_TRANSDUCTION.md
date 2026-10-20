# Encrypted carry experiments: aligned phase and a nonlinear local gate

Date: 2026-10-20. Baseline: `2b9c40704a730e4dda4505a80cf087ccbd7a2fb2`.
Scope: native-ring research tests, not production refresh admission.

The precharge proposal now has two encrypted follow-ups. An aligned sister
frame produces a ciphertext decoding to the actual carry for supported native
inputs. Its old residual survives as output noise. A separate nonlinear
degree-two gate computes one local ternary carry with a fresh output-error
bound independent of that residual. Neither result supplies the full
8192-term nonlinear carry circuit.

## Aligned sister frame

Keep all eight S8 root coordinates. Add sister plaintext coordinates for each
work prime q_i and for the target plaintext t. Their operation payload product
is `M=Q_work*t` (135 bits), which covers the native signed S interval. These
are **plaintext encodings of separate full-modulus ciphertexts**, not raw
coprime RLWE lanes. The payload factor subset is distinct from the intact root.

Each coordinate encrypts `S mod m`, with S=R0+R1*s. One key family uses a
common independent boot secret and fresh randomness for every coordinate
encryption. Ciphertext moduli stay in the boot basis:

```text
Q_boot factors = {1811939329,2113929217,2130706433,1107296257}
Q_boot = 9036942976776574374355364829233938433 (123 bits)
t = 65537, N = 8192.
```

All boot primes exceed every coordinate modulus, so ordinary plaintext-range
requirements are preserved. The test validates primality, NTT compatibility,
coprimality, and both in-tree security screens at the independently supplied
128-bit target. These screens are not external security certification.

For coordinate m use `w_m=inverse(M/m,m)`. Integer multiplication by w_m and
ciphertext addition give a torus phase with exact ideal value

```text
sum_m w_m * (Q_boot/m)*(S mod m)
  = Q_boot*S/(Q_work*t)                 (mod Q_boot).
```

With `S=Q_work*K+g`, `|g|<=Q_work/2`, this is

```text
phase = (Q_boot/t)*K + Q_boot*g/(Q_work*t) + E_assembly
|E_assembly| <= sum_m w_m*E_m
             <= 287487982247299167448314438.
```

The weighted error bound has 88 bits, against 106 half-scale bits in the
target encoding. A supported residual bound must cover the retained term too.
The test chooses its bound from public parameters and known input history:
fresh encryption plus a known signed additive perturbation. It does not admit
an input using its decrypted residual.

Actual encrypted evaluation checks six native coefficients on a fresh
encrypt(7) and on the same ciphertext with positive/negative public error
`floor(Q_work/(8t))` added to coefficient zero. It checks the decoded carry,
the public-history error certificate, and the stronger measured identity

```text
|Q_work * (t*phase - Q_boot*K) - Q_boot*g|
    <= Q_work*t*E_assembly,
```

with the grid difference centered modulo Q_boot*t. All 18 carries are
nonzero. In perturbed coefficient zero the retained old noise exceeds the
new assembly bound by a factor greater than 1000. This excludes interpreting
the successful carry decoding as noise refresh.

There is a sharp negative control: at `S=(Q_work-1)/2`, even one unit of
positive phase error changes the aligned output's decoded carry from zero
to one. A carry guarantee therefore needs an input margin; residue capacity
alone does not admit every point arbitrarily close to the threshold.

## Nonlinear local ternary gate

For public centered r0,r1 and one secret trit u in {-1,0,1}, define the public
table

```text
k_minus = nearest_Q(r0-r1), k_zero = 0, k_plus = nearest_Q(r0+r1)
a = (k_plus+k_minus)/2 mod t
b = (k_plus-k_minus)/2 mod t
K(u) = a*u^2 + b*u mod t.
```

Division by two here is multiplication by its modular inverse in the odd
plaintext ring. This is interpolation of a known three-point function; it
does not divide a hidden ciphertext or assume an exact-divisibility promise.
There are five possible gates for centered inputs. For example `r0=r1=h_Q`
gives `K(u)=(u^2+u)/2`, with table {0,0,1} in order {-1,0,1}. This is exactly
one of the local integer threshold crossings from the carry cocycle.

Key-holder setup encrypts the selected trit as a constant plaintext under
the independent boot secret. The evaluator receives only that ciphertext,
public coefficients and an ordinary relinearization key. It squares once
using the main-only exact BFV multiplier, then applies the public linear
combination. It never decrypts, reconstructs a secret-dependent phase, or
selects the polynomial from a secret value.

For this constant-plaintext circuit the bound includes zero-encryption
noise, component-lift winding, the quadratic error term, rescale rounding,
gadget-switch error and centered public scalar multiplication. The clear
probe independently reproduces the same calculation:

```text
input error <= 49156
square error <= 216246458418925570
output error <= 7085963949472963821568 (73 bits)
target half-scale: 106 bits.
```

The bound does not depend on r0,r1 or their residual g. The test exercises
all five gates for all three trits at native N=8192 and t=65537, checking the
constant output and three other coefficients. Cached evaluation of identical
public polynomials yields 60 encrypted coefficient checks corresponding to
147 signed native boundary vectors. The independent clear probe exhausts
3825 small-Q ternary cases as well.

The local gate's scalar-trit precharge is an explicit different interface
from the encrypted polynomial S8 coordinates. Extracting these scalar trits
from the existing polynomial precharge or generating a general coefficient
key family still has a separate resource and noise cost. No unimplemented
conversion is silently assumed here.

## Remaining composition gap

The local gate takes a **public** starting remainder. After a secret term is
added, the updated remainder is encrypted. Reusing the starting public value
does not compose: for Q=17, starting r=8 and two terms 8, the total carry is
one, while evaluating both local crossings independently at r=8 gives two.

The required next interface must support the updated encrypted remainder or
a different bounded block representation closed under composition. It must
account for the work to produce that representation, its encoding changes,
and every multiplication's error. This is the precise remaining nonlinear
secret-sum problem. Passing a scalar gate or decrypting K correctly with
retained old noise does not admit it.

The general distinction between linear re-encryption and nonlinear noise
removal agrees with the bootstrapping objective in
[Geelen--Vercauteren](https://eprint.iacr.org/2022/1363). The algebra and the
new constructions above are derived and tested here, not attributed to that
paper.

The follow-up [encrypted-state composition experiment](SAFE_BASIS_CARRY_COMPOSITION.md)
tests a packed selector producer, bounded sequential/balanced composition,
and a sparse near-cut coefficient refresh followed by an encrypted square.
It addresses the public-starting-remainder limitation for those bounded
cases, not the full secret sum or production refresh admission.

## Reproduction

```sh
python3 scripts/safe_basis_carry_probe.py
cargo test --locked --offline -j1 -p nine65 --lib precharged_ -- --nocapture
```

The new source-bound artifact is `safe-basis-carry.json`; the previous
`safe-basis-precharge.json` remains historical evidence for its recorded
source revision. Source edits are not hidden by rewriting its hashes.
Public refresh admission, correctness and security gates remain active.
