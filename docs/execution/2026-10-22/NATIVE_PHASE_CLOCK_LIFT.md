# Native-period lift through an encrypted phase clock

Research only. Native public refresh remains fail-closed. This is a
source-bound way to preserve the Q-sheet information lost by the earlier
period13/S8 projection, not a complete full-ring refresh.

## Preserve Q before projecting

For a public residual-form coefficient with hidden source trits:

```text
S = R0 + sum_i Ri*si = Q*K+g, |g|<=V, si in {-1,0,1}
M = 2N, small carry-coordinate period m
bi = round(M*Ri/(m*Q))
z = b0 + sum_i bi*si (mod M).
```

The encrypted clock rotates by z, near M*K/m. Q stays the actual native
source period; it is NOT replaced by a local13 chart. Public residuals are
normalized by Q before encrypted selection, instead of discarding its
quotient and trying to recover it from a small-modulus projection.

For a proved participating secret norm H, each public rounding costs at
most one half, giving the exact sufficient window allowance

```text
|2*m*z - 2*M*K| <= ceil(2*M*V/Q)+m*(H+1) = W2
```

where distance is on the circle. H can use both the source-key norm and
public nonzero residual support. This test's public quantizer uses U256 on
public coefficients only. An admitted residue-only preprocessing kernel
has not been implemented; no hidden S or g is reconstructed by evaluation.

## Negacyclic geometry and composite control

An N-coefficient accumulator imposes F(z+N)=-F(z). For odd m, windows around
integer sheet centers can hold arbitrary output values when W2<N: valid
windows and their negacyclic mirrors cannot overlap. The compiler explicitly
deposits values and opposite mirrors and rejects conflicts. Unused positions
are zero. The special m=2 lookup outputs (-1)^K, then pays for conversion
to parity. This is not a compiler for arbitrary even-period functions.

If |K|<=B and odd m>2B, the signed lookup gives the INTEGER K. For H=32,
centered source components give B=16, so composite33 suffices without an
encrypted CRT reconstruction of a larger carry.

| H | Composite m | Allowance | W2 at N8192 | Result |
| --- | --- | --- | ---: | --- |
| 32 | 33 | V<=floor(Q/8) | 5185 | fits below8192 |
| 64 | 65 | V<=floor(Q/8) | 8321 | refused |
| 64 | 65 | V<=floor(Q/16) | 6273 | fits below8192 |
| 8192 | 33 | V<=floor(Q/8) | 274465 | refused |

The composite controls precision and support, not another ciphertext prime
or free noise headroom. The weight32/64 entries are CONDITIONAL mathematical
preflights: no live sparse-key switch, sparse-key security assessment, or
input-history certificate is supplied. The encrypted probes instead use two
public nonzero residual terms, so H<=2 independently of the rest of the key.

## Native RNS implementation and bounds

See `crates/nine65/src/ops/tropical_phase_clock_tests.rs`. Each source trit's
plus/minus selectors have two raw native gadget columns encrypting the bit
and bit times the independent outer secret. Existing hybrid target switching
applies them to the two ciphertext components; no BFV multiply/scale-round
is used in the external product.

Selector-controlled rotation is the standard CMUX identity
`C+external_product(X^b*C-C,Enc_bit)`, implemented with NINE65's own RNS
gadget and monomial kernels, not an external backend. The primary reference
for this building block is [Liberating TFHE](https://eprint.iacr.org/2022/1177.pdf).
The Q-normalized carry coordinates and window construction above are the
specific construction tested here.

The public lookup is directly encoded with a centered inverse-N preconditioner.
A logarithmic native Galois trace extracts its constant coefficient. Thus no
encrypted dense coefficient/slot transform or plaintext slot root is needed.
The preconditioner is calculated; it equals -8 for N8192, plaintext65537.

Let t=65537, Q_b be the existing five-prime outer modulus, eta=3, gadget
radix B_g=1024, and D=20 lane digits. For ell public residual terms:

```text
E_g        = N*eta*(B_g-1)*D
E_external <= 2*E_g
V0         <= (Q_b mod t)*max_abs_encoded_lookup_coefficient
V_clock    <= V0+4*ell*t*E_g
V_trace    <= N*V_clock+t*(N-1)*E_g
V_parity   <= ((t-1)/2)*(V_trace+(Q_b mod t)).
```

V is the ideal-grid error |t*phase-Q_b*message| modulo t*Q_b. A CMUX selects
one signed permutation of the OLD error; the correlated errors cancel, so
its recurrence is E_old+E_external, not 3*E_old+E_external. Both ternary
branches execute without learning the selected bit. The inverse-two cost
for parity is explicitly charged.

The tests check 2*V<Q_b and independently observe every output coefficient
with a secret-key U256 client oracle. That oracle never supplies values or
measured errors to evaluation. These research calculations do not issue
authenticated production history types.

## Follow-up: recover the source message coefficient

The dependent probe constructs public source components satisfying
p*C_i=Q*A_i+R_i, p=65537. Its R0=Q/128 gives substantial incoming phase error.
After computing K from ciphertexts, it produces

```text
message = A0+sum_i Ai*si+K (mod p).
```

The affine part uses the same opaque selector precharge; it is not a supplied
plaintext. A separate client rounds the SOURCE phase directly and checks the
recovered coefficient. The affine ideal-grid bound is

```text
V_affine <= (Q_b mod t)*(|A0_centered|+sum_i |Ai_centered|)+4*ell*t*E_g
V_message <= V_affine+V_carry.
```

There is NO term proportional to the old g. The test compares normalized V/Q
before/after and squares the recovered MESSAGE, not just its carry. It extracts
one source coefficient into a constant plaintext under the outer key. It does
not preserve other plaintext coefficients, return to the work key/modulus,
or repeat a full-ring refresh. Fixtures are not authenticated live histories.

## Practical limits

The [compact precharge follow-up](../2026-10-23/COMPACT_PHASE_CLOCK_PRECHARGE.md)
derives selectors from packed raw columns and shared key material, with
explicitly larger derived errors. Native storage/noise comparisons now have
conditional smaller layouts; the encrypted compaction checks are N16/N64.
Streaming expansion reduces repeated switches but does not yet establish
practical native latency, memory, security or repeat closure.

One five-lane N8192 ciphertext stores 655360 bytes. With two bit keys per
trit, two columns per bit, and D=20 ciphertexts per column, full-source
precharge is N*4*D*655360 = 429496729600 bytes = 400 GiB, before metadata.
The two-term native probe needs 100 MiB of selector keys and 162.5 MiB of
trace keys, plus other keys. No 400 GiB material is generated. Full-ring
assembly additionally needs separate work for every desired output coefficient.
Weight32 does not reduce the number of control positions when the support
is private: the evaluator cannot skip secret zero positions. The two-term
probe skips only PUBLIC zero residual weights. It is not a 32-key sparse
bootstrap construction.

Key compaction requires new error and key-security analysis; noisier derived
keys cannot retain the direct eta=3 bound. Dense-source handling, public input
and key/history binding, S8/Root211 capability integration, output assembly,
return relationships and repeated refresh remain open. The coordinate clocks
reuse one source precharge; that is not a production proof of the intact root.

## Observed verification

The optimized four-test run passed with the native opt-in probe enabled:
4 passed, 0 failed, 0 ignored. All coefficients of each extracted output and
its following square are checked, not only coefficient zero.

| Probe | Source period | Observed carry/parity V bits | Bound bits | Message recovery |
| --- | --- | --- | --- | --- |
| N256, insecure, sheets -1/0/+1 | Q_work119 | composite33:41, parity:56 | 52,67 | 3 coefficients; 112-bit incoming V; output V at most41 bits |
| N8192, screened outer tuple, sheets 0/+1 | Q_work119 | composite33:50, parity:65 | 62,77 | 1 coefficient; incoming V112 bits; observed V50 bits; bound62 bits |

The N256 probe checks nine dependent squares; the N8192 probe checks five.
The native recovered message is 24141 and its following MESSAGE square is
correct. The independent source phase oracle supplies no input to the
producer. These are bounded two-term probes, not full live refresh runs.

## Reproduction

Small-ring native-Q tests and public native-window checks:

`cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib phase_clock_ -- --nocapture`

Include the native N8192 two-term alias and coefficient-recovery probe:

`cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --lib phase_clock_ -- --include-ignored --nocapture`

N256 is explicitly insecure. The N8192 outer tuple must pass the existing two
lattice screens before key generation. That alone does not admit the complete
scheme or the new key relationships. No production gate is opened.
