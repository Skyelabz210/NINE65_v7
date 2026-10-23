# Larger outer ring and reduction before the return key switch

This research change removes the arithmetic closure refusal found in the
[full-polynomial return analysis](FULL_POLYNOMIAL_PUBLIC_RETURN.md), under
the same CONDITIONAL source norm32. It changes the outer parameters and the
order of return operations. It does not admit the default dense source or
complete the public bootstrap goal. Production gates remain closed.

Implementation: `crates/nine65/tests/research/outer_ring_return.rs`, inside
the existing research integration harness. It uses NINE65's RNS, NTT, raw
gadget and public rank kernels. There is no external bootstrap backend or
additional Safe Basis root.

## Why the return order matters

The preceding experiment switched the outer secret to the working secret
at Q_outer, then dropped the special prime. That publishes work-key samples
at the OUTER modulus, so increasing Q_outer must also respect the working
key's smaller dimension. Merely increasing the outer modulus fails the
existing parameter screen.

The new path instead does:

```text
source work ciphertext, N8192/Q119
  -> encrypted lift in outer ring N16384/Q241
  -> reduce Q241 to Q119 under the SAME dense outer secret
  -> switch the even and odd outer-secret parts to the work key at Q119
  -> work ciphertext, N8192/Q119.
```

The working ciphertext modulus is unchanged. The source-bit precharges are
encrypted under the outer key; the working key is never used to encrypt a
return sample at Q241. Joint/circular security of these relationships is
still an open assumption, not a consequence of screening each dense tuple.

The outer tuple is the four working primes followed by
`[1811939329,2113929217,2130706433,1107296257]`. Its exact product has241 bits.
The existing full-model screen REFUSES it at N8192 (97-bit minimum). At
N16384 it returns `ScreenedFullModelAgreement`: classical228, hybrid194,
quantum129 bits, for the dense outer key and claimed target128. The old
dimension's refusal is a retained regression. No source or service security
target is lowered to make the tuple pass.

## Full-polynomial affine recovery is linear

For source components, public residue-only preprocessing gives

```text
p*C_i = Q*A_i+R_i
S=R0+R1*s_work=Q*K+g
message=A0+A1*s_work+K (mod p).
```

The phase clock must produce the integer K. The affine polynomial does NOT
need one encrypted bit operation per source term and output coefficient.
The key holder supplies one ordinary BFV ciphertext of `s_work(Y^2)` under
the outer key. The evaluator multiplies it by public `A1(Y^2)` and adds
public `A0(Y^2)`. Both negative source trits and negacyclic wrap are retained.
The fresh precharge's full encryption error is charged, then multiplied by
the public polynomial l1 norm. It is not assigned a raw eta=3 error.

This removes the affine part's quadratic raw-switch loop. Carry clocks
remain per coefficient. With source size n, outer size2n, their online count
plus trace and return is `4*n^2+n*log2(2n)+2` raw switches, instead of the
previous `8*n^2+n*log2(n)+1`. This is a counted implementation change, not a
latency benchmark.

## Return across both modulus and ring degree

The recovered polynomial occupies even powers of Y, with X=Y^2. Each extra
outer prime is dropped using the existing public small-divisor formula:

```text
r=center_P(C mod P)
round(C/P) mod q_i=(C_i-r)*P^-1 mod q_i.
V_next<=ceil(V/P)+ceil(p*(N_outer+1)/2).
```

The rounding allowance uses the DENSE OUTER secret norm, not source norm32.
Every intermediate drop must pass its own decoding-bound check. The
evaluator never observes a decrypted phase to perform this reduction.

At Q119, split the outer secret as `s_outer(Y)=se(X)+Y*so(X)`. The even
phase of the reduced ciphertext is exactly

```text
c0_even+c1_even*se+X*c1_odd*so (mod X^N_work+1).
```

Two raw return keys at the working modulus implement those two terms.
The X factor is essential, including its negacyclic boundary sign. Tests
check the parity identity independently and reject omitting the odd branch
or using the outer components directly under the working key.

## Wide bounds and bounded working sets

The native worst-case assembled error bound is143 bits. The new recovery
ledger therefore uses U512 through assembly and modulus reduction. A
native-size public calculation checks the actual Rust routine against the
Python arbitrary-integer result:

`8619523015289380252955284725379368213479424`.

The native input probe also exposed an independent width issue: `4*N*V`
in the phase-window numerator overflowed u128 before division by Q. The
shared phase-window routine now uses U512 and a bounded public quotient
search. The N8192 and N16384 boundary regressions give5185 and9281 for
H32, composite33, source V<=Q/8. Overflow checks remain enabled.

Keeping all8192 outer clocks resident would require16GiB of ciphertext
words. Evaluation instead processes public output batches, with all hidden
source positions visited for every batch. Packed expansion processes one
polarity at a time, halving its recursion-stack word allowance. It never
reads private zero support. Repeating expansion costs time and is charged.
Batching does not reduce the full assembled error bound.

## Native public ledger

`scripts/outer_ring_return_budget.py` searches raw/Galois radices1..10bits
and packed block powers1..8192, using outer N16384/Q241, work N8192/Q119,
source norm32, composite33, source V<=Q/8, and a public output batch of64.

The minimum stored-key candidate uses block8192 and10-bit raw/Galois/return
digits. Its conditional ledger is:

| Quantity | Result |
| --- | ---: |
| Assembled outer V bound | 143 bits |
| V after the modulus drops | 30 bits |
| V after the work-key return | 46 bits |
| Following full-polynomial product V bound | 80 bits |
| Stored ciphertext/NTT polynomial words, including return keys | 1,071,644,672 bytes |
| Resident64-clock batch | 134,217,728 bytes |
| Single-polarity expansion stack allowance | 1,056,964,608 bytes |
| Keys + stack allowance + clock batch | 2,262,827,008 bytes |
| Repeated expansion + online raw switches per refresh | 444,703,746 |

Keys/stack/clocks exclude contexts, metadata, ordinary evaluation keys and
other scratch. The word allowance is not a measured native process peak.
There is no native encrypted full-source timing or memory admission. The
switch count remains substantial, despite eliminating the affine loop.

All1400 candidates in this finite search pass the conditional arithmetic
checks. The previous200GiB result applied to the earlier Q149/N8192 return
order and layout. It is not a lower bound on this new construction or on
CRAM. Source H8192 STILL fails the new clock window and integer carry range;
the larger outer modulus does not repair that geometric constraint.

## Executed evidence and remaining requirements

The encrypted integration uses explicitly insecure workN16/outerN32,
Q119/Q241, private source weight2 with both signs, composite9, block8,
10-bit gadget digits and four-output batches. Its dense nonconstant input
is publicly encrypted, squared, phase-loaded, recovered, returned, and used
again with the SAME precharge for a second dependent cycle and final square.
All coefficients, including the outer odd zero coefficients, are checked.

| Quantity, V bits | Cycle0 | Cycle1 |
| --- | ---: | ---: |
| Incoming observed | 110 | 110 |
| Assembled outer observed / bound | 60 / 79 | 60 / 79 |
| Reduced observed / bound | 19 / 21 | 18 / 21 |
| Returned observed / bound | 31 / 37 | 31 / 37 |
| Following polynomial product bound | 61 | 61 |

The batched run checks22,816 outer raw switches and4 return raw switches
across two cycles. Carry omission corrupts6 coefficients in total; wrong-key
and missing-cross-term controls also fail. Continuation uses producer bounds,
not measured errors.

The separate native-input check creates an actual N8192/Q119 public-key
ciphertext with a research-only sparse32 source, squares a dense polynomial,
and processes every coefficient through the PUBLIC residue preprocessor.
An independent CLIENT oracle checks the hidden native sheet, message and
clock window for all8192 coefficients. It does not allocate native encrypted
selector keys or evaluate an encrypted native clock. Sparse-source security
is explicitly unadmitted; this is geometry/preprocessing evidence only.

The full bootstrap goal still needs an assessed source/key distribution,
joint/circular key assumptions, authenticated key/epoch/history binding,
intact S8/Root211 capability integration, useful measured native execution,
and an actual native repeated public bootstrap. These requirements are not
replaced by the small encrypted run, the native client oracle, or the dense
outer parameter screen. Production refresh remains fail-closed.

Exact source hashes, build provenance, public parameter-screen output,
analysis, and accepted test logs are retained in
`artifacts/execution/2026-10-23/outer-ring-return/`. The focused harness links
the unchanged existing Cargo-built library with debug assertions and overflow
checks. The full filesystem still prevents the unrelated audit-binary Cargo
link set. No package-wide Cargo or hosted CI green result is claimed. No
linting is run and no production gate is changed.
