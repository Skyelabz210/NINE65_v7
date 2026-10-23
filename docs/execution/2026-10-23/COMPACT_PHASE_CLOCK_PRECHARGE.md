# Compact precharge: storage, noise, latency and reentry are separate

Research follow-up to the
[native phase-clock lift](../2026-10-22/NATIVE_PHASE_CLOCK_LIFT.md).
No production refresh gate or key format is changed. The new encrypted
compaction experiment runs at explicitly insecure N16/N64, with native
source period Q_work119 and the existing five-prime outer modulus Q154.
Native N8192 numbers below are public parameter calculations, NOT an
executed full-source compact refresh or a sparse-key security certificate.
This changes how one source precharge supplies its selector controls; it
adds neither an independent Safe Basis nor any ciphertext primes.

## Public derivation from shared key material

The direct layout precharges a separate RGSW-style selector for every source
trit. Instead divide source positions into blocks of G, a power of two
dividing outer N. For each block and each plus/minus polarity, the key holder
precharges only the raw CONSTANT gadget column of

```text
(1/G) * sum_j selector_j * X^((N/G)*j)   (mod Q_b).
```

The inverse-G is put in the secret setup message before sampling fresh eta=3
encryption error. It is not applied to an already noisy ciphertext. All masks
are uniform over the complete main RNS product and signed errors are shared
consistently by its lanes.

The public evaluator extracts a source coefficient with shifts and Galois
trace. This gives a raw constant column for the hidden bit. A SHARED native
raw multiplier encrypting the outer secret supplies the bit-times-secret
column. It is derived from two columns whose targets are s_boot and
s_boot^2. Evaluation receives neither source bits nor outer secret.
The shared self-key-dependent material still needs a joint security analysis;
the old lattice parameter screen alone does not establish it.

The derived two-column selector controls the existing phase clock and affine
BFV rounding equation. No centered chart, winding or source plaintext is
supplied. The test-only raw gadget type is separate from production's fixed
10-bit relinearization-key type; production key validation is not bypassed.

## Actual derived error, not a reset to eta

For radix 2^b let L_b bound the sum of unsigned digits of any canonical main
coefficient, summed over lanes. The last digit is charged at its actual
public maximum. Every step is exact integer arithmetic.

```text
E_galois = N * L_galois * eta
beta_constant = G*eta + (G-1)*E_galois
beta_secret = N*beta_constant + E_external(shared_outer_multiplier)
E_external(derived_selector) = N*L_raw*(beta_constant+beta_secret).
```

The N in beta_secret is the outer secret norm upper bound, not the source
secret's sparse norm. Substituting source norm32 for it would be unsound.
No independence of derived rows or reused errors is assumed. Their
deterministic absolute bounds are propagated through both selector columns,
all CMUX operations, the final trace and affine message recovery.

A naive full-block compact layout at the CURRENT 10-bit gadget radix decodes
but FAILS the following-square budget. That refusal is retained. Smaller
raw/Galois digits and bounded blocks can fit the comparison envelope; this
is not permission to treat the new keys as fresh direct precharge.

The raw-row client test checks every row against its intended CRT-idempotent
message and its derived error bound. Ordinary BFV decoding would be the wrong
way to test those unscaled gadget messages.

## Streaming expansion reduces repeated work

Point extraction repeats log2(G) Galois switches for every requested scalar
row. The implemented batch expansion shares each switch between even and
odd children:

```text
even = C + sigma(C)
odd  = X^(-stride) * (C - sigma(C)).
```

Recursive splitting visits every public position in fixed order, including
encrypted zero controls. The leaf has the SAME bound beta_constant as point
extraction. No private support is read or skipped. Depth-first traversal
uses a temporary stack; fewer switches do not imply free working memory.

For all N positions, D_raw rows and N/G blocks:

```text
point derivation switches = 2*N*D_raw*(log2(G)+2)
stream derivation switches = 2*(N/G)*D_raw*(G-1) + 4*N*D_raw.
```

These counts exclude NTT work inside each raw switch. The cached evaluator
explicitly applies psi/psi^-1 around cyclic NTT transforms. An initial raw-row
failure exposed the omitted twist; a regression now distinguishes
X^(N-1)*X=-1 from the erroneous cyclic +1. Bounds were not weakened. Cached
pointwise arithmetic uses u64 only after checking main primes are <=2^31.

## Public native resource comparison

Stored polynomial words, excluding ordinary keys/metadata and temporary
evaluation buffers, are counted as

```text
(2*(N/G)*D_raw + 2*D_raw + log2(N)*D_galois) * ciphertext_bytes.
```

At N8192, ciphertext_bytes=655360. The old direct 10-bit source-selector
layout alone costs 400 GiB. In the declared finite search (radices1..10 bits,
G powers1..8192), with source norm32, ALL8192 public terms, composite33,
V_source<=Q_source/8 and the same outer tuple:

| Candidate | Stored words, bytes | Output V bits | Conditions |
| --- | ---: | ---: | --- |
| G2048, raw/Galois radix2bits | 1205862400 (about1.12GiB) | 111 | decoding and one square fit; optimistic reentry FAILS |
| G512, raw/Galois radix2bits | 2464153600 (about2.30GiB) | 109 | additionally passes the optimistic reentry phase test |

The first tuple needs 17,039,360 point-derivation switches per coefficient;
batch expansion lowers this to 3,931,520. The second needs 3,929,600 streaming
derivation switches. Millions of raw switches per coefficient are NOT a
practical latency admission. The model also reports a conservative temporary
stack allowance separately from stored-key bytes. Loading the entire key
plus that stack is not admitted within this session's memory budget.

The extra reentry check matters: the smallest-memory tuple's next square is
decodable but already exceeds the source Q/8 phase allowance, even under an
ideal noiseless linear return. The larger tuple only passes that NECESSARY
phase condition. It supplies no actual sparse-source switch, return noise,
key/history binding or repeated-refresh proof. Dense8192 source norm still
fails the clock window independently of compaction.

## Executable checks and scope

The N16 test derives 14 positive/negative/zero controls across packed blocks,
checks both columns' raw errors, and consumes full-polynomial messages.
The N64 test uses a private weight2 source and processes all64 nonzero public
weights without skipping encrypted zeros. One compact precharge is reused for
two public residual inputs, including signed weights; they select different
sheets. Both recover the independently rounded BFV coefficient and check its
following message square. This is not an N8192 encrypted compaction run.

N64 stores 6,553,600 bytes of polynomial words in this layout. It streams
derived selectors instead of storing a direct per-position matrix. It does
not implement the intact S8/Root211 capability, full output assembly, live
source admission, work-key return or repeat closure.

The verified N64 outputs are message24141 on sheet1 and message43525 on
sheet0. Their observed scaled errors are42 and49 bits, both within the
69-bit bound. Both following message squares pass. The two-input run uses
31,116 raw switches. The raw-row and transform-domain regressions remain
ordinary tests; the slower full-position probe is opt-in and is explicitly
included in the acceptance run.

Reproduce the encrypted tests with sufficient build space:

`cargo test --locked --offline --config 'profile.test.package.nine65.opt-level=2' -j1 -p nine65 --test coefficient_slot_gate phase_clock_compact -- --include-ignored --nocapture`

The workspace Cargo attempt failed linking unrelated audit binaries when the
disk filled. Acceptance instead uses a directly compiled focused test harness
against the already Cargo-built library, with debug assertions and overflow
checks enabled. Its exact command and library/executable hashes are recorded
in artifacts. That is not a green package-wide Cargo or hosted CI result.

`python3 -m unittest discover -s scripts -p 'test_compact_phase_clock_budget.py' -v`

`python3 scripts/compact_phase_clock_budget.py`

The [full-polynomial return follow-up](FULL_POLYNOMIAL_PUBLIC_RETURN.md)
implements residue-only preprocessing, full output assembly, a work-key/
modulus return and two dependent cycles at insecure N32. Its full-polynomial
native budget refuses the compact layouts above; their scalar comparison
must not be read as full-ring repeat admission. Native latency/memory,
admitted source/key history, joint and sparse-key security, intact root
integration and native repeated execution remain open.
