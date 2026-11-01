# System goal, deep analysis, and remediation — 2026-10-28

Analysis starts at `31bb5b4` on `codex/recumbent-plan-reconciliation`.
This is an architecture and correctness review of active execution paths,
their admission rules, and available regression evidence. It is not an
independent cryptographic security audit or a proof of every repository module.
The supplied documents describe intended constructions and proposed results;
executable code and independently checked identities determine current capability.

## Goal and acceptance contract

The intended system is a public evaluator for exact modular computation on
encrypted data, using CRAM/recumbent residue state to retain main residues,
authentic overflow/anchor information, and sufficient lift history through
arithmetic. The architectural objective is fixed-basis composition with exact
division and reversible carry handling, eventually supporting deep encrypted
programs and quantized tropical operations such as `max(a,b)`.

The current implementation is a finite-depth BFV/RNS prototype with several
distinct evaluator paths. Keeping an integer quotient exact is one requirement;
preserving the encrypted phase through convolution, rounding, relinearization,
and key-domain return is another. Neither implies the other automatically.

The user's clarified contract is retained:

* Decisions and capacity calculations use exact integers.
* Reconstruction is permitted; synthetic residue emissions from Garner/MRC
  in the compute path are prohibited.
* IID uniform driving digits, Eulerian detailed balance of the Holte carry
  process, logical invertibility, and joint output-coordinate uniformity are
  separate properties. The arrow harness reports the latter properties for
  its declared finite fixture; it does not certify arbitrary ciphertexts.
* A public evaluator receives public/evaluation keys, never the client secret.
* Admission requires actual represented capacity, an authenticated lift/range
  contract where needed, and a justified phase-error bound. Counters or
  redundant residues alone do not establish those properties.

## Active system map

| Layer | Active source | Established behavior and remaining boundary |
| --- | --- | --- |
| Configuration and security admission | `params/secure_configs.rs`, `params/validation.rs` | Exact factor-vector metadata and candidate parameter checks. Security labels require independent attestation; the documented `secure_256` in-tree MATZOV screen is 240 bits. |
| Client encryption / decoding | `ops/encrypt.rs`, `ops/rns_fhe.rs` | Secret-bearing boundary. Single-modulus encoding uses nearest `q*m/t`; RNS has separate scaling and key structures. They cannot share modulus capacity by name alone. |
| Legacy single-modulus evaluator | `ops/homomorphic.rs` | Addition, subtraction, negation, and plaintext scalar arithmetic modulo `q`. Raw methods are unchecked; ct×ct `mul` already returns an error. This remediation corrects its tracked admission and capability reporting. |
| Main-Q exact route | `ops/exact_mul.rs`, `ops/cram_main.rs`, `noise/certified.rs` | Explicit exact multiplication plan; immutable per-ciphertext bound and domain state in the main-Q wrapper. Its integer phase bound is stronger evidence than a caller-resettable budget. It remains bounded computation. |
| DualRNS public evaluator | `ops/cram_public.rs`, `ops/rns_fhe.rs` | Public/client key split, emission ledger, actual main/anchor arithmetic. Legacy zero-product sentinel branches remain and require migration to checked/limb metadata. |
| Recumbent coefficient arithmetic | `arithmetic/recumbent.rs`, `arithmetic/rank_residue_divider.rs` | Checked signed intervals, authentic quotient lanes, retained remainders, tested finite inverse. Current ingress starts from trusted clear values; interval endpoints are i128 and the general divisor is u64. Not yet a live wide BFV rescale replacement. |
| Public refresh | `ops/bootstrap.rs`, `ops/auto_bootstrap.rs` | Public Phase 1 refuses because the secret-dependent displaced convolution carry is missing. Zero-noise witnesses show why separately rounding components is insufficient. |
| Chart and carry research | `ops/tropical_phase_clock_tests.rs`, exact carry/chart scripts | Finite chart identities and restricted encrypted phase-clock experiments. The phase-clock module explicitly does not admit full dense-source refresh. These tests do not supply a general encrypted max gate. |
| Deployment surfaces | service, WASM, MANA, UNHAL crates | Wrappers inherit the arithmetic and admission contracts of the route they call. Deployment cannot establish a missing carry transition or security attestation. |

One important trust boundary remains: the legacy `TrackedEvaluator` accepts raw
ciphertexts and exposes a mutable budget; `AutoBootstrapEvaluator` has a
per-ciphertext ledger, but `TrackedCiphertext::fresh` can publicly wrap an
arbitrary raw ciphertext and its `ct` field is public. Those interfaces do not
authenticate a fresh-noise assertion. They require a trusted caller and cannot
serve as proof of operation history for adversarial ingress. The private fields
and admitted producers of `CramMainCiphertext` provide the existing pattern for
closing that boundary. This continuation repairs numerical admission; it does
not silently claim those legacy interfaces have become provenance-safe.

## Confirmed defects remediated in this continuation

### Single-modulus admission spent unrepresented RNS capacity

`TrackedEvaluator::new` used `NoiseBudget::from_config`, which computes capacity
from the entire product of `config.primes`. Its inner `BFVEvaluator` operates
only modulo `config.q`. `FHEConfig::for_depth(1,4096,0)` therefore appeared to
fund large scalar multiplications although its additional primes never entered
the ciphertext. A new integration regression failed before the fix because
`try_mul_plain(...,65530)` returned success.

The constructor now uses `NoiseBudget::from_single_modulus`. Its conservative
bound accounts for fresh encryption error plus the nearest-encoding error of
at most one half, and rounds `q/(2t)` capacity downward. Extra unused primes
cannot increase this budget. The config must still match the encryption
parameters; raw ciphertexts and explicit test budgets are not authenticated
provenance. The certified main-Q wrapper is the existing design to follow
for future per-ciphertext admission.

The regression includes a deterministic phase witness: a ciphertext encoding
65292 with error 1000 decrypts correctly before multiplication, but raw
multiplication by 65530 decrypts to a value different from the required 1715.
The checked call refuses it without debiting the ledger. This preserves the
failure mechanism independently of a fuzz seed.

### Capacity was one bit too optimistic

The RNS ledger used `bit_length(Delta)-1` as log2 capacity for the boundary
`|e| < Delta/2`. For a strict bound `|e| < 2^b`, the conservative exponent is
`bit_length(Delta)-2`. For example, Delta=15231 admits a power-of-two bound of
4096, not 8192. The previous formula fails even at Delta=2.

An exhaustive small-integer regression checks that the selected power-of-two
capacity is no greater than Delta/2. It failed before the correction. Both
initialization and post-refresh reset now inherit the corrected RNS capacity.
This may refuse operations one bit earlier; no threshold was relaxed to make
tests pass. The separate exact integer `ScalarNoiseModel` was not changed.

### Preflight did not match execution

The no-argument `can_mul_plain` charged scalar 3, which is not a conservative
estimate for arbitrary scalars below t. It now checks the largest canonical
scalar, and `can_mul_plain_scalar(m)` matches the exact cost charged by
`try_mul_plain`. Raw scalars above t use the explicit scalar query.
`can_mul` and `remaining_depth` now report false/zero because the single-q
ct×ct implementation is retired regardless of the ledger's numerical balance.

### Fuzzing requested an unsupported arithmetic contract

`fuzz_homomorphic` requested a depth-sized prime chain but used the single-q
API and asserted correctness for every scalar below t. It now uses the NTT
prime `q=2^60-2^14+1`, n=4096, t=65537, eta=3, with security claim zero.
This actual single modulus funds the full scalar domain. No input-domain or
correctness assertion was removed. The target asserts that its entire scalar
domain is budgeted; the underfunded former configuration remains a negative
integration regression. The 60-bit tuple is an arithmetic test fixture, not
a newly admitted security profile.

### Historical claims hid tests of active behavior

`docs/RETIRED_MECHANISMS.md` described unbounded depth as established. It is now
marked as historical rationale with an explicit current correction. Three
ignored noise-ledger tests were run unchanged and passed; they now run normally
because threshold validation, threshold inclusivity, and reset accounting are
live code. This restores coverage without enabling public refresh or changing
the historical encrypted refresh tests.

## Timing investigation

The previous CI run measured adjacency operand-magnitude signal t=43.2611
with control t=4.7569. On this workspace, the unchanged release implementation
measured magnitude signal 1.9837/control 0.7853 and operand-order signal
1.0384/control 1.0084. Both are below the existing threshold 5.

The CI finding remains unresolved across environments. No kernel change,
threshold increase, retry-until-pass policy, or library-wide constant-time
claim follows from these local null results. Retain both statistical probes
and their controls. Next isolate compiler/CPU effects on the failing CI build
and inspect its generated code before choosing a targeted arithmetic change.

## Remaining engineering obligations

| Priority | Obligation | Concrete acceptance evidence |
| --- | --- | --- |
| P0 correctness | Integrate a wide divisor and authenticated signed-lift state into actual ciphertext arithmetic. | Boundary, shared-factor, overflow and randomized tests against an independent exact oracle; authentic main/anchor outputs on live inputs; unchanged key-domain provenance. |
| P0 admission | Restrict raw-to-fresh wrapping and mutable raw state in the tracked legacy APIs. | Only admitted encryption/import can establish a fresh bound; cloning preserves it; attempts to reset an old ciphertext or replace its raw data cannot bypass admission. |
| P0 correctness | Compute the encrypted secret-dependent Phase-1 carry and key-domain return. | Zero-noise witnesses corrected by the actual public circuit; boundary plaintexts and dense-source tests; no secret-key access at evaluation; end-to-end refresh under every claimed profile. |
| P0 regression | Resolve the existing four full-library failures and other research-target failures individually. | Preserve failing witnesses; distinguish parameter refusal from wrong plaintext; do not classify failures as retired solely to green CI. |
| P1 metadata | Remove remaining `q_product == 0` / `!= 0` control-flow sentinels. | Checked or multi-limb capacity selected explicitly, poisoned-snapshot tests, wide named-profile regression, recumbency source gate passes. |
| P1 timing | Explain the CI adjacency timing failure. | Same build/CPU configuration, valid controls and generated-code evidence, then unchanged statistical gates. |
| P1 integration | Implement quantized encrypted `max(a,b)`. | Certified difference corridor; encrypted selector for `d>0`; `b+selector*d`; ties, signs and chart crossings; measured depth and phase bounds. Clear ordering identities alone do not meet this gate. |
| P1 assurance | Reconcile ignored tests and public claims with actual call paths. | Per-test rationale, active-path tests restored, no unsupported depth/security claims. Independent estimator artifacts bound to the exact parameter tuple. |

These are implementation tasks within the commissioned work, not requests for
another finished implementation upload. The current changes repair admission
and evidence integrity while preserving the fixed-basis objective. They do not
complete the encrypted recumbent port or authorize public refresh.

## Reproduction and evidence

The new `single_modulus_admission` integration target and the noise-budget and
homomorphic unit groups run in both profiles in `exactness_focused.yml`.
The existing full-library and fuzz jobs remain independent required evidence.

```sh
cargo test -p nine65 --test single_modulus_admission
cargo test -p nine65 --release --test single_modulus_admission
cargo test -p nine65 --lib noise::budget::
cargo test -p nine65 --lib ops::homomorphic::tests::
cargo test -p nine65 --lib --release
cargo clippy -p nine65 --lib --test single_modulus_admission -- -D warnings
bash scripts/check_no_panics.sh ratchet
python3 scripts/check_residue_native_architecture.py
```

Validation results and hashed logs are recorded in `evidence/validation.json`.

Focused results: all 3 new integration regressions pass in debug and release;
all 18 budget tests and 24 homomorphic unit tests pass in debug. Clippy with
warnings denied, formatting, the panic ratchet, and the 14-file architecture
scan pass. The separate recumbency capacity scan still fails its two historical
sentinel pattern classes; it is not relabelled as a pass.

The full `nine65 --lib --release` run reports **1,017 passed, 4 failed,
135 ignored**, versus the prior **1,013 passed, 4 failed, 138 ignored**.
The four failure names are unchanged: the triple-precharge terminal preflight,
the secure-128 and secure-192 symmetric depth benchmarks, and the secure-128
zero-noise constant self-square control. The new capacity regression and the
three restored budget tests account for the four additional passes. The full
run also covers the affected budget and homomorphic groups in release.

The local libFuzzer executable was built with stable Rust without sanitizer or
coverage instrumentation. All 64 valid seeded 32-byte inputs completed, including
both previously reported scalar pairs, within a 256-iteration invocation.
Subsequent mutations can be rejected by `Arbitrary` decoding; 256 is not a claim
of 256 valid arithmetic cases. This is seeded smoke evidence, not a replacement
for the nightly instrumented Fuzz Smoke CI job. The seed corpus is archived
alongside the logs.
