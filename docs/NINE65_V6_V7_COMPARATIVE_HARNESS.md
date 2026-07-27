# NINE65 v6/v7 Comparative Harness

## Purpose

This harness answers two separate questions without conflating them:

1. Did the implementation become faster or slower between NINE65 v6 and v7 under the same arithmetic dimensions?
2. How much additional cost or benefit is introduced by the v7 DualRNS/CRAM execution path relative to the v7 legacy path under that same tuple?

The comparison is exploratory. It records observations and failures rather than encoding the optimization roadmap as an assumed conclusion.

## Shared comparison tuple

The cross-version regression run uses the v6 `secure_128` arithmetic shape:

```text
N                  4096
main moduli        998244353, 985661441, 754974721
plaintext modulus  65537
CBD eta            3
threads            1
build profile      release
```

v7 exposes this as `v6_compat_4096`. It is available only when the test-only `allow_insecure` feature is enabled. Its security claim is set to zero because current v7 production `secure_128` uses `N=8192`. The compatibility tuple is for implementation regression analysis, not production use or security ranking.

## Components

### `cram_comparative_probe`

The Rust probe executes the legacy BFV and DualRNS paths in one process with one compiler build, seed, parameter tuple, and machine. It reports integer nanosecond averages for:

```text
encrypt
decrypt
ciphertext addition
ciphertext subtraction, legacy path
ciphertext negation, legacy path
plaintext addition
plaintext multiplication
ciphertext multiplication
```

Every reported operation class has an explicit decrypt-and-compare correctness check. The probe also runs a ciphertext-squaring chain and records, per attempted depth:

```text
operation latency
level before and after
expected plaintext modulo t
decrypted plaintext
mismatch delta modulo t
operation error
correctness result
```

The probe records evaluation-key structure so that statements about auxiliary relinearization material can be tested directly:

```text
relinearization component count
decomposition base
decomposition digit count
```

It performs no bootstrap and reports no simulated refresh.

### `run_nine65_v6_v7_compare.py`

The Python runner builds and executes:

```text
v6: nine65_bench --config secure_128
v7: cram_comparative_probe --config v6_compat_4096
```

Both repositories are executed on the same host. The runner records:

```text
repository commits
hardware and OS metadata
exact commands
build logs
stdout and stderr
raw JSON outputs
integer timing samples
correctness failures
parameter-contract failures
```

It produces normalized `fhe-comparison-record-v1` records and passes them to `cram_compare_results.py`.

## Ranking rules

A latency ratio is emitted only when all of the following match exactly:

```text
operation
scheme
plaintext semantics
target security field
security-estimator identity
N
exact log2(Q) bit length
plaintext modulus
slot count
refresh kind
hardware fingerprint
thread count
build profile
sample policy
```

Both records must contain at least one correctness trial and zero failures. A failed correctness gate sets:

```json
{
  "ranking_allowed": false,
  "left_over_right_median": null
}
```

The v6 legacy and v7 legacy paths share a comparison group. The v7 DualRNS path remains in a distinct scheme group, preventing a direct ranking from being mislabeled as a like-for-like legacy regression.

## Local execution

Clone both repositories beside one another, then run from the v7 checkout:

```bash
python3 scripts/run_nine65_v6_v7_compare.py \
  --v6-root ../NINE65_v6_a_Clockwork_Prime/NINE65/NINE65_v6_a_Clockwork_Prime \
  --v7-root . \
  --output-dir artifacts/v6_v7_compare/local \
  --repetitions 7 \
  --iterations 100 \
  --mul-iterations 10 \
  --ct-mul-depth 8
```

For a rapid compile and correctness pass:

```bash
cargo build --release -p nine65 \
  --bin cram_comparative_probe \
  --features serde,allow_insecure

target/release/cram_comparative_probe \
  --config v6_compat_4096 \
  --iterations 2 \
  --mul-iterations 1 \
  --ct-mul-depth 2 \
  --output artifacts/v6_v7_compare/smoke.json
```

## Interpretation boundaries

The harness can establish:

- same-machine v6/v7 implementation regressions under the shared tuple;
- legacy-versus-DualRNS cost within the current v7 implementation;
- exact locations and deltas of depth-chain mismatches;
- whether current evaluation keys contain relinearization components and decomposition digits;
- whether a proposed optimization changes latency, correctness, memory metadata, or depth behavior.

The harness does not by itself establish:

- RLWE security strength;
- equivalence between the millibit budget ledger and a CRAM winding witness;
- industry-wide performance leadership;
- bootstrap performance, because this probe does not refresh;
- the correctness of arbitrary composite NTT moduli;
- the correctness or performance of Wasan HD or the 216-op registry before those paths exist and are separately instrumented.

Those remain separate hypothesis gates in the broader exploratory matrix.
