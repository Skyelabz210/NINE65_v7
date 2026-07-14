# CRAM-Enhanced FHE Exploratory Harness Plan

Status: exploratory, evidence-producing, non-promotional.

This plan converts the current CRAM/NINE65 interpretation into falsifiable experiments. A claim is not promoted because it is architecturally plausible. It is promoted only when the corresponding harness produces reproducible evidence on pinned code, hardware, parameters, and workload.

## Global evidence contract

Every run records:

- repository and commit;
- dirty-tree status;
- Rust toolchain and compiler target;
- operating system, kernel, CPU model, logical CPUs, and memory;
- build profile and enabled features;
- FHE configuration, ring dimension, plaintext modulus, main primes, anchor primes when exposed, eta, claimed security, and estimator identity;
- random seed;
- complete workload sequence;
- refresh kind: none, simulated, or real bootstrap;
- refresh timing: pre-operation or post-operation;
- operation timings in integer nanoseconds;
- correctness after every checked operation;
- exact expected and decrypted residues;
- deterministic budget-accounting state;
- candidate winding counters, explicitly labeled as hypotheses until linked to a production winding witness;
- key-switch and relinearization structure observed from the active key type;
- all errors and early stops.

No floating-point quantity is load-bearing. Ratios are stored as exact numerator/denominator pairs, permille integers, or integer nanoseconds.

## Claim classification

| ID | Claim under test | Current source observation | Required test | Promotion gate |
|---|---|---|---|---|
| H01 | Depth failure is an off-by-one winding-wall event rather than a multiplication/rescale defect | Current `NoiseBudget` is a deterministic millibit estimator; it does not presently expose a ciphertext winding witness | Trace every operation, decrypt every step, record multiplication count, budget state, candidate wall, route, level, mismatch delta, and rescale outcome | Failure depth and mismatch must be predicted exactly across seeds, messages, configs, and workload order by the winding model, while competing rescale/error models fail |
| H02 | Each multiplication consumes one winding unit and additions consume zero | Current budget code assigns nonzero costs to add and add-plain; displayed percentages can hide small decrements | Run add-only, mul-plain-only, ct-mul-only, and interleaved traces with unrounded millibits and candidate winding counters | Exact one-unit correspondence across all multiplication routes and zero state change for additions in the production winding witness |
| H03 | The observed 12-percent decrement is exact and invariant | Percentage output is rounded and configuration dependent | Record exact before/after millibits and rational decrement for every operation/config | Identical reduced fraction across seeds and configurations, or claim is narrowed to the configurations where it holds |
| H04 | Refresh is a carry event restoring a fixed 93-percent state | `reset_after_bootstrap` computes a configuration-dependent post-bootstrap budget | Compare real bootstrap, simulated reset, and no-refresh traces; distinguish pre/post trigger timing | Real bootstrap correctness and measured post-refresh state match the carry model across configurations; simulated refresh is never counted as real evidence |
| H05 | K-Elimination replaces relinearization/key switching with zero auxiliary components | Current `DualRNSEvalKey` contains relinearization components, a decomposition base, and a digit count | Structural inventory plus per-stage timing/instrumentation of tensor, rescale, relinearization, and key switch | Active multiplication path demonstrates no auxiliary decomposition or relinearization use; otherwise claim is rejected or narrowed |
| H06 | Security follows a CRAM validity product | Current parameter validator labels its estimate rough and recommends an LWE estimator | Compare claimed bits, HE-standard bounds, repository estimator output, optional external LWE-estimator output, and the validity product as separate metrics | Independent RLWE/LWE analysis supports the same security estimate; validity product alone is never reported as cryptographic security |
| H07 | Increasing N to 8192 repairs secure_128 | Security and performance depend on full parameter set, not N alone | Compare validated candidate sets at N=4096 and N=8192 with identical estimator and correctness workloads | At least 128-bit target under the selected independent estimator, full correctness, and measured cost reported |
| H08 | Adding primes increases security without adverse effect | Increasing log(Q) can reduce RLWE security for fixed N even while increasing noise capacity | Sweep prime-chain variants using one security estimator and one depth harness | Candidate must meet both security and correctness gates; no monotonic-security assumption |
| H09 | Composite or power-of-two moduli improve NTT performance | NTT requires compatible roots and invertibility; primality and ring structure affect correctness | Candidate-modulus validator, forward/inverse NTT round trip, convolution differential test, and throughput test | Exact round trip and convolution at scale, security compatibility, and measured speedup |
| H10 | Clockwork refresh costs about 143 microseconds | Existing harness can perform simulated resets unless real bootstrap keys are enabled | Tag every refresh as simulated or real and benchmark real bootstrap separately | Same-machine real-bootstrap distribution with full metadata and correctness |
| H11 | NINE65 outperforms SEAL, OpenFHE, or TFHE-rs | Existing tables use different machines, schemes, security levels, packing, and operations | Common-result schema and strict compatibility key | Same hardware, equivalent security/function/packing, identical sample policy, and raw artifacts |
| H12 | Wasan key storage reduces key generation to lookup | No production evidence yet | Separate cold key generation, validated persistent loading, integrity verification, and warm retrieval | End-to-end key validity and security preserved; storage is not described as key generation |
| H13 | The 216-op registry collapses circuit depth | No closed-composition equivalence evidence yet | Compile registry compositions and differential-test against direct circuits over exhaustive small domains and production samples | Exact semantic equivalence and lower measured expensive-operation count |

## Harness layers

### Layer A: source and architecture inventory

`scripts/cram_claim_inventory.py` scans active source files and emits machine-readable evidence for structural claims, including:

- relinearization key components and decomposition fields;
- simulated-refresh branches;
- real-bootstrap paths;
- benchmark floating-point tokens;
- rough-security-estimator warnings;
- reconstruction or scalar materialization language in active paths.

This layer establishes what the current implementation actually contains. It does not establish runtime behavior.

### Layer B: real FHE hypothesis probe

`cram_exploratory_probe` runs real Dual-RNS operations and emits a step trace. Supported dimensions include:

- configuration;
- workload;
- chain depth;
- seed;
- real refresh policy;
- trigger threshold;
- pre-operation versus post-operation refresh;
- explicit candidate wall;
- per-step decryption checks.

The probe keeps the repository noise estimator and the candidate winding model separate.

### Layer C: matrix orchestration

`scripts/run_cram_exploratory_matrix.py` executes a declared matrix and stores one JSON result per case plus a manifest. It must not infer success from process completion alone; each result's correctness and error fields are evaluated.

### Layer D: comparative analysis

`scripts/cram_compare_results.py` consumes normalized result documents from NINE65 and external implementations. It compares only records with an identical compatibility key:

- semantic operation;
- scheme and plaintext semantics;
- target security and estimator;
- polynomial degree;
- ciphertext modulus bits;
- packing/slot count;
- hardware and thread count;
- compiler profile;
- refresh kind;
- sample policy.

Nonmatching records are reported as incomparable, not ranked.

## Required workload families

1. `add_only`: repeated ct+ct with fresh fixed right operand.
2. `mul_plain_only`: repeated plaintext multiplication.
3. `mul_ct_only`: repeated ct×ct with a fresh fixed right ciphertext.
4. `interleaved`: multiply, add, add, multiply pattern.
5. `audit_chain`: exact operation sequence used by the current audit JSON.
6. `threshold_sweep`: trigger thresholds from 0 to 500 permille.
7. `pre_post_refresh`: identical sequence with refresh before and after the risky operation.
8. `seed_sweep`: deterministic seeds selected before execution.
9. `message_sweep`: zero, one, t-1, midpoint, and deterministic random messages.
10. `parameter_sweep`: secure_128, secure_128_deep, secure_192, secure_256, plus explicitly named experimental candidates.

## Required output distinctions

The report must never merge these categories:

- accounting budget versus measured correctness;
- candidate winding count versus a verified production winding witness;
- simulated refresh versus real bootstrap;
- plaintext multiplication versus ciphertext multiplication;
- basic single-modulus BFV versus Dual-RNS multiplication;
- claimed security versus estimator result;
- cold key generation versus persisted-key retrieval;
- same-machine comparison versus published cross-machine figures.

## Stop conditions

A run stops and records evidence when:

- an FHE operation returns an error;
- decryption differs from the exact expected plaintext;
- a real bootstrap fails;
- an architectural counter is nonzero;
- output metadata is incomplete;
- a comparison compatibility key differs.

Exploratory failures remain artifacts. They are not deleted, rounded away, or converted into successful averages.
