# NINE65 v7: October 17 gate reconciliation and expansion

**Reviewed remote base:** `main@89d641b35b355f3cd9ddbcd7437df7c2f87ade81` (October 14, 2026).
**Authority:** `docs/execution/2026-10-03/tasks.json` and its 43 task contracts; `docs/execution/2026-10-06/SESSION_PLAN.md`; `TODO.md`. This is a dated additive crosswalk, not a replacement queue or an acceptance statement.
**Evidence level:** code and hosted-log inspection. No new Rust or crypto acceptance suite was executed for this review.

## 1. Corrections to the September WR-0..WR-9 quick reference

| September item | October disposition | Live owner / acceptance |
| --- | --- | --- |
| WR-0 CI/evidence | **Partially restored**: Actions execute on `main`; required release checks and branch rulesets remain open | F00, F02, G00, V05; #79, #92, #64, #137 |
| WR-1 exact integration | **A main-only exact route exists** in `ops/exact_mul.rs`; general public `mul` and the dual/auto path still do not universally route through it | C00, C01, C02, C06, B01; #157, #158, #176 |
| WR-2 differential/WIRE-Q | **In progress**: main-only tensor path has its own implementation and tests; public service/wire and caller closure remain | C03, C04, F02, B01; #29 and related |
| WR-3 fixed work | Source-level work and CT workflows exist; completed CT workflow does not certify hardware constant time for every path | V01, V02; #18, #72 |
| WR-4 lifted transduction | Lift/operator work exists, but the intact S8 priming-root and live sister-frame source/epoch contract are still acceptance gates | S00-S05, #159, #184 |
| WR-5A/B sampler/security | Source includes a full-Q bootstrap mask test and parameter screens; issue closure still requires current-tuple reproducibility and external assessment | R00-R03, V00, #82, #83, #75 |
| WR-5C public bootstrap | **Blocked**: legacy Phase 1 is fail-closed because encrypted displaced carry/digit-removal is absent | R01, R02, B00-B07, #95, #117 |
| WR-6 auto refresh | A per-ciphertext ledger implementation exists, but public tracking is forgeable and uses a legacy dual path; eligibility must be bound to certified lineage | C02, C03, B08, B09, #93 historical |
| #16 / #73 stress-depth | **Blocked**: GSO repeated-square depth 4 and checked dual decrypt still have concrete wrong-plaintext gates | #157, #158, #176, B09, F02 |
| WR-7/8/9 security, API, claims | Continue in parallel; promotion requires final SHA-bound evidence | V00-V05, C03-C05, G00; #75, #86, #88, #94, #178 |

## 2. Confirmed current-head hosted results

At `89d641b` the CI T1 static and fast jobs pass; T2 full workspace test fails. The `nine65 --lib` test summary in the T2 job is **943 passed, 8 failed, 125 ignored**. The exactness-focused and constant-time workflow *jobs* succeeded, without establishing a release-wide pass. No repository rulesets were returned by the GitHub rulesets read.

* [Main CI run 38517099674](https://github.com/Skyelabz210/NINE65_v7/actions/runs/38517099674) records the test failures.
* [Fuzz Smoke 38517099707](https://github.com/Skyelabz210/NINE65_v7/actions/runs/38517099707) records wrong encrypted roundtrip (`59905 -> 59902`), a deserialization allocation attempt of `0x17ffffe8f0` bytes, and homomorphic fuzz failure.
* [Residue-native 38517099728](https://github.com/Skyelabz210/NINE65_v7/actions/runs/38517099728) reports 21 prohibited occurrences in `cram_ct.rs` and `ops/bootstrap.rs` (the gate scans 11 files). Preserve this red check while classifying *reachable production*, *disabled legacy*, *test-only*, and *oracle* code paths.
* [Comparative 38517099755](https://github.com/Skyelabz210/NINE65_v7/actions/runs/38517099755) fails compilation because its comparison-only `allow_insecure` feature is forbidden in release builds. The paired workflow change in this PR moves only its correctness smoke to debug. The release comparison runner and scale-sweep workflow need separate remediation, not a relaxed release gate.

## 3. New acceptance refinements and missed coupling

### P0-A: Close arithmetic correctness before noise/depth attribution

Owner: F02/C01/B01, issues #157/#158/#176. Reproduce **first erroneous coefficient and first erroneous operation**, preserving the exact tuple, input, seed, intermediate main-Q components and oracle. Distinguish errors from (a) BFV component scale/round, (b) relinearization/key switch, (c) mod-Q wrap/phase loss, and (d) decryption or message encoding. Compare clear integer reference and test-only BigInt/RNS reconstruction oracle, then require exact decrypt equality at *every* depth. For a discovered supported-bound crossing, return a typed refusal **before** wrong plaintext. Never count attempted operations as correct depth.

Specific fixtures: zero-fresh-error signed ±1, t-neighbor representatives, exact rounding ties, nonzero Gaussian error, main basis permutations, `Q*t` u128/U256 transitions, and changing plaintext modulus. Record first divergence separately for ciphertext phase, oracle plaintext, and available noise bound.

### P0-B: Bind operation history and capacity certificates to immutable context

Owner: C01/C02/C06/B01. `ExactMulEvaluator::try_mul_no_relin_exact_observed` derives auxiliary tensors before multiplication and uses the N/2 bound for the summed cross term. Keep that coherence. The raw scaler can only trust bounds that originate from a sealed producer, not arbitrary caller arrays.

`TrackedCiphertext` currently exposes `pub ct` and `TrackedCiphertext::fresh(ct, config)` publicly while its noise ledger is private. A caller can mutate ciphertext components or re-wrap an old ciphertext with a fresh budget. Before claiming automatic budget correctness, replace arbitrary public construction with a checked fresh-encryption producer and a separate *untrusted/imported* state that receives no unearned budget. The certificate should bind parameter fingerprint, key/epoch identity, modulus level, encoding, ciphertext component shape, operation id/parent ids, and certified conservative noise bound. Reject mismatches, cycles, forged flags, stale key epochs and cross-config operands.

Tests: mutate public ciphertext then request refresh; re-wrap deep ciphertext; clone/diverge DAG branches; use ciphertext from another key/tuple; swap main prime order; import/export and replay. Every case yields a validated result or an early typed refusal. No public verifier assumes decryption secrets.

### P0-C: Treat complete public refresh as a new admitted encrypted circuit

Owner: R00-R03, B00-B09, #95/#117. Maintain `public_phase1_soundness_gate` until a verified encrypted circuit computes the missing nonlinear displaced quotient/carry, or an explicitly specified BFV-preserving digit-removal equivalent. Exact CRT lifting of public components is **representation**, not an encrypted BFV decryption/rounding circuit. A secret-key reference helper may be used *only as a test oracle*, never in the public evaluator.

Acceptance stages: (1) algebraic map and signed carry/radius certificate, (2) circuit with encrypted input and no evaluator decryption secret, (3) independent same-prime encode/contract oracle and key-epoch proof, (4) refreshed `Enc(9)`, squared `Enc(3)` then refresh, added `Enc(3)+Enc(6)` then refresh, (5) multiply-refresh-multiply-refresh all coefficients for every admitted tuple, (6) invalid tuple, capacity/noise/key/serialization refusals, (7) external security attestation for *complete* keys and tuple. Refuse public refresh on unsupported parameters regardless of parameter-only headroom predicate.

### P0-D: Distinguish dual legacy state from publishable WIRE-Q interfaces

Owner: C00/C03/C04/S05. `auto_bootstrap.rs::mul_auto` still invokes `mul_dual_public`; `TrackedCiphertext` owns a `DualRNSCiphertext`. Inspect service exports, key serialization, key switching, Galois/bootstrap keys and roundtrips as one public secret-dependent surface. Enforce main-Q-only published objects. Operation-local auxiliary residues are permitted with same-X provenance, checked capacity, and secure scratch disposal; persistent coprime lanes are not. Keep refusals until compatible main-only key and ciphertext objects are admitted.

### P0-E: Release gates must be executable, mandatory, and scoped

Owner: G00/V05/#79. Define separate required-check names for (i) mandatory correctness/serialization/fuzz, (ii) architecture/claim policy, (iii) security estimation/CT at defined scope, and (iv) optional experimental benchmarks. Do not make a mandatory success depend on skipped jobs or `continue-on-error` without an enforcement step. Pin SHA and Rust toolchain per result. Add a main-branch ruleset after jobs are stable; the current repo returned none. Require the same gates on bot/human commits.

### P1-F: Resource-adversarial parsing and feature-safe benchmarking

Owner: #86/#178/#94, F02/V04. Bound byte length, declared vector counts, all decoded multiplication products, allocations, and trailing bytes **before** construction; reject malformed or context-invalid keys/ciphertexts. Preserve crash/oom fuzz cases as regression corpus. Benchmark harnesses must separate (A) debug, comparison-only insecure *correctness* fixtures and (B) release, production-admitted *performance* configurations. Include config fingerprint, compiler, CPU, feature set, original ciphertext equality and per-op time distribution. Never compare debug timing against release or promote an invalid-depth completion count.

### P1-G: Reconcile A1/WASSAN semantics

Owner: #184/S00-S05. Distinguish polynomial-ring coefficient addition from positional integer addition. Add checked digit capacity and explicit inter-digit carries; test maximum u64 moduli, dimension zero, carry chains and exact conversion boundaries. Symbolic `phi` is a nomenclature issue until an executing numeric path is demonstrated. Keep this independent of CRAM's WIRE-Q rules.

## 4. Updated release-directed DAG

```text
F00 -> F02 -> {C00,C01,C06, #157/#158/#176, fuzz regressions}
                   |
                   +-> C02 provenance -> C03 WIRE-Q -> C04 service -> C05 binding
                   |                             |
S00 -> S01 -> S02 -> S03 -> S04 -> S05 ----------+
                   |                             |
                   +-> R00 -> R01 -> R02 -> R03 -> B00 -> B01
                                                          |
                                            B02 -> B03 -> B04 -> B05 -> B06
                                                                    |
                                                                    v
                                                                    B07 -> B08 -> B09
V00 parameter/security ------------------------------> R03 and B07 admission
G00 hosted CI ------------------------> each accepted milestone and V05 release
V01/V02 side-channel + V03/V04 performance + external audit -------> V05
H00 -> H01 -> H02 -> H03 -> H04 (separate Three Locks milestone)
```

The diagram is an acceptance **view**, not a rewrite of `tasks.json`'s validated dependencies. Parallel roots can proceed now. Any artifact implying success must be checked against the authoritative task card, result schema, dependency closure and independent review before marking accepted.

## 5. Evidence packet schema to require at each gate

Store a machine-readable result with: `{ source_sha, parent_sha, toolchain, cargo_lock_sha, task_id, config_fingerprint, key_epoch_if_applicable, build_profile, features, command, start/end, exit_code, pass_count, fail_count, ignore_count, skipped_count, log_hashes, oracle_inputs, first_divergence, reviewer, disposition }`. Use `PASS`, `FAIL`, `BLOCKED`, or `UNRUN` with unambiguous meaning; do not silently convert `BLOCKED` into `PASS`. For hardware CT include architecture, compiler flags, executable hash, classification of secrets and repeated measurement methodology.

## 6. Follow-on changes (separate tickets or existing owners)

1. #137/#86: reproduce both fuzz cases and persist minimized seeds with resource caps; fix imports before transport exposure.
2. #157/#158/#176: provide coefficient-first arithmetic trace before another depth report.
3. [#189](https://github.com/Skyelabz210/NINE65_v7/issues/189) / C02/B08: make noise lineage impossible to reset by public wrapping or mutation.
4. C03/S05: map source reachability of all 21 residue-architecture findings, then remove or isolate production violations without disabling scanner coverage.
5. [#190](https://github.com/Skyelabz210/NINE65_v7/issues/190) / F02/G00/#79: repair remaining release-insecure comparative/scale runners and configure required branch checks.
6. R00-R03/B00-B09: mathematical encrypted Phase-1 circuit, certified tuple and all-coefficient repeated refresh; retain the public fail-closed gate meanwhile.

**Boundary preserved:** exact integer/residue runtime; no Garner/MRS evaluator reconstruction; heterogeneous Safe Basis including composite operator lanes where valid; WIRE-Q published-state partition; typed failures; no depth/security/performance claims without reproducible source-bound evidence.