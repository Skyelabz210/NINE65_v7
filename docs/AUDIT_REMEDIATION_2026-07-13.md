# NINE65 Audit Remediation Record — 2026-07-13

## Scope

This record maps the July 13 physical-audit findings and the subsequent source audit to the current v8 codebase and the corrective changes on `audit/remediate-2026-07-13`.

The initial audit reported two load-bearing concerns:

1. `secure_128` was estimated at 98 effective bits by the audit environment rather than the claimed 128 bits.
2. Unrefreshed depth chains produced decryption mismatches at depth 8 for `secure_128` and depth 5 for `secure_192` / `secure_256`.

The source audit then identified three additional correctness hazards:

3. statistical auto-bootstrap failure did not control the benchmark exit status;
4. manual and automatic refresh decisions could occur after an over-budget multiplication;
5. large RNS products were saturated into `u128::MAX`, and `FHEConfig::custom` accepted `t >= q_i`.

The remediation treats parameter attestation, arithmetic correctness, and execution mode as separate gates. It does not convert a finite leveled-FHE ceiling into an unlimited-depth claim.

## Resolution matrix

| Finding | Root condition | Remediation | Status |
|---|---|---|---|
| External audit estimates `secure_128` below 128 bits | The repository estimator and the external audit do not share a pinned estimator artifact and identical attack model | The audit benchmark defaults to `secure_128_deep` (`N = 8192`). `secure_128` remains a compatibility/comparison profile until an independent exact-tuple artifact is checked in. | Operationally mitigated; external attestation remains open |
| Depth 5–8 mismatch | A no-bootstrap chain was compared with an 80-operation target | The harness separates `no_bootstrap`, `clockwork_manual`, and `clockwork_auto`. Leveled mode stops before an operation the tracked budget cannot fund. | Resolved in code; runtime gate pending |
| Simulated refresh counted as bootstrap | The legacy harness reset only its software noise counter | Simulated refresh was removed. Refresh modes execute `ClockworkBootstrap`; JSON reports `simulated_refreshes = 0`. | Resolved in code; runtime gate pending |
| Statistical failures could exit successfully | Overall status read only `depth_chain.correct` | `overall_correct` is the conjunction of depth correctness and requested statistical correctness; either failure exits nonzero. | Resolved in code; CI assertion added |
| Multiplication occurred before budget preflight | Refresh was decided after ct×ct execution | Manual and automatic paths check `can_perform(mul + relin)` and the trigger before multiplication. A post-bootstrap budget that still cannot fund the operation fails closed. | Resolved in code; runtime gate pending |
| `--auto-bootstrap` did not drive the evaluator | The flag generated keys but the loop remained on the legacy path | Auto mode executes `AutoBootstrapEvaluator::mul_auto` over live DualRNS ciphertexts. | Resolved in code; runtime gate pending |
| ct×ct timing mislabeled K-Elimination | Timing used a basic single-modulus operation | Timing calls `RNSFHEContext::mul_dual_public` and reports `DualRNS + K-Elimination`. | Resolved |
| Addition-chain budget exhaustion was ignored | `add_auto` discarded `NoiseBudget::consume` errors | Added checked addition and pre-operation refresh; the compatibility wrapper fails loudly on refresh failure. | Resolved in code |
| Saturated large RNS products | `rns_product()` used saturating `u128` multiplication and fed the result into noise accounting | Added checked scalar projection, exact dynamic little-endian limbs, exact product bit length, and exact multi-limb division by `t`. Scalar access panics on overflow rather than saturating. | Resolved in code; boundary tests added |
| Invalid custom plaintext modulus | `FHEConfig::custom()` accepted `t == q_i` and `t > q_i` | Custom construction now requires `2 <= t < q_i` for every field lane. | Resolved in code; boundary tests added |
| SBNI shape mismatch / empty-source panics | The injector assumed valid entropy and limb dimensions | SBNI validates entropy, lane count, modulus range, limb count, and limb length before mutation. | Resolved in code |
| Floating-point benchmark and statistical reporting | Rates and distribution checks used binary floating point | Remediated paths use integers or exactly scaled integer inequalities. | Resolved in code |

## Exact modulus accounting

The canonical full ciphertext modulus remains the ordered RNS prime vector. Large products are handled as exact, dynamically sized little-endian `u64` limbs.

The parameter API now provides:

- `try_rns_product() -> Option<u128>` for checked scalar projection;
- `rns_product_limbs()` for the exact full product;
- `rns_product_bit_length()` for exact size accounting;
- fail-closed `rns_product()` for callers with a proven `u128` precondition;
- exact multi-limb division by the plaintext modulus for RNS noise-budget bit length.

Boundary tests cover products below, equal to, and above `u128::MAX`. The equality vector uses the exact factorization

```text
2^128 - 1 = (2^64 - 1) × 274177 × 67280421310721.
```

No saturated or wrapped scalar product is permitted to influence noise, capacity, security, routing, or boundary decisions.

## Security parameter handling

The in-tree estimator is an integer-only engineering screen, not an independent lattice-security certificate. Therefore:

- `secure_128_deep` is the conservative audit profile;
- named security claims require the exact estimator version, attack models, distributions, ring dimension, ordered modulus chain, and raw output;
- disagreement is resolved in favor of the lower reproducible estimate;
- HE Standard table compliance is necessary evidence, not complete attestation.

## Depth semantics

Three measurements remain distinct:

1. **No bootstrap** — a finite leveled-FHE survey.
2. **Manual Clockwork bootstrap** — explicit pre-operation refresh.
3. **Automatic Clockwork bootstrap** — evaluator-managed pre-operation refresh.

A requested depth passes only when every completed step decrypts exactly, every required refresh succeeds, the operation budget is preflighted, and any requested statistical trial set has zero failures.

## CRAM / RNS invariants

- Ciphertext state remains resident in DualRNS main and anchor lanes.
- ct×ct rescaling remains on K-Elimination.
- NTT lanes remain prime CLASS-F lanes.
- Anchor and boundary routes remain CLASS-R and are governed by coprimality plus explicit range.
- No Garner reconstruction or mixed-radix conversion is introduced into the hot path.
- Number-line values are emitted only at explicit boundary/decryption projection.

## Verification gate

`.github/workflows/audit_remediation.yml` is configured to:

- reject floating-point tokens in the remediated Rust paths;
- statically verify that statistical correctness controls overall exit status;
- run Rust formatting;
- compile the benchmark with `serde`;
- run exact parameter/product-boundary tests;
- run SBNI and auto-bootstrap unit tests;
- execute a leveled DualRNS smoke test;
- execute an automatic-refresh 100-trial statistical smoke test;
- assert `overall_correct = true`, zero statistical failures, and zero simulated refreshes.

## Merge state

No GitHub Actions run is attached to the connector-authored head at the time of this record. The Python structural harness passed delimiter balance, exactness-token checks, boundary arithmetic, and required control-flow assertions, but it is not a Rust compiler or runtime substitute.

The branch remains non-mergeable by policy until:

1. `cargo fmt --all -- --check` passes;
2. the benchmark and library compile;
3. the exact parameter, SBNI, and auto-bootstrap tests pass;
4. both benchmark smoke runs pass;
5. an independent estimator artifact is supplied before any external named-security claim.
