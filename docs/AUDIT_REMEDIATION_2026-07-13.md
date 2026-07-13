# NINE65 Audit Remediation Record — 2026-07-13

## Scope

This record maps the July 13 physical audit findings to the current v8 codebase and the corrective changes on `audit/remediate-2026-07-13`.

The audit reported two load-bearing concerns:

1. `secure_128` was estimated at 98 effective bits by the audit environment rather than the claimed 128 bits.
2. unrefreshed depth chains produced decryption mismatches at depth 8 for `secure_128` and depth 5 for `secure_192` / `secure_256`.

The remediation treats these as separate parameter-attestation and execution-mode questions. It does not convert an unrefreshed leveled-FHE ceiling into an unlimited-depth claim.

## Resolution matrix

| Finding | Root condition | Remediation | Status |
|---|---|---|---|
| External audit estimates `secure_128` below 128 bits | The repository's integer estimator and the external audit do not share a reproducible estimator artifact or identical attack model | The audit benchmark now defaults to `secure_128_deep` (`N = 8192`). `secure_128` remains available for compatibility and comparative testing, but external 128-bit attestation is not inferred from the in-tree estimator alone. | Fail-closed operational mitigation; independent estimator reconciliation remains required before an external 128-bit claim |
| Depth 5–8 mismatch | A no-bootstrap chain was compared with an 80-operation target | The benchmark now separates `no_bootstrap`, `clockwork_manual`, and `clockwork_auto`. No-bootstrap mode stops and returns failure at the first rejected multiplication, exhausted budget, or decryption mismatch. | Resolved |
| Simulated refresh counted as bootstrap | The legacy harness reset only its software noise counter while leaving the ciphertext unchanged | Simulated refresh was removed. Both bootstrap modes execute `ClockworkBootstrap`; JSON always reports `simulated_refreshes = 0`. | Resolved |
| `--auto-bootstrap` did not drive the auto evaluator | The flag generated keys but the depth loop continued on the legacy ciphertext path | Auto mode now executes `AutoBootstrapEvaluator::mul_auto` over live DualRNS ciphertexts. | Resolved |
| ct×ct timing labeled K-Elimination while measuring the basic single-modulus evaluator | Benchmark routing and reporting were inconsistent | ct×ct timing now calls `RNSFHEContext::mul_dual_public` with the evaluation key and reports `DualRNS + K-Elimination`. | Resolved |
| Addition-chain noise exhaustion could be ignored | `AutoBootstrapEvaluator::add_auto` discarded `NoiseBudget::consume` errors | Added `try_add_auto`; addition now refreshes on exhaustion or threshold crossing. The compatibility wrapper fails loudly if refresh fails. | Resolved |
| Invalid auto-bootstrap thresholds | Any `u32` threshold was accepted | Thresholds are restricted to `0..=1000` permille. | Resolved |
| SBNI shape mismatch / empty-source panics were non-local and poorly diagnosed | The injector assumed all limb and entropy dimensions were valid | SBNI now checks entropy, lane count, modulus range, limb count, and limb length before mutation. | Resolved |
| Floating-point benchmark and statistical reporting | Percentages, rates, and chi-square checks used binary floating point | All remediated paths use integer or exactly scaled integer comparisons. | Resolved |

## Security parameter handling

The current in-tree estimator is an integer-only engineering estimator. It is useful as a regression signal, but it is not a substitute for a reproducible external lattice-estimator run. Therefore:

- `secure_128_deep` is the default audit profile.
- `secure_128` must not be presented as externally attested solely because `HEStandardBounds::is_compliant` or the internal estimator returns a passing value.
- A release claim must include the exact estimator version, attack models, secret distribution, error distribution, ring dimension, full modulus chain, and output artifact.
- Any disagreement between an external estimator and the in-tree estimate is resolved in favor of the lower result until reproduced and reconciled.

This policy preserves exact arithmetic while separating arithmetic correctness from security estimation.

## Depth semantics

Three measurements are now kept distinct:

1. **No bootstrap** — measures the leveled-FHE ceiling. It is expected to terminate after a finite number of ct×ct multiplications.
2. **Manual Clockwork bootstrap** — executes a real refresh when the exact integer noise tracker reaches its trigger or the current level must be refreshed before retry.
3. **Automatic Clockwork bootstrap** — delegates every multiplication to `AutoBootstrapEvaluator` and records actual bootstrap count.

A requested depth is reported as achieved only when every completed step decrypts to the exact expected plaintext and no failure condition is present.

## CRAM / RNS invariants

The remediated benchmark remains recumbent:

- ciphertext state stays in DualRNS main and anchor lanes;
- ct×ct rescaling uses the K-Elimination path;
- no Garner reconstruction or mixed-radix conversion is introduced into the hot path;
- bootstrap and SBNI preserve the main/anchor lane relationship;
- all reported percentages and rates are integer quotients with declared truncation.

NTT lanes remain CLASS-F and use NTT-compatible primes. Anchor and boundary operations remain CLASS-R and require coprimality rather than unnecessary primality assumptions.

## Verification gate

`.github/workflows/audit_remediation.yml` performs the following checks:

- rejects floating-point tokens in the remediated Rust paths;
- checks Rust formatting;
- compiles the benchmark with `serde`;
- runs SBNI invariant tests;
- runs auto-bootstrap unit tests;
- executes a one-depth DualRNS benchmark smoke test and validates its JSON contract.

The audit branch is mergeable only after this gate and the repository's existing gates pass.
