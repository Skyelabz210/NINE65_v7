# NINE65 Audit Remediation Record — 2026-07-13

## Scope

This record maps the July 13 physical audit and subsequent source audit to the current v8 codebase and branch `audit/remediate-2026-07-13`.

The findings were:

1. the former `secure_128` tuple (`N = 4096`, three approximately 30-bit lanes) was independently estimated below its 128-bit name;
2. unrefreshed chains produced decryption mismatches at finite depth;
3. statistical auto-bootstrap failure did not control process exit status;
4. refresh could be selected after an over-budget multiplication;
5. large RNS products were saturated into `u128::MAX`;
6. `FHEConfig::custom()` accepted `t >= q_i`;
7. the main noise ledger still summed lane bit widths instead of measuring the exact product quotient.

Parameter attestation, arithmetic correctness, and execution mode are separate gates. A finite leveled-FHE ceiling is not an unlimited-depth result.

## Resolution matrix

| Finding | Remediation | Status |
|---|---|---|
| Former `secure_128` tuple screened below its name | `secure_128` now uses `N = 8192` with the same three-lane RNS chain. Named production profiles use exact full-chain bit length, strict internal claim screening, HE-bound enforcement, and an audited `N >= 8192` floor. | Code corrected; independent exact-tuple attestation remains required |
| Depth mismatch | The harness separates `no_bootstrap`, `clockwork_manual`, and `clockwork_auto`. | Code corrected; runtime gate pending |
| Simulated refresh | Counter-only reset was removed. Refresh modes execute real `ClockworkBootstrap` and report `simulated_refreshes = 0`. | Code corrected; runtime gate pending |
| Statistical failure exited successfully | `overall_correct = depth_correct && statistical_correct` when statistical testing is requested. | Code corrected; CI assertion added |
| Multiplication occurred before budget preflight | Manual and automatic paths check exact integer operation cost and trigger state before ct×ct. Insufficient post-bootstrap budget fails closed. | Code corrected; runtime gate pending |
| Auto flag bypassed auto evaluator | Auto mode executes `AutoBootstrapEvaluator::mul_auto` over live DualRNS ciphertexts. | Code corrected |
| ct×ct timing mislabeled K-Elimination | Timing calls `RNSFHEContext::mul_dual_public` and reports `DualRNS + K-Elimination`. | Code corrected |
| Addition exhaustion was ignored | Checked addition propagates refresh and budget errors. | Code corrected |
| Saturated large RNS products | Added checked scalar projection, exact dynamic little-endian limbs, exact bit length, and fail-closed scalar access. | Code corrected; boundary tests added |
| Invalid custom plaintext modulus | Custom construction requires `2 <= t < q_i` for every field lane. | Code corrected; boundary tests added |
| Summed lane widths in noise tracking | Fresh and post-bootstrap budgets now derive from exact multi-limb `floor(Q / t)` bit length. | Code corrected; focused tests and CI gate added |
| SBNI shape and entropy assumptions | SBNI validates entropy, lane count, modulus range, limb count, and limb length before mutation. | Code corrected |
| Floating-point reporting | Remediated paths use integers or exactly scaled integer inequalities. | Code corrected |

## Exact modulus and noise accounting

The ordered RNS prime vector is the canonical full ciphertext modulus representation. Large products are represented as exact dynamically sized little-endian `u64` limbs.

The parameter API provides:

- `try_rns_product() -> Option<u128>` for checked scalar projection;
- `rns_product_limbs()` for the exact full product;
- `rns_product_bit_length()` for exact size accounting;
- fail-closed `rns_product()` for callers with a proven `u128` precondition;
- exact multi-limb division by `t` for quotient-size accounting.

The noise ledger independently computes the exact limbs of `Q`, divides them by `t`, and uses the exact quotient bit length for fresh and post-bootstrap budgets. Per-prime bit-width sums cannot drive these decisions.

Boundary tests cover products below, equal to, and above `u128::MAX`. The equality vector uses:

```text
2^128 - 1 = (2^64 - 1) × 274177 × 67280421310721.
```

No saturated or wrapped scalar product may influence noise, capacity, security, route selection, or boundary decisions.

## Security parameter handling

The in-tree estimator is a deterministic integer engineering screen, not an independent lattice-security certificate.

- `secure_128` and `secure_128_deep` now both use `N = 8192`.
- `secure_192` and `secure_256` retain `N = 16384`.
- Test profiles below 128 bits can construct in test/debug modes but can never satisfy production-safety guards.
- Every external named-security claim requires the estimator version, attack model, distributions, ring dimension, ordered modulus chain, and raw output artifact.
- Disagreement is resolved in favor of the lower reproducible result.

The benchmark defaults to `secure_128_deep` as the conservative audit workload. That default does not make the profile independently attested.

## Depth semantics

1. **No bootstrap** — finite leveled-FHE survey.
2. **Manual Clockwork bootstrap** — explicit pre-operation refresh.
3. **Automatic Clockwork bootstrap** — evaluator-managed pre-operation refresh.

A requested depth passes only when every completed step decrypts exactly, every required refresh succeeds, operation cost is preflighted, and any requested statistical trial set has zero failures.

## CRAM / RNS invariants

- Ciphertext state remains resident in DualRNS main and anchor lanes.
- ct×ct rescaling remains on K-Elimination.
- NTT lanes remain prime CLASS-F lanes.
- Anchor and boundary routes remain CLASS-R with coprimality and explicit range requirements.
- Garner reconstruction and mixed-radix conversion are excluded from the hot path.
- Number-line values are emitted only at explicit decryption or boundary projection.

## Verification gate

`.github/workflows/audit_remediation.yml` is configured to:

- reject floating-point tokens in remediated paths;
- assert statistical correctness controls overall exit status;
- assert exact quotient-size noise accounting is active;
- assert `secure_128` contains the audited `N = 8192` dimension;
- run Rust formatting and benchmark compilation;
- run exact product, security-profile, noise-budget, SBNI, and auto-bootstrap tests;
- execute leveled and real automatic-refresh benchmark smoke runs;
- require exact decryption, zero statistical failures, and zero simulated refreshes.

## Merge state

No GitHub Actions run is attached to the current connector-authored head. Static and Python integer-oracle checks are not substitutes for Rust compilation or execution.

The branch remains draft and must not merge until:

1. formatting and compilation pass;
2. exact parameter, security-profile, noise, SBNI, and bootstrap tests pass;
3. leveled and automatic-refresh smoke runs pass;
4. independent estimator artifacts exist before any external named-security claim.