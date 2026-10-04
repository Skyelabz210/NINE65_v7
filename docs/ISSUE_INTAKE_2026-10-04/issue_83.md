# Issue #83: [P1] Make bootstrap security validation exact and non-tautological

- state: open
- labels: (none)
- created: 2026-08-31T07:09:07Z  updated: 2026-09-04T09:44:15Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/83

---

## Finding

`validate_bootstrap_primes` labels its third gate as a security check, but it currently:

1. estimates `log2(Q)` by **summing per-prime bit lengths** rather than taking the exact product bit length, and
2. `BootstrapKey::generate` calls it with `target_security = boot_log_q`, where `boot_log_q` is computed by the **same summed-width formula**.

That means the security-size portion of the validation is satisfied by construction and does not validate the configured security claim or Ring-LWE hardness. The source comment says LWE security is validated separately, but this call path itself does not establish that property.

## Required fix

1. Replace summed per-lane widths with the exact bit length of the exact boot-prime product.
2. Separate structural validation (prime, NTT compatibility, distinct/coprime lanes) from security screening.
3. Screen each concrete boot chain using the same explicit secret/error assumptions as the work configuration.
4. Run both Core-SVP and MATZOV in-tree screens and the factorization-aware screen; a structural refusal must fail closed for a named production path.
5. The required security target must come from the work/config security contract, not from the modulus being validated.
6. Include the boot tuple in the external estimator artifacts required by #75.
7. If this helper is only a modulus-structure validator, rename it accordingly and remove security language rather than leaving a tautological gate.
8. Preserve exact integer arithmetic throughout.

## Regression tests

- Exact `Q_boot` bit length where summed lane widths overcount.
- An intentionally under-secure boot tuple that is structurally valid but must fail the security screen.
- A malformed/non-coprime/non-NTT tuple rejected before screening.
- Every shipped work config maps to the exact boot tuple expected by `ClockworkBootstrap::new` and receives an archived screen result.
- Constructor/security-gate outputs agree with the report surfaced to users.

## Mandatory before/after performance evidence

Record before/after integer timings for `ClockworkBootstrap::new`, bootstrap key generation, and one refresh per named config. The estimator may run at construction/keygen time but must not enter the evaluation hot path. Attach exact correctness results and timing medians from the same machine/toolchain/features.

## Completion condition

No bootstrap path may describe `log2(Q_boot) >= target` as a security validation when `target` was derived from that same `Q_boot`. Security screening must consume the declared security contract and exact tuple.