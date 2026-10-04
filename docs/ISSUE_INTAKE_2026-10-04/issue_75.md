# Issue #75: [G1] Run external lattice-estimator attestation for all shipped parameter sets

- state: open
- labels: gap-remediation, critical, security
- created: 2026-08-30T22:14:27Z  updated: 2026-09-04T09:44:40Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/75

---

**Priority**: Critical / Blocking
**Source**: NINE65 v7 Comprehensive Compendium (2026-08-30 audit), §8.1
**Evidence**: `docs/CLAIM_SURFACE_AND_LIMITS` §2.5

## Gap
No external lattice-estimator attestation. Security claims for shipped N=8192/16384 tuples are unverified.

## Impact
Security claims for shipped parameter sets cannot be independently confirmed.

## Remediation
Run `lattice-estimator` (SageMath) for each shipped tuple; archive raw input/output.

## Acceptance Criterion
Archived artifact with exact tuple, estimator version, and raw output for all 4 shipped parameter sets.