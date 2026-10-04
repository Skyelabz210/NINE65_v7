# Issue #64: [G2] Make full test suite reproducible in constrained environments

- state: open
- labels: gap-remediation, testing, critical
- created: 2026-08-30T22:14:00Z  updated: 2026-09-04T11:16:21Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/64

---

**Priority**: Critical / Blocking
**Source**: NINE65 v7 Comprehensive Compendium (2026-08-30 audit), §8.1
**Evidence**: `cargo test` timed out at 10 min in 2 vCPU sandbox

## Gap
Full test suite not reproducible in constrained environments.

## Impact
CI may pass but independent verification is blocked.

## Remediation
Optimize test runtime; add a "fast smoke" suite; document expected runtime per config.

## Acceptance Criterion
`cargo test --release` completes in <30 min on 4+ vCPU.