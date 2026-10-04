# Issue #73: [H1] Increase public-mode depth beyond 2-4

- state: open
- labels: enhancement, gap-remediation
- created: 2026-08-30T22:14:27Z  updated: 2026-09-04T11:22:57Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/73

---

**Priority**: High
**Source**: NINE65 v7 Comprehensive Compendium (2026-08-30 audit), §8.2
**Evidence**: README "Current limits"

## Gap
Public-mode depth limited to 2-4 without refresh. Nonlinear public FHE beyond the direct boundary is not established.

## Impact
Limited multi-party use cases.

## Remediation
Increase Delta headroom; improve noise management; hybrid mode.

## Acceptance Criterion
Verified depth ≥5 on `secure_128_deep`.