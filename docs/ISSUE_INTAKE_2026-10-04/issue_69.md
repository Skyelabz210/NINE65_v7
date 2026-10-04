# Issue #69: [L1] Fix 4 compiler warnings (unused variables, dead code)

- state: open
- labels: gap-remediation, hygiene, low-priority
- created: 2026-08-30T22:14:00Z  updated: 2026-09-04T09:09:46Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/69

---

**Priority**: Low
**Source**: NINE65 v7 Comprehensive Compendium (2026-08-30 audit), §8.4
**Evidence**: Unused variables in `debug_secure_256.rs`, `max_noise_resilience_test.rs`; dead code in `fhe-service`

## Gap
4 compiler warnings — minor code hygiene.

## Remediation
Fix or prefix with underscore.