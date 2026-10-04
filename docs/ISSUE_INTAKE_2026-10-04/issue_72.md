# Issue #72: [G3] Close open constant-time findings F-2 and F-3

- state: open
- labels: gap-remediation, critical, security
- created: 2026-08-30T22:14:27Z  updated: 2026-09-04T11:07:22Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/72

---

**Priority**: Critical / Blocking
**Source**: NINE65 v7 Comprehensive Compendium (2026-08-30 audit), §8.1
**Evidence**: F-2 (2.96× variance in `mod_switch_down_dual`), F-3 (0.60% in `extract_k`)

## Gap
Public constant-time not fully closed. 2 of 11 CT findings remain open; source-level CT does not close hardware leakage channels (cache timing, address traces).

## Impact
Timing side-channel remains exploitable.

## Remediation
Replace `U256::div_mod_u64` with CT alternative; adopt `AdjacencyKElim` for F-3; complete CT-NTT/cache gates.

## Acceptance Criterion
All gates pass `t < 5`; address-trace evidence collected; disassembly reviewed.

## Related
Overlaps with #18 (Security audit - constant-time verification and side-channel hardening).