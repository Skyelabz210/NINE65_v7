# Issue #76: [H2] Resolve secure_256 naming vs MATZOV binding (240 vs 256)

- state: open
- labels: documentation, gap-remediation, security
- created: 2026-08-30T22:14:27Z  updated: 2026-09-04T09:44:34Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/76

---

**Priority**: High
**Source**: NINE65 v7 Comprehensive Compendium (2026-08-30 audit), §8.2
**Evidence**: `docs/CLAIM_SURFACE_AND_LIMITS` §2

## Gap
`secure_256` falls 16 bits short under MATZOV model (240 vs 256 claimed). Documented but not resolved.

## Impact
Name implies more security than the weakest model provides.

## Remediation
Rename to `secure_240` or add MATZOV-gated constructor.

## Acceptance Criterion
No name implies more security than the weakest model.