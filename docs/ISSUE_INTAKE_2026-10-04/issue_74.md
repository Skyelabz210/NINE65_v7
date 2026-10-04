# Issue #74: [H5] Restore allow_insecure gate without breaking workspace tests

- state: open
- labels: bug, gap-remediation, security
- created: 2026-08-30T22:14:27Z  updated: 2026-09-04T09:58:51Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/74

---

**Priority**: High
**Source**: NINE65 v7 Comprehensive Compendium (2026-08-30 audit), §8.2
**Evidence**: `crates/nine65/src/lib.rs:145`

## Gap
`allow_insecure` gate commented out.

## Impact
Test configs could leak into production builds.

## Remediation
Restructure fhe-service test architecture.

## Acceptance Criterion
Gate compiles without breaking `cargo test --release --workspace`.