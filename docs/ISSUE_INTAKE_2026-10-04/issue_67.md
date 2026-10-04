# Issue #67: [M1] Remove or clearly mark deprecated Coq proofs as historical

- state: open
- labels: documentation, medium-priority, gap-remediation, verification
- created: 2026-08-30T22:14:00Z  updated: 2026-08-31T10:21:29Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/67

---

**Priority**: Medium
**Source**: NINE65 v7 Comprehensive Compendium (2026-08-30 audit), §8.3
**Evidence**: `proofs/coq/`

## Gap
Coq proofs deprecated but present. Several don't compile, several have `Admitted` lemmas, one has a known counterexample.

## Impact
Confusion about verification basis; risk of citing Coq proofs as machine-checked.

## Remediation
Remove or clearly mark as historical.

## Acceptance Criterion
No one cites Coq proofs as machine-checked.

## Related
Supersedes/contradicts #20 (Expand Coq proofs) — recommend closing #20 in favor of this.