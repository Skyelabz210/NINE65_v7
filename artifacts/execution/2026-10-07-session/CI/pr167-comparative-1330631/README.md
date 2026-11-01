# PR #167 comparative smoke evidence

Source head: `13306310547ef96e8737365a8ffab1f8a74d385d`

Workflow run: https://github.com/Skyelabz210/NINE65_v7/actions/runs/37671711926

The hosted smoke produced valid debug-profile output and completed both
requested ciphertext multiplication depths correctly. Its old aggregate
status is `FAIL` because `correctness.legacy.mul_ct` is intentionally false
and `mul_ct_status` is `refused-#135`. All supported legacy checks and all
DualRNS checks are true. This artifact is retained unchanged as evidence for
the follow-up that recognizes only that exact refusal pair while keeping the
missing legacy capability explicit.

SHA-256:

* `nine65-v7-comparative-smoke/result.json`:
  `e4c1a002b573418c4801d49aeb76bd7c79b35dedab5347ebf0ea142f665ab4d8`
* `nine65-v7-comparative-smoke/stdout.log`:
  `e138703add8850d9a9815bb2e62f46442dc5b33bffd1f6665a105dde44fd10e2`
