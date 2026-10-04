# Issue #137: Triage the 15 test failures --no-fail-fast newly surfaced (beyond the known 5 in #117)

- state: open
- labels: bug, testing
- created: 2026-09-04T11:17:22Z  updated: 2026-09-04T11:17:22Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/137

---

## Context

Once PR #136 (issue #64/#130) lands `--no-fail-fast`, `cargo test --release --workspace` completes instead of stopping after `nine65 --lib`'s 5 known failures (issue #117). Measured result: **1903 passed / 20 failed / 258 ignored** — 15 failures beyond the known 5, previously invisible to every workspace-wide test run.

## The 15, as currently known (none individually root-caused yet — this issue is the triage tracker)

- **9 in `crates/nine65/tests/noise_profile.rs`** — one root cause already identified: current 4-lane `secure_128` (post the 2026-08-26 recut, see #91/#121) now violates a `Q*t < 2^128` precondition that file documents. This is the fifth independent piece of fallout from that recut found this session (after #62, #91/#121, #19's benchmark tooling, #132's lane-permutation vectors). Likely the fastest of the 15 to fix — same shape as #132: stale assumption from before the recut.
- **1 in `k_elimination_basis_regression.rs`** — not yet triaged.
- **1 in `residue_space_ciphertext.rs`** — possibly the same defect as #132 (lane-permutation vectors stale post-recut) or a distinct failure in the same file — not yet confirmed which.
- **1 in `full_system_exercise.rs`** — not yet triaged.
- **1 in `basis_invariance.rs`** — not yet triaged.
- **1 in `bootstrap_integration.rs`** — plausibly related to #117/#95 (bootstrap refresh corruption) given the file name, but not confirmed — could equally be an unrelated, recut-driven, or otherwise distinct defect.
- **1 in `depth_and_noise.rs`** — plausibly related to #81 (depth-2 correctness), which per today's investigation may already be resolved for its originally-reported case — this could be a different depth/config combination still failing, or something unrelated. Not confirmed.

## Required work

For each: reproduce (`cargo test --release -p nine65 --test <file> --features allow_insecure -- --nocapture`), determine whether it's (a) fallout from the `secure_128` recut (stale hardcoded assumption — likely quick, safe fix, same pattern as #132), (b) a manifestation of an already-tracked deeper issue (#117/#95 bootstrap corruption, #81 depth-2 — confirm or rule out per-file), or (c) something genuinely new and undiagnosed. File or link accordingly; this issue can be closed once every one of the 15 has a confirmed disposition (fixed, linked to an existing issue, or has its own new issue).

## Not done here

No individual failure has been reproduced or fixed yet — this issue exists to make sure the count and rough shape (from PR #136's real measurement) isn't lost before someone triages each one.