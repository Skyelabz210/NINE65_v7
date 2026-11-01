# PR #168 merge-ref evidence for `c93a058`

PR #168 was merged by the repository owner at `c93a058e2106441029647e69e252d3b410fdeab1` on 2026-10-07 19:45:24 UTC. This directory preserves the first GitHub Actions run set on that merge commit.

## CI and correctness

CI run [37676889216](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37676889216): T1 Fast Gate and static analysis pass; T2 completes with 856 passed, 94 failed, and 125 ignored. The new `test_u512_mod_u256_matches_reference_for_sparse_and_dense_values` fails at dividend 2/modulus 2, confirming the partial-mask defect. The separate `class_f_alpha_lanes_must_be_prime_and_distinct` regression also fails. The failed-job log is `ci/t2-failed.log`, SHA-256 `a004510d4f52d6bd7f1629f299a2919fd5178c0405eaad4f00d5e45628478871`.

Merge-ref CT run [37676889107](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37676889107) passes all statistical contrasts once. The reducer signal is 1.1272, full-path signal 1.2671, and adjacency K-Elimination signal 3.6537. The tested source has the partial-mask correctness bug confirmed by the PR-head differential test, so these timing scores do not validate the arithmetic or an accepted CT fix. Raw CT output is under `ct/ct-dudect-blocking/`.

CRAM-public run [37676889200](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37676889200) repeats the two multiply failures seen on PR head `904448a`: the exact coefficient needs 255/253 bits, while the evaluation key spans 60/120 bits. Both tests passed on the preceding merged head `0f85873`.

Scale sweep run [37676889143](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37676889143) and comparative harness run [37676889066](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37676889066) both stop on DualRNS multiplication. Their errors report 254–256-bit exact values against 96–128-bit gadget capacity. The raw scale manifest and standard error logs are under `scale/`; comparative logs are under `comparative/`.

Fuzz Smoke run [37676889257](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37676889257) fails deserialize (six-byte input requests `0xb70002fd0` = 49,123,700,688 bytes), encrypt/decrypt (15,110 → 15,109), and homomorphic addition (0 + 35,073 → 35,071). The three raw corpus files and SHA-256 values are retained in `fuzz/`. CRAM exploratory run 37676889127 also fails its multiply cases; its raw JSON and logs are under `exploratory/`.

## Architecture checks

CRAM Recumbency run 37676889214 and Audit Remediation run 37676889186 fail their source-bound checks. Residue-native run 37676889104 reports `garner_reconstruct_subset` at `crates/exact_transcendentals/src/cram_ct.rs:2067`. The exact logs are retained here.

## Reducer diagnosis and next action

The partial-mask defect was in the reducer prototype merged by PR #168: it widened a 64-bit all-ones selector, then negated it as `u128`, yielding only a partial 128-bit mask. T2 run 37676097379 fails the differential test at dividend 2, modulus 2; this explains the new multiply capacity failures. Branch `codex/2026-10-07-ct-regression-followup` now expands a one-bit condition at 128-bit width. Validate that fix with the differential arithmetic test, T2, CRAM-public, scale, comparative, and CT gates before accepting any timing result.
