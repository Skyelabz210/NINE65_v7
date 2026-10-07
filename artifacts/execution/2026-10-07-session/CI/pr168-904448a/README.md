# PR #168 hosted artifacts for `904448a`

PR #168 head `904448a73fb17427a7d05bde16e2d74c6b74e4d0` was merged by the repository owner at merge commit `c93a058e2106441029647e69e252d3b410fdeab1` on 2026-10-07 19:45:24 UTC. These artifacts preserve the initial hosted check set on that code head; later T2/merge-ref status is tracked in the session plan and issue #92.

## CT

Run [37676097485](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37676097485) source/functional checks pass. The blocking workflow fails because a separate `AdjacencyKElim::extract_k` small-vs-near-cap contrast reports `t_control=4.0863`, `t_signal=6.3291`, threshold 5, medians 1,241,019 ns and 1,242,111 ns.

The new isolated reducer contrast reports `t_control=1.1190`, `t_signal=0.1719`, medians 5,238 ns and 5,238 ns. The full `mod_switch_down_dual` all-zero vs uniform contrast reports `t_control=0.0504`, `t_signal=1.0673`, medians 79,529,441 ns and 79,708,205 ns. The magnitude-matched positive-vs-negative contrast reports `t_signal=0.5217`. These below-threshold values came from an incorrect partial-mask prototype and are diagnostic only, not accepted CT evidence. Raw output is `ct/ct-dudect-blocking/dudect_blocking_output.txt`, SHA-256 `ea3e935ebc500bc61cd2a5c455442786f4e4bb32d950c7023f795e94b6896df4`.

## Fuzz Smoke

Run [37676097295](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37676097295) reproduces three defects. Deserialize input is 5 bytes and triggers AddressSanitizer out-of-memory. Encrypt/decrypt returns 65,289 for plaintext 65,292. The homomorphic input passes addition and subtraction in this run, then returns 61,587 for `512 * 65,404`, expected 62,978. NTT and K-Elimination pass. Raw crash inputs and hashes are retained in `fuzz/`.

## CRAM and architecture checks

Run [37676097325](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37676097325) fails two of five `cram_public_mode` tests: `multiply_is_recorded_as_a_materialization_pinned` and `depth3_public_squaring_chain_reaches_256`. Both passed on merged PR #167 head `0f85873`. The errors say exact coefficient values require 255/253 bits while evaluation keys span 60/120 bits. Source review found the reducer mask-width bug: a 64-bit all-ones condition was widened and negated as `u128`, yielding a partial mask. The current follow-up fixes that expansion; the differential test, T2, and CRAM rerun must verify it.

Exact CRAM run 37676097499 and exact Dual-RNS run 37676097339 fail their existing source-bound architecture checks. Their complete logs are retained in `exact-cram.log` and `exact-dual-rns.log`.

## Other gates

On this code head, T1 Fast Gate, static analysis, T3, CT source/functional, and application platform gates pass. T2 run 37676097379 completed with 856 passed, 94 failed, and 125 ignored. Its arithmetic differential test fails at dividend 2, modulus 2, directly confirming the partial-mask defect; the complete job log is `t2-workspace.log` (SHA-256 `caa9b3016d6b8f60eec0063b08bc2a4148ddcd5f6dcc920196e104310882bd30`). The local arithmetic prototype was not built in the constrained checkout; hosted checks are the evidence for this SHA.
