# PR #169 hosted evidence for `84ce6da`

Draft PR [#169](https://github.com/Skyelabz210/NINE65_v7/pull/169) is based on merge commit `c93a058` and tests head `84ce6da2a18faa2c63a55fa7d662aff670fbe472`.

## Passing gates

T1 Fast Gate, T1 Static Analysis & Proofs, and T3 pass. Application-platform checks pass, as do CT source and functional checks. The static analysis job passes both source scans for floating-point usage.

## Correctness and timing gates

T2 run [37678425778](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37678425778), job 112988404676, is still running. CRAM-public correctness run [37678425583](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37678425583) is pending.

The CT source/functional job passes, but the blocking statistical job in [run 37678425725](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37678425725) fails the full `mod_switch_down_dual` all-zero-vs-uniform contrast: control `t=0.9809`, signal `t=18.2519`, medians 134.46 ms and 134.64 ms. The isolated `U512::mod_u256` contrast passes once (`t_signal=2.9168`); the magnitude-matched positive-vs-negative full-path contrast also passes once (`t_signal=0.5676`). The same-class control is below threshold, so the full-path signal remains actionable. The raw output is `ct/ct-dudect-blocking/dudect_blocking_output.txt`, SHA-256 `5e3455f7f2386c0b2d78ce03412983da987eb36690a6dee445855c19d362a5b7`.

The decimal `t_control` and `t_signal` values are Dudect statistical t-scores, not floating-point arithmetic in the Rust crypto code. These are one run only and do not close the CT finding.

Source review after this run found remaining coefficient-derived branches and variable-latency reductions in `SignedU256::center` and `mod_switch_down_dual`: center selection, quotient rounding, signed lane encoding, and `%` reductions. A second fixed-work correction is being prepared on the branch; it is not included in this `84ce6da` evidence.

## Fuzz Smoke

Run [37678425578](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37678425578): deserialize, encrypt/decrypt, and homomorphic targets fail; K-Elimination and NTT pass. The deserialize target triggers AddressSanitizer while attempting to allocate `0xed00017e8` bytes from a five-byte input. Encrypt/decrypt returns 65,480 for plaintext 65,483. Homomorphic addition returns 62,492 for `62,495 + 0`. These are the same open defect classes seen on earlier heads, with new input witnesses. The failed log is `fuzz-failed.log`, SHA-256 `ca6e34d830227e27808f9f1a367cd3482ed33cf283c73381f68bab232e2b7fd5`.

Crash corpus SHA-256 values:

- deserialize: `84f3bc3086c56ad54eb28acd7070963d7166861b9915239cf05dd6da217c1744`
- encrypt/decrypt: `ace10c5e9ebaaac9d617f183d25b7d942bb359005d8236d396028937df0ba840`
- homomorphic: `41b6a575bc098d5d2f670e585e86a956f4e04445fb1314564282148f4d0b49f0`

## Architecture checks

Exact CRAM run [37678425652](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37678425652) and exact Dual-RNS run [37678425775](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37678425775) fail their existing source-bound checks. These findings are separate from the reducer correction and remain open.

## Comparative checks

Scale run [37679066010](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37679066010), profile `quick` with required depth completion, passes both `v6_compat_4096` and `secure_128`: both cases return PASS, complete depth 2/2, and report no operation-correctness or process failures. The manifest is under `scale/nine65-v7-scale-quick/`.

Comparative run [37679073764](https://github.com/Skyelabz210/NINE65_v7/actions/runs/37679073764) passes its v7 smoke: all supported legacy operations and all DualRNS operations are correct, and both DualRNS multiplication depths decrypt to 64 and 4096 as expected. The same-machine v6 comparison is explicitly skipped because the repository secret `NINE65_CROSS_REPO_TOKEN` is not configured, so no v6/v7 performance comparison was produced. Raw outputs are under `comparative/`.
