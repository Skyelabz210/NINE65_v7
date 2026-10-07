# PR #167 probe-smoke hosted result

- Actions run: https://github.com/Skyelabz210/NINE65_v7/actions/runs/37668065434
- Tested PR head: `999c539` (the workflow manifest records its synthetic merge commit)
- Exact NTT candidate probe: completes; 998244353 passes roundtrip and convolution, and the other three candidates are rejected as invalid configurations.
- Quick FHE matrix: 4 cases, 0 process successes, 0 reported pass/fail results, 4 missing result files. Each case exited on the release security guard because key generation received test-only `ShadowHarvester` randomness.

The guard is functioning as designed. The next harness update selects a debug-profile probe for this seeded exploratory matrix and includes the actual build profile in each result and in comparison compatibility metadata. These debug timings are not release performance evidence. The raw manifest, comparison, per-case stderr/stdout and NTT result are retained alongside this summary.

## Follow-up hosted run on PR head `cb6b4a9`

- Actions run: https://github.com/Skyelabz210/NINE65_v7/actions/runs/37668431001
- The release-mode seeded FHE probe still trips the intended `ShadowHarvester` guard in all four quick cases. It produces no result files, so the comparison contains zero records. The downloaded raw artifacts are in [`cb6b4a9/`](cb6b4a9/).
- The next update changes the matrix build and execution profile to debug, records `build_profile` in probe metadata, and keeps the exact NTT candidate probe in release. Debug FHE timings remain informational.

The matching CT and fuzz artifacts from this run set are preserved under `../pr167-ct-37668430997/` and `../pr167-fuzz-37668431023/`.
