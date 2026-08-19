# Depth-Correctness Matrix

Generated on 2026-02-14 09:51:41 UTC

> **2026-08-19 note:** this matrix's data comes from
> `benchmark_symmetric_max_depth_secure_128`/`_192`
> (`crates/nine65/src/ops/gso_fhe.rs`), which run 50 symmetric multiplications
> and record noise-collapse counts and timing — **they never call decrypt and
> never assert plaintext correctness**. "Correctness Verified: ✓ PASS" below
> means "zero noise collapses observed," not "decrypt-checked correct at
> depth 50." For decrypt-checked, CI-asserted depth evidence, see
> `crates/nine65/tests/time_crystal_verification.rs::symmetric_depth_is_unbounded`
> (asserts and decrypt-checks a 128-level floor, `secure_128`, no bootstrap)
> and `crates/nine65/tests/depth_and_noise.rs::depth_and_noise_curve_deep_chain`
> (asserts a 32-level regression floor, decrypt-checked at every step). The
> timing figures below are not reproduced in this pass — see CLAUDE.md's
> "Performance Baselines" for current numbers.

## Symmetric Mode Depth Verification

This matrix shows the maximum depth achieved and correctness verification for each secure configuration.

| Config | Max Depth Achieved | Total Collapses | Correctness Verified | Avg Time/Mul |
|--------|-------------------|-----------------|---------------------|--------------|
| secure_128 | 50 | 0 | ✓ PASS (no-collapse only — see note above) | 121.41ms |
| secure_192 | 50 | 0 | ✓ PASS (no-collapse only — see note above) | 191.95ms |


## Pass/Fail Thresholds

- **Max Depth Target**: 50 levels for symmetric mode
- **Collapses Limit**: 0 (no collapses allowed for verified correctness)
- **Correctness**: this document's "verified" means zero noise collapses at max depth ≥ 50, not decrypt-checked plaintext correctness (see note above)

## Notes

- Collapses indicate when noise budget is exceeded and rescaling occurs
- For symmetric mode, 0 collapses indicates that the computation maintained full precision
- All tested configurations achieved the target depth of 50 levels without collapses
