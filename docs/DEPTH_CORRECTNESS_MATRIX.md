# Depth-Correctness Matrix

Generated on 2026-02-14 09:51:41 UTC

> **2026-10-04 current-source recheck:** per-step decryption was added to the
> same repeated-squaring benchmarks. In one debug run each, `secure_128`
> matched depths 1–3 and failed at depth 4 (`got=55380`, `expected=65536`);
> `secure_192` also matched depths 1–3 and failed at depth 4 (`got=65532`,
> `expected=65536`). The archived 50-step rows below are historical counter
> and timing records, not correctness results. The separate 128-step
> `mul-by-1` test uses a different workload and does not certify repeated
> squaring. See the source-bound test logs in
> [`artifacts/execution/2026-10-04-depth-gate`](../artifacts/execution/2026-10-04-depth-gate/).

> **Depth-4 isolation:** a constructed ciphertext with no fresh encryption
> error, `c1=0` and `c0=2Δ`, passes four self-squares. A second constructed
> ciphertext with no fresh error, `c1=1` and `c0=2Δ−s`, starts with the same
> exact decryption phase but fails at depth 4 (`39957` vs `65536`). The observed
> signed-K width there is 145 bits against roughly 220 bits of anchor product.
> Thus the current evidence points to the nontrivial ciphertext multiplication,
> relinearization and scale-round chain, not a simple S8 carry or anchor-width
> wrap. These controls do not by themselves prove which component introduces
> the first excessive BFV error; #157 tracks that isolation. The GSO collapse
> path changes noise metadata and swarm state, not ciphertext coefficients.
> The standalone Recumbent carrier has a separate exactness defect (#159) and
> is not wired into this route.

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

- Collapse counts are diagnostic metadata; zero collapses do not imply correct
  plaintext or adequate BFV decryption headroom.
- Both current-source repeated-squaring tests stopped on a plaintext mismatch
  at depth 4. No 50-level correctness claim follows from this matrix.
