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

> **After the canonical-phase correction (PR #160):** the two directly
> distinguished phases `Q-1` and `-1` now pass the rescale regression, but the
> repeated-square depth-4 gate remains red: `secure_128` gives `56106` versus
> `65536`, and `secure_192` gives `0` versus `65536`. In the zero-fresh-error
> controls, `c1=0` still passes through depth 4. With `c1=1`, seed `2` gives
> `0` versus `65536`, and seed `4` gives `2` versus `1` at depth 4. Seed `4`
> reaches the `-1 mod t` plaintext at depth 3 and passes there, so simply
> crossing that plaintext boundary does not explain the depth-4 error. Both
> nontrivial controls show a `+1 mod t` discrepancy, which is an observation,
> not a justified correction rule. Their observed K widths remain below the
> admitted anchor width. The phase fix is necessary but does not certify the
> BFV scale-round or relinearization chain. Logs are in the same artifact
> directory under `fixed-*`; the direct phase regression is in
> [`artifacts/execution/2026-10-04-rescale-phase`](../artifacts/execution/2026-10-04-rescale-phase/).

> **Large-winding scalar oracle:** an independent arbitrary-integer fixture at
> `K=±(2^145+12345)` confirms `k_elim_rescale_dual` returns the correct
> `round(X/Δ) mod Q` main residues for both signs. Its output anchor residues
> instead describe the canonical mod-`Q` representative, not the unreduced
> signed quotient. That phase reset is measured, but is not yet proven to be
> the depth-4 defect. The existing public manufactured-rescale guardrail
> explicitly shows that replacing canonical anchors with centered anchors
> can break the next multiplication. The StarLift corpus uses 36/37 plus a
> star-prime ladder for winding; its 36/37 observer alone reports `K mod 37`.
> The current CRAM Property Signature Σ reads **sign from known winding K**
> and **parity from the mod-2 lane**. It does not contain a separate RNSB
> sign-proxy or quarantine transition. A future sign operator must establish
> its own bound-certified, phase-locked, nonpublished input; parity alone
> cannot distinguish `+1` from `-1`. See the generated
> [`large-phase-oracle.json`](../artifacts/execution/2026-10-04-depth-gate/large-phase-oracle.json)
> and its [`generator`](../scripts/rescale_large_phase_oracle.py).

> **Full coefficient audit, deterministic zero-fresh-error seed 2:** at depth
> 4, an independent signed CRT oracle checked all `8192` coefficients of both
> folded components. The live `k_elim_rescale_dual` output matched exact
> `round(X/Δ)` on **all 16,384** coefficients. Replacing only that fourth
> rescale with exact `round(tX/Q)` changed 8,192 coefficients in component 0
> and 7,620 in component 1, but both versions still decrypted to `65532`
> instead of `65536`. The decoded phase error against the expected message
> point is about `3.7Δ`; 8,000 nonconstant phase coefficients exceed `Δ/8`
> at depth 4, versus none through depth 3. This establishes a phase/noise
> overrun and rules out a scalar division mistake at the first failing step;
> it does **not** yet distinguish insufficient refresh from an earlier
> ciphertext phase/fold defect. The source-bound
> [`coefficient audit`](../artifacts/execution/2026-10-04-depth-gate/coefficient-audit-128.json),
> [phase log](../artifacts/execution/2026-10-04-depth-gate/logs/phase-profile-128.log),
> and [independent analyzer](../scripts/analyze_depth4_residue_pairs.py)
> reproduce the finding. The raw synthetic-key residue dump is generated in
> `/tmp` by the ignored diagnostic test and is not a production artifact.

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
