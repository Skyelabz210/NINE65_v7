# Reanalysis Synthesis

**Analyst:** Claude Opus 4.6 (cross-verification of Codex deep-planning-audit)
**Date:** 2026-02-11
**Scope:** Verify reanalysis claims, answer question matrix, amend execution plan

---

## 1) Verification of Insight Log Claims

All 5 logic gap claims independently verified against source code:

| # | Claim | Verdict | Evidence |
|---|-------|---------|----------|
| 1 | README references `benchmark_max_depth` (nonexistent) | **CONFIRMED** | README.md:257 — actual name is `benchmark_symmetric_max_depth` in gso_fhe.rs:785 |
| 2 | Security estimate drift (README vs baseline) | **CONFIRMED** | secure_256: 268.1 bits (README) vs 226 bits (baseline) — **42-bit discrepancy** |
| 3 | Test count drift (627 vs 640 in same file) | **CONFIRMED** | README.md:5 badge says 640; README.md:21 summary says 627 |
| 4 | Zero-time artifacts in baseline | **CONFIRMED** | K-Elimination EXACT_DIVIDE, DIVMOD, SCALE_ROUND all show 0.00ms |
| 5 | 16ms framing vs actual secure baseline | **CONFIRMED** | Comparison doc uses light_rns_exact (16ms); secure_128 actual: 146ms; secure_192: 444ms |

Additional findings not in original insight log:

| # | Finding | Severity |
|---|---------|----------|
| 6 | `nine65_vs_seal_comparison.rs` doesn't actually run SEAL — it benchmarks NINE65 only | High |
| 7 | Test `add_plain_rejects_scalar_exceeding_plaintext_modulus` is **failing** (message mismatch) | Medium |
| 8 | Benchmark CI (`.github/workflows/ci.yml:256-260`) explicitly says "Don't fail the build, just warn" | High |
| 9 | Performance baselines use `cargo test --nocapture` println!, not Criterion — no statistical rigor | High |
| 10 | FHE_BENCHMARK_COMPARISON.md dated Dec 30, 2025 — cites Zama blog, arXiv papers, no local reproduction | High |

---

## 2) Prior Execution Plan (fhe-service hardening) — Verified Status

| Item | Status | Notes |
|------|--------|-------|
| CF-1 | **DONE** | compile_error! in fhe-service/main.rs:8-9 |
| CF-2 | **DONE** | noise_budget.consume in handle_encrypt:227-231 |
| CF-3 | **DONE** | Single unix_now_seconds in main.rs:141, no duplication |
| CF-4 | **DONE** | Per-session Arc<RwLock<Session>> pattern |
| CF-5 | **DONE** | All wire fields renamed to noise_budget_estimate_millibits |
| CF-6 | **DONE** | Rescale credit applied in handlers.rs:416-424 |
| H-1 | **DONE** | TTL reaper thread every 60s, default 3600s TTL |
| H-2 | **DONE** | README matches all 9 implemented endpoints |
| H-5 | **NOT DONE** | getrandom uses .expect() — panics on OS entropy failure |
| H-9 | **PARTIAL** | 5 serde unwrap() calls remain in handlers.rs:168,181,245,286,447 |

Items H-3, H-4, H-6, H-7, H-8, Q-1 through Q-5: not yet verified by agents (need manual check).

---

## 3) Question Matrix — Answers

### Q01: Which metric profile is official for external claims?

**Answer:** `secure_128` is the minimum for any external claim. All three secure profiles (`secure_128`, `secure_192`, `secure_256`) should be reported with explicit labels. `light_rns_exact` is a test/development config and must never appear in external-facing metrics.

**Rationale:** The current FHE_BENCHMARK_COMPARISON.md derives its headline "16ms mul" from `light_rns_exact`, which uses parameters that do not meet any security target. The actual `secure_128` mul is 146ms. Mixing test-config numbers into claims creates a credibility problem that is straightforward to avoid.

**Action:** Add a `docs/benchmarking/PROFILE_POLICY.md` that designates `secure_128/192/256` as claim-eligible and `light_rns_exact` as internal-only. Gate FHE_BENCHMARK_COMPARISON.md behind this.

### Q02: Should `light_rns_exact` numbers remain in headline docs?

**Answer:** No. Move to internal engineering appendix. These numbers are useful for development regression tracking but are misleading in any context where a reader might interpret them as production performance.

**Action:** Remove from README headline tables. Create `docs/engineering/INTERNAL_BENCHMARKS.md` for test-config metrics.

### Q03: Which comparison targets are in official scope?

**Answer:** For v5 symmetric mode: **OpenFHE** (BFV mode) and **SEAL** (BFV mode). Both are widely deployed BFV implementations. TFHE-rs uses a different scheme (TFHE/CGGI) and is not parameter-equivalent — include only as a footnote with explicit scheme-difference disclaimer. HElib is less actively maintained and can be deferred.

**Action:** Pin OpenFHE v1.2.x and SEAL v4.1.x. Document parameter mapping. Do not publish comparative claims until a local reproducible harness exists.

### Q04: What parameter-equivalence mapping for cross-library comparisons?

**Answer:** Map by (n, log2(q), t, sigma) tuples. NINE65 `secure_128` = n=4096, q=2^54-33, t=65537, sigma=3.2. Find the closest parameter set in SEAL/OpenFHE that achieves the same security level per the lattice estimator. Document any differences in q decomposition, NTT implementation, or key-switching strategy as methodology notes.

**Action:** Create `docs/benchmarking/PARAMETER_MAP.md` with side-by-side tables.

### Q05: Should benchmark CI be blocking or advisory?

**Answer:** **Tiered.** Critical operations (encrypt, decrypt, mul under secure_128) should be merge-blocking with a 20% regression threshold. Extended benchmarks (all configs, batch, depth) remain advisory on PRs but blocking on release branches.

**Rationale:** The current "just warn" policy in ci.yml:259 means performance regressions can ship without anyone noticing. But blocking everything would create flake-driven friction.

**Action:** Split benchmark-check into `benchmark-critical` (blocking) and `benchmark-extended` (advisory). Define regression thresholds.

### Q06: Minimum statistical standard for publishing performance deltas?

**Answer:** Minimum 10 runs, report median and p95, require coefficient of variation < 15% for wall-clock metrics. For sub-microsecond operations, use instruction counts (callgrind or perf stat) instead of wall-clock.

**Action:** Codify in `docs/benchmarking/STATISTICS_POLICY.md`. Enforce in baseline generation scripts.

### Q07: Which environment fields are mandatory for every benchmark artifact?

**Answer:** CPU model + governor, kernel version, rustc version, cargo version, commit hash, feature flags, config profile, timestamp (UTC), and whether turbo boost was disabled. Optional: NUMA topology, memory bandwidth.

**Action:** Extend `scripts/generate_performance_baseline.sh` to emit all mandatory fields. Add schema validation.

### Q08: Instruction-level benchmarking requirement?

**Answer:** Yes, for sub-microsecond operations only. The 0ns artifacts in the K-Elimination baseline prove wall-clock is inadequate at that granularity. Use `criterion` with `--bench` harness (already exists) for micro operations. For FHE ops (>1ms), wall-clock with statistical reporting is sufficient.

**Action:** Replace println!-based timing for K-Elimination ops with Criterion benches. Add `cachegrind`-mode option for CI.

### Q09: Side-channel readiness release gate?

**Answer:** For symmetric mode: constant-time NTT (done — Barrett reduction), constant-time polynomial operations (done), constant-time decrypt path (NOT done — Q-4 from prior plan: `mul()` used instead of `mul_ct()`). Exit criteria: all secret-dependent operations use CT primitives, timing test suite passes (`[timing]` CI job), no data-dependent branching in encrypt/decrypt/evaluate paths.

**Action:** Fix Q-4 (decrypt path). Add timing-test coverage for decrypt. Gate release on timing-tests job passing.

### Q10: Deprecated/stale benchmark docs policy?

**Answer:** Auto-archive. Any benchmark doc not regenerated within 30 days of the latest release gets a `[STALE — regenerate before citing]` header injected by CI. Hard-fail only for README.md headline claims.

**Action:** Add `scripts/docs/check_freshness.sh` that compares doc timestamps against latest release tag.

### Q11: Auto-generated README benchmark tables?

**Answer:** Yes. The current manual tables are already wrong (security estimates differ by 42 bits). Generate from canonical baseline artifacts.

**Action:** Create `scripts/docs/generate_readme_tables.py` that reads PERFORMANCE_BASELINE and LATTICE_ESTIMATOR_BASELINE files and emits markdown table fragments. README includes them via generation script in CI.

### Q12: Proprietary feature-path evidence surfacing?

**Answer:** For now, defer. The `accelerated` feature path is not relevant to symmetric-mode seal-off. When needed: private CI runs the benchmark, produces a signed JSON artifact with commit hash + metrics, published to a digest file in the public repo without source code.

**Action:** Deferred to Phase 2.

### Q13: Mandatory end-to-end service benchmark scenarios?

**Answer:** Four scenarios: (1) single session create→encrypt→mul×3→decrypt→delete, (2) 8 concurrent sessions performing mixed operations, (3) batch encrypt 1024 values then batch decrypt, (4) error storm (invalid ciphertexts, expired sessions, oversized payloads).

**Action:** Implement in `crates/fhe-service/benches/` or as integration test with timing capture.

### Q14: Canonical noise-budget and correctness envelope for depth testing?

**Answer:** For each secure config, publish: (config, max_depth_achieved, noise_budget_at_each_level, correctness_verified_at_each_level). The current depth benchmarks in gso_fhe.rs already track this but output is println!-based and not machine-readable.

**Action:** Make depth benchmarks emit structured JSON. Add `docs/DEPTH_CORRECTNESS_MATRIX.md` generated from this output.

### Q15: Baseline regeneration cadence?

**Answer:** Tiered: smoke benchmarks on every PR (blocking for critical tier), full baseline on nightly CI, archived baseline on each release tag.

**Action:** Add `nightly` schedule trigger in ci.yml for full baseline. Tag-triggered job for release baselines.

### Q16: Historical artifact retention?

**Answer:** Keep only (1) current v5 baselines and (2) the most recent pre-upgrade snapshot. Everything else moves to `archive/` with explicit `[ARCHIVED — not v5 current]` labels. The 2,759-file scan mentioned in the insight log confirms legacy density is high.

**Action:** Index and tag. Already partially done via `archive/` directory.

### Q17: Fuzz targets in CI?

**Answer:** `fuzz_encrypt_decrypt` and `fuzz_k_elimination` should run nightly with 60-second budgets. Not merge-blocking (fuzz is inherently probabilistic), but crash findings create blocking issues.

**Action:** Add nightly fuzz job in ci.yml. Artifact upload for crash corpus.

### Q18: Benchmark claims at timer resolution limits?

**Answer:** Operations measuring <100ns must use instruction counts or Criterion's built-in nanosecond harness with sufficient iterations. The current 0ns rows are invalid and must not appear in any published artifact.

**Action:** The 0ns K-Elimination entries should be replaced by Criterion benchmarks from `timing.rs` (which already benchmarks K-Elimination properly). Update baseline generation to pull from Criterion output.

### Q19: Service-level SLOs?

**Answer:** Not yet. Premature before the service is hardened (H-5, H-9 still open). Define SLOs after macro benchmarks exist and the service has run under load testing.

**Action:** Defer to Phase 4 of the new execution plan.

### Q20: Final approving authority for benchmark claims?

**Answer:** The repository owner (founder@hackfate.us) for all external claims. For internal engineering metrics, the contributor who regenerated the baseline. Codify in governance doc.

**Action:** Add to `docs/benchmarking/BENCHMARK_GOVERNANCE.md`.

---

## 4) Insights Collected

### I-1: The 42-bit security estimate gap is the highest-priority fix

README claims secure_256 provides 268.1-bit security. The lattice estimator baseline says 226 bits. A 42-bit discrepancy in a security claim is not a documentation drift issue — it's a correctness issue. Either the estimator changed between when README was written and when the baseline was generated, or the numbers were transcribed incorrectly. Either way, README must be regenerated from the authoritative baseline before any further publication.

### I-2: The "16ms mul" claim is indefensible as written

FHE_BENCHMARK_COMPARISON.md's headline claim derives entirely from `light_rns_exact`, a test config with no security guarantees. The actual secure_128 mul is 146ms — 9x slower. The document should either be rewritten using secure configs exclusively, or reclassified as an internal research note.

### I-3: The benchmark infrastructure has two disconnected stacks

Criterion benches exist (`fhe_scaling.rs`, `throughput.rs`, `timing.rs`) and produce statistically rigorous results. But the baseline generation scripts use `cargo test --nocapture` with println! formatting. These two systems don't share data, don't share formats, and can produce contradictory numbers. Unifying them is the highest-leverage infrastructure change.

### I-4: The fhe-service hardening is substantially complete

8 of 10 checked items are DONE. The remaining gaps (H-5: getrandom panic, H-9: serde unwrap) are real but bounded. The other AI executed the plan competently. The failing test (`add_plain_rejects_scalar_exceeding_plaintext_modulus`) is a message-matching issue, not a security issue.

### I-5: The Codex execution plan is sound but oversized for current team

54 tasks across 10 phases spanning 9+ weeks is thorough but assumes a multi-person team with DevOps, Perf Eng, and Security roles. For current reality (solo + AI), the tasks need to be distilled to the 15-20 that have the highest impact on claim credibility. The governance/policy docs (T001-T005) can be collapsed into a single file. The CI enforcement tasks (T040-T044) are high-leverage and should be prioritized over the macro benchmark suite (T021-T025).

### I-6: CF-1 was placed in the wrong file

The compile_error! for `allow_insecure` is in `crates/fhe-service/src/main.rs:8-9`, not in `crates/nine65/src/lib.rs` as the original plan specified. This means the guard only protects the fhe-service binary, not the nine65 library itself. A downstream consumer could still use `nine65` with `allow_insecure` in release mode. The guard should also be in `crates/nine65/src/lib.rs`.

---

## 5) Amended Execution Plan

The original Codex plan (54 tasks) is merged with the prior fhe-service plan (20 tasks) and distilled to actionable items prioritized by impact on claim credibility and security posture.

### IMMEDIATE — Fix broken claims (before any publication)

| ID | Task | Source | Est |
|----|------|--------|-----|
| F-1 | Regenerate README security estimate table from latest lattice estimator baseline | Verified gap #2 | 30 min |
| F-2 | Fix README test count (pick one: 627 or 640, verify, use that) | Verified gap #3 | 15 min |
| F-3 | Fix README benchmark command (`benchmark_max_depth` → `benchmark_symmetric_max_depth`) | Verified gap #1 | 5 min |
| F-4 | Reclassify FHE_BENCHMARK_COMPARISON.md: add header "INTERNAL RESEARCH NOTE — numbers from test config, not production parameters" or rewrite with secure_128 numbers | Verified gap #5 | 1 hr |
| F-5 | Fix failing test `add_plain_rejects_scalar_exceeding_plaintext_modulus` | Verified finding #7 | 15 min |
| F-6 | Add CF-1 compile_error! to `crates/nine65/src/lib.rs` (currently only in fhe-service) | Synthesis I-6 | 5 min |

### HIGH — Remaining fhe-service hardening

| ID | Task | Source | Est |
|----|------|--------|-----|
| S-1 | H-5: Wrap getrandom in Result at entropy/secure.rs — return HTTP 500 instead of panic | Prior plan | 30 min |
| S-2 | H-9: Replace 5 serde unwrap() calls with map_err in handlers.rs | Prior plan | 15 min |
| S-3 | Verify H-3/H-4/H-6/H-7/H-8 status (keep-alive, batch limit, 413, response cap, request cap) | Prior plan | 1 hr |
| S-4 | Q-2: Uniform error status codes (remove 422 for NoiseExhausted → all 400) | Prior plan | 30 min |
| S-5 | Q-4: Decrypt path mul → mul_ct for constant-time | Prior plan | 30 min |
| S-6 | Q-5: Document IND-CPA security boundary in fhe-service README | Prior plan | 15 min |

### HIGH — Benchmark credibility infrastructure

| ID | Task | Source | Est |
|----|------|--------|-----|
| B-1 | Create `docs/benchmarking/PROFILE_POLICY.md` — designate secure configs as claim-eligible, light as internal | Q01, Q02 | 30 min |
| B-2 | Fix 0ns artifacts — replace println!-based K-Elimination timing with Criterion bench output in baselines | Q08, Q18 | 2 hr |
| B-3 | Unify baseline generation: have `scripts/generate_performance_baseline.sh` pull from Criterion JSON where available | I-3 | 2 hr |
| B-4 | Add mandatory environment metadata to baseline scripts (CPU governor, kernel, rustc, commit, features) | Q07 | 1 hr |
| B-5 | Create `docs/benchmarking/CLAIM_REGISTRY.md` — map every README claim to the artifact that backs it | Codex T003 | 2 hr |
| B-6 | Convert benchmark-check CI from advisory to tiered (critical blocking, extended advisory) | Q05, Codex T040 | 2 hr |

### MEDIUM — Documentation reconciliation

| ID | Task | Source | Est |
|----|------|--------|-----|
| D-1 | Add stale-claim scanner: script that diffs README values against baseline files, fails CI if drift detected | Codex T008, T041 | 3 hr |
| D-2 | Create benchmark statistics policy (min 10 runs, median + p95, CV < 15%) | Q06 | 30 min |
| D-3 | Add nightly fuzz job for fuzz_encrypt_decrypt and fuzz_k_elimination (60s each) | Q17 | 1 hr |
| D-4 | Add comparator manifest (OpenFHE v1.2.x, SEAL v4.1.x) with parameter map | Q03, Q04 | 1 hr |
| D-5 | Generate structured depth-correctness matrix (JSON) from gso_fhe depth benchmarks | Q14 | 2 hr |

### LOW — Deferred (Phase 2+)

| ID | Task | Source | Notes |
|----|------|--------|-------|
| P2-1 | End-to-end service benchmark suite (macro) | Q13, Codex T021-T025 | After hardening complete |
| P2-2 | Service SLO definitions | Q19 | After macro benchmarks exist |
| P2-3 | Proprietary `accelerated` feature evidence | Q12 | Not relevant to symmetric seal-off |
| P2-4 | Auto-generated README tables from CI | Q11, Codex T035 | After claim registry stable |
| P2-5 | Benchmark lineage index (v2/v5 history) | Q16, Codex T006 | Archive tagging |
| P2-6 | Benchmark governance doc and review cadence | Q20, Codex T001 | After infrastructure exists |

### Execution Order (first 5 working days)

```
Day 1:  F-1, F-2, F-3, F-4, F-5, F-6  (fix broken claims — 2 hr)
Day 1:  S-1, S-2                         (critical hardening — 45 min)
Day 2:  S-3, S-4, S-5, S-6              (verify + finish hardening — 2.5 hr)
Day 2:  B-1                              (profile policy — 30 min)
Day 3:  B-2, B-3                         (unify benchmark infrastructure — 4 hr)
Day 4:  B-4, B-5                         (metadata + claim registry — 3 hr)
Day 5:  B-6, D-1                         (CI enforcement — 5 hr)
```

**Total actionable items: 23 (6 immediate + 6 hardening + 6 benchmark + 5 docs)**
**Estimated effort: ~30 hours**
**Deferred to Phase 2: 6 items**

---

## 6) Codex Plan Assessment

The Codex 54-task plan is structurally sound. It correctly identifies the core problem: benchmark claims are disconnected from generated evidence. Its layered approach (micro/meso/macro/adversarial) is the right architecture.

Where it overshoots:
- Tasks T001-T005 (governance) can be one file, not five
- Tasks T006-T010 (artifact normalization) are process overhead before the core problem (wrong numbers in README) is fixed
- Tasks T021-T025 (macro benchmarks) depend on fhe-service hardening being complete (it isn't)
- Tasks T045-T049 (service integration) depend on Phase 2 features (Galois, batch encoder) that don't exist yet

Where it's missing:
- Doesn't reference the fhe-service hardening plan at all (H-5, H-9, Q-2, Q-4 still open)
- Doesn't catch CF-1 being in the wrong file
- Doesn't catch the failing test
- Doesn't address the `nine65_vs_seal_comparison.rs` naming issue (implies SEAL comparison but doesn't run SEAL)

The amended plan above folds the highest-impact Codex items into the existing fhe-service plan and prioritizes "fix the broken claims" over "build governance frameworks."
