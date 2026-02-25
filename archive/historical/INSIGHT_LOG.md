Project: NINE65 v5
Date: 2026-02-11
Analyst: Codex (deep-planning-audit)

## 1) Evidence Map

Applied (implemented + wired):
- [ ] Core benchmark infrastructure exists with Criterion benches in `crates/nine65/benches/fhe_scaling.rs`, `crates/nine65/benches/throughput.rs`, `crates/nine65/benches/timing.rs`, `crates/mana/benches/lane_ops.rs`, and `crates/exact_transcendentals/benches/performance.rs`.
- [ ] Deep-depth and arithmetic benchmark tests exist in `crates/nine65/src/ops/gso_fhe.rs` (`depth_benchmarks` and `arithmetic_benchmarks` modules).
- [ ] Performance and security baseline generators exist in `scripts/generate_performance_baseline.sh` and `scripts/generate_security_baseline.sh`.
- [ ] Baseline artifacts are present in `docs/PERFORMANCE_BASELINE_2026-02-09.md`, `docs/LATTICE_ESTIMATOR_BASELINE_2026-02-09.md`, and `docs/baselines/pre_exact_transcendentals_20260209_092437Z/`.
- [ ] CI includes benchmark and timing jobs in `.github/workflows/ci.yml` (`benchmark-check`, `timing-tests`).
- [ ] Formal proof mapping exists in `docs/FORMALIZATION_INDEX.md` and proof artifacts exist under `proofs/coq/` and `lean4/KElimination/`.
- [ ] Security posture and limitations are explicitly documented as pre-production in `README.md`, `docs/ARCHITECTURE.md`, `docs/REDSHIRT_SECURITY_ASSESSMENT.md`, and `docs/NINE65_V5_FHE_DEEP_ANALYSIS_TEST_REPORT.md`.
- [ ] Workspace excludes optional bindings by default in `Cargo.toml` (`exclude = ["fuzz", "crates/nine65-python", "crates/nine65-wasm"]`), matching default test flow.

Intended (documented, not wired):
- [ ] Release checklist expects reproducible benchmark/security artifacts each release, but this is not automatically enforced in CI (`docs/RELEASE_CHECKLIST.md`, `.github/workflows/ci.yml`).
- [ ] Documentation states benchmark reproducibility and gating intent, but benchmark CI is non-blocking and warning-only (`README.md`, `.github/workflows/ci.yml`).
- [ ] Benchmark comparison doc intends industry-grade comparisons but still uses older static assumptions and dated framing (`docs/FHE_BENCHMARK_COMPARISON.md`).
- [ ] Deep public-mode claims and mod-switch progress are documented, but public-mode baseline persistence is still called partial in audit docs (`README.md`, `docs/COMPREHENSIVE_AUDIT_REPORT_V5.md`).
- [ ] Existing system audits describe Phase 2 benchmark/service integration goals that are not yet fully wired (`COMPREHENSIVE_SYSTEM_AUDIT_2026-02-11.md`).

Expected (claims not yet verified):
- [ ] Depth-50 benchmark claims are based on test-style benchmark output and not yet bound to a formal performance budget gate with controlled variance (`docs/PERFORMANCE_BASELINE_2026-02-09.md`, `.github/workflows/ci.yml`).
- [ ] Competitive benchmark claims are presented as comparative conclusions without a reproducible competitor replay harness committed in v5 (`docs/FHE_BENCHMARK_COMPARISON.md`).
- [ ] Security estimate values are inconsistent across docs, indicating unresolved source-of-truth drift (`README.md` vs `docs/LATTICE_ESTIMATOR_BASELINE_2026-02-09.md`).
- [ ] "Formal proofs" and "verified innovations" language remains broad in historical/canonical references, while current v5 mapping explicitly excludes parts of prior scope (`NINE65_CODEX_REFERENCE.md`, `docs/FORMALIZATION_INDEX.md`).

## 2) Gaps

Logic gaps:
- [ ] Benchmark command drift: `README.md` references `benchmark_max_depth`, but no such test symbol exists in `crates/nine65/src/ops/gso_fhe.rs`; only secure-specific benchmark names exist.
- [ ] Security estimate drift: `README.md` table values differ materially from `docs/LATTICE_ESTIMATOR_BASELINE_2026-02-09.md`.
- [ ] Performance narrative drift: `docs/FHE_BENCHMARK_COMPARISON.md` uses 16ms and 812ms framing that conflicts with secure baseline figures in `docs/PERFORMANCE_BASELINE_2026-02-09.md`.
- [ ] Test count drift in one document: `README.md` executive summary shows 627 while the same file later states total executed 640.
- [ ] Zero-time artifacts: baseline logs include 0ns and 0.00ms rows, indicating timer-resolution or methodology limitations in current benchmark presentation (`docs/PERFORMANCE_BASELINE_2026-02-09.md`, `docs/baselines/pre_exact_transcendentals_20260209_092437Z/PRE_UPGRADE_METRICS_SUMMARY.md`).

Assumptions:
- [ ] Assumes test-based benchmark output is sufficient for comparative claims (`docs/PERFORMANCE_BASELINE_2026-02-09.md`).
- [ ] Assumes historical benchmark narratives from v2/older ecosystems can be safely mixed into v5 messaging (`NINE65_CODEX_REFERENCE.md`, `docs/FHE_BENCHMARK_COMPARISON.md`, `archive/`, `jobs/v5/`).
- [ ] Assumes CI benchmark warning mode is enough to control regressions (`.github/workflows/ci.yml`).
- [ ] Assumes secure-mode benchmark results can be cleanly compared to heterogeneous external stacks without normalized harness constraints (`docs/FHE_BENCHMARK_COMPARISON.md`).

Bias risks:
- [ ] Internal benchmark data and self-authored comparative framing dominate, creating confirmation bias risk (`docs/FHE_BENCHMARK_COMPARISON.md`, `docs/PERFORMANCE_BASELINE_2026-02-09.md`).
- [ ] Legacy artifact volume can bias analysis toward stale conclusions if lineage is not explicitly partitioned (`archive/`, `jobs/v5/`, `/home/acid/Projects` historical documents).
- [ ] Security posture language is conservative in current docs but overly strong in older canonical references, creating interpretation bias (`README.md`, `docs/ARCHITECTURE.md`, `NINE65_CODEX_REFERENCE.md`).

Practicality gaps:
- [ ] No single benchmark source of truth file with versioned schema, provenance, and status across micro/meso/macro layers.
- [ ] No first-class end-to-end service benchmark suite for encrypted API workflows under load in this repo baseline set.
- [ ] No consistent benchmark environment pinning and variance envelope policy beyond ad hoc environment stamps.
- [ ] Optional/proprietary or feature-gated paths are not uniformly exercised by public CI, reducing confidence in whole-system claims (`.github/workflows/ci.yml`, `crates/nine65/Cargo.toml`).

Operational gaps:
- [ ] No policy that blocks merges when benchmark doc claims diverge from generated baselines.
- [ ] No automated docs sync mechanism to prevent stale numbers in `README.md` and comparison documents.
- [ ] No mandatory artifact promotion pipeline from benchmark run to release bundle to immutable archive.
- [ ] Fuzzing exists but is not integrated into regular CI gates (`fuzz/`, `docs/COMPREHENSIVE_TEST_REPORT_V5.md`).
- [ ] Benchmark governance ownership and review cadence are not codified in one runbook.

## 3) Risks and Constraints
- [ ] Risk: Claim credibility erosion due to conflicting metrics between README, comparison docs, and baseline docs - Impact: high - Mitigation: enforce single-source metric manifests and CI docs-sync checks.
- [ ] Risk: Regression escape in performance-critical paths due to non-blocking benchmark checks - Impact: high - Mitigation: introduce tiered blocking gates for high-priority operations.
- [ ] Risk: Side-channel posture remains pre-production while performance pressure increases - Impact: high - Mitigation: dedicated security hardening gate before any production readiness label.
- [ ] Risk: Historical artifacts contaminate decision-making for current architecture - Impact: medium - Mitigation: provenance tagging and lineage partitioning.
- [ ] Constraint: Hardware variance across benchmark hosts - Impact: medium - Mitigation: normalized benchmark tiers (instruction, wall-clock, and load envelope).
- [ ] Constraint: Proprietary feature paths cannot be fully validated in public CI - Impact: medium - Mitigation: mirrored private CI evidence with signed artifact publication.

## 4) Opportunities
- [ ] Opportunity: Build a layered benchmark stack (micro/meso/macro/adversarial) with traceable provenance and confidence intervals.
- [ ] Opportunity: Convert baseline generation scripts into repeatable release gates that feed docs automatically.
- [ ] Opportunity: Add benchmark lineage index for v2-v5 continuity and stale-claim prevention.
- [ ] Opportunity: Introduce differential cryptographic correctness plus performance co-gates (not performance-only).
- [ ] Opportunity: Align formal proof mapping with runtime benchmark targets to expose proof-to-performance coverage gaps.

## 5) Open Questions
- [ ] Which benchmark profile is the public source of truth for claims: `light_rns_exact`, `secure_128`, `secure_192`, or all three with explicit labeling? - Why it matters: avoids cherry-picking - Method to resolve: governance decision plus metric schema update.
- [ ] Should benchmark CI be warning-only or blocking for selected critical operations? - Why it matters: regression containment - Method to resolve: trial period with historical replay and false-positive analysis.
- [ ] What exact statistical confidence threshold is required for publishing comparative performance claims? - Why it matters: scientific validity - Method to resolve: define policy in benchmark runbook and enforce in pipeline.
- [ ] Which external comparator versions and parameter maps are approved for official comparisons? - Why it matters: fairness and reproducibility - Method to resolve: pin versions and scripts in a dedicated comparator harness.
- [ ] What is the production-readiness exit criterion for timing side-channel mitigation? - Why it matters: security gating - Method to resolve: explicit checklist and owner sign-off.
- [ ] How should proprietary acceleration paths publish verification evidence without exposing IP? - Why it matters: trust in optional paths - Method to resolve: signed summarized artifacts from private CI.
- [ ] Should historical references (v2/MYSTIC) be moved to a separate lineage appendix to reduce confusion in v5 docs? - Why it matters: context hygiene - Method to resolve: docs restructuring PR.

## 6) Notes
- [ ] Full scrape snapshot across `/home/acid/Projects` found 2,759 files total, including 1,205 markdown, 652 rust, and 73 python files; this confirms high legacy artifact density and validates the need for lineage partitioning.
- [ ] Canonical references requested by the planning workflow were found, but some live in `/home/acid/Projects/MYSTIC/` and are historically adjacent rather than v5-runtime sources (`INNOVATION_RESOURCE_INDEX.md`, `ENHANCED_GAP_ANALYSIS_WITH_NINE65.md`, `GAP_RESOLUTION_REPORT.md`, `nine65_v2_complete/INDEX.md`).
- [ ] The v5 repo already contains prior audit/plan outputs in `archive/` and `jobs/v5/`; these are useful context but must not replace fresh validation against current code and current baselines.
- [ ] Current benchmark ecosystem is mixed-mode: Criterion benches, test-printed benchmarks, and generated markdown baselines. Unifying these is the highest leverage systems action.
