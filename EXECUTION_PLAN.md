Project: NINE65 v5
Date: 2026-02-11
Scope: full-system reanalysis for current-state correctness, benchmark credibility, cross-layer coupling, and production-readiness evidence
Principles: Rust-first, no feature-flag fallbacks, deterministic arithmetic, evidence over narrative, reproducibility before claims

## 0) Program Definition

Objective:
- Replace fragmented benchmark and validation practice with a single, verifiable, multi-layer system that reflects the current v5 architecture, not legacy snapshots.

Non-negotiables:
- No fallback architecture tracks.
- One source of truth for published metrics.
- Every claim must map to code path, test/benchmark artifact, and timestamped environment.
- Security hardening gates are first-class blockers.

## 1) Goals and Acceptance Criteria

- Goal 1: Establish a canonical claim-to-evidence registry for all performance, depth, and security statements.
- Goal 2: Build layered benchmark frameworks (micro, meso, macro, adversarial) with machine-readable outputs and reproducible environments.
- Goal 3: Close cross-layer drift between docs, code, scripts, CI, and service integration.
- Goal 4: Introduce strict release gates that reject stale or contradictory benchmark/security claims.
- Goal 5: Separate current v5 truth from legacy v2/MYSTIC and archive artifacts while preserving lineage.
- Goal 6: Provide decision-ready roadmap for remaining high-risk security and operational gaps.

Acceptance criteria:
- [ ] Every benchmark claim in `README.md` is generated from versioned baseline artifacts.
- [ ] `docs/FHE_BENCHMARK_COMPARISON.md` is either fully reproducible under pinned harnesses or demoted to clearly-labeled research context.
- [ ] CI enforces benchmark gates for at least one critical operation set per tier (micro and macro).
- [ ] Security estimate values are internally consistent across all docs and baseline artifacts.
- [ ] Side-channel readiness has explicit exit criteria and tracked status.
- [ ] End-to-end service benchmark suite exists and runs in automated cadence.
- [ ] Legacy artifacts are tagged with provenance and excluded from active claim generation.
- [ ] Release checklist is executable and verifiable, not advisory only.

## 2) Task List (Ordered)

### Phase 0 - Governance and Source of Truth (Week 1)

- [ ] T001 - Create `docs/benchmarking/BENCHMARK_GOVERNANCE.md` that defines claim policy, ownership, and publication flow - verification: governance doc approved by core, perf, and security owners.
- [ ] T002 - Create `docs/benchmarking/METRIC_SCHEMA.md` with canonical fields (metric_id, scope, config, feature set, host, commit, command, stats, confidence, artifact path) - verification: schema lint script passes on existing baseline docs converted to schema.
- [ ] T003 - Create `docs/benchmarking/CLAIM_REGISTRY.md` mapping each public claim to evidence artifact IDs - verification: all current README benchmark/security rows mapped.
- [ ] T004 - Decide official metric profiles for public claims (`secure_128`, `secure_192`, `secure_256`, with explicit test-only profile treatment) - verification: signed decision record committed.
- [ ] T005 - Define comparator scope and pinned versions for external libraries - verification: comparator manifest committed and referenced by CI.

### Phase 1 - Artifact and Lineage Normalization (Week 1 to Week 2)

- [ ] T006 - Add `docs/benchmarking/LINEAGE_INDEX.md` partitioning v5-current, v5-archive, v2, and external historical artifacts - verification: all known baseline and archive folders indexed with status tags.
- [ ] T007 - Add `scripts/benchmark/normalize_baseline_artifacts.sh` to convert existing markdown and logs into schema-compliant json/csv artifacts - verification: conversion produces deterministic outputs from current baseline docs.
- [ ] T008 - Add stale-claim scanner that diff-checks docs values against canonical artifacts - verification: scanner identifies known drifts currently in README and comparison docs.
- [ ] T009 - Introduce artifact naming convention with timestamp, commit hash, profile, and host fingerprint - verification: generated files follow convention in dry run.
- [ ] T010 - Establish immutable artifact storage path and retention policy - verification: retention policy documented and test upload path validated.

### Phase 2 - Microbenchmark Framework Hardening (Week 2 to Week 3)

- [ ] T011 - Split microbench targets into deterministic and host-sensitive classes (instruction-focused vs wall-clock) - verification: benchmark taxonomy document created and applied to all existing bench files.
- [ ] T012 - Add precision guardrails for low-latency operations to prevent "0ns" outputs (increase iterations, aggregate cycles, or alternate harness) - verification: no 0ns rows in regenerated microbench artifacts.
- [ ] T013 - Build dedicated microbench harness wrapper under `scripts/benchmark/run_microbench.sh` with pinned cpu-governor instructions and metadata capture - verification: wrapper outputs schema-complete artifact.
- [ ] T014 - Add benchmark coverage for currently missing high-value ops (Galois rotations, batch encode/decode, serialization cost) - verification: new benchmarks compile and emit artifacts.
- [ ] T015 - Add benchmark sanity checks that reject impossible throughput values and timer-resolution artifacts - verification: sanity checker fails on intentionally malformed sample artifact.

### Phase 3 - Meso Benchmark and Correctness Coupling (Week 3 to Week 4)

- [ ] T016 - Create operation-chain benchmarks that mirror real cryptographic workflows (encrypt->mul chain->rescale/decrypt) per secure profile - verification: artifacts include depth, correctness, and noise envelope.
- [ ] T017 - Couple each meso benchmark with correctness assertions (not timing-only) and deterministic test vectors - verification: each benchmark output includes pass/fail correctness section.
- [ ] T018 - Build public-mode depth matrix harness with explicit decomposition-base and config dimensions - verification: matrix artifact generated for all approved profiles.
- [ ] T019 - Add noise-budget trajectory capture to meso benchmarks - verification: per-step noise data exported and checked against configured limits.
- [ ] T020 - Define allowed variance bands and confidence reporting for meso benchmarks - verification: policy applied in generated report footer.

### Phase 4 - Macro End-to-End Benchmark Framework (Week 4 to Week 5)

- [ ] T021 - Implement end-to-end service benchmark suite under `crates/fhe-service` test/bench tooling (session create, encrypt, evaluate, decrypt, delete) - verification: reproducible macrobench artifacts generated in CI-like environment.
- [ ] T022 - Add concurrent session throughput and contention benchmark scenarios (session store lock pressure, mixed operation workloads) - verification: p50/p95/p99 latency metrics captured.
- [ ] T023 - Add payload-size and serialization overhead benchmarks for realistic ciphertext transport sizes - verification: payload vs latency curve artifact generated.
- [ ] T024 - Add macrobench error-path benchmarks (invalid ciphertexts, malformed requests, session-not-found storms) - verification: error rates and resource impact captured.
- [ ] T025 - Define service-level benchmark acceptance thresholds and regression budgets - verification: thresholds committed and validated against current baseline.

### Phase 5 - Security and Adversarial Validation Track (Week 5 to Week 6)

- [ ] T026 - Create side-channel hardening validation checklist with measurable pass criteria - verification: checklist approved and tied to release gates.
- [ ] T027 - Add adversarial benchmark suite for worst-case key/ciphertext patterns and hostile request patterns - verification: adversarial artifact set generated with reproducible seeds.
- [ ] T028 - Integrate fuzz cadence policy (nightly or scheduled) and artifact capture into CI governance - verification: fuzz job runs and uploads crash corpus deltas.
- [ ] T029 - Reconcile security estimator values across all docs from one generated baseline source - verification: zero value drift in security tables after regeneration.
- [ ] T030 - Add explicit production-readiness blocker ledger for unresolved security issues - verification: blocker status visible in release summary artifact.

### Phase 6 - Proof-Code-Benchmark Coherence (Week 6)

- [ ] T031 - Expand formalization map to include benchmark coverage references for each mapped theorem/module where relevant - verification: `docs/FORMALIZATION_INDEX.md` includes benchmark linkage column.
- [ ] T032 - Mark excluded proof domains in all public claims to prevent over-broad "fully verified" language - verification: docs scanner confirms required disclaimer presence.
- [ ] T033 - Add proof-build and benchmark-run joint report template to show mathematical and empirical status together - verification: generated joint report for one release candidate.
- [ ] T034 - Build coverage gap report: proof-mapped modules lacking benchmark coverage, and benchmark-heavy modules lacking formal traceability - verification: report generated and reviewed.

### Phase 7 - Documentation and Claim Reconciliation (Week 6 to Week 7)

- [ ] T035 - Replace manually maintained benchmark tables in `README.md` with generated include blocks from canonical artifacts - verification: docs regeneration script updates README deterministically.
- [ ] T036 - Rebuild `docs/FHE_BENCHMARK_COMPARISON.md` using pinned comparator harness outputs or reclassify as non-claim research note - verification: claim status header present and validated.
- [ ] T037 - Correct stale command references (for example invalid benchmark target names) via command-liveness checks - verification: all listed commands resolve to existing targets.
- [ ] T038 - Synchronize baseline doc references to latest generated artifacts only - verification: docs linter detects no outdated baseline links.
- [ ] T039 - Add "claim freshness" timestamp and commit hash stamps to headline docs - verification: freshness metadata present and machine-checked.

### Phase 8 - CI and Release Gate Enforcement (Week 7 to Week 8)

- [ ] T040 - Convert benchmark-check from advisory to tiered gating (critical set blocking, extended set advisory) - verification: PR with induced regression fails at critical tier.
- [ ] T041 - Add docs-claim consistency check to CI (fails on metric drift) - verification: intentional mismatch triggers failure.
- [ ] T042 - Add artifact completeness check (environment metadata + schema validity required) - verification: missing metadata causes CI failure.
- [ ] T043 - Wire baseline generation scripts into release workflow and artifact upload path - verification: release candidate produces full baseline bundle automatically.
- [ ] T044 - Add benchmark trend dashboard export (CSV/JSON) for longitudinal monitoring - verification: trend artifact generated across at least three runs.

### Phase 9 - Service Integration Completion for Benchmark-Relevant Features (Week 8 to Week 9)

- [ ] T045 - Integrate Galois rotation endpoints and corresponding macrobench scenarios - verification: rotation benchmarks and API tests pass.
- [ ] T046 - Integrate batch mode encode/decode path and benchmark slot-level throughput - verification: batch throughput artifact vs single-item baseline generated.
- [ ] T047 - Integrate parallel encrypt/decrypt path where applicable and benchmark at realistic concurrency - verification: measurable throughput gain documented with guardrails.
- [ ] T048 - Expose depth-aware config options in service API with validation - verification: config acceptance tests and benchmark matrix include new config.
- [ ] T049 - Add session TTL/reaper, rate limiting, and audit logging benchmarks as operational security gates - verification: macrobench includes these controls with overhead analysis.

### Phase 10 - Rollout and Operationalization (Week 9 onward)

- [ ] T050 - Publish v5 benchmark handbook and operator runbook update - verification: docs reviewed and linked from root README.
- [ ] T051 - Establish weekly benchmark review cadence with owner rotation - verification: recurring review records in `docs/benchmarking/reviews/`.
- [ ] T052 - Establish monthly claim audit against latest artifacts - verification: monthly signed audit report generated.
- [ ] T053 - Add deprecation policy for stale benchmark artifacts and historical docs - verification: archive tags applied automatically after policy threshold.
- [ ] T054 - Freeze "production-ready" labeling until all critical security and benchmark gates are green - verification: release checklist includes hard blocker checks.

## 3) Validation Gates

- Gate A: Schema Integrity Gate
  - Required: all benchmark/security artifacts validate against `METRIC_SCHEMA`.
  - Evidence: schema validator output and artifact manifest.

- Gate B: Command Liveness Gate
  - Required: every command in README/docs resolves to live targets.
  - Evidence: command-liveness CI report.

- Gate C: Claim Consistency Gate
  - Required: zero drift between docs claims and canonical artifacts.
  - Evidence: docs-claim diff checker output.

- Gate D: Microbenchmark Credibility Gate
  - Required: no timer-resolution artifacts; confidence stats present.
  - Evidence: microbench report with variance and confidence metadata.

- Gate E: Meso Correctness-Performance Gate
  - Required: benchmark chains include correctness and noise validation.
  - Evidence: combined timing + correctness artifact.

- Gate F: Macro Service Gate
  - Required: end-to-end benchmarks for single, concurrent, and adversarial scenarios.
  - Evidence: macrobench suite outputs with p50/p95/p99 and error metrics.

- Gate G: Security Readiness Gate
  - Required: side-channel blocker checklist status tracked and critical blockers closed for release labeling.
  - Evidence: signed security gate report.

- Gate H: Formal-Coherence Gate
  - Required: proof mapping and benchmark mapping have no unresolved high-severity contradictions.
  - Evidence: proof-code-benchmark coherence report.

- Gate I: CI Enforcement Gate
  - Required: critical benchmark regressions fail PR checks.
  - Evidence: CI policy and regression test demonstration.

- Gate J: Release Artifact Gate
  - Required: release bundle contains baseline docs, raw artifacts, environment metadata, and claim registry snapshot.
  - Evidence: release artifact manifest.

## 4) Risks

- Risk: Benchmark gate flakiness due to host variance.
  - Mitigation: tiered gates, instruction-level supplemental metrics, variance envelopes.

- Risk: Increased CI runtime and developer friction.
  - Mitigation: split smoke vs extended tiers and scheduled heavy runs.

- Risk: Security hardening and benchmarking efforts compete for bandwidth.
  - Mitigation: shared gate model where security blockers are explicit and non-negotiable.

- Risk: Legacy artifacts continue to be cited unintentionally.
  - Mitigation: lineage index, stale-doc scanner, archive labeling policy.

- Risk: Proprietary acceleration path remains unverifiable publicly.
  - Mitigation: signed summarized evidence from private CI and clear claim boundaries.

## 5) Dependencies

- Dependency: Cryptography owner for security-model and side-channel exit criteria.
  - Source: core crypto maintainers.

- Dependency: Performance engineering owner for benchmark architecture and statistics policy.
  - Source: performance team.

- Dependency: DevOps owner for CI gate implementation and artifact publication.
  - Source: platform team.

- Dependency: Documentation owner for generated-claim workflow and freshness policy.
  - Source: docs/release maintainers.

- Dependency: Service maintainers for macrobench and feature wiring tasks.
  - Source: `crates/fhe-service` owners.

- Dependency: Optional proprietary CI channel for `accelerated` feature evidence.
  - Source: private infrastructure maintainers.

## 6) Initial Execution Order (First 10 Working Days)

- Day 1-2: T001-T005 (governance, profile decisions, comparator scope).
- Day 3-4: T006-T010 (artifact normalization and lineage index).
- Day 5-6: T011-T015 (microbench hardening and zero-time guardrails).
- Day 7-8: T016-T020 (meso correctness-performance coupling).
- Day 9-10: T035-T039 (documentation and claim reconciliation bootstrap).

Success checkpoint at Day 10:
- [ ] Claim registry exists.
- [ ] Drift scanner catches known inconsistencies.
- [ ] Regenerated docs remove contradictory benchmark/security values.
- [ ] First canonical artifact set published with schema validation.
