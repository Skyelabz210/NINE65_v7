# NINE65 v7 — Repository Census Audit

**Date:** 2026-03-08
**Branch:** claude/repo-census-audit-3b6a0
**Commit base:** 62c2ad5

---

## 1. High-Level Summary

| Metric | Value |
|--------|-------|
| **Total .rs files** | 190 |
| **Total Rust LOC** | ~93,184 |
| **Total repo files** (excl. .git, target) | 687 |
| **Workspace crates** | 7 |
| **Formal proofs (Coq)** | 16 files / 6,554 lines |
| **Formal proofs (Lean4)** | 19 files / 3,692 lines |
| **Documentation files** | 58 files / ~13,771 lines |
| **Quality-gate scripts** | 12 files / 1,815 lines |
| **CI workflows** | 3 |

---

## 2. Test Suite Status

### 2.1 Per-Crate Test Results (cargo test --release)

| Crate | Passed | Failed | Ignored | Status |
|-------|--------|--------|---------|--------|
| clockwork-core | 46 | 0 | 0 | PASS |
| exact_transcendentals | 143 | 0 | 0 | PASS |
| fhe-service | 45 | 0 | 0 | PASS |
| mana | 30 | 0 | 0 | PASS |
| nexgen_rational | 95 | 0 | 0 | PASS |
| unhal | 10 | 0 | 3 | PASS |
| **nine65 (lib)** | **796** | **11** | **10** | **FAIL** |
| nine65 (integration) | — | — | — | **COMPILE ERROR** |
| **Total** | **1,165** | **11** | **13** | |

### 2.2 Failing Tests (nine65 lib — 11 failures)

All 11 failures trace to an index-out-of-bounds panic in `crates/nine65/src/ops/sbni.rs:84`:

```
index out of bounds: the len is N but the index is N
```

**Affected tests:**
1. `comprehensive_benchmarks::benchmark_depth_specific_operations_secure_128`
2. `comprehensive_benchmarks::benchmark_noise_budget_accuracy`
3. `comprehensive_benchmarks::benchmark_noise_growth_secure_128`
4. `ops::rns_fhe::tests::test_compare_symmetric_vs_public`
5. `ops::rns_fhe::tests::test_modulus_switching_basic`
6. `ops::rns_fhe::tests::test_mul_dual_public_auto_mod_switch_depth2`
7. `ops::rns_fhe::tests::test_mul_dual_public_depth3_chain`
8. `ops::rns_fhe::tests::test_mul_dual_public_with_mod_switch`
9. `ops::rns_fhe::tests::test_public_mode_depth_sweep`
10. `ops::rns_fhe::tests::test_tracked_deep_multiplication_chain`
11. `ops::rns_fhe::tests::test_try_decrypt_dual_returns_err_on_noise_exhaustion`

**Root cause:** `inject_dual_in_place` in `sbni.rs` uses the ciphertext limb count as an index without bounds checking — the index equals the length (off-by-one).

### 2.3 Integration Test Compile Errors (nine65)

`crates/nine65/tests/full_system_exercise.rs` has **33 compile errors** — references to removed/renamed `FHEConfig` constructors:
- `FHEConfig::depth3_128_insecure()`
- `FHEConfig::depth4_128_insecure()`
- And similar variants no longer present in `params/mod.rs`

These appear to have been left behind after a refactor that removed insecure config constructors.

---

## 3. Crate-by-Crate Inventory

### 3.1 nine65 (Core FHE Library)

**Purpose:** Complete BFV FHE system — encrypt, decrypt, add, mul, bootstrap, noise management, key generation.

| Category | Count |
|----------|-------|
| Source directories | 11 (arithmetic, bootstrap, entropy, keys, kiosk, noise, ops, params, ring, security, bin) |
| Source files (src/) | ~85 |
| Lines of code | ~56,360 |
| Tests (lib) | 796 passed + 11 failed + 10 ignored |
| Integration test files | 12 |
| Functions (pub fn + fn) | ~2,509 |
| Feature flags | 24+ |
| Binaries | 4 (nine65_v7_demo, nine65_bench, fhe_demo, security_estimator_baseline) |

**Largest files:**
- `ops/rns_fhe.rs` — 11,144 lines (BFV core operations)
- `arithmetic/rns.rs` — 2,920 lines (RNS/CRT parallel computation)
- `ops/bootstrap.rs` — 2,636 lines (3-path bootstrap)
- `arithmetic/k_elimination.rs` — 1,502 lines (exact rescaling)
- `entropy/crt_shadow.rs` — 1,412 lines (CRT shadow entropy)
- `ops/gso_fhe.rs` — 1,422 lines (GSO depth management)
- `ops/homomorphic.rs` — 1,412 lines (BFVEvaluator)
- `ops/rns_mul.rs` — 1,300 lines (RNS-based ct×ct multiplication)
- `noise/mod.rs` — 1,185 lines (noise infrastructure)
- `entropy/shadow_entropy_monitor.rs` — 1,091 lines (adaptive monitoring)
- `ops/symmetric_bootstrap.rs` — 1,110 lines (symmetric bootstrap)

**Module breakdown:**
- **arithmetic/** (21 files, ~14,850 LOC) — RNS, K-Elimination, NTT, Montgomery, Barrett, MobiusInt, CORDIC backend
- **ops/** (13 files, ~15,600 LOC) — BFV encrypt/decrypt/add/mul, bootstrap (3 paths), GSO, Galois, neural, batch
- **entropy/** (8 files, ~4,690 LOC) — CRT Shadow, CSPRNG, WASSAN noise, deterministic RNG
- **params/** (7 files, ~3,120 LOC) — FHEConfig, security estimator, secure configs, prime tables
- **noise/** (4 files, ~2,165 LOC) — NoiseBudget, P² quantile, EMA, boundary
- **bootstrap/** (5 files, ~1,870 LOC) — Three-Lock, Clockwork, MaskLayer, OuterLayer
- **keys/** (2 files, ~1,750 LOC) — SecretKey, PublicKey, EvalKey, BootstrapKey, KSK
- **kiosk/** (7 files, ~1,650 LOC) — Self-destructing FHE units (Bullet, Capsule, Fuse)
- **security/** (6 files, ~1,500 LOC) — CT verification, GRO gates, KeyManager, SecretData
- **ring/** (3 files, ~1,130 LOC) — RingPolynomial, PolynomialPool

### 3.2 clockwork-core

**Purpose:** Formal-spec-compliant RNS arithmetic with bound tracking, GRO timing gates, and integrity checks.

| Metric | Value |
|--------|-------|
| Files | 9 |
| LOC | 3,171 |
| Tests | 46 (all pass) |
| Dependencies | subtle, crc32fast, zeroize |

**Files:** basis.rs (549), gearstack.rs (473), gro.rs (449), integrity.rs (425), key_lifecycle.rs (444), garner.rs (370), decode_to_q.rs (225), bound_tracker.rs (195), lib.rs (41)

### 3.3 exact_transcendentals

**Purpose:** Exact integer-only transcendental functions (sin, cos, exp, ln, sqrt, pi) via CORDIC, AGM, binary splitting, continued fractions. Zero dependencies.

| Metric | Value |
|--------|-------|
| Files | 10 |
| LOC | 7,212 |
| Tests | 143 (all pass) |
| Dependencies | None |
| Features | std (default), arbitrary-precision |

**Files:** lib.rs (1,624), cordic.rs (967), agm.rs (839), binary_splitting.rs (796), bigint.rs (790), crt.rs (580), continued_fraction.rs (536), sqrt.rs (492), constants.rs (319), crt_rational.rs (269)

### 3.4 nexgen_rational

**Purpose:** Exact i128 rational arithmetic with bit-threshold GCD scheduling. Zero dependencies.

| Metric | Value |
|--------|-------|
| Files | 9 |
| LOC | 2,153 |
| Tests | 95 (all pass) |
| Dependencies | None |

**Files:** ops.rs (537), normalize.rs (493), policy.rs (376), types.rs (238), binary_gcd.rs (201), exact_coeff.rs (195), error.rs (83), lib.rs (17), mod.rs (13)

### 3.5 fhe-service

**Purpose:** REST API microservice for session-based FHE operations. Key material stays server-side.

| Metric | Value |
|--------|-------|
| Files | 5 |
| LOC | 2,666 |
| Tests | 45 (all pass) |
| Dependencies | nine65, serde, serde_json, base64, bincode, thiserror, getrandom |
| Features | allow_insecure, exact_rational |

**Files:** main.rs (1,425), handlers.rs (475), http.rs (300), session.rs (262), wire.rs (204)

### 3.6 mana

**Purpose:** FHE Stream Accelerator — lane-parallel pipeline treating CRT prime moduli as compute lanes.

| Metric | Value |
|--------|-------|
| Files | 6 |
| LOC | 2,194 |
| Tests | 30 (all pass) |
| Dependencies | zeroize, rayon (optional) |
| Features | parallel (opt-in) |

**Files:** lane.rs (736), gso.rs (428), parallel.rs (379), anchor.rs (322), stream.rs (293), lib.rs (36)

### 3.7 unhal

**Purpose:** Universal Neuromorphic Hardware Abstraction Layer — unified API over MANA for auto-detected accelerator selection.

| Metric | Value |
|--------|-------|
| Files | 4 |
| LOC | 899 |
| Tests | 10 passed + 3 ignored |
| Dependencies | mana, rayon (optional) |
| Features | parallel (default), simd (stub) |

**Files:** accelerator.rs (395), batch.rs (243), pipeline.rs (195), lib.rs (66)

---

## 4. Formal Verification

### 4.1 Coq Proofs (16 files, 6,554 lines)

| Proof File | Lines | Subject |
|------------|-------|---------|
| MontgomeryContext.v | 1,099 | Montgomery modular exponentiation correctness |
| OrderFinding.v | 915 | Order-finding for cyclotomic rings |
| KElimination.v | 711 | K-Elimination rescaling algorithm |
| MontgomeryPersistent.v | 574 | Persistent Montgomery state preservation |
| SideChannelResistance.v | 483 | Constant-time timing resistance |
| GSOFHE.v | 441 | GSO depth management bounds |
| MobiusInt.v | 370 | Mobius inversion on integers |
| KElimination_Completed.v | 322 | K-Elimination anchor limb handling |
| MQReLU.v | 317 | Encrypted MQ-ReLU activation function |
| IntegerSoftmax.v | 234 | Integer-based softmax correctness |
| PadeEngine.v | 229 | Pade approximant engine |
| StateCompression.v | 205 | FHE state compression and recovery |
| CyclotomicPhase.v | 197 | Cyclotomic field phase analysis |
| CRTShadowEntropy.v | 179 | CRT Shadow entropy harvester |
| ExactCoefficient.v | 162 | Exact coefficient reconstruction |
| EncryptedQuantum.v | 116 | Encrypted quantum computation primitives |

### 4.2 Lean4 Proofs (19 files, 3,692 lines)

| Proof File | Lines | Subject |
|------------|-------|---------|
| KElimination.lean | 692 | Main K-Elimination entry point |
| Hardness.lean (AHOP/) | 363 | AHOP hardness reduction |
| CRT.lean (Lattice/) | 246 | Chinese Remainder Theorem |
| OrderFinding.lean | 237 | Order-finding algorithm |
| Algebra.lean (AHOP/) | 213 | AHOP algebraic structures |
| Montgomery.lean | 200 | Montgomery multiplication |
| MobiusInt.lean | 179 | Mobius inversion |
| SideChannel.lean | 172 | Side-channel resistance |
| MQReLU.lean | 172 | MQ-ReLU correctness |
| EncryptedQuantum.lean | 170 | Encrypted quantum primitives |
| StateCompression.lean | 168 | State compression |
| GSOFHE.lean | 176 | GSO-FHE depth management |
| CyclotomicPhase.lean | 153 | Cyclotomic phase analysis |
| ExactCoefficient.lean | 148 | Exact coefficient reconstruction |
| IntegerSoftmax.lean | 122 | Integer softmax |
| PadeEngine.lean | 105 | Pade approximant engine |
| Parameters.lean (AHOP/) | 69 | AHOP parameters |
| ShadowEntropy.lean | 58 | Shadow entropy harvesting |
| Basic.lean | 37 | Core definitions |

---

## 5. Documentation (58 files)

### By Category:
- **Architecture & Design:** 7 files (ARCHITECTURE.md, CLOCKWORK_FORMAL_SPECIFICATION.md, etc.)
- **Security & Threat Analysis:** 11 files (SECURITY_PROOFS.md, SIDE_CHANNEL_THREAT_MODEL.md, NIST_COMPLIANCE_MATRIX.md, etc.)
- **Performance Baselines:** 8 files + 2 JSON data files (5 dated baselines from Jan–Feb 2026)
- **Lattice Estimator Baselines:** 4 files (Jan–Feb 2026)
- **Test & Audit Reports:** 8 files (CLOCKWORK_BOOTSTRAP_TEST_REPORT.md, COMPREHENSIVE_AUDIT_REPORT_V5.md, etc.)
- **Execution Plans:** 6 files
- **Release & Operations:** 6 files
- **Code Artifacts:** 2 files (clockwork_bootstrap_public.rs, k_elim_edge_cases.py)
- **Other:** CLAIM_REGISTRY.csv, FAQ_HOTSHEET.md, FHE_BENCHMARK_COMPARISON.md

---

## 6. Scripts & CI

### 6.1 Quality-Gate Scripts (12 files, 1,815 lines)

| Script | Lines | Purpose |
|--------|-------|---------|
| generate_summary_json.sh | 439 | Generate test/benchmark JSON summaries |
| regression_scan.sh | 247 | Regression detection across builds |
| verify_constant_time.sh | 229 | Verify constant-time code paths |
| generate_performance_baseline.sh | 192 | Generate performance baseline metrics |
| generate_depth_correctness_matrix.py | 172 | Depth vs correctness matrix (Python) |
| check_stale_claims.sh | 162 | Validate stale claims in registry |
| check_no_floats_runtime.sh | 95 | Enforce zero floating-point |
| check_no_panics.sh | 95 | Scan for unsafe panic macros |
| check_claim_registry.sh | 77 | Verify claim registry completeness |
| extract_criterion_summary.py | 65 | Extract Criterion benchmark summaries (Python) |
| generate_security_baseline.sh | 28 | Generate security parameter baselines |
| metrics.sh | 14 | Quick metrics snapshot |

### 6.2 CI Workflows (3 files)
- `ci.yml` — Main CI pipeline (tests, clippy, fmt)
- `coq_proofs.yml` — Coq formal proof verification
- `ct_verification.yml` — Constant-time verification

---

## 7. Additional Directories

| Directory | Contents |
|-----------|----------|
| apps/ | fhe-service REST API, nine65-telemetry-gateway |
| archive/ | Historical artifacts, PDFs, prior reports |
| fuzz/ | Fuzzing infrastructure and targets |
| sdks/python/ | Python bindings |
| security_proofs/ | Standalone security verification crate |
| verified-innovations/ | Compiled Coq proof artifacts (.vo, .vok, .vos) |
| state/ | blueprint.json runtime state |

---

## 8. Root Configuration

| File | Lines | Purpose |
|------|-------|---------|
| Cargo.toml | 40 | Workspace manifest (7 crates) |
| Cargo.lock | 1,160 | Dependency lock file |
| Dockerfile | 39 | Two-stage Docker build |
| deny.toml | 36 | Cargo-deny supply chain security |
| LICENSE | 10 | Proprietary (Acidlabz210) |
| CLAUDE.md | ~130 | Claude Code project context |
| README.md | ~250 | Project overview |
| SECURITY.md | ~130 | Security policy |
| CONTRIBUTING.md | ~100 | Contribution guidelines |
| .github/workflows/ | 3 files | CI pipelines |

---

## 9. Known Issues Summary

| Issue | Severity | Location | Description |
|-------|----------|----------|-------------|
| SBNI index out of bounds | HIGH | `ops/sbni.rs:84` | Off-by-one in `inject_dual_in_place` — causes 11 test failures |
| Stale integration tests | MEDIUM | `tests/full_system_exercise.rs` | 33 compile errors referencing removed `FHEConfig` constructors |
| 3 ignored unhal tests | LOW | unhal crate | Tests skipped (likely feature-gated) |
| 10 ignored nine65 tests | LOW | nine65 lib | Tests skipped (likely slow_tests or feature-gated) |

---

## 10. Aggregate Statistics

| Category | Files | Lines of Code | Tests |
|----------|-------|---------------|-------|
| nine65 (core) | ~85 | ~56,360 | 817 (796p/11f/10i) |
| clockwork-core | 9 | 3,171 | 46 |
| exact_transcendentals | 10 | 7,212 | 143 |
| nexgen_rational | 9 | 2,153 | 95 |
| fhe-service | 5 | 2,666 | 45 |
| mana | 6 | 2,194 | 30 |
| unhal | 4 | 899 | 13 (10p/3i) |
| **Rust Total** | **~128 src** | **~74,655** | **1,189** |
| Coq proofs | 16 | 6,554 | — |
| Lean4 proofs | 19 | 3,692 | — |
| Docs | 58 | ~13,771 | — |
| Scripts | 12 | 1,815 | — |
| **Grand Total** | **~233+ src** | **~100,487** | **1,189** |

---

*Generated by Claude Code census audit on 2026-03-08.*
