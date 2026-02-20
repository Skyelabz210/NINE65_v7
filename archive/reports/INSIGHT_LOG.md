# INSIGHT_LOG.md

Project: NINE65 v5 public-ready variant
Date: 2026-01-27
Analyst: Codex

## 1) Evidence Map

Applied (implemented + wired):
- [ ] CI pipeline with build/test/clippy/rustfmt/audit/deny plus scheduled timing tests (.github/workflows/ci.yml)
- [ ] Ciphertext and Galois key serde + validation helpers, with deprecated unsafe deserialization paths (crates/nine65/src/ops/encrypt.rs, crates/nine65/src/ops/galois.rs)
- [ ] Fuzz target for deserialization validation (fuzz/fuzz_targets/fuzz_deserialize.rs)
- [ ] Production-safe parameter sets and deprecation of insecure configs (crates/nine65/src/params/secure_configs.rs, crates/nine65/src/params/mod.rs)
- [ ] Constant-time Montgomery operations implemented (crates/nine65/src/arithmetic/montgomery.rs)
- [ ] Noise budget tracking and tracked public-mode ops (crates/nine65/src/noise/budget.rs, crates/nine65/src/ops/rns_fhe.rs)
- [ ] Release checklist with perf gate guidance (docs/RELEASE_CHECKLIST.md)

Intended (documented, not wired):
- [ ] Public-mode modulus switching path exists, but depth verification is only in ignored or diagnostic tests (crates/nine65/src/ops/rns_fhe.rs)
- [ ] Lattice estimator integration referenced in docs, but no script or published artifacts exist in repo (docs/SECURITY_GAP_ANALYSIS.md)

Expected (claims not yet verified):
- [ ] README security estimates and docs/SECURITY_PROOFS rough estimates conflict with RedShirt findings (README.md, docs/SECURITY_PROOFS.md, docs/REDSHIRT_SECURITY_ASSESSMENT.md)
- [ ] Performance claims in README and benchmark docs lack enforced perf gates or published baselines (README.md, docs/FHE_BENCHMARK_COMPARISON.md, docs/RELEASE_CHECKLIST.md)
- [ ] Architecture docs reference removed quantum modules and assert production-ready status while public mode depth is limited (README.md, docs/ARCHITECTURE.md, docs/SECURITY_GAP_ANALYSIS.md)

## 2) Gaps

Logic gaps:
- [ ] Public mode depth is effectively 1; depth-2 fails in diagnostics and is documented as a critical gap (docs/SECURITY_GAP_ANALYSIS.md, docs/SECURITY_PROOFS.md, crates/nine65/src/ops/rns_fhe.rs)
- [ ] Public-mode overflow at N=4096 is called out in security gap analysis; fix status is not verified in repo (docs/SECURITY_GAP_ANALYSIS.md)
- [ ] "Zero floating-point guarantee" conflicts with compiler noise analysis using floats (README.md vs crates/nine65/src/compiler.rs)

Assumptions:
- [ ] Security rating 9.0/10 and "production ready" labels are accurate despite RedShirt stating production not recommended until gaps are fixed (docs/SECURITY_GAP_ANALYSIS.md, docs/ARCHITECTURE.md, docs/REDSHIRT_SECURITY_ASSESSMENT.md)
- [ ] SecureConfig is the default for public releases, but README examples still use light_rns_exact (README.md)
- [ ] Shadow entropy NIST compliance is complete, but RedShirt marks it partial (README.md, docs/REDSHIRT_SECURITY_ASSESSMENT.md)

Bias risks:
- [ ] Performance tables and "best in class" claims rely on internal runs without published baselines (README.md, docs/FHE_BENCHMARK_COMPARISON.md)

Practicality gaps:
- [ ] Public key FHE (multi-party) circuits cannot exceed depth-1 without fixes; a public-ready variant cannot promise deeper public computations yet (docs/SECURITY_GAP_ANALYSIS.md, crates/nine65/src/ops/rns_fhe.rs)
- [ ] No Python or WASM bindings for broader adoption (docs/SECURITY_GAP_ANALYSIS.md)
- [ ] Proprietary license blocks public distribution unless clarified or changed (LICENSE)

Operational gaps:
- [ ] Fuzzing exists but is not wired into CI (fuzz/fuzz_targets/fuzz_deserialize.rs, .github/workflows/ci.yml)
- [ ] Release artifacts and vulnerability disclosure policy are missing (no SECURITY.md, no CONTRIBUTING.md)
- [ ] Doc drift across README/ARCHITECTURE/SECURITY_PROOFS vs current assessments and code

## 3) Risks and Constraints
- [ ] Public-mode depth limitation can yield incorrect results after a single multiplication; high user risk for public-key workflows
- [ ] Inconsistent security claims create compliance and reputational risk in a public release
- [ ] Constraint: no unsafe code; crypto core must remain deterministic and integer-only
- [ ] Constraint: performance claims must be reproducible on documented hardware

## 4) Opportunities
- [ ] Define a public-ready profile: SecureConfig-only defaults, remove insecure examples, and enforce production-safe assertions at entry points
- [ ] Turn perf and security baselines into CI artifacts or documented release gates
- [ ] Add public release docs: SECURITY.md, CONTRIBUTING.md, RELEASE_NOTES.md, and explicit supported-scope statements

## 5) Open Questions
- [ ] What exact definition of "public-ready" is required: public-key depth target, supported modes, and minimum security level?
- [ ] Should public releases allow the allow_insecure feature at all, or must it be disabled in published artifacts?
- [ ] Which config is the production default: secure_128, secure_192, or something else?
- [ ] Are the README performance and security claims intended for public marketing, or should they be downgraded to internal notes?
- [ ] What license and disclosure policy should govern the public release?
- [ ] Do we need third-party audit sign-off before declaring public readiness?

## 6) Notes
- CI exists and covers build/test/clippy/fmt/audit/deny; timing tests run on schedule (see .github/workflows/ci.yml)
- Public mode diagnostics and depth sweep tests are ignored by default; they need explicit enablement for gating
