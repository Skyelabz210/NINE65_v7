# EXECUTION_PLAN.md

Project: NINE65 v5 public-ready variant
Date: 2026-01-27
Scope: Public release hardening for public-key FHE, documentation alignment, and release gating
Principles: Rust-first, no feature-flag fallbacks, deterministic integer-only arithmetic.

## 1) Goals and Acceptance Criteria
- Goal 1: Define public-ready scope and enforce a production-safe default
- Goal 2: Public mode supports the agreed depth target with secure configs
- Goal 3: Security and performance claims are consistent, reproducible, and documented
- Goal 4: Release pipeline and docs are ready for external users

Acceptance criteria:
- [ ] Public-ready definition published (supported modes, depth target, security baseline)
- [ ] README and docs use SecureConfig by default; insecure configs are clearly test-only
- [ ] Public-mode depth tests pass at the agreed depth on secure_128 or secure_192
- [ ] Lattice estimator outputs are recorded and referenced in security docs
- [ ] CI or release gates cover tests, security checks, and at least one reproducible perf baseline
- [ ] Public release docs include SECURITY.md, CONTRIBUTING.md, and license decision

## 2) Task List (Ordered)
- [ ] Task 1: Define public-ready scope and defaults
  - Outcome: A single public-ready profile (config + features) with no insecure fallbacks
  - Verification: New doc section in README and a compile-time guard or runtime assert in public entry points

- [ ] Task 2: Public-mode depth remediation
  - Outcome: Public-key FHE passes depth target (>= 2, or higher if required) on secure configs
  - Work: resolve public-mode noise growth, verify modulus switching path, and confirm no overflow at N=4096/8192
  - Verification: Unignored depth tests in crates/nine65/src/ops/rns_fhe.rs and a new regression test for depth target

- [ ] Task 3: Security estimator integration
  - Outcome: Reproducible security estimates for secure_128/secure_192/secure_256
  - Work: add a script or documented command sequence and store results in docs
  - Verification: docs/SECURITY_PROOFS.md and docs/SECURITY_GAP_ANALYSIS.md updated with estimator outputs

- [ ] Task 4: Documentation alignment pass
  - Outcome: No conflicting security or architecture claims
  - Work: update README, docs/ARCHITECTURE.md, docs/SECURITY_PROOFS.md, and docs/REDSHIRT_SECURITY_ASSESSMENT.md addendum
  - Verification: cross-doc consistency check (security tables, module lists, performance claims)

- [ ] Task 5: Release validation gates
  - Outcome: CI or release checklist enforces functional, security, and perf baselines
  - Work: wire fuzz target into CI (nightly if needed), define perf baseline environment and thresholds, ensure no ignored critical tests
  - Verification: CI config updated and release checklist reflects enforced gates

- [ ] Task 6: Public release packaging
  - Outcome: External users can build, audit, and report issues
  - Work: add SECURITY.md and CONTRIBUTING.md, decide license, add versioning/release notes
  - Verification: new docs exist and README points to them

## 3) Validation Gates
- Gate A: Public-mode depth target passes on secure configs with non-ignored tests
- Gate B: Security estimator outputs are recorded and cited in security docs
- Gate C: README quick start uses SecureConfig and removes insecure examples
- Gate D: CI or release checklist enforces tests, audit, deny, and perf baseline
- Gate E: Public release docs and license are finalized

## 4) Risks
- Risk: Public-mode depth fix may require parameter changes that affect performance or API defaults
- Risk: Security claim alignment may require removing or downgrading published benchmark claims
- Risk: External audit timelines can delay public readiness

## 5) Dependencies
- Lattice estimator tooling and reproducible scripts
- External audit availability (if required for public readiness)
- Hardware baseline for perf gates
- License decision for public distribution
