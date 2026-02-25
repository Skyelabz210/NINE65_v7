# NINE65 v6 "a Clockwork Prime" — Master Execution Plan

**Date**: 2026-02-15
**Source**: Deep system analysis + FHE landscape research (NIST, lattice attacks, IBM key recovery paper)
**Status**: 953 tests passing, 0 failures — but CRITICAL gaps identified
**Goal**: Production-ready FHE system with verified security guarantees

---

## INTELLIGENCE BRIEFING: What We're Up Against

### IBM Key Recovery Attack on BFV (2025) — DIRECTLY RELEVANT
IBM Research demonstrated key recovery attacks against BFV implementations in SEAL, OpenFHE, and Lattigo with 217-256 bit security parameters. Attacks take minutes to hours on standard hardware. Root cause: **noise overflow causes decryption failures that leak key bits**. This validates our exact-arithmetic approach but demands we close noise-budget gaps immediately.

### NIST FHE Standardization
- NIST PEC project tracking FHE; Threshold Call submissions due 2025
- ISO/IEC FHE standard influenced by HomomorphicEncryption.org parameters
- HES9 meeting: March 5-6, 2026, Seoul — our parameter choices must align
- HE Standard v1.1 security tables are the baseline (already referenced in our code)

### Lattice Attack Updates
- MATZOV dual attack reduced Kyber-512/768/1024 security by 3.5-12.3 bits below NIST thresholds
- New NTRU key recovery with 400 leaked coefficients: β drops from 350→38 (Falcon-512)
- Core-SVP model remains conservative; MATZOV more aggressive but realistic
- Our estimator uses Core-SVP (good) but should cross-validate with MATZOV

### Circular Security
- Counterexamples found for LWE-with-hint circular security assumptions (used in iO constructions)
- New CRO (Circular Security with Random Opening) assumption proposed as fix
- Our Clockwork Bootstrap uses circular security (boot_sk = work_sk) — needs formal validation

### Competition Landscape
- OpenFHE 1.4.2 (Oct 2025): BFV/BGV/CKKS/FHEW — most complete
- TFHE-rs v1.5 (Jan 2026): Pure Rust, stable API, ZK proof support
- SEAL: BFV/CKKS/BGV — 200% faster per-op than others
- Orion (ASPLOS 2025 best paper): 2.38x FHE-ML speedup, YOLO-v1 with 139M params
- Cinnamon: 36,600x speedup on BERT via scale-out FHE

### FHE-ML State of the Art
- Inference: practical with CKKS/BFV (Orion, Cinnamon prove viability)
- Training: still challenging; bootstrapping latency is the bottleneck
- Integer-only approaches (BFV/BGV) gaining ground over approximate (CKKS)
- Our bootstrap-free + unlimited-depth is architecturally superior IF noise is handled

---

## SYSTEM ANALYSIS: Current State

### Strengths
- 953 tests, 0 failures
- `#![forbid(unsafe_code)]` on nine65, nexgen_rational, mana
- Integer-only compliance: ZERO float violations in runtime code
- Clockwork Bootstrap: unlimited depth with auto-refresh
- K-Elimination: formally verified in Coq + Lean4
- Security estimator: integer-only, HE Standard v1.1 compliant
- CI: 10 gates including security audit, claim drift, benchmark regression

### Critical Gaps (11 CRITICAL issues)
| ID | Issue | Impact |
|----|-------|--------|
| C1 | 26+ `panic!()` in production code | Crashes instead of error returns |
| C2 | 30+ `unwrap()`/`expect()` in production | Same — crashes, info leaks |
| C3 | CT enforcement planned but NOT implemented | Side-channel vulnerability |
| C4 | GRO timing gates not integrated into keygen/decrypt | Timing attacks possible |
| C5 | K-Elimination preconditions not validated at runtime | Silent logic errors |
| C6 | Noise budget overflow not detected (wraps negative) | Silent decryption failure → key recovery (IBM attack vector) |
| C7 | NTT config validation uses assert not error | Crashes on bad config |
| C8 | Entropy source has no health checks | Single point of failure |
| C9 | Side-channel hardening tracking absent | No visibility into posture |
| C10 | Circular security claim untested | Bootstrap correctness unverified |
| C11 | Error messages leak cryptographic values | Side-channel via error text |

### High Priority Gaps (13 HIGH issues)
| ID | Issue |
|----|-------|
| H1 | NTT not marked CT-safe vs variable-time |
| H2 | Bootstrap primes not auto-validated |
| H3 | Modswitch rescaling exactness unverified |
| H4 | Noise tracking not integrated with evaluator |
| H5 | Missing edge case tests (8 categories) |
| H6 | No constant-time regression testing in CI |
| H7 | Limit checking not comprehensive |
| H8 | Public APIs without Rustdoc |
| H9 | Formalization index incomplete |
| H10 | CI missing float/panic/CT gates |
| H11 | Benchmark gate advisory only |
| H12 | Large files need refactoring (rns_fhe.rs ~7200 lines) |
| H13 | Secret info in error messages |

---

## EXECUTION PLAN

### Architecture: 6 Segments, 3 Phases

```
PHASE 1: FORTIFY (Segments A + B in parallel)
├── Segment A: Error Handling & Panic Elimination [CRITICAL]
└── Segment B: Cryptographic Correctness Hardening [CRITICAL]

PHASE 2: HARDEN (Segments C + D in parallel, after Phase 1)
├── Segment C: Security Integration & Side-Channel [CRITICAL]
└── Segment D: Test Coverage & Verification [HIGH]

PHASE 3: POLISH (Segments E + F in parallel, after Phase 2)
├── Segment E: CI/CD Gates & Tooling [HIGH]
└── Segment F: Documentation & Compliance [HIGH]
```

Prerequisites:
- Phase 2 requires Phase 1 (error handling must be clean before security integration)
- Phase 3 requires Phase 2 (tests must exist before CI gates enforce them)
- Segments within each phase are independent and can run in parallel

---

## SEGMENT A: Error Handling & Panic Elimination
**Phase**: 1 (parallel with B)
**Prerequisites**: None
**Estimated Tasks**: 8
**Quality Gate**: Zero panics/unwraps in `cargo build --release` output; all replaced with `Nine65Result<T>`

### A1: Audit and catalog all panic sites
- Grep all `panic!()`, `unwrap()`, `expect()`, `unreachable!()` in non-test code
- Create tracking spreadsheet: file, line, current behavior, replacement error type
- **TDD**: Write test that asserts each site now returns `Err(...)` instead of panicking

### A2: Extend Nine65Error with missing variants
- Add: `NoModularInverse`, `NTTConfigError`, `BootstrapConfigError`, `EntropyFailure`, `NoiseBudgetExhausted`, `KElimPreconditionViolation`, `LimitExceeded`
- **TDD**: Write test for each new error variant construction and Display impl

### A3: Replace panics in K-Elimination (k_elimination.rs)
- Replace `panic!("K-Elimination overflow...")` with `Err(Nine65Error::KElimPreconditionViolation)`
- Add `validate_preconditions(&m, &a) -> Nine65Result<()>`
- **TDD**: Test each precondition violation returns correct error

### A4: Replace panics in NTT (ntt.rs, ntt_fft.rs)
- Replace `assert!` in NTTEngine::new() with error-returning `try_new()`
- Replace `panic!("primitive root not found")` with error
- **TDD**: Test invalid modulus returns NTTConfigError

### A5: Replace panics in bootstrap (bootstrap.rs, keys/bootstrap.rs)
- All `.expect("Inverse exists")` → `.ok_or(Nine65Error::NoModularInverse { ... })?`
- All `.expect("Bootstrap...")` → proper error propagation
- **TDD**: Test bootstrap with invalid primes returns error

### A6: Replace panics in RNS-FHE (rns_fhe.rs, rns_mul.rs)
- Replace all `panic!` and `unwrap()` with error propagation
- Change `RNSFHEContext::new()` to use `try_new()` internally (already exists, wire up)
- **TDD**: Test each error path

### A7: Replace panics in key generation (keys/mod.rs, entropy/secure.rs)
- Replace `expect("CRITICAL: OS CSPRNG failure...")` with `Err(Nine65Error::EntropyFailure)`
- Change `KeySet::generate_secure()` to return `Nine65Result<Self>`
- **TDD**: Test entropy failure returns error (mock entropy source)

### A8: Remove secret values from error messages
- Audit all error messages for prime values, key material, noise values
- Replace with generic messages; log details to secure channel only
- **TDD**: Test error Display output contains no numeric values from crypto params

**Quality Gate A**:
- [ ] `grep -r "panic!" crates/nine65/src/ --include="*.rs" | grep -v "#\[cfg(test)\]" | grep -v "mod tests" | wc -l` = 0
- [ ] `grep -r "\.unwrap()" crates/nine65/src/ --include="*.rs" | grep -v test | wc -l` = 0 (excluding test code)
- [ ] All 953+ tests still pass
- [ ] All new error paths have dedicated tests

---

## SEGMENT B: Cryptographic Correctness Hardening
**Phase**: 1 (parallel with A)
**Prerequisites**: None
**Estimated Tasks**: 7
**Quality Gate**: All preconditions validated; noise overflow detected; NTT validated

### B1: Add K-Elimination runtime precondition validation
- Implement `KElimination::validate_preconditions(m: u64, a: u64) -> Nine65Result<()>`
  - Check: M > 0, A > 0, gcd(M, A) = 1, X < M*A
- Wire into every division call site
- **TDD**: Test each precondition with boundary values (M*A - 1, M*A, 0, non-coprime)

### B2: Fix noise budget overflow detection
- Replace raw `i64` budget with checked arithmetic (`checked_sub`, `checked_mul`)
- Add `NoiseBudget::is_exhausted()` method
- Add 95% threshold warning
- Return `Err(Nine65Error::NoiseBudgetExhausted)` when budget crosses zero
- **TDD**: Test depth-100 circuit detects exhaustion; test budget never wraps negative

### B3: Validate NTT configuration at construction
- Add `NTTEngine::try_new()` that validates:
  - N is power of 2
  - (q-1) % (2N) == 0
  - Primitive root exists
- Deprecate panicking `new()`, redirect to `try_new().expect()`
- **TDD**: Test each invalid config returns specific error

### B4: Validate bootstrap prime chain
- Add `validate_bootstrap_primes()`:
  - Each prime is NTT-friendly for configured N
  - No overlap with anchor primes
  - Product chain sufficient for configured depth
- Call at ClockworkBootstrap::new()
- **TDD**: Test with deliberately invalid primes

### B5: Add bootstrap rescaling exactness verification
- After modswitch Q→t, verify error is within bound (< 1)
- Add `modswitch_to_t_verified()` that returns error bound alongside result
- **TDD**: Test 100K random values, verify zero rescaling errors (matching report claim)

### B6: Integrate noise tracking with evaluator
- Create `TrackedEvaluator` wrapper around homomorphic operations
- All operations check noise budget before executing
- Return `Nine65Result` with budget status
- **TDD**: Test noise exhaustion is detected before decryption failure

### B7: Cross-validate security estimator with MATZOV model
- Add `CostModel::MATZOV` path in security_estimator.rs
- Compare estimates: MATZOV should give lower (more aggressive) numbers
- Verify our parameters still meet claimed security under MATZOV
- **TDD**: Test all 3 secure configs pass under both CoreSVP and MATZOV models

**Quality Gate B**:
- [ ] K-Elimination: All Coq preconditions checked at runtime
- [ ] Noise budget: Impossible to silently overflow
- [ ] NTT: Invalid configs return errors, never panic
- [ ] Bootstrap: Chain validated, rescaling verified exact
- [ ] Security: Parameters validated under both cost models
- [ ] All 953+ tests still pass + new tests

---

## SEGMENT C: Security Integration & Side-Channel Hardening
**Phase**: 2 (parallel with D; requires A complete)
**Prerequisites**: Segment A (error handling must be clean)
**Estimated Tasks**: 7
**Quality Gate**: CT enforcement active; GRO integrated; side-channel threat model documented

### C1: Implement constant-time enforcement via SecretKeyPath trait
- Define `trait SecretKeyPath` that marks CT-safe code paths
- Implement for NTT operations that handle secret key material
- Make `decrypt()` require `impl SecretKeyPath` context
- Use phantom types to prevent secret data entering non-CT paths
- **TDD**: Test that attempting to use secret data in non-CT path fails to compile (doc-test)

### C2: Mark NTT implementations as CT-safe or variable-time
- Audit `ntt.rs` and `ntt_fft.rs` for data-dependent branching
- Add `// CT-SAFE` or `// NOT-CT` documentation comments
- Add feature gate `ct_ntt_only` to restrict to CT-safe paths
- **TDD**: Test NTT with CT feature gate enabled uses correct path

### C3: Integrate GRO timing gates into keygen
- Wrap secret key generation in `TimingGate::new()` / `TimingGate::execute()`
- Ensure keygen timing is constant regardless of key material
- **TDD**: Test keygen executes within GRO timing window; measure variance < 5%

### C4: Integrate GRO timing gates into decrypt
- Wrap decryption in GRO timing gate
- Ensure decrypt timing independent of plaintext/noise level
- **TDD**: Decrypt 1000 ciphertexts with varied noise, measure timing variance

### C5: Add entropy health checks (NIST SP 800-90B compliance)
- Implement `EntropyHealthCheck` trait with self-test
- Pre-fill entropy pool from getrandom at startup
- Monitor pool levels; return `EntropyFailure` if depleted
- **TDD**: Test health check detects low entropy; test graceful degradation

### C6: Add circular security validation tests
- Test that boot_sk coefficients match work_sk (ternary, lifted)
- Test full bootstrap cycle: encrypt→bootstrap→decrypt→verify plaintext
- Test that bootstrapped ciphertext is valid under work key
- **TDD**: (These ARE the tests — TDD cycle: write test, watch fail, implement validation)

### C7: Create side-channel threat model document
- Document all known side-channels: timing, cache, power, EM
- Map each to mitigation (GRO, CT ops, etc.)
- Mark status: MITIGATED / PARTIAL / OPEN
- Link to relevant tests
- **TDD**: N/A (documentation task) — but add CI check that document exists

**Quality Gate C**:
- [ ] `SecretKeyPath` trait enforced for decrypt + keygen
- [ ] GRO gates wrapping all secret-key operations
- [ ] Entropy health check passes on startup
- [ ] Circular security test passes (encrypt→bootstrap→decrypt roundtrip)
- [ ] `docs/SIDE_CHANNEL_THREAT_MODEL.md` exists with all channels documented
- [ ] Timing variance < 5% for keygen and decrypt

---

## SEGMENT D: Test Coverage & Verification
**Phase**: 2 (parallel with C; requires B complete)
**Prerequisites**: Segment B (correctness fixes must be in place)
**Estimated Tasks**: 6
**Quality Gate**: All edge cases covered; timing regression baseline established

### D1: Add K-Elimination edge case tests
- Boundary: X = M*A - 1 (maximum valid input)
- Coprimality: gcd(M,A) ≠ 1 (must return error)
- Zero inputs: M = 0, A = 0 (must return error)
- Large values: near u64::MAX
- **TDD**: Red-green-refactor for each case

### D2: Add NTT edge case tests
- Invalid (q, N) pairs (non-NTT-friendly modulus)
- N = 1 (degenerate case)
- Maximum supported N
- **TDD**: Each must return proper error

### D3: Add bootstrap depth-50 end-to-end test
- Encrypt value, perform 50 multiplications with auto-bootstrap
- Verify final decrypted value is correct
- Track noise budget at each step
- **TDD**: Write test, verify it exercises actual bootstrap trigger

### D4: Add noise budget exhaustion edge cases
- Budget at exactly 0 (boundary)
- Budget at 1 millibit (near-zero)
- Budget after maximum-depth computation
- **TDD**: Verify exhaustion is detected, not silently overflowed

### D5: Add entropy failure simulation test
- Mock getrandom to return error
- Verify graceful error return (no panic)
- Verify error message contains no secret data
- **TDD**: Requires mock entropy source implementation

### D6: Establish constant-time regression baseline
- Measure keygen latency distribution (10K runs)
- Measure decrypt latency distribution (10K runs)
- Save baseline for CI comparison
- Flag deviation > 5% as regression
- **TDD**: Test that timing measurement infrastructure works correctly

**Quality Gate D**:
- [ ] Every error variant in Nine65Error has at least one test triggering it
- [ ] Bootstrap depth-50 test passes with correct decryption
- [ ] Noise exhaustion detected before decryption failure (zero silent overflows)
- [ ] Timing baseline established and saved as artifact
- [ ] Entropy failure handled gracefully (no panics)
- [ ] Zero test regressions

---

## SEGMENT E: CI/CD Gates & Tooling
**Phase**: 3 (parallel with F; requires C + D complete)
**Prerequisites**: Segments C and D (tests must exist for gates to enforce)
**Estimated Tasks**: 5
**Quality Gate**: All CI gates green; no panics/floats/timing-regressions pass PR check

### E1: Add no-panics-in-release CI gate
- Script: scan `cargo build --release` output for panic-related code
- Alternative: `grep -r "panic!" crates/*/src/ --include="*.rs"` excluding test modules
- Fail CI if any panics found in non-test code
- **TDD**: Add deliberately panicking code in test, verify gate catches it

### E2: Add float-detection CI gate
- Script: scan all .rs files for f32/f64/as f64/as f32 in non-compiler, non-test code
- Based on existing `check_no_floats.py` pattern from exact_transcendentals
- Fail CI if violations found
- **TDD**: Add deliberately floating file, verify gate catches it

### E3: Add constant-time regression CI gate
- Run timing tests weekly (extend existing timing-tests job)
- Compare against baseline from D6
- Fail if deviation > 5%
- **TDD**: Verify gate infrastructure with known-good baseline

### E4: Add formalization index validation gate
- Check that every module with Coq proof has entry in FORMALIZATION_INDEX
- Check that every entry references an existing Coq file
- Fail if out of sync
- **TDD**: Add entry pointing to nonexistent file, verify gate catches it

### E5: Tighten benchmark regression gate
- Change from advisory to enforced for critical operations
- 5% regression budget with override requiring `[skip-bench-gate]` + reviewer approval
- Add specific thresholds for: encrypt (<1ms), add (<50us), mul (<500us)
- **TDD**: Verify gate triggers on artificial regression

**Quality Gate E**:
- [ ] All CI gates pass on current codebase
- [ ] No-panics gate catches deliberately introduced panic
- [ ] Float-detection gate catches deliberately introduced float
- [ ] Timing regression gate has baseline and comparison logic
- [ ] Formalization gate validates index against actual proof files
- [ ] Benchmark gate enforced with specific thresholds

---

## SEGMENT F: Documentation & Compliance
**Phase**: 3 (parallel with E; requires C + D complete)
**Prerequisites**: Segments C and D (must document actual state, not aspirational)
**Estimated Tasks**: 5
**Quality Gate**: All public APIs documented; formalization index complete; compliance matrix filled

### F1: Complete formalization index
- Map every module to Coq/Lean4 proofs (or mark "TBD")
- Add columns: Module, Proof File, Theorem, Status (PROVED/PARTIAL/TBD)
- Add benchmark linkage column per EXECUTION_PLAN requirement
- **TDD**: N/A (documentation) — but validation gate from E4 will enforce

### F2: Add Rustdoc to public APIs
- Focus on: RNSFHEContext, KElimination, ClockworkBootstrap, SecureConfig
- Add usage examples in doc comments
- Link to Coq theorems where applicable
- **TDD**: `cargo doc --no-deps 2>&1 | grep "warning" | wc -l` must decrease

### F3: Create NIST compliance matrix
- Map NINE65 capabilities against:
  - HE Standard v1.1 security tables
  - NIST PEC FHE requirements (when published)
  - ISO/IEC FHE draft
- Document gaps and alignment
- **TDD**: N/A (documentation)

### F4: Update README for v6
- Remove v5 references
- Document Clockwork Bootstrap (unlimited depth)
- Update test counts (953+)
- Update benchmark numbers from latest baseline
- Document public mode with secure_128/192/256
- **TDD**: N/A (documentation)

### F5: Create v6 release checklist
- All CRITICALs closed
- All HIGHs closed or tracked with timeline
- Side-channel threat model reviewed
- Formalization index complete
- CI gates all green
- Security estimator validated under both cost models
- No secret data in error messages
- **TDD**: N/A (process document)

**Quality Gate F**:
- [ ] Formalization index: every Coq proof mapped to code module
- [ ] `cargo doc --no-deps` generates with zero missing-doc warnings for public items
- [ ] NIST compliance matrix exists with gap analysis
- [ ] README reflects v6 state accurately
- [ ] Release checklist exists and all CRITICALs checkable

---

## EXECUTION TIMELINE

```
Week 1-2: PHASE 1 (Segments A + B in parallel)
├── Segment A: Error handling cleanup (8 tasks)
└── Segment B: Cryptographic correctness (7 tasks)
    QUALITY GATE: Zero panics, validated preconditions, noise overflow detected

Week 3-4: PHASE 2 (Segments C + D in parallel)
├── Segment C: Security integration (7 tasks)
└── Segment D: Test coverage (6 tasks)
    QUALITY GATE: CT enforcement active, edge cases covered, timing baseline set

Week 5-6: PHASE 3 (Segments E + F in parallel)
├── Segment E: CI/CD gates (5 tasks)
└── Segment F: Documentation (5 tasks)
    QUALITY GATE: All gates green, docs complete, release checklist passable
```

**Total**: 38 tasks across 6 segments, 3 phases
**Parallel capacity**: 2 segments per phase = effective ~19 sequential task-groups

---

## RISK REGISTER

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Error handling changes break existing tests | HIGH | MEDIUM | Run full test suite after each file; TDD approach |
| CT enforcement requires API breaking changes | MEDIUM | HIGH | Use trait-based approach to minimize breakage |
| GRO integration reveals timing vulnerabilities | MEDIUM | HIGH | Document in threat model; fix before release |
| MATZOV validation shows parameters too weak | LOW | CRITICAL | Increase N or add primes; fall back to secure_192 minimum |
| Noise budget fix reveals deep-circuit failures | MEDIUM | HIGH | Document failure modes; add bootstrap trigger points |
| IBM key recovery vector applies to our impl | LOW | CRITICAL | Noise overflow fix (B2) directly addresses this |

---

## SUCCESS CRITERIA

v6 is production-ready when:
1. Zero `panic!()` or `unwrap()` in non-test code
2. All K-Elimination Coq preconditions validated at runtime
3. Noise budget overflow impossible (checked arithmetic)
4. Constant-time enforcement active for secret-key operations
5. GRO timing gates integrated into keygen + decrypt
6. All 11 CI gates passing
7. Security estimator validated under CoreSVP + MATZOV
8. Circular security property tested end-to-end
9. Side-channel threat model documented with all channels assessed
10. Formalization index complete
