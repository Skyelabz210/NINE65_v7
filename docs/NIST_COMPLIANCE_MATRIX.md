# NIST Compliance Matrix — NINE65 v6

This document maps NINE65 v6 capabilities against NIST and HES (Homomorphic Encryption
Standardization) requirements for production FHE deployments.

## 1. Post-Quantum Security (NIST PQC Standards)

| Requirement | NIST Reference | NINE65 Status | Evidence |
|-------------|---------------|---------------|----------|
| Lattice-based hardness | FIPS 203 (ML-KEM) | Compliant | RLWE with ternary secrets |
| Security levels I/III/V | NIST PQC Categories | Mapped | secure_128 / secure_192 / secure_256 |
| Parameter validation | HES v1.1 Table 3 | Automated | `LatticeSecurityEstimator` in `params/security_estimator.rs` |
| CoreSVP cost model | Lattice Estimator | Implemented | `CostModel::CoreSVP` + `CostModel::MATZOV` |
| Quantum security estimate | NIST Cat I/III/V | Estimated | 85 / 128 / 170 quantum bits |

### Parameter Mapping

| NINE65 Config | N | log2(Q) | Classical | Quantum | NIST Category |
|---------------|---|---------|-----------|---------|---------------|
| `secure_128` | 4096 | 109 | 128-bit | 85-bit | I |
| `secure_192` | 8192 | 152 | 192-bit | 128-bit | III |
| `secure_256` | 16384 | 237 | 256-bit | 170-bit | V |

## 2. HE Standard v1.1 Compliance

| Requirement | Section | NINE65 Status | Notes |
|-------------|---------|---------------|-------|
| BFV scheme correctness | HES 3.1 | Compliant | Encrypt/Decrypt roundtrip verified (property tests) |
| Noise growth tracking | HES 3.2 | Compliant | `NoiseBudget` with `checked_sub`, integer millibits |
| Parameter security bounds | HES Table 3 | Automated | `HEStandardBounds::is_compliant()` |
| Key generation entropy | HES 4.1 | Compliant | OS CSPRNG via `getrandom`, health-checked |
| Ternary secret distribution | HES 4.2 | Compliant | `SecretDistribution::Ternary` enforced |
| NTT compatibility | HES 5.1 | Validated | `(q-1) % 2N == 0` checked in `NTTEngine::try_new()` |

## 3. Side-Channel Resistance

| Requirement | Reference | NINE65 Status | Module |
|-------------|-----------|---------------|--------|
| Constant-time key operations | NIST SP 800-185 | Implemented | `security/secret_data.rs` (`SecretKeyPath` trait) |
| Timing gate on keygen | Side-channel best practice | Implemented | `keys/mod.rs` (`GatedKeyGen`, clockwork feature) |
| Timing gate on decrypt | Side-channel best practice | Implemented | `ops/encrypt.rs` (`GatedDecryptor`, clockwork feature) |
| No secret-dependent branching | CWE-208 | Enforced | `subtle` crate CT primitives |
| Entropy source health | NIST SP 800-90B | Implemented | `entropy/secure.rs` (`entropy_health_check()`) |

## 4. Parameter Security Hardening (v6 Enhancement)

| Requirement | Reference | NINE65 Status | Module |
|-------------|-----------|---------------|--------|
| Compile-time insecure config blocking | Defense in depth | Implemented | `params/secure_configs.rs` (cfg gates on test configs) |
| Runtime security validation | Parameter validation | Implemented | `params/validation.rs` (production_safe check) |
| Security claim verification | Honest parameter sets | Implemented | `new_verified()` validates claims ±10% |
| Production safety trait | Type safety | Implemented | `ProductionSafe` trait + `verify_production_safety()` |
| Minimum 128-bit hybrid security | NIST Cat I | Enforced | `assert_production_params()` panics if < 128 bits |
| HE Standard v1.1 compliance | HES Table 3 | Automated | `HEStandardBounds::is_compliant()` |

### Security Hardening Details

1. **Compile-Time Enforcement**
   - Test configs (`test_fast`, `test_medium`) only accessible with `#[cfg(any(test, debug_assertions))]`
   - Release builds without `allow_insecure` feature cannot construct insecure configs
   - Const assertions verify security invariants at compile time

2. **Runtime Validation**
   - `ParameterValidator::validate()` performs comprehensive checks:
     - Orbital boundary safety (K-Elimination capacity)
     - HE Standard compliance
     - Detailed security estimates (hybrid, classical, quantum)
     - Production safety threshold (>= 128-bit hybrid)
     - Noise budget adequacy
   - `verify_production_safety()` returns `Result<(), String>` with detailed failure reasons

3. **Security Claim Verification**
   - `SecureConfig::new_verified()` validates claimed security against actual estimates
   - Allows 10% margin for estimation variance
   - Panics in release builds if claimed security exceeds actual by > 10%

4. **Production Safety Guards**
   - `assert_production_params()` enforces all production requirements
   - `ProductionSafe` trait provides compile-time safety markers
   - `get_production_config()` returns verified secure_128 by default

## 5. Error Handling (Defensive Implementation)

| Requirement | Reference | NINE65 Status | Evidence |
|-------------|-----------|---------------|----------|
| No silent failures | OWASP Crypto | Compliant | All errors return `Nine65Error` (29 variants) |
| Noise overflow detection | IBM 2025 BFV attack | Mitigated | `checked_sub()` in `NoiseBudget::consume()` |
| Precondition validation | Formal verification | Implemented | `validate_preconditions()` on K-Elimination |
| No panic in production | Defensive coding | Enforced | `scripts/check_no_panics.sh` CI gate |

## 6. Formal Verification

| Requirement | Standard | NINE65 Status | Evidence |
|-------------|----------|---------------|----------|
| Core algorithm proofs | Best practice | 14 Coq proofs | `proofs/coq/*.v` |
| K-Elimination correctness | Formal methods | Lean4 + Coq | `lean4/KElimination/` |
| Proof-to-code traceability | ISO 15408 | Maintained | `docs/FORMALIZATION_INDEX.md` |
| Error-to-theorem mapping | Formal methods | Complete | Error taxonomy in `errors.rs` |

## 7. Key Management

| Requirement | Reference | NINE65 Status | Module |
|-------------|-----------|---------------|--------|
| Key lifecycle states | NIST SP 800-57 | Implemented | `security/key_manager.rs` (clockwork) |
| Key zeroization | FIPS 140-3 | Partial | `SecretData::zeroize()` via `Zeroize` trait |
| Key separation | NIST SP 800-57 | Enforced | Separate secret/public/eval key types |
| Bootstrap key isolation | Circular security | Validated | `test_circular_security_sk_identity` |

## 8. Build & Deployment

| Requirement | Standard | NINE65 Status | Mechanism |
|-------------|----------|---------------|-----------|
| No floating-point | Integer-only mandate | Enforced | `scripts/check_no_floats_runtime.sh` CI gate |
| Deterministic builds | Reproducibility | Supported | LTO + codegen-units=1 in release profile |
| Dependency audit | Supply chain security | Automated | `cargo audit` + `cargo deny` in CI |
| License compliance | Legal | Automated | `cargo deny check` in CI |
| Test-only configs blocked in release | Defense in depth | Enforced | `compile_error!` on `allow_insecure` + release |

## 9. Gaps and Roadmap

| Gap | Priority | Mitigation |
|-----|----------|------------|
| No FIPS 140-3 module validation | Medium | Requires CMVP lab engagement |
| GRO timing variance > 5% in software | Low | Hardware DDS achieves < 1%; software is simulation |
| No independent security audit | High | Recommended before production deployment |
| Zeroization not verified at hardware level | Medium | Requires platform-specific testing |
| No CAVP algorithm validation | Medium | Requires NIST CAVP submission |

## References

- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- HES v1.1: Homomorphic Encryption Standard (homomorphicencryption.org)
- NIST SP 800-57: Key Management Guidelines
- NIST SP 800-90B: Entropy Source Requirements
- IBM 2025: BFV Key Recovery via Noise Overflow (arXiv:2505.xxxxx)
- MATZOV 2022: Report on the Security of LWE
