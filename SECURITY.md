# Security Policy

This document describes the security policy for NINE65, an exact-integer BFV/DualRNS Fully Homomorphic Encryption substrate providing finite leveled computation plus low-depth refresh paths. It is not an unlimited-depth system; see `README.md` for current scope and evidence links and `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md` for what is and is not established. NINE65 is a proprietary Rust workspace comprising the following crates: `nine65`, `clockwork-core`, `mana`, `unhal`, and `nexgen_rational`. Lean 4 is the machine-checked formalization of record; the `proofs/coq/` tree is a legacy exploration and is not the verification basis.

## Supported Versions

| Version | Status | Support Level |
|---------|--------|---------------|
| v7.x | Current | Active security updates and patches |
| v5.x | Legacy | Critical fixes only; migrate to v7 |

Versions prior to v5 are unsupported and should not be used.

## Reporting a Vulnerability

We take the security of NINE65 seriously. If you discover a vulnerability, please report it responsibly.

### Contact

Email: **security@hackfate.us**

Do not open public issues for security vulnerabilities. Use the email address above for all security-related reports.

### What to Include

- A clear description of the vulnerability and its potential impact.
- Steps to reproduce the issue, including parameter configurations and crate versions.
- Affected crate(s) and module(s) (e.g., `nine65::security`, `clockwork-core::evaluator`).
- Any relevant proof-of-concept code or test vectors.
- Your assessment of severity (critical, high, medium, low).

### Response Timeline

| Milestone | Timeframe |
|-----------|-----------|
| Acknowledgment of report | Within 48 hours |
| Initial assessment and severity classification | Within 7 days |
| Fix development and internal verification | Depends on severity |
| Coordinated disclosure | 90 days from initial report |

We follow a 90-day responsible disclosure timeline. If a fix is released before the 90-day window, disclosure may proceed earlier with mutual agreement. If exceptional circumstances require an extension, we will communicate this to the reporter.

## Security Considerations

### Parameter Security

Named profiles are internally screened research configurations, not independently
validated production-security levels. No profile currently has external
attestation for its exact tuple. The in-tree figures are heuristic estimates:

| Profile | Core-SVP screen | MATZOV screen |
| --- | --- | --- |
| secure_128 / secure_128_deep | 196 | 176 |
| secure_192 | 320 | 288 |
| secure_256 | 267 | 240 |

In particular, secure_256 does not reach its nominal name under MATZOV.
These numbers do not establish post-quantum security or confidentiality of
correlated evaluation keys. See [current status](docs/PUBLIC_REFRESH_STATUS.md)
and [the security model](docs/security/SECURITY_MODEL_PUBLIC_REFRESH.md).

Configurations such as `light_insecure`, `he_standard_128_insecure`, and `light_rns_exact_insecure` exist solely for testing and development. These require the `allow_insecure` feature flag to compile and **must not be used in production deployments**. All legacy presets in `FHEConfig` have been renamed with an `_insecure` suffix to prevent accidental production use.

### The `allow_insecure` Feature Flag

The `allow_insecure` feature flag enables test-only parameter configurations with reduced security margins. This flag exists to facilitate rapid development iteration and testing. Enabling it in a production build is a security violation. CI pipelines should verify that release builds do not set this flag.

### Side-Channel Considerations

Constant-time primitives are available in `crates/nine65/src/security/secret_data.rs`. These primitives use the `subtle` crate for constant-time comparisons and conditional selection. Code paths that handle secret key material should use these primitives exclusively.

### Noise Budget Tracking

For noise-sensitive operations, use `TrackedEvaluator` to monitor noise budget consumption across homomorphic circuit evaluations. This helps detect unexpected noise growth that could compromise correctness or security margins before it becomes critical.

## Deployment Warning: fhe-service Decryption Oracle

The service is a server-key-holder boundary: session secret keys stay with the
operator, so this is not evaluator-blind FHE. It defaults to loopback and uses
tenant-bound authorization. The `/v1/sessions/{id}/decrypt` route is disabled
unless `FHE_ENABLE_DECRYPT=1` and its separate `FHE_DECRYPT_TOKEN` check succeeds.
Those controls do not make adversarial decryption queries safe: exposing the
capability to untrusted callers creates a chosen-ciphertext oracle surface.
Non-loopback deployments require an authenticated TLS boundary such as a
reverse proxy or mTLS. See the service README and security-mode matrix.

**Do not expose the fhe-service decrypt endpoint to untrusted clients.** Deployment guidance:
- Place the service behind an authentication layer (mTLS, API key, or equivalent) that restricts access to authorized enclave operators only.
- Avoid architectures where end-users can directly submit ciphertexts for decryption.
- If IND-CCA2 security is a requirement, a different key-encapsulation scheme is needed before fhe-service can be used in that threat model.

### Production Safety Assertions

Constructor parameter checks enforce their implemented screening and arithmetic
preconditions. They are not external security certificates. Release library
builds with `allow_insecure` are rejected at compile time; this feature does
not provide a production bypass. Research execution uses the documented
opt-in development/test profiles.

---

## Known Limitations

- **Functional scope**: exact leveled computation has finite parameter- and
  history-dependent capacity. Use the sourced capability table in README.md;
  the former high symmetric-depth claim is not an accepted capability.
- **Public refresh**: the opt-in PublicRefreshCircuit has identified native
  execution and deterministic noise evidence. Legacy Clockwork entry points
  remain fail-closed. The full correlated key setup is not production admitted.
- **Timing**: branchless arithmetic and timing/assembly tests are evidence,
  not complete constant-time certification. The November 1 main-branch
  Montgomery multiplication measurement exceeded its blocking t=5 threshold
  (signal8.6550, control1.4003); investigation and controlled repeats are required.
  See [the timing roadmap](docs/CT_VERIFICATION_PLAN.md). Do not weaken the
  threshold or classify a failed measurement as an established exploit.
- **Open security obligations**: related-key confidentiality, independent exact
  parameter attestation, a probabilistic decryption-failure bound and research
  refresh constant-time posture remain unestablished. Deterministic bounds,
  functional tests and selected Lean proofs do not discharge those obligations.

## Scope

### In-Scope

The following areas are in-scope for security vulnerability reports:

- Cryptographic primitives (encryption, decryption, key generation, homomorphic evaluation).
- Parameter security and lattice hardness estimates.
- Side-channel vulnerabilities (timing, cache, power analysis) in cryptographic code paths.
- Noise management correctness affecting security guarantees.
- Secret key material handling and zeroization.
- Formal proof soundness (Coq and Lean4 proof artifacts).

### Out-of-Scope

The following are out-of-scope:

- Website, documentation hosting, or infrastructure issues unrelated to the cryptographic library.
- Bugs in non-cryptographic utility code that do not affect security properties.
- Denial-of-service via pathological inputs to non-security-critical code paths.
- Issues in third-party dependencies (report these to the respective maintainers, but do notify us if they affect NINE65 security).
