# Security Policy

This document describes the security policy for NINE65, an unlimited-depth Fully Homomorphic Encryption system with three verified bootstrap paths. NINE65 is a proprietary Rust workspace comprising the following crates: `nine65`, `clockwork-core`, `mana`, `unhal`, and `nexgen_rational`. Formal verification is provided via Coq and Lean4 proofs.

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

NINE65 provides multiple parameter configurations. Only the following are validated for production use:

- `secure_128` -- targets 128-bit post-quantum security
- `secure_192` -- targets 192-bit post-quantum security
- `secure_256` -- targets 256-bit post-quantum security

Configurations such as `light`, `he_standard_128`, and `light_rns_exact` exist solely for testing and development. These require the `allow_insecure` feature flag to compile and **must not be used in production deployments**.

### The `allow_insecure` Feature Flag

The `allow_insecure` feature flag enables test-only parameter configurations with reduced security margins. This flag exists to facilitate rapid development iteration and testing. Enabling it in a production build is a security violation. CI pipelines should verify that release builds do not set this flag.

### Side-Channel Considerations

Constant-time primitives are available in `crates/nine65/src/security/secret_data.rs`. These primitives use the `subtle` crate for constant-time comparisons and conditional selection. Code paths that handle secret key material should use these primitives exclusively.

### Noise Budget Tracking

For noise-sensitive operations, use `TrackedEvaluator` to monitor noise budget consumption across homomorphic circuit evaluations. This helps detect unexpected noise growth that could compromise correctness or security margins before it becomes critical.

## Deployment Warning: fhe-service Decryption Oracle

The `fhe-service` crate exposes a `/decrypt` endpoint for session-based decryption. **This endpoint is a decryption oracle.** Any caller with network access to this endpoint can submit arbitrary ciphertexts and observe whether decryption succeeds. This constitutes a CCA2 (adaptive chosen-ciphertext) attack surface.

**Do not expose the fhe-service decrypt endpoint to untrusted clients.** Deployment guidance:
- Place the service behind an authentication layer (mTLS, API key, or equivalent) that restricts access to authorized enclave operators only.
- Avoid architectures where end-users can directly submit ciphertexts for decryption.
- If IND-CCA2 security is a requirement, a different key-encapsulation scheme is needed before fhe-service can be used in that threat model.

---

## Known Limitations

- **Public-mode depth**: Symmetric mode supports 50+ levels. Public mode has automatic modulus switching at level 3+ (since 2026-02-06) which extends depth beyond the original 4-5 level baseline, but remains shallower than symmetric mode.
- **Timing side-channel hardening**: Constant-time hardening for Montgomery multiplication and K-Elimination paths is ongoing. Deployment in adversarial timing-observation environments is not recommended until this work is complete.
- **Security estimator validation**: The built-in lattice security estimator provides rough Core-SVP + GSA estimates. These outputs should be validated against current lattice attack literature (e.g., lattice-estimator, recent IACR publications) before relying on them for security claims.

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
