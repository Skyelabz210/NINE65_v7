# QUESTION_MATRIX.md

Project: NINE65 v5 public-ready variant
Date: 2026-01-27

- Question: What does "public-ready" mean for this release (public-key depth target, supported modes, minimum security level)?
  Why it matters: This defines acceptance criteria and test gates.
  Method: Owner decision documented in README and EXECUTION_PLAN.md.

- Question: Which configuration is the production default (secure_128 vs secure_192)?
  Why it matters: Security baseline and performance claims depend on it.
  Method: Run lattice estimator on both, compare to target risk profile, then decide.

- Question: Should allow_insecure be disabled for public releases?
  Why it matters: Public builds can accidentally expose test-only configs.
  Method: Decide policy and enforce with compile-time guard or feature matrix.

- Question: Are README performance and security claims intended for marketing or internal reference only?
  Why it matters: Public claims must be reproducible and consistent with audits.
  Method: Decide claim scope, then update README and benchmark docs accordingly.

- Question: Is third-party audit sign-off required before public release?
  Why it matters: External trust and compliance expectations.
  Method: Set requirement and timeline; if required, schedule audit and attach report summary.

- Question: What license and disclosure policy should govern the public release?
  Why it matters: Legal clarity and user trust.
  Method: Choose license, add SECURITY.md and CONTRIBUTING.md, and update README.
