# WR-7 — Factorization-Aware Production Security Admission

## Objective

Make production configuration admission reject or label unverified unsafe tuples rather than attach unsupported security claims.

## Required work

- integrate factorization-aware screening into production admission;
- separate claimed, screened, and unverified constructor states;
- resolve secure_256 naming against the weakest accepted model;
- freeze exact tuple fingerprints before external attestation;
- prohibit saturation/sentinel metadata in admission decisions.

## Acceptance

Exact structural/factorization boundary tests; raw constructors cannot silently assert security for unscreened tuples; feature-dependent fingerprint tests; documentation contains no security claim stronger than current evidence.
