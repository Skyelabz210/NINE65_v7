# WR-5B — Exact Bootstrap Security Validation

## Objective

Separate exact structural validity from security screening for bootstrap parameters and refuse structurally invalid or unscreenable tuples.

## Requirements

1. Use exact product bit length, not summed lane widths.
2. Keep declared target security independent of Q_boot.
3. Run in-tree models plus factorization-aware screening.
4. Archive an exact tuple fingerprint: ordered primes, N, t, eta, feature set, commit SHA.
5. Return typed refusal rather than a guessed security value.

## Acceptance

Boundary tests for bit length and overflow; deterministic fingerprints; no saturation/sentinel metadata in security/capacity/routing; labels distinguish claimed, screened, externally attested; no change to public bootstrap availability.
