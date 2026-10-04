# Issue #88: [P1] Remove unchecked security labeling from FHEConfig::custom and for_depth

- state: open
- labels: (none)
- created: 2026-08-31T07:10:36Z  updated: 2026-09-04T09:44:28Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/88

---

## Finding

Two public raw-parameter constructors can manufacture security metadata that is not established by the tuple they return:

- `FHEConfig::custom` sets `security_bits = estimate_security(n, primes[0])`, a legacy heuristic that looks only at the first prime instead of the full RNS product/factorization.
- `FHEConfig::for_depth(depth, n, security_bits)` accepts a caller-supplied `security_bits` and stores it directly after choosing a prime count; it does not prove that the constructed tuple meets that number.

Later production context construction performs additional checks, but the `FHEConfig` object itself can carry misleading security metadata and can be consumed/reporting by code that has not yet passed through that gate.

## Required work

1. Separate **claimed**, **screened**, and **unverified** security states in the type/API.
2. Do not populate a field named/used as verified security from `primes[0]` or from an unchecked caller argument.
3. Route production-capable custom/depth constructors through the exact full-product + factorization-aware screening policy from #87 and the dual-model policy.
4. If a tuple is intended only for experiments, return/type it as unverified/insecure and require an explicit conversion after screening before production APIs accept it.
5. Deprecate or remove the legacy `estimate_security(n, q:u64)` from production decisions.
6. Make `for_depth` fail when the requested depth cannot obtain enough distinct valid NTT primes rather than silently returning fewer than requested.
7. Preserve integer-only calculations.

## Tests

- Multi-prime custom configs where first-prime width is unchanged but full-Q width changes must not report identical verified security by construction.
- Caller asking `for_depth(..., security_bits=512)` must not receive a tuple labeled 512 unless the configured screen explicitly supports it.
- Insufficient prime discovery must be a typed failure.
- Named/validated conversion produces the same screening report used by the production context.

## Mandatory before/after performance evidence

Benchmark `custom`/`for_depth` construction and validated conversion across representative sizes. Also run the canonical FHE operation benchmark before/after to prove the metadata/type cleanup changes no arithmetic hot path. Record integer timing units only.

## Completion condition

No raw `FHEConfig` can present an unchecked first-prime heuristic or caller-entered number as established production security.