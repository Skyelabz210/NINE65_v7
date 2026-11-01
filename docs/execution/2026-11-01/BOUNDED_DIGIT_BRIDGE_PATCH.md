# Attached bounded-digit bridge patch

The supplied patch is integrated into `coefficient_slot_gate.rs` and the exact
research CI runner. It adds encrypted evaluation of `F(X)=X-G(X)H(X)` on
coefficient-derived slots, subtracts the residual and returns `p*m` to
coefficient form.

The default case uses N=8, p=17, B=2, eight near-31-bit NTT primes and a
degree-9 polynomial. All 85 permitted clear inputs are checked. Its exact
coefficient vector also matches the independent Python construction:

`[0,238,0,57,0,222,0,78,0,273]` modulo 289.

Encrypted checks now assert all three stages: coefficient-to-slot values,
every residual digit, and every recovered `p*m` coefficient. The attachment
only printed the intermediate digit comparison; the integrated test asserts
it explicitly. Polynomial products/evaluation use i128 intermediates, prime
search reuses the repository's primality predicate, and invalid support/lane
counts are rejected before key allocation. The original configurable research
knobs `BDG_B` and `BDG_LANES` remain available.

## Validation

The complete integration target passes **43 tests, zero failures, 19 ignored**.
The three coefficient/slot bridge tests pass together. Target-specific Clippy
with warnings denied, formatting, research-runner controls, security/status
claim checks and diff checks pass. The independent Python oracle completes
9,482 exhaustive small-prime checks, including its corruption controls.

| Probe | Result |
| --- | --- |
| B=1, lanes=8 | passes |
| B=2, lanes=8 (default) | passes |
| B=3, lanes=8 | passes |
| B=2, lanes=6 | passes |
| B=2, lanes=2 | residual plaintext assertion fails; not admitted as a success |
| B=0 or lanes=9 | parameter validation rejects |

The low-lane failure is an executed underprovisioned case, not an analytic
noise-capacity certificate. The test constructs `W=p*m+eps` within the stated
support; it does not issue a source-history certificate or implement an entire
refresh/return circuit. The native N8192 implementation and its execution in
[the memory report](NATIVE_REFRESH_MEMORY.md) remain separate. The matching
algebraic identity is already covered by
`PublicRefreshDigit.residual_polynomial_correct`.

Reproduce the default:

```sh
cargo test --locked --config profile.test.package.nine65.opt-level=2 -j2 \
  -p nine65 --features allow_insecure --test coefficient_slot_gate \
  encrypted_slot_bridge_removes_bounded_digit_error_and_recovers_p_times_message \
  -- --exact --nocapture
```

This uses the optimized test profile with debug assertions. The release
`allow_insecure` prohibition is retained. Source hashes and execution logs are
in `bounded-digit-bridge-evidence` beside this report.
