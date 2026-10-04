# Issue #85: [P1] Make fallible constructors truly fallible: remove production-security panics from try_* APIs

- state: open
- labels: (none)
- created: 2026-08-31T07:09:43Z  updated: 2026-09-04T09:57:58Z
- url: https://github.com/Skyelabz210/NINE65_v7/issues/85

---

## Finding

`RNSFHEContext::try_new` is documented as the fallible constructor and returns `Nine65Result<Self>`, but its first production-safety action is `assert_production_safe_fhe_config(config)`, which uses `assert!` for dimension, estimator, and HE-bound failures in release builds.

Therefore an invalid/unverified production config can abort/panic through a function whose API contract says the error is returned. With the workspace release profile using `panic = "abort"`, this is materially different from a typed configuration failure.

## Required work

1. Add a fallible raw-config production validator, e.g. `verify_production_safe_fhe_config(&FHEConfig) -> Nine65Result<()>` (or a dedicated typed error).
2. Make every `try_*` constructor/path call fallible validators with `?`; no `assert!`, `unwrap`, or `expect` may be reachable for caller-supplied invalid configuration.
3. Keep infallible convenience constructors only when their name/signature makes the panic contract explicit, and implement them as wrappers around the fallible primitive.
4. Audit all public `try_*` APIs for the same panic-through-Result pattern.
5. Keep debug assertions only for internal invariants already proven by construction; caller-controlled validity is a typed error.
6. Preserve the exact same integer security calculations.

## Correctness tests

- In a release-mode test, feed configs failing each individual production-safety condition and assert the exact typed error; process must remain alive.
- Verify valid named configs construct identically before/after.
- Add a source/API regression gate preventing `assert!`/`unwrap`/`expect` in the caller-validation prefix of `try_*` APIs.

## Mandatory before/after performance evidence

Benchmark context construction for all named configs and the first encrypt/multiply/decrypt operation after construction. The change should have no hot-path cost. Publish integer nanosecond/microsecond medians and exact output equality for before/after builds using the same machine/toolchain/features.

## Completion condition

Every API advertised as fallible returns a typed error for invalid caller input in release mode; it does not terminate the process.