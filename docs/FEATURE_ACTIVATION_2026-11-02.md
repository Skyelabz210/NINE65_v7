# FPD and feature activation — 2026-11-02

The main-Q service evaluator now prepares its public hybrid relinearization
key once and calls `try_mul_exact_prepared`. This preserves the existing FPD
scale-and-round rule, main-Q wire format, key domain checks, immutable history
bounds, and refusal before noise exhaustion. No key or parameter is weakened.
The temporary raw key is dropped after preparing its transform cache.

For division claims, see the [API-by-API scope note](FPD_DIVISION_SCOPE_2026-11-02.md).
This activation accelerates BFV multiplication; it does not remove
`CramPublicEvaluator::exact_divide`'s shared-factor rejection or add a general
encrypted division adapter.

## Enabled paths

| Item | Activation and scope |
| --- | --- |
| Remainder-adjusted FPD | `CramMainEvaluator::multiply` → `ExactMulEvaluator` → `ExactScaleRound`; already the service route, now measured explicitly |
| Persistent Montgomery | Existing main-RNS storage and NTT kernels on that route |
| Prepared hybrid relinearization | Now used by default in `CramMainEvaluator`, including service sessions; transformed keys reused across operations |
| MANA/UNHAL | `accelerated` remains enabled; the prepared hybrid kernel also has its existing bounded per-lane workers |
| Exact transcendentals | Existing default integer backend |
| Exact rational bridge | `exact_rational` now enabled by default; exposes exact rational arithmetic, parameter and noise helper APIs |
| Clockwork integrity | `clockwork` now enabled by default; exposes GRO timing, checksums and key-lifecycle APIs, distinct from public bootstrap admission |
| Shadow monitoring | `adaptive-threading` now enabled by default, transitively enabling `shadow-entropy`; monitor methods execute instead of returning their feature-disabled stub |
| Public research refresh | Explicit `allow_insecure` opt-in and `public_refresh_circuit` example; prepared outer keys, bounded carry and fused lift already wired |

Availability of an optional API is not evidence of an end-to-end speedup.
The FPD service route continues to use its certified scalar noise model and
does not acquire an adaptive Rayon pool merely because monitoring is enabled.
Main-Q prepared keys cost setup time and retained memory; the benchmark
reports both preparation time and transformed-key payload separately.

## Flags with different purposes

`reference_ntt` selects the quadratic validation engine. `sequential` and
`parallel`/`generic-rayon` select alternative execution configurations.
`deterministic_rng`, `allow_insecure`, `slow_tests`, `benchmarks`, and
`debug_dual_mul` are explicit testing/research/diagnostic choices.
`serde`, `logging`, and `secure_seed` remain application integration options.
`ntt_fft` is a compatibility alias; the fast NTT is already the default.
These are not a set to enable with `--all-features`.

`--no-default-features` remains available to downstream callers needing a
smaller feature surface. FPD and prepared-key evaluation are APIs, not Cargo
features, and remain available in that build.

## Reproduction

```bash
# Current integrated stack; OS RNG; real release library; five samples plus warmup.
cargo run --locked -p nine65 --release --features serde \
  --example fpd_stack_timings

# Research backend preflight without generating native keys.
cargo run --locked --config profile.dev.package.nine65.opt-level=2 \
  -p nine65 --features allow_insecure --example public_refresh_circuit -- --describe

# Actual reduced-ring encrypted refresh/return/repeated-square regression.
cargo test --locked --config profile.test.package.nine65.opt-level=2 \
  -p nine65 --lib --features allow_insecure \
  ops::public_refresh_native::complete_public_refresh_returns_original_key_for_three_cycles \
  -- --exact --nocapture
```

The native five-cycle example is the same example command without `--describe`.
Its prior archived run required about 57 minutes and 8.70 GiB peak RSS.
Preflight and reduced-ring tests are not a new native timing result.
Production security admission of the related-key setup remains as described
in [current public-refresh status](PUBLIC_REFRESH_STATUS.md).

The new timing capture uses schema `nine65-fpd-stack-v1` and a separate output
file from `op_timings.json`, preserving the historical DualRNS baseline.
It records full parameter tuples, compiled features, integer samples/medians,
setup costs and correctness. Set `NINE65_BENCH_COMMIT` to the exact measured
commit and `NINE65_BENCH_JSON_OUT` to preserve each run. Raw/prepared timings
share one key and identical ciphertext inputs; the service wrapper is a
separate public API measurement including its bound checks and plan creation.

## Measured FPD comparison

Two sequential release runs on an Intel Xeon Platinum 8573C, Debian 13,
Rust 1.89.0, source `dde5ea20ecff8198d0eb3353ec038243b42b188f`:

| Profile | Raw FPD multiply (ms) | Prepared FPD multiply (ms) | Prepared speedup | Service multiply (ms) |
| --- | ---: | ---: | ---: | ---: |
| `secure_128` | 80.254–86.465 | 37.158–41.219 | 2.10–2.16× | 60.668–63.113 |
| `secure_192` | 266.388–281.679 | 110.368–126.448 | 2.23–2.41× | 166.281–181.675 |
| `secure_256` | 372.988–374.360 | 147.200–148.209 | 2.53× | 218.039–219.805 |

Each timing range spans the two per-run medians of five samples, not a
confidence interval. Speedups divide paired raw/prepared medians within
each run. All 36 correctness trials (including warmups) passed both
raw/prepared limb equality and decryption checks. OS randomness was used;
`allow_insecure`, `reference_ntt`, `parallel` and `sequential` were disabled.
All task-owned builds and tests had finished before timing; the shared host
was not CPU-pinned, so these are local engineering measurements.

Prepared-key payloads were 6.5, 20 and 28.5 MiB respectively. Preparation
took 16–42, 60–64 and about 78 ms respectively, excluded from operation
timings. Complete service setup is recorded separately in each capture.
The service measurements include evaluator-plan creation and bound checks;
they are not a before/after service-speedup claim. No refresh was timed.

Raw samples, full parameter tuples and compiled features are preserved in
[run 1](../artifacts/execution/2026-11-02/fpd-stack/run-1.json) and
[run 2](../artifacts/execution/2026-11-02/fpd-stack/run-2.json).
[Provenance](../artifacts/execution/2026-11-02/fpd-stack/provenance.json)
records the source commit, build/run commands, host and capture hashes.

## Validation

Validated with Rust 1.89.0 on the implementation snapshot
`dde5ea2` (including `b0ca63d`):

- Default core library: **1,201 passed, 139 ignored**, using
  `cargo test --locked -p nine65 --lib --config profile.test.package.nine65.opt-level=2 -- --test-threads=4`.
- Release service: **54 passed, 27 ignored**.
- Shadow-monitor regressions: **19 passed** with defaults and **19 passed**
  with the optional `parallel` feature. Activation exposed a duplicated
  sampling gate and a feature-specific variable-name error; both are fixed.
- Minimal `--no-default-features` library build passed.
- Clippy for the library and timing example with `serde` passed with
  `-D warnings`; formatting and whitespace checks passed.
- Exact-route denylist (including its injected-violation self-test),
  residue-native architecture, public-refresh status/security-claim checks,
  and integer-only runtime/test/benchmark scans passed.

The core run actually executed
`ops::rns_fhe::cram_main::tests::prepared_main_multiply_is_identical_to_unprepared_fpd`,
`ops::public_refresh_circuit::tests::public_refresh_conforms_on_full_polynomials_histories_and_forks_across_seeds`,
and `ops::public_refresh_native::complete_public_refresh_returns_original_key_for_three_cycles`.
The first checks all ciphertext limbs against the raw-key FPD route; the
latter two execute reduced-ring encrypted refresh. The research example's
`--describe` preflight also passed. The costly native five-cycle run was not
repeated, and ignored tests are not counted as passes.
