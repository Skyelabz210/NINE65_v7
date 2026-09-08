# Test Tiers

Issue #78 ([M3] Add test categorization for tiered CI execution). Complements
#64 (make the full suite reproducible in constrained environments) and is
gated by #79 (CI has run zero times since 2026-02-27, so nothing here is
wired as a *required* GitHub status check yet — see "CI wiring" below).

The owner's assignment comment on #78 (PR #97) fixed two constraints as
non-negotiable, quoted verbatim because they are the acceptance bar for this
whole scheme: "keeping the complete release suite reachable and required"
and "Categorization must improve runtime, not hide failing tests." Every
choice below is in service of those two sentences.

## The three tiers

| Tier | Script | What it runs | Cargo boundary |
|---|---|---|---|
| FAST | `scripts/run_tests_fast.sh` | every crate's `--lib` unit tests, release | Cargo target selection (`--lib`) |
| MEDIUM | `scripts/run_tests_medium.sh` | the complete required suite — identical to the pre-existing CI `full-test` job | none — full workspace, default features |
| SLOW | `scripts/run_tests_slow.sh` | 3 pre-existing opt-in surfaces: `slow_tests` feature, `op_timings` perf suite, `nine65-extreme-tests` | Cargo feature gates + `#[ignore]` |

None of the three touch a single `#[ignore]`/`#[cfg]` attribute. They compose
Cargo's own existing target/feature boundaries:

- FAST is `--lib`, which Cargo already treats as a distinct target from every
  `tests/*.rs` integration binary.
- MEDIUM is exactly what `cargo test --workspace --verbose --exclude
  nine65-python --exclude nine65-wasm` already ran in `ci.yml`'s `full-test`
  job before this change — a byte-for-byte wrapper, not a new invocation, so
  nothing that passed before stops running and nothing that failed before
  starts being silently skipped.
- SLOW composes three flags that already existed for a different reason
  (long runtime, not correctness) before issue #78: nine65's `slow_tests`
  Cargo feature (`ops/rns_fhe.rs`), the `#[ignore]`d `op_timings` suite
  (CLAUDE.md's "Performance Baselines" table is measured from it), and
  `nine65-extreme-tests`'s `extreme-tests` feature (13 adversarial/boundary
  modules answering ~20 questions the default suite does not ask).

**Explicitly not folded into SLOW**: the `#[ignore]`d tests in
`ops/{bootstrap,rns_fhe}.rs` and `tests/bootstrap_*.rs`. Those are ignored
for a *different* reason than runtime — VESTIGIAL/RETIRED MECHANISM premises
this substrate no longer has (see CLAUDE.md's "Bootstrap Paths" section and
`docs/RETIRED_MECHANISMS.md`) — and are not expected to pass. Folding them
into a timing tier via a blanket `--include-ignored` would make "slow" fail
by construction, which defeats the point of a tier. That is a separate
quarantine/retirement concern, tracked independently of test categorization.

## Measured counts and timings

Measured 2026-09-04, this repo's default release profile
(`[profile.release]`: `lto = "fat"`, `codegen-units = 1`), on a 4-vCPU
shared container. **Caveat that matters more than the numbers**: this run
shared the host with a large wave of concurrent agent sessions — 16 sibling
git worktrees were active, each running its own `cargo build`/`cargo test`;
load average measured as high as ~63 on 4 vCPUs, with 9-21 concurrent
`rustc`/`cargo` processes observed at points during this run. Wall-clock
times below are therefore inflated well beyond what a dedicated CI runner
would see and must not be read as a performance claim. Only the **pass /
fail / ignored counts** are load-independent and trustworthy as measured.

### FAST (`scripts/run_tests_fast.sh`)

`cargo test --release --workspace --lib --exclude nine65-python --exclude nine65-wasm`

| crate | passed | failed | ignored | time |
|---|---|---|---|---|
| clockwork-core | 46 | 0 | 0 | 1.65s |
| cram-core | 7 | 0 | 0 | 0.15s |
| exact_transcendentals | 535 | 0 | 0 | 0.23s |
| mana | 28 | 0 | 0 | 0.01s |
| math_utils | 11 | 0 | 0 | 0.00s |
| nexgen_rational | 95 | 0 | 0 | 0.23s |
| nine65 | 880 | 5 | 124 | 675.33s |
| **total** | **1602** | **5** | **124** | **real 17m8.890s** (user 10m24.860s, sys 0m12.992s) |

**FAST is a Cargo-target-boundary split, not a wall-clock-fast tier as
measured today.** Several tests living inside nine65's `--lib` target ran
60+ seconds individually during this run, including
`comprehensive_benchmarks::comprehensive_benchmarks::benchmark_depth_specific_operations_secure_128`,
`comprehensive_benchmarks::comprehensive_benchmarks::benchmark_noise_growth_secure_128`,
`ops::bootstrap::tests::diag_measure_noise_growth`,
`ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_{128,192}`,
`ops::rns_fhe::tests::{accel_timing_probe_mul_dual_public,
mul_dual_public_winding_margin_measured_directly,
public_relin_gadget_identity_is_exact_at_every_depth,
test_public_mode_depth_sweep}`, and the `ops::auto_bootstrap` repeated-
squaring tests below. None of these carry `#[ignore]` or a feature gate —
they are unconditionally part of `--lib`. This is exactly the drift
`scripts/check_test_tier_drift.py` exists to catch (see its own docstring);
this run is empirical confirmation the risk it warns about is already
realized, not hypothetical. Run `python3 scripts/check_test_tier_drift.py`
for a systematic per-test timing inventory rather than this run's
incidental sample, once a quieter host is available to set a real
threshold against.

**Known failures found (pre-existing, unrelated to this change)**: 5 tests
failed in `nine65`, none of them touched by this PR (which changes zero
files under `crates/*/src/`, so every one of these already fails on `main`):

- `ops::auto_bootstrap::tests::repeated_squaring_is_exact_under_auto_refresh_secure_128_deep`
- `ops::auto_bootstrap::tests::repeated_squaring_is_exact_under_auto_refresh_secure_192`
- `ops::auto_bootstrap::tests::repeated_squaring_is_exact_under_auto_refresh_secure_256`
- `ops::auto_bootstrap::tests::squaring_refresh_costs_exactly_one_bootstrap`
- `ops::bootstrap::tests::diag_measure_noise_growth`

The last one's own diagnostic output is worth quoting directly — it is more
serious than a single failing assertion:

```
=== diag_measure_noise_growth: public refresh vs the decryption oracle ===
config              lanes  headroom  required    admits |   refresh(7)     refresh(7)^2
secure_128              4        71        47      true | 65536 (WRONG)    40018 (WRONG)
secure_128_deep         4        71        47      true | 65536 (WRONG)    40018 (WRONG)
secure_192              5        96        49      true |   40 (WRONG)    40518 (WRONG)
=== end diag_measure_noise_growth ===
```

This is not a new finding — it is a direct, independent reproduction of an
**already-tracked, already-documented open regression**. CLAUDE.md's own
"Bootstrap Paths" section (as of this checkout) records it explicitly:
`docs/PUBLIC_REFRESH_CORRUPTS_ADMITTED_CONFIGS_2026-09-03.md` found that
`diag_measure_noise_growth` "now decrypts wrong for every admitted config it
measured (`secure_128_deep`, `secure_192`) — not just the historical
secure_128 failure mode ..., and not just at the subsequent multiply, but on
`refresh(7)` itself," tracked as **issue #95 / WR-5A / WR-5B**, explicitly
"not resolved by the 2026-08-26 re-cut." The run measured on this page
adds one data point to that existing tracking: `secure_128` (re-cut
2026-08-26 to the same 4-lane tuple `secure_128_deep` uses, and correctly
`admits: true` here — no doc/code mismatch on the gate itself) shows the
identical `65536`/`40018` corruption as `secure_128_deep`, consistent with
the two configs sharing a tuple. `secure_256` is not one of this test's
three `cases`, so nothing here speaks to it. This PR does not touch
bootstrap/gate logic and does not attempt to resolve issue #95 — it is
mentioned here only because it explains 5 of FAST's, MEDIUM's, and SLOW's
failures across every tier this PR adds, and CLAUDE.md's own line applies
directly to how those failures should be read: "Do not read 'admitted' in
this section as 'refresh verified working.'"

### MEDIUM (`scripts/run_tests_medium.sh`)

`cargo test --workspace --verbose --exclude nine65-python --exclude nine65-wasm`

Identical command to the pre-existing `full-test` "Run all workspace tests"
CI step — debug profile (no `--release`). nine65's `--lib` pass/fail/ignored
counts below (880/5/124) are identical to FAST's, on the same source and
the same 5 failing tests (verified by diffing both runs' `failures:` lists)
— no build-profile-dependent divergence was found here, despite debug's
default `overflow-checks = true` vs release's `false` (`Cargo.toml`'s
`[profile.release]` does not override this) being a real difference between
the two runs. What MEDIUM adds beyond FAST is every `tests/*.rs` integration
target — and, as the finding below shows, that addition mostly did not get
to run in this measurement.

| crate / integration target | passed | failed | ignored | time |
|---|---|---|---|---|
| clockwork-core (`--lib`) | 46 | 0 | 0 | 8.25s |
| cram-core (`--lib`) | 7 | 0 | 0 | 0.32s |
| cram-core `tests/workload_scales.rs` | 5 | 0 | 0 | 0.01s |
| exact_transcendentals (`--lib`) | 535 | 0 | 0 | 0.19s |
| exact_transcendentals `tests/a2_residue_native.rs` | 5 | 0 | 0 | 0.16s |
| exact_transcendentals `tests/arrow_emission_joint_property.rs` | 8 | 0 | 0 | 0.02s |
| exact_transcendentals `tests/arrow_emission_reversibility.rs` | 4 | 0 | 0 | 0.01s |
| exact_transcendentals `tests/cram_gates.rs` | 16 | 0 | 0 | 0.04s |
| exact_transcendentals `tests/lifted_transduction_module.rs` | 6 | 0 | 0 | 0.00s |
| exact_transcendentals `tests/safe_basis_lifted_transduction.rs` | 9 | 0 | 0 | 0.10s |
| fhe-service (`--lib`) | 24 | 0 | 29 (WIRE-Q fail-closed, `docs/FHE_SERVICE_WIRE_Q_OUTAGE_2026-09-03.md`) | 18.95s |
| mana (`--lib`) | 28 | 0 | 0 | 0.05s |
| math_utils (`--lib`) | 11 | 0 | 0 | 0.00s |
| nexgen_rational (`--lib`) | 95 | 0 | 0 | 0.21s |
| nine65 (`--lib`) | 880 | **5** | 124 | 1200.32s |
| **subtotal reached** | **1659** | **5** | **153** | **real 23m54.150s** (user 48m14.749s, sys 0m31.995s) |

**Critical finding: `cargo test --workspace` stops at the first failing
package and never reaches the rest of the "required, complete" suite.**
Cargo's default is fail-fast across a multi-package `--workspace` test run
(no `--no-fail-fast` is passed, matching the pre-existing CI command exactly
— this script changes nothing here). Because `nine65`'s `--lib` target has
the 5 pre-existing failures documented under FAST above, the run terminates
immediately after that target's `test result: FAILED` line — **every one of
nine65's `tests/*.rs` integration binaries (`bootstrap_integration`,
`security_integration`, `audit_regressions`, `noise_profile`,
`cram_public_mode`, `error_variant_coverage`, `op_timings`, `random_encrypt`,
`bootstrap_parameter_exploration`, `bootstrap_residue_shape_regression`,
and more), `nine65-extreme-tests`, `private-feedback-core`,
`private-feedback-nine65`, and `unhal` were compiled but never executed** in
this run (confirmed: they were all built during the compile phase, per the
`--verbose` log, but no `running N tests` / `test result:` line for any of
them appears anywhere in the output). `error_variant_coverage` is separately
invoked as its own CI step right after this one specifically because of this
kind of gap — but a dozen-plus other integration targets have no such
individual step and are silently unreached whenever nine65's `--lib` fails
first.

This is **pre-existing behavior**, not introduced by this categorization
change — `scripts/run_tests_medium.sh` is a byte-for-byte wrapper of the
exact command `ci.yml`'s `full-test` job already ran, so this gap has been
present in CI (when CI last ran, pre-2026-02-27) exactly as it is here. It
is flagged because it bears directly on issue #78's own acceptance bar
("keeping the complete release suite reachable and required," "must improve
runtime, not hide failing tests") — right now, whenever `nine65 --lib` has
any failing test, the "required, complete" suite silently stops there.
`crates/nine65/tests/` alone holds 28 integration-test files
(`bootstrap_integration.rs`, `security_integration.rs`,
`audit_regressions.rs`, `op_timings.rs`, `random_encrypt.rs`, and 23 more —
see `ls crates/nine65/tests/*.rs`), none of which ran in this measurement,
on top of `nine65-extreme-tests`, `private-feedback-core`,
`private-feedback-nine65` and `unhal` — with zero indication in the exit
code or summary that anything downstream was skipped rather than passed.
Fixing this (e.g. via `--no-fail-fast`, run per-package, or explicit
downstream steps) is out of scope for this PR — it would change MEDIUM's
behavior,
which this PR deliberately keeps identical to the pre-existing command —
but it is a real gap worth its own follow-up issue.

### SLOW (`scripts/run_tests_slow.sh`)

| part | command | passed | failed | ignored | time |
|---|---|---|---|---|---|
| [1/3] `slow_tests` feature | `cargo test -p nine65 --lib --release --features slow_tests` | 814 | **5** | 124 | 91.38s |
| [2/3] `op_timings` | `cargo test -p nine65 --test op_timings --release --features allow_insecure -- --ignored --nocapture` | 1 | 0 | 0 | 15.08s |
| [3/3] `nine65-extreme-tests` | `cargo test -p nine65-extreme-tests --release --features extreme-tests` | 77 | **8** | 0 | 7.42s |
| **total** | | **892** | **13** | **124** | **real 3m12.771s** (user 10m16.811s, sys 0m11.918s) |

Part [1/3]'s 5 failures are the identical `ops::auto_bootstrap`/
`ops::bootstrap` set documented under FAST — the `slow_tests` feature adds
long-running tests in `ops/rns_fhe.rs` on top of the default set; it does
not touch the bootstrap tests, so the same pre-existing failures reappear
(814 passed here vs FAST's 880, because this is a `-p nine65`-scoped build
and does not get the `--workspace` feature unification from
`nine65-extreme-tests`'s dev-dependency that FAST/MEDIUM benefit from —
expected, not a defect).

Part [2/3] passed and reproduces real, fresh per-operation timings in the
exact table format CLAUDE.md's "Performance Baselines" section documents
from this same suite:

| Config | N | main lanes | Encrypt ms | Add ms | Public mul ms | Symmetric mul ms | Decrypt ms |
|---|---|---|---|---|---|---|---|
| `secure_128` | 8192 | 4 | 7.41 | 1.901 | 384.39 | 97.03 | 2.49 |
| `secure_128_deep` | 8192 | 4 | 7.12 | 1.952 | 392.33 | 102.92 | 2.57 |
| `secure_192` | 16384 | 5 | 20.03 | 5.098 | 1033.54 | 232.37 | 7.18 |
| `secure_256` | 16384 | 6 | 21.47 | 5.641 | 1196.56 | 246.21 | 7.74 |

(Measured under the same heavy shared-host contention as everything else on
this page — not a replacement for CLAUDE.md's own dedicated baseline run.)

Part [3/3]'s 8 failures are new names but the same underlying cause as
everything else on this page — every one traces to bootstrap/refresh
correctness, not to anything this categorization PR touches:
`bootstrap_adversarial::tests::{test_bootstrap_all_three_paths_same_
plaintext, test_bootstrap_on_fresh_ciphertext,
test_bootstrap_roundtrip_sampled_plaintexts}`,
`boundary_tests::tests::{test_anchor_capacity_bits_canonical,
test_proximity_warn80_region, test_proximity_warn90_region}`,
`cross_config_operations::tests::test_bootstrap_config_mismatch_returns_
error`, and `depth_stress_tests::tests::test_public_key_unlimited_depth_100`
(panics with "No bootstrap was triggered over 100 multiplications" —
consistent with the same noise-budget/admissibility gate issue documented
under FAST's `diag_measure_noise_growth` finding).

**Bug found and fixed during this verification pass**: the script as first
written used `set -euo pipefail`, so part [1/3]'s pre-existing failure
aborted the whole script before parts [2/3] and [3/3] ever ran — 0%
coverage of `op_timings` and `nine65-extreme-tests`, unconditionally, for
as long as those 5 bootstrap failures stand (which is now). That directly
contradicted this tier's own purpose and issue #78's "must not hide failing
tests" bar, so it was fixed here: each part now runs unconditionally, exit
statuses are tracked independently, and the script exits nonzero overall
iff any part failed (verified above: exit 1 — parts 1 and 3 failed, 2
passed — with all three actually executing and reporting). This was the one
change made to the previously-drafted scripts during this verification
pass; everything else in `scripts/run_tests_{fast,medium}.sh` and
`scripts/check_test_tier_drift.py` was verified as-is.

## CI wiring

- **MEDIUM** replaces `full-test`'s inline `cargo test --workspace --verbose
  ...` command 1:1 in `.github/workflows/ci.yml`. Zero behavior change.
- **SLOW** is wired as a new, purely additive T4 job (`slow-test-tier`),
  gated on the identical `if:` condition every other T4 job in this file
  already uses (schedule / `[deep-ci]` / manual "deep" dispatch).
- **FAST is deliberately NOT wired into T1** (the "~3 min, every push" fast
  gate). Two independent reasons, both now confirmed empirically by this
  session's measured run, not speculation:
  1. A from-scratch `cargo test --lib --release` compile+run (this repo's
     `lto = "fat"`, `codegen-units = 1` release profile) took 17m8.890s
     wall-clock in this run — and per the table above, several individual
     tests inside `--lib` cost 60s+ each on their own, independent of
     compile time or host contention.
  2. CI has not executed successfully since 2026-02-27 (issue #79), so
     there is no warm-cache steady-state timing to measure against a real
     GitHub Actions runner. Guessing that the existing cargo-registry/
     target caches would keep FAST under the T1 budget is exactly the kind
     of unvalidated CI change issue #78's assignment comment asked this
     work not to make.

  Wiring `bash scripts/run_tests_fast.sh` into `fast-gate` is the natural
  next step once #79 clears and a real CI run's timing is on record — and,
  per the finding above, once the individual 60+s tests inside `--lib` are
  either moved to `tests/*.rs` (medium tier) or gated behind `slow_tests`.

## Drift detection

`scripts/check_test_tier_drift.py` builds every workspace crate's `--lib`
test binary once, then times each test individually (via direct binary
invocation with `--exact`, not `cargo test --report-time`, since that needs
a nightly toolchain and this repo's CI is `dtolnay/rust-toolchain@stable`).
Any test over `--threshold-secs` (default 2.0s) is flagged as a candidate
to move out of the FAST tier. Advisory by default (reports, exits 0);
`--mode enforced` exits 1 on any finding. Not wired into CI yet — same
reasoning as FAST above: there is no CI baseline yet to decide the right
default threshold against, and this session's measured findings (the 60s+
tests listed above) already show real drift to triage before turning
enforcement on.

```
python3 scripts/check_test_tier_drift.py                       # full inventory + timing
python3 scripts/check_test_tier_drift.py -p nine65 --threshold-secs 1.0
python3 scripts/check_test_tier_drift.py --list-only            # inventory only
python3 scripts/check_test_tier_drift.py --mode enforced        # exit 1 on drift
```

## Local usage

```
bash scripts/run_tests_fast.sh     # inner dev loop
bash scripts/run_tests_medium.sh   # required, pre-push
bash scripts/run_tests_slow.sh     # weekly / pre-release
```

Extra arguments forward to the underlying `cargo test` invocation(s), e.g.
`scripts/run_tests_fast.sh -p nine65 -- --nocapture`.
