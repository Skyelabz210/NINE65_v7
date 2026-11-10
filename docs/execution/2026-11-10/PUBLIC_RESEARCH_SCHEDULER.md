# Explicit public research refresh scheduler

Base: `7ada6503634a824e80bc4bcfd6231ad0178d7ed3` (current `origin/main` at
implementation start). This is a bounded library addition, not production
admission or an application-wide backend switch. Read
[public-refresh status](../../PUBLIC_REFRESH_STATUS.md) for the separate
functional, provenance, security, and legacy-gate claims.

## API and policy

`ops::public_refresh_circuit::scheduler::PublicResearchRefreshScheduler`
wraps an already generated `PublicRefreshCircuit` and a required lifetime
`max_refresh_attempts` limit. It is available under the circuit's existing
`allow_insecure`/unit-test gate. It owns no client or secret-key object.

- `forecast_add`, `forecast_multiply`, and `forecast_square` perform only
  deterministic integer bound arithmetic. Forecasts identify the key family,
  exact input lineages, selected refresh operands, output bound and output
  source radius. They do not create ciphertexts or issue history certificates.
- `add`, `multiply`, and `square` recompute admission from the current sealed
  inputs and remaining budget. No API accepts a forecast as execution authority.
  Thus editing or retaining a preview cannot reset history or reuse a spent
  budget.
- The scheduler first attempts direct evaluation. Otherwise it considers
  refreshing the left operand, right operand, or both, in that order. It picks
  the first supported option, minimizing refresh calls among those candidate
  schedules, with a deterministic left-before-right tie break. A square refreshes its single
  operand once and reuses that returned ciphertext for both factors. Binary
  `multiply` treats its two arguments separately; use `square` to share a
  refreshed operand.
- Every admitted add/multiply/square result must fit the work decode bound and remain inside
  this circuit's source-conversion radius. The scheduler may therefore refresh
  before raw arithmetic would exhaust decryption capacity. This preserves the
  next refresh opportunity rather than waiting until recovery is impossible.
- Every selected input must itself still support source conversion. Inputs
  already taken beyond source support by another evaluator fail closed.
- The complete attempt budget is checked before any encrypted refresh begins.
  Failed backend calls consume an attempt, and no retry or alternate backend is
  automatic. Binary operations have at most two attempts; squares have at most
  one. If a second refresh or the final operation fails, completed refresh work
  remains counted, but caller-owned input ciphertexts are unchanged.

The source evaluator now exposes typed read-only operation/source forecasts;
its existing add/multiply methods use those same ledger routines. All numeric
planning helpers admit each bound before arithmetic, including U512 extremes.
Source-family pointer identity is checked before forecasting any operation.
Actual refresh return still uses the existing sealed root/history/key-family
validation, and the scheduler additionally checks the promised return bound,
unchanged root capability, and advancing ciphertext lineage.

## Errors and boundaries

`SchedulerError` distinguishes source errors (including `DomainMismatch`),
`OperationUnfunded`, `RefreshBudgetExceeded`, an identified operand's
`RefreshFailed`, and an executed output's `ForecastMismatch`. Only the existing
`SourceError::NoiseExhausted` is interpreted as a capacity forecast that may
justify considering another public schedule; other errors retain their cause.

There is no fallback to legacy `ClockworkBootstrap`, symmetric/secret-key
refresh, or metadata reset. `AutoBootstrapEvaluator`, production gates,
parameter/security admission, and existing raw evidence are unchanged. This
wrapper does not offer a CPU-time or memory quota, global optimal scheduling,
a DAG/compiler integration, remote attestation, or serialized forecast replay.
The attempt cap bounds refresh calls, not the cost of an individual native
call. A caller can inspect a forecast before explicitly executing the method.

## Verification

The final local verification and exact executed tests are recorded below.
Reduced encrypted tests use work/source N=8, outer N=32, t=65537, four work
primes and the existing thirteen-prime research outer tuple. They do not claim
a latest-head N8192 rerun. The native source/circuit data and security premise
are unchanged.

Passed locally on Rust 1.89.0, debug assertions enabled, with
`profile.test.package.nine65.opt-level=2` for encrypted unit tests:

- Eleven exact-name scheduler regressions, one test per command and zero ignored
  tests, using `python3 scripts/run_public_refresh_research_gates.py --suite scheduler`.
  The runner rejects successful zero-test exits.
- The repeat-square regression executed 12 squares and 3 real public refreshes
  for each of two seeds: 24 squares, 6 refreshes, 192 full-polynomial coefficient
  comparisons. Other tests cover addition-triggered refresh, binary refresh,
  foreign key families, exhausted history, stale forecast/budget handling,
  whole-operation budget reservation, and first/second-refresh failures.
- All existing public-refresh-circuit/key-graph tests alongside scheduler tests.
- Seven public-source regressions, including the existing N8192 same-ring and
  N32768 embedded source-preparation tests. Source preparation is not a full
  encrypted native refresh cycle.
- Both exact-name production-boundary regressions: legacy public Phase 1 stays
  typed fail-closed and config support still requires sound Phase 1.
- The `SourceWorkCiphertext` compile-fail doctest: direct bound reset is refused
  because the field remains private.
- Research/default library checks; strict research library Clippy (`-D warnings`);
  workspace formatting and `git diff --check`; five Python runner unit tests.

No full workspace test sweep, full native N8192 refresh cycle, production
security assessment, deployment, push, or merge was performed. This is local
implementation and scoped correctness evidence, not a full-repository pass.
