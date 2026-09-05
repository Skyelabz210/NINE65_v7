# Benchmark Regression Checking — 2026-09-03

Resolves issue #19's core gap: `crates/nine65/tests/op_timings.rs` has measured
encrypt/add/public-mul/symmetric-mul/decrypt per secure config since
2026-08-23, and `.github/workflows/ci.yml`'s `benchmark-regression` job has
existed for about as long — but neither one compares a timing number to
anything. The CI job runs `scripts/regression_scan.sh` (a *source* gate: test
count floor, float/panic scan — nothing about wall-clock time) plus
`cargo bench -- --test`, Criterion's smoke mode: one sample per benchmark, no
statistics, nothing to compare against. Both were, and remain, honestly named
in intent but not in effect. This closes the actual gap: capture, baseline,
compare, threshold.

## What landed

1. **Capture.** `crates/nine65/tests/op_timings.rs` now also writes an
   integer-nanosecond JSON capture (`bench-results/op_timings.json` by
   default, or `$NINE65_BENCH_JSON_OUT`) alongside its existing markdown
   table — every raw sample plus its median, per operation, per config, plus
   the full config tuple `(n, primes, t)`. The JSON is hand-serialized (no
   `serde_json`): the test target's only required feature is
   `allow_insecure`, and adding a `serde` requirement would have changed the
   documented reproduce command. `median_ns` and the ms-formatted markdown
   column both come from one integer-only helper (`median_ns` + `ns_to_ms_string`,
   sort-and-index / integer div-mod) — no `f32`/`f64` anywhere in the new
   code path, per CLAUDE.md's "Important Coding Rules" and this task's
   explicit instruction that benchmark reporting stay integer-only.
2. **Baseline.** `docs/benchmarks/op_timings_baseline.json` — the four
   `CLAUDE.md` "Performance Baselines" table figures (measured 2026-08-23),
   transcribed to integer nanoseconds, one entry per config **tuple** (never
   bare name — see below for why that distinction is load-bearing here, not
   theoretical).
3. **Compare.** `scripts/check_benchmark_regression.py` — loads one or more
   captures, pools their raw samples per `(tuple, operation)`, takes the
   integer median, and diffs against the baseline in basis points (integer
   multiply + floor-divide, no float). Exits 1 on any regression past
   `--threshold-percent` (default 25).

Run it:

```bash
cargo test -p nine65 --test op_timings --release --features allow_insecure \
  -- --ignored --nocapture
python3 scripts/check_benchmark_regression.py
```

## Matching by tuple, not name — this is not a hypothetical

The comparator keys every config by `(n, primes, t)` read out of the JSON,
never by the `config` name string. CLAUDE.md already documents why in the
abstract (`secure_128` denoted three different tuples across this project's
history — N=4096/3 primes, then N=8192/3 primes, then N=8192/4 primes). This
task's own verification run turned up a **live, current instance** of exactly
that failure mode:

- `SecureConfig::secure_128()` was re-cut from a 3-prime chain to a 4-prime
  chain on **2026-08-28** — five days after the 2026-08-23 measurement that
  produced the CLAUDE.md/README baseline table (`docs/OPEN_WORK_2026-08-26.md`
  section A3; commits `bc7b620` and `0b200af`). Neither `CLAUDE.md` nor
  `README.md` was updated with fresh numbers after the recut, so the
  currently-committed baseline table under the name `secure_128` is now stale
  for what that name means on `main` today.
- Current `secure_128` is, since that recut, numerically identical to
  `secure_128_deep` — same `n=8192`, same four primes
  `[998244353, 985661441, 754974721, 469762049]`, same `t=65537`.

`docs/benchmarks/op_timings_baseline.json` records this honestly: the
historical 3-prime `secure_128` entry is kept (citation-faithful to
CLAUDE.md) but marked `"tuple_status": "STALE..."`, and a current
`secure_128` capture correctly matches against the `secure_128_deep` entry
instead (same tuple), reported under the joined label
`secure_128 / secure_128_deep` rather than silently attributing its numbers
to one name and dropping the other — see "Two names, one tuple" below.
Comparing today's 4-prime `secure_128` against the stale 3-prime baseline
figure would have produced a meaningless number in either direction (it's a
strictly bigger chain now, doing more work); the tool detects the tuple
mismatch and refuses that comparison instead of eyeballing it.

## Two names, one tuple

`pool_current()` pools samples per tuple, not per name. When two config
NAMES share one tuple in the same capture (`secure_128` and
`secure_128_deep`, right now) an earlier version of this tool let the second
name silently overwrite the first in a plain `dict[tuple, str]`, which both
discarded a label and merged unrelated call sites into one row without
saying so. Caught during this task's own verification run (see "Real
capture" below — the very first live comparison hit exactly this case).
Fixed: both names are kept and reported jointly (`"secure_128 / secure_128_deep"`);
pooling their samples together is correct once the tuples are equal — it is
the same underlying computation, so more samples is a smaller-noise median,
not two different medians hidden as one.

## Threshold: 25%, and why

- `docs/roadmap/T5_BENCHMARKS_AND_REPRODUCIBILITY.md` and
  `docs/CRAM_PUBLIC_BASELINE_2026-08-26.md` already establish and use a
  **>25% median regression** rule for this exact house pattern (medians over
  repeated in-process rounds, `op_timings.rs`-style) — deliberately looser
  than the **~20% run-to-run reproduce-window** CLAUDE.md and README.md
  document for the same harness. This script's default (`--threshold-percent 25`)
  matches that existing, already-reasoned house number rather than inventing
  a new one.
- That 20% figure is itself a measurement, not a guess: "Run-to-run spread on
  `secure_128` public mul across four separate invocations was 281–302ms" —
  an ~7% half-spread around the ~292ms median (≈14% peak-to-peak) on the
  same "4 vCPU shared container" class this task ran on. 25% sits
  comfortably above that.
- Repeated-run pooling (`--current a.json b.json c.json`, recommended: 3,
  matching the house `op_timings.rs`/T5 convention) further damps single-run
  noise by taking the median over every round from every run combined,
  before the threshold is even applied.

This is a starting point, not a ceiling: tighten it for a quieter runner,
loosen it for a noisier one, but only after measuring that runner's own
noise floor — which is exactly what this task's own verification run below
forced into the open.

## Real capture, and an honest problem with it

This container was captured under **extreme, real contention**: at capture
time, `ps aux` showed ~29–38 concurrent `cargo`/`rustc` processes (sibling
agent sessions building in parallel worktrees sharing this repo's
`CARGO_TARGET_DIR`), and `uptime` load average reached **37–41 on 4 vCPUs**.
The `op_timings` release build alone (fat LTO, `codegen-units=1`) took
16m51s under that load, and the timed rounds ran while dozens of other
processes were being scheduled onto the same 4 cores — `Instant::now()`
measures wall clock, so every sample absorbed that scheduling noise.

Commit measured: `43a7d33`. Environment: `rustc 1.94.1 (e408947bf 2026-03-25)`,
Linux 6.18.44, 4 vCPU (`Intel(R) Xeon(R) Processor @ 2.10GHz`), default
features (MANA + UNHAL active), `--release`.

Result, comparing that real capture against the committed baseline:

```
$ python3 scripts/check_benchmark_regression.py --current bench-results/op_timings.json
[REGRESSION] secure_128 / secure_128_deep add            baseline=      1528000 ns  current=      2416420 ns  delta=  +58.14%
[REGRESSION] secure_128 / secure_128_deep decrypt        baseline=      2510000 ns  current=     13948988 ns  delta= +455.73%
[REGRESSION] secure_128 / secure_128_deep encrypt        baseline=      6600000 ns  current=     39111288 ns  delta= +492.59%
[REGRESSION] secure_128 / secure_128_deep public_mul     baseline=    408660000 ns  current=   2741059692 ns  delta= +570.74%
[REGRESSION] secure_128 / secure_128_deep symmetric_mul  baseline=     93140000 ns  current=    751722337 ns  delta= +707.08%
[REGRESSION] secure_192           add            baseline=      5488000 ns  current=     19250701 ns  delta= +250.77%
[REGRESSION] secure_192           decrypt        baseline=      7510000 ns  current=     60875874 ns  delta= +710.59%
[REGRESSION] secure_192           encrypt        baseline=     23090000 ns  current=    141449350 ns  delta= +512.60%
[REGRESSION] secure_192           public_mul     baseline=   1114120000 ns  current=  11648062964 ns  delta= +945.49%
[REGRESSION] secure_192           symmetric_mul  baseline=    247210000 ns  current=   2425227644 ns  delta= +881.03%
[REGRESSION] secure_256           add            baseline=      5943000 ns  current=      9730383 ns  delta=  +63.72%
[REGRESSION] secure_256           decrypt        baseline=      7780000 ns  current=     37625850 ns  delta= +383.62%
[REGRESSION] secure_256           encrypt        baseline=     22410000 ns  current=    101855207 ns  delta= +354.50%
[REGRESSION] secure_256           public_mul     baseline=   1017910000 ns  current=   8103878881 ns  delta= +696.12%
[REGRESSION] secure_256           symmetric_mul  baseline=    262960000 ns  current=   1718642631 ns  delta= +553.57%

RESULT: REGRESSION DETECTED (threshold 25%)
```
(exit code 1)

Read this as **the tool working correctly on real data, not as a code
regression**: a 3–9× wall-clock slowdown under 37-41 load average on a 4-core
box is exactly what contended scheduling produces, and nothing in this task's
diff touches the arithmetic hot path. No threshold this tool could
reasonably default to should absorb a 9× swing — that would make it useless
against the regressions it exists to catch (the constant-time change to
`BarrettContext::reduce_ct` that motivated writing `op_timings.rs` in the
first place moved the innermost NTT loop, not a few percent). The honest
conclusion is that **this specific run is not a valid baseline-reproduction
data point** for this container's uncontended performance — it's kept here,
unmodified, specifically because it is the real, actually-executed
regression-path demonstration this task asked for, and because it caught the
name-collision bug described above. Re-run on a quiet container to get a
clean same-tuple comparison; the tool does not need to change to do that,
only the ambient load does.

## Two controlled demonstrations, isolated from that noise

To show both outcomes without depending on getting a quiet window on a
shared box, two small hand-authored fixtures exercise the comparison logic
directly (clearly marked `SYNTHETIC EXAMPLE` in their own `source` field —
not claimed as real captures). Both compare against the same committed
baseline, `secure_128_deep`.

**Pass:** every operation offset by a different amount, all within ±25%
(+8%, −5%, +0%, +15%, −12%):

```
$ python3 scripts/check_benchmark_regression.py --current bench-results/synthetic_pass_example.json
[PASS      ] secure_128_deep      add            baseline=      1528000 ns  current=      1451600 ns  delta=   -5.00%
[PASS      ] secure_128_deep      decrypt        baseline=      2510000 ns  current=      2208800 ns  delta=  -12.00%
[PASS      ] secure_128_deep      encrypt        baseline=      6600000 ns  current=      7128000 ns  delta=   +8.00%
[PASS      ] secure_128_deep      public_mul     baseline=    408660000 ns  current=    408660000 ns  delta=   +0.00%
[PASS      ] secure_128_deep      symmetric_mul  baseline=     93140000 ns  current=    107111000 ns  delta=  +15.00%

RESULT: PASS (no operation regressed more than 25% against baseline)
```
(exit code 0)

**Regression:** everything unchanged except `public_mul`, deliberately set
to +30% — past the default 25% threshold, everything else exactly at
baseline:

```
$ python3 scripts/check_benchmark_regression.py --current bench-results/synthetic_regression_example.json
[PASS      ] secure_128_deep      add            baseline=      1528000 ns  current=      1528000 ns  delta=   +0.00%
[PASS      ] secure_128_deep      decrypt        baseline=      2510000 ns  current=      2510000 ns  delta=   +0.00%
[PASS      ] secure_128_deep      encrypt        baseline=      6600000 ns  current=      6600000 ns  delta=   +0.00%
[REGRESSION] secure_128_deep      public_mul     baseline=    408660000 ns  current=    531258000 ns  delta=  +30.00%
[PASS      ] secure_128_deep      symmetric_mul  baseline=     93140000 ns  current=     93140000 ns  delta=   +0.00%

RESULT: REGRESSION DETECTED (threshold 25%)
```
(exit code 1)

Both deltas land on the exact integer percentage they were constructed with
(`+30.00%` for a `1.30×` input, `+8.00%`/`−5.00%`/`+15.00%`/`−12.00%` for
their inputs) — confirming the basis-point arithmetic (`(current - baseline)
* 10000 // baseline`, integer multiply + floor-divide) is exact for these
round inputs, with no float anywhere in the path.

## Updating the baseline

There is no separate tool — `--update-baseline` is the documented process:

```bash
python3 scripts/check_benchmark_regression.py --update-baseline \
  --current bench-results/run1.json bench-results/run2.json bench-results/run3.json
```

Review the resulting diff to `docs/benchmarks/op_timings_baseline.json` like
any other source change before committing it — this repo's culture (see
CLAUDE.md's "Performance Baselines" section) is unusually strict about not
overwriting a documented baseline without stating what changed and why.

## What this does not cover yet

Scoped deliberately narrow, per this task's brief:

- **CI wiring.** `.github/workflows/ci.yml`'s `benchmark-regression` job is
  untouched. GitHub Actions has not executed on this repository since
  2026-02-27 (issue #79, open) — wiring this comparator into a workflow that
  cannot run would be unverifiable busywork. Once #79 clears, the follow-up
  is mechanical: run the capture, run the comparator, upload
  `--report-out`'s JSON as an artifact, fail the job on a non-zero exit.
- **Coverage beyond `op_timings.rs`'s existing five ops.** Issue #19's
  original comment thread (2026-08-31) asks for a wider matrix — bootstrap
  latency (all 3 paths), key/context generation, K-Elimination/rescale,
  MANA/UNHAL lane kernels, the compare-bit kernel. `op_timings.rs` does not
  measure these today; extending it is a separate task the same way
  `cram_public_timings.rs` (T5, landed 2026-08-26) extended coverage to the
  CRAM-public surface, following the same house pattern this tool now also
  consumes.
- **Criterion integration.** `scripts/extract_criterion_summary.py` already
  exists for pulling `target/criterion/**/new/estimates.json` into JSON;
  wiring Criterion bench output into this same comparator (rather than only
  `op_timings.rs`'s JSON) is straightforward future work — the schema would
  need a small adapter, not a redesign.
