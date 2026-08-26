# T5 — Benchmarked Regression Tests + Reproducibility Metrics

**Tier: HANDOFF-SAFE.** Mechanical: follow the existing `op_timings.rs`
pattern exactly. The guardrails from T2 catch any accidental behavior
change; this task only measures, it does not modify evaluator logic.

## Goal

A new `crates/nine65/tests/cram_public_timings.rs`, structured identically
to the existing `crates/nine65/tests/op_timings.rs`, covering the
CRAM-public surface (`CramPublicEvaluator`) and the manufactured-chain path,
plus a dated baseline doc recording the numbers with a reproduce command.

## Files (read these first — do not guess the pattern)

- `crates/nine65/tests/op_timings.rs` — the house pattern to copy. Read its
  header comment (explains WHY it exists — a perf claim nobody re-runs is
  the same class of problem as a CI claim nobody checks), `median()`
  helper, and `time_config()`'s per-op timing loop shape (each op timed in
  a loop, medians taken, every round decrypts and asserts exactness so a
  timing number never comes from a wrong answer).
- `CLAUDE.md` (repo root) §Performance Baselines — the baseline-doc format
  to match: table + reproduce command + a "stale figures to stop quoting"
  discipline. Read the whole section once; it documents exactly the
  failure modes this task must avoid (comparing across a config
  redefinition, trusting an unreproduced number, over-interpreting a ratio
  without re-measuring).
- `crates/nine65/src/ops/cram_public.rs` — `CramPublicEvaluator`'s public
  methods to time: `encrypt_with_rng`, `add`, `mul_plain`, `exact_divide`,
  `mul` (materializing), `mul_manufactured`, `decrypt`.
- `crates/nine65/src/params/mod.rs::manufactured_m2b_insecure` — the
  manufactured config to benchmark alongside a general one
  (`secure_128_deep` — NOT `secure_128`, which the CLAUDE.md bootstrap
  table already flags as refused for related reasons; deep configs are the
  ones this codebase's other benchmarks use).

## DO NOT

- **Do not key any comparison on a config NAME across time.** CLAUDE.md
  documents the exact house failure mode: `secure_128` was redefined
  between February and August (N=4096→8192, 3→3+5 lanes), making a
  Feb-vs-August delta under that name meaningless. Always record the full
  config TUPLE (n, primes, t) in the baseline doc, not just the name.
- **Do not report a single run as a baseline.** Minimum 3 runs, medians,
  per the `op_timings.rs` pattern.
- **Do not skip the determinism check.** This codebase's CLAUDE.md commits
  to "bit-identical results across all platforms" — verify it, don't assume
  it, by running each op twice in-process on IDENTICAL seeds and hashing
  every ciphertext limb.
- **Do not silently drop an op from the table** if it fails or is skipped
  for a config — note it explicitly (house rule: no silent truncation of
  coverage; if something is out of scope, say so in the doc).

## Steps

1. Create `crates/nine65/tests/cram_public_timings.rs`:
   - Header comment: why it exists (mirror `op_timings.rs`'s framing),
     reproduce command.
   - `#[ignore]`d tests (same as `op_timings.rs` — these are slow and not
     part of the default `cargo test` run).
   - Configs: `manufactured_m2b_insecure()` and `secure_128_deep()`.
   - Ops per config: encrypt, add, mul_plain, exact_divide, mul
     (materializing — only meaningful on `secure_128_deep`, or on the
     manufactured config via `mul_dual_public` if that entry point still
     exists there), mul_manufactured (manufactured config only), decrypt.
   - Fixed, DOCUMENTED seeds (write them in the file, e.g. `ShadowHarvester::with_seed(4242)`
     — copy the exact seed `op_timings.rs` uses if there's no reason to
     diverge, so cross-file comparison stays possible).
   - 3 runs, medians (reuse or adapt `op_timings.rs`'s `median()` helper).
   - Machine context: print `nproc` and a CPU model line (read `/proc/cpuinfo`,
     same as CLAUDE.md's existing baseline entries record "4 vCPU shared
     container @ 2.80 GHz").
   - Determinism check: for each op, run it twice in-process with IDENTICAL
     seeds; hash all ciphertext limbs (any stable hash — even a simple
     accumulator over the `Vec<Vec<u64>>` limbs is fine, this is not a
     security-sensitive hash); assert the two hashes are equal.
2. Freeze M2b's already-measured acceptance numbers as pinned constants,
   following `unified_rescale.rs`'s existing pinned-measured-constants
   pattern (grep that file for how it documents a measured constant as a
   comment next to an `assert_eq!`): depth-3 result = 256, the
   `manufactured_rescale_matches_ground_truth_on_known_values` sweep's
   `checked >= 50` point count, and the M3 noise margin from T3's card
   (only if T3 has landed by the time this runs — otherwise skip and note
   it as pending).
3. Write `docs/CRAM_PUBLIC_BASELINE_<YYYY-MM-DD>.md` (today's date when you
   run this): table of op → median ms, per config; commit hash the
   measurement was taken at; the exact config tuples (not just names);
   seeds used; the reproduce command; a "regression rule" section stating
   future runs flag a >25% median regression against this baseline (the
   house reproduce-window in `op_timings.rs`/CLAUDE.md is ±20% — this
   task's regression THRESHOLD is intentionally a bit looser than the
   reproduce-window, so normal run-to-run noise doesn't false-positive).

## Commands

```
cargo test -p nine65 --test cram_public_timings --release --features allow_insecure -- --ignored --nocapture
```

## Acceptance criteria

- New test file exists, follows the `op_timings.rs` pattern (medians,
  every round decrypts and asserts exactness, `#[ignore]`d, reproduce
  command in the header).
- Determinism check passes (identical seeds → byte-identical ciphertexts).
- Baseline doc written with full config tuples (not bare names), commit
  hash, seeds, and reproduce command.
- Running the suite a second time reproduces the recorded medians within
  ±20% (the house reproduce-window).

## Escalate-if

- A timing comes back wildly inconsistent across the 3 runs (>2x spread) —
  investigate before reporting a median; this usually means the container
  is under contention or the test needs more warmup, not that the
  implementation is actually that variable.
- The determinism check FAILS — this is not a benchmarking problem, it's a
  correctness regression against a hard platform requirement (CLAUDE.md:
  "Deterministic execution — bit-identical results across all platforms
  required"). Stop, do not paper over it in the benchmark, escalate to a
  frontier-capable session.
