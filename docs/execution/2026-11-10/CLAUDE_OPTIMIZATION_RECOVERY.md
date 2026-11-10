# Claude optimization integration: reconstructed and checked

Date: 2026-11-10. This is bounded review-branch validation, not a main merge,
complete correctness suite, performance result or security admission.

## Recovery and exact inputs

A cloud replacement removed the earlier uncommitted integration, its raw logs
and the pending upload payload. GitHub rejected its recorded tree as a missing
object. The old tree was not recovered, and its earlier test counts are not
claimed for this reconstruction.

The research input `0986fca6183d9e537e955c2285ba59f66f9003d1` was merged locally
onto main `a6780e9a0a4ca633d941cdd8b42973560948a0ab`. Main's full CLAUDE.md and
coefficient_slot_gate.rs were retained. Its scheduler, entropy, depth, Lean,
parameter evidence, exact-evaluator and architecture-meter work is preserved.
The tested source tree is `04100b4babd40ae859837c6b6aeb765c65fee814`.
The publication adds fresh logs and this report without subsequent Rust edits.

## Integrated implementation and restored fixes

- Cached per-level and anchor CRT plans, prime Montgomery reducers, single-pass
  gadget digits, fused negacyclic NTT, shared tensor transforms and NTT-domain
  paired sums from Claude's branch. Historical timing documents remain scoped
  to their original measurements; no speedup was remeasured here.
- Preserved shared architecture counters. Valid cached reconstruction increments
  its counter; rejected U256 conversion does not. Anchor reconstruction and
  free-standing helpers are not all counted by that one counter.
- Removed the general CRT fallback for unsupported U256 bases. Both entry paths
  check the exact product before widening and fail explicitly for empty/oversized
  bases. Existing infallible APIs panic only at those unsupported conversions;
  wide RNS contexts remain constructible for the arbitrary-width exact path.
- Fixed divisor one and 255/256-bit divisor handling. Quotient/remainder and
  capped rounding share one exact implementation. Zero rescale delta returns
  a typed error. Added tests for full-width boundaries and >512-bit admission.
- Restored the explicit reference NTT backend's tensor and paired-sum APIs using
  independent textbook products. Its comparison tests do not call FFT kernels.
- Made sequential override accelerated dispatch, retained zero-digit no-work
  behavior, and added signed/reduced-level/first-error/meter regressions.
- Guarded every safe Ntt32 entry point with exact length and runtime AVX-512F
  checks before writes or unsafe instructions. Expanded scalar equivalence over
  all named work/anchor tuples and tail/native sizes. Ntt32 remains unwired to
  production dispatch and cannot handle the native outer chart's 59-bit lanes.
- Test-only reference tables/helpers are compiled only for tests. Explicit
  optional-dependency requirements keep two existing diagnostic targets from
  breaking no-default builds. Formatting and test-only lint issues were fixed.

## Fresh executed checks

Pinned Rust/Cargo 1.89.0, debug profile, two build jobs, dev/test debug info off.
The final source completed all commands in the
[results manifest](../../../artifacts/execution/2026-11-10/claude-recovered/results.json).
The [evidence manifest](../../../artifacts/execution/2026-11-10/claude-recovered/manifest.json)
records exact filters, counts and raw-log hashes. Intermediate failures are
retained in before-lint-fix and do not replace final successful outcomes.

- Default architecture-meter targeted library execution: **106 passed, zero
  failed, three existing ignored tests**. This includes 57 RNS/CRT/divisor,
  12 FFT, 24 textbook NTT tests and the signed digits, actual public multiply,
  K0 identities/refusals, secure_192 and legacy-bootstrap refusal checks.
  Each final filter had a 45-second ceiling; the binary build had 150 seconds.
- Workspace/all-targets clippy with architecture-meter and warnings denied.
- All-targets clippy with reference_ntt,sequential,architecture-meter and
  warnings denied. This compiles the feature-selected reference backend; its
  full FHE runtime suite was not run.
- No-default all-targets compilation. Three pre-existing unused/dead-code
  warnings in SafeBasis test code remain; this is not a lint-clean claim there.
- Sequential calling-thread test: one pass.
- UNHAL API tests: two reported passes. Wrong-length rejection executes;
  unsupported-host rejection returns early on this AVX-capable machine.
- The actual AVX-512 scalar-equivalence kernel test executed successfully across
  secure_128/192/256 main and anchor primes, multiple lengths and input patterns.
- Explicit allow_insecure coefficient-slot test: one pass, **85 encrypted
  residual/message pairs across 11 batches**, preserving stage and coefficient
  assertions. This remains an insecure toy correctness fixture.
- Formatting/diff checks, deterministic NTT source invariant check and claim
  registry check passed. Source checks do not establish timing behavior.

## Routes and remaining coverage

Named work Q widths are 119/146/175 bits. Allocated legacy boot chains are
146/177/206 bits and the full catalog is 235 bits. K reconstruction uses seven
anchors (220 bits) or the first eight (251 bits), not the full ten-anchor basis.
These paths fit cached U256 plans. The 650-bit native research outer chart uses
PublicRefreshCircuit -> SplitDigitEvaluator -> prepared ExactMulEvaluator, not
this U256 conversion. Its return drops to the work prefix before exact return
key switching. Legacy free CRT callers remain uncached behind legacy bootstrap
refusal. MainOnlyBaseExt's exact U1024 boundary comparison is internal to the
same evaluator, not a switch to an older FHE implementation.

The full workspace suite, full native refresh, dense/extreme K0 matrix, release
build, target timing and constant-time campaigns were not run. Dense K0 was not
repeated after reconstruction: the prior lost worktree's all-slots attempt hit
90 seconds and was never a pass. Unsupported-AVX execution needs another host.
Signed digit fixtures currently use secure_128; the wide-context fixture uses
the ten-anchor basis rather than the full 650-bit native chart. No new general
constant-time or production-security claim follows from these checks.

Next: integrate through the serialized owner, check changed-file interactions,
and complete the remaining bounded runtime coverage before any stronger claim.
No hosted CI, external review or deployment was launched by this work.
