# FPD and integer-division integration follow-up

PR #206 was merged into the activation branch. Integration commit `83f5355`
merges main `de4c3a8`, preserving the research-refresh/proof updates and the
architecture-meter feature while retaining the activated feature defaults.
README conflicts were resolved to distinguish typed integer division from the
legacy scalar component API. Historical manifests and raw results are unchanged.

## Division panic-policy correction

Hosted static analysis at `0740289` found three new `unwrap` sites and one
`expect` in the integer circuit evaluator. `5ede1648737b240bcfcaf311c02f07f9fbc83aec`
replaces them with typed `InternalCircuit` errors, including checked lookup of
live wires. The panic baseline is unchanged. All eight division regressions,
Clippy, formatting, 21 comparison-contract controls and the relevant claim,
refresh-status and route checks pass locally. The native shared-factor and
coefficient checks retain their original semantics and limits.

## Signature benchmark scheduling failure

At `5ede164`, hosted workspace tests pass. The subsequent release Clockwork
step reports 1,210 passes, 140 ignored tests and one failure:
`entropy::crt_shadow::tests::test_benchmark_signature_overhead`. Its single
100,000-operation timing pair measured 4.122373 ms without the signature and
8.447283 ms with it, exceeding the strict 100% overhead limit. The
[hosted log](https://github.com/Skyelabz210/NINE65_v7/actions/runs/41516571729/job/125522057763)
preserves that failure. No signature production code changed in this branch.

A fixed diagnostic schedule reproduced the problem: 20 serial invocations
passed, while 24 of 40 invocations with four processes pinned to one CPU failed.
Serial means no injected competitors; other host/build activity was not excluded.
The old test's millisecond-scale batches are vulnerable to asymmetric preemption
and discard their outputs without an optimization barrier.

Commit `e4b9168c6f485d7d949e121e22daf86becfe7708` changes only the test harness:

- Keep the test active and retain the strict `<100%` overhead limit.
- Consume opaque inputs and outputs through `black_box`.
- Warm both paths, alternate their measurement order, and take nine paired
  ratios with one million operations per batch.
- Check the median ratio, retaining every raw pair in the test output.
- Verify product/signature correctness before measuring, and add deterministic
  controls rejecting a sustained twofold slowdown and a majority of slow pairs.

The revised test passes the same 20 serial and 40 contended invocations. All
21 CRT-shadow module tests pass, as do Clippy and the integer-only/panic checks.
These runs validate the harness under the tested scheduling conditions; they
do not establish zero overhead, a constant-time property, or a new encrypted
division speedup. The follow-up hosted suite must be assessed at its own SHA.

The exact full release Clockwork command subsequently passes locally at
`6e8de9ba621bf347e9d39f1f0ceb1dddc4476892`: 1,212 passed, 140 ignored and
zero failures, in 300.90 seconds. This result precedes the worker-policy
correction below; it is not a latest-head rerun.

The [manifest and archived transcripts](../artifacts/execution/2026-11-02/fpd-integration-followup/manifest.json)
bind both source versions, the executed diagnostic driver, raw samples and
commands. The archived driver retains its original workspace paths; adjust
those paths when reproducing it in another checkout.

## Prepared-key sequential feature correction

The automated review found that prepared keys selected workers from ring size
and CPU availability without honoring `sequential`. A regression at N=1024
with four main lanes reproduces the issue on the baseline: four selected
workers where the feature requires one. Small-ring tests alone could not
detect it because they already select one worker.

Commit `bbcde3c17f6ec1c84507b67ca10ffa28edeac0ab` forces one worker both at key
preparation and at execution when `sequential` is enabled. Prepared-key
acceleration is retained. Three prepared-key tests pass in each of the default
and sequential builds, including exact coefficient equality against raw keys;
the existing opt-in N32768 timing test remains ignored. All eight division
regressions also pass using the sequential build, including native coefficient
checks. Clippy, formatting, CI-policy controls and the route denylist pass.

The required full CI job now explicitly runs the prepared-key tests with the
sequential feature. The [red/green evidence manifest](../artifacts/execution/2026-11-02/sequential-prepared-keys/manifest.json)
preserves commands, hashes and source scopes, including the earlier full-release
log. Hosted results must still be read at their own final head.

## Remaining capability boundary

The strict comparative scale sweep continues to fail on two unsupported legacy
`BFVEvaluator::mul` cases (#135). At `5ede164` its actual two-case matrix reports
zero wrong plaintexts, zero unexpected process failures, zero supported-operation
correctness failures and two completed depth chains. No capability gate is
relaxed. Typed encrypted integer division remains finite and noise-admitted;
native four-bit execution is demonstrated, unrestricted 64-bit execution is not.
