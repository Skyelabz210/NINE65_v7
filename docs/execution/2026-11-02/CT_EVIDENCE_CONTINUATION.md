# Hosted follow-up and three-valued timing evidence

At `a186dd8cf71b91f852732dacba192a568509abe6`, 13 of the 14 associated
PR workflows pass. This confirms the smoke-validator and current-modulus-ledger
repairs in hosted execution. Full CI, exactness, recumbency, audit remediation,
public-refresh research, Lean, application, fuzz and residue-native workflows
are successful. Optional scheduled/dispatched jobs retain their own skipped
states; a successful workflow does not mean every optional job ran.

The strict scale sweep is the remaining red workflow. Its actual two-case
matrix reports zero wrong plaintexts, zero supported-operation correctness
failures, zero unexpected process failures, two completed depth chains and
two expected unsupported legacy multiplication operations. The diagnostic
repair holds; complete capability coverage remains unsupported. This work
does not relax the strict sweep to manufacture a green result.

## Timing job success versus measurement evidence

The [hosted timing job](https://github.com/Skyelabz210/NINE65_v7/actions/runs/41353893978/job/124989710783)
is successful, but its ten exact tests produce eleven observable reports:
eight below threshold at this sample size and three inconclusive. One exact
test measures both U512 reduction and the full rescale, so test and observable
counts differ.

| Observable | Control t | Signal t | Verdict |
| --- | --- | --- | --- |
| Montgomery exponent Hamming weight | 6.3406 | 2.0117 | Inconclusive |
| Montgomery reduction operand magnitude | 6.3649 | 4.0619 | Inconclusive |
| Montgomery multiplication operand magnitude | 4.8804 | 4.1648 | Below threshold at this sample size |
| Barrett reduction operand magnitude | 11.2538 | 12.2974 | Inconclusive |

The original main-branch Montgomery multiplication signal (control 1.4003,
signal 8.6550) remains open. Its archived job contains ten below-threshold
observables and one measured dependence. A subsequent below-threshold result
does not resolve the earlier signal. No arithmetic kernel, threshold, cropping,
sample schedule or Rust timing assertion is changed in this continuation.

## Collector and workflow change

At `b31f3fe`, `scripts/summarize_ct_verdicts.py` produces JSON and Markdown
with separate `below_threshold`, `inconclusive`, `timing_dependence` and invalid
collection states. `constant_time_established` is always false. It preserves
the existing nonblocking policy for inconclusive measurements while keeping
them out of the below-threshold count.

The workflow now captures a separate log and both Cargo/tee process statuses
for each selected test. It still executes all ten after an earlier failure,
keeps the aggregate log, and publishes a summary even after a build/run failure.
The summary fails on missing invocations, zero matching tests, missing reports,
unexpected crashes, capture failures or measured dependence. Successful
collection checks the exact named test and one actually executed, non-ignored
Rust test per invocation. It expects two observable reports for the compound
rescale test. Source and actual checkout SHAs, raw-log hashes, runner/compiler
metadata and compiled-function assembly remain available in the artifacts.

Statistics in the human transcript are rounded to four decimal places. The
collector preserves the Rust verdict instead of reclassifying a displayed
5.0000 that could represent a value immediately below the threshold. It is a
log consistency check, not an independent statistical test or authenticated
measurement attestation.

## Validation and reproducibility

Sixteen deterministic controls pass, including missing/zero tests, wrong exact
test names, crashes after a good verdict, capture failure, duplicate invocation,
incomplete compound reports and malformed statistics. Two controls execute the
actual workflow shell loop with **synthetic** transcripts and a stub Cargo:
one collects all ten tests/eleven observables; the other preserves an injected
exit 101/timing failure while collecting the remaining tests. These are capture
and classification controls, not cryptographic timing measurements.

The collector also replays both actual archived hosted jobs. The current job
classifies as **inconclusive** (8 below, 3 inconclusive); the original main job
classifies as **timing_dependence** (10 below, 1 measured dependence). Raw
timestamped logs are preserved. Replayed per-test logs remove only timestamp
prefixes and job-group wrappers. Since the old workflow did not archive a
process-status ledger, those replay ledgers infer Cargo outcomes from the
Rust test-result lines and mark that provenance explicitly. They are not new
executions or new independently recorded process exits.

```sh
python3 scripts/test_summarize_ct_verdicts.py
python3 scripts/summarize_ct_verdicts.py \
  --input-dir docs/execution/2026-11-02/ct-evidence/current \
  --output /tmp/ct-replay.json --markdown /tmp/ct-replay.md
```

The same command with `main-failure` must return 1 and retain the measured
dependence. Original hosted inventory, raw/replayed logs, controls, source
hashes and replay classifications are in the
[manifest](ct-evidence/manifest.json). The new collector is verified locally;
its controls also pass in
[hosted source/functional job125135590970](https://github.com/Skyelabz210/NINE65_v7/actions/runs/41401989840/job/125135590970)
at `b31f3fe`. The complete timing job for that snapshot is still in progress
when this evidence is recorded; no result is inferred from its controls. Native
arithmetic and its [previous acceptance](../2026-11-01/ASSESSMENT_REMEDIATION.md)
are unchanged. Joint-key confidentiality, independent parameter attestation
and production admission remain unestablished.
