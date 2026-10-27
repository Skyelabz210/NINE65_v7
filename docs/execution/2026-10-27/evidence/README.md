# Validation evidence

`validation.json` identifies the tested code commit, source hashes, commands,
results and limitations. Its compressed logs include failing-before arithmetic
regressions and the complete affected release-library result. The code commit
precedes this documentation-only evidence commit.

The arrow reports exercise the actual Rust coefficient API. The drop fixture
passes all finite gates. The full-basis rank fixture intentionally fails the
stronger joint-output-uniformity diagnostic while retaining correct arithmetic
and input recovery. This diagnostic is separate from IID driving digits and
Holte detailed balance.

`holte-python-results.json` and `centered-chart-results.json` record finite
exact-integer checks. The all-arity Holte argument is written in
[`HOLTE_REVERSIBILITY.md`](../HOLTE_REVERSIBILITY.md).

The three existing Garner architecture findings, six capacity-contract finding
classes, and four affected release-library failures remain visible. These
artifacts do not admit production refresh.

`review/` preserves the independent probes and their transcript-copied aggregate
results. Those records explicitly say they were captured from the completed
review rather than freshly rerun during archiving. They contain local execution
paths; reproduce them after adjusting those paths to the checkout location.
