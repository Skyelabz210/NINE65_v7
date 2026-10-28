# Public refresh: verified repairs and remaining admission gates

Baseline: `091c4ff` (2026-10-28). This checkpoint distinguishes regression
repairs from enabling public refresh. Issue #95 remains open. Issue #117 is
closed on GitHub; that closure does not establish a correct native refresh.

## Repairs

Two existing scale-Jacobian tests fail because a later diagnostic assumes
that its `p+1` sister modulus divides the Jacobian step. The narrow tuple
uses `L=4999*p`, with `p=65537`, so `L mod (p+1)=60539`. Its carry,
residual, and dependent-product checks precede this unrelated diagnostic.
The wider tuple deliberately includes the `p+1` factor. The checked
conversion now refuses the incompatible sister view, preserves the narrow
tuple's original checks, and continues checking the full diagnostic on
compatible wider tuples. Both formerly failing tests and the boundary and
wide-tuple controls pass. A refusal is not evidence for the missing view.

A third test incorrectly required Q241 to fail the old U256 rank-capacity
guard. The implementation already uses a U512 fallback. The native
Frobenius test now checks the actual certificate (283 auxiliary bits versus
262 required) and squares an encrypted source-derived polynomial at Q241.
All 16,384 coefficients agree with an independent schoolbook oracle. Its
original Q211 modulus-drop, nonlinear section, negative controls, and
repeat-preflight refusal remain checked. This supersedes the old capacity
refusal recorded in the October 23 Frobenius note.

A fourth stale assertion required the canonical decoder to reject the
composite target 22, although even coprime targets are now supported. The
2/11 cocycle regression now checks canonical rounding against an independent
integer oracle and checks the decrypted encrypted results with that decoder.
Its no-plaintext-root, carry, paired-coordinate, and dependent-square
assertions remain part of the test.

The complete small-ring public refresh, return, and repeat tests were
explicitly ignored and omitted by normal CI runs. A focused research job
runs the selected opt-in tests by exact name and rejects zero matching
tests. It separately checks native arithmetic capacity and that production
public refresh still refuses.
The existing forced native-refresh acceptance job remains in place; a
passing research job cannot satisfy its `real_refreshes > 0` requirement.

## Existing evidence reproduced on this checkout

- Compact encrypted selector checks pass.
- The dense-work/source pipeline switches to an independent sparse source,
  refreshes all 16 coefficients, returns to the original work key, reuses
  its evaluation keys for two dependent cycles, and performs a final square.
  This is an explicitly insecure N16/N32 research fixture.
- The full-polynomial N32 return pipeline also checks two dependent cycles.
- The native N8192 dense-to-sparse input transform preserves all 8192
  coefficients. Its subsequent clock geometry is checked by a client oracle;
  this test does **not** execute a native encrypted refresh.
- The Python parameter ledgers pass their focused tests. Passing a ledger
  does not certify a ciphertext history or admit the construction.

## What still blocks public refresh

1. **A practical native encrypted carry producer.** The complete packed
   pipeline counts 444,703,747 raw switches per refresh. The batched chart
   research has not supplied the low-noise common-T signed lift needed to
   replace that circuit. Correctly decoding a carry without a useful output
   noise bound does not close this requirement.
2. **Authenticated production integration.** Source key, modulus, scale,
   epoch, history, and noise bounds must be tied to the intact S8/Root211
   authority and dependent sister views. Caller-supplied research bounds
   are not production certificates.
3. **Security evidence for the actual publication.** The H96/Q60 source
   assessment completed 24 configured searches, with a minimum reported
   cost of 161.34 bits. Missing attack-model coverage and joint/KDM
   assumptions for source, outer, and return keys remain separate gates.
   The newer public-cover selector distribution is a different candidate.
4. **Native repeated execution.** Every coefficient must survive refresh,
   return to the work key, a useful multiplication, and another refresh
   under producer bounds, with measured resources and passing hosted gates.

The production `public_phase1_soundness_gate` remains closed. No native
public-refresh, production-security, or release-completion claim follows
from these repairs.

## Reproduction

With the pinned Rust 1.89.0 toolchain on `PATH`, run:

```sh
python3 scripts/run_public_refresh_research_gates.py --suite production-boundary
python3 scripts/run_public_refresh_research_gates.py --suite research
python3 scripts/run_public_refresh_research_gates.py --suite native-arithmetic
PYTHONPATH=scripts python3 -m unittest -v test_run_public_refresh_research_gates test_public_refresh_architecture test_compact_phase_clock_budget test_outer_ring_return_budget test_source_encapsulation_budget
```

The Rust runner requires one executed passing test for each exact name,
including explicitly selected ignored probes. It preserves each command's
output under `work/public-refresh-gates` and fails on an absent test,
ignored-only result, test failure, or timeout. The native arithmetic suite
tests an individual construction; it is not a native refresh cycle.

## Validation result

- The focused runner passes all 10 selected Rust tests: two production
  refusal tests, seven research tests, and one native arithmetic test.
- All 42 non-ignored tests in `coefficient_slot_gate` pass. The target still
  has 19 ignored tests; three are separately selected by the focused runner.
- All 32 Python runner and parameter-ledger checks pass.
- Targeted Clippy with `-D warnings`, formatting of the changed Rust files,
  the benches/tests no-floats gate, workflow validation, and diff checks pass.

These are local targeted results. A full workspace sweep and hosted CI were
not run. The unchanged forced-real-refresh job still requires an actual
native automatic refresh and is not satisfied by the research results.

## Source map

- [Source encapsulation and complete small-ring pipeline](../2026-10-23/SPARSE_SOURCE_ENCAPSULATION.md)
- [Completed configured source assessment and circuit cost](../2026-10-23/SHARED_DIGIT_KERNEL_AND_SOURCE_ASSESSMENT.md)
- [Batched lift and remaining signed-lift construction](../2026-10-24/PLAN.md)
- [Alternative live-source selector experiment](../2026-10-25/PHASE_CLOCK_LIVE_SOURCE_EVIDENCE.md)

Document dates alone do not order these results: several October 23 pages
contain later follow-ups. Use their linked implementation and evidence.
