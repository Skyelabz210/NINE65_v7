# Safe Basis slow-fixture bound review

Prepared 2026-11-09 on main base `69e2e00e679d4e8604a22b53c99babce5ebba50c`.
The focused repair was checked with the repository-pinned Rust 1.89.0, including
the native encrypted fixture. Publication is for review; no merge is authorized.

## Scope

These four failures belong to the older test-only Safe Basis/sister-tray route.
They do not report a failure of `ops::public_refresh_circuit::PublicRefreshCircuit`.
The existing encrypted correction, message restoration and original-key return
are described in [current refresh status](../../PUBLIC_REFRESH_STATUS.md).
Legacy Clockwork remains disabled. This proposal does not close any joint-key
confidentiality, external-attestation, constant-time or production-admission gap.

The current-main November 8 [slow-tier job](https://github.com/Skyelabz210/NINE65_v7/actions/runs/42463759744/job/128678443683)
reports 1,218 passes, four failures and 132 ignored tests in its first stage.
The earlier scheduled-CI harness proposal is separate and is not changed here.

## One false rejection, three real resource refusals

`safe_basis_composition_tests::Noise::new_with_indexed_selector` multiplies its
projected-selector estimate by **16**, retaining a measured trace safety margin.
The resulting public bound is `65904671850496`; the five-prime half-scale is
`117984527272727065037126399264836478558604` (137 bits).

The older `safe_basis_pair_probe.py`, `safe_basis_three_pair_probe.py`,
`safe_basis_triple_precharge_probe.py` and `safe_basis_tray_transition_probe.py`
use the pre-margin estimate. Their successful budgets must not be interpreted
as current Rust admissions. Their historical evidence and raw logs are preserved.

A new [integer diagnostic](../../../scripts/safe_basis_current_bounds.py) applies
the current margin and records the following exact comparisons. Its
[source-pinned output](safe-basis-current-bounds.json) is a public planning model,
not an encrypted run, an independent proof of the noise model, or Rust refinement.
It refuses to report after a fingerprinted input changes until the model is
reviewed again.

| Fixture / stage | Current integer bound | Result |
| --- | --- | --- |
| Pair-precharge: six-term root modulo 3 | 143487364442685097949665097315220891543597 | Above half-scale; genuine refusal |
| Three-pair terminal carry at positive offset | 93745078102582398588188168775782131116281 | Below half-scale, despite also being 137 bits |
| Triple-precharge: first following square | 223202566911318450070487589240156854456321 | Above half-scale; genuine refusal |
| Sister tray: third compact proposal, modulo 21 | 120529386131860840228865404486405906096233 | Above half-scale; genuine refusal |

The pair fixture fails while constructing the *six-term* state, before reaching
its later four-term refresh assertions. The sister fixture's retained compact
layout already fails at 21, before choosing its extra composite target.

## Focused repair

The native three-pair test called `cube_error_bound`, which already admits the
bound through `Noise::admit`'s full-width comparison, then imposed a second,
stricter condition: `bits(bound) < bits(half)`. Equal bit lengths do not mean
that the bound is exhausted. The proposed change uses `words(bound) < words(half)`,
matching the existing exact gate.

The key-free Rust preflight gains explicit checks for the actual same-bit carry,
`half - 1` acceptance, and `half` / `half + 1` refusal. It executes no ciphertext
multiplications. No limit, prime, safety margin, source producer or cryptographic
implementation is changed. The other three failing fixtures are left failing;
there are no new skips and no workflow changes.

Possible follow-on work for the three real refusals requires a justified tighter
bound or a different encrypted construction, followed by native execution and
security screening. Removing the trace margin or adding the existing sixth
prime is not an acceptable shortcut: the existing six-prime profile explicitly
fails the dual security screen.

## Executed checks and remaining limits

After explicit approval, official Rust 1.89.0, rustfmt and clippy were installed
in an isolated workspace. The rustup installer checksum was verified against
its official download. [Raw logs and source hashes](safe-basis-evidence/manifest.json)
identify this run; the original missing-tool failures remain in the local review
record and were not converted into successful tests.

Passed locally on the repaired Rust source:

- Exact key-free preflight: **one passed**, none ignored. Carry bounds are
  `[137, 137, 136, 136]` bits, including the exact threshold controls.
- Exact ignored native fixture: **one passed**, none ignored, in **93.84 seconds**
  of test time. It performed **425,984 coefficient/error checks**, 146 carry
  selector products and four phase products. The repaired carry/readout/refresh
  assertions pass. Its following square is still refused before multiplication
  at 179 error bits versus the 137-bit half-scale.
- Related Safe Basis module: **25 passed, six existing ignores**. The native
  test above was separately selected with `--exact --ignored`.
- Both production-boundary regressions: **two exact tests passed**, preserving
  the legacy fail-closed behavior.
- `cargo fmt --all -- --check` and
  `cargo clippy --locked --workspace --all-targets -j2 -- -D warnings`.
- 44 Python regression tests: the ten new diagnostic regressions plus the
  research-runner, lift-refinement, real-evidence validator and architecture tests.
- Refresh-status routing and historical evidence checks, public-refresh security
  claims, claim registry, stale-claim scanner, both no-floats scans, production
  panic ratchet and `git diff --check`.

The 425,984 comparisons concern this one chosen research fixture, not that many
independent encrypted inputs, and not the different `PublicRefreshCircuit`
backend. The source-pinned Python report continues to say `native_tests_executed: 0`
because that script itself does not execute any Rust or ciphertext operations.

Remaining limits:

- The other three scheduled slow-fixture failures are unchanged and remain
  resource refusals under the current model. No full slow tier or full workspace
  test suite was rerun, and this is not a full-CI-green claim.
- Of ten proof-harness Python tests, two harness tests pass and eight fail/error
  because `lean` is absent. No Lean proof was checked in this environment.
- No new `PublicRefreshCircuit` native run or security/production admission is
  claimed. No workflow, legacy gate, prime environment or noise margin changed.
- Hosted CI and external review of the published commit are separate checks.
  Nothing was merged or deployed.

## Reproduction

Use the repository's pinned Rust 1.89.0. The two test commands below must each
report exactly one test executed. The second explicitly runs the otherwise
ignored native fixture.

```sh
cargo fmt --all -- --check
cargo test --locked --config profile.test.package.nine65.opt-level=2 -j2 \
  -p nine65 --features allow_insecure --lib -- \
  ops::expanded_bootstrap::safe_basis_composition_tests::pair_precharge::terminal::terminal_three_pair_carry_and_phase_bounds_preflight \
  --exact --test-threads=1 --nocapture
cargo test --locked --config profile.test.package.nine65.opt-level=2 -j2 \
  -p nine65 --features allow_insecure --lib -- \
  ops::expanded_bootstrap::safe_basis_composition_tests::pair_precharge::terminal::terminal_three_pair_native_carry_phase_and_sister_views \
  --exact --ignored --test-threads=1 --nocapture
```

If formatting changes a fingerprinted source, review it and update that one
fingerprint before rerunning the Python diagnostic and regressions. Record actual
native outcomes on the tested snapshot. Keep the three separate resource
refusals visible and do not claim full slow-tier green.
