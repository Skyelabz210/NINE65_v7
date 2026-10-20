# CI lint policy

Clippy and formatting steps are disabled by default across every workflow in
this repository. Each such step runs only when the GitHub Actions repository
variable `ENABLE_LINT` is exactly `true`. An absent variable, `false`, or any
other value skips linting. To keep lint off, leave the variable unset.

The `fast-gate` job still runs dependency license/advisory checks. Its job ID
and display name are retained for existing check references, and `full-test`
still depends on it. Skipping a lint step does not skip the full test suite.
Builds, correctness tests, fuzzing, architecture checks, and cryptographic
admission remain enforced whenever their workflow runs.

The existing manual-only workflow triggers (the CI cost pause) are unchanged.
A local Git commit does not run GitHub Actions. The workflow change takes
effect on GitHub after the containing branch is pushed and that revision runs;
old red runs keep their original result. Other repositories need the same
workflow configuration; this file does not change a GitHub account-wide setting.

## Observed CI failure

The latest primary CI run inspected on 2026-10-19 was
[39009441823](https://github.com/Skyelabz210/NINE65_v7/actions/runs/39009441823),
for `6507e8081b10710855723f6f7311e0e48f4678b0`, not the local transport commit.
Formatting, Clippy, dependency checks, and static analysis passed. The full
`nine65 --lib` suite reported 944 passed, 7 failed, and 125 ignored:

- Four automatic-refresh tests hit the public Phase 1 refusal because the
  secret-dependent displaced quotient/carry transition is not implemented.
- The `secure_128` symmetric depth test returned 56106 instead of 65536 at
  depth 4; `secure_192` returned 0 instead of 65536 at depth 4.
- The zero-noise repeated-square diagnostic also failed its exactness controls.

Disabling style/lint checks cannot repair those arithmetic/refresh failures.
The tested main-Q scalar HTTP route is narrower than these failing legacy
paths. Do not present its successful round trip as a passing full FHE suite.
