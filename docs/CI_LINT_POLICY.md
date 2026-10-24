# CI lint policy

Clippy and formatting steps are active, unconditional gates in every workflow
that declares them. The primary `fast-gate` installs `clippy` and `rustfmt`,
runs `cargo fmt --all -- --check`, runs workspace Clippy with warnings denied,
and then performs dependency license/advisory checks.

Push, pull-request, and scheduled triggers are active again. Path-filtered
specialized workflows retain their original scopes, and manual dispatch remains
available. Builds, correctness tests, fuzzing, architecture checks, and
cryptographic admission remain enforced alongside linting.

A local Git commit does not run GitHub Actions. Workflow changes take effect
after the containing revision is pushed; old runs retain their original result.
This is repository-specific configuration, not a GitHub account-wide setting.

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
