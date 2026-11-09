# Contributing to NINE65

NINE65 is an exact-integer BFV/DualRNS research prototype. Start with
[README.md](README.md), [repository conventions](CLAUDE.md) and
[current refresh status](docs/PUBLIC_REFRESH_STATUS.md).
It does not claim unlimited depth or production security.

Use Rust 1.89.0 as pinned in `rust-toolchain.toml`. Lean tooling is needed only
for formal proof work; use `lean4/KElimination/lean-toolchain`. Legacy Coq
experiments are not the maintained proof basis.

## Changes and validation

Keep changes scoped and explain the affected API, behavior and assumptions.
For code changes, run the relevant tests plus formatting and lint checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace -- -D warnings
bash scripts/run_tests_medium.sh
```

For documentation and claim changes, run the claim/status checks listed in
[README.md](README.md). Record missing tooling, failing checks, ignored tests
and unexecuted resource-intensive targets explicitly. Workspace tests do not
include excluded bindings or every feature-gated integration test.

Keep crypto/residue computation integer-only, unsupported operations fail-closed,
secret material zeroized and production randomness CSPRNG-backed. Follow the
[CRAM integration contract](docs/CRAM_INTEGRATION_CONTRACT.md) and identify the
[security mode](docs/SECURITY_MODE_MATRIX.md) affected by each change.

## Evidence and reporting

Name the exact source commit, tuple, command, tested domain and raw artifact
for new measurements. Preserve historical evidence and distinguish functional
correctness, performance, proof scope, confidentiality and side-channel posture.
Do not cite a heuristic planner or noise-counter reset as encrypted execution.
Report vulnerabilities according to [SECURITY.md](SECURITY.md).

## License

The repository [LICENSE](LICENSE) defines the current grant. This guide does
not impose a separate copyright assignment or invent additional permissions.
The superseded contribution guide is [archived](archive/hygiene/2026-11-04/CONTRIBUTING.md).
