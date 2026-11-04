# NINE65

NINE65 is a Rust research prototype for exact-integer BFV/DualRNS encrypted
computation and CRAM residue arithmetic. Public evaluation, trusted-key-holder
refresh, service and experimental bindings have different key boundaries;
see the [security mode matrix](docs/SECURITY_MODE_MATRIX.md).

## Current scope

- Finite-depth public addition and multiplication are implemented in `nine65`.
- The explicit `ops::public_refresh_circuit::PublicRefreshCircuit` research
  backend implements encrypted correction and original-key return. It requires
  `allow_insecure`; release library/example builds reject that feature.
- Legacy/default `ClockworkBootstrap` public refresh remains disabled on all
  named profiles. Its refusal does not describe the separate research backend.
- Related-key confidentiality, external parameter attestation, a probabilistic
  decryption-failure bound and research refresh constant-time posture remain
  unestablished. There is no production-readiness or unlimited-depth claim.
- `secure_128` and `secure_128_deep` currently use the same tuple. `secure_256`
  is an API label: its in-tree MATZOV screen is 240 bits, not certified 256-bit
  security. All named-security values require independent exact-tuple evidence.

Read [current public-refresh status and notation](docs/PUBLIC_REFRESH_STATUS.md)
and the [security pack](docs/security/README.md) before interpreting old reports.
The status guide scopes legacy `K_0`, native `K_native`, residual `rho` and
adjacent `kappa` to their actual producers and equations.

## Evidence and limits

The archived native research run checked five refreshes and five following
squares: 81,920 coefficient comparisons. It took 56.6 minutes including setup
and 8.70 GiB peak RSS. This was an identified older snapshot, not a latest-head
rerun. Later single-cycle, memory and phase-error witnesses have their own
source commits in the [status guide](docs/PUBLIC_REFRESH_STATUS.md).
The documented return certificate is 562 error bits below a 633-bit threshold;
this deterministic certificate is not a probabilistic failure bound or a
confidentiality proof.

Historical named-profile depth and timing measurements are retained in the
[claim-surface record](docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md) and
[archived README](archive/hygiene/2026-11-04/ROOT_README.md).
They are not fresh benchmarks of this checkout. Compare exact tuples, features,
commits and machines rather than profile names across revisions.

Claims are indexed in `docs/CLAIM_REGISTRY.csv`, interpreted by the
[claim evidence ledger](docs/CLAIM_EVIDENCE_LEDGER.md), and governed by
`docs/BENCHMARK_PROFILE_POLICY.md`. Registry classification is not security
certification. The [hygiene record](docs/maintenance/HYGIENE_2026-11-04.md)
states what was checked and what could not be rerun.

## Build and verification

Install the Rust toolchain pinned in `rust-toolchain.toml` (1.89.0).
Run from the repository root:

```bash
cargo build --locked --release --workspace
cargo fmt --all -- --check
cargo test --locked --release --workspace --no-fail-fast
```

The workspace excludes the Python, WASM and FFI bindings and `fuzz`;
those need separate builds. Feature-gated and ignored tests are not covered by
the default workspace command. Do not interpret a build or zero matching tests
as executed encrypted evidence.

Run the documentation and architecture gates:

```bash
bash scripts/check_claim_registry.sh
bash scripts/check_stale_claims.sh
python3 scripts/check_public_refresh_status.py
python3 scripts/check_public_refresh_security_claims.py
python3 scripts/check_residue_native_architecture.py
bash scripts/check_no_floats_runtime.sh
```

Lean is the formalization of record. With the pinned Lean toolchain installed:

```bash
python3 scripts/check_public_refresh_proofs.py
(cd lean4/KElimination && lake build && bash scripts/axiom_audit.sh)
```

Proof statements have their own assumptions and scope; they do not establish
Rust refinement or confidentiality of the full related-key setup. Legacy Coq
explorations are not the maintained verification basis.

## Public refresh status

Inspect the native plan and key inventory without generating keys:

```bash
cargo run --locked -p nine65 --features allow_insecure \
  --example public_refresh_circuit -- --describe
```

The expensive encrypted five-cycle example uses OS randomness and an optimized
**development** profile:

```bash
cargo run --locked --config profile.dev.package.nine65.opt-level=2 \
  -p nine65 --features allow_insecure --example public_refresh_circuit
```

This research run is resource intensive. Keep its correctness, resource cost,
root/provenance binding and production security as separate claims.

## Architecture and execution contract

See the [architecture map](docs/ARCHITECTURE.md),
[CRAM showcase](docs/CRAM_SHOWCASE.md), and
[CRAM integration contract](docs/CRAM_INTEGRATION_CONTRACT.md).
Reconstruction is permitted under the declared operation contract;
Garner/mixed-radix synthetic emissions, prohibited information loss and
floating-point residue computation remain forbidden. K-Elimination requires
its divisibility, coprimality, anchor-capacity and uniqueness-range conditions.
The general shared-factor encrypted division adapter is not enabled.

The [FPD feature branch](https://github.com/Skyelabz210/NINE65_v7/pull/204)
has separate prepared-key/default-feature work; a branch result is not evidence
that its defaults are integrated in this checkout.

## Contributing and security

Use [CONTRIBUTING.md](CONTRIBUTING.md) for development checks,
[AGENTS.md](AGENTS.md) and [CLAUDE.md](CLAUDE.md) for repository conventions,
and [SECURITY.md](SECURITY.md) for security policy and reporting.
Hosted workflows are active; consult runs for the exact commit and workflow.
No repository-wide green CI claim follows from a passing specialized job.

## License

See [LICENSE](LICENSE) for the current grant. GitHub visibility and the license
grant are separate; public visibility alone does not grant reuse rights.
