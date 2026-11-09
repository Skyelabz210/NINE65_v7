# Repository context and conventions

Read [AGENTS.md](AGENTS.md), [README.md](README.md) and
[current public-refresh status and notation](docs/PUBLIC_REFRESH_STATUS.md).
The earlier context is [archived](archive/hygiene/2026-11-04/CLAUDE.md);
its test counts, timing tables, deployment status and work lists are historical.

## Coding rules

- Keep cryptographic arithmetic integer-only. `compiler.rs` is a static,
  heuristic planning tool with floating-point estimates, not an encrypted run.
  Timing statistics and diagnostic harnesses have separate scopes.
- Preserve typed refusal at unsupported parameter, division and refresh boundaries.
- Use OS CSPRNG-backed `SecureRng` for security-critical randomness.
  `ShadowHarvester` is for deterministic tests and reviewed non-secret streams.
- Preserve secret zeroization and constant-time-oriented primitives. Source
  structure alone does not establish target-specific side-channel resistance.
- Reconstruction is permitted under declared operation semantics. Garner and
  mixed-radix synthetic emissions remain prohibited in residue computation.
- Do not reset a noise counter and describe it as a ciphertext refresh.
- Do not enable legacy public bootstrap gates based on the separate research
  backend, headroom screens, or canonical plaintext-root preservation.
- Preserve frozen logs, manifests and hashes. Record the actual executed test,
  exact source commit, parameters and limitations for new evidence.

## Verification workflow

Install missing required tooling from its official source at the pinned version
before running the relevant step; a missing executable is not a reason to defer
verification. Use isolated tool/cache paths in managed environments. Record
actual installation or network failures and try the supported installation route.

For proof gaps, first reuse existing library results, then write explicit
assumptions, derivations, intuition, boundary checks and a second review pass.
Use the [written proof coverage map](docs/proofs/README.md). New hand-derived
arguments remain distinct from machine-checked results; existing proof gates
stay enforced. Do not fabricate closure of open cryptographic assumptions.

## Build and features

Use the pinned Rust toolchain and the commands in [README.md](README.md).
The `nine65` default features include `exact_transcendentals_backend`,
`accelerated`, `exact_rational`, `clockwork` and `adaptive-threading`;
`accelerated` enables MANA and UNHAL. Rayon remains opt-in.
`ntt_fft` is a compatibility alias; `reference_ntt` selects the reference path.
Read `crates/nine65/Cargo.toml` for the current feature graph.
`allow_insecure` enables unadmitted research in development/test builds;
release library/example builds reject it.

Run tests with `--no-fail-fast` to collect later targets after a failure.
Ignored/feature-gated tests and excluded binding crates require separate runs.
The required workspace suite uses the CI test profile in README. A whole
workspace release test sweep also discovers toy `coefficient_slot_gate` setups
that the release library correctly refuses; keep the production parameter floor
and use the documented development-test mode for those experiments.
Do not copy old test counts or benchmark values into current capability claims.
Use [CI lint policy](docs/CI_LINT_POLICY.md) and exact hosted run results.

## Authority and navigation

Current executable source and evidence for the exact commit take precedence
over historical plans. Read the [architecture map](docs/ARCHITECTURE.md),
[security mode matrix](docs/SECURITY_MODE_MATRIX.md),
[CRAM contract](docs/CRAM_INTEGRATION_CONTRACT.md) and
[claim ledger](docs/CLAIM_EVIDENCE_LEDGER.md).
The maintained formalization is Lean; legacy Coq exploration is not the
verification basis. No general constant-time, unlimited-depth or production
security claim is established.
