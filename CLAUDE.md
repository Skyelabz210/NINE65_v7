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

## Build and features

Use the pinned Rust toolchain and the commands in [README.md](README.md).
The `nine65` default features are `exact_transcendentals_backend` and
`accelerated`; the latter enables MANA and UNHAL. Rayon remains opt-in.
`ntt_fft` is a compatibility alias; `reference_ntt` selects the reference path.
Read `crates/nine65/Cargo.toml` for the current feature graph.
`allow_insecure` enables unadmitted research in development/test builds;
release library/example builds reject it.

Run tests with `--no-fail-fast` to collect later targets after a failure.
Ignored/feature-gated tests and excluded binding crates require separate runs.
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
