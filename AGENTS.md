# AGENTS.md — Repository Guidelines and AI Roster

## AI Roster and Division of Labor

This project uses a multi-agent pipeline with clearly scoped roles.
Each agent operates within its lane. Do not reassign tasks across lanes without updating this file.

### Jules (google-labs-jules[bot])
**Role:** Deep autonomous engineering  
**Invocation:** Assign a GitHub Issue with a well-scoped problem description  
**Scope:** Multi-file architectural work, security hardening, correctness fixes,
  formal proof alignment, large refactors. Jules reads the entire codebase,
  reasons across files, and delivers production-ready commits autonomously.  
**CI behavior:** BYPASSES all CI tiers. Jules validates its own work internally.
  Its commits will not trigger Actions runs — this is intentional and saves minutes.  
**Do not use for:** Routine lint fixes, small single-file changes, documentation edits.
  Jules' talent is wasted on work that takes a human 5 minutes.

### Gemini Flash (Google AI Studio — free tier)
**Role:** PR code review  
**Invocation:** Automatic on every non-bot pull request (T3 CI tier)  
**Scope:** Structured diff review covering security, correctness, performance,
  and proof alignment. Posts results as a PR comment.  
**Requires secret:** GEMINI_API_KEY (repo secret, Settings → Secrets)  
**Cost:** Zero Actions minutes. One HTTP call per PR.

### Qwen Coder Cloud (Alibaba DashScope, npm deployment)
**Role:** Claim registry semantic audit, math-hole detection  
**Invocation:** Automatic on Sunday schedule or [deep-ci] tag (T4 CI tier)  
**Scope:** Cross-references the claim registry against source code for semantic
  consistency. Flags stale claims, unproven security assertions, and missing
  coverage for significant features. Ideal for NINE65 formal claim validation
  given its strength in mathematical reasoning and code analysis.  
**Requires secret:** QWEN_API_KEY (repo secret, Settings → Secrets)  
**Model:** qwen-coder-plus via DashScope compatible API

### Qwen Coder Local (Ollama)
**Role:** Pre-commit fast checks, local development  
**Invocation:** Developer machine only — never appears in CI  
**Scope:** Fast local pattern scanning, format suggestions, quick analysis
  before pushing. Zero latency, zero cost, no network round-trip.

### @claude (Anthropic Claude)
**Role:** Orchestration, quality assurance, deep targeted analysis  
**Invocation:** Mention @claude in a PR comment or issue  
**Scope:** Cross-cutting concerns, resolving conflicts between agents,
  quality gate enforcement, architecture decisions, debugging complex
  interactions between modules. Use when you need reasoning that spans
  the full system context — FHE math, Rust safety, CI, deployment, proofs.  
**Not in hot-path:** Claude is not automated in CI loops. Invoked on-demand
  so it can do real work rather than rubber-stamping routine checks.

### Codex
**Role:** Advanced math verification, proof-hole detection  
**Invocation:** On-demand  
**Scope:** Checking advanced mathematical claims, finding logical holes in
  formal proofs, verifying arithmetic correctness in RNS/NTT/Montgomery
  implementations. The go-to for "does this math actually hold?" questions.

---

## CI Tier Reference

| Tag in commit message | Effect |
|---|---|
| _(no tag, push to develop)_ | T1 only: fmt + clippy + deny + static analysis |
| _(pull request)_ | T1 + T3: fast gate + Gemini AI review |
| _(merge to main)_ | T1 + T2: fast gate + full test suite |
| `[full-ci]` | T1 + T2: forces full test suite on any branch |
| `[deep-ci]` | T1 + T4: forces benchmarks + coverage + Qwen audit |
| `[timing]` | T4 timing tests only |
| _(Sunday 2AM UTC)_ | T4: full deep analysis suite |
| workflow_dispatch | Manual: choose tier via input |

Jules and Dependabot commits skip all tiers regardless of tags.

---

## Project Structure and Module Organization

This workspace is Rust-first and organized under `crates/*`:

- `crates/nine65` — core FHE engine (arithmetic, ops, params, keys, noise, security)
- `crates/mana`, `crates/unhal` — acceleration and hardware abstraction
- `crates/clockwork-core`, `crates/nexgen_rational` — supporting math/runtime primitives
- `crates/nine65-python`, `crates/nine65-wasm` — optional bindings

Formal artifacts live in `proofs/coq/` and `lean4/KElimination/`.  
Integration/property tests are in `crates/nine65/tests/` and `random_encrypt_proptest.rs`.  
Operational docs are in `docs/`; historical reports are under `archive/`.

---

## Build, Test, and Development Commands

Use release mode for meaningful results:

```
cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm
cargo test --release --exclude nine65-python --exclude nine65-wasm
cargo test -p nine65 --lib --release
cargo test -p nine65-python --features python --release
cargo test -p nine65-wasm --target wasm32-unknown-unknown --release
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
```

---

## Coding Style and Naming Conventions

- Idiomatic Rust: `snake_case` for files/functions/modules; `CamelCase` for types/traits
- Keep modules focused by domain (e.g. `ops/rns_fhe.rs`, `params/secure_configs.rs`)
- Prefer explicit error types (`thiserror`) over panic-based control flow
- **Runtime cryptographic code is integer-only — no `f32`/`f64` in runtime paths**
  - Exception: `crates/nine65/src/compiler.rs` uses `f64` for offline static noise analysis
- Constant-time operations required for all security-sensitive code paths

---

## Testing Guidelines

- Unit tests next to code (`mod tests`) and cross-module behavior in `crates/nine65/tests/`
- Descriptive test names: `test_mul_dual_public_depth3_chain`
- When touching crypto logic, run at minimum:
  `cargo test -p nine65 --lib --release`
- Relevant crate tests: mana, clockwork-core, nexgen_rational, unhal
- Proof/tooling checks if algorithm semantics change:
  `cd lean4/KElimination && lake build`

---

## Commit and Pull Request Guidelines

- Conventional Commit prefixes: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `audit:`
- Keep commits scoped to one concern
- Include evidence updates when claims change (tests, benchmarks, or security notes)
- PRs should include: clear summary, impacted crates/files, exact validation commands run,
  updated docs for any behavior/security/performance changes

---

## Secrets Required for Full Pipeline

| Secret name | Used by | Purpose |
|---|---|---|
| `GEMINI_API_KEY` | T3 AI review | Gemini 2.0 Flash PR review comments |
| `QWEN_API_KEY` | T4 claim audit | Qwen Coder Plus DashScope API |

Add secrets at: Settings → Secrets and variables → Actions → New repository secret
