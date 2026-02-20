# Repository Guidelines

## Project Structure & Module Organization
This workspace is Rust-first and organized under `crates/*`:
- `crates/nine65`: core FHE engine (arithmetic, ops, params, keys, noise, security).
- `crates/mana`, `crates/unhal`: acceleration and hardware abstraction.
- `crates/clockwork-core`, `crates/nexgen_rational`: supporting math/runtime primitives.
- `crates/nine65-python`, `crates/nine65-wasm`: optional bindings.

Formal artifacts live in `proofs/coq/` and `lean4/KElimination/`.  
Integration/property tests are in `crates/nine65/tests/` and `random_encrypt_proptest.rs`.  
Operational docs are in `docs/`; historical reports are under `archive/`.

## Build, Test, and Development Commands
Use release mode for meaningful results:
- `cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm`  
  Builds core/support crates without optional binding toolchains.
- `cargo test --release --exclude nine65-python --exclude nine65-wasm`  
  Runs default workspace validation.
- `cargo test -p nine65 --lib --release`  
  Core FHE verification (fastest gate for main code changes).
- `cargo test -p nine65-python --features python --release`  
  Python binding checks (requires PyO3 toolchain).
- `cargo test -p nine65-wasm --target wasm32-unknown-unknown --release`  
  WASM binding checks.
- `cargo fmt --all -- --check` and `cargo clippy --workspace -- -D warnings`.

## Coding Style & Naming Conventions
Follow idiomatic Rust:
- `snake_case` for files/functions/modules; `CamelCase` for types/traits.
- Keep modules focused by domain (for example `ops/rns_fhe.rs`, `params/secure_configs.rs`).
- Prefer explicit error types (`thiserror`) over panic-based control flow.

Runtime cryptographic code is integer-only; avoid `f32`/`f64` in runtime paths.  
Exception: `crates/nine65/src/compiler.rs` uses `f64` for offline static noise analysis.

## Testing Guidelines
Place unit tests next to code (`mod tests`) and cross-module behavior in `crates/nine65/tests/`.  
Use descriptive test names (`test_mul_dual_public_depth3_chain`).  
When touching crypto logic, run at least:
1. `cargo test -p nine65 --lib --release`
2. Relevant crate tests (`mana`, `clockwork-core`, `nexgen_rational`, `unhal`)
3. Proof/tooling checks if algorithm semantics change (`cd lean4/KElimination && lake build`).

## Commit & Pull Request Guidelines
Commit style follows Conventional Commit prefixes seen in history:
`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `audit:`.  
Keep commits scoped to one concern and include evidence updates when claims change (tests, benchmarks, or security notes).

PRs should include:
- clear summary and impacted crates/files,
- exact validation commands run,
- updated docs for any behavior/security/performance changes.
