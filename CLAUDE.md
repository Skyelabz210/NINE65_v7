# CLAUDE.md — Project Context for Claude Code

## Project Overview
**NINE65 v8 "Shadow Butterfly"** — A proprietary exact-integer BFV/DualRNS FHE substrate built on the QMNF (Quantized Modular Number Field) architecture. Written entirely in Rust with zero floating-point arithmetic in its crypto/arithmetic hot paths (see "Important Coding Rules" below for the one documented, non-cryptographic exception).

It provides finite leveled computation plus low-depth refresh paths. **It is not an unlimited-depth system and does not claim to be** — `docs/LINEAGE.md` places "unlimited depth", "depth 50" and "bootstrap-free" on the deprecation list, and the measured public direct-square depths are 2–4. The verified capability table is in `README.md`; per-number provenance and the not-established list are in `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md`.

---

## Cloud Run Deployment
- **Platform:** Google Cloud Run
- **Service name:** nine65-v7
- **Region:** us-south1 (Dallas)
- **Project:** astro-resonance
- **URL:** https://nine65-v7-517338038154.us-south1.run.app (Disabled — billing paused)
- **Deploy method:** Push to main branch triggers Cloud Build auto-build and deploy
- **Container port:** 8080

---

## Repository Structure
NINE65_v7/
├── crates/
│   ├── nine65/              # Core FHE library (689+ tests)
│   │   └── src/
│   │       ├── arithmetic/  # RNS, K-Elimination, NTT, Montgomery
│   │       ├── ops/
│   │       │   ├── rns_fhe.rs        # BFV ops (encrypt, mul, decrypt)
│   │       │   ├── bootstrap.rs      # Clockwork Bootstrap (3 paths)
│   │       │   ├── auto_bootstrap.rs # AutoBootstrapEvaluator
│   │       │   └── gso_fhe.rs        # GSO depth management
│   │       ├── entropy/     # CRT Shadow + CSPRNG
│   │       ├── security/    # CT primitives, GRO gates
│   │       ├── keys/        # Key generation (BSK, KSK, eval keys)
│   │       ├── noise/       # Noise budget tracking (millibits)
│   │       └── params/      # Secure configs + security estimator
│   ├── clockwork-core/      # Formal-spec RNS (Garner, GRO, bounds)
│   ├── exact_transcendentals/ # Exact CORDIC transcendentals
│   ├── nexgen_rational/     # Exact i128 rational arithmetic
│   ├── fhe-service/         # Session management
│   ├── mana/                # FHE stream accelerator (lane-parallel pipeline; Rayon opt-in)
│   └── unhal/               # Hardware abstraction layer
├── proofs/coq/              # 14 machine-checked Coq proofs
├── lean4/KElimination/      # 4 Lean4 formalizations
├── scripts/                 # Quality gates
└── docs/                    # Security proofs, benchmarks, compliance

---

## Build & Test Commands

Build all crates (release):
  cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm

Run all tests:
  cargo test --release --workspace --exclude nine65-python --exclude nine65-wasm

Core FHE tests only:
  cargo test -p nine65 --lib --release

Bootstrap-specific tests:
  cargo test -p nine65 --lib --release -- bootstrap
  cargo test -p nine65 --test bootstrap_integration --release --features allow_insecure
  cargo test -p nine65 --test bootstrap_parameter_exploration --release --features allow_insecure

(Standalone `-p nine65` runs of integration-test and bench targets need
`--features allow_insecure`: those targets link the library without cfg(test),
so the release-mode secure-RNG gate would otherwise reject their seeded
ShadowHarvester. The workspace-wide command above needs nothing extra. Each
affected target declares this via required-features in crates/nine65/Cargo.toml.)

Security tests:
  cargo test -p nine65 security::tests -- --nocapture

Depth benchmarks:
  cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 -- --nocapture

---

## Bootstrap Paths
All three are **public** refresh paths (evaluator-side, public bootstrap key
material only). None of their roundtrip tests currently runs: the suites in
`ops/bootstrap.rs`, `tests/bootstrap_integration.rs`,
`tests/bootstrap_parameter_exploration.rs` and
`tests/bootstrap_residue_shape_regression.rs` are `#[ignore]`d as
VESTIGIAL/RETIRED, so "verified exact" cannot be sourced to the running suite.

- Circular: `bootstrap()` — boot_sk = lift(work_sk)
- Non-Circular (KSK): `bootstrap_with_ksk()` — independent boot_sk, gadget key switch
- Auto-Bootstrap: `AutoBootstrapEvaluator::mul_auto()` — auto trigger on noise threshold

**Admissibility gate.** All three refuse configs whose main chain cannot carry a
public refresh, via `params::secure_configs::ensure_public_refresh_supported`
(typed `Nine65Error::BootstrapConfigMismatch`, never a panic). `secure_128` and
`hardware_opt` (3 lanes) are refused: 42 bits of post-refresh `Delta` headroom
against the 47 one multiply needs. Measured by
`ops::bootstrap::tests::diag_measure_noise_growth`, the refresh output still
decrypts correctly, but the first multiply after it returns a
wrong-but-plausible plaintext (`refresh(7)` squares to `34037`, not `49`) with
no error raised anywhere in the pipeline. `secure_128_deep`, `secure_192` and `secure_256`
(4/5/6 lanes) are admitted. The symmetric secret-key refresh
(`SymmetricBootstrap::bootstrap`) is a separate path and is not gated by this.

## Security Configs
Screened 2026-08-22 by `params::secure_configs::tests::screened_levels_for_named_configs`
against the tuples actually in `secure_configs.rs`. `log2(q)` is the exact bit
length of the prime product.

| constructor | n | lanes | log2(q) | claimed | Core-SVP | MATZOV | binding | public refresh |
|---|---|---|---|---|---|---|---|---|
| `secure_128()` | 8192 | 3 | 90 | 128 | 259 | 233 | 233 | refused |
| `secure_128_deep()` | 8192 | 4 | 119 | 128 | 196 | 176 | 176 | yes |
| `secure_192()` | 16384 | 5 | 146 | 192 | 320 | 288 | 288 | yes |
| `secure_256()` | 16384 | 6 | 175 | 256 | 267 | **240** | **240** | yes |
| `hardware_opt()` | 8192 | 3 | 90 | 128 | 259 | 233 | 233 | refused |

Every name clears its own number under Core-SVP, the model `new_verified` gates
on. `secure_256` falls 16 bits short under MATZOV; that gap is documented on the
constructor and readable via `SecureConfig::screened_security_dual()`. No config
is renamed.

Two stale figures to stop quoting:

- The previous table here (secure_128 129/86/129, secure_192 374/213/318,
  secure_256 311/177/264) came from `docs/LATTICE_ESTIMATOR_BASELINE_2026-02-25.md`.
  Its `secure_128` row was computed at **n=4096**, not the shipped 8192. Its
  192/256 rows used the `security_estimator_baseline` binary's floor-sum
  `log2(q)` (147/177) rather than the exact product bit length the constructor
  gates on (146/175) — a conservative over-estimate of `q`, hence the slightly
  lower bits.
- "secure_256 screens at ~227 bits" describes the **superseded** chain at
  `log2(q)=203`, replaced 2026-02-25. It does not describe the current 175-bit
  chain.

These are screening numbers from a deterministic integer heuristic, not
independent lattice-security certificates. `secure_configs.rs`'s own policy — an
archived external estimator run for the exact shipped tuple — remains unmet for
n=8192/16384. See `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md`.

---

## Important Coding Rules
- ZERO floats in crypto/arithmetic hot paths — no f32/f64 in K-Elimination, Montgomery, NTT, RNS, or any encrypt/decrypt/eval code path, ever. (`compiler.rs::NoiseModel` is a planning-only noise estimator with `pub f64` fields — it never touches ciphertext coefficients — and is the one documented exception; do not extend float usage beyond it.)
- Integer-only arithmetic throughout (K-Elimination, Montgomery, NTT)
- Constant-time operations required for all security-sensitive code paths
- Test configs (allow_insecure) are blocked in release builds — never use in production
- Deterministic execution — bit-identical results across all platforms required
- All bootstrap paths must produce exact plaintext recovery

## Feature Flags
- ntt_fft (default): FFT-based NTT
- parallel: Opt-in Rayon parallelism (MANA is the canonical accelerator)
- clockwork: GRO timing gates, bound tracking, key lifecycle, integrity
- exact_rational: NexGen rational bridge (exact noise, BFV delta)
- shadow-entropy: CRT shadow entropy harvester
- adaptive-threading: Entropy-based adaptive threads (requires shadow-entropy)
- accelerated: MANA + UNHAL integration
- deterministic_rng: Reproducible testing
- allow_insecure: Test-only configs (blocked in release)

---

## Workspace Crates
- nine65: Core FHE — arithmetic, ring, ops, security, entropy, keys, noise, params (599+ tests)
- clockwork-core: Formal-spec RNS — bound tracking, GRO timing, Garner, integrity (46 tests)
- exact_transcendentals: Exact transcendental functions via integer CORDIC (143 tests)
- nexgen_rational: Exact i128 rational arithmetic, zero-dep (95 tests)
- fhe-service: FHE session management and serialization (22 tests)
- mana: FHE stream accelerator, lane-parallel pipeline engine (30 tests)
- unhal: Hardware abstraction layer (10 tests)

---

## Formal Verification

**Lean 4 is the formalization of record.** `lean4/KElimination/` builds cleanly
against the pinned Mathlib (`lake build`: 0 errors, 0 `sorry`), with a single
documented axiom `ahop_hardness` (the AHOP cryptographic hardness assumption).
The library globs all submodules, so every `KElimination.*` proof file is
elaborated (19 modules). See `docs/LEAN_FORMAL_VERIFICATION_2026-06-03.md`.

  cd lean4/KElimination && lake build   # requires Lean v4.27.0-rc1 + Mathlib

The `proofs/coq/` and `verified-innovations/proofs/coq/` trees are a **legacy
NINE65 v2-era exploration**, predating the move to Lean. They are not maintained
and are NOT the verification basis: several files do not compile and several
contain `Admitted` lemmas. Do not cite the Coq tree as machine-checked.

---

## Performance Baselines (CPU only, no GPU required)
secure_128: Encrypt 23.56ms | Add 0.83ms | Mul 152.13ms | Decrypt 11.06ms | Depth 50 in 6.29s
secure_192: Encrypt 61.59ms | Add 2.10ms | Mul 459.02ms | Decrypt 29.00ms | Depth 50 in 10.10s
RNS 4-lane: ADD 65.7ns (15.2M/s) | MUL 95.6ns (10.5M/s)

---

## License
Proprietary. See LICENSE. NINE65 v8 built on QMNF architecture by Acidlabz210.
