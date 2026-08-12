# CLAUDE.md — Project Context for Claude Code

## Project Overview
**NINE65 v8 "Shadow Butterfly"** — A proprietary, unlimited-depth Fully Homomorphic Encryption (FHE) system built on the QMNF (Quantized Modular Number Field) architecture. Written entirely in Rust with zero floating-point arithmetic across all crates.

Key achievement: First FHE system with fully verified bootstrap roundtrip across all three paths (circular, non-circular KSK, and auto-triggered), enabling truly unlimited-depth computation.

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
  cargo test -p nine65 --test bootstrap_integration --release
  cargo test -p nine65 --test bootstrap_parameter_exploration --release

Security tests:
  cargo test -p nine65 security::tests -- --nocapture

Depth benchmarks:
  cargo test -p nine65 --lib --release ops::gso_fhe::depth_benchmarks::benchmark_symmetric_max_depth_secure_128 -- --nocapture

---

## Bootstrap Paths
- Circular: bootstrap() — boot_sk = lift(work_sk) — Verified exact
- Non-Circular (KSK): bootstrap_with_ksk() — independent boot_sk, gadget key switch — Verified exact
- Auto-Bootstrap: AutoBootstrapEvaluator::mul_auto() — auto trigger on noise threshold — Verified 10+ chained muls

## Security Configs
- SecureConfig::secure_128() — n=8192, log2(q)=90, classical=129/quantum=86/hybrid=129
- SecureConfig::secure_192() — n=16384, log2(q)=147, classical=374/quantum=213/hybrid=318
- SecureConfig::secure_256() — n=16384, log2(q)=177, classical=311/quantum=177/hybrid=264

# Lattice Estimator confirmed (2026-02-25, NINE65 built-in estimator):
# Core-SVP: secure_128=129 bits, secure_192=318 bits, secure_256=264 bits
# MATZOV:   secure_128=116 bits, secure_192=286 bits, secure_256=237 bits
# See: docs/LATTICE_ESTIMATOR_BASELINE_2026-02-25.md

---

## Important Coding Rules
- ZERO floats — no f32/f64 anywhere in the workspace, ever
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
