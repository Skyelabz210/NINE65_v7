# CLAUDE.md — Project Context for Claude Code

## Project Overview
**NINE65 v8 "Shadow Butterfly"** — A proprietary exact-integer BFV/DualRNS FHE substrate built on the QMNF (Quantized Modular Number Field) architecture. Written entirely in Rust with zero floating-point arithmetic in its crypto/arithmetic hot paths (see "Important Coding Rules" below for the one documented, non-cryptographic exception).

It provides finite leveled computation plus low-depth refresh paths. **It is not an unlimited-depth system and does not claim to be** — `docs/LINEAGE.md` places "unlimited depth", "depth 50" and "bootstrap-free" on the deprecation list, and the measured public direct-square depths are 2–4. The verified capability table is in `README.md`; per-number provenance and the not-established list are in `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md`.

---

## Open Work — read this first

`docs/OPEN_WORK_2026-08-26.md` is the current handoff: what is decided, what is
blocked on an owner decision, what is measured-but-unfixed, and — section D — a
list of settled questions that LOOK open and must not be re-derived. Two
retractions in the 2026-08-22..26 session came from re-reasoning instead of
re-reading; section D exists to stop a third.

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
(typed `Nine65Error::BootstrapConfigMismatch`, never a panic).

`secure_128` was **re-cut 2026-08-26** (`docs/OPEN_WORK_2026-08-26.md` §A3)
from three main primes to four; it now builds the exact same tuple as
`secure_128_deep` and is therefore **admitted**, not refused. The retired
three-lane tuple — 42 bits of post-refresh `Delta` headroom against the 47 one
multiply needs, refused, with `refresh(7)` squaring to a wrong-but-plausible
`34037` instead of `49` (measured by
`ops::bootstrap::tests::diag_measure_noise_growth`) — is historical only; see
`docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md` (flagged there as superseded on
this point) for its archived numbers. `hardware_opt` no longer has a
constructor in `secure_configs.rs` as of this writing; its continued presence
in older docs is a separate, unresolved discrepancy, not addressed here.

`secure_128_deep`, `secure_192` and `secure_256` (4/5/6 lanes) are admitted,
and `secure_128` now joins them on the same arithmetic. The symmetric
secret-key refresh (`SymmetricBootstrap::bootstrap`) is a separate path and is
not gated by this.

**Open regression, separate from the above (2026-09-03):**
`docs/PUBLIC_REFRESH_CORRUPTS_ADMITTED_CONFIGS_2026-09-03.md` found that on
current `main`, `diag_measure_noise_growth` itself now decrypts wrong for
every admitted config it measured (`secure_128_deep`, `secure_192`) — not just
the historical secure_128 failure mode above, and not just at the subsequent
multiply, but on `refresh(7)` itself. Tracked separately as issue #95 /
WR-5A / WR-5B; not resolved by the 2026-08-26 re-cut and not resolved by this
documentation pass. Do not read "admitted" in this section as "refresh
verified working."

## Security Configs
Screened 2026-08-22 by `params::secure_configs::tests::screened_levels_for_named_configs`
against the tuples actually in `secure_configs.rs`. `log2(q)` is the exact bit
length of the prime product. `secure_128`'s row reflects the 2026-08-26 re-cut
described above; the screen itself was run pre-recut on the tuple `secure_128`
now shares with `secure_128_deep`, so the numbers were already correct for
that tuple under the `secure_128_deep` name and are simply carried over.

| constructor | n | lanes | log2(q) | claimed | Core-SVP | MATZOV | binding | public refresh |
|---|---|---|---|---|---|---|---|---|
| `secure_128()` | 8192 | 4 | 119 | 128 | 196 | 176 | 176 | yes |
| `secure_128_deep()` | 8192 | 4 | 119 | 128 | 196 | 176 | 176 | yes |
| `secure_192()` | 16384 | 5 | 146 | 192 | 320 | 288 | 288 | yes |
| `secure_256()` | 16384 | 6 | 175 | 256 | 267 | **240** | **240** | yes |

Every name clears its own number under Core-SVP, the model `new_verified` gates
on. `secure_256` falls 16 bits short under MATZOV; that gap is documented on the
constructor and readable via `SecureConfig::screened_security_dual()`. No config
is renamed. (`hardware_opt` is dropped from this table: no such constructor
exists in the current `secure_configs.rs`, and the screening test that
produces this table does not run one — see the note under "Bootstrap Paths."
The retired `secure_128` figures this replaces — 259 / 233 / 233, refused —
are archived in `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md`.)

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

Measured 2026-08-23 by `crates/nine65/tests/op_timings.rs`, default features
(MANA + UNHAL active), 4 vCPU shared container @ 2.80 GHz. Medians; every round
decrypts and asserts exactness, so no timing comes from a wrong answer.

| config | Encrypt | Add | Public mul | Symmetric mul | Decrypt |
|---|---|---|---|---|---|
| secure_128 | 5.38ms | 1.405ms | 292.40ms | 82.07ms | 1.83ms |
| secure_128_deep | 6.60ms | 1.528ms | 408.66ms | 93.14ms | 2.51ms |
| secure_192 | 23.09ms | 5.488ms | 1114.12ms | 247.21ms | 7.51ms |
| secure_256 | 22.41ms | 5.943ms | 1017.91ms | 262.96ms | 7.78ms |

Reproduce:
  cargo test -p nine65 --test op_timings --release --features allow_insecure -- --ignored --nocapture

On the figures previously recorded here (secure_128 Encrypt 23.56ms | Add 0.83ms
| Mul 152.13ms | Decrypt 11.06ms): the commit that wrote them, 364bd6a
(2026-02-24), was checked out in a worktree and measured on this machine.
Encrypt (21.96ms), Add (0.672ms) and Decrypt (10.14ms) all REPRODUCE within 20%,
stable over three runs. Public mul does not: 316.54ms measured against 152.13ms
recorded. So this machine is comparable to whatever produced them and the
discrepancy is not hardware — the mul figure was simply wrong when written, and
secure_128 public mul has never measured ~152ms on this code.

A caution that matters more than the numbers: `secure_128` was REDEFINED
between February and August. At 364bd6a it was N=4096 with 3 main primes; it is
now N=8192 with 3 main + 5 anchor lanes ("Increased from 4096 to maintain
security with larger Q"). Encrypt, add and decrypt are all O(N x lanes), so the
current secure_128 does roughly 3.2x the work of February's under the same name.
Any Feb-to-now delta keyed on the config NAME is therefore meaningless.

An earlier revision of this file published such a delta anyway, including a
claimed ~2x `add` regression. THERE IS NO ADD REGRESSION. Measured with a
tight-loop probe, add is 0.207ms at 364bd6a and 1.04ms now -- a 5.0x ratio
against a ~3.2x work ratio, the remainder being memory and allocation scaling.
The claim is withdrawn rather than rescaled: dividing a measurement by an
estimated work ratio yields an estimate, not a measurement. Eliminated first:
the release profile (lto=fat/cgu=1 measures 1.03ms vs cargo defaults 0.85-1.01ms
at HEAD, nowhere near 5x) and a git bisect over all 274 commits in the range,
which converged on a commit whose tree is a divergent re-import rather than a
behavioural change.

What survives, because it was measured at ONE commit with ONE config: the
152.13ms public-mul figure recorded at 364bd6a does not reproduce at 364bd6a
itself, where the same N=4096 secure_128 measures 316.54ms over three runs. That
figure was wrong when written. Encrypt (21.96ms), Add (0.672ms) and Decrypt
(10.14ms) all DO reproduce there within 20%, so the machine is not the
explanation.

The session-scope conclusion is unaffected, because it compares two commits that
share a config definition: b03aa4a built in a separate worktree gives 301.55ms
for secure_128 public mul against 281-302ms at HEAD. Nothing in the 2026-08-22
session made anything slower. The "Depth 50" line is separately inconsistent
with the measured public direct-square depths of 2-4 in README.md and is not
reinstated.

RNS 4-lane micro-numbers (ADD 65.7ns / MUL 95.6ns) are likewise un-provenanced
and were not re-measured; treat them as unverified until they are.

---

## License
Proprietary. See LICENSE. NINE65 v8 built on QMNF architecture by Acidlabz210.
