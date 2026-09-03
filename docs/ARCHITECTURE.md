# NINE65 Architecture

**Version**: 6.0 — full rewrite
**Snapshot**: `main@43a7d33` (2026-09-03)
**Status**: Pre-production. The production evaluator multiply route (Track 1
T1.4) is not integrated, public bootstrap is fail-closed (issue #95), and the
`fhe-service` HTTP encrypt/decrypt/evaluate endpoints are currently
non-functional (see §7). None of that is a defect this document proposes to
paper over — it is the architecture as shipped, described honestly.

> This is a **module/layer map kept in sync with the actual source tree**.
> `CLAUDE.md` at the repo root remains the primary, most frequently updated
> source of truth for build commands, current numbers, and open work — where
> this document and `CLAUDE.md` disagree, `CLAUDE.md` wins. This document
> exists so a new contributor gets a correct picture of *where things live and
> how the pieces connect* without having to read forty documents in `docs/`.

---

## 0. How to read this document

`docs/LINEAGE.md` sets the authority order used throughout this repository,
and it applies here too:

1. current executable code on the reviewed commit;
2. passing CI and checked raw evidence for that commit;
3. the current Lean formalization of record;
4. current normative docs (`CLAUDE.md`, `SECURITY_MODE_MATRIX.md`, the claim
   ledger, benchmark policy);
5. dated audits and benchmark reports;
6. historical papers and archived reports.

No number in this document should be read as stronger than its citation. Where
a figure is unverified or two documents disagree, that is stated rather than
resolved by picking one.

---

## 1. What NINE65 is

NINE65 v8 "Shadow Butterfly" is a proprietary exact-integer BFV/DualRNS FHE
substrate built on the QMNF (Quantized Modular Number Field) architecture,
written entirely in Rust with zero floating-point arithmetic in its
crypto/arithmetic hot paths (`compiler.rs::NoiseModel` is the one documented,
non-cryptographic exception — see `CLAUDE.md`'s "Important Coding Rules").

It provides finite leveled computation plus low-depth refresh paths. **It is
not an unlimited-depth system and does not claim to be** — `docs/LINEAGE.md`
places "unlimited depth", "depth 50", and "bootstrap-free" on its deprecation
list, and the measured public direct-square depths are 2–4
(`docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md` §1). Depth is *unbounded by the
level ladder* in a specific, narrower sense explained in §8: exact
residue-space division never drops a lane, so there is no level counter to
exhaust — that is a different claim from "unlimited depth," and older source
comments in this tree (e.g. `ops/gso_fhe.rs`'s module doc, still headed
"Enables unlimited-depth homomorphic computation... Status: VERIFIED") predate
the correction and should not be read as current.

The current production security architecture is **WIRE-Q** (§6): only
residues modulo divisors of the RLWE security modulus `Q` may ever leave the
secret-holder or evaluator boundary. This superseded the prior "persistent
DualRNS main+anchor ciphertext" direction in September 2026 and is the frame
every section below assumes.

---

## 2. Workspace layout

The root `Cargo.toml` declares `members = ["crates/*"]` and excludes
`fuzz`, `crates/nine65-python`, `crates/nine65-wasm`, and `crates/nine65-ffi`
from the default workspace build (they build independently, each with its own
FFI/binding surface).

### 2.1 Crates covered by `CLAUDE.md`'s Repository Structure section

| Crate | Role | Tests (per `CLAUDE.md`) |
|---|---|---|
| `nine65` | Core FHE library: arithmetic, ring, ops, security, entropy, keys, noise, params | 689+ (`--lib`) |
| `clockwork-core` | Formal-spec RNS: bound tracking, GRO timing, Garner, integrity | 46 |
| `exact_transcendentals` | Exact transcendental functions via integer CORDIC/AGM; also hosts the CRAM machine/harness modules (§2.3) | 143 |
| `nexgen_rational` | Exact `i128` rational arithmetic, zero external dependencies | 95 |
| `fhe-service` | HTTP session management for FHE operations (currently outaged — §7) | 22 |
| `mana` | FHE stream accelerator: lane-parallel pipeline engine, Rayon opt-in | 30 |
| `unhal` | Hardware abstraction layer over MANA | 10 |

These counts are as recorded in `CLAUDE.md`; this document does not
re-measure them.

### 2.2 Other in-workspace crates (not covered by `CLAUDE.md`'s table)

These build as part of the default workspace (`crates/*`) but are not
mentioned in `CLAUDE.md`'s Repository Structure section. Listed here so their
existence is not a surprise:

| Crate | What it is |
|---|---|
| `cram-core` | "Residue-native CRAM state, invariants, and architectural gates for NINE65" (its own `Cargo.toml` description); `#![deny(clippy::float_arithmetic)]`. |
| `math_utils` | "Unified core mathematical primitives for QMNF, CRAM, and Hydra" — intended as a single source of truth for modular arithmetic/primality shared across the QMNF ecosystem. |
| `nine65-extreme-tests` | "Extreme boundary and adversarial test harness for NINE65 v7" — a standalone crate of adversarial/stress tests (bootstrap, depth-stress, cross-config) that live in `src/`, not `tests/`, because they are a harness rather than a `#[cfg(test)]` module. |
| `private-feedback-core` | Defines a reference `SAFE_BASIS`/slot layout (`[2,3,5,7,11,13,17,19]`, 8 lanes) for a private-feedback reference application; `#![forbid(unsafe_code)]`, `#![deny(clippy::float_arithmetic)]`. |
| `private-feedback-nine65` | Adapter crate wiring `private-feedback-core` to `nine65::ops::rns_fhe::{DualRNSCiphertext, DualRNSPublicKey, RNSFHEContext}`. |

### 2.3 Excluded from the default workspace build

| Crate | Why excluded |
|---|---|
| `nine65-ffi` | C FFI bindings for the Kiosk computation-unit surface (§4.9); separate build target. |
| `nine65-python` | PyO3 Python bindings; separate build target. |
| `nine65-wasm` | WASM/browser bindings (`wasm-bindgen`); does not expose bootstrap (documented in its own comments). |
| `fuzz` | Fuzz targets; excluded so `autobenches`/normal builds don't pull them in. |

None of these three binding crates is covered by the build/test commands in
`CLAUDE.md`, and this document makes no capability claim about them beyond
"they exist and build separately."

---

## 3. `nine65` core module map

This is the module structure actually present under `crates/nine65/src/` on
the snapshot commit above (`ls`, not memory).

### 3.1 Top-level modules (declared in `lib.rs`)

| Module | Purpose |
|---|---|
| `arithmetic/` | Low-level integer math: RNS, K-Elimination, NTT, Montgomery, exact rescale kernels (§3.2) |
| `bootstrap/` | **Three-Lock Bootstrap** — a distinct, mostly-quarantined protected-re-encryption subsystem. See §3.3's naming-collision note; do not confuse with `ops::bootstrap`. |
| `compiler.rs` | FHE circuit compiler / offline noise planner (`NoiseModel`) — the one module permitted `f64` fields, and only for planning, never for ciphertext coefficients |
| `comprehensive_benchmarks.rs` | Additional benchmark harness code |
| `entropy/` | Random number generation: CRT Shadow entropy, deterministic test RNG, OS CSPRNG wrapper |
| `errors.rs` | The standardized `Nine65Error` taxonomy (typed errors, e.g. `BootstrapFailed`, `BootstrapConfigMismatch`) |
| `kat.rs` | Known-Answer Tests |
| `keys/` | Key generation and management (secret/public/evaluation/bootstrap keys) |
| `noise/` | Noise budget tracking (millibits) |
| `ops/` | FHE operations: encrypt/decrypt, homomorphic add/mul, the public "Clockwork Bootstrap" refresh paths, the exact-multiply Track 1 work (§3.2, §6) |
| `params/` | Configuration presets, `SecureConfig` constructors, the lattice-security estimator |
| `ring/` | Polynomial ring operations (`R_q[X]/(X^N+1)`) |
| `security/` | Constant-time primitives, GRO timing gates, secret-data zeroization markers, CT statistical verification |
| `accelerated.rs` | Integration point for MANA/UNHAL acceleration |
| `kiosk/` | "Ammunition model" self-destructing FHE computation units (Bullets/Capsules/Fuses) — a distinct application-layer subsystem, backing `nine65-ffi` |
| `cram_ct_wrap.rs` | Wraps `DualRNSCiphertext` in `exact_transcendentals::cram_ct::CramCiphertext` for a per-coefficient integrity fingerprint (not a substitute for the RNS security layer) |

`v2_integration_tests` is a private (`mod`, not `pub mod`) test-only module.

### 3.2 `arithmetic/` and `ops/` submodules

These two directories are where the multiply/rescale architecture actually
lives, and where the old (2026-01-24) table was most out of date — it listed
`k_elimination.rs`, `order_finding.rs`, `ntt.rs`, `montgomery.rs`, `rns.rs`
only; the directory now holds 29 files. Selected files, grouped by role
(exhaustive file list is `ls crates/nine65/src/arithmetic/`):

| File | Role |
|---|---|
| `rns.rs` | Residue Number System core: multi-prime adaptive support |
| `montgomery.rs` / `persistent_montgomery.rs` | Division-free modular multiplication; persistent variant keeps values in Montgomery form across an operation chain |
| `barrett.rs` | Barrett reduction for isolated (non-chained) reductions |
| `ntt.rs` / `ntt_fft.rs` | Negacyclic NTT; `ntt_fft.rs` (Cooley-Tukey, O(N log N)) is the default, unconditionally active path — `reference_ntt`'s O(N²) DFT is validation-only |
| `k_elimination.rs` | K-Elimination: exact dual-family division (the primitive the whole "no modulus switching" architecture in §8 is built on) |
| `order_finding.rs` | Non-circular order finding (BSGS) in multiplicative groups |
| `base_ext.rs` | Shenoy-Kumaresan base extension — reads a value's residue in one basis from its residues in another, without reconstructing the value; requires an externally supplied redundant residue |
| `main_only_base_ext.rs` | **Track 1 T1.2** — derives every auxiliary residue from the mod-`Q` main residues *alone*, no redundant/anchor lane required (the WIRE-Q-compliant replacement for `base_ext.rs` in the evaluator route — see §6) |
| `exact_scale_round.rs` | **Track 1 T1.3** — exact coefficient-level BFV scale-and-round (`Y = round(Xc·t/Q)`) over a derived-transient auxiliary base; refuses insufficient auxiliary capacity as a typed error rather than truncating |
| `compare_bit.rs` / `compare_bit_verify.rs` / `compare_bit_vectors.rs` | Constant-time comparison-bit kernel (`b = floor(2X/M)` from residues alone) plus its external-oracle verification and adversarial vector fixtures (Track 2 / PR #104, §9) |
| `unified_rescale.rs` | "One residue-native primitive, two exits" exact-Δ rescale |
| `residue_division.rs` / `kelim_residue_divider.rs` / `bounded_rns.rs` | Proof-carrying bounded quotient/division machinery and bit-width bound tracking |
| `mq_relu.rs`, `integer_softmax.rs`, `pade_engine.rs`, `cyclotomic_phase.rs`, `transcendental_backend.rs` | Integer-only ML/transcendental primitives (ReLU, softmax, Padé exp/sin/cos/log, ring trigonometry) built on the exact arithmetic below them |
| `rational_bridge.rs` | Bridge to `nexgen_rational`'s exact `i128` fractions |
| `valuation.rs`, `mobius_int.rs`, `integer_math.rs`, `exact_coeff.rs`, `exact_divider.rs`, `ct_mul_exact.rs`, `cyclotomic_phase.rs`, `boundary.rs` | Supporting exact-integer utilities (valuation/divisibility, signed-magnitude representation, dual-track coefficients, capacity proximity checks) |

`ops/` (16 files, versus the old table's 8):

| File | Role |
|---|---|
| `encrypt.rs` | BFV encrypt/decrypt |
| `homomorphic.rs` | Add/sub/mul/negate |
| `rns_fhe.rs` | The main RNS-native FHE evaluator: `RNSFHEContext`, `DualRNSCiphertext`/`DualRNSPublicKey`, encrypt, `mul_dual_public`, the limb-local `exact_rescale` (valid only while `Delta² <= Q` — see §6) |
| `cram_public.rs` | CRAM-Public Mode: "the single working CRAM variant of the FHE evaluator," a deliberately narrowed public-only path with a per-operation emission ledger |
| `track1_exact_multiply_lock.rs` | Track 1 T1.1 — a `#[cfg(test)]` child of `ops::rns_fhe` that pins the current limb-local rescale's *failure* against an exact oracle on chains where `Delta² > Q`, and pins the target semantics for the not-yet-integrated replacement route |
| `bootstrap.rs` | **`ops::bootstrap::ClockworkBootstrap`** — public (evaluator-side) ciphertext refresh: circular, KSK-separated, auto-triggered (§4) |
| `auto_bootstrap.rs` | `AutoBootstrapEvaluator` — opt-in wrapper triggering refresh on a noise threshold |
| `symmetric_bootstrap.rs` | `SymmetricBootstrap` — secret-key-holder-side protected re-encryption, a separate path not covered by the public admissibility gate |
| `sbni.rs` | Shadow Butterfly Noise Injection — **retired mechanism**, kept for record (§8) |
| `galois.rs` | Rotation operations (Galois automorphisms) for SIMD-slot rotation |
| `batch.rs` | SIMD-style value packing/batching encoder |
| `neural.rs` | `FHENeuralEvaluator` — neural-network-layer evaluation on ciphertexts |
| `parallel.rs` | Parallel encrypt/decrypt for throughput |
| `arrow_emission_gate.rs` | Public forwarding layer for the exact align-and-drop primitive |

### 3.3 Naming collision to be aware of: two `ClockworkBootstrap` types

`nine65::bootstrap::ClockworkBootstrap` (`src/bootstrap/clockwork.rs`) and
`nine65::ops::bootstrap::ClockworkBootstrap` (`src/ops/bootstrap.rs`) are two
**different** public structs with the **same name** at different module
paths. This is exactly the kind of thing that gives a new contributor a wrong
mental model, so it is called out explicitly here:

- `nine65::bootstrap::*` is the **Three-Lock Bootstrap**: Layer 1
  information-theoretic mask (Shannon one-time pad, `mask.rs`), Layer 2 RLWE
  outer encryption (`outer.rs`), Layer 3 algebraic mask removal
  (`clockwork.rs`), orchestrated by `three_lock.rs`. Per
  `docs/RETIRED_MECHANISMS.md` Part II, this subsystem is **quarantined as
  VESTIGIAL** — no production caller exists anywhere in the workspace
  (`RETIRED_MECHANISMS.md` §10.2, call-site rows 9–11), and most of its tests
  are `#[ignore]`d.
- `nine65::ops::bootstrap::*` is the subsystem `CLAUDE.md`'s "Bootstrap Paths"
  section actually describes: the three currently-relevant public refresh
  paths (circular, KSK, auto-triggered), gated by
  `ensure_public_refresh_supported` and, per issue #95, by
  `public_phase1_soundness_gate()`. See §4.

Do not read documentation, tests, or comments that say "Clockwork Bootstrap"
without checking which module they mean.

---

## 4. Public bootstrap: three refresh paths, all currently unproven end-to-end

Per `CLAUDE.md`'s "Bootstrap Paths" section (the authoritative summary; this
section restates it in the architecture-map context):

| Path | Entry point | Mechanism |
|---|---|---|
| Circular | `ClockworkBootstrap::bootstrap()` | `boot_sk = lift(work_sk)` |
| Non-circular (KSK) | `ClockworkBootstrap::bootstrap_with_ksk()` | independent `boot_sk`, gadget key switch |
| Auto-bootstrap | `AutoBootstrapEvaluator::mul_auto()` | auto-triggers a refresh on a noise threshold |

All three are **public** (evaluator-side, public bootstrap key material only)
paths in `ops/bootstrap.rs`. **None of their roundtrip tests currently runs**:
the suites in `ops/bootstrap.rs`, `tests/bootstrap_integration.rs`,
`tests/bootstrap_parameter_exploration.rs`, and
`tests/bootstrap_residue_shape_regression.rs` are `#[ignore]`d as
VESTIGIAL/RETIRED (`docs/RETIRED_MECHANISMS.md` Part II, §8), so "verified
exact" cannot currently be sourced to a running suite for any of the three.

**The admissibility gate.** All three refuse configurations whose main chain
cannot carry a public refresh, via
`params::secure_configs::ensure_public_refresh_supported` (a typed
`Nine65Error::BootstrapConfigMismatch`, never a panic):

| constructor | lanes | admits public refresh? |
|---|---|---|
| `secure_128()` | 3 | refused — 42 bits of post-refresh `Delta` headroom against the 47 one multiply needs |
| `hardware_opt()` | 3 | refused, same reason |
| `secure_128_deep()` | 4 | admitted |
| `secure_192()` | 5 | admitted |
| `secure_256()` | 6 | admitted |

**Public bootstrap is currently fail-closed regardless of admission.** Per
`docs/NINE65_LIVE_STATE_ADDENDUM_2026-09-03.md` and
`docs/NINE65_CURRENT_STATE_AND_WORK_REQUESTS_2026-09-03.md` §1.1 item 6,
`bootstrap()` and `bootstrap_with_ksk()` still call
`public_phase1_soundness_gate()`, which unconditionally returns a typed
`Nine65Error::BootstrapFailed` ("Phase 1 does not yet propagate the
secret-dependent displaced quotient/carry through the CRAM Safe-Root/Lift
state"). Issue #95 — the replacement Phase-1 correction/encoding — was
**reopened on 2026-09-03** because its actual acceptance criteria are not
met. The planned replacement is tracked as WR-5 (WR-5A sampler / WR-5B
security validation / WR-5C the actual correction / WR-5D metadata cleanup) in
`docs/NINE65_CURRENT_STATE_AND_WORK_REQUESTS_2026-09-03.md`.

**Open question about the admissibility gate itself.** A 2026-09-03 finding
(`docs/PUBLIC_REFRESH_CORRUPTS_ADMITTED_CONFIGS_2026-09-03.md`) measured
`ops::bootstrap::tests::diag_measure_noise_growth` — which bypasses only the
soundness gate to measure what the refresh phases actually produce — and
found `refresh(7)` itself (not just the following multiply) wrong for
`secure_128_deep` (`65536`) and `secure_192` (`40`), i.e. two of the three
configs the table above calls "admitted." This directly contradicts the
implication of the admissibility table (that admitted configs don't have this
problem) and trips the test's own built-in tripwire assertion ("the gate is
admitting a corrupting path — fix the predicate, do not relax this
assertion"). This is confirmed and unfixed as of the snapshot date; it is left
deliberately red rather than `#[ignore]`d, pending an owner decision. Do not
read "admitted" in the table above as "safe" without also reading that
finding.

The symmetric secret-key refresh (`SymmetricBootstrap::bootstrap`,
`ops/symmetric_bootstrap.rs`) is architecturally separate and is **not**
gated by `ensure_public_refresh_supported`; its own test suite is likewise
`#[ignore]`d as VESTIGIAL (`RETIRED_MECHANISMS.md` §8.1, 20 tests).

---

## 5. Security configs

Screened 2026-08-22 against the tuples actually in
`crates/nine65/src/params/secure_configs.rs` (`CLAUDE.md`'s "Security
Configs" section is the authoritative copy of this table; reproduced here for
the architecture map):

| constructor | n | lanes | log2(q) | claimed | Core-SVP | MATZOV | binding | public refresh |
|---|---|---|---|---|---|---|---|---|
| `secure_128()` | 8192 | 3 | 90 | 128 | 259 | 233 | 233 | refused |
| `secure_128_deep()` | 8192 | 4 | 119 | 128 | 196 | 176 | 176 | yes (§4 caveat) |
| `secure_192()` | 16384 | 5 | 146 | 192 | 320 | 288 | 288 | yes (§4 caveat) |
| `secure_256()` | 16384 | 6 | 175 | 256 | 267 | **240** | **240** | yes |
| `hardware_opt()` | 8192 | 3 | 90 | 128 | 259 | 233 | 233 | refused |

Every name clears its own number under Core-SVP, the model the estimator
gates on. `secure_256` falls 16 bits short of its claim under MATZOV — that
gap is documented on the constructor itself, not hidden. These are screening
numbers from a deterministic integer heuristic, **not independent lattice-
security certificates**; an archived external estimator run for the exact
shipped tuple remains unmet for `n=8192/16384`
(`docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md` §2, WR-7 in the current work
requests). `light()`, `he_standard_128()`, and `standard_128()` (`FHEConfig`,
not `SecureConfig`) are historical, test-only/insecure configs gated behind
`allow_insecure` regardless of their claimed bit strength.

---

## 6. The WIRE-Q security boundary and the exact-multiply track

### 6.1 Why WIRE-Q exists

Per `docs/WIRE_Q_FAIL_CLOSED_2026-09-02.md`: published keys and ciphertexts
must carry only their declared single-RNS mod-`Q` representation. Anchor,
Shadow, StarLift, redundant, lift, and other CRAM execution residues are
operation-local (evaluator-internal, "D3") state and must never be serialized
by the FHE service or appear on a published key/ciphertext. This is the
current production security architecture direction, stated as invariants
D0–D6 in `docs/NINE65_CURRENT_STATE_AND_WORK_REQUESTS_2026-09-03.md` §2:

- **D0** — WIRE-Q is the production security boundary; only mod-Q-only
  objects may be published.
- **D1** — exact integer/residue arithmetic remains mandatory; no
  floating-point correctness/capacity/security decision.
- **D2** — no Garner or mixed-radix hot path in production evaluator
  arithmetic.
- **D3** — the production multiply/rescale path must not materialize a
  canonical integer `X`; number-line reconstruction stays an explicit
  boundary/oracle operation.
- **D4** — K-Elimination/canonical-rank/lift machinery is a bounded
  quotient/carry projection with explicit range certificates, never a wire
  format.
- **D5** — complexity claims must distinguish sequential work from parallel
  depth; unbounded scalar work must not be described as O(1).
- **D6** — fail closed before optimizing: a typed unsupported/capacity error
  is correct behavior; a wrong plaintext, silent wrap, or uncertified
  fallback route is not.

### 6.2 What is currently gated closed

Two independent fail-closed gates currently exist:

1. **`fhe-service`'s dual-RNS wire boundary.** `Session::dual_ct_to_b64` /
   `Session::dual_ct_from_b64` (`crates/fhe-service/src/session.rs`)
   unconditionally return `Err("WIRE-Q: ...")` for any input — they never
   encode or decode a dual-RNS (anchor-bearing) ciphertext anymore.
2. **`RNSFHEContext::mul`'s route check.** The public single-RNS multiply
   entry point checks that the configuration selects `BajardSingle` before
   entering the legacy per-limb rescale; a configuration selected for
   K-Elimination/dual rescaling must go through `mul_auto` with matching auto
   keys instead, rather than silently producing a ciphertext from an
   uncertified rescale.

### 6.3 The exact-multiply replacement route: staged, not integrated

The intended production replacement for the legacy limb-local rescale is
being built as Track 1 (PR #103) in three completed stages plus one pending
stage:

| Stage | What | Status |
|---|---|---|
| T1.1 | `ops::rns_fhe::track1_exact_multiply_lock` — pins the current rescale's failure against an exact oracle, defines the target semantics | landed |
| T1.2 | `arithmetic::main_only_base_ext::MainOnlyBaseExt` — derives auxiliary residues from main mod-Q residues alone, no redundant lane | landed |
| T1.3 | `arithmetic::exact_scale_round::ExactScaleRound` — exact coefficient-level BFV scale-and-round over a derived-transient auxiliary base; refuses insufficient capacity | landed, but **not yet wired into the evaluator** |
| T1.4 | Evaluator integration: turn T1.2+T1.3 into the actual `mul`/rescale route while preserving a mod-Q-only wire object | **not implemented** |

`docs/NINE65_CURRENT_STATE_AND_WORK_REQUESTS_2026-09-03.md` §1.2 states this
plainly: "the exact multiply kernel is therefore mathematically staged but not
a production evaluator route." Until T1.4 (tracked as WR-1) lands, the
evaluator's real multiply path remains the pre-existing limb-local
`exact_rescale` in `rns_fhe.rs`, valid only while `Delta² <= Q`, with the
`BajardSingle`/`mul_auto` route split from §6.2 as the only currently-enforced
guard against its known failure mode.

---

## 7. `fhe-service`: HTTP API is currently non-functional end-to-end

`crates/fhe-service` provides HTTP session management
(`session.rs`/`handlers.rs`/`http.rs`/`auth.rs`/`wire.rs`) over the `nine65`
evaluator. As of the snapshot date, **every `POST /v1/sessions/{id}/encrypt`
request returns `400 ENCRYPT_FAILED`, unconditionally, for every
configuration** — and decrypt/evaluate are equally broken for the same
reason.

Root cause (`docs/FHE_SERVICE_WIRE_Q_OUTAGE_2026-09-03.md`): the WIRE-Q
fail-closed patch (§6.2, PR #107, merged as `8f59127`) correctly closed the
dual-RNS import/export path, but no single-RNS mod-Q wire encode/decode path
was ever wired into `handlers.rs` to replace it. `handle_encrypt` calls
`session.dual_ct_to_b64(&ciphertext)?` on the ciphertext it just produced, to
build its own response body — and that call now always errors, because it is
the same retired dual-RNS path. `handle_decrypt` and `handle_evaluate` call
the matching `dual_ct_from_b64`/`dual_ct_to_b64` the same way. This is a
materially different (and more severe) situation than PR #107's own
description claimed ("rejects dual/anchor-bearing ciphertext import and
export"); it also rejects the service's own freshly encrypted, non-anchor-
bearing output, because there is no other path.

Evidence:

```
cargo test --release -p fhe-service
test result: ok. 24 passed; 0 failed; 29 ignored; 0 measured; 0 filtered out
```

The 29 tests that exercise `POST /encrypt` (directly or via
`setup_and_encrypt`/`setup_and_encrypt_config`) were marked `#[ignore]` with a
reason string pointing at the outage document — following the same
`#[ignore = "..."]` convention `CLAUDE.md` documents for the bootstrap
suites — rather than left silently red or deleted. Every ignored test's body
and assertions are untouched.

The fix is the same single-RNS mod-Q wire type §6.1's "Required replacement"
list calls for, wired into `Session`/`handlers` so `handle_encrypt` never
calls the retired dual-RNS path for its own output. This is tracked as WR-2
(WIRE-Q closure), downstream of WR-1 (T1.4 evaluator integration, §6.3) in
`docs/NINE65_CURRENT_STATE_AND_WORK_REQUESTS_2026-09-03.md`. Until it lands,
**no session created through the HTTP API can produce a usable ciphertext**,
so nothing downstream of encrypt can be exercised through the service either.

---

## 8. Retired mechanisms: modulus switching, the noise budget ladder

`docs/RETIRED_MECHANISMS.md` (authoritative, 2026-08-09) records that NINE65
**no longer implements modulus switching**, and explains why that is a
one-way architectural decision rather than a missing feature:

- A classical BFV rescale fuses two operations: divide the value by the top
  prime (inexact — it adds a rounding term), and drop that prime from the
  basis (**forced**, to absorb the rounding). That fusion produces a finite,
  strictly descending level chain, and depth is bounded by the starting
  prime count.
- NINE65 divides in residue space **exactly** (K-Elimination for
  `gcd(d,M)=1`; Fused Piggyback Division for `gcd(d,M)>1`), so there is no
  rounding term to absorb and **no lane is ever dropped**. The two halves of
  classical rescale come apart: the value shrinks, the basis does not move.
- The consequence: **depth is unbounded because the operation never spent
  anything — not because levels get replenished.** There is no level
  counter, no "levels remaining," and no exhaustion condition any code path
  can reach for the operations this covers.

Because bootstrap exists specifically to recover an *exhausted level chain*,
and no such chain exists in the retained architecture, the classical-ladder
bootstrap machinery (Three-Lock Bootstrap, §3.3) and modulus-switching test
suites are quarantined rather than "fixed" — repairing them to pass on their
own terms would mean reintroducing a level ladder, which is explicitly
disallowed (`RETIRED_MECHANISMS.md` §5, §11). `RETIRED_MECHANISMS.md` §10
also establishes, by grepping every non-test call site in the workspace, that
`ops/rns_fhe.rs` (the encrypt/mul/div/decrypt critical path) never calls
bootstrap at all — bootstrap is reachable only through the explicit opt-in
`AutoBootstrapEvaluator` wrapper, which no other production code calls.

This retirement is a separate claim from "unlimited depth" (§1): it explains
*why there is no ladder to run out of*, not that depth has no practical
ceiling. Public direct-square depth is measured at 2–4 (§1), bounded by noise
growth rather than by a lane count.

---

## 9. Constant-time work in flight (Track 2 / PR #104)

`arithmetic::compare_bit` (`b = floor(2X/M)` from residues alone) is a D2
(secret-holder-boundary) fixed-work centering kernel with its own external
verification (`compare_bit_verify.rs`) against adversarially generated vector
fixtures (`compare_bit_vectors.rs`). Per
`docs/NINE65_CURRENT_STATE_AND_WORK_REQUESTS_2026-09-03.md` §1.1 item 7, the
source-level implementation and Python/Rust-oracle evidence exist, but the PR
is stale against current `main` and non-mergeable, and current-facing
**constant-time claims must remain scoped to source-level/fixed-work
exactness** — hardware constant-time (disassembly plus two-class
timing/address-trace evidence on x86-64 and ARM) has not been collected.
`CompareBit::decide_ct` is a D2 primitive only; it is not license to
reconstruct evaluator D3 (derived-transient) values.

---

## 10. Formal verification

**Lean 4 is the formalization of record.** `lean4/KElimination/` builds
cleanly against the pinned Mathlib (`lake build`: 0 errors, 0 `sorry`), with a
single documented axiom `ahop_hardness` (the AHOP cryptographic hardness
assumption). The library globs all submodules, so every `KElimination.*`
proof file is elaborated (19 modules). See
`docs/LEAN_FORMAL_VERIFICATION_2026-06-03.md`.

```
cd lean4/KElimination && lake build   # requires Lean v4.27.0-rc1 + Mathlib
```

`proofs/coq/` (and `verified-innovations/proofs/coq/`) is a **legacy NINE65
v2-era exploration predating the move to Lean**. It is not maintained and is
**not the verification basis** — several files do not compile and several
contain `Admitted` lemmas. Do not cite the Coq tree as machine-checked, even
where a source file's doc comment points at a Coq proof by filename (several
still do, e.g. `arithmetic/k_elimination.rs`'s reference to
`proofs/coq/KElimination.v`) — the Lean counterpart is the sound coverage.

---

## 11. Build, test, and feature flags

See `CLAUDE.md`'s "Build & Test Commands" and "Feature Flags" sections for
the authoritative, maintained command list. Summary:

```bash
# build everything except the Python/WASM binding crates
cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm

# full test suite
cargo test --release --workspace --exclude nine65-python --exclude nine65-wasm

# core FHE tests only
cargo test -p nine65 --lib --release
```

Standalone `-p nine65` runs of integration-test/bench targets need
`--features allow_insecure`, because those targets link the library without
`cfg(test)`, and the release-mode secure-RNG gate would otherwise reject their
seeded `ShadowHarvester`. The workspace-wide command above needs nothing
extra.

Feature flags actually declared in `crates/nine65/Cargo.toml` (`default =
["exact_transcendentals_backend", "accelerated"]`):

| Feature | Default | Purpose |
|---|---|---|
| `exact_transcendentals_backend` | on | Exact integer CORDIC/AGM transcendentals |
| `accelerated` | on | Pulls in `mana`/`unhal` for the canonical accelerator pipeline |
| `ntt_fft` | (legacy alias) | The FFT NTT path is unconditionally active regardless of this flag; kept for downstream `Cargo.toml` compatibility |
| `reference_ntt` | off | O(N²) DFT reference NTT, validation-only |
| `parallel` / `generic-rayon` | off | Opt-in Rayon parallelism for MANA's legacy stream API; the production hot path does not need or use this |
| `clockwork` | off | GRO timing gates, bound tracking, key lifecycle, integrity (`clockwork-core`) |
| `exact_rational` | off | NexGen rational bridge (exact noise, BFV delta) |
| `shadow-entropy` | off | CRT shadow entropy harvester (internal subsystem) |
| `adaptive-threading` | off | Entropy-based adaptive threading; requires `shadow-entropy` |
| `deterministic_rng` | off | ChaCha-based reproducible test RNG |
| `serde` | off | JSON + bincode serialization |
| `allow_insecure` | off | Test-only insecure configs; **blocked in release builds**, never for production |
| `logging` | off | Structured diagnostics via the `log` facade |
| `secure_seed` | off | OS CSPRNG seeding convenience for `ShadowHarvester` |
| `debug_dual_mul` | off | Verbose debug output for DualRNS K-Elimination rescaling |
| `slow_tests` / `benchmarks` | off | Gate long-running tests/benches |
| `sequential` | off | Force sequential execution (disables all parallelism) |

`ntt_fft`'s default was previously "reference NTT vs FFT" — it is now a
no-op legacy alias, as the flag's own doc comment in `Cargo.toml` states; the
old ARCHITECTURE.md's feature table already carried this correction and it is
preserved here.

---

## 12. Performance baselines

Measured 2026-08-23 by `crates/nine65/tests/op_timings.rs`, default features
(MANA + UNHAL active), 4 vCPU shared container @ 2.80 GHz. Every timed round
decrypts and asserts exactness, so no figure below comes from a wrong answer.
Reproduced verbatim from `CLAUDE.md`:

| config | Encrypt | Add | Public mul | Symmetric mul | Decrypt |
|---|---|---|---|---|---|
| secure_128 | 5.38ms | 1.405ms | 292.40ms | 82.07ms | 1.83ms |
| secure_128_deep | 6.60ms | 1.528ms | 408.66ms | 93.14ms | 2.51ms |
| secure_192 | 23.09ms | 5.488ms | 1114.12ms | 247.21ms | 7.51ms |
| secure_256 | 22.41ms | 5.943ms | 1017.91ms | 262.96ms | 7.78ms |

```bash
cargo test -p nine65 --test op_timings --release --features allow_insecure -- --ignored --nocapture
```

`CLAUDE.md` documents at length why several older figures (a claimed ~2x
`add` regression; a 152.13ms public-mul figure at commit `364bd6a`; a
"Depth 50" claim) were investigated and withdrawn rather than restated — see
its Performance Baselines section for the full account, including the
`secure_128` redefinition (N=4096→8192, 3 lanes→3 main+5 anchor) that makes
any name-keyed before/after comparison across that boundary meaningless. This
document does not repeat that investigation; it only carries the current,
reproducible numbers forward.

---

## 13. What is not done — the current work-request ledger

`docs/NINE65_CURRENT_STATE_AND_WORK_REQUESTS_2026-09-03.md` is the execution
control plane for the next completion wave; `CLAUDE.md`'s "Open Work — read
this first" pointer to `docs/OPEN_WORK_2026-08-26.md` covers the prior
session's handoff (owner decisions, measured-but-unfixed findings, and a list
of settled questions not to re-derive). Load-bearing open items, condensed:

- **WR-1 / Track 1 T1.4** — exact evaluator multiply/rescale integration; not
  implemented (§6.3).
- **WR-2** — WIRE-Q differential/serialization closure, including the
  `fhe-service` single-RNS wire type; not implemented (§7).
- **WR-3** — PR #104 Track 2 CompareBit completion, rebase, and hardware
  constant-time evidence; stale/non-mergeable (§9).
- **WR-4** — promote `lifted_transduction.rs` (staged behind the integration
  test shim, PR #99) into a typed, exported provider.
- **WR-5 (A–D)** — rebuild public bootstrap (#95) around a valid encrypted
  Phase-1 correction; public refresh remains fail-closed until this lands
  (§4).
- **WR-6** — per-ciphertext auto-refresh/noise state (#93); depends on WR-5C.
- **WR-7** — factorization-aware production security admission, `secure_256`
  naming disposition, external lattice-estimator attestation (#75/#76/#87/#88).
- **WR-8** — service/API/input hardening: HTTP framing fail-closed work,
  typed constructor errors in place of caller-controlled panics, panic/unwrap
  ratchet enforcement.
- **WR-9** — CI/benchmark evidence plumbing; final README performance and
  depth/capability claims are explicitly **deferred until the architecture
  freezes**, per that document's own text.
- **WR-0** — restore executed CI evidence for current `main`. Per
  `docs/NINE65_LIVE_STATE_ADDENDUM_2026-09-03.md`: "workflow definitions
  exist, but no executed workflow/check evidence was found for this September
  head... no current-main build, test, formatting, security, or benchmark
  result is asserted."

The safe summary sentence, quoted directly from that document because it is
already precisely scoped:

> Exact mod-Q arithmetic kernels are advancing; WIRE-Q is enforced; unsafe
> public multiply/refresh routes fail closed; public bootstrap and general
> auto-refresh remain incomplete.

---

## 14. Related documents

- `../CLAUDE.md` — the current, most-frequently-maintained architecture and
  build reference; authoritative over this file wherever they disagree.
- `docs/NINE65_CURRENT_STATE_AND_WORK_REQUESTS_2026-09-03.md` — execution
  control plane: what's landed, what's not, dependency graph, work requests.
- `docs/NINE65_LIVE_STATE_ADDENDUM_2026-09-03.md` — reconciled state as of
  the latest snapshot, CI evidence disposition.
- `docs/WIRE_Q_FAIL_CLOSED_2026-09-02.md` — the WIRE-Q wire-boundary contract
  and its known consequence.
- `docs/FHE_SERVICE_WIRE_Q_OUTAGE_2026-09-03.md` — the `fhe-service` HTTP
  outage this document summarizes in §7.
- `docs/PUBLIC_REFRESH_CORRUPTS_ADMITTED_CONFIGS_2026-09-03.md` — the
  admissibility-gate finding this document summarizes in §4.
- `docs/RETIRED_MECHANISMS.md` — modulus switching, the noise budget/ladder,
  and the Three-Lock Bootstrap; authoritative on what NINE65 no longer
  implements and why.
- `docs/OPEN_WORK_2026-08-26.md` — prior session handoff: owner decisions,
  measured-but-unfixed findings, settled questions not to re-derive.
- `docs/CLAIM_SURFACE_AND_LIMITS_2026-08-22.md` — per-number provenance for
  the verified-capability table and the not-established list.
- `docs/LINEAGE.md` — the historical-stage map and the authority order used
  throughout this document.
- `proofs/coq/` — legacy, unmaintained Coq exploration predating the move to
  Lean; not the verification basis.
- `lean4/KElimination/` — Lean 4 formalization of record (`lake build`: 0
  errors, 0 `sorry`).

---

*Full rewrite: 2026-09-03, against `main@43a7d33`, for issue #66. Supersedes
the 2026-01-24 "Version 5.0" document and its 2026-08-19 spot corrections.*
