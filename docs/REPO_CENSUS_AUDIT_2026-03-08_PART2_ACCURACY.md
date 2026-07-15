# NINE65 v7 — Repository Census Audit, Part 2: Accuracy & Cross-Reference Atlas

**Date:** 2026-03-08
**Branch:** claude/repo-census-audit-3b6a0
**Companion to:** REPO_CENSUS_AUDIT_2026-03-08.md

This part covers the cross-reference sections of the audit: complete crate inventory,
name-collision matrix, dependency topology, and documentation-accuracy findings.
Every entry stands alone. No recommendations — inventory only.

---

## A. Complete Crate Inventory (14 crates)

CLAUDE.md documents 7 crates. The repository actually contains **15 Cargo manifests** —
one workspace root plus 14 crates. The workspace root (`/Cargo.toml`) declares
`members = ["crates/*"]` but **excludes** `fuzz`, `crates/nine65-python`,
`crates/nine65-wasm`, and `crates/nine65-ffi`. `security_proofs/` lives outside the
workspace entirely.

| # | Crate | Path | In workspace? | Documented in CLAUDE.md? | Purpose |
|---|-------|------|---------------|--------------------------|---------|
| 1 | nine65 | crates/nine65 | yes | yes | Core BFV FHE library |
| 2 | clockwork-core | crates/clockwork-core | yes | yes | Formal-spec RNS, GRO, integrity |
| 3 | exact_transcendentals | crates/exact_transcendentals | yes | yes | Integer-only transcendentals |
| 4 | nexgen_rational | crates/nexgen_rational | yes | yes | Exact i128 rational arithmetic |
| 5 | fhe-service | crates/fhe-service | yes | yes | HTTP session microservice |
| 6 | mana | crates/mana | yes | yes | FHE stream accelerator |
| 7 | unhal | crates/unhal | yes | yes | Hardware abstraction layer |
| 8 | **math_utils** | crates/math_utils | yes | **NO** | **ORPHAN — see below** |
| 9 | **nine65-extreme-tests** | crates/nine65-extreme-tests | yes | NO | Extreme/adversarial test crate |
| 10 | **nine65-ffi** | crates/nine65-ffi | excluded | NO | C FFI (cdylib/staticlib) |
| 11 | **nine65-python** | crates/nine65-python | excluded | NO | PyO3 Python bindings |
| 12 | **nine65-wasm** | crates/nine65-wasm | excluded | NO | wasm-bindgen WASM bindings |
| 13 | **nine65-fuzz** | fuzz/ | excluded | NO | libfuzzer targets (5) |
| 14 | **qmnf-security-analysis** | security_proofs/ | standalone | partial | Attack-estimator binaries |

### A.1 Orphan crate: math_utils

```
FILE: crates/math_utils/Cargo.toml
ITEM: package math_utils 0.1.0
REFERENCE: author "Manus AI"; description "Unified core mathematical primitives for QMNF, CRAM, and Hydra"
TARGET: any crate depending on math_utils
STATUS: UNRESOLVED (orphan)
CURRENT STATE: 301-line single-file crate (src/lib.rs). No other crate references
  math_utils in any Cargo.toml. The description names two systems ("CRAM", "Hydra")
  that do not otherwise appear as crates in this repository. It is a workspace member
  (matches crates/*) but is imported by nothing.
```

---

## B. Name Collision Matrix (Section 3)

### B.1 Type-name collisions

#### `DualRNSPoly` — OVERLAPPING (3 definitions, identical fields)
```
crates/nine65/src/ops/rns_fhe.rs:239   { main: Vec<Vec<u64>>, anchor: Vec<Vec<u64>>, n: usize }  derives Clone,Zeroize(+serde,custom Debug)  ← CANONICAL (in prelude)
crates/nine65/src/ops/rns_mul.rs:40    { main: Vec<Vec<u64>>, anchor: Vec<Vec<u64>>, n: usize }  derives Clone
docs/clockwork_bootstrap_public.rs:67  { main: Vec<Vec<u64>>, anchor: Vec<Vec<u64>>, n: usize }  derives Clone,Debug
```

#### `DualRNSCiphertext` — DIVERGENT (rns_mul lacks `level`)
```
crates/nine65/src/ops/rns_fhe.rs:276   { c0: DualRNSPoly, c1: DualRNSPoly, level: usize }  ← CANONICAL (in prelude)
crates/nine65/src/ops/rns_mul.rs:51    { c0: DualRNSPoly, c1: DualRNSPoly }   ← NO level field
docs/clockwork_bootstrap_public.rs:74  { c0: DualRNSPoly, c1: DualRNSPoly, level: usize }
```

#### `DualRNSKeySet` — DIVERGENT (rns_mul adds `secret_key_single`)
```
crates/nine65/src/ops/rns_fhe.rs:326   { secret_key: DualRNSSecretKey, public_key: DualRNSPublicKey }  ← CANONICAL
crates/nine65/src/ops/rns_mul.rs:70    { secret_key, public_key, secret_key_single: SecretKey }   ← extra field
```

#### `SecurityEstimate` — DIVERGENT (two definitions, same crate, both public)
```
crates/nine65/src/security/mod.rs:63              { classical_bits, quantum_bits, best_attack: String, confidence: ConfidenceLevel, ratio_permille }  ← prelude (5 fields)
crates/nine65/src/params/security_estimator.rs:39 { classical_bits, quantum_bits, hybrid_bits, effective_bits, bkz_block_size, bkz_iterations, meets_claim, analysis }  ← re-exported via params (8 fields)
```
Both reachable from the public API by different paths (`security::SecurityEstimate` vs `params::SecurityEstimate`).

#### `BootstrapKey` — DIVERGENT (2 definitions, same crate)
```
crates/nine65/src/keys/bootstrap.rs:136     { enc_s: DualRNSCiphertext, eval_key: DualRNSEvalKey, public_key: DualRNSPublicKey, t_work: u64, q_min: u128 }
crates/nine65/src/bootstrap/clockwork.rs:68 { sk: BootstrapSecretKey, pk_coeffs: (RingPolynomial,RingPolynomial), delta: u64, n, q, t, eta }  ← re-exported from bootstrap/mod.rs (canonical for `crate::bootstrap::BootstrapKey`)
```

#### `ClockworkBootstrap` — DIVERGENT (2 definitions, same crate)
```
crates/nine65/src/ops/bootstrap.rs:31       { work_config, boot_config, t, n, q_min, bootstrap_depth, boot_ctx: RNSFHEContext }
crates/nine65/src/bootstrap/clockwork.rs:155 { n, q, t, eta, ke: KElimination }   ← re-exported from bootstrap/mod.rs
```

#### `ExactCoeff` — DIVERGENT (cross-crate, completely different types)
```
crates/nexgen_rational/src/exact_coeff.rs:17       pub struct ExactCoeff(pub i128);   (newtype)
crates/nine65/src/arithmetic/exact_coeff.rs:36     pub struct ExactCoeff { inner: RnsInner, anchor: AnchorTrack }   (dual-track RNS)
```

### B.2 Function-name duplication (utility copies)

| Function | Copies | Locations |
|----------|--------|-----------|
| `mod_inverse` | 13 files | clockwork-core/basis.rs, nine65 arithmetic (ntt, ntt_fft, rns, order_finding, ct_mul_exact, cyclotomic_phase, exact_divider), entropy/crt_shadow.rs, kiosk/fold.rs, ops/galois.rs, params/primes.rs, security_proofs |
| `gcd_u64` | 8 across 7 files | clockwork-core, exact_transcendentals, nine65 (4 modules), 2 test files |
| `mod_inverse_u128` | 6 files | mana/anchor.rs, mana/stream.rs, nine65 k_elimination.rs, rns.rs, keys/bootstrap.rs, docs ref |
| `extended_gcd_i128` | 5 files | mana (anchor, stream), nine65 (k_elimination, keys/bootstrap), docs ref — all identical signature |
| `mul_mod_u128` | 4 files | clockwork-core/basis.rs, mana/anchor.rs, nine65 (k_elimination, rns) |

### B.3 Constant collisions

```
BOOTSTRAP_PRIMES  — DIVERGENT
  crates/nine65/src/keys/bootstrap.rs:21       [u64; 8] = [998244353, 985661441, 754974721, 469762049, 167772161, 1811939329, 595591169, 645922817]  ← CANONICAL (verified)
  docs/clockwork_bootstrap_public.rs:154       [u64; 6] = [998244353, 985661441, 754974721, 469762049, 1811939329, 2013265921]  ← STALE: different length AND contents

BOOTSTRAP_ANCHOR_COUNT — IDENTICAL (both = 3): keys/bootstrap.rs:33, docs:164

PI / HALF_PI / TWO_PI / SCALE — IDENTICAL duplicates within exact_transcendentals
  (cordic.rs duplicates the Scaled30 values from constants.rs)

Pade exp coefficients [1680, 840, 180, 20, 1] — IDENTICAL values, 3 names:
  nine65 pade_engine.rs (PADE_EXP_P/Q), nine65 integer_softmax.rs (PADE_P/Q), exact_transcendentals constants.rs (EXP_P/Q as i64)

TEST_PRIME = 998244353 — 12+ identical test-scoped copies (acceptable duplication)
```

---

## C. Dependency Topology (Section 4)

### C.1 Internal dependency graph
```
                 math_utils  (orphan — no edges)
                 qmnf-security-analysis  (standalone — no edges)

  exact_transcendentals ◄─┐
  nexgen_rational      ◄──┤
  clockwork-core       ◄──┼── nine65 ◄──── fhe-service, nine65-ffi,
  mana ◄── unhal ◄────────┘                nine65-python, nine65-wasm,
  mana ◄──────────────────┘                nine65-extreme-tests(dev), nine65-fuzz(dev)
```
nine65 is the central hub. All five math/accelerator crates are **optional** deps of
nine65, gated by features: `accelerated`→mana+unhal, `exact_transcendentals_backend`
(default)→exact_transcendentals, `exact_rational`→nexgen_rational, `clockwork`→clockwork-core.
The only non-nine65 internal edge is **unhal → mana**.

### C.2 External dependency version misalignment
```
ITEM: bincode
STATUS: DIVERGED
CURRENT STATE: nine65 pins bincode 2.0; fhe-service, nine65-python, nine65-wasm pin
  bincode 1.3. bincode 1.x and 2.x are API-incompatible. The binding/service crates
  serialize nine65 types via serde+bincode 1.3 while nine65's own serde feature uses
  bincode 2.0 — a serialization seam across the version boundary.
```
Other shared deps are aligned: zeroize 1.7, getrandom 0.2, subtle 2.5, sha2 0.10,
thiserror 1.0, rand_core 0.6, rand_chacha 0.3, rayon 1.10, wide 0.7, criterion 0.5,
proptest 1.4, serde 1.0, serde_json 1.0, crc32fast 1.3. (clockwork-core and
exact_transcendentals declare subtle/criterion as direct deps rather than
`workspace = true`, but the pinned versions match — style inconsistency only.)

### C.3 Internal import hubs (nine65)
345 `use crate::` + 102 `use super::` lines. Most-imported modules:
params (85), arithmetic (60), entropy (56), ops (53), errors (23), keys (19),
ring (15), noise (13). Hottest leaves: `ops::rns_fhe` (25), `params::secure_configs` (23),
`errors::*` (23). `src/accelerated.rs` is the sole integration point importing both mana and unhal.

---

## D. Documentation Accuracy Cross-Reference (Section 6) — CRITICAL

Format: STATUS ∈ {MATCHES, DIVERGED, STALE, EXISTS, UNRESOLVED}.

### D.1 Test-count claims
```
FILE: CLAUDE.md
REFERENCE: "Core FHE library (689+ tests)"  AND  "nine65: Core FHE — ... (599+ tests)"
TARGET: nine65 test count
STATUS: STALE + internally inconsistent
CURRENT STATE: Actual nine65 #[test] count = 1,058 (880 in src/, 178 in tests/).
  CLAUDE.md cites two different figures (689+ and 599+) for the same crate.
  NOTE: the live test run currently shows 11 failing lib tests and 33 integration
  compile errors (see main report §2), so not all 1,058 pass today.
```

### D.2 Secure-config parameters
```
FILE: CLAUDE.md / crates/nine65/src/params/secure_configs.rs
REFERENCE: "secure_128() — n=4096, log2(q)=90, classical=129/quantum=86/hybrid=129"
STATUS: MATCHES (with rounding)
CURRENT STATE: secure_configs.rs:156 — n=4096, 3×30-bit primes, t=65537. Actual
  log2(Q)≈89.3 (rounded to 90). Core-SVP=129 matches the lattice baseline.

REFERENCE: "secure_192() — n=16384, log2(q)=147, classical=374/quantum=213/hybrid=318"
STATUS: DIVERGED (log2(q))
CURRENT STATE: secure_configs.rs:199 — n=16384, 5 primes, t=65537. Actual log2(Q)≈145.4,
  not 147. Core-SVP=318 matches baseline. The "classical=374/quantum=213" figures are
  not present in docs/LATTICE_ESTIMATOR_BASELINE_2026-02-25.md (unverified source).

REFERENCE: "secure_256() — n=16384, log2(q)=177, classical=311/quantum=177/hybrid=264"
STATUS: DIVERGED (log2(q))
CURRENT STATE: secure_configs.rs:229 — n=16384, 6 primes, t=65537. Actual log2(Q)≈174.5,
  not 177. Core-SVP=264 matches. The in-code doc-comment (lines 219-222) also says
  "log(Q)=177" — the drift is propagated in both CLAUDE.md and source comments.
```

### D.3 Plaintext modulus & lattice baselines
```
REFERENCE: t=65537   STATUS: MATCHES — all production configs use 65537
  (secure_configs.rs:166,184,206,235,249)
REFERENCE: "Core-SVP: 128=129, 192=318, 256=264 / MATZOV: 128=116, 192=286, 256=237"
STATUS: MATCHES — exactly matches docs/LATTICE_ESTIMATOR_BASELINE_2026-02-25.md:21-31
```

### D.4 Bootstrap path claims
```
REFERENCE: "fully verified bootstrap roundtrip across all three paths" + bootstrap() /
  bootstrap_with_ksk() / AutoBootstrapEvaluator::mul_auto()
STATUS: EXISTS (functions present; "first FHE system" claim not code-verifiable)
CURRENT STATE:
  ops/bootstrap.rs:532  pub fn bootstrap(&self, ct: &DualRNSCiphertext, bsk: &BootstrapKey, _ksk: &KeySwitchKey) -> Nine65Result<DualRNSCiphertext>
  ops/bootstrap.rs:561  pub fn bootstrap_with_ksk(&self, ct: &DualRNSCiphertext, bsk: &BootstrapKey, ksk: &KeySwitchKey) -> Nine65Result<DualRNSCiphertext>
  ops/auto_bootstrap.rs:14,60  AutoBootstrapEvaluator + mul_auto()
  (Additional bootstrap() definitions: symmetric_bootstrap.rs:144, bootstrap/three_lock.rs:165)
```

### D.5 Proof-count claims
```
REFERENCE: CLAUDE.md "14 machine-checked Coq proofs"
STATUS: STALE (undercount)
CURRENT STATE: 16 .v files in proofs/coq/. CLAUDE.md's enumerated list names 14; two
  additional files exist: KElimination_Completed.v and MontgomeryPersistent.v
  (CLAUDE.md lists "Montgomery" once; there are two: MontgomeryContext.v + MontgomeryPersistent.v).

REFERENCE: CLAUDE.md "4 Lean4 proofs: K-Elimination, Core Definitions, Shadow Entropy, Modular Arithmetic"
STATUS: DIVERGED (large undercount)
CURRENT STATE: 20 .lean files (excl. lakefile.lean) under lean4/KElimination/, including
  EncryptedQuantum, MobiusInt, CyclotomicPhase, ShadowEntropy, ExactCoefficient,
  StateCompression, SideChannel, PadeEngine, Montgomery, GSOFHE, OrderFinding,
  IntegerSoftmax, MQReLU, Lattice/CRT, and an AHOP/ subdir (Algebra, Parameters, Hardness).
  The named file "Modular Arithmetic" does not exist as such.
```

### D.6 Version fossils in docs/
```
STATUS: STALE / mixed-generation
CURRENT STATE: Cargo version is 0.1.0; branding is "v7". docs/ mixes generations:
  v7 (~143 mentions), v5 (~69), v6 (~29), v8 (~18).
  - v8 docs imply a generation BEYOND current v7 branding:
    docs/AUDIT_REPORT_V8.md ("v8 Shadow Butterfly"), docs/RETIRED_Composite_Moduli_Fix_2.md
    (cites a "v8 Parameter Specification").
  - docs/integration/analysis_report.md references an external blueprint at a foreign
    path (/home/ubuntu/msnuslot/cram965/...NINE65_v8_Blueprint.md) and lists "active bugs
    A-1, A-2, A-3" as blockers — stale external context.
  - v5/v6 reports present and not marked retired: COMPREHENSIVE_TEST_REPORT_V5.md,
    NINE65_V5_FHE_DEEP_ANALYSIS_TEST_REPORT.md, COMPREHENSIVE_AUDIT_REPORT_V5.md,
    RELEASE_CHECKLIST_V6.md.
```

### D.7 Standalone public reference file
```
FILE: docs/clockwork_bootstrap_public.rs
STATUS: DIVERGED (BOOTSTRAP_PRIMES) / EXISTS (other types are illustrative redefinitions)
CURRENT STATE: This file is an explicit standalone extract (it redefines DualRNSPoly,
  DualRNSCiphertext, BootstrapKey, KeySwitchKey, FHEConfig rather than importing them).
  Its BOOTSTRAP_PRIMES is [u64; 6] with different primes than the real [u64; 8] in
  keys/bootstrap.rs:21 (see §B.3). Function entry points it presents (bootstrap(),
  generate_bootstrap_key(), build_round_table()) correspond to real APIs.
```

---

## E. Doc-Comment Audit (Section 7)

### E.1 Proof/theorem references — all on-disk artifacts EXIST
Every Coq/Lean file named in a nine65 `//!`/`///` doc comment exists on disk. Mapped
references include: errors.rs → KElimination.v/GSOFHE.v/OrderFinding.v/MQReLU.v/
ExactCoefficient.v; ops/neural.rs → PadeEngine.v/MQReLU.v/CyclotomicPhase.v/
IntegerSoftmax.v/MobiusInt.v; entropy/crt_shadow.rs → CRTShadowEntropy.v + ShadowEntropy.lean;
arithmetic/* → matching .v files; security/secret_data.rs → SideChannelResistance.v.

Four Coq proofs exist but are **not referenced** by any nine65 doc comment:
`EncryptedQuantum.v`, `StateCompression.v`, `MontgomeryContext.v`, `KElimination_Completed.v`.

```
STATUS: UNRESOLVED (external)
ops/rns_fhe.rs:4-6,769,1309,1605,3275 — references "Paper1/Paper2/Paper4" and
  "Paper 2 Lemma". No in-repo artifact corresponds to these paper numbers.
```

### E.2 Stale doc example
```
FILE: crates/nine65/src/keys/mod.rs
LINE: 501
ITEM: /// # Example code block
REFERENCE: KeySet::generate_gated(&config, &ntt, &gate)?
STATUS: UNRESOLVED (method does not exist)
CURRENT STATE: The real API is GatedKeyGen::generate_secure(&config, &ntt, &gate)
  (keys/mod.rs:521). TimingGate::new(...) in the same example is correct
  (security/gro_gate.rs:30). The example is marked `ignore`, so it is not compiled
  by doctests and the staleness is not caught by the build.
```
All other examined `# Example` blocks reference current type/function names. All Rust
examples in nine65 are marked `ignore`/`rust,ignore` (not doctest-compiled).

### E.3 Debt markers
No actionable TODO/FIXME/XXX/HACK markers exist in nine65/src. The only grep matches are
substring false positives from the brand string "HackFate.us".

---

## F. Verified Findings Index

| # | Finding | Evidence |
|---|---------|----------|
| 1 | 14 crates exist; CLAUDE.md documents 7 | `find . -name Cargo.toml` → 15 manifests |
| 2 | `math_utils` is an orphan crate | No Cargo.toml references it |
| 3 | bincode version split: 2.0 (nine65) vs 1.3 (service/python/wasm) | Cargo.toml inspection |
| 4 | nine65 has 1,058 tests, not 689+/599+ | grep `#[test]`: 880 src + 178 tests/ |
| 5 | 16 Coq proofs, not 14 | `ls proofs/coq/*.v` |
| 6 | 20 Lean4 proofs, not 4 | `ls lean4/KElimination/**/*.lean` |
| 7 | secure_192/256 log2(q) inflated (147/177 vs ~145/~174) | secure_configs.rs primes |
| 8 | BOOTSTRAP_PRIMES diverges (8 real vs 6 in public doc) | keys/bootstrap.rs:21 verified |
| 9 | `SecurityEstimate` / `BootstrapKey` / `ClockworkBootstrap` each defined twice in nine65 | grep `pub struct` |
| 10 | Stale doc example: `KeySet::generate_gated` does not exist | keys/mod.rs:501 vs :521 |
| 11 | v5/v6/v8 docs intermixed; v8 docs imply generation beyond "v7" | docs/ grep |
| 12 | 11 lib test failures (sbni.rs:84 OOB) + 33 integration compile errors | cargo test (main report §2) |

---

*Part 2 generated by Claude Code census audit on 2026-03-08. Inventory only — no recommendations.*
