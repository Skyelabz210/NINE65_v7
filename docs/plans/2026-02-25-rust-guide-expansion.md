# NINE65 Rust Guide Expansion — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expand the NINE65 Rust Guide from 13 flat pages to 37 structured pages with just-the-docs theme, cheatsheet landing page, collapsible sidebar navigation, and complete coverage of all system operations, internals, and tooling.

**Architecture:** Jekyll GitHub Pages site using just-the-docs theme with remote_theme. Pages organized into 6 collapsible sidebar sections. Each page uses YAML front matter for ordering and parent assignment. Custom dark CSS overlay.

**Tech Stack:** Jekyll, just-the-docs remote theme, GitHub Pages, Markdown/Kramdown, Mermaid diagrams

**Site:** https://skyelabz210.github.io/NINE65-Rust-Guide/

---

## Phase 1: Theme & Infrastructure

### Task 1: Migrate to just-the-docs theme

**Files:**
- Modify: `NINE65-Rust-Guide/docs/_config.yml`
- Create: `NINE65-Rust-Guide/docs/_sass/custom/custom.scss`

**Step 1: Update _config.yml**

Replace entire file with just-the-docs config including: remote_theme, color_scheme, search, nav sections, mermaid support, footer, aux links.

**Step 2: Create custom dark SCSS**

Dark background (#0d1117), lighter text (#c9d1d9), accent color for links, monospace code blocks, sidebar styling.

**Step 3: Verify build**

```bash
cd NINE65-Rust-Guide && bundle exec jekyll serve
# Or push and check GitHub Pages build
```

**Step 4: Commit**

```bash
git add docs/_config.yml docs/_sass/
git commit -m "feat(guide): migrate to just-the-docs theme with dark mode"
```

---

### Task 2: Add YAML front matter to all existing pages

**Files:** All 12 existing `.md` files in `NINE65-Rust-Guide/docs/`

Every page needs `nav_order`, `parent`, and `grand_parent` fields for just-the-docs sidebar. Example:

```yaml
---
layout: default
title: Architecture
parent: How It Works
nav_order: 1
---
```

Section parent pages (no content, just nav grouping):
- `getting-started-section.md` (parent: none, has_children: true)
- `foundation-section.md`
- `using-the-system-section.md`
- `how-it-works-section.md`
- `tools-and-testing-section.md`
- `reference-section.md`

**Step 1: Create 6 section parent pages**
**Step 2: Update front matter on all 12 existing pages**
**Step 3: Remove formal-proofs.md from navigation (delete or set nav_exclude: true)**
**Step 4: Commit**

---

## Phase 2: Landing Page + Cheatsheet

### Task 3: Rewrite index.md with cheatsheet and sectioned navigation

**Files:**
- Modify: `NINE65-Rust-Guide/docs/index.md`

The landing page should contain:
1. Title + one-line description
2. **Cheatsheet** (quick-access command table) — the most common commands grouped by purpose:

```
BUILD
  cargo build --release --workspace --exclude nine65-python --exclude nine65-wasm

TEST
  cargo test -p nine65 --lib --release                           # Core (721 tests)
  cargo test --release --workspace --exclude nine65-python ...    # Full (1,351)
  cargo test -p nine65-extreme-tests --features extreme-tests --release  # Extreme (85)
  cargo test -p nine65 --lib --release -- bootstrap              # Filter by area
  cargo test -p nine65 --lib --release -- --nocapture             # See output

RUN
  cargo run -p nine65 --release --bin nine65_v7_demo              # Full system demo
  cargo run -p nine65 --release --bin nine65_bench                # Benchmark harness
  cargo run -p nine65 --release --bin security_estimator_baseline # Lattice estimator
  cargo run -p nine65 --release --bin fhe_demo                    # Interactive FHE demo

BENCH (Criterion)
  cargo bench -p nine65 --bench timing                            # Operation timing
  cargo bench -p nine65 --bench throughput                        # Throughput
  cargo bench -p nine65 --bench fhe_scaling                       # FFT scaling
  cargo bench -p nine65 --bench adaptive_rayon --features parallel # Adaptive threads

QUALITY
  cargo clippy --workspace --exclude nine65-python --exclude nine65-wasm
  cargo fmt --all -- --check
  cargo doc --open -p nine65

COVERAGE
  cargo llvm-cov -p nine65 --lib --release --html
```

3. Sectioned page links with descriptions

---

## Phase 3: Foundation Pages (5 new)

### Task 4: getting-started.md

**File:** `NINE65-Rust-Guide/docs/getting-started.md`

Step-by-step "your first FHE computation":
1. Check prerequisites (rustc --version)
2. Build the workspace
3. Run the demo (cargo run --bin nine65_v7_demo)
4. Write your own: encrypt 42, encrypt 7, add them, decrypt → 49
5. Complete code example using SecureConfig::secure_128(), RNSFHEContext, encrypt, add, decrypt
6. "Where to go next" links

### Task 5: cargo-reference.md

**File:** `NINE65-Rust-Guide/docs/cargo-reference.md`

Every cargo subcommand from `cargo --list` relevant to NINE65:
- build, check, test, bench, run, clean — with NINE65-specific flags
- clippy, fmt, doc — quality tools
- tree, metadata — dependency inspection
- install (nextest, llvm-cov, pretty-test)
- rustc, rustdoc — compiler pass-through
- add, remove — dependency management
- fetch, update, vendor — lockfile management
- Each with: what it does, NINE65-specific example, expected output

### Task 6: rust-patterns.md

**File:** `NINE65-Rust-Guide/docs/rust-patterns.md`

Rust features as they appear in NINE65:
- `Nine65Result<T>` and the `?` operator — error propagation
- `#[cfg(...)]` feature gating — how allow_insecure works
- `Zeroize` + `ZeroizeOnDrop` — secure memory clearing
- `thiserror::Error` derive — the error taxonomy
- `pub(crate)` visibility — internal vs public API
- Trait bounds (`impl FheRng`) — polymorphic RNG
- `Arc<Vec<u64>>` in ManaStream — shared ownership without cloning
- `#![forbid(unsafe_code)]` and `#![deny(clippy::float_arithmetic)]`
- Generics and lifetimes as they appear (`BFVEncryptor<'a>`, `ParallelEncryptor<'a>`)
- The prelude pattern — what `use nine65::prelude::*` gives you

### Task 7: feature-flags.md

**File:** `NINE65-Rust-Guide/docs/feature-flags.md`

Each feature flag with:
- What it enables (specific modules/types that become available)
- When to use it
- Behavioral changes
- Example cargo command
- Combinations that make sense

Flags: ntt_fft, parallel, clockwork, exact_rational, shadow-entropy, adaptive-threading, accelerated, deterministic_rng, allow_insecure, serde, extreme-tests

### Task 8: glossary.md

**File:** `NINE65-Rust-Guide/docs/glossary.md`

~50 terms with anchor IDs for cross-linking:
BFV, BKZ, bootstrap, BSK, CBD, ciphertext, CRT, constant-time, Core-SVP, delta, DualRNS, evaluation key, Galois, GRO, GSO, HE Standard, K-Elimination, KSK, RLWE, lattice, MATZOV, millibits, modswitch, Montgomery, NTT, NTT-friendly, noise budget, permille, plaintext modulus, polynomial ring, public key, RNS, relinearization, rescaling, secret key, SIMD, ternary secret, Three-Lock, U256, zeroize

Each: term, one-sentence definition, link to relevant page

---

## Phase 4: Using the System Pages (7 new)

### Task 9: cookbook.md

**File:** `NINE65-Rust-Guide/docs/cookbook.md`

Code-first reference. Two-column style (description | code). Sections:
1. Basic BFV: encode → encrypt → add → decrypt
2. DualRNS FHE: RNSFHEContext setup → encrypt → mul → decrypt
3. Auto-bootstrap: unlimited depth chain
4. Batch encoding: pack multiple values
5. Galois rotation: rotate slots
6. Key generation: all key types
7. Key serialization roundtrip
8. Neural evaluation: encrypted ReLU, Sigmoid
9. Noise budget inspection
10. GSO-FHE: depth tracking with collapses
11. Kiosk: create Bullet unit, compute, destroy

### Task 10: key-management.md

**File:** `NINE65-Rust-Guide/docs/key-management.md`

Key types and relationships:
- SecretKey (ternary polynomial, ZeroizeOnDrop)
- PublicKey (pk0, pk1)
- EvaluationKey (relinearization)
- BootstrapKey (BSK — working sk encrypted under boot params)
- KeySwitchKey (KSK — boot→work key switching)
- GaloisKey / GaloisKeySet
- Key generation: generate() vs generate_secure()
- Memory safety: Zeroize, ZeroizeOnDrop, SecretPoly, SecretScalar
- security/key_manager.rs: key lifecycle management

### Task 11: batch-and-galois.md

**File:** `NINE65-Rust-Guide/docs/batch-and-galois.md`

- BatchEncoder: pack N values into one ciphertext
- Coefficient batching vs SIMD slot batching (future)
- Encode/decode API
- GaloisEngine: automorphisms σ_k (X → X^k)
- Slot rotation: left/right via exponent 5^r mod 2N
- GaloisKey generation per rotation distance
- GaloisEvaluator: apply rotation to ciphertext
- Limitations: t ≡ 1 (mod 2N) required for true SIMD

### Task 12: neural-ops.md

**File:** `NINE65-Rust-Guide/docs/neural-ops.md`

The FHE neural evaluator:
- ActivationType enum: None, ReLU, LeakyReLU, Sigmoid, Tanh, Softmax, GELU
- Underlying primitives:
  - MQ-ReLU: O(1) sign detection (~20ns vs ~2ms comparison circuit)
  - PadeEngine: Pade [4/4] for exp/sigmoid/tanh (~200ns vs ~50ms polynomial)
  - IntegerSoftmax: exact sum guarantee
  - CyclotomicPhase: ring-native sin/cos
  - MobiusInt: signed arithmetic without M/2 threshold failure
- DenseLayer, NeuralNetwork, FHENeuralEvaluator types
- Performance: 1,000-100,000x faster than standard FHE polynomial approximation
- Code examples for each activation

### Task 13: mana.md

**File:** `NINE65-Rust-Guide/docs/mana.md`

MANA accelerator architecture:
- Lane: single CRT prime channel (embarrassingly parallel, O(N) branchless)
- ManaStream: multi-lane CRT with Arc<Vec<u64>> shared primes
- StreamOps trait
- ParallelStream (requires `parallel` feature)
- AnchorContext, KAnchor
- GsoSwarm, QbitAgent (GSO within MANA)
- How it relates to AcceleratedFHE in nine65/accelerated.rs
- When to use MANA vs raw RNSFHEContext

### Task 14: entropy.md

**File:** `NINE65-Rust-Guide/docs/entropy.md`

- ShadowHarvester: LFSR + counter mixing, deterministic, NOT thread-safe
  - new(), with_seed(), next_u64()
  - When to use: testing, reproducible benchmarks
- SecureRng: OS CSPRNG wrapper
  - When to use: production key generation
- FheRng trait: polymorphic RNG interface
- CRT Shadow entropy (crt_shadow.rs): harvesting entropy from computation byproducts
- ShadowEntropyMonitor: adaptive threading based on entropy
- Deterministic vs secure: decision tree
- Thread safety: one ShadowHarvester per thread

### Task 15: fhe-service.md

**File:** `NINE65-Rust-Guide/docs/fhe-service.md`

- HTTP session management for FHE
- Serialization/deserialization of contexts and ciphertexts
- Cloud Run deployment (nine65-v7, us-south1, currently disabled)
- How the service wraps RNSFHEContext for network transport
- The serde feature flag

---

## Phase 5: How It Works Pages (9 new + 3 updates)

### Task 16: bfv-scheme.md

**File:** `NINE65-Rust-Guide/docs/bfv-scheme.md`

BFV FHE explained:
- Plaintext space Z_t, ciphertext space R_q
- Delta = floor(q/t) — the scaling factor
- Encoding: m → delta * m (polynomial)
- Encryption: ct = (pk0*u + e1 + delta*m, pk1*u + e2) where u random, e error
- Decryption: m = round(t * (c0 + c1*s) / q) mod t
- Addition: component-wise add of ciphertext pairs
- Multiplication: tensor product → degree-3 → relinearize → degree-2
- Why noise grows: each operation adds/amplifies error terms
- The two APIs: BFVEncoder/Encryptor/Decryptor vs RNSFHEContext
  - Basic BFV (ops/encrypt.rs): single modulus, learning
  - DualRNS (ops/rns_fhe.rs): production, K-Elimination, bootstrap
- BFVEvaluator vs TrackedEvaluator: checked vs unchecked operations

### Task 17: bfv-params.md

**File:** `NINE65-Rust-Guide/docs/bfv-params.md`

Parameter meanings and selection:
- n (ring dimension): security vs performance tradeoff, must be power of 2
- q (ciphertext modulus): product of NTT-friendly primes, larger = more depth but less security
- t (plaintext modulus): 65537 in all configs, must satisfy NTT constraints
- CBD parameter (eta): error distribution width, larger = more security
- NTT-friendly primes: q ≡ 1 (mod 2N) for primitive root existence
- The HE Standard v1.1 bounds table
- How NINE65 chose its parameters (n, primes, claimed security)
- params/primes.rs, params/validation.rs, params/exact_params.rs
- SecureConfig internals: new_verified() runs the lattice estimator at construction

### Task 18: k-elimination.md

**File:** `NINE65-Rust-Guide/docs/k-elimination.md`

Deep dive:
- The problem: RNS division requires full CRT reconstruction → O(k²)
- The insight: use anchor primes to track the quotient k
- The algorithm:
  ```
  V = v_alpha (mod alpha_cap)
  V = v_beta (mod beta_cap)
  k = (v_beta - v_alpha) * alpha_cap_inv (mod beta_cap)
  V = v_alpha + k * alpha_cap
  ```
- KElimConfig: Minimal, Standard, FHE, MaxPrecision
- KElimBuilder: custom alpha/beta primes
- capacity_bits(): how much range you have
- capacity_proximity(): check if approaching limits
- The 3-anchor → 5-anchor fix: why 3 anchors (94-bit product) failed for secure_128
- DualRNSContext::for_fhe() always uses 5 anchors (159-bit capacity)
- Coq proof: k_elimination_complete
- Performance: O(k) vs O(k²) Mixed Radix Conversion

### Task 19: ntt.md

**File:** `NINE65-Rust-Guide/docs/ntt.md`

- What NTT does: polynomial multiplication in O(N log N) instead of O(N²)
- Coefficient domain vs evaluation domain (NTT domain)
- Cooley-Tukey decimation-in-time algorithm
- Two engines: NTTEngine (DFT, basic) vs NTTEngineFFT (FFT-based, 500-2000x faster)
- The ntt_fft feature flag (default: on)
- NTT-friendly primes: why q ≡ 1 (mod 2N) is required
- Forward transform: coefficients → evaluation points
- Inverse transform: evaluation points → coefficients
- Pointwise multiplication in NTT domain
- Montgomery form throughout NTT butterfly operations
- RingPolynomial invariant: always stored in coefficient domain

### Task 20: montgomery.md

**File:** `NINE65-Rust-Guide/docs/montgomery.md`

- What Montgomery form is: represent a as aR mod q, arithmetic without division
- Why constant-time matters: timing side-channel attacks
- MontgomeryContext: basic Montgomery reduction
- PersistentMontgomery: values STAY in Montgomery form (no repeated conversion)
- PersistentPolynomial: polynomial with all coefficients in Montgomery form
- BarrettContext: alternative modular reduction (used where Montgomery isn't optimal)
- HybridModContext: combines Barrett + Montgomery
- How it integrates with NTT butterfly operations
- Coq proof: Montgomery.v (montgomery_reduce(a * R) == a mod q)

### Task 21: three-lock.md

**File:** `NINE65-Rust-Guide/docs/three-lock.md`

- Why three locks: protecting the plaintext during re-encryption
- Layer 1 (Shannon): information-theoretic mask over everything
- Layer 2 (Montgomery): RLWE encryption around masked ciphertext
- Layer 3 (Clockwork): protected re-encryption in registers
- Lock sequence: Shannon mask → Montgomery RLWE encrypt → Clockwork re-encrypt
- Unlock sequence: Montgomery decrypt → Clockwork decrypt+re-encrypt → Shannon unmask
- SecurityTier: Tier1Minimal, Tier2Production, Tier3Maximum
- ThreeLockBootstrap::new(), bootstrap(), bootstrap_stats()
- MaskLayer, OuterLayer, OuterCiphertext types
- Relationship to ClockworkBootstrap (ops/bootstrap.rs) — Three-Lock wraps Clockwork

### Task 22: gso-fhe.md

**File:** `NINE65-Rust-Guide/docs/gso-fhe.md`

- Gravitational Swarm Optimization for noise bounding
- NoiseEstimate: distance, basin_id, mul_depth, collapse_count
- Basin assignment: each plaintext maps to an attractor basin
- Collapse: when noise exceeds basin radius, swarm reconverges (~1ms vs 100-1000ms bootstrap)
- GSOFHEContext: wraps RNSFHEContext with GSO tracking
- GSOCiphertext: ciphertext + NoiseEstimate
- Shadow entropy byproduct of swarm dynamics
- Depth benchmarks: benchmark_symmetric_max_depth_secure_128
- Relationship to bootstrap: GSO is the noise model, bootstrap is the refresh mechanism

### Task 23: boundary.md

**File:** `NINE65-Rust-Guide/docs/boundary.md`

- CapacityRegion: Safe, Warn80, Warn90, Critical
- capacity_proximity_bits(value_bits, capacity_bits) → CapacityReport
- post_switch_margin_bits(value_bits, new_capacity_bits) → PostSwitchMargin
- KElimination::capacity_proximity(value: u128)
- DualRNSContext methods: anchor_capacity_bits() (159), check_k_proximity(), check_intermediate_proximity(), max_intermediate_bits()
- All 3 secure configs: intermediate values at ~45-47% capacity — safe
- PyO3: FHEContext::boundary_report()
- WASM: WasmFHEContext::boundary_report()

### Task 24: kiosk.md

**File:** `NINE65-Rust-Guide/docs/kiosk.md`

Self-destructing FHE computation units:
- KioskUnitType: Bullet (single-use), Capsule (multi-use), Fuse (time-limited)
- KioskLifecycle trait: activate(), compute(), destroy()
- UnitStatus: Created, Active, Computing, Destroyed
- FoldOperator: algebraic folding renders RNS state meaningless before zeroing
- DestructionSequence: Fold + Zero + Receipt generation
- DestructionReceipt: SHA-256 proof of proper destruction
- EntropyFuse: Shadow entropy countdown to self-destruction
- Inv8CheckLane: redundant RNS channel for DDoS/inversion attack detection
- ReceiptVerifier: verify destruction happened correctly

### Task 25: circuit-compiler.md

**File:** `NINE65-Rust-Guide/docs/circuit-compiler.md`

Bootstrap-free FHE circuit compiler:
- OpType: Add, Multiply, Rescale, Relinearize, Rotate, Input, Output
- Circuit DAG representation
- Static noise analysis: pre-compute modulus chain for circuit depth
- NOTE: This module allows float arithmetic for static analysis (#![allow(clippy::float_arithmetic)]) — exception to the zero-float rule because it's compile-time tooling, not runtime computation
- How to use: define circuit → analyze → get parameter recommendations

### Task 26: Update architecture.md

**File:** `NINE65-Rust-Guide/docs/architecture.md`

Add sections for:
- The two encryption APIs (basic BFV vs DualRNS)
- Kiosk subsystem overview
- Circuit compiler overview
- Neural operations overview
- Three-Lock vs Clockwork bootstrap distinction
- Updated system diagram (Mermaid) showing all subsystems
- The prelude: what `use nine65::prelude::*` gives you

### Task 27: Update crate-map.md

**File:** `NINE65-Rust-Guide/docs/crate-map.md`

Add ALL missing files:
- ops/: encrypt.rs, homomorphic.rs, batch.rs, galois.rs, neural.rs, parallel.rs, rns_mul.rs, symmetric_bootstrap.rs
- arithmetic/: barrett.rs, boundary.rs, bounded_rns.rs, ct_mul_exact.rs, cyclotomic_phase.rs, exact_coeff.rs, exact_divider.rs, integer_math.rs, integer_softmax.rs, mobius_int.rs, mq_relu.rs, order_finding.rs, pade_engine.rs, persistent_montgomery.rs, rational_bridge.rs, transcendental_backend.rs, valuation.rs
- bootstrap/: three_lock.rs, mask.rs, outer.rs, clockwork.rs
- kiosk/: all submodules
- compiler.rs, kat.rs, accelerated.rs, comprehensive_benchmarks.rs, errors.rs
- ring/: polynomial.rs, pool.rs
- security/: gro_gate.rs, integrity.rs, key_manager.rs, secret_data.rs

### Task 28: Update bootstrap.md

**File:** `NINE65-Rust-Guide/docs/bootstrap.md`

Add section clarifying:
- ops/bootstrap.rs has ClockworkBootstrap (the 3-phase noise reset)
- bootstrap/ module has ThreeLockBootstrap (3-layer security wrapping)
- Link to new three-lock.md for details
- When to use which

---

## Phase 6: Tools & Testing Pages (3 new)

### Task 29: benchmarks.md

**File:** `NINE65-Rust-Guide/docs/benchmarks.md`

- nine65_bench binary: args (--config, --max-depth, --output, --a, --b), JSON output
- 6 Criterion bench files:
  - timing.rs: per-operation latency
  - throughput.rs: operations per second
  - fhe_scaling.rs: O(N log N) FFT scaling across ring dimensions
  - adaptive_rayon.rs: adaptive threading vs static Rayon (requires --features parallel)
  - threading_comparison.rs: thread count comparison
  - nine65_vs_seal_comparison.rs: native Rust vs SEAL comparison (Montgomery, NTT, etc.)
- comprehensive_benchmarks.rs: noise growth, batch ops, depth limits (run as tests)
- "Do changes reflect in benchmarks?" YES — all benches import from nine65::
- How to read Criterion output
- Performance baselines table (from CLAUDE.md)

### Task 30: clockwork-core.md

**File:** `NINE65-Rust-Guide/docs/clockwork-core.md`

Formal-spec RNS:
- Design invariants INV-1 through INV-7
- RnsBasis: CRT basis management
- Bound: sound bound tracking (|Center(X)| < 2^H(X))
- DecodeToQ: decode from RNS back to Z_q
- k_eliminate (Garner reconstruction)
- GearStack: modulus chain management
- GroGate: golden-ratio oscillator timing gates
- TripleRedundant: integrity verification
- key_lifecycle: secure key memory management (only unsafe code)
- How clockwork-core relates to nine65's arithmetic/ module

### Task 31: kat.md

**File:** `NINE65-Rust-Guide/docs/kat.md`

Known Answer Tests:
- What KATs are and why they matter (regression, cross-platform, certification)
- KATVector: test vectors with seed, config, operation, expected result
- KATOperation: EncryptDecrypt, HomomorphicAdd, MulPlain, CtCtAdd
- KATResult: passed, expected, actual, ct_hash
- STANDARD_KATS: pre-defined vectors
- run_all_kats(): run all and check
- When to run KATs: after code changes, before releases, on new platforms

---

## Phase 7: Reference Pages (1 new)

### Task 32: error-reference.md

**File:** `NINE65-Rust-Guide/docs/error-reference.md`

Every Nine65Error variant:
- K-Elimination: NotCoprime, RangeOverflow, ModulusZero, AnchorZero, InexactDivision
- GSO-FHE: NoiseOverflow, DepthExceeded
- Order Finding: OrderNotFound, NotCoprimeToModulus
- Arithmetic: Overflow, InvalidParameter
- Crypto: DecryptionFailed, KeyGenFailed, SecurityLevelNotMet
- Encoding: MessageOutOfBounds, InvalidPolynomialDegree, KeyRegimeMismatch
- NTT: NTTConfigError
- Config: ConfigError
- Batching: BatchingNotSupported, TooManySlotValues, NoModularInverse
- Serialization errors

For each: error message, what causes it, which theorem it maps to, what to do about it

---

## Phase 8: Cross-Linking & Polish

### Task 33: Add "Where to go next" footers to all pages

Every page gets 2-3 contextual cross-links at the bottom.

### Task 34: Add Mermaid system diagram to architecture.md

Interactive diagram showing all subsystem connections with clickable links to their pages.

### Task 35: Final review and commit

Verify all 37 pages render, all cross-links work, sidebar navigation correct, search works.

---

## Execution Order

Phases can be parallelized:
- Phase 1 (theme) MUST be first
- Phase 2 (landing page) after Phase 1
- Phases 3-7 can be parallelized (pages are independent)
- Phase 8 (polish) MUST be last

Recommended parallel batches:
- Batch A: Phase 3 (foundation pages)
- Batch B: Phase 4 (using the system pages)
- Batch C: Phase 5 (how it works pages)
- Batch D: Phase 6+7 (tools + reference pages)
