# hackfate.us v7 Complete Site Update — Design Document

**Date**: 2026-02-21
**Status**: Approved
**Author**: Acid + Claude

---

## Objective

Update hackfate.us from v5 to v7, introducing the Three-Lock Bootstrap architecture, Kiosk deployment model, real benchmarks, and updated proof listings — all without disclosing proprietary implementation details.

## Disclosure Rules

| Category | Show | Don't Show |
|----------|------|------------|
| Three-Lock names | Shannon Mask, RLWE Outer, Clockwork | How any lock is constructed |
| Three-Lock purpose | Defense class per lock (info-theoretic / computational / re-encryption) | Parameters, mask generation, Montgomery internals |
| Bootstrap paths | 3 paths exist (circular, KSK, auto) | modswitch/key-switch internals |
| Benchmarks | Raw v7 timing numbers, standalone | Competitor comparisons |
| Proofs | Proof names + property verified | Links to proof files, formulas, definitions |
| Kiosk | Business concept (BULLET/CAPSULE/FUSE) | Fold-chain mechanics, INV-8, entropy rate math |
| Stack layers | L0-L3 names + what they solve | Algorithms, code, parameter derivations |
| Security level | NIST Level 1 verified, show all lattice estimator numbers | Don't overclaim 192/256 as meeting those targets |
| Test counts | 935+ tests, 0 failures | Test names, what specific tests verify |

## Security Claims Strategy

- Claim NIST Post-Quantum Level 1 (128-bit) as **verified** via lattice estimator
- Show actual numbers for all configs: 129/159/226 bits honestly
- State external cryptographic audit is pending
- Let the numbers speak — no competitor comparisons

## Site Structure

### Navigation (Updated)
```
Research | Technology | Three-Lock | Innovations | Benchmarks | Demo | Proofs | Kiosk | SaaS | About | Contact
```

### Pages to Update (8)

1. **index.html** — v5→v7, new hero, Three-Lock headline, stats strip
2. **benchmarks.html** — real v7 numbers in clean tables
3. **nine65-saas.html** — v5→v7, updated stats
4. **proofs.html** — all v7 proofs with one-line descriptors, no links
5. **technology.html** — fill with conceptual L0-L3 stack
6. **demo.html** — v5→v7 text updates
7. **clockwork-bootstrap.html** — redirect to three-lock.html
8. **All navs/footers** — updated across every page

### New Pages (2)

9. **three-lock.html** — Three-Lock Bootstrap architecture
10. **kiosk.html** — Kiosk deployment model

## Per-Page Content

### index.html (Homepage)

**Hero**: "NINE65 v7 — Bootstrap Complete"
**Subtitle**: "Unlimited-depth FHE with Three-Lock conjunction security"

**Three headline cards**:
- Unlimited Depth — Three verified bootstrap paths, zero depth ceiling
- Three-Lock Protection — Conjunction security: all three layers must be broken simultaneously
- Formally Verified — 70+ machine-checked proofs in Coq and Lean4

**Stats strip**: 935+ tests | 7 crates | 70+ proofs | 3 bootstrap paths | 128-bit verified

**CTAs**: Three-Lock Architecture → three-lock.html, Kiosk Model → kiosk.html

### three-lock.html (NEW)

**Hero**: "Three-Lock Bootstrap — Protected Re-Encryption"

**Section 1: The Problem**
Bootstrap is the moment FHE is most vulnerable — the ciphertext must be re-encrypted, briefly exposing the computation boundary. Every FHE system has this exposure window. NINE65 v7 protects it with three independent, nested security layers.

**Section 2: Three Locks**

Three cards:
- **Lock 1: Shannon Mask** (Outermost) — Information-theoretic protection. Even with unlimited computation, the masked values reveal zero bits about the plaintext. Based on one-time pad theory.
- **Lock 2: RLWE Outer Encryption** (Middle) — Computational hardness. Even if the Shannon mask fails, the ciphertext is still protected by a lattice-based encryption layer whose security reduces to the Ring-LWE problem.
- **Lock 3: Clockwork Inner** (Core) — The actual re-encryption mechanism. Depth-1 homomorphic operation that refreshes noise for unlimited depth. Protected by both outer layers during execution.

**Section 3: Conjunction Property**
An attacker must break ALL THREE simultaneously — information-theoretic + computational + algebraic. Breaking one reveals nothing useful because the remaining locks still protect the data.

**Section 4: Three Bootstrap Paths**

| Path | Description | Status |
|------|-------------|--------|
| Circular | boot_sk derived from work_sk | Verified exact |
| Non-Circular (KSK) | Independent boot_sk, gadget key switch | Verified exact |
| Auto-Bootstrap | Automatic trigger on noise threshold | Verified 10+ chained muls |

**Section 5: Verification**
- 78 bootstrap-specific tests, all passing
- Formal proofs covering circular security, modswitch correctness, key generation
- Pending formal external cryptographic audit

### kiosk.html (NEW)

**Hero**: "The Kiosk Model — Self-Destructing FHE"

**Section 1: The Problem with Centralized FHE**
Centralized FHE servers hold keys in memory continuously, exposing a persistent attack surface. The algebraic homomorphism that enables encrypted computation also creates structural vulnerabilities that cannot be patched — they are inherent to the design.

**Section 2: The Inversion**
Instead of running FHE on provider-owned servers, ship self-destructing computation units to consumer hardware. The provider sells cryptographic capability, not compute time.

**Section 3: Three Deployment Models**

| Model | Scope | Analogy |
|-------|-------|---------|
| **BULLET** | Single computation | One round of ammunition |
| **CAPSULE** | N computations | Magazine |
| **FUSE** | Time-limited window | Timed demolition charge |

**Section 4: Self-Destruction**
Units exist only during active computation (milliseconds of attack surface). After computation completes, the destruction sequence fires: cryptographic state is folded into algebraic meaninglessness and zeroed from memory. A destruction receipt (cryptographic hash) proves the computation occurred and the unit self-destructed, without revealing input, output, or keys.

**Section 5: Shadow Entropy Metering**
Every computation produces an irreducible cryptographic byproduct — shadow entropy. This byproduct serves as both the metering mechanism and the tamper detection system. The amount of shadow entropy a computation produces is deterministic and predictable from the circuit description (which is always public in FHE). Enforcement is mathematical, not contractual.

**Section 6: Dead Man's Switch**
Five independent triggers fire immediate destruction: integrity mismatch, memory violation, clock anomaly, heartbeat timeout, and client abort. No graceful shutdown. The adversary gets nothing.

**Section 7: Status**
Core FHE engine: production-ready (935+ tests). Kiosk infrastructure: in development. Shadow entropy harvesting: implemented. Fold/destruction/receipt: implementation phase.

### benchmarks.html

**Hero**: "NINE65 v7 Benchmarks"
**Label**: "Internal release build. CPU only, no GPU. All timings from Criterion benchmarks on production hardware."

**Table 1: FHE Operations**

| Operation | secure_128 | secure_192 |
|-----------|------------|------------|
| Encrypt | 23.56ms | 61.59ms |
| Add | 0.83ms | 2.10ms |
| Multiply (K-Elimination rescale) | 152.13ms | 459.02ms |
| Decrypt | 11.06ms | 29.00ms |

**Table 2: Depth Chains (Symmetric Mode)**

| Config | Depth | Total Time | Avg per Multiply |
|--------|-------|------------|-----------------|
| secure_128 | 50 | 6.29s | 125.81ms |
| secure_192 | 50 | 10.10s | 201.91ms |

**Table 3: RNS Arithmetic (4-lane)**

| Operation | Latency | Throughput |
|-----------|---------|------------|
| ADD | 65.7ns | 15.2M ops/s |
| MUL | 95.6ns | 10.5M ops/s |

**Table 4: Lattice Security (Post-Quantum)**

| Config | n | log2(q) | Min Attack Cost (log2 ops) |
|--------|---|---------|---------------------------|
| secure_128 | 4096 | 89.08 | 129 |
| secure_192 | 8192 | 145.08 | 159 |
| secure_256 | 16384 | 203.38 | 226 |

**Security note**: "NIST Post-Quantum Level 1 (128-bit) verified. Higher configurations available with measured attack costs shown above. Formal external cryptographic audit pending."

### proofs.html

**Hero**: "Formal Verification — 70+ Machine-Checked Proofs"
**Methodology**: "All proofs verified with Coq 8.18+ and Lean4 + Mathlib. Zero admitted statements (Coq). Zero sorry statements (Lean4). Three axioms used: Core-SVP hardness assumption, Ring-LWE to SVP reduction, BKZ cost model."

**Coq Proofs (14)**

| Proof | Property Verified |
|-------|-------------------|
| KElimination | Exact overflow recovery in RNS division |
| GSOFHE | Depth management correctness for encrypted circuits |
| CRTShadowEntropy | Shadow entropy statistical independence from inputs |
| OrderFinding | Multiplicative order detection in modular groups |
| MQReLU | Integer activation function preserves FHE noise bounds |
| IntegerSoftmax | Exact integer softmax output sums correctly |
| MontgomeryPersistent | Montgomery form persistence across chained operations |
| MobiusInt | Mobius function integer arithmetic roundtrip correctness |
| CyclotomicPhase | Cyclotomic polynomial phase evaluation correctness |
| PadeEngine | Pade approximant identity and zero properties |
| ExactCoefficient | Exact polynomial coefficient extraction |
| StateCompression | Compressed state preserves computation integrity |
| SideChannelResistance | Constant-time operation execution verification |
| EncryptedQuantum | Quantum operation simulation in encrypted domain |

**Lean4 Proofs (17+ core files)**

| Proof | Property Verified |
|-------|-------------------|
| Basic | Core algebraic definitions and axioms |
| ShadowEntropy | NIST SP 800-22 statistical test compliance |
| ZMod | Modular arithmetic foundations and inverses |
| AHOP/Algebra | Post-quantum algebraic structure properties |
| AHOP/Hardness | Hardness assumption formalization |
| AHOP/Parameters | Parameter instantiation at 128-bit security |
| Lattice/CRT | Chinese Remainder Theorem over lattice structures |
| Montgomery | Montgomery multiplication correctness |
| GSOFHE | Encrypted circuit depth bound proofs |
| MQReLU | Integer ReLU noise bound preservation |
| IntegerSoftmax | Integer softmax summation exactness |
| OrderFinding | Modular order detection correctness |
| PadeEngine | Rational approximation identities |
| MobiusInt | Integer Mobius function properties |
| CyclotomicPhase | Phase polynomial evaluation |
| ExactCoefficient | Coefficient extraction exactness |
| StateCompression | State compression integrity |
| SideChannel | Timing-independent operation proofs |
| EncryptedQuantum | Encrypted quantum gate simulation |

**Innovation Proofs (Lean4, 24 files)**

Listed by number (02-25) with one-line property descriptions covering: persistent Montgomery, integer neural networks, cyclotomic phase, binary GCD, PLMG rails, DC helix, Grover swarm, WASSAN noise, time crystal, GSO, MANA accelerator, RayRam, Clockwork Prime, bootstrap-free FHE, real-time FHE.

**NIST Compliance Proofs (14 files)**

Covering: AHOP security, ring definitions, IND-CPA game formalization, homomorphic security reduction, NIST parameter compliance, K-Elimination correctness, security lemmas, complete security argument.

### technology.html

**Hero**: "The Stack — Integer-Only FHE from First Principles"

Four conceptual layers:

- **L0: Exact Arithmetic** — All computation in exact integer and rational arithmetic. Zero floating-point at any layer. Deterministic, bit-identical results across platforms. Formally verified.
- **L1: K-Elimination** — Exact division in Residue Number Systems. Solves a 60-year-old bottleneck that prevented practical RNS-based FHE. No other system has this.
- **L2: Integrity Verification** — RNS encoding with algebraic integrity checking. Corrupted operations detected at the first computation step, not at the end of the circuit.
- **L3: Three-Lock FHE** — Bootstrap-free homomorphic encryption with unlimited depth through Three-Lock conjunction security. Three independent protection layers during re-encryption.

"Implementation details and source code available under licensing agreement."

### nine65-saas.html

- All v5 references → v7
- Stats updated: 935+ tests | 7 crates | 3 bootstrap paths
- Three-Lock mentioned as security differentiator
- Roadmap updated to reflect current status

### demo.html

- v5 → v7 text updates
- "Preview mode — simulated data" retained
- Add note: "Protected by Three-Lock conjunction security"

### clockwork-bootstrap.html

Meta refresh redirect to three-lock.html. Preserves existing URLs/bookmarks.

## Design System

- Keep existing dark cyberpunk CSS (styles.css untouched)
- Match existing HTML patterns: page-hero, section, container, card grids
- Match existing meta/OG/Twitter card patterns
- Accessible: skip links, ARIA labels, semantic HTML
- Responsive: existing mobile nav toggle pattern
- No new JavaScript required (static content pages)

## Deployment

- Clone DeuxAxios/hackfate repo
- Create branch for v7 update
- Apply all changes
- PR to main branch
- GitHub Pages auto-deploys from main

## Risk Mitigation

- No implementation details disclosed
- No links to proof source files
- No competitor comparisons in benchmarks
- Security claims limited to what lattice estimator proves (Level 1)
- Higher config numbers shown honestly without overclaiming
- External audit clearly noted as pending
- Kiosk page marks infrastructure as "in development"
