# hackfate.us v7 Site Update — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Update hackfate.us from v5 to v7, introducing Three-Lock Bootstrap architecture page, Kiosk deployment model page, real benchmarks, updated proofs, and filled technology page — without disclosing implementation details.

**Architecture:** Static HTML site hosted on GitHub Pages via `DeuxAxios/hackfate` repo. Dark cyberpunk theme (styles.css). No build tools — raw HTML/CSS/JS. All pages share identical nav/footer patterns. Two new pages (three-lock.html, kiosk.html), eight updated pages.

**Tech Stack:** HTML5, CSS3 (existing styles.css with CSS custom properties), vanilla JS (existing script.js), GitHub Pages deployment.

**Repo:** `DeuxAxios/hackfate` (GitHub Pages, deploys from `main`)

**Design Doc:** `docs/plans/2026-02-21-hackfate-v7-site-update-design.md`

---

## Shared Patterns Reference

### Updated Navigation HTML (used in ALL pages)

```html
<nav class="nav" aria-label="Primary">
    <div class="nav-container">
        <a href="index.html" class="nav-logo">HACKFATE</a>
        <div class="nav-links" id="nav-links">
            <a href="research.html">Research</a>
            <a href="technology.html">Technology</a>
            <a href="three-lock.html">Three-Lock</a>
            <a href="innovations.html">Innovations</a>
            <a href="benchmarks.html">Benchmarks</a>
            <a href="demo.html">Demo</a>
            <a href="proofs.html">Proofs</a>
            <a href="kiosk.html">Kiosk</a>
            <a href="nine65-saas.html">SaaS</a>
            <a href="about.html">About</a>
            <a href="contact.html" class="nav-cta">Contact</a>
        </div>
        <button class="nav-toggle" type="button" aria-label="Toggle menu" aria-controls="nav-links" aria-expanded="false">
            <span></span>
            <span></span>
            <span></span>
        </button>
    </div>
</nav>
```

### Updated Footer HTML (used in ALL pages)

```html
<footer class="footer">
    <div class="container">
        <div class="footer-content">
            <div class="footer-brand">
                <span class="footer-logo">HACKFATE</span>
                <p>"Truth cannot be approximated."</p>
            </div>
            <div class="footer-links">
                <a href="research.html">Research</a>
                <a href="technology.html">Technology</a>
                <a href="three-lock.html">Three-Lock</a>
                <a href="innovations.html">Innovations</a>
                <a href="benchmarks.html">Benchmarks</a>
                <a href="proofs.html">Proofs</a>
                <a href="kiosk.html">Kiosk</a>
                <a href="nine65-saas.html">SaaS</a>
                <a href="about.html">About</a>
                <a href="contact.html">Contact</a>
            </div>
        </div>
        <div class="footer-bottom">
            <p>&copy; 2026 Anthony Diaz. All rights reserved.</p>
            <p>Proprietary technology protected. Public research available under respective licenses.</p>
            <p><a href="privacy.html" class="footer-legal-link">Privacy Policy</a></p>
        </div>
    </div>
</footer>
```

### Disclosure Rules (MUST follow for ALL content)

- Three-Lock: names + defense class only. No construction details.
- Benchmarks: raw v7 numbers only. No competitor comparisons.
- Proofs: names + property verified only. No links to source files. No formulas.
- Kiosk: business concept only. No fold-chain, INV-8, entropy rate math.
- Security: Claim Level 1 verified. Show all lattice numbers honestly. Note external audit pending.

---

## Task 1: Clone Repo and Create Branch

**Files:**
- Work in: local clone of `DeuxAxios/hackfate`

**Step 1: Clone the repo**

```bash
cd /home/acid/Projects
gh repo clone DeuxAxios/hackfate /home/acid/Projects/hackfate-site
cd /home/acid/Projects/hackfate-site
```

**Step 2: Create feature branch**

```bash
git checkout -b v7-complete-update
```

**Step 3: Verify site structure**

```bash
ls *.html
```

Expected: all existing HTML files listed.

---

## Task 2: Create three-lock.html (NEW PAGE)

**Files:**
- Create: `three-lock.html`

**Step 1: Create the full page**

Write `three-lock.html` with:
- Standard meta tags (match existing pattern from clockwork-bootstrap.html)
- Title: "Three-Lock Bootstrap | HackFate"
- OG description: "Protected re-encryption with Three-Lock conjunction security. Three independent defense layers protect the most vulnerable moment in FHE."
- Updated nav (from Shared Patterns above)
- Page hero: "Three-Lock Bootstrap" / "Protected Re-Encryption with Conjunction Security"

Main content sections:

**Section 1 — "The Vulnerable Moment"**: Bootstrap is when FHE re-encrypts to refresh noise — the ciphertext boundary is briefly exposed. Every FHE system has this window. NINE65 v7 protects it with three independent, nested security layers that must ALL be broken simultaneously.

**Section 2 — "Three Locks" (card grid, 3 cards)**:
- Card 1: **Shannon Mask** (Outermost) — "Information-theoretic protection. Even with unlimited computational power, masked values reveal zero bits about the plaintext. Grounded in one-time pad theory — the gold standard of theoretical cryptography."
- Card 2: **RLWE Outer Encryption** (Middle) — "Computational hardness barrier. Even if the Shannon mask were compromised, the ciphertext remains protected by lattice-based encryption. Security reduces to the Ring Learning With Errors problem — a foundation of post-quantum cryptography."
- Card 3: **Clockwork Inner** (Core) — "The re-encryption mechanism itself. A depth-1 homomorphic operation that refreshes noise budget for unlimited depth. During execution, it is shielded by both outer layers — never exposed directly."

**Section 3 — "Conjunction Security"**: An attacker must break all three locks simultaneously — information-theoretic certainty AND computational hardness AND algebraic structure. Compromising one layer reveals nothing useful because the remaining locks still protect the plaintext. This is defense-in-depth applied to cryptographic protocol design.

**Section 4 — "Three Bootstrap Paths" (table or card grid)**:
| Path | Security Model | Status |
|------|---------------|--------|
| Circular | boot_sk derived from work_sk | Verified — exact plaintext recovery |
| Non-Circular (KSK) | Independent boot_sk with gadget key switch | Verified — exact plaintext recovery |
| Auto-Bootstrap | Automatic trigger on noise threshold | Verified — 10+ chained multiplications |

**Section 5 — "Verification"**: 78 bootstrap-specific tests, all passing. Formal proofs covering circular security, modswitch correctness, and key generation. 935+ total workspace tests. Pending formal external cryptographic audit.

- Updated footer (from Shared Patterns above)
- Back-to-top link
- Script tag

Use existing CSS classes: `page-hero`, `section`, `container`, `section-title`, `achievement-grid`/`overview-grid`, `achievement-card`/`overview-card`, `modes-grid`, `mode-card`, `mode-badge`, `verification-grid`, etc. Match the visual style of clockwork-bootstrap.html.

**Step 2: Verify the page renders**

Open in browser or validate HTML structure.

**Step 3: Commit**

```bash
git add three-lock.html
git commit -m "feat: add Three-Lock Bootstrap architecture page"
```

---

## Task 3: Create kiosk.html (NEW PAGE)

**Files:**
- Create: `kiosk.html`

**Step 1: Create the full page**

Write `kiosk.html` with:
- Standard meta tags
- Title: "Kiosk Architecture | HackFate"
- OG description: "Self-destructing FHE on consumer hardware. Disposable computation units that exist only during active use."
- Updated nav
- Page hero: "The Kiosk Model" / "Self-Destructing FHE on Consumer Hardware"

Main content sections:

**Section 1 — "The Problem with Centralized FHE"**: Centralized FHE servers hold cryptographic keys in memory continuously, creating a persistent attack surface. The algebraic homomorphism that enables encrypted computation also creates structural vulnerabilities inherent to the deployment model — not bugs that can be patched, but consequences of the architecture itself.

**Section 2 — "The Inversion"**: Instead of running FHE on provider-owned servers, ship self-destructing disposable computation units to consumer hardware. The provider sells cryptographic capability, not compute time. Units exist only during active computation — milliseconds of attack surface instead of 24/7 exposure.

**Section 3 — "Three Deployment Models" (card grid, 3 cards)**:
- Card 1: **BULLET** — "Single computation. One encrypted operation, then destruction. Use case: secure voting, sealed-bid auctions, medical queries. Analogy: a single round of ammunition."
- Card 2: **CAPSULE** — "N computations. A measured allocation of encrypted operations before automatic destruction. Use case: recurring analytics, ML inference batches. Analogy: a magazine."
- Card 3: **FUSE** — "Time-limited window. Active for a defined duration, then destruction regardless of operations consumed. Use case: development, testing, burst workloads. Analogy: timed demolition charge."

**Section 4 — "Self-Destruction"**: Destruction is not cleanup — it is an integral part of the computation lifecycle. After computation completes, cryptographic state is transformed into algebraic meaninglessness and zeroed from memory in microseconds. A destruction receipt — a cryptographic hash of the final system state — proves the computation occurred and the unit self-destructed, without revealing inputs, outputs, or keys.

**Section 5 — "Shadow Entropy Metering"**: Every FHE computation produces an irreducible cryptographic byproduct: shadow entropy. This byproduct serves simultaneously as the billing mechanism and the tamper detection system. The amount of shadow entropy a computation produces is deterministic and predictable from the circuit description — which is always public in FHE. Enforcement is mathematical, not contractual. There is no DRM to crack, no license server to spoof.

**Section 6 — "Dead Man's Switch"**: Five independent triggers fire immediate destruction with no graceful shutdown: integrity mismatch, memory access violation, clock anomaly, heartbeat timeout, and client-initiated abort. If destruction fires from triggers 1-4, the client receives no result. The adversary gets nothing.

**Section 7 — "Development Status"** (use mode-card or similar grid):
- Core FHE Engine: Production-ready (935+ tests, 0 failures)
- Shadow Entropy Harvesting: Implemented
- Three-Lock Bootstrap: Verified (3 paths)
- Fold/Destruction/Receipt: Implementation phase
- WASM Compilation Target: Planned
- Consumer Provisioning: Design phase

- Updated footer
- Back-to-top link
- Script tag

**Step 2: Verify page renders**

**Step 3: Commit**

```bash
git add kiosk.html
git commit -m "feat: add Kiosk Architecture page — self-destructing FHE model"
```

---

## Task 4: Update index.html

**Files:**
- Modify: `index.html`

**Step 1: Update navigation**

Replace the existing `<nav>` block with the updated nav from Shared Patterns.

**Step 2: Update hero section**

Replace hero content:
- Title: keep "HACKFATE" glitch effect
- Tagline: "NINE65 v7 — Bootstrap Complete."
- Subtitle: "Unlimited-depth homomorphic encryption with Three-Lock conjunction security. Three independent defense layers. 935+ tests. 70+ formal proofs. Zero floating-point."
- Pillars: "Unlimited Depth | Three-Lock Security | Formally Verified"
- CTAs: "Three-Lock Architecture" → three-lock.html (primary), "View Benchmarks" → benchmarks.html (secondary), "Kiosk Model" → kiosk.html (secondary)

**Step 3: Update overview grid**

Replace the 6 overview cards with:
1. **Three-Lock Bootstrap** — "Protected re-encryption with three independent security layers. Conjunction security: all three must be broken simultaneously." → three-lock.html
2. **Kiosk Architecture** — "Self-destructing FHE on consumer hardware. Disposable computation units that exist only during active use." → kiosk.html
3. **NINE65 for SaaS** — "Process encrypted data without decryption. Sub-millisecond latency, zero floating-point." → nine65-saas.html
4. **Benchmarks** — "Real v7 performance data. Encrypt, multiply, decrypt timings. Lattice security analysis." → benchmarks.html
5. **Formal Proofs** — "70+ machine-checked proofs in Coq and Lean4. Zero admitted. Zero sorry." → proofs.html
6. **Technology** — "Integer-only FHE from first principles. Four-layer exact arithmetic stack." → technology.html

**Step 4: Update SaaS highlight section**

- Change "NINE65 FHE v5" → "NINE65 v7"
- Change "627 passing tests" → "935+ passing tests across 7 workspace crates"
- Change "Depth-50 circuits in 139ms" → "Depth-50 circuits in 6.29s (secure_128) with K-Elimination exact rescaling"
- Add card: "Three-Lock Protection" — "Conjunction security during bootstrap: Shannon mask, RLWE outer encryption, and Clockwork inner — all three must be broken simultaneously."

**Step 5: Update footer**

Replace footer with updated version from Shared Patterns.

**Step 6: Remove duplicate demo link in footer**

The current footer has `demo.html` listed twice. The updated footer from Shared Patterns fixes this.

**Step 7: Commit**

```bash
git add index.html
git commit -m "feat: update homepage to v7 — Three-Lock, Kiosk, real stats"
```

---

## Task 5: Rewrite benchmarks.html

**Files:**
- Modify: `benchmarks.html` (full rewrite of main content)

**Step 1: Update meta/nav/footer**

- Update title/description to reference v7
- Replace nav and footer with Shared Patterns

**Step 2: Replace hero**

Title: "NINE65 v7 Benchmarks"
Subtitle: "Internal release build. CPU only, no GPU acceleration. All timings from production hardware."

**Step 3: Replace main content with real benchmark tables**

Use HTML tables with existing CSS table styling or card layout. Four sections:

**Section 1 — "FHE Operations"**

| Operation | secure_128 | secure_192 |
|-----------|------------|------------|
| Encrypt | 23.56 ms | 61.59 ms |
| Add | 0.83 ms | 2.10 ms |
| Multiply (K-Elimination rescale) | 152.13 ms | 459.02 ms |
| Decrypt | 11.06 ms | 29.00 ms |

**Section 2 — "Depth Chains (Symmetric Mode)"**

| Config | Max Depth | Total Time | Avg per Multiply |
|--------|-----------|------------|-----------------|
| secure_128 | 50 | 6.29s | 125.81 ms |
| secure_192 | 50 | 10.10s | 201.91 ms |

**Section 3 — "RNS Arithmetic (4-lane)"**

| Operation | Latency | Throughput |
|-----------|---------|------------|
| ADD | 65.7 ns | 15.2 M ops/s |
| MUL | 95.6 ns | 10.5 M ops/s |

**Section 4 — "Lattice Security (Post-Quantum)"**

| Config | Polynomial Degree (n) | log2(q) | Min Attack Cost (log2 ops) |
|--------|----------------------|---------|---------------------------|
| secure_128 | 4,096 | 89.08 | 129 |
| secure_192 | 8,192 | 145.08 | 159 |
| secure_256 | 16,384 | 203.38 | 226 |

Security note below table: "NIST Post-Quantum Level 1 (128-bit) verified under both Core-SVP and Matzov cost models. Higher parameter configurations available with measured attack costs shown. Formal external cryptographic audit pending."

**Step 4: Add test coverage section**

| Crate | Tests | Status |
|-------|-------|--------|
| nine65 (core FHE) | 611+ | All passing |
| clockwork-core | 46 | All passing |
| exact_transcendentals | 143 | All passing |
| nexgen_rational | 95 | All passing |
| fhe-service | 22 | All passing |
| mana | 30 | All passing |
| unhal | 10 | All passing |
| **Total** | **935+** | **0 failures** |

**Step 5: Commit**

```bash
git add benchmarks.html
git commit -m "feat: benchmarks page with real v7 numbers and lattice security"
```

---

## Task 6: Rewrite proofs.html

**Files:**
- Modify: `proofs.html` (rewrite main content section)

**Step 1: Update meta/nav/footer**

- Title: "Formal Verification | HackFate"
- Replace nav and footer with Shared Patterns

**Step 2: Update hero**

Title: "Formal Verification"
Subtitle: "70+ machine-checked proofs in Coq 8.18+ and Lean4 with Mathlib. Zero admitted statements. Zero sorry statements."

**Step 3: Add methodology section**

"Three axioms used across the proof corpus: Core-SVP hardness assumption, Ring-LWE to SVP reduction, and BKZ cost model. All other results are proven from first principles."

**Step 4: Add Coq proof listing (14 proofs)**

Use a table or card grid — no links to source files:

| Proof | Property Verified |
|-------|-------------------|
| KElimination | Exact overflow recovery in RNS division |
| GSOFHE | Depth management correctness for encrypted circuits |
| CRTShadowEntropy | Shadow entropy statistical independence from computation inputs |
| OrderFinding | Multiplicative order detection in modular groups |
| MQReLU | Integer activation function preserves FHE noise bounds |
| IntegerSoftmax | Exact integer softmax summation correctness |
| MontgomeryPersistent | Montgomery form persistence across chained operations |
| MobiusInt | Mobius function integer arithmetic roundtrip |
| CyclotomicPhase | Cyclotomic polynomial phase evaluation correctness |
| PadeEngine | Pade approximant identity and zero properties |
| ExactCoefficient | Exact polynomial coefficient extraction |
| StateCompression | Compressed state preserves computation integrity |
| SideChannelResistance | Constant-time operation execution verification |
| EncryptedQuantum | Quantum operation simulation in encrypted domain |

**Step 5: Add Lean4 core proof listing (17+ files)**

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
| SideChannel | Timing-independent operation proofs |
| EncryptedQuantum | Encrypted quantum gate simulation |
| StateCompression | State compression integrity |

**Step 6: Add Innovation proofs section (24 Lean4 files)**

Brief section: "24 additional Lean4 proofs cover per-innovation mathematical correctness across the full innovation stack, including persistent Montgomery arithmetic, integer neural networks, binary GCD, PLMG rails, GSO depth management, MANA acceleration, Clockwork Prime, bootstrap-free FHE, and real-time FHE operations."

**Step 7: Add NIST compliance proof section (14 files)**

"14 dedicated proof files cover NIST compliance: AHOP security reductions, IND-CPA game formalization, ring definitions, homomorphic security, K-Elimination soundness, security lemmas, and the complete security argument."

**Step 8: Add verification summary**

Card or highlight box:
- Coq: 14 proofs, 0 admitted statements, Coq 8.18+
- Lean4: 55+ proof files, 0 sorry statements, Lean 4.x + Mathlib
- Axioms: 3 (all standard cryptographic assumptions)
- Formal external audit: Pending

**Step 9: Remove any existing links to GitHub proof source files**

If the current proofs.html links to `https://github.com/DeuxAxios/hackfate` or specific proof file paths, remove those links. Keep only the proof names and property descriptions.

**Step 10: Commit**

```bash
git add proofs.html
git commit -m "feat: proofs page with 70+ proofs listed — names and properties only"
```

---

## Task 7: Rewrite technology.html

**Files:**
- Modify: `technology.html` (currently near-empty, needs full content)

**Step 1: Update meta/nav/footer**

- Title: "Technology | HackFate"
- Description: "Integer-only FHE from first principles. Four-layer exact arithmetic stack."
- Replace nav and footer

**Step 2: Replace hero**

Title: "The Stack"
Subtitle: "Integer-only FHE built from first principles. Every layer exists because the one below it created a requirement."

**Step 3: Add four-layer stack section (card grid)**

Card 1 — **L0: Exact Arithmetic**
"All computation in exact integer and rational arithmetic. Zero floating-point operations at any layer — enforced at compile time, not by convention. Results are deterministic and bit-identical across platforms, compilers, and architectures. Formally verified."

Card 2 — **L1: K-Elimination**
"Exact division in Residue Number Systems. For 60 years, RNS division required expensive full reconstruction that serialized parallel computation. K-Elimination solves this exactly, enabling practical RNS-based FHE for the first time."

Card 3 — **L2: Integrity Verification**
"RNS encoding with algebraic integrity checking. Corrupted operations — whether from hardware faults or adversarial inputs — are detected at the first computation step, not at the end of the circuit. Failed integrity triggers immediate destruction in Kiosk mode."

Card 4 — **L3: Three-Lock FHE**
"Unlimited-depth homomorphic encryption with Three-Lock conjunction security. Three independent protection layers during re-encryption. Three verified bootstrap paths: circular, non-circular (KSK), and auto-triggered. 935+ tests, all passing."

**Step 4: Add "Why Integer-Only" section**

"Every floating-point operation is a precision loss. In isolation, the error is negligible. Across thousands of operations — training a neural network, evaluating a deep circuit, computing a financial model — errors compound into unreliable results. NINE65 eliminates this entirely. The answer is exact, or the system tells you it cannot compute it. There is no silent degradation."

**Step 5: Add licensing note**

"Implementation details and source code available under licensing agreement. Contact us for technical evaluation access."

**Step 6: Commit**

```bash
git add technology.html
git commit -m "feat: technology page with four-layer stack — conceptual only"
```

---

## Task 8: Update nine65-saas.html

**Files:**
- Modify: `nine65-saas.html`

**Step 1: Update nav/footer** with Shared Patterns.

**Step 2: Global text replacements**

- "v5" → "v7" (all occurrences)
- "627 passing tests" → "935+ passing tests" (or similar test count references)
- "627 tests" → "935+ tests"
- Any reference to bootstrap count → "3 verified bootstrap paths"

**Step 3: Add Three-Lock mention**

In the security section (if one exists) or create a new card: "Three-Lock Conjunction Security — Protected re-encryption with three independent defense layers: information-theoretic, computational, and algebraic. All three must be broken simultaneously."

**Step 4: Update performance numbers** to match v7 benchmarks where referenced.

**Step 5: Update roadmap** section if present — reflect current v7 status.

**Step 6: Commit**

```bash
git add nine65-saas.html
git commit -m "feat: update SaaS page to v7 — stats, Three-Lock, benchmarks"
```

---

## Task 9: Update demo.html

**Files:**
- Modify: `demo.html`

**Step 1: Update nav/footer** with Shared Patterns.

**Step 2: Text replacements**

- "v5" → "v7" (all occurrences in visible text and comments)
- Keep "Preview mode — simulated data" notice

**Step 3: Add Three-Lock reference**

Add text near the demo area: "Protected by Three-Lock conjunction security during bootstrap operations."

**Step 4: Commit**

```bash
git add demo.html
git commit -m "chore: update demo page references to v7"
```

---

## Task 10: Create clockwork-bootstrap.html redirect

**Files:**
- Modify: `clockwork-bootstrap.html` (replace with redirect)

**Step 1: Replace entire file with redirect**

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0; url=three-lock.html">
    <title>Redirecting to Three-Lock Bootstrap | HackFate</title>
    <link rel="canonical" href="https://hackfate.us/three-lock.html">
</head>
<body>
    <p>This page has moved to <a href="three-lock.html">Three-Lock Bootstrap</a>.</p>
</body>
</html>
```

**Step 2: Commit**

```bash
git add clockwork-bootstrap.html
git commit -m "chore: redirect clockwork-bootstrap.html to three-lock.html"
```

---

## Task 11: Update remaining pages nav/footer

**Files:**
- Modify: `research.html`, `qmnf.html`, `about.html`, `contact.html`, `privacy.html`, `walkthrough.html`, `innovations.html`, `shadow-entropy.html`, `404.html`

**Step 1: For each file, replace nav block** with updated nav from Shared Patterns.

**Step 2: For each file, replace footer block** with updated footer from Shared Patterns.

**Step 3: Verify no broken links** — all nav items point to existing pages.

**Step 4: Commit**

```bash
git add research.html qmnf.html about.html contact.html privacy.html walkthrough.html innovations.html shadow-entropy.html 404.html
git commit -m "chore: update nav and footer across all pages — add Three-Lock, Kiosk links"
```

---

## Task 12: Update sitemap.xml

**Files:**
- Modify: `sitemap.xml`

**Step 1: Add new pages**

Add entries for:
- `https://hackfate.us/three-lock.html`
- `https://hackfate.us/kiosk.html`

Match existing entry format (URL, lastmod, changefreq, priority).

**Step 2: Update lastmod dates** on modified pages.

**Step 3: Commit**

```bash
git add sitemap.xml
git commit -m "chore: add three-lock and kiosk to sitemap"
```

---

## Task 13: Final Review and PR

**Step 1: Verify all pages**

```bash
# Check for broken internal links
grep -roh 'href="[^"]*\.html"' *.html | sort -u | while read link; do
    file=$(echo "$link" | sed 's/href="//;s/"$//')
    [ ! -f "$file" ] && echo "BROKEN: $file"
done
```

Expected: no broken links.

**Step 2: Check no v5 references remain**

```bash
grep -rn "v5\b" *.html | grep -v "clockwork-bootstrap.html"
```

Expected: no results (all v5 references replaced).

**Step 3: Check no proof source links**

```bash
grep -n "github.com.*proof\|github.com.*lean4\|github.com.*coq\|\.lean\|\.v\"" proofs.html
```

Expected: no links to proof source files on proofs.html.

**Step 4: Push and create PR**

```bash
git push -u origin v7-complete-update
gh pr create --title "v7: Complete site update — Three-Lock, Kiosk, real benchmarks" --body "$(cat <<'EOF'
## Summary
- Update entire site from NINE65 v5 to v7
- Add Three-Lock Bootstrap architecture page (names + conceptual purpose, no implementation details)
- Add Kiosk Architecture page (BULLET/CAPSULE/FUSE deployment models, business concept)
- Replace benchmark page with real v7 numbers (standalone, no competitor comparisons)
- Rewrite proofs page with 70+ proofs listed (names + properties only, no source links)
- Fill technology page with four-layer conceptual stack
- Update all navigation and footers across all pages
- Redirect clockwork-bootstrap.html to three-lock.html
- Update sitemap

## Disclosure compliance
- No implementation details disclosed
- No links to proof source files
- No competitor comparisons
- Security claims limited to verified Level 1 (128-bit)
- Higher config numbers shown honestly
- External audit noted as pending
- Kiosk infrastructure marked as in-development

## Test plan
- [ ] All internal links resolve
- [ ] No remaining v5 references
- [ ] No proof source file links on proofs page
- [ ] Mobile nav works on all new pages
- [ ] GitHub Pages deploys successfully

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

**Step 5: Verify deployment**

After PR merges, verify https://hackfate.us loads with v7 content.
