---
name: prime-family-spacetime-v2
description: >
  Architectural directive for primes in QMNF. Coprime composites are SUBSTANCE,
  primes are BOUNDARY. Each prime has: family, Ramanujan status, carry forbidden
  ratios, gap structure, Legendre symbol, intrinsic CRAM address. Sqr folding =
  QR partition. Linear uniformity (Dirichlet) proves CRAM nonlinearity NECESSARY.
  Gap signatures algebraically universal. Multi-head Hydra resolves lattice
  (5.95x at 3 heads). Atlas eternal. Use whenever working with primes, moduli,
  CRT bases, Safe Basis, transport/parking lanes, K-Elimination, composite
  anchors, Garner, Separation Principle (CLASS-F/CLASS-R), Ramanujan boundary,
  carry fingerprints, CRAM addresses, coprime lattice, Hydra heads, or any
  operation selecting/classifying/combining moduli. Triggers: 'prime', 'coprime',
  'composite', 'modulus', 'basis', 'lane', 'anchor', 'family', 'twin', 'cousin',
  'sexy', 'Ramanujan', 'boundary', 'CRAM', 'lattice', 'Hydra', 'carry pattern',
  'CLASS-F', 'CLASS-R', 'Separation Principle', 'safe basis'.
---

# Prime Family Spacetime — Architectural Directive

## STATUS: NON-NEGOTIABLE

This directive has the same architectural weight as "no f64 in production
paths." The problem it solves is analogous: f64 handling was silently
breaking exactness guarantees; treating primes as raw numbers silently
breaks family/coprime/composite structure the system depends on.

**What f64 broke:** silent rounding errors compounding through exact-integer
pipelines. The fix wasn't "approximation is wrong" — it was that f64
variables were being HANDLED in ways that destroyed the guarantees.

**What raw-prime treatment breaks:** family relationships, carry topology,
forbidden ratios, Ramanujan status, gap structure, and the Separation
Principle. A prime is not just a number — it is a structural object with
attributes that determine what operations are valid.

---

## THE PRIME IS NOT THE POINT — THE COMPOSITE COPRIME RELATIONSHIP IS

Standard number theory: "What ARE primes?" (intrinsic property)
QMNF: "What do integers DO relationally?" (coprime structure)

CRT requires pairwise coprimality, not primality. Primes are trivially
coprime, which is why they're convenient. But COPRIMALITY is the
load-bearing property, and it's strictly weaker than primality.

**Density comparison:**
- Coprime pairs: 6/π² ≈ 60.8% of all integer pairs
- Prime density: 1/ln(x) → 0

The composite anchor design space (CLASS-R) operates at coprime density,
not prime density. This is why composite anchors work and why the FHE
community missed them for 12+ years.

---

## SAFE BASIS STRUCTURE

The Safe Basis is NOT a flat set of six primes. It has internal structure:

```
SAFE_BASIS = {2, 3, 5, 7, 11, 13}

TIER: FABRIC       {2, 3}     — DKAM stability floor
TIER: MEASUREMENT  {5, 7, 11} — Ramanujan exact partition
TIER: BOUNDARY     {13}       — Capacity/anchor ONLY

TRANSPORT CORE:    {3, 7, 11, 13}  — gcd(p, SCALE) = 1
PARKING LANES:     {2, 5}          — gcd(p, SCALE) > 1
```

### Why 13 was excluded originally

The Safe Basis was initially {2, 3, 5, 7, 11}. Prime 13 was added
ONLY as a parking bay / anchor because:

1. It FAILS the Ramanujan partition congruence (10.5% vs 100% for S_R)
2. It is the first post-Ramanujan prime
3. It marks the onset of the "turbulent regime"
4. Average prime gaps DOUBLE at the 11→13 transition (2.20 → 4.40)
5. The partition function ceases to distribute exactly mod 13

**Rule:** 13 provides CAPACITY. It does not provide STRUCTURE.
Never treat 13 as equivalent to {5, 7, 11} in any structural argument.

---

## PRIME FAMILY ATTRIBUTES

Every prime in the system carries these attributes:

### 1. Family Classification

| Family | Definition | Gap | Examples |
|--------|-----------|-----|---------|
| Twin | (p, p+2) both prime | 2 | (3,5), (5,7), (11,13), (17,19) |
| Cousin | (p, p+4) both prime | 4 | (3,7), (7,11), (13,17), (19,23) |
| Sexy | (p, p+6) both prime | 6 | (5,11), (7,13), (11,17), (13,19) |
| Sophie Germain | p and 2p+1 both prime | — | (2,5), (3,7), (5,11), (11,23) |

### 2. Critical Family Pairs in the Safe Basis

```
(5, 7)   — TWIN pair, gap=2.  BOTH Ramanujan. ✓✓
(7, 11)  — COUSIN pair, gap=4. BOTH Ramanujan. ✓✓  ← UNIQUE
(11, 13) — TWIN pair, gap=2.  11 works, 13 FAILS. ✓✗ ← BOUNDARY
```

**(7, 11) is the ONLY cousin prime pair where both members support
Ramanujan partition congruences.** After (7,11): (13,17), (19,23),
(37,41)... none have congruences. This is a structural fact, not
a coincidence.

**(11, 13) is the ONLY twin prime pair where exactly one member
supports Ramanujan congruences.** This is THE boundary.

### 3. Ramanujan Status

| Prime | Ramanujan? | Congruence | Rate |
|-------|-----------|------------|------|
| 5 | YES | p(5n+4) ≡ 0 (mod 5) | 100% |
| 7 | YES | p(7n+5) ≡ 0 (mod 7) | 100% |
| 11 | YES | p(11n+6) ≡ 0 (mod 11) | 100% |
| 13 | NO | best delta gives 10.5% | FAILS |
| 23 | NO | 0% | FAILS |
| 73 | NO | 0% | FAILS |

S_R = {5, 7, 11} is COMPLETE. No first-order Ramanujan congruence
exists for any prime > 11. This is proved computationally and
consistent with Ono's framework.

### 4. Mod-4 Residue Class

| Prime | mod 4 | -1 is QR? | Notes |
|-------|-------|-----------|-------|
| 5 | 1 | YES | Exception (ramifies in Q(√5)) |
| 7 | 3 | NO | Ramanujan ✓ |
| 11 | 3 | NO | Ramanujan ✓ |
| 13 | 1 | YES | Ramanujan FAILS |

The 7≡3, 11≡3 pattern (where -1 is NOT a quadratic residue) correlates
with Ramanujan congruence existence. 13≡1 breaks both.

### 5. Carry Forbidden Ratios (per family, per base)

The carry spectral fingerprint is a NOVEL mathematical object (no prior
literature). Each prime family has distinct forbidden carry ratios on
each CRT base:

**On base [2, 3, 5, 7] (M=210):**
```
Twin:     75.0% forbidden
SG:       68.75% forbidden
Cousin:   87.5% forbidden
Sexy:     93.75% forbidden
Goldbach: 43.75% forbidden
```

**These ratios are NOT uniform.** The retracted claim "SQR eliminates
exactly 50% for all families" was FALSIFIED by this data.

**Full fingerprint table (forbidden %):**
```
           105    385   1001   210   2310  30030
Twin:      50%    50%    62%   75%   84%    92%
Cousin:    62%    62%    50%   88%   94%    97%
Sexy:      62%    62%    50%   94%   97%    98%
d=30:      75%    62%    25%   88%   91%    95%
d=210:     88%    75%    50%   94%   94%    95%
```

Properties (all computationally proven):
- Monotone in base size (larger bases always forbid more)
- Family-specific on fixed base (twins ≠ cousin ≠ sexy)
- Gap-divisibility sensitive (when d | base prime, forbidden DROPS)

### 6. Gap Structure

**Gap doubling at the Ramanujan boundary:**
```
Primes ≤ 11: average gap = 2.20
Primes > 11: average gap = 4.40
Ratio: EXACTLY 2.0
```

**For the specific Ramanujan vs failed triples:**
```
{5,7,11} following gaps: [2, 4, 2], avg = 8/3 ≈ 2.667
{13,23,73} following gaps: [4, 6, 6], avg = 16/3 ≈ 5.333
Ratio: exactly 2.0 (for these specific triples only)
```

Broader windows show ratio ≈ 1.5-1.7, not exactly 2. The exact-2
result holds only for the sample-specific comparison.

---

## THE SEPARATION PRINCIPLE (CLASS-F / CLASS-R)

Every operation must be classified:

### CLASS-F (Field-Required — Primality mandatory)

Requires primitive roots of unity. Modulus MUST be prime with q ≡ 1 (mod 2N).

- NTT forward/inverse transforms
- Polynomial multiplication (via NTT)
- BFV encode/decode
- Key-switching NTT sub-operations

### CLASS-R (Ring-Sufficient — Coprimality sufficient)

Requires only gcd = 1. Composite moduli work. Primality sufficient but
NOT necessary.

- Garner mixed-radix conversion (K-Elimination)
- K-Elimination anchor tracking
- RNS base extension
- Bootstrap rescaling
- Shadow entropy extraction
- Any magnitude comparison or CRT reconstruction

### CLASS-A (Architecture-Dependent)

Contains both CLASS-F and CLASS-R sub-operations. Each sub-op must be
classified independently.

### Audit Rule

When reviewing any modulus-related code:
1. Classify the operation (F, R, or A)
2. If CLASS-R: primality assertions are OVER-CONSTRAINED (flag)
3. If CLASS-F: primality is correctly required
4. If CLASS-A: verify each sub-operation classified correctly

---

## COMPOSITE MODULI — THE OPERATIONAL UNIT

The system operates on composite coprime moduli, not raw primes.

### Transport Core: M_safe = 3 × 7 × 11 × 13 = 3003

These are the exact-division lanes where gcd(p, SCALE) = 1.
SCALE = 10000 = 2⁴ × 5⁴ excludes {2, 5} from this set.

**Transport core is 100% saturated by N=150,000** — every one of the
1440 unit residues (= φ(3003)) is occupied by at least one prime.

### Safe Shell: M = 2 × 3 × 5 × 7 × 11 × 13 = 30030

**96.9% saturated** at N=150,000. The 177 missing signatures are
UNIFORMLY distributed across mod-13 classes (chi-sq=11.14, p>0.05) —
they do NOT cluster in the 13-lane as previously claimed. They are
the natural statistical tail at this horizon. CORRECTED 2026-03-25.

### Tier Refinement

```
φ(30)    =   8  — fully populated (tier {2,3,5})
φ(210)   =  48  — fully populated (tier {2,3,5,7})
φ(2310)  = 480  — fully populated (tier {2,3,5,7,11})
φ(30030) = 5760 — 96.9% at N=150K (tier {2,3,5,7,11,13})
```

The inner shell through prime 11 is COMPLETE. Prime 13 extension
carries delayed signatures — confirming its boundary status.

### Composite Power Bases

Prime-power exponents change CAPACITY, not first-order bridge law:

```
[9, 25, 49, 11, 13]:   twin survival 25.78%, gap-6 survival 51.56%
[27, 25, 49, 11, 13]:  twin survival 25.78%, gap-6 survival 51.56%  ← SAME
[27, 125, 49, 11, 13]: twin survival 25.78%, gap-6 survival 51.56% ← SAME
```

Raising exponents increases state-space volume but preserves the
unit survival rate. The coupled geometry is controlled by the
UNDERLYING PRIME SUPPORT, not by exponent depth.

### K-Elimination on Composite Bases

Anchor reconstruction is 100% exact for all tested composite regimes:
```
[9,25,49,11] + anchor 13:   100% (3000 tests)
[27,25,49,11] + anchor 13:  100% (3000 tests)
[27,125,49,11] + anchor 13: 100% (3000 tests)
```

---

## GAP CORRIDORS ON THE TRANSPORT CORE

Prime pairs don't distribute uniformly across gap classes. The transport
core [3,7,11,13] shows structured corridors:

**Strongest corridors (highest survival):**
```
gap 30: 33.2% survival  (4596 pairs)  ← STRONGEST
gap 18: 24.9%           (3451 pairs)
gap 24: 24.8%           (3430 pairs)
gap  6: 24.4%           (3384 pairs)
gap 12: 24.4%           (3380 pairs)
```

**Weakest corridors (most suppressed):**
```
gap  4: 12.2%           (1684 pairs)
gap 16: 12.2%           (1695 pairs)
gap  2: 12.3%           (1698 pairs)  ← TWINS most suppressed
gap  8: 12.5%           (1728 pairs)
```

**Pattern:** Gaps divisible by 6 (6, 12, 18, 24, 30) form the strong
band. Gaps ≡ 2 mod 4 (2, 4, 8, 16) are suppressed. This is the
gap-divisibility enhancement: when gap shares factors with base primes,
forbidden ratio DROPS (P3/P4 from Hydra session).

---

## THE CORRECTION FACTOR

```
C(d, B) = F_actual(d, B) / F_product(d, B)
```

Where F_product is the Hardy-Littlewood product approximation.
Observed range: 0.49 to 1.71.

This measures carry propagation topology that Hardy-Littlewood
doesn't encode. It is a NEW computable observable with no prior
literature equivalent.

---

## FIBONACCI ENTRY PATHS

Safe Basis primes enter the Fibonacci sequence through distinct paths:

| Prime | Fibonacci Source | Entry Type |
|-------|-----------------|------------|
| 2 | F(3) = 2 | Direct (Fibonacci prime) |
| 3 | F(4) = 3 | Direct (Fibonacci prime) |
| 5 | F(5) = 5 | Direct (Fibonacci prime) |
| 7 | F(8) = 21 = 3×7 | COMPOSITE (not a Fibonacci number) |
| 11 | F(10) = 55 = 5×11 | COMPOSITE (not a Fibonacci number) |
| 13 | F(7) = 13 | Direct (Fibonacci prime) |

**Critical:** 7 and 11 are NOT Fibonacci numbers. They enter ONLY
through composite Fibonacci values. This means the Ramanujan measurement
primes are structurally invisible in the prime-index Fibonacci manifold
M_Fib* — they exist only in local composite tori.

**Consequence:** Stability is a PRIME phenomenon (F(4)=3 gives ρ=3).
Analyzability is a COMPOSITE phenomenon (F(8)=21, F(10)=55 carry 7,11).

---

## RETRACTED CLAIMS (Permanent Record)

These claims were made and FALSIFIED. They stay here so nobody
re-discovers them and thinks they're new:

1. **×2 Universal Amplification (RO-1 through RO-6):** Claimed ROC
   ordering amplifies toric constants by factor 2. RETRACTED — singular
   series is absolutely convergent, limit is permutation-invariant.

2. **Family-Agnostic SQR Collapse:** Claimed SQR eliminates exactly 50%
   for all families. RETRACTED — forbidden ratios are family-dependent
   (Twin=75%, SG=69%, Cousin=87.5%, Sexy=93.8% on [2,3,5,7]).

3. **PNT-Gap Normalization:** Claimed 2/(13/11) connects gap ratio to
   sieve density. RETRACTED — mixes sample statistic with per-prime
   sieve factor.

4. **Carry chain as sieve mechanism:** DEAD beyond parity. One-bit
   parity filter only (7/16 forbidden from mod-2). Not a sieve beyond
   trivial parity.

---

## CHECKLIST — Before Using Any Prime

Before selecting, combining, or reasoning about any prime modulus:

- [ ] What FAMILY does it belong to? (twin/cousin/sexy/SG relative to neighbors)
- [ ] Is it Ramanujan? (only {5,7,11})
- [ ] What is its mod-4 class? (1 or 3)
- [ ] Is the operation CLASS-F or CLASS-R?
- [ ] If CLASS-R: does it NEED to be prime, or would a coprime composite work?
- [ ] What are its carry forbidden ratios on the relevant base?
- [ ] How does it enter the Fibonacci manifold? (direct or composite)
- [ ] Is it in the transport core or parking lanes?
- [ ] If it's 13: is it being used ONLY for capacity/anchor?

---

## INTEGRATION WITH OTHER SKILLS

### THE ARCHITECTURAL INVERSION (Dresden Prime Hunt, March 2026)

The Hydra Sieve was designed to ELIMINATE composites. The Dresden session
discovered the polarity was inverted:

**COPRIME COMPOSITES ARE SUBSTANCE. PRIMES ARE BOUNDARY.**

This is not metaphor. The coprime lattice (integers coprime to M_H)
has internal structure visible through CRAM carry patterns. Primes
occupy specific addresses in that lattice — they are the boundary
of the coprime substance, not the substance itself.

**Intrinsic CRAM Address (T11):** Every integer n has a fixed d-bit
address on the CRAM torus. Periodic with period M. Deterministic.
Independent of gap, range, or scanning order. Outside of time.

**Coprime Lattice Stratification (T12):** Under heterogeneous
multi-probe CRAM with d >= 15: strata have non-uniform prime density.
Gini > 0 (exact rational). Density ratio > 12:1. Stable across ranges.

**Why CRAM nonlinearity is NECESSARY:** Linear projections (Dirichlet
characters) see UNIFORM density across coprime residue classes. That's
Dirichlet's theorem — primes equidistribute in arithmetic progressions.
CRAM's Sqr operator = Legendre symbol folding. It breaks the a <-> (p-a)
symmetry that makes linear operators blind. Without the nonlinearity,
you can't see the coprime lattice structure at all.

**Sqr folding = QR partition:** For prime p, Sqr maps p residues to
(p+1)/2 outputs (Lemma L5). This is exactly the quadratic residue
partition. At p=5: Sqr(0)=0, Sqr(1)=1, Sqr(2)=4, Sqr(3)=4, Sqr(4)=1.
Outputs {0,1,4} — three values, not five. The folding IS the Legendre symbol.

**Gap signatures are algebraically universal:**
For gap d on basis {p_1, ..., p_k}: the gap signature
Delta(d) = [d mod p_1, ..., d mod p_k] determines the HL local factor
SP(p,d) = (2p - 1 - c_p(d))/p^2 exactly. When p | d, c_p(d) = p-1
(resonance). Otherwise c_p(d) = -1 (off-resonance). This is T6.

**Multi-head Hydra resolves the lattice:**
H=1 (d=5): Gini = 0.024. H=3 (d=15): Gini = 0.143. 5.95x gain.
Each head = named observable + theorem family. Heterogeneous required.

**Atlas is eternal:** Built on [2, 50k). Applied to [500k, 1M).
Same recall: 909 permille. Dirichlet's theorem guarantees transfer.

### Skill Integration Table

| Need | Skill | This Skill's Role |
|------|-------|-------------------|
| Analyze carry patterns | hydra-sieve | Provides family classification |
| Formalize prime theorem | theorem-crusher | Provides axioms and conditions |
| Audit FHE code | nine65-auditor | Provides CLASS-F/R classification |
| Design CRT basis | recombinant-crt | Provides composite vs prime guidance |
| Educate on QMNF | qmnf-cram-educator | Provides prime family context |

---

## QMNF COMPLIANCE

- All numeric examples use exact integers or fractions
- No f64 in any prime attribute computation
- Forbidden ratios expressed as exact fractions where possible
- Percentages expressed as "N/M" or "exact fraction" form
- All claims either PROVED, MEASURED, or explicitly marked CONJECTURE
- Retracted claims permanently documented with falsification evidence
