---
name: cram-operator
description: >
  Operational command skill for CRAM (Configurable Residue Arithmetic Machine)
  system. Goes beyond education into EXECUTION: how to run CRAM schemas, diagnose
  lane behavior, apply DKAM subcriticality analysis, build staging lane accumulators,
  interpret carry patterns, and avoid known failure modes. Use whenever OPERATING
  the CRAM system — running NS solvers, analyzing stretching concentration, building
  winding number surveys, applying Dresden Codex algorithms, computing singular
  series via staging lanes, or diagnosing CRT lane behavior. Also trigger for:
  DKAM analysis, subcriticality checks, spectral gap analysis (to prevent the
  known error), carry pattern interpretation, shadow/boundary detection, lane
  nullification, sync schema operation, pharmacokinetic framing of PDE balance,
  Tao complementarity analysis, or any operational question about "how do I use
  CRAM to do X." This is the DOING skill, not the LEARNING skill. For education,
  use qmnf-cram-educator. For primes/families, use prime-family-spacetime.
  Triggers: 'run CRAM', 'DKAM', 'subcritical', 'lane concentration', 'staging
  lane', 'winding number', 'carry pattern', 'sync schema', 'lane nullification',
  'stretching degree', 'resonance order', 'clean window', 'K_vort', 'energy
  neutrality', 'NS solver', 'operate', 'diagnose lane', 'what went wrong',
  'pharmacokinetic', 'Tao complementarity', 'spectral gap' (to warn about E1).
---

# CRAM Operator Skill — Operational Command Reference

## STATUS: OPERATIONAL

This skill encodes hard-won operational knowledge from 116+ kills.
It tells you HOW to operate, WHAT to watch for, and WHERE the bodies
are buried (killed hypotheses documented for prevention).

---

## QUICK REFERENCE: The Numbers That Matter

```
Safe Basis:        B = {2, 3, 5, 7, 11, 13}
Product:           M = 30,030
Transport Core:    {3, 7, 11, 13}  (gcd(p, SCALE) = 1)
Parking Lanes:     {2, 5}          (gcd(p, SCALE) > 1)
SCALE:             10,000 = 2⁴ × 5⁴
Ramanujan Primes:  S_R = {5, 7, 11}
Shadow Prime:      11 (unique, T-SHADOW proved)
Boundary Prime:    13 (first post-Ramanujan)

DKAM:              deg(stretching) = 2 < 3 = ρ(B)
Topology count:    16⁶ = 16,777,216 (4 roots × 4 posts × 6 lanes)
```

---

## SECTION 1: DKAM SUBCRITICALITY OPERATIONS

### When to apply DKAM analysis

Apply whenever you encounter a NONLINEAR operation on CRT residues and need
to determine if it's structurally safe (subcritical) or dangerous (supercritical).

### The three-step DKAM check

```
STEP 1: Determine deg(F)
  - Scale the input by λ: compute F(λx) / F(x)
  - If ratio = λ^d → deg(F) = d
  - For NS stretching: d = 2 (verified λ=1..10, <0.1% error)
  - For generic bilinear: d = 2 (but Tao shows generics blow up)
  - For cubic nonlinearity: d = 3 (EXCEEDS ρ — supercritical!)

STEP 2: Determine ρ(B)
  - ρ = min(B) = smallest prime in basis
  - For Safe Basis: ρ = 2 (includes parking lanes)
  - For Transport Core: ρ = 3 (excludes {2, 5})
  - For ANY admissible extension: ρ ≥ 3 (because 2 ∉ admissible)

STEP 3: Compare
  - deg(F) < ρ(B) → SUBCRITICAL (clean window, DKAM protects)
  - deg(F) = ρ(B) → CRITICAL (boundary case, no guarantee)
  - deg(F) > ρ(B) → SUPERCRITICAL (resonance excitation possible)
```

### CRITICAL: Which basis for which check?

- NS stretching: use TRANSPORT CORE {3,7,11,13}, ρ = 3, deg = 2 → SAFE
- If you include parking lanes: ρ = 2, deg = 2 → CRITICAL (not safe!)
- The admissibility condition (gcd(p, SCALE) = 1) is what gives ρ ≥ 3

### Tao Complementarity (use when discussing NS regularity)

```
Tao (2016):  GENERIC degree-2 bilinear operators → blowup
DKAM:        SPECIFIC NS degree-2 operator → subcritical in CRT

NOT contradictory. COMPLEMENTARY.

Tao's averaging DESTROYS exact degree-2 structure.
CRT arithmetic PRESERVES it (ring homomorphism, L1).
The non-genericity IS the exact algebraic degree.
```

---

## SECTION 2: LANE DIAGNOSTICS

### Per-lane energy audit

To diagnose where a nonlinear term concentrates its energy:

```python
# For each prime p in basis, compute:
lane_energy[p] = Σ_{ij} |F[i,j] mod p|

# Stretching concentration ratio (SCR):
SCR = Σ_{p∈{7,11,13}} lane_energy[p] / Σ_{p∈B} lane_energy[p]

# EXPECTED for NS stretching: SCR ∈ [0.78, 0.86]
# If SCR < 0.70: stretching is NOT concentrating → investigate
# If SCR > 0.90: extreme concentration → check for numerical artifact
```

### Known lane behavior (NS)

```
Lane 2:   2-4% of stretching energy (parking, fabric)
Lane 3:   5-9% (fabric, stability floor)
Lane 5:   10-20% (Ramanujan, measurement)
Lane 7:   15-22% (Ramanujan, bridge) ← DKAM protected
Lane 11:  19-36% (Ramanujan, shadow) ← DKAM protected, highest variability
Lane 13:  28-43% (boundary)          ← DKAM protected
```

### Ring homomorphism verification

After every solver step, verify:

```python
for p in SAFE_BASIS:
    for i, j in grid:
        expected = (omega[i,j] - adv[i,j] + (nu * lap[i,j]) // SCALE) % p
        actual = omega_new[i,j] % p
        assert expected == actual, f"Ring homomorphism violation at ({i},{j}) mod {p}"

# EXPECTED: zero violations. Any violation means:
# - Cascade bug (carries between lanes) → check INV-1
# - Float contamination → check all operations are integer
# - SCALE division error → check gcd(p, SCALE) = 1
```

---

## SECTION 3: STAGING LANE ACCUMULATOR

### What it does

Converts a continuous quantity (like the tail of an infinite product)
into a sequence of discrete carry events on CRT lanes.

### Construction

```python
def staging_lane_accumulator(corrections, threshold, hot_lane_mod):
    """
    corrections: sequence of exact rational corrections (one per prime)
    threshold: carry firing threshold (e.g., Fraction(1, 4))
    hot_lane_mod: prime modulus for the hot lane (e.g., 11)
    """
    accumulator = Fraction(0)
    wraps = 0
    
    for correction in corrections:
        accumulator += correction
        while accumulator >= threshold:
            accumulator -= threshold
            wraps += 1
        while accumulator < 0:
            accumulator += threshold
            wraps -= 1
    
    shadow_fingerprint = wraps % hot_lane_mod
    return wraps, shadow_fingerprint, float(accumulator)
```

### Singular series application

For gap d, the corrections are:
- `1/(p-1)²` when p does NOT divide d (factor < 1, positive correction)
- `-1/(p-1)` when p DIVIDES d (factor > 1, negative correction)

### Interpretation

```
wraps > 0: tail accumulates positively → FEWER prime pairs expected
wraps < 0: tail wraps backward → MORE prime pairs expected
wraps = 0: balanced → moderate pair density

shadow_fingerprint = wraps mod 11: shadow prime's view of the winding
boundary_fingerprint = wraps mod 13: boundary prime's view

R² = 0.9829 between winding number and actual pair count (d=2..1000)
```

---

## SECTION 4: CRAM SYNC SCHEMA

### When to use

When comparing solutions at different resolutions or configurations.
Do NOT sync on raw CRT residues (they alias chaotically). Sync on OBSERVABLES.

### The five observables

```
O1: Energy        E = Σ ω²             (integer, should be conserved)
O2: Enstrophy     Z = Σ |∇ω|²          (integer, should decrease for ν > 0)
O3: Max vorticity W = max |ω|           (integer, bounded if regular)
O4: Circulation   C = Σ ω               (integer, should be zero)
O5: Palinstrophy  P = Σ |Δω|²           (integer, higher-order diagnostic)
```

### Sync classification

```python
def classify_sync(delta, basis=SAFE_BASIS):
    residues = tuple(abs(delta) % p for p in basis)
    zero_lanes = sum(1 for r in residues if r == 0)
    
    if delta == 0:        return 'EXACT_SYNC'
    elif zero_lanes >= 4: return 'NEAR_SYNC'
    elif zero_lanes >= 2: return 'PARTIAL_SYNC'
    else:                 return 'DRIFTING'
```

### Shadow/boundary sync indicators

```
shadow_sync = (delta % 11 == 0)     # shadow-synchronized
boundary_sync = (delta % 13 == 0)   # boundary-synchronized

NOTE: At random, shadow sync rate ≈ 9.1%, boundary ≈ 7.7%.
Rates significantly above random indicate structural sync.
Rates AT random indicate no special sync (honest observation).
```

---

## SECTION 5: DRESDEN CODEX OPERATIONAL PATTERNS

### Algorithm 6: Selective Lane Nullification

Choose stride S such that S ≡ 0 mod {lanes to silence}.

```
Maya stride: S = 78 = 2 × 3 × 13
  Silences: {2, 3, 13} (parking + boundary)
  Active:   {5, 7, 11} (S_R = Ramanujan primes only)
  
  78 mod 2  = 0 (silenced)
  78 mod 3  = 0 (silenced)
  78 mod 5  = 3 (active)
  78 mod 7  = 1 (active)
  78 mod 11 = 1 (active)
  78 mod 13 = 0 (silenced)
```

**WARNING:** Lane nullification changes the physics (Gate A-Q4: FAIL).
Use for ANALYSIS (identifying which lanes carry what signal), NOT for
modifying the solver. The stride-S solver diverges from standard by 2×
within 30 steps.

### Algorithm 7: Zero-Drift Epoch Traversal

For deep-time computation: reduce mod M first, then compute.

```python
# Instead of computing 32000 × 365 steps:
effective = (32000 * 365) % M_SAFE  # One modular reduction
# Then compute from effective displacement — zero drift.
```

### Algorithm 16: State Vector Synchronization (New Year Protocol)

Periodic consistency check between distributed computations:

```
1. Each node computes locally for one epoch (365 steps, or similar)
2. At sync point: all nodes extract observables (O1-O5)
3. K-Eliminate between nodes: winding number = sync diagnostic
4. If winding > threshold: node has drifted → resync from anchor
```

---

## SECTION 6: KILLED HYPOTHESES (PERMANENT RECORD)

These are DEAD. Do not resurrect them. They are documented here so
nobody re-discovers them and thinks they're new.

### E1: Spectral Gap Conflation (KILLED — session of Mar 26, 2026)

```
CLAIM: CRT product torus has 841× larger spectral gap → 
       resolution-independent Poincaré constant → NS regularity.

TRUTH: CRT ring isomorphism transports the standard Laplacian with
       IDENTICAL eigenvalues (verified to machine epsilon).
       The 841× gap was for the PRODUCT Laplacian (per-factor
       independent modes), which is a DIFFERENT operator.
       
THREE OPERATORS:
  #1: Standard Laplacian on ℤ/MZ
  #2: CRT-transported (diagonal-shift) Laplacian on ∏ℤ/pᵢZ
  #3: Product Laplacian (per-factor independent) on ∏ℤ/pᵢZ
  
  #1 = #2 spectrally (PROVED).
  #3 ≠ #1 (PROVED, different spectrum, larger gap).
  
  NS uses #1/#2. The gap advantage is for #3. Does not apply.

DETECTION: If you compute eigenvalues and get 841×, you're looking
at operator #3. Check which operator you're actually using.

STATUS: PERMANENTLY DEAD. DKAM subcriticality (T3) is UNAFFECTED.
```

### E2: Carry Chain Sieve (KILLED — pre-session)

```
CLAIM: Carry chains between lanes act as a prime sieve.
TRUTH: Dead beyond parity. One-bit parity filter only.
```

### E3: Convergence Rate as Oracle (KILLED — session of Mar 26, 2026)

```
CLAIM: The convergence rate of the inverted scaffold differs by gap d
       in a way that detects prime pair infinitude.
TRUTH: After absorbing dividing primes, tail convergence rates are
       IDENTICAL across all gaps. The oracle hypothesis is dead.
       The WINDING NUMBER (not rate) does differ and has R² = 0.98.
```

### E4: Stride-S Preserving Physics (KILLED — session of Mar 26, 2026)

```
CLAIM: Nullifying CRT lanes via stride-S timestep preserves NS physics.
TRUTH: Energy diverges 2× within 30 steps. Lane nullification changes
       the solution. Use for analysis only, not solver modification.
```

### E5: Raw CRT Sync Between Resolutions (KILLED — session of Mar 26, 2026)

```
CLAIM: K-Eliminate between raw vorticity values at different N gives
       meaningful sync information.
TRUTH: Raw CRT residues of large integers alias chaotically. Winding
       numbers are huge (~20K) and meaningless. Sync on OBSERVABLES
       (energy, enstrophy, K_vort), not raw field values.
```

---

## SECTION 7: NS SOLVER OPERATIONAL CHECKLIST

Before running nsgrid3d or any CRT-NS solver:

```
PRE-FLIGHT:
  [ ] All values integer? No float anywhere in pipeline?
  [ ] Basis admissible? gcd(p, SCALE) = 1 for all transport primes?
  [ ] SCALE correct? (10000 = 2⁴ × 5⁴)
  [ ] Jacobi iterations sufficient for Poisson convergence? (≥200)
  [ ] Time step within CFL condition?

PER-STEP MONITORING:
  [ ] Ring homomorphism: verify V7 (or spot-check every 10 steps)
  [ ] Energy conservation: verify V8 (should be integer zero)
  [ ] K_vort: compute, should be 0. If >0, consider scaffold extension.
  [ ] Per-lane energy: compute SCR. Should be 0.78-0.86 for NS.

POST-RUN DIAGNOSTICS:
  [ ] Enstrophy trend: should be bounded/decreasing at tested Re.
  [ ] Max vorticity trend: should be bounded.
  [ ] Energy ratio E_final/E_initial: should be close to 1.
  [ ] Any ring homomorphism violations? If yes: STOP. Debug.
```

---

## SECTION 8: PHARMACOKINETIC FRAMING

### When to use

When analyzing the BALANCE between a source term (stretching, infusion,
accumulation) and a sink term (dissipation, elimination, clearing).

### The mapping

```
Pharmacokinetics          CRT-NS
─────────────────         ────────────────────
Drug concentration C(t)   Vorticity ω(t)
Infusion rate             Stretching energy input (deg 2)
k_el (elimination const)  gap × ν (spectral gap × viscosity)
Steady state C_ss         Bounded K_vort (regularity)
Half-life t½              Dissipation timescale
AUC (area under curve)    Enstrophy integral
Dosing interval           Timestep Δt
Therapeutic window        Clean window (deg < ρ)
```

### The regularity condition (pharmacokinetic form)

```
k_el > stretching_rate
⟺  gap × ν > C × ‖ω‖²
⟺  (resolution-dependent) × ν > C × (bounded by energy conservation)

NOTE: After killing E1, the spectral gap IS resolution-dependent on
the standard Laplacian. The pharmacokinetic argument as originally
stated is DEAD. The surviving form uses DKAM arithmetic invariance
instead of spectral gap. See Section 1.
```

---

## SECTION 9: KEY VALIDATION IDENTITIES

These can be checked without understanding any proofs:

```
V1:  |adv(2ω)| / |adv(ω)| = 4 ± 1%         [stretching degree = 2]
V2:  |adv(10ω)| / |adv(ω)| = 100 ± 0.1%    [stretching degree = 2]
V3:  ρ({3,7,11,13}) = 3                      [resonance order]
V4:  2 < 3                                    [clean window]
V5:  gcd(2, 10000) = 2 ≠ 1                   [2 excluded from admissible]
V6:  gcd(3, 10000) = 1                        [3 is admissible]
V7:  ω_{t+1} mod p = (ω_t - adv + ν·Δω/S) mod p   [ring homomorphism]
V8:  Σ ω·A^skew·ω = 0 (integer)              [energy conservation]
V9:  K_vort(t) = 0 for tested configs         [vorticity bounded]
V10: SCR ≥ 0.78 for N ∈ {4,...,16}            [stretching concentration]
```

---

## SECTION 10: INTEGRATION WITH OTHER SKILLS

| Need | Skill | This Skill's Role |
|------|-------|-------------------|
| Learn CRAM basics | qmnf-cram-educator | Operator assumes you know basics |
| Prime family analysis | prime-family-spacetime | Provides prime attributes for lane analysis |
| Formalize a result | theorem-crusher | Operator provides the data to formalize |
| Audit FHE code | nine65-auditor | Operator provides DKAM check methodology |
| Design CRT basis | recombinant-crt | Operator provides admissibility criteria |
| Trace innovation history | innovation-genealogy | Operator provides current state of kills |
| Decompose a problem | gap-scout | Operator provides lane-parallel decomposition |
| Attack a hard problem | tao-blueprint-method | Operator provides DKAM as a proof strategy |
| Explore variations | truth-perturber | Operator provides known invariants to perturb |
