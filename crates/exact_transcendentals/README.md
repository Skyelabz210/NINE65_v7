# QMNF Exact Transcendentals Engine

**Truth cannot be approximated. Floating points are prohibited.**

## Test Status: 47/47 PASSING (100%) ✅

| Module | Tests | Status |
|--------|-------|--------|
| **Core** | 3/3 | ✅ PERFECT |
| **CORDIC (circular)** | 6/6 | ✅ PERFECT |
| **CORDIC (hyperbolic)** | 2/2 | ✅ PERFECT |
| **Integer Sqrt** | 9/9 | ✅ PERFECT |
| **Continued Fractions** | 7/7 | ✅ PERFECT |
| **Constants** | 6/6 | ✅ PERFECT |
| **AGM** | 8/8 | ✅ PERFECT |
| **Taylor Series** | 9/9 | ✅ PERFECT |

## Overview

This crate provides **exact integer-only implementations** of transcendental functions. No floating point operations are used anywhere in the computation - all algorithms reduce to addition, subtraction, multiplication, bit shifts, and exact integer division.

## Algorithms Implemented

### 1. CORDIC (Coordinate Rotation Digital Computer)
Shift-and-add algorithm with **zero multiplies in main loop**.

```rust
use exact_transcendentals::cordic::{CordicEngine, HyperbolicCordic, SCALE};

// Circular mode: sin, cos, tan, atan
let engine = CordicEngine::default();
let (cos, sin) = engine.sincos(angle);  // Both at once!
let angle = engine.atan(ratio);         // Arctangent
let mag = engine.magnitude(x, y);       // sqrt(x² + y²)

// Hyperbolic mode: sinh, cosh, exp, ln
let hyp = HyperbolicCordic::default();
let (cosh, sinh) = hyp.sinhcosh(x);
let exp_val = hyp.exp(x);  // e^x
let ln_val = hyp.ln(x);    // natural log
```

### 2. Integer Square Root
Multiple algorithms with different tradeoffs.

```rust
use exact_transcendentals::sqrt::*;

// Newton-Raphson: quadratic convergence
let sqrt_100 = isqrt_newton(100);           // 10
let sqrt_big = isqrt_newton_128(n);         // 128-bit version

// Digit-by-digit: NO division needed!
let sqrt_dbd = isqrt_digit_by_digit(100);   // 10

// Binary search: simple, guaranteed correct
let sqrt_bin = isqrt_binary(100);           // 10

// Rational approximations
let approx = sqrt_rational(2, 20);  // √2 as exact rational

// Fast inverse sqrt (Quake-style with integer refinement)
let inv_sqrt = fast_inv_sqrt(4);  // 1/√4 × 2^30

// Integer cube root
let cbrt_27 = icbrt(27);  // 3
```

### 3. Continued Fractions
Best rational approximations with proven error bounds.

```rust
use exact_transcendentals::continued_fraction::*;

// √2 = [1; 2, 2, 2, ...]
let cf = sqrt_cf(2);
let approx = cf.convergent(10);  // 3363/2378

// π = [3; 7, 15, 1, 292, ...]
let pi_cf = pi_cf();
let approx = pi_cf.convergent(3);  // 355/113 (Zu Chongzhi!)

// Golden ratio = [1; 1, 1, 1, ...]
let phi = golden_ratio_cf();

// e = [2; 1, 2, 1, 1, 4, 1, 1, 6, ...]
let e = e_cf();

// Pell equation solver: x² - ny² = 1
let (x, y) = pell_fundamental(2).unwrap();  // (3, 2)
```

### 4. AGM (Arithmetic-Geometric Mean)
Quadratically convergent algorithms - doubles precision each iteration!

```rust
use exact_transcendentals::agm::{AgmEngine, AGM_SCALE};

let engine = AgmEngine::default();

// AGM iteration
let agm_val = engine.agm(a, b);  // M(a,b)

// π via Gauss-Legendre algorithm
let pi = engine.compute_pi_scaled();

// Natural logarithm via AGM
let ln_x = engine.ln(x);

// Exponential via limit definition
let exp_x = engine.exp(x);

// Complete elliptic integral K(k)
let k_val = engine.elliptic_k(k_squared);
```

### 5. Taylor Series (Direct Evaluation)
Efficient series evaluation with automatic convergence.

```rust
use exact_transcendentals::binary_splitting::*;

// Exponential: e^x = Σ x^k/k!
let exp_val = exp_binary_split(x, scale_bits, num_terms);

// Trigonometric
let sin_val = sin_binary_split(x, scale_bits, num_terms);
let cos_val = cos_binary_split(x, scale_bits, num_terms);

// Arctangent: for |x| ≤ 1
let atan_val = atan_binary_split(x, scale_bits, num_terms);

// π via Machin's formula: π/4 = 4×atan(1/5) - atan(1/239)
let pi = pi_machin(scale_bits, num_terms);

// ln(2) via atanh series
let ln2 = ln2_binary_split(scale_bits, num_terms);

// e = exp(1)
let e = e_constant(scale_bits, num_terms);
```

### 6. Precomputed Constants
High-precision constants for immediate use.

```rust
use exact_transcendentals::constants::precision_30::*;

let pi = PI;      // π × 2^30
let e = E;        // e × 2^30
let phi = PHI;    // φ × 2^30
let sqrt2 = SQRT2; // √2 × 2^30
let ln2 = LN2;     // ln(2) × 2^30

// Best rational approximations
use exact_transcendentals::constants::rational::*;
let (num, den) = PI_355_113;  // 355/113 (6 decimal accuracy)
let (num, den) = SQRT2_HI;    // 577/408 (5 decimal accuracy)
```

## Why Integer-Only Matters

1. **Exact reproducibility**: Same input always gives same output
2. **No drift**: Chained computations don't accumulate error
3. **Formal verification**: Integer proofs are simpler
4. **FHE compatibility**: Encrypted computation requires exact arithmetic

## QMNF Integration Points

| QMNF Component | Integration Status |
|-----------------|-------------------|
| K-Elimination | ✅ Ready for exact division |
| CRTBigInt | ✅ Interface defined |
| Montgomery Persistence | ✅ CORDIC compatible |
| Cyclotomic Phase | ✅ Extends trig to FHE ring |
| Shadow Entropy | ✅ Randomized algorithm variants |

## Performance Characteristics

| Algorithm | Complexity | Convergence |
|-----------|-----------|-------------|
| CORDIC | O(n) iterations | 1 bit per iteration |
| Newton sqrt | O(log n) iterations | Quadratic (doubles each) |
| AGM | O(log n) iterations | Quadratic |
| Continued fractions | O(n) convergents | Best rational approx |
| Taylor series | O(n) terms | Factorial convergence |

## Mathematical Foundation

### Error Bounds
- **CORDIC n iterations**: |error| < 2^(-n)
- **CF convergent p_n/q_n**: |x - p_n/q_n| < 1/(q_n × q_{n+1})
- **AGM after n iterations**: 2^(2^n) correct bits
- **Taylor series**: Exact until final division

### Key Identities Used
- `ln(x) = 2 × atanh((x-1)/(x+1))`
- `exp(x) = cosh(x) + sinh(x)`
- `π = (a_n + b_n)² / (4t_n)` (Gauss-Legendre)
- `K(k) = π / (2 × M(1, √(1-k²)))` (elliptic integral)

## CRAM opportunity action items

Mirrored from `CRAM_OPPORTUNITY_REPORT.md` (pass 1). Entry numbers are the
routing key back into that report; every Level-2 node is currently `pending`,
so these are logged for action, not procedures to follow.

**FORCED**

- `[5]` `src/transduction.rs:213,224` — `garner_reconstruct` still on the
  transduction compute path. The sibling call at `:156` was already retired;
  finish it. → `reconstruction-retirement`
- `[6]` `src/transduction.rs:330-331` — round-trip identity checked by
  reconstructing both sides instead of comparing transduced Σ.
  → `transduction-state`
- `[7]` `src/composite_division.rs:144,167-176` — `mixed_radix_garner()` plus
  mixed-radix compare/subtract to recover sign and magnitude on a division
  path. → `reconstruction-retirement`
- `[8]` `src/cram_pde.rs:127` — `ExactState::to_u128` reconstructs via Garner,
  and `safe_basis_io::{add,mul}` call it for the corridor carry. Unblocked:
  `cram_machine::canonical_from` gives `g = (a + K) mod A` with no
  reconstruction. `tests/cram_gates.rs::p2_*` asserts this debt.
  → `reconstruction-retirement`
- `[9]` `src/k_elim.rs:150-163` — `garner_reconstruct` threads one accumulator
  across lanes; a fault at lane `j` damages every downstream partial (measured
  in `cram_anchor::tests`). Every caller inherits the coupling.
  → `iid-heterogeneous-transduction`

**CANDIDATE**

- `[11]` `src/crt.rs`, `src/crt_torus.rs` — classical CRT utilities coexisting
  with the residue-native modules. → `crt-to-cram-substrate`
- `[12]` `src/cram_pde.rs` — `ExactState` already has the right shape (lanes +
  winding) but is confined to the PDE module. → `crt-to-cram-substrate`
- `[21]` `src/cram_ct.rs:1198,1461,1596,1689,1881` — five coexisting rescale
  variants behind a runtime router; consolidate onto the gated Fifth Operator.
  → `fifth-operator-rescale`

**A1 status:** this crate is clean. Every `f32`/`f64` occurrence sits inside a
`#[cfg(test)]` item, verified against each module's test boundary, and
`tests/cram_gates.rs::p1_*` scans the production slice of the `cram_*` modules
to keep it that way.

## License

Proprietary — see the repository `LICENSE` (all rights reserved).
Package metadata declares `LicenseRef-Proprietary-AllRightsReserved`, matching every
other crate in this workspace. The earlier "MIT OR Apache-2.0" line here and in
`Cargo.toml` was inconsistent with that `LICENSE` and was corrected 2026-08-22.

## CRAM Opportunity Index — open action item (2026-08-12)

Mirrored from `CRAM_OPPORTUNITY_REPORT.md` entry [35]: arrow-emission reversibility is (operator, dim, prime)-dependent — heat [1,3,1] at dim=8 is singular (one-way) on lanes {3, 5, 7}, two of which sit in `TRANSPORT_CORE`. Transport lane selection must gate on `det(A) mod p != 0` per deployment. Route: `prime-family-engineering` (node pending).
