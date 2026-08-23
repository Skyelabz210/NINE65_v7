# QMNF Exact Transcendentals Engine - Project Documentation

## Project Overview

The QMNF Exact Transcendentals Engine is a Rust crate that provides exact integer arithmetic for transcendental functions. The project follows the "Truth cannot be approximated" philosophy, prohibiting any floating-point operations in computations. All algorithms reduce to addition, subtraction, multiplication, bit shifts, and exact integer division.

### Key Features

- **Exact Integer Arithmetic**: No floating-point operations anywhere in the computation
- **Multiple Algorithm Implementations**: CORDIC, Integer Newton-Raphson, AGM, Binary Splitting, Continued Fractions
- **QMNF Integration**: Implements QMNF components like K-Elimination for exact division
- **High Performance**: Optimized algorithms with documented complexity characteristics
- **Comprehensive Testing**: 47/47 tests passing with cross-validation and identity verification

### Algorithms Implemented

#### 1. CORDIC (Coordinate Rotation Digital Computer)
- Shift-and-add algorithm with zero multiplies in the main loop
- Supports circular mode (sin, cos, tan, atan) and hyperbolic mode (sinh, cosh, exp, ln)
- Convergence rate: 1 bit per iteration

#### 2. Integer Square Root
- Newton-Raphson: Quadratic convergence with exact integer division
- Digit-by-digit: No division needed, linear convergence
- Binary search: Simple and guaranteed correct
- Rational approximations with specified precision

#### 3. Continued Fractions
- Best rational approximations with proven error bounds
- Support for √2, π, e, golden ratio, and Pell equation solving
- Convergent generation with alternating over/under properties

#### 4. AGM (Arithmetic-Geometric Mean)
- Quadratically convergent algorithms (doubles precision each iteration)
- Computes π, natural logarithm, exponential, and elliptic integrals
- Gauss-Legendre algorithm for π computation

#### 5. Taylor Series (Binary Splitting)
- Efficient series evaluation with automatic convergence
- Supports exp, sin, cos, atan, ln(2), and e constant
- Machin's formula for π computation

#### 6. Precomputed Constants
- High-precision constants for immediate use (π, e, φ, √2, ln(2))
- Best rational approximations with documented accuracy

## Project Structure

```
exact_transcendentals/
├── Cargo.toml          # Package manifest
├── README.md          # Main documentation
├── src/
│   ├── agm.rs         # Arithmetic-Geometric Mean algorithms
│   ├── bigint.rs      # Arbitrary precision integer support
│   ├── binary_splitting.rs # Binary splitting for series evaluation
│   ├── constants.rs   # Precomputed mathematical constants
│   ├── continued_fraction.rs # Continued fraction algorithms
│   ├── cordic.rs      # CORDIC algorithm implementations
│   ├── crt.rs         # Chinese Remainder Theorem support
│   ├── crt_rational.rs # CRT rational number support
│   ├── lib.rs         # Main library entry point
│   └── sqrt.rs        # Integer square root algorithms
├── scripts/           # Utility scripts
└── target/            # Build artifacts
```

## Building and Running

### Prerequisites
- Rust 2021 edition or later
- Cargo package manager

### Build Commands
```bash
# Build in debug mode
cargo build

# Build in release mode (optimized)
cargo build --release

# Run all tests
cargo test

# Run tests with cross-validation
cargo test --tests

# Run benchmarks (if available)
cargo bench
```

### Features
- `std` (default): Enables standard library support
- `arbitrary-precision`: Enables arbitrary precision via CRTBigInt + HCVLangBigInt integration

## Development Conventions

### Error Handling
- Uses custom `TranscendentalError` enum for all error conditions
- Follows QMNF ArithResult/OverflowError pattern with explicit typed errors
- No silent saturation or sentinel values as error indicators

### Fixed-Point Representation
- Uses power-of-2 scaling for fixed-point arithmetic
- Common scales: 2^30 (balance of precision and headroom), 2^62 (maximum for i64)
- All transcendental functions operate on scaled integer inputs

### Testing Strategy
- Comprehensive unit tests for each algorithm
- Cross-validation tests verifying agreement between independent algorithm paths
- Identity verification tests confirming mathematical relationships
- Truth-perturber discovery tests exploring mathematical boundaries

### Performance Targets
- 64-bit precision: <100ns per operation
- Arbitrary precision: O(M(n) log n) where M(n) is multiplication time
- Documented complexity and convergence characteristics for all algorithms

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
|-----------|------------|-------------|
| CORDIC | O(n) iterations | 1 bit per iteration |
| Newton sqrt | O(log n) iterations | Quadratic (doubles each) |
| AGM | O(log n) iterations | Quadratic |
| Continued fractions | O(n) convergents | Best rational approx |
| Taylor series | O(n) terms | Factorial convergence |

## License

Proprietary — `LicenseRef-Proprietary-AllRightsReserved`, matching this crate's
`Cargo.toml` and the repository `LICENSE` ("All rights reserved"). This file
previously read "MIT OR Apache-2.0"; no permission to use, copy, modify or
distribute is granted by that stale line or by any other copy of it.
