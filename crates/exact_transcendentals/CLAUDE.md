# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A Rust library (`no_std`-compatible) providing exact integer-only implementations of transcendental functions. No floating-point operations anywhere in computation — all algorithms reduce to add, subtract, multiply, bit-shift, and exact integer division. Part of the QMNF ecosystem.

## Build & Test Commands

```bash
cargo build                    # Debug build
cargo build --release          # Optimized build (LTO enabled)
cargo test                     # Run all 143 tests (base)
cargo test --features arbitrary-precision  # Run all 179 tests (with CRTBigInt)
cargo test -- --nocapture      # With println! output visible
cargo test cordic              # Tests for a specific module
cargo test test_sincos_zero    # Run a single test by name
cargo test --no-default-features --features arbitrary-precision  # no_std + CRT
cargo test --no-default-features  # Build in no_std mode
```

No linter or formatter is configured. No CI pipeline exists yet.

### Quality Gates

```bash
scripts/quality-gate.sh        # Run all 6 gates (see below)
scripts/check_no_floats.py     # Float scanner only (fast)
```

A **git pre-commit hook** automatically runs the quality gate when `src/` or `Cargo.toml` files are staged. The 6 gates are:

| Gate | What it checks |
|------|----------------|
| Float scan | Zero f32/f64 in production code (skips `#[cfg(test)]` blocks) |
| Debug build | `cargo build` succeeds |
| Release build | `cargo build --release` succeeds (LTO) |
| no_std build | `cargo build --no-default-features` succeeds |
| Tests (debug) | `cargo test` — all 143 base tests pass |
| Tests (release) | `cargo test --release` — identical results under optimization |
| Tests (arb-prec) | `cargo test --features arbitrary-precision` — 179 tests (base + CRT) |

## Architecture

All values are represented as **scaled integers**: a real value `v` is stored as `v * 2^n` where `n` is the scale factor (typically 30 or 62 bits). The core type `ExactRational` (in `lib.rs`) holds exact `num/den` pairs with `i128` components and uses Stein's binary GCD for reduction.

### Module Map

| Module | What it computes | Technique | Scale factor |
|---|---|---|---|
| `cordic` | sin, cos, tan, atan, atan2, magnitude, sinh, cosh, exp, ln | Shift-and-add rotation (zero multiplies in main loop) | `2^30` (i64) |
| `sqrt` | isqrt (Newton, digit-by-digit, binary search), rational sqrt, inverse sqrt, cube root | Newton-Raphson / digit extraction | Various |
| `agm` | AGM iteration, pi (Gauss-Legendre), ln, exp, elliptic K(k), Gauss/lemniscate constants | Arithmetic-geometric mean | `2^62` (u128) |
| `binary_splitting` | exp, sin, cos, atan, pi (Machin + Chudnovsky), ln2, e | Recursive divide-and-conquer series evaluation | Configurable |
| `continued_fraction` | CF for sqrt(n)/e/pi/phi/ln2, convergents, Pell equation solver, generalized tan CF | Continued fraction expansion | Exact rational |
| `constants` | Precomputed pi/e/phi/sqrt2/ln2/etc at 30-bit and 62-bit precision, rational approximations, CORDIC angle tables, Pade coefficients | Lookup tables | `2^30` / `2^62` |
| `bigint`* | `HCVLangBigInt` — arbitrary-precision signed integers (base 2^64 limbs) | Schoolbook mul, binary GCD | Unlimited |
| `crt`* | `CRTBigInt` — Chinese Remainder Theorem bounded integers (10 Fibonacci-prime moduli) | CRT + Garner reconstruction | ±2^126 |
| `crt_rational`* | `CRTRational` — exact rational with arbitrary-precision num/den | BigInt GCD reduction | Unlimited |

*Modules marked with `*` require `--features arbitrary-precision`.

### Key Design Patterns

- **Two CORDIC engines**: `CordicEngine` (circular: trig) and `HyperbolicCordic` (hyperbolic: exp/ln). Hyperbolic mode repeats iterations at indices 4, 13, 40, ... (the 3k+1 sequence) for convergence.
- **Binary splitting** uses a `BinarySplitState { p, q, b, t }` tuple that combines recursively — the generic `binary_split()` function accepts closures for `a(k)`, `b(k)`, `p(k)`, `q(k)`.
- **Overflow protection**: `binary_split()` returns `Option` (None on overflow). AGM uses `checked_mul` with fallback paths. `checked_mul_i128`/`checked_add_i128` helpers return `TranscendentalError`.
- **Checked API**: `tan_checked()`, `ln_checked()`, `exp_checked()` return `TransResult<T>` instead of sentinel values (`i64::MAX`, `i64::MIN`, `u128::MAX`). `ExactRational` has `checked_add`, `checked_mul`, `checked_div` returning `Option`. Legacy sentinel-based methods are retained for backward compatibility.
- **`#[cfg(test)]` float usage**: `to_f64()` and `from_scaled()` helpers exist only behind `#[cfg(test)]` for verification against `std::f64::consts`. This is the only place floats appear.

### Feature Flags

- `std` (default) — standard library support
- `arbitrary-precision` — CRTBigInt + HCVLangBigInt + CRTRational + big binary splitting + big_isqrt

## Integer-Only Mandate

This crate enforces zero floating-point in production code. All numeric values use `i64`, `u64`, `i128`, or `u128`. The `ExactRational` type handles exact division. Float conversions exist only in `#[cfg(test)]` blocks for comparison against known constants.

## Dependencies

Zero external dependencies. Zero dev-dependencies. Pure Rust, `no_std`-compatible with `alloc`.
