# NexGen Rational Integration Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Integrate the NexGen exact rational arithmetic framework into NINE65 v5 as a workspace crate, bridging it with existing RNS/K-Elimination infrastructure for exact noise tracking and parameter computation.

**Architecture:** NexGen Rational becomes `crates/nexgen_rational/` — a zero-dependency workspace crate providing i128-based exact rational arithmetic (NexGenRat). The nine65 crate gains a `rational_bridge` module that connects NexGenRat to existing ExactDivider, KElimination, and NoiseBudgetTracker. This gives NINE65 exact fractional arithmetic (a/b) alongside its existing modular integer RNS pipeline.

**Tech Stack:** Rust 2021, i128 checked arithmetic, binary GCD (Stein's), adaptive normalization, proptest for property testing.

**Key constraint:** NINE65 already has `ExactCoeff` in `arithmetic/exact_coeff.rs` (dual-track RNS coefficients). NexGen also has `ExactCoeff` (i128 wrapper). These are **different types** — NexGen's lives namespaced under `nexgen_rational::ExactCoeff`, no rename needed.

---

## Task 1: Create nexgen_rational workspace crate

**Files:**
- Create: `crates/nexgen_rational/Cargo.toml`
- Create: `crates/nexgen_rational/src/lib.rs`
- Create: `crates/nexgen_rational/src/exact_coeff.rs`
- Create: `crates/nexgen_rational/src/binary_gcd.rs`
- Create: `crates/nexgen_rational/src/rat_ng/mod.rs`
- Create: `crates/nexgen_rational/src/rat_ng/types.rs`
- Create: `crates/nexgen_rational/src/rat_ng/error.rs`
- Create: `crates/nexgen_rational/src/rat_ng/normalize.rs`
- Create: `crates/nexgen_rational/src/rat_ng/policy.rs`
- Create: `crates/nexgen_rational/src/rat_ng/ops.rs`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "nexgen_rational"
version.workspace = true
edition.workspace = true
authors.workspace = true
description = "Exact i128 rational arithmetic — zero floating-point"

[dependencies]
# Zero dependencies — pure integer arithmetic

[dev-dependencies]
proptest = { workspace = true }
```

**Step 2: Extract source from zip and copy into crate**

Source location: `/home/acid/Downloads/nexgen_rational_execution.zip`

Extract all `.rs` files from `src/` into `crates/nexgen_rational/src/`, preserving directory structure. The files are:
- `src/lib.rs` (17 lines — module root)
- `src/exact_coeff.rs` (184 lines — i128 coefficient wrapper)
- `src/binary_gcd.rs` (202 lines — Stein's GCD algorithm)
- `src/rat_ng/mod.rs` (14 lines — rational module root)
- `src/rat_ng/types.rs` (242 lines — NexGenRat, DenState, DivOut)
- `src/rat_ng/error.rs` (80 lines — ArithmeticError enum)
- `src/rat_ng/normalize.rs` (486 lines — I3 adaptive normalization)
- `src/rat_ng/policy.rs` (366 lines — I1/I2 division trichotomy)
- `src/rat_ng/ops.rs` (498 lines — add/sub/mul/div with I4 overflow)

**Important fix:** If the extracted Cargo.toml says `edition = "2024"`, change it to use `edition.workspace = true` (workspace is "2021"). The "2024" edition requires Rust 1.85+ and may cause issues.

**Step 3: Verify the crate builds standalone**

Run: `cargo build -p nexgen_rational --release`
Expected: Build succeeds with 0 errors.

**Step 4: Run NexGen's 95 built-in tests**

Run: `cargo test -p nexgen_rational --release`
Expected: 95 tests pass (11 exact_coeff + 14 binary_gcd + 10 types + 2 error + 16 normalize + 17 policy + 25 ops).

**Step 5: Commit**

```bash
git add crates/nexgen_rational/
git commit -m "feat: add nexgen_rational crate — exact i128 rational arithmetic"
```

---

## Task 2: Wire nexgen_rational into workspace

**Files:**
- Modify: `Cargo.toml` (workspace root, line 2 — members list)
- Modify: `crates/nine65/Cargo.toml` (add dependency)

**Step 1: Add to workspace members**

In root `Cargo.toml`, the members list at line 2 says `members = ["crates/*"]`. Since `nexgen_rational` is in `crates/`, it's auto-included. Verify this:

Run: `cargo build --workspace --release 2>&1 | grep nexgen_rational`
Expected: Shows `Compiling nexgen_rational v0.1.0`

**Step 2: Add nexgen_rational as optional dependency to nine65**

In `crates/nine65/Cargo.toml`, add under `[dependencies]`:

```toml
nexgen_rational = { path = "../nexgen_rational", optional = true }
```

Add a feature flag:

```toml
[features]
# ... existing features ...
exact_rational = ["nexgen_rational"]
```

**Step 3: Verify workspace still builds**

Run: `cargo build --workspace --release`
Expected: Build succeeds, all 4 crates compile.

**Step 4: Verify nine65 builds with the new feature**

Run: `cargo build -p nine65 --release --features exact_rational`
Expected: Build succeeds, nexgen_rational is linked.

**Step 5: Run all tests to ensure no regression**

Run: `cargo test --workspace --release`
Expected: All existing tests pass + NexGen's 95 tests.

**Step 6: Commit**

```bash
git add Cargo.toml crates/nine65/Cargo.toml
git commit -m "feat: wire nexgen_rational into workspace as optional nine65 dependency"
```

---

## Task 3: Create rational bridge module in nine65

**Files:**
- Create: `crates/nine65/src/arithmetic/rational_bridge.rs`
- Modify: `crates/nine65/src/arithmetic/mod.rs` (add module + re-export)

**Step 1: Write the failing test**

Create a test at the bottom of `rational_bridge.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_rational_to_residues() {
        // 3/4 should produce correct residues mod small primes
        let rat = RationalBridge::new(3, 4).unwrap();
        let p = 17u64;
        // 3/4 mod 17 = 3 * 4^(-1) mod 17 = 3 * 13 mod 17 = 39 mod 17 = 5
        let residue = rat.to_residue(p);
        assert_eq!(residue, 5);
    }

    #[test]
    fn bridge_exact_division_trichotomy() {
        // 12/4 = 3 exactly → ExactAFC
        let result = RationalBridge::exact_divide(12, 4);
        assert!(result.is_exact());
        assert_eq!(result.quotient(), 3);
    }

    #[test]
    fn bridge_from_kelim_reconstruction() {
        // Reconstruct from K-Elimination output
        let rat = RationalBridge::from_integer(42);
        assert_eq!(rat.numerator(), 42);
        assert_eq!(rat.denominator(), 1);
        assert!(rat.is_integer());
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p nine65 --lib --release --features exact_rational -- arithmetic::rational_bridge`
Expected: FAIL — module doesn't exist yet.

**Step 3: Implement the bridge**

```rust
//! Bridge between NexGen exact rationals and NINE65's RNS infrastructure.
//!
//! Provides conversions between NexGenRat (i128 exact fractions) and
//! NINE65's modular residue types for exact parameter computation.

use nexgen_rational::exact_coeff::ExactCoeff as NGExactCoeff;
use nexgen_rational::rat_ng::types::{NexGenRat, DivOut};
use nexgen_rational::rat_ng::error::ArithmeticError as NGError;
use nexgen_rational::rat_ng::ops;
use nexgen_rational::rat_ng::policy;

/// Bridge between exact rationals and RNS residue representation.
///
/// Holds a NexGenRat value and provides conversions to/from
/// the modular arithmetic used by NINE65's FHE pipeline.
#[derive(Clone, Debug)]
pub struct RationalBridge {
    inner: NexGenRat,
}

/// Errors from rational bridge operations.
#[derive(Debug)]
pub enum BridgeError {
    /// Denominator was zero
    ZeroDenominator,
    /// Arithmetic overflow in i128
    Overflow(String),
    /// Modular inverse does not exist (gcd(den, p) != 1)
    NoInverse { den: u64, modulus: u64 },
    /// NexGen arithmetic error
    Arithmetic(NGError),
}

impl From<NGError> for BridgeError {
    fn from(e: NGError) -> Self {
        BridgeError::Arithmetic(e)
    }
}

impl RationalBridge {
    /// Create a rational bridge from numerator/denominator.
    pub fn new(num: i128, den: i128) -> Result<Self, BridgeError> {
        if den == 0 {
            return Err(BridgeError::ZeroDenominator);
        }
        let rat = NexGenRat::new(NGExactCoeff(num), NGExactCoeff(den));
        Ok(Self { inner: rat })
    }

    /// Create from an integer value (den = 1).
    pub fn from_integer(val: i128) -> Self {
        Self {
            inner: NexGenRat::new(NGExactCoeff(val), NGExactCoeff(1)),
        }
    }

    /// Access numerator as i128.
    pub fn numerator(&self) -> i128 {
        self.inner.numerator().0
    }

    /// Access denominator as i128.
    pub fn denominator(&self) -> i128 {
        self.inner.denominator().0
    }

    /// Returns true if this is an integer (den = 1).
    pub fn is_integer(&self) -> bool {
        self.inner.is_integer()
    }

    /// Convert rational to a residue mod p.
    ///
    /// Computes (num * den^(-1)) mod p using extended Euclidean algorithm.
    /// Returns the residue in [0, p).
    ///
    /// # Panics
    /// If gcd(den, p) != 1 (inverse doesn't exist).
    pub fn to_residue(&self, p: u64) -> u64 {
        let num = self.inner.numerator().0.rem_euclid(p as i128) as u64;
        let den = self.inner.denominator().0.rem_euclid(p as i128) as u64;
        let den_inv = mod_inverse_u64(den, p)
            .expect("denominator must be invertible mod p");
        ((num as u128 * den_inv as u128) % p as u128) as u64
    }

    /// Convert rational to residues for multiple moduli.
    pub fn to_residues(&self, moduli: &[u64]) -> Vec<u64> {
        moduli.iter().map(|&p| self.to_residue(p)).collect()
    }

    /// Perform exact integer division using NexGen's trichotomy.
    ///
    /// Returns DivOut (ExactInverse, ExactAFC, or FPD).
    pub fn exact_divide(a: i128, b: i128) -> DivOut {
        policy::divide_coeff(NGExactCoeff(a), NGExactCoeff(b))
    }

    /// Add two rational bridges.
    pub fn add(&self, other: &Self) -> Result<Self, BridgeError> {
        let result = ops::add(&self.inner, &other.inner)?;
        Ok(Self { inner: result })
    }

    /// Subtract two rational bridges.
    pub fn sub(&self, other: &Self) -> Result<Self, BridgeError> {
        let result = ops::sub(&self.inner, &other.inner)?;
        Ok(Self { inner: result })
    }

    /// Multiply two rational bridges.
    pub fn mul(&self, other: &Self) -> Result<Self, BridgeError> {
        let result = ops::mul(&self.inner, &other.inner)?;
        Ok(Self { inner: result })
    }

    /// Divide two rational bridges.
    pub fn div(&self, other: &Self) -> Result<Self, BridgeError> {
        let result = ops::div(&self.inner, &other.inner)?;
        Ok(Self { inner: result })
    }
}

/// Extended Euclidean algorithm for modular inverse.
/// Returns a^(-1) mod m, or None if gcd(a, m) != 1.
fn mod_inverse_u64(a: u64, m: u64) -> Option<u64> {
    if m == 0 {
        return None;
    }
    if m == 1 {
        return Some(0);
    }
    let (mut old_r, mut r) = (m as i128, a as i128);
    let (mut old_s, mut s) = (0i128, 1i128);

    while r != 0 {
        let q = old_r / r;
        let tmp_r = r;
        r = old_r - q * r;
        old_r = tmp_r;
        let tmp_s = s;
        s = old_s - q * s;
        old_s = tmp_s;
    }

    if old_r != 1 {
        return None; // gcd != 1, no inverse
    }

    Some(old_s.rem_euclid(m as i128) as u64)
}
```

**Step 4: Add module to arithmetic/mod.rs**

Add to `crates/nine65/src/arithmetic/mod.rs`:

```rust
#[cfg(feature = "exact_rational")]
pub mod rational_bridge;
#[cfg(feature = "exact_rational")]
pub use rational_bridge::RationalBridge;
```

**Step 5: Run tests to verify they pass**

Run: `cargo test -p nine65 --lib --release --features exact_rational -- arithmetic::rational_bridge`
Expected: 3 tests pass.

**Step 6: Commit**

```bash
git add crates/nine65/src/arithmetic/rational_bridge.rs crates/nine65/src/arithmetic/mod.rs
git commit -m "feat: add rational_bridge connecting NexGen rationals to NINE65 RNS"
```

---

## Task 4: Exact noise budget tracking with rationals

**Files:**
- Create: `crates/nine65/src/noise/exact_noise.rs`
- Modify: `crates/nine65/src/noise/mod.rs` (add module)

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_noise_encrypt_has_initial_budget() {
        let tracker = ExactNoiseTracker::new(152); // 128-bit security → 152-bit budget
        assert_eq!(tracker.total_budget_bits(), 152);
        assert!(tracker.remaining_budget_bits() > 0);
    }

    #[test]
    fn exact_noise_mul_reduces_budget() {
        let mut tracker = ExactNoiseTracker::new(152);
        let before = tracker.remaining_budget_rational();
        tracker.on_mul(16); // plaintext modulus t=16, log2(t)=4
        let after = tracker.remaining_budget_rational();
        // Multiplication increases noise, reducing budget
        assert!(after.numerator() < before.numerator()
            || after.denominator() > before.denominator(),
            "Budget must decrease after multiplication");
    }

    #[test]
    fn exact_noise_remaining_depth_estimate() {
        let mut tracker = ExactNoiseTracker::new(152);
        let depth = tracker.remaining_depth_estimate(16);
        // With 152-bit budget and t=16, should support many levels
        assert!(depth > 10, "Should support at least 10 levels with 152-bit budget");
    }

    #[test]
    fn exact_noise_tracks_additions_cheaply() {
        let mut tracker = ExactNoiseTracker::new(152);
        let before = tracker.remaining_budget_bits_approx();
        for _ in 0..100 {
            tracker.on_add();
        }
        let after = tracker.remaining_budget_bits_approx();
        // 100 additions should consume roughly 7 bits (log2(100) ≈ 6.6)
        let consumed = before - after;
        assert!(consumed < 10, "100 additions should consume < 10 bits, got {consumed}");
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p nine65 --lib --release --features exact_rational -- noise::exact_noise`
Expected: FAIL — module doesn't exist.

**Step 3: Implement exact noise tracker**

```rust
//! Exact noise budget tracking using NexGen rational arithmetic.
//!
//! Tracks FHE noise growth as exact rational fractions instead of
//! millibits approximations. This gives precise depth estimates
//! and optimal bootstrap scheduling.

use crate::arithmetic::rational_bridge::RationalBridge;

/// Exact noise tracker using rational arithmetic.
///
/// Noise budget is tracked as an exact rational number of bits.
/// Operations consume budget according to standard BFV noise formulas.
///
/// # Noise model (BFV)
/// - Encrypt: initial noise ≈ 3 bits
/// - Add: noise_out = noise_a + noise_b (worst case: +1 bit)
/// - Mul: noise_out ≈ noise_a + noise_b + log2(t) + small constant
/// - Rescale: noise_out = noise - log2(q_i)
pub struct ExactNoiseTracker {
    /// Total budget in bits (rational for sub-bit precision).
    total_budget: RationalBridge,
    /// Current noise level in bits (rational).
    current_noise: RationalBridge,
    /// Number of additions since last multiplication.
    add_count: u64,
    /// Number of multiplications performed.
    mul_count: u64,
}

impl ExactNoiseTracker {
    /// Create a new tracker with the given budget in bits.
    pub fn new(budget_bits: u32) -> Self {
        let total = RationalBridge::from_integer(budget_bits as i128);
        // Initial noise after encryption: ~3.2 bits = 16/5
        let initial_noise = RationalBridge::new(16, 5).unwrap();
        Self {
            total_budget: total,
            current_noise: initial_noise,
            add_count: 0,
            mul_count: 0,
        }
    }

    /// Total budget in bits.
    pub fn total_budget_bits(&self) -> u32 {
        self.total_budget.numerator() as u32
    }

    /// Remaining budget as exact rational.
    pub fn remaining_budget_rational(&self) -> RationalBridge {
        self.total_budget.sub(&self.current_noise)
            .unwrap_or_else(|_| RationalBridge::from_integer(0))
    }

    /// Remaining budget as approximate integer bits (floor).
    pub fn remaining_budget_bits_approx(&self) -> u32 {
        let remaining = self.remaining_budget_rational();
        let n = remaining.numerator();
        let d = remaining.denominator();
        if n <= 0 || d <= 0 {
            return 0;
        }
        (n / d) as u32
    }

    /// Record an addition operation.
    ///
    /// Additions are cheap: we batch them and compute log2(count)
    /// at query time rather than per-operation.
    pub fn on_add(&mut self) {
        self.add_count += 1;
    }

    /// Record a multiplication operation.
    ///
    /// Multiplication grows noise by approximately:
    ///   noise_new = noise_old * 2 + log2(t) + 1
    ///
    /// We use exact rationals: noise_new = noise_old + noise_old + log2_exact(t) + 1
    pub fn on_mul(&mut self, plaintext_modulus: u64) {
        // Flush pending additions first
        self.flush_additions();

        // Noise doubles + log2(t) + small constant
        let doubled = self.current_noise.add(&self.current_noise).unwrap();
        let log2_t = RationalBridge::from_integer(ilog2_exact(plaintext_modulus));
        let constant = RationalBridge::from_integer(1);
        self.current_noise = doubled.add(&log2_t).unwrap().add(&constant).unwrap();
        self.mul_count += 1;
    }

    /// Record a rescale operation (modulus switching).
    ///
    /// Rescaling removes log2(q_i) bits of noise.
    pub fn on_rescale(&mut self, dropped_modulus: u64) {
        self.flush_additions();
        let reduction = RationalBridge::from_integer(ilog2_exact(dropped_modulus));
        self.current_noise = self.current_noise.sub(&reduction)
            .unwrap_or_else(|_| RationalBridge::from_integer(0));
    }

    /// Estimate remaining multiplicative depth.
    ///
    /// Computes how many more multiplications can be performed
    /// before noise exceeds the budget.
    pub fn remaining_depth_estimate(&mut self, plaintext_modulus: u64) -> u32 {
        self.flush_additions();
        let remaining = self.remaining_budget_bits_approx();
        let cost_per_mul = ilog2_exact(plaintext_modulus) as u32 + 2; // noise + log2(t) + const
        if cost_per_mul == 0 {
            return u32::MAX;
        }
        remaining / cost_per_mul
    }

    /// Flush batched additions into noise estimate.
    ///
    /// log2(n additions) ≈ ceil(log2(add_count + 1))
    fn flush_additions(&mut self) {
        if self.add_count == 0 {
            return;
        }
        let add_noise_bits = ilog2_exact(self.add_count + 1);
        let add_noise = RationalBridge::from_integer(add_noise_bits);
        self.current_noise = self.current_noise.add(&add_noise)
            .unwrap_or(self.current_noise.clone());
        self.add_count = 0;
    }
}

/// Integer-only log2 (ceiling), returns 0 for input 0-1.
fn ilog2_exact(val: u64) -> i128 {
    if val <= 1 {
        return 0;
    }
    (64 - (val - 1).leading_zeros()) as i128
}
```

**Step 4: Add module to noise/mod.rs**

Add to `crates/nine65/src/noise/mod.rs`:

```rust
#[cfg(feature = "exact_rational")]
pub mod exact_noise;
#[cfg(feature = "exact_rational")]
pub use exact_noise::ExactNoiseTracker;
```

**Step 5: Run tests to verify they pass**

Run: `cargo test -p nine65 --lib --release --features exact_rational -- noise::exact_noise`
Expected: 4 tests pass.

**Step 6: Commit**

```bash
git add crates/nine65/src/noise/exact_noise.rs crates/nine65/src/noise/mod.rs
git commit -m "feat: exact noise budget tracking via NexGen rationals"
```

---

## Task 5: Exact BFV delta computation

**Files:**
- Create: `crates/nine65/src/params/exact_params.rs`
- Modify: `crates/nine65/src/params/mod.rs` (add module)

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_delta_computation() {
        // Δ = q/t where q = ciphertext modulus, t = plaintext modulus
        // For q = 65537, t = 16: Δ = 65537/16 = 4096 + 1/16
        let delta = ExactDelta::new(65537, 16);
        assert_eq!(delta.floor(), 4096);
        assert_eq!(delta.remainder_num(), 1);
        assert_eq!(delta.remainder_den(), 16);
    }

    #[test]
    fn exact_delta_scale_and_round() {
        // scale_and_round(m, Δ) = round(m * t / q) = round(m / Δ)
        let delta = ExactDelta::new(65537, 16);
        // m = 4096 → m/Δ = 4096 * 16 / 65537 ≈ 0.9999... → rounds to 1
        let result = delta.scale_and_round(4096);
        assert_eq!(result, 1);
    }

    #[test]
    fn exact_delta_for_secure_config() {
        // For secure_128: q is product of ~30-bit primes
        // Just verify it doesn't overflow
        let q: u128 = (1u128 << 60) - 1; // ~60-bit modulus
        let t: u64 = 65537;
        let delta = ExactDelta::from_u128(q, t);
        assert!(delta.floor_u128() > 0);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p nine65 --lib --release --features exact_rational -- params::exact_params`
Expected: FAIL — module doesn't exist.

**Step 3: Implement exact delta**

```rust
//! Exact BFV delta (Δ = q/t) computation using rational arithmetic.
//!
//! In BFV encryption, Δ = floor(q/t) is used for encoding. The exact
//! remainder q - t*Δ affects noise growth. Tracking this exactly
//! prevents rounding errors from accumulating across levels.

use crate::arithmetic::rational_bridge::RationalBridge;

/// Exact representation of Δ = q/t for BFV encoding.
///
/// Stores Δ as floor(q/t) + remainder/t, giving exact fractional
/// representation without any approximation.
pub struct ExactDelta {
    /// The exact rational q/t
    rational: RationalBridge,
    /// Cached floor value
    floor_val: i128,
    /// Remainder: q - t * floor(q/t)
    remainder: i128,
    /// Plaintext modulus t
    t: i128,
}

impl ExactDelta {
    /// Create exact delta from q and t (both fitting in i128).
    pub fn new(q: u64, t: u64) -> Self {
        let q128 = q as i128;
        let t128 = t as i128;
        let floor_val = q128 / t128;
        let remainder = q128 - t128 * floor_val;
        let rational = RationalBridge::new(q128, t128).unwrap();
        Self {
            rational,
            floor_val,
            remainder,
            t: t128,
        }
    }

    /// Create from u128 values (for large moduli).
    ///
    /// Truncates to i128 range. For moduli > 2^127, use RNS-level
    /// delta computation instead.
    pub fn from_u128(q: u128, t: u64) -> Self {
        // For very large q, we compute floor and remainder using u128
        let t128 = t as u128;
        let floor_val = (q / t128) as i128;
        let remainder = (q % t128) as i128;
        let rational = RationalBridge::new(floor_val * t as i128 + remainder, t as i128).unwrap();
        Self {
            rational,
            floor_val,
            remainder,
            t: t as i128,
        }
    }

    /// Floor of q/t.
    pub fn floor(&self) -> i128 {
        self.floor_val
    }

    /// Floor as u128 (for large values).
    pub fn floor_u128(&self) -> u128 {
        self.floor_val as u128
    }

    /// Remainder numerator: q mod t.
    pub fn remainder_num(&self) -> i128 {
        self.remainder
    }

    /// Remainder denominator (always t).
    pub fn remainder_den(&self) -> i128 {
        self.t
    }

    /// Exact scale-and-round: round(m * t / q).
    ///
    /// This is the BFV decoding operation. Using exact arithmetic
    /// ensures no rounding drift.
    pub fn scale_and_round(&self, m: i128) -> i128 {
        // round(m * t / q) = floor(m * t / q + 1/2)
        //                   = floor((2 * m * t + q) / (2 * q))
        let two_m_t = 2i128.checked_mul(m).and_then(|v| v.checked_mul(self.t));
        let q = self.floor_val * self.t + self.remainder;
        let two_q = 2i128.checked_mul(q);

        match (two_m_t, two_q) {
            (Some(num_base), Some(denom)) if denom != 0 => {
                let numerator = num_base.checked_add(q).unwrap_or(num_base);
                numerator / denom
            }
            _ => {
                // Fallback for overflow: use simpler formula
                (m * self.t + q / 2) / q
            }
        }
    }
}
```

**Step 4: Add module to params/mod.rs**

Find the params module and add:

```rust
#[cfg(feature = "exact_rational")]
pub mod exact_params;
#[cfg(feature = "exact_rational")]
pub use exact_params::ExactDelta;
```

**Step 5: Run tests to verify they pass**

Run: `cargo test -p nine65 --lib --release --features exact_rational -- params::exact_params`
Expected: 3 tests pass.

**Step 6: Commit**

```bash
git add crates/nine65/src/params/exact_params.rs crates/nine65/src/params/mod.rs
git commit -m "feat: exact BFV delta computation via NexGen rationals"
```

---

## Task 6: Property tests for rational bridge

**Files:**
- Create: `crates/nine65/tests/rational_bridge_proptest.rs`

**Step 1: Write property tests**

```rust
//! Property-based tests for the rational bridge integration.
//!
//! Validates that NexGen rational arithmetic produces correct
//! residues for NINE65's modular arithmetic pipeline.

#![cfg(feature = "exact_rational")]

use nine65::arithmetic::rational_bridge::RationalBridge;
use proptest::prelude::*;

/// Small primes for modular residue testing.
const TEST_PRIMES: [u64; 5] = [17, 31, 61, 127, 251];

proptest! {
    /// Rational addition: (a/b + c/d) mod p must equal
    /// ((a*d + b*c) * (b*d)^(-1)) mod p
    #[test]
    fn add_residue_consistency(
        a in -1000i128..1000,
        b in 1i128..100,
        c in -1000i128..1000,
        d in 1i128..100,
    ) {
        let r1 = RationalBridge::new(a, b).unwrap();
        let r2 = RationalBridge::new(c, d).unwrap();

        if let Ok(sum) = r1.add(&r2) {
            for &p in &TEST_PRIMES {
                let res_sum = sum.to_residue(p);
                let res1 = r1.to_residue(p);
                let res2 = r2.to_residue(p);
                let expected = (res1 as u128 + res2 as u128) % p as u128;
                prop_assert_eq!(
                    res_sum, expected as u64,
                    "({a}/{b} + {c}/{d}) mod {p}: got {res_sum}, expected {expected}"
                );
            }
        }
    }

    /// Rational multiplication: (a/b * c/d) mod p must equal
    /// (a*c * (b*d)^(-1)) mod p
    #[test]
    fn mul_residue_consistency(
        a in -100i128..100,
        b in 1i128..50,
        c in -100i128..100,
        d in 1i128..50,
    ) {
        let r1 = RationalBridge::new(a, b).unwrap();
        let r2 = RationalBridge::new(c, d).unwrap();

        if let Ok(prod) = r1.mul(&r2) {
            for &p in &TEST_PRIMES {
                let res_prod = prod.to_residue(p);
                let res1 = r1.to_residue(p);
                let res2 = r2.to_residue(p);
                let expected = (res1 as u128 * res2 as u128) % p as u128;
                prop_assert_eq!(
                    res_prod, expected as u64,
                    "({a}/{b} * {c}/{d}) mod {p}: got {res_prod}, expected {expected}"
                );
            }
        }
    }

    /// Division trichotomy: for all a, b with b != 0,
    /// exactly one of ExactInverse/ExactAFC/FPD holds,
    /// and a = b*q + r with 0 <= |r| < |b|.
    #[test]
    fn division_trichotomy_holds(
        a in -10000i128..10000,
        b in 1i128..1000,
    ) {
        let result = RationalBridge::exact_divide(a, b);
        let q = result.quotient().0;
        let r = result.remainder().0;

        // Division algorithm: a = b*q + r
        prop_assert_eq!(a, b * q + r, "Division algorithm violated: {a} != {b}*{q} + {r}");

        // Remainder bound: |r| < |b|
        prop_assert!(r.abs() < b.abs(), "Remainder {r} >= divisor {b}");
    }

    /// Integer rationals must have residue equal to value mod p.
    #[test]
    fn integer_rational_residue(val in -10000i128..10000) {
        let rat = RationalBridge::from_integer(val);
        for &p in &TEST_PRIMES {
            let residue = rat.to_residue(p);
            let expected = val.rem_euclid(p as i128) as u64;
            prop_assert_eq!(
                residue, expected,
                "Integer {val} mod {p}: got {residue}, expected {expected}"
            );
        }
    }
}
```

**Step 2: Run property tests**

Run: `cargo test -p nine65 --test rational_bridge_proptest --release --features exact_rational`
Expected: All 4 property tests pass (each running 256 cases by default).

**Step 3: Commit**

```bash
git add crates/nine65/tests/rational_bridge_proptest.rs
git commit -m "test: property-based tests for rational bridge residue consistency"
```

---

## Task 7: Workspace-level verification and final integration

**Files:**
- Modify: `CLAUDE.md` (add nexgen_rational to crate table and feature flags)

**Step 1: Full workspace build**

Run: `cargo build --workspace --release`
Expected: All 4 crates build (nine65, mana, unhal, nexgen_rational).

**Step 2: Full workspace test**

Run: `cargo test --workspace --release`
Expected: All tests pass. Previous 488 + NexGen's 95 + bridge's 3 + noise's 4 + params's 3 + proptests.

**Step 3: Test with exact_rational feature**

Run: `cargo test -p nine65 --release --features exact_rational`
Expected: All nine65 tests pass including new exact_rational modules.

**Step 4: Test without exact_rational feature (no regression)**

Run: `cargo test -p nine65 --release`
Expected: All existing tests still pass (new modules are gated behind feature flag).

**Step 5: Update CLAUDE.md**

Add `nexgen_rational` to the Workspace Crates table and `exact_rational` to Feature Flags.

**Step 6: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md with nexgen_rational crate and exact_rational feature"
```

---

## Dependency Graph

```
Task 1 (create crate) → Task 2 (wire into workspace) → Task 3 (bridge module)
                                                              ↓
                                                    ┌────────┴────────┐
                                                    ↓                 ↓
                                              Task 4 (noise)   Task 5 (params)
                                                    ↓                 ↓
                                                    └────────┬────────┘
                                                             ↓
                                                    Task 6 (proptests)
                                                             ↓
                                                    Task 7 (verify + docs)
```

## Future Work (not in this plan)

- **Port NexGen normalization scheduler to work with KElimination** — adaptive GCD scheduling informed by K-Elimination overflow detection
- **FHEPolynomial with exact coefficients** — Vec<RationalBridge> for exact polynomial representation
- **Benchmark suite** — Compare exact rational path vs current millibits noise tracking
- **Formal verification** — Coq proof of T9 overflow theorem alignment with K-Elimination capacity bounds
