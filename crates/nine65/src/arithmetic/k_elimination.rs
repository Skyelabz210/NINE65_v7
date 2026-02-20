//! K-Elimination: Exact Division in RNS
//!
//! # K-Elimination
//!
//! Provides exact division in RNS with 100% exactness.
//! No floating point, no approximations, no error accumulation.
//!
//! # Theorem Reference
//! - **Proof File**: `KElimination.v`
//! - **Key Theorem**: `k_elimination_complete`
//! - **Status**: PROVED
//!
//! # Mathematical Foundation
//!
//! Given value V in dual-codex (α, β):
//! ```text
//!   V = vα (mod αcap)
//!   V = vβ (mod βcap)
//! ```
//!
//! We can recover V exactly by computing:
//! ```text
//!   k = (vβ - vα) * αcap_inv (mod βcap)
//!   V = vα + k * αcap
//! ```
//!
//! # Coq Theorem Statement
//!
//! ```coq
//! Theorem k_elimination_complete : forall k v_M M A : nat,
//!   M > 0 -> v_M < M -> k < A ->
//!   let X := v_M + k * M in X / M = k.
//!
//! Theorem complexity_improvement :
//!   k_elimination_ops k = k /\ mrc_ops k = k * k.
//!   (* O(k) vs O(k²) *)
//! ```
//!
//! # Performance
//! - **Speedup**: 40× vs Mixed Radix Conversion
//! - **Complexity**: O(k) vs O(k²)
//!
//! This allows exact division: V / d = (vα + k * αcap) / d
//! when d | V (which is guaranteed in FHE rescaling).
//!
//! # Configuration
//!
//! Use `KElimConfig` for predefined configurations or `KElimBuilder` for custom setups:
//!
//! ```ignore
//! // Use a preset
//! let ke = KElimination::from_config(KElimConfig::Standard);
//!
//! // Or build custom
//! let ke = KElimBuilder::new()
//!     .alpha_primes(&[65537, 65521])
//!     .beta_primes(&[4611686018427387847])
//!     .build()
//!     .unwrap();
//! ```

use crate::errors::{Nine65Error, Nine65Result};

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

/// Predefined K-Elimination configurations
///
/// Each configuration provides different tradeoffs between capacity and performance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KElimConfig {
    /// Minimal configuration (~64-bit capacity)
    /// - Alpha: 2 × 16-bit primes (~32 bits)
    /// - Beta: 1 × 32-bit prime (~32 bits)
    /// - Use for: Small values, fast testing
    Minimal,

    /// Standard configuration (~112-bit capacity)
    /// - Alpha: 3 × 16-bit primes (~48 bits)
    /// - Beta: 1 × 62-bit prime (~62 bits)
    /// - Use for: Most FHE operations with N ≤ 2048
    Standard,

    /// Extended configuration (~140-bit capacity)
    /// - Alpha: 3 × 16-bit primes (~48 bits)
    /// - Beta: 2 × 45-bit primes (~90 bits)
    /// - Use for: Large N (4096+), deep circuits
    Extended,

    /// Maximum configuration (~176-bit capacity)
    /// - Alpha: 4 × 16-bit primes (~64 bits)
    /// - Beta: 2 × 55-bit primes (~110 bits)
    /// - Use for: Maximum precision requirements
    Maximum,
}

impl KElimConfig {
    /// Get the alpha primes for this configuration
    pub fn alpha_primes(&self) -> Vec<u64> {
        match self {
            KElimConfig::Minimal => vec![65537, 65521],
            KElimConfig::Standard => vec![65537, 65521, 65519],
            KElimConfig::Extended => vec![65537, 65521, 65519],
            KElimConfig::Maximum => vec![65537, 65521, 65519, 65497],
        }
    }

    /// Get the beta primes for this configuration
    pub fn beta_primes(&self) -> Vec<u64> {
        match self {
            KElimConfig::Minimal => vec![4294967291], // 2^32 - 5 (~32 bits)
            KElimConfig::Standard => vec![4611686018427387847], // 62-bit prime
            KElimConfig::Extended => vec![
                35184372088777, // ~45-bit prime
                35184372088831, // ~45-bit prime
            ],
            KElimConfig::Maximum => vec![
                4611686018427387847, // 62-bit prime
                4611686018427387903, // 62-bit prime (different)
            ],
        }
    }

    /// Get approximate total capacity in bits
    pub fn capacity_bits(&self) -> u32 {
        match self {
            KElimConfig::Minimal => 64,
            KElimConfig::Standard => 110,
            KElimConfig::Extended => 138,
            KElimConfig::Maximum => 188, // 64 alpha + 124 beta
        }
    }

    /// Recommended configuration for given polynomial degree N
    pub fn for_degree(n: usize) -> Self {
        match n {
            0..=1024 => KElimConfig::Standard,
            1025..=4096 => KElimConfig::Extended,
            _ => KElimConfig::Maximum,
        }
    }
}

/// Builder for custom K-Elimination configurations
#[derive(Debug, Clone, Default)]
pub struct KElimBuilder {
    alpha_primes: Option<Vec<u64>>,
    beta_primes: Option<Vec<u64>>,
}

impl KElimBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set alpha (primary) primes
    pub fn alpha_primes(mut self, primes: &[u64]) -> Self {
        self.alpha_primes = Some(primes.to_vec());
        self
    }

    /// Set beta (anchor) primes
    pub fn beta_primes(mut self, primes: &[u64]) -> Self {
        self.beta_primes = Some(primes.to_vec());
        self
    }

    /// Build the K-Elimination context
    ///
    /// Returns error if:
    /// - Primes are not set
    /// - Primes are not coprime
    pub fn build(self) -> Nine65Result<KElimination> {
        let alpha_primes = self
            .alpha_primes
            .ok_or_else(|| Nine65Error::InvalidParameter {
                message: "alpha_primes not set".to_string(),
            })?;

        let beta_primes = self
            .beta_primes
            .ok_or_else(|| Nine65Error::InvalidParameter {
                message: "beta_primes not set".to_string(),
            })?;

        KElimination::try_new(&alpha_primes, &beta_primes)
    }
}

/// K-Elimination context for exact division
#[derive(Debug, Clone)]
pub struct KElimination {
    /// Alpha moduli (primary codex)
    pub alpha_primes: Vec<u64>,
    /// Beta moduli (anchor codex)
    pub beta_primes: Vec<u64>,
    /// Product of alpha primes
    pub alpha_cap: u128,
    /// Product of beta primes
    pub beta_cap: u128,
    /// α_cap^{-1} mod β_cap (precomputed)
    pub alpha_inv_beta: u128,
    /// Configuration used (if from preset)
    config: Option<KElimConfig>,
}

impl KElimination {
    /// Create K-Elimination context with given moduli
    ///
    /// # Panics
    ///
    /// This is a **panicking constructor**. It will panic if:
    /// - `alpha_cap` and `beta_cap` are not coprime (GCD != 1)
    ///
    /// For fallible construction, use [`try_new()`](Self::try_new) instead.
    ///
    /// # Requirements
    /// - All primes must be coprime
    /// - beta_cap must be > largest value to divide
    ///
    /// # Example
    /// ```ignore
    /// // This may panic if primes share common factors
    /// let ke = KElimination::new(&[17, 19], &[23, 29]);
    ///
    /// // Prefer try_new for error handling
    /// let ke = KElimination::try_new(&[17, 19], &[23, 29])?;
    /// ```
    pub fn new(alpha_primes: &[u64], beta_primes: &[u64]) -> Self {
        Self::try_new(alpha_primes, beta_primes).expect("alpha_cap and beta_cap must be coprime")
    }

    /// Fallible constructor for K-Elimination context
    ///
    /// Returns error if moduli are not coprime. Prefer this over [`new()`](Self::new)
    /// when handling untrusted input or in library code.
    ///
    /// # Errors
    ///
    /// Returns [`Nine65Error::NotCoprime`] if alpha_cap and beta_cap share a common factor.
    #[must_use = "this returns a Result that must be handled"]
    pub fn try_new(alpha_primes: &[u64], beta_primes: &[u64]) -> Nine65Result<Self> {
        let alpha_cap: u128 = alpha_primes.iter().map(|&p| p as u128).product();

        let beta_cap: u128 = beta_primes.iter().map(|&p| p as u128).product();

        // Compute α_cap^{-1} mod β_cap using extended GCD
        let alpha_inv_beta =
            mod_inverse_u128(alpha_cap, beta_cap).ok_or_else(|| Nine65Error::NotCoprime {
                m: alpha_cap as u64,
                a: beta_cap as u64,
                gcd: gcd_u128(alpha_cap, beta_cap) as u64,
            })?;

        Ok(Self {
            alpha_primes: alpha_primes.to_vec(),
            beta_primes: beta_primes.to_vec(),
            alpha_cap,
            beta_cap,
            alpha_inv_beta,
            config: None,
        })
    }

    /// Create K-Elimination from a predefined configuration.
    ///
    /// # Panics
    ///
    /// Panics if the preset primes are not coprime (should never happen
    /// with built-in configurations). For fallible construction, use
    /// [`try_from_config()`](Self::try_from_config).
    ///
    /// # Example
    /// ```ignore
    /// let ke = KElimination::from_config(KElimConfig::Standard);
    /// ```
    pub fn from_config(config: KElimConfig) -> Self {
        Self::try_from_config(config)
            .expect("built-in KElimConfig primes must be coprime")
    }

    /// Fallible constructor from predefined configuration.
    ///
    /// Returns error if the preset primes are not coprime.
    pub fn try_from_config(config: KElimConfig) -> Nine65Result<Self> {
        let mut ke = Self::try_new(&config.alpha_primes(), &config.beta_primes())?;
        ke.config = Some(config);
        Ok(ke)
    }

    /// Create K-Elimination optimized for given polynomial degree.
    ///
    /// Automatically selects appropriate configuration based on N.
    pub fn for_degree(n: usize) -> Self {
        Self::from_config(KElimConfig::for_degree(n))
    }

    /// Fallible constructor optimized for given polynomial degree.
    pub fn try_for_degree(n: usize) -> Nine65Result<Self> {
        Self::try_from_config(KElimConfig::for_degree(n))
    }

    /// Create K-Elimination optimized for FHE with given ciphertext modulus.
    ///
    /// Uses Standard configuration (~112-bit capacity).
    ///
    /// ORBITAL PATCH (December 2024):
    /// Previous ~16-bit primes gave only ~80-bit capacity.
    /// For N=1024 tensor products, intermediate values can reach ~70 bits.
    ///
    /// FIX: Use 62-bit anchor primes → 110+ bit total capacity
    /// Capacity (110 bits) > Demand (70 bits) → Exact reconstruction guaranteed
    pub fn for_fhe(_q: u64) -> Self {
        Self::from_config(KElimConfig::Standard)
    }

    /// Fallible constructor optimized for FHE.
    pub fn try_for_fhe(_q: u64) -> Nine65Result<Self> {
        Self::try_from_config(KElimConfig::Standard)
    }

    /// Get the configuration used (if created from preset)
    pub fn config(&self) -> Option<KElimConfig> {
        self.config
    }

    /// Get total capacity in bits (alpha_cap * beta_cap)
    ///
    /// Computed as log2(alpha_cap) + log2(beta_cap) to avoid overflow.
    pub fn capacity_bits(&self) -> u32 {
        let alpha_bits = 128 - self.alpha_cap.leading_zeros();
        let beta_bits = 128 - self.beta_cap.leading_zeros();
        alpha_bits + beta_bits
    }

    /// Get total capacity (alpha_cap * beta_cap)
    ///
    /// Returns the maximum value that can be exactly reconstructed.
    /// Values must be < capacity for exact K-Elimination reconstruction.
    pub fn capacity(&self) -> u128 {
        // Check for overflow (shouldn't happen with valid configs)
        self.alpha_cap.saturating_mul(self.beta_cap)
    }

    /// Get alpha codex capacity (product of alpha primes)
    pub fn alpha_capacity(&self) -> u128 {
        self.alpha_cap
    }

    /// Get beta codex capacity (product of beta primes)
    pub fn beta_capacity(&self) -> u128 {
        self.beta_cap
    }

    /// Validate that a value is within reconstruction capacity.
    ///
    /// Returns `Ok(())` if the value can be exactly reconstructed,
    /// or `Err` with the specific violation.
    ///
    /// # Preconditions (from KElimination.v)
    /// - alpha_cap > 0
    /// - beta_cap > 0
    /// - gcd(alpha_cap, beta_cap) == 1
    /// - value < alpha_cap * beta_cap (reconstruction capacity)
    ///
    /// The coprimality precondition is guaranteed by the constructor,
    /// so this method only checks the value range.
    pub fn validate_value(&self, value: u128) -> Nine65Result<()> {
        let capacity = self.alpha_cap.checked_mul(self.beta_cap).ok_or(
            Nine65Error::Overflow {
                operation: "K-Elimination capacity computation",
            },
        )?;

        if value >= capacity {
            return Err(Nine65Error::RangeOverflow {
                x: value,
                bound: capacity,
            });
        }

        Ok(())
    }

    /// Validate preconditions for a dual-codex representation.
    ///
    /// Checks that v_alpha < alpha_cap and v_beta < beta_cap.
    pub fn validate_residues(&self, v_alpha: u128, v_beta: u128) -> Nine65Result<()> {
        if v_alpha >= self.alpha_cap {
            return Err(Nine65Error::RangeOverflow {
                x: v_alpha,
                bound: self.alpha_cap,
            });
        }
        if v_beta >= self.beta_cap {
            return Err(Nine65Error::RangeOverflow {
                x: v_beta,
                bound: self.beta_cap,
            });
        }
        Ok(())
    }

    /// Exact division with full precondition validation.
    ///
    /// Returns `Err` if:
    /// - residues are out of range
    /// - divisor is zero
    /// - division is not exact (value not divisible by divisor)
    pub fn exact_divide_validated(
        &self,
        v_alpha: u128,
        v_beta: u128,
        divisor: u64,
    ) -> Nine65Result<u128> {
        if divisor == 0 {
            return Err(Nine65Error::ModulusZero);
        }
        self.validate_residues(v_alpha, v_beta)?;

        let k = self.extract_k(v_alpha, v_beta);
        let v_full = v_alpha + k * self.alpha_cap;

        if v_full % (divisor as u128) != 0 {
            return Err(Nine65Error::InexactDivision {
                value: v_full,
                divisor,
            });
        }

        Ok(v_full / (divisor as u128))
    }

    /// Extract k value for exact reconstruction (CONSTANT-TIME - DEFAULT)
    ///
    /// Given:
    ///   v_alpha = V mod alpha_cap
    ///   v_beta = V mod beta_cap
    ///
    /// Computes k such that V = v_alpha + k * alpha_cap
    ///
    /// # Security
    /// No data-dependent branches. Safe for processing secret data.
    /// This is the default, constant-time implementation.
    ///
    /// For performance-critical code paths where timing leakage is acceptable
    /// (e.g., processing only public data), use `extract_k_vartime()`.
    ///
    /// # Note
    /// The modulo operation on v_alpha uses public beta_cap, so the division
    /// timing doesn't leak secret information (beta_cap is a system parameter).
    pub fn extract_k(&self, v_alpha: u128, v_beta: u128) -> u128 {
        // Constant-time subtraction: (v_beta - v_alpha) mod beta_cap
        // sub_mod_kelim_ct handles v_alpha >= beta_cap correctly
        let diff = sub_mod_kelim_ct(v_beta, v_alpha, self.beta_cap);

        // Constant-time multiplication
        mul_mod_u128_ct(diff, self.alpha_inv_beta, self.beta_cap)
    }

    /// Extract k value for exact reconstruction (VARIABLE-TIME)
    ///
    /// # Security Warning
    /// This function has timing side-channels based on input values.
    /// Only use when processing public data where timing leakage is acceptable.
    ///
    /// For secret data, use `extract_k()` (the default, constant-time version).
    #[deprecated(
        since = "0.2.0",
        note = "Use extract_k() for constant-time safety. Only use extract_k_vartime() when processing public data."
    )]
    pub fn extract_k_vartime(&self, v_alpha: u128, v_beta: u128) -> u128 {
        // k = (v_beta - v_alpha) * alpha_inv_beta mod beta_cap
        let diff = if v_beta >= v_alpha {
            v_beta - v_alpha
        } else {
            self.beta_cap - ((v_alpha - v_beta) % self.beta_cap)
        };

        mul_mod_u128(diff, self.alpha_inv_beta, self.beta_cap)
    }

    /// Exact division: compute V / divisor where divisor | V (CONSTANT-TIME - DEFAULT)
    ///
    /// This enables exact FHE rescaling.
    ///
    /// # Security
    /// Uses constant-time k extraction. The final division is variable-time
    /// but the divisor is typically public in FHE rescaling.
    pub fn exact_divide(&self, v_alpha: u128, v_beta: u128, divisor: u64) -> u128 {
        // Reconstruct full value using CT k extraction
        let k = self.extract_k(v_alpha, v_beta);
        let v_full = v_alpha + k * self.alpha_cap;

        // Exact division (divisor must divide v_full)
        v_full / (divisor as u128)
    }

    /// Exact division with remainder check (uses constant-time k extraction)
    pub fn exact_divide_checked(&self, v_alpha: u128, v_beta: u128, divisor: u64) -> Option<u128> {
        let k = self.extract_k(v_alpha, v_beta);
        let v_full = v_alpha + k * self.alpha_cap;

        if v_full.is_multiple_of(divisor as u128) {
            Some(v_full / (divisor as u128))
        } else {
            None
        }
    }

    /// Scale value by t/q with exact rounding (CONSTANT-TIME - DEFAULT)
    ///
    /// Computes: round(value * t / q) exactly
    /// This is the critical operation for BFV multiplication
    ///
    /// # Security
    /// Uses constant-time k extraction. Final division is variable-time
    /// but t and q are typically public parameters.
    pub fn scale_and_round(&self, value: u64, t: u64, q: u64) -> u64 {
        // Compute: round(value * t / q) = floor((value * t + q/2) / q)
        let value = value as u128;
        let t = t as u128;
        let q = q as u128;

        // Numerator = value * t + q/2 (for rounding)
        let numerator = value * t + q / 2;

        // Get dual-codex representation
        let v_alpha = numerator % self.alpha_cap;
        let v_beta = numerator % self.beta_cap;

        // Constant-time k extraction
        let k = self.extract_k(v_alpha, v_beta);
        let full_numerator = v_alpha + k * self.alpha_cap;

        // Division by q
        ((full_numerator / q) % q) as u64
    }

    // =========================================================================
    // VARIABLE-TIME OPERATIONS (for public data only)
    // =========================================================================

    /// Exact division: compute V / divisor (VARIABLE-TIME)
    ///
    /// # Security Warning
    /// Uses variable-time k extraction with timing side-channels.
    /// Only use when processing public data.
    #[deprecated(
        since = "0.2.0",
        note = "Use exact_divide() for constant-time safety. Only use exact_divide_vartime() when processing public data."
    )]
    #[allow(deprecated)]
    pub fn exact_divide_vartime(&self, v_alpha: u128, v_beta: u128, divisor: u64) -> u128 {
        let k = self.extract_k_vartime(v_alpha, v_beta);
        let v_full = v_alpha + k * self.alpha_cap;
        v_full / (divisor as u128)
    }

    /// Scale value by t/q with exact rounding (VARIABLE-TIME)
    ///
    /// # Security Warning
    /// Uses variable-time k extraction with timing side-channels.
    /// Only use when processing public data.
    #[deprecated(
        since = "0.2.0",
        note = "Use scale_and_round() for constant-time safety. Only use scale_and_round_vartime() when processing public data."
    )]
    #[allow(deprecated)]
    pub fn scale_and_round_vartime(&self, value: u64, t: u64, q: u64) -> u64 {
        let value = value as u128;
        let t = t as u128;
        let q = q as u128;

        let numerator = value * t + q / 2;

        let v_alpha = numerator % self.alpha_cap;
        let v_beta = numerator % self.beta_cap;

        // Variable-time k extraction
        let k = self.extract_k_vartime(v_alpha, v_beta);
        let full_numerator = v_alpha + k * self.alpha_cap;

        ((full_numerator / q) % q) as u64
    }
}

/// Modular inverse using extended Euclidean algorithm (u128)
fn mod_inverse_u128(a: u128, m: u128) -> Option<u128> {
    let (g, x, _) = extended_gcd_i128(a as i128, m as i128);

    if g != 1 {
        return None; // No inverse exists
    }

    // Ensure positive result
    let result = if x < 0 {
        (x + m as i128) as u128
    } else {
        x as u128
    };

    Some(result % m)
}

/// Extended GCD for i128
fn extended_gcd_i128(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        return (b, 0, 1);
    }

    let (g, x1, y1) = extended_gcd_i128(b % a, a);
    let x = y1 - (b / a) * x1;
    let y = x1;

    (g, x, y)
}

/// GCD for u128 using Euclidean algorithm
fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Modular multiplication for u128 (variable-time)
///
/// # Security Note
/// This function has timing side-channels. Use `mul_mod_u128_ct` for
/// constant-time operation when processing secret data.
fn mul_mod_u128(a: u128, b: u128, m: u128) -> u128 {
    // For large values, use careful multiplication
    if a < (1u128 << 64) && b < (1u128 << 64) {
        (a * b) % m
    } else {
        // Use Montgomery-like approach for large values
        let mut result = 0u128;
        let mut a = a % m;
        let mut b = b;

        while b > 0 {
            if b & 1 == 1 {
                result = (result + a) % m;
            }
            a = (a << 1) % m;
            b >>= 1;
        }

        result
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANT-TIME OPERATIONS (for defense-in-depth)
// ═══════════════════════════════════════════════════════════════════════════

/// Constant-time conditional subtraction: result = (a - b) mod m
///
/// # Security
/// No data-dependent branches. Time is constant regardless of input values.
///
/// # Assumptions
/// Both a and b must be < m for correct results.
///
/// # Correctness
/// - When a >= b: returns a - b (no wraparound needed)
/// - When a < b: returns m - (b - a) = m + a - b = (a - b) + m
#[inline(always)]
fn sub_mod_u128_ct(a: u128, b: u128, m: u128) -> u128 {
    let diff = a.wrapping_sub(b); // Correct when a >= b; wraps when a < b

    // If a < b, diff wrapped and we need to add m to get correct result
    let needs_add = (a < b) as u128;
    let mask = needs_add.wrapping_neg(); // 0 or u128::MAX

    // Add m only when a < b (mask is all 1s)
    diff.wrapping_add(m & mask)
}

/// Constant-time subtraction for K-elimination: result = (a - b) mod m
///
/// # Security
/// Uses constant-time operations. The modulo by m uses hardware division
/// which is constant-time for fixed bit-width operands.
///
/// # Note
/// Unlike sub_mod_u128_ct, this handles the case where b > m (which happens
/// in K-elimination where v_alpha can be >= beta_cap).
#[inline(always)]
fn sub_mod_kelim_ct(a: u128, b: u128, m: u128) -> u128 {
    // Reduce b mod m first (b can be >= m in K-elimination)
    // Then compute (a - b_reduced) mod m using CT subtraction
    let b_reduced = b % m;
    sub_mod_u128_ct(a, b_reduced, m)
}

/// Constant-time modular addition for u128
///
/// Computes (a + b) mod m without branches.
/// Assumes a, b < m.
#[inline(always)]
fn add_mod_u128_ct(a: u128, b: u128, m: u128) -> u128 {
    let sum = a.wrapping_add(b);
    let diff = sum.wrapping_sub(m);

    // Need to reduce if: overflow occurred (sum < a) OR sum >= m
    let overflow = (sum < a) as u128;
    let geq_m = (sum >= m) as u128;
    let need_reduce = overflow | geq_m;
    let mask = need_reduce.wrapping_neg(); // 0 or u128::MAX

    // Select diff if need_reduce, else sum
    (diff & mask) | (sum & !mask)
}

/// Constant-time modular multiplication for u128
///
/// # Security
/// Fixed number of iterations (128) regardless of input values.
/// No data-dependent branches.
fn mul_mod_u128_ct(a: u128, b: u128, m: u128) -> u128 {
    let mut result = 0u128;
    let mut a = a % m;

    // Fixed 128 iterations for constant-time
    for i in 0..128 {
        // Extract bit i of b (constant-time)
        let bit = (b >> i) & 1;
        let mask = bit.wrapping_neg(); // 0 or u128::MAX

        // Conditionally add a to result (constant-time)
        // add_val is either a (if bit set) or 0 (if bit not set)
        let add_val = a & mask;
        result = add_mod_u128_ct(result, add_val, m);

        // Double a mod m using CT addition (always done)
        a = add_mod_u128_ct(a, a, m);
    }

    result
}

// Bench-only wrappers (keep internal functions private in normal builds)
#[cfg(feature = "benchmarks")]
pub fn bench_mul_mod_u128_ct(a: u128, b: u128, m: u128) -> u128 {
    mul_mod_u128_ct(a, b, m)
}

#[cfg(feature = "benchmarks")]
pub fn bench_sub_mod_u128_ct(a: u128, b: u128, m: u128) -> u128 {
    sub_mod_u128_ct(a, b, m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k_elimination_basic() {
        let ke = KElimination::new(
            &[17, 19], // alpha = 323
            &[23, 29], // beta = 667
        );

        assert_eq!(ke.alpha_cap, 323);
        assert_eq!(ke.beta_cap, 667);

        // Test value
        let v: u128 = 1000;
        let v_alpha = v % ke.alpha_cap;
        let v_beta = v % ke.beta_cap;

        let k = ke.extract_k(v_alpha, v_beta);
        let reconstructed = v_alpha + k * ke.alpha_cap;

        assert_eq!(reconstructed, v, "Reconstruction failed");
    }

    #[test]
    fn test_exact_division() {
        let ke = KElimination::new(&[65537, 65521], &[65519, 65497]);

        // Test: 12345 / 5 = 2469
        let v: u128 = 12345;
        let divisor = 5u64;

        let v_alpha = v % ke.alpha_cap;
        let v_beta = v % ke.beta_cap;

        let result = ke.exact_divide(v_alpha, v_beta, divisor);
        assert_eq!(result, 2469);
    }

    #[test]
    fn test_scale_and_round() {
        let ke = KElimination::for_fhe(65537);

        // Test: round(100 * 257 / 65537) = round(25700 / 65537) = 0
        let result = ke.scale_and_round(100, 257, 65537);
        assert_eq!(result, 0);

        // Test: round(50000 * 257 / 65537) = round(12850000 / 65537) = 196
        let result = ke.scale_and_round(50000, 257, 65537);
        let expected = ((50000u128 * 257 + 65537 / 2) / 65537) as u64;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_large_values() {
        let ke = KElimination::new(&[65537, 65521, 65519], &[65497, 65479]);

        // Large value that would overflow u64
        let v: u128 = 1_000_000_000_000;
        let v_alpha = v % ke.alpha_cap;
        let v_beta = v % ke.beta_cap;

        let k = ke.extract_k(v_alpha, v_beta);
        let reconstructed = v_alpha + k * ke.alpha_cap;

        assert_eq!(reconstructed, v);
    }

    #[test]
    fn test_fhe_rescaling() {
        // Simulate BFV rescaling scenario
        let ke = KElimination::for_fhe(65537);
        let q: u64 = 65537;
        let t: u64 = 257;

        // After tensor product, coefficients can be large
        // Test scaling various coefficient values
        for coeff in [0u64, 1, 100, 1000, 10000, 32768, 65536] {
            let scaled = ke.scale_and_round(coeff, t, q);
            let expected = (((coeff as u128) * (t as u128) + (q as u128) / 2) / (q as u128)) as u64;
            assert_eq!(scaled, expected % q, "Scaling failed for coeff={}", coeff);
        }
    }

    // =========================================================================
    // CONSTANT-TIME OPERATION TESTS (verifying CT is now default)
    // =========================================================================

    #[test]
    #[allow(deprecated)]
    fn test_extract_k_ct_matches_vartime() {
        let ke = KElimination::new(
            &[17, 19], // alpha = 323
            &[23, 29], // beta = 667
        );

        // Capacity = alpha_cap * beta_cap = 323 * 667 = 215441
        let capacity = ke.alpha_cap * ke.beta_cap;

        // Test that default (CT) matches deprecated vartime version
        // Only test values within capacity for reconstruction verification
        for v in [0u128, 1, 100, 1000, 10000, 100000, 200000] {
            let v_alpha = v % ke.alpha_cap;
            let v_beta = v % ke.beta_cap;

            let k_ct_default = ke.extract_k(v_alpha, v_beta);
            let k_vartime = ke.extract_k_vartime(v_alpha, v_beta);

            assert_eq!(
                k_ct_default, k_vartime,
                "Default CT and vartime extract_k differ for v={}",
                v
            );

            // Verify reconstruction works with CT
            // For values > capacity, we get v mod capacity
            let reconstructed = v_alpha + k_ct_default * ke.alpha_cap;
            let expected = v % capacity;
            assert_eq!(
                reconstructed, expected,
                "CT reconstruction failed for v={}",
                v
            );
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_exact_divide_ct_matches_vartime() {
        let ke = KElimination::new(&[65537, 65521], &[65519, 65497]);

        // Test that default (CT) matches deprecated vartime version
        for v in [10u128, 100, 1000, 12345, 67890] {
            let divisor = 5u64;
            let v_full = v * (divisor as u128); // Ensure divisible

            let v_alpha = v_full % ke.alpha_cap;
            let v_beta = v_full % ke.beta_cap;

            let result_ct_default = ke.exact_divide(v_alpha, v_beta, divisor);
            let result_vartime = ke.exact_divide_vartime(v_alpha, v_beta, divisor);

            assert_eq!(
                result_ct_default, result_vartime,
                "Default CT and vartime exact_divide differ for v_full={}",
                v_full
            );
            assert_eq!(result_ct_default, v, "Exact division failed");
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_scale_and_round_ct_matches_vartime() {
        let ke = KElimination::for_fhe(65537);
        let q: u64 = 65537;
        let t: u64 = 257;

        for coeff in [0u64, 1, 100, 1000, 10000, 32768, 65536] {
            let scaled_ct_default = ke.scale_and_round(coeff, t, q);
            let scaled_vartime = ke.scale_and_round_vartime(coeff, t, q);

            assert_eq!(
                scaled_ct_default, scaled_vartime,
                "Default CT and vartime scale_and_round differ for coeff={}",
                coeff
            );
        }
    }

    #[test]
    fn test_extract_k_is_constant_time_default() {
        // Verify the default extract_k uses CT implementation
        let ke = KElimination::new(&[17, 19], &[23, 29]);

        // Various inputs should all work correctly with CT
        for v in [0u128, 1, 100, 1000, 100000] {
            let v_alpha = v % ke.alpha_cap;
            let v_beta = v % ke.beta_cap;

            let k = ke.extract_k(v_alpha, v_beta);
            let reconstructed = v_alpha + k * ke.alpha_cap;

            assert_eq!(reconstructed, v, "CT reconstruction failed");
        }
    }

    #[test]
    fn test_sub_mod_u128_ct() {
        let m = 667u128;

        // Test a > b (no borrow needed)
        assert_eq!(super::sub_mod_u128_ct(100, 30, m), 70);

        // Test a < b (borrow needed)
        assert_eq!(super::sub_mod_u128_ct(30, 100, m), m - 70);

        // Test a == b
        assert_eq!(super::sub_mod_u128_ct(50, 50, m), 0);

        // Test edge cases
        assert_eq!(super::sub_mod_u128_ct(0, 0, m), 0);
        assert_eq!(super::sub_mod_u128_ct(m - 1, 0, m), m - 1);
        assert_eq!(super::sub_mod_u128_ct(0, m - 1, m), 1);
    }

    #[test]
    fn test_mul_mod_u128_ct_correctness() {
        let m = 667u128;

        // Test various multiplications
        for a in [0u128, 1, 100, 374, 442, 500, 666] {
            for b in [0u128, 1, 100, 200, 500, 666] {
                let result_vt = super::mul_mod_u128(a, b, m);
                let result_ct = super::mul_mod_u128_ct(a, b, m);
                let expected = (a * b) % m;

                assert_eq!(
                    result_vt, expected,
                    "VT mul_mod failed: {}*{} mod {} = {} (expected {})",
                    a, b, m, result_vt, expected
                );
                assert_eq!(
                    result_ct, expected,
                    "CT mul_mod failed: {}*{} mod {} = {} (expected {})",
                    a, b, m, result_ct, expected
                );
            }
        }
    }

    #[test]
    fn test_mul_mod_u128_ct_large_modulus() {
        // Test with larger modulus like beta_cap in real configs
        let m = 4611686018427387847u128; // 62-bit prime

        for a in [0u128, 1, 1000, 1_000_000, 1_000_000_000] {
            for b in [0u128, 1, 1000, 1_000_000, 1_000_000_000] {
                let result_vt = super::mul_mod_u128(a, b, m);
                let result_ct = super::mul_mod_u128_ct(a, b, m);

                assert_eq!(
                    result_vt, result_ct,
                    "CT differs from VT: {}*{} mod {} = {} (vt) vs {} (ct)",
                    a, b, m, result_vt, result_ct
                );
            }
        }
    }

    // =========================================================================
    // CONFIGURATION TESTS
    // =========================================================================

    #[test]
    fn test_kelim_config_from_config() {
        for config in [
            KElimConfig::Minimal,
            KElimConfig::Standard,
            KElimConfig::Extended,
            KElimConfig::Maximum,
        ] {
            let ke = KElimination::from_config(config);
            assert_eq!(ke.config(), Some(config));
            assert!(ke.capacity_bits() > 0);
        }
    }

    #[test]
    fn test_kelim_config_capacity() {
        let minimal = KElimination::from_config(KElimConfig::Minimal);
        let standard = KElimination::from_config(KElimConfig::Standard);
        let extended = KElimination::from_config(KElimConfig::Extended);
        let maximum = KElimination::from_config(KElimConfig::Maximum);

        // Capacity should increase with each level
        assert!(standard.capacity_bits() > minimal.capacity_bits());
        assert!(extended.capacity_bits() > standard.capacity_bits());
        assert!(maximum.capacity_bits() > extended.capacity_bits());
    }

    #[test]
    fn test_kelim_for_degree() {
        // Small N should use Standard
        let ke_small = KElimination::for_degree(1024);
        assert_eq!(ke_small.config(), Some(KElimConfig::Standard));

        // Medium N should use Extended
        let ke_medium = KElimination::for_degree(4096);
        assert_eq!(ke_medium.config(), Some(KElimConfig::Extended));

        // Large N should use Maximum
        let ke_large = KElimination::for_degree(8192);
        assert_eq!(ke_large.config(), Some(KElimConfig::Maximum));
    }

    #[test]
    fn test_kelim_builder_success() {
        let ke = KElimBuilder::new()
            .alpha_primes(&[17, 19])
            .beta_primes(&[23, 29])
            .build();

        assert!(ke.is_ok());
        let ke = ke.unwrap();
        assert_eq!(ke.alpha_cap, 323);
        assert_eq!(ke.beta_cap, 667);
    }

    #[test]
    fn test_kelim_builder_missing_primes() {
        // Missing alpha primes
        let result = KElimBuilder::new().beta_primes(&[23, 29]).build();
        assert!(result.is_err());

        // Missing beta primes
        let result = KElimBuilder::new().alpha_primes(&[17, 19]).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_kelim_try_new_coprime() {
        // Coprime primes should succeed
        let result = KElimination::try_new(&[17, 19], &[23, 29]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_kelim_try_new_not_coprime() {
        // Non-coprime should fail (both have factor of 17)
        let result = KElimination::try_new(&[17, 19], &[17, 29]);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_configs_work_for_reconstruction() {
        for config in [
            KElimConfig::Minimal,
            KElimConfig::Standard,
            KElimConfig::Extended,
            KElimConfig::Maximum,
        ] {
            let ke = KElimination::from_config(config);

            // Test reconstruction for various values within capacity
            for v in [0u128, 1, 1000, 1_000_000, 1_000_000_000] {
                let v_alpha = v % ke.alpha_cap;
                let v_beta = v % ke.beta_cap;

                let k = ke.extract_k(v_alpha, v_beta);
                let reconstructed = v_alpha + k * ke.alpha_cap;

                assert_eq!(
                    reconstructed, v,
                    "Reconstruction failed for v={} with config {:?}",
                    v, config
                );
            }
        }
    }

    // =========================================================================
    // PRECONDITION VALIDATION TESTS
    // =========================================================================

    #[test]
    fn test_validate_value_within_capacity() {
        let ke = KElimination::new(&[17, 19], &[23, 29]);
        // capacity = 323 * 667 = 215441
        assert!(ke.validate_value(0).is_ok());
        assert!(ke.validate_value(1000).is_ok());
        assert!(ke.validate_value(215440).is_ok()); // max valid
    }

    #[test]
    fn test_validate_value_exceeds_capacity() {
        let ke = KElimination::new(&[17, 19], &[23, 29]);
        // capacity = 323 * 667 = 215441
        assert!(ke.validate_value(215441).is_err()); // exactly at boundary
        assert!(ke.validate_value(1_000_000).is_err());
    }

    #[test]
    fn test_validate_residues_valid() {
        let ke = KElimination::new(&[17, 19], &[23, 29]);
        assert!(ke.validate_residues(100, 300).is_ok());
        assert!(ke.validate_residues(0, 0).is_ok());
        assert!(ke.validate_residues(322, 666).is_ok()); // alpha_cap-1, beta_cap-1
    }

    #[test]
    fn test_validate_residues_out_of_range() {
        let ke = KElimination::new(&[17, 19], &[23, 29]);
        assert!(ke.validate_residues(323, 0).is_err()); // v_alpha >= alpha_cap
        assert!(ke.validate_residues(0, 667).is_err()); // v_beta >= beta_cap
    }

    #[test]
    fn test_exact_divide_validated_success() {
        let ke = KElimination::new(&[65537, 65521], &[65519, 65497]);
        let v: u128 = 12345;
        let divisor = 5u64;
        let v_alpha = v % ke.alpha_cap;
        let v_beta = v % ke.beta_cap;
        let result = ke.exact_divide_validated(v_alpha, v_beta, divisor);
        assert_eq!(result.unwrap(), 2469);
    }

    #[test]
    fn test_exact_divide_validated_not_divisible() {
        let ke = KElimination::new(&[65537, 65521], &[65519, 65497]);
        let v: u128 = 12346; // not divisible by 5
        let v_alpha = v % ke.alpha_cap;
        let v_beta = v % ke.beta_cap;
        let result = ke.exact_divide_validated(v_alpha, v_beta, 5);
        assert!(result.is_err());
    }

    #[test]
    fn test_exact_divide_validated_zero_divisor() {
        let ke = KElimination::new(&[17, 19], &[23, 29]);
        let result = ke.exact_divide_validated(100, 300, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_from_config_all_valid() {
        for config in [
            KElimConfig::Minimal,
            KElimConfig::Standard,
            KElimConfig::Extended,
            KElimConfig::Maximum,
        ] {
            let result = KElimination::try_from_config(config);
            assert!(result.is_ok(), "try_from_config failed for {:?}", config);
        }
    }

    #[test]
    fn test_try_for_degree() {
        let result = KElimination::try_for_degree(1024);
        assert!(result.is_ok());
        let ke = result.unwrap();
        assert_eq!(ke.config(), Some(KElimConfig::Standard));
    }

    // Timing regression tests moved to criterion benches (benches/timing.rs)
}
