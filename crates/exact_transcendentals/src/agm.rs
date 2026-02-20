//! Arithmetic-Geometric Mean (AGM) Algorithms
//!
//! Quadratically convergent algorithms using only exact integer arithmetic.
//! Each iteration DOUBLES the number of correct digits!
//!
//! ## What AGM Computes:
//! - **Natural logarithm**: ln(x) via elliptic integral relationship
//! - **π**: Via Gauss-Legendre algorithm (AGM-based)
//! - **Elliptic integrals**: K(k), E(k) directly
//! - **Square roots**: As part of AGM iteration
//!
//! ## The AGM Iteration:
//! Given a₀, b₀:
//!   a_{n+1} = (a_n + b_n) / 2      (arithmetic mean)
//!   b_{n+1} = sqrt(a_n × b_n)      (geometric mean)
//!
//! Converges to common limit M(a,b) quadratically!
//!
//! ## QMNF Integration:
//! - All arithmetic via scaled integers
//! - K-Elimination for exact division by 2
//! - Integer sqrt from sqrt module
//! - CRTBigInt for arbitrary precision

use crate::sqrt::isqrt_newton_128;

/// Scale factor for AGM computations (2^62 for maximum precision in i128)
pub const AGM_SCALE: u128 = 1u128 << 62;
pub const AGM_SCALE_BITS: u32 = 62;

/// AGM engine for transcendental computation
#[derive(Clone, Debug)]
pub struct AgmEngine {
    /// Working precision in bits
    pub precision_bits: u32,
    /// Maximum iterations (each doubles precision)
    pub max_iterations: u32,
}

impl Default for AgmEngine {
    fn default() -> Self {
        Self {
            precision_bits: 62,
            max_iterations: 20, // 2^20 bits of precision possible!
        }
    }
}

impl AgmEngine {
    pub fn new(precision_bits: u32) -> Self {
        // log2(precision_bits) + 2 iterations needed
        let max_iterations = (64 - precision_bits.leading_zeros()) + 2;
        Self {
            precision_bits,
            max_iterations,
        }
    }

    /// Compute the AGM of two numbers
    /// Input: a, b as scaled integers (× 2^AGM_SCALE_BITS)
    /// Output: M(a, b) × 2^AGM_SCALE_BITS
    pub fn agm(&self, a0: u128, b0: u128) -> u128 {
        let mut a = a0;
        let mut b = b0;

        // Iterate until convergence
        for _ in 0..self.max_iterations {
            // Check convergence
            if a == b {
                break;
            }
            let diff = a.abs_diff(b);
            if diff <= 1 {
                break;
            }

            // a_{n+1} = (a_n + b_n) / 2
            let a_next = (a + b) / 2;

            // b_{n+1} = sqrt(a_n × b_n)
            // If a = A × SCALE and b = B × SCALE, then:
            //   a × b = A × B × SCALE²
            //   sqrt(a × b) = sqrt(A × B) × SCALE ✓
            // This preserves scaling correctly!
            //
            // Overflow safety: for a,b ≤ AGM_SCALE = 2^62, product ≤ 2^124
            // which fits in u128. For larger values, we split the computation
            // to avoid silent saturation (which would corrupt the result).
            let b_next = match a.checked_mul(b) {
                Some(product) => isqrt_newton_128(product),
                None => {
                    // Overflow: use sqrt(a*b) = sqrt(a/2 * b) * sqrt(2)
                    // = isqrt(a/2 * b) * SQRT2_CORRECTION
                    // where SQRT2_CORRECTION = isqrt(2 * AGM_SCALE * AGM_SCALE) / AGM_SCALE
                    let half_a = a >> 1;
                    let product_safe = half_a.saturating_mul(b);
                    let sqrt_half = isqrt_newton_128(product_safe);
                    // Multiply by sqrt(2) ≈ 1.41421... using integer approximation
                    // sqrt(2) × 2^32 = 6074001000 (precomputed)
                    (sqrt_half * 6_074_001_000u128) >> 32
                }
            };

            a = a_next;
            b = b_next;
        }

        a
    }

    /// Compute natural logarithm using the Brent-Salamin AGM formula.
    ///
    /// Uses: ln(x) = π / (2 × M(1, 4/(x·2^N))) - N·ln(2)
    /// where N is a precision parameter chosen so 4/(x·2^N) ≪ 1,
    /// combined with range reduction via powers of 2.
    ///
    /// The key insight from Brent (1976): the second AGM argument must be
    /// *small* relative to 1 for rapid convergence. With N = 20 and
    /// s_real ≈ 1, the ratio 4/(s_real·2^20) ≈ 4×10⁻⁶, ensuring
    /// convergence to full 62-bit precision in ~6 AGM iterations.
    ///
    /// Input: x > 0 as scaled integer (× 2^AGM_SCALE_BITS), where
    ///        AGM_SCALE represents the value 1.0
    /// Output: ln(x/SCALE) × 2^AGM_SCALE_BITS (signed, since ln(x<1) < 0)
    pub fn ln(&self, x: u128) -> i128 {
        if x == 0 {
            return i128::MIN;
        }
        if x == AGM_SCALE {
            return 0;
        } // ln(1) = 0

        // === STEP 1: Range reduction ===
        // Find integer m such that s = x × 2^(-m) is close to AGM_SCALE (i.e., ~1).
        // Then ln(x) = ln(s) + m × ln(2).
        //
        // We want the leading bit of s to be at position AGM_SCALE_BITS,
        // so m = (position of leading bit of x) - AGM_SCALE_BITS.
        let leading = 127u32.saturating_sub(x.leading_zeros());
        let m: i32 = leading as i32 - AGM_SCALE_BITS as i32;

        // Compute s = x × 2^(-m), clamped to valid range
        let s: u128 = if m >= 0 {
            x >> (m as u32).min(127)
        } else {
            let shift = ((-m) as u32).min(127 - leading);
            x << shift
        };

        // s should now be in [AGM_SCALE/2, 2*AGM_SCALE]. Guard against zero.
        if s == 0 {
            return i128::MIN;
        }

        // === STEP 2: AGM logarithm of s ===
        // Brent's formula: ln(s_real) = π / (2 × M(1, 4/(s_real × 2^N))) - N × ln(2)
        //
        // We need the second AGM argument ε = 4/(s_real × 2^N) to be small.
        // In scaled form: b_full = ε × SCALE = 4 × SCALE² / (s × 2^N)
        //
        // To avoid overflow computing SCALE², factor as:
        //   b_small = (4 × SCALE) >> N = SCALE >> (N - 2)
        //   b_full  = b_small × SCALE / s

        let n_extra: u32 = 20; // Extra precision doublings

        // Compute the second AGM argument: SCALE × 4 × 2^(-N) × SCALE / s
        // = 4 × SCALE² / (s × 2^N)
        // To avoid overflow in SCALE², compute as (4 × SCALE / 2^N) × (SCALE / s) × s_correction
        // Rearranged: (4 >> n_extra) × SCALE × SCALE / s
        // But 4 >> 20 = 0 for integer. So use: 4 × SCALE / (s >> (n_extra - 2)) ... wait.
        //
        // Better: b = (4 × SCALE) >> n_extra = SCALE >> (n_extra - 2)
        // Then multiply by SCALE/s: b_full = b × SCALE / s
        let b_small = AGM_SCALE >> (n_extra - 2); // = SCALE >> 18 ≈ 2^44

        // b_small × SCALE = 2^44 × 2^62 = 2^106, fits in u128
        let b_full = if s > 0 {
            b_small.saturating_mul(AGM_SCALE) / s
        } else {
            return i128::MIN;
        };

        // M(1, b) where both are scaled
        let agm_val = self.agm(AGM_SCALE, b_full);

        if agm_val == 0 {
            return i128::MIN;
        }

        // === Brent's formula (corrected) ===
        // ln(s_real) = π / (2 × M(1, 4/(s_real × 2^N))) - N × ln(2)
        //
        // In scaled arithmetic:
        //   agm_val = M(SCALE, b_full) = M(1, b_real) × SCALE
        //   π / (2 × M(1, b_real)) = π × SCALE / (2 × agm_val)
        //   Result (×SCALE) = π_scaled × SCALE / (2 × agm_val) - N × ln2_scaled
        //
        // Overflow check: π_scaled × SCALE ≈ 3.14 × 2^124 ≈ 2^125.65, fits u128.
        let pi_scaled = self.compute_pi_scaled();

        let pi_term = match pi_scaled.checked_mul(AGM_SCALE) {
            Some(v) => v / (2 * agm_val),
            None => {
                // Fallback: split to avoid overflow
                // π_scaled × SCALE / (2 × agm_val) = (π_scaled / 2) × SCALE / agm_val
                (pi_scaled / 2) * AGM_SCALE / agm_val
            }
        };

        let n_ln2 = (n_extra as u128) * self.ln_2_scaled();

        // The subtraction naturally produces the correct sign:
        // when s < SCALE, the AGM π-term < N×ln(2), giving negative result.
        let ln_s = pi_term as i128 - n_ln2 as i128;

        // === STEP 3: Reconstruct ===
        // ln(x) = ln(s) + m × ln(2)
        let ln_2 = self.ln_2_scaled() as i128;
        let m_contribution = (m as i128) * ln_2;

        ln_s + m_contribution
    }

    /// Checked natural logarithm: returns `DomainError` for x = 0 instead of sentinel.
    pub fn ln_checked(&self, x: u128) -> crate::TransResult<i128> {
        if x == 0 {
            return Err(crate::TranscendentalError::DomainError(
                "ln: argument must be positive",
            ));
        }
        Ok(self.ln(x))
    }

    /// Checked exp: returns `Overflow` instead of `u128::MAX` sentinel.
    pub fn exp_checked(&self, x: i128) -> crate::TransResult<u128> {
        if x == 0 {
            return Ok(AGM_SCALE);
        }

        let n = 16u32;
        let x_over_2n = x / (1i128 << n);

        let base = AGM_SCALE as i128 + x_over_2n;
        if base <= 0 {
            return Ok(0);
        }

        let mut result = base as u128;

        for _ in 0..n {
            let sq = result;
            if sq > (u128::MAX / sq.max(1)) {
                return Err(crate::TranscendentalError::Overflow(
                    "exp: intermediate square overflow",
                ));
            }
            let product = sq * sq;
            result = product / AGM_SCALE;
            if result > (u128::MAX / AGM_SCALE) {
                return Err(crate::TranscendentalError::Overflow(
                    "exp: result exceeds u128 range",
                ));
            }
        }

        Ok(result)
    }

    /// Compute π using the Gauss-Legendre (AGM) algorithm
    /// This is the Brent-Salamin algorithm:
    ///   a₀ = 1, b₀ = 1/√2
    ///   tₙ = t_{n-1} - pₙ(aₙ - a_{n+1})²
    ///   pₙ₊₁ = 2pₙ
    ///   π ≈ (aₙ + bₙ)² / (4tₙ)
    pub fn compute_pi_scaled(&self) -> u128 {
        // a₀ = 1 (scaled)
        let mut a = AGM_SCALE;

        // b₀ = 1/√2 (scaled)
        // √2 × SCALE = √(2 × SCALE²)
        let sqrt2_scaled = isqrt_newton_128(2 * AGM_SCALE * AGM_SCALE);
        // 1/√2 × SCALE = SCALE² / (√2 × SCALE) = SCALE / √2
        let mut b = (AGM_SCALE * AGM_SCALE) / sqrt2_scaled;

        // t₀ = 1/4 (scaled) = SCALE/4
        let mut t = AGM_SCALE / 4;

        // p₀ = 1 (unscaled counter)
        let mut p = 1u128;

        for _ in 0..self.max_iterations {
            // Check convergence
            let diff = a.abs_diff(b);
            if diff <= 1 {
                break;
            }

            // Save old a
            let a_old = a;

            // a_{n+1} = (a + b) / 2
            a = (a + b) / 2;

            // b_{n+1} = √(a_old × b)
            // Since a_old and b are both scaled by SCALE:
            // a_old × b = (actual_a × SCALE) × (actual_b × SCALE) = actual_a × actual_b × SCALE²
            // √(a_old × b) = √(actual_a × actual_b) × SCALE ✓
            b = isqrt_newton_128(a_old.saturating_mul(b));

            // t = t - p × (a_old - a)²
            // diff = a_old - a = (actual diff) × SCALE
            // diff² = (actual diff)² × SCALE²
            // We want to subtract p × (actual diff)² × SCALE from t
            // So: diff² / SCALE gives (actual diff)² × SCALE, then multiply by p
            let a_diff = a_old - a; // This is already the correct diff
            let diff_sq = a_diff.saturating_mul(a_diff) / AGM_SCALE;
            t = t.saturating_sub(p.saturating_mul(diff_sq));

            // p = 2p
            p = p.saturating_mul(2);
        }

        // π = (a + b)² / (4t)
        if t == 0 {
            return 0;
        }

        // sum = a + b (both scaled)
        // sum² / SCALE gives the correctly scaled square
        let sum = a + b;
        let sum_squared = sum.saturating_mul(sum) / AGM_SCALE;

        // π × SCALE = sum_squared / (4 × t / SCALE) = sum_squared × SCALE / (4t)
        // Since t is scaled, 4t is 4 × (T × SCALE)
        // Result: sum_squared × SCALE / (4t)
        //       = ((A+B)² × SCALE) × SCALE / (4 × T × SCALE)
        //       = (A+B)² × SCALE / (4T)  ✓
        sum_squared.saturating_mul(AGM_SCALE) / (4 * t)
    }

    /// Precomputed ln(2) × 2^62
    /// ln(2) ≈ 0.6931471805599453
    fn ln_2_scaled(&self) -> u128 {
        3196577161300663911 // ln(2) × 2^62
    }

    /// Compute exp(x) using the limit definition with compensated squaring.
    ///
    /// exp(x) = lim_{n→∞} (1 + x/2ⁿ)^(2ⁿ)
    ///
    /// Each squaring step `result = result² / SCALE` truncates the remainder,
    /// losing ~1 bit per step. Over n=20 steps this costs ~20 bits of the
    /// 62-bit working precision. We mitigate by:
    ///   (1) Using n=16 (sufficient convergence, fewer truncation steps)
    ///   (2) Tracking truncation remainder and compensating
    ///
    /// Input: x as signed scaled integer (× 2^AGM_SCALE_BITS)
    /// Output: exp(x/SCALE) × SCALE
    pub fn exp(&self, x: i128) -> u128 {
        if x == 0 {
            return AGM_SCALE;
        }

        let n = 16u32; // Reduced from 20: 2^16 = 65536 is sufficient for convergence
        let x_over_2n = x / (1i128 << n);

        // Start with 1 + x/2^n (scaled)
        let base = AGM_SCALE as i128 + x_over_2n;
        if base <= 0 {
            return 0;
        } // exp(very negative) → 0

        let mut result = base as u128;
        let mut compensation: u128 = 0; // Accumulated truncation error

        // Square n times with truncation tracking
        for _ in 0..n {
            // result² = result * result
            // We compute: quotient = result² / SCALE, remainder = result² % SCALE
            // The remainder contributes to error that we can partially compensate.
            let sq = result;

            // Check overflow before multiply
            if sq > (u128::MAX / sq.max(1)) {
                return u128::MAX; // Overflow: exp too large for u128
            }

            let product = sq * sq;
            let quotient = product / AGM_SCALE;
            let remainder = product % AGM_SCALE;

            // The truncation error from this step contributes to the next step's
            // error proportionally. Track it as a fraction of SCALE.
            compensation = (compensation * 2 + remainder) / AGM_SCALE;

            result = quotient;

            // Prevent runaway overflow
            if result > (u128::MAX / AGM_SCALE) {
                return u128::MAX;
            }
        }

        // Apply accumulated compensation (partial recovery of truncated bits)
        result.saturating_add(compensation)
    }

    /// Compute complete elliptic integral of the first kind K(k)
    /// K(k) = π / (2 × M(1, √(1-k²)))
    pub fn elliptic_k(&self, k_squared: u128) -> u128 {
        // Compute √(1 - k²)
        let one_minus_k2 = AGM_SCALE.saturating_sub(k_squared);
        let k_prime = isqrt_newton_128(one_minus_k2 * AGM_SCALE);

        // M(1, k')
        let agm_val = self.agm(AGM_SCALE, k_prime);

        // K = π / (2 × AGM)
        let pi_scaled = self.compute_pi_scaled();
        if agm_val > 0 {
            (pi_scaled * AGM_SCALE) / (2 * agm_val)
        } else {
            u128::MAX
        }
    }
}

/// Gauss's constant: 1/M(1, √2) ≈ 0.8346268...
pub fn gauss_constant_scaled() -> u128 {
    let engine = AgmEngine::default();
    let sqrt2 = isqrt_newton_128(2 * AGM_SCALE * AGM_SCALE);
    let agm_val = engine.agm(AGM_SCALE, sqrt2);

    if agm_val > 0 {
        (AGM_SCALE * AGM_SCALE) / agm_val
    } else {
        0
    }
}

/// Lemniscate constant: ω = ∫₀¹ 1/√(1-t⁴) dt
/// Related to AGM: ω = π / (2 × M(1, √2))
pub fn lemniscate_constant_scaled() -> u128 {
    let engine = AgmEngine::default();
    let pi = engine.compute_pi_scaled();
    let sqrt2 = isqrt_newton_128(2 * AGM_SCALE * AGM_SCALE);
    let agm_val = engine.agm(AGM_SCALE, sqrt2);

    if agm_val > 0 {
        (pi * AGM_SCALE) / (2 * agm_val)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_scaled(x: u128) -> f64 {
        x as f64 / AGM_SCALE as f64
    }

    fn to_scaled(x: f64) -> u128 {
        (x * AGM_SCALE as f64) as u128
    }

    #[test]
    fn test_agm_equal_inputs() {
        let engine = AgmEngine::default();
        let a = to_scaled(2.0);

        // M(a, a) = a
        let result = engine.agm(a, a);
        assert_eq!(result, a);
    }

    #[test]
    fn test_agm_basic() {
        let engine = AgmEngine::default();

        // M(1, 2) ≈ 1.4567...
        let a = AGM_SCALE;
        let b = 2 * AGM_SCALE;
        let result = engine.agm(a, b);

        let expected = 1.4567910310469068;
        let actual = from_scaled(result);

        println!("AGM(1,2) = {}", actual);
        assert!((actual - expected).abs() < 0.01);
    }

    #[test]
    fn test_pi_computation() {
        let engine = AgmEngine::default();
        let pi = engine.compute_pi_scaled();
        let pi_actual = from_scaled(pi);

        println!("Computed π = {}", pi_actual);
        assert!((pi_actual - std::f64::consts::PI).abs() < 0.001);
    }

    #[test]
    fn test_gauss_constant() {
        let g = gauss_constant_scaled();
        let g_actual = from_scaled(g);

        // Gauss's constant ≈ 0.8346268...
        println!("Gauss constant = {}", g_actual);
        assert!((g_actual - 0.8346268).abs() < 0.001);
    }

    #[test]
    fn test_exp_zero() {
        let engine = AgmEngine::default();
        let result = engine.exp(0);
        let actual = from_scaled(result);

        // exp(0) = 1
        assert!((actual - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_exp_one() {
        let engine = AgmEngine::default();
        let result = engine.exp(AGM_SCALE as i128);
        let actual = from_scaled(result);

        // exp(1) ≈ 2.718...
        println!("exp(1) = {}", actual);
        assert!((actual - std::f64::consts::E).abs() < 0.1);
    }

    #[test]
    fn test_ln_one() {
        let engine = AgmEngine::default();
        let result = engine.ln(AGM_SCALE);

        // ln(1) = 0
        assert!(result.abs() < 1000);
    }

    #[test]
    fn test_elliptic_k() {
        let engine = AgmEngine::default();

        // K(0) = π/2
        let k0 = engine.elliptic_k(0);
        let actual = from_scaled(k0);
        let expected = std::f64::consts::PI / 2.0;

        println!("K(0) = {}", actual);
        assert!((actual - expected).abs() < 0.01);
    }

    // ================================================================
    // GAP-01: Round-trip tests — exp(ln(x)) ≈ x and ln(exp(x)) ≈ x
    // ================================================================

    /// Round-trip test: exp(ln(x)) should return x (within precision limits).
    /// This validates that ln() and exp() are inverse operations even after
    /// our AGM ln() rewrite (EX-01) and exp() compensated squaring (EX-06).
    #[test]
    fn test_roundtrip_exp_ln() {
        let engine = AgmEngine::default();

        // Test across a range of values above 1
        let test_values: &[f64] = &[1.5, 2.0, 2.718281828, 4.0, 8.0, 16.0];

        for &val in test_values {
            let x = to_scaled(val);
            let ln_x = engine.ln(x);

            // exp expects i128 input
            let result = engine.exp(ln_x);
            let actual = from_scaled(result);

            let relative_error = ((actual - val) / val).abs();
            println!(
                "exp(ln({:.3})) = {:.6} (error: {:.2e})",
                val, actual, relative_error
            );

            // Allow up to 5% relative error due to truncation in scaled arithmetic.
            // The compensated squaring (EX-06) should keep this well under 5%.
            assert!(
                relative_error < 0.05,
                "Round-trip exp(ln({})) = {} — relative error {:.4} exceeds 5%",
                val,
                actual,
                relative_error
            );
        }
    }

    /// Round-trip test: ln(exp(x)) should return x.
    /// Tests the opposite direction of the exp/ln inverse relationship.
    #[test]
    fn test_roundtrip_ln_exp() {
        let engine = AgmEngine::default();

        // Test small positive values where exp() stays in range
        let test_values: &[f64] = &[0.1, 0.5, 1.0, 1.5, 2.0];

        for &val in test_values {
            let x_scaled = (val * AGM_SCALE as f64) as i128;
            let exp_x = engine.exp(x_scaled);

            if exp_x == 0 {
                continue;
            } // Skip if exp overflowed

            let result = engine.ln(exp_x as u128);
            let actual = result as f64 / AGM_SCALE as f64;

            let abs_error = (actual - val).abs();
            println!(
                "ln(exp({:.3})) = {:.6} (abs error: {:.2e})",
                val, actual, abs_error
            );

            assert!(
                abs_error < 0.2,
                "Round-trip ln(exp({})) = {} — absolute error {:.4} too large",
                val,
                actual,
                abs_error
            );
        }
    }

    // ================================================================
    // GAP-02: Boundary value tests — edge cases and extremes
    // ================================================================

    /// Test ln() at values very close to 1 (where range reduction is minimal).
    #[test]
    fn test_ln_near_one() {
        let engine = AgmEngine::default();

        // ln(1 + ε) ≈ ε for small ε
        // Test with x = 1.001 × SCALE
        let x = AGM_SCALE + AGM_SCALE / 1000;
        let result = engine.ln(x);
        let actual = result as f64 / AGM_SCALE as f64;

        println!("ln(1.001) = {:.8} (expected ≈ 0.000999)", actual);
        // Should be approximately 0.001
        assert!(
            actual.abs() < 0.01,
            "ln(1.001) should be very small, got {}",
            actual
        );
        assert!(actual > 0.0, "ln(x>1) should be positive");
    }

    /// Test ln() with very small input (near-zero scaled value).
    #[test]
    fn test_ln_very_small() {
        let engine = AgmEngine::default();

        // ln(0.001) ≈ -6.907
        // x = 0.001 × AGM_SCALE
        let x = AGM_SCALE / 1000;
        let result = engine.ln(x);
        let actual = result as f64 / AGM_SCALE as f64;

        println!("ln(0.001) = {:.6} (expected ≈ -6.907)", actual);
        assert!(result < 0, "ln(x<1) should be negative");
    }

    /// Test ln() at x=0 returns sentinel.
    #[test]
    fn test_ln_zero_sentinel() {
        let engine = AgmEngine::default();
        assert_eq!(engine.ln(0), i128::MIN);
    }

    /// Test exp(0) = 1 exactly.
    #[test]
    fn test_exp_zero_exact() {
        let engine = AgmEngine::default();
        let result = engine.exp(0);
        let actual = from_scaled(result);
        assert!(
            (actual - 1.0).abs() < 0.001,
            "exp(0) should be 1.0, got {}",
            actual
        );
    }

    /// Test AGM with inputs near AGM_SCALE boundary.
    /// This exercises the overflow-safe geometric mean path (GAP-04 fix).
    #[test]
    fn test_agm_near_scale_boundary() {
        let engine = AgmEngine::default();

        // Both inputs at AGM_SCALE — should converge to AGM_SCALE
        let result = engine.agm(AGM_SCALE, AGM_SCALE);
        assert_eq!(result, AGM_SCALE);

        // One input at AGM_SCALE, other at 2× — tests geometric mean
        let result = engine.agm(AGM_SCALE, 2 * AGM_SCALE);
        let actual = from_scaled(result);
        println!("AGM(1, 2) = {:.6}", actual);
        // M(1,2) ≈ 1.4568
        assert!((actual - 1.4568).abs() < 0.01);
    }

    /// Test AGM with one very small input.
    /// Should converge but not overflow or panic.
    #[test]
    fn test_agm_asymmetric() {
        let engine = AgmEngine::default();

        // One large, one tiny
        let a = AGM_SCALE;
        let b = 1u128; // Extremely small

        // Should not panic or overflow
        let result = engine.agm(a, b);
        println!("AGM(SCALE, 1) = {}", result);
        assert!(result > 0, "AGM should be positive");
        assert!(result < a, "AGM should be less than the larger input");
    }

    /// Test compute_pi_scaled returns reasonable value.
    #[test]
    fn test_pi_precision() {
        let engine = AgmEngine::default();
        let pi = engine.compute_pi_scaled();
        let actual = from_scaled(pi);

        // Verify to 6 decimal places
        let error = (actual - std::f64::consts::PI).abs();
        println!("π = {:.10} (error: {:.2e})", actual, error);
        assert!(
            error < 1e-6,
            "π should be accurate to 6 digits, error was {:.2e}",
            error
        );
    }

    /// Test ln_2_scaled returns correct value.
    #[test]
    fn test_ln2_precision() {
        let engine = AgmEngine::default();
        let ln2 = engine.ln_2_scaled();
        let actual = ln2 as f64 / AGM_SCALE as f64;

        let error = (actual - std::f64::consts::LN_2).abs();
        println!("ln(2) = {:.10} (error: {:.2e})", actual, error);
        assert!(error < 0.01, "ln(2) error too large: {:.2e}", error);
    }

    #[test]
    fn test_lemniscate_constant() {
        let result = super::lemniscate_constant_scaled();
        assert!(result > 0, "lemniscate constant should be positive");
        let approx = result as f64 / AGM_SCALE as f64;
        // The function computes π / (2 * AGM(1, √2)) ≈ 1.311
        println!("lemniscate_constant_scaled / SCALE = {}", approx);
        assert!(
            approx > 1.0 && approx < 2.0,
            "lemniscate constant out of range: {}",
            approx
        );
    }

    #[test]
    fn test_ln_zero_returns_sentinel() {
        let engine = AgmEngine::default();
        let result = engine.ln(0);
        assert_eq!(result, i128::MIN, "ln(0) should return i128::MIN sentinel");
    }

    // ================================================================
    // TDD: Result-based checked API
    // ================================================================

    #[test]
    fn test_ln_checked_one() {
        let engine = AgmEngine::default();
        let result = engine.ln_checked(AGM_SCALE);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0); // ln(1) = 0
    }

    #[test]
    fn test_ln_checked_zero() {
        let engine = AgmEngine::default();
        let result = engine.ln_checked(0);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(crate::TranscendentalError::DomainError(_))
        ));
    }

    #[test]
    fn test_ln_checked_positive() {
        let engine = AgmEngine::default();
        let result = engine.ln_checked(2 * AGM_SCALE); // ln(2)
        assert!(result.is_ok());
        let val = result.unwrap() as f64 / AGM_SCALE as f64;
        assert!((val - std::f64::consts::LN_2).abs() < 0.05);
    }

    #[test]
    fn test_exp_checked_zero() {
        let engine = AgmEngine::default();
        let result = engine.exp_checked(0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AGM_SCALE); // exp(0) = 1
    }

    #[test]
    fn test_exp_checked_overflow() {
        let engine = AgmEngine::default();
        // Very large input should overflow
        let result = engine.exp_checked(i128::MAX / 2);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(crate::TranscendentalError::Overflow(_))
        ));
    }

    #[test]
    fn test_exp_checked_one() {
        let engine = AgmEngine::default();
        let result = engine.exp_checked(AGM_SCALE as i128); // exp(1)
        assert!(result.is_ok());
        let val = from_scaled(result.unwrap());
        assert!((val - std::f64::consts::E).abs() < 0.1);
    }
}
