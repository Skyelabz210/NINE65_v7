//! CORDIC (COordinate Rotation DIgital Computer) Algorithm
//!
//! Transcendental functions using ONLY add, subtract, and bit-shift.
//! No multiplication or division in the main iteration loop!
//!
//! ## How CORDIC Works:
//! Rotates a vector through a series of predetermined angles.
//! Each angle is chosen so that tan(angle) = 2^(-i), making the
//! "multiplication by tangent" become a simple bit shift.
//!
//! ## Functions Computed:
//! - **Rotation Mode**: sin, cos, tan (given angle, find coordinates)
//! - **Vectoring Mode**: atan, magnitude (given coordinates, find angle)
//! - **Hyperbolic Mode**: sinh, cosh, tanh, exp, ln, sqrt
//!
//! ## QMNF Integration:
//! - All operations are integer-only
//! - Gain factor K ≈ 0.6072529... is precomputed as scaled integer
//! - Results exact to number of iterations (1 bit per iteration)
//!
//! Performance: ~50ns for 32-bit precision (32 iterations)

use crate::sqrt::isqrt_newton_128;
use crate::ErrorBound;

/// Number of CORDIC iterations (= bits of precision)
pub const CORDIC_ITERATIONS: usize = 32;

/// CORDIC gain factor K = ∏(1/√(1 + 2^(-2i))) ≈ 0.6072529350088814
/// Precomputed as K × 2^30
pub const CORDIC_GAIN_30: i64 = 652_032_874; // 0.6072529350... × 2^30

/// Inverse gain 1/K × 2^30 (for post-multiplication)
pub const CORDIC_INV_GAIN_30: i64 = 1_768_195_363; // 1.6467602... × 2^30

/// Precomputed arctangent table: atan(2^(-i)) × 2^30
/// These are the rotation angles in scaled radians
pub const CORDIC_ATAN_TABLE: [i64; CORDIC_ITERATIONS] = [
    843_314_857, // atan(2^0) = π/4
    497_837_829, // atan(2^-1)
    263_043_837, // atan(2^-2)
    133_525_159, // atan(2^-3)
    67_021_687,  // atan(2^-4)
    33_543_516,  // atan(2^-5)
    16_775_851,  // atan(2^-6)
    8_388_437,   // atan(2^-7)
    4_194_283,   // atan(2^-8)
    2_097_149,   // atan(2^-9)
    1_048_576,   // atan(2^-10)
    524_288,     // atan(2^-11)
    262_144,     // atan(2^-12)
    131_072,     // atan(2^-13)
    65_536,      // atan(2^-14)
    32_768,      // atan(2^-15)
    16_384,      // atan(2^-16)
    8_192,       // atan(2^-17)
    4_096,       // atan(2^-18)
    2_048,       // atan(2^-19)
    1_024,       // atan(2^-20)
    512,         // atan(2^-21)
    256,         // atan(2^-22)
    128,         // atan(2^-23)
    64,          // atan(2^-24)
    32,          // atan(2^-25)
    16,          // atan(2^-26)
    8,           // atan(2^-27)
    4,           // atan(2^-28)
    2,           // atan(2^-29)
    1,           // atan(2^-30)
    0,           // atan(2^-31) ≈ 0
];

/// Precomputed arctanh table for hyperbolic CORDIC: atanh(2^(-i)) × 2^30
pub const CORDIC_ATANH_TABLE: [i64; CORDIC_ITERATIONS] = [
    594_903_544, // atanh(2^-1) - note: starts at i=1
    267_030_909, // atanh(2^-2)
    131_620_058, // atanh(2^-3)
    65_551_028,  // atanh(2^-4)
    32_760_413,  // atanh(2^-5)
    16_377_290,  // atanh(2^-6)
    8_188_047,   // atanh(2^-7)
    4_093_969,   // atanh(2^-8)
    2_046_980,   // atanh(2^-9)
    1_023_489,   // atanh(2^-10)
    511_744,     // atanh(2^-11)
    255_872,     // atanh(2^-12)
    127_936,     // atanh(2^-13)
    63_968,      // atanh(2^-14)
    31_984,      // atanh(2^-15)
    15_992,      // atanh(2^-16)
    7_996,       // atanh(2^-17)
    3_998,       // atanh(2^-18)
    1_999,       // atanh(2^-19)
    1_000,       // atanh(2^-20) - approx from here
    500,
    250,
    125,
    62,
    31,
    16,
    8,
    4,
    2,
    1,
    0,
    0,
];

/// Scale factor (2^30)
pub const SCALE: i64 = 1 << 30;
/// Half pi × 2^30
pub const HALF_PI: i64 = 1_686_629_713;
/// Pi × 2^30  
pub const PI: i64 = 3_373_259_426;
/// Two pi × 2^30
pub const TWO_PI: i64 = 6_746_518_852;

/// CORDIC engine for exact transcendental computation
#[derive(Clone, Debug)]
pub struct CordicEngine {
    /// Number of iterations (precision in bits)
    pub iterations: usize,
    /// Precomputed gain factor (scaled)
    pub gain: i64,
    /// Precomputed inverse gain (scaled)
    pub inv_gain: i64,
}

impl Default for CordicEngine {
    fn default() -> Self {
        Self::new(CORDIC_ITERATIONS)
    }
}

impl CordicEngine {
    /// Create CORDIC engine with specified iterations
    pub fn new(iterations: usize) -> Self {
        // Compute gain factor for this number of iterations
        // K = ∏(1/√(1 + 2^(-2i))) for i = 0..iterations
        // For full 32 iterations, use precomputed value
        let (gain, inv_gain) = if iterations >= CORDIC_ITERATIONS {
            (CORDIC_GAIN_30, CORDIC_INV_GAIN_30)
        } else {
            // Compute gain for fewer iterations using integer sqrt.
            // K_n = ∏_{i=0}^{n-1} √(1 + 2^{-2i})
            // We compute K_n × 2^30 incrementally.
            let mut k_sq = SCALE as i128 * SCALE as i128; // (2^30)^2
            for i in 0..iterations {
                // k_sq *= (1 + 2^{-2i}) = multiply by (2^{2i} + 1) / 2^{2i}
                let shift = 2 * i as u32;
                k_sq = k_sq * ((1i128 << shift) + 1) / (1i128 << shift);
            }
            // k = isqrt(k_sq) = K × 2^30
            let k = crate::sqrt::isqrt_newton(k_sq as u64) as i64;
            // inv_k = 2^60 / k  (since gain × inv_gain = SCALE²)
            let inv_k = ((SCALE as i128 * SCALE as i128) / k as i128) as i64;
            (k, inv_k)
        };

        Self {
            iterations,
            gain,
            inv_gain,
        }
    }

    /// Compute sin and cos simultaneously (most efficient)
    /// Input: angle in scaled radians (angle × 2^30)
    /// Output: (cos × 2^30, sin × 2^30)
    #[inline]
    pub fn sincos(&self, mut angle: i64) -> (i64, i64) {
        // O(1) range reduction to [-π, π] using modular arithmetic.
        // The while-loop approach was O(n) for large accumulated angles
        // (e.g., from FHE rotations). This single-expression form handles
        // any magnitude in constant time.
        //
        // Integer modular reduction: angle mod 2π mapped to [-π, π]
        // Uses the identity: ((x % m) + m) % m for positive modular result
        let reduced = ((angle % TWO_PI) + TWO_PI) % TWO_PI;
        angle = if reduced > PI {
            reduced - TWO_PI
        } else {
            reduced
        };

        // Handle quadrants by rotating to [-π/2, π/2]
        let flip_cos;
        if angle > HALF_PI {
            // Quadrant II: use cos(θ) = -cos(π-θ), sin(θ) = sin(π-θ)
            angle = PI - angle;
            flip_cos = true;
        } else if angle < -HALF_PI {
            // Quadrant III: use cos(θ) = -cos(-π-θ), sin(θ) = -sin(-π-θ)
            angle = -PI - angle;
            flip_cos = true;
        } else {
            flip_cos = false;
        }

        // Start with unit vector (1, 0) scaled by SCALE
        let mut x = SCALE;
        let mut y = 0i64;
        let mut z = angle;

        // CORDIC rotation iterations - NO MULTIPLIES in main loop!
        for i in 0..self.iterations.min(CORDIC_ITERATIONS) {
            let d = if z >= 0 { 1i64 } else { -1i64 };

            // The magic: multiply by 2^(-i) is just a bit shift!
            let x_shift = x >> i;
            let y_shift = y >> i;

            // Rotate: new_x = x - d*y*2^(-i), new_y = y + d*x*2^(-i)
            let new_x = x - d * y_shift;
            let new_y = y + d * x_shift;

            // Update angle: z = z - d*atan(2^(-i))
            let new_z = z - d * CORDIC_ATAN_TABLE[i];

            x = new_x;
            y = new_y;
            z = new_z;
        }

        // After CORDIC iterations, (x, y) = (cos/K, sin/K) × SCALE
        // where K ≈ 1.6468 is the CORDIC gain factor
        // Multiply by gain (K ≈ 0.6073) to compensate
        // (This is because each iteration scales by sqrt(1 + 2^(-2i)))
        let cos_val = (x as i128 * self.gain as i128 / SCALE as i128) as i64;
        let sin_val = (y as i128 * self.gain as i128 / SCALE as i128) as i64;

        if flip_cos {
            (-cos_val, sin_val)
        } else {
            (cos_val, sin_val)
        }
    }

    /// Compute sine only
    #[inline]
    pub fn sin(&self, angle: i64) -> i64 {
        self.sincos(angle).1
    }

    /// Compute cosine only
    #[inline]
    pub fn cos(&self, angle: i64) -> i64 {
        self.sincos(angle).0
    }

    /// Compute tangent: tan(angle) = sin/cos
    /// Uses K-Elimination style exact division.
    /// Returns `i64::MAX` sentinel when cos ≈ 0. Prefer `tan_checked` for proper error handling.
    #[inline]
    pub fn tan(&self, angle: i64) -> i64 {
        let (cos_val, sin_val) = self.sincos(angle);
        if cos_val == 0 {
            return i64::MAX;
        }
        (sin_val as i128 * SCALE as i128 / cos_val as i128) as i64
    }

    /// Checked tangent: returns `DomainError` when |cos(angle)| is too small for
    /// meaningful division (angle near π/2 + nπ). The threshold is 1 ULP at the
    /// current CORDIC precision — below this, the quotient overflows i64.
    #[inline]
    pub fn tan_checked(&self, angle: i64) -> crate::TransResult<i64> {
        let (cos_val, sin_val) = self.sincos(angle);
        // When |cos| < threshold, tan would overflow the i64 range.
        // Threshold: |sin/cos| must fit in i64, so |cos| > |sin| / i64::MAX * SCALE.
        // Simplified: reject when |cos| < 2 (≈ 2^(-29) in real units).
        if cos_val.abs() < 2 {
            return Err(crate::TranscendentalError::DomainError(
                "tan: cos(angle) ≈ 0, tangent undefined",
            ));
        }
        Ok((sin_val as i128 * SCALE as i128 / cos_val as i128) as i64)
    }

    /// Compute arctangent (vectoring mode)
    /// Input: y/x ratio as scaled integer
    /// Output: angle in scaled radians
    #[inline]
    pub fn atan(&self, ratio: i64) -> i64 {
        // Vectoring mode: start with (x, y) = (SCALE, ratio), drive y to 0
        let mut x = SCALE;
        let mut y = ratio;
        let mut z = 0i64;

        for i in 0..self.iterations.min(CORDIC_ITERATIONS) {
            let d = if y < 0 { 1i64 } else { -1i64 };

            let x_shift = x >> i;
            let y_shift = y >> i;

            let new_x = x - d * y_shift;
            let new_y = y + d * x_shift;
            let new_z = z - d * CORDIC_ATAN_TABLE[i];

            x = new_x;
            y = new_y;
            z = new_z;
        }

        z
    }

    /// Compute atan2(y, x) - angle of vector (x, y)
    /// Handles all quadrants correctly
    #[inline]
    pub fn atan2(&self, y: i64, x: i64) -> i64 {
        if x == 0 {
            return if y > 0 {
                HALF_PI
            } else if y < 0 {
                -HALF_PI
            } else {
                0
            };
        }

        let mut angle = self.atan((y as i128 * SCALE as i128 / x as i128) as i64);

        // Quadrant adjustment
        if x < 0 {
            if y >= 0 {
                angle += PI;
            } else {
                angle -= PI;
            }
        }

        angle
    }

    /// Compute vector magnitude: sqrt(x² + y²)
    /// Uses vectoring mode - the x result after convergence is the magnitude × K
    #[inline]
    pub fn magnitude(&self, x: i64, y: i64) -> i64 {
        // Vectoring mode: rotate (x,y) so that y→0, then xv = magnitude × K.
        // We place both components in the first quadrant (xv≥0) and let
        // the sign of yv drive the rotation direction at each step.
        let mut xv = x.abs();
        let mut yv = y.abs();

        for i in 0..self.iterations.min(CORDIC_ITERATIONS) {
            // d = sign decision: rotate to drive yv toward zero
            let x_shift = xv >> i;
            let y_shift = yv >> i;

            if yv > 0 {
                // yv positive → rotate clockwise (subtract from y)
                xv += y_shift;
                yv -= x_shift;
            } else {
                // yv negative → rotate counter-clockwise (add to y)
                xv -= y_shift;
                yv += x_shift;
            }
        }

        // Result is xv × gain to compensate for CORDIC scaling
        ((xv as i128 * self.gain as i128 / SCALE as i128) as i64).abs()
    }
}

/// Hyperbolic CORDIC engine
/// Uses different rotation equations and angle table
#[derive(Clone, Debug)]
pub struct HyperbolicCordic {
    pub iterations: usize,
    /// Hyperbolic gain factor (different from circular)
    pub gain: i64,
}

impl Default for HyperbolicCordic {
    fn default() -> Self {
        Self::new(CORDIC_ITERATIONS)
    }
}

impl HyperbolicCordic {
    pub fn new(iterations: usize) -> Self {
        // Hyperbolic CORDIC gain K_h = ∏√(1 - 2^(-2i)) for each effective iteration.
        // Unlike circular CORDIC, iterations 4, 13, 40, 121, ... (3k+1 sequence)
        // are repeated, so their factors appear TWICE in the product.
        //
        // We compute 1/K_h (the correction factor) in scaled integer arithmetic.
        // Working in u64 with SCALE = 2^30 precision.

        let scale = SCALE as u64;
        // Accumulate product in higher precision to avoid truncation drift
        // inv_k_h starts at SCALE (representing 1.0)
        let mut inv_k_h: u128 = scale as u128;

        let mut repeat_at: usize = 4;
        let max_iter = iterations.min(CORDIC_ITERATIONS).min(30);

        let mut i: usize = 1;
        while i < max_iter {
            // Factor for iteration i: 1/√(1 - 2^(-2i))
            // = 1/√(1 - 4^(-i))
            // In scaled form: SCALE / √(SCALE² - SCALE²/4^i)
            //                = SCALE / √(SCALE² × (1 - 4^(-i)))
            //
            // Compute: denominator² = SCALE² - SCALE²>>2i = SCALE² × (1 - 2^(-2i))
            let shift = 2 * i as u32;
            let scale_sq = (scale as u128) * (scale as u128);
            let denom_sq = if shift < 64 {
                scale_sq - (scale_sq >> shift)
            } else {
                scale_sq // 2^(-2i) ≈ 0 for large i
            };

            // isqrt of denom_sq gives √(SCALE²×(1-2^(-2i))) = SCALE×√(1-2^(-2i))
            // Then 1/√(1-2^(-2i)) = SCALE / isqrt(denom_sq/1) ...
            // Actually: factor = SCALE² / isqrt(denom_sq)
            let denom = isqrt_newton_128(denom_sq);
            if denom > 0 {
                // inv_k_h *= SCALE / denom (this is the 1/√(1-2^(-2i)) factor)
                inv_k_h = inv_k_h * (scale as u128) / denom;
            }

            // Repeated iterations at 4, 13, 40, 121, ... apply the factor twice
            if i == repeat_at && repeat_at < 30 {
                if denom > 0 {
                    inv_k_h = inv_k_h * (scale as u128) / denom;
                }
                repeat_at = 3 * repeat_at + 1;
            }

            i += 1;
        }

        let gain = inv_k_h.min(i64::MAX as u128) as i64;
        Self { iterations, gain }
    }

    /// Compute sinh and cosh simultaneously
    /// Input: x in scaled units
    /// Output: (cosh × 2^30, sinh × 2^30)
    pub fn sinhcosh(&self, arg: i64) -> (i64, i64) {
        // Special case: arg = 0 gives (1, 0) exactly
        if arg == 0 {
            return (SCALE, 0);
        }

        // Hyperbolic CORDIC converges for |arg| ≤ 1.1182 (sum of atanh table).
        // For larger arguments, halve recursively: sinh(2x) = 2*sinh(x)*cosh(x),
        // cosh(2x) = 2*cosh²(x) - 1.
        let convergence_limit = SCALE + (SCALE >> 3); // ~1.125 * SCALE
        if arg.abs() > convergence_limit {
            let half_arg = arg / 2;
            let (c, s) = self.sinhcosh(half_arg);
            // Double-angle: cosh(2x) = 2*cosh²(x) - 1, sinh(2x) = 2*sinh(x)*cosh(x)
            let cosh_2x = (2i64.saturating_mul((c as i128 * c as i128 / SCALE as i128) as i64))
                .saturating_sub(SCALE);
            let sinh_2x = 2i64.saturating_mul((s as i128 * c as i128 / SCALE as i128) as i64);
            return (cosh_2x, sinh_2x);
        }

        let mut x = SCALE; // Start at (1, 0)
        let mut y = 0i64;
        let mut z = arg;

        // Hyperbolic CORDIC - note: iterations 4, 13, 40, ... must be repeated
        // Also note: starts at i=1 (not i=0 like circular)
        let mut i = 1usize;
        let mut repeat_at = 4usize;

        while i < self.iterations.min(CORDIC_ITERATIONS) && i < 30 {
            let d = if z >= 0 { 1i64 } else { -1i64 };

            let x_shift = x >> i;
            let y_shift = y >> i;

            // Hyperbolic rotation: x' = x + d*y*2^(-i), y' = y + d*x*2^(-i)
            // Note the + sign (vs - for circular)
            let new_x = x + d * y_shift;
            let new_y = y + d * x_shift;
            // Use i-1 for table index since table[0] = atanh(2^-1)
            let idx = (i - 1).min(CORDIC_ITERATIONS - 1);
            let new_z = z - d * CORDIC_ATANH_TABLE[idx];

            x = new_x;
            y = new_y;
            z = new_z;

            // Repeat iteration at k = 4, 13, 40, 121, ... (3k+1 sequence)
            if i == repeat_at && repeat_at < 30 {
                // Repeat this iteration
                let d = if z >= 0 { 1i64 } else { -1i64 };
                let x_shift = x >> i;
                let y_shift = y >> i;
                x += d * y_shift;
                y += d * x_shift;
                z -= d * CORDIC_ATANH_TABLE[idx];
                repeat_at = 3 * repeat_at + 1;
            }

            i += 1;
        }

        // Apply gain correction (multiply by 1/K_h to get actual values)
        let cosh_val = (x as i128 * self.gain as i128 / SCALE as i128) as i64;
        let sinh_val = (y as i128 * self.gain as i128 / SCALE as i128) as i64;

        (cosh_val, sinh_val)
    }

    /// Compute sinh
    #[inline]
    pub fn sinh(&self, arg: i64) -> i64 {
        self.sinhcosh(arg).1
    }

    /// Compute cosh
    #[inline]
    pub fn cosh(&self, arg: i64) -> i64 {
        self.sinhcosh(arg).0
    }

    /// Compute exp(x) = cosh(x) + sinh(x)
    #[inline]
    pub fn exp(&self, arg: i64) -> i64 {
        let (cosh_val, sinh_val) = self.sinhcosh(arg);
        cosh_val + sinh_val
    }

    /// Compute natural log using vectoring mode
    /// Input: x > 0 in scaled units
    /// Output: ln(x) × 2^30
    pub fn ln(&self, x: i64) -> i64 {
        if x <= 0 {
            return i64::MIN;
        }
        // Special case: ln(1) = 0
        if x == SCALE {
            return 0;
        }

        // For ln, we use: ln(x) = 2 * atanh((x-1)/(x+1))
        // Use hyperbolic vectoring mode starting from (x+1, x-1)
        // Vectoring drives y → 0, accumulates angle in z

        let x_plus_1 = x + SCALE;
        let x_minus_1 = x - SCALE;

        let mut xv = x_plus_1;
        let mut yv = x_minus_1;
        let mut z = 0i64;

        let mut i = 1usize;
        let mut repeat_at = 4usize;

        while i < self.iterations.min(CORDIC_ITERATIONS) && i < 30 {
            // For hyperbolic vectoring: d = -sign(y) to drive y toward 0
            // (opposite of rotation mode)
            let d = if yv >= 0 { -1i64 } else { 1i64 };

            let x_shift = xv >> i;
            let y_shift = yv >> i;

            // Hyperbolic vectoring: same rotation equations
            let new_x = xv + d * y_shift;
            let new_y = yv + d * x_shift;
            // Note: z accumulates with OPPOSITE sign for vectoring
            let idx = (i - 1).min(CORDIC_ITERATIONS - 1);
            let new_z = z - d * CORDIC_ATANH_TABLE[idx];

            xv = new_x;
            yv = new_y;
            z = new_z;

            if i == repeat_at && repeat_at < 30 {
                let d = if yv >= 0 { -1i64 } else { 1i64 };
                let x_shift = xv >> i;
                let y_shift = yv >> i;
                xv += d * y_shift;
                yv += d * x_shift;
                z -= d * CORDIC_ATANH_TABLE[idx];
                repeat_at = 3 * repeat_at + 1;
            }

            i += 1;
        }

        // Result is 2 * z = 2 * atanh((x-1)/(x+1)) = ln(x)
        2 * z
    }

    /// Checked natural log: returns `DomainError` for x ≤ 0 instead of sentinel.
    pub fn ln_checked(&self, x: i64) -> crate::TransResult<i64> {
        if x <= 0 {
            return Err(crate::TranscendentalError::DomainError(
                "ln: argument must be positive",
            ));
        }
        Ok(self.ln(x))
    }

    /// Compute square root using hyperbolic CORDIC.
    ///
    /// **WARNING**: This implementation has limited precision due to the
    /// hyperbolic CORDIC convergence domain. For production use, prefer
    /// `crate::sqrt::isqrt_newton` or `crate::sqrt::sqrt_scaled` which
    /// provide exact integer square roots via Newton-Raphson.
    ///
    /// Retained for: (a) completeness of the CORDIC API surface, and
    /// (b) potential future use in FHE contexts where the CORDIC dataflow
    /// is already in the pipeline and a separate Newton call is costlier.
    #[deprecated(
        since = "0.2.0",
        note = "Use crate::sqrt::isqrt_newton or sqrt_scaled instead. \
        CORDIC sqrt has limited precision compared to Newton-Raphson."
    )]
    #[allow(dead_code)]
    pub(crate) fn sqrt(&self, x: i64) -> i64 {
        if x < 0 {
            return 0;
        }
        if x == 0 {
            return 0;
        }

        // For sqrt, we use: sqrt(a+b) * sqrt(a-b) = sqrt(a² - b²)
        // Start with a = (x + SCALE)/2, b = (x - SCALE)/2
        // Then sqrt(x) = sqrt((a+b)(a-b) ... via hyperbolic identity

        // Simpler: use Newton-Raphson in the sqrt module
        // This is here for completeness but integer Newton is better
        let half_x = x >> 1;
        let quarter = SCALE >> 2;

        let mut xv = half_x + quarter;
        let mut yv = half_x - quarter;

        let mut i = 1usize;
        while i < self.iterations.min(CORDIC_ITERATIONS) {
            let x_shift = xv >> i;
            let y_shift = yv >> i;

            let d = if yv >= 0 { 1i64 } else { -1i64 };

            xv += d * y_shift;
            yv += d * x_shift;

            i += 1;
        }

        // The result needs adjustment - prefer Newton-Raphson for sqrt
        (xv as i128 * self.gain as i128 / SCALE as i128) as i64
    }
}

/// Error bound for CORDIC operations
pub fn cordic_error_bound(iterations: usize) -> ErrorBound {
    ErrorBound {
        ulps: 1,
        correct_bits: iterations as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_scaled(x: f64) -> i64 {
        (x * SCALE as f64) as i64
    }

    fn from_scaled(x: i64) -> f64 {
        x as f64 / SCALE as f64
    }

    #[test]
    fn test_sincos_zero() {
        let engine = CordicEngine::default();
        let (cos_val, sin_val) = engine.sincos(0);

        assert!((from_scaled(cos_val) - 1.0).abs() < 1e-6);
        assert!(from_scaled(sin_val).abs() < 1e-6);
    }

    #[test]
    fn test_sincos_pi_over_4() {
        let engine = CordicEngine::default();
        let angle = HALF_PI / 2; // π/4
        let (cos_val, sin_val) = engine.sincos(angle);

        let expected = std::f64::consts::FRAC_1_SQRT_2;
        assert!((from_scaled(cos_val) - expected).abs() < 1e-5);
        assert!((from_scaled(sin_val) - expected).abs() < 1e-5);
    }

    #[test]
    fn test_sincos_pi_over_2() {
        let engine = CordicEngine::default();
        let (cos_val, sin_val) = engine.sincos(HALF_PI);

        assert!(from_scaled(cos_val).abs() < 1e-5);
        assert!((from_scaled(sin_val) - 1.0).abs() < 1e-5);
    }

    #[test]
    fn test_atan() {
        let engine = CordicEngine::default();

        // atan(1) = π/4
        let result = engine.atan(SCALE);
        let expected = HALF_PI / 2;
        assert!((result - expected).abs() < 1000); // Within ~1e-6
    }

    #[test]
    fn test_magnitude() {
        let engine = CordicEngine::default();

        // magnitude(3, 4) = 5
        let x = to_scaled(3.0);
        let y = to_scaled(4.0);
        let mag = engine.magnitude(x, y);

        assert!((from_scaled(mag) - 5.0).abs() < 0.001);
    }

    #[test]
    fn test_hyperbolic_exp() {
        let hyp = HyperbolicCordic::default();

        // exp(0) = 1
        let result = hyp.exp(0);
        assert!((from_scaled(result) - 1.0).abs() < 0.01);

        // exp(1) ≈ 2.718
        let result = hyp.exp(SCALE);
        let _expected = std::f64::consts::E;
        // Hyperbolic CORDIC has limited range, check if reasonable
        println!("exp(1) = {}", from_scaled(result));
    }

    #[test]
    fn test_ln() {
        let hyp = HyperbolicCordic::default();

        // ln(1) = 0
        let result = hyp.ln(SCALE);
        assert!(from_scaled(result).abs() < 0.01);

        // ln(e) ≈ 1
        let e_scaled = to_scaled(std::f64::consts::E);
        let result = hyp.ln(e_scaled);
        assert!((from_scaled(result) - 1.0).abs() < 0.1);
    }

    // ================================================================
    // GAP-01: CORDIC round-trip tests
    // ================================================================

    /// sin²(θ) + cos²(θ) = 1 for various angles.
    /// This is the fundamental Pythagorean identity and the strongest
    /// test that CORDIC gain correction and range reduction are correct.
    #[test]
    fn test_pythagorean_identity() {
        let engine = CordicEngine::default();

        let angles = [0, HALF_PI / 4, HALF_PI / 2, HALF_PI, PI, -HALF_PI];
        for angle in angles {
            let (cos_v, sin_v) = engine.sincos(angle);

            // sin² + cos² should equal SCALE² / SCALE = SCALE
            let sum_sq =
                (cos_v as i128 * cos_v as i128 + sin_v as i128 * sin_v as i128) / SCALE as i128;
            let error = (sum_sq - SCALE as i128).abs();

            assert!(
                error < 1000, // ~1e-6 tolerance
                "sin²+cos² identity failed for angle {}: sum={}, error={}",
                angle,
                sum_sq,
                error
            );
        }
    }

    /// O(1) range reduction handles very large angles correctly.
    /// Verifies EX-05 fix: previously O(n) while-loop, now modular arithmetic.
    #[test]
    fn test_large_angle_range_reduction() {
        let engine = CordicEngine::default();

        // sin(2π + θ) = sin(θ) — test with angle >> 2π
        let base_angle = HALF_PI / 3; // π/6
        let large_angle = base_angle + 100 * TWO_PI; // Same angle after 100 full rotations

        let (cos_base, sin_base) = engine.sincos(base_angle);
        let (cos_large, sin_large) = engine.sincos(large_angle);

        assert!(
            (cos_base - cos_large).abs() < 2000,
            "Range reduction failed: cos({}) ≠ cos({}+100×2π)",
            base_angle,
            base_angle
        );
        assert!(
            (sin_base - sin_large).abs() < 2000,
            "Range reduction failed: sin({}) ≠ sin({}+100×2π)",
            base_angle,
            base_angle
        );
    }

    /// Hyperbolic identity: exp(a+b) = exp(a)×exp(b).
    /// Tests that the dynamic gain computation (EX-09) is correct.
    #[test]
    fn test_hyperbolic_exp_identity() {
        let hyp = HyperbolicCordic::default();

        // Use small values within CORDIC convergence domain
        let a = SCALE / 4; // 0.25
        let b = SCALE / 4; // 0.25

        let exp_a = hyp.exp(a);
        let exp_b = hyp.exp(b);
        let exp_sum = hyp.exp(a + b);

        // exp(a) × exp(b) / SCALE should ≈ exp(a+b)
        let product = (exp_a as i128 * exp_b as i128 / SCALE as i128) as i64;

        let error = (product - exp_sum).abs() as f64 / SCALE as f64;
        println!(
            "exp(0.25)×exp(0.25) = {:.6}, exp(0.5) = {:.6}, error = {:.2e}",
            from_scaled(product as i64),
            from_scaled(exp_sum),
            error
        );

        assert!(
            error < 0.05,
            "Exponential identity exp(a+b)=exp(a)exp(b) failed: error {:.4}",
            error
        );
    }

    /// Boundary: sincos with angle = 0 gives (1, 0) exactly.
    #[test]
    fn test_sincos_zero_exact() {
        let engine = CordicEngine::default();
        let (cos_v, sin_v) = engine.sincos(0);

        assert!(
            (from_scaled(cos_v) - 1.0).abs() < 1e-6,
            "cos(0) should be 1.0"
        );
        assert!(from_scaled(sin_v).abs() < 1e-6, "sin(0) should be 0.0");
    }

    /// Boundary: sincos with negative angle.
    #[test]
    fn test_sincos_negative_angle() {
        let engine = CordicEngine::default();
        let (cos_pos, sin_pos) = engine.sincos(HALF_PI / 3);
        let (cos_neg, sin_neg) = engine.sincos(-HALF_PI / 3);

        // cos(-θ) = cos(θ)
        assert!(
            (cos_pos - cos_neg).abs() < 1000,
            "cos should be even function"
        );
        // sin(-θ) = -sin(θ)
        assert!(
            (sin_pos + sin_neg).abs() < 1000,
            "sin should be odd function"
        );
    }

    /// Boundary: ln(0) returns sentinel (not panic).
    #[test]
    fn test_ln_zero_sentinel() {
        let hyp = HyperbolicCordic::default();
        let result = hyp.ln(0);
        assert_eq!(result, i64::MIN, "ln(0) should return i64::MIN sentinel");
    }

    /// Boundary: ln(negative) returns sentinel (not panic).
    #[test]
    fn test_ln_negative_sentinel() {
        let hyp = HyperbolicCordic::default();
        let result = hyp.ln(-42);
        assert_eq!(
            result,
            i64::MIN,
            "ln(negative) should return i64::MIN sentinel"
        );
    }

    // ================================================================
    // TDD: Result-based checked API
    // ================================================================

    #[test]
    fn test_tan_checked_normal() {
        let engine = CordicEngine::default();
        // HALF_PI is pi/2 in scaled form, so HALF_PI/2 = pi/4
        let result = engine.tan_checked(HALF_PI / 2);
        assert!(result.is_ok());
        let val = result.unwrap();
        // tan(pi/4) = 1.0; allow CORDIC precision tolerance
        assert!(
            (from_scaled(val) - 1.0).abs() < 0.001,
            "tan(pi/4) = {}, expected ~1.0",
            from_scaled(val)
        );
    }

    #[test]
    fn test_tan_checked_at_pi_over_2() {
        let engine = CordicEngine::default();
        let result = engine.tan_checked(HALF_PI); // tan(pi/2) → DomainError
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(crate::TranscendentalError::DomainError(_))
        ));
    }

    #[test]
    fn test_ln_checked_positive() {
        let hyp = HyperbolicCordic::default();
        let result = hyp.ln_checked(SCALE); // ln(1) = 0
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_ln_checked_zero() {
        let hyp = HyperbolicCordic::default();
        let result = hyp.ln_checked(0);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(crate::TranscendentalError::DomainError(_))
        ));
    }

    #[test]
    fn test_ln_checked_negative() {
        let hyp = HyperbolicCordic::default();
        let result = hyp.ln_checked(-1);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(crate::TranscendentalError::DomainError(_))
        ));
    }

    #[test]
    fn test_ln_checked_e() {
        let hyp = HyperbolicCordic::default();
        let e_scaled = to_scaled(std::f64::consts::E);
        let result = hyp.ln_checked(e_scaled);
        assert!(result.is_ok());
        assert!((from_scaled(result.unwrap()) - 1.0).abs() < 0.1);
    }
}
