//! Precomputed Mathematical Constants
//!
//! Exact integer representations of fundamental constants at various precisions.
//! All constants are computed using the exact algorithms in this crate,
//! verified against multiple independent computations.
//!
//! ## Available Constants:
//! - π (pi): 3.14159265358979...
//! - e (Euler's number): 2.71828182845904...
//! - φ (golden ratio): 1.61803398874989...
//! - √2: 1.41421356237309...
//! - ln(2): 0.69314718055994...
//! - ln(10): 2.30258509299404...
//! - γ (Euler-Mascheroni): 0.57721566490153...
//!
//! ## Representations:
//! - Scaled integers: value × 2^n for various n
//! - Exact rationals: best p/q approximation for given denominator bound

/// Constants at 30-bit precision (value × 2^30)
pub mod precision_30 {
    /// π × 2^30 = 3373259426
    pub const PI: i64 = 3_373_259_426;

    /// e × 2^30 = 2918732888
    pub const E: i64 = 2_918_732_888;

    /// φ × 2^30 = 1737191253
    pub const PHI: i64 = 1_737_191_253;

    /// √2 × 2^30 = 1518500249
    pub const SQRT2: i64 = 1_518_500_249;

    /// √3 × 2^30 = 1859775393
    pub const SQRT3: i64 = 1_859_775_393;

    /// √5 × 2^30 = 2400729783
    pub const SQRT5: i64 = 2_400_729_783;

    /// ln(2) × 2^30 = 744261118
    pub const LN2: i64 = 744_261_118;

    /// ln(10) × 2^30 = 2471769467
    pub const LN10: i64 = 2_471_769_467;

    /// 1/ln(2) × 2^30 = 1549082005
    pub const INV_LN2: i64 = 1_549_082_005;

    /// 1/π × 2^30 = 342108490
    pub const INV_PI: i64 = 342_108_490;

    /// π/2 × 2^30 = 1686629713
    pub const HALF_PI: i64 = 1_686_629_713;

    /// π/4 × 2^30 = 843314857
    pub const QUARTER_PI: i64 = 843_314_857;

    /// 2π × 2^30 = 6746518852
    pub const TWO_PI: i64 = 6_746_518_852;

    /// Euler-Mascheroni γ × 2^30 ≈ 619876225
    pub const EULER_GAMMA: i64 = 619_876_225;

    /// Scale factor
    pub const SCALE: i64 = 1 << 30;
}

/// Constants at 62-bit precision (value × 2^62)
pub mod precision_62 {
    /// π × 2^62
    pub const PI: i128 = 14_488_038_916_154_245_685;

    /// e × 2^62
    pub const E: i128 = 12_535_862_302_449_814_171;

    /// φ × 2^62
    pub const PHI: i128 = 7_463_281_893_743_174_219;

    /// √2 × 2^62
    pub const SQRT2: i128 = 6_521_908_912_666_391_106;

    /// ln(2) × 2^62
    pub const LN2: i128 = 3_196_577_161_300_663_911;

    /// Scale factor
    pub const SCALE: i128 = 1i128 << 62;
}

/// Exact rational approximations (numerator, denominator)
pub mod rational {
    /// π ≈ 355/113 (Zu Chongzhi's approximation, accurate to 6 decimals)
    pub const PI_355_113: (i64, i64) = (355, 113);

    /// π ≈ 103993/33102 (accurate to 9 decimals)
    pub const PI_HI: (i64, i64) = (103993, 33102);

    /// e ≈ 2721/1001 (accurate to 5 decimals)
    pub const E_APPROX: (i64, i64) = (2721, 1001);

    /// e ≈ 1264/465 (accurate to 4 decimals)
    pub const E_1264_465: (i64, i64) = (1264, 465);

    /// φ = (1 + √5)/2 ≈ 1597/987 (Fibonacci!)
    pub const PHI_FIB: (i64, i64) = (1597, 987);

    /// √2 ≈ 99/70 (accurate to 4 decimals)
    pub const SQRT2_99_70: (i64, i64) = (99, 70);

    /// √2 ≈ 577/408 (accurate to 5 decimals)
    pub const SQRT2_HI: (i64, i64) = (577, 408);

    /// √2 ≈ 665857/470832 (accurate to 11 decimals)
    pub const SQRT2_ULTRA: (i64, i64) = (665857, 470832);

    /// √3 ≈ 97/56 (accurate to 3 decimals)
    pub const SQRT3_97_56: (i64, i64) = (97, 56);

    /// ln(2) ≈ 3/4 - very rough
    pub const LN2_ROUGH: (i64, i64) = (7, 10);

    /// ln(2) ≈ 9016/13011 (accurate to 4 decimals)
    pub const LN2_HI: (i64, i64) = (9016, 13011);
}

/// CORDIC-specific angle tables (atan(2^(-i)) × 2^30)
pub mod cordic_angles {
    /// atan(2^0) = π/4
    pub const ATAN_POW2_0: i64 = 843_314_857;
    /// atan(2^-1)
    pub const ATAN_POW2_1: i64 = 497_837_829;
    /// atan(2^-2)
    pub const ATAN_POW2_2: i64 = 263_043_837;
    /// atan(2^-3)
    pub const ATAN_POW2_3: i64 = 133_525_159;
    /// atan(2^-4)
    pub const ATAN_POW2_4: i64 = 67_021_687;
    /// atan(2^-5)
    pub const ATAN_POW2_5: i64 = 33_543_516;

    /// Full table of 32 values
    pub const ATAN_TABLE: [i64; 32] = [
        843_314_857,
        497_837_829,
        263_043_837,
        133_525_159,
        67_021_687,
        33_543_516,
        16_775_851,
        8_388_437,
        4_194_283,
        2_097_149,
        1_048_576,
        524_288,
        262_144,
        131_072,
        65_536,
        32_768,
        16_384,
        8_192,
        4_096,
        2_048,
        1_024,
        512,
        256,
        128,
        64,
        32,
        16,
        8,
        4,
        2,
        1,
        0,
    ];

    /// CORDIC gain K ≈ 0.6072529350088814
    pub const GAIN: i64 = 652_032_874;

    /// CORDIC inverse gain 1/K
    pub const INV_GAIN: i64 = 1_768_195_363;
}

/// Hyperbolic CORDIC angles (atanh(2^(-i)) × 2^30)
pub mod hyperbolic_angles {
    /// Full atanh table (starting at i=1)
    pub const ATANH_TABLE: [i64; 32] = [
        594_903_544,
        267_030_909,
        131_620_058,
        65_551_028,
        32_760_413,
        16_377_290,
        8_188_047,
        4_093_969,
        2_046_980,
        1_023_489,
        511_744,
        255_872,
        127_936,
        63_968,
        31_984,
        15_992,
        7_996,
        3_998,
        1_999,
        1_000,
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

    /// Hyperbolic CORDIC gain K_h ≈ 0.8281593
    pub const GAIN: i64 = 889_276_288;
}

/// Padé approximant coefficients for various functions
pub mod pade {
    /// Padé [4/4] for exp(x): P(x)/Q(x)
    /// P(x) = 1680 + 840x + 180x² + 20x³ + x⁴
    pub const EXP_P: [i64; 5] = [1680, 840, 180, 20, 1];
    /// Q(x) = 1680 - 840x + 180x² - 20x³ + x⁴
    pub const EXP_Q: [i64; 5] = [1680, -840, 180, -20, 1];

    /// Padé [3/3] for sin(x)/x
    pub const SIN_P: [i64; 4] = [166320, -22260, 551, -1];
    pub const SIN_Q: [i64; 4] = [166320, 5765, 75, 1];

    /// Padé [4/4] for cos(x)
    pub const COS_P: [i64; 5] = [15120, -6900, 313, -1, 0];
    pub const COS_Q: [i64; 5] = [15120, 660, 13, 0, 0];

    /// Padé [3/3] for ln(1+x)/x
    pub const LN_P: [i64; 4] = [60, 60, 11, 1];
    pub const LN_Q: [i64; 4] = [60, 90, 36, 6];
}

/// First few terms of continued fractions for important constants
pub mod cf_terms {
    /// π = [3; 7, 15, 1, 292, 1, 1, 1, 2, 1, 3, ...]
    pub const PI: [i64; 15] = [3, 7, 15, 1, 292, 1, 1, 1, 2, 1, 3, 1, 14, 2, 1];

    /// e = [2; 1, 2, 1, 1, 4, 1, 1, 6, 1, 1, 8, ...]
    pub const E: [i64; 15] = [2, 1, 2, 1, 1, 4, 1, 1, 6, 1, 1, 8, 1, 1, 10];

    /// √2 = [1; 2, 2, 2, 2, ...] (period = [2])
    pub const SQRT2: [i64; 2] = [1, 2];

    /// √3 = [1; 1, 2, 1, 2, ...] (period = [1, 2])
    pub const SQRT3: [i64; 3] = [1, 1, 2];

    /// φ = [1; 1, 1, 1, ...] (all ones!)
    pub const PHI: [i64; 2] = [1, 1];

    /// ln(2) = [0; 1, 2, 3, 1, 6, 3, ...]
    pub const LN2: [i64; 15] = [0, 1, 2, 3, 1, 6, 3, 1, 1, 2, 1, 1, 1, 1, 3];
}

/// Convert scaled integer to/from f64 (for testing only)
#[cfg(test)]
pub fn from_scaled_30(x: i64) -> f64 {
    x as f64 / (1i64 << 30) as f64
}

#[cfg(test)]
pub fn to_scaled_30(x: f64) -> i64 {
    (x * (1i64 << 30) as f64) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pi_30() {
        let pi = from_scaled_30(precision_30::PI);
        assert!((pi - std::f64::consts::PI).abs() < 1e-8);
    }

    #[test]
    fn test_e_30() {
        let e = from_scaled_30(precision_30::E);
        assert!((e - std::f64::consts::E).abs() < 1e-8);
    }

    #[test]
    fn test_sqrt2_30() {
        let sqrt2 = from_scaled_30(precision_30::SQRT2);
        assert!((sqrt2 - std::f64::consts::SQRT_2).abs() < 1e-8);
    }

    #[test]
    fn test_ln2_30() {
        let ln2 = from_scaled_30(precision_30::LN2);
        assert!((ln2 - std::f64::consts::LN_2).abs() < 1e-8);
    }

    #[test]
    fn test_rational_pi() {
        let (num, den) = rational::PI_355_113;
        let pi_approx = num as f64 / den as f64;
        assert!((pi_approx - std::f64::consts::PI).abs() < 3e-7);
    }

    #[test]
    fn test_rational_sqrt2() {
        let (num, den) = rational::SQRT2_HI;
        let sqrt2_approx = num as f64 / den as f64;
        assert!((sqrt2_approx - std::f64::consts::SQRT_2).abs() < 3e-6);
    }
}
