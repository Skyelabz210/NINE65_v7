//! K-Elimination: exact dual-family division support.
//!
//! CLASS-F alpha lanes are distinct prime field moduli. CLASS-R beta lanes
//! may be composite, but every lane must be greater than one, distinct, and
//! pairwise coprime within and across families. The ordered modulus vectors are
//! canonical. Scalar reconstruction helpers in this module are explicit
//! boundary/reference utilities; production FHE paths must remain in DualRNS
//! main and anchor lanes.

use crate::errors::{Nine65Error, Nine65Result};
use crate::params::is_prime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KElimConfig {
    Minimal,
    Standard,
    Extended,
    Maximum,
    HardwareOpt,
}

impl KElimConfig {
    pub fn alpha_primes(&self) -> Vec<u64> {
        match self {
            Self::Minimal => vec![65537, 65521],
            Self::Standard | Self::Extended | Self::HardwareOpt => {
                vec![65537, 65521, 65519]
            }
            Self::Maximum => vec![65537, 65521, 65519, 65497],
        }
    }

    /// CLASS-R anchor moduli. Primality is unnecessary; coprimality is required.
    pub fn beta_moduli(&self) -> Vec<u64> {
        match self {
            Self::Minimal => vec![4294967291],
            Self::Standard => vec![4611686018427387847],
            Self::Extended => vec![35184372088777, 35184372088831],
            Self::Maximum => vec![4611686018427387847, 4611686018427387903],
            Self::HardwareOpt => vec![1152921515344265237, 4294967291],
        }
    }

    #[deprecated(
        since = "8.0.0",
        note = "Use beta_moduli(); CLASS-R lanes need coprimality, not primality"
    )]
    pub fn beta_primes(&self) -> Vec<u64> {
        self.beta_moduli()
    }

    pub fn capacity_bits(&self) -> u32 {
        KElimination::from_config(*self).capacity_bit_length()
    }

    pub fn for_degree(n: usize) -> Self {
        match n {
            0..=1024 => Self::Standard,
            1025..=4096 => Self::Extended,
            _ => Self::Maximum,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct KElimBuilder {
    alpha_primes: Option<Vec<u64>>,
    beta_moduli: Option<Vec<u64>>,
}

impl KElimBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn alpha_primes(mut self, primes: &[u64]) -> Self {
        self.alpha_primes = Some(primes.to_vec());
        self
    }

    pub fn beta_moduli(mut self, moduli: &[u64]) -> Self {
        self.beta_moduli = Some(moduli.to_vec());
        self
    }

    #[deprecated(
        since = "8.0.0",
        note = "Use beta_moduli(); CLASS-R lanes need coprimality, not primality"
    )]
    pub fn beta_primes(self, moduli: &[u64]) -> Self {
        self.beta_moduli(moduli)
    }

    pub fn build(self) -> Nine65Result<KElimination> {
        let alpha_primes = self
            .alpha_primes
            .ok_or_else(|| Nine65Error::InvalidParameter {
                message: "alpha_primes not set".to_string(),
            })?;
        let beta_moduli = self
            .beta_moduli
            .ok_or_else(|| Nine65Error::InvalidParameter {
                message: "beta_moduli not set".to_string(),
            })?;
        KElimination::try_new(&alpha_primes, &beta_moduli)
    }
}

#[derive(Debug, Clone)]
pub struct KElimination {
    pub alpha_primes: Vec<u64>,
    pub beta_moduli: Vec<u64>,
    pub alpha_cap: u128,
    pub beta_cap: u128,
    pub alpha_inv_beta: u128,
    config: Option<KElimConfig>,
}

impl KElimination {
    pub fn new(alpha_primes: &[u64], beta_moduli: &[u64]) -> Self {
        Self::try_new(alpha_primes, beta_moduli)
            .expect("K-Elimination safe-basis invariants must hold")
    }

    pub fn try_new(alpha_primes: &[u64], beta_moduli: &[u64]) -> Nine65Result<Self> {
        validate_alpha_family(alpha_primes)?;
        validate_beta_family(beta_moduli)?;
        validate_cross_family(alpha_primes, beta_moduli)?;

        let alpha_cap = checked_product(alpha_primes, "alpha product")?;
        let beta_cap = checked_product(beta_moduli, "beta product")?;
        let family_gcd = gcd_u128(alpha_cap, beta_cap);
        if family_gcd != 1 {
            return Err(Nine65Error::NotCoprime {
                m: diagnostic_u64(alpha_cap),
                a: diagnostic_u64(beta_cap),
                gcd: diagnostic_u64(family_gcd),
            });
        }

        let alpha_inv_beta = mod_inverse_u128(alpha_cap, beta_cap).ok_or_else(|| {
            Nine65Error::NotCoprime {
                m: diagnostic_u64(alpha_cap),
                a: diagnostic_u64(beta_cap),
                gcd: diagnostic_u64(family_gcd),
            }
        })?;

        Ok(Self {
            alpha_primes: alpha_primes.to_vec(),
            beta_moduli: beta_moduli.to_vec(),
            alpha_cap,
            beta_cap,
            alpha_inv_beta,
            config: None,
        })
    }

    pub fn alpha_primes(&self) -> Vec<u64> {
        self.alpha_primes.clone()
    }

    pub fn beta_moduli(&self) -> Vec<u64> {
        self.beta_moduli.clone()
    }

    #[deprecated(
        since = "8.0.0",
        note = "Use beta_moduli(); CLASS-R lanes need coprimality, not primality"
    )]
    pub fn beta_primes(&self) -> Vec<u64> {
        self.beta_moduli.clone()
    }

    pub fn from_config(config: KElimConfig) -> Self {
        Self::try_from_config(config).expect("built-in K-Elim safe basis must validate")
    }

    pub fn try_from_config(config: KElimConfig) -> Nine65Result<Self> {
        let mut value = Self::try_new(&config.alpha_primes(), &config.beta_moduli())?;
        value.config = Some(config);
        Ok(value)
    }

    pub fn for_degree(n: usize) -> Self {
        Self::from_config(KElimConfig::for_degree(n))
    }

    pub fn try_for_degree(n: usize) -> Nine65Result<Self> {
        Self::try_from_config(KElimConfig::for_degree(n))
    }

    pub fn for_fhe(_q: u64) -> Self {
        Self::from_config(KElimConfig::Standard)
    }

    pub fn try_for_fhe(_q: u64) -> Nine65Result<Self> {
        Self::try_from_config(KElimConfig::Standard)
    }

    pub fn config(&self) -> Option<KElimConfig> {
        self.config
    }

    /// Exact 256-bit little-endian capacity limbs for alpha_cap × beta_cap.
    pub fn capacity_limbs(&self) -> Vec<u64> {
        trim_fixed_limbs(multiply_u128(self.alpha_cap, self.beta_cap))
    }

    pub fn capacity_bit_length(&self) -> u32 {
        limbs_bit_length(&self.capacity_limbs())
    }

    pub fn capacity_bits(&self) -> u32 {
        self.capacity_bit_length()
    }

    pub fn try_capacity(&self) -> Option<u128> {
        self.alpha_cap.checked_mul(self.beta_cap)
    }

    #[deprecated(
        since = "8.1.0",
        note = "Use try_capacity(), capacity_limbs(), or capacity_bit_length()"
    )]
    pub fn capacity(&self) -> u128 {
        self.try_capacity().expect(
            "K-Elimination capacity exceeds u128; use capacity_limbs or capacity_bit_length",
        )
    }

    pub fn alpha_capacity(&self) -> u128 {
        self.alpha_cap
    }

    pub fn beta_capacity(&self) -> u128 {
        self.beta_cap
    }

    pub fn capacity_proximity(
        &self,
        value: u128,
    ) -> crate::arithmetic::boundary::CapacityReport {
        use crate::arithmetic::boundary::{capacity_proximity_bits, u128_bit_length};
        capacity_proximity_bits(u128_bit_length(value), self.capacity_bit_length())
    }

    pub fn validate_value(&self, value: u128) -> Nine65Result<()> {
        if let Some(capacity) = self.try_capacity() {
            if value >= capacity {
                return Err(Nine65Error::RangeOverflow {
                    x: value,
                    bound: capacity,
                });
            }
        }
        Ok(())
    }

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

    /// Explicit scalar boundary/reference division with complete validation.
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
        let value = self.reconstruct_boundary_checked(v_alpha, v_beta)?;
        if value % divisor as u128 != 0 {
            return Err(Nine65Error::InexactDivision { value, divisor });
        }
        Ok(value / divisor as u128)
    }

    /// Extract the bounded winding index k from dual-family residues.
    pub fn extract_k(&self, v_alpha: u128, v_beta: u128) -> u128 {
        let diff = sub_mod_kelim_ct(v_beta, v_alpha, self.beta_cap);
        mul_mod_u128_ct(diff, self.alpha_inv_beta, self.beta_cap)
    }

    #[deprecated(
        since = "0.2.0",
        note = "Use extract_k(); variable-time extraction is for public reference data only"
    )]
    pub fn extract_k_vartime(&self, v_alpha: u128, v_beta: u128) -> u128 {
        let reduced_alpha = v_alpha % self.beta_cap;
        let diff = if v_beta >= reduced_alpha {
            v_beta - reduced_alpha
        } else {
            self.beta_cap - (reduced_alpha - v_beta)
        };
        mul_mod_u128(diff, self.alpha_inv_beta, self.beta_cap)
    }

    /// Scalar boundary/reference helper. Production FHE code must use lane-wise
    /// DualRNS transduction rather than this projection.
    pub fn exact_divide(&self, v_alpha: u128, v_beta: u128, divisor: u64) -> u128 {
        assert!(divisor != 0, "divisor must be nonzero");
        let value = self
            .reconstruct_boundary_checked(v_alpha, v_beta)
            .expect("K-Elimination scalar boundary reconstruction overflow");
        value / divisor as u128
    }

    pub fn exact_divide_checked(
        &self,
        v_alpha: u128,
        v_beta: u128,
        divisor: u64,
    ) -> Option<u128> {
        if divisor == 0 {
            return None;
        }
        let value = self.reconstruct_boundary_checked(v_alpha, v_beta).ok()?;
        if value % divisor as u128 == 0 {
            Some(value / divisor as u128)
        } else {
            None
        }
    }

    /// Public scalar reference scaling helper.
    pub fn scale_and_round(&self, value: u64, t: u64, q: u64) -> u64 {
        assert!(q != 0, "q must be nonzero");
        let numerator = value as u128 * t as u128 + q as u128 / 2;
        let v_alpha = numerator % self.alpha_cap;
        let v_beta = numerator % self.beta_cap;
        let full_numerator = self
            .reconstruct_boundary_checked(v_alpha, v_beta)
            .expect("K-Elimination scalar scaling reconstruction overflow");
        ((full_numerator / q as u128) % q as u128) as u64
    }

    #[deprecated(
        since = "0.2.0",
        note = "Use exact_divide(); variable-time division is for public reference data only"
    )]
    #[allow(deprecated)]
    pub fn exact_divide_vartime(
        &self,
        v_alpha: u128,
        v_beta: u128,
        divisor: u64,
    ) -> u128 {
        assert!(divisor != 0, "divisor must be nonzero");
        let k = self.extract_k_vartime(v_alpha, v_beta);
        let value = v_alpha
            .checked_add(
                k.checked_mul(self.alpha_cap)
                    .expect("K-Elimination scalar reconstruction multiplication overflow"),
            )
            .expect("K-Elimination scalar reconstruction addition overflow");
        value / divisor as u128
    }

    #[deprecated(
        since = "0.2.0",
        note = "Use scale_and_round(); variable-time scaling is for public reference data only"
    )]
    #[allow(deprecated)]
    pub fn scale_and_round_vartime(&self, value: u64, t: u64, q: u64) -> u64 {
        assert!(q != 0, "q must be nonzero");
        let numerator = value as u128 * t as u128 + q as u128 / 2;
        let v_alpha = numerator % self.alpha_cap;
        let v_beta = numerator % self.beta_cap;
        let k = self.extract_k_vartime(v_alpha, v_beta);
        let full_numerator = v_alpha
            .checked_add(
                k.checked_mul(self.alpha_cap)
                    .expect("K-Elimination scalar scaling multiplication overflow"),
            )
            .expect("K-Elimination scalar scaling addition overflow");
        ((full_numerator / q as u128) % q as u128) as u64
    }

    fn reconstruct_boundary_checked(
        &self,
        v_alpha: u128,
        v_beta: u128,
    ) -> Nine65Result<u128> {
        self.validate_residues(v_alpha, v_beta)?;
        let k = self.extract_k(v_alpha, v_beta);
        let winding = k
            .checked_mul(self.alpha_cap)
            .ok_or(Nine65Error::Overflow {
                operation: "K-Elimination scalar boundary multiplication",
            })?;
        v_alpha.checked_add(winding).ok_or(Nine65Error::Overflow {
            operation: "K-Elimination scalar boundary addition",
        })
    }
}

fn validate_alpha_family(values: &[u64]) -> Nine65Result<()> {
    if values.is_empty() {
        return Err(Nine65Error::InvalidParameter {
            message: "CLASS-F alpha family must not be empty".to_string(),
        });
    }
    for (index, &value) in values.iter().enumerate() {
        if value <= 1 || !is_prime(value) {
            return Err(Nine65Error::InvalidParameter {
                message: format!("CLASS-F alpha modulus {value} is not prime"),
            });
        }
        for &previous in &values[..index] {
            let gcd = gcd_u128(value as u128, previous as u128);
            if gcd != 1 {
                return Err(Nine65Error::NotCoprime {
                    m: value,
                    a: previous,
                    gcd: gcd as u64,
                });
            }
        }
    }
    Ok(())
}

fn validate_beta_family(values: &[u64]) -> Nine65Result<()> {
    if values.is_empty() {
        return Err(Nine65Error::InvalidParameter {
            message: "CLASS-R beta family must not be empty".to_string(),
        });
    }
    for (index, &value) in values.iter().enumerate() {
        if value <= 1 {
            return Err(Nine65Error::InvalidParameter {
                message: format!("CLASS-R beta modulus {value} must be greater than one"),
            });
        }
        for &previous in &values[..index] {
            let gcd = gcd_u128(value as u128, previous as u128);
            if gcd != 1 {
                return Err(Nine65Error::NotCoprime {
                    m: value,
                    a: previous,
                    gcd: gcd as u64,
                });
            }
        }
    }
    Ok(())
}

fn validate_cross_family(alpha: &[u64], beta: &[u64]) -> Nine65Result<()> {
    for &alpha_modulus in alpha {
        for &beta_modulus in beta {
            let gcd = gcd_u128(alpha_modulus as u128, beta_modulus as u128);
            if gcd != 1 {
                return Err(Nine65Error::NotCoprime {
                    m: alpha_modulus,
                    a: beta_modulus,
                    gcd: gcd as u64,
                });
            }
        }
    }
    Ok(())
}

fn checked_product(values: &[u64], operation: &'static str) -> Nine65Result<u128> {
    values
        .iter()
        .try_fold(1u128, |acc, &value| acc.checked_mul(value as u128))
        .ok_or(Nine65Error::Overflow { operation })
}

fn multiply_u128(a: u128, b: u128) -> [u64; 4] {
    let a0 = a as u64 as u128;
    let a1 = (a >> 64) as u64 as u128;
    let b0 = b as u64 as u128;
    let b1 = (b >> 64) as u64 as u128;

    let p00 = a0 * b0;
    let p01 = a0 * b1;
    let p10 = a1 * b0;
    let p11 = a1 * b1;

    let limb0 = p00 as u64;
    let middle = (p00 >> 64) + (p01 as u64 as u128) + (p10 as u64 as u128);
    let limb1 = middle as u64;
    let upper = (p01 >> 64) + (p10 >> 64) + (p11 as u64 as u128) + (middle >> 64);
    let limb2 = upper as u64;
    let limb3 = ((p11 >> 64) + (upper >> 64)) as u64;
    [limb0, limb1, limb2, limb3]
}

fn trim_fixed_limbs(limbs: [u64; 4]) -> Vec<u64> {
    let mut result = limbs.to_vec();
    while result.len() > 1 && result.last() == Some(&0) {
        result.pop();
    }
    result
}

fn limbs_bit_length(limbs: &[u64]) -> u32 {
    for index in (0..limbs.len()).rev() {
        if limbs[index] != 0 {
            return index as u32 * 64 + (64 - limbs[index].leading_zeros());
        }
    }
    0
}

fn diagnostic_u64(value: u128) -> u64 {
    if value > u64::MAX as u128 {
        u64::MAX
    } else {
        value as u64
    }
}

/// Variable-time inverse over public safe-basis moduli using coefficients kept
/// modulo `modulus`; no signed narrowing occurs.
fn mod_inverse_u128(value: u128, modulus: u128) -> Option<u128> {
    if modulus <= 1 {
        return None;
    }
    let mut r = modulus;
    let mut new_r = value % modulus;
    let mut coefficient = 0u128;
    let mut new_coefficient = 1u128;

    while new_r != 0 {
        let quotient = r / new_r;
        let next_r = r - quotient * new_r;
        r = new_r;
        new_r = next_r;

        let scaled = mul_mod_u128(quotient, new_coefficient, modulus);
        let next_coefficient = sub_mod_u128_ct(coefficient, scaled, modulus);
        coefficient = new_coefficient;
        new_coefficient = next_coefficient;
    }

    if r == 1 {
        Some(coefficient)
    } else {
        None
    }
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let remainder = a % b;
        a = b;
        b = remainder;
    }
    a
}

fn sub_mod_u128_ct(a: u128, b: u128, modulus: u128) -> u128 {
    let difference = a.wrapping_sub(b);
    let mask = ((a < b) as u128).wrapping_neg();
    difference.wrapping_add(modulus & mask)
}

fn sub_mod_kelim_ct(a: u128, b: u128, modulus: u128) -> u128 {
    sub_mod_u128_ct(a, b % modulus, modulus)
}

/// Exact branchless modular addition for normalized residues `a,b < modulus`.
fn add_mod_u128_ct(a: u128, b: u128, modulus: u128) -> u128 {
    debug_assert!(modulus != 0);
    debug_assert!(a < modulus);
    debug_assert!(b < modulus);

    let threshold = modulus - b;
    let reduced = a.wrapping_sub(threshold);
    let sum = a.wrapping_add(b);
    let reduce_mask = ((a >= threshold) as u128).wrapping_neg();
    (reduced & reduce_mask) | (sum & !reduce_mask)
}

fn mul_mod_u128_ct(a: u128, b: u128, modulus: u128) -> u128 {
    if modulus == 0 {
        return 0;
    }
    let mut result = 0u128;
    let mut addend = a % modulus;
    for bit in 0..128 {
        let selected = ((b >> bit) & 1).wrapping_neg();
        result = add_mod_u128_ct(result, addend & selected, modulus);
        addend = add_mod_u128_ct(addend, addend, modulus);
    }
    result
}

fn mul_mod_u128(a: u128, b: u128, modulus: u128) -> u128 {
    mul_mod_u128_ct(a, b, modulus)
}

#[cfg(feature = "benchmarks")]
pub fn bench_mul_mod_u128_ct(a: u128, b: u128, modulus: u128) -> u128 {
    mul_mod_u128_ct(a, b, modulus)
}

#[cfg(feature = "benchmarks")]
pub fn bench_sub_mod_u128_ct(a: u128, b: u128, modulus: u128) -> u128 {
    sub_mod_u128_ct(a, b, modulus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_basis_validation() {
        assert!(KElimination::try_new(&[17, 19], &[23, 29]).is_ok());
        assert!(KElimination::try_new(&[15, 17], &[23]).is_err());
        assert!(KElimination::try_new(&[17, 17], &[23]).is_err());
        assert!(KElimination::try_new(&[17, 19], &[23, 46]).is_err());
        assert!(KElimination::try_new(&[17, 19], &[17, 23]).is_err());
    }

    #[test]
    fn exact_capacity_metadata() {
        for config in [
            KElimConfig::Minimal,
            KElimConfig::Standard,
            KElimConfig::Extended,
            KElimConfig::Maximum,
            KElimConfig::HardwareOpt,
        ] {
            let value = KElimination::from_config(config);
            if let Some(capacity) = value.try_capacity() {
                assert_eq!(
                    value.alpha_cap.checked_mul(value.beta_cap),
                    Some(capacity)
                );
                assert_eq!(
                    value.capacity_limbs().len(),
                    if capacity >> 64 == 0 { 1 } else { 2 }
                );
            } else {
                assert_eq!(value.alpha_cap.checked_mul(value.beta_cap), None);
                assert!(value.capacity_bit_length() > 128);
                assert!(value.capacity_limbs().len() >= 3);
            }
        }
    }

    #[test]
    fn exact_capacity_bits_match_presets() {
        assert_eq!(KElimConfig::Minimal.capacity_bits(), 64);
        assert_eq!(KElimConfig::Standard.capacity_bits(), 110);
        assert_eq!(KElimConfig::Extended.capacity_bits(), 138);
        assert_eq!(KElimConfig::Maximum.capacity_bits(), 188);
        assert_eq!(KElimConfig::HardwareOpt.capacity_bits(), 140);
    }

    #[test]
    fn extraction_and_division_match_reference_values() {
        let value = KElimination::new(&[17, 19], &[23, 29]);
        for scalar in [0u128, 1, 1000, 10_000, 200_000] {
            let alpha = scalar % value.alpha_cap;
            let beta = scalar % value.beta_cap;
            let reconstructed = alpha + value.extract_k(alpha, beta) * value.alpha_cap;
            assert_eq!(reconstructed, scalar);
        }

        let division = KElimination::new(&[65537, 65521], &[65519, 65497]);
        let scalar = 12_345u128;
        assert_eq!(
            division.exact_divide_checked(
                scalar % division.alpha_cap,
                scalar % division.beta_cap,
                5,
            ),
            Some(2469)
        );
    }

    #[test]
    fn validated_division_rejects_range_and_inexactness() {
        let value = KElimination::new(&[17, 19], &[23, 29]);
        assert!(value
            .exact_divide_validated(value.alpha_cap, 0, 1)
            .is_err());
        let scalar = 1001u128;
        assert!(value
            .exact_divide_validated(
                scalar % value.alpha_cap,
                scalar % value.beta_cap,
                2,
            )
            .is_err());
    }

    #[test]
    fn scale_and_round_matches_integer_reference() {
        let value = KElimination::for_fhe(65537);
        for coefficient in [0u64, 1, 100, 1000, 10_000, 32_768, 65_536] {
            let expected =
                ((coefficient as u128 * 257 + 65537 / 2) / 65537) as u64;
            assert_eq!(value.scale_and_round(coefficient, 257, 65537), expected);
        }
    }

    #[test]
    fn constant_and_variable_extractors_agree() {
        let value = KElimination::new(&[17, 19], &[23, 29]);
        for scalar in [0u128, 1, 100, 1000, 10_000, 100_000, 200_000] {
            let alpha = scalar % value.alpha_cap;
            let beta = scalar % value.beta_cap;
            #[allow(deprecated)]
            let variable = value.extract_k_vartime(alpha, beta);
            assert_eq!(value.extract_k(alpha, beta), variable);
        }
    }

    #[test]
    fn modular_multiplication_matches_reference() {
        let modulus = 4611686018427387847u128;
        for (a, b) in [
            (0u128, 0u128),
            (1, 1),
            (12345, 67890),
            (modulus - 1, modulus - 1),
        ] {
            assert_eq!(mul_mod_u128_ct(a, b, modulus), (a * b) % modulus);
        }
    }

    #[test]
    fn modular_addition_handles_u128_wrap_boundary() {
        let modulus = u128::MAX - 158;
        let a = modulus - 1;
        let b = modulus - 1;
        assert_eq!(add_mod_u128_ct(a, b, modulus), modulus - 2);
    }

    #[test]
    fn inverse_handles_public_moduli_above_i128() {
        let modulus = u128::MAX - 158;
        let value = 5u128;
        let inverse = mod_inverse_u128(value, modulus).expect("inverse must exist");
        assert_eq!(mul_mod_u128(value, inverse, modulus), 1);
    }
}