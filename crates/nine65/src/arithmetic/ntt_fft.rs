//! NTT FFT - Cooley-Tukey O(N log N) implementation.
//!
//! This is the default NTT engine. The O(N^2) DFT reference implementation
//! in `ntt.rs` can be selected with `--features reference_ntt` for validation.
//! All butterfly addresses and twiddle indices depend only on public parameters.

#![allow(clippy::needless_range_loop)]

use super::montgomery::MontgomeryContext;
use super::persistent_montgomery::PersistentMontgomery;
use crate::errors::{Nine65Error, Nine65Result};
use crate::params::is_prime;

/// FFT-based NTT engine.
#[derive(Clone)]
pub struct NTTEngineFFT {
    pub mont: MontgomeryContext,
    pub pm: PersistentMontgomery,
    pub q: u64,
    pub n: usize,
    log_n: usize,
    pub psi: u64,
    pub omega: u64,
    n_inv_mont: u64,
    twiddles_fwd: Vec<u64>,
    twiddles_inv: Vec<u64>,
    psi_powers_mont: Vec<u64>,
    psi_inv_powers_mont: Vec<u64>,
    pub psi_inv: u64,
    pub omega_inv: u64,
    pub n_inv: u64,
    pub psi_powers: Vec<u64>,
    pub psi_inv_powers: Vec<u64>,
    pub omega_powers: Vec<u64>,
    pub omega_inv_powers: Vec<u64>,
}

impl NTTEngineFFT {
    /// Construct an NTT engine or panic on invalid public parameters.
    pub fn new(q: u64, n: usize) -> Self {
        Self::try_new(q, n).expect("NTT FFT configuration invalid")
    }

    /// Construct an NTT engine after enforcing the CLASS-F field conditions.
    pub fn try_new(q: u64, n: usize) -> Nine65Result<Self> {
        if !n.is_power_of_two() {
            return Err(Nine65Error::NTTConfigError {
                message: format!("N must be a nonzero power of 2, got {n}"),
            });
        }
        if !is_prime(q) {
            return Err(Nine65Error::NTTConfigError {
                message: format!("CLASS-F NTT modulus must be prime, got {q}"),
            });
        }

        let two_n = n
            .checked_mul(2)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| Nine65Error::NTTConfigError {
                message: format!("2N does not fit in u64 for N={n}"),
            })?;
        if (q - 1) % two_n != 0 {
            return Err(Nine65Error::NTTConfigError {
                message: format!("q-1 ({}) must be divisible by 2N ({two_n})", q - 1),
            });
        }

        let log_n = n.trailing_zeros() as usize;
        let mont = MontgomeryContext::new(q);
        let pm = PersistentMontgomery::new(q);
        let psi = Self::try_find_primitive_root(q, two_n as usize)?;
        let omega = mod_pow(psi, 2, q);
        let omega_inv = mod_inverse(omega, q);
        let psi_inv = mod_inverse(psi, q);
        let n_inv = mod_inverse(n as u64, q);
        let n_inv_mont = mont.to_montgomery(n_inv);
        let twiddles_fwd = Self::compute_twiddles(&mont, omega, n);
        let twiddles_inv = Self::compute_twiddles(&mont, omega_inv, n);
        let psi_powers_mont = (0..n)
            .map(|index| mont.to_montgomery(mod_pow(psi, index as u64, q)))
            .collect();
        let psi_inv_powers_mont = (0..n)
            .map(|index| mont.to_montgomery(mod_pow(psi_inv, index as u64, q)))
            .collect();

        Ok(Self {
            mont,
            pm,
            q,
            n,
            log_n,
            psi,
            omega,
            n_inv_mont,
            twiddles_fwd,
            twiddles_inv,
            psi_powers_mont,
            psi_inv_powers_mont,
            psi_inv,
            omega_inv,
            n_inv,
            psi_powers: (0..n).map(|index| mod_pow(psi, index as u64, q)).collect(),
            psi_inv_powers: (0..n)
                .map(|index| mod_pow(psi_inv, index as u64, q))
                .collect(),
            omega_powers: (0..n)
                .map(|index| mod_pow(omega, index as u64, q))
                .collect(),
            omega_inv_powers: (0..n)
                .map(|index| mod_pow(omega_inv, index as u64, q))
                .collect(),
        })
    }

    fn compute_twiddles(mont: &MontgomeryContext, omega: u64, n: usize) -> Vec<u64> {
        let mut twiddles = vec![0_u64; n];
        let mut power = 1_u64;
        for twiddle in &mut twiddles {
            *twiddle = mont.to_montgomery(power);
            power = ((power as u128 * omega as u128) % mont.q as u128) as u64;
        }
        twiddles
    }

    /// Variable-time setup operation over public parameters only.
    fn try_find_primitive_root(q: u64, order: usize) -> Nine65Result<u64> {
        let exponent = (q - 1) / order as u64;
        for generator in 2..q {
            let candidate = mod_pow(generator, exponent, q);
            let half = mod_pow(candidate, (order / 2) as u64, q);
            if half == q - 1 && mod_pow(candidate, order as u64, q) == 1 {
                return Ok(candidate);
            }
        }
        Err(Nine65Error::NTTConfigError {
            message: format!("no primitive root found for q={q}, order={order}"),
        })
    }

    #[inline]
    fn bit_reverse(value: usize, bits: usize) -> usize {
        value.reverse_bits() >> (usize::BITS as usize - bits)
    }

    fn bit_reverse_permute(&self, values: &mut [u64]) {
        for index in 0..self.n {
            let reversed = Self::bit_reverse(index, self.log_n);
            if index < reversed {
                values.swap(index, reversed);
            }
        }
    }

    /// Forward NTT using Cooley-Tukey butterfly (in-place, Montgomery form)
    ///
    /// Control flow, addresses, and twiddle indices are public.
    ///
    /// Complexity: O(N log N) vs O(N²) for DFT
    ///
    /// (This used to take an extra `shadow: &mut Option<Vec<u64>>` parameter
    /// so a caller could capture each twiddle multiply's discarded Montgomery
    /// quotient. Its only feeder was SBNI's entropy harvest; SBNI's removal
    /// left every remaining call passing `&mut None`, so the capture branch
    /// was permanently unreachable. Removed per issue #68 — see
    /// docs/LADDER_REMOVAL.md §6.3 item 4.)
    pub fn ntt_inplace(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.n);
        self.bit_reverse_permute(values);

        let mut width = 1_usize;
        while width < self.n {
            let half = width;
            width *= 2;
            let twiddle_step = self.n / width;

            for block in (0..self.n).step_by(width) {
                let mut twiddle_index = 0_usize;
                for offset in 0..half {
                    let upper_index = block + offset;
                    let lower_index = upper_index + half;
                    let upper = values[upper_index];
                    let product =
                        self.twiddles_fwd[twiddle_index] as u128 * values[lower_index] as u128;
                    let lower = self.mont.montgomery_reduce(product);

                    values[upper_index] = self.mont.montgomery_add(upper, lower);
                    values[lower_index] = self.mont.montgomery_sub(upper, lower);
                    twiddle_index += twiddle_step;
                }
            }
        }
    }

    /// Inverse NTT. Control flow, addresses, and twiddle indices are public.
    pub fn intt_inplace(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.n);
        self.bit_reverse_permute(values);

        let mut width = 1_usize;
        while width < self.n {
            let half = width;
            width *= 2;
            let twiddle_step = self.n / width;

            for block in (0..self.n).step_by(width) {
                let mut twiddle_index = 0_usize;
                for offset in 0..half {
                    let upper_index = block + offset;
                    let lower_index = upper_index + half;
                    let upper = values[upper_index];
                    let lower = self
                        .mont
                        .montgomery_mul(self.twiddles_inv[twiddle_index], values[lower_index]);
                    values[upper_index] = self.mont.montgomery_add(upper, lower);
                    values[lower_index] = self.mont.montgomery_sub(upper, lower);
                    twiddle_index += twiddle_step;
                }
            }
        }

        for value in values {
            *value = self.mont.montgomery_mul(*value, self.n_inv_mont);
        }
    }

    pub fn ntt(&self, values: &[u64]) -> Vec<u64> {
        let mut result = values.to_vec();
        for value in &mut result {
            *value = self.mont.to_montgomery(*value);
        }
        self.ntt_inplace(&mut result);
        for value in &mut result {
            *value = self.mont.from_montgomery(*value);
        }
        result
    }

    pub fn intt(&self, values: &[u64]) -> Vec<u64> {
        let mut result = values.to_vec();
        for value in &mut result {
            *value = self.mont.to_montgomery(*value);
        }
        self.intt_inplace(&mut result);
        for value in &mut result {
            *value = self.mont.from_montgomery(*value);
        }
        result
    }

    pub fn multiply(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        let mut output = Vec::with_capacity(self.n);
        self.multiply_into(left, right, &mut output);
        output
    }

    pub fn multiply_into(&self, left: &[u64], right: &[u64], output: &mut Vec<u64>) {
        debug_assert_eq!(left.len(), self.n);
        debug_assert_eq!(right.len(), self.n);

        output.clear();
        output.reserve(self.n.saturating_sub(output.capacity()));
        let mut right_work = Vec::with_capacity(self.n);

        for index in 0..self.n {
            let left_twisted = self.mont.montgomery_mul(
                self.mont.to_montgomery(left[index]),
                self.psi_powers_mont[index],
            );
            let right_twisted = self.mont.montgomery_mul(
                self.mont.to_montgomery(right[index]),
                self.psi_powers_mont[index],
            );
            output.push(left_twisted);
            right_work.push(right_twisted);
        }

        self.ntt_inplace(output);
        self.ntt_inplace(&mut right_work);
        for index in 0..self.n {
            output[index] = self.mont.montgomery_mul(output[index], right_work[index]);
        }
        self.intt_inplace(output);
        for index in 0..self.n {
            let untwisted = self
                .mont
                .montgomery_mul(output[index], self.psi_inv_powers_mont[index]);
            output[index] = self.mont.from_montgomery(untwisted);
        }
    }

    pub fn multiply_ct(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        self.multiply(left, right)
    }

    pub fn multiply_persistent(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        let mut output = Vec::with_capacity(self.n);
        self.multiply_persistent_into(left, right, &mut output);
        output
    }

    pub fn multiply_persistent_into(&self, left: &[u64], right: &[u64], output: &mut Vec<u64>) {
        debug_assert_eq!(left.len(), self.n);
        debug_assert_eq!(right.len(), self.n);

        output.clear();
        output.reserve(self.n.saturating_sub(output.capacity()));
        output.extend(left.iter().enumerate().map(|(index, value)| {
            self.mont
                .montgomery_mul(*value, self.psi_powers_mont[index])
        }));
        let mut right_work: Vec<u64> = right
            .iter()
            .enumerate()
            .map(|(index, value)| {
                self.mont
                    .montgomery_mul(*value, self.psi_powers_mont[index])
            })
            .collect();

        self.ntt_inplace(output);
        self.ntt_inplace(&mut right_work);
        for index in 0..self.n {
            output[index] = self.mont.montgomery_mul(output[index], right_work[index]);
        }
        self.intt_inplace(output);
        for index in 0..self.n {
            output[index] = self
                .mont
                .montgomery_mul(output[index], self.psi_inv_powers_mont[index]);
        }
    }

    #[inline]
    pub fn add(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        debug_assert_eq!(left.len(), self.n);
        debug_assert_eq!(right.len(), self.n);
        left.iter()
            .zip(right)
            .map(|(a, b)| self.mont.montgomery_add(*a, *b))
            .collect()
    }

    #[inline]
    pub fn sub(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        debug_assert_eq!(left.len(), self.n);
        debug_assert_eq!(right.len(), self.n);
        left.iter()
            .zip(right)
            .map(|(a, b)| self.mont.montgomery_sub(*a, *b))
            .collect()
    }

    #[inline]
    pub fn neg(&self, values: &[u64]) -> Vec<u64> {
        values
            .iter()
            .map(|value| self.mont.montgomery_neg(*value))
            .collect()
    }

    #[inline]
    pub fn scalar_mul(&self, values: &[u64], scalar: u64) -> Vec<u64> {
        let scalar_mont = self.mont.to_montgomery(scalar);
        values
            .iter()
            .map(|value| {
                let value_mont = self.mont.to_montgomery(*value);
                self.mont
                    .from_montgomery(self.mont.montgomery_mul(value_mont, scalar_mont))
            })
            .collect()
    }
}

/// Variable-time setup helper over public values.
fn mod_pow(base: u64, exponent: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    let mut result = 1_u64;
    let mut base = base % modulus;
    let mut exponent = exponent;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        exponent >>= 1;
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
    }
    result
}

/// Variable-time setup helper over public values.
fn mod_inverse(value: u64, modulus: u64) -> u64 {
    let mut remainder = (modulus as i128, value as i128);
    let mut coefficient = (0_i128, 1_i128);
    while remainder.1 != 0 {
        let quotient = remainder.0 / remainder.1;
        remainder = (remainder.1, remainder.0 - quotient * remainder.1);
        coefficient = (coefficient.1, coefficient.0 - quotient * coefficient.1);
    }
    while coefficient.0 < 0 {
        coefficient.0 += modulus as i128;
    }
    (coefficient.0 % modulus as i128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 998_244_353;

    #[test]
    fn ntt_intt_roundtrip() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 8);
        let original = vec![1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(engine.intt(&engine.ntt(&original)), original);
    }

    #[test]
    fn multiply_small() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 8);
        let left = vec![1, 2, 3, 0, 0, 0, 0, 0];
        let right = vec![4, 5, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            engine.multiply(&left, &right),
            vec![4, 13, 22, 15, 0, 0, 0, 0]
        );
    }

    #[test]
    fn negacyclic_wrap() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 4);
        let left = vec![0, 0, 0, 1];
        let right = vec![0, 1, 0, 0];
        assert_eq!(
            engine.multiply(&left, &right),
            vec![TEST_PRIME - 1, 0, 0, 0]
        );
    }

    #[test]
    fn multiply_matches_schoolbook() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 8);
        let left: Vec<u64> = (0..8).map(|index| index * 12_345 % TEST_PRIME).collect();
        let right: Vec<u64> = (0..8).map(|index| index * 67_890 % TEST_PRIME).collect();
        let actual = engine.multiply(&left, &right);

        let mut expected = vec![0_i128; 8];
        for left_index in 0..8 {
            for right_index in 0..8 {
                let product = left[left_index] as i128 * right[right_index] as i128;
                let index = left_index + right_index;
                if index < 8 {
                    expected[index] += product;
                } else {
                    expected[index - 8] -= product;
                }
            }
        }
        let expected: Vec<u64> = expected
            .into_iter()
            .map(|value| {
                let modulus = TEST_PRIME as i128;
                (((value % modulus) + modulus) % modulus) as u64
            })
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn class_f_constructor_rejects_composite_modulus() {
        assert!(NTTEngineFFT::try_new(65, 2).is_err());
    }

    #[test]
    fn constructor_rejects_non_power_of_two_degree() {
        assert!(NTTEngineFFT::try_new(TEST_PRIME, 7).is_err());
    }

    #[test]
    fn constructor_rejects_incompatible_prime() {
        assert!(NTTEngineFFT::try_new(17, 32).is_err());
    }

    #[test]
    fn branchless_coefficient_ops_match_integer_reference() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 8);
        let samples = [0, 1, 2, TEST_PRIME / 2, TEST_PRIME - 2, TEST_PRIME - 1];
        for &left in &samples {
            for &right in &samples {
                assert_eq!(
                    engine.add(&[left; 8], &[right; 8])[0],
                    (left + right) % TEST_PRIME
                );
                assert_eq!(
                    engine.sub(&[left; 8], &[right; 8])[0],
                    (left + TEST_PRIME - right) % TEST_PRIME
                );
            }
            let expected_negation = if left == 0 { 0 } else { TEST_PRIME - left };
            assert_eq!(engine.neg(&[left; 8])[0], expected_negation);
        }
    }
}
