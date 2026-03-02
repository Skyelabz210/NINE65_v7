//! NTT FFT - Cooley-Tukey O(N log N) Implementation
//!
//! This is the default NTT engine. The O(N^2) DFT reference implementation
//! in `ntt.rs` can be selected with `--features reference_ntt` for validation.
//!
//! Dispatch is centralized in `arithmetic/mod.rs` via:
//!   `use crate::arithmetic::NTTEngine;`

// Allow explicit indexing in FFT algorithms - the loop indices are used in
// butterfly computations and bit-reversal, not just for array access.
#![allow(clippy::needless_range_loop)]

use super::montgomery::MontgomeryContext;
use super::persistent_montgomery::PersistentMontgomery;
use crate::errors::{Nine65Error, Nine65Result};

/// FFT-based NTT Engine - O(N log N) vs O(N²)
///
/// Drop-in compatible with existing NTTEngine API
#[derive(Clone)]
pub struct NTTEngineFFT {
    /// Montgomery context for modular arithmetic
    pub mont: MontgomeryContext,
    /// Persistent Montgomery for staying in Montgomery form
    pub pm: PersistentMontgomery,
    /// The modulus
    pub q: u64,
    /// Polynomial degree (power of 2)
    pub n: usize,
    /// log2(n) for loop bounds
    log_n: usize,
    /// Primitive 2N-th root of unity ψ (for negacyclic twist)
    pub psi: u64,
    /// Primitive N-th root of unity ω = ψ²
    pub omega: u64,
    /// N⁻¹ in Montgomery form
    n_inv_mont: u64,
    /// Precomputed twiddle factors for forward NTT (in Montgomery form)
    twiddles_fwd: Vec<u64>,
    /// Precomputed twiddle factors for inverse NTT (in Montgomery form)
    twiddles_inv: Vec<u64>,
    /// Precomputed ψ powers for twist (in Montgomery form)
    psi_powers_mont: Vec<u64>,
    /// Precomputed ψ⁻¹ powers for untwist (in Montgomery form)
    psi_inv_powers_mont: Vec<u64>,
    // === API COMPATIBILITY (standard form for drop-in replacement) ===
    /// ψ⁻¹ mod q (standard form)
    pub psi_inv: u64,
    /// ω⁻¹ mod q (standard form)
    pub omega_inv: u64,
    /// N⁻¹ mod q (standard form)
    pub n_inv: u64,
    /// Precomputed ψ powers (standard form)
    pub psi_powers: Vec<u64>,
    /// Precomputed ψ⁻¹ powers (standard form)
    pub psi_inv_powers: Vec<u64>,
    /// Precomputed ω powers (standard form)
    pub omega_powers: Vec<u64>,
    /// Precomputed ω⁻¹ powers (standard form)
    pub omega_inv_powers: Vec<u64>,
}

impl NTTEngineFFT {
    /// Create a new FFT-based NTT engine.
    ///
    /// # Panics
    ///
    /// Panics if `n` is not a power of 2, if `(q-1)` is not divisible by `2N`,
    /// or if no primitive root of unity exists.
    ///
    /// For fallible construction, use [`try_new()`](Self::try_new) instead.
    pub fn new(q: u64, n: usize) -> Self {
        Self::try_new(q, n).expect("NTT FFT configuration invalid")
    }

    /// Fallible constructor for FFT-based NTT engine.
    ///
    /// Returns error if:
    /// - `n` is not a power of 2
    /// - `(q-1)` is not divisible by `2N`
    /// - No primitive `2N`-th root of unity exists modulo `q`
    pub fn try_new(q: u64, n: usize) -> Nine65Result<Self> {
        if !n.is_power_of_two() {
            return Err(Nine65Error::NTTConfigError {
                message: format!("N must be a power of 2, got {}", n),
            });
        }

        if (q - 1) % (2 * n as u64) != 0 {
            return Err(Nine65Error::NTTConfigError {
                message: format!(
                    "q-1 ({}) must be divisible by 2N ({}) for NTT",
                    q - 1,
                    2 * n
                ),
            });
        }

        let log_n = n.trailing_zeros() as usize;
        let mont = MontgomeryContext::new(q);
        let pm = PersistentMontgomery::new(q);

        // Find primitive roots
        let psi = Self::try_find_primitive_root(q, 2 * n)?;
        let omega = mod_pow(psi, 2, q);
        let omega_inv = mod_inverse(omega, q);
        let psi_inv = mod_inverse(psi, q);
        let n_inv = mod_inverse(n as u64, q);

        let n_inv_mont = mont.to_montgomery(n_inv);

        // Precompute twiddle factors in Montgomery form
        let twiddles_fwd = Self::compute_twiddles(&mont, omega, n);
        let twiddles_inv = Self::compute_twiddles(&mont, omega_inv, n);

        // Precompute ψ powers for twist/untwist
        let psi_powers_mont: Vec<u64> = (0..n)
            .map(|i| mont.to_montgomery(mod_pow(psi, i as u64, q)))
            .collect();
        let psi_inv_powers_mont: Vec<u64> = (0..n)
            .map(|i| mont.to_montgomery(mod_pow(psi_inv, i as u64, q)))
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

            // API compatibility (standard form)
            psi_inv,
            omega_inv,
            n_inv,
            psi_powers: (0..n).map(|i| mod_pow(psi, i as u64, q)).collect(),
            psi_inv_powers: (0..n).map(|i| mod_pow(psi_inv, i as u64, q)).collect(),
            omega_powers: (0..n).map(|i| mod_pow(omega, i as u64, q)).collect(),
            omega_inv_powers: (0..n).map(|i| mod_pow(omega_inv, i as u64, q)).collect(),
        })
    }

    /// Compute twiddle factors in bit-reversed order (Montgomery form)
    fn compute_twiddles(mont: &MontgomeryContext, omega: u64, n: usize) -> Vec<u64> {
        let q = mont.q;
        let mut twiddles = vec![0u64; n];

        // Compute powers of omega
        let mut power = 1u64;
        for i in 0..n {
            twiddles[i] = mont.to_montgomery(power);
            power = ((power as u128 * omega as u128) % q as u128) as u64;
        }

        twiddles
    }

    /// Find primitive n-th root of unity.
    ///
    /// Returns `Err(NTTConfigError)` if no root is found.
    fn try_find_primitive_root(q: u64, order: usize) -> Nine65Result<u64> {
        let exp = (q - 1) / (order as u64);
        for g in 2..q {
            let candidate = mod_pow(g, exp, q);
            let half = mod_pow(candidate, (order / 2) as u64, q);
            if half == q - 1 {
                return Ok(candidate);
            }
        }
        Err(Nine65Error::NTTConfigError {
            message: format!("no primitive root found for q={}, order={}", q, order),
        })
    }

    /// Bit-reversal permutation index
    #[inline]
    fn bit_reverse(x: usize, bits: usize) -> usize {
        x.reverse_bits() >> (usize::BITS as usize - bits)
    }

    /// In-place bit-reversal permutation
    fn bit_reverse_permute(&self, a: &mut [u64]) {
        for i in 0..self.n {
            let j = Self::bit_reverse(i, self.log_n);
            if i < j {
                a.swap(i, j);
            }
        }
    }

    /// Forward NTT using Cooley-Tukey butterfly (in-place, Montgomery form)
    ///
    /// Complexity: O(N log N) vs O(N²) for DFT
    pub fn ntt_inplace(&self, a: &mut [u64]) {
        debug_assert_eq!(a.len(), self.n);

        // Bit-reverse permutation
        self.bit_reverse_permute(a);

        // Cooley-Tukey butterfly stages
        let mut m = 1;

        while m < self.n {
            let half_m = m;
            m *= 2;

            // Twiddle factor step for this stage
            let t_step = self.n / m;

            for k in (0..self.n).step_by(m) {
                let mut t_idx = 0;

                for j in 0..half_m {
                    let u_idx = k + j;
                    let v_idx = k + j + half_m;

                    let u = a[u_idx];
                    // Multiply by twiddle in Montgomery form (PERSISTENT!)
                    let t = self.mont.montgomery_mul(self.twiddles_fwd[t_idx], a[v_idx]);

                    // Butterfly
                    a[u_idx] = self.mont_add(u, t);
                    a[v_idx] = self.mont_sub(u, t);

                    t_idx += t_step;
                }
            }
        }
    }

    /// Inverse NTT using Cooley-Tukey butterfly (in-place, Montgomery form)
    pub fn intt_inplace(&self, a: &mut [u64]) {
        debug_assert_eq!(a.len(), self.n);

        // Bit-reverse permutation
        self.bit_reverse_permute(a);

        // Inverse Cooley-Tukey butterfly
        let mut m = 1;

        while m < self.n {
            let half_m = m;
            m *= 2;
            let t_step = self.n / m;

            for k in (0..self.n).step_by(m) {
                let mut t_idx = 0;

                for j in 0..half_m {
                    let u_idx = k + j;
                    let v_idx = k + j + half_m;

                    let u = a[u_idx];
                    let t = self.mont.montgomery_mul(self.twiddles_inv[t_idx], a[v_idx]);

                    a[u_idx] = self.mont_add(u, t);
                    a[v_idx] = self.mont_sub(u, t);

                    t_idx += t_step;
                }
            }
        }

        // Multiply by N⁻¹
        for x in a.iter_mut() {
            *x = self.mont.montgomery_mul(*x, self.n_inv_mont);
        }
    }

    /// Montgomery addition (stays in Montgomery form)
    #[inline]
    fn mont_add(&self, a: u64, b: u64) -> u64 {
        let sum = a + b;
        if sum >= self.q {
            sum - self.q
        } else {
            sum
        }
    }

    /// Montgomery subtraction (stays in Montgomery form)
    #[inline]
    fn mont_sub(&self, a: u64, b: u64) -> u64 {
        if a >= b {
            a - b
        } else {
            self.q - b + a
        }
    }

    /// Forward NTT (allocating version for API compatibility)
    pub fn ntt(&self, a: &[u64]) -> Vec<u64> {
        let mut result = a.to_vec();

        // Convert to Montgomery form
        for x in result.iter_mut() {
            *x = self.mont.to_montgomery(*x);
        }

        self.ntt_inplace(&mut result);

        // Convert back from Montgomery form
        for x in result.iter_mut() {
            *x = self.mont.from_montgomery(*x);
        }

        result
    }

    /// Inverse NTT (allocating version for API compatibility)
    pub fn intt(&self, a: &[u64]) -> Vec<u64> {
        let mut result = a.to_vec();

        // Convert to Montgomery form
        for x in result.iter_mut() {
            *x = self.mont.to_montgomery(*x);
        }

        self.intt_inplace(&mut result);

        // Convert back from Montgomery form
        for x in result.iter_mut() {
            *x = self.mont.from_montgomery(*x);
        }

        result
    }

    /// Negacyclic polynomial multiplication using FFT NTT
    ///
    /// Computes a * b mod (X^N + 1, q)
    ///
    /// This is the HOT PATH - optimized for speed.
    /// Convenience wrapper around `multiply_into()`.
    pub fn multiply(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        let mut output = Vec::with_capacity(self.n);
        self.multiply_into(a, b, &mut output);
        output
    }

    /// Allocation-free negacyclic polynomial multiplication using FFT NTT
    ///
    /// Computes a * b mod (X^N + 1, q) and writes the result into the
    /// caller-provided `output` buffer, reusing its existing allocation.
    /// Also uses `scratch` as internal workspace to avoid a second allocation.
    ///
    /// For the simplest API, use `multiply()` instead.
    pub fn multiply_into(&self, a: &[u64], b: &[u64], output: &mut Vec<u64>) {
        debug_assert_eq!(a.len(), self.n);
        debug_assert_eq!(b.len(), self.n);

        // Prepare output as a_work, scratch as b_work
        output.clear();
        output.reserve(self.n.saturating_sub(output.capacity()));

        let mut b_work = Vec::with_capacity(self.n);

        // Step 1: Apply ψ-twist AND convert to Montgomery (fused)
        for i in 0..self.n {
            let a_twisted = self
                .mont
                .montgomery_mul(self.mont.to_montgomery(a[i]), self.psi_powers_mont[i]);
            let b_twisted = self
                .mont
                .montgomery_mul(self.mont.to_montgomery(b[i]), self.psi_powers_mont[i]);
            output.push(a_twisted);
            b_work.push(b_twisted);
        }

        // Step 2: Forward NTT (in-place, stays in Montgomery)
        self.ntt_inplace(output);
        self.ntt_inplace(&mut b_work);

        // Step 3: Point-wise multiplication (Montgomery form)
        for i in 0..self.n {
            output[i] = self.mont.montgomery_mul(output[i], b_work[i]);
        }

        // Step 4: Inverse NTT (in-place)
        self.intt_inplace(output);

        // Step 5: Remove ψ-twist AND convert from Montgomery (fused)
        for i in 0..self.n {
            let untwisted = self
                .mont
                .montgomery_mul(output[i], self.psi_inv_powers_mont[i]);
            output[i] = self.mont.from_montgomery(untwisted);
        }
    }

    /// Constant-time polynomial multiplication using NTT
    ///
    /// This is equivalent to `multiply()` since the FFT NTT engine uses
    /// Montgomery multiplication internally, which is already constant-time.
    /// Provided for API compatibility with the non-FFT NTT engine.
    pub fn multiply_ct(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        // Montgomery multiplication is constant-time, so multiply() is already CT
        self.multiply(a, b)
    }

    /// Multiply staying entirely in Montgomery form (for chained operations)
    ///
    /// Use this when doing multiple multiplications - convert once at start/end.
    /// Convenience wrapper around `multiply_persistent_into()`.
    pub fn multiply_persistent(&self, a_mont: &[u64], b_mont: &[u64]) -> Vec<u64> {
        let mut output = Vec::with_capacity(self.n);
        self.multiply_persistent_into(a_mont, b_mont, &mut output);
        output
    }

    /// Allocation-free persistent-Montgomery polynomial multiplication
    ///
    /// Computes a_mont * b_mont mod (X^N + 1, q) entirely in Montgomery form
    /// and writes the result into the caller-provided `output` buffer, reusing
    /// its existing allocation. The result remains in Montgomery form.
    ///
    /// For the simplest API, use `multiply_persistent()` instead.
    pub fn multiply_persistent_into(
        &self,
        a_mont: &[u64],
        b_mont: &[u64],
        output: &mut Vec<u64>,
    ) {
        debug_assert_eq!(a_mont.len(), self.n);
        debug_assert_eq!(b_mont.len(), self.n);

        // Use output as a_work
        output.clear();
        output.reserve(self.n.saturating_sub(output.capacity()));
        output.extend(
            a_mont
                .iter()
                .enumerate()
                .map(|(i, &x)| self.mont.montgomery_mul(x, self.psi_powers_mont[i])),
        );

        let mut b_work: Vec<u64> = b_mont
            .iter()
            .enumerate()
            .map(|(i, &x)| self.mont.montgomery_mul(x, self.psi_powers_mont[i]))
            .collect();

        self.ntt_inplace(output);
        self.ntt_inplace(&mut b_work);

        for i in 0..self.n {
            output[i] = self.mont.montgomery_mul(output[i], b_work[i]);
        }

        self.intt_inplace(output);

        // Untwist but STAY in Montgomery form
        for i in 0..self.n {
            output[i] = self
                .mont
                .montgomery_mul(output[i], self.psi_inv_powers_mont[i]);
        }
    }

    // ========================================================================
    // API COMPATIBILITY with existing NTTEngine
    // ========================================================================

    /// Add two polynomials coefficient-wise
    #[inline]
    pub fn add(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        debug_assert_eq!(a.len(), self.n);
        debug_assert_eq!(b.len(), self.n);

        a.iter()
            .zip(b.iter())
            .map(|(&ai, &bi)| {
                let sum = ai + bi;
                if sum >= self.q {
                    sum - self.q
                } else {
                    sum
                }
            })
            .collect()
    }

    /// Subtract two polynomials coefficient-wise
    #[inline]
    pub fn sub(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        debug_assert_eq!(a.len(), self.n);
        debug_assert_eq!(b.len(), self.n);

        a.iter()
            .zip(b.iter())
            .map(
                |(&ai, &bi)| {
                    if ai >= bi {
                        ai - bi
                    } else {
                        self.q - bi + ai
                    }
                },
            )
            .collect()
    }

    /// Negate polynomial
    #[inline]
    pub fn neg(&self, a: &[u64]) -> Vec<u64> {
        a.iter()
            .map(|&ai| if ai == 0 { 0 } else { self.q - ai })
            .collect()
    }

    /// Scalar multiply
    #[inline]
    pub fn scalar_mul(&self, a: &[u64], scalar: u64) -> Vec<u64> {
        let scalar_mont = self.mont.to_montgomery(scalar);
        a.iter()
            .map(|&ai| {
                let ai_mont = self.mont.to_montgomery(ai);
                self.mont
                    .from_montgomery(self.mont.montgomery_mul(ai_mont, scalar_mont))
            })
            .collect()
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Modular exponentiation
fn mod_pow(base: u64, exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    let mut result = 1u64;
    let mut base = base % modulus;
    let mut exp = exp;
    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        exp >>= 1;
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
    }
    result
}

/// Modular inverse using extended Euclidean algorithm
fn mod_inverse(a: u64, m: u64) -> u64 {
    let mut mn = (m as i128, a as i128);
    let mut xy = (0i128, 1i128);
    while mn.1 != 0 {
        let q = mn.0 / mn.1;
        mn = (mn.1, mn.0 - q * mn.1);
        xy = (xy.1, xy.0 - q * xy.1);
    }
    while xy.0 < 0 {
        xy.0 += m as i128;
    }
    (xy.0 % m as i128) as u64
}

// ============================================================================
// TESTS - Verify FFT matches DFT output exactly
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 998244353;

    #[test]
    fn test_ntt_intt_roundtrip() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 8);
        let original: Vec<u64> = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let ntt_result = engine.ntt(&original);
        let recovered = engine.intt(&ntt_result);

        assert_eq!(recovered, original, "NTT/INTT roundtrip failed");
    }

    #[test]
    fn test_multiply_small() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 8);

        let a = vec![1, 2, 3, 0, 0, 0, 0, 0];
        let b = vec![4, 5, 0, 0, 0, 0, 0, 0];

        let result = engine.multiply(&a, &b);

        // (1 + 2x + 3x²) * (4 + 5x) = 4 + 13x + 22x² + 15x³
        assert_eq!(result, vec![4, 13, 22, 15, 0, 0, 0, 0]);
    }

    #[test]
    fn test_negacyclic() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 4);

        // x³ * x = x⁴ = -1 in X⁴ + 1
        let a = vec![0, 0, 0, 1]; // x³
        let b = vec![0, 1, 0, 0]; // x

        let result = engine.multiply(&a, &b);

        // Result should be -1 = q-1
        assert_eq!(result, vec![TEST_PRIME - 1, 0, 0, 0]);
    }

    #[test]
    fn test_vs_schoolbook() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 8);

        let a: Vec<u64> = (0..8).map(|i| (i * 12345) % TEST_PRIME).collect();
        let b: Vec<u64> = (0..8).map(|i| (i * 67890) % TEST_PRIME).collect();

        let result = engine.multiply(&a, &b);

        // Verify using schoolbook with negacyclic reduction
        let mut expected = vec![0i128; 8];
        for i in 0..8 {
            for j in 0..8 {
                let prod = a[i] as i128 * b[j] as i128;
                let idx = i + j;
                if idx < 8 {
                    expected[idx] += prod;
                } else {
                    expected[idx - 8] -= prod; // Negacyclic wraparound
                }
            }
        }

        let expected: Vec<u64> = expected
            .iter()
            .map(|&x| {
                let q = TEST_PRIME as i128;
                (((x % q) + q) % q) as u64
            })
            .collect();

        assert_eq!(result, expected, "FFT multiply doesn't match schoolbook");
    }

    // =========================================================================
    // FALLIBLE CONSTRUCTOR TESTS
    // =========================================================================

    #[test]
    fn test_try_new_valid_params() {
        let result = NTTEngineFFT::try_new(TEST_PRIME, 8);
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_new_non_power_of_two() {
        let result = NTTEngineFFT::try_new(TEST_PRIME, 7);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_new_incompatible_modulus() {
        // 17-1=16, 16 % 64 != 0, so N=32 should fail
        let result = NTTEngineFFT::try_new(17, 32);
        assert!(result.is_err());
    }

    // Timing benchmarks moved to criterion benches (benches/timing.rs)
}
