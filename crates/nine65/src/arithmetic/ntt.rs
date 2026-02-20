//! NTT Engine - Gen 3 Number Theoretic Transform
//!
//! Negacyclic convolution via ψ-twist for X^N+1 rings.
//! Uses correct DFT matrix approach for guaranteed correctness.
//!
//! # Thread Safety
//!
//! `NTTEngine` is **immutable after construction** and implements `Send + Sync`.
//! Multiple threads can safely share an `NTTEngine` reference for parallel polynomial
//! operations. All methods take `&self` and perform no internal mutation.

// Allow explicit indexing in NTT algorithms - the loop indices are used in calculations
// (e.g., k*j mod N for twiddle factor lookup), not just for array access.
#![allow(clippy::needless_range_loop)]

use super::barrett::BarrettContext;
use super::montgomery::MontgomeryContext;
use crate::errors::{Nine65Error, Nine65Result};

/// NTT Engine for polynomial arithmetic in Z_q[X]/(X^N + 1)
///
/// # Thread Safety
///
/// `NTTEngine` is `Send + Sync`. It is immutable after construction and can be
/// safely shared across threads. All operations are pure functions on the input
/// polynomials.
///
/// ```ignore
/// use std::sync::Arc;
/// use std::thread;
///
/// let engine = Arc::new(NTTEngine::new(998244353, 1024));
/// let handles: Vec<_> = (0..4).map(|_| {
///     let eng = Arc::clone(&engine);
///     thread::spawn(move || {
///         // Safe to use eng from multiple threads
///         eng.ntt(&vec![0u64; 1024])
///     })
/// }).collect();
/// ```
#[derive(Clone)]
pub struct NTTEngine {
    /// Montgomery context for modular arithmetic
    pub mont: MontgomeryContext,
    /// Barrett context for constant-time reduction
    pub barrett: BarrettContext,
    /// The modulus
    pub q: u64,
    /// Polynomial degree (power of 2)
    pub n: usize,
    /// Primitive 2N-th root of unity ψ (for negacyclic twist)
    pub psi: u64,
    /// Primitive N-th root of unity ω = ψ² (for NTT)
    pub omega: u64,
    /// Inverse of ω
    pub omega_inv: u64,
    /// Inverse of ψ
    pub psi_inv: u64,
    /// N^(-1) mod q
    pub n_inv: u64,
    /// Precomputed powers of ψ: psi_powers[i] = ψ^i mod q
    pub psi_powers: Vec<u64>,
    /// Precomputed inverse powers of ψ
    pub psi_inv_powers: Vec<u64>,
    /// Precomputed powers of ω
    pub omega_powers: Vec<u64>,
    /// Precomputed inverse powers of ω
    pub omega_inv_powers: Vec<u64>,
}

impl NTTEngine {
    /// Create a new NTT engine for the given prime and degree.
    ///
    /// # Panics
    ///
    /// Panics if `n` is not a power of 2, if `(q-1)` is not divisible by `2N`,
    /// or if no primitive root of unity exists.
    ///
    /// For fallible construction, use [`try_new()`](Self::try_new) instead.
    pub fn new(q: u64, n: usize) -> Self {
        Self::try_new(q, n).expect("NTT configuration invalid")
    }

    /// Fallible constructor for NTT engine.
    ///
    /// Returns error if:
    /// - `n` is not a power of 2
    /// - `(q-1)` is not divisible by `2N` (NTT compatibility requirement)
    /// - No primitive `2N`-th root of unity exists modulo `q`
    ///
    /// # Example
    /// ```ignore
    /// let engine = NTTEngine::try_new(998244353, 1024)?;
    /// ```
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

        let mont = MontgomeryContext::new(q);
        let barrett = BarrettContext::new(q);

        // Find primitive 2N-th root of unity (ψ)
        let psi = Self::try_find_primitive_root(q, 2 * n)?;
        let psi_inv = mod_inverse(psi, q);

        // ω = ψ² is primitive N-th root
        let omega = mod_pow(psi, 2, q);
        let omega_inv = mod_inverse(omega, q);

        // N^(-1) mod q
        let n_inv = mod_inverse(n as u64, q);

        // Precompute powers
        let psi_powers: Vec<u64> = (0..n).map(|i| mod_pow(psi, i as u64, q)).collect();
        let psi_inv_powers: Vec<u64> = (0..n).map(|i| mod_pow(psi_inv, i as u64, q)).collect();
        let omega_powers: Vec<u64> = (0..n).map(|i| mod_pow(omega, i as u64, q)).collect();
        let omega_inv_powers: Vec<u64> =
            (0..n).map(|i| mod_pow(omega_inv, i as u64, q)).collect();

        Ok(Self {
            mont,
            barrett,
            q,
            n,
            psi,
            omega,
            omega_inv,
            psi_inv,
            n_inv,
            psi_powers,
            psi_inv_powers,
            omega_powers,
            omega_inv_powers,
        })
    }

    /// Find a primitive n-th root of unity modulo prime q.
    ///
    /// Returns `Err(NTTConfigError)` if no root is found.
    fn try_find_primitive_root(q: u64, order: usize) -> Nine65Result<u64> {
        let exp = (q - 1) / (order as u64);

        for g in 2..q {
            let candidate = mod_pow(g, exp, q);
            // Check it's primitive: candidate^(order/2) should be -1 (= q-1)
            let half = mod_pow(candidate, (order / 2) as u64, q);
            if half == q - 1 {
                return Ok(candidate);
            }
        }

        Err(Nine65Error::NTTConfigError {
            message: format!("no primitive root found for q={}, order={}", q, order),
        })
    }

    /// Forward NTT using DFT matrix
    pub fn ntt(&self, a: &[u64]) -> Vec<u64> {
        let mut result = vec![0u64; self.n];

        for k in 0..self.n {
            let mut sum = 0u128;
            for j in 0..self.n {
                let exp = (k * j) % self.n;
                let w = self.omega_powers[exp];
                sum += (a[j] as u128) * (w as u128);
            }
            result[k] = (sum % self.q as u128) as u64;
        }

        result
    }

    /// Constant-time forward NTT using DFT matrix
    ///
    /// Uses Barrett constant-time reduction to prevent timing side-channels.
    /// Use this variant when processing secret polynomials (e.g., secret key operations).
    pub fn ntt_ct(&self, a: &[u64]) -> Vec<u64> {
        let mut result = vec![0u64; self.n];

        for k in 0..self.n {
            let mut sum = 0u128;
            for j in 0..self.n {
                let exp = (k * j) % self.n;
                let w = self.omega_powers[exp];
                sum += (a[j] as u128) * (w as u128);
            }
            result[k] = self.barrett.reduce_ct(sum);
        }

        result
    }

    /// Inverse NTT using inverse DFT matrix
    pub fn intt(&self, a: &[u64]) -> Vec<u64> {
        let mut result = vec![0u64; self.n];

        for k in 0..self.n {
            let mut sum = 0u128;
            for j in 0..self.n {
                let exp = (k * j) % self.n;
                let w = self.omega_inv_powers[exp];
                sum += (a[j] as u128) * (w as u128);
            }
            result[k] = ((sum % self.q as u128) * self.n_inv as u128 % self.q as u128) as u64;
        }

        result
    }

    /// Constant-time inverse NTT using inverse DFT matrix
    ///
    /// Uses Barrett constant-time reduction to prevent timing side-channels.
    /// Use this variant when processing secret polynomials.
    pub fn intt_ct(&self, a: &[u64]) -> Vec<u64> {
        let mut result = vec![0u64; self.n];

        for k in 0..self.n {
            let mut sum = 0u128;
            for j in 0..self.n {
                let exp = (k * j) % self.n;
                let w = self.omega_inv_powers[exp];
                sum += (a[j] as u128) * (w as u128);
            }
            // Two CT reductions: first for sum, then for multiplication by n_inv
            let sum_reduced = self.barrett.reduce_ct(sum);
            let scaled = (sum_reduced as u128) * (self.n_inv as u128);
            result[k] = self.barrett.reduce_ct(scaled);
        }

        result
    }

    /// Multiply two polynomials using NTT (negacyclic convolution)
    /// This computes a * b mod (X^N + 1, q)
    pub fn multiply(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), self.n);
        assert_eq!(b.len(), self.n);

        // Step 1: Apply ψ-twist (convert to cyclic domain)
        let a_twisted: Vec<u64> = a
            .iter()
            .enumerate()
            .map(|(i, &ai)| ((ai as u128 * self.psi_powers[i] as u128) % self.q as u128) as u64)
            .collect();

        let b_twisted: Vec<u64> = b
            .iter()
            .enumerate()
            .map(|(i, &bi)| ((bi as u128 * self.psi_powers[i] as u128) % self.q as u128) as u64)
            .collect();

        // Step 2: Forward NTT
        let a_ntt = self.ntt(&a_twisted);
        let b_ntt = self.ntt(&b_twisted);

        // Step 3: Point-wise multiplication
        let c_ntt: Vec<u64> = a_ntt
            .iter()
            .zip(b_ntt.iter())
            .map(|(&ai, &bi)| ((ai as u128 * bi as u128) % self.q as u128) as u64)
            .collect();

        // Step 4: Inverse NTT
        let c_twisted = self.intt(&c_ntt);

        // Step 5: Remove ψ-twist
        let result: Vec<u64> = c_twisted
            .iter()
            .enumerate()
            .map(|(i, &ci)| ((ci as u128 * self.psi_inv_powers[i] as u128) % self.q as u128) as u64)
            .collect();

        result
    }

    /// Constant-time multiply two polynomials using NTT (negacyclic convolution)
    ///
    /// Uses Barrett constant-time reduction throughout to prevent timing side-channels.
    /// Use this variant when either operand contains secret data.
    pub fn multiply_ct(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), self.n);
        assert_eq!(b.len(), self.n);

        // Step 1: Apply ψ-twist using CT reduction
        let a_twisted: Vec<u64> = a
            .iter()
            .enumerate()
            .map(|(i, &ai)| {
                self.barrett
                    .reduce_ct((ai as u128) * (self.psi_powers[i] as u128))
            })
            .collect();

        let b_twisted: Vec<u64> = b
            .iter()
            .enumerate()
            .map(|(i, &bi)| {
                self.barrett
                    .reduce_ct((bi as u128) * (self.psi_powers[i] as u128))
            })
            .collect();

        // Step 2: Forward NTT (CT variant)
        let a_ntt = self.ntt_ct(&a_twisted);
        let b_ntt = self.ntt_ct(&b_twisted);

        // Step 3: Point-wise multiplication with CT reduction
        let c_ntt: Vec<u64> = a_ntt
            .iter()
            .zip(b_ntt.iter())
            .map(|(&ai, &bi)| self.barrett.reduce_ct((ai as u128) * (bi as u128)))
            .collect();

        // Step 4: Inverse NTT (CT variant)
        let c_twisted = self.intt_ct(&c_ntt);

        // Step 5: Remove ψ-twist with CT reduction
        let result: Vec<u64> = c_twisted
            .iter()
            .enumerate()
            .map(|(i, &ci)| {
                self.barrett
                    .reduce_ct((ci as u128) * (self.psi_inv_powers[i] as u128))
            })
            .collect();

        result
    }

    /// Add two polynomials coefficient-wise
    pub fn add(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), self.n);
        assert_eq!(b.len(), self.n);

        a.iter()
            .zip(b.iter())
            .map(|(&ai, &bi)| {
                let sum = ai as u128 + bi as u128;
                if sum >= self.q as u128 {
                    (sum - self.q as u128) as u64
                } else {
                    sum as u64
                }
            })
            .collect()
    }

    /// Subtract two polynomials coefficient-wise
    pub fn sub(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), self.n);
        assert_eq!(b.len(), self.n);

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
    pub fn neg(&self, a: &[u64]) -> Vec<u64> {
        a.iter()
            .map(|&ai| if ai == 0 { 0 } else { self.q - ai })
            .collect()
    }

    /// Scalar multiply
    pub fn scalar_mul(&self, a: &[u64], scalar: u64) -> Vec<u64> {
        a.iter()
            .map(|&ai| ((ai as u128 * scalar as u128) % self.q as u128) as u64)
            .collect()
    }

    // =========================================================================
    // PARALLEL OPERATIONS (requires "parallel" feature)
    // =========================================================================

    /// Parallel forward NTT using rayon
    ///
    /// Uses parallel iteration over output indices for speedup on large N.
    /// Automatically falls back to sequential for small N.
    #[cfg(feature = "parallel")]
    pub fn ntt_par(&self, a: &[u64]) -> Vec<u64> {
        use rayon::prelude::*;

        // Only parallelize for N >= 1024 (overhead not worth it for smaller)
        if self.n < 1024 {
            return self.ntt(a);
        }

        (0..self.n)
            .into_par_iter()
            .map(|k| {
                let mut sum = 0u128;
                for j in 0..self.n {
                    let exp = (k * j) % self.n;
                    let w = self.omega_powers[exp];
                    sum += (a[j] as u128) * (w as u128);
                }
                (sum % self.q as u128) as u64
            })
            .collect()
    }

    /// Parallel inverse NTT using rayon
    #[cfg(feature = "parallel")]
    pub fn intt_par(&self, a: &[u64]) -> Vec<u64> {
        use rayon::prelude::*;

        if self.n < 1024 {
            return self.intt(a);
        }

        (0..self.n)
            .into_par_iter()
            .map(|k| {
                let mut sum = 0u128;
                for j in 0..self.n {
                    let exp = (k * j) % self.n;
                    let w = self.omega_inv_powers[exp];
                    sum += (a[j] as u128) * (w as u128);
                }
                ((sum % self.q as u128) * self.n_inv as u128 % self.q as u128) as u64
            })
            .collect()
    }

    /// Parallel polynomial multiplication
    #[cfg(feature = "parallel")]
    pub fn multiply_par(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        use rayon::prelude::*;

        assert_eq!(a.len(), self.n);
        assert_eq!(b.len(), self.n);

        // For small N, use sequential version
        if self.n < 1024 {
            return self.multiply(a, b);
        }

        // Step 1: Apply ψ-twist in parallel
        let a_twisted: Vec<u64> = a
            .par_iter()
            .enumerate()
            .map(|(i, &ai)| ((ai as u128 * self.psi_powers[i] as u128) % self.q as u128) as u64)
            .collect();

        let b_twisted: Vec<u64> = b
            .par_iter()
            .enumerate()
            .map(|(i, &bi)| ((bi as u128 * self.psi_powers[i] as u128) % self.q as u128) as u64)
            .collect();

        // Step 2: Parallel forward NTT
        let a_ntt = self.ntt_par(&a_twisted);
        let b_ntt = self.ntt_par(&b_twisted);

        // Step 3: Parallel point-wise multiplication
        let c_ntt: Vec<u64> = a_ntt
            .par_iter()
            .zip(b_ntt.par_iter())
            .map(|(&ai, &bi)| ((ai as u128 * bi as u128) % self.q as u128) as u64)
            .collect();

        // Step 4: Parallel inverse NTT
        let c_twisted = self.intt_par(&c_ntt);

        // Step 5: Remove ψ-twist in parallel
        c_twisted
            .par_iter()
            .enumerate()
            .map(|(i, &ci)| ((ci as u128 * self.psi_inv_powers[i] as u128) % self.q as u128) as u64)
            .collect()
    }

    /// Parallel coefficient-wise addition
    #[cfg(feature = "parallel")]
    pub fn add_par(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        use rayon::prelude::*;

        if self.n < 1024 {
            return self.add(a, b);
        }

        a.par_iter()
            .zip(b.par_iter())
            .map(|(&ai, &bi)| {
                let sum = ai as u128 + bi as u128;
                if sum >= self.q as u128 {
                    (sum - self.q as u128) as u64
                } else {
                    sum as u64
                }
            })
            .collect()
    }

    /// Parallel coefficient-wise subtraction
    #[cfg(feature = "parallel")]
    pub fn sub_par(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        use rayon::prelude::*;

        if self.n < 1024 {
            return self.sub(a, b);
        }

        a.par_iter()
            .zip(b.par_iter())
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

    /// Parallel scalar multiplication
    #[cfg(feature = "parallel")]
    pub fn scalar_mul_par(&self, a: &[u64], scalar: u64) -> Vec<u64> {
        use rayon::prelude::*;

        if self.n < 1024 {
            return self.scalar_mul(a, scalar);
        }

        a.par_iter()
            .map(|&ai| ((ai as u128 * scalar as u128) % self.q as u128) as u64)
            .collect()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 998244353;

    // Static assertions: NTTEngine must be Send + Sync for safe multi-threading
    const _: () = {
        const fn assert_send<T: Send>() {}
        const fn assert_sync<T: Sync>() {}
        assert_send::<NTTEngine>();
        assert_sync::<NTTEngine>();
    };

    #[test]
    fn test_ntt_roundtrip() {
        let engine = NTTEngine::new(TEST_PRIME, 8);
        let original = vec![1, 2, 3, 4, 5, 6, 7, 8];

        // Apply twist + NTT + INTT + untwist
        let twisted: Vec<u64> = original
            .iter()
            .enumerate()
            .map(|(i, &x)| ((x as u128 * engine.psi_powers[i] as u128) % engine.q as u128) as u64)
            .collect();

        let ntt_result = engine.ntt(&twisted);
        let intt_result = engine.intt(&ntt_result);

        let result: Vec<u64> = intt_result
            .iter()
            .enumerate()
            .map(|(i, &x)| {
                ((x as u128 * engine.psi_inv_powers[i] as u128) % engine.q as u128) as u64
            })
            .collect();

        assert_eq!(result, original);
    }

    #[test]
    fn test_ntt_multiply_correctness_small() {
        let engine = NTTEngine::new(TEST_PRIME, 8);

        let a = vec![1, 2, 3, 0, 0, 0, 0, 0];
        let b = vec![4, 5, 0, 0, 0, 0, 0, 0];

        let result = engine.multiply(&a, &b);

        // (1 + 2x + 3x^2) * (4 + 5x) = 4 + 13x + 22x^2 + 15x^3
        assert_eq!(result, vec![4, 13, 22, 15, 0, 0, 0, 0]);
    }

    #[test]
    fn test_ntt_negacyclic() {
        let engine = NTTEngine::new(TEST_PRIME, 4);

        // x^3 * x = x^4 = -1 in X^4 + 1
        let a = vec![0, 0, 0, 1]; // x^3
        let b = vec![0, 1, 0, 0]; // x

        let result = engine.multiply(&a, &b);

        assert_eq!(result, vec![TEST_PRIME - 1, 0, 0, 0]);
    }

    #[test]
    fn test_ntt_multiply_random() {
        let engine = NTTEngine::new(TEST_PRIME, 8);

        let a: Vec<u64> = (0..8).map(|i| (i * 12345) % TEST_PRIME).collect();
        let b: Vec<u64> = (0..8).map(|i| (i * 67890) % TEST_PRIME).collect();

        let result = engine.multiply(&a, &b);

        // Verify using schoolbook multiplication with negacyclic reduction
        let mut expected = vec![0i128; 8];
        for i in 0..8 {
            for j in 0..8 {
                let prod = a[i] as i128 * b[j] as i128;
                let idx = i + j;
                if idx < 8 {
                    expected[idx] += prod;
                } else {
                    expected[idx - 8] -= prod;
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

        assert_eq!(result, expected);
    }

    #[test]
    fn test_polynomial_add() {
        let engine = NTTEngine::new(TEST_PRIME, 4);
        let result = engine.add(&[1, 2, 3, 4], &[5, 6, 7, 8]);
        assert_eq!(result, vec![6, 8, 10, 12]);
    }

    #[test]
    fn test_polynomial_sub() {
        let engine = NTTEngine::new(TEST_PRIME, 4);
        let result = engine.sub(&[10, 20, 30, 40], &[5, 6, 7, 8]);
        assert_eq!(result, vec![5, 14, 23, 32]);
    }

    #[test]
    fn test_ntt_benchmark_1024() {
        let engine = NTTEngine::new(TEST_PRIME, 1024);

        let a: Vec<u64> = (0..1024).map(|i| i % TEST_PRIME).collect();
        let b: Vec<u64> = (0..1024).map(|i| (i * 2) % TEST_PRIME).collect();

        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = engine.multiply(&a, &b);
        }
        let elapsed = start.elapsed();

        println!("NTT 1024-point multiply x100: {:?}", elapsed);
    }

    // =========================================================================
    // PARALLEL OPERATION TESTS (requires "parallel" feature)
    // =========================================================================

    #[cfg(feature = "parallel")]
    #[test]
    fn test_parallel_ntt_matches_sequential_small() {
        // For small N, parallel should fall back to sequential
        let engine = NTTEngine::new(TEST_PRIME, 8);
        let a = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let seq_result = engine.ntt(&a);
        let par_result = engine.ntt_par(&a);

        assert_eq!(
            seq_result, par_result,
            "Parallel NTT should match sequential for small N"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_parallel_ntt_matches_sequential_large() {
        // For large N, parallel should still produce same results
        let engine = NTTEngine::new(TEST_PRIME, 1024);
        let a: Vec<u64> = (0..1024).map(|i| (i * 12345) % TEST_PRIME).collect();

        let seq_result = engine.ntt(&a);
        let par_result = engine.ntt_par(&a);

        assert_eq!(
            seq_result, par_result,
            "Parallel NTT should match sequential for large N"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_parallel_intt_matches_sequential() {
        let engine = NTTEngine::new(TEST_PRIME, 1024);
        let a: Vec<u64> = (0..1024).map(|i| (i * 67890) % TEST_PRIME).collect();

        let seq_result = engine.intt(&a);
        let par_result = engine.intt_par(&a);

        assert_eq!(
            seq_result, par_result,
            "Parallel INTT should match sequential"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_parallel_multiply_matches_sequential() {
        let engine = NTTEngine::new(TEST_PRIME, 1024);

        let a: Vec<u64> = (0..1024).map(|i| (i * 12345) % TEST_PRIME).collect();
        let b: Vec<u64> = (0..1024).map(|i| (i * 67890) % TEST_PRIME).collect();

        let seq_result = engine.multiply(&a, &b);
        let par_result = engine.multiply_par(&a, &b);

        assert_eq!(
            seq_result, par_result,
            "Parallel multiply should match sequential"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_parallel_add_matches_sequential() {
        let engine = NTTEngine::new(TEST_PRIME, 1024);

        let a: Vec<u64> = (0..1024).map(|i| (i * 123) % TEST_PRIME).collect();
        let b: Vec<u64> = (0..1024).map(|i| (i * 456) % TEST_PRIME).collect();

        let seq_result = engine.add(&a, &b);
        let par_result = engine.add_par(&a, &b);

        assert_eq!(
            seq_result, par_result,
            "Parallel add should match sequential"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_parallel_sub_matches_sequential() {
        let engine = NTTEngine::new(TEST_PRIME, 1024);

        let a: Vec<u64> = (0..1024)
            .map(|i| (TEST_PRIME - 1 - i) % TEST_PRIME)
            .collect();
        let b: Vec<u64> = (0..1024).map(|i| i % TEST_PRIME).collect();

        let seq_result = engine.sub(&a, &b);
        let par_result = engine.sub_par(&a, &b);

        assert_eq!(
            seq_result, par_result,
            "Parallel sub should match sequential"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_parallel_scalar_mul_matches_sequential() {
        let engine = NTTEngine::new(TEST_PRIME, 1024);

        let a: Vec<u64> = (0..1024).map(|i| (i * 789) % TEST_PRIME).collect();
        let scalar = 42u64;

        let seq_result = engine.scalar_mul(&a, scalar);
        let par_result = engine.scalar_mul_par(&a, scalar);

        assert_eq!(
            seq_result, par_result,
            "Parallel scalar_mul should match sequential"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_parallel_ntt_roundtrip() {
        let engine = NTTEngine::new(TEST_PRIME, 1024);
        let original: Vec<u64> = (0..1024).map(|i| i % TEST_PRIME).collect();

        // Apply twist + parallel NTT + parallel INTT + untwist
        let twisted: Vec<u64> = original
            .iter()
            .enumerate()
            .map(|(i, &x)| ((x as u128 * engine.psi_powers[i] as u128) % engine.q as u128) as u64)
            .collect();

        let ntt_result = engine.ntt_par(&twisted);
        let intt_result = engine.intt_par(&ntt_result);

        let result: Vec<u64> = intt_result
            .iter()
            .enumerate()
            .map(|(i, &x)| {
                ((x as u128 * engine.psi_inv_powers[i] as u128) % engine.q as u128) as u64
            })
            .collect();

        assert_eq!(
            result, original,
            "Parallel NTT roundtrip should recover original"
        );
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn test_parallel_multiply_correctness() {
        let engine = NTTEngine::new(TEST_PRIME, 1024);

        let a: Vec<u64> = (0..1024).map(|i| (i * 12345) % TEST_PRIME).collect();
        let b: Vec<u64> = (0..1024).map(|i| (i * 67890) % TEST_PRIME).collect();

        let result = engine.multiply_par(&a, &b);

        // Verify using schoolbook multiplication with negacyclic reduction
        let mut expected = vec![0i128; 1024];
        for i in 0..1024 {
            for j in 0..1024 {
                let prod = a[i] as i128 * b[j] as i128;
                let idx = i + j;
                if idx < 1024 {
                    expected[idx] += prod;
                } else {
                    expected[idx - 1024] -= prod;
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

        assert_eq!(
            result, expected,
            "Parallel multiply should be mathematically correct"
        );
    }

    // =========================================================================
    // CONSTANT-TIME OPERATION TESTS
    // =========================================================================

    #[test]
    fn test_ntt_ct_matches_ntt() {
        let engine = NTTEngine::new(TEST_PRIME, 8);
        let a = vec![1, 2, 3, 4, 5, 6, 7, 8];

        let vt_result = engine.ntt(&a);
        let ct_result = engine.ntt_ct(&a);

        assert_eq!(
            vt_result, ct_result,
            "CT NTT should match variable-time NTT"
        );
    }

    #[test]
    fn test_ntt_ct_matches_ntt_large() {
        let engine = NTTEngine::new(TEST_PRIME, 1024);
        let a: Vec<u64> = (0..1024).map(|i| (i * 12345) % TEST_PRIME).collect();

        let vt_result = engine.ntt(&a);
        let ct_result = engine.ntt_ct(&a);

        assert_eq!(
            vt_result, ct_result,
            "CT NTT should match variable-time NTT for large N"
        );
    }

    #[test]
    fn test_intt_ct_matches_intt() {
        let engine = NTTEngine::new(TEST_PRIME, 8);
        let a = vec![100, 200, 300, 400, 500, 600, 700, 800];

        let vt_result = engine.intt(&a);
        let ct_result = engine.intt_ct(&a);

        assert_eq!(
            vt_result, ct_result,
            "CT INTT should match variable-time INTT"
        );
    }

    #[test]
    fn test_intt_ct_matches_intt_large() {
        let engine = NTTEngine::new(TEST_PRIME, 1024);
        let a: Vec<u64> = (0..1024).map(|i| (i * 67890) % TEST_PRIME).collect();

        let vt_result = engine.intt(&a);
        let ct_result = engine.intt_ct(&a);

        assert_eq!(
            vt_result, ct_result,
            "CT INTT should match variable-time INTT for large N"
        );
    }

    #[test]
    fn test_multiply_ct_matches_multiply() {
        let engine = NTTEngine::new(TEST_PRIME, 8);

        let a = vec![1, 2, 3, 0, 0, 0, 0, 0];
        let b = vec![4, 5, 0, 0, 0, 0, 0, 0];

        let vt_result = engine.multiply(&a, &b);
        let ct_result = engine.multiply_ct(&a, &b);

        assert_eq!(
            vt_result, ct_result,
            "CT multiply should match variable-time multiply"
        );
        // Verify correctness: (1 + 2x + 3x^2) * (4 + 5x) = 4 + 13x + 22x^2 + 15x^3
        assert_eq!(ct_result, vec![4, 13, 22, 15, 0, 0, 0, 0]);
    }

    #[test]
    fn test_multiply_ct_matches_multiply_large() {
        let engine = NTTEngine::new(TEST_PRIME, 1024);

        let a: Vec<u64> = (0..1024).map(|i| (i * 12345) % TEST_PRIME).collect();
        let b: Vec<u64> = (0..1024).map(|i| (i * 67890) % TEST_PRIME).collect();

        let vt_result = engine.multiply(&a, &b);
        let ct_result = engine.multiply_ct(&a, &b);

        assert_eq!(
            vt_result, ct_result,
            "CT multiply should match variable-time multiply for large N"
        );
    }

    #[test]
    fn test_ntt_ct_roundtrip() {
        let engine = NTTEngine::new(TEST_PRIME, 8);
        let original = vec![1, 2, 3, 4, 5, 6, 7, 8];

        // Apply twist + CT NTT + CT INTT + untwist
        let twisted: Vec<u64> = original
            .iter()
            .enumerate()
            .map(|(i, &x)| {
                engine
                    .barrett
                    .reduce_ct((x as u128) * (engine.psi_powers[i] as u128))
            })
            .collect();

        let ntt_result = engine.ntt_ct(&twisted);
        let intt_result = engine.intt_ct(&ntt_result);

        let result: Vec<u64> = intt_result
            .iter()
            .enumerate()
            .map(|(i, &x)| {
                engine
                    .barrett
                    .reduce_ct((x as u128) * (engine.psi_inv_powers[i] as u128))
            })
            .collect();

        assert_eq!(result, original, "CT NTT roundtrip should recover original");
    }

    #[test]
    fn test_multiply_ct_negacyclic() {
        let engine = NTTEngine::new(TEST_PRIME, 4);

        // x^3 * x = x^4 = -1 in X^4 + 1
        let a = vec![0, 0, 0, 1]; // x^3
        let b = vec![0, 1, 0, 0]; // x

        let result = engine.multiply_ct(&a, &b);

        assert_eq!(
            result,
            vec![TEST_PRIME - 1, 0, 0, 0],
            "CT multiply should handle negacyclic correctly"
        );
    }

    // =========================================================================
    // FALLIBLE CONSTRUCTOR TESTS
    // =========================================================================

    #[test]
    fn test_try_new_valid_params() {
        let result = NTTEngine::try_new(TEST_PRIME, 8);
        assert!(result.is_ok());
    }

    #[test]
    fn test_try_new_non_power_of_two() {
        let result = NTTEngine::try_new(TEST_PRIME, 7);
        assert!(result.is_err());
        match result {
            Err(ref e) => assert!(e.to_string().contains("power of 2"), "wrong error: {}", e),
            Ok(_) => unreachable!(),
        }
    }

    #[test]
    fn test_try_new_incompatible_modulus() {
        // 17 is prime, 17-1=16, but 16 % (2*8=16) == 0, so N=8 works.
        // Try N=32: 16 % 64 != 0, so this should fail.
        let result = NTTEngine::try_new(17, 32);
        assert!(result.is_err());
        match result {
            Err(ref e) => assert!(
                e.to_string().contains("divisible by 2N"),
                "wrong error: {}",
                e
            ),
            Ok(_) => unreachable!(),
        }
    }

    #[test]
    fn test_try_new_1024_degree() {
        let result = NTTEngine::try_new(TEST_PRIME, 1024);
        assert!(result.is_ok());
    }

    // Timing regression tests moved to criterion benches (benches/timing.rs)
}
