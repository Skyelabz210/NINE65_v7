//! # Stream - Multi-Lane CRT Parallel Execution
//!
//! A ManaStream holds coefficients across multiple CRT lanes (primes).
//! Each lane operates independently - perfect for parallelization.
//!
//! ## Design
//!
//! ```text
//! Stream: value V represented as (V mod p1, V mod p2, ..., V mod pk)
//!
//! Lane 0 [prime=17]: [3, 5, 2, 8, ...]  <- Can process with SIMD
//! Lane 1 [prime=19]: [4, 6, 1, 9, ...]  <- Independent, parallel with Rayon
//! Lane 2 [prime=23]: [1, 2, 0, 5, ...]  <- No carry between lanes
//! ```

use crate::lane::{Lane, LaneOps};
use std::sync::Arc;

/// Multi-lane CRT representation
/// Uses Arc<Vec<u64>> for primes to avoid cloning on every operation
#[derive(Clone, Debug)]
pub struct ManaStream {
    /// Lanes: one per prime modulus
    pub lanes: Vec<Lane>,
    /// Prime moduli (shared via Arc - no clone overhead)
    pub primes: Arc<Vec<u64>>,
    /// Coefficient count per lane
    pub n: usize,
    /// Cached product of all primes (CRT modulus) - computed once
    pub product_cache: u128,
}

/// Compute product of primes once
#[inline]
fn compute_product(primes: &[u64]) -> u128 {
    primes.iter().fold(1u128, |acc, &p| acc * p as u128)
}

impl ManaStream {
    /// Create a new stream with given primes and size
    pub fn new(primes: &[u64], n: usize) -> Self {
        let lanes = primes.iter().map(|&p| Lane::new(p, n)).collect();
        let product_cache = compute_product(primes);
        Self {
            lanes,
            primes: Arc::new(primes.to_vec()),
            n,
            product_cache,
        }
    }

    /// Create from integer values, reducing to each prime
    pub fn from_ints(values: &[u64], primes: &[u64]) -> Self {
        let n = values.len();
        let lanes = primes
            .iter()
            .map(|&p| Lane::from_int_slice(values, p))
            .collect();
        let product_cache = compute_product(primes);
        Self {
            lanes,
            primes: Arc::new(primes.to_vec()),
            n,
            product_cache,
        }
    }

    /// Number of lanes (primes)
    #[inline]
    pub fn num_lanes(&self) -> usize {
        self.lanes.len()
    }

    /// Number of coefficients per lane
    #[inline]
    pub fn len(&self) -> usize {
        self.n
    }

    /// Is empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Get the product of all primes (CRT modulus) - cached
    #[inline]
    pub fn product(&self) -> u128 {
        self.product_cache
    }

    /// Reconstruct integer at position i using CRT
    ///
    /// Note: Result only valid if original value < product of primes
    pub fn reconstruct_at(&self, i: usize) -> u128 {
        let m = self.product();
        let mut result = 0u128;

        for (lane, &p) in self.lanes.iter().zip(self.primes.iter()) {
            let mi = m / p as u128;
            let mi_inv = mod_inverse_u128(mi % p as u128, p as u128);
            let term = (lane.coeffs[i] as u128 * mi_inv) % p as u128;
            let contribution = (term * mi) % m;
            result = (result + contribution) % m;
        }

        result
    }
}

/// Stream operations - sequential baseline (Rayon version in parallel.rs)
pub trait StreamOps {
    /// Add two streams lane-wise
    fn add(&self, other: &Self) -> Self;

    /// Subtract two streams lane-wise
    fn sub(&self, other: &Self) -> Self;

    /// Negate all lanes
    fn neg(&self) -> Self;

    /// Multiply two streams lane-wise (coefficient-wise per lane)
    fn mul(&self, other: &Self) -> Self;

    /// Scalar multiply all lanes
    fn scalar_mul(&self, scalar: u64) -> Self;
}

impl StreamOps for ManaStream {
    #[inline]
    fn add(&self, other: &Self) -> Self {
        debug_assert_eq!(self.primes, other.primes);
        debug_assert_eq!(self.n, other.n);

        let lanes = self
            .lanes
            .iter()
            .zip(other.lanes.iter())
            .map(|(a, b)| a.add(b))
            .collect();

        Self {
            lanes,
            primes: Arc::clone(&self.primes),
            n: self.n,
            product_cache: self.product_cache,
        }
    }

    #[inline]
    fn sub(&self, other: &Self) -> Self {
        debug_assert_eq!(self.primes, other.primes);
        debug_assert_eq!(self.n, other.n);

        let lanes = self
            .lanes
            .iter()
            .zip(other.lanes.iter())
            .map(|(a, b)| a.sub(b))
            .collect();

        Self {
            lanes,
            primes: Arc::clone(&self.primes),
            n: self.n,
            product_cache: self.product_cache,
        }
    }

    #[inline]
    fn neg(&self) -> Self {
        let lanes = self.lanes.iter().map(|a| a.neg()).collect();

        Self {
            lanes,
            primes: Arc::clone(&self.primes),
            n: self.n,
            product_cache: self.product_cache,
        }
    }

    #[inline]
    fn mul(&self, other: &Self) -> Self {
        debug_assert_eq!(self.primes, other.primes);
        debug_assert_eq!(self.n, other.n);

        let lanes = self
            .lanes
            .iter()
            .zip(other.lanes.iter())
            .map(|(a, b)| a.mul(b))
            .collect();

        Self {
            lanes,
            primes: Arc::clone(&self.primes),
            n: self.n,
            product_cache: self.product_cache,
        }
    }

    #[inline]
    fn scalar_mul(&self, scalar: u64) -> Self {
        let lanes = self.lanes.iter().map(|a| a.scalar_mul(scalar)).collect();

        Self {
            lanes,
            primes: Arc::clone(&self.primes),
            n: self.n,
            product_cache: self.product_cache,
        }
    }
}

/// Modular inverse for u128 (extended Euclidean)
fn mod_inverse_u128(a: u128, m: u128) -> u128 {
    let (g, x, _) = extended_gcd_i128(a as i128, m as i128);
    debug_assert_eq!(g, 1, "No inverse exists");

    if x < 0 {
        (x + m as i128) as u128
    } else {
        x as u128
    }
}

fn extended_gcd_i128(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        return (b, 0, 1);
    }
    let (g, x1, y1) = extended_gcd_i128(b % a, a);
    let x = y1 - (b / a) * x1;
    let y = x1;
    (g, x, y)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_add() {
        let primes = vec![17, 19, 23];
        let a = ManaStream::from_ints(&[1, 2, 3, 4], &primes);
        let b = ManaStream::from_ints(&[5, 6, 7, 8], &primes);
        let c = a.add(&b);

        // Verify by reconstruction
        assert_eq!(c.reconstruct_at(0), 6);
        assert_eq!(c.reconstruct_at(1), 8);
        assert_eq!(c.reconstruct_at(2), 10);
        assert_eq!(c.reconstruct_at(3), 12);
    }

    #[test]
    fn test_stream_mul() {
        let primes = vec![17, 19, 23];
        let a = ManaStream::from_ints(&[2, 3, 4], &primes);
        let b = ManaStream::from_ints(&[5, 6, 7], &primes);
        let c = a.mul(&b);

        assert_eq!(c.reconstruct_at(0), 10);
        assert_eq!(c.reconstruct_at(1), 18);
        assert_eq!(c.reconstruct_at(2), 28);
    }

    #[test]
    fn test_crt_reconstruction() {
        let primes = vec![17, 19, 23]; // product = 7429

        // Test various values within product range
        for &v in &[0u64, 1, 42, 100, 1000, 7000] {
            let stream = ManaStream::from_ints(&[v], &primes);
            let reconstructed = stream.reconstruct_at(0);
            assert_eq!(reconstructed, v as u128, "CRT failed for {}", v);
        }
    }

    #[test]
    fn test_large_value_reconstruction() {
        // Use larger primes for bigger range
        let primes = vec![65537, 65521, 65519]; // product = ~2^48

        let v: u64 = 1_000_000_000_000;
        let stream = ManaStream::from_ints(&[v], &primes);
        let reconstructed = stream.reconstruct_at(0);
        assert_eq!(reconstructed, v as u128);
    }
}
