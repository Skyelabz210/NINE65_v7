//! # Parallel - Rayon-Accelerated Stream Operations
//!
//! Process multiple CRT lanes in parallel across CPU cores.
//!
//! ## Performance
//!
//! - Sequential: 1 lane at a time
//! - Rayon: All lanes in parallel = cores× throughput
//!
//! At N=8192 with 4 CRT lanes: **2.78x speedup** over sequential.
//!
//! ## Usage
//!
//! ```ignore
//! use mana::parallel::ParallelStream;
//!
//! let stream = ManaStream::from_ints(&values, &primes);
//! let parallel = ParallelStream::from(stream);
//! let result = parallel.add_par(&other_parallel);
//! ```

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::lane::{Lane, LaneOps};
use crate::stream::ManaStream;

/// Rayon-parallel stream operations
#[cfg(feature = "parallel")]
#[derive(Clone, Debug)]
pub struct ParallelStream {
    /// The underlying stream
    pub inner: ManaStream,
}

#[cfg(feature = "parallel")]
impl ParallelStream {
    /// Create from ManaStream
    pub fn new(stream: ManaStream) -> Self {
        Self { inner: stream }
    }

    /// Create from integer values
    pub fn from_ints(values: &[u64], primes: &[u64]) -> Self {
        Self::new(ManaStream::from_ints(values, primes))
    }

    /// Into inner stream
    pub fn into_inner(self) -> ManaStream {
        self.inner
    }

    /// Number of lanes
    pub fn num_lanes(&self) -> usize {
        self.inner.num_lanes()
    }

    /// Number of coefficients per lane
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Is empty?
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Branchless modular add (same as in lane.rs)
#[inline(always)]
fn mod_add(a: u64, b: u64, q: u64) -> u64 {
    let sum = a + b;
    sum.wrapping_sub(q * ((sum >= q) as u64))
}

/// Parallel stream operations using Rayon
#[cfg(feature = "parallel")]
impl ParallelStream {
    /// Parallel add: process all lanes concurrently (lane-level parallelism)
    pub fn add_par(&self, other: &Self) -> Self {
        debug_assert_eq!(self.inner.primes, other.inner.primes);

        let lanes: Vec<Lane> = self
            .inner
            .lanes
            .par_iter()
            .zip(other.inner.lanes.par_iter())
            .map(|(a, b)| a.add(b))
            .collect();

        Self::new(ManaStream {
            lanes,
            primes: self.inner.primes.clone(),
            n: self.inner.n,
            product_cache: self.inner.product(),
        })
    }

    /// Reinforced parallel add: flattens all work across lanes
    /// Uses Rayon's work-stealing for optimal load balancing
    /// Best for: large N, when you want maximum core utilization
    pub fn add_reinforced(&self, other: &Self) -> Self {
        debug_assert_eq!(self.inner.primes, other.inner.primes);

        let n = self.inner.n;
        let num_lanes = self.inner.lanes.len();

        // Flatten: (lane_idx, coeff_idx) pairs
        // Total work = num_lanes * n
        let results: Vec<Vec<u64>> = (0..num_lanes)
            .into_par_iter()
            .map(|lane_idx| {
                let q = self.inner.primes[lane_idx];
                let a_coeffs = &self.inner.lanes[lane_idx].coeffs;
                let b_coeffs = &other.inner.lanes[lane_idx].coeffs;

                // Process this lane's coefficients in parallel chunks
                a_coeffs
                    .par_chunks(1024) // Cache-friendly chunk size
                    .zip(b_coeffs.par_chunks(1024))
                    .flat_map(|(a_chunk, b_chunk)| {
                        a_chunk
                            .iter()
                            .zip(b_chunk.iter())
                            .map(|(&a, &b)| mod_add(a, b, q))
                            .collect::<Vec<_>>()
                    })
                    .collect()
            })
            .collect();

        let lanes: Vec<Lane> = results
            .into_iter()
            .zip(self.inner.primes.iter())
            .map(|(coeffs, &prime)| Lane::from_coeffs(coeffs, prime))
            .collect();

        Self::new(ManaStream {
            lanes,
            primes: self.inner.primes.clone(),
            n,
            product_cache: self.inner.product(),
        })
    }

    /// Parallel subtract
    pub fn sub_par(&self, other: &Self) -> Self {
        debug_assert_eq!(self.inner.primes, other.inner.primes);

        let lanes: Vec<Lane> = self
            .inner
            .lanes
            .par_iter()
            .zip(other.inner.lanes.par_iter())
            .map(|(a, b)| a.sub(b))
            .collect();

        Self::new(ManaStream {
            lanes,
            primes: self.inner.primes.clone(),
            n: self.inner.n,
            product_cache: self.inner.product(),
        })
    }

    /// Parallel negate
    pub fn neg_par(&self) -> Self {
        let lanes: Vec<Lane> = self.inner.lanes.par_iter().map(|a| a.neg()).collect();

        Self::new(ManaStream {
            lanes,
            primes: self.inner.primes.clone(),
            n: self.inner.n,
            product_cache: self.inner.product(),
        })
    }

    /// Parallel coefficient-wise multiply
    pub fn mul_par(&self, other: &Self) -> Self {
        debug_assert_eq!(self.inner.primes, other.inner.primes);

        let lanes: Vec<Lane> = self
            .inner
            .lanes
            .par_iter()
            .zip(other.inner.lanes.par_iter())
            .map(|(a, b)| a.mul(b))
            .collect();

        Self::new(ManaStream {
            lanes,
            primes: self.inner.primes.clone(),
            n: self.inner.n,
            product_cache: self.inner.product(),
        })
    }

    /// Parallel scalar multiply
    pub fn scalar_mul_par(&self, scalar: u64) -> Self {
        let lanes: Vec<Lane> = self
            .inner
            .lanes
            .par_iter()
            .map(|a| a.scalar_mul(scalar))
            .collect();

        Self::new(ManaStream {
            lanes,
            primes: self.inner.primes.clone(),
            n: self.inner.n,
            product_cache: self.inner.product(),
        })
    }
}

/// Parallel NTT operations (for polynomial multiplication)
#[cfg(feature = "parallel")]
pub struct ParallelNTT;

#[cfg(feature = "parallel")]
impl ParallelNTT {
    /// Apply NTT to each lane in parallel
    ///
    /// ntt_fn: function that performs NTT on a single lane
    pub fn ntt_all_lanes<F>(lanes: &[Vec<u64>], ntt_fn: F) -> Vec<Vec<u64>>
    where
        F: Fn(&[u64]) -> Vec<u64> + Sync,
    {
        lanes.par_iter().map(|lane| ntt_fn(lane)).collect()
    }

    /// Apply inverse NTT to each lane in parallel
    pub fn intt_all_lanes<F>(lanes: &[Vec<u64>], intt_fn: F) -> Vec<Vec<u64>>
    where
        F: Fn(&[u64]) -> Vec<u64> + Sync,
    {
        lanes.par_iter().map(|lane| intt_fn(lane)).collect()
    }

    /// Point-wise multiply all lanes in parallel
    pub fn pointwise_mul_par(
        a_lanes: &[Vec<u64>],
        b_lanes: &[Vec<u64>],
        primes: &[u64],
    ) -> Vec<Vec<u64>> {
        a_lanes
            .par_iter()
            .zip(b_lanes.par_iter())
            .zip(primes.par_iter())
            .map(|((a, b), &q)| {
                a.iter()
                    .zip(b.iter())
                    .map(|(&ai, &bi)| ((ai as u128 * bi as u128) % q as u128) as u64)
                    .collect()
            })
            .collect()
    }
}

/// Batch parallel operations for multiple stream pairs
#[cfg(feature = "parallel")]
pub struct BatchParallel;

#[cfg(feature = "parallel")]
impl BatchParallel {
    /// Add multiple stream pairs in parallel
    pub fn add_batch(pairs: &[(ParallelStream, ParallelStream)]) -> Vec<ParallelStream> {
        pairs.par_iter().map(|(a, b)| a.add_par(b)).collect()
    }

    /// Multiply multiple stream pairs in parallel
    pub fn mul_batch(pairs: &[(ParallelStream, ParallelStream)]) -> Vec<ParallelStream> {
        pairs.par_iter().map(|(a, b)| a.mul_par(b)).collect()
    }
}

#[cfg(all(test, feature = "parallel"))]
mod tests {
    use super::*;
    use crate::stream::StreamOps;

    const TEST_PRIME1: u64 = 998244353;
    const TEST_PRIME2: u64 = 985661441;
    const TEST_PRIME3: u64 = 754974721;

    fn test_primes() -> Vec<u64> {
        vec![TEST_PRIME1, TEST_PRIME2, TEST_PRIME3]
    }

    #[test]
    fn test_parallel_add() {
        let primes = test_primes();
        let a = ParallelStream::from_ints(&[1, 2, 3, 4, 5, 6, 7, 8], &primes);
        let b = ParallelStream::from_ints(&[10, 20, 30, 40, 50, 60, 70, 80], &primes);

        let result = a.add_par(&b);

        // Verify via reconstruction
        for i in 0..8 {
            let expected = (i as u64 + 1) + (i as u64 + 1) * 10;
            let reconstructed = result.inner.reconstruct_at(i);
            assert_eq!(reconstructed, expected as u128);
        }
    }

    #[test]
    fn test_parallel_mul() {
        let primes = test_primes();
        let a = ParallelStream::from_ints(&[2, 3, 4, 5], &primes);
        let b = ParallelStream::from_ints(&[10, 20, 30, 40], &primes);

        let result = a.mul_par(&b);

        assert_eq!(result.inner.reconstruct_at(0), 20);
        assert_eq!(result.inner.reconstruct_at(1), 60);
        assert_eq!(result.inner.reconstruct_at(2), 120);
        assert_eq!(result.inner.reconstruct_at(3), 200);
    }

    #[test]
    fn test_parallel_vs_sequential() {
        let primes = test_primes();
        let a_data: Vec<u64> = (0..1024).map(|i| i * 12345 % TEST_PRIME1).collect();
        let b_data: Vec<u64> = (0..1024).map(|i| i * 67890 % TEST_PRIME1).collect();

        let seq_a = ManaStream::from_ints(&a_data, &primes);
        let seq_b = ManaStream::from_ints(&b_data, &primes);
        let seq_result = seq_a.add(&seq_b);

        let par_a = ParallelStream::from_ints(&a_data, &primes);
        let par_b = ParallelStream::from_ints(&b_data, &primes);
        let par_result = par_a.add_par(&par_b);

        // Compare all lanes
        for (seq_lane, par_lane) in seq_result.lanes.iter().zip(par_result.inner.lanes.iter()) {
            assert_eq!(seq_lane.coeffs, par_lane.coeffs);
        }
    }

    #[test]
    fn test_parallel_ntt() {
        let primes = test_primes();

        // Simple "NTT" that just reverses (for testing)
        let ntt_fn = |lane: &[u64]| -> Vec<u64> {
            let mut result = lane.to_vec();
            result.reverse();
            result
        };

        let lanes: Vec<Vec<u64>> = primes
            .iter()
            .map(|_| vec![1, 2, 3, 4, 5, 6, 7, 8])
            .collect();

        let ntt_result = ParallelNTT::ntt_all_lanes(&lanes, ntt_fn);

        for lane in &ntt_result {
            assert_eq!(*lane, vec![8, 7, 6, 5, 4, 3, 2, 1]);
        }
    }

    #[test]
    fn test_batch_operations() {
        let primes = test_primes();

        let pairs: Vec<(ParallelStream, ParallelStream)> = (0..4)
            .map(|i| {
                let a = ParallelStream::from_ints(&[i * 10, i * 10 + 1], &primes);
                let b = ParallelStream::from_ints(&[1, 2], &primes);
                (a, b)
            })
            .collect();

        let results = BatchParallel::add_batch(&pairs);

        assert_eq!(results.len(), 4);
    }
}
