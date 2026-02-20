//! # Accelerator - Unified Hardware Abstraction
//!
//! High-level interface that automatically selects the best execution path:
//! - SIMD when available (4× throughput per lane)
//! - Rayon when multiple lanes (cores× throughput)
//! - Sequential fallback
//!
//! ## Usage
//!
//! ```ignore
//! use unhal::prelude::*;
//!
//! let config = AcceleratorConfig::auto_detect();
//! let accel = Accelerator::new(config);
//!
//! let result = accel.add_streams(&a, &b);
//! ```

use mana::stream::{ManaStream, StreamOps};

#[cfg(feature = "parallel")]
use mana::parallel::ParallelStream;

/// Accelerator execution mode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Sequential (no SIMD, no parallelism)
    Sequential,
    /// SIMD only (vectorized, single-threaded)
    Simd,
    /// Parallel only (multi-threaded, no SIMD)
    Parallel,
    /// Full acceleration (SIMD + Rayon)
    Full,
}

impl ExecutionMode {
    /// Detect best mode based on compile-time features
    pub fn auto_detect() -> Self {
        #[cfg(all(feature = "simd", feature = "parallel"))]
        {
            ExecutionMode::Full
        }

        #[cfg(all(feature = "simd", not(feature = "parallel")))]
        {
            ExecutionMode::Simd
        }

        #[cfg(all(not(feature = "simd"), feature = "parallel"))]
        {
            ExecutionMode::Parallel
        }

        #[cfg(not(any(feature = "simd", feature = "parallel")))]
        {
            ExecutionMode::Sequential
        }
    }
}

/// Accelerator configuration
#[derive(Clone, Debug)]
pub struct AcceleratorConfig {
    /// Execution mode
    pub mode: ExecutionMode,
    /// Minimum size to use parallel execution (smaller = sequential)
    pub parallel_threshold: usize,
    /// Number of threads (0 = auto, uses Rayon default)
    pub num_threads: usize,
}

impl Default for AcceleratorConfig {
    fn default() -> Self {
        Self {
            mode: ExecutionMode::auto_detect(),
            parallel_threshold: 256,
            num_threads: 0,
        }
    }
}

impl AcceleratorConfig {
    /// Create with auto-detected mode
    pub fn auto_detect() -> Self {
        Self::default()
    }

    /// Force sequential mode (for testing/comparison)
    pub fn sequential() -> Self {
        Self {
            mode: ExecutionMode::Sequential,
            ..Default::default()
        }
    }

    /// Force SIMD-only mode
    pub fn simd_only() -> Self {
        Self {
            mode: ExecutionMode::Simd,
            ..Default::default()
        }
    }

    /// Force parallel-only mode
    pub fn parallel_only() -> Self {
        Self {
            mode: ExecutionMode::Parallel,
            ..Default::default()
        }
    }

    /// Force full acceleration
    pub fn full() -> Self {
        Self {
            mode: ExecutionMode::Full,
            ..Default::default()
        }
    }
}

/// Main accelerator interface
#[derive(Clone, Debug)]
pub struct Accelerator {
    /// Configuration
    pub config: AcceleratorConfig,
}

impl Accelerator {
    /// Create new accelerator with config
    pub fn new(config: AcceleratorConfig) -> Self {
        Self { config }
    }

    /// Create with auto-detected settings
    pub fn auto() -> Self {
        Self::new(AcceleratorConfig::auto_detect())
    }

    /// Should use parallel for this size?
    #[inline]
    fn should_parallelize(&self, num_lanes: usize) -> bool {
        num_lanes >= self.config.parallel_threshold
    }

    /// Add two streams using best available path
    pub fn add_streams(&self, a: &ManaStream, b: &ManaStream) -> ManaStream {
        #[cfg(all(feature = "simd", feature = "parallel"))]
        {
            match self.config.mode {
                ExecutionMode::Sequential => a.add(b),
                ExecutionMode::Simd => self.add_simd(a, b),
                ExecutionMode::Parallel => {
                    if self.should_parallelize(a.num_lanes()) {
                        self.add_parallel(a, b)
                    } else {
                        a.add(b)
                    }
                }
                ExecutionMode::Full => {
                    if self.should_parallelize(a.num_lanes()) {
                        self.add_simd_parallel(a, b)
                    } else {
                        self.add_simd(a, b)
                    }
                }
            }
        }

        #[cfg(all(feature = "simd", not(feature = "parallel")))]
        {
            match self.config.mode {
                ExecutionMode::Simd => self.add_simd(a, b),
                _ => a.add(b),
            }
        }

        #[cfg(all(not(feature = "simd"), feature = "parallel"))]
        {
            match self.config.mode {
                ExecutionMode::Parallel => {
                    if self.should_parallelize(a.num_lanes()) {
                        self.add_parallel(a, b)
                    } else {
                        a.add(b)
                    }
                }
                _ => a.add(b),
            }
        }

        #[cfg(not(any(feature = "simd", feature = "parallel")))]
        {
            a.add(b)
        }
    }

    /// Subtract two streams
    pub fn sub_streams(&self, a: &ManaStream, b: &ManaStream) -> ManaStream {
        #[cfg(all(feature = "simd", feature = "parallel"))]
        {
            match self.config.mode {
                ExecutionMode::Sequential => a.sub(b),
                ExecutionMode::Simd => self.sub_simd(a, b),
                ExecutionMode::Parallel => {
                    if self.should_parallelize(a.num_lanes()) {
                        self.sub_parallel(a, b)
                    } else {
                        a.sub(b)
                    }
                }
                ExecutionMode::Full => {
                    if self.should_parallelize(a.num_lanes()) {
                        self.sub_simd_parallel(a, b)
                    } else {
                        self.sub_simd(a, b)
                    }
                }
            }
        }

        #[cfg(all(feature = "simd", not(feature = "parallel")))]
        {
            match self.config.mode {
                ExecutionMode::Simd => self.sub_simd(a, b),
                _ => a.sub(b),
            }
        }

        #[cfg(all(not(feature = "simd"), feature = "parallel"))]
        {
            match self.config.mode {
                ExecutionMode::Parallel => {
                    if self.should_parallelize(a.num_lanes()) {
                        self.sub_parallel(a, b)
                    } else {
                        a.sub(b)
                    }
                }
                _ => a.sub(b),
            }
        }

        #[cfg(not(any(feature = "simd", feature = "parallel")))]
        {
            a.sub(b)
        }
    }

    /// Multiply two streams (coefficient-wise)
    pub fn mul_streams(&self, a: &ManaStream, b: &ManaStream) -> ManaStream {
        match self.config.mode {
            ExecutionMode::Sequential => a.mul(b),

            #[cfg(feature = "parallel")]
            ExecutionMode::Parallel | ExecutionMode::Full => {
                if self.should_parallelize(a.num_lanes()) {
                    self.mul_parallel(a, b)
                } else {
                    a.mul(b)
                }
            }

            _ => a.mul(b),
        }
    }

    // ========================================================================
    // SIMD implementations
    // ========================================================================

    #[cfg(feature = "simd")]
    fn add_simd(&self, a: &ManaStream, b: &ManaStream) -> ManaStream {
        // SIMD module removed, fallback to sequential
        a.add(b)
    }

    #[cfg(feature = "simd")]
    fn sub_simd(&self, a: &ManaStream, b: &ManaStream) -> ManaStream {
        // SIMD module removed, fallback to sequential
        a.sub(b)
    }

    // ========================================================================
    // Parallel implementations
    // ========================================================================

    #[cfg(feature = "parallel")]
    fn add_parallel(&self, a: &ManaStream, b: &ManaStream) -> ManaStream {
        let pa = ParallelStream::new(a.clone());
        let pb = ParallelStream::new(b.clone());
        pa.add_par(&pb).into_inner()
    }

    #[cfg(feature = "parallel")]
    fn sub_parallel(&self, a: &ManaStream, b: &ManaStream) -> ManaStream {
        let pa = ParallelStream::new(a.clone());
        let pb = ParallelStream::new(b.clone());
        pa.sub_par(&pb).into_inner()
    }

    #[cfg(feature = "parallel")]
    fn mul_parallel(&self, a: &ManaStream, b: &ManaStream) -> ManaStream {
        let pa = ParallelStream::new(a.clone());
        let pb = ParallelStream::new(b.clone());
        pa.mul_par(&pb).into_inner()
    }

    // ========================================================================
    // SIMD + Parallel implementations
    // ========================================================================

    #[cfg(all(feature = "simd", feature = "parallel"))]
    fn add_simd_parallel(&self, a: &ManaStream, b: &ManaStream) -> ManaStream {
        let pa = ParallelStream::new(a.clone());
        let pb = ParallelStream::new(b.clone());
        pa.add_par(&pb).into_inner()
    }

    #[cfg(all(feature = "simd", feature = "parallel"))]
    fn sub_simd_parallel(&self, a: &ManaStream, b: &ManaStream) -> ManaStream {
        let pa = ParallelStream::new(a.clone());
        let pb = ParallelStream::new(b.clone());
        pa.sub_par(&pb).into_inner()
    }
}

/// Convenience functions for common operations
impl Accelerator {
    /// Add multiple stream pairs in batch
    pub fn add_batch(&self, pairs: &[(ManaStream, ManaStream)]) -> Vec<ManaStream> {
        pairs.iter().map(|(a, b)| self.add_streams(a, b)).collect()
    }

    /// Chain of additions: sum of all streams
    pub fn sum_streams(&self, streams: &[ManaStream]) -> Option<ManaStream> {
        let mut iter = streams.iter();
        let first = iter.next()?.clone();
        Some(iter.fold(first, |acc, s| self.add_streams(&acc, s)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMES: [u64; 3] = [998244353, 985661441, 754974721];

    #[test]
    fn test_accelerator_auto() {
        let accel = Accelerator::auto();
        let mode = accel.config.mode;

        // Should pick best available
        #[cfg(all(feature = "simd", feature = "parallel"))]
        assert_eq!(mode, ExecutionMode::Full);

        #[cfg(all(feature = "simd", not(feature = "parallel")))]
        assert_eq!(mode, ExecutionMode::Simd);

        #[cfg(all(not(feature = "simd"), feature = "parallel"))]
        assert_eq!(mode, ExecutionMode::Parallel);
    }

    #[test]
    fn test_add_streams() {
        let accel = Accelerator::auto();

        let a = ManaStream::from_ints(&[1, 2, 3, 4], &PRIMES);
        let b = ManaStream::from_ints(&[5, 6, 7, 8], &PRIMES);

        let result = accel.add_streams(&a, &b);

        assert_eq!(result.reconstruct_at(0), 6);
        assert_eq!(result.reconstruct_at(1), 8);
        assert_eq!(result.reconstruct_at(2), 10);
        assert_eq!(result.reconstruct_at(3), 12);
    }

    #[test]
    fn test_sum_streams() {
        let accel = Accelerator::auto();

        let streams: Vec<ManaStream> = (0..5)
            .map(|i| ManaStream::from_ints(&[i * 10, i * 10 + 1], &PRIMES))
            .collect();

        let sum = accel.sum_streams(&streams).unwrap();

        // Sum of 0+10+20+30+40 = 100
        assert_eq!(sum.reconstruct_at(0), 100);
        // Sum of 1+11+21+31+41 = 105
        assert_eq!(sum.reconstruct_at(1), 105);
    }
}
