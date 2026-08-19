//! # Accelerator - Unified Hardware Abstraction
//!
//! **The production hot path is [`Accelerator::run_lanes`].** nine65's
//! per-limb NTT and per-coefficient K-Elimination loops call it directly:
//! UNHAL decides the execution strategy, MANA's dependency-free,
//! deterministic scoped-thread lane executor (`mana::executor`) runs it, and
//! output is bit-identical regardless of thread count or scheduling — see
//! that method's doc comment for the full contract. This does not depend on
//! the `parallel` feature and does not use rayon.
//!
//! The rest of this module — `add_streams`/`sub_streams`/`mul_streams` and
//! the `ExecutionMode`/ `AcceleratorConfig` machinery below — is a separate,
//! older stream-level API with its own dispatch:
//! - **SIMD**: `ExecutionMode::Simd`/`Full` route here, but the SIMD
//!   implementations (`add_simd`, `sub_simd`) are currently dead-code
//!   fallbacks to the sequential path — "the SIMD module removed, fallback
//!   to sequential" per their own bodies. There is no vectorized speedup on
//!   this path today; any prior "4× throughput" claim for it was not
//!   backed by an implementation and should not be repeated.
//! - **Rayon**: `ExecutionMode::Parallel`/`Full` route to
//!   `mana::parallel::ParallelStream`, gated behind the opt-in `parallel`
//!   feature (off by default in this workspace). This is legacy relative to
//!   `run_lanes` and is not the mechanism nine65's hot path uses.
//! - **Sequential**: always available, no dependencies.
//!
//! ## Usage
//!
//! ```ignore
//! use unhal::prelude::*;
//!
//! // Production path: UNHAL decides, MANA executes.
//! let accel = Accelerator::auto();
//! let results = accel.run_lanes(lanes, |lane_idx| compute_lane(lane_idx));
//!
//! // Legacy stream-level API (SIMD path is a no-op fallback; Rayon path
//! // requires the `parallel` feature):
//! let config = AcceleratorConfig::auto_detect();
//! let accel = Accelerator::new(config);
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
    /// Minimum LANE count before lane-level work dispatches to MANA's
    /// deterministic executor. Distinct from `parallel_threshold`, which
    /// was sized for per-stream ELEMENT counts (default 256) — production
    /// FHE tracks carry 8–16 lanes, so gating lane dispatch on the element
    /// threshold meant the parallel path could never engage. Lane dispatch
    /// does not depend on the rayon `parallel` feature: MANA's executor is
    /// dependency-free scoped threads with bit-identical output.
    pub lane_parallel_threshold: usize,
}

impl Default for AcceleratorConfig {
    fn default() -> Self {
        Self {
            mode: ExecutionMode::auto_detect(),
            parallel_threshold: 256,
            num_threads: 0,
            lane_parallel_threshold: 2,
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
            // Sequential means sequential: lane dispatch stays inline too.
            lane_parallel_threshold: usize::MAX,
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

    /// Dispatch `lanes` independent lane computations through the best
    /// available path: MANA's deterministic lane executor when the lane
    /// count clears `lane_parallel_threshold`, inline sequential otherwise.
    ///
    /// This is the UNHAL entry point for the production FHE hot path
    /// (nine65's per-limb NTT and per-coefficient K-Elimination loops).
    /// UNHAL decides the strategy; MANA executes the lanes. Output is
    /// bit-identical for every strategy — MANA's executor pins that
    /// contract in its own tests, and this method adds nothing
    /// data-dependent: the branch below reads only the lane count and
    /// configuration, never lane values.
    pub fn run_lanes<T, F>(&self, lanes: usize, lane_fn: F) -> Vec<T>
    where
        T: Send,
        F: Fn(usize) -> T + Sync,
    {
        if lanes >= self.config.lane_parallel_threshold {
            mana::executor::run_lanes(lanes, lane_fn)
        } else {
            mana::executor::run_lanes_sequential(lanes, lane_fn)
        }
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

    /// UNHAL lane dispatch: auto engages MANA's executor at production lane
    /// counts (8-16), sequential() never does, and both produce bit-identical
    /// output.
    #[test]
    fn lane_dispatch_engages_at_production_lane_counts_and_stays_bit_identical() {
        let auto = Accelerator::auto();
        let seq = Accelerator::new(AcceleratorConfig::sequential());

        assert!(auto.config.lane_parallel_threshold <= 8,
            "auto config must engage at production lane counts (8-16)");
        assert_eq!(seq.config.lane_parallel_threshold, usize::MAX);

        let work = |i: usize| -> Vec<u64> {
            let p = [23u64, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89][i % 16];
            (0..128u64).map(|x| x.wrapping_mul(p).wrapping_add(i as u64) % p).collect()
        };

        for lanes in [1usize, 2, 8, 16] {
            let a = auto.run_lanes(lanes, work);
            let s = seq.run_lanes(lanes, work);
            let r = mana::executor::run_lanes_sequential(lanes, work);
            assert_eq!(a, r, "auto dispatch diverged at {lanes} lanes");
            assert_eq!(s, r, "sequential dispatch diverged at {lanes} lanes");
        }
    }
}
