//! Polynomial Object Pool - Reusable polynomial allocations
//!
//! FHE operations create many temporary polynomials. This pool reduces
//! allocation overhead by reusing previously allocated coefficient vectors.
//!
//! ## Usage
//!
//! ```ignore
//! // Get thread-local pool
//! let pool = PolynomialPool::thread_local();
//!
//! // Acquire polynomial from pool
//! let mut poly = pool.acquire(1024, q);
//!
//! // Use polynomial...
//!
//! // Return to pool when done (happens automatically on drop if using PooledPolynomial)
//! pool.release(poly);
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use zeroize::Zeroize;

/// Object pool for RingPolynomial coefficient vectors
///
/// Maintains a thread-local cache of pre-allocated vectors indexed by size.
/// This significantly reduces allocation overhead in hot paths.
pub struct PolynomialPool {
    /// Cache of available vectors by size (n -> Vec of coefficient buffers)
    cache: HashMap<usize, Vec<Vec<u64>>>,
    /// Maximum vectors to cache per size
    max_per_size: usize,
    /// Statistics: total acquires
    stats_acquires: u64,
    /// Statistics: cache hits
    stats_hits: u64,
}

impl Default for PolynomialPool {
    fn default() -> Self {
        Self::new()
    }
}

impl PolynomialPool {
    /// Create a new polynomial pool
    pub fn new() -> Self {
        Self::with_capacity(16)
    }

    /// Create pool with specified max vectors per size
    pub fn with_capacity(max_per_size: usize) -> Self {
        Self {
            cache: HashMap::new(),
            max_per_size,
            stats_acquires: 0,
            stats_hits: 0,
        }
    }

    /// Get the thread-local pool instance
    pub fn thread_local() -> &'static std::thread::LocalKey<RefCell<PolynomialPool>> {
        thread_local! {
            static POOL: RefCell<PolynomialPool> = RefCell::new(PolynomialPool::new());
        }
        &POOL
    }

    /// Acquire a polynomial buffer of the specified size
    ///
    /// If a cached buffer exists, it is reused (zeroed first).
    /// Otherwise, a new buffer is allocated.
    pub fn acquire(&mut self, n: usize, q: u64) -> PooledPolynomial {
        self.stats_acquires += 1;

        let coeffs = if let Some(cached) = self.cache.get_mut(&n).and_then(|v| v.pop()) {
            self.stats_hits += 1;
            cached
        } else {
            vec![0u64; n]
        };

        PooledPolynomial { coeffs, q }
    }

    /// Acquire and zero-initialize a polynomial buffer
    pub fn acquire_zeroed(&mut self, n: usize, q: u64) -> PooledPolynomial {
        let mut poly = self.acquire(n, q);
        poly.coeffs.iter_mut().for_each(|c| *c = 0);
        poly
    }

    /// Release a polynomial buffer back to the pool
    ///
    /// The buffer is zeroed before caching for security.
    pub fn release(&mut self, mut poly: PooledPolynomial) {
        // Security: zero sensitive data in-place (don't use zeroize which clears the Vec!)
        let n = poly.coeffs.len();
        for c in poly.coeffs.iter_mut() {
            *c = 0;
        }

        let cache = self.cache.entry(n).or_default();
        if cache.len() < self.max_per_size {
            cache.push(poly.coeffs);
        }
        // If cache is full, the vector is dropped (deallocated)
    }

    /// Pre-warm the pool with a specified number of buffers per size
    pub fn prewarm(&mut self, sizes: &[usize], count: usize) {
        for &n in sizes {
            let cache = self.cache.entry(n).or_default();
            while cache.len() < count.min(self.max_per_size) {
                cache.push(vec![0u64; n]);
            }
        }
    }

    /// Clear all cached buffers
    pub fn clear(&mut self) {
        for (_, mut buffers) in self.cache.drain() {
            for buffer in &mut buffers {
                // Zero sensitive data before dropping
                for c in buffer.iter_mut() {
                    *c = 0;
                }
            }
        }
    }

    /// Get cache statistics (acquires, hits)
    pub fn stats(&self) -> (u64, u64) {
        (self.stats_acquires, self.stats_hits)
    }

    /// Get cache hit ratio in permille (0-1000, where 1000 = 100%)
    pub fn hit_ratio_permille(&self) -> u32 {
        if self.stats_acquires == 0 {
            0
        } else {
            ((self.stats_hits as u64 * 1000) / self.stats_acquires as u64) as u32
        }
    }

    /// Total cached buffers across all sizes
    pub fn total_cached(&self) -> usize {
        self.cache.values().map(|v| v.len()).sum()
    }
}

impl Drop for PolynomialPool {
    fn drop(&mut self) {
        self.clear();
    }
}

/// A pooled polynomial with coefficient buffer from the pool
///
/// This is a lightweight wrapper that holds coefficients from the pool.
/// Convert to/from RingPolynomial for operations.
pub struct PooledPolynomial {
    /// Coefficient buffer
    pub coeffs: Vec<u64>,
    /// The modulus
    pub q: u64,
}

impl PooledPolynomial {
    /// Create from existing coefficients (for non-pooled use)
    pub fn from_coeffs(coeffs: Vec<u64>, q: u64) -> Self {
        let reduced: Vec<u64> = coeffs.iter().map(|&c| c % q).collect();
        Self { coeffs: reduced, q }
    }

    /// Get polynomial degree (N)
    pub fn degree(&self) -> usize {
        self.coeffs.len()
    }

    /// Convert to RingPolynomial (takes ownership of coefficients)
    pub fn into_ring_polynomial(self) -> super::RingPolynomial {
        super::RingPolynomial {
            coeffs: self.coeffs,
            q: self.q,
        }
    }

    /// Create from RingPolynomial (takes ownership)
    pub fn from_ring_polynomial(poly: super::RingPolynomial) -> Self {
        Self {
            coeffs: poly.coeffs,
            q: poly.q,
        }
    }
}

impl Zeroize for PooledPolynomial {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

/// RAII guard for automatic pool release
///
/// When dropped, the polynomial is automatically returned to the pool.
pub struct PoolGuard<'a> {
    poly: Option<PooledPolynomial>,
    pool: &'a RefCell<PolynomialPool>,
}

impl<'a> PoolGuard<'a> {
    /// Create a new guard that will release the polynomial on drop
    pub fn new(poly: PooledPolynomial, pool: &'a RefCell<PolynomialPool>) -> Self {
        Self {
            poly: Some(poly),
            pool,
        }
    }

    /// Take ownership of the polynomial (prevents auto-release)
    pub fn take(mut self) -> PooledPolynomial {
        // SAFETY: PoolGuard always contains Some until Drop takes it
        self.poly
            .take()
            .expect("PoolGuard invariant: poly is always Some until drop")
    }
}

impl<'a> AsRef<PooledPolynomial> for PoolGuard<'a> {
    fn as_ref(&self) -> &PooledPolynomial {
        self.poly
            .as_ref()
            .expect("PoolGuard invariant: poly is always Some until drop")
    }
}

impl<'a> AsMut<PooledPolynomial> for PoolGuard<'a> {
    fn as_mut(&mut self) -> &mut PooledPolynomial {
        self.poly
            .as_mut()
            .expect("PoolGuard invariant: poly is always Some until drop")
    }
}

impl Drop for PoolGuard<'_> {
    fn drop(&mut self) {
        if let Some(poly) = self.poly.take() {
            self.pool.borrow_mut().release(poly);
        }
    }
}

/// Helper macro for using the thread-local pool
///
/// Usage:
/// ```ignore
/// with_pool!(|pool| {
///     let poly = pool.acquire(1024, q);
///     // use poly...
///     pool.release(poly);
/// });
/// ```
#[macro_export]
macro_rules! with_pool {
    (|$pool:ident| $body:expr) => {{
        $crate::ring::PolynomialPool::thread_local().with(|cell| {
            let mut $pool = cell.borrow_mut();
            $body
        })
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_acquire_release() {
        let mut pool = PolynomialPool::new();

        // First acquire allocates
        let poly1 = pool.acquire(1024, 998244353);
        assert_eq!(poly1.coeffs.len(), 1024);

        // Release back to pool
        pool.release(poly1);
        assert_eq!(pool.total_cached(), 1);

        // Second acquire reuses
        let poly2 = pool.acquire(1024, 998244353);
        assert_eq!(poly2.coeffs.len(), 1024);
        assert_eq!(pool.stats(), (2, 1)); // 2 acquires, 1 hit
    }

    #[test]
    fn test_pool_zeroing() {
        let mut pool = PolynomialPool::new();

        // Create polynomial with data
        let mut poly = pool.acquire(8, 100);
        poly.coeffs
            .iter_mut()
            .enumerate()
            .for_each(|(i, c)| *c = i as u64 + 1);

        // Release should zero
        pool.release(poly);

        // Acquire again - should be zeroed
        let poly2 = pool.acquire(8, 100);
        assert!(
            poly2.coeffs.iter().all(|&c| c == 0),
            "Buffer should be zeroed"
        );
    }

    #[test]
    fn test_pool_different_sizes() {
        let mut pool = PolynomialPool::new();

        let p512 = pool.acquire(512, 100);
        let p1024 = pool.acquire(1024, 100);
        let p2048 = pool.acquire(2048, 100);

        pool.release(p512);
        pool.release(p1024);
        pool.release(p2048);

        assert_eq!(pool.total_cached(), 3);

        // Acquire specific sizes
        let _ = pool.acquire(1024, 100);
        assert_eq!(pool.total_cached(), 2);
    }

    #[test]
    fn test_pool_max_capacity() {
        let mut pool = PolynomialPool::with_capacity(2);

        // Release 3 polynomials, only 2 should be cached
        for _ in 0..3 {
            let poly = pool.acquire(8, 100);
            pool.release(poly);
        }

        // Only 2 should be cached due to capacity limit
        // (Note: each acquire consumes one from cache if available)
        // After 3 cycles: acquire (miss), release, acquire (hit), release, acquire (hit), release
        // Final state: 2 in cache
        assert!(pool.total_cached() <= 2);
    }

    #[test]
    fn test_pool_prewarm() {
        let mut pool = PolynomialPool::new();
        pool.prewarm(&[512, 1024, 2048], 4);

        assert_eq!(pool.total_cached(), 12); // 3 sizes × 4 each
    }

    #[test]
    fn test_pool_guard_auto_release() {
        let pool_cell = RefCell::new(PolynomialPool::new());

        {
            let poly = pool_cell.borrow_mut().acquire(8, 100);
            let _guard = PoolGuard::new(poly, &pool_cell);
            // guard drops here, releasing polynomial
        }

        assert_eq!(pool_cell.borrow().total_cached(), 1);
    }

    #[test]
    fn test_pool_guard_take() {
        let pool_cell = RefCell::new(PolynomialPool::new());

        let poly = {
            let poly = pool_cell.borrow_mut().acquire(8, 100);
            let guard = PoolGuard::new(poly, &pool_cell);
            guard.take() // Takes ownership, prevents auto-release
        };

        // Not released to pool
        assert_eq!(pool_cell.borrow().total_cached(), 0);

        // Manual release
        pool_cell.borrow_mut().release(poly);
        assert_eq!(pool_cell.borrow().total_cached(), 1);
    }

    #[test]
    fn test_pooled_polynomial_conversion() {
        let pooled = PooledPolynomial::from_coeffs(vec![1, 2, 3, 4], 100);
        let ring = pooled.into_ring_polynomial();

        assert_eq!(ring.coeffs, vec![1, 2, 3, 4]);
        assert_eq!(ring.q, 100);

        let back = PooledPolynomial::from_ring_polynomial(ring);
        assert_eq!(back.coeffs, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_thread_local_pool() {
        PolynomialPool::thread_local().with(|cell| {
            let mut pool = cell.borrow_mut();
            let poly = pool.acquire(64, 100);
            pool.release(poly);
            assert_eq!(pool.total_cached(), 1);
        });
    }

    #[test]
    fn test_hit_ratio() {
        let mut pool = PolynomialPool::new();

        // First acquire is a miss
        let p1 = pool.acquire(8, 100);
        assert_eq!(pool.hit_ratio_permille(), 0);

        pool.release(p1);

        // Second acquire is a hit
        let p2 = pool.acquire(8, 100);
        assert_eq!(pool.stats(), (2, 1));
        // 1 hit / 2 acquires = 500 permille
        assert_eq!(pool.hit_ratio_permille(), 500);

        pool.release(p2);
    }
}
