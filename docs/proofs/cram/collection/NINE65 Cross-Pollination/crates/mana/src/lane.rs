//! # Lane - Single CRT Prime Modulus Channel
//!
//! A Lane represents coefficients under a single prime modulus.
//! Operations within a lane are embarrassingly parallel - no carry propagation.
//!
//! ## Performance
//!
//! - Add/Sub: O(N) branchless for LLVM auto-vectorization
//! - Mul: O(N) modular multiply with u128 intermediate
//! - No dependencies between coefficients = perfect ILP

use std::sync::Arc;
use zeroize::Zeroize;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// A single CRT lane: coefficients mod a prime
#[derive(Clone, Debug, Zeroize)]
pub struct Lane {
    /// Coefficients in this lane
    pub coeffs: Vec<u64>,
    /// The prime modulus for this lane
    pub prime: u64,
    /// Precomputed: prime - 1 (for fast negation check)
    prime_m1: u64,
}

impl Lane {
    /// Create a new lane with given prime and size
    #[inline]
    pub fn new(prime: u64, size: usize) -> Self {
        debug_assert!(prime > 1, "Prime must be > 1");
        Self {
            coeffs: vec![0; size],
            prime,
            prime_m1: prime - 1,
        }
    }

    /// Create from existing coefficients
    #[inline]
    pub fn from_coeffs(coeffs: Vec<u64>, prime: u64) -> Self {
        Self {
            coeffs,
            prime,
            prime_m1: prime - 1,
        }
    }

    /// Create from integer, reducing each coefficient mod prime
    #[inline]
    pub fn from_int_slice(values: &[u64], prime: u64) -> Self {
        let coeffs = values.iter().map(|&v| v % prime).collect();
        Self::from_coeffs(coeffs, prime)
    }

    /// Number of coefficients
    #[inline]
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    /// Is empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }

    /// Get prime modulus
    #[inline]
    pub fn prime(&self) -> u64 {
        self.prime
    }
}

/// Lane operations trait - enables SIMD dispatch
pub trait LaneOps {
    /// Add two lanes coefficient-wise
    fn add(&self, other: &Self) -> Self;

    /// Subtract two lanes coefficient-wise
    fn sub(&self, other: &Self) -> Self;

    /// Negate all coefficients
    fn neg(&self) -> Self;

    /// Multiply two lanes coefficient-wise (Hadamard product)
    fn mul(&self, other: &Self) -> Self;

    /// Scalar multiply all coefficients
    fn scalar_mul(&self, scalar: u64) -> Self;

    /// Add scalar to all coefficients
    fn scalar_add(&self, scalar: u64) -> Self;
}

/// Branchless modular add: (a + b) mod q
/// Uses conditional move pattern for LLVM auto-vectorization
#[inline(always)]
fn mod_add(a: u64, b: u64, q: u64) -> u64 {
    let sum = a + b;
    // Branchless: subtract q if sum >= q
    sum.wrapping_sub(q * ((sum >= q) as u64))
}

/// Branchless modular sub: (a - b) mod q
#[inline(always)]
fn mod_sub(a: u64, b: u64, q: u64) -> u64 {
    // Branchless: add q if a < b
    a.wrapping_sub(b).wrapping_add(q * ((a < b) as u64))
}

impl LaneOps for Lane {
    #[inline]
    fn add(&self, other: &Self) -> Self {
        debug_assert_eq!(self.prime, other.prime);
        debug_assert_eq!(self.len(), other.len());

        let q = self.prime;
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| mod_add(a, b, q))
            .collect();

        Self::from_coeffs(coeffs, q)
    }

    #[inline]
    fn sub(&self, other: &Self) -> Self {
        debug_assert_eq!(self.prime, other.prime);
        debug_assert_eq!(self.len(), other.len());

        let q = self.prime;
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| mod_sub(a, b, q))
            .collect();

        Self::from_coeffs(coeffs, q)
    }

    #[inline]
    fn neg(&self) -> Self {
        let q = self.prime;
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .map(|&a| {
                // Branchless: q - a if a != 0, else 0
                (q - a) * ((a != 0) as u64)
            })
            .collect();

        Self::from_coeffs(coeffs, q)
    }

    #[inline]
    fn mul(&self, other: &Self) -> Self {
        debug_assert_eq!(self.prime, other.prime);
        debug_assert_eq!(self.len(), other.len());

        let q = self.prime as u128;
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| ((a as u128 * b as u128) % q) as u64)
            .collect();

        Self::from_coeffs(coeffs, self.prime)
    }

    #[inline]
    fn scalar_mul(&self, scalar: u64) -> Self {
        let q = self.prime as u128;
        let s = (scalar % self.prime) as u128;
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .map(|&a| ((a as u128 * s) % q) as u64)
            .collect();

        Self::from_coeffs(coeffs, self.prime)
    }

    #[inline]
    fn scalar_add(&self, scalar: u64) -> Self {
        let q = self.prime;
        let s = scalar % q;
        let coeffs: Vec<u64> = self.coeffs.iter().map(|&a| mod_add(a, s, q)).collect();

        Self::from_coeffs(coeffs, q)
    }
}

/// Parallel lane operations - coefficient-level parallelism within a single lane
#[cfg(feature = "parallel")]
impl Lane {
    /// Parallel add for large lanes (N >= 4096)
    /// Uses Rayon to parallelize coefficient operations
    #[inline]
    pub fn add_par(&self, other: &Self) -> Self {
        debug_assert_eq!(self.prime, other.prime);
        debug_assert_eq!(self.len(), other.len());

        let q = self.prime;
        let coeffs: Vec<u64> = self
            .coeffs
            .par_iter()
            .zip(other.coeffs.par_iter())
            .map(|(&a, &b)| mod_add(a, b, q))
            .collect();

        Self::from_coeffs(coeffs, q)
    }

    /// Parallel subtract
    #[inline]
    pub fn sub_par(&self, other: &Self) -> Self {
        debug_assert_eq!(self.prime, other.prime);
        debug_assert_eq!(self.len(), other.len());

        let q = self.prime;
        let coeffs: Vec<u64> = self
            .coeffs
            .par_iter()
            .zip(other.coeffs.par_iter())
            .map(|(&a, &b)| mod_sub(a, b, q))
            .collect();

        Self::from_coeffs(coeffs, q)
    }

    /// Parallel multiply
    #[inline]
    pub fn mul_par(&self, other: &Self) -> Self {
        debug_assert_eq!(self.prime, other.prime);
        debug_assert_eq!(self.len(), other.len());

        let q = self.prime as u128;
        let coeffs: Vec<u64> = self
            .coeffs
            .par_iter()
            .zip(other.coeffs.par_iter())
            .map(|(&a, &b)| ((a as u128 * b as u128) % q) as u64)
            .collect();

        Self::from_coeffs(coeffs, self.prime)
    }
}

/// Montgomery context for fast modular reduction within a lane
#[derive(Clone, Debug)]
pub struct MontgomeryLane {
    /// The prime modulus
    pub q: u64,
    /// R = 2^64 mod q (Montgomery R)
    pub r: u64,
    /// R^2 mod q (for conversion to Montgomery form)
    pub r2: u64,
    /// -q^(-1) mod 2^64 (Montgomery constant)
    pub q_inv_neg: u64,
}

impl MontgomeryLane {
    /// Create Montgomery context for a prime
    pub fn new(q: u64) -> Self {
        let r = Self::compute_r(q);
        let r2 = Self::compute_r2(q);
        let q_inv_neg = Self::compute_q_inv_neg(q);

        Self {
            q,
            r,
            r2,
            q_inv_neg,
        }
    }

    fn compute_r(q: u64) -> u64 {
        // R = 2^64 mod q
        let r_big = 1u128 << 64;
        (r_big % q as u128) as u64
    }

    fn compute_r2(q: u64) -> u64 {
        // R^2 mod q
        let r = Self::compute_r(q) as u128;
        let r2 = (r * r) % q as u128;
        r2 as u64
    }

    fn compute_q_inv_neg(q: u64) -> u64 {
        // -q^(-1) mod 2^64 using Newton's method
        let mut inv: u64 = 1;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(q.wrapping_mul(inv)));
        }
        inv.wrapping_neg()
    }

    /// Convert to Montgomery form: aR mod q
    #[inline]
    pub fn to_mont(&self, a: u64) -> u64 {
        self.mont_mul(a, self.r2)
    }

    /// Convert from Montgomery form: a/R mod q
    #[inline]
    pub fn from_mont(&self, a: u64) -> u64 {
        self.mont_reduce(a as u128)
    }

    /// Montgomery multiplication: ab/R mod q
    #[inline]
    pub fn mont_mul(&self, a: u64, b: u64) -> u64 {
        self.mont_reduce(a as u128 * b as u128)
    }

    /// Montgomery reduction: t/R mod q
    #[inline]
    fn mont_reduce(&self, t: u128) -> u64 {
        let m = (t as u64).wrapping_mul(self.q_inv_neg);
        let t = (t + m as u128 * self.q as u128) >> 64;
        let result = t as u64;
        if result >= self.q {
            result - self.q
        } else {
            result
        }
    }
}

// =============================================================================
// PERSISTENT LANE - Coefficients NEVER leave Montgomery form
// =============================================================================

/// Persistent Lane: ALL coefficients in Montgomery form ⊗
///
/// Traditional approach (70 years of overhead):
///   to_mont(x) → compute → compute → from_mont(result)
///
/// Persistent Lane:
///   ⊗ coeffs stay in Montgomery form FOREVER
///   Only convert at TRUE I/O boundaries
///
/// Performance: Eliminates N-1 conversions for N operations
/// Uses Arc<MontgomeryLane> to avoid cloning 32 bytes per operation
#[derive(Clone, Debug)]
pub struct PersistentLane {
    /// Coefficients in Montgomery form (⊗)
    pub coeffs: Vec<u64>,
    /// Montgomery context (shared via Arc - no clone overhead)
    pub mont: Arc<MontgomeryLane>,
}

impl PersistentLane {
    /// Create from standard coefficients (converts to ⊗ form ONCE)
    pub fn from_standard(coeffs: &[u64], q: u64) -> Self {
        let mont = Arc::new(MontgomeryLane::new(q));
        let mont_coeffs: Vec<u64> = coeffs.iter().map(|&c| mont.to_mont(c % q)).collect();
        Self {
            coeffs: mont_coeffs,
            mont,
        }
    }

    /// Create from coefficients already in Montgomery form
    pub fn from_montgomery(coeffs: Vec<u64>, mont: MontgomeryLane) -> Self {
        Self {
            coeffs,
            mont: Arc::new(mont),
        }
    }

    /// Create from coefficients with shared Arc context
    pub fn from_montgomery_arc(coeffs: Vec<u64>, mont: Arc<MontgomeryLane>) -> Self {
        Self { coeffs, mont }
    }

    /// Create zero lane in Montgomery form
    pub fn zero(n: usize, q: u64) -> Self {
        let mont = Arc::new(MontgomeryLane::new(q));
        Self {
            coeffs: vec![0; n],
            mont,
        } // 0 in standard = 0 in Montgomery
    }

    /// Number of coefficients
    #[inline]
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    /// Is empty?
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }

    /// Get prime modulus
    #[inline]
    pub fn prime(&self) -> u64 {
        self.mont.q
    }

    // =========================================================================
    // PERSISTENT OPERATIONS - Never leave ⊗ form!
    // =========================================================================

    /// ⊗ Add: stays in Montgomery form
    #[inline]
    pub fn add(&self, other: &Self) -> Self {
        debug_assert_eq!(self.mont.q, other.mont.q);
        let q = self.mont.q;
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| {
                let sum = a + b;
                if sum >= q {
                    sum - q
                } else {
                    sum
                }
            })
            .collect();
        Self {
            coeffs,
            mont: Arc::clone(&self.mont),
        }
    }

    /// ⊗ Subtract: stays in Montgomery form
    #[inline]
    pub fn sub(&self, other: &Self) -> Self {
        debug_assert_eq!(self.mont.q, other.mont.q);
        let q = self.mont.q;
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| if a >= b { a - b } else { q - b + a })
            .collect();
        Self {
            coeffs,
            mont: Arc::clone(&self.mont),
        }
    }

    /// ⊗ Negate: stays in Montgomery form
    #[inline]
    pub fn neg(&self) -> Self {
        let q = self.mont.q;
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .map(|&a| if a == 0 { 0 } else { q - a })
            .collect();
        Self {
            coeffs,
            mont: Arc::clone(&self.mont),
        }
    }

    /// ⊗ Multiply: Montgomery mul, result stays in ⊗ form
    /// This is the KEY operation - no conversion overhead!
    #[inline]
    pub fn mul(&self, other: &Self) -> Self {
        debug_assert_eq!(self.mont.q, other.mont.q);
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(&a, &b)| self.mont.mont_mul(a, b))
            .collect();
        Self {
            coeffs,
            mont: Arc::clone(&self.mont),
        }
    }

    /// ⊗ Scalar multiply (scalar must be in Montgomery form)
    #[inline]
    pub fn scalar_mul(&self, scalar_mont: u64) -> Self {
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .map(|&c| self.mont.mont_mul(c, scalar_mont))
            .collect();
        Self {
            coeffs,
            mont: Arc::clone(&self.mont),
        }
    }

    /// ⊗ Square all coefficients
    #[inline]
    pub fn square(&self) -> Self {
        let coeffs: Vec<u64> = self
            .coeffs
            .iter()
            .map(|&a| self.mont.mont_mul(a, a))
            .collect();
        Self {
            coeffs,
            mont: Arc::clone(&self.mont),
        }
    }

    // =========================================================================
    // BOUNDARY OPERATIONS - Only at TRUE I/O!
    // =========================================================================

    /// Convert to standard form (only at output!)
    pub fn to_standard(&self) -> Vec<u64> {
        self.coeffs
            .iter()
            .map(|&c| self.mont.from_mont(c))
            .collect()
    }

    /// Convert to Lane (exits Montgomery form)
    pub fn to_lane(&self) -> Lane {
        Lane::from_coeffs(self.to_standard(), self.mont.q)
    }

    /// Convert one coefficient to standard form
    #[inline]
    pub fn get_standard(&self, i: usize) -> u64 {
        self.mont.from_mont(self.coeffs[i])
    }
}

/// Parallel Persistent Lane operations
#[cfg(feature = "parallel")]
impl PersistentLane {
    /// ⊗ Parallel add
    #[inline]
    pub fn add_par(&self, other: &Self) -> Self {
        debug_assert_eq!(self.mont.q, other.mont.q);
        let q = self.mont.q;
        let coeffs: Vec<u64> = self
            .coeffs
            .par_iter()
            .zip(other.coeffs.par_iter())
            .map(|(&a, &b)| {
                let sum = a + b;
                if sum >= q {
                    sum - q
                } else {
                    sum
                }
            })
            .collect();
        Self {
            coeffs,
            mont: Arc::clone(&self.mont),
        }
    }

    /// ⊗ Parallel multiply - the money operation
    #[inline]
    pub fn mul_par(&self, other: &Self) -> Self {
        debug_assert_eq!(self.mont.q, other.mont.q);
        let mont = &self.mont;
        let coeffs: Vec<u64> = self
            .coeffs
            .par_iter()
            .zip(other.coeffs.par_iter())
            .map(|(&a, &b)| mont.mont_mul(a, b))
            .collect();
        Self {
            coeffs,
            mont: Arc::clone(&self.mont),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 998244353;

    #[test]
    fn test_lane_add() {
        let a = Lane::from_coeffs(vec![1, 2, 3, 4], TEST_PRIME);
        let b = Lane::from_coeffs(vec![5, 6, 7, 8], TEST_PRIME);
        let c = a.add(&b);
        assert_eq!(c.coeffs, vec![6, 8, 10, 12]);
    }

    #[test]
    fn test_lane_sub() {
        let a = Lane::from_coeffs(vec![10, 20, 30, 40], TEST_PRIME);
        let b = Lane::from_coeffs(vec![3, 5, 7, 9], TEST_PRIME);
        let c = a.sub(&b);
        assert_eq!(c.coeffs, vec![7, 15, 23, 31]);
    }

    #[test]
    fn test_lane_sub_wrap() {
        let a = Lane::from_coeffs(vec![1], TEST_PRIME);
        let b = Lane::from_coeffs(vec![5], TEST_PRIME);
        let c = a.sub(&b);
        assert_eq!(c.coeffs, vec![TEST_PRIME - 4]);
    }

    #[test]
    fn test_lane_mul() {
        let a = Lane::from_coeffs(vec![2, 3, 4], TEST_PRIME);
        let b = Lane::from_coeffs(vec![5, 6, 7], TEST_PRIME);
        let c = a.mul(&b);
        assert_eq!(c.coeffs, vec![10, 18, 28]);
    }

    #[test]
    fn test_lane_neg() {
        let a = Lane::from_coeffs(vec![0, 1, TEST_PRIME - 1], TEST_PRIME);
        let b = a.neg();
        assert_eq!(b.coeffs, vec![0, TEST_PRIME - 1, 1]);
    }

    #[test]
    fn test_montgomery_roundtrip() {
        let mont = MontgomeryLane::new(TEST_PRIME);

        for &x in &[0u64, 1, 42, 12345, TEST_PRIME - 1] {
            let m = mont.to_mont(x);
            let back = mont.from_mont(m);
            assert_eq!(back, x, "Montgomery roundtrip failed for {}", x);
        }
    }

    #[test]
    fn test_montgomery_mul() {
        let mont = MontgomeryLane::new(TEST_PRIME);

        let a = 12345u64;
        let b = 67890u64;
        let expected = ((a as u128 * b as u128) % TEST_PRIME as u128) as u64;

        let a_mont = mont.to_mont(a);
        let b_mont = mont.to_mont(b);
        let c_mont = mont.mont_mul(a_mont, b_mont);
        let c = mont.from_mont(c_mont);

        assert_eq!(c, expected);
    }

    // =========================================================================
    // PERSISTENT LANE TESTS
    // =========================================================================

    #[test]
    fn test_persistent_lane_add() {
        let a = PersistentLane::from_standard(&[1, 2, 3, 4], TEST_PRIME);
        let b = PersistentLane::from_standard(&[5, 6, 7, 8], TEST_PRIME);
        let c = a.add(&b);

        // Convert back to verify
        assert_eq!(c.to_standard(), vec![6, 8, 10, 12]);
    }

    #[test]
    fn test_persistent_lane_mul() {
        let a = PersistentLane::from_standard(&[2, 3, 4], TEST_PRIME);
        let b = PersistentLane::from_standard(&[5, 6, 7], TEST_PRIME);
        let c = a.mul(&b);

        // 2*5=10, 3*6=18, 4*7=28
        assert_eq!(c.to_standard(), vec![10, 18, 28]);
    }

    #[test]
    fn test_persistent_lane_chain() {
        // Key test: chain of ops WITHOUT intermediate conversions
        let a = PersistentLane::from_standard(&[10, 20, 30], TEST_PRIME);
        let b = PersistentLane::from_standard(&[2, 3, 4], TEST_PRIME);

        // (a + b) * a - stays in Montgomery form throughout
        let sum = a.add(&b); // [12, 23, 34]
        let prod = sum.mul(&a); // [120, 460, 1020]
        let result = prod.sub(&b); // [118, 457, 1016]

        assert_eq!(result.to_standard(), vec![118, 457, 1016]);
    }

    #[test]
    fn test_persistent_vs_regular_mul() {
        // Compare persistent vs regular multiplication
        let vals_a: Vec<u64> = (1..=100).collect();
        let vals_b: Vec<u64> = (101..=200).collect();

        // Regular lane
        let lane_a = Lane::from_coeffs(vals_a.clone(), TEST_PRIME);
        let lane_b = Lane::from_coeffs(vals_b.clone(), TEST_PRIME);
        let lane_result = lane_a.mul(&lane_b);

        // Persistent lane
        let pers_a = PersistentLane::from_standard(&vals_a, TEST_PRIME);
        let pers_b = PersistentLane::from_standard(&vals_b, TEST_PRIME);
        let pers_result = pers_a.mul(&pers_b);

        // Results should match
        assert_eq!(pers_result.to_standard(), lane_result.coeffs);
    }

    #[test]
    fn test_persistent_lane_benchmark() {
        // Quick benchmark: 1000 chained multiplications
        let a = PersistentLane::from_standard(&[12345; 1024], TEST_PRIME);
        let b = PersistentLane::from_standard(&[67890; 1024], TEST_PRIME);

        let start = std::time::Instant::now();
        let mut result = a.clone();
        for _ in 0..1000 {
            result = result.mul(&b);
        }
        let persistent_time = start.elapsed();

        // Verify result is valid
        let sample = result.get_standard(0);
        assert!(sample < TEST_PRIME);

        println!("Persistent 1000 muls (N=1024): {:?}", persistent_time);
    }
}
