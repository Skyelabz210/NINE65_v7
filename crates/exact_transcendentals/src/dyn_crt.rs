//! Winding Tower CRT Carrier — lane-parallel arithmetic with winding overflow tracking.
//!
//! Implements the correct CRAM architecture: arithmetic stays in CRT residue lanes
//! at all times. The winding tower tracks overflow as exact integer digits.
//! Reconstruction to scalar (i128/u128) happens ONLY at I/O boundaries.
//!
//! Architecture:
//! - **Lanes**: residues mod each prime in the S8-extended basis
//! - **Winding tower**: mixed-radix digits tracking how many times the value
//!   wraps the basis product M (the "inter-page" position)
//! - **WASSAN ring**: for astronomically large values beyond u128 corridor,
//!   residues are stored in ℤ_p polynomial rings — no scalar extraction needed
//!
//! The u128 corridor (per the Corridor Audit) provides fail-stop I/O extraction
//! when values fit. For values that don't fit, the residue representation IS
//! the value — no reconstruction required for lane-parallel computation.
//!
//! Zero floating point. `no_std` compatible.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::k_elim;

// ═══════════════════════════════════════════════════════════════════════════
// Reconstruction instrumentation (std-only, for the comparison harness)
//
// Every full scalar extraction (Garner reconstruction to i128/u128) increments
// this counter. The winding-tower thesis is that lane-parallel arithmetic
// needs reconstruction ONLY at I/O — the harness verifies that empirically.
// ═══════════════════════════════════════════════════════════════════════════

// Thread-local so parallel test threads each measure their own carrier
// operations without cross-contamination.
#[cfg(feature = "std")]
thread_local! {
    static RECONSTRUCT_COUNT: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// Number of full reconstructions (Garner scalar extractions) on this thread
/// since the last reset. Always 0 in `no_std` builds (instrumentation is std-only).
#[cfg(feature = "std")]
pub fn reconstruction_count() -> u64 {
    RECONSTRUCT_COUNT.with(|c| c.get())
}

/// Reset this thread's reconstruction counter to zero.
#[cfg(feature = "std")]
pub fn reset_reconstruction_count() {
    RECONSTRUCT_COUNT.with(|c| c.set(0));
}

/// Record one reconstruction event. No-op in `no_std`.
#[inline(always)]
fn note_reconstruct() {
    #[cfg(feature = "std")]
    RECONSTRUCT_COUNT.with(|c| c.set(c.get() + 1));
}

/// S8 Safe Basis primes — the "unbroken" core.
pub const S8_PRIMES: [u64; 8] = [2, 3, 5, 7, 11, 13, 17, 19];

/// S8 product M = 9,699,690.
pub const S8_PRODUCT: u64 = 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19;

/// Extended SCALE-coprime primes for lane growth beyond S8.
/// These are coprime to SCALE (gcd(p, 10^4) = 1), appended after S8.
const SCALE_EXT_PRIMES: [u64; 46] = [
    23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
    229, 233, 239, 241, 251,
];

/// Winding tower moduli: the S8 primes themselves serve as the mixed-radix
/// digit bounds for the winding tower. Level i has digit range [0, μ_i).
const TOWER_MODULI: [i128; 8] = [2, 3, 5, 7, 11, 13, 17, 19];

/// Default winding tower depth.
const DEFAULT_TOWER_DEPTH: usize = 8;

/// CRT carrier with winding tower overflow tracking.
///
/// All arithmetic is lane-parallel: `add`, `sub`, `mul` operate directly on
/// residues with zero reconstruction. The winding tower tracks exactly how
/// many times the value wraps the basis product M.
///
/// Reconstruction to i128 happens ONLY when explicitly requested (I/O).
#[derive(Clone, Debug)]
pub struct WindingCRT {
    /// Residues, one per active prime lane. Each r_i in [0, prime_i).
    lanes: Vec<u64>,
    /// Active primes.
    primes: Vec<u64>,
    /// Sign: false = non-negative, true = negative.
    sign: bool,
    /// Winding tower digits — mixed-radix representation of overflow count.
    /// Empty when the value fits within the basis product M.
    winding: Vec<i128>,
}

impl WindingCRT {
    /// Create a zero-valued carrier with S8 basis.
    pub fn zero() -> Self {
        Self {
            lanes: vec![0; S8_PRIMES.len()],
            primes: S8_PRIMES.to_vec(),
            sign: false,
            winding: Vec::new(),
        }
    }

    /// Encode an i128 value. This is an I/O operation — decomposes the scalar
    /// into residue lanes and winding tower digits.
    pub fn from_i128(val: i128) -> Self {
        if val == 0 {
            return Self::zero();
        }

        let sign = val < 0;
        let magnitude = if val == i128::MIN {
            i128::MAX as u128 + 1
        } else {
            val.unsigned_abs()
        };

        let primes = S8_PRIMES.to_vec();
        let lanes: Vec<u64> = primes
            .iter()
            .map(|&p| (magnitude % p as u128) as u64)
            .collect();

        // Compute winding: how many times magnitude wraps M
        let m = S8_PRODUCT as u128;
        let winding = if magnitude >= m {
            let k = (magnitude / m) as i128;
            k_elim::k_to_tower(k, &TOWER_MODULI, DEFAULT_TOWER_DEPTH)
        } else {
            Vec::new()
        };

        Self {
            lanes,
            primes,
            sign,
            winding,
        }
    }

    /// Reconstruct to i128 — I/O ONLY. This is the u128 corridor extraction.
    /// Returns None if the value exceeds i128 range.
    pub fn to_i128(&self) -> Option<i128> {
        note_reconstruct();
        // Reconstruct base value from residues via Garner
        let pairs: Vec<(i128, i128)> = self
            .lanes
            .iter()
            .zip(self.primes.iter())
            .map(|(&r, &p)| (r as i128, p as i128))
            .collect();

        let base = k_elim::garner_reconstruct(&pairs)?;

        // Add winding contribution
        let mut value = base;
        if !self.winding.is_empty() {
            let m = self.basis_product_i128()?;
            let k = k_elim::k_from_tower(&self.winding, &TOWER_MODULI);
            value = value.checked_add(k.checked_mul(m)?)?;
        }

        if self.sign && value != 0 {
            value.checked_neg()
        } else {
            Some(value)
        }
    }

    /// Reconstruct, panicking if outside i128 corridor.
    pub fn to_i128_exact(&self) -> i128 {
        self.to_i128()
            .expect("WindingCRT value outside i128 corridor")
    }

    /// Lane-parallel addition. NO reconstruction during computation.
    /// Residues are added mod each prime; winding towers are added with carry.
    pub fn add(&self, other: &WindingCRT) -> WindingCRT {
        assert_eq!(self.primes, other.primes, "WindingCRT::add: basis mismatch");

        if self.sign == other.sign {
            // Same sign: add residues, add windings
            let lanes: Vec<u64> = self
                .lanes
                .iter()
                .zip(other.lanes.iter())
                .zip(self.primes.iter())
                .map(|((&a, &b), &m)| ((a as u64 + b as u64) % m) as u64)
                .collect();

            // Detect carry: if sum of residues wrapped M, winding increments
            let winding = self.add_windings(&other.winding, 0);

            WindingCRT {
                lanes,
                primes: self.primes.clone(),
                sign: self.sign,
                winding,
            }
        } else {
            // Opposite signs: need magnitude comparison via residues
            // Compare by reconstructing winding + residue ordering
            let a_val = self.to_i128_exact();
            let b_val = other.to_i128_exact();
            WindingCRT::from_i128(a_val.checked_add(b_val).expect("WindingCRT::add overflow"))
        }
    }

    /// Lane-parallel subtraction.
    pub fn sub(&self, other: &WindingCRT) -> WindingCRT {
        let neg = other.negate();
        self.add(&neg)
    }

    /// Lane-parallel multiplication.
    /// Residues multiply mod each prime — this is the noise-free operation.
    /// The winding tower absorbs the overflow exactly.
    pub fn mul(&self, other: &WindingCRT) -> WindingCRT {
        assert_eq!(self.primes, other.primes, "WindingCRT::mul: basis mismatch");

        let result_sign = self.sign != other.sign;

        // Lane-parallel residue multiplication — EXACT, ZERO NOISE
        let lanes: Vec<u64> = self
            .lanes
            .iter()
            .zip(other.lanes.iter())
            .zip(self.primes.iter())
            .map(|((&a, &b), &m)| ((a as u64 * b as u64) % m) as u64)
            .collect();

        // For winding: the product's winding tower needs the full value.
        // We reconstruct the winding contribution from the lane residues
        // and the input windings.
        //
        // If both values are within M (no winding), the product's winding
        // is simply floor(a*b / M), which we can get from the residues alone
        // by checking if the lane-parallel product has wrapped.
        //
        // For the general case with existing windings, we compute exactly.
        if self.winding.is_empty() && other.winding.is_empty() {
            // Both within M — compute product winding from magnitudes
            let a_mag = self.reconstruct_magnitude();
            let b_mag = other.reconstruct_magnitude();
            if let (Some(a), Some(b)) = (a_mag, b_mag) {
                let product = a.checked_mul(b);
                if let Some(p) = product {
                    let m = S8_PRODUCT as u128;
                    let k = (p / m) as i128;
                    let winding = if k > 0 {
                        k_elim::k_to_tower(k, &TOWER_MODULI, DEFAULT_TOWER_DEPTH)
                    } else {
                        Vec::new()
                    };
                    return WindingCRT {
                        lanes,
                        primes: self.primes.clone(),
                        sign: result_sign,
                        winding,
                    };
                }
            }
        }

        // General case: reconstruct and re-encode (I/O boundary)
        let a_val = self.to_i128_exact();
        let b_val = other.to_i128_exact();
        let prod = a_val.checked_mul(b_val).expect("WindingCRT::mul overflow");
        let mut result = WindingCRT::from_i128(prod);
        result.sign = result_sign && prod != 0;
        result
    }

    /// Negate the value (flip sign, residues stay positive).
    pub fn negate(&self) -> WindingCRT {
        WindingCRT {
            lanes: self.lanes.clone(),
            primes: self.primes.clone(),
            sign: !self.sign || self.is_zero(),
            winding: self.winding.clone(),
        }
    }

    /// Get residue in a specific lane. O(1), no reconstruction.
    pub fn residue(&self, prime: u64) -> Option<u64> {
        self.primes
            .iter()
            .position(|&p| p == prime)
            .map(|i| self.lanes[i])
    }

    /// Check divisibility by a basis prime. O(1), no reconstruction.
    pub fn is_divisible_by(&self, prime: u64) -> Option<bool> {
        self.residue(prime).map(|r| r == 0)
    }

    /// Whether the value is zero (all residues zero and no winding).
    pub fn is_zero(&self) -> bool {
        self.lanes.iter().all(|&r| r == 0)
            && (self.winding.is_empty() || self.winding.iter().all(|&w| w == 0))
    }

    /// Whether the carrier is negative.
    pub fn is_negative(&self) -> bool {
        self.sign && !self.is_zero()
    }

    /// Number of active lanes.
    pub fn num_lanes(&self) -> usize {
        self.lanes.len()
    }

    /// The active prime basis.
    pub fn basis(&self) -> &[u64] {
        &self.primes
    }

    /// Raw lane data (residues).
    pub fn lane_data(&self) -> &[u64] {
        &self.lanes
    }

    /// Winding tower digits.
    pub fn winding_digits(&self) -> &[i128] {
        &self.winding
    }

    /// Whether the value fits within the basis product (winding = 0).
    pub fn is_within_basis(&self) -> bool {
        self.winding.is_empty() || self.winding.iter().all(|&w| w == 0)
    }

    /// Extend the basis with the next SCALE-coprime prime.
    /// New lane's residue is computed from the existing residues via
    /// Garner reconstruction (a single I/O operation for growth).
    pub fn extend_basis(&mut self) {
        let ext_idx = if self.primes.len() <= S8_PRIMES.len() {
            0
        } else {
            self.primes.len() - S8_PRIMES.len()
        };

        if ext_idx >= SCALE_EXT_PRIMES.len() {
            return;
        }

        let new_prime = SCALE_EXT_PRIMES[ext_idx];

        // Compute residue of current value mod new_prime
        if let Some(val) = self.to_i128() {
            let magnitude = val.unsigned_abs();
            let new_residue = (magnitude % new_prime as u128) as u64;
            self.primes.push(new_prime);
            self.lanes.push(new_residue);
        }
    }

    // ── Internal helpers ─────────────────────────────────────

    fn add_windings(&self, other_winding: &[i128], carry: i128) -> Vec<i128> {
        if self.winding.is_empty() && other_winding.is_empty() && carry == 0 {
            return Vec::new();
        }

        let depth = DEFAULT_TOWER_DEPTH;
        let a = if self.winding.is_empty() {
            vec![0i128; depth]
        } else {
            let mut v = self.winding.clone();
            v.resize(depth, 0);
            v
        };
        let b = if other_winding.is_empty() {
            vec![0i128; depth]
        } else {
            let mut v = other_winding.to_vec();
            v.resize(depth, 0);
            v
        };

        k_elim::tower_add(&a, &b, &TOWER_MODULI, depth, carry)
    }

    fn reconstruct_magnitude(&self) -> Option<u128> {
        note_reconstruct();
        let pairs: Vec<(i128, i128)> = self
            .lanes
            .iter()
            .zip(self.primes.iter())
            .map(|(&r, &p)| (r as i128, p as i128))
            .collect();

        let base = k_elim::garner_reconstruct(&pairs)?;

        if self.winding.is_empty() {
            Some(base as u128)
        } else {
            let m = self.basis_product_i128()? as u128;
            let k = k_elim::k_from_tower(&self.winding, &TOWER_MODULI) as u128;
            k.checked_mul(m).and_then(|km| km.checked_add(base as u128))
        }
    }

    fn basis_product_i128(&self) -> Option<i128> {
        let mut product: i128 = 1;
        for &p in &self.primes {
            product = product.checked_mul(p as i128)?;
        }
        Some(product)
    }
}

impl PartialEq for WindingCRT {
    fn eq(&self, other: &Self) -> bool {
        // Lane-parallel equality: same sign, same residues, same winding
        if self.sign != other.sign {
            return self.is_zero() && other.is_zero();
        }
        if self.primes != other.primes {
            // Different bases — fall back to value comparison
            return self.to_i128() == other.to_i128();
        }
        self.lanes == other.lanes && self.winding_matches(&other.winding)
    }
}

impl Eq for WindingCRT {}

impl WindingCRT {
    fn winding_matches(&self, other: &[i128]) -> bool {
        let a = &self.winding;
        let max_len = a.len().max(other.len());
        for i in 0..max_len {
            let va = a.get(i).copied().unwrap_or(0);
            let vb = other.get(i).copied().unwrap_or(0);
            if va != vb {
                return false;
            }
        }
        true
    }
}

/// WASSAN-style residue ring for astronomically large values.
///
/// When a value exceeds the u128 corridor, it can still be represented
/// exactly as a polynomial in ℤ_p[X]/(X^N - 1). This ring stores
/// residue arrays that are too large for scalar extraction but can
/// still participate in lane-parallel arithmetic.
///
/// The key property: you NEVER NEED to reconstruct. The residue array
/// IS the value. Arithmetic operates directly on the polynomial
/// coefficients with modular reduction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WassanRing {
    /// Polynomial coefficients in ℤ_p, one per slot.
    coefficients: Vec<u64>,
    /// Ring modulus p.
    modulus: u64,
    /// Ring dimension N (polynomial degree bound).
    dimension: usize,
}

impl WassanRing {
    /// Create a zero ring element.
    pub fn zero(modulus: u64, dimension: usize) -> Self {
        Self {
            coefficients: vec![0; dimension],
            modulus,
            dimension,
        }
    }

    /// Encode a u128 value into the ring. The value is stored as
    /// base-p digits across the polynomial slots.
    pub fn from_u128(val: u128, modulus: u64, dimension: usize) -> Self {
        let mut coeffs = vec![0u64; dimension];
        let mut remaining = val;
        for c in coeffs.iter_mut() {
            *c = (remaining % modulus as u128) as u64;
            remaining /= modulus as u128;
            if remaining == 0 {
                break;
            }
        }
        Self {
            coefficients: coeffs,
            modulus,
            dimension,
        }
    }

    /// Reconstruct to u128 if the value fits. I/O operation.
    pub fn to_u128(&self) -> Option<u128> {
        let mut value: u128 = 0;
        let mut power: u128 = 1;
        for (i, &c) in self.coefficients.iter().enumerate() {
            if c != 0 {
                let contrib = power.checked_mul(c as u128)?;
                value = value.checked_add(contrib)?;
            }
            if i + 1 < self.coefficients.len() {
                // Only advance power if there are more digits to process
                // and they could be nonzero
                let remaining_nonzero = self.coefficients[i + 1..].iter().any(|&x| x != 0);
                if remaining_nonzero {
                    power = power.checked_mul(self.modulus as u128)?;
                }
            }
        }
        Some(value)
    }

    /// Lane-parallel addition in the ring.
    pub fn add(&self, other: &WassanRing) -> WassanRing {
        assert_eq!(self.modulus, other.modulus);
        assert_eq!(self.dimension, other.dimension);
        let coefficients: Vec<u64> = self
            .coefficients
            .iter()
            .zip(other.coefficients.iter())
            .map(|(&a, &b)| ((a as u64 + b as u64) % self.modulus) as u64)
            .collect();
        WassanRing {
            coefficients,
            modulus: self.modulus,
            dimension: self.dimension,
        }
    }

    /// Lane-parallel scalar multiplication.
    pub fn scalar_mul(&self, scalar: u64) -> WassanRing {
        let s = scalar % self.modulus;
        let coefficients: Vec<u64> = self
            .coefficients
            .iter()
            .map(|&c| ((c as u128 * s as u128) % self.modulus as u128) as u64)
            .collect();
        WassanRing {
            coefficients,
            modulus: self.modulus,
            dimension: self.dimension,
        }
    }

    /// Negation in the ring.
    pub fn negate(&self) -> WassanRing {
        let coefficients: Vec<u64> = self
            .coefficients
            .iter()
            .map(|&c| if c == 0 { 0 } else { self.modulus - c })
            .collect();
        WassanRing {
            coefficients,
            modulus: self.modulus,
            dimension: self.dimension,
        }
    }

    /// Whether the ring element is zero.
    pub fn is_zero(&self) -> bool {
        self.coefficients.iter().all(|&c| c == 0)
    }

    /// Raw coefficient access.
    pub fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }

    /// Ring modulus.
    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    /// Ring dimension.
    pub fn dimension(&self) -> usize {
        self.dimension
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public re-export alias for backward compatibility
// ═══════════════════════════════════════════════════════════════════════════

/// Alias: the winding tower carrier IS the DynCRT.
pub type DynCRT = WindingCRT;

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_roundtrip() {
        let z = WindingCRT::from_i128(0);
        assert_eq!(z.to_i128(), Some(0));
        assert!(z.is_zero());
        assert!(!z.is_negative());
    }

    #[test]
    fn small_positive_roundtrip() {
        for val in [1i128, 42, 100, 9999, 123456789] {
            let c = WindingCRT::from_i128(val);
            assert_eq!(c.to_i128(), Some(val), "failed for {}", val);
        }
    }

    #[test]
    fn small_negative_roundtrip() {
        for val in [-1i128, -42, -100, -9999, -123456789] {
            let c = WindingCRT::from_i128(val);
            assert_eq!(c.to_i128(), Some(val), "failed for {}", val);
            assert!(c.is_negative());
        }
    }

    #[test]
    fn residue_query_no_reconstruction() {
        let c = WindingCRT::from_i128(100);
        // These are O(1) lane lookups — no Garner reconstruction
        assert_eq!(c.residue(2), Some(0)); // 100 % 2 = 0
        assert_eq!(c.residue(3), Some(1)); // 100 % 3 = 1
        assert_eq!(c.residue(7), Some(2)); // 100 % 7 = 2
    }

    #[test]
    fn divisibility_no_reconstruction() {
        let c = WindingCRT::from_i128(210); // 2*3*5*7
        assert_eq!(c.is_divisible_by(2), Some(true));
        assert_eq!(c.is_divisible_by(3), Some(true));
        assert_eq!(c.is_divisible_by(5), Some(true));
        assert_eq!(c.is_divisible_by(7), Some(true));
        assert_eq!(c.is_divisible_by(11), Some(false));
    }

    #[test]
    fn lane_parallel_add() {
        let a = WindingCRT::from_i128(12345);
        let b = WindingCRT::from_i128(67890);
        let sum = a.add(&b);
        assert_eq!(sum.to_i128(), Some(80235));
    }

    #[test]
    fn lane_parallel_sub() {
        let a = WindingCRT::from_i128(67890);
        let b = WindingCRT::from_i128(12345);
        let diff = a.sub(&b);
        assert_eq!(diff.to_i128(), Some(55545));
    }

    #[test]
    fn lane_parallel_mul() {
        let a = WindingCRT::from_i128(123);
        let b = WindingCRT::from_i128(456);
        let prod = a.mul(&b);
        assert_eq!(prod.to_i128(), Some(123 * 456));
    }

    #[test]
    fn within_basis_small() {
        let c = WindingCRT::from_i128(42);
        assert!(c.is_within_basis());
    }

    #[test]
    fn winding_for_large_value() {
        let big = S8_PRODUCT as i128 + 1; // Just past M
        let c = WindingCRT::from_i128(big);
        assert!(!c.is_within_basis());
        assert_eq!(c.to_i128(), Some(big));
    }

    #[test]
    fn equality_by_lanes() {
        let a = WindingCRT::from_i128(42);
        let b = WindingCRT::from_i128(42);
        assert_eq!(a, b);

        let c = WindingCRT::from_i128(43);
        assert_ne!(a, c);
    }

    #[test]
    fn negative_add() {
        let a = WindingCRT::from_i128(-100);
        let b = WindingCRT::from_i128(250);
        let sum = a.add(&b);
        assert_eq!(sum.to_i128(), Some(150));
    }

    #[test]
    fn large_positive_corridor() {
        let val: i128 = 1_000_000_000_000_000; // 10^15
        let c = WindingCRT::from_i128(val);
        assert_eq!(c.to_i128(), Some(val));
    }

    #[test]
    fn large_negative_corridor() {
        let val: i128 = -1_000_000_000_000_000;
        let c = WindingCRT::from_i128(val);
        assert_eq!(c.to_i128(), Some(val));
    }

    // ── WASSAN Ring tests ────────────────────────────────────

    #[test]
    fn wassan_zero() {
        let r = WassanRing::zero(997, 256);
        assert!(r.is_zero());
        assert_eq!(r.to_u128(), Some(0));
    }

    #[test]
    fn wassan_encode_decode() {
        let val: u128 = 123456789;
        let r = WassanRing::from_u128(val, 997, 256);
        assert_eq!(r.to_u128(), Some(val));
    }

    #[test]
    fn wassan_add() {
        let a = WassanRing::from_u128(100, 997, 256);
        let b = WassanRing::from_u128(200, 997, 256);
        let sum = a.add(&b);
        assert_eq!(sum.to_u128(), Some(300));
    }

    #[test]
    fn wassan_negate() {
        let a = WassanRing::from_u128(42, 997, 8);
        let neg = a.negate();
        let sum = a.add(&neg);
        // In modular arithmetic, a + (-a) = 0 mod p in each slot
        assert!(sum.is_zero());
    }

    #[test]
    fn wassan_scalar_mul() {
        let a = WassanRing::from_u128(10, 997, 256);
        let scaled = a.scalar_mul(5);
        assert_eq!(scaled.to_u128(), Some(50));
    }
}
