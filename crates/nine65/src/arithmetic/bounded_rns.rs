//! Bit-width bound tracking for RNS coefficients.
//!
//! Wraps Clockwork's [`Bound`] concept to track coefficient bit-widths
//! through FHE arithmetic chains. Detects potential overflow BEFORE it
//! corrupts computation, complementing NINE65's noise tracking.
//!
//! # Usage
//!
//! ```ignore
//! let mut a = BoundedValue::new(30); // 30-bit coefficient
//! let b = BoundedValue::new(30);
//! a.on_add(&b);       // now 31 bits (carry)
//! a.on_mul(&b);       // now 61 bits
//! assert!(!a.would_overflow(64)); // fits in u64
//! ```

use clockwork_core::Bound;

/// Tracks the maximum bit-width of a value through arithmetic operations.
///
/// Wraps Clockwork's `Bound` with a NINE65-oriented API for FHE operations
/// (add, mul, rescale). All tracking is exact integer arithmetic — no floats.
pub struct BoundedValue {
    inner: Bound,
}

impl BoundedValue {
    /// Create a bound for a value known to fit in `initial_bits` bits.
    pub fn new(initial_bits: u32) -> Self {
        Self {
            inner: Bound::new(initial_bits),
        }
    }

    /// Create a bound from a known constant value.
    /// Returns the minimal bound: ceil(log2(|value| + 1)).
    pub fn from_value(value: i128) -> Self {
        Self {
            inner: Bound::from_value(value),
        }
    }

    /// Current bit-width bound.
    pub fn bit_width(&self) -> u32 {
        self.inner.bits()
    }

    /// Addition: width grows by 1 bit (carry).
    /// H(X+Y) <= max(H(X), H(Y)) + 1
    pub fn on_add(&mut self, other: &BoundedValue) {
        self.inner = Bound::add_bound(&self.inner, &other.inner);
    }

    /// Subtraction: same growth as addition.
    pub fn on_sub(&mut self, other: &BoundedValue) {
        self.inner = Bound::sub_bound(&self.inner, &other.inner);
    }

    /// Multiplication: widths add.
    /// H(X*Y) <= H(X) + H(Y)
    pub fn on_mul(&mut self, other: &BoundedValue) {
        self.inner = Bound::mul_bound(&self.inner, &other.inner);
    }

    /// Scalar multiplication by a known constant.
    /// H(c*X) <= H(c) + H(X)
    pub fn on_scalar_mul(&mut self, scalar_bits: u32) {
        self.inner = Bound::scalar_mul_bound(scalar_bits, &self.inner);
    }

    /// Rescaling: width decreases by the dropped prime's bit-width.
    /// This models the BFV rescale (divide-and-round by a prime).
    pub fn on_rescale(&mut self, prime_bits: u32) {
        let current = self.inner.bits();
        self.inner = Bound::new(current.saturating_sub(prime_bits));
    }

    /// Negation: width unchanged.
    pub fn on_negate(&mut self) {
        self.inner = Bound::neg_bound(&self.inner);
    }

    /// Check if current width would overflow a given capacity in bits.
    pub fn would_overflow(&self, capacity_bits: u32) -> bool {
        self.inner.bits() > capacity_bits
    }

    /// Check if promotion is needed given capacity and guard margin.
    pub fn needs_promotion(&self, capacity_bits: u32, guard: u32) -> bool {
        self.inner.needs_promotion(capacity_bits, guard)
    }

    /// Compute dot-product bound (tighter than chaining add+mul).
    /// `term_bounds` is a slice of (H(w_j), H(x_j)) pairs.
    pub fn dot_product_bound(term_bounds: &[(u32, u32)]) -> Self {
        Self {
            inner: Bound::dot_product_bound(term_bounds),
        }
    }

    /// Access the underlying Clockwork Bound.
    pub fn inner(&self) -> &Bound {
        &self.inner
    }
}

impl Clone for BoundedValue {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl core::fmt::Debug for BoundedValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BoundedValue")
            .field("bit_width", &self.inner.bits())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_add_tracks_width() {
        let mut bound = BoundedValue::new(30);
        let other = BoundedValue::new(30);
        bound.on_add(&other);
        assert_eq!(bound.bit_width(), 31);
    }

    #[test]
    fn bounded_add_asymmetric() {
        let mut bound = BoundedValue::new(30);
        let other = BoundedValue::new(20);
        bound.on_add(&other);
        // max(30, 20) + 1 = 31
        assert_eq!(bound.bit_width(), 31);
    }

    #[test]
    fn bounded_mul_tracks_width() {
        let mut bound = BoundedValue::new(30);
        let other = BoundedValue::new(30);
        bound.on_mul(&other);
        assert_eq!(bound.bit_width(), 60);
    }

    #[test]
    fn bounded_mul_asymmetric() {
        let mut bound = BoundedValue::new(10);
        let other = BoundedValue::new(8);
        bound.on_mul(&other);
        assert_eq!(bound.bit_width(), 18);
    }

    #[test]
    fn bounded_rescale_reduces_width() {
        let mut bound = BoundedValue::new(90);
        bound.on_rescale(30);
        assert_eq!(bound.bit_width(), 60);
    }

    #[test]
    fn bounded_rescale_saturates_at_zero() {
        let mut bound = BoundedValue::new(10);
        bound.on_rescale(30);
        assert_eq!(bound.bit_width(), 0);
    }

    #[test]
    fn overflow_detection() {
        let mut bound = BoundedValue::new(120);
        let other = BoundedValue::new(120);
        bound.on_mul(&other); // 240 bits
        assert!(bound.would_overflow(128));
        assert!(!bound.would_overflow(256));
    }

    #[test]
    fn fhe_chain_simulation() {
        // Simulate: encrypt (30-bit plaintext) -> add -> mul -> rescale
        let mut ct = BoundedValue::new(30);
        let other = BoundedValue::new(30);

        ct.on_add(&other); // 31 bits
        assert_eq!(ct.bit_width(), 31);

        let mul_rhs = BoundedValue::new(30);
        ct.on_mul(&mul_rhs); // 61 bits
        assert_eq!(ct.bit_width(), 61);

        ct.on_rescale(30); // 31 bits
        assert_eq!(ct.bit_width(), 31);

        assert!(!ct.would_overflow(64));
    }

    #[test]
    fn from_value_tracking() {
        let b = BoundedValue::from_value(255);
        assert_eq!(b.bit_width(), 8);

        let b = BoundedValue::from_value(0);
        assert_eq!(b.bit_width(), 0);

        let b = BoundedValue::from_value(-128);
        assert_eq!(b.bit_width(), 8);
    }

    #[test]
    fn dot_product_tighter_than_chain() {
        // 4-element dot product of 8-bit × 8-bit values
        let terms: Vec<(u32, u32)> = vec![(8, 8), (8, 8), (8, 8), (8, 8)];
        let dp = BoundedValue::dot_product_bound(&terms);
        // ceil(log2(4)) + max(8+8) = 2 + 16 = 18
        assert_eq!(dp.bit_width(), 18);
    }

    #[test]
    fn promotion_check() {
        let b = BoundedValue::new(60);
        // With guard=4, needs 64 bits capacity
        assert!(b.needs_promotion(63, 4));
        assert!(!b.needs_promotion(64, 4));
        assert!(!b.needs_promotion(128, 4));
    }
}
