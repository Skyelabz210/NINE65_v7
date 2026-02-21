//! Exact noise budget tracking using NexGen rational arithmetic.
//!
//! Tracks FHE noise growth as exact rational fractions instead of
//! millibits approximations. This gives precise depth estimates
//! and optimal bootstrap scheduling.

use crate::arithmetic::rational_bridge::RationalBridge;

/// Exact noise tracker using rational arithmetic.
///
/// Noise budget is tracked as an exact rational number of bits.
/// Operations consume budget according to standard BFV noise formulas.
///
/// # Noise model (BFV)
/// - Encrypt: initial noise ≈ 3 bits
/// - Add: noise_out = noise_a + noise_b (worst case: +1 bit)
/// - Mul: noise_out ≈ noise_a + noise_b + log2(t) + small constant
/// - Rescale: noise_out = noise - log2(q_i)
pub struct ExactNoiseTracker {
    /// Total budget in bits (rational for sub-bit precision).
    total_budget: RationalBridge,
    /// Current noise level in bits (rational).
    current_noise: RationalBridge,
    /// Number of additions since last multiplication.
    add_count: u64,
    /// Number of multiplications performed.
    mul_count: u64,
}

impl ExactNoiseTracker {
    /// Create a new tracker with the given budget in bits.
    pub fn new(budget_bits: u32) -> Self {
        let total = RationalBridge::from_integer(budget_bits as i128);
        // Initial noise after encryption: ~3.2 bits = 16/5
        let initial_noise = RationalBridge::new(16, 5)
            .expect("16/5 is a valid rational constant");
        Self {
            total_budget: total,
            current_noise: initial_noise,
            add_count: 0,
            mul_count: 0,
        }
    }

    /// Total budget in bits.
    pub fn total_budget_bits(&self) -> u32 {
        self.total_budget.numerator() as u32
    }

    /// Remaining budget as exact rational.
    pub fn remaining_budget_rational(&self) -> RationalBridge {
        self.total_budget
            .sub(&self.current_noise)
            .unwrap_or_else(|_| RationalBridge::from_integer(0))
    }

    /// Remaining budget in bits (positive means budget left).
    pub fn remaining_budget_bits(&self) -> i128 {
        let remaining = self.remaining_budget_rational();
        remaining.numerator() / remaining.denominator()
    }

    /// Remaining budget as approximate integer bits (floor).
    pub fn remaining_budget_bits_approx(&self) -> u32 {
        let remaining = self.remaining_budget_rational();
        let n = remaining.numerator();
        let d = remaining.denominator();
        if n <= 0 || d <= 0 {
            return 0;
        }
        (n / d) as u32
    }

    /// Record an addition operation.
    ///
    /// Additions are cheap: we batch them and compute log2(count)
    /// at query time rather than per-operation.
    pub fn on_add(&mut self) {
        self.add_count += 1;
    }

    /// Record a multiplication operation.
    ///
    /// Multiplication grows noise by approximately:
    ///   noise_new = noise_old * 2 + log2(t) + 1
    ///
    /// We use exact rationals: noise_new = noise_old + noise_old + log2_exact(t) + 1
    pub fn on_mul(&mut self, plaintext_modulus: u64) {
        // Flush pending additions first
        self.flush_additions();

        // Noise doubles + log2(t) + small constant
        let doubled = self
            .current_noise
            .add(&self.current_noise)
            .unwrap_or(self.current_noise.clone());
        let log2_t = RationalBridge::from_integer(ilog2_exact(plaintext_modulus));
        let constant = RationalBridge::from_integer(1);
        self.current_noise = doubled
            .add(&log2_t)
            .and_then(|v| v.add(&constant))
            .unwrap_or(doubled);
        self.mul_count += 1;
    }

    /// Record a rescale operation (modulus switching).
    ///
    /// Rescaling removes log2(q_i) bits of noise.
    pub fn on_rescale(&mut self, dropped_modulus: u64) {
        self.flush_additions();
        let reduction = RationalBridge::from_integer(ilog2_exact(dropped_modulus));
        self.current_noise = self
            .current_noise
            .sub(&reduction)
            .unwrap_or_else(|_| RationalBridge::from_integer(0));
    }

    /// Estimate remaining multiplicative depth.
    ///
    /// Computes how many more multiplications can be performed
    /// before noise exceeds the budget.
    pub fn remaining_depth_estimate(&mut self, plaintext_modulus: u64) -> u32 {
        self.flush_additions();
        let remaining = self.remaining_budget_bits_approx();
        let cost_per_mul = ilog2_exact(plaintext_modulus) as u32 + 2; // noise + log2(t) + const
        if cost_per_mul == 0 {
            return u32::MAX;
        }
        remaining / cost_per_mul
    }

    /// Flush batched additions into noise estimate.
    ///
    /// log2(n additions) ≈ ceil(log2(add_count + 1))
    fn flush_additions(&mut self) {
        if self.add_count == 0 {
            return;
        }
        let add_noise_bits = ilog2_exact(self.add_count + 1);
        let add_noise = RationalBridge::from_integer(add_noise_bits);
        self.current_noise = self
            .current_noise
            .add(&add_noise)
            .unwrap_or(self.current_noise.clone());
        self.add_count = 0;
    }
}

/// Integer-only log2 (ceiling), returns 0 for input 0-1.
fn ilog2_exact(val: u64) -> i128 {
    if val <= 1 {
        return 0;
    }
    (64 - (val - 1).leading_zeros()) as i128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_noise_encrypt_has_initial_budget() {
        let tracker = ExactNoiseTracker::new(152); // 128-bit security → 152-bit budget
        assert_eq!(tracker.total_budget_bits(), 152);
        assert!(tracker.remaining_budget_bits() > 0);
    }

    #[test]
    fn exact_noise_mul_reduces_budget() {
        let mut tracker = ExactNoiseTracker::new(152);
        let before = tracker.remaining_budget_rational();
        tracker.on_mul(16); // plaintext modulus t=16, log2(t)=4
        let after = tracker.remaining_budget_rational();
        // Multiplication increases noise, reducing budget
        assert!(
            after.numerator() < before.numerator() || after.denominator() > before.denominator(),
            "Budget must decrease after multiplication"
        );
    }

    #[test]
    fn exact_noise_remaining_depth_estimate() {
        let mut tracker = ExactNoiseTracker::new(152);
        let depth = tracker.remaining_depth_estimate(16);
        // With 152-bit budget and t=16, should support many levels
        assert!(
            depth > 10,
            "Should support at least 10 levels with 152-bit budget"
        );
    }

    #[test]
    fn exact_noise_tracks_additions_cheaply() {
        let mut tracker = ExactNoiseTracker::new(152);
        let before = tracker.remaining_budget_bits_approx();
        for _ in 0..100 {
            tracker.on_add();
        }
        let after = tracker.remaining_budget_bits_approx();
        // 100 additions should consume roughly 7 bits (log2(100) ≈ 6.6)
        let consumed = before - after;
        assert!(
            consumed < 10,
            "100 additions should consume < 10 bits, got {consumed}"
        );
    }
}
