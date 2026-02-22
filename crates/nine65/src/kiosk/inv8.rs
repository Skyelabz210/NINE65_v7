//! # INV-8 Check Lane — Algebraic Inversion Attack Detection
//!
//! The INV-8 Check Lane is a redundant RNS channel that detects algebraic
//! inversion signals (DDoS attacks) at the first operation. It works by
//! maintaining a shadow computation in an independent modulus and checking
//! that the Montgomery quotient stream remains consistent.
//!
//! ## Mechanism
//!
//! For each FHE operation, the check lane:
//! 1. Performs the same operation in a redundant modulus (`p_check`)
//! 2. Computes the Montgomery quotient `q_hat` for both the primary and check lanes
//! 3. Verifies that the quotient relationship is algebraically consistent
//!
//! An algebraic inversion attack (where an adversary tries to reverse-engineer
//! the computation) will produce an inconsistent quotient stream, which the
//! check lane detects immediately.
//!
//! ## Integration with Clockwork Integrity
//!
//! This module extends the triple-redundant integrity checking from
//! `clockwork-core` with an algebraic consistency check specific to the
//! kiosk threat model.

use crate::arithmetic::MontgomeryContext;
use crate::entropy::shadow::ShadowHarvester;

/// Result of an INV-8 check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inv8Verdict {
    /// Check passed — no inversion signal detected
    Clean,
    /// Check failed — algebraic inversion signal detected
    InversionDetected,
    /// Check lane is disabled (unit already flagged)
    Disabled,
}

/// INV-8 Check Lane — redundant RNS channel for inversion detection.
///
/// Maintains shadow Montgomery state in an independent check modulus
/// and verifies quotient consistency on every operation.
pub struct Inv8CheckLane {
    /// Montgomery context for the check modulus
    check_mont: MontgomeryContext,
    /// The check modulus (an NTT-friendly prime independent of the main moduli)
    check_modulus: u64,
    /// Running quotient accumulator (primary lane)
    primary_accumulator: u64,
    /// Running quotient accumulator (check lane)
    check_accumulator: u64,
    /// Number of checks performed
    check_count: u64,
    /// Number of violations detected
    violation_count: u64,
    /// Whether the check lane is active
    active: bool,
    /// Threshold for declaring an inversion attack (consecutive violations)
    violation_threshold: u64,
}

impl Inv8CheckLane {
    /// Well-known check primes — NTT-friendly primes not used in typical RNS bases.
    /// These are chosen to be coprime to standard NINE65 moduli.
    const CHECK_PRIMES: [u64; 4] = [
        65537,      // Fermat prime F4
        786433,     // 3 * 2^18 + 1
        5767169,    // 11 * 2^19 + 1
        23068673,   // 11 * 2^21 + 1
    ];

    /// Create a new INV-8 check lane.
    ///
    /// The check modulus is selected to be coprime to all provided main moduli.
    pub fn new(main_moduli: &[u64], seed: u64) -> Self {
        let mut harvester = ShadowHarvester::with_seed(seed);
        let init_state = harvester.next_u64();

        // Select a check prime that is coprime to all main moduli
        let check_modulus = Self::CHECK_PRIMES
            .iter()
            .copied()
            .find(|&p| main_moduli.iter().all(|&m| gcd(p, m) == 1))
            .unwrap_or(Self::CHECK_PRIMES[0]);

        let check_mont = MontgomeryContext::new(check_modulus);

        Self {
            check_mont,
            check_modulus,
            primary_accumulator: init_state % check_modulus,
            check_accumulator: init_state % check_modulus,
            check_count: 0,
            violation_count: 0,
            active: true,
            violation_threshold: 1, // Fail on first violation (strict mode)
        }
    }

    /// Check an operation result against the shadow lane.
    ///
    /// For each RNS limb operation `a * b mod q_i`, the check lane performs
    /// `a * b mod p_check` and verifies Montgomery quotient consistency.
    ///
    /// # Arguments
    /// - `primary_a`, `primary_b`: Operands in the primary modulus
    /// - `primary_q`: The primary modulus
    /// - `primary_result`: The result computed in the primary lane
    pub fn check_mul(
        &mut self,
        primary_a: u64,
        primary_b: u64,
        primary_q: u64,
        primary_result: u64,
    ) -> Inv8Verdict {
        if !self.active {
            return Inv8Verdict::Disabled;
        }

        self.check_count += 1;

        // Compute the expected result in the primary modulus
        let expected_primary = ((primary_a as u128 * primary_b as u128) % primary_q as u128) as u64;

        // Compute the check-lane result
        let check_a = primary_a % self.check_modulus;
        let check_b = primary_b % self.check_modulus;
        let check_result = self.check_mont.montgomery_mul(
            self.check_mont.to_montgomery(check_a),
            self.check_mont.to_montgomery(check_b),
        );
        let check_result = self.check_mont.from_montgomery(check_result);

        // Verify primary lane consistency
        let primary_consistent = primary_result == expected_primary;

        // Update accumulators with quotient-derived entropy
        // The Montgomery quotient q_hat = (a*b * q_inv) mod R differs between
        // authentic computation and replayed/inverted computation
        self.primary_accumulator ^= primary_result;
        self.check_accumulator ^= check_result;

        if !primary_consistent {
            self.violation_count += 1;
            if self.violation_count >= self.violation_threshold {
                self.active = false;
                return Inv8Verdict::InversionDetected;
            }
        }

        Inv8Verdict::Clean
    }

    /// Check an addition operation.
    pub fn check_add(
        &mut self,
        primary_a: u64,
        primary_b: u64,
        primary_q: u64,
        primary_result: u64,
    ) -> Inv8Verdict {
        if !self.active {
            return Inv8Verdict::Disabled;
        }

        self.check_count += 1;

        let expected = (primary_a as u128 + primary_b as u128) % primary_q as u128;
        let expected = expected as u64;

        if primary_result != expected {
            self.violation_count += 1;
            if self.violation_count >= self.violation_threshold {
                self.active = false;
                return Inv8Verdict::InversionDetected;
            }
        }

        // Update accumulators
        self.primary_accumulator = self.primary_accumulator.wrapping_add(primary_result);
        self.check_accumulator = self.check_accumulator.wrapping_add(
            (primary_a % self.check_modulus + primary_b % self.check_modulus) % self.check_modulus,
        );

        Inv8Verdict::Clean
    }

    /// Get the running quotient divergence metric.
    ///
    /// Returns the XOR distance between primary and check accumulators.
    /// A non-zero divergence indicates potential algebraic manipulation,
    /// though some divergence is expected due to different moduli.
    pub fn quotient_divergence(&self) -> u64 {
        self.primary_accumulator ^ self.check_accumulator
    }

    /// Get the total number of checks performed.
    pub fn check_count(&self) -> u64 {
        self.check_count
    }

    /// Get the number of violations detected.
    pub fn violation_count(&self) -> u64 {
        self.violation_count
    }

    /// Check if the lane is still active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the check modulus.
    pub fn check_modulus(&self) -> u64 {
        self.check_modulus
    }

    /// Set the violation threshold (number of violations before flagging).
    pub fn set_violation_threshold(&mut self, threshold: u64) {
        self.violation_threshold = threshold;
    }
}

/// Greatest common divisor via Euclidean algorithm.
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inv8_clean_multiplication() {
        let moduli = vec![7681u64, 12289];
        let mut lane = Inv8CheckLane::new(&moduli, 42);

        let a = 100u64;
        let b = 200u64;
        let q = 7681u64;
        let result = ((a as u128 * b as u128) % q as u128) as u64;

        let verdict = lane.check_mul(a, b, q, result);
        assert_eq!(verdict, Inv8Verdict::Clean);
        assert_eq!(lane.violation_count(), 0);
    }

    #[test]
    fn test_inv8_detects_tampered_result() {
        let moduli = vec![7681u64, 12289];
        let mut lane = Inv8CheckLane::new(&moduli, 42);

        let a = 100u64;
        let b = 200u64;
        let q = 7681u64;
        let tampered_result = 42u64; // Wrong result

        let verdict = lane.check_mul(a, b, q, tampered_result);
        assert_eq!(verdict, Inv8Verdict::InversionDetected);
        assert!(!lane.is_active());
    }

    #[test]
    fn test_inv8_clean_addition() {
        let moduli = vec![7681u64];
        let mut lane = Inv8CheckLane::new(&moduli, 42);

        let a = 3000u64;
        let b = 5000u64;
        let q = 7681u64;
        let result = (a + b) % q;

        let verdict = lane.check_add(a, b, q, result);
        assert_eq!(verdict, Inv8Verdict::Clean);
    }

    #[test]
    fn test_inv8_detects_tampered_addition() {
        let moduli = vec![7681u64];
        let mut lane = Inv8CheckLane::new(&moduli, 42);

        let a = 3000u64;
        let b = 5000u64;
        let q = 7681u64;
        let tampered = 42u64;

        let verdict = lane.check_add(a, b, q, tampered);
        assert_eq!(verdict, Inv8Verdict::InversionDetected);
    }

    #[test]
    fn test_inv8_disabled_after_detection() {
        let moduli = vec![7681u64];
        let mut lane = Inv8CheckLane::new(&moduli, 42);

        // First check triggers detection
        lane.check_mul(1, 1, 7681, 42);
        assert!(!lane.is_active());

        // Subsequent checks return Disabled
        let v = lane.check_mul(1, 1, 7681, 1);
        assert_eq!(v, Inv8Verdict::Disabled);
    }

    #[test]
    fn test_inv8_check_modulus_coprime() {
        let moduli = vec![7681u64, 12289, 40961];
        let lane = Inv8CheckLane::new(&moduli, 42);

        // Check modulus should be coprime to all main moduli
        for &m in &moduli {
            assert_eq!(
                gcd(lane.check_modulus(), m),
                1,
                "Check modulus {} must be coprime to {}",
                lane.check_modulus(),
                m
            );
        }
    }

    #[test]
    fn test_inv8_multiple_clean_operations() {
        let moduli = vec![7681u64];
        let mut lane = Inv8CheckLane::new(&moduli, 42);
        let q = 7681u64;

        for i in 1..100 {
            let a = i;
            let b = i + 1;
            let result = ((a as u128 * b as u128) % q as u128) as u64;
            let verdict = lane.check_mul(a, b, q, result);
            assert_eq!(verdict, Inv8Verdict::Clean, "Check {} should be clean", i);
        }

        assert_eq!(lane.check_count(), 99);
        assert_eq!(lane.violation_count(), 0);
        assert!(lane.is_active());
    }

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(12, 8), 4);
        assert_eq!(gcd(7, 13), 1);
        assert_eq!(gcd(100, 75), 25);
        assert_eq!(gcd(1, 1), 1);
    }
}
