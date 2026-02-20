//! Valuation Tracker - Kill #67 (Integration-Ready)
//!
//! Multi-valuation oracle for O(small) divisibility checks in FHE rescaling.
//!
//! Mathematical basis: p-adic valuations ν_p(x) track prime power divisibility.
//! For x = p^a × m where gcd(p, m) = 1, we have ν_p(x) = a.
//!
//! Key properties:
//!   ν_p(x × y) = ν_p(x) + ν_p(y)
//!   ν_p(x + y) ≥ min(ν_p(x), ν_p(y))
//!   ν_p(x / y) = ν_p(x) - ν_p(y) (for exact division)
//!
//! This enables O(factoring d) divisibility checks, independent of the size of x.
//!
//! # Example
//!
//! ```
//! use nine65::arithmetic::valuation::ValuationTracker;
//!
//! // x = 6048 = 2^5 × 3^3 × 7
//! let tracker = ValuationTracker::from_integer(6048);
//!
//! // Can we divide by 24 = 2^3 × 3?
//! assert_eq!(tracker.can_divide(24), Some(true));  // Yes: ν_2 ≥ 3, ν_3 ≥ 1
//!
//! // Can we divide by 49 = 7^2?
//! assert_eq!(tracker.can_divide(49), Some(false)); // No: ν_7 = 1 < 2
//! ```

use std::collections::BTreeMap; // Deterministic iteration order

/// Small primes to track by default.
/// These cover most common FHE rescaling divisors.
const TRACKED_PRIMES: &[u64] = &[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];

/// Maximum prime to consider in trial division.
const MAX_FACTOR_PRIME: u64 = 1000;

/// Result of a divisibility check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Divisibility {
    /// Definitely divisible
    Yes,
    /// Definitely not divisible
    No,
    /// Cannot determine (unfactored components may contain required factors)
    Unknown,
}

impl Divisibility {
    /// Convert to Option<bool> for compatibility.
    pub fn to_option(self) -> Option<bool> {
        match self {
            Divisibility::Yes => Some(true),
            Divisibility::No => Some(false),
            Divisibility::Unknown => None,
        }
    }

    /// Returns true only if definitely divisible.
    pub fn is_definitely_divisible(self) -> bool {
        matches!(self, Divisibility::Yes)
    }

    /// Returns true only if definitely not divisible.
    pub fn is_definitely_not_divisible(self) -> bool {
        matches!(self, Divisibility::No)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Unfactored {
    #[default]
    None,
    Zero,
    Value(u64),
    Unknown,
}

/// Multi-valuation oracle for tracking p-adic valuations.
///
/// Enables O(small) divisibility checks during FHE rescaling operations.
///
/// # Determinism
///
/// This type uses `BTreeMap` internally to ensure deterministic iteration
/// order across all methods, which is important for reproducible behavior
/// in `suggest_rescale_factor` and similar operations.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValuationTracker {
    /// Maps prime p → valuation ν_p(x), sorted by prime for determinism
    valuations: BTreeMap<u64, u32>,
    /// The "unfactored" part (product of large prime factors)
    /// - None: complete factorization known
    /// - Zero: represents zero (infinite valuation at all primes)
    /// - Value(n) where n > 1: unfactored remainder
    /// - Unknown: overflow or loss of information in unfactored tracking
    unfactored: Unfactored,
}

impl ValuationTracker {
    /// Create an empty tracker (represents 1).
    pub fn one() -> Self {
        Self {
            valuations: BTreeMap::new(),
            unfactored: Unfactored::None,
        }
    }

    /// Create a tracker representing zero.
    ///
    /// Zero has "infinite" valuation at all primes.
    pub fn zero() -> Self {
        Self {
            valuations: BTreeMap::new(),
            unfactored: Unfactored::Zero,
        }
    }

    /// Create a tracker from known prime factorization.
    ///
    /// # Arguments
    /// * `factors` - Slice of (prime, exponent) pairs
    ///
    /// # Example
    /// ```
    /// use nine65::arithmetic::valuation::ValuationTracker;
    /// // 72 = 2^3 × 3^2
    /// let tracker = ValuationTracker::from_factorization(&[(2, 3), (3, 2)]);
    /// assert_eq!(tracker.valuation(2), 3);
    /// ```
    pub fn from_factorization(factors: &[(u64, u32)]) -> Self {
        Self {
            valuations: factors
                .iter()
                .filter(|(_, e)| *e > 0) // Skip zero exponents
                .cloned()
                .collect(),
            unfactored: Unfactored::None,
        }
    }

    /// Create a tracker by factoring an integer.
    ///
    /// For small integers, this is fast. For large integers with
    /// large prime factors, we track what we can and store the rest
    /// in `unfactored`.
    pub fn from_integer(mut n: u64) -> Self {
        if n == 0 {
            return Self::zero();
        }

        let mut valuations = BTreeMap::new();

        // Trial division by small primes
        for &p in TRACKED_PRIMES {
            if n == 1 {
                break;
            }
            let mut exp = 0u32;
            while n.is_multiple_of(p) {
                n /= p;
                exp += 1;
            }
            if exp > 0 {
                valuations.insert(p, exp);
            }
        }

        // Continue trial division up to MAX_FACTOR_PRIME
        let mut p = TRACKED_PRIMES.last().copied().unwrap_or(2) + 2;
        while p <= MAX_FACTOR_PRIME && p * p <= n {
            let mut exp = 0u32;
            while n.is_multiple_of(p) {
                n /= p;
                exp += 1;
            }
            if exp > 0 {
                valuations.insert(p, exp);
            }
            p += 2;
        }

        Self {
            valuations,
            unfactored: if n > 1 {
                Unfactored::Value(n)
            } else {
                Unfactored::None
            },
        }
    }

    /// Create from product of moduli (common in RNS).
    ///
    /// # Arguments
    /// * `moduli` - The RNS moduli whose product we're tracking
    pub fn from_moduli_product(moduli: &[u64]) -> Self {
        let mut result = Self::one();
        for &m in moduli {
            result = result.mul(&Self::from_integer(m));
        }
        result
    }

    /// Returns true if the complete factorization is known.
    pub fn is_fully_factored(&self) -> bool {
        matches!(self.unfactored, Unfactored::None | Unfactored::Zero)
    }

    /// Returns true if this represents zero.
    pub fn is_zero(&self) -> bool {
        matches!(self.unfactored, Unfactored::Zero)
    }

    /// Returns true if this represents one.
    pub fn is_one(&self) -> bool {
        self.valuations.is_empty() && matches!(self.unfactored, Unfactored::None)
    }

    /// Get the valuation of prime p.
    ///
    /// Returns 0 if p doesn't divide the tracked number.
    /// For zero, returns u32::MAX (representing infinity).
    pub fn valuation(&self, p: u64) -> u32 {
        if self.is_zero() {
            return u32::MAX; // Zero is divisible by any power
        }
        self.valuations.get(&p).copied().unwrap_or(0)
    }

    /// Check if the tracked number is divisible by d.
    ///
    /// This is the key operation: O(factoring d), independent of x.
    ///
    /// # Returns
    /// - `Some(true)` if definitely divisible
    /// - `Some(false)` if definitely not divisible
    /// - `None` if cannot determine (unfactored parts may interact)
    pub fn can_divide(&self, d: u64) -> Option<bool> {
        self.divisibility(d).to_option()
    }

    /// Check divisibility with explicit result type.
    ///
    /// Prefer this over `can_divide` for clearer intent.
    pub fn divisibility(&self, d: u64) -> Divisibility {
        if d == 0 {
            return Divisibility::No; // Division by zero
        }
        if d == 1 {
            return Divisibility::Yes;
        }
        if self.is_zero() {
            return Divisibility::Yes; // Zero is divisible by anything
        }

        // Factor d
        let d_factors = Self::from_integer(d);

        // Check each prime factor of d against our valuations
        for (&p, &required_exp) in &d_factors.valuations {
            let have_exp = self.valuation(p);
            if have_exp < required_exp {
                return Divisibility::No;
            }
        }

        // Handle unfactored parts
        match (self.unfactored, d_factors.unfactored) {
            (Unfactored::Zero, _) => Divisibility::Yes,
            (_, Unfactored::Zero) => Divisibility::No,
            (Unfactored::None, Unfactored::None) => Divisibility::Yes,
            (Unfactored::None, Unfactored::Value(_)) => Divisibility::No,
            (Unfactored::None, Unfactored::Unknown) => Divisibility::No,
            (Unfactored::Value(_), Unfactored::None) => Divisibility::Yes,
            (Unfactored::Unknown, Unfactored::None) => Divisibility::Yes,
            (Unfactored::Value(our_uf), Unfactored::Value(d_uf)) => {
                if our_uf % d_uf == 0 {
                    Divisibility::Yes
                } else if gcd(our_uf, d_uf) > 1 {
                    Divisibility::Unknown
                } else {
                    Divisibility::No
                }
            }
            (Unfactored::Unknown, Unfactored::Value(_)) => Divisibility::Unknown,
            (Unfactored::Value(_), Unfactored::Unknown) => Divisibility::Unknown,
            (Unfactored::Unknown, Unfactored::Unknown) => Divisibility::Unknown,
        }
    }

    /// Multiply two tracked numbers (add valuations).
    pub fn mul(&self, other: &Self) -> Self {
        // Handle zero cases
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }

        let mut valuations = self.valuations.clone();

        for (&p, &exp) in &other.valuations {
            *valuations.entry(p).or_insert(0) += exp;
        }

        let unfactored = match (self.unfactored, other.unfactored) {
            (Unfactored::Zero, _) | (_, Unfactored::Zero) => Unfactored::Zero,
            (Unfactored::Unknown, _) | (_, Unfactored::Unknown) => Unfactored::Unknown,
            (Unfactored::None, Unfactored::None) => Unfactored::None,
            (Unfactored::Value(a), Unfactored::None) | (Unfactored::None, Unfactored::Value(a)) => {
                Unfactored::Value(a)
            }
            (Unfactored::Value(a), Unfactored::Value(b)) => match a.checked_mul(b) {
                Some(prod) => Unfactored::Value(prod),
                None => Unfactored::Unknown,
            },
        };

        Self {
            valuations,
            unfactored,
        }
    }

    /// Attempt exact division.
    ///
    /// # Returns
    /// - `Ok(result)` if division is definitely exact
    /// - `Err(DivisionError)` if division is not exact or cannot be determined
    pub fn checked_div(&self, d: u64) -> Result<Self, DivisionError> {
        match self.divisibility(d) {
            Divisibility::No => Err(DivisionError::NotExact),
            Divisibility::Unknown => Err(DivisionError::Uncertain),
            Divisibility::Yes => {
                let d_factors = Self::from_integer(d);
                let mut valuations = self.valuations.clone();

                for (&p, &exp) in &d_factors.valuations {
                    match valuations.get_mut(&p) {
                        Some(v) if *v >= exp => {
                            *v -= exp;
                            if *v == 0 {
                                valuations.remove(&p);
                            }
                        }
                        _ => return Err(DivisionError::NotExact),
                    }
                }

                // Handle unfactored parts
                let unfactored = match (self.unfactored, d_factors.unfactored) {
                    (Unfactored::Zero, _) => Unfactored::Zero,
                    (_, Unfactored::Zero) => return Err(DivisionError::NotExact),
                    (Unfactored::None, Unfactored::None) => Unfactored::None,
                    (Unfactored::Value(a), Unfactored::None) => Unfactored::Value(a),
                    (Unfactored::Unknown, Unfactored::None) => Unfactored::Unknown,
                    (Unfactored::None, Unfactored::Value(_))
                    | (Unfactored::None, Unfactored::Unknown) => {
                        return Err(DivisionError::NotExact)
                    }
                    (Unfactored::Value(a), Unfactored::Value(b)) => {
                        if a % b == 0 {
                            let result = a / b;
                            if result > 1 {
                                Unfactored::Value(result)
                            } else {
                                Unfactored::None
                            }
                        } else {
                            return Err(DivisionError::NotExact);
                        }
                    }
                    (Unfactored::Unknown, Unfactored::Value(_)) => {
                        return Err(DivisionError::Uncertain)
                    }
                    (Unfactored::Value(_), Unfactored::Unknown)
                    | (Unfactored::Unknown, Unfactored::Unknown) => {
                        return Err(DivisionError::Uncertain)
                    }
                };

                Ok(Self {
                    valuations,
                    unfactored,
                })
            }
        }
    }

    /// Divide by d, panicking if not exact.
    ///
    /// # Panics
    /// Panics if the division is not provably exact.
    pub fn div_exact(&self, d: u64) -> Self {
        self.checked_div(d).expect("Division is not provably exact")
    }

    /// Add (gives lower bound on valuations).
    ///
    /// After addition, ν_p(x + y) ≥ min(ν_p(x), ν_p(y)).
    /// We track the minimum as a conservative estimate.
    pub fn add_conservative(&self, other: &Self) -> Self {
        // Handle zero cases
        if self.is_zero() {
            return other.clone();
        }
        if other.is_zero() {
            return self.clone();
        }

        let mut valuations = BTreeMap::new();

        // Only primes present in BOTH have guaranteed minimum valuation
        for (&p, &exp1) in &self.valuations {
            if let Some(&exp2) = other.valuations.get(&p) {
                valuations.insert(p, exp1.min(exp2));
            }
        }

        // If either has unfactored part, result has uncertainty
        let unfactored = match (self.unfactored, other.unfactored) {
            (Unfactored::None, Unfactored::None) => Unfactored::None,
            _ => Unfactored::Unknown,
        };

        Self {
            valuations,
            unfactored,
        }
    }

    /// Get all tracked prime-exponent pairs in deterministic order.
    pub fn factors(&self) -> impl Iterator<Item = (u64, u32)> + '_ {
        self.valuations.iter().map(|(&p, &e)| (p, e))
    }

    /// Get the unfactored remainder, if any.
    pub fn unfactored_part(&self) -> Option<u64> {
        match self.unfactored {
            Unfactored::Value(u) if u > 1 => Some(u),
            _ => None,
        }
    }

    /// Reconstruct the tracked number (if small enough).
    ///
    /// Returns `None` if the number would overflow u64.
    pub fn to_integer(&self) -> Option<u64> {
        if self.is_zero() {
            return Some(0);
        }

        let mut result = 1u64;

        for (&p, &exp) in &self.valuations {
            let p_pow = p.checked_pow(exp)?;
            result = result.checked_mul(p_pow)?;
        }

        match self.unfactored {
            Unfactored::None => {}
            Unfactored::Zero => return Some(0),
            Unfactored::Value(unfactored) => {
                result = result.checked_mul(unfactored)?;
            }
            Unfactored::Unknown => return None,
        }

        Some(result)
    }
}

/// Error type for division operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DivisionError {
    /// Division is provably not exact.
    NotExact,
    /// Cannot determine if division is exact (unfactored components).
    Uncertain,
}

impl std::fmt::Display for DivisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DivisionError::NotExact => write!(f, "division is not exact"),
            DivisionError::Uncertain => {
                write!(f, "cannot determine if division is exact")
            }
        }
    }
}

impl std::error::Error for DivisionError {}

/// Greatest common divisor.
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Integration with FHE rescaling operations.
pub mod fhe_integration {
    use super::*;

    /// Tracked ciphertext with valuation information.
    #[derive(Debug, Clone)]
    pub struct TrackedCiphertext<C> {
        /// The actual ciphertext
        pub ciphertext: C,
        /// Valuation tracker for the modulus product
        pub modulus_tracker: ValuationTracker,
        /// Current level (number of rescales performed)
        pub level: usize,
    }

    impl<C> TrackedCiphertext<C> {
        /// Create from ciphertext and moduli.
        pub fn new(ciphertext: C, moduli: &[u64]) -> Self {
            Self {
                ciphertext,
                modulus_tracker: ValuationTracker::from_moduli_product(moduli),
                level: 0,
            }
        }

        /// Check if rescaling by d is valid.
        ///
        /// Returns `true` only if definitely divisible.
        pub fn can_rescale(&self, d: u64) -> bool {
            self.modulus_tracker
                .divisibility(d)
                .is_definitely_divisible()
        }

        /// Check rescaling with explicit result.
        pub fn rescale_check(&self, d: u64) -> Divisibility {
            self.modulus_tracker.divisibility(d)
        }

        /// Update tracker after rescaling.
        ///
        /// # Panics
        /// Panics if the rescaling is not provably valid.
        pub fn after_rescale(&mut self, d: u64) {
            self.modulus_tracker = self.modulus_tracker.div_exact(d);
            self.level += 1;
        }

        /// Try to update tracker after rescaling.
        pub fn try_after_rescale(&mut self, d: u64) -> Result<(), DivisionError> {
            self.modulus_tracker = self.modulus_tracker.checked_div(d)?;
            self.level += 1;
            Ok(())
        }
    }

    /// Batch check multiple rescaling factors.
    ///
    /// Returns the first factor that is definitely valid.
    pub fn find_valid_rescale_factor(
        tracker: &ValuationTracker,
        candidates: &[u64],
    ) -> Option<u64> {
        candidates
            .iter()
            .find(|&&d| tracker.divisibility(d).is_definitely_divisible())
            .copied()
    }

    /// Suggest optimal rescale factor based on available valuations.
    ///
    /// Attempts to construct a factor close to `target_bits` bits
    /// using available prime powers, in deterministic order.
    ///
    /// # Arguments
    /// * `tracker` - The valuation tracker
    /// * `target_bits` - Target bit size for the factor
    ///
    /// # Returns
    /// `Some(factor)` if a non-trivial factor can be constructed,
    /// `None` if no suitable factor exists.
    pub fn suggest_rescale_factor(tracker: &ValuationTracker, target_bits: u32) -> Option<u64> {
        if tracker.is_zero() || tracker.is_one() {
            return None;
        }

        let mut factor = 1u64;
        let mut bits = 0u32;

        // BTreeMap iteration is deterministic (sorted by key)
        for (&p, &max_exp) in &tracker.valuations {
            // Try largest power first, decreasing
            for exp in (1..=max_exp).rev() {
                // Use checked_pow to avoid overflow
                let Some(p_pow) = p.checked_pow(exp) else {
                    continue; // Skip if overflow
                };

                let p_bits = 64 - p_pow.leading_zeros();

                if bits + p_bits <= target_bits {
                    // Use checked_mul to avoid overflow
                    let Some(new_factor) = factor.checked_mul(p_pow) else {
                        continue; // Skip if overflow
                    };

                    factor = new_factor;
                    bits += p_bits;
                    break; // Use this exponent for this prime
                }
            }

            if bits >= target_bits {
                break;
            }
        }

        if factor > 1 {
            Some(factor)
        } else {
            None
        }
    }

    /// Compute the maximum power of `p` that divides the modulus product.
    pub fn max_power_of(tracker: &ValuationTracker, p: u64) -> u32 {
        tracker.valuation(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_integer() {
        // 72 = 2^3 × 3^2
        let tracker = ValuationTracker::from_integer(72);
        assert_eq!(tracker.valuation(2), 3);
        assert_eq!(tracker.valuation(3), 2);
        assert_eq!(tracker.valuation(5), 0);
        assert_eq!(tracker.to_integer(), Some(72));
        assert!(tracker.is_fully_factored());
    }

    #[test]
    fn test_can_divide() {
        // 6048 = 2^5 × 3^3 × 7
        let tracker = ValuationTracker::from_integer(6048);

        // 24 = 2^3 × 3 → divisible
        assert_eq!(tracker.divisibility(24), Divisibility::Yes);

        // 49 = 7^2 → not divisible (only have 7^1)
        assert_eq!(tracker.divisibility(49), Divisibility::No);

        // 8 = 2^3 → divisible
        assert_eq!(tracker.divisibility(8), Divisibility::Yes);

        // 32 = 2^5 → divisible
        assert_eq!(tracker.divisibility(32), Divisibility::Yes);

        // 64 = 2^6 → not divisible
        assert_eq!(tracker.divisibility(64), Divisibility::No);
    }

    #[test]
    fn test_mul() {
        let a = ValuationTracker::from_integer(12); // 2^2 × 3
        let b = ValuationTracker::from_integer(18); // 2 × 3^2
        let c = a.mul(&b);

        // Result: 216 = 2^3 × 3^3
        assert_eq!(c.valuation(2), 3);
        assert_eq!(c.valuation(3), 3);
        assert_eq!(c.to_integer(), Some(216));
    }

    #[test]
    fn test_checked_div() {
        let tracker = ValuationTracker::from_integer(6048);

        // Valid division
        let divided = tracker.checked_div(24).unwrap();
        // 6048 / 24 = 252 = 2^2 × 3^2 × 7
        assert_eq!(divided.valuation(2), 2);
        assert_eq!(divided.valuation(3), 2);
        assert_eq!(divided.valuation(7), 1);
        assert_eq!(divided.to_integer(), Some(252));

        // Invalid division
        assert_eq!(tracker.checked_div(64), Err(DivisionError::NotExact));
    }

    #[test]
    #[should_panic(expected = "not provably exact")]
    fn test_div_exact_panics() {
        let tracker = ValuationTracker::from_integer(72);
        let _ = tracker.div_exact(64); // Should panic
    }

    #[test]
    fn test_from_moduli_product() {
        let moduli = vec![17, 19, 23];
        let tracker = ValuationTracker::from_moduli_product(&moduli);

        // Product = 17 × 19 × 23 = 7429
        assert_eq!(tracker.valuation(17), 1);
        assert_eq!(tracker.valuation(19), 1);
        assert_eq!(tracker.valuation(23), 1);
        assert_eq!(tracker.divisibility(17), Divisibility::Yes);
        assert_eq!(tracker.divisibility(289), Divisibility::No); // 17^2
    }

    #[test]
    fn test_suggest_rescale_deterministic() {
        use fhe_integration::*;

        // Product with known factorization: 2^10 × 3^5 × 5^3
        let tracker = ValuationTracker::from_factorization(&[(2, 10), (3, 5), (5, 3)]);

        // Run multiple times - should be deterministic
        let factor1 = suggest_rescale_factor(&tracker, 20);
        let factor2 = suggest_rescale_factor(&tracker, 20);
        let factor3 = suggest_rescale_factor(&tracker, 20);

        assert_eq!(factor1, factor2);
        assert_eq!(factor2, factor3);

        // Verify the factor is valid
        if let Some(f) = factor1 {
            assert!(tracker.divisibility(f).is_definitely_divisible());
        }
    }

    #[test]
    fn test_zero() {
        let zero = ValuationTracker::zero();
        assert!(zero.is_zero());
        assert!(!zero.is_one());

        // Zero is divisible by anything (except 0)
        assert_eq!(zero.divisibility(123), Divisibility::Yes);
        assert_eq!(zero.divisibility(0), Divisibility::No);

        assert_eq!(zero.to_integer(), Some(0));
    }

    #[test]
    fn test_one() {
        let one = ValuationTracker::one();
        assert!(one.is_one());
        assert!(!one.is_zero());

        // One is only divisible by 1
        assert_eq!(one.divisibility(1), Divisibility::Yes);
        assert_eq!(one.divisibility(2), Divisibility::No);

        assert_eq!(one.to_integer(), Some(1));
    }

    #[test]
    fn test_unfactored_uncertainty() {
        // Large prime that won't be factored
        let large_prime = 1_000_003u64;
        let tracker = ValuationTracker::from_integer(large_prime);

        // We can't factor it, so unfactored should be set
        assert!(!tracker.is_fully_factored());
        assert_eq!(tracker.unfactored_part(), Some(large_prime));

        // Divisibility by small primes is definitely no
        assert_eq!(tracker.divisibility(2), Divisibility::No);
        assert_eq!(tracker.divisibility(3), Divisibility::No);

        // Divisibility by itself might be unknown or yes depending on
        // how we handle unfactored matching
        let div_result = tracker.divisibility(large_prime);
        assert!(matches!(
            div_result,
            Divisibility::Yes | Divisibility::Unknown
        ));
    }

    #[test]
    fn test_checked_div_uncertain() {
        // Create a tracker with unfactored component
        let large_prime = 1_000_003u64;
        let tracker = ValuationTracker::from_integer(large_prime * 4); // 4 × large_prime

        // Dividing by 4 should work
        assert!(tracker.checked_div(4).is_ok());

        // Dividing by 8 should fail (not exact)
        assert_eq!(tracker.checked_div(8), Err(DivisionError::NotExact));
    }

    #[test]
    fn test_add_conservative() {
        // 12 = 2^2 × 3
        let a = ValuationTracker::from_integer(12);
        // 18 = 2 × 3^2
        let b = ValuationTracker::from_integer(18);

        let sum = a.add_conservative(&b);

        // After addition, we only know:
        // ν_2(a+b) ≥ min(2, 1) = 1
        // ν_3(a+b) ≥ min(1, 2) = 1
        assert_eq!(sum.valuation(2), 1);
        assert_eq!(sum.valuation(3), 1);
    }

    #[test]
    fn test_overflow_protection() {
        // This would overflow without checked_pow
        let huge = ValuationTracker::from_factorization(&[(2, 64)]);

        // to_integer should return None (overflow)
        assert_eq!(huge.to_integer(), None);

        // Multiplication with overflow should mark unfactored as unknown
        let large = ValuationTracker::from_integer(10_000_000_019);
        let product = large.mul(&large);
        assert!(matches!(product.unfactored, Unfactored::Unknown));
        assert_eq!(product.divisibility(10_000_000_019), Divisibility::Unknown);
    }

    #[test]
    fn test_fhe_rescale_flow() {
        use fhe_integration::*;

        // Simulate FHE modulus chain: 2^60 × 3^10 × 5^5 (for demonstration)
        let tracker = ValuationTracker::from_factorization(&[(2, 60), (3, 10), (5, 5)]);

        // Can we rescale by 2^20?
        assert!(tracker.divisibility(1 << 20).is_definitely_divisible());

        // Can we rescale by 3^5?
        assert!(tracker.divisibility(243).is_definitely_divisible()); // 3^5 = 243

        // After rescaling by 2^20
        let after = tracker.checked_div(1 << 20).unwrap();
        assert_eq!(after.valuation(2), 40); // 60 - 20 = 40

        // Suggest a ~30-bit factor
        let suggested = suggest_rescale_factor(&after, 30);
        assert!(suggested.is_some());
    }
}
