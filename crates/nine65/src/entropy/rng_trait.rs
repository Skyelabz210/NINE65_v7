//! RNG Trait - Unified interface for FHE randomness sources
//!
//! Provides a common interface for both deterministic (Shadow) and
//! cryptographically secure (OS CSPRNG) randomness sources.
//!
//! # Security Guidance
//!
//! | Operation | Recommended RNG |
//! |-----------|-----------------|
//! | Key generation | `SecureRng` (MANDATORY) |
//! | Encryption randomness | `SecureRng` (production) or `ShadowHarvester` (testing) |
//! | Testing/benchmarks | `DeterministicRng` or `ShadowHarvester` |
//!
//! # Example
//!
//! ```ignore
//! use nine65::entropy::{FheRng, SecureRng, ShadowHarvester};
//!
//! // Production: use secure randomness
//! let mut rng = SecureRng::new();
//! let ct = encryptor.encrypt_with_rng(42, &mut rng);
//!
//! // Testing: use deterministic randomness
//! let mut rng = ShadowHarvester::with_seed(42);
//! let ct = encryptor.encrypt_with_rng(42, &mut rng);
//! ```

#[cfg(any(test, feature = "deterministic_rng"))]
use super::deterministic::DeterministicRng;
use super::secure::SecureRng;
use super::shadow::ShadowHarvester;

/// Trait for FHE-compatible random number generators
///
/// Both `SecureRng` and `ShadowHarvester` implement this trait,
/// allowing encryption and other operations to be generic over
/// the randomness source.
pub trait FheRng {
    /// Generate a random u64
    fn next_u64(&mut self) -> u64;

    /// Generate a random u64 in range [0, bound)
    fn uniform(&mut self, bound: u64) -> u64;

    /// Generate a ternary value {-1, 0, 1}
    fn ternary(&mut self) -> i64;

    /// Generate a CBD(eta) sample in range [-eta, eta]
    fn cbd(&mut self, eta: usize) -> i64;

    /// Generate a vector of ternary values
    fn ternary_vector(&mut self, n: usize) -> Vec<i64> {
        (0..n).map(|_| self.ternary()).collect()
    }

    /// Generate a vector of CBD samples
    fn cbd_vector(&mut self, n: usize, eta: usize) -> Vec<i64> {
        (0..n).map(|_| self.cbd(eta)).collect()
    }

    /// Generate a uniform vector in [0, bound)
    fn uniform_vector(&mut self, n: usize, bound: u64) -> Vec<u64> {
        (0..n).map(|_| self.uniform(bound)).collect()
    }

    /// Check if this RNG is cryptographically secure
    fn is_secure(&self) -> bool;
}

impl FheRng for ShadowHarvester {
    fn next_u64(&mut self) -> u64 {
        ShadowHarvester::next_u64(self)
    }

    fn uniform(&mut self, bound: u64) -> u64 {
        ShadowHarvester::uniform(self, bound)
    }

    fn ternary(&mut self) -> i64 {
        ShadowHarvester::ternary(self)
    }

    fn cbd(&mut self, eta: usize) -> i64 {
        ShadowHarvester::cbd(self, eta)
    }

    fn is_secure(&self) -> bool {
        false // Shadow entropy is deterministic, not secure
    }
}

impl FheRng for SecureRng {
    fn next_u64(&mut self) -> u64 {
        SecureRng::random_u64(self)
    }

    fn uniform(&mut self, bound: u64) -> u64 {
        SecureRng::random_u64_bounded(self, bound)
    }

    fn ternary(&mut self) -> i64 {
        SecureRng::random_ternary(self)
    }

    fn cbd(&mut self, eta: usize) -> i64 {
        SecureRng::random_cbd(self, eta)
    }

    fn is_secure(&self) -> bool {
        true // OS CSPRNG is secure
    }
}

#[cfg(any(test, feature = "deterministic_rng"))]
impl FheRng for DeterministicRng {
    fn next_u64(&mut self) -> u64 {
        DeterministicRng::next_u64(self)
    }

    fn uniform(&mut self, bound: u64) -> u64 {
        DeterministicRng::uniform(self, bound)
    }

    fn ternary(&mut self) -> i64 {
        DeterministicRng::ternary(self)
    }

    fn cbd(&mut self, eta: usize) -> i64 {
        DeterministicRng::cbd(self, eta)
    }

    fn is_secure(&self) -> bool {
        false // Deterministic RNG is test-only
    }
}

/// Wrapper that enforces secure RNG usage in production
///
/// In release builds without `allow_insecure` feature, this will
/// panic if a non-secure RNG is used for security-critical operations.
#[cfg(not(any(test, debug_assertions, feature = "allow_insecure")))]
pub fn require_secure_rng<R: FheRng>(rng: &R, operation: &str) {
    if !rng.is_secure() {
        panic!(
            "SECURITY ERROR: Non-secure RNG used for {}!\n\
             Use SecureRng for production. Shadow entropy is test-only.",
            operation
        );
    }
}

#[cfg(any(test, debug_assertions, feature = "allow_insecure"))]
pub fn require_secure_rng<R: FheRng>(_rng: &R, _operation: &str) {
    // In test/debug mode, allow any RNG
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shadow_implements_fhe_rng() {
        let mut rng = ShadowHarvester::with_seed(42);
        assert!(!rng.is_secure());

        let val = rng.next_u64();
        assert!(val > 0);

        let bounded = rng.uniform(100);
        assert!(bounded < 100);

        let tern = rng.ternary();
        assert!((-1..=1).contains(&tern));
    }

    #[test]
    fn test_secure_implements_fhe_rng() {
        let mut rng = SecureRng::new();
        assert!(rng.is_secure());

        let val = rng.next_u64();
        assert!(val > 0 || val == 0); // Could be 0, that's fine

        let bounded = rng.uniform(100);
        assert!(bounded < 100);

        let tern = rng.ternary();
        assert!((-1..=1).contains(&tern));
    }

    #[test]
    fn test_ternary_vector() {
        let mut rng = ShadowHarvester::with_seed(123);
        let vec = rng.ternary_vector(100);
        assert_eq!(vec.len(), 100);
        assert!(vec.iter().all(|&v| (-1..=1).contains(&v)));
    }

    #[test]
    fn test_deterministic_rng() {
        let mut rng = DeterministicRng::with_seed(42);
        assert!(!rng.is_secure());

        let val = rng.next_u64();
        assert!(val > 0 || val == 0);

        let bounded = rng.uniform(100);
        assert!(bounded < 100);

        let tern = rng.ternary();
        assert!((-1..=1).contains(&tern));
    }
}
