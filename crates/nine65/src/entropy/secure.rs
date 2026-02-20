//! Secure Entropy Module - OS CSPRNG Wrapper
//!
//! SECURITY CRITICAL: This module provides cryptographically secure
//! random number generation using the operating system's CSPRNG.
//!
//! ## Usage
//!
//! ```ignore
//! use nine65::entropy::SecureRng;
//!
//! // Create a CSPRNG instance
//! let mut rng = SecureRng::new();
//!
//! // Generate random values
//! let key_bytes = rng.random_bytes(32);
//! let random_value = rng.random_u64();
//! let bounded = rng.random_u64_bounded(998244353);
//! ```
//!
//! Use this for:
//! - Secret key generation
//! - Public key randomness (the 'a' polynomial)
//! - Any security-critical random values
//!
//! Do NOT use Shadow Entropy for security-critical operations.

use getrandom::getrandom;
use getrandom::Error as GetRandomError;

/// Result type for secure entropy operations.
pub type SecureEntropyResult<T> = Result<T, GetRandomError>;

/// Cryptographically Secure Pseudo-Random Number Generator
///
/// Wraps the operating system's CSPRNG (via `getrandom` crate).
/// This is the correct entropy source for all cryptographic operations.
///
/// # Security
///
/// - Backed by `/dev/urandom` on Linux, `CryptGenRandom` on Windows
/// - Suitable for key generation and all security-critical uses
/// - NIST SP 800-90B compliant entropy source
#[derive(Debug, Default)]
pub struct SecureRng {
    _private: (), // Prevent construction except via new()
}

impl SecureRng {
    /// Create a new CSPRNG instance
    #[inline]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Fill a buffer with cryptographically secure random bytes.
    #[inline]
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        secure_bytes(buf);
    }

    /// Fallible byte fill using OS CSPRNG.
    #[inline]
    pub fn try_fill_bytes(&mut self, buf: &mut [u8]) -> SecureEntropyResult<()> {
        try_secure_bytes(buf)
    }

    /// Generate a vector of cryptographically secure random bytes
    #[inline]
    pub fn random_bytes(&mut self, len: usize) -> Vec<u8> {
        self.try_random_bytes(len)
            .expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
    }

    /// Fallible random byte generation.
    #[inline]
    pub fn try_random_bytes(&mut self, len: usize) -> SecureEntropyResult<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.try_fill_bytes(&mut buf)?;
        Ok(buf)
    }

    /// Generate a cryptographically secure random u64
    #[inline]
    pub fn random_u64(&mut self) -> u64 {
        self.try_random_u64()
            .expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
    }

    /// Fallible random u64 generation.
    #[inline]
    pub fn try_random_u64(&mut self) -> SecureEntropyResult<u64> {
        try_secure_u64()
    }

    /// Generate a cryptographically secure random u128
    #[inline]
    pub fn random_u128(&mut self) -> u128 {
        self.try_random_u128()
            .expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
    }

    /// Fallible random u128 generation.
    #[inline]
    pub fn try_random_u128(&mut self) -> SecureEntropyResult<u128> {
        try_secure_u128()
    }

    /// Generate a cryptographically secure random u64 in range [0, bound)
    ///
    /// Uses rejection sampling to avoid modulo bias.
    #[inline]
    pub fn random_u64_bounded(&mut self, bound: u64) -> u64 {
        self.try_random_u64_bounded(bound)
            .expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
    }

    /// Fallible bounded random generation.
    #[inline]
    pub fn try_random_u64_bounded(&mut self, bound: u64) -> SecureEntropyResult<u64> {
        try_secure_u64_bounded(bound)
    }

    /// Generate a cryptographically secure ternary value {-1, 0, 1}
    #[inline]
    pub fn random_ternary(&mut self) -> i64 {
        self.try_random_ternary()
            .expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
    }

    /// Fallible ternary sampling.
    #[inline]
    pub fn try_random_ternary(&mut self) -> SecureEntropyResult<i64> {
        try_secure_ternary()
    }

    /// Generate a CBD(eta) sample using secure randomness
    #[inline]
    pub fn random_cbd(&mut self, eta: usize) -> i64 {
        self.try_random_cbd(eta)
            .expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
    }

    /// Fallible CBD sampling.
    #[inline]
    pub fn try_random_cbd(&mut self, eta: usize) -> SecureEntropyResult<i64> {
        try_secure_cbd(eta)
    }

    /// Generate a ternary polynomial {-1, 0, 1}^n
    #[inline]
    pub fn ternary_polynomial(&mut self, n: usize) -> Vec<i64> {
        self.try_ternary_polynomial(n)
            .expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
    }

    /// Fallible ternary polynomial generation.
    #[inline]
    pub fn try_ternary_polynomial(&mut self, n: usize) -> SecureEntropyResult<Vec<i64>> {
        try_secure_ternary_vector(n)
    }

    /// Generate a CBD(eta) polynomial of length n
    #[inline]
    pub fn cbd_polynomial(&mut self, n: usize, eta: usize) -> Vec<i64> {
        self.try_cbd_polynomial(n, eta)
            .expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
    }

    /// Fallible CBD polynomial generation.
    #[inline]
    pub fn try_cbd_polynomial(&mut self, n: usize, eta: usize) -> SecureEntropyResult<Vec<i64>> {
        try_secure_cbd_vector(n, eta)
    }

    /// Generate a uniform polynomial with coefficients in [0, bound)
    #[inline]
    pub fn uniform_polynomial(&mut self, n: usize, bound: u64) -> Vec<u64> {
        self.try_uniform_polynomial(n, bound)
            .expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
    }

    /// Fallible uniform polynomial generation.
    #[inline]
    pub fn try_uniform_polynomial(
        &mut self,
        n: usize,
        bound: u64,
    ) -> SecureEntropyResult<Vec<u64>> {
        try_secure_uniform_vector(n, bound)
    }
}

/// Get cryptographically secure random bytes from OS
///
/// # Panics
/// Panics if the OS CSPRNG fails. Use `try_secure_bytes()` to handle failures.
#[inline]
pub fn secure_bytes(buf: &mut [u8]) {
    try_secure_bytes(buf)
        .expect("CRITICAL: OS CSPRNG failure - system entropy unavailable, cannot proceed safely");
}

/// Fallible secure byte fill from OS CSPRNG.
#[inline]
pub fn try_secure_bytes(buf: &mut [u8]) -> SecureEntropyResult<()> {
    getrandom(buf)
}

/// Generate a cryptographically secure random u64
#[inline]
pub fn secure_u64() -> u64 {
    try_secure_u64().expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
}

/// Fallible random u64 generation.
#[inline]
pub fn try_secure_u64() -> SecureEntropyResult<u64> {
    let mut buf = [0u8; 8];
    try_secure_bytes(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Generate a cryptographically secure random u128
#[inline]
pub fn secure_u128() -> u128 {
    try_secure_u128().expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
}

/// Fallible random u128 generation.
#[inline]
pub fn try_secure_u128() -> SecureEntropyResult<u128> {
    let mut buf = [0u8; 16];
    try_secure_bytes(&mut buf)?;
    Ok(u128::from_le_bytes(buf))
}

/// Generate a cryptographically secure random u64 in range [0, bound)
///
/// Uses rejection sampling to avoid modulo bias.
#[inline]
pub fn secure_u64_bounded(bound: u64) -> u64 {
    try_secure_u64_bounded(bound).expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
}

/// Fallible bounded random generation.
#[inline]
pub fn try_secure_u64_bounded(bound: u64) -> SecureEntropyResult<u64> {
    if bound == 0 {
        return Ok(0);
    }
    if bound == 1 {
        return Ok(0);
    }

    // Rejection sampling to avoid modulo bias
    // threshold is the largest multiple of bound that fits in u64
    let threshold = u64::MAX - (u64::MAX % bound);

    loop {
        let val = try_secure_u64()?;
        if val < threshold {
            return Ok(val % bound);
        }
        // Rejection probability is at most 50%, expected iterations < 2
    }
}

/// Generate a cryptographically secure ternary value {-1, 0, 1}
///
/// Returns values with equal probability (1/3 each).
#[inline]
pub fn secure_ternary() -> i64 {
    try_secure_ternary().expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
}

/// Fallible ternary sampling.
#[inline]
pub fn try_secure_ternary() -> SecureEntropyResult<i64> {
    // Use rejection sampling for uniform distribution over 3 values
    loop {
        let r = try_secure_u64()? % 4; // 0, 1, 2, 3
        if r < 3 {
            return Ok((r as i64) - 1); // -1, 0, 1
        }
        // Reject r=3, try again (25% rejection rate)
    }
}

/// Generate a CBD(η) sample using secure randomness
///
/// Centered Binomial Distribution: sum of η coin flips minus η coin flips
/// Range: [-η, η], variance: η/2
#[inline]
pub fn secure_cbd(eta: usize) -> i64 {
    try_secure_cbd(eta).expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
}

/// Fallible CBD sampling.
#[inline]
pub fn try_secure_cbd(eta: usize) -> SecureEntropyResult<i64> {
    let mut sum = 0i64;

    // Each iteration: add one bit, subtract another bit
    // This gives CBD with parameter η
    for _ in 0..eta {
        let bits = try_secure_u64()?;
        let a = (bits & 1) as i64;
        let b = ((bits >> 1) & 1) as i64;
        sum += a - b;
    }

    Ok(sum)
}

/// Generate a vector of CBD(η) samples
pub fn secure_cbd_vector(n: usize, eta: usize) -> Vec<i64> {
    try_secure_cbd_vector(n, eta).expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
}

/// Fallible CBD vector generation.
pub fn try_secure_cbd_vector(n: usize, eta: usize) -> SecureEntropyResult<Vec<i64>> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(try_secure_cbd(eta)?);
    }
    Ok(out)
}

/// Generate a vector of uniform random values in [0, bound)
pub fn secure_uniform_vector(n: usize, bound: u64) -> Vec<u64> {
    try_secure_uniform_vector(n, bound)
        .expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
}

/// Fallible uniform vector generation.
pub fn try_secure_uniform_vector(n: usize, bound: u64) -> SecureEntropyResult<Vec<u64>> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(try_secure_u64_bounded(bound)?);
    }
    Ok(out)
}

/// Run a basic health check on the OS CSPRNG.
///
/// Generates two 32-byte samples and verifies they differ and contain
/// non-zero entropy. This catches catastrophic CSPRNG failures
/// (stuck entropy pool, /dev/urandom misconfiguration).
///
/// # Returns
///
/// `true` if the CSPRNG appears healthy; `false` otherwise.
///
/// # When to Call
///
/// Call at application startup, before the first key generation,
/// and periodically during long-running FHE computations.
pub fn entropy_health_check() -> bool {
    let mut buf1 = [0u8; 32];
    let mut buf2 = [0u8; 32];

    if try_secure_bytes(&mut buf1).is_err() {
        return false;
    }
    if try_secure_bytes(&mut buf2).is_err() {
        return false;
    }

    // Check for stuck entropy (same output twice)
    // Two identical 32-byte samples is a 2^{-256} event —
    // if it happens, the CSPRNG is broken.
    if buf1 == buf2 {
        return false;
    }

    // Check for all-zeros (dead entropy pool)
    if buf1.iter().all(|&b| b == 0) || buf2.iter().all(|&b| b == 0) {
        return false;
    }

    true
}

/// Generate a ternary vector {-1, 0, 1}^n
pub fn secure_ternary_vector(n: usize) -> Vec<i64> {
    try_secure_ternary_vector(n).expect("CRITICAL: OS CSPRNG failure - system entropy unavailable")
}

/// Fallible ternary vector generation.
pub fn try_secure_ternary_vector(n: usize) -> SecureEntropyResult<Vec<i64>> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(try_secure_ternary()?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_bytes() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        secure_bytes(&mut buf1);
        secure_bytes(&mut buf2);

        // Should be different (probability of same: 2^-256)
        assert_ne!(buf1, buf2, "CSPRNG produced identical outputs");

        // Should have non-zero entropy
        assert!(buf1.iter().any(|&b| b != 0), "CSPRNG produced all zeros");
    }

    #[test]
    fn test_secure_u64_bounded() {
        // Test various bounds
        for bound in [2, 3, 7, 100, 65537, 998244353] {
            for _ in 0..100 {
                let val = secure_u64_bounded(bound);
                assert!(val < bound, "Value {} >= bound {}", val, bound);
            }
        }
    }

    #[test]
    fn test_secure_ternary_distribution() {
        let samples: Vec<i64> = (0..10000).map(|_| secure_ternary()).collect();

        // All values should be in {-1, 0, 1}
        for &s in &samples {
            assert!((-1..=1).contains(&s), "Ternary out of range: {}", s);
        }

        // Check rough uniformity (each should be ~3333)
        let neg_ones = samples.iter().filter(|&&s| s == -1).count();
        let zeros = samples.iter().filter(|&&s| s == 0).count();
        let pos_ones = samples.iter().filter(|&&s| s == 1).count();

        // Allow 20% deviation from expected
        assert!(
            neg_ones > 2500 && neg_ones < 4200,
            "Bad -1 count: {}",
            neg_ones
        );
        assert!(zeros > 2500 && zeros < 4200, "Bad 0 count: {}", zeros);
        assert!(
            pos_ones > 2500 && pos_ones < 4200,
            "Bad 1 count: {}",
            pos_ones
        );
    }

    #[test]
    fn test_secure_cbd() {
        let eta = 3;
        let samples: Vec<i64> = (0..10000).map(|_| secure_cbd(eta)).collect();

        // All values should be in [-η, η]
        for &s in &samples {
            assert!(
                s >= -(eta as i64) && s <= eta as i64,
                "CBD out of range: {} not in [{}, {}]",
                s,
                -(eta as i64),
                eta
            );
        }

        // Check variance is approximately η/2
        // Integer-only: compute mean and variance in scaled units (x1000)
        let sum: i128 = samples.iter().map(|&s| s as i128).sum();
        let n = samples.len() as i128;
        let mean_x1000 = (sum * 1000) / n;
        let var_x1000 = samples
            .iter()
            .map(|&s| {
                let d = s as i128 * 1000 - mean_x1000;
                d * d
            })
            .sum::<i128>()
            / (n * 1000);
        let expected_var_x1000 = eta as i128 * 500; // eta/2 * 1000
        let diff = (var_x1000 - expected_var_x1000).abs();
        assert!(
            diff < 500, // 0.5 * 1000
            "CBD variance (x1000) {} far from expected (x1000) {}",
            var_x1000,
            expected_var_x1000
        );
    }

    #[test]
    fn test_entropy_health_check_passes() {
        assert!(
            entropy_health_check(),
            "Entropy health check should pass on a healthy system"
        );
    }

    #[test]
    fn test_entropy_health_check_multiple_calls() {
        // Health check should consistently pass
        for i in 0..5 {
            assert!(
                entropy_health_check(),
                "Entropy health check failed on iteration {}",
                i
            );
        }
    }

    #[test]
    fn test_secure_vectors() {
        let n = 1024;
        let bound = 998244353u64;

        let uniform = secure_uniform_vector(n, bound);
        assert_eq!(uniform.len(), n);
        assert!(uniform.iter().all(|&v| v < bound));

        let ternary = secure_ternary_vector(n);
        assert_eq!(ternary.len(), n);
        assert!(ternary.iter().all(|&v| (-1..=1).contains(&v)));

        let cbd = secure_cbd_vector(n, 3);
        assert_eq!(cbd.len(), n);
        assert!(cbd.iter().all(|&v| (-3..=3).contains(&v)));
    }
}
