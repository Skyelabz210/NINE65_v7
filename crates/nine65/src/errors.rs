//! NINE65 Error Taxonomy
//!
//! Standardized error types derived from Coq proof preconditions.
//! Every error maps to a specific theorem violation.
//!
//! # Theorem Reference
//! Error conditions are derived from:
//! - `KElimination.v` — Division preconditions
//! - `GSOFHE.v` — Noise bounds
//! - `OrderFinding.v` — Coprimality requirements
//! - `MQReLU.v` — Modulus constraints

use thiserror::Error;

/// NINE65 Error Types
///
/// Comprehensive error taxonomy for all components.
/// Each variant maps to a specific Coq precondition violation.
#[derive(Debug, Clone, Error)]
pub enum Nine65Error {
    // ═══════════════════════════════════════════════════
    // K-ELIMINATION ERRORS (KElimination.v)
    // ═══════════════════════════════════════════════════
    /// Coprimality violation: gcd(M, A) ≠ 1
    ///
    /// # Theorem Reference
    /// `KElimination.v:kElimination_core` requires coprime moduli
    #[error("coprimality violation: gcd({m}, {a}) = {gcd} ≠ 1")]
    NotCoprime { m: u64, a: u64, gcd: u64 },

    /// Range overflow: X ≥ M * A
    ///
    /// # Theorem Reference
    /// `KElimination.v:kElimination_core` requires X < M * A
    #[error("range overflow: X={x} ≥ M*A={bound}")]
    RangeOverflow { x: u128, bound: u128 },

    /// Modulus zero: M must be > 0
    ///
    /// # Theorem Reference
    /// `KElimination.v` — M > 0 precondition
    #[error("modulus zero: M must be > 0")]
    ModulusZero,

    /// Anchor zero: A must be > 0
    ///
    /// # Theorem Reference
    /// `KElimination.v` — A > 0 precondition
    #[error("anchor zero: A must be > 0")]
    AnchorZero,

    /// Inexact division: divisor does not divide value
    ///
    /// # Theorem Reference
    /// `ExactCoefficient.v:div_exact` requires divisibility
    #[error("inexact division: {value} not divisible by {divisor}")]
    InexactDivision { value: u128, divisor: u64 },

    // ═══════════════════════════════════════════════════
    // GSO-FHE ERRORS (GSOFHE.v)
    // ═══════════════════════════════════════════════════
    /// Noise overflow: exceeded collapse threshold
    ///
    /// # Theorem Reference
    /// `GSOFHE.v:noise_bounded` — noise ≤ threshold
    #[error("noise overflow: {level} > threshold {threshold}")]
    NoiseOverflow { level: u64, threshold: u64 },

    /// Depth exceeded: circuit too deep
    ///
    /// # Theorem Reference
    /// `GSOFHE.v:depth_50_achievable` — depth bounds
    #[error("depth exceeded: {depth} > max {max_depth}")]
    DepthExceeded { depth: u32, max_depth: u32 },

    // ═══════════════════════════════════════════════════
    // ORDER FINDING ERRORS (OrderFinding.v)
    // ═══════════════════════════════════════════════════
    /// Order not found within bound
    ///
    /// # Theorem Reference
    /// `OrderFinding.v:lagrange_bound` — order ≤ N-1
    #[error("order not found: a={a} mod N={n} within bound {bound}")]
    OrderNotFound { a: u64, n: u64, bound: u64 },

    /// Not coprime to modulus (for order finding)
    ///
    /// # Theorem Reference
    /// `OrderFinding.v:lagrange_bound` requires gcd(a, N) = 1
    #[error("not coprime to modulus: gcd({a}, {n}) ≠ 1")]
    NotCoprimeToModulus { a: u64, n: u64 },

    // ═══════════════════════════════════════════════════
    // ARITHMETIC ERRORS
    // ═══════════════════════════════════════════════════
    /// Integer overflow during computation
    ///
    /// # Note
    /// Coq `nat` is unbounded; Rust u64/u128 is not.
    /// This error indicates need for BigUint.
    #[error("integer overflow in {operation}")]
    Overflow { operation: &'static str },

    /// Invalid parameter configuration
    #[error("invalid parameter: {message}")]
    InvalidParameter { message: String },

    // ═══════════════════════════════════════════════════
    // CRYPTOGRAPHIC ERRORS
    // ═══════════════════════════════════════════════════
    /// Decryption failed (noise too high)
    #[error("decryption failed: noise exceeded budget")]
    DecryptionFailed,

    /// Key generation failed
    #[error("key generation failed: {reason}")]
    KeyGenFailed { reason: String },

    /// Security level not met
    #[error("security level not met: {bits} bits < required {required} bits")]
    SecurityLevelNotMet { bits: u32, required: u32 },

    // ═══════════════════════════════════════════════════
    // ENCODING/ENCRYPTION ERRORS
    // ═══════════════════════════════════════════════════
    /// Message out of plaintext space bounds
    ///
    /// # Theorem Reference
    /// BFV encoding requires m < t (plaintext modulus)
    #[error("message out of bounds: {message} >= plaintext modulus {modulus}")]
    MessageOutOfBounds { message: u64, modulus: u64 },

    /// Invalid polynomial degree
    #[error("invalid polynomial degree: got {got}, expected {expected}")]
    InvalidPolynomialDegree { got: usize, expected: usize },

    /// Key regime mismatch
    #[error("key regime mismatch: {message}")]
    KeyRegimeMismatch { message: String },

    /// NTT configuration error
    #[error("NTT configuration error: {message}")]
    NTTConfigError { message: String },

    /// Invalid configuration
    #[error("configuration error: {message}")]
    ConfigError { message: String },

    // ═══════════════════════════════════════════════════
    // BATCHING ERRORS
    // ═══════════════════════════════════════════════════
    /// Batching not supported for given parameters
    ///
    /// # Requirement
    /// CRT batching requires `t ≡ 1 (mod 2N)` for the ring to split
    #[error("batching not supported for t={t}, N={n}: {reason}")]
    BatchingNotSupported { t: u64, n: usize, reason: String },

    /// Too many slot values for batching
    #[error("too many slot values: got {got}, max {max}")]
    TooManySlotValues { got: usize, max: usize },

    /// No modular inverse exists
    #[error("no modular inverse: {value}^(-1) mod {modulus} does not exist")]
    NoModularInverse { value: u64, modulus: u64 },

    // ═══════════════════════════════════════════════════
    // SERIALIZATION ERRORS
    // ═══════════════════════════════════════════════════
    /// Deserialization failed
    ///
    /// # Security
    /// Returned when deserializing untrusted input fails validation.
    /// Prevents DoS via malformed data.
    #[error("deserialization error: {message}")]
    DeserializationError { message: String },

    // ═══════════════════════════════════════════════════
    // BOOTSTRAP ERRORS
    // ═══════════════════════════════════════════════════
    /// Bootstrap procedure failed
    #[error("bootstrap failed: {reason}")]
    BootstrapFailed { reason: String },

    /// Bootstrap configuration mismatch
    #[error("bootstrap config mismatch: {reason}")]
    BootstrapConfigMismatch { reason: String },

    /// Arithmetic overflow during bootstrap
    #[error("bootstrap arithmetic overflow in: {operation}")]
    BootstrapOverflow { operation: String },

    // ═══════════════════════════════════════════════════
    // ENTROPY ERRORS
    // ═══════════════════════════════════════════════════
    /// OS CSPRNG failure
    ///
    /// The operating system's cryptographic random number generator
    /// failed to provide entropy. This indicates a fundamental
    /// system-level problem.
    #[error("entropy source failure: {reason}")]
    EntropyFailure { reason: String },

    // ═══════════════════════════════════════════════════
    // NOISE BUDGET ERRORS
    // ═══════════════════════════════════════════════════
    /// Noise budget exhausted — decryption would fail
    ///
    /// # Security
    /// IBM's 2025 BFV key recovery attack exploits noise overflow.
    /// This error MUST be returned (never silently wrapped) to prevent
    /// decryption failure oracles.
    #[error("noise budget exhausted: needed {required_mb} millibits, had {available_mb}")]
    NoiseBudgetExhausted { required_mb: i64, available_mb: i64 },

    // ═══════════════════════════════════════════════════
    // REGIME MISMATCH ERRORS
    // ═══════════════════════════════════════════════════
    /// Single/Dual RNS regime mismatch
    ///
    /// Ciphertext, key, or operation does not match the
    /// expected RNS regime (Single vs Dual K-Elimination).
    #[error("regime mismatch in {operation}: expected {expected}, got {got}")]
    RegimeMismatch {
        operation: &'static str,
        expected: &'static str,
        got: &'static str,
    },
}

/// Result type alias for NINE65 operations
pub type Nine65Result<T> = Result<T, Nine65Error>;

impl Nine65Error {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Nine65Error::NoiseOverflow { .. }
                | Nine65Error::DepthExceeded { .. }
                | Nine65Error::BootstrapFailed { .. }
                | Nine65Error::NoiseBudgetExhausted { .. }
        )
    }

    /// Check if error is batching-related
    pub fn is_batching_error(&self) -> bool {
        matches!(
            self,
            Nine65Error::BatchingNotSupported { .. }
                | Nine65Error::TooManySlotValues { .. }
                | Nine65Error::NoModularInverse { .. }
        )
    }

    /// Get error category for logging
    pub fn category(&self) -> &'static str {
        match self {
            Nine65Error::NotCoprime { .. }
            | Nine65Error::RangeOverflow { .. }
            | Nine65Error::ModulusZero
            | Nine65Error::AnchorZero
            | Nine65Error::InexactDivision { .. } => "K-Elimination",

            Nine65Error::NoiseOverflow { .. } | Nine65Error::DepthExceeded { .. } => "GSO-FHE",

            Nine65Error::OrderNotFound { .. } | Nine65Error::NotCoprimeToModulus { .. } => {
                "Order Finding"
            }

            Nine65Error::Overflow { .. } | Nine65Error::InvalidParameter { .. } => "Arithmetic",

            Nine65Error::DecryptionFailed
            | Nine65Error::KeyGenFailed { .. }
            | Nine65Error::SecurityLevelNotMet { .. } => "Cryptographic",

            Nine65Error::MessageOutOfBounds { .. }
            | Nine65Error::InvalidPolynomialDegree { .. }
            | Nine65Error::KeyRegimeMismatch { .. } => "Encoding",

            Nine65Error::NTTConfigError { .. } | Nine65Error::ConfigError { .. } => "Configuration",

            Nine65Error::BatchingNotSupported { .. }
            | Nine65Error::TooManySlotValues { .. }
            | Nine65Error::NoModularInverse { .. } => "Batching",

            Nine65Error::DeserializationError { .. } => "Serialization",

            Nine65Error::BootstrapFailed { .. }
            | Nine65Error::BootstrapConfigMismatch { .. }
            | Nine65Error::BootstrapOverflow { .. } => "Bootstrap",

            Nine65Error::EntropyFailure { .. } => "Entropy",

            Nine65Error::NoiseBudgetExhausted { .. } => "Noise",

            Nine65Error::RegimeMismatch { .. } => "Regime",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Nine65Error::NotCoprime {
            m: 10,
            a: 15,
            gcd: 5,
        };
        assert!(err.to_string().contains("coprimality violation"));
        assert_eq!(err.category(), "K-Elimination");
    }

    #[test]
    fn test_error_recoverable() {
        let recoverable = Nine65Error::NoiseOverflow {
            level: 100,
            threshold: 50,
        };
        let not_recoverable = Nine65Error::ModulusZero;

        assert!(recoverable.is_recoverable());
        assert!(!not_recoverable.is_recoverable());
    }

    #[test]
    fn test_entropy_failure_error() {
        let err = Nine65Error::EntropyFailure {
            reason: "OS CSPRNG unavailable".to_string(),
        };
        assert!(err.to_string().contains("entropy source failure"));
        assert_eq!(err.category(), "Entropy");
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_noise_budget_exhausted_error() {
        let err = Nine65Error::NoiseBudgetExhausted {
            required_mb: 5000,
            available_mb: 2000,
        };
        assert!(err.to_string().contains("noise budget exhausted"));
        assert_eq!(err.category(), "Noise");
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_regime_mismatch_error() {
        let err = Nine65Error::RegimeMismatch {
            operation: "encrypt_auto",
            expected: "Dual",
            got: "Single",
        };
        assert!(err.to_string().contains("regime mismatch"));
        assert_eq!(err.category(), "Regime");
        assert!(!err.is_recoverable());
    }
}
