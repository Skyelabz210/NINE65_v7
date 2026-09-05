//! Entropy Module - NINE65 Entropy System
//!
//! ## Core Entropy Sources
//!
//! ### Shadow Entropy (`shadow` module)
//! - Deterministic, reproducible randomness
//! - Use for: Testing, benchmarks
//! - Fast: <10ns per sample
//! - **NOT SECURE** - never use for production keys
//!
//! ### Secure Entropy (`secure` module)
//! - OS CSPRNG (non-deterministic)
//! - Use for: Key generation, encryption randomness
//! - Required for production security
//!
//! ### Deterministic CSPRNG (`deterministic` module)
//! - ChaCha20-based deterministic RNG
//! - Use for: Reproducible tests/benchmarks
//! - NOT for production secrecy
//!
//! ### FheRng Trait (`rng_trait` module)
//! - Unified interface for both entropy sources
//! - Allows generic code over randomness source
//!
//! # Security Guidance
//!
//! | Operation | Recommended | Alternative |
//! |-----------|-------------|-------------|
//! | Secret key generation | `SecureRng` | NONE |
//! | Public key randomness | `SecureRng` | NONE |
//! | Encryption randomness | `SecureRng` | `ShadowHarvester` (testing only) |
//! | Testing/benchmarks | `DeterministicRng` | `ShadowHarvester` |
//!
//! # Example
//!
//! ```ignore
//! use nine65::entropy::{FheRng, SecureRng, ShadowHarvester};
//!
//! // Production encryption
//! let mut rng = SecureRng::new();
//! let ct = encryptor.encrypt_with_rng(42, &mut rng);
//!
//! // Testing with deterministic randomness
//! let mut rng = ShadowHarvester::with_seed(42);
//! let ct = encryptor.encrypt_with_rng(42, &mut rng);
//! ```

pub mod rng_trait;
pub mod secure;
pub mod shadow;

#[cfg(any(test, feature = "deterministic_rng"))]
pub mod deterministic;

#[cfg(feature = "shadow-entropy")]
pub mod crt_shadow;
// RETIRED (issue #68): `wassan_noise` (WASSAN Holographic Noise Field) had
// zero production callers — it was never part of the entropy guidance table
// above and the `wassan` Cargo feature alias that used to gate it was already
// removed as a no-op in 2026-03-01. Only its own tests exercised it. Removed
// entirely; see docs/ENTROPY_MODEL.md and docs/LADDER_REMOVAL.md for the
// SBNI retirement this completes alongside.

// NEW: Shadow Entropy Monitor for adaptive resource management
pub mod shadow_entropy_monitor;

pub use rng_trait::{require_secure_rng, FheRng};
pub use shadow::ShadowHarvester;

#[cfg(any(test, feature = "deterministic_rng"))]
pub use deterministic::DeterministicRng;

#[cfg(feature = "shadow-entropy")]
pub use crt_shadow::{
    CRTShadowContext, IntegratedShadowRNS, QuotientSignature, ShadowAccumulator, ShadowStats,
};
// Export the shadow entropy monitor
pub use shadow_entropy_monitor::{AdaptiveFHEContext, ShadowEntropyMonitor};

pub use secure::{
    entropy_health_check, secure_bytes, secure_cbd, secure_cbd_vector, secure_ternary,
    secure_ternary_vector, secure_u128, secure_u64, secure_u64_bounded, secure_uniform_vector,
    try_secure_bytes, try_secure_cbd, try_secure_cbd_vector, try_secure_ternary,
    try_secure_ternary_vector, try_secure_u128, try_secure_u64, try_secure_u64_bounded,
    try_secure_uniform_vector, SecureEntropyResult, SecureRng,
};

/// Generate a cryptographically secure seed from OS CSPRNG.
///
/// Convenience function for creating a ShadowHarvester with secure initialization:
/// ```ignore
/// let seed = secure_seed_from_os();
/// let mut rng = ShadowHarvester::with_seed(seed);
/// ```
///
/// This provides deterministic operation after initialization while ensuring
/// the starting state is unpredictable.
#[cfg(feature = "secure_seed")]
#[inline]
pub fn secure_seed_from_os() -> u64 {
    secure_u64()
}
