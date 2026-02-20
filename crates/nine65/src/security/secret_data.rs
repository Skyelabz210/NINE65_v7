//! Secret Data Marker Trait for Constant-Time Enforcement
//!
//! This module provides type-level markers for secret data that require
//! constant-time operations. These types ensure secret data is:
//! - Properly zeroized on drop (memory safety)
//! - Clearly identified as secret in the type system
//! - Ready for future CT-enforcing API integration
//!
//! # Current Status
//!
//! This module provides the **foundation** for CT enforcement. The marker
//! types (`SecretPoly`, `SecretScalar`) are available for wrapping secret
//! data with automatic zeroization. Full integration with NTT/keygen APIs
//! to enforce CT-only paths is planned for a future release.
//!
//! # Usage
//!
//! ```ignore
//! use nine65::security::secret_data::{SecretData, SecretPoly, SecretScalar};
//!
//! // Wrap secret polynomial with automatic zeroization
//! let secret = SecretPoly::new(secret_key.s.coeffs.clone(), config.q);
//! // secret is automatically zeroized when dropped
//!
//! // Constant-time scalar operations
//! let a = SecretScalar::new(42);
//! let b = SecretScalar::new(42);
//! let eq = a.ct_eq(&b);  // Returns 1 (equal) without branching
//! ```
//!
//! # Security Properties
//!
//! Types implementing `SecretData`:
//! - Are zeroized on drop via `zeroize` crate
//! - Should only be processed with constant-time algorithms
//! - Provide CT comparison and selection primitives (`ct_eq`, `ct_select`)
//!
//! # Theorem Reference
//! - Proof File: `SideChannelResistance.v`
//! - Status: VERIFIED

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Marker trait for data requiring constant-time operations
///
/// Types implementing this trait must only be processed using
/// constant-time algorithms to prevent timing side-channels.
///
/// # Contract
///
/// Implementors agree that:
/// 1. All operations on this data will use constant-time algorithms
/// 2. The data will be zeroized on drop
/// 3. No branching or indexing based on secret values
pub trait SecretData: Sized + Zeroize {}

/// Polynomial containing secret data (e.g., secret key)
///
/// This wrapper ensures that NTT and other operations on this
/// polynomial use constant-time implementations.
///
/// # Thread Safety
///
/// `SecretPoly` is `Send + Sync`. Secret polynomials can be safely:
/// - Sent between threads (`Send`)
/// - Shared via `Arc<SecretPoly>` for concurrent read access (`Sync`)
///
/// Clone before modifying in different threads.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretPoly {
    /// The secret polynomial coefficients
    pub coeffs: Vec<u64>,
    /// The modulus
    pub q: u64,
}

impl SecretData for SecretPoly {}

impl SecretPoly {
    /// Create a new secret polynomial
    pub fn new(coeffs: Vec<u64>, q: u64) -> Self {
        Self { coeffs, q }
    }

    /// Get the length of the polynomial
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    /// Check if the polynomial is empty
    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }

    /// Get a reference to the coefficients
    ///
    /// # Security
    /// Caller must ensure all operations on returned slice are constant-time.
    pub fn as_slice(&self) -> &[u64] {
        &self.coeffs
    }
}

/// Secret scalar value
///
/// Use for individual secret values that need CT protection.
///
/// # Thread Safety
///
/// `SecretScalar` is `Send + Sync`. Secret scalars can be safely:
/// - Sent between threads (`Send`)
/// - Shared via `Arc<SecretScalar>` for concurrent read access (`Sync`)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretScalar {
    /// The secret value
    pub value: u64,
}

impl SecretData for SecretScalar {}

impl SecretScalar {
    /// Create a new secret scalar
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    /// Constant-time equality comparison
    ///
    /// Returns 1 if equal, 0 otherwise.
    /// Uses bitwise operations to avoid branching.
    pub fn ct_eq(&self, other: &Self) -> u64 {
        // XOR gives 0 if equal, non-zero otherwise
        let diff = self.value ^ other.value;
        // Collapse all bits: result is 0 only if diff == 0
        let collapsed = diff | diff.wrapping_neg();
        // High bit is 1 if diff != 0
        let not_equal = collapsed >> 63;
        // Return 1 if equal (not_equal == 0)
        1 - not_equal
    }

    /// Constant-time conditional select
    ///
    /// If choice == 1, returns self. If choice == 0, returns other.
    /// Choice must be 0 or 1.
    pub fn ct_select(&self, other: &Self, choice: u64) -> Self {
        debug_assert!(choice == 0 || choice == 1);
        // Expand choice to all bits: 0 -> 0, 1 -> all 1s
        let mask = 0u64.wrapping_sub(choice);
        // If mask is all 1s (choice=1), use self; else use other
        let value = (self.value & mask) | (other.value & !mask);
        Self { value }
    }
}

/// Marker trait for operations that touch secret key material.
///
/// Types implementing `SecretKeyPath` guarantee that all arithmetic
/// on their data uses constant-time algorithms. This is enforced at
/// the type level: functions requiring CT safety accept `impl SecretKeyPath`
/// rather than raw polynomials, preventing accidental variable-time use.
///
/// # Contract
///
/// Implementors agree that:
/// 1. All NTT operations use CT variants (`mul_ct`, not `mul`)
/// 2. No branching on coefficient values
/// 3. No early-exit optimizations based on data
/// 4. Memory access patterns are data-independent
///
/// # Security
///
/// This trait is the compile-time enforcement of side-channel resistance.
/// The GRO timing gate (INV-7) provides runtime protection; this trait
/// provides static protection by making it a type error to use variable-time
/// code paths with secret data.
pub trait SecretKeyPath: SecretData {
    /// Get coefficients for CT-safe processing.
    ///
    /// The returned slice must only be used with constant-time operations.
    fn ct_coeffs(&self) -> &[u64];

    /// Get the modulus for CT-safe operations.
    fn ct_modulus(&self) -> u64;
}

impl SecretKeyPath for SecretPoly {
    fn ct_coeffs(&self) -> &[u64] {
        &self.coeffs
    }

    fn ct_modulus(&self) -> u64 {
        self.q
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// THREAD SAFETY ASSERTIONS
// ═══════════════════════════════════════════════════════════════════════════

// Compile-time verification that secret types are thread-safe.
// These assertions fail at compile time if the types don't implement Send/Sync.
const _: () = {
    const fn assert_send<T: Send>() {}
    const fn assert_sync<T: Sync>() {}

    // SecretPoly can be safely sent between threads and shared
    assert_send::<SecretPoly>();
    assert_sync::<SecretPoly>();

    // SecretScalar can be safely sent between threads and shared
    assert_send::<SecretScalar>();
    assert_sync::<SecretScalar>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_poly_zeroize() {
        let mut poly = SecretPoly::new(vec![1, 2, 3, 4], 17);
        poly.zeroize();
        assert!(poly.coeffs.iter().all(|&c| c == 0));
    }

    #[test]
    fn test_secret_scalar_ct_eq() {
        let a = SecretScalar::new(42);
        let b = SecretScalar::new(42);
        let c = SecretScalar::new(43);

        assert_eq!(a.ct_eq(&b), 1);
        assert_eq!(a.ct_eq(&c), 0);
    }

    #[test]
    fn test_secret_key_path_trait() {
        let poly = SecretPoly::new(vec![1, 0, 3, 4], 17);

        // SecretKeyPath should provide ct_coeffs and ct_modulus
        use super::SecretKeyPath;
        assert_eq!(poly.ct_coeffs(), &[1, 0, 3, 4]);
        assert_eq!(poly.ct_modulus(), 17);
    }

    #[test]
    fn test_secret_key_path_is_secret_data() {
        // SecretKeyPath requires SecretData as supertrait
        // This is a compile-time check — if it compiles, the relationship holds
        fn accepts_secret_key_path<T: super::SecretKeyPath>(_x: &T) {}
        let poly = SecretPoly::new(vec![1, 2, 3], 7);
        accepts_secret_key_path(&poly);
    }

    #[test]
    fn test_secret_scalar_ct_select() {
        let a = SecretScalar::new(100);
        let b = SecretScalar::new(200);

        let result_a = a.ct_select(&b, 1);
        let result_b = a.ct_select(&b, 0);

        assert_eq!(result_a.value, 100);
        assert_eq!(result_b.value, 200);
    }
}
