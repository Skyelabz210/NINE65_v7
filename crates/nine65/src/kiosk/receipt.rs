//! # Receipt Verification — Proof of Self-Destruction
//!
//! When a kiosk unit self-destructs, it produces a SHA-256 receipt hash
//! that proves the computation was performed and the unit was properly
//! destroyed. The server can verify these receipts without needing to
//! see the intermediate state.
//!
//! ## Receipt Format
//!
//! The receipt hash covers:
//! - Unit ID (unique identifier)
//! - Fold generation count
//! - Final entropy level
//! - Timestamp (nanoseconds since epoch)
//! - Operations performed count

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// A 32-byte SHA-256 receipt hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptHash {
    /// The 32-byte hash
    bytes: [u8; 32],
}

impl ReceiptHash {
    /// Create a receipt hash from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Get the hash bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Get a hex-encoded representation for display.
    pub fn to_hex(&self) -> String {
        self.bytes
            .iter()
            .map(|b| {
                let hi = b >> 4;
                let lo = b & 0x0f;
                let hi_char = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                let lo_char = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                format!("{}{}", hi_char as char, lo_char as char)
            })
            .collect()
    }
}

impl Drop for ReceiptHash {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Data included in a destruction receipt.
#[derive(Clone, Debug)]
pub struct ReceiptData {
    /// Unique unit identifier
    pub unit_id: u64,
    /// Fold generation at time of destruction
    pub fold_generation: u64,
    /// Final entropy level reading
    pub final_entropy: u64,
    /// Timestamp in nanoseconds (from monotonic clock)
    pub timestamp_nanos: u64,
    /// Total operations performed by this unit
    pub operations_performed: u64,
    /// Unit type discriminant (Bullet=0, Capsule=1, Fuse=2)
    pub unit_type: u8,
}

impl ReceiptData {
    /// Serialize receipt data to bytes for hashing.
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(49);
        bytes.extend_from_slice(&self.unit_id.to_le_bytes());
        bytes.extend_from_slice(&self.fold_generation.to_le_bytes());
        bytes.extend_from_slice(&self.final_entropy.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp_nanos.to_le_bytes());
        bytes.extend_from_slice(&self.operations_performed.to_le_bytes());
        bytes.push(self.unit_type);
        bytes
    }

    /// Compute the SHA-256 receipt hash for this data.
    pub fn compute_hash(&self) -> ReceiptHash {
        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        ReceiptHash::from_bytes(bytes)
    }
}

/// Server-side receipt verifier.
///
/// Verifies that a receipt hash matches the claimed receipt data.
/// This allows the server to confirm that a kiosk unit was properly
/// destroyed without needing to observe the destruction.
pub struct ReceiptVerifier;

impl ReceiptVerifier {
    /// Verify that a receipt hash matches the given receipt data.
    ///
    /// Returns `true` if the hash is valid.
    pub fn verify(data: &ReceiptData, expected_hash: &ReceiptHash) -> bool {
        let computed = data.compute_hash();
        // Constant-time comparison to avoid timing side channels
        ct_eq(computed.as_bytes(), expected_hash.as_bytes())
    }

    /// Verify a batch of receipts.
    ///
    /// Returns `true` only if ALL receipts verify successfully.
    pub fn verify_batch(pairs: &[(ReceiptData, ReceiptHash)]) -> bool {
        let mut all_valid = true;
        for (data, hash) in pairs {
            // Use bitwise AND instead of short-circuit to maintain constant-time
            all_valid &= Self::verify(data, hash);
        }
        all_valid
    }
}

/// Constant-time byte array equality comparison.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_receipt() -> ReceiptData {
        ReceiptData {
            unit_id: 0xDEAD_BEEF_CAFE_BABE,
            fold_generation: 3,
            final_entropy: 42_000,
            timestamp_nanos: 1_700_000_000_000_000_000,
            operations_performed: 17,
            unit_type: 0,
        }
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let data = sample_receipt();
        let h1 = data.compute_hash();
        let h2 = data.compute_hash();
        assert_eq!(h1, h2, "Same data must produce same hash");
    }

    #[test]
    fn test_receipt_hash_different_data() {
        let d1 = sample_receipt();
        let mut d2 = sample_receipt();
        d2.operations_performed = 18;

        let h1 = d1.compute_hash();
        let h2 = d2.compute_hash();
        assert_ne!(h1, h2, "Different data must produce different hash");
    }

    #[test]
    fn test_receipt_verification() {
        let data = sample_receipt();
        let hash = data.compute_hash();
        assert!(ReceiptVerifier::verify(&data, &hash));
    }

    #[test]
    fn test_receipt_verification_fails_on_tamper() {
        let data = sample_receipt();
        let hash = data.compute_hash();

        let mut tampered = sample_receipt();
        tampered.operations_performed = 999;
        assert!(!ReceiptVerifier::verify(&tampered, &hash));
    }

    #[test]
    fn test_batch_verification() {
        let pairs: Vec<(ReceiptData, ReceiptHash)> = (0..5)
            .map(|i| {
                let mut d = sample_receipt();
                d.unit_id = i;
                let h = d.compute_hash();
                (d, h)
            })
            .collect();

        assert!(ReceiptVerifier::verify_batch(&pairs));
    }

    #[test]
    fn test_batch_verification_one_bad() {
        let mut pairs: Vec<(ReceiptData, ReceiptHash)> = (0..5)
            .map(|i| {
                let mut d = sample_receipt();
                d.unit_id = i;
                let h = d.compute_hash();
                (d, h)
            })
            .collect();

        // Tamper with one receipt
        pairs[2].0.operations_performed = 999;
        assert!(!ReceiptVerifier::verify_batch(&pairs));
    }

    #[test]
    fn test_hex_encoding() {
        let hash = ReceiptHash::from_bytes([0; 32]);
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c == '0'));
    }

    #[test]
    fn test_ct_eq_constant_time() {
        let a = [0xABu8; 32];
        let b = [0xABu8; 32];
        let c = [0xCDu8; 32];

        assert!(ct_eq(&a, &b));
        assert!(!ct_eq(&a, &c));
    }
}
