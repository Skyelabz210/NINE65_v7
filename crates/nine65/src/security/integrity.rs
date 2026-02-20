//! CRC32 integrity checking for RNS polynomial limbs.
//!
//! Catches memory corruption (bit flips, buffer overflows) that could
//! silently corrupt FHE computations. Uses `crc32fast` (already a
//! Clockwork dependency) for hardware-accelerated checksums.
//!
//! # Usage
//!
//! ```ignore
//! let limb: Vec<u64> = vec![1, 2, 3, 4, 5];
//! let checksum = compute_limb_checksum(&limb);
//!
//! // ... some computation ...
//!
//! assert!(verify_limb_checksum(&limb, checksum), "corruption detected!");
//! ```

use clockwork_core::integrity::AsBytes;

/// Compute a CRC32 checksum over an RNS polynomial limb.
///
/// The limb is serialized as little-endian u64 values and hashed.
pub fn compute_limb_checksum(limb: &[u64]) -> u32 {
    let bytes = limb.to_vec().as_bytes();
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&bytes);
    hasher.finalize()
}

/// Verify that an RNS limb matches a previously computed checksum.
pub fn verify_limb_checksum(limb: &[u64], expected: u32) -> bool {
    compute_limb_checksum(limb) == expected
}

/// Integrity-checked polynomial limb: stores data alongside its checksum.
pub struct CheckedLimb {
    data: Vec<u64>,
    checksum: u32,
}

impl CheckedLimb {
    /// Create a new integrity-checked limb.
    pub fn new(data: Vec<u64>) -> Self {
        let checksum = compute_limb_checksum(&data);
        Self { data, checksum }
    }

    /// Verify integrity and return a reference to the data.
    /// Returns `None` if the checksum doesn't match (corruption detected).
    pub fn verify(&self) -> Option<&[u64]> {
        if verify_limb_checksum(&self.data, self.checksum) {
            Some(&self.data)
        } else {
            None
        }
    }

    /// Update the data and recompute the checksum.
    pub fn update(&mut self, data: Vec<u64>) {
        self.checksum = compute_limb_checksum(&data);
        self.data = data;
    }

    /// Get the stored checksum.
    pub fn checksum(&self) -> u32 {
        self.checksum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_passes_for_valid_data() {
        let limb: Vec<u64> = vec![100, 200, 300];
        let checksum = compute_limb_checksum(&limb);
        assert!(verify_limb_checksum(&limb, checksum));
    }

    #[test]
    fn integrity_detects_corruption() {
        let limb: Vec<u64> = vec![1, 2, 3, 4, 5];
        let checksum = compute_limb_checksum(&limb);
        let mut corrupted = limb.clone();
        corrupted[2] = 999;
        assert!(!verify_limb_checksum(&corrupted, checksum));
    }

    #[test]
    fn integrity_detects_single_bit_flip() {
        let limb: Vec<u64> = vec![0xDEAD_BEEF_CAFE_BABE; 1024];
        let checksum = compute_limb_checksum(&limb);
        let mut corrupted = limb.clone();
        corrupted[512] ^= 1; // single bit flip
        assert!(!verify_limb_checksum(&corrupted, checksum));
    }

    #[test]
    fn integrity_detects_length_change() {
        let limb: Vec<u64> = vec![1, 2, 3];
        let checksum = compute_limb_checksum(&limb);
        let extended: Vec<u64> = vec![1, 2, 3, 0];
        assert!(!verify_limb_checksum(&extended, checksum));
    }

    #[test]
    fn checked_limb_round_trip() {
        let data = vec![42u64, 99, 123, 456, 789];
        let checked = CheckedLimb::new(data.clone());
        assert_eq!(checked.verify(), Some(data.as_slice()));
    }

    #[test]
    fn checked_limb_update() {
        let mut checked = CheckedLimb::new(vec![1, 2, 3]);
        assert!(checked.verify().is_some());
        checked.update(vec![4, 5, 6]);
        assert_eq!(checked.verify(), Some([4u64, 5, 6].as_slice()));
    }

    #[test]
    fn empty_limb() {
        let limb: Vec<u64> = vec![];
        let checksum = compute_limb_checksum(&limb);
        assert!(verify_limb_checksum(&limb, checksum));
    }

    #[test]
    fn large_limb_performance() {
        // 4096 coefficients (typical RLWE polynomial size)
        let limb: Vec<u64> = (0..4096).collect();
        let checksum = compute_limb_checksum(&limb);
        assert!(verify_limb_checksum(&limb, checksum));
    }
}
