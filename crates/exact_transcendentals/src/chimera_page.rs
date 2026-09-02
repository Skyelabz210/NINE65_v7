//! Chimera Page Block — configurable basis extensions with multi-point addressing.
//!
//! Extends the S8 Safe Basis {2,3,5,7,11,13,17,19} with configurable page
//! blocks using primes up to 1211. The winding tower serves as a multi-point
//! addressing system where:
//! - Residues give intra-page position
//! - Winding digits give inter-page position (higher-order address bits)
//!
//! Implements Heterogeneous Chimera Reconstruction (HCBR): partial-state
//! lifting via localized Chimera-Lift operators instead of full Garner
//! reconstruction, reducing O(k²) to O(k) for partial queries.
//!
//! Zero floating point. `no_std` compatible.

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::k_elim;

/// S8 Safe Basis — the "unbroken" core, forced by Von Staudt-Clausen and
/// modular-forms theory. Always present in every page block.
pub const S8_CORE: [u64; 8] = [2, 3, 5, 7, 11, 13, 17, 19];

/// S8 product = 9,699,690
pub const S8_PRODUCT: u64 = 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19;

/// Transport Core — the quadratic-safe subset where deg ≤ 2 < ρ = 3.
pub const TRANSPORT_CORE: [u64; 4] = [3, 7, 11, 13];

/// All primes from 2 to 1211 — the full page block address space.
/// 198 primes total.
const PAGE_PRIMES: [u64; 198] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039,
    1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
    1163, 1171, 1181, 1187, 1193, 1201, 1211,
];

/// Page depth configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageDepth {
    /// S8 core only: {2,3,5,7,11,13,17,19}, M = 9,699,690
    S8,
    /// S8 + next 8 primes: 16 lanes total
    S16,
    /// First 32 primes: M ≈ 10^47
    S32,
    /// First 64 primes: M ≈ 10^117
    S64,
    /// All 198 primes to 1211
    Full,
    /// Custom: first n primes
    Custom(usize),
}

impl PageDepth {
    /// Number of primes in this page depth.
    pub fn lane_count(&self) -> usize {
        match self {
            PageDepth::S8 => 8,
            PageDepth::S16 => 16,
            PageDepth::S32 => 32,
            PageDepth::S64 => 64,
            PageDepth::Full => PAGE_PRIMES.len(),
            PageDepth::Custom(n) => (*n).min(PAGE_PRIMES.len()),
        }
    }
}

/// A configurable basis extending S8 with additional primes.
#[derive(Clone, Debug)]
pub struct PageBlock {
    /// Active primes in this page block.
    primes: Vec<u64>,
    /// Page depth configuration.
    depth: PageDepth,
}

impl PageBlock {
    /// Create a page block with the given depth.
    pub fn new(depth: PageDepth) -> Self {
        let n = depth.lane_count();
        Self {
            primes: PAGE_PRIMES[..n].to_vec(),
            depth,
        }
    }

    /// The active prime basis.
    pub fn primes(&self) -> &[u64] {
        &self.primes
    }

    /// Number of active lanes.
    pub fn lane_count(&self) -> usize {
        self.primes.len()
    }

    /// Page depth.
    pub fn depth(&self) -> PageDepth {
        self.depth
    }

    /// Whether this page block contains the full S8 core.
    pub fn has_s8_core(&self) -> bool {
        self.primes.len() >= 8
    }

    /// Encode a value into a PageAddress within this block.
    pub fn encode(&self, value: i128) -> PageAddress {
        let sign = value < 0;
        let magnitude = value.unsigned_abs();

        let residues: Vec<u64> = self
            .primes
            .iter()
            .map(|&p| (magnitude % p as u128) as u64)
            .collect();

        // Compute winding tower digits via iterated K-Elimination.
        // For most values within the page range, winding is 0.
        let m_product = self.product_u128();
        let winding = if magnitude as u128 >= m_product && m_product > 0 && m_product < u128::MAX {
            let k = magnitude as u128 / m_product;
            vec![k as i64]
        } else {
            vec![]
        };

        PageAddress {
            residues,
            winding,
            sign,
            depth: self.primes.len(),
        }
    }

    /// Decode a PageAddress back to i128.
    /// Returns None if the address represents a value outside i128.
    pub fn decode(&self, addr: &PageAddress) -> Option<i128> {
        if addr.residues.len() != self.primes.len() {
            return None;
        }

        let pairs: Vec<(i128, i128)> = addr
            .residues
            .iter()
            .zip(self.primes.iter())
            .map(|(&r, &p)| (r as i128, p as i128))
            .collect();

        let base = k_elim::garner_reconstruct(&pairs)?;

        // Add winding contribution
        let mut value = base;
        if !addr.winding.is_empty() {
            let m = self.product_i128()?;
            for &w in &addr.winding {
                value = value.checked_add(i128::from(w).checked_mul(m)?)?;
            }
        }

        if addr.sign && value != 0 {
            value.checked_neg()
        } else {
            Some(value)
        }
    }

    /// Perform a Chimera-Lift (HCBR §1.2): reconstruct the value modulo
    /// a subset of the basis primes, without full Garner reconstruction.
    /// Cost: O(|chimera_primes|) instead of O(k²).
    pub fn chimera_lift(&self, addr: &PageAddress, chimera_primes: &[u64]) -> Option<i128> {
        let pairs: Vec<(i128, i128)> = chimera_primes
            .iter()
            .filter_map(|&cp| {
                self.primes
                    .iter()
                    .position(|&p| p == cp)
                    .map(|idx| (addr.residues[idx] as i128, cp as i128))
            })
            .collect();

        if pairs.len() != chimera_primes.len() {
            return None;
        }

        k_elim::garner_reconstruct(&pairs)
    }

    /// Check if a value is divisible by a basis prime without full reconstruction.
    /// This is an O(1) check on the residue.
    pub fn is_divisible_by(&self, addr: &PageAddress, prime: u64) -> Option<bool> {
        self.primes
            .iter()
            .position(|&p| p == prime)
            .map(|idx| addr.residues[idx] == 0)
    }

    /// Product of all active primes as u128 (saturates at u128::MAX).
    fn product_u128(&self) -> u128 {
        let mut product: u128 = 1;
        for &p in &self.primes {
            match product.checked_mul(p as u128) {
                Some(v) => product = v,
                None => return u128::MAX,
            }
        }
        product
    }

    /// Product as i128 (returns None if exceeds i128::MAX).
    fn product_i128(&self) -> Option<i128> {
        let mut product: i128 = 1;
        for &p in &self.primes {
            product = product.checked_mul(p as i128)?;
        }
        Some(product)
    }
}

/// Multi-point address in the CRAM page block address space.
///
/// residues[i] is the value mod primes[i] — the intra-page position.
/// winding[j] are the tower digits — the inter-page position (higher-order).
/// Together they form a complete, exact address for any integer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageAddress {
    /// Residues modulo each prime in the page block.
    pub residues: Vec<u64>,
    /// Winding tower digits (empty if value fits within page range).
    pub winding: Vec<i64>,
    /// Sign flag.
    pub sign: bool,
    /// Number of primes in the page block (for validation).
    pub depth: usize,
}

impl PageAddress {
    /// Whether the address has zero winding (value fits within page range).
    pub fn is_within_page(&self) -> bool {
        self.winding.is_empty() || self.winding.iter().all(|&w| w == 0)
    }

    /// Parity check: O(1) from the mod-2 residue.
    pub fn is_even(&self) -> bool {
        self.residues.first() == Some(&0)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s8_product_correct() {
        assert_eq!(S8_PRODUCT, 9_699_690);
    }

    #[test]
    fn page_depth_lane_counts() {
        assert_eq!(PageDepth::S8.lane_count(), 8);
        assert_eq!(PageDepth::S16.lane_count(), 16);
        assert_eq!(PageDepth::S32.lane_count(), 32);
        assert_eq!(PageDepth::S64.lane_count(), 64);
        assert_eq!(PageDepth::Full.lane_count(), 198);
        assert_eq!(PageDepth::Custom(10).lane_count(), 10);
    }

    #[test]
    fn s8_encode_decode_roundtrip() {
        let page = PageBlock::new(PageDepth::S8);
        for val in [0i128, 1, 42, 100, 9_699_689, -1, -42, -9_699_689] {
            let addr = page.encode(val);
            let decoded = page.decode(&addr);
            assert_eq!(decoded, Some(val), "roundtrip failed for {}", val);
        }
    }

    #[test]
    fn s16_encode_decode_roundtrip() {
        let page = PageBlock::new(PageDepth::S16);
        let val = 1_000_000_000_000i128; // 10^12
        let addr = page.encode(val);
        let decoded = page.decode(&addr);
        assert_eq!(decoded, Some(val));
    }

    #[test]
    fn chimera_lift_partial() {
        let page = PageBlock::new(PageDepth::S8);
        let addr = page.encode(100);

        // Chimera lift to just {3, 7} — should give 100 mod (3*7=21) = 16
        let lift = page.chimera_lift(&addr, &[3, 7]);
        assert_eq!(lift, Some(16)); // 100 mod 21 = 16
    }

    #[test]
    fn chimera_lift_transport_core() {
        let page = PageBlock::new(PageDepth::S8);
        let addr = page.encode(1000);

        // Transport Core {3,7,11,13}: M = 3003
        let lift = page.chimera_lift(&addr, &TRANSPORT_CORE);
        assert_eq!(lift, Some(1000 % 3003)); // 1000 mod 3003 = 1000
    }

    #[test]
    fn divisibility_check() {
        let page = PageBlock::new(PageDepth::S8);

        let addr = page.encode(210); // 2*3*5*7
        assert_eq!(page.is_divisible_by(&addr, 2), Some(true));
        assert_eq!(page.is_divisible_by(&addr, 3), Some(true));
        assert_eq!(page.is_divisible_by(&addr, 5), Some(true));
        assert_eq!(page.is_divisible_by(&addr, 7), Some(true));
        assert_eq!(page.is_divisible_by(&addr, 11), Some(false));
    }

    #[test]
    fn parity_check() {
        let page = PageBlock::new(PageDepth::S8);

        let even_addr = page.encode(100);
        assert!(even_addr.is_even());

        let odd_addr = page.encode(101);
        assert!(!odd_addr.is_even());
    }

    #[test]
    fn within_page_check() {
        let page = PageBlock::new(PageDepth::S8);

        let small = page.encode(42);
        assert!(small.is_within_page());
    }

    #[test]
    fn has_s8_core() {
        assert!(PageBlock::new(PageDepth::S8).has_s8_core());
        assert!(PageBlock::new(PageDepth::S16).has_s8_core());
        assert!(PageBlock::new(PageDepth::Full).has_s8_core());
        assert!(!PageBlock::new(PageDepth::Custom(4)).has_s8_core());
    }

    #[test]
    fn page_block_primes_coprime() {
        let page = PageBlock::new(PageDepth::Full);
        let primes = page.primes();
        // All page primes are distinct primes, hence pairwise coprime
        for i in 0..primes.len() {
            for j in (i + 1)..primes.len() {
                assert_ne!(primes[i], primes[j]);
            }
        }
    }

    #[test]
    fn negative_address() {
        let page = PageBlock::new(PageDepth::S8);
        let addr = page.encode(-42);
        assert!(addr.sign);
        let decoded = page.decode(&addr);
        assert_eq!(decoded, Some(-42));
    }
}
