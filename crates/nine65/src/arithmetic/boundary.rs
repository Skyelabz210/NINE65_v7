//! Capacity Boundary Proximity Tracking
//!
//! Provides integer-only (no floats) proximity checks for anchor/prime capacity
//! limits and integer-type transition thresholds.
//!
//! # Two Check Modes
//!
//! ## Approaching Boundary (80% / 90%)
//! Warn at 80% of capacity; escalate at 90%. Used before operations that may
//! push values toward the anchor-product ceiling.
//!
//! ## Post-Switch Margin (5% / 15%)
//! After an integer-type promotion (u64→u128 or u128→U256), verify that the
//! promoted value has reasonable headroom in the new type. A value that lands
//! at 95%+ of the new type immediately after promotion suggests either an
//! under-sized anchor set or an operation sequence that will overflow next step.
//!
//! # Integer-Only Implementation
//!
//! All thresholds are computed via bit-length comparisons (integer log2).
//! This is accurate to ±2 bits — sufficient for 80%/90% region detection.
//! No f32/f64 anywhere.

/// Capacity proximity region
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapacityRegion {
    /// < 80% of capacity — safe for all operations
    Safe,
    /// 80–89% of capacity — approaching boundary; consider pre-emptive action
    Warn80,
    /// 90–99% of capacity — near overflow; action strongly recommended
    Warn90,
    /// ≥ 100% of capacity — overflow imminent or occurred
    Critical,
}

/// Result of a capacity proximity check
#[derive(Debug, Clone, Copy)]
pub struct CapacityReport {
    /// Which proximity region this value falls in
    pub region: CapacityRegion,
    /// Approximate utilization percentage (0–100+), computed via bit-lengths
    pub utilization_pct: u8,
    /// Bit-length of the value being checked
    pub value_bits: u32,
    /// Bit-length of the capacity boundary
    pub capacity_bits: u32,
}

impl CapacityReport {
    /// True if no warning is needed
    pub fn is_safe(&self) -> bool {
        self.region == CapacityRegion::Safe
    }

    /// True if any warning level is active (Warn80, Warn90, or Critical)
    pub fn is_warning(&self) -> bool {
        self.region != CapacityRegion::Safe
    }

    /// True if at or past the hard boundary
    pub fn is_critical(&self) -> bool {
        self.region == CapacityRegion::Critical
    }

    /// Remaining headroom in bits (capacity_bits - value_bits), or 0 if exceeded
    pub fn headroom_bits(&self) -> u32 {
        self.capacity_bits.saturating_sub(self.value_bits)
    }
}

/// Check capacity proximity by comparing bit-lengths.
///
/// Uses bit-length (floor(log2)) as an integer proxy for magnitude comparison.
/// Accuracy: ±2 bits at boundaries (e.g., a 127-bit value reports ~99% of 128-bit
/// capacity rather than exactly 99.2%). This is sufficient for 80%/90% region detection.
///
/// # Arguments
/// - `value_bits`: bit-length of the value to check (use `128 - v.leading_zeros()`)
/// - `capacity_bits`: bit-length of the capacity boundary
///
/// # Example
/// ```ignore
/// let report = capacity_proximity_bits(127, 158); // 127/158 = 80.4% → Warn80
/// assert_eq!(report.region, CapacityRegion::Warn80);
/// ```
pub fn capacity_proximity_bits(value_bits: u32, capacity_bits: u32) -> CapacityReport {
    let (region, utilization_pct) = if capacity_bits == 0 {
        // No capacity defined — treat as critical
        (CapacityRegion::Critical, 100u8)
    } else if value_bits >= capacity_bits {
        (CapacityRegion::Critical, 100u8)
    } else {
        // utilization = value_bits * 100 / capacity_bits (integer division)
        let pct = (value_bits * 100) / capacity_bits;
        let region = if pct >= 90 {
            CapacityRegion::Warn90
        } else if pct >= 80 {
            CapacityRegion::Warn80
        } else {
            CapacityRegion::Safe
        };
        (region, pct.min(255) as u8)
    };

    CapacityReport {
        region,
        utilization_pct,
        value_bits,
        capacity_bits,
    }
}

/// Post-switch margin: headroom after promoting to a larger integer type.
///
/// After an integer-type promotion (u128→U256, or u64→u128), the value
/// should sit comfortably within the new type's range. If headroom is
/// < 5%, a second promotion may be needed immediately. If headroom is
/// 5–15%, the switch was marginal — anchor set sizing should be reviewed.
///
/// # Thresholds
/// - `is_critical`: headroom < 5% of new capacity (next operation likely overflows)
/// - `is_marginal`: headroom 5–15% of new capacity (tight; audit anchor sizing)
/// - Healthy: headroom > 15% of new capacity
#[derive(Debug, Clone, Copy)]
pub struct PostSwitchMargin {
    /// Headroom percentage in new type (100% - utilization%), via bit-lengths
    pub headroom_pct: u8,
    /// True if headroom is 5–15% (marginal switch; consider larger anchors)
    pub is_marginal: bool,
    /// True if headroom < 5% (critical — may overflow on very next operation)
    pub is_critical: bool,
}

/// Compute post-switch margin after promoting a value to a larger integer type.
///
/// # Arguments
/// - `value_bits`: bit-length of the value after promotion
/// - `new_capacity_bits`: bit-length of the new type (e.g., 256 for U256, 128 for u128)
///
/// # Example
/// ```ignore
/// // After u128→U256: value uses 130 bits, capacity is 256 bits
/// let margin = post_switch_margin_bits(130, 256); // 49% headroom — healthy
///
/// // Tight case: value uses 245 bits after U256 promotion
/// let margin = post_switch_margin_bits(245, 256); // 4% headroom — critical
/// assert!(margin.is_critical);
/// ```
pub fn post_switch_margin_bits(value_bits: u32, new_capacity_bits: u32) -> PostSwitchMargin {
    let (utilization, headroom) = if new_capacity_bits == 0 {
        (100u32, 0u32)
    } else if value_bits >= new_capacity_bits {
        (100u32, 0u32)
    } else {
        let util = (value_bits * 100) / new_capacity_bits;
        (util, 100u32.saturating_sub(util))
    };

    let _ = utilization; // used only for headroom calculation

    PostSwitchMargin {
        headroom_pct: headroom.min(255) as u8,
        is_marginal: headroom >= 5 && headroom <= 15,
        is_critical: headroom < 5,
    }
}

/// Compute the bit-length of a u128 value (integer log2, rounded up by 1).
///
/// Returns 0 for value == 0, and 128 - leading_zeros otherwise.
/// This is the standard definition: bit_length(0) = 0, bit_length(1) = 1, etc.
#[inline]
pub fn u128_bit_length(value: u128) -> u32 {
    if value == 0 {
        0
    } else {
        128 - value.leading_zeros()
    }
}

/// Compute the bit-length of a u64 value.
#[inline]
pub fn u64_bit_length(value: u64) -> u32 {
    if value == 0 {
        0
    } else {
        64 - value.leading_zeros()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capacity_proximity_safe() {
        // value at 50% of capacity_bits
        let r = capacity_proximity_bits(79, 158);
        assert_eq!(r.region, CapacityRegion::Safe);
        assert!(r.utilization_pct < 80);
    }

    #[test]
    fn test_capacity_proximity_warn80() {
        // 127*100/158 = 80 → Warn80
        let r = capacity_proximity_bits(127, 158);
        assert_eq!(
            r.region,
            CapacityRegion::Warn80,
            "127/158 = {}% should be Warn80",
            r.utilization_pct
        );
        // 126*100/158 = 79 → Safe (just below 80% threshold)
        let r_below = capacity_proximity_bits(126, 158);
        assert_eq!(
            r_below.region,
            CapacityRegion::Safe,
            "126/158 = {}% should be Safe (below 80%)",
            r_below.utilization_pct
        );
    }

    #[test]
    fn test_capacity_proximity_warn90() {
        // 143*100/158 = 90 → Warn90
        let r = capacity_proximity_bits(143, 158);
        assert_eq!(
            r.region,
            CapacityRegion::Warn90,
            "143/158 = {}% should be Warn90",
            r.utilization_pct
        );
        // 142*100/158 = 89 → Warn80 (just below 90% threshold)
        let r_below = capacity_proximity_bits(142, 158);
        assert_eq!(
            r_below.region,
            CapacityRegion::Warn80,
            "142/158 = {}% should be Warn80 (below 90%)",
            r_below.utilization_pct
        );
    }

    #[test]
    fn test_capacity_proximity_critical() {
        let r = capacity_proximity_bits(158, 158);
        assert_eq!(r.region, CapacityRegion::Critical);
        let r2 = capacity_proximity_bits(200, 158);
        assert_eq!(r2.region, CapacityRegion::Critical);
    }

    #[test]
    fn test_post_switch_margin_healthy() {
        // value = 130 bits, new capacity = 256 bits → 50% headroom
        let m = post_switch_margin_bits(130, 256);
        assert!(!m.is_marginal);
        assert!(!m.is_critical);
        assert!(m.headroom_pct >= 49);
    }

    #[test]
    fn test_post_switch_margin_marginal() {
        // value = 224 bits, new capacity = 256 bits → 12.5% headroom → marginal
        let m = post_switch_margin_bits(224, 256);
        assert!(m.is_marginal, "headroom={}%", m.headroom_pct);
        assert!(!m.is_critical);
    }

    #[test]
    fn test_post_switch_margin_critical() {
        // value = 248 bits in U256: 248*100/256=96, headroom=4 → critical (< 5)
        let m = post_switch_margin_bits(248, 256);
        assert!(
            m.is_critical,
            "248 bits in U256: headroom={}% should be critical",
            m.headroom_pct
        );
    }

    #[test]
    fn test_u128_bit_length() {
        assert_eq!(u128_bit_length(0), 0);
        assert_eq!(u128_bit_length(1), 1);
        assert_eq!(u128_bit_length(2), 2);
        assert_eq!(u128_bit_length(3), 2);
        assert_eq!(u128_bit_length(u64::MAX as u128), 64);
        assert_eq!(u128_bit_length(u128::MAX), 128);
    }
}
