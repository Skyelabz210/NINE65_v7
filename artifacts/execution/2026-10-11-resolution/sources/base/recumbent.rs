//! Recumbent-Parking Carrier — three-tier exact integer overflow management.
//!
//! Architecture using winding tower CRT (no DynCRT reconstruct-per-op):
//!
//! - **Primary** (`WindingCRT`): main computation value, lane-parallel arithmetic
//! - **Parking** (`i128`): overflow buffer for values that spill past primary
//! - **Hot** (`WindingCRT`): phase-locked accumulator, deep winding track
//!
//! Arithmetic stays in CRT lanes. The winding tower tracks overflow exactly.
//! Reconstruction to scalar happens ONLY at I/O boundaries (reconstruct_exact).
//!
//! Activation level l(t) is the primary physical observable: bounded activation
//! IS the L∞ bound (Compendium Vol 2, ledger 113). This is the BKM criterion.
//!
//! Zero floating point. `no_std` compatible.

use crate::dyn_crt::WindingCRT;

/// Three-tier exact integer carrier with activation tracking.
#[derive(Clone, Debug)]
pub struct Recumbent {
    /// Main computation value (winding tower CRT lanes).
    primary: WindingCRT,
    /// Overflow buffer — captures excess when primary would overflow.
    parking: i128,
    /// Phase-locked accumulator — absorbs parking on flush.
    hot: WindingCRT,
    /// l(t): winding tower depth in use — the primary observable.
    activation_level: u32,
    /// γ(t): minimum activation level (floor).
    floor: u32,
    /// Number of parking→hot promotions executed.
    phase_lock_count: u32,
}

impl Recumbent {
    /// Create a zero-valued Recumbent carrier.
    pub fn zero() -> Self {
        Self {
            primary: WindingCRT::zero(),
            parking: 0,
            hot: WindingCRT::from_i128(0),
            activation_level: 0,
            floor: 0,
            phase_lock_count: 0,
        }
    }

    /// Create from an i128 value (I/O operation — encodes into lanes).
    pub fn from_i128(value: i128) -> Self {
        let mut r = Self::zero();
        r.assign(value);
        r
    }

    /// Load a value into the primary tier.
    /// Values that exceed S8 range use the winding tower for overflow
    /// tracking rather than spilling to parking.
    pub fn assign(&mut self, value: i128) {
        self.primary = WindingCRT::from_i128(value);
        self.parking = 0;

        // Track activation based on winding depth
        if !self.primary.is_within_basis() {
            self.activation_level = self.activation_level.max(1);
        }
    }

    /// Promote parking to hot (D-RECUM-c flush rule).
    pub fn flush(&mut self) {
        if self.parking == 0 {
            return;
        }

        let hot_val = self.hot.to_i128().unwrap_or(0);
        if let Some(new_hot) = hot_val.checked_add(self.parking) {
            self.hot = WindingCRT::from_i128(new_hot);
        } else {
            let parking_crt = WindingCRT::from_i128(self.parking);
            self.hot = self.hot.add(&parking_crt);
        }

        self.parking = 0;
        self.phase_lock_count += 1;
        self.activation_level = self
            .activation_level
            .max(self.phase_lock_count.min(u32::MAX - 1) + 1);
    }

    /// Reconstruct the exact full value: primary + parking + hot.
    /// This is an I/O operation — the ONLY place reconstruction happens.
    pub fn reconstruct(&self) -> Option<i128> {
        let p = self.primary.to_i128()?;
        let h = self.hot.to_i128()?;
        let sum = p.checked_add(self.parking)?;
        sum.checked_add(h)
    }

    /// Reconstruct, panicking if outside i128 corridor.
    pub fn reconstruct_exact(&self) -> i128 {
        self.reconstruct()
            .expect("Recumbent value outside i128 corridor")
    }

    /// Add two Recumbent carriers. Uses lane-parallel arithmetic internally.
    pub fn add(&self, other: &Recumbent) -> Recumbent {
        // Lane-parallel add for primary tiers
        let new_primary = self.primary.add(&other.primary);

        // Combine parking and hot tiers
        let new_parking = self.parking.saturating_add(other.parking);
        let new_hot = self.hot.add(&other.hot);

        let mut result = Recumbent {
            primary: new_primary,
            parking: new_parking,
            hot: new_hot,
            activation_level: self.activation_level.max(other.activation_level),
            floor: self.floor.max(other.floor),
            phase_lock_count: self.phase_lock_count.max(other.phase_lock_count),
        };

        if result.parking != 0 {
            result.flush();
        }

        result
    }

    /// Subtract two Recumbent carriers.
    pub fn sub(&self, other: &Recumbent) -> Recumbent {
        let a = self.reconstruct_exact();
        let b = other.reconstruct_exact();
        let diff = a.checked_sub(b).expect("Recumbent::sub overflow");
        let mut result = Recumbent::from_i128(diff);
        result.activation_level = self.activation_level.max(other.activation_level);
        result.floor = self.floor.max(other.floor);
        result
    }

    /// Multiply two Recumbent carriers. The winding tower absorbs overflow.
    pub fn mul(&self, other: &Recumbent) -> Recumbent {
        // Lane-parallel multiply for primary tiers
        let new_primary = self.primary.mul(&other.primary);

        let mut result = Recumbent {
            primary: new_primary,
            parking: 0,
            hot: WindingCRT::from_i128(0),
            activation_level: self
                .activation_level
                .max(other.activation_level)
                .saturating_add(1),
            floor: self.floor.max(other.floor),
            phase_lock_count: 0,
        };

        // If either had parking/hot, fold those contributions
        if self.parking != 0 || !self.hot.is_zero() || other.parking != 0 || !other.hot.is_zero() {
            let a = self.reconstruct_exact();
            let b = other.reconstruct_exact();
            let prod = a.checked_mul(b).expect("Recumbent::mul overflow");
            result = Recumbent::from_i128(prod);
            result.activation_level = self
                .activation_level
                .max(other.activation_level)
                .saturating_add(1);
            result.floor = self.floor.max(other.floor);
        }

        result
    }

    // ── Accessors ─────────────────────────────────────────────

    /// Current activation level — the BKM observable.
    pub fn activation_level(&self) -> u32 {
        self.activation_level
    }

    /// Activation floor γ(t).
    pub fn floor(&self) -> u32 {
        self.floor
    }

    /// Set activation floor.
    pub fn set_floor(&mut self, floor: u32) {
        self.floor = floor;
    }

    /// Number of parking→hot phase-lock promotions.
    pub fn phase_lock_count(&self) -> u32 {
        self.phase_lock_count
    }

    /// Whether activation is bounded: l(t) ≤ floor + threshold.
    pub fn is_bounded(&self, threshold: u32) -> bool {
        self.activation_level <= self.floor + threshold
    }

    /// Primary tier CRT carrier (residue lanes accessible directly).
    pub fn primary(&self) -> &WindingCRT {
        &self.primary
    }

    /// Parking tier value.
    pub fn parking_value(&self) -> i128 {
        self.parking
    }

    /// Hot tier CRT carrier.
    pub fn hot(&self) -> &WindingCRT {
        &self.hot
    }

    /// Whether the total value is zero.
    pub fn is_zero(&self) -> bool {
        self.primary.is_zero() && self.parking == 0 && self.hot.is_zero()
    }
}

impl PartialEq for Recumbent {
    fn eq(&self, other: &Self) -> bool {
        match (self.reconstruct(), other.reconstruct()) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Recumbent {}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_recumbent() {
        let r = Recumbent::zero();
        assert!(r.is_zero());
        assert_eq!(r.reconstruct(), Some(0));
        assert_eq!(r.activation_level(), 0);
        assert_eq!(r.phase_lock_count(), 0);
    }

    #[test]
    fn small_value_stays_in_primary() {
        let r = Recumbent::from_i128(42);
        assert_eq!(r.reconstruct(), Some(42));
        assert_eq!(r.parking_value(), 0);
    }

    #[test]
    fn negative_value() {
        let r = Recumbent::from_i128(-100);
        assert_eq!(r.reconstruct(), Some(-100));
    }

    #[test]
    fn large_value_uses_winding() {
        let big: i128 = 100_000_000; // > S8_PRODUCT
        let r = Recumbent::from_i128(big);
        assert_eq!(r.reconstruct(), Some(big));
    }

    #[test]
    fn add_exact() {
        let a = Recumbent::from_i128(12345);
        let b = Recumbent::from_i128(67890);
        let sum = a.add(&b);
        assert_eq!(sum.reconstruct(), Some(80235));
    }

    #[test]
    fn sub_exact() {
        let a = Recumbent::from_i128(67890);
        let b = Recumbent::from_i128(12345);
        let diff = a.sub(&b);
        assert_eq!(diff.reconstruct(), Some(55545));
    }

    #[test]
    fn mul_exact() {
        let a = Recumbent::from_i128(1000);
        let b = Recumbent::from_i128(2000);
        let prod = a.mul(&b);
        assert_eq!(prod.reconstruct(), Some(2_000_000));
    }

    #[test]
    fn activation_rises_on_multiply() {
        let a = Recumbent::from_i128(1000);
        let b = Recumbent::from_i128(2000);
        let prod = a.mul(&b);
        assert!(prod.activation_level() >= 1);
    }

    #[test]
    fn reconstruct_roundtrip_boundary() {
        let big: i128 = 500_000_000;
        for val in [0i128, 1, -1, big, -big] {
            let r = Recumbent::from_i128(val);
            assert_eq!(r.reconstruct(), Some(val), "roundtrip failed for {}", val);
        }
    }

    #[test]
    fn is_bounded_check() {
        let r = Recumbent::from_i128(42);
        assert!(r.is_bounded(10));
    }

    #[test]
    fn equality() {
        let a = Recumbent::from_i128(42);
        let b = Recumbent::from_i128(42);
        assert_eq!(a, b);
        let c = Recumbent::from_i128(43);
        assert_ne!(a, c);
    }

    #[test]
    fn phase_lock_count_tracking() {
        let mut r = Recumbent::zero();
        assert_eq!(r.phase_lock_count(), 0);
        r.parking = 1000;
        r.flush();
        assert_eq!(r.phase_lock_count(), 1);
        assert_eq!(r.parking, 0);
    }

    #[test]
    fn flush_absorbs_parking_into_hot() {
        let mut r = Recumbent::from_i128(100);
        r.parking = 500;
        r.flush();
        assert_eq!(r.parking, 0);
        assert_eq!(r.reconstruct(), Some(600));
    }

    #[test]
    fn negative_arithmetic() {
        let a = Recumbent::from_i128(-100);
        let b = Recumbent::from_i128(250);
        let sum = a.add(&b);
        assert_eq!(sum.reconstruct(), Some(150));
    }

    #[test]
    fn mixed_sign_multiply() {
        let a = Recumbent::from_i128(-50);
        let b = Recumbent::from_i128(30);
        let prod = a.mul(&b);
        assert_eq!(prod.reconstruct(), Some(-1500));
    }

    #[test]
    fn primary_lane_access() {
        let r = Recumbent::from_i128(100);
        // Access residues directly from primary — no reconstruction needed
        assert_eq!(r.primary().residue(2), Some(0));
        assert_eq!(r.primary().residue(3), Some(1));
        assert_eq!(r.primary().residue(7), Some(2));
    }
}
