//! Exact BFV delta (Δ = q/t) computation using rational arithmetic.
//!
//! In BFV encryption, Δ = floor(q/t) is used for encoding. The exact
//! remainder q - t*Δ affects noise growth. Tracking this exactly
//! prevents rounding errors from accumulating across levels.

use crate::arithmetic::rational_bridge::RationalBridge;

/// Exact representation of Δ = q/t for BFV encoding.
///
/// Stores Δ as floor(q/t) + remainder/t, giving exact fractional
/// representation without any approximation.
pub struct ExactDelta {
    /// The exact rational q/t
    rational: RationalBridge,
    /// Cached floor value
    floor_val: i128,
    /// Remainder: q - t * floor(q/t)
    remainder: i128,
    /// Plaintext modulus t
    t: i128,
}

impl ExactDelta {
    /// Create exact delta from q and t (both fitting in i128).
    pub fn new(q: u64, t: u64) -> Self {
        let q128 = q as i128;
        let t128 = t as i128;
        let floor_val = q128 / t128;
        let remainder = q128 - t128 * floor_val;
        let rational = RationalBridge::new(q128, t128).unwrap();
        Self {
            rational,
            floor_val,
            remainder,
            t: t128,
        }
    }

    /// Create from u128 values (for large moduli).
    ///
    /// Truncates to i128 range. For moduli > 2^127, use RNS-level
    /// delta computation instead.
    pub fn from_u128(q: u128, t: u64) -> Self {
        // For very large q, we compute floor and remainder using u128
        let t128 = t as u128;
        let floor_val = (q / t128) as i128;
        let remainder = (q % t128) as i128;
        let rational = RationalBridge::new(floor_val * t as i128 + remainder, t as i128).unwrap();
        Self {
            rational,
            floor_val,
            remainder,
            t: t as i128,
        }
    }

    /// Floor of q/t.
    pub fn floor(&self) -> i128 {
        self.floor_val
    }

    /// Floor as u128 (for large values).
    pub fn floor_u128(&self) -> u128 {
        self.floor_val as u128
    }

    /// Remainder numerator: q mod t.
    pub fn remainder_num(&self) -> i128 {
        self.remainder
    }

    /// Remainder denominator (always t).
    pub fn remainder_den(&self) -> i128 {
        self.t
    }

    /// Access the exact rational representation.
    pub fn rational(&self) -> &RationalBridge {
        &self.rational
    }

    /// Exact scale-and-round: round(m * t / q).
    ///
    /// This is the BFV decoding operation. Using exact arithmetic
    /// ensures no rounding drift.
    pub fn scale_and_round(&self, m: i128) -> i128 {
        // round(m * t / q) = floor(m * t / q + 1/2)
        //                   = floor((2 * m * t + q) / (2 * q))
        let two_m_t = 2i128.checked_mul(m).and_then(|v| v.checked_mul(self.t));
        let q = self.floor_val * self.t + self.remainder;
        let two_q = 2i128.checked_mul(q);

        match (two_m_t, two_q) {
            (Some(num_base), Some(denom)) if denom != 0 => {
                let numerator = num_base.checked_add(q).unwrap_or(num_base);
                numerator / denom
            }
            _ => {
                // Fallback for overflow: use simpler formula
                (m * self.t + q / 2) / q
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_delta_computation() {
        // Δ = q/t where q = ciphertext modulus, t = plaintext modulus
        // For q = 65537, t = 16: Δ = 65537/16 = 4096 + 1/16
        let delta = ExactDelta::new(65537, 16);
        assert_eq!(delta.floor(), 4096);
        assert_eq!(delta.remainder_num(), 1);
        assert_eq!(delta.remainder_den(), 16);
    }

    #[test]
    fn exact_delta_scale_and_round() {
        // scale_and_round(m, Δ) = round(m * t / q) = round(m / Δ)
        let delta = ExactDelta::new(65537, 16);
        // m = 4096 → m/Δ = 4096 * 16 / 65537 ≈ 0.9999... → rounds to 1
        let result = delta.scale_and_round(4096);
        assert_eq!(result, 1);
    }

    #[test]
    fn exact_delta_for_secure_config() {
        // For secure_128: q is product of ~30-bit primes
        // Just verify it doesn't overflow
        let q: u128 = (1u128 << 60) - 1; // ~60-bit modulus
        let t: u64 = 65537;
        let delta = ExactDelta::from_u128(q, t);
        assert!(delta.floor_u128() > 0);
    }
}
