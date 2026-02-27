//! Boundary and Capacity Diagnostics
//!
//! Monitors RNS product capacities and integer type boundaries to detect
//! "Anchor Capacity Drift" and other structural overflows.
//!
//! All calculations use integer-only arithmetic for deterministic cross-platform behavior.

use crate::errors::{Nine65Error, Nine65Result};

/// Status of a capacity boundary check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryStatus {
    /// Utilization is within safe bounds (< 80%)
    Safe(u32),
    /// Utilization is approaching boundary (80-89%)
    WarningApproaching(u32),
    /// Utilization is critical (>= 90%)
    CriticalApproaching(u32),
    /// Utilization exceeded 100% (Overflow)
    Exceeded(u32),
    /// Post-switch verification: very low utilization (0-4%)
    PostSwitchNominal(u32),
    /// Post-switch verification: low utilization (5-15%)
    PostSwitchCaution(u32),
}

/// Full diagnostic report for a capacity audit
#[derive(Debug, Clone, Copy)]
pub struct BoundaryDiagnostic {
    pub status: BoundaryStatus,
    pub required_bits: u32,
    pub capacity_bits: u32,
    pub utilization_percent: u32,
}

impl BoundaryDiagnostic {
    /// Perform an audit given required bits and available capacity bits.
    ///
    /// Implements the 80%/90% approaching checks and 5%/15% post-switch checks.
    pub fn audit(required_bits: u32, capacity_bits: u32, is_post_switch: bool) -> Self {
        if capacity_bits == 0 {
            return Self {
                status: BoundaryStatus::Exceeded(100),
                required_bits,
                capacity_bits: 0,
                utilization_percent: 100,
            };
        }

        let utilization = (required_bits * 100) / capacity_bits;

        let status = if utilization >= 100 {
            BoundaryStatus::Exceeded(utilization)
        } else if is_post_switch {
            if utilization < 5 {
                BoundaryStatus::PostSwitchNominal(utilization)
            } else if utilization <= 15 {
                BoundaryStatus::PostSwitchCaution(utilization)
            } else {
                BoundaryStatus::Safe(utilization)
            }
        } else if utilization >= 90 {
            BoundaryStatus::CriticalApproaching(utilization)
        } else if utilization >= 80 {
            BoundaryStatus::WarningApproaching(utilization)
        } else {
            BoundaryStatus::Safe(utilization)
        };

        Self {
            status,
            required_bits,
            capacity_bits,
            utilization_percent: utilization,
        }
    }

    /// Convert diagnostic to a Result, flagging warnings as Errors if strict.
    pub fn to_result(&self, strict: bool) -> Nine65Result<()> {
        match self.status {
            BoundaryStatus::Exceeded(u) => Err(Nine65Error::InvalidParameter {
                message: format!(
                    "Capacity overflow: utilization {}% ({} bits / {} bits capacity)",
                    u, self.required_bits, self.capacity_bits
                ),
            }),
            BoundaryStatus::CriticalApproaching(u) if strict => {
                Err(Nine65Error::InvalidParameter {
                    message: format!("CRITICAL: Capacity utilization {}% is >= 90%", u),
                })
            }
            BoundaryStatus::WarningApproaching(u) if strict => Err(Nine65Error::InvalidParameter {
                message: format!("WARNING: Capacity utilization {}% is >= 80%", u),
            }),
            _ => Ok(()),
        }
    }
}

/// Helper for bit-length of u128 (stable ilog2 alternative)
pub fn u128_bit_length(n: u128) -> u32 {
    if n == 0 {
        0
    } else {
        128 - n.leading_zeros()
    }
}

/// Helper for bit-length of RNS product given prime bit-widths
pub fn rns_product_bit_length(primes: &[u64]) -> u32 {
    primes
        .iter()
        .map(|&p| 64 - (p.leading_zeros() as u32))
        .sum::<u32>()
}

/// Identifies the required integer width for a given bit-length
pub fn required_int_width(bits: u32) -> u32 {
    if bits <= 64 {
        64
    } else if bits <= 128 {
        128
    } else if bits <= 192 {
        192
    } else {
        256
    }
}
