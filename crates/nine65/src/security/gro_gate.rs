//! GRO (Golden-Ratio Oscillator) Timing Gate for FHE key operations.
//!
//! Wraps Clockwork's [`GroGate`] to add timing isolation to NINE65's
//! key-dependent operations. Secret key operations (decrypt, keygen,
//! evk generation) should only execute during GRO windows, making
//! timing side-channels harder to exploit.
//!
//! # Design
//!
//! The GRO uses two oscillators with frequencies in golden-ratio
//! proportion. Coincidence windows (where both phases are close)
//! are uniformly distributed but unpredictable from an external
//! observer's perspective. By gating key operations to these windows,
//! the execution timing becomes value-independent (INV-7).
//!
//! All frequencies are rational (integer phase increments) — no
//! floating point. See Clockwork Axiom A3.

use clockwork_core::gro::{GroParams, Window};
use clockwork_core::GroGate;

/// Timing gate for NINE65 key operations.
///
/// Wraps Clockwork's GRO with NINE65-appropriate defaults and API.
/// Use this to gate decrypt, keygen, and evaluation key operations.
pub struct TimingGate {
    gro: GroGate,
}

impl TimingGate {
    /// Create a timing gate with golden-ratio oscillators.
    ///
    /// - `n_acc`: accumulator bit-width (16 for testing, 32+ for production)
    /// - `window_width`: coincidence window width in phase units
    ///
    /// Returns `None` if parameters are invalid.
    pub fn new(n_acc: u32, window_width: u64) -> Option<Self> {
        // Use delta_phi_a = 1000 as a reasonable base increment
        let gro = GroGate::golden_ratio(n_acc, 1000, window_width)?;
        Some(TimingGate { gro })
    }

    /// Create from explicit GRO parameters.
    pub fn from_params(params: GroParams) -> Option<Self> {
        let gro = GroGate::new(params)?;
        Some(TimingGate { gro })
    }

    /// Find the next coincidence window starting at or after `from`.
    ///
    /// Returns `None` if no window found within `max_search` steps.
    pub fn next_window(&self, from: u64, max_search: u64) -> Option<Window> {
        self.gro.next_window(from, max_search)
    }

    /// Is time step `t` inside a coincidence window?
    pub fn is_window(&self, t: u64) -> bool {
        self.gro.is_window(t)
    }

    /// Check if the GRO has maximal coincidence period (2^n_acc).
    ///
    /// Maximal period ensures uniform window distribution (T9/T10).
    pub fn is_maximal_period(&self) -> bool {
        self.gro.is_maximal_period()
    }

    /// Exact coincidence period.
    pub fn coincidence_period(&self) -> u64 {
        self.gro.coincidence_period()
    }

    /// Count window occurrences in a range (for testing/validation).
    pub fn count_windows_in_range(&self, from: u64, to: u64) -> u64 {
        self.gro.count_windows_in_range(from, to)
    }

    /// Access the underlying Clockwork GRO gate.
    pub fn inner(&self) -> &GroGate {
        &self.gro
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gro_gate_controls_execution() {
        let gate = TimingGate::new(16, 100).unwrap();
        let window = gate.next_window(0, 100_000);
        assert!(window.is_some(), "Should find a window within 100K steps");
        let w = window.unwrap();
        assert!(w.duration > 0, "Window must have nonzero duration");
    }

    #[test]
    fn gro_gate_has_maximal_period() {
        let gate = TimingGate::new(16, 100).unwrap();
        assert!(gate.is_maximal_period());
    }

    #[test]
    fn gro_gate_various_sizes() {
        for n_acc in [16u32, 20, 24, 28, 32] {
            let gate = TimingGate::new(n_acc, 50).unwrap();
            assert!(
                gate.is_maximal_period(),
                "Should have maximal period for n_acc={n_acc}"
            );
            assert_eq!(gate.coincidence_period(), 1u64 << n_acc);
        }
    }

    #[test]
    fn gro_gate_window_equidistribution() {
        let gate = TimingGate::new(16, 100).unwrap();
        let total_steps = 1u64 << 16;
        let num_bins = 8u64;
        let bin_size = total_steps / num_bins;

        let mut bin_counts = vec![0u64; num_bins as usize];
        for t in 0..total_steps {
            if gate.is_window(t) {
                let bin = (t / bin_size).min(num_bins - 1);
                bin_counts[bin as usize] += 1;
            }
        }

        let total_windows: u64 = bin_counts.iter().sum();
        let expected_per_bin = total_windows / num_bins;

        for (bin, &count) in bin_counts.iter().enumerate() {
            let deviation = if count > expected_per_bin {
                count - expected_per_bin
            } else {
                expected_per_bin - count
            };
            let max_deviation = expected_per_bin / 2 + 1;
            assert!(
                deviation <= max_deviation,
                "Equidistribution violation: bin {bin} has {count}, expected ~{expected_per_bin}"
            );
        }
    }

    #[test]
    fn gro_gate_rejects_invalid() {
        // n_acc too small
        assert!(TimingGate::new(4, 100).is_none());
        // n_acc too large
        assert!(TimingGate::new(64, 100).is_none());
    }
}
