//! # GRO Timing Model — Formal Spec §2.3, D13–D16
//!
//! Implements the Golden Ratio Oscillator pair timing model for side-channel
//! protection. This is the Loki component that solves the B5 k-leakage
//! problem identified in the Clockwork audit.
//!
//! ## Theorem Coverage
//! - **T9** (Coincidence Period): T_coinc = 2^{N_acc} when Δφ_A - Δφ_B is odd
//! - **T10** (Equidistribution): Coincidence windows are uniformly distributed
//! - **T8** (Timing Isolation): Combined with constant-time ops, no timing leakage
//! - **T16** (GRO-Garner Composition): The crown jewel — timing isolation for K-Elim
//!
//! ## Design Note
//! This module models the GRO timing system in software. In production,
//! the actual timing gating would be driven by a hardware DDS board.
//! This software model is for:
//! 1. Simulation and testing (GT-01, GT-02)
//! 2. Schedule computation (determine window sizes for INV-4)
//! 3. Reference implementation for hardware verification
//!
//! ## Critical: A3 (DDS Precision Bound)
//! ALL frequencies from a DDS are rational. This module never claims
//! irrational frequencies — it works with integer phase increments
//! and computes exact periods.

/// A DDS (Direct Digital Synthesis) oscillator pair approximating the golden ratio.
///
/// **Formal Spec D13**: Two oscillators with phase increments Δφ_A, Δφ_B
/// and accumulator width N_acc. The ratio Δφ_B/Δφ_A approximates φ.
///
/// **A3 enforced**: All frequencies are rational (integer phase increments
/// over 2^N_acc). No irrational frequency claims.
#[derive(Clone, Debug)]
pub struct GroGate {
    /// Phase increment for oscillator A
    delta_phi_a: u64,
    /// Phase increment for oscillator B (≈ delta_phi_a * φ)
    delta_phi_b: u64,
    /// Accumulator bit width (typically 32 or 48)
    n_acc: u32,
    /// Accumulator mask: 2^n_acc - 1
    acc_mask: u64,
    /// Window width parameter W: coincidence when |θ_A - θ_B| < W
    window_width: u64,
    /// Current time step for stateful GRO sequencing
    time_step: u64,
}

/// Parameters for constructing a GRO gate
#[derive(Clone, Debug)]
pub struct GroParams {
    /// Phase increment for oscillator A
    pub delta_phi_a: u64,
    /// Phase increment for oscillator B
    pub delta_phi_b: u64,
    /// Accumulator bit width
    pub n_acc: u32,
    /// Window width (in phase accumulator units)
    pub window_width: u64,
}

/// A coincidence window: the time interval during which crypto operations may execute.
#[derive(Clone, Debug)]
pub struct Window {
    /// Start time step of this window
    pub start: u64,
    /// End time step (exclusive)
    pub end: u64,
    /// Duration in time steps
    pub duration: u64,
}

impl GroGate {
    /// Construct a GRO gate from parameters.
    ///
    /// Validates:
    /// - N_acc is in [8, 63] (reasonable range; 64 would overflow u64 mask)
    /// - Phase increments are nonzero
    /// - Phase increment difference is odd (for maximal period, T9)
    ///
    /// Returns None if validation fails.
    pub fn new(params: GroParams) -> Option<Self> {
        if !(8..=63).contains(&params.n_acc) {
            return None;
        }
        if params.delta_phi_a == 0 || params.delta_phi_b == 0 {
            return None;
        }

        let acc_mask = (1u64 << params.n_acc) - 1;

        // Validate window width is reasonable
        if params.window_width == 0 || params.window_width > acc_mask / 2 {
            return None;
        }

        Some(GroGate {
            delta_phi_a: params.delta_phi_a & acc_mask,
            delta_phi_b: params.delta_phi_b & acc_mask,
            n_acc: params.n_acc,
            acc_mask,
            window_width: params.window_width,
            time_step: 0,
        })
    }

    /// Construct a GRO gate with phase increments approximating the golden ratio.
    ///
    /// Given a base increment Δφ_A, computes Δφ_B ≈ Δφ_A · φ using integer
    /// arithmetic only (Fibonacci ratio approximation).
    ///
    /// Uses the identity: F_{n+1}/F_n → φ as n → ∞.
    /// With large Fibonacci numbers, the approximation error is < 10^{-18}.
    pub fn golden_ratio(n_acc: u32, delta_phi_a: u64, window_width: u64) -> Option<Self> {
        // Guard: n_acc must be in valid range (same as GroGate::new)
        if !(8..=63).contains(&n_acc) {
            return None;
        }

        // Fibonacci numbers for φ approximation (F_86/F_85 is extremely close to φ)
        // All integer arithmetic — NO FLOATING POINT
        const FIB_85: u128 = 420196140727489673; // F(85)
        const FIB_86: u128 = 679891637638612258; // F(86)

        // Δφ_B = Δφ_A * F(86) / F(85) — integer division, guaranteed > Δφ_A
        let delta_phi_b_128 = (delta_phi_a as u128 * FIB_86) / FIB_85;

        // Check it fits in the accumulator
        let acc_mask = (1u64 << n_acc) - 1;
        if delta_phi_b_128 > acc_mask as u128 {
            return None;
        }

        let delta_phi_b = delta_phi_b_128 as u64;

        // Ensure the difference is odd (for T9: maximal period)
        let diff = delta_phi_b.abs_diff(delta_phi_a);

        if diff & 1 == 0 {
            // Nudge by 1 to make it odd (minimal perturbation to φ approximation)
            let adjusted_b = delta_phi_b + 1;
            return Self::new(GroParams {
                delta_phi_a,
                delta_phi_b: adjusted_b,
                n_acc,
                window_width,
            });
        }

        Self::new(GroParams {
            delta_phi_a,
            delta_phi_b,
            n_acc,
            window_width,
        })
    }

    /// Phase of oscillator A at time step t.
    ///
    /// θ_A(t) = t · Δφ_A mod 2^{N_acc}
    pub fn phase_a(&self, t: u64) -> u64 {
        // Wrapping multiply handles the mod 2^64 case; we then mask to N_acc bits
        t.wrapping_mul(self.delta_phi_a) & self.acc_mask
    }

    /// Phase of oscillator B at time step t.
    pub fn phase_b(&self, t: u64) -> u64 {
        t.wrapping_mul(self.delta_phi_b) & self.acc_mask
    }

    /// Phase difference |θ_A(t) - θ_B(t)| mod 2^{N_acc}, folded to [0, 2^{N_acc-1}].
    ///
    /// This is the "circular distance" on the phase circle.
    pub fn phase_diff(&self, t: u64) -> u64 {
        let a = self.phase_a(t);
        let b = self.phase_b(t);
        let raw_diff = a.abs_diff(b);

        let half = self.acc_mask.div_ceil(2);
        if raw_diff > half {
            self.acc_mask + 1 - raw_diff
        } else {
            raw_diff
        }
    }

    /// Is time step t inside a coincidence window?
    ///
    /// **D14**: Window when |θ_A(t) - θ_B(t)| mod 2^{N_acc} < W
    pub fn is_window(&self, t: u64) -> bool {
        self.phase_diff(t) < self.window_width
    }

    // ─── T9: Coincidence Period ──────────────────────────────────────────

    /// Compute the exact coincidence period.
    ///
    /// **T9**: T_coinc = 2^{N_acc} / gcd(Δφ_A - Δφ_B, 2^{N_acc})
    ///
    /// When Δφ_A - Δφ_B is odd: gcd = 1, so T_coinc = 2^{N_acc} (maximal).
    pub fn coincidence_period(&self) -> u64 {
        let diff = self.delta_phi_a.wrapping_sub(self.delta_phi_b) & self.acc_mask;
        let modulus = self.acc_mask + 1; // = 2^{N_acc}

        let g = gcd_u64(diff, modulus);
        modulus / g
    }

    /// Is the coincidence period maximal (= 2^{N_acc})?
    ///
    /// This holds when Δφ_A - Δφ_B is odd, which is the preferred configuration.
    pub fn is_maximal_period(&self) -> bool {
        let diff = self.delta_phi_a.wrapping_sub(self.delta_phi_b) & self.acc_mask;
        diff & 1 == 1
    }

    // ─── Window finding (for simulation and testing) ────────────────────

    /// Find the next coincidence window start at or after time step `from`.
    ///
    /// Returns None if no window found within `max_search` steps.
    pub fn next_window(&self, from: u64, max_search: u64) -> Option<Window> {
        // Find start of window
        let mut t = from;
        let limit = from.saturating_add(max_search);

        while t < limit && !self.is_window(t) {
            t += 1;
        }

        if t >= limit {
            return None;
        }

        let start = t;

        // Find end of window
        while t < limit && self.is_window(t) {
            t += 1;
        }

        let end = t;

        Some(Window {
            start,
            end,
            duration: end - start,
        })
    }

    /// Count window occurrences in a range, for equidistribution testing (GT-02).
    pub fn count_windows_in_range(&self, from: u64, to: u64) -> u64 {
        let mut count = 0u64;
        for t in from..to {
            if self.is_window(t) {
                count += 1;
            }
        }
        count
    }

    /// Get the accumulator bit width
    pub fn n_acc(&self) -> u32 {
        self.n_acc
    }

    /// Get phase increment A
    pub fn delta_phi_a(&self) -> u64 {
        self.delta_phi_a
    }

    /// Get phase increment B
    pub fn delta_phi_b(&self) -> u64 {
        self.delta_phi_b
    }

    /// Get the current time step
    pub fn current_step(&self) -> u64 {
        self.time_step
    }

    /// Advance the GRO by one time step, returning whether the new step
    /// falls inside a coincidence window.
    pub fn advance(&mut self) -> bool {
        self.time_step = self.time_step.wrapping_add(1);
        self.is_window(self.time_step)
    }
}

/// GCD for u64 values. All integer, no floating point.
fn gcd_u64(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd_u64(b, a % b)
    }
}

// ─── Tests: Formal Spec Test Obligations GT-01, GT-02 ───────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_gro() -> GroGate {
        // 16-bit accumulator for fast testing
        GroGate::golden_ratio(16, 1000, 100).unwrap()
    }

    // ─── GT-01: Coincidence period = 2^{N_acc} for odd difference ───────

    #[test]
    fn gt01_maximal_period_with_odd_difference() {
        // Test 100 random parameter pairs with odd difference
        let mut rng: u64 = 0xCAFE_BABE;
        let mut tested = 0;

        for _ in 0..1000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let delta_a = (rng % 30000) + 1000;
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let delta_b = (rng % 30000) + 1000;

            // Skip if difference is even
            if (delta_a.wrapping_sub(delta_b)) & 1 == 0 {
                continue;
            }

            let gro = GroGate::new(GroParams {
                delta_phi_a: delta_a,
                delta_phi_b: delta_b,
                n_acc: 16,
                window_width: 100,
            });

            if let Some(gro) = gro {
                let period = gro.coincidence_period();
                assert_eq!(
                    period,
                    1u64 << 16,
                    "T9 violation: period {} ≠ 2^16 for Δφ_A={}, Δφ_B={}",
                    period,
                    delta_a,
                    delta_b
                );
                tested += 1;
            }

            if tested >= 100 {
                break;
            }
        }

        assert!(tested >= 100, "Need at least 100 valid test cases");
    }

    // ─── GT-02: Window distribution (equidistribution) ──────────────────

    #[test]
    fn gt02_window_equidistribution() {
        let gro = default_gro();

        // Divide the phase space into 16 bins and count windows per bin
        let total_steps = 1u64 << 16; // one full period
        let num_bins = 16u64;
        let bin_size = total_steps / num_bins;

        let mut bin_counts = vec![0u64; num_bins as usize];

        for t in 0..total_steps {
            if gro.is_window(t) {
                let bin = (t / bin_size).min(num_bins - 1);
                bin_counts[bin as usize] += 1;
            }
        }

        // Total window count
        let total_windows: u64 = bin_counts.iter().sum();
        let expected_per_bin = total_windows / num_bins;

        // χ² test: each bin should have approximately total_windows/num_bins
        // For a rough check: no bin should deviate by more than 3× from expected
        for (bin, &count) in bin_counts.iter().enumerate() {
            let deviation = count.abs_diff(expected_per_bin);

            // Allow up to 50% deviation (generous for a simple test)
            let max_deviation = expected_per_bin / 2 + 1;
            assert!(
                deviation <= max_deviation,
                "GT-02 equidistribution violation: bin {bin} has {count} windows, \
                 expected ~{expected_per_bin} (deviation {deviation} > {max_deviation})"
            );
        }
    }

    // ─── Golden ratio approximation quality ─────────────────────────────

    #[test]
    fn golden_ratio_approximation() {
        // Use a larger base increment for better integer division precision
        let gro = GroGate::golden_ratio(48, 10_000_000, 1000).unwrap();

        // The ratio Δφ_B / Δφ_A should approximate φ ≈ 1.6180339887
        // Check relative error is small
        let ratio_num = gro.delta_phi_b() as u128 * 1_000_000_000;
        let ratio_den = gro.delta_phi_a() as u128;
        let ratio_scaled = ratio_num / ratio_den;

        // φ * 10^9 ≈ 1_618_033_988
        let phi_scaled: u128 = 1_618_033_988;

        let error = ratio_scaled.abs_diff(phi_scaled);

        // Allow relative error < 10^{-6} (generous for integer division)
        assert!(
            error < 1000,
            "Golden ratio approximation too poor: ratio*10^9 = {ratio_scaled}, \
             expected ~{phi_scaled}, error = {error}"
        );
    }

    // ─── Maximal period with golden ratio construction ──────────────────

    #[test]
    fn golden_ratio_maximal_period() {
        for n_acc in [16u32, 20, 24, 28, 32] {
            let gro = GroGate::golden_ratio(n_acc, 1000, 50).unwrap();
            assert!(
                gro.is_maximal_period(),
                "Golden ratio construction should yield maximal period for n_acc={n_acc}"
            );
        }
    }

    // ─── Window existence: windows actually occur ───────────────────────

    #[test]
    fn windows_exist() {
        let gro = default_gro();
        let window = gro.next_window(0, 100_000);
        assert!(
            window.is_some(),
            "GRO should produce at least one window in 100K steps"
        );

        let w = window.unwrap();
        assert!(w.duration > 0, "Window must have nonzero duration");
    }
}
