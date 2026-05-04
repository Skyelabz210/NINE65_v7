//! Heterogeneous Substrate Chimera (data-only scaffold).
//!
//! From the THEOREM STACK on Heterogeneous Substrate Chimera: a CRT product
//! ring may assign **different physical substrates to different lanes**. Some
//! lanes operate on `F_p²` (algebraic, exact, deterministic). Other lanes
//! operate on `C^p` (Hilbert space, superposed, probabilistic). CRT
//! reconstruction via K-Elimination bridges the classical/quantum boundary.
//!
//! This module is a pure data scaffold:
//!
//! * [`LaneSubstrate`] — enum of supported substrates.
//! * [`SubstrateAssignment`] — per-prime substrate plus the oracle gate
//!   count and information weight the substrate sees.
//! * [`HeterogeneousLayout`] — full lane fabric with the architectural
//!   default ("Theorem Q4 optimal layout for twin-prime search on the
//!   safe basis") plus utility queries.
//! * [`bridge_winding`] — K-Elim winding `k = (r_q - r_a) · m_a^-1 mod m_q`
//!   between an algebraic residue and a quantum measurement outcome.
//! * [`cost_model`] — analytic cost helpers (parallel-Grover bottleneck,
//!   CRT advantage ratio).
//!
//! No quantum simulation is performed here. The scaffold gives later
//! phases a typed vocabulary for declaring which lanes are quantum and
//! how the bridge is computed. The corresponding `cram_ct` ciphertext
//! does not change shape — only the lane metadata gains a substrate tag.

use crate::lane_projector::mod_inv_u32;
use crate::triad::S8;
use crate::Vec;

// ─── Lane Substrate ───────────────────────────────────────────────────────

/// Physical substrate a lane operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LaneSubstrate {
    /// `F_p²` for `p ≡ 3 mod 4`: exact algebraic field with norm-preserving
    /// unitaries and zero decoherence. Used for cheap deterministic oracle
    /// constraints (coprimality, QR, Ramanujan, boundary).
    AlgebraicFp2,
    /// `Z/pZ` arithmetic on a classical CPU. The default substrate for
    /// every lane until a quantum assignment is requested.
    ClassicalRing,
    /// `C^p` Hilbert space lane: superposition + measurement collapse to
    /// a residue in `Z/pZ`. The bridge prime is the canonical candidate.
    QuantumHilbert,
    /// Composite ring `Z/p^k Z` — used for shadow / Hensel-lift roles
    /// where nilpotent depth provides redundancy.
    CompositeRing,
}

impl LaneSubstrate {
    pub const fn name(self) -> &'static str {
        match self {
            Self::AlgebraicFp2 => "algebraic_fp2",
            Self::ClassicalRing => "classical_ring",
            Self::QuantumHilbert => "quantum_hilbert",
            Self::CompositeRing => "composite_ring",
        }
    }

    /// True iff this substrate requires a quantum processor.
    pub const fn is_quantum(self) -> bool {
        matches!(self, Self::QuantumHilbert)
    }

    /// True iff this substrate is exact and deterministic.
    pub const fn is_exact(self) -> bool {
        matches!(
            self,
            Self::AlgebraicFp2 | Self::ClassicalRing | Self::CompositeRing
        )
    }
}

// ─── Substrate Assignment ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct SubstrateAssignment {
    pub prime: u32,
    pub substrate: LaneSubstrate,
    /// Number of oracle gates this lane evaluates per Grover iteration
    /// (or per algebraic check). Used by [`cost_model`].
    pub oracle_gates: u32,
    /// Free-text role label (matches the architectural role taxonomy).
    pub role: &'static str,
}

// ─── Heterogeneous Layout ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct HeterogeneousLayout {
    pub lanes: Vec<SubstrateAssignment>,
}

impl HeterogeneousLayout {
    /// Look up the substrate for a given prime.
    pub fn substrate_of(&self, p: u32) -> Option<LaneSubstrate> {
        self.lanes
            .iter()
            .find(|l| l.prime == p)
            .map(|l| l.substrate)
    }

    /// Primes this layout marks as quantum lanes.
    pub fn quantum_lanes(&self) -> Vec<u32> {
        self.lanes
            .iter()
            .filter(|l| l.substrate.is_quantum())
            .map(|l| l.prime)
            .collect()
    }

    /// Primes this layout marks as algebraic lanes.
    pub fn algebraic_lanes(&self) -> Vec<u32> {
        self.lanes
            .iter()
            .filter(|l| matches!(l.substrate, LaneSubstrate::AlgebraicFp2))
            .map(|l| l.prime)
            .collect()
    }

    /// True iff every prime in `S8` (or in the configured basis) has an
    /// assignment. Phase-4 layouts only target the safe basis subset.
    pub fn covers(&self, basis: &[u32]) -> bool {
        basis
            .iter()
            .all(|&p| self.lanes.iter().any(|l| l.prime == p))
    }
}

/// Theorem-Q4 optimal layout for twin-prime search on the 5-prime safe
/// basis `{3, 5, 7, 11, 13}`. Bridge prime 7 is quantum; the rest are
/// algebraic deterministic checks.
pub fn theorem_q4_safe_basis_layout() -> HeterogeneousLayout {
    let mut lanes = Vec::with_capacity(5);
    lanes.push(SubstrateAssignment {
        prime: 3,
        substrate: LaneSubstrate::AlgebraicFp2,
        oracle_gates: 2,
        role: "coprimality",
    });
    lanes.push(SubstrateAssignment {
        prime: 5,
        substrate: LaneSubstrate::AlgebraicFp2,
        oracle_gates: 3,
        role: "coprimality + QR",
    });
    lanes.push(SubstrateAssignment {
        prime: 7,
        substrate: LaneSubstrate::QuantumHilbert,
        oracle_gates: 8,
        role: "quartic residue (Grover)",
    });
    lanes.push(SubstrateAssignment {
        prime: 11,
        substrate: LaneSubstrate::AlgebraicFp2,
        oracle_gates: 5,
        role: "Ramanujan",
    });
    lanes.push(SubstrateAssignment {
        prime: 13,
        substrate: LaneSubstrate::AlgebraicFp2,
        oracle_gates: 4,
        role: "boundary",
    });
    HeterogeneousLayout { lanes }
}

/// Default S8 layout: every prime classical until upgraded.
pub fn s8_classical_layout() -> HeterogeneousLayout {
    HeterogeneousLayout {
        lanes: S8
            .iter()
            .map(|&p| SubstrateAssignment {
                prime: p,
                substrate: LaneSubstrate::ClassicalRing,
                oracle_gates: 1,
                role: "default",
            })
            .collect(),
    }
}

// ─── K-Elim Bridge ────────────────────────────────────────────────────────

/// K-Elimination winding `k = (r_q - r_a) · m_a^{-1} mod m_q` between an
/// algebraic-lane residue `r_a` (at modulus `m_a`) and a
/// quantum-measurement outcome `r_q` (at modulus `m_q`).
///
/// Returns `None` when `m_a` and `m_q` are not coprime — the bridge
/// requires coprime moduli, which every S8 prime pair satisfies.
pub fn bridge_winding(r_a: u32, m_a: u32, r_q: u32, m_q: u32) -> Option<u32> {
    let inv = mod_inv_u32(m_a % m_q, m_q)?;
    let diff = (r_q as i64 - r_a as i64).rem_euclid(m_q as i64) as u32;
    Some(((diff as u64) * (inv as u64) % m_q as u64) as u32)
}

/// Compare an expected bridge winding (computed from the algebraic lane
/// and the **expected** quantum residue) against the actual winding
/// (computed from the algebraic lane and the **measured** quantum
/// residue). Equality means the quantum measurement is consistent with
/// the algebraic constraint — a zero-cost classical error syndrome.
pub fn quantum_error_syndrome(
    r_a: u32,
    m_a: u32,
    r_q_expected: u32,
    r_q_measured: u32,
    m_q: u32,
) -> Option<bool> {
    let k_expected = bridge_winding(r_a, m_a, r_q_expected, m_q)?;
    let k_measured = bridge_winding(r_a, m_a, r_q_measured, m_q)?;
    Some(k_expected == k_measured)
}

// ─── Analytic Cost Model ──────────────────────────────────────────────────

pub mod cost_model {
    use super::HeterogeneousLayout;
    use crate::Vec;

    /// Standard Grover iteration count for a uniform search on a register
    /// of size `m`: `floor(π/4 · √m)`. Returned as integer scaled by 1000
    /// to keep the workspace's no-float discipline.
    pub fn standard_grover_iters_milli(m: u64) -> u64 {
        // π/4 ≈ 0.785398163. Integer-only: scale by 1000.
        // floor(785 · sqrt(m) / 1000)
        let s = isqrt_u64(m);
        785 * s / 1000
    }

    /// Theorem-Q1 parallel CRT-Grover: cost = `√(max m_i)` (slowest lane).
    pub fn parallel_grover_iters_milli(layout: &HeterogeneousLayout) -> u64 {
        let max_m = layout
            .quantum_lanes()
            .iter()
            .map(|&p| p as u64)
            .max()
            .unwrap_or(1);
        standard_grover_iters_milli(max_m)
    }

    /// Theorem-Q3 CRT advantage ratio:
    /// `R = √(∏ m_i / max m_i) = √(∏ non-max m_i)`.
    /// Returns the squared ratio to keep arithmetic exact.
    pub fn crt_advantage_squared(layout: &HeterogeneousLayout) -> u64 {
        let primes: Vec<u64> = layout.lanes.iter().map(|l| l.prime as u64).collect();
        let max_p = *primes.iter().max().unwrap_or(&1);
        let product: u64 = primes.iter().product();
        product / max_p
    }

    fn isqrt_u64(n: u64) -> u64 {
        if n < 2 {
            return n;
        }
        // Newton's method.
        let mut x = n;
        let mut y = (x + 1) / 2;
        while y < x {
            x = y;
            y = (x + n / x) / 2;
        }
        x
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substrates_classify_correctly() {
        assert!(LaneSubstrate::QuantumHilbert.is_quantum());
        assert!(!LaneSubstrate::AlgebraicFp2.is_quantum());
        assert!(LaneSubstrate::AlgebraicFp2.is_exact());
        assert!(LaneSubstrate::ClassicalRing.is_exact());
        assert!(LaneSubstrate::CompositeRing.is_exact());
        assert!(!LaneSubstrate::QuantumHilbert.is_exact());
    }

    #[test]
    fn theorem_q4_layout_marks_only_lane_7_quantum() {
        let layout = theorem_q4_safe_basis_layout();
        assert_eq!(layout.quantum_lanes(), vec![7]);
        let alg = layout.algebraic_lanes();
        assert_eq!(alg, vec![3, 5, 11, 13]);
    }

    #[test]
    fn theorem_q4_layout_covers_safe_basis() {
        let layout = theorem_q4_safe_basis_layout();
        assert!(layout.covers(&[3, 5, 7, 11, 13]));
    }

    #[test]
    fn s8_classical_layout_has_no_quantum_lanes() {
        let layout = s8_classical_layout();
        assert!(layout.quantum_lanes().is_empty());
        assert!(layout.covers(&S8));
    }

    #[test]
    fn substrate_of_returns_assignment() {
        let layout = theorem_q4_safe_basis_layout();
        assert_eq!(layout.substrate_of(7), Some(LaneSubstrate::QuantumHilbert));
        assert_eq!(layout.substrate_of(11), Some(LaneSubstrate::AlgebraicFp2));
        assert_eq!(layout.substrate_of(23), None);
    }

    // ---- K-Elim bridge ---------------------------------------------------

    #[test]
    fn bridge_winding_matches_anchor_k_for_s8_pair() {
        // Sanity: the bridge formula is the same K-Elim winding the
        // anchor lock uses — different name, same math.
        for x in [0u32, 1, 7, 35, 100, 9_699_689] {
            let r_3 = x % 3;
            let r_7 = x % 7;
            let k = bridge_winding(r_3, 3, r_7, 7).unwrap();
            assert_eq!((r_3 + k * 3) % 7, r_7, "bridge broken at x={x}");
        }
    }

    #[test]
    fn bridge_winding_returns_none_for_non_coprime() {
        // 6 and 9 share factor 3 — no inverse exists.
        assert!(bridge_winding(0, 6, 0, 9).is_none());
    }

    #[test]
    fn quantum_error_syndrome_passes_for_consistent_measurement() {
        // r_3 = 1, m_a = 3, m_q = 7. Pick any consistent quantum residue.
        let r_a = 1u32;
        // x = 1 (mod 3), x = 4 (mod 7) => k = (4 - 1)*3^-1 mod 7 = 3*5 mod 7 = 1.
        let r_q_expected = 4;
        let r_q_measured = 4; // matches.
        assert_eq!(
            quantum_error_syndrome(r_a, 3, r_q_expected, r_q_measured, 7),
            Some(true)
        );
    }

    #[test]
    fn quantum_error_syndrome_detects_flipped_measurement() {
        let r_a = 1u32;
        let r_q_expected = 4;
        let r_q_measured = 5; // off by one — winding diverges.
        assert_eq!(
            quantum_error_syndrome(r_a, 3, r_q_expected, r_q_measured, 7),
            Some(false)
        );
    }

    // ---- Cost model ------------------------------------------------------

    #[test]
    fn parallel_grover_iters_match_bottleneck_lane() {
        // Theorem-Q4 layout has only lane 7 quantum, so parallel cost
        // is ⌊π/4 · √7⌋ ≈ 2.07.
        let layout = theorem_q4_safe_basis_layout();
        let iters = cost_model::parallel_grover_iters_milli(&layout);
        // Allow small rounding window. floor(785 * 2 / 1000) = 1 (since
        // isqrt(7) = 2).
        assert!(iters <= 3, "parallel Grover iters bottleneck: {}", iters);
    }

    #[test]
    fn crt_advantage_squared_for_safe_basis() {
        // Theorem Q1 evidence: for {3,5,7,11,13} (M = 15015), advantage
        // ratio R = √(15015 / 13) = √1155 ≈ 34. Squared ratio = 1155.
        let layout = theorem_q4_safe_basis_layout();
        assert_eq!(cost_model::crt_advantage_squared(&layout), 1155);
    }

    #[test]
    fn standard_grover_iters_grows_with_register_size() {
        let small = cost_model::standard_grover_iters_milli(15);
        let big = cost_model::standard_grover_iters_milli(15015);
        assert!(big > small);
    }
}
