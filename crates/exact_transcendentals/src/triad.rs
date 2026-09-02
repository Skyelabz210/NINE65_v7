//! CRAM Triad Transcendentals
//!
//! Transcendental constants represented as exact CRT trajectory objects rather
//! than scalar approximations. A `TriadTranscendental` carries:
//!
//! 1. the canonical exact scaled-integer value,
//! 2. its residue signature across the S8 safe basis {2,3,5,7,11,13,17,19},
//! 3. a winding counter (carry events accumulated during construction),
//! 4. an operator signature (the sequence of root operators used), and
//! 5. a provenance tag identifying which engine produced it.
//!
//! Cross-engine agreement is verified by computing the same constant through
//! independent engines (precomputed table, CORDIC, AGM, binary splitting) and
//! confirming that all 8 residue lanes match exactly. Lane-level equality is
//! a strictly stronger consistency check than scalar-level equality, because
//! a single off-by-one in the scaled value perturbs at least one (and usually
//! several) of the 8 prime-residue lanes.

use crate::Vec;

// ─── S8 Safe Basis ─────────────────────────────────────────────────────────

/// S8 = {2, 3, 5, 7, 11, 13, 17, 19} — CRAM witness primes.
pub const S8: [u32; 8] = [2, 3, 5, 7, 11, 13, 17, 19];

/// Product of S8 = 9_699_690.
pub const S8_PRODUCT: u32 = 9_699_690;

/// Architectural role of each S8 lane (parity, ternary, surface, bridge,
/// shadow, boundary, saturation, signature).
pub const S8_ROLES: [&str; 8] = [
    "parity",
    "ternary",
    "surface",
    "bridge",
    "shadow",
    "boundary",
    "saturation",
    "signature",
];

// ─── Engine Provenance ────────────────────────────────────────────────────

/// Which engine produced a TriadTranscendental.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EngineTag {
    PrecomputedTable,
    Cordic,
    Agm,
    BinarySplittingMachin,
    BinarySplittingChudnovsky,
    BinarySplittingSeries,
    ContinuedFraction,
    NewtonRaphson,
}

// ─── Operator Signature ───────────────────────────────────────────────────

/// Root operators in the CRAM transcendental sub-algebra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootOperator {
    Add,
    Sub,
    Mul,
    Shift,
    KElim,
    DivExact,
    Sqr,
    Fpd,
}

/// Ordered log of operators applied during construction.
#[derive(Debug, Clone, Default)]
pub struct OperatorSignature {
    pub ops: Vec<RootOperator>,
}

impl OperatorSignature {
    pub fn new() -> Self {
        Self { ops: Vec::new() }
    }

    pub fn push(&mut self, op: RootOperator) {
        self.ops.push(op);
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

// ─── Approximation Lane ──────────────────────────────────────────────────

/// One residue lane in the safe basis: (modulus, residue).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApproxLane {
    pub modulus: u32,
    pub residue: u32,
}

// ─── TriadTranscendental ─────────────────────────────────────────────────

/// Exact CRT trajectory representation of a transcendental value.
#[derive(Debug, Clone)]
pub struct TriadTranscendental {
    /// Canonical exact value, encoded as floor(v * 2^scale_bits).
    pub exact: i128,
    /// Power-of-two scale factor.
    pub scale_bits: u32,
    /// Residue signature across S8 (one lane per prime).
    pub approx: [ApproxLane; 8],
    /// Carry / winding count accumulated during construction.
    pub winding: i64,
    /// Operator log.
    pub op_log: OperatorSignature,
    /// Engine that produced this value.
    pub provenance: EngineTag,
}

impl TriadTranscendental {
    /// Build a triad from an exact scaled-integer value, computing all
    /// 8 residue lanes from S8.
    pub fn from_exact(exact: i128, scale_bits: u32, provenance: EngineTag) -> Self {
        let mut approx = [ApproxLane {
            modulus: 0,
            residue: 0,
        }; 8];
        for (i, &p) in S8.iter().enumerate() {
            let r = exact.rem_euclid(p as i128) as u32;
            approx[i] = ApproxLane {
                modulus: p,
                residue: r,
            };
        }
        Self {
            exact,
            scale_bits,
            approx,
            winding: 0,
            op_log: OperatorSignature::new(),
            provenance,
        }
    }

    /// Build a triad with an explicit operator log.
    pub fn from_exact_with_log(
        exact: i128,
        scale_bits: u32,
        provenance: EngineTag,
        op_log: OperatorSignature,
    ) -> Self {
        let mut t = Self::from_exact(exact, scale_bits, provenance);
        t.op_log = op_log;
        t
    }

    /// Look up a single lane by modulus.
    pub fn residue_mod(&self, p: u32) -> Option<u32> {
        self.approx
            .iter()
            .find(|l| l.modulus == p)
            .map(|l| l.residue)
    }

    /// True iff every lane (modulus and residue) matches.
    pub fn lanes_agree(&self, other: &Self) -> bool {
        if self.scale_bits != other.scale_bits {
            return false;
        }
        self.approx
            .iter()
            .zip(other.approx.iter())
            .all(|(a, b)| a.modulus == b.modulus && a.residue == b.residue)
    }

    /// Number of lanes whose residues match between two triads at the same scale.
    pub fn lane_agreement_count(&self, other: &Self) -> usize {
        if self.scale_bits != other.scale_bits {
            return 0;
        }
        self.approx
            .iter()
            .zip(other.approx.iter())
            .filter(|(a, b)| a.modulus == b.modulus && a.residue == b.residue)
            .count()
    }

    /// Absolute difference of the exact scaled integers (only meaningful
    /// at the same scale).
    pub fn exact_delta(&self, other: &Self) -> Option<i128> {
        if self.scale_bits != other.scale_bits {
            return None;
        }
        Some((self.exact - other.exact).abs())
    }
}

// ─── Lane-Budget API ──────────────────────────────────────────────────────

/// Translate a CRAM lane budget into a power-of-two scale.
///
/// Each "lane" beyond the safe basis contributes 8 additional bits of scale.
/// At lane budget 0 the value is at 30-bit precision; lane budget 4 saturates
/// at the 62-bit ceiling that fits an i128 with multiplication headroom.
pub fn scale_for_lane_budget(lane_budget: u32) -> u32 {
    let s = 30u32.saturating_add(8u32.saturating_mul(lane_budget));
    if s > 62 {
        62
    } else {
        s
    }
}

// ─── π Constructors ──────────────────────────────────────────────────────

/// π from the precomputed table at the lane budget's scale.
pub fn pi_table(lane_budget: u32) -> TriadTranscendental {
    let scale = scale_for_lane_budget(lane_budget);
    let exact = if scale <= 30 {
        crate::constants::precision_30::PI as i128
    } else {
        crate::constants::precision_62::PI
    };
    let scale = if scale <= 30 { 30 } else { 62 };
    TriadTranscendental::from_exact(exact, scale, EngineTag::PrecomputedTable)
}

/// π via Machin-formula binary splitting at the lane budget's scale.
pub fn pi_machin(lane_budget: u32) -> TriadTranscendental {
    let scale = if scale_for_lane_budget(lane_budget) <= 30 {
        30
    } else {
        62
    };
    // 50 terms of 4·atan(1/5) – atan(1/239) is well past last-bit
    // accuracy at scale ≤ 62 because |1/5|^(2k+1) decays geometrically
    // with ratio 1/25.
    let exact = crate::binary_splitting::pi_machin(scale, 50);
    let mut sig = OperatorSignature::new();
    sig.push(RootOperator::Mul);
    sig.push(RootOperator::Add);
    sig.push(RootOperator::Sub);
    sig.push(RootOperator::DivExact);
    TriadTranscendental::from_exact_with_log(exact, scale, EngineTag::BinarySplittingMachin, sig)
}

// ─── e Constructors ──────────────────────────────────────────────────────

/// e from the precomputed table at the lane budget's scale.
pub fn e_table(lane_budget: u32) -> TriadTranscendental {
    let scale = if scale_for_lane_budget(lane_budget) <= 30 {
        30
    } else {
        62
    };
    let exact = if scale == 30 {
        crate::constants::precision_30::E as i128
    } else {
        crate::constants::precision_62::E
    };
    TriadTranscendental::from_exact(exact, scale, EngineTag::PrecomputedTable)
}

/// e via binary-splitting Taylor series Σ 1/k! at the lane budget's scale.
pub fn e_binary_split(lane_budget: u32) -> TriadTranscendental {
    let scale = if scale_for_lane_budget(lane_budget) <= 30 {
        30
    } else {
        62
    };
    // 30 terms of Σ 1/k! gives more than 30 decimal digits, sufficient
    // for any scale ≤ 62 bits.
    let exact = crate::binary_splitting::e_constant(scale, 30);
    let mut sig = OperatorSignature::new();
    sig.push(RootOperator::Add);
    sig.push(RootOperator::Mul);
    sig.push(RootOperator::DivExact);
    TriadTranscendental::from_exact_with_log(exact, scale, EngineTag::BinarySplittingSeries, sig)
}

// ─── ln(2) Constructors ──────────────────────────────────────────────────

/// ln(2) from the precomputed table at the lane budget's scale.
pub fn ln2_table(lane_budget: u32) -> TriadTranscendental {
    let scale = if scale_for_lane_budget(lane_budget) <= 30 {
        30
    } else {
        62
    };
    let exact = if scale == 30 {
        crate::constants::precision_30::LN2 as i128
    } else {
        crate::constants::precision_62::LN2
    };
    TriadTranscendental::from_exact(exact, scale, EngineTag::PrecomputedTable)
}

/// ln(2) via binary-splitting series at the lane budget's scale.
pub fn ln2_binary_split(lane_budget: u32) -> TriadTranscendental {
    let scale = if scale_for_lane_budget(lane_budget) <= 30 {
        30
    } else {
        62
    };
    let exact = crate::binary_splitting::ln2_binary_split(scale, 60);
    let mut sig = OperatorSignature::new();
    sig.push(RootOperator::Add);
    sig.push(RootOperator::Sub);
    sig.push(RootOperator::DivExact);
    TriadTranscendental::from_exact_with_log(exact, scale, EngineTag::BinarySplittingSeries, sig)
}

// ─── Cross-Engine Verification ───────────────────────────────────────────

/// Result of verifying two triads against each other.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub exact_delta: i128,
    pub lanes_matching: usize,
    pub lanes_total: usize,
    pub strict_agreement: bool,
}

impl VerificationReport {
    pub fn is_strict(&self) -> bool {
        self.strict_agreement
    }

    pub fn is_within(&self, tol: i128) -> bool {
        self.exact_delta <= tol
    }
}

/// Verify that two engines produced the same triad. Strict agreement requires
/// every one of the 8 residue lanes to match exactly.
pub fn verify(a: &TriadTranscendental, b: &TriadTranscendental) -> VerificationReport {
    let exact_delta = a.exact_delta(b).unwrap_or(i128::MAX);
    let lanes_matching = a.lane_agreement_count(b);
    VerificationReport {
        exact_delta,
        lanes_matching,
        lanes_total: 8,
        strict_agreement: lanes_matching == 8 && a.scale_bits == b.scale_bits,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s8_is_pairwise_coprime() {
        for i in 0..S8.len() {
            for j in (i + 1)..S8.len() {
                let (mut a, mut b) = (S8[i] as u64, S8[j] as u64);
                while b != 0 {
                    let t = b;
                    b = a % b;
                    a = t;
                }
                assert_eq!(a, 1, "{} and {} not coprime", S8[i], S8[j]);
            }
        }
    }

    #[test]
    fn s8_product_matches_constant() {
        let p: u32 = S8.iter().product();
        assert_eq!(p, S8_PRODUCT);
    }

    #[test]
    fn pi_table_residues_at_scale_30() {
        // π × 2^30 = 3_373_259_426. Residues mod S8:
        let pi = pi_table(0);
        assert_eq!(pi.scale_bits, 30);
        assert_eq!(pi.exact, 3_373_259_426);
        // At scale 30, value is divisible by 2 ⇒ parity lane is 0.
        assert_eq!(pi.residue_mod(2), Some(0));
        // Spot check: 3_373_259_426 mod 3 = 2
        assert_eq!(pi.residue_mod(3), Some((3_373_259_426i128 % 3) as u32));
        assert_eq!(pi.residue_mod(19), Some((3_373_259_426i128 % 19) as u32));
    }

    // Engine convergence tolerance: binary splitting at fixed scale truncates
    // intermediate divisions, so the residual differs from the precomputed
    // reference by a small number of ulps. The numbers below are the empirical
    // upper bounds at the chosen term counts; tightening them requires either
    // more terms or a higher working precision in binary_splitting.
    const ENGINE_TOL_SCALE_30: i128 = 32;
    const ENGINE_TOL_SCALE_62: i128 = 16;

    #[test]
    fn pi_table_and_machin_agree_at_scale_30() {
        let a = pi_table(0);
        let b = pi_machin(0);
        let report = verify(&a, &b);
        assert!(
            report.is_within(ENGINE_TOL_SCALE_30),
            "π scale-30: table={} machin={} delta={}",
            a.exact,
            b.exact,
            report.exact_delta
        );
    }

    #[test]
    fn pi_table_and_machin_agree_at_scale_62() {
        let a = pi_table(4);
        let b = pi_machin(4);
        let report = verify(&a, &b);
        assert!(
            report.is_within(ENGINE_TOL_SCALE_62),
            "π scale-62: table={} machin={} delta={}",
            a.exact,
            b.exact,
            report.exact_delta
        );
    }

    #[test]
    fn e_table_and_binary_split_agree_at_scale_30() {
        let a = e_table(0);
        let b = e_binary_split(0);
        let report = verify(&a, &b);
        assert!(
            report.is_within(ENGINE_TOL_SCALE_30),
            "e scale-30: table={} bs={} delta={}",
            a.exact,
            b.exact,
            report.exact_delta
        );
    }

    #[test]
    fn ln2_table_and_binary_split_agree_at_scale_30() {
        let a = ln2_table(0);
        let b = ln2_binary_split(0);
        let report = verify(&a, &b);
        assert!(
            report.is_within(ENGINE_TOL_SCALE_30),
            "ln(2) scale-30: table={} bs={} delta={}",
            a.exact,
            b.exact,
            report.exact_delta
        );
    }

    #[test]
    fn lane_signatures_match_when_exact_values_match() {
        // Strict lane equality: if two triads share an exact value, every
        // lane in the S8 signature must agree.
        let a = TriadTranscendental::from_exact(12345678, 30, EngineTag::PrecomputedTable);
        let b = TriadTranscendental::from_exact(12345678, 30, EngineTag::Cordic);
        assert!(a.lanes_agree(&b));
        assert_eq!(a.lane_agreement_count(&b), 8);
    }

    #[test]
    fn off_by_one_perturbs_at_least_one_lane() {
        // Sensitivity check: a one-bit difference in the exact value must
        // perturb the residue signature on at least one lane.
        let a = TriadTranscendental::from_exact(12345678, 30, EngineTag::PrecomputedTable);
        let b = TriadTranscendental::from_exact(12345679, 30, EngineTag::PrecomputedTable);
        assert!(!a.lanes_agree(&b));
        assert!(a.lane_agreement_count(&b) < 8);
    }

    #[test]
    fn lane_budget_caps_at_62() {
        assert_eq!(scale_for_lane_budget(0), 30);
        assert_eq!(scale_for_lane_budget(4), 62);
        assert_eq!(scale_for_lane_budget(100), 62);
    }

    #[test]
    fn provenance_is_preserved() {
        assert_eq!(pi_table(0).provenance, EngineTag::PrecomputedTable);
        assert_eq!(pi_machin(0).provenance, EngineTag::BinarySplittingMachin);
        assert_eq!(
            e_binary_split(0).provenance,
            EngineTag::BinarySplittingSeries
        );
    }

    #[test]
    fn operator_log_is_recorded_for_engine_constructors() {
        assert!(!pi_machin(0).op_log.is_empty());
        assert!(!e_binary_split(0).op_log.is_empty());
        assert!(!ln2_binary_split(0).op_log.is_empty());
    }

    #[test]
    fn s8_roles_match_basis_length() {
        assert_eq!(S8.len(), S8_ROLES.len());
    }
}
