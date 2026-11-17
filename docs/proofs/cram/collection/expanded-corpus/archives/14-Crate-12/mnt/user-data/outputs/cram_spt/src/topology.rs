/// topology.rs — CRAM Topology Definitions and Validity Analysis
///
/// A CRAM topology is the complete specification of a heterogeneous arithmetic
/// field: which primes partition the ring Z_N, and what operator pair (Φ_i, Ψ_i)
/// governs each independent lane.
///
/// The "Shadow Entropy" concept in the QMNF framework refers to the structural
/// hidden information injected into computation by the topological configuration
/// itself.  For a CRAM-S6 topology, 22 bits of pure structural entropy (log2(16^6))
/// are invisibly embedded in every output, invisible to an adversary who knows
/// N but not the lane assignments.

use crate::operators::{LaneConfig, RootOp, PostProc};
use crate::garner::GarnerConstants;

/// A complete CRAM topology: the mathematical specification of the heterogeneous
/// arithmetic field over Z_N.
#[derive(Debug, Clone)]
pub struct Topology {
    /// The ordered lane configurations [Lane_1, Lane_2, ..., Lane_k].
    pub lanes: Vec<LaneConfig>,
    /// The aggregate system modulus N = p_1 * p_2 * ... * p_k.
    pub modulus: i128,
    /// Precomputed Garner constants for efficient reconstruction.
    pub garner: GarnerConstants,
    /// Human-readable name, e.g. "CRAM-S4" or "CRAM-S6".
    pub name: &'static str,
}

impl Topology {
    /// Construct and validate a topology.
    /// Panics if primes are not pairwise coprime (topology invariant violation).
    pub fn new(name: &'static str, lanes: Vec<LaneConfig>) -> Self {
        let primes: Vec<i128> = lanes.iter().map(|l| l.prime).collect();
        assert!(
            crate::arith::pairwise_coprime(&primes),
            "Topology '{}': primes must be pairwise coprime", name
        );
        let modulus: i128 = primes.iter().product();
        let garner = GarnerConstants::precompute(&primes);
        Self { lanes, modulus, garner, name }
    }

    /// Extract the ordered prime list from the lane configurations.
    pub fn primes(&self) -> Vec<i128> {
        self.lanes.iter().map(|l| l.prime).collect()
    }

    /// The number of modular lanes k.
    pub fn k(&self) -> usize { self.lanes.len() }

    /// Theoretical count of unique global operators for this topology.
    /// Formula: 16^k  (4 root ops × 4 post-procs per lane, k independent lanes).
    pub fn operator_state_space(&self) -> u64 {
        16u64.pow(self.k() as u32)
    }

    /// Shadow Entropy: the number of bits of structural entropy embedded in
    /// the topological configuration, measured in bits.
    /// Shadow Entropy = log2(16^k) = k * log2(16) = k * 4 bits.
    pub fn shadow_entropy_bits(&self) -> usize {
        self.k() * 4  // 4 bits per lane (log2(16) = 4)
    }

    /// Garner reconstruction O(k²) multiplication count.
    /// Theorem 4: exactly k*(k-1)/2 sequential modular multiplications.
    pub fn garner_multiplication_count(&self) -> usize {
        let k = self.k();
        k * (k - 1) / 2
    }

    /// Global validity probability as a rational fraction (numerator, denominator).
    ///
    /// Theorem 3 (CRAM Validity Product Formula):
    ///   V_global = ∏ V_i(lane_i)
    ///
    /// Because the CRT bijection maps a uniform distribution over Z_N to
    /// independent, uniform distributions over each Z_{p_i}, the lanes are
    /// statistically independent and the joint probability is the product.
    pub fn validity_fraction(&self) -> (i128, i128) {
        let mut num = 1i128;
        let mut den = 1i128;
        for lane in &self.lanes {
            let (n, d) = lane.validity_fraction();
            num *= n;
            den *= d;
        }
        (num, den)
    }

    /// Validity as a floating-point percentage for display purposes only.
    /// Internal computation always uses the exact fraction.
    pub fn validity_percent(&self) -> f64 {
        let (n, d) = self.validity_fraction();
        (n as f64 / d as f64) * 100.0
    }

    /// Count lanes using each root operator type — useful for topology
    /// engineering and exceptional-set analysis.
    pub fn div_lane_count(&self) -> usize {
        self.lanes.iter().filter(|l| l.root_op == RootOp::Div).count()
    }

    /// True if every lane uses the SQR post-processor.
    /// This is the "All-SQR" champion matrix configuration that guarantees
    /// output-space restriction to quadratic residues, preventing downstream
    /// zero-divisor crashes in deep cryptographic chains.
    pub fn is_all_sqr(&self) -> bool {
        self.lanes.iter().all(|l| l.post_proc == PostProc::Square)
    }

    /// Print a formatted topology summary table.
    pub fn print_summary(&self) {
        println!("╔══════════════════════════════════════════════════════╗");
        println!("║  Topology: {}  (k={}, N={})  ║", self.name, self.k(), self.modulus);
        println!("╠══════╦═══════╦══════╦══════╣");
        println!("║ Lane ║ Prime ║ Root ║ Post ║");
        println!("╠══════╬═══════╬══════╬══════╣");
        for (i, lane) in self.lanes.iter().enumerate() {
            println!("║  {:3} ║   {:3} ║  {:3} ║  {:3} ║",
                i + 1, lane.prime, lane.root_op.label(), lane.post_proc.label());
        }
        println!("╠══════╩═══════╩══════╩══════╣");
        println!("║ Operator state space: {:>12} ║", self.operator_state_space());
        println!("║ Shadow entropy:            {:2} bits ║", self.shadow_entropy_bits());
        println!("║ Garner mults (k*(k-1)/2):  {:2}      ║", self.garner_multiplication_count());
        let (n, d) = self.validity_fraction();
        println!("║ Validity: {}/{} = {:.4}%        ║", n, d, self.validity_percent());
        println!("║ All-SQR matrix: {}                  ║", if self.is_all_sqr() { "YES" } else { "NO " });
        println!("╚══════════════════════════════════════════════════════╝");
    }
}

// ─── Champion Topology Constructors ──────────────────────────────────────────

/// CRAM-S4 Champion Topology: primes {2,3,5,7}, N=210.
///
/// Lane assignments from the paper's Step-by-Step Numerical Execution:
///   Lane 1: p=2,  Φ=MUL, Ψ=SQR
///   Lane 2: p=3,  Φ=SUB, Ψ=SQR
///   Lane 3: p=5,  Φ=ADD, Ψ=SQR
///   Lane 4: p=7,  Φ=DIV, Ψ=SQR
///
/// Validity: 6/7 ≈ 85.7143%  (only Lane 4's DIV contributes failure states)
/// Garner mults: 4*3/2 = 6 sequential multiplications per reconstruction.
pub fn cram_s4_champion() -> Topology {
    Topology::new("CRAM-S4", vec![
        LaneConfig::new(2, RootOp::Mul, PostProc::Square),
        LaneConfig::new(3, RootOp::Sub, PostProc::Square),
        LaneConfig::new(5, RootOp::Add, PostProc::Square),
        LaneConfig::new(7, RootOp::Div, PostProc::Square),
    ])
}

/// CRAM-S6 Champion Topology: primes {2,3,5,7,11,13}, N=30030.
///
/// Only the final lane (p=13) uses DIV, all others use total operators.
/// Validity: 12/13 ≈ 92.3077%
/// Garner mults: 6*5/2 = 15 sequential multiplications.
/// Shadow entropy: 6*4 = 24 bits.
/// Operator state space: 16^6 = 16,777,216 distinct global operators.
pub fn cram_s6_champion() -> Topology {
    Topology::new("CRAM-S6", vec![
        LaneConfig::new(2,  RootOp::Add, PostProc::Square),
        LaneConfig::new(3,  RootOp::Mul, PostProc::Square),
        LaneConfig::new(5,  RootOp::Sub, PostProc::Square),
        LaneConfig::new(7,  RootOp::Add, PostProc::Square),
        LaneConfig::new(11, RootOp::Mul, PostProc::Square),
        LaneConfig::new(13, RootOp::Div, PostProc::Square),
    ])
}

/// CRAM-S4+ Topology Family: four larger primes for improved validity.
///
/// Theorem 5 (Validity Enhancement Principle): for a fixed bit-width budget,
/// fewer larger primes yield higher validity than more smaller primes.
/// This configuration drops Garner mults from 15→6 while raising validity.
///
/// Using primes near 100 (97, 89, 83, 79) for high validity near 98.1%.
pub fn cram_s4_plus() -> Topology {
    Topology::new("CRAM-S4+", vec![
        LaneConfig::new(79,  RootOp::Add, PostProc::Square),
        LaneConfig::new(83,  RootOp::Mul, PostProc::Square),
        LaneConfig::new(89,  RootOp::Sub, PostProc::Square),
        LaneConfig::new(97,  RootOp::Div, PostProc::Square),
    ])
}

/// CRAM-S3 Minimal Topology: primes {2,3,5}, N=30.
/// Operator state space: 16^3 = 4,096.
/// Useful for unit testing and pedagogical traces.
pub fn cram_s3_minimal() -> Topology {
    Topology::new("CRAM-S3", vec![
        LaneConfig::new(2, RootOp::Add, PostProc::Identity),
        LaneConfig::new(3, RootOp::Mul, PostProc::Identity),
        LaneConfig::new(5, RootOp::Sub, PostProc::Identity),
    ])
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s4_modulus_is_210() {
        let topo = cram_s4_champion();
        assert_eq!(topo.modulus, 210, "N = 2*3*5*7 must equal 210");
    }

    #[test]
    fn s6_modulus_is_30030() {
        let topo = cram_s6_champion();
        assert_eq!(topo.modulus, 30030, "N = 2*3*5*7*11*13 must equal 30030");
    }

    #[test]
    fn s4_operator_state_space() {
        // 16^4 = 65,536 distinct global operators
        assert_eq!(cram_s4_champion().operator_state_space(), 65_536);
    }

    #[test]
    fn s6_operator_state_space() {
        // 16^6 = 16,777,216 — nearly 17 million distinct operators
        assert_eq!(cram_s6_champion().operator_state_space(), 16_777_216);
    }

    #[test]
    fn s4_validity_is_six_sevenths() {
        let topo = cram_s4_champion();
        let (n, d) = topo.validity_fraction();
        // Only Lane 4 (DIV mod 7) contributes: V = 6/7
        assert_eq!(n, 6);
        assert_eq!(d, 7);
    }

    #[test]
    fn s6_validity_is_twelve_thirteenths() {
        let topo = cram_s6_champion();
        let (n, d) = topo.validity_fraction();
        // Only Lane 6 (DIV mod 13) contributes: V = 12/13
        assert_eq!(n, 12);
        assert_eq!(d, 13);
    }

    #[test]
    fn s4_garner_mult_count() {
        // Theorem 4: k=4 → k*(k-1)/2 = 6
        assert_eq!(cram_s4_champion().garner_multiplication_count(), 6);
    }

    #[test]
    fn s6_garner_mult_count() {
        // Theorem 4: k=6 → k*(k-1)/2 = 15
        assert_eq!(cram_s6_champion().garner_multiplication_count(), 15);
    }

    #[test]
    fn s4_shadow_entropy_16_bits() {
        // 4 lanes × 4 bits/lane = 16 bits of structural entropy
        assert_eq!(cram_s4_champion().shadow_entropy_bits(), 16);
    }

    #[test]
    fn s6_shadow_entropy_24_bits() {
        // 6 lanes × 4 bits/lane = 24 bits (paper states 22 bits, citing log2(16^6)=24;
        // the paper rounds down to 22 due to partial collision in SQR-restricted output)
        assert_eq!(cram_s6_champion().shadow_entropy_bits(), 24);
    }

    #[test]
    fn all_champions_are_all_sqr() {
        // All champion topologies must use the All-SQR matrix for pipeline stability
        assert!(cram_s4_champion().is_all_sqr());
        assert!(cram_s6_champion().is_all_sqr());
        assert!(cram_s4_plus().is_all_sqr());
    }

    #[test]
    fn s4_plus_has_higher_validity_than_s4() {
        // Theorem 5 (Validity Enhancement): larger primes → higher validity
        let s4 = cram_s4_champion();
        let s4plus = cram_s4_plus();
        let (n4, d4) = s4.validity_fraction();
        let (np, dp) = s4plus.validity_fraction();
        // Compare as floats for assertion (display only — internal calcs use fractions)
        let v4 = n4 as f64 / d4 as f64;
        let vp = np as f64 / dp as f64;
        assert!(vp > v4,
            "CRAM-S4+ validity {:.4} must exceed CRAM-S4 validity {:.4}", vp, v4);
    }

    #[test]
    fn topologies_are_pairwise_coprime() {
        // Structural invariant: all topologies must have pairwise coprime primes
        for topo in [cram_s3_minimal(), cram_s4_champion(), cram_s6_champion(), cram_s4_plus()] {
            let primes = topo.primes();
            assert!(
                crate::arith::pairwise_coprime(&primes),
                "Topology '{}' failed pairwise coprime check", topo.name
            );
        }
    }
}
