//! CRAM Comparison Harness — measures the winding-tower architecture against
//! existing carriers across correctness, reconstruction count, and depth.
//!
//! The central thesis under test: lane-parallel arithmetic in the winding-tower
//! carrier needs full reconstruction (Garner scalar extraction) ONLY at I/O
//! boundaries, whereas a reconstruct-per-op carrier reconstructs on every step.
//! Fewer reconstructions ⇒ no compute blow-up, no noise growth.
//!
//! Strategies compared:
//! - **WindingTower**: lane-parallel `WindingCRT`, reconstruct at I/O only
//! - **ReconstructPerOp**: baseline that reconstructs both operands every op
//!   (this is the OLD DynCRT behaviour we replaced)
//! - **WassanRing**: ℤ_p residue ring for add-chains (no scalar extraction)
//!
//! Metrics per run:
//! - `reconstructions`: full Garner extractions performed (lower is better)
//! - `correct`: result matches ground-truth checked i128 arithmetic
//! - `max_winding_depth`: deepest winding tower reached
//!
//! Variations are pluggable: add a new strategy by implementing one function
//! that returns a `ChainStats`. Zero floating point. Harness output is std-only.

// Vec and the carriers are used only by the std-gated strategy runners;
// the no_std surface of this module is just Workload/ChainStats/ground_truth.
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "std")]
use crate::dyn_crt::{WassanRing, WindingCRT};

/// Which arithmetic workload to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Workload {
    /// Sum a sequence of values (depth = n additions).
    AddChain,
    /// Product of a sequence of values (depth = n multiplications).
    MulChain,
    /// Alternating add/mul over a sequence.
    Mixed,
}

/// Result of running one strategy on one workload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainStats {
    /// Strategy name.
    pub strategy: &'static str,
    /// Workload run.
    pub workload: Workload,
    /// Number of operations in the chain.
    pub ops: usize,
    /// Full reconstructions (Garner scalar extractions) performed.
    pub reconstructions: u64,
    /// Final reconstructed value (None if outside corridor / overflow).
    pub final_value: Option<i128>,
    /// Whether the final value matches ground truth.
    pub correct: bool,
    /// Deepest winding tower observed during the run.
    pub max_winding_depth: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// Ground truth (plain checked i128 arithmetic)
// ═══════════════════════════════════════════════════════════════════════════

/// Ground-truth result for a workload over `inputs`. Returns None on overflow.
pub fn ground_truth(workload: Workload, inputs: &[i128]) -> Option<i128> {
    match workload {
        Workload::AddChain => {
            let mut acc = 0i128;
            for &v in inputs {
                acc = acc.checked_add(v)?;
            }
            Some(acc)
        }
        Workload::MulChain => {
            let mut acc = 1i128;
            for &v in inputs {
                acc = acc.checked_mul(v)?;
            }
            Some(acc)
        }
        Workload::Mixed => {
            let mut acc = 0i128;
            for (i, &v) in inputs.iter().enumerate() {
                if i % 2 == 0 {
                    acc = acc.checked_add(v)?;
                } else {
                    acc = acc.checked_mul(v)?;
                }
            }
            Some(acc)
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Strategy: Winding Tower (reconstruct at I/O only)
// ═══════════════════════════════════════════════════════════════════════════

/// Run a workload using the winding-tower carrier. Reconstruction happens
/// only once, at the final readout.
#[cfg(feature = "std")]
pub fn run_winding(workload: Workload, inputs: &[i128]) -> ChainStats {
    use crate::dyn_crt::{reconstruction_count, reset_reconstruction_count};

    reset_reconstruction_count();
    let mut max_depth = 0usize;

    let acc = match workload {
        Workload::AddChain => {
            let mut acc = WindingCRT::from_i128(0);
            for &v in inputs {
                acc = acc.add(&WindingCRT::from_i128(v));
                max_depth = max_depth.max(acc.winding_digits().len());
            }
            acc
        }
        Workload::MulChain => {
            let mut acc = WindingCRT::from_i128(1);
            for &v in inputs {
                acc = acc.mul(&WindingCRT::from_i128(v));
                max_depth = max_depth.max(acc.winding_digits().len());
            }
            acc
        }
        Workload::Mixed => {
            let mut acc = WindingCRT::from_i128(0);
            for (i, &v) in inputs.iter().enumerate() {
                if i % 2 == 0 {
                    acc = acc.add(&WindingCRT::from_i128(v));
                } else {
                    acc = acc.mul(&WindingCRT::from_i128(v));
                }
                max_depth = max_depth.max(acc.winding_digits().len());
            }
            acc
        }
    };

    // Single I/O reconstruction at the end.
    let final_value = acc.to_i128();
    let reconstructions = reconstruction_count();
    let truth = ground_truth(workload, inputs);

    ChainStats {
        strategy: "WindingTower",
        workload,
        ops: inputs.len(),
        reconstructions,
        final_value,
        correct: final_value == truth,
        max_winding_depth: max_depth,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Strategy: Reconstruct-Per-Op (the OLD DynCRT baseline we replaced)
// ═══════════════════════════════════════════════════════════════════════════

/// Run a workload reconstructing both operands to i128 on every step, then
/// re-encoding. This models the old DynCRT behaviour: every arithmetic op is
/// an I/O round-trip. Used as the comparison baseline.
#[cfg(feature = "std")]
pub fn run_reconstruct_per_op(workload: Workload, inputs: &[i128]) -> ChainStats {
    use crate::dyn_crt::{reconstruction_count, reset_reconstruction_count};

    reset_reconstruction_count();

    // Helper: reconstruct both operands, combine in i128, re-encode.
    fn op_add(a: &WindingCRT, b: &WindingCRT) -> WindingCRT {
        let x = a.to_i128().expect("corridor");
        let y = b.to_i128().expect("corridor");
        WindingCRT::from_i128(x.checked_add(y).expect("overflow"))
    }
    fn op_mul(a: &WindingCRT, b: &WindingCRT) -> WindingCRT {
        let x = a.to_i128().expect("corridor");
        let y = b.to_i128().expect("corridor");
        WindingCRT::from_i128(x.checked_mul(y).expect("overflow"))
    }

    let acc = match workload {
        Workload::AddChain => {
            let mut acc = WindingCRT::from_i128(0);
            for &v in inputs {
                acc = op_add(&acc, &WindingCRT::from_i128(v));
            }
            acc
        }
        Workload::MulChain => {
            let mut acc = WindingCRT::from_i128(1);
            for &v in inputs {
                acc = op_mul(&acc, &WindingCRT::from_i128(v));
            }
            acc
        }
        Workload::Mixed => {
            let mut acc = WindingCRT::from_i128(0);
            for (i, &v) in inputs.iter().enumerate() {
                if i % 2 == 0 {
                    acc = op_add(&acc, &WindingCRT::from_i128(v));
                } else {
                    acc = op_mul(&acc, &WindingCRT::from_i128(v));
                }
            }
            acc
        }
    };

    let final_value = acc.to_i128();
    let reconstructions = reconstruction_count();
    let truth = ground_truth(workload, inputs);

    ChainStats {
        strategy: "ReconstructPerOp",
        workload,
        ops: inputs.len(),
        reconstructions,
        final_value,
        correct: final_value == truth,
        max_winding_depth: 0,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Strategy: WASSAN Ring (add chains, no scalar extraction during compute)
// ═══════════════════════════════════════════════════════════════════════════

/// Run an add-chain in the WASSAN residue ring. The residue array IS the value;
/// no Garner reconstruction occurs — extraction to u128 is a positional decode
/// at I/O only. MulChain is not supported (ring mul needs convolution); returns
/// a stats row flagged accordingly.
#[cfg(feature = "std")]
pub fn run_wassan(workload: Workload, inputs: &[i128], modulus: u64, dim: usize) -> ChainStats {
    // Only add-chains over non-negative inputs are modelled here.
    if workload != Workload::AddChain || inputs.iter().any(|&v| v < 0) {
        return ChainStats {
            strategy: "WassanRing",
            workload,
            ops: inputs.len(),
            reconstructions: 0,
            final_value: None,
            correct: false,
            max_winding_depth: 0,
        };
    }

    let mut acc = WassanRing::zero(modulus, dim);
    for &v in inputs {
        acc = acc.add(&WassanRing::from_u128(v as u128, modulus, dim));
    }

    let final_value = acc.to_u128().and_then(|u| i128::try_from(u).ok());
    let truth = ground_truth(workload, inputs);

    ChainStats {
        strategy: "WassanRing",
        workload,
        ops: inputs.len(),
        reconstructions: 0, // residue array is the value — no Garner extraction
        final_value,
        correct: final_value == truth,
        max_winding_depth: 0,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Comparison driver + report
// ═══════════════════════════════════════════════════════════════════════════

/// Run all applicable strategies on a workload and collect their stats.
#[cfg(feature = "std")]
pub fn run_comparison(workload: Workload, inputs: &[i128]) -> Vec<ChainStats> {
    let mut out = Vec::new();
    out.push(run_winding(workload, inputs));
    out.push(run_reconstruct_per_op(workload, inputs));
    if workload == Workload::AddChain && inputs.iter().all(|&v| v >= 0) {
        out.push(run_wassan(workload, inputs, 1_000_003, 32));
    }
    out
}

/// Format a comparison table as a string (std-only).
#[cfg(feature = "std")]
pub fn format_report(title: &str, stats: &[ChainStats]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "\n=== {} ===", title);
    let _ = writeln!(
        s,
        "{:<18} {:>5} {:>16} {:>9} {:>12}",
        "strategy", "ops", "reconstructions", "correct", "windingMax"
    );
    let _ = writeln!(s, "{}", "-".repeat(64));
    for st in stats {
        let _ = writeln!(
            s,
            "{:<18} {:>5} {:>16} {:>9} {:>12}",
            st.strategy,
            st.ops,
            st.reconstructions,
            if st.correct { "yes" } else { "NO" },
            st.max_winding_depth
        );
    }
    s
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn ground_truth_add() {
        let inputs: Vec<i128> = (1..=10).collect();
        assert_eq!(ground_truth(Workload::AddChain, &inputs), Some(55));
    }

    #[test]
    fn ground_truth_mul() {
        let inputs = [2i128, 3, 5, 7];
        assert_eq!(ground_truth(Workload::MulChain, &inputs), Some(210));
    }

    #[test]
    fn winding_add_chain_correct() {
        let inputs: Vec<i128> = (1..=20).collect();
        let stats = run_winding(Workload::AddChain, &inputs);
        assert!(stats.correct, "winding add chain must be exact");
        assert_eq!(stats.final_value, Some(210));
    }

    #[test]
    fn winding_mul_chain_correct() {
        let inputs = [2i128, 3, 5, 7, 11, 13];
        let stats = run_winding(Workload::MulChain, &inputs);
        assert!(stats.correct, "winding mul chain must be exact");
        assert_eq!(stats.final_value, Some(30030));
    }

    #[test]
    fn reconstruct_per_op_also_correct() {
        let inputs: Vec<i128> = (1..=20).collect();
        let stats = run_reconstruct_per_op(Workload::AddChain, &inputs);
        assert!(stats.correct);
        assert_eq!(stats.final_value, Some(210));
    }

    #[test]
    fn winding_uses_fewer_reconstructions_on_add() {
        // The headline result: same correct answer, far fewer reconstructions.
        let inputs: Vec<i128> = (1..=30).collect();
        let winding = run_winding(Workload::AddChain, &inputs);
        let baseline = run_reconstruct_per_op(Workload::AddChain, &inputs);

        assert!(winding.correct && baseline.correct);
        assert_eq!(winding.final_value, baseline.final_value);

        // Winding does a single I/O reconstruction (all-positive add chain
        // stays lane-parallel). Baseline reconstructs on every op.
        assert!(
            winding.reconstructions < baseline.reconstructions,
            "winding {} should be < baseline {}",
            winding.reconstructions,
            baseline.reconstructions
        );
        assert_eq!(
            winding.reconstructions, 1,
            "all-positive add chain should reconstruct exactly once (final I/O)"
        );
    }

    #[test]
    fn wassan_add_chain_zero_reconstructions() {
        let inputs: Vec<i128> = (1..=100).collect();
        let stats = run_wassan(Workload::AddChain, &inputs, 1_000_003, 32);
        assert!(stats.correct, "wassan add chain must be exact");
        assert_eq!(stats.final_value, Some(5050));
        assert_eq!(stats.reconstructions, 0, "ring needs no Garner extraction");
    }

    #[test]
    fn comparison_all_agree() {
        let inputs: Vec<i128> = (1..=50).collect();
        let results = run_comparison(Workload::AddChain, &inputs);
        let truth = ground_truth(Workload::AddChain, &inputs);
        for r in &results {
            assert!(r.correct, "{} disagreed with ground truth", r.strategy);
            assert_eq!(r.final_value, truth);
        }
    }

    #[test]
    fn report_renders() {
        let inputs: Vec<i128> = (1..=25).collect();
        let results = run_comparison(Workload::AddChain, &inputs);
        let report = format_report("add-chain 1..=25", &results);
        assert!(report.contains("WindingTower"));
        assert!(report.contains("ReconstructPerOp"));
    }

    /// Prints the full comparison so `cargo test -- --nocapture` shows the
    /// effectiveness numbers across workloads.
    #[test]
    fn print_effectiveness_report() {
        let add_inputs: Vec<i128> = (1..=40).collect();
        let mul_inputs = [2i128, 3, 5, 7, 11, 13, 17, 19];
        let mixed_inputs: Vec<i128> = (1..=12).collect();

        let add = run_comparison(Workload::AddChain, &add_inputs);
        let mul = run_comparison(Workload::MulChain, &mul_inputs);
        let mixed = run_comparison(Workload::Mixed, &mixed_inputs);

        println!("{}", format_report("AddChain 1..=40", &add));
        println!("{}", format_report("MulChain S8 primes", &mul));
        println!("{}", format_report("Mixed 1..=12", &mixed));

        // Sanity: winding correct on every workload it fully supports.
        assert!(add[0].correct && mul[0].correct && mixed[0].correct);
    }
}
