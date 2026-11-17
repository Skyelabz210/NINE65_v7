/// engine.rs — The Core CRAM Execution Engine
///
/// This module implements the central CRAM computation pipeline:
///   1. Decompose inputs A, B into residue tuples via Recumbent CRT
///   2. Apply heterogeneous lane operators (Root × Post-Processor) in parallel
///   3. Optionally reconstruct via Garner's algorithm (I/O boundary only)
///
/// The fundamental architectural division is between:
///   - CramResult<ResidueTuple>  → Residue-Native (lazy) mode: sub-nanosecond,
///     suitable for deep chains; no Garner penalty.
///   - CramResult<i128>          → Eager mode: full Garner reconstruction,
///     ~307 ns overhead, used only at I/O boundaries.
///
/// Theorem 1 (Correctness of Residue-Native Computing) guarantees that
/// the lazy path produces exactly the same final integer as the eager path.

use crate::topology::Topology;
use crate::garner::{decompose, reconstruct, garner_reconstruct, GarnerResult};

// ─── Error and Result Types ───────────────────────────────────────────────────

/// A CRAM operation result — either a successful output or an
/// "exceptional set" event, where one or more lanes entered an undefined
/// state (division by zero, uninvertible element, etc.).
///
/// Exceptional states are first-class values, not panics.  They carry
/// the lane index that triggered the failure and the residues that
/// were computed successfully before the failure.  This structure
/// supports the AHOP timing-obfuscation strategy, where exceptional
/// events are deliberately exploited as defensive stalls.
#[derive(Debug, Clone)]
pub enum CramError {
    /// A lane encountered an undefined operation (DIV/INV on zero).
    ExceptionalSet {
        /// Which lane triggered the failure (0-indexed).
        lane_index: usize,
        /// The input residues for A that were being processed.
        a_residues: Vec<i128>,
        /// The input residues for B that were being processed.
        b_residues: Vec<i128>,
    },
}

pub type CramResult<T> = Result<T, CramError>;

// ─── Residue Tuple ────────────────────────────────────────────────────────────

/// A decomposed integer: its independent residue components over the
/// topology's prime lanes.  This is the native working format under
/// Residue-Native Computing.  Staying in this form defers the O(k²)
/// Garner penalty for the entire duration of a computation chain.
#[derive(Debug, Clone, PartialEq)]
pub struct ResidueTuple {
    pub residues: Vec<i128>,
    pub primes:   Vec<i128>,
}

impl ResidueTuple {
    pub fn new(residues: Vec<i128>, primes: Vec<i128>) -> Self {
        assert_eq!(residues.len(), primes.len());
        Self { residues, primes }
    }

    /// Reconstruct to a scalar integer — the I/O boundary operation.
    /// This triggers the O(k²) Garner reconstruction cost.
    pub fn reconstruct(&self, garner: &crate::garner::GarnerConstants) -> i128 {
        reconstruct(&self.residues, garner)
    }
}

// ─── The CRAM Engine ──────────────────────────────────────────────────────────

/// The stateful CRAM execution engine bound to a fixed topology.
///
/// The engine's topology is immutable after construction.  All operations
/// are exact integer arithmetic — no floating-point anywhere.
pub struct CramEngine {
    pub topology: Topology,
}

impl CramEngine {
    pub fn new(topology: Topology) -> Self {
        Self { topology }
    }

    // ── Decomposition ─────────────────────────────────────────────────────────

    /// Decompose a scalar integer into a residue tuple for this topology.
    /// This is the entry point for any value entering the CRAM pipeline.
    pub fn decompose(&self, x: i128) -> ResidueTuple {
        let primes = self.topology.primes();
        ResidueTuple::new(decompose(x, &primes), primes)
    }

    // ── Core Lane Execution ───────────────────────────────────────────────────

    /// Execute one full CRAM operation in Residue-Native mode.
    ///
    /// Both inputs are already in residue form (e.g. the outputs of previous
    /// operations in a deep chain).  The result is returned as a ResidueTuple
    /// without any Garner reconstruction — sub-nanosecond execution.
    ///
    /// This is the fundamental execution loop: each lane runs its assigned
    /// (Root, PostProc) pair independently.  Lanes are logically parallel;
    /// in a SIMD-capable runtime they can be vectorized across lanes
    /// (inter-lane parallelism), though intra-instance Garner remains serial.
    pub fn execute_residue(
        &self,
        a: &ResidueTuple,
        b: &ResidueTuple,
    ) -> CramResult<ResidueTuple> {
        let k = self.topology.k();
        let mut output_residues = Vec::with_capacity(k);

        for i in 0..k {
            let lane   = &self.topology.lanes[i];
            let a_res  = a.residues[i];
            let b_res  = b.residues[i];

            match lane.evaluate(a_res, b_res) {
                Some(r) => output_residues.push(r),
                None    => {
                    return Err(CramError::ExceptionalSet {
                        lane_index: i,
                        a_residues: a.residues.clone(),
                        b_residues: b.residues.clone(),
                    });
                }
            }
        }

        Ok(ResidueTuple::new(output_residues, self.topology.primes()))
    }

    /// Execute a CRAM operation with scalar inputs and scalar output.
    ///
    /// This is the "eager" mode: decompose → execute → reconstruct.
    /// It pays the full O(k²) Garner cost and should only be used at
    /// I/O boundaries, not inside deep computation chains.
    ///
    /// For the canonical paper trace: engine.execute(17, 23) on CRAM-S4 = 165.
    pub fn execute(&self, a_int: i128, b_int: i128) -> CramResult<i128> {
        let a = self.decompose(a_int);
        let b = self.decompose(b_int);
        let result = self.execute_residue(&a, &b)?;
        Ok(result.reconstruct(&self.topology.garner))
    }

    /// Execute with a detailed Garner trace — useful for pedagogical
    /// verification and debugging deep chains.
    pub fn execute_traced(&self, a_int: i128, b_int: i128)
        -> CramResult<(i128, GarnerResult, ResidueTuple)>
    {
        let a = self.decompose(a_int);
        let b = self.decompose(b_int);
        let result_residues = self.execute_residue(&a, &b)?;
        let garner_result = garner_reconstruct(
            &result_residues.residues,
            &self.topology.garner,
        );
        Ok((garner_result.value, garner_result, result_residues))
    }

    // ── Residue-Native Chain Execution ────────────────────────────────────────

    /// Execute a chain of n operations in Residue-Native mode (lazy reconstruction).
    ///
    /// This implements the T_lazy(n) = T_d + n*T_r + T_rec path from Theorem 2.
    /// Reconstruction is called ONCE at the end, regardless of chain depth n.
    ///
    /// For large n, this approaches the asymptotic speedup:
    ///   lim_{n→∞} T_traditional(n) / T_lazy(n) = (T_d + T_r + T_rec) / T_r
    ///
    /// With T_rec = 307 ns dominating, this yields ~1 + 307/1 ≈ 308× speedup
    /// per operation in very deep chains (or ~47.5× at realistic chain depths).
    pub fn execute_chain_lazy(
        &self,
        initial_a: i128,
        initial_b: i128,
        additional_bs: &[i128],
    ) -> CramResult<i128> {
        // Single decomposition at chain entry
        let mut accumulator = self.decompose(initial_a);
        let b_start = self.decompose(initial_b);

        // Apply first operation
        accumulator = self.execute_residue(&accumulator, &b_start)?;

        // Continue chain entirely in residue-native form — no Garner until the end
        for &b_scalar in additional_bs {
            let b_res = self.decompose(b_scalar);
            accumulator = self.execute_residue(&accumulator, &b_res)?;
        }

        // Single reconstruction at chain exit (the I/O boundary)
        Ok(accumulator.reconstruct(&self.topology.garner))
    }

    /// Execute the same chain in "traditional" mode (eager reconstruction after
    /// each step) for comparison against the lazy path.
    ///
    /// This implements the T_traditional(n) = n*(T_d + T_r + T_rec) path.
    /// Used in tests to verify Theorem 1: lazy and eager produce identical output.
    pub fn execute_chain_traditional(
        &self,
        initial_a: i128,
        initial_b: i128,
        additional_bs: &[i128],
    ) -> CramResult<i128> {
        // Eager: reconstruct after every operation
        let mut current = self.execute(initial_a, initial_b)?;

        for &b_scalar in additional_bs {
            current = self.execute(current, b_scalar)?;
        }

        Ok(current)
    }

    // ── Validity Analysis ─────────────────────────────────────────────────────

    /// Count how many of the first `n` operation pairs (A, A+1) are valid.
    /// Returns (valid_count, total_count) for empirical validity estimation.
    ///
    /// This is the empirical counterpart to the theoretical Validity Product
    /// Formula (Theorem 3).  For a properly implemented topology the two
    /// should converge as n grows.
    pub fn empirical_validity(&self, n: i128) -> (usize, usize) {
        let n_mod = self.topology.modulus;
        let mut valid = 0usize;
        for i in 0..n {
            let a = i % n_mod;
            let b = (i + 1) % n_mod;
            if self.execute(a, b).is_ok() {
                valid += 1;
            }
        }
        (valid, n as usize)
    }

    /// Print a full step-by-step execution trace matching the paper's format.
    pub fn print_trace(&self, a_int: i128, b_int: i128) {
        println!("\n══════════════════════════════════════════════════════");
        println!("  CRAM Execution Trace: {} ⊛_{} {}", a_int, self.topology.name, b_int);
        println!("══════════════════════════════════════════════════════");

        let a_res = self.decompose(a_int);
        let b_res = self.decompose(b_int);

        println!("\n─ Phase 1: Residue-Native Decomposition ─");
        println!("  A = {} → {:?}", a_int, a_res.residues);
        println!("  B = {} → {:?}", b_int, b_res.residues);

        println!("\n─ Phase 2: Root Operator Application ─");
        let primes = self.topology.primes();
        let mut intermediate = Vec::new();
        for (i, lane) in self.topology.lanes.iter().enumerate() {
            let a_r = a_res.residues[i];
            let b_r = b_res.residues[i];
            match lane.root_op.apply(a_r, b_r, lane.prime) {
                Some(r) => {
                    println!("  Lane {}: {}({}, {}) mod {} = {}",
                        i + 1, lane.root_op.label(), a_r, b_r, lane.prime, r);
                    intermediate.push(r);
                }
                None => {
                    println!("  Lane {}: {}({}, {}) mod {} = EXCEPTIONAL",
                        i + 1, lane.root_op.label(), a_r, b_r, lane.prime);
                    println!("  [Operation falls into exceptional set — aborting trace]");
                    return;
                }
            }
        }

        println!("  Intermediate state: {:?}", intermediate);

        println!("\n─ Phase 3: Unary Post-Processing (All-SQR Matrix) ─");
        let mut final_residues = Vec::new();
        for (i, lane) in self.topology.lanes.iter().enumerate() {
            let v = intermediate[i];
            match lane.post_proc.apply(v, primes[i]) {
                Some(r) => {
                    println!("  Lane {}: {}({}) mod {} = {}",
                        i + 1, lane.post_proc.label(), v, primes[i], r);
                    final_residues.push(r);
                }
                None => {
                    println!("  Lane {}: exceptional state in post-processor", i + 1);
                    return;
                }
            }
        }
        println!("  Final residue tuple: {:?}", final_residues);

        println!("\n─ Phase 4: Garner CRT Reconstruction ─");
        let garner = garner_reconstruct(&final_residues, &self.topology.garner);
        println!("  Mixed-radix coefficients: {:?}", garner.mixed_radix_coeffs);
        println!("  Modular multiplications: {} (= k*(k-1)/2 = {})",
            garner.multiplication_count,
            self.topology.garner_multiplication_count());
        println!("  Result x ∈ Z_{}: {}", garner.modulus, garner.value);

        // Diagnostic confirmation
        println!("\n─ Diagnostic Confirmation ─");
        let all_match = final_residues.iter().zip(primes.iter()).all(|(&r, &p)| {
            garner.value % p == r
        });
        for (&r, &p) in final_residues.iter().zip(primes.iter()) {
            println!("  {} mod {} = {} (expected {})", garner.value, p, garner.value % p, r);
        }
        println!("  ✓ All residues confirmed: {}", all_match);
        println!("\n  ⊛ {} ⊛ {} = {}", a_int, b_int, garner.value);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::{cram_s4_champion, cram_s6_champion, cram_s4_plus};

    fn s4_engine() -> CramEngine { CramEngine::new(cram_s4_champion()) }
    fn s6_engine() -> CramEngine { CramEngine::new(cram_s6_champion()) }

    // ── Canonical paper result: 17 ⊛_S4 23 = 165 ─────────────────────────────

    #[test]
    fn canonical_paper_result_17_op_23_is_165() {
        // THE central verification of the entire implementation.
        // From the paper's complete step-by-step numerical trace.
        let engine = s4_engine();
        let result = engine.execute(17, 23).expect("17 ⊛_S4 23 must be valid");
        assert_eq!(result, 165,
            "Paper canonical: 17 ⊛_{{S4}} 23 = 165; got {}", result);
    }

    // ── Phase-by-phase intermediate state verification ────────────────────────

    #[test]
    fn phase1_decomposition_17_23() {
        let engine = s4_engine();
        let a = engine.decompose(17);
        let b = engine.decompose(23);
        // Paper Phase 1: A=17 → (1,2,2,3), B=23 → (1,2,3,2)
        assert_eq!(a.residues, vec![1, 2, 2, 3]);
        assert_eq!(b.residues, vec![1, 2, 3, 2]);
    }

    #[test]
    fn phase2_root_operator_intermediate() {
        // After root operators: (MUL→1, SUB→0, ADD→0, DIV→5)
        let engine = s4_engine();
        let a = engine.decompose(17);
        let b = engine.decompose(23);
        let primes = engine.topology.primes();
        let intermediates: Vec<i128> = engine.topology.lanes.iter().enumerate()
            .map(|(i, lane)| lane.root_op.apply(a.residues[i], b.residues[i], primes[i]).unwrap())
            .collect();
        assert_eq!(intermediates, vec![1, 0, 0, 5],
            "Phase 2 intermediate must be (1,0,0,5)");
    }

    #[test]
    fn phase3_all_sqr_post_processing() {
        // After All-SQR: (1²=1, 0²=0, 0²=0, 5²=25≡4) → (1,0,0,4)
        let phase2 = vec![1, 0, 0, 5];
        let primes = vec![2, 3, 5, 7];
        let post_applied: Vec<i128> = phase2.iter().zip(primes.iter())
            .map(|(&v, &p)| crate::arith::mod_square(v, p))
            .collect();
        assert_eq!(post_applied, vec![1, 0, 0, 4],
            "Phase 3 All-SQR must produce (1,0,0,4)");
    }

    // ── Theorem 1: Lazy == Eager on a 5-step chain ────────────────────────────

    #[test]
    fn theorem1_lazy_equals_eager_s4() {
        let engine = s4_engine();
        // Build a valid input chain (avoiding exceptional sets on S4)
        let additional_bs = vec![5i128, 9, 13, 17];
        let lazy = engine.execute_chain_lazy(3, 7, &additional_bs);
        let eager = engine.execute_chain_traditional(3, 7, &additional_bs);
        // Both should succeed (or both fail at the same point)
        match (lazy, eager) {
            (Ok(l), Ok(e)) => assert_eq!(l, e,
                "Theorem 1: lazy and eager must produce identical output"),
            (Err(_), Err(_)) => { /* Both hit the same exceptional set — acceptable */ }
            _ => panic!("Lazy and eager diverged — Theorem 1 violated!"),
        }
    }

    #[test]
    fn theorem1_lazy_equals_eager_s6() {
        let engine = s6_engine();
        let additional_bs = vec![100i128, 200, 300];
        let lazy  = engine.execute_chain_lazy(11, 23, &additional_bs);
        let eager = engine.execute_chain_traditional(11, 23, &additional_bs);
        match (lazy, eager) {
            (Ok(l), Ok(e)) => assert_eq!(l, e, "S6 Theorem 1 violation"),
            (Err(_), Err(_)) => {}
            _ => panic!("S6 lazy/eager diverged!"),
        }
    }

    // ── Exceptional set generation ────────────────────────────────────────────

    #[test]
    fn exceptional_set_is_detected() {
        // Force a DIV by zero: b ≡ 0 mod 7 with a≠0 mod 7.
        // B=7 means b_4 = 7 mod 7 = 0 → DIV lane fails.
        let engine = s4_engine();
        let result = engine.execute(1, 7);
        assert!(result.is_err(), "B=7 must trigger exceptional set in Lane 4 (DIV mod 7)");
        if let Err(CramError::ExceptionalSet { lane_index, .. }) = result {
            assert_eq!(lane_index, 3, "Failure must be in Lane 4 (index 3)");
        }
    }

    // ── Theorem 3: Empirical validity matches theoretical fraction ────────────

    #[test]
    fn theorem3_empirical_validity_s4() {
        // CRAM-S4: theoretical validity = 6/7 ≈ 85.7143%
        // Sample 210 operations (one full Z_210 cycle)
        let engine = s4_engine();
        let (valid, total) = engine.empirical_validity(210);
        let empirical = valid as f64 / total as f64;
        let theoretical = 6.0 / 7.0;
        let error = (empirical - theoretical).abs();
        assert!(
            error < 0.02,
            "Empirical validity {:.4} should be close to theoretical {:.4}", empirical, theoretical
        );
    }

    // ── Residue tuple consistency ─────────────────────────────────────────────

    #[test]
    fn residue_native_execute_produces_valid_tuple() {
        let engine = s4_engine();
        let a = engine.decompose(17);
        let b = engine.decompose(23);
        let result = engine.execute_residue(&a, &b).expect("17 ⊛ 23 must be valid");
        // Verify the tuple reconstructs to 165
        let scalar = result.reconstruct(&engine.topology.garner);
        assert_eq!(scalar, 165);
    }

    // ── Non-commutativity check ───────────────────────────────────────────────

    #[test]
    fn cram_s4_is_not_commutative() {
        // CRAM generates partial quasigroups that are generally non-commutative.
        // While some (A,B) pairs may commute by coincidence, the general case must not.
        let engine = s4_engine();
        let mut found_non_commutative = false;
        for a in 1i128..20 {
            for b in 1i128..20 {
                let ab = engine.execute(a, b);
                let ba = engine.execute(b, a);
                if let (Ok(ab_val), Ok(ba_val)) = (ab, ba) {
                    if ab_val != ba_val {
                        found_non_commutative = true;
                        break;
                    }
                }
            }
            if found_non_commutative { break; }
        }
        assert!(found_non_commutative,
            "CRAM-S4 must exhibit non-commutativity for at least some inputs");
    }

    // ── Non-associativity check ───────────────────────────────────────────────

    #[test]
    fn cram_s4_is_not_associative() {
        // The paper states CRAM operations are associativity-false partial quasigroups.
        // Verify F(F(a,b),c) ≠ F(a,F(b,c)) for at least one valid triple.
        let engine = s4_engine();
        let mut found_non_assoc = false;
        'outer: for a in 1i128..15 {
            for b in 1i128..15 {
                for c in 1i128..15 {
                    let lhs = engine.execute(a, b).and_then(|ab| engine.execute(ab, c));
                    let rhs = engine.execute(b, c).and_then(|bc| engine.execute(a, bc));
                    if let (Ok(l), Ok(r)) = (lhs, rhs) {
                        if l != r {
                            found_non_assoc = true;
                            break 'outer;
                        }
                    }
                }
            }
        }
        assert!(found_non_assoc,
            "CRAM-S4 must exhibit non-associativity for some valid triple (a,b,c)");
    }
}
