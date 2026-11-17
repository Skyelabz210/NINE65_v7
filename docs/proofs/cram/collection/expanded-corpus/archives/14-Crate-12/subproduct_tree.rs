/// subproduct_tree.rs — Sub-quadratic CRT via the Subproduct Tree
///
/// ── Motivation ───────────────────────────────────────────────────────────────
///
/// Garner's algorithm reconstructs x from residues in exactly k*(k-1)/2
/// sequential modular multiplications (Theorem 4).  For CRAM-S4 that is 6,
/// for CRAM-S6 it is 15.  The sequential dependency chain prevents parallelism.
///
/// For large-k topologies the cost is quadratic:
///   k=16  → 120 muls    k=32  → 496 muls    k=64  → 2016 muls
///
/// The Subproduct Tree achieves reconstruction in exactly k-1 CRT merge
/// operations, each requiring exactly one modular multiplication (precomputed
/// inverse eliminates runtime mod_inverse calls):
///   k=16  → 15 muls     k=32  → 31 muls     k=64  → 63 muls
///
/// Reduction ratios: k=6 → 3.0×, k=16 → 8.0×, k=64 → 32.0×
///
/// ── Tree Structure ───────────────────────────────────────────────────────────
///
/// For primes [p_0, p_1, p_2, p_3, p_4, p_5] (CRAM-S6):
///
///   levels[0]:  [2,   3,  5,   7,  11, 13]   ← leaves (individual primes)
///   levels[1]:  [6,      35,      143    ]    ← pairwise products + odd carry
///   levels[2]:  [210,         143        ]    ← (6*35=210, 143 carried)
///   levels[3]:  [30030                   ]    ← root N = ∏ p_i
///
/// Odd-k groups at each level are carried to the next level unchanged,
/// preserving the coprimality invariant throughout the tree.
///
/// ── Two Dual Operations ──────────────────────────────────────────────────────
///
/// RECONSTRUCT (bottom-up CRT merge):
///   Start: k (residue, prime) pairs
///   Each level: merge adjacent pairs via the 2-prime CRT formula
///     x = r_L + m_L × t   where   t = (r_R − r_L) × m_L⁻¹ mod m_R
///   End: one (x, N) pair — x is the unique integer in Z_N
///   Cost: k−1 modular multiplications (all precomputed)
///
/// DECOMPOSE (top-down remainder descent):
///   Start: x at root
///   Each level: split each node value v (known mod parent product) into
///     v mod left_child_product  and  v mod right_child_product
///   End: k residues, one per leaf prime
///   Cost: k−1 modular reductions (plain %)
///
/// Both operations are exactly inverse to each other — verified by
/// full Z_210 round-trip and Z_30030 sampled cross-check.
///
/// ── Crossover with Garner ────────────────────────────────────────────────────
///
/// SPT uses fewer modular multiplications for ALL k ≥ 3.  However, at low k
/// (< ~12) Garner's multiplications are on single-precision values while SPT
/// merges at higher tree levels involve multi-precision products.  For i128
/// (all current CRAM topologies) both are O(1) per op, so SPT wins outright.
/// For CRTBigInt topologies where primes span hundreds of bits, the polynomial
/// multiplier cost makes SPT's k*log²(k) vs Garner's k² advantage decisive.
///
/// ── Compatibility ────────────────────────────────────────────────────────────
///
/// `SptConstants` mirrors the `GarnerConstants` API.  Both are constructed from
/// the same prime slice and expose `reconstruct` / `decompose` / `verify_roundtrip`.
/// They can be used interchangeably; all results are algebraically identical.

use crate::arith::{canonical, mod_inverse, mod_mul};

// ─── Result Type ─────────────────────────────────────────────────────────────

/// Full result of an SPT reconstruction, carrying value plus cost metrics
/// for benchmarking against the Garner O(k²) baseline.
#[derive(Debug, Clone)]
pub struct SptResult {
    /// The reconstructed integer x ∈ Z_N.
    pub value: i128,
    /// The aggregate modulus N = p_0 × … × p_{k−1}.
    pub modulus: i128,
    /// Number of CRT merge operations performed.
    /// Always equals k−1 regardless of k or input values.
    pub merge_count: usize,
    /// Number of modular multiplications executed.
    /// Always equals k−1 (one per merge, using precomputed inverses).
    /// Compare to Garner's k*(k-1)/2 to see the reduction ratio.
    pub mod_mul_count: usize,
}

// ─── Subproduct Tree Constants ────────────────────────────────────────────────

/// Precomputed subproduct tree for a fixed prime set.
///
/// Mirrors the `GarnerConstants` API surface.  Construct once per topology;
/// reuse across all reconstruction and decomposition calls.
///
/// Memory: O(k) — all tree levels together hold exactly 2k−1 values.
#[derive(Debug, Clone)]
pub struct SptConstants {
    /// The full binary product tree.
    ///
    /// `levels[0]` = leaves (the individual primes).
    /// `levels[depth]` = root ([N]).
    /// `levels[l][j]` = product of all primes in the j-th subtree at level l.
    ///
    /// Odd-k groups at any level are carried forward unchanged:
    ///   levels[l] has len ceil(levels[l-1].len() / 2).
    levels: Vec<Vec<i128>>,

    /// Precomputed CRT inverses for bottom-up reconstruction.
    ///
    /// `crt_inv[l][j]` = `levels[l][2j]⁻¹ mod levels[l][2j+1]`
    ///
    /// These eliminate runtime `mod_inverse` calls during reconstruction,
    /// reducing each merge to a single `mod_mul` call.
    crt_inv: Vec<Vec<i128>>,

    /// Number of primes k.
    pub k: usize,
    /// Aggregate modulus N = ∏ p_i.
    pub modulus: i128,
    /// Depth of the tree: ceil(log₂(k)).
    pub depth: usize,
}

impl SptConstants {
    /// Build the subproduct tree and precompute all CRT inverses.
    ///
    /// This is a one-time O(k log k) setup cost, paid before the first
    /// reconstruction.  After precomputation, each `reconstruct` call costs
    /// exactly k−1 modular multiplications.
    ///
    /// Panics if any prime product overflows i128 — use `CRTBigInt` for
    /// topologies where N exceeds 2^127.  All current CRAM topologies
    /// (N ≤ 30030 for S6) are well within i128 range.
    pub fn precompute(primes: &[i128]) -> Self {
        let k = primes.len();
        assert!(k >= 2,
            "SptConstants requires at least 2 primes (got {})", k);

        // ── Build levels bottom-up ────────────────────────────────────────────
        // levels[0] = individual primes (leaves).
        // At each subsequent level, adjacent pairs are multiplied together;
        // if the count is odd the last element carries forward unchanged.
        let mut levels: Vec<Vec<i128>> = vec![primes.to_vec()];
        let mut current = primes.to_vec();

        while current.len() > 1 {
            let mut next = Vec::new();
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    let product = current[i]
                        .checked_mul(current[i + 1])
                        .unwrap_or_else(|| panic!(
                            "Prime product overflow i128 at level {}: {}×{} \
                             — use CRTBigInt for topologies where N > 2^127",
                            levels.len(), current[i], current[i + 1]
                        ));
                    next.push(product);
                    i += 2;
                } else {
                    // Odd carry: passes to next level unchanged.
                    next.push(current[i]);
                    i += 1;
                }
            }
            levels.push(next.clone());
            current = next;
        }

        let depth = levels.len() - 1;
        let modulus = levels[depth][0];

        // ── Precompute CRT inverses for each merge pair ───────────────────────
        // For level l, merge pair j:
        //   m_left  = levels[l][2j]
        //   m_right = levels[l][2j+1]
        //   inv     = m_left⁻¹ mod m_right
        //
        // These are the only modular inverses needed during reconstruction.
        // They are precomputed once and reused on every call.
        let mut crt_inv: Vec<Vec<i128>> = Vec::with_capacity(depth);
        for l in 0..depth {
            let level = &levels[l];
            let mut row = Vec::new();
            let mut j = 0;
            while j + 1 < level.len() {
                let m_left  = level[j];
                let m_right = level[j + 1];
                let inv = mod_inverse(m_left, m_right)
                    .unwrap_or_else(|| panic!(
                        "SptConstants: non-coprime products at level {} pair {}: \
                         gcd({},{}) > 1 — primes must be pairwise coprime",
                        l, j, m_left, m_right
                    ));
                row.push(inv);
                j += 2;
            }
            crt_inv.push(row);
        }

        SptConstants { levels, crt_inv, k, modulus, depth }
    }

    // ── Reconstruction (bottom-up CRT merge) ─────────────────────────────────

    /// Reconstruct an integer from its residue tuple.
    ///
    /// Executes exactly k−1 CRT merges and k−1 modular multiplications
    /// (one per merge, using the precomputed inverses).  Returns a full
    /// `SptResult` with value, modulus, and cost counters.
    ///
    /// The 2-prime CRT merge formula:
    ///
    ///   Given x ≡ r_L (mod m_L) and x ≡ r_R (mod m_R):
    ///     t = (r_R − r_L) · m_L⁻¹  mod m_R          (one mod_mul)
    ///     x = r_L + m_L · t          mod m_L·m_R     (exact integer mul)
    pub fn reconstruct(&self, residues: &[i128]) -> SptResult {
        assert_eq!(
            residues.len(), self.k,
            "SPT reconstruct: got {} residues, expected {}", residues.len(), self.k
        );

        // Initialise working state: (residue mod prime, prime) for each lane.
        let mut current: Vec<(i128, i128)> = residues.iter()
            .zip(self.levels[0].iter())
            .map(|(&r, &p)| (canonical(r, p), p))
            .collect();

        let mut merge_count   = 0usize;
        let mut mod_mul_count = 0usize;

        // Ascend the tree, merging pairs at each level.
        for l in 0..self.depth {
            let mut next      = Vec::with_capacity((current.len() + 1) / 2);
            let mut pair_idx  = 0usize;
            let mut i         = 0usize;

            while i < current.len() {
                if i + 1 < current.len() {
                    let (r_l, m_l) = current[i];
                    let (r_r, m_r) = current[i + 1];

                    // t = (r_R − r_L) · inv mod m_R
                    let diff = canonical(r_r - r_l, m_r);
                    let inv  = self.crt_inv[l][pair_idx];
                    let t    = mod_mul(diff, inv, m_r);
                    mod_mul_count += 1;

                    // x = r_L + m_L · t   (exact, then canonical into Z_{m_L·m_R})
                    let combined_m = m_l * m_r; // checked_mul in precompute; safe here
                    let x = canonical(r_l + m_l * t, combined_m);

                    next.push((x, combined_m));
                    merge_count += 1;
                    pair_idx    += 1;
                    i           += 2;
                } else {
                    // Odd carry: passes to the next level without a merge.
                    next.push(current[i]);
                    i += 1;
                }
            }

            current = next;
        }

        // After ascending all levels, exactly one (x, N) pair remains.
        debug_assert_eq!(current.len(), 1,
            "SPT reconstruct: expected 1 final pair, got {}", current.len());

        SptResult {
            value:         current[0].0,
            modulus:       current[0].1,
            merge_count,
            mod_mul_count,
        }
    }

    /// Convenience wrapper — reconstruct and return only the scalar value.
    pub fn reconstruct_scalar(&self, residues: &[i128]) -> i128 {
        self.reconstruct(residues).value
    }

    // ── Decomposition (top-down remainder descent) ────────────────────────────

    /// Decompose a scalar integer into its residue tuple.
    ///
    /// Descends the subproduct tree from root to leaves, splitting each node's
    /// value into its left and right children via plain modular reduction (%).
    ///
    /// Cost: k−1 modular reductions (one per tree edge), all exact.
    ///
    /// Correctness: decompose(reconstruct(r)) == r for all valid residue tuples.
    /// This is the formal check of the CRT bijection underpinning Theorem 1.
    pub fn decompose(&self, x: i128) -> Vec<i128> {
        // Start at the root: x reduced into Z_N.
        let mut current = vec![canonical(x, self.modulus)];

        // Descend level-by-level from root to leaves.
        // At each step, each node at the current level spawns its children.
        for lev in (0..self.depth).rev() {
            let child_level = &self.levels[lev];
            let mut next = Vec::with_capacity(child_level.len());

            for (parent_idx, &parent_val) in current.iter().enumerate() {
                let left_idx  = 2 * parent_idx;
                let right_idx = 2 * parent_idx + 1;

                // Left child always exists.
                next.push(parent_val % child_level[left_idx]);

                // Right child may be absent (odd carry at this level).
                if right_idx < child_level.len() {
                    next.push(parent_val % child_level[right_idx]);
                }
            }

            current = next;
        }

        // After reaching level 0, current = [x mod p_0, ..., x mod p_{k-1}].
        debug_assert_eq!(current.len(), self.k,
            "SPT decompose: expected {} residues, got {}", self.k, current.len());

        current
    }

    // ── Round-trip verification ───────────────────────────────────────────────

    /// Verify the CRT bijection: decompose ∘ reconstruct = identity in Z_N.
    ///
    /// This is the formal check of the bijection that underlies Theorem 1
    /// (Correctness of Residue-Native Computing).
    pub fn verify_roundtrip(&self, x: i128) -> bool {
        let residues = self.decompose(x);
        let result   = self.reconstruct_scalar(&residues);
        result == canonical(x, self.modulus)
    }

    // ── Diagnostics ───────────────────────────────────────────────────────────

    /// Print the full tree structure for inspection and documentation.
    pub fn print_tree(&self) {
        println!("  SubproductTree (k={}, N={}, depth={}):", self.k, self.modulus, self.depth);
        for (l, level) in self.levels.iter().enumerate() {
            let label = if l == 0 { " (primes)" } else if l == self.depth { " (root N)" } else { "" };
            println!("    levels[{}]{}: {:?}", l, label, level);
        }
        println!("  CRT inverses (precomputed):");
        for (l, row) in self.crt_inv.iter().enumerate() {
            println!("    crt_inv[{}]: {:?}", l, row);
        }
    }

    /// Report the theoretical multiplication savings over Garner.
    pub fn garner_reduction(&self) -> (usize, usize, f64) {
        let garner_muls = self.k * (self.k - 1) / 2;
        let spt_muls    = self.k - 1;
        let ratio       = garner_muls as f64 / spt_muls as f64;
        (garner_muls, spt_muls, ratio)
    }
}

// ─── Standalone Convenience Functions ────────────────────────────────────────

/// Reconstruct a scalar from residues using SPT.
/// Equivalent to `SptConstants::precompute(primes).reconstruct_scalar(residues)`.
/// For repeated use, prefer precomputing `SptConstants` directly.
pub fn spt_reconstruct(residues: &[i128], primes: &[i128]) -> i128 {
    SptConstants::precompute(primes).reconstruct_scalar(residues)
}

/// Decompose a scalar into residues using SPT.
/// Equivalent to `SptConstants::precompute(primes).decompose(x)`.
pub fn spt_decompose(x: i128, primes: &[i128]) -> Vec<i128> {
    SptConstants::precompute(primes).decompose(x)
}

/// Cross-validate that SPT and Garner produce identical results for all
/// residue tuples corresponding to integers 0..n over the given primes.
/// Returns (total_checked, mismatches) — mismatches must be 0.
pub fn cross_validate_spt_garner(
    primes:    &[i128],
    spt:       &SptConstants,
    garner:    &crate::garner::GarnerConstants,
    sample_n:  i128,
) -> (usize, usize) {
    let modulus: i128 = primes.iter().product();
    let step = if sample_n >= modulus { 1 } else { modulus / sample_n };
    let mut checked    = 0usize;
    let mut mismatches = 0usize;

    for x in (0..modulus).step_by(step as usize) {
        let residues     = spt.decompose(x);
        let spt_val      = spt.reconstruct_scalar(&residues);
        let garner_val   = crate::garner::reconstruct(&residues, garner);
        if spt_val != garner_val {
            mismatches += 1;
        }
        checked += 1;
    }

    (checked, mismatches)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::garner::{GarnerConstants, garner_reconstruct, decompose as garner_decompose};

    fn s3_primes() -> Vec<i128> { vec![2, 3, 5] }
    fn s4_primes() -> Vec<i128> { vec![2, 3, 5, 7] }
    fn s6_primes() -> Vec<i128> { vec![2, 3, 5, 7, 11, 13] }

    // ── Tree structure correctness ────────────────────────────────────────────

    #[test]
    fn s4_tree_levels_correct() {
        // levels[0]=[2,3,5,7], levels[1]=[6,35], levels[2]=[210]
        let spt = SptConstants::precompute(&s4_primes());
        assert_eq!(spt.levels[0], vec![2, 3, 5, 7]);
        assert_eq!(spt.levels[1], vec![6, 35]);
        assert_eq!(spt.levels[2], vec![210]);
        assert_eq!(spt.modulus, 210);
        assert_eq!(spt.depth, 2);
    }

    #[test]
    fn s6_tree_levels_correct() {
        // k=6 with odd-carry produces 4 levels
        let spt = SptConstants::precompute(&s6_primes());
        assert_eq!(spt.levels[0], vec![2, 3, 5, 7, 11, 13]);
        assert_eq!(spt.levels[1], vec![6, 35, 143]);   // 2*3=6, 5*7=35, 11*13=143
        assert_eq!(spt.levels[2], vec![210, 143]);      // 6*35=210, 143 carried
        assert_eq!(spt.levels[3], vec![30030]);         // 210*143=30030
        assert_eq!(spt.modulus, 30030);
        assert_eq!(spt.depth, 3);
    }

    #[test]
    fn s3_tree_levels_odd_carry() {
        // k=3 (odd): levels[0]=[2,3,5], levels[1]=[6,5], levels[2]=[30]
        let spt = SptConstants::precompute(&s3_primes());
        assert_eq!(spt.levels[0], vec![2, 3, 5]);
        assert_eq!(spt.levels[1], vec![6, 5]);  // 2*3=6, 5 carried
        assert_eq!(spt.levels[2], vec![30]);    // 6*5=30
        assert_eq!(spt.modulus, 30);
    }

    // ── CRT inverse precomputation ────────────────────────────────────────────

    #[test]
    fn s4_crt_inv_correct() {
        // crt_inv[0][0] = 2^{-1} mod 3 = 2
        // crt_inv[0][1] = 5^{-1} mod 7 = 3
        // crt_inv[1][0] = 6^{-1} mod 35 = 6  (because 6*6=36≡1 mod 35)
        let spt = SptConstants::precompute(&s4_primes());
        assert_eq!(spt.crt_inv[0], vec![2, 3]);
        assert_eq!(spt.crt_inv[1], vec![6]);
    }

    #[test]
    fn crt_inv_correctness_invariant() {
        // For every precomputed inverse: m_left * inv ≡ 1 (mod m_right)
        let spt = SptConstants::precompute(&s6_primes());
        for (l, row) in spt.crt_inv.iter().enumerate() {
            for (j, &inv) in row.iter().enumerate() {
                let m_left  = spt.levels[l][2 * j];
                let m_right = spt.levels[l][2 * j + 1];
                let product = crate::arith::mod_mul(m_left, inv, m_right);
                assert_eq!(product, 1,
                    "Inverse check failed: level={} pair={}: {}×{}≢1 mod {}",
                    l, j, m_left, inv, m_right);
            }
        }
    }

    // ── Paper canonical result: 17 ⊛_S4 23 = 165 ─────────────────────────────

    #[test]
    fn paper_trace_reconstruct_165() {
        let spt = SptConstants::precompute(&s4_primes());
        let result = spt.reconstruct(&[1, 0, 0, 4]);
        assert_eq!(result.value, 165,
            "SPT: paper canonical result (1,0,0,4) must reconstruct to 165");
    }

    #[test]
    fn paper_trace_merge_count_is_k_minus_1() {
        let spt = SptConstants::precompute(&s4_primes());
        let result = spt.reconstruct(&[1, 0, 0, 4]);
        // k=4: exactly k-1 = 3 merges (vs Garner's k*(k-1)/2 = 6)
        assert_eq!(result.merge_count, 3,
            "SPT k=4 must use exactly k-1=3 merges");
        assert_eq!(result.mod_mul_count, 3,
            "SPT k=4 must use exactly k-1=3 modular multiplications");
    }

    #[test]
    fn s6_merge_count_is_k_minus_1() {
        let spt = SptConstants::precompute(&s6_primes());
        let result = spt.reconstruct(&[0, 1, 2, 3, 4, 5]);
        // k=6: exactly k-1 = 5 merges (vs Garner's k*(k-1)/2 = 15)
        assert_eq!(result.merge_count, 5,
            "SPT k=6 must use exactly k-1=5 merges");
        assert_eq!(result.mod_mul_count, 5,
            "SPT k=6 must use exactly k-1=5 modular multiplications");
    }

    #[test]
    fn s3_odd_k_merge_count() {
        // k=3 (odd): k-1 = 2 merges
        let spt = SptConstants::precompute(&s3_primes());
        let result = spt.reconstruct(&[1, 2, 2]); // 17 over {2,3,5}
        assert_eq!(result.value, 17);
        assert_eq!(result.merge_count, 2,
            "SPT k=3 must use exactly k-1=2 merges");
    }

    // ── Decomposition correctness ─────────────────────────────────────────────

    #[test]
    fn decompose_17_s4() {
        // Paper Phase 1: A=17 → (1, 2, 2, 3) over {2,3,5,7}
        let spt = SptConstants::precompute(&s4_primes());
        assert_eq!(spt.decompose(17), vec![1, 2, 2, 3]);
    }

    #[test]
    fn decompose_23_s4() {
        // Paper Phase 1: B=23 → (1, 2, 3, 2) over {2,3,5,7}
        let spt = SptConstants::precompute(&s4_primes());
        assert_eq!(spt.decompose(23), vec![1, 2, 3, 2]);
    }

    #[test]
    fn decompose_matches_garner_decompose() {
        // SPT decompose must be identical to the CRT bijection used by Garner.
        let spt = SptConstants::precompute(&s6_primes());
        let primes = s6_primes();
        for x in (0..30030i128).step_by(13) {
            let spt_res    = spt.decompose(x);
            let garner_res = garner_decompose(x, &primes);
            assert_eq!(spt_res, garner_res,
                "SPT and Garner decompose disagree for x={}", x);
        }
    }

    // ── SPT ↔ Garner identity (the critical cross-validation) ────────────────

    #[test]
    fn spt_matches_garner_full_z210() {
        // For every integer in Z_210: SPT reconstruct = Garner reconstruct.
        let primes  = s4_primes();
        let spt     = SptConstants::precompute(&primes);
        let garner  = GarnerConstants::precompute(&primes);
        for x in 0..210i128 {
            let residues = spt.decompose(x);
            let spt_val    = spt.reconstruct_scalar(&residues);
            let garner_val = crate::garner::reconstruct(&residues, &garner);
            assert_eq!(spt_val, garner_val,
                "SPT ≠ Garner for x={} residues={:?}", x, residues);
        }
    }

    #[test]
    fn spt_matches_garner_s6_sampled() {
        // Sampled cross-check over Z_30030 (every 7th value = 4290 checks).
        let primes = s6_primes();
        let spt    = SptConstants::precompute(&primes);
        let garner = GarnerConstants::precompute(&primes);
        let (checked, mismatches) = cross_validate_spt_garner(
            &primes, &spt, &garner, 4290
        );
        assert_eq!(mismatches, 0,
            "SPT ≠ Garner in {} of {} checks over Z_30030", mismatches, checked);
    }

    // ── CRT round-trip (Theorem 1 foundation) ─────────────────────────────────

    #[test]
    fn roundtrip_s4_all_residues() {
        // Full Z_210 round-trip: every integer must survive decompose/reconstruct.
        let spt = SptConstants::precompute(&s4_primes());
        for x in 0..210i128 {
            assert!(spt.verify_roundtrip(x),
                "SPT round-trip failed for x={}", x);
        }
    }

    #[test]
    fn roundtrip_s6_sampled() {
        // Every 30th value of Z_30030 (1001 checks).
        let spt = SptConstants::precompute(&s6_primes());
        for x in (0..30030i128).step_by(30) {
            assert!(spt.verify_roundtrip(x),
                "SPT S6 round-trip failed for x={}", x);
        }
    }

    #[test]
    fn roundtrip_s3_odd_k_all_residues() {
        // Full Z_30 round-trip with odd k=3.
        let spt = SptConstants::precompute(&s3_primes());
        for x in 0..30i128 {
            assert!(spt.verify_roundtrip(x),
                "SPT S3 round-trip failed for x={}", x);
        }
    }

    // ── Boundary and edge cases ───────────────────────────────────────────────

    #[test]
    fn reconstruct_zero() {
        let spt = SptConstants::precompute(&s4_primes());
        assert_eq!(spt.reconstruct_scalar(&[0, 0, 0, 0]), 0);
    }

    #[test]
    fn reconstruct_n_minus_1() {
        // x = 209 = N−1 over S4: residues (1,2,4,6) over (2,3,5,7)
        let spt = SptConstants::precompute(&s4_primes());
        let residues = spt.decompose(209);
        assert_eq!(residues, vec![1, 2, 4, 6]);
        assert_eq!(spt.reconstruct_scalar(&residues), 209);
    }

    // ── Reduction ratio verification ──────────────────────────────────────────

    #[test]
    fn garner_reduction_s4() {
        let spt = SptConstants::precompute(&s4_primes());
        let (garner, spt_m, ratio) = spt.garner_reduction();
        assert_eq!(garner, 6);   // k*(k-1)/2
        assert_eq!(spt_m,  3);   // k-1
        // ratio ≈ 2.0×
        assert!((ratio - 2.0).abs() < 1e-10,
            "S4 reduction ratio must be 2.0×, got {:.4}", ratio);
    }

    #[test]
    fn garner_reduction_s6() {
        let spt = SptConstants::precompute(&s6_primes());
        let (garner, spt_m, ratio) = spt.garner_reduction();
        assert_eq!(garner, 15);  // k*(k-1)/2
        assert_eq!(spt_m,   5);  // k-1
        // ratio = 3.0×
        assert!((ratio - 3.0).abs() < 1e-10,
            "S6 reduction ratio must be 3.0×, got {:.4}", ratio);
    }

    // ── Larger artificial topologies — scaling validation ─────────────────────

    #[test]
    fn larger_topology_k8_round_trip() {
        // k=8 using first 8 primes: {2,3,5,7,11,13,17,19}
        let primes: Vec<i128> = vec![2, 3, 5, 7, 11, 13, 17, 19];
        let spt    = SptConstants::precompute(&primes);
        let garner = GarnerConstants::precompute(&primes);
        let n: i128 = primes.iter().product(); // = 9699690

        // merge count must be k-1 = 7
        let result = spt.reconstruct(&spt.decompose(12345));
        assert_eq!(result.merge_count,   7, "k=8: expected 7 merges");
        assert_eq!(result.mod_mul_count, 7, "k=8: expected 7 mod_muls");

        // Spot check 500 values
        for x in (0..n).step_by((n / 500) as usize) {
            let res = spt.decompose(x);
            let sv  = spt.reconstruct_scalar(&res);
            let gv  = crate::garner::reconstruct(&res, &garner);
            assert_eq!(sv, gv, "k=8 SPT ≠ Garner for x={}", x);
        }
    }
}
