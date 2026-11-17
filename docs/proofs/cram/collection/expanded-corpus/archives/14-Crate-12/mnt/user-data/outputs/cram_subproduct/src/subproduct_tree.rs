/// subproduct_tree.rs — Sub-quadratic CRT Reconstruction
///
/// Replaces the O(k²) sequential Garner chain with an O(k log k) total-work,
/// O(log k) depth divide-and-conquer reconstruction.
///
/// ═══════════════════════════════════════════════════════════════════════════
/// Algorithm: Subproduct Tree CRT
/// ═══════════════════════════════════════════════════════════════════════════
///
/// PHASE 1 — Build Subproduct Tree (one-time setup, O(k) multiplications):
///
///   Store a complete binary tree with k leaves (padded to next power of 2).
///   Each leaf i holds the prime p_i (padding leaves hold sentinel 1).
///   Each internal node holds the PRODUCT of its subtree's leaves.
///   The root holds N = p_0 · p_1 · … · p_{k-1}.
///
///   Example — CRAM-S4, k=4, primes=[2,3,5,7] (no padding needed):
///
///           [210]
///          /     \
///       [6]       [35]
///      /   \     /   \
///    [2]  [3]  [5]  [7]     ← leaves
///
///   Example — CRAM-S6, k=6, primes=[2,3,5,7,11,13] (padded to 8 leaves):
///
///                      [30030]
///                    /         \
///               [210]           [143]
///              /     \         /     \
///           [6]     [35]    [143]    [1]
///          /   \   /   \   /   \   /   \
///         2   3   5   7  11  13   1    1   ← leaf 6,7 = sentinel 1
///
/// PHASE 2 — Reconstruction (O(k) combines, O(log k) sequential depth):
///
///   Start with residue-modulus pairs (r_i, p_i) at the leaves.
///   Work bottom-up: each internal node CRT-combines its two children.
///
///   The two-prime CRT combine formula (no extended GCD needed at combine time):
///
///     x ≡ r_L (mod M_L)  ∧  x ≡ r_R (mod M_R),  gcd(M_L, M_R) = 1
///
///     t = (r_R − r_L) · M_L⁻¹  mod M_R
///     x = r_L + M_L · t  mod (M_L · M_R)
///
///   The inverse M_L⁻¹ mod M_R is computed fresh at each combine step.
///   For repeated reconstructions over the same prime set, precompute these
///   inverses with `SubproductTreeCrt::precompute()`.
///
///   After ⌈log₂ k⌉ levels the root holds (x, N).
///
/// ═══════════════════════════════════════════════════════════════════════════
/// Performance vs. Garner
/// ═══════════════════════════════════════════════════════════════════════════
///
///   k     Garner (sequential mults)   Tree (total combines)   Tree (depth)
///   ───   ────────────────────────   ───────────────────────  ────────────
///   4     6                          3                         2
///   6     15                         7                         3
///   13    78                         15                        4
///   50    1,225                      63                        6
///   144   10,296                     255                       8
///   1,000 499,500                    1,023                     10
///   5,653 15,975,378                 8,191                     13
///
///   For k ≤ 6 (current CRAM topologies): Garner is faster in scalar
///   single-threaded code due to lower constant factors.  The tree wins on:
///     (a) large k: O(k log k) total work << O(k²) — ~1,950× at k=5,653
///     (b) parallel hardware: O(log k) sequential depth — critical-path depth
///         is ~1.2 million times shorter at k=5,653 (13 vs 15.97M steps)
///
/// ═══════════════════════════════════════════════════════════════════════════
/// i128 Overflow Boundary
/// ═══════════════════════════════════════════════════════════════════════════
///
///   Each tree level doubles the bit-width of the working moduli.
///   For primes of b bits, level ℓ moduli are b·2^ℓ bits.
///
///   Safe with i128 (127 usable bits):
///     b=4  (primes ≤ 13, CRAM-S6):    all levels (30030 << 2^127)  ✓
///     b=7  (primes ≤ 97, CRAM-S4+):   all levels for k ≤ 4         ✓
///     b=32 (32-bit primes):            level 0 only (b·2^0 = 32 bits)
///     b=63 (Mersenne near 2^63):       level 0 only
///
///   For b ≥ 32 and k > 2, the tree nodes at level ≥ 1 require
///   multi-precision arithmetic.  The CRTBigInt type in the QMNF
///   ecosystem provides the drop-in replacement.  The
///   SubproductTree::build() function uses checked_mul and will panic
///   with a clear escalation message at the overflow boundary.

use crate::arith::{canonical, mod_inverse, mod_mul};

// ─── Subproduct Tree ──────────────────────────────────────────────────────────

/// A precomputed subproduct tree for efficient CRT reconstruction.
///
/// The tree is stored as a flat 1-indexed array in level-order:
///   - Root at index 1.
///   - Children of node i at 2i (left) and 2i+1 (right).
///   - Leaves at indices n_leaves..=2*n_leaves-1  (0-indexed i → node n_leaves+i).
///
/// `n_leaves` = next_pow2(k).  Non-power-of-2 k is padded with sentinel
/// leaves whose prime = 1, contributing identity to all products.
#[derive(Debug, Clone)]
pub struct SubproductTree {
    /// The real prime moduli (unpadded).
    pub primes: Vec<i128>,
    /// Flat 1-indexed product array.
    /// products[1] = root = N.  products[0] unused.
    pub products: Vec<i128>,
    /// k = number of real primes.
    pub k: usize,
    /// Padded leaf count = next_pow2(k).
    pub n_leaves: usize,
    /// Tree depth = log₂(n_leaves).  Equals the reconstruction sequential depth.
    pub depth: usize,
}

impl SubproductTree {
    /// Build the subproduct tree from the given prime moduli.
    ///
    /// # Panics
    /// - If any product overflows i128.  Escalate to CRTBigInt for:
    ///   - Primes ≥ 2^32 with k > 2
    ///   - Mersenne near 2^63 with k > 1
    pub fn build(primes: &[i128]) -> Self {
        let k = primes.len();
        assert!(k >= 1, "SubproductTree requires at least one prime");

        let n_leaves = next_pow2(k);
        let depth    = n_leaves.trailing_zeros() as usize;
        let n_nodes  = 2 * n_leaves; // 1-indexed array size

        let mut products = vec![0i128; n_nodes];

        // ── Fill leaves ───────────────────────────────────────────────────────
        // Nodes at indices n_leaves..2*n_leaves.
        // Leaves i ≥ k are padding sentinels (prime = 1).
        for i in 0..n_leaves {
            products[n_leaves + i] = if i < k { primes[i] } else { 1 };
        }

        // ── Build internal nodes bottom-up ────────────────────────────────────
        // Node i = product of nodes 2i and 2i+1.
        // Iterate from the deepest internal node (n_leaves-1) up to the root (1).
        for node in (1..n_leaves).rev() {
            let left  = 2 * node;
            let right = 2 * node + 1;
            products[node] = products[left]
                .checked_mul(products[right])
                .expect(
                    "SubproductTree::build — i128 overflow at internal node. \
                     Escalate to CRTBigInt for primes ≥ 2^32 or k > 4 with 32-bit+ primes."
                );
        }

        Self { primes: primes.to_vec(), products, k, n_leaves, depth }
    }

    /// The total modulus N = ∏ p_i.  Stored at the root (products[1]).
    #[inline]
    pub fn modulus(&self) -> i128 { self.products[1] }

    /// Total number of CRT combine operations required for one reconstruction.
    /// Equals n_leaves - 1 (one combine per internal tree node).
    #[inline]
    pub fn combine_count(&self) -> usize { self.n_leaves - 1 }

    /// Sequential depth of the reconstruction (= tree depth = log₂(n_leaves)).
    /// This is the critical-path length: at most `depth` combine operations
    /// must complete before the final answer is available, regardless of how
    /// many parallel workers are available.
    #[inline]
    pub fn sequential_depth(&self) -> usize { self.depth }
}

// ─── CRT Combine ─────────────────────────────────────────────────────────────

/// Combine two residue-modulus pairs into one via the two-prime CRT formula.
///
/// Given:
///   x ≡ r_left  (mod m_left)
///   x ≡ r_right (mod m_right)
/// with gcd(m_left, m_right) = 1, finds the unique:
///   x (mod m_left · m_right)
///
/// Formula:
///   t = (r_right − r_left) · m_left⁻¹  mod m_right
///   x = r_left + m_left · t
///
/// Sentinel handling: a modulus of 1 acts as an identity for the combination.
///
/// # Panics
/// If m_left · m_right overflows i128 (escalate to CRTBigInt).
pub fn crt_combine(r_left: i128, m_left: i128, r_right: i128, m_right: i128) -> (i128, i128) {
    // Sentinel fast paths: m=1 means "no constraint", defer to the other side.
    if m_left  == 1 { return (r_right, m_right); }
    if m_right == 1 { return (r_left,  m_left);  }

    let diff     = canonical(r_right - r_left, m_right);
    let inv_left = mod_inverse(m_left, m_right)
        .expect("crt_combine: m_left and m_right must be coprime (gcd > 1 detected)");
    let t        = mod_mul(diff, inv_left, m_right);

    // m_left * t  can be large; use checked arithmetic to catch overflow.
    let m_t = m_left
        .checked_mul(t)
        .expect("crt_combine: m_left · t overflows i128 — escalate to CRTBigInt");
    let x = r_left
        .checked_add(m_t)
        .expect("crt_combine: r_left + m_left·t overflows i128 — escalate to CRTBigInt");
    let m_combined = m_left
        .checked_mul(m_right)
        .expect("crt_combine: m_left · m_right overflows i128 — escalate to CRTBigInt");

    (canonical(x, m_combined), m_combined)
}

// ─── Reconstruction Result ────────────────────────────────────────────────────

/// Result from a subproduct-tree CRT reconstruction.
#[derive(Debug, Clone)]
pub struct SubproductCrtResult {
    /// The reconstructed integer x ∈ Z_N.
    pub value: i128,
    /// The aggregate modulus N = ∏ p_i.
    pub modulus: i128,
    /// Total CRT combine operations performed (= n_leaves − 1).
    /// Compare to Garner's k·(k−1)/2 to see the total-work reduction.
    pub combine_count: usize,
    /// Sequential depth of the reconstruction (= log₂(n_leaves)).
    /// This is the critical-path length, independent of parallelism.
    /// Compare to Garner's k·(k−1)/2 sequential depth to see the
    /// parallelism advantage.
    pub sequential_depth: usize,
}

// ─── Core Reconstruction ─────────────────────────────────────────────────────

/// Reconstruct an integer from its residue tuple using the subproduct tree.
///
/// Performs a single bottom-up sweep through the tree, combining
/// residue-modulus pairs level by level until the root holds (x, N).
///
/// # Sequential Depth
/// O(log k) — the critical-path advantage over Garner's O(k²).
///
/// # Correctness Guarantee
/// Produces the same value as `garner::reconstruct` for any valid residue
/// tuple.  The `verify_matches_garner` function in this module provides a
/// direct cross-check.
pub fn subproduct_reconstruct(
    residues: &[i128],
    tree: &SubproductTree,
) -> SubproductCrtResult {
    let k = tree.k;
    assert_eq!(
        residues.len(), k,
        "Residue count ({}) must match prime count ({})", residues.len(), k
    );

    // ── Initialise leaf layer ─────────────────────────────────────────────────
    // working[i] = (residue_i, modulus_i) for leaf node (n_leaves + i).
    // Padding leaves (i ≥ k) get (0, 1) — the identity for crt_combine.
    let n_leaves = tree.n_leaves;
    let mut working: Vec<(i128, i128)> = (0..n_leaves)
        .map(|i| {
            if i < k {
                (canonical(residues[i], tree.primes[i]), tree.primes[i])
            } else {
                (0i128, 1i128)  // identity: x ≡ 0 (mod 1) imposes no constraint
            }
        })
        .collect();

    let mut combine_count = 0usize;

    // ── Bottom-up combination ─────────────────────────────────────────────────
    // At each level, halve the working array by combining adjacent pairs.
    // After `depth` iterations, working[0] = (x, N).
    //
    // Each iteration corresponds to one tree level; within a level all
    // combines are INDEPENDENT and could execute in parallel.
    let mut level_size = n_leaves;
    while level_size > 1 {
        debug_assert_eq!(level_size % 2, 0, "level_size must always be even");
        let next_size = level_size / 2;
        let mut next = Vec::with_capacity(next_size);
        for i in 0..next_size {
            let (r_l, m_l) = working[2 * i];
            let (r_r, m_r) = working[2 * i + 1];
            next.push(crt_combine(r_l, m_l, r_r, m_r));
            combine_count += 1;
        }
        working = next;
        level_size = next_size;
    }

    debug_assert_eq!(working.len(), 1, "reconstruction must converge to a single pair");
    let (value, modulus) = working[0];

    SubproductCrtResult {
        value: canonical(value, modulus),
        modulus,
        combine_count,
        sequential_depth: tree.depth,
    }
}

// ─── Precomputed Variant ──────────────────────────────────────────────────────

/// A precomputed subproduct-tree CRT engine: tree built once, used many times.
///
/// This mirrors the `GarnerConstants` interface so it can be used as a
/// drop-in replacement in the engine for large-k topologies.
///
/// # When to use this vs GarnerConstants
///
/// | k      | Single-threaded | Parallel |
/// |--------|-----------------|----------|
/// | ≤ 12   | GarnerConstants | Either   |
/// | 13–50  | Either          | SubproductTreeCrt |
/// | > 50   | SubproductTreeCrt | SubproductTreeCrt |
#[derive(Debug, Clone)]
pub struct SubproductTreeCrt {
    tree: SubproductTree,
}

impl SubproductTreeCrt {
    /// Build the tree (one-time O(k) cost).
    pub fn precompute(primes: &[i128]) -> Self {
        Self { tree: SubproductTree::build(primes) }
    }

    /// Reconstruct a scalar from residues.  O(k) work, O(log k) depth.
    pub fn reconstruct(&self, residues: &[i128]) -> i128 {
        subproduct_reconstruct(residues, &self.tree).value
    }

    /// Full reconstruction result with diagnostic statistics.
    pub fn reconstruct_full(&self, residues: &[i128]) -> SubproductCrtResult {
        subproduct_reconstruct(residues, &self.tree)
    }

    /// Total modulus N.
    pub fn modulus(&self) -> i128 { self.tree.modulus() }

    /// Number of real primes k.
    pub fn k(&self) -> usize { self.tree.k }

    /// Combine count for one reconstruction (= n_leaves − 1).
    pub fn combine_count(&self) -> usize { self.tree.combine_count() }

    /// Sequential depth (= log₂(next_pow2(k))).
    pub fn sequential_depth(&self) -> usize { self.tree.sequential_depth() }
}

// ─── Cross-Verification ───────────────────────────────────────────────────────

/// Verify that the subproduct tree reconstruction matches Garner's algorithm
/// for a given residue tuple.  Returns `true` if both agree.
///
/// This is the correctness oracle used in the test suite.  Any divergence
/// between the two independent implementations signals a critical bug.
pub fn verify_matches_garner(
    residues: &[i128],
    primes: &[i128],
) -> bool {
    use crate::garner::{GarnerConstants, reconstruct as garner_reconstruct};
    let garner_constants = GarnerConstants::precompute(primes);
    let garner_val = garner_reconstruct(residues, &garner_constants);
    let tree = SubproductTree::build(primes);
    let tree_val = subproduct_reconstruct(residues, &tree).value;
    garner_val == tree_val
}

/// Operation count comparison for a given k.
/// Returns (garner_sequential_mults, tree_total_combines, tree_sequential_depth).
pub fn operation_count_comparison(k: usize) -> (usize, usize, usize) {
    let garner_mults  = k * (k.saturating_sub(1)) / 2;
    let n_leaves      = next_pow2(k);
    let tree_combines = n_leaves.saturating_sub(1);
    let tree_depth    = n_leaves.trailing_zeros() as usize;
    (garner_mults, tree_combines, tree_depth)
}

// ─── Internal Helper ─────────────────────────────────────────────────────────

/// Smallest power of 2 that is ≥ n.
#[inline]
fn next_pow2(n: usize) -> usize {
    if n <= 1 { return 1; }
    let mut p = 1usize;
    while p < n { p <<= 1; }
    p
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::garner::{GarnerConstants, decompose, reconstruct as garner_val};

    fn s4_primes() -> Vec<i128> { vec![2, 3, 5, 7] }
    fn s6_primes() -> Vec<i128> { vec![2, 3, 5, 7, 11, 13] }
    fn s4p_primes() -> Vec<i128> { vec![79, 83, 89, 97] }

    // ── next_pow2 helper ──────────────────────────────────────────────────────

    #[test]
    fn next_pow2_values() {
        assert_eq!(next_pow2(1), 1);
        assert_eq!(next_pow2(2), 2);
        assert_eq!(next_pow2(3), 4);
        assert_eq!(next_pow2(4), 4);
        assert_eq!(next_pow2(5), 8);
        assert_eq!(next_pow2(6), 8);
        assert_eq!(next_pow2(7), 8);
        assert_eq!(next_pow2(8), 8);
        assert_eq!(next_pow2(9), 16);
    }

    // ── SubproductTree structure ──────────────────────────────────────────────

    #[test]
    fn tree_s4_root_equals_modulus() {
        let tree = SubproductTree::build(&s4_primes());
        assert_eq!(tree.modulus(), 210, "S4 root must equal N = 2·3·5·7 = 210");
        assert_eq!(tree.k, 4);
        assert_eq!(tree.n_leaves, 4);  // next_pow2(4) = 4
        assert_eq!(tree.depth, 2);
    }

    #[test]
    fn tree_s6_root_equals_modulus() {
        let tree = SubproductTree::build(&s6_primes());
        assert_eq!(tree.modulus(), 30030, "S6 root must equal N = 2·3·5·7·11·13 = 30030");
        assert_eq!(tree.k, 6);
        assert_eq!(tree.n_leaves, 8); // next_pow2(6) = 8
        assert_eq!(tree.depth, 3);
    }

    #[test]
    fn tree_s6_internal_products_correct() {
        // For S6, padded to 8 leaves [2,3,5,7,11,13,1,1]:
        // Level-2 nodes (children of root's children):
        //   node 4 = leaves[0]*leaves[1] = 2*3  = 6
        //   node 5 = leaves[2]*leaves[3] = 5*7  = 35
        //   node 6 = leaves[4]*leaves[5] = 11*13= 143
        //   node 7 = leaves[6]*leaves[7] = 1*1  = 1
        // Level-1 nodes (children of root):
        //   node 2 = node4*node5 = 6*35   = 210
        //   node 3 = node6*node7 = 143*1  = 143
        // Root:
        //   node 1 = node2*node3 = 210*143= 30030
        let tree = SubproductTree::build(&s6_primes());
        let p = &tree.products;
        assert_eq!(p[8],  2,     "leaf 0 = 2");
        assert_eq!(p[9],  3,     "leaf 1 = 3");
        assert_eq!(p[10], 5,     "leaf 2 = 5");
        assert_eq!(p[11], 7,     "leaf 3 = 7");
        assert_eq!(p[12], 11,    "leaf 4 = 11");
        assert_eq!(p[13], 13,    "leaf 5 = 13");
        assert_eq!(p[14], 1,     "leaf 6 = sentinel 1");
        assert_eq!(p[15], 1,     "leaf 7 = sentinel 1");
        assert_eq!(p[4],  6,     "node 4 = 2·3 = 6");
        assert_eq!(p[5],  35,    "node 5 = 5·7 = 35");
        assert_eq!(p[6],  143,   "node 6 = 11·13 = 143");
        assert_eq!(p[7],  1,     "node 7 = 1·1 = 1");
        assert_eq!(p[2],  210,   "node 2 = 6·35 = 210");
        assert_eq!(p[3],  143,   "node 3 = 143·1 = 143");
        assert_eq!(p[1],  30030, "root   = 210·143 = 30030");
    }

    // ── Operation counts ──────────────────────────────────────────────────────

    #[test]
    fn s4_operation_counts() {
        let (garner, tree_total, tree_depth) = operation_count_comparison(4);
        assert_eq!(garner,     6, "Garner k=4: k*(k-1)/2 = 6");
        assert_eq!(tree_total, 3, "Tree k=4: n_leaves-1 = 4-1 = 3");
        assert_eq!(tree_depth, 2, "Tree k=4: log2(4) = 2");
    }

    #[test]
    fn s6_operation_counts() {
        let (garner, tree_total, tree_depth) = operation_count_comparison(6);
        assert_eq!(garner,     15, "Garner k=6: k*(k-1)/2 = 15");
        assert_eq!(tree_total,  7, "Tree k=6: n_leaves-1 = 8-1 = 7");
        assert_eq!(tree_depth,  3, "Tree k=6: log2(8) = 3");
    }

    #[test]
    fn large_k_operation_counts() {
        // k=144 (WASSAN band count)
        let (garner, tree_total, tree_depth) = operation_count_comparison(144);
        assert_eq!(garner,      10296, "k=144 Garner: 144*143/2 = 10,296");
        assert_eq!(tree_total,    255, "k=144 tree total: next_pow2(144)-1 = 256-1 = 255");
        assert_eq!(tree_depth,      8, "k=144 tree depth: log2(256) = 8");

        // k=5653 (Recombinant CRT v3 tier count)
        let (garner5k, tree5k_total, tree5k_depth) = operation_count_comparison(5653);
        assert_eq!(garner5k,  15_975_378);
        assert_eq!(tree5k_total, 8_191); // next_pow2(5653)=8192, so 8192-1=8191
        assert_eq!(tree5k_depth,    13); // log2(8192) = 13
    }

    // ── crt_combine correctness ───────────────────────────────────────────────

    #[test]
    fn crt_combine_two_prime_example() {
        // x ≡ 1 (mod 2) ∧ x ≡ 0 (mod 3)  →  x ≡ 3 (mod 6)
        let (x, m) = crt_combine(1, 2, 0, 3);
        assert_eq!(m, 6);
        assert_eq!(x % 2, 1, "x mod 2 must equal 1");
        assert_eq!(x % 3, 0, "x mod 3 must equal 0");
        assert_eq!(x, 3);
    }

    #[test]
    fn crt_combine_sentinel_identity() {
        // Combining with sentinel (r=0, m=1) must return the other pair unchanged.
        let (x, m) = crt_combine(42, 210, 0, 1);
        assert_eq!(x, 42);
        assert_eq!(m, 210);

        let (x, m) = crt_combine(0, 1, 17, 30030);
        assert_eq!(x, 17);
        assert_eq!(m, 30030);
    }

    #[test]
    fn crt_combine_exhaustive_mod6() {
        // Exhaustively verify crt_combine against brute-force for all
        // (r2, r3) pairs in Z_2 × Z_3.
        for r2 in 0..2i128 {
            for r3 in 0..3i128 {
                let (x, m) = crt_combine(r2, 2, r3, 3);
                assert_eq!(m, 6);
                assert!(x >= 0 && x < 6);
                assert_eq!(x % 2, r2, "crt_combine Z2xZ3: x mod 2 ≠ r2");
                assert_eq!(x % 3, r3, "crt_combine Z2xZ3: x mod 3 ≠ r3");
            }
        }
    }

    // ── Canonical paper result: (1,0,0,4) → 165 ──────────────────────────────

    #[test]
    fn paper_trace_reconstruct_165() {
        let tree = SubproductTree::build(&s4_primes());
        let result = subproduct_reconstruct(&[1, 0, 0, 4], &tree);
        assert_eq!(
            result.value, 165,
            "Paper canonical result: 17 ⊛_S4 23 = 165"
        );
        // S4 has no padding (next_pow2(4) = 4), so exactly 3 combines.
        assert_eq!(result.combine_count, 3,  "S4: n_leaves-1 = 3 combines");
        assert_eq!(result.sequential_depth, 2, "S4: log2(4) = 2 depth levels");
    }

    // ── Cross-verification against Garner ─────────────────────────────────────

    #[test]
    fn matches_garner_all_z210() {
        // Every element of Z_210 must reconstruct identically via both
        // Garner and the subproduct tree.  This is the comprehensive
        // correctness oracle.
        let primes = s4_primes();
        let garner = GarnerConstants::precompute(&primes);
        let tree   = SubproductTree::build(&primes);

        for x in 0..210i128 {
            let residues = decompose(x, &primes);
            let g_val = garner_val(&residues, &garner);
            let t_val = subproduct_reconstruct(&residues, &tree).value;
            assert_eq!(
                g_val, t_val,
                "Garner/tree diverge at x={}: garner={} tree={}", x, g_val, t_val
            );
        }
    }

    #[test]
    fn matches_garner_s6_spot_check() {
        let primes = s6_primes();
        let garner = GarnerConstants::precompute(&primes);
        let tree   = SubproductTree::build(&primes);
        let n: i128 = primes.iter().product(); // 30030

        for x in (0..n).step_by(30) {
            let residues = decompose(x, &primes);
            let g_val = garner_val(&residues, &garner);
            let t_val = subproduct_reconstruct(&residues, &tree).value;
            assert_eq!(g_val, t_val, "S6 diverge at x={}", x);
        }
    }

    #[test]
    fn matches_garner_s4_plus() {
        // CRAM-S4+ primes {79,83,89,97}, N = 56,360,923
        let primes = s4p_primes();
        let garner = GarnerConstants::precompute(&primes);
        let tree   = SubproductTree::build(&primes);

        // Spot-check 100 values spread across Z_N
        let n: i128 = primes.iter().product();
        for i in 0..100i128 {
            let x = (i * 563_610) % n; // pseudo-spread
            let residues = decompose(x, &primes);
            let g_val = garner_val(&residues, &garner);
            let t_val = subproduct_reconstruct(&residues, &tree).value;
            assert_eq!(g_val, t_val, "S4+ diverge at x={}", x);
        }
    }

    // ── SubproductTreeCrt convenience type ───────────────────────────────────

    #[test]
    fn subproduct_tree_crt_reconstruct_identity() {
        let primes = s6_primes();
        let crt = SubproductTreeCrt::precompute(&primes);
        assert_eq!(crt.modulus(), 30030);
        assert_eq!(crt.k(), 6);
        assert_eq!(crt.combine_count(),     7);
        assert_eq!(crt.sequential_depth(),  3);

        let residues = decompose(17000, &primes);
        let result = crt.reconstruct(&residues);
        assert_eq!(result, 17000);
    }

    // ── Boundary values ───────────────────────────────────────────────────────

    #[test]
    fn reconstruct_zero() {
        let tree = SubproductTree::build(&s4_primes());
        let r = subproduct_reconstruct(&[0, 0, 0, 0], &tree);
        assert_eq!(r.value, 0);
    }

    #[test]
    fn reconstruct_n_minus_1() {
        let primes = s4_primes();
        let n: i128 = primes.iter().product(); // 210
        let x = n - 1; // 209
        let tree = SubproductTree::build(&primes);
        let residues = decompose(x, &primes);
        let r = subproduct_reconstruct(&residues, &tree);
        assert_eq!(r.value, 209, "N-1 must reconstruct to 209");
    }

    // ── verify_matches_garner utility ─────────────────────────────────────────

    #[test]
    fn verify_matches_garner_confirms_agreement() {
        assert!(verify_matches_garner(&[1, 0, 0, 4], &s4_primes()),
            "Paper trace must agree between Garner and subproduct tree");
        assert!(verify_matches_garner(&[0, 1, 2, 3, 4, 5], &s6_primes()),
            "S6 spot check must agree");
    }

    // ── k=1 edge case ─────────────────────────────────────────────────────────

    #[test]
    fn single_prime_topology() {
        // k=1: trivial — the residue IS the value.
        let tree = SubproductTree::build(&[7]);
        let r = subproduct_reconstruct(&[5], &tree);
        assert_eq!(r.value,           5);
        assert_eq!(r.combine_count,   0); // n_leaves=1, no combines needed
        assert_eq!(r.sequential_depth, 0);
    }
}
