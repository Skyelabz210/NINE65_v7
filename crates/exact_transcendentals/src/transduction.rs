//! # Transduction: CRT Basis-to-Basis Bridge
//!
//! Transduction converts a value represented as residues in one CRT basis
//! to residues in a different CRT basis, without reconstructing the full
//! integer when the value lies within the representable range of both bases.
//!
//! Given a value `v` with residue representation `x_a[i] = v mod a_i` in
//! basis A = {a_0, ..., a_{N-1}}, transduction produces the representation
//! `y_b[j] = v mod b_j` in basis B = {b_0, ..., b_{M-1}}.
//!
//! ## Algorithm
//!
//! 1. Precompute CRT lifting coefficients: for each `(i, j)` pair, compute
//!    `alpha_ij` such that the CRT unit vector `e_i` in basis A (the unique
//!    value in `[0, M_A)` that is `1 mod a_i` and `0 mod a_k` for `k != i`)
//!    has residue `alpha_ij = e_i mod b_j`.
//!
//! 2. Apply: `y_j = sum_i (x_i * alpha_ij) mod b_j`.
//!
//! This works because `v = sum_i x_i * e_i (mod M_A)`, so the formula
//! recovers `v mod b_j` for values in `[0, M_A)`.
//!
//! ## CRAM Integration (Phase 4)
//!
//! Transduction is the key operation enabling CRAM (Configurable Residue
//! Arithmetic Machine) to switch between heterogeneous modular bases
//! without leaving the residue domain.
//!
//! ## Two scales, same identity, deliberately separate implementations
//!
//! `nine65`'s `arithmetic::main_only_base_ext::MainOnlyBaseExt` and
//! `arithmetic::exact_scale_round::ExactScaleRound` implement the *same*
//! rank/base-extension identity this module does (`raw = sum_i x_i * e_i`,
//! rank `t = raw / M_A`, target residue `= (raw - t*M_A) mod b_j`) — but at
//! FHE-ciphertext scale: `u64` lanes, `U256`/`U512` internals, and main
//! bases up to a few hundred bits (e.g. `secure_128`'s four ~30-bit NTT
//! primes, `M_A ~ 2^119`). This module's `i128` arithmetic is sized for
//! "Safe Basis" scale (a handful of small primes, `M_A` under a few dozen
//! bits) and — as of [`TransductionMap::try_new`] — refuses, rather than
//! silently wraps on, any basis pair too large for that. Reach for
//! `MainOnlyBaseExt`/`ExactScaleRound` at FHE-ciphertext scale; reach for
//! `TransductionMap` at CRAM-substrate scale. Neither is a drop-in
//! replacement for the other's numeric range.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::k_elim;

// ---------------------------------------------------------------------------
// Named Safe Basis configurations
// ---------------------------------------------------------------------------

/// Safe Basis S6: first 6 primes (product = 30030).
pub const S6_BASIS: [i128; 6] = [2, 3, 5, 7, 11, 13];

/// Safe Basis S8: first 8 primes (product = 9699690).
pub const S8_BASIS: [i128; 8] = [2, 3, 5, 7, 11, 13, 17, 19];

/// Transport Core: odd-prime subset used for inter-lane shuttling.
pub const TRANSPORT_CORE: [i128; 4] = [3, 7, 11, 13];

// ---------------------------------------------------------------------------
// TransductionMap
// ---------------------------------------------------------------------------

/// Approximate bit length of a positive `i128`, for diagnostics only.
///
/// `i128` has no `leading_zeros`-based `BITS` helper for "how big is this
/// value", so this computes it directly: `128 - leading_zeros(x)` is the
/// position of the highest set bit, i.e. `floor(log2(x)) + 1`. Non-positive
/// inputs (including overflow sentinels that never got a real value) report
/// `0` rather than a garbage bit count.
fn approx_bits(x: i128) -> u32 {
    if x <= 0 {
        0
    } else {
        128 - x.leading_zeros()
    }
}

/// Typed refusal for a basis pair whose CRT machinery cannot be carried in
/// `i128` without silent wraparound.
///
/// [`TransductionMap::apply`]'s accumulator (`raw = sum_i modd(x_a[i], a_i) *
/// idempotents[i]`) and its wrap-term correction are both proportional to
/// `M_A = prod(basis_a)`, not just to the values being transduced. For
/// "Safe Basis" scale bases (a handful of small primes) this is tiny; for
/// FHE-ciphertext-scale bases (e.g. the four secure_128 main primes,
/// `M_A ~ 2^119`) it overflows `i128` — in debug builds via a checked-arith
/// panic at the accumulation site, in release builds via silent wraparound
/// that returns wrong residues with no error raised anywhere. This type lets
/// [`TransductionMap::try_new`] refuse such a basis pair at construction, so
/// the wrong regime is structurally unreachable rather than merely
/// detectable after the fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransductionCapacityError {
    /// `prod(basis_a)` itself does not fit in `i128` (checked at every
    /// partial product, not just the final value).
    BasisAProductOverflow,
    /// `prod(basis_b)` itself does not fit in `i128`.
    BasisBProductOverflow,
    /// A load-bearing bound used inside `apply()` — the raw accumulator
    /// bound `M_A * sum(basis_a)`, or the wrap-term bound
    /// `sum(basis_a) * max(basis_b)` — either overflowed `i128` outright or
    /// landed inside the safety margin kept clear of the `i128` edge.
    InsufficientI128Capacity {
        /// Which bound was violated, for diagnosability.
        bound_kind: &'static str,
        /// Approximate bit length of the offending bound (or, when the
        /// bound itself overflowed before it could be formed, of the
        /// largest input that fed it).
        approx_bits: u32,
    },
}

/// Precomputed CRT coefficient matrix for converting residues from basis A
/// to basis B.
///
/// `coefficients[i][j]` stores `alpha_ij = e_i mod b_j`, where `e_i` is
/// the CRT unit vector for lane `i` in basis A.
pub struct TransductionMap {
    /// coefficients[i][j] = CRT unit vector e_i (basis A) evaluated mod b_j.
    coefficients: Vec<Vec<i128>>,
    /// The CRT unit vectors e_i themselves, needed for the wrap term.
    idempotents: Vec<i128>,
    /// Source basis moduli.
    basis_a: Vec<i128>,
    /// Target basis moduli.
    basis_b: Vec<i128>,
    /// Product of all moduli in basis A.
    m_a: i128,
    /// Product of all moduli in basis B.
    m_b: i128,
}

impl TransductionMap {
    /// Construct a transduction map from `basis_a` to `basis_b`, refusing
    /// (rather than silently wrapping) any basis pair whose CRT bookkeeping
    /// cannot be carried in `i128`.
    ///
    /// Precomputes `alpha_ij = (M_A / a_i) * (M_A / a_i)^{-1}_{a_i} mod b_j`
    /// where `M_A = prod(a_i)`.
    ///
    /// # Capacity certificate
    ///
    /// [`Self::apply`] forms `raw = sum_i modd(x_a[i], a_i) * e_i` where each
    /// term is `< a_i * M_A` (since `modd(x, a_i) <= a_i - 1 < a_i`, and
    /// `e_i = mulmod(m_over_ai, inv, m_a)` below is always reduced into
    /// `[0, M_A)`), so `raw < M_A * sum(basis_a)`. It also forms the wrap
    /// term `t * modd(m_a, b_j)` where `t = raw / m_a < sum(basis_a)` and
    /// `modd(m_a, b_j) < max(basis_b)`, so that term is
    /// `< sum(basis_a) * max(basis_b)`.
    ///
    /// This computes both bounds with checked arithmetic and requires each
    /// to land under `i128::MAX / 2` — a factor-of-2 safety margin so the
    /// incremental `raw +=` accumulation in `apply()` (which walks up to the
    /// bound one term at a time, never all at once) never comes within a
    /// factor of 2 of the `i128` edge partway through. The much smaller
    /// per-lane intermediate `acc + r_i * coefficients[i][j]` inside
    /// `apply()` is bounded by `b_j * (1 + max(basis_a))`, far under the raw
    /// bound in every basis pair checked here, so it needs no separate gate.
    ///
    /// Returns [`TransductionCapacityError`] if either bound overflows
    /// `i128` outright or falls inside that margin.
    pub fn try_new(basis_a: &[i128], basis_b: &[i128]) -> Result<Self, TransductionCapacityError> {
        // Guard the product itself at every step: an intermediate partial
        // product can overflow i128 even when the caller never reaches a
        // basis large enough for the *final* product to overflow.
        let mut m_a: i128 = 1;
        for &a in basis_a {
            m_a = m_a
                .checked_mul(a)
                .ok_or(TransductionCapacityError::BasisAProductOverflow)?;
        }
        let mut m_b: i128 = 1;
        for &b in basis_b {
            m_b = m_b
                .checked_mul(b)
                .ok_or(TransductionCapacityError::BasisBProductOverflow)?;
        }

        let margin = i128::MAX / 2;

        // Raw accumulator bound: M_A * sum(basis_a). `sum_a` itself is
        // guarded with checked_add (not a plain `.sum()`) so this function
        // has no unchecked arithmetic anywhere on the path to a capacity
        // decision -- even though overflowing this specific sum would need
        // a basis_a with individually gigantic moduli, which the m_a
        // checked-product loop above would already have caught on far
        // fewer elements in every realistic case.
        let mut sum_a: i128 = 0;
        for &a in basis_a {
            sum_a = sum_a.checked_add(a).ok_or(
                TransductionCapacityError::InsufficientI128Capacity {
                    bound_kind: "raw accumulator (sum(basis_a) itself overflowed)",
                    approx_bits: approx_bits(sum_a).max(approx_bits(a)),
                },
            )?;
        }
        let raw_bound =
            m_a.checked_mul(sum_a)
                .ok_or(TransductionCapacityError::InsufficientI128Capacity {
                    bound_kind: "raw accumulator (overflowed forming the bound)",
                    approx_bits: approx_bits(m_a).max(approx_bits(sum_a)),
                })?;
        if raw_bound >= margin {
            return Err(TransductionCapacityError::InsufficientI128Capacity {
                bound_kind: "raw accumulator",
                approx_bits: approx_bits(raw_bound),
            });
        }

        // Wrap-term bound: sum(basis_a) * max(basis_b).
        let max_b = basis_b.iter().copied().max().unwrap_or(1);
        let wrap_bound = sum_a.checked_mul(max_b).ok_or(
            TransductionCapacityError::InsufficientI128Capacity {
                bound_kind: "wrap term (overflowed forming the bound)",
                approx_bits: approx_bits(sum_a).max(approx_bits(max_b)),
            },
        )?;
        if wrap_bound >= margin {
            return Err(TransductionCapacityError::InsufficientI128Capacity {
                bound_kind: "wrap term",
                approx_bits: approx_bits(wrap_bound),
            });
        }

        Ok(Self::construct_checked(basis_a, basis_b, m_a, m_b))
    }

    /// Construct a transduction map from `basis_a` to `basis_b`.
    ///
    /// # Panics
    ///
    /// Panics if any modulus in `basis_a` is not pairwise coprime with the
    /// others (i.e., if a CRT inverse does not exist), or if the basis pair
    /// fails the `i128` capacity certificate documented on
    /// [`Self::try_new`] (see [`TransductionCapacityError`]).
    pub fn new(basis_a: &[i128], basis_b: &[i128]) -> Self {
        Self::try_new(basis_a, basis_b)
            .expect("TransductionMap: basis capacity or coprimality violated")
    }

    /// Shared construction body for a basis pair that has already cleared
    /// the capacity certificate (`m_a`/`m_b` passed in to avoid recomputing
    /// products already formed under `checked_mul` by the caller).
    ///
    /// # Panics
    ///
    /// Panics if any modulus in `basis_a` is not pairwise coprime with the
    /// others — a distinct failure mode from capacity, left as a panic per
    /// the existing contract.
    fn construct_checked(basis_a: &[i128], basis_b: &[i128], m_a: i128, m_b: i128) -> Self {
        let n = basis_a.len();
        let m = basis_b.len();

        let mut coefficients = Vec::with_capacity(n);
        let mut idempotents = Vec::with_capacity(n);

        for i in 0..n {
            let a_i = basis_a[i];
            // M_A / a_i
            let m_over_ai = m_a / a_i;
            // (M_A / a_i)^{-1} mod a_i
            let inv = k_elim::mod_inv(k_elim::modd(m_over_ai, a_i), a_i)
                .expect("basis_a moduli must be pairwise coprime");
            // e_i = (M_A / a_i) * inv, reduced mod M_A to stay in [0, M_A)
            let e_i = k_elim::mulmod(m_over_ai, inv, m_a);

            let mut row = Vec::with_capacity(m);
            for j in 0..m {
                let b_j = basis_b[j];
                row.push(k_elim::modd(e_i, b_j));
            }
            coefficients.push(row);
            idempotents.push(e_i);
        }

        TransductionMap {
            coefficients,
            idempotents,
            basis_a: basis_a.to_vec(),
            basis_b: basis_b.to_vec(),
            m_a,
            m_b,
        }
    }

    /// Apply transduction: convert residues from basis A to basis B.
    ///
    /// `x_a[i]` = value mod `a_i`. Returns `result[j]` = value mod `b_j`,
    /// valid for values in `[0, M_A)`.
    ///
    /// The algorithm uses the precomputed coefficient matrix. For lanes in
    /// basis B that also appear in basis A, the residue is copied directly.
    /// For lanes that share factors with M_A, the CRT lifting formula
    /// `y_j = sum_i (x_i * alpha_ij) mod b_j` applies directly. For
    /// disjoint-basis lanes, Garner reconstruction is used to recover the
    /// canonical value in `[0, M_A)` before reducing mod `b_j`.
    ///
    /// # Panics
    ///
    /// Panics if `x_a.len() != basis_a.len()`.
    pub fn apply(&self, x_a: &[i128]) -> Vec<i128> {
        assert_eq!(
            x_a.len(),
            self.basis_a.len(),
            "input residue count must match basis_a length"
        );

        let m = self.basis_b.len();

        // A2 — RESIDUE-NATIVE. The precomputed coefficient matrix
        // `alpha_ij = e_i mod b_j` (CRT idempotents of basis A, reduced into
        // each target lane) lets every target residue be read directly:
        //
        //     y_j = ( sum_i x_i * alpha_ij )  mod b_j
        //
        // exact for values in [0, M_A) — the documented domain of this method.
        // Nothing proportional to the value is ever formed: the largest
        // intermediate is basis-sized, not value-sized.
        //
        // The previous implementation called `garner_reconstruct` here, which
        // materialised the integer and destroyed the winding — a mixed-radix
        // cascade inside the very operator whose purpose is to move between
        // fixtures WITHOUT leaving residue space. Retired per A2: Garner's
        // digit i depends on digits 0..i-1, whereas each target lane below is
        // read independently, so the source lanes stay i.i.d.
        // raw = sum_i x_i * e_i, unreduced. x = raw - t*M_A with t = floor(raw/M_A),
        // since apply() is documented for values in [0, M_A).
        let mut raw: i128 = 0;
        for (i, &a_i) in self.basis_a.iter().enumerate() {
            raw += k_elim::modd(x_a[i], a_i) * self.idempotents[i];
        }
        let t = raw / self.m_a;

        let mut result = Vec::with_capacity(m);
        for j in 0..m {
            let b_j = self.basis_b[j];

            // Shared lane: copy straight across. This is the phase lock — a
            // lane present in both fixtures carries the phase unchanged.
            if let Some(i) = self.basis_a.iter().position(|&a_i| a_i == b_j) {
                result.push(k_elim::modd(x_a[i], b_j));
                continue;
            }

            let mut acc: i128 = 0;
            for (i, &a_i) in self.basis_a.iter().enumerate() {
                let r_i = k_elim::modd(x_a[i], a_i);
                acc = k_elim::modd(acc + r_i * self.coefficients[i][j], b_j);
            }
            // Wrap term. sum_i x_i*e_i overshoots x by t*M_A, and that term
            // only vanishes mod b_j when b_j | M_A. t is basis-sized (raw is
            // bounded by M_A * sum(a_i)), so forming it is not a value-sized
            // reconstruction — and each e_i term is read independently, so
            // there is no threaded accumulator. A2 holds.
            acc = k_elim::modd(acc - t * k_elim::modd(self.m_a, b_j), b_j);
            result.push(acc);
        }

        result
    }

    /// Verify that transduction preserved the value — residue-native.
    ///
    /// Two representations agree modulo `lcm(M_A, M_B)` iff the value read
    /// from basis A reproduces `x_b` on every B lane AND the value read
    /// from basis B reproduces `x_a` on every A lane: by CRT, lanewise
    /// agreement on both bases IS agreement mod the lcm. Both reads are
    /// lanewise transductions through the idempotent tables — no integer is
    /// ever materialised, no digit depends on another digit. There are no
    /// cascades.
    ///
    /// (Previous implementation Garner-reconstructed both sides and compared
    /// mod lcm — a positional exit for a question residue space answers
    /// directly. Retired per A2; semantics unchanged.)
    pub fn verify(&self, x_a: &[i128], x_b: &[i128]) -> bool {
        assert_eq!(x_a.len(), self.basis_a.len());
        assert_eq!(x_b.len(), self.basis_b.len());

        // Basis B must be pairwise coprime for the reverse read (the old
        // Garner path reported such inputs as unverifiable; keep that
        // contract without panicking).
        for i in 0..self.basis_b.len() {
            for j in (i + 1)..self.basis_b.len() {
                if k_elim::gcd(self.basis_b[i], self.basis_b[j]) != 1 {
                    return false;
                }
            }
        }

        // A -> B lanewise read must reproduce x_b.
        let from_a = self.apply(x_a);
        for (j, &b_j) in self.basis_b.iter().enumerate() {
            if k_elim::modd(from_a[j], b_j) != k_elim::modd(x_b[j], b_j) {
                return false;
            }
        }

        // B -> A lanewise read must reproduce x_a.
        let map_ba = TransductionMap::new(&self.basis_b, &self.basis_a);
        let from_b = map_ba.apply(x_b);
        for (i, &a_i) in self.basis_a.iter().enumerate() {
            if k_elim::modd(from_b[i], a_i) != k_elim::modd(x_a[i], a_i) {
                return false;
            }
        }

        true
    }

    /// Read-only access to source basis.
    pub fn basis_a(&self) -> &[i128] {
        &self.basis_a
    }

    /// Read-only access to target basis.
    pub fn basis_b(&self) -> &[i128] {
        &self.basis_b
    }

    /// Product of source basis moduli.
    pub fn m_a(&self) -> i128 {
        self.m_a
    }

    /// Product of target basis moduli.
    pub fn m_b(&self) -> i128 {
        self.m_b
    }

    /// Read-only access to the precomputed CRT coefficient matrix.
    ///
    /// `coefficients()[i][j]` = CRT unit vector `e_i` (basis A) reduced
    /// mod `b_j`. These are the `alpha_ij` values used in the direct
    /// CRT lifting formula `y_j = sum_i (x_i * alpha_ij) mod b_j`,
    /// which is exact when every `b_j` divides `M_A`.
    pub fn coefficients(&self) -> &[Vec<i128>] {
        &self.coefficients
    }
}

// ---------------------------------------------------------------------------
// Convenience functions for named bases
// ---------------------------------------------------------------------------

/// Transduct residues from S6 basis to S8 basis.
///
/// Input: 6 residues mod {2, 3, 5, 7, 11, 13}.
/// Output: 8 residues mod {2, 3, 5, 7, 11, 13, 17, 19}.
pub fn transduct_s6_to_s8(residues_s6: &[i128]) -> Vec<i128> {
    let map = TransductionMap::new(&S6_BASIS, &S8_BASIS);
    map.apply(residues_s6)
}

/// Transduct residues from S8 basis to S6 basis.
///
/// Input: 8 residues mod {2, 3, 5, 7, 11, 13, 17, 19}.
/// Output: 6 residues mod {2, 3, 5, 7, 11, 13}.
///
/// Note: values >= 30030 (product of S6) will be reduced mod 30030.
pub fn transduct_s8_to_s6(residues_s8: &[i128]) -> Vec<i128> {
    let map = TransductionMap::new(&S8_BASIS, &S6_BASIS);
    map.apply(residues_s8)
}

/// Verify a round-trip transduction: A -> B -> A preserves the original
/// residues for a given value.
///
/// The value must lie in `[0, min(M_A, M_B))` for the round-trip to be
/// exact. For values in `[0, max(M_A, M_B))`, the result is correct
/// modulo `min(M_A, M_B)`.
pub fn verify_roundtrip(basis_a: &[i128], basis_b: &[i128], value: i128) -> bool {
    // Decompose value into basis A
    let residues_a: Vec<i128> = basis_a.iter().map(|&m| k_elim::modd(value, m)).collect();

    // A -> B
    let map_ab = TransductionMap::new(basis_a, basis_b);
    let residues_b = map_ab.apply(&residues_a);

    // B -> A
    let map_ba = TransductionMap::new(basis_b, basis_a);
    let residues_a_prime = map_ba.apply(&residues_b);

    // Two residue vectors over the SAME basis represent the same value mod
    // M_A iff they agree lane by lane — that IS the identity, by CRT. The
    // Garner "double check" that used to follow this loop reconstructed both
    // vectors to positional integers and compared them mod M_A: a value-sized
    // exit that could never disagree with the lanewise comparison above it.
    // Retired per A2. There are no cascades.
    for (i, &a_i) in basis_a.iter().enumerate() {
        if k_elim::modd(residues_a[i], a_i) != k_elim::modd(residues_a_prime[i], a_i) {
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::k_elim;

    /// Helper: decompose a value into residues for a given basis.
    fn decompose(value: i128, basis: &[i128]) -> Vec<i128> {
        basis.iter().map(|&m| k_elim::modd(value, m)).collect()
    }

    // Test 1: Transducting to the same basis is identity.
    #[test]
    fn transduct_identity() {
        let basis = [3i128, 5, 7];
        let map = TransductionMap::new(&basis, &basis);

        // Test several values in [0, 105)
        for value in [0, 1, 7, 42, 100, 104] {
            let residues = decompose(value, &basis);
            let result = map.apply(&residues);
            assert_eq!(
                residues, result,
                "identity transduction failed for value {}",
                value
            );
        }
    }

    // Test 2: S6 -> S8 preserves value.
    #[test]
    fn transduct_s6_to_s8_preserves() {
        // S6 product = 30030, S8 product = 9699690
        // For values in [0, 30030), transduction should give exact results.
        let test_values = [0, 1, 42, 1000, 12345, 29999, 30029];

        for &value in &test_values {
            let residues_s6 = decompose(value, &S6_BASIS);
            let residues_s8 = super::transduct_s6_to_s8(&residues_s6);

            // Each residue in S8 should match value mod b_j
            for (j, &b_j) in S8_BASIS.iter().enumerate() {
                assert_eq!(
                    residues_s8[j],
                    k_elim::modd(value, b_j),
                    "S6->S8 mismatch for value {} mod {}",
                    value,
                    b_j
                );
            }
        }
    }

    // Test 3: S8 -> S6 preserves value (mod 30030).
    #[test]
    fn transduct_s8_to_s6_preserves() {
        // S8 product = 9699690, S6 product = 30030
        // Values in [0, 30030) should round-trip exactly.
        let test_values = [0, 1, 42, 1000, 12345, 29999, 30029];

        for &value in &test_values {
            let residues_s8 = decompose(value, &S8_BASIS);
            let residues_s6 = super::transduct_s8_to_s6(&residues_s8);

            for (j, &a_j) in S6_BASIS.iter().enumerate() {
                assert_eq!(
                    residues_s6[j],
                    k_elim::modd(value, a_j),
                    "S8->S6 mismatch for value {} mod {}",
                    value,
                    a_j
                );
            }
        }
    }

    // Test 4: S6 -> S8 -> S6 round-trip = original.
    #[test]
    fn transduct_roundtrip_s6_s8() {
        let test_values = [0, 1, 42, 999, 12345, 30029];

        for &value in &test_values {
            assert!(
                verify_roundtrip(&S6_BASIS, &S8_BASIS, value),
                "S6->S8->S6 roundtrip failed for value {}",
                value
            );
        }
    }

    // Test 5: S8 -> S6 -> S8 round-trip = original (mod M_S6).
    #[test]
    fn transduct_roundtrip_s8_s6() {
        // For values in [0, min(M_S6, M_S8)) = [0, 30030), round-trip is exact.
        let test_values = [0, 1, 42, 999, 12345, 30029];

        for &value in &test_values {
            assert!(
                verify_roundtrip(&S8_BASIS, &S6_BASIS, value),
                "S8->S6->S8 roundtrip failed for value {}",
                value
            );
        }
    }

    // Test 6: Small bases {3, 5} -> {7, 11} preserves small values.
    #[test]
    fn transduct_small_bases() {
        let basis_a = [3i128, 5];
        let basis_b = [7i128, 11];
        let map = TransductionMap::new(&basis_a, &basis_b);

        // M_A = 15. For values in [0, 15), transduction should be exact.
        for value in 0..15 {
            let x_a = decompose(value, &basis_a);
            let x_b = map.apply(&x_a);

            for (j, &b_j) in basis_b.iter().enumerate() {
                assert_eq!(
                    x_b[j],
                    k_elim::modd(value, b_j),
                    "small basis transduction failed for value {} mod {}",
                    value,
                    b_j
                );
            }
        }
    }

    // Test 7: Transport Core {3, 7, 11, 13} -> S8.
    #[test]
    fn transduct_transport_core_to_s8() {
        let map = TransductionMap::new(&TRANSPORT_CORE, &S8_BASIS);
        // M_TRANSPORT = 3*7*11*13 = 3003
        let m_tc: i128 = TRANSPORT_CORE.iter().product();
        assert_eq!(m_tc, 3003);

        let test_values = [0, 1, 42, 1000, 3002];
        for &value in &test_values {
            let x_tc = decompose(value, &TRANSPORT_CORE);
            let x_s8 = map.apply(&x_tc);

            for (j, &b_j) in S8_BASIS.iter().enumerate() {
                assert_eq!(
                    x_s8[j],
                    k_elim::modd(value, b_j),
                    "TC->S8 failed for value {} mod {}",
                    value,
                    b_j
                );
            }
        }
    }

    // Test 8: Zero transducts to zero.
    #[test]
    fn transduct_zero() {
        let basis_a = [3i128, 5, 7];
        let basis_b = [11i128, 13, 17, 19];
        let map = TransductionMap::new(&basis_a, &basis_b);

        let zeros_a = vec![0i128; basis_a.len()];
        let result = map.apply(&zeros_a);

        for (j, &r) in result.iter().enumerate() {
            assert_eq!(r, 0, "zero transduction produced non-zero at lane {}", j);
        }
    }

    // Test 9: Verification function catches wrong results.
    #[test]
    fn transduct_verify_basic() {
        let basis_a = [3i128, 5, 7];
        let basis_b = [11i128, 13];
        let map = TransductionMap::new(&basis_a, &basis_b);

        let value = 42i128;
        let x_a = decompose(value, &basis_a);
        let x_b = map.apply(&x_a);

        // Correct transduction should verify
        assert!(
            map.verify(&x_a, &x_b),
            "verify returned false for correct transduction"
        );

        // Tamper with a residue — verification should fail
        let mut x_b_bad = x_b.clone();
        x_b_bad[0] = (x_b_bad[0] + 1) % basis_b[0];
        assert!(
            !map.verify(&x_a, &x_b_bad),
            "verify returned true for tampered transduction"
        );
    }

    // Test 10: Arbitrary coprime basis pairs.
    #[test]
    fn transduct_custom_basis() {
        // Use non-sequential primes
        let basis_a = [17i128, 23, 29];
        let basis_b = [31i128, 37, 41, 43];
        let map = TransductionMap::new(&basis_a, &basis_b);

        let m_a: i128 = basis_a.iter().product(); // 17*23*29 = 11339

        let test_values = [0, 1, 100, 5000, 11338];
        for &value in &test_values {
            assert!(value < m_a, "test value must be in [0, M_A)");

            let x_a = decompose(value, &basis_a);
            let x_b = map.apply(&x_a);

            // Check each residue matches
            for (j, &b_j) in basis_b.iter().enumerate() {
                assert_eq!(
                    x_b[j],
                    k_elim::modd(value, b_j),
                    "custom basis failed for value {} mod {}",
                    value,
                    b_j
                );
            }

            // Also verify via the verify method
            assert!(
                map.verify(&x_a, &x_b),
                "custom basis verify failed for value {}",
                value
            );
        }
    }

    // Test 11: try_new agrees with new on Safe-Basis-scale bases — the
    // capacity certificate must be a no-op for the bases this crate actually
    // ships (S6, S8, TRANSPORT_CORE). This is the regression proving the
    // fix stays backward compatible: identical construction, identical
    // apply() output.
    #[test]
    fn try_new_matches_new_on_safe_basis_scale() {
        let via_new = TransductionMap::new(&S6_BASIS, &S8_BASIS);
        let via_try_new =
            TransductionMap::try_new(&S6_BASIS, &S8_BASIS).expect("Safe Basis must be accepted");

        for &value in &[0i128, 1, 42, 12345, 29999, 30029] {
            let x_a = decompose(value, &S6_BASIS);
            assert_eq!(
                via_new.apply(&x_a),
                via_try_new.apply(&x_a),
                "new() and try_new() diverged for value {value}"
            );
            // And both must actually be correct against a direct mod check —
            // reproducing this module's own S6->S8 first-wrap coverage.
            for (j, &b_j) in S8_BASIS.iter().enumerate() {
                assert_eq!(
                    via_try_new.apply(&x_a)[j],
                    k_elim::modd(value, b_j),
                    "S6->S8 mismatch via try_new for value {value} mod {b_j}"
                );
            }
        }
    }

    // Test 12: try_new REFUSES the FHE-ciphertext-scale basis that silently
    // corrupts data under the old unchecked `new`. These are secure_128's
    // four main primes (see CLAUDE.md's security config table); M_A ~ 2^119,
    // and the raw-accumulator bound M_A * sum(basis_a) ~ 2^151 overflows
    // i128 outright — this must come back as a typed error, never `Ok`.
    #[test]
    fn try_new_refuses_fhe_scale_main_basis() {
        let basis_a: [i128; 4] = [998244353, 985661441, 754974721, 469762049];
        let basis_b: [i128; 3] = [1004535809, 1224736769, 167772161];

        let err = match TransductionMap::try_new(&basis_a, &basis_b) {
            Err(e) => e,
            Ok(_) => panic!("FHE-scale basis_a must be refused, not silently accepted"),
        };
        match err {
            // The raw-accumulator bound M_A * sum(basis_a) (~2^119 * ~2^32 =
            // ~2^151) overflows i128 outright before it can even be formed,
            // so the reported bits describe the largest input that fed it
            // (M_A itself, ~119 bits here) rather than the (unrepresentable)
            // bound — that is exactly the diagnosable overflow case, not a
            // false positive.
            TransductionCapacityError::InsufficientI128Capacity {
                bound_kind,
                approx_bits,
            } => {
                assert!(
                    bound_kind.contains("raw accumulator"),
                    "expected the raw accumulator bound to be the one that overflows, got {bound_kind:?}"
                );
                assert!(approx_bits > 0, "expected a diagnosable bit length, got 0");
            }
            other => panic!("expected InsufficientI128Capacity, got {other:?}"),
        }

        // Confirm this is not a coprimality artifact: the same basis_a is
        // pairwise coprime (four distinct NTT-friendly primes), so a naive
        // `new()` would not panic on that path — it would run straight into
        // the overflow this test exists to catch.
        for i in 0..basis_a.len() {
            for j in (i + 1)..basis_a.len() {
                assert_eq!(k_elim::gcd(basis_a[i], basis_a[j]), 1);
            }
        }
    }

    // Test 13: the boundary is genuine, not a blanket refusal — a basis pair
    // that DOES fit the certified bound must be accepted by try_new AND
    // must transduce correctly, cross-checked against a plain `modd`
    // reference computed independently of TransductionMap.
    #[test]
    fn try_new_accepts_basis_within_bound_and_apply_is_correct() {
        // Product ~1e18 (~2^60); raw bound M_A * sum(basis_a) ~ 2^82, well
        // under the i128::MAX/2 margin (~2^126).
        let basis_a: [i128; 3] = [1_000_003, 1_000_033, 1_000_037];
        let basis_b: [i128; 2] = [1_000_039, 1_000_049];

        let map = TransductionMap::try_new(&basis_a, &basis_b)
            .expect("this basis pair fits comfortably inside the certified bound");

        let m_a: i128 = basis_a.iter().product();
        for &value in &[0i128, 1, 12345, 999_999_999, m_a - 1] {
            let x_a = decompose(value, &basis_a);
            let x_b = map.apply(&x_a);
            for (j, &b_j) in basis_b.iter().enumerate() {
                // Independent reference: plain modd of the original value,
                // not routed through TransductionMap at all.
                assert_eq!(
                    x_b[j],
                    k_elim::modd(value, b_j),
                    "within-bound basis mismatch for value {value} mod {b_j}"
                );
            }
        }
    }
}
