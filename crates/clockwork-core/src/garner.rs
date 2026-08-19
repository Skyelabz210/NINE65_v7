//! # Garner Mixed-Radix Digits & K-Elimination — Formal Spec §2.1, D5–D6
//!
//! Implements the Garner algorithm for mixed-radix decomposition and the
//! K-Elimination 2-gear step that is the core of Clockwork arithmetic.
//!
//! ## Theorem Coverage
//! - **T2** (K-Elimination Correctness): k ∈ {0,...,a-1} and X ≡ r + k·m (mod m·a)
//! - **T16** (GRO-Garner Composition): When implemented constant-time + GRO gated,
//!   no timing information about X leaks through k computation.
//!
//! ## Constant-Time Guarantee (G14 correction)
//! `k_eliminate_ct` and `garner_decompose_ct` are branchless: no
//! secret-dependent `if`/`match` on `r`/`s`/digit values, and no
//! secret-indexed memory access. That branchlessness comes from
//! [`reduce_u128_ct`] — a bit-serial, fixed-iteration-count (128 steps)
//! shift-and-conditional-subtract reduction using only compare/shift/wrap
//! arithmetic — used everywhere a modulus reduction is needed on
//! secret-dependent data, instead of the native `%`/`/` operators (whose
//! latency on most CPUs *does* vary with operand magnitude, which is exactly
//! the "not really constant-time" gap an earlier version of this module had:
//! it claimed CT via `subtle::ConditionallySelectable` while never actually
//! calling into `subtle`, and every reduction was a plain data-dependent
//! `%`). `subtle` is not used or imported here; the technique instead
//! mirrors the accepted branchless mask pattern already used and CT-tested
//! elsewhere in this workspace (see
//! `nine65::arithmetic::k_elimination::{sub_mod_u128_ct, mul_mod_u128_ct}`
//! and `nine65::security::ct_verification`), reimplemented locally because
//! this crate does not depend on `nine65` (the dependency runs the other
//! way). `mod_inverse` calls inside `garner_decompose_ct` operate only on
//! the (public, fixed-per-basis) *moduli*, never on secret residues, so its
//! variable-time Euclidean algorithm is not a secret-dependent side channel.

use crate::basis::mod_inverse;

// ─── D6: K-Elimination (2-Gear Garner Step) ─────────────────────────────────

/// K-Elimination: compute the Garner digit k for the 2-modulus case.
///
/// **Formal Spec D6**: Given coprime m, a and:
///   X ≡ r (mod m)
///   X ≡ s (mod a)
/// Compute:
///   k = (s - r) · m^{-1} (mod a)
///
/// Then X ≡ r + k·m (mod m·a), with k ∈ {0, ..., a-1}.
///
/// **T2 guarantees**: correctness, uniqueness, and range.
///
/// # Arguments
/// - `r`: residue of X mod m (must be in [0, m))
/// - `s`: residue of X mod a (must be in [0, a))
/// - `m`: first modulus
/// - `a`: second modulus (coprime to m)
/// - `m_inv_mod_a`: precomputed m^{-1} mod a
///
/// # Returns
/// The Garner digit k ∈ {0, ..., a-1}
///
/// # Panics
/// Debug-asserts that inputs are in valid ranges.
pub fn k_eliminate(r: u64, s: u64, m: u64, a: u64, m_inv_mod_a: u64) -> u64 {
    debug_assert!(r < m, "r={r} must be < m={m}");
    debug_assert!(s < a, "s={s} must be < a={a}");
    debug_assert!(m_inv_mod_a < a, "inverse must be < a");

    // k = (s - r) · m^{-1} mod a
    // Handle underflow: if s < r, add a to (s - r) before mod
    let a128 = a as u128;
    let diff = if s >= r {
        (s - r) as u128
    } else {
        // (s - r + a) mod a when treating as residues mod a
        // But r might be >= a, so we need: (s as i128 - r as i128).rem_euclid(a)
        let s128 = s as u128;
        let r_mod_a = (r as u128) % a128;
        (s128 + a128 - r_mod_a) % a128
    };

    let k = (diff * (m_inv_mod_a as u128)) % a128;
    k as u64
}

/// Branchless (data-independent iteration count and control flow) reduction
/// of `x` modulo `modulus`, for `x` up to 128 bits and `modulus` up to 64
/// bits. Processes `x` one bit at a time from the most significant bit using
/// only shifts, wrapping arithmetic, and a mask-selected conditional
/// subtract — never the native `%`/`/` operators, whose instruction latency
/// on most CPUs depends on operand magnitude and is therefore not a safe
/// primitive for secret-dependent values.
///
/// Fixed 128 iterations regardless of `x` or `modulus`; each iteration does
/// the same shift/compare/mask/subtract sequence regardless of the running
/// remainder's value, so there is no data-dependent branch and no
/// data-dependent number of steps.
#[inline]
fn reduce_u128_ct(x: u128, modulus: u128) -> u128 {
    debug_assert!(modulus != 0, "reduce_u128_ct: modulus must be nonzero");
    let mut remainder: u128 = 0;
    for bit in (0..128).rev() {
        // remainder = remainder*2 + next bit of x. remainder stays < modulus
        // (<= 2^64 - 1) after every prior step, so this shift cannot overflow
        // u128 (result < 2*modulus <= 2^65).
        let next_bit = (x >> bit) & 1;
        remainder = (remainder << 1) | next_bit;
        // Branchless conditional subtract: `>=` is a plain compare (fixed
        // latency), never a DIV/MOD instruction.
        let mask = ((remainder >= modulus) as u128).wrapping_neg();
        remainder = remainder.wrapping_sub(modulus & mask);
    }
    remainder
}

/// Constant-time K-Elimination for secret-dependent paths.
///
/// **Formal Spec T16 requirement**: This version ensures:
/// - No secret-dependent branches
/// - No secret-dependent memory access
/// - Uniform, data-independent operation sequence regardless of input values
///   (see [`reduce_u128_ct`] for what "constant-time" means concretely here)
///
/// # Arguments
/// Same as `k_eliminate`, but all reductions go through [`reduce_u128_ct`]
/// instead of the native `%` operator.
///
/// # Safety
/// This function is safe to call on secret-dependent values without
/// creating timing side channels, PROVIDED it runs under GRO gating (T16).
pub fn k_eliminate_ct(r: u64, s: u64, _m: u64, a: u64, m_inv_mod_a: u64) -> u64 {
    let a128 = a as u128;
    let s128 = s as u128;
    let r_mod_a = reduce_u128_ct(r as u128, a128);

    // diff = (s - r_mod_a) mod a, without branching on whether s >= r_mod_a:
    // s128 < a128 and r_mod_a < a128, so s128 + a128 - r_mod_a lies in
    // (0, 2*a128) — always representable and always reducible by one mod.
    let no_borrow = s128 + a128 - r_mod_a;
    let diff = reduce_u128_ct(no_borrow, a128);

    let k = reduce_u128_ct(diff * (m_inv_mod_a as u128), a128);
    k as u64
}

// ─── D5: Full Garner Decomposition ──────────────────────────────────────────

/// Result of a full Garner mixed-radix decomposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarnerDigits {
    /// The mixed-radix digits d_0, d_1, ..., d_k
    /// d_i ∈ {0, 1, ..., p_i - 1}
    pub digits: Vec<u64>,
    /// The moduli used (for reconstruction)
    pub moduli: Vec<u64>,
}

impl GarnerDigits {
    /// Reconstruct the value X mod M_k from Garner digits.
    ///
    /// X = d_0 + d_1·p_0 + d_2·p_0·p_1 + ... + d_k·∏_{j<k} p_j
    ///
    /// All integer arithmetic. No floating point.
    ///
    /// # Panics
    /// Panics if the running product of moduli overflows u128.
    pub fn reconstruct(&self) -> u128 {
        let mut result: u128 = 0;
        let mut weight: u128 = 1; // ∏_{j=0}^{i-1} p_j

        for (i, &d_i) in self.digits.iter().enumerate() {
            result = result
                .checked_add(
                    (d_i as u128)
                        .checked_mul(weight)
                        .expect("Garner reconstruct: digit × weight overflows u128"),
                )
                .expect("Garner reconstruct: accumulator overflows u128");
            if i < self.moduli.len() - 1 {
                weight = weight
                    .checked_mul(self.moduli[i] as u128)
                    .expect("Garner reconstruct: weight product overflows u128");
            }
        }
        result
    }

    /// Check that all digits are in valid range.
    pub fn is_valid(&self) -> bool {
        self.digits.len() == self.moduli.len()
            && self
                .digits
                .iter()
                .zip(self.moduli.iter())
                .all(|(&d, &p)| d < p)
    }
}

/// Compute the full Garner mixed-radix decomposition of X given its residues.
///
/// **Formal Spec D5**: For pairwise coprime p = (p_0, ..., p_k), compute
/// the unique digits (d_0, ..., d_k) with d_i ∈ {0, ..., p_i - 1} such that:
///
///   X ≡ d_0 + d_1·p_0 + d_2·p_0·p_1 + ... + d_k·∏_{j<k} p_j  (mod M_k)
///
/// This is the iterative Garner algorithm: each step is a K-Elimination.
///
/// # Arguments
/// - `residues`: the residue vector (r_0, ..., r_k)
/// - `moduli`: the pairwise coprime moduli (p_0, ..., p_k)
///
/// # Returns
/// `GarnerDigits` containing the mixed-radix expansion.
pub fn garner_decompose(residues: &[u64], moduli: &[u64]) -> GarnerDigits {
    assert_eq!(
        residues.len(),
        moduli.len(),
        "Residue/moduli length mismatch"
    );
    let k = moduli.len();

    if k == 0 {
        return GarnerDigits {
            digits: vec![],
            moduli: vec![],
        };
    }

    // Working copy of residues — we reference these as we peel off digits
    let working: Vec<u64> = residues.to_vec();
    let mut digits: Vec<u64> = Vec::with_capacity(k);

    // d_0 = r_0 (first digit is just the first residue)
    digits.push(working[0]);

    // For each subsequent digit, perform iterative peeling (standard Garner)
    // Inner loop goes FORWARD: j = 0 to i-1
    for i in 1..k {
        let mut current = working[i];

        for j in 0..i {
            let p_i = moduli[i] as u128;
            let d_j = digits[j] as u128;
            let cur = current as u128;

            // current = (current - digits[j]) * moduli[j]^{-1} mod moduli[i]
            let diff = (cur + p_i - (d_j % p_i)) % p_i;

            let inv = mod_inverse(moduli[j] as i128, moduli[i] as i128)
                .expect("Moduli must be pairwise coprime");
            current = ((diff * inv as u128) % p_i) as u64;
        }

        digits.push(current);
    }

    GarnerDigits {
        digits,
        moduli: moduli.to_vec(),
    }
}

/// Constant-time version of garner_decompose for secret-dependent values.
///
/// Uses [`k_eliminate_ct`] internally for every inner Garner step (this is
/// now literally true — previously this function reimplemented the same
/// computation inline using native `%`, which contradicted its own "uses
/// k_eliminate_ct" doc comment and was not actually constant-time; see the
/// module-level G14 correction note). Required by T16 for secret paths.
pub fn garner_decompose_ct(residues: &[u64], moduli: &[u64]) -> GarnerDigits {
    assert_eq!(residues.len(), moduli.len());
    let k = moduli.len();

    if k == 0 {
        return GarnerDigits {
            digits: vec![],
            moduli: vec![],
        };
    }

    let working: Vec<u64> = residues.to_vec();
    let mut digits: Vec<u64> = Vec::with_capacity(k);
    digits.push(working[0]);

    for i in 1..k {
        let mut current = working[i];

        for j in 0..i {
            // moduli[i]/moduli[j] are the (public) RNS basis — fixed for a
            // given context and identical across every call, so computing
            // their inverse with a variable-time Euclidean algorithm here
            // does not leak anything about the secret residues/digits.
            let inv = mod_inverse(moduli[j] as i128, moduli[i] as i128)
                .expect("Moduli must be pairwise coprime");

            // current = (current - digits[j]) * moduli[j]^{-1} mod moduli[i],
            // via the genuinely constant-time step (see k_eliminate_ct doc).
            current = k_eliminate_ct(digits[j], current, moduli[j], moduli[i], inv);
        }

        digits.push(current);
    }

    GarnerDigits {
        digits,
        moduli: moduli.to_vec(),
    }
}

// ─── Tests: Formal Spec Test Obligations CT-02 ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::basis::RnsBasis;

    // ─── CT-02: K-Elimination vs naive CRT decode ───────────────────────

    #[test]
    fn ct02_k_eliminate_vs_crt() {
        let moduli = vec![7u64, 11, 13];
        let _basis = RnsBasis::new(moduli.clone()).unwrap();

        // Precompute inverses
        let inv_7_mod_11 = mod_inverse(7, 11).unwrap();
        let _inv_7_mod_13 = mod_inverse(7, 13).unwrap();

        // Test all values in [0, 7*11)
        for x in 0u128..77 {
            let r = (x % 7) as u64;
            let s = (x % 11) as u64;

            let k = k_eliminate(r, s, 7, 11, inv_7_mod_11);

            // Verify T2(i): k ∈ {0, ..., 10}
            assert!(k < 11, "T2(i) violation: k={k} >= a=11");

            // Verify T2(ii): X ≡ r + k·m (mod m·a)
            let reconstructed = r as u128 + (k as u128) * 7;
            assert_eq!(
                x % 77,
                reconstructed % 77,
                "T2(ii) violation: x={x}, r={r}, s={s}, k={k}"
            );
        }
    }

    #[test]
    fn ct02_k_eliminate_large_random() {
        let m = 251u64;
        let a = 509u64;
        let inv = mod_inverse(m as i128, a as i128).unwrap();

        let mut rng: u64 = 0xFEED_FACE_DEAD_BEEF;
        for _ in 0..1_000_000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let x = (rng as u128) % (m as u128 * a as u128);

            let r = (x % m as u128) as u64;
            let s = (x % a as u128) as u64;

            let k = k_eliminate(r, s, m, a, inv);

            // T2(i): range check
            assert!(k < a, "k={k} out of range");

            // T2(ii): reconstruction check
            let reconstructed = (r as u128 + k as u128 * m as u128) % (m as u128 * a as u128);
            assert_eq!(x, reconstructed, "K-Elim mismatch at x={x}");

            // T2: constant-time version must agree
            let k_ct = k_eliminate_ct(r, s, m, a, inv);
            assert_eq!(k, k_ct, "CT vs non-CT disagreement at x={x}");
        }
    }

    // ─── Full Garner decomposition round-trip ───────────────────────────

    #[test]
    fn garner_decompose_roundtrip_exhaustive() {
        let moduli = vec![7u64, 11, 13];
        let basis = RnsBasis::new(moduli.clone()).unwrap();
        let m = basis.capacity();

        for x in 0..m {
            let residues = basis.encode(x);
            let digits = garner_decompose(&residues, &moduli);

            // Verify digit ranges
            assert!(digits.is_valid(), "Invalid digits for x={x}");

            // Verify reconstruction
            let reconstructed = digits.reconstruct();
            assert_eq!(x, reconstructed, "Garner roundtrip failed for x={x}");
        }
    }

    #[test]
    fn garner_decompose_ct_matches_standard() {
        let moduli = vec![251u64, 509, 521];
        let basis = RnsBasis::new(moduli.clone()).unwrap();

        let mut rng: u64 = 0xCAFE_BABE_1234_5678;
        for _ in 0..100_000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let x = (rng as u128) % basis.capacity();

            let residues = basis.encode(x);
            let digits_std = garner_decompose(&residues, &moduli);
            let digits_ct = garner_decompose_ct(&residues, &moduli);

            assert_eq!(
                digits_std.digits, digits_ct.digits,
                "CT decomposition diverged at x={x}"
            );
        }
    }
}
