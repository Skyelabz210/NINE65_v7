//! S8 Lane Projection and Garner Reconstruction.
//!
//! Phase 1 of the CRAM-CT specification: project an integer (or a polynomial
//! of integer coefficients) into the S8 safe basis residue lanes, and
//! reconstruct via Garner's algorithm. This is the metadata layer that lets
//! a CRAM ciphertext carry an S8 signature alongside its security-bearing
//! RLWE residues.
//!
//! The lane projection is a *witness*, not a replacement for the RNS
//! representation used inside `nine65`. The S8 signature is small (8 small
//! residues per coefficient, product 9_699_690) and exists for proof-carrying
//! diagnostics: corruption, off-by-one shifts, lane-boundary mistakes, and
//! winding errors all perturb at least one S8 lane and are therefore caught
//! by signature verification.
//!
//! The projection is invertible up to the S8 product:
//!
//! * For any integer `x` with `|x| < S8_PRODUCT / 2` (signed) or
//!   `0 <= x < S8_PRODUCT` (unsigned), `garner_reconstruct(project(x)) == x`.
//! * For larger `x`, the result is `x mod S8_PRODUCT`, with the original
//!   "winding count" `floor(x / S8_PRODUCT)` available separately as the
//!   triad-style winding witness.

use crate::triad::{S8, S8_PRODUCT};
use crate::Vec;

/// Eight S8 residues describing a single integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S8Signature {
    pub residues: [u32; 8],
}

impl S8Signature {
    /// Project a signed integer into S8 residues.
    pub fn project(x: i128) -> Self {
        let mut r = [0u32; 8];
        for (i, &p) in S8.iter().enumerate() {
            r[i] = x.rem_euclid(p as i128) as u32;
        }
        Self { residues: r }
    }

    /// Look up a single residue by prime modulus.
    pub fn residue_mod(&self, p: u32) -> Option<u32> {
        S8.iter().position(|&q| q == p).map(|i| self.residues[i])
    }

    /// True iff every lane matches.
    pub fn lanes_eq(&self, other: &Self) -> bool {
        self.residues == other.residues
    }
}

// ─── Modular Inverse ─────────────────────────────────────────────────────

/// Extended Euclidean modular inverse for small u32 moduli.
/// Returns `Some(x)` such that `(a * x) mod m == 1`, or `None` if `gcd(a, m) != 1`.
pub fn mod_inv_u32(a: u32, m: u32) -> Option<u32> {
    let (mut old_r, mut r) = (a as i64, m as i64);
    let (mut old_s, mut s) = (1i64, 0i64);
    while r != 0 {
        let q = old_r / r;
        let tmp_r = old_r - q * r;
        old_r = r;
        r = tmp_r;
        let tmp_s = old_s - q * s;
        old_s = s;
        s = tmp_s;
    }
    if old_r != 1 {
        return None;
    }
    Some(((old_s % m as i64 + m as i64) % m as i64) as u32)
}

// ─── Garner Reconstruction ────────────────────────────────────────────────

/// Reconstruct the unique integer in `[0, S8_PRODUCT)` whose residues match
/// the signature, using Garner's incremental CRT algorithm.
///
/// Garner's algorithm is:
///   v_1 = a_1
///   v_k = (a_k - x_{k-1}) * (m_1 * m_2 * ... * m_{k-1})^{-1}  mod m_k
///   x_k = x_{k-1} + v_k * (m_1 * ... * m_{k-1})
/// where `a_i` is the residue at lane `i` and `x_k` is the running
/// reconstructed integer.
pub fn garner_reconstruct(sig: &S8Signature) -> u32 {
    // Working in u64 to hold partial products up to S8_PRODUCT (~10^7).
    let mut x: u64 = sig.residues[0] as u64;
    let mut radix: u64 = S8[0] as u64;
    for i in 1..S8.len() {
        let m_i = S8[i];
        let a_i = sig.residues[i] as i64;
        let x_mod_mi = (x % m_i as u64) as i64;
        let diff = ((a_i - x_mod_mi).rem_euclid(m_i as i64)) as u32;
        let radix_mod_mi = (radix % m_i as u64) as u32;
        let inv = mod_inv_u32(radix_mod_mi, m_i)
            .expect("S8 primes are pairwise coprime so radix has an inverse mod m_i");
        let v_i = ((diff as u64) * (inv as u64)) % (m_i as u64);
        x += v_i * radix;
        radix *= m_i as u64;
    }
    debug_assert_eq!(radix, S8_PRODUCT as u64);
    x as u32
}

/// Reconstruct as a signed integer, recentred around zero modulo S8_PRODUCT.
pub fn garner_reconstruct_signed(sig: &S8Signature) -> i32 {
    let r = garner_reconstruct(sig);
    let half = S8_PRODUCT / 2;
    if r > half {
        (r as i64 - S8_PRODUCT as i64) as i32
    } else {
        r as i32
    }
}

// ─── Polynomial Projection ───────────────────────────────────────────────

/// S8 signature of a polynomial: one signature per coefficient.
#[derive(Debug, Clone)]
pub struct PolynomialS8Signature {
    pub signatures: Vec<S8Signature>,
}

impl PolynomialS8Signature {
    /// Project each coefficient of a polynomial into its own S8 signature.
    pub fn from_coeffs(coeffs: &[i128]) -> Self {
        let signatures = coeffs.iter().map(|&c| S8Signature::project(c)).collect();
        Self { signatures }
    }

    /// Reconstruct each coefficient as an unsigned residue in `[0, S8_PRODUCT)`.
    pub fn reconstruct_unsigned(&self) -> Vec<u32> {
        self.signatures.iter().map(garner_reconstruct).collect()
    }

    /// Reconstruct each coefficient recentred around zero.
    pub fn reconstruct_signed(&self) -> Vec<i32> {
        self.signatures
            .iter()
            .map(garner_reconstruct_signed)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_zero() {
        let s = S8Signature::project(0);
        assert_eq!(s.residues, [0; 8]);
    }

    #[test]
    fn project_one() {
        let s = S8Signature::project(1);
        assert_eq!(s.residues, [1; 8]);
    }

    #[test]
    fn project_negative_recentres_into_lane() {
        let s = S8Signature::project(-1);
        // -1 mod p = p - 1 for each p in S8.
        assert_eq!(s.residues, [1, 2, 4, 6, 10, 12, 16, 18]);
    }

    #[test]
    fn modular_inverse_correctness() {
        for &p in &S8 {
            for a in 1..p {
                let inv = mod_inv_u32(a, p).unwrap();
                assert_eq!(
                    (a as u64 * inv as u64) % p as u64,
                    1,
                    "{}^-1 mod {} = {} broken",
                    a,
                    p,
                    inv
                );
            }
        }
    }

    #[test]
    fn modular_inverse_returns_none_for_non_coprime() {
        // 6 and 9 share factor 3; no inverse exists.
        assert!(mod_inv_u32(6, 9).is_none());
    }

    #[test]
    fn garner_reconstructs_zero() {
        let sig = S8Signature::project(0);
        assert_eq!(garner_reconstruct(&sig), 0);
    }

    #[test]
    fn garner_reconstructs_one() {
        let sig = S8Signature::project(1);
        assert_eq!(garner_reconstruct(&sig), 1);
    }

    #[test]
    fn garner_reconstructs_max_minus_one() {
        let sig = S8Signature::project((S8_PRODUCT - 1) as i128);
        assert_eq!(garner_reconstruct(&sig), S8_PRODUCT - 1);
    }

    #[test]
    fn garner_reconstructs_arbitrary_in_range() {
        let cases: &[u32] = &[
            7, 42, 100, 1_234, 30_030, 99_999, 1_000_000, 5_678_901, 9_699_689,
        ];
        for &x in cases {
            let sig = S8Signature::project(x as i128);
            assert_eq!(garner_reconstruct(&sig), x, "garner failed for x={x}");
        }
    }

    #[test]
    fn garner_wraps_around_s8_product() {
        // x larger than S8_PRODUCT reconstructs to x mod S8_PRODUCT.
        let big = (S8_PRODUCT as i128) * 7 + 12345;
        let sig = S8Signature::project(big);
        assert_eq!(garner_reconstruct(&sig), 12345);
    }

    #[test]
    fn signed_reconstruct_recentres_around_zero() {
        let sig = S8Signature::project(-1);
        assert_eq!(garner_reconstruct_signed(&sig), -1);
        let sig = S8Signature::project(-12345);
        assert_eq!(garner_reconstruct_signed(&sig), -12345);
    }

    #[test]
    fn polynomial_roundtrip_signed() {
        let coeffs = [-1_000_000i128, -1, 0, 1, 1_000_000, 4_000_000];
        let p = PolynomialS8Signature::from_coeffs(&coeffs);
        let recon = p.reconstruct_signed();
        let expected: Vec<i32> = coeffs.iter().map(|&c| c as i32).collect();
        assert_eq!(recon, expected);
    }

    #[test]
    fn polynomial_roundtrip_unsigned() {
        let coeffs: Vec<i128> = (0..32).map(|k| k as i128 * 100_000).collect();
        let p = PolynomialS8Signature::from_coeffs(&coeffs);
        let recon = p.reconstruct_unsigned();
        for (k, &got) in recon.iter().enumerate() {
            let expected = ((k as u64 * 100_000) % S8_PRODUCT as u64) as u32;
            assert_eq!(got, expected, "lane {k}: got {got}, expected {expected}");
        }
    }

    #[test]
    fn lane_disagreement_detects_off_by_one() {
        let sig_a = S8Signature::project(123_456);
        let sig_b = S8Signature::project(123_457);
        assert!(!sig_a.lanes_eq(&sig_b));
    }

    #[test]
    fn residue_lookup_works_for_each_s8_prime() {
        let sig = S8Signature::project(42);
        for &p in &S8 {
            assert_eq!(sig.residue_mod(p), Some(42 % p));
        }
        assert!(sig.residue_mod(23).is_none());
    }
}
