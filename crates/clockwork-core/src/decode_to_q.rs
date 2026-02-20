//! # Decode-to-q — Formal Spec §2.1 D9
//!
//! The ONLY bridge from Clockwork representation space (ℤ_{M_k}) back to
//! RLWE ciphertext space (ℤ_q). This is where INV-1 (fixed q) and INV-2
//! (representation consistency) are enforced.
//!
//! ## Critical Invariant
//! ```text
//! DecQ_p(Enc_p(c̃)) = c̃ mod q = c   for all c ∈ ℤ_q
//! ```
//!
//! This is Theorem T5, and every coefficient must pass through this map
//! before being used in any RLWE operation.
//!
//! ## Design: q is FIXED
//! The RLWE modulus q is set once at construction and never changes.
//! This is INV-1 — the most important invariant in the entire system.

use crate::basis::RnsBasis;
use crate::gearstack::GearStack;

/// The Decode-to-q bridge: maps Clockwork residues back to ℤ_q.
///
/// **Formal Spec D9**: DecQ_p(r_0, ..., r_k) = Dec_p(r_0, ..., r_k) mod q
///
/// ## Invariants
/// - `q` is fixed at construction and NEVER changes (INV-1)
/// - `basis.capacity() >= q` (precondition for T5 correctness)
/// - The decode convention (unsigned or centered) is fixed at construction
#[derive(Clone, Debug)]
pub struct DecodeToQ {
    /// The RLWE cryptographic modulus — FIXED, IMMUTABLE
    q: u64,
    /// Whether to use centered lift before reducing mod q
    centered: bool,
}

/// Decode convention: how to interpret the CRT-decoded value before reducing mod q
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeConvention {
    /// Unsigned: interpret CRT output as element of [0, M_k), then reduce mod q
    Unsigned,
    /// Centered: interpret CRT output via centered lift [-M_k/2, M_k/2], then reduce mod q
    /// This is recommended for signed coefficient arithmetic
    Centered,
}

impl DecodeToQ {
    /// Create a new Decode-to-q bridge with a FIXED cryptographic modulus.
    ///
    /// This modulus NEVER changes after construction. This is INV-1.
    ///
    /// # Arguments
    /// - `q`: The RLWE cryptographic modulus (must be ≥ 2)
    /// - `convention`: Whether to use unsigned or centered decode
    pub fn new(q: u64, convention: DecodeConvention) -> Self {
        assert!(q >= 2, "Cryptographic modulus must be ≥ 2");
        DecodeToQ {
            q,
            centered: matches!(convention, DecodeConvention::Centered),
        }
    }

    /// The fixed cryptographic modulus.
    pub fn q(&self) -> u64 {
        self.q
    }

    /// Decode a residue vector to ℤ_q.
    ///
    /// **T5 guarantee**: DecQ(Enc_p(c̃)) = c for c ∈ ℤ_q, provided M_k ≥ q.
    ///
    /// # Precondition
    /// `basis.capacity() >= q` (checked at runtime)
    pub fn decode(&self, basis: &RnsBasis, residues: &[u64]) -> u64 {
        assert!(
            basis.capacity() >= self.q as u128,
            "INV-1/T5 precondition: M_k ({}) must be ≥ q ({})",
            basis.capacity(),
            self.q
        );

        if self.centered {
            // Centered path: decode to centered lift, then reduce mod q
            let centered = basis.decode_centered(residues);
            let q_i128 = self.q as i128;
            ((centered % q_i128 + q_i128) % q_i128) as u64
        } else {
            // Unsigned path: decode to [0, M_k), then reduce mod q
            let unsigned = basis.decode(residues);
            (unsigned % (self.q as u128)) as u64
        }
    }

    /// Decode a GearStack value to ℤ_q.
    pub fn decode_gearstack(&self, gs: &GearStack) -> u64 {
        self.decode(gs.basis(), gs.residues())
    }

    /// Encode a ℤ_q coefficient into a Clockwork residue vector.
    ///
    /// This is the inverse direction: ℤ_q → Clockwork.
    /// The coefficient c is lifted to its canonical representative c̃,
    /// then encoded into RNS residues.
    ///
    /// For unsigned convention: c̃ = c ∈ [0, q)
    /// For centered convention: c̃ ∈ [-q/2, q/2]
    pub fn encode(&self, basis: &RnsBasis, c: u64) -> Vec<u64> {
        assert!(c < self.q, "Coefficient {c} must be < q={}", self.q);

        if self.centered {
            let half_q = (self.q / 2) as i128;
            let c_centered = if (c as i128) > half_q {
                c as i128 - self.q as i128
            } else {
                c as i128
            };
            basis.encode_signed(c_centered)
        } else {
            basis.encode(c as u128)
        }
    }

    /// Round-trip verification: encode then decode must return the original.
    ///
    /// **Test obligation CT-05**: This must hold for all c ∈ [0, q).
    pub fn verify_roundtrip(&self, basis: &RnsBasis, c: u64) -> bool {
        let residues = self.encode(basis, c);
        let decoded = self.decode(basis, &residues);
        decoded == c
    }
}

// ─── Tests: Formal Spec Test Obligation CT-05 ───────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_basis() -> RnsBasis {
        // M_k = 251 * 509 * 521 * 1021 = ~67.9 billion, well above any reasonable q
        RnsBasis::new(vec![251, 509, 521, 1021]).unwrap()
    }

    // ─── CT-05: DecQ(Enc_p(c̃)) = c for all c ∈ [0, q) ─────────────────

    #[test]
    fn ct05_roundtrip_unsigned_exhaustive() {
        let basis = test_basis();
        let q = 4093u64; // a prime near 2^12

        let dtq = DecodeToQ::new(q, DecodeConvention::Unsigned);

        // Exhaustive for this q
        for c in 0..q {
            assert!(
                dtq.verify_roundtrip(&basis, c),
                "CT-05 unsigned roundtrip failed for c={c}, q={q}"
            );
        }
    }

    #[test]
    fn ct05_roundtrip_centered_exhaustive() {
        let basis = test_basis();
        let q = 4093u64;

        let dtq = DecodeToQ::new(q, DecodeConvention::Centered);

        for c in 0..q {
            assert!(
                dtq.verify_roundtrip(&basis, c),
                "CT-05 centered roundtrip failed for c={c}, q={q}"
            );
        }
    }

    #[test]
    fn ct05_multiple_bases() {
        // Test with 5 different basis choices (CT-05 requirement)
        let bases = vec![
            RnsBasis::new(vec![7, 11, 13, 17, 19]).unwrap(),
            RnsBasis::new(vec![251, 509]).unwrap(),
            RnsBasis::new(vec![1021, 1031, 1033]).unwrap(),
            RnsBasis::new(vec![65521, 65519]).unwrap(), // near 2^16
            RnsBasis::new(vec![251, 509, 521, 1021]).unwrap(),
        ];

        let q = 997u64; // small enough to be exhaustive across all bases

        for (idx, basis) in bases.iter().enumerate() {
            let dtq_u = DecodeToQ::new(q, DecodeConvention::Unsigned);
            let dtq_c = DecodeToQ::new(q, DecodeConvention::Centered);

            for c in 0..q {
                assert!(
                    dtq_u.verify_roundtrip(basis, c),
                    "CT-05 failed: basis {idx}, unsigned, c={c}"
                );
                assert!(
                    dtq_c.verify_roundtrip(basis, c),
                    "CT-05 failed: basis {idx}, centered, c={c}"
                );
            }
        }
    }

    #[test]
    fn invariant_q_never_changes() {
        let dtq = DecodeToQ::new(4093, DecodeConvention::Unsigned);
        // q is immutable by construction — no setter exists.
        // This test documents the invariant.
        assert_eq!(dtq.q(), 4093);
        // There is no `set_q` method — INV-1 is enforced by the type system.
    }

    #[test]
    #[should_panic(expected = "must be ≥ q")]
    fn rejects_insufficient_basis() {
        let tiny_basis = RnsBasis::new(vec![7, 11]).unwrap(); // M_k = 77
        let dtq = DecodeToQ::new(100, DecodeConvention::Unsigned); // q = 100 > 77
        let residues = vec![3, 5];
        dtq.decode(&tiny_basis, &residues); // should panic
    }
}
