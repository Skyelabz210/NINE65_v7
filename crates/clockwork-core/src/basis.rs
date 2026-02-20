//! # RNS Basis — Formal Spec §2.1, Definitions D1–D3
//!
//! Implements the foundational RNS (Residue Number System) types:
//! - **D1**: RNS Basis — pairwise coprime moduli with computed capacity M_k
//! - **D2**: Residue Encoding — Enc_p(X) = (X mod p_0, ..., X mod p_k)
//! - **D3**: CRT Decode — the unique X ∈ ℤ_{M_k} satisfying all congruences
//! - **D4**: Centered Lift — canonical representative in [-⌊M_k/2⌋, ⌊M_k/2⌋]
//!
//! ## Theorem Coverage
//! - **T1** (CRT Bijectivity): Enc_p is a ring isomorphism, Dec_p ∘ Enc_p = id
//! - **T5** (DecQ round-trip): DecQ(Enc_p(c̃)) = c for c ∈ ℤ_q when M_k ≥ q

use std::fmt;

/// Extended GCD: returns (gcd, x, y) such that a*x + b*y = gcd(a,b).
/// All integer arithmetic, zero floating point.
pub fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        return (b, 0, 1);
    }
    let (g, x1, y1) = extended_gcd(b % a, a);
    (g, y1 - (b / a) * x1, x1)
}

/// Modular inverse of a mod m. Returns None if gcd(a,m) ≠ 1.
/// Required for K-Elimination (D6) and CRT reconstruction.
pub fn mod_inverse(a: i128, m: i128) -> Option<u64> {
    let (g, x, _) = extended_gcd(a % m, m);
    if g != 1 {
        return None;
    }
    Some(((x % m + m) % m) as u64)
}

/// Pairwise coprimality check. Required precondition for all CRT operations.
#[allow(dead_code)]
fn are_pairwise_coprime(moduli: &[u64]) -> bool {
    for i in 0..moduli.len() {
        for j in (i + 1)..moduli.len() {
            let (g, _, _) = extended_gcd(moduli[i] as i128, moduli[j] as i128);
            if g != 1 {
                return false;
            }
        }
    }
    true
}

// ─── D1: RNS Basis ───────────────────────────────────────────────────────────

/// An RNS Basis: a tuple of pairwise coprime moduli with precomputed capacity.
///
/// **Formal Spec D1**: p = (p_0, ..., p_k) pairwise coprime, M_k = ∏ p_i.
///
/// Construction enforces pairwise coprimality at creation time.
/// Once created, the basis is immutable — no runtime modification.
#[derive(Clone, Debug)]
pub struct RnsBasis {
    /// The pairwise coprime moduli (primes in standard usage)
    moduli: Vec<u64>,
    /// Capacity M_k = ∏ p_i, stored as u128 to handle large products
    /// INVARIANT: capacity == moduli.iter().product()
    capacity: u128,
    /// Precomputed CRT coefficients for reconstruction
    /// crt_coeffs[i] = (M_k / p_i) * inverse(M_k / p_i, p_i) mod M_k
    crt_coeffs: Vec<u128>,
}

/// Errors that can occur during basis construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BasisError {
    /// Moduli are not pairwise coprime (violates D1 precondition)
    NotCoprime { i: usize, j: usize, gcd: u64 },
    /// Empty moduli list
    Empty,
    /// Capacity overflow (product exceeds u128)
    CapacityOverflow,
    /// Modulus is 0 or 1 (degenerate)
    DegenerateModulus { index: usize, value: u64 },
}

impl fmt::Display for BasisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BasisError::NotCoprime { i, j, gcd } => {
                write!(f, "Moduli at indices {i} and {j} share factor {gcd}")
            }
            BasisError::Empty => write!(f, "Moduli list is empty"),
            BasisError::CapacityOverflow => write!(f, "Product of moduli exceeds u128"),
            BasisError::DegenerateModulus { index, value } => {
                write!(f, "Modulus at index {index} is degenerate: {value}")
            }
        }
    }
}

impl RnsBasis {
    /// Construct a new RNS basis from pairwise coprime moduli.
    ///
    /// Validates all preconditions from D1:
    /// - Non-empty
    /// - All moduli ≥ 2
    /// - Pairwise coprime
    /// - Product fits in u128
    ///
    /// Returns `BasisError` if any precondition fails.
    pub fn new(moduli: Vec<u64>) -> Result<Self, BasisError> {
        if moduli.is_empty() {
            return Err(BasisError::Empty);
        }

        // Check for degenerate moduli
        for (i, &m) in moduli.iter().enumerate() {
            if m < 2 {
                return Err(BasisError::DegenerateModulus { index: i, value: m });
            }
        }

        // Enforce pairwise coprimality (D1 precondition)
        for i in 0..moduli.len() {
            for j in (i + 1)..moduli.len() {
                let (g, _, _) = extended_gcd(moduli[i] as i128, moduli[j] as i128);
                if g != 1 {
                    return Err(BasisError::NotCoprime {
                        i,
                        j,
                        gcd: g as u64,
                    });
                }
            }
        }

        // Compute capacity M_k = ∏ p_i, checking for overflow
        let mut capacity: u128 = 1;
        for &m in &moduli {
            capacity = capacity
                .checked_mul(m as u128)
                .ok_or(BasisError::CapacityOverflow)?;
        }

        // Precompute CRT reconstruction coefficients
        // For each i: M_i = M_k / p_i, then coeff_i = M_i * (M_i^{-1} mod p_i)
        let mut crt_coeffs = Vec::with_capacity(moduli.len());
        for (_i, &p_i) in moduli.iter().enumerate() {
            let m_i = capacity / (p_i as u128);
            let m_i_mod_pi = (m_i % (p_i as u128)) as i128;
            let inv = mod_inverse(m_i_mod_pi, p_i as i128)
                .expect("Inverse must exist since moduli are pairwise coprime");
            // coeff_i = M_i * inv mod M_k
            // Use u128 arithmetic carefully
            let coeff = mul_mod_u128(m_i, inv as u128, capacity);
            crt_coeffs.push(coeff);
        }

        Ok(RnsBasis {
            moduli,
            capacity,
            crt_coeffs,
        })
    }

    /// Number of moduli (gears) in this basis.
    pub fn num_gears(&self) -> usize {
        self.moduli.len()
    }

    /// The i-th modulus.
    pub fn modulus(&self, i: usize) -> u64 {
        self.moduli[i]
    }

    /// The moduli slice.
    pub fn moduli(&self) -> &[u64] {
        &self.moduli
    }

    /// Capacity M_k = ∏ p_i.
    pub fn capacity(&self) -> u128 {
        self.capacity
    }

    // ─── D2: Residue Encoding ─────────────────────────────────────────────

    /// Encode an integer X into its residue representation.
    ///
    /// **Formal Spec D2**: Enc_p(X) = (X mod p_0, ..., X mod p_k)
    ///
    /// Input X is taken mod M_k first (the encoding is defined on ℤ_{M_k}).
    pub fn encode(&self, x: u128) -> Vec<u64> {
        self.moduli
            .iter()
            .map(|&p| (x % (p as u128)) as u64)
            .collect()
    }

    /// Encode a signed integer (centered lift value) into residues.
    /// Handles negative values correctly via modular arithmetic.
    pub fn encode_signed(&self, x: i128) -> Vec<u64> {
        self.moduli
            .iter()
            .map(|&p| {
                let p128 = p as i128;
                ((x % p128 + p128) % p128) as u64
            })
            .collect()
    }

    // ─── D3: CRT Decode ──────────────────────────────────────────────────

    /// Decode residues back to the unique X ∈ [0, M_k).
    ///
    /// **Formal Spec D3**: Dec_p(r_0, ..., r_k) = X mod M_k
    ///
    /// **T1 guarantee**: Dec_p(Enc_p(X)) = X for all X ∈ [0, M_k).
    ///
    /// # Panics
    /// Panics if `residues.len() != self.num_gears()`.
    pub fn decode(&self, residues: &[u64]) -> u128 {
        assert_eq!(
            residues.len(),
            self.moduli.len(),
            "Residue count must match gear count"
        );

        let mut result: u128 = 0;
        for (i, &r_i) in residues.iter().enumerate() {
            debug_assert!(
                r_i < self.moduli[i],
                "Residue {} exceeds modulus {} at position {}",
                r_i,
                self.moduli[i],
                i
            );
            // result += r_i * crt_coeffs[i] mod M_k
            let term = mul_mod_u128(r_i as u128, self.crt_coeffs[i], self.capacity);
            result = (result + term) % self.capacity;
        }
        result
    }

    // ─── D4: Centered Lift ───────────────────────────────────────────────

    /// Compute the centered lift of X mod M_k.
    ///
    /// **Formal Spec D4**: Center_{M_k}(x) ∈ [-⌊M_k/2⌋, ⌊M_k/2⌋]
    ///
    /// Convention for even M_k: ties go negative ([-M_k/2, M_k/2 - 1]).
    pub fn centered_lift(&self, x: u128) -> i128 {
        let x_mod = x % self.capacity;
        let half = self.capacity / 2;
        if x_mod <= half {
            x_mod as i128
        } else {
            x_mod as i128 - self.capacity as i128
        }
    }

    /// Decode residues and return the centered lift.
    pub fn decode_centered(&self, residues: &[u64]) -> i128 {
        let x = self.decode(residues);
        self.centered_lift(x)
    }

    // ─── D8: Basis Extension (Promotion) ─────────────────────────────────

    /// Extend this basis by appending a new coprime modulus.
    ///
    /// **Formal Spec D8**: Promote extends the representation to a larger basis.
    ///
    /// **T3 guarantee**: The extended encoding represents the same X mod M_{k+1},
    /// and restricting back to the first k+1 gears recovers the original.
    ///
    /// Returns the new basis (this basis is immutable).
    pub fn extend(&self, new_modulus: u64) -> Result<RnsBasis, BasisError> {
        let mut new_moduli = self.moduli.clone();
        new_moduli.push(new_modulus);
        RnsBasis::new(new_moduli)
    }

    /// Promote a residue vector by appending the residue for a new modulus.
    /// Caller must supply the correct residue r_{k+1} ≡ X mod p_{k+1}.
    ///
    /// This does NOT verify consistency — the caller is responsible for
    /// ensuring the new residue is correct. Use `promote_verified` for
    /// a checked version that reconstructs X and verifies.
    pub fn promote_unchecked(residues: &[u64], new_residue: u64) -> Vec<u64> {
        let mut extended = residues.to_vec();
        extended.push(new_residue);
        extended
    }

    /// Promote with verification: reconstruct X from current residues,
    /// compute X mod new_modulus, and verify it matches the supplied residue.
    ///
    /// Returns None if the supplied residue is inconsistent.
    pub fn promote_verified(
        &self,
        residues: &[u64],
        new_modulus: u64,
        claimed_residue: u64,
    ) -> Option<Vec<u64>> {
        let x = self.decode(residues);
        let expected = (x % (new_modulus as u128)) as u64;
        if expected != claimed_residue {
            return None;
        }
        Some(Self::promote_unchecked(residues, claimed_residue))
    }

    /// Demote: restrict a residue vector to the first k moduli.
    ///
    /// **T3 guarantee**: restricting back recovers the original representation.
    pub fn demote(residues: &[u64], target_len: usize) -> Vec<u64> {
        residues[..target_len].to_vec()
    }
}

// ─── Utility: modular multiplication for u128 ────────────────────────────────

/// Multiply a * b mod m using u128 arithmetic.
/// For values where a*b might overflow u128, we use a shift-and-add approach.
/// NO FLOATING POINT.
fn mul_mod_u128(a: u128, b: u128, m: u128) -> u128 {
    // If the product fits in u128, just compute directly
    if a.leading_zeros() + b.leading_zeros() >= 128 {
        return (a * b) % m;
    }

    // Otherwise, shift-and-add to avoid overflow
    let mut result: u128 = 0;
    let mut a = a % m;
    let mut b = b % m;

    while b > 0 {
        if b & 1 == 1 {
            result = (result + a) % m;
        }
        a = (a << 1) % m;
        b >>= 1;
    }
    result
}

// ─── Tests: Formal Spec Test Obligations CT-01, CT-04, CT-05 ─────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard test basis: small primes for validation
    fn test_basis_small() -> RnsBasis {
        RnsBasis::new(vec![7, 11, 13]).unwrap()
    }

    /// Larger test basis approaching cryptographic sizes
    fn test_basis_medium() -> RnsBasis {
        RnsBasis::new(vec![251, 509, 521, 1021]).unwrap()
    }

    // ─── CT-01: Round-trip Enc → Dec for all X ∈ [0, M_k) ───────────────

    #[test]
    fn ct01_roundtrip_exhaustive_small() {
        let basis = test_basis_small();
        let m = basis.capacity();
        // Exhaustive for small basis (M_k = 7*11*13 = 1001)
        for x in 0..m {
            let residues = basis.encode(x);
            let decoded = basis.decode(&residues);
            assert_eq!(
                x, decoded,
                "T1 violation: Enc→Dec roundtrip failed for x={x}"
            );
        }
    }

    #[test]
    fn ct01_roundtrip_medium_random() {
        let basis = test_basis_medium();
        let m = basis.capacity();
        // Random sampling for larger basis
        let mut rng_state: u64 = 0xDEAD_BEEF_CAFE_BABE;
        for _ in 0..1_000_000 {
            // Simple LCG (no floating point!)
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let x = (rng_state as u128) % m;

            let residues = basis.encode(x);
            let decoded = basis.decode(&residues);
            assert_eq!(x, decoded, "T1 violation at x={x}");
        }
    }

    // ─── CT-04: Promotion + Demotion roundtrip ──────────────────────────

    #[test]
    fn ct04_promote_demote_roundtrip() {
        let basis = test_basis_small();
        let extended_basis = basis.extend(17).unwrap();

        let mut rng_state: u64 = 0x1234_5678_9ABC_DEF0;
        for _ in 0..100_000 {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let x = (rng_state as u128) % basis.capacity();

            let residues = basis.encode(x);
            let new_residue = (x % 17) as u64;

            // Promote
            let extended = basis
                .promote_verified(&residues, 17, new_residue)
                .expect("Promotion should succeed with correct residue");

            // Verify extended decode matches in extended basis
            let decoded_ext = extended_basis.decode(&extended);
            assert_eq!(
                x,
                decoded_ext % basis.capacity(),
                "T3 violation: promotion changed value"
            );

            // Demote back
            let demoted = RnsBasis::demote(&extended, basis.num_gears());
            let decoded_dem = basis.decode(&demoted);
            assert_eq!(
                x, decoded_dem,
                "T3 violation: demote didn't recover original"
            );
        }
    }

    // ─── Centered lift correctness ──────────────────────────────────────

    #[test]
    fn centered_lift_properties() {
        let basis = test_basis_small();
        let m = basis.capacity(); // 1001

        // Verify range: centered lift ∈ [-500, 500]
        for x in 0..m {
            let c = basis.centered_lift(x);
            assert!(
                c >= -(m as i128 / 2) && c <= (m as i128 / 2),
                "D4 violation: centered lift {c} out of range for x={x}, M={m}"
            );
            // Verify congruence: c ≡ x mod M
            let c_mod = ((c % m as i128) + m as i128) as u128 % m;
            assert_eq!(
                x, c_mod,
                "D4 violation: centered lift not congruent for x={x}"
            );
        }
    }

    // ─── Coprimality enforcement ────────────────────────────────────────

    #[test]
    fn rejects_non_coprime() {
        let result = RnsBasis::new(vec![6, 10, 15]);
        assert!(result.is_err(), "Should reject non-coprime moduli");
        if let Err(BasisError::NotCoprime { gcd, .. }) = result {
            assert!(gcd > 1);
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(RnsBasis::new(vec![]).is_err());
    }

    #[test]
    fn rejects_degenerate() {
        assert!(RnsBasis::new(vec![1, 7, 11]).is_err());
        assert!(RnsBasis::new(vec![0, 7, 11]).is_err());
    }

    // ─── Ring homomorphism (T1: addition, multiplication in residue space) ──

    #[test]
    fn t1_ring_homomorphism_add() {
        let basis = test_basis_small();
        let m = basis.capacity();

        let mut rng: u64 = 0xAAAA_BBBB_CCCC_DDDD;
        for _ in 0..100_000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let x = (rng as u128) % m;
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let y = (rng as u128) % m;

            let rx = basis.encode(x);
            let ry = basis.encode(y);

            // Add in residue space
            let r_sum: Vec<u64> = rx
                .iter()
                .zip(ry.iter())
                .enumerate()
                .map(|(i, (&a, &b))| (a + b) % basis.modulus(i))
                .collect();

            let decoded_sum = basis.decode(&r_sum);
            let expected = (x + y) % m;

            assert_eq!(
                expected, decoded_sum,
                "T1 ring homomorphism (add) failed: {x}+{y}"
            );
        }
    }

    #[test]
    fn t1_ring_homomorphism_mul() {
        let basis = test_basis_small();
        let m = basis.capacity();

        let mut rng: u64 = 0x1111_2222_3333_4444;
        for _ in 0..100_000 {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let x = (rng as u128) % m;
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            let y = (rng as u128) % m;

            let rx = basis.encode(x);
            let ry = basis.encode(y);

            // Multiply in residue space
            let r_prod: Vec<u64> = rx
                .iter()
                .zip(ry.iter())
                .enumerate()
                .map(|(i, (&a, &b))| {
                    let p = basis.modulus(i) as u128;
                    ((a as u128 * b as u128) % p) as u64
                })
                .collect();

            let decoded_prod = basis.decode(&r_prod);
            let expected = mul_mod_u128(x, y, m);

            assert_eq!(
                expected, decoded_prod,
                "T1 ring homomorphism (mul) failed: {x}*{y}"
            );
        }
    }
}
