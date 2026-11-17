/// arith.rs — Exact Integer Arithmetic Primitives for CRAM
///
/// The QMNF philosophical constraint: truth cannot be approximated.
/// Every function in this module operates strictly on i128 exact integers.
/// No floating-point operations exist anywhere in this file.
///
/// When larger primes are required, replace i128 with a CRTBigInt type
/// that implements the same trait surface (Add, Sub, Mul, Rem, etc.).

/// Canonical positive residue: maps any integer into [0, modulus).
/// This is used after every subtraction to prevent negative residues
/// from propagating through the lane pipeline.
#[inline(always)]
pub fn canonical(x: i128, m: i128) -> i128 {
    ((x % m) + m) % m
}

/// Extended Euclidean Algorithm.
/// Returns (gcd, s, t) satisfying: a*s + b*t = gcd.
/// This is the bedrock of modular inversion throughout the CRAM engine.
pub fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (g, s, t) = extended_gcd(b, a % b);
        // Back-substitution: s_new = t_old, t_new = s_old - (a/b)*t_old
        (g, t, s - (a / b) * t)
    }
}

/// Modular inverse of `a` mod `m`.
/// Returns None when gcd(a, m) > 1 — this is the signal for the
/// exceptional-set condition in DIV and INV operators.
pub fn mod_inverse(a: i128, m: i128) -> Option<i128> {
    let a_canon = canonical(a, m);
    let (g, s, _) = extended_gcd(a_canon, m);
    if g != 1 {
        None // no inverse — DIV/INV exceptional state
    } else {
        Some(canonical(s, m))
    }
}

/// Modular squaring with canonical output.
#[inline(always)]
pub fn mod_square(x: i128, m: i128) -> i128 {
    canonical(x * x, m)
}

/// Modular multiplication with canonical output.
#[inline(always)]
pub fn mod_mul(a: i128, b: i128, m: i128) -> i128 {
    canonical(a * b, m)
}

/// Modular addition with canonical output.
#[inline(always)]
pub fn mod_add(a: i128, b: i128, m: i128) -> i128 {
    canonical(a + b, m)
}

/// Modular subtraction with canonical output.
#[inline(always)]
pub fn mod_sub(a: i128, b: i128, m: i128) -> i128 {
    canonical(a - b, m)
}

/// Modular negation: -x ≡ m - x (mod m).
#[inline(always)]
pub fn mod_neg(x: i128, m: i128) -> i128 {
    if x == 0 { 0 } else { m - canonical(x, m) }
}

/// Check that a list of moduli are pairwise coprime — a topological
/// invariant required before constructing any CRAM topology.
pub fn pairwise_coprime(primes: &[i128]) -> bool {
    for i in 0..primes.len() {
        for j in (i + 1)..primes.len() {
            let (g, _, _) = extended_gcd(primes[i], primes[j]);
            if g != 1 {
                return false;
            }
        }
    }
    true
}

// ─── Unit tests for all arithmetic primitives ────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_negative() {
        // -1 mod 7 should canonicalize to 6, not -1
        assert_eq!(canonical(-1, 7), 6);
        assert_eq!(canonical(-11, 7), 3);
        assert_eq!(canonical(0, 7), 0);
    }

    #[test]
    fn test_extended_gcd_basic() {
        let (g, s, t) = extended_gcd(12, 8);
        assert_eq!(g, 4);
        // Verify Bezout: 12s + 8t = gcd
        assert_eq!(12 * s + 8 * t, g as i128);
    }

    #[test]
    fn test_mod_inverse_known() {
        // From the paper trace: 2^{-1} mod 7 = 4, because 2*4 = 8 ≡ 1 mod 7
        assert_eq!(mod_inverse(2, 7), Some(4));
        // 3^{-1} mod 5 = 2, because 3*2 = 6 ≡ 1 mod 5
        assert_eq!(mod_inverse(3, 5), Some(2));
        // C_2 from the Garner trace: p1^{-1} mod p2 = 2^{-1} mod 3 = 2
        assert_eq!(mod_inverse(2, 3), Some(2));
    }

    #[test]
    fn test_mod_inverse_exceptional() {
        // 0 has no inverse — this is the DIV exceptional-set trigger
        assert_eq!(mod_inverse(0, 7), None);
        // Non-prime moduli: gcd(6,9) = 3 > 1, no inverse
        assert_eq!(mod_inverse(6, 9), None);
    }

    #[test]
    fn test_mod_square() {
        // 5^2 = 25 ≡ 4 mod 7 — directly from the paper Phase 3 trace
        assert_eq!(mod_square(5, 7), 4);
        // 0^2 = 0 — SQR post-processor on zero inputs (Lanes 2,3 in trace)
        assert_eq!(mod_square(0, 3), 0);
        assert_eq!(mod_square(0, 5), 0);
    }

    #[test]
    fn test_pairwise_coprime_s4() {
        // CRAM-S4 primes {2,3,5,7} must be pairwise coprime
        assert!(pairwise_coprime(&[2, 3, 5, 7]));
    }

    #[test]
    fn test_pairwise_coprime_s6() {
        // CRAM-S6 primes {2,3,5,7,11,13}
        assert!(pairwise_coprime(&[2, 3, 5, 7, 11, 13]));
    }

    #[test]
    fn test_pairwise_coprime_rejects_composites() {
        // {6, 9} share factor 3 — should reject
        assert!(!pairwise_coprime(&[6, 9]));
    }
}
