//! # Math Utils — Unified Core Mathematical Primitives
//!
//! Single source of truth for modular arithmetic, primality testing, GCD, and
//! modular inverse. All QMNF, CRAM, and Hydra crates depend on this instead of
//! duplicating primitives.
//!
//! ## Zero-Float Guarantee
//!
//! All operations use exact integer arithmetic. No floating-point operations.

#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]

// ============================================================================
// MODULAR ARITHMETIC
// ============================================================================

/// Addition mod m, overflow-safe via u128 promotion.
#[inline]
pub fn addmod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 + b as u128) % m as u128) as u64
}

/// Subtraction mod m, overflow-safe.
#[inline]
pub fn submod(a: u64, b: u64, m: u64) -> u64 {
    if a >= b {
        (a - b) % m
    } else {
        m - ((b - a) % m)
    }
}

/// Multiplication mod m, overflow-safe via u128 promotion.
#[inline]
pub fn mulmod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

/// Modular exponentiation via binary method.
pub fn mod_pow(mut base: u64, mut exp: u64, m: u64) -> u64 {
    if m == 1 {
        return 0;
    }
    let mut result = 1u64;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mulmod(result, base, m);
        }
        exp >>= 1;
        if exp > 0 {
            base = mulmod(base, base, m);
        }
    }
    result
}

/// GCD via Stein's binary algorithm (branchless-friendly).
pub fn gcd(mut a: u64, mut b: u64) -> u64 {
    if a == 0 {
        return b;
    }
    if b == 0 {
        return a;
    }
    let shift = (a | b).trailing_zeros();
    a >>= a.trailing_zeros();
    loop {
        b >>= b.trailing_zeros();
        if a > b {
            std::mem::swap(&mut a, &mut b);
        }
        b -= a;
        if b == 0 {
            return a << shift;
        }
    }
}

/// Modular inverse via Extended Euclidean Algorithm.
/// Returns `Some(x)` where `a * x ≡ 1 (mod m)`, or `None` if `gcd(a, m) != 1`.
pub fn mod_inverse(a: u64, m: u64) -> Option<u64> {
    if a == 0 || m == 0 {
        return None;
    }
    let (mut old_r, mut r) = (a as i128, m as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    while r != 0 {
        let q = old_r / r;
        let tmp_r = r;
        r = old_r - q * r;
        old_r = tmp_r;
        let tmp_s = s;
        s = old_s - q * s;
        old_s = tmp_s;
    }
    if old_r != 1 {
        return None;
    }
    let result = ((old_s % m as i128) + m as i128) as u128 % m as u128;
    Some(result as u64)
}

// ============================================================================
// PRIMALITY TESTING
// ============================================================================

/// Deterministic primality test (trial division, sufficient for sieve range).
pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n < 4 {
        return true;
    }
    if n % 2 == 0 || n % 3 == 0 {
        return false;
    }
    let mut i = 5u64;
    while i.saturating_mul(i) <= n {
        if n % i == 0 || n % (i + 2) == 0 {
            return false;
        }
        i += 6;
    }
    true
}

// ============================================================================
// GARNER RECONSTRUCTION
// ============================================================================

/// Reconstruct a value from its CRT residues using Garner's algorithm.
/// Given residues r_i and moduli m_i, returns the unique value X < ∏m_i
/// such that X ≡ r_i (mod m_i) for all i.
pub fn garner_reconstruct(residues: &[u64], moduli: &[u64]) -> u128 {
    let k = residues.len();
    if k == 0 {
        return 0;
    }
    if k == 1 {
        return residues[0] as u128;
    }

    let mut v = vec![0u64; k];
    v[0] = residues[0];

    for i in 1..k {
        let mi = moduli[i];
        let mut temp = residues[i] % mi;
        for j in 0..i {
            let vj = v[j] % mi;
            if temp < vj {
                temp += mi;
            }
            temp -= vj;
            let mj_inv = mod_inverse(moduli[j] % mi, mi)
                .expect("moduli must be pairwise coprime");
            temp = mulmod(temp, mj_inv, mi);
        }
        v[i] = temp;
    }

    let mut result = v[0] as u128;
    let mut product = moduli[0] as u128;
    for i in 1..k {
        result += v[i] as u128 * product;
        product *= moduli[i] as u128;
    }
    result
}

// ============================================================================
// K-ELIMINATION
// ============================================================================

/// K-Elimination: recover winding number k from two coprime residues.
/// Given X ≡ r (mod m) and X ≡ s (mod a) where gcd(m, a) = 1,
/// returns k such that X = r + k*m, unique for 0 ≤ X < m*a.
pub fn k_eliminate(r: u64, s: u64, m: u64, a: u64) -> u64 {
    debug_assert_eq!(gcd(m, a), 1, "m and a must be coprime");
    let m_inv = mod_inverse(m % a, a).expect("m must be invertible mod a");
    mulmod(submod(s % a, r % a, a), m_inv, a)
}

/// Reconstruct X from two coprime residues via K-Elimination.
pub fn k_reconstruct(r: u64, s: u64, m: u64, a: u64) -> u128 {
    r as u128 + k_eliminate(r, s, m, a) as u128 * m as u128
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addmod() {
        assert_eq!(addmod(5, 7, 10), 2);
        assert_eq!(addmod(u64::MAX, 1, u64::MAX), 1);
        assert_eq!(addmod(0, 0, 7), 0);
    }

    #[test]
    fn test_submod() {
        assert_eq!(submod(3, 7, 10), 6);
        assert_eq!(submod(7, 3, 10), 4);
        assert_eq!(submod(0, 0, 7), 0);
    }

    #[test]
    fn test_mulmod() {
        assert_eq!(mulmod(7, 8, 10), 6);
        assert_eq!(mulmod(0, 12345, 7), 0);
    }

    #[test]
    fn test_mod_pow() {
        assert_eq!(mod_pow(2, 10, 1000), 24); // 1024 mod 1000
        assert_eq!(mod_pow(3, 0, 7), 1);
        assert_eq!(mod_pow(0, 5, 7), 0);
    }

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(12, 8), 4);
        assert_eq!(gcd(7, 13), 1);
        assert_eq!(gcd(0, 5), 5);
        assert_eq!(gcd(5, 0), 5);
    }

    #[test]
    fn test_mod_inverse() {
        assert_eq!(mod_inverse(3, 11), Some(4));   // 3·4 = 12 ≡ 1 (mod 11)
        assert_eq!(mod_inverse(7, 13), Some(2));   // 7·2 = 14 ≡ 1 (mod 13)
        assert_eq!(mod_inverse(0, 7), None);
        assert_eq!(mod_inverse(6, 9), None);       // gcd(6,9) = 3

        // Verify for all invertible elements mod 13
        for a in 1..13u64 {
            let inv = mod_inverse(a, 13).unwrap();
            assert_eq!(mulmod(a, inv, 13), 1, "inverse of {a} mod 13 failed");
        }
    }

    #[test]
    fn test_is_prime() {
        let primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];
        for &p in &primes {
            assert!(is_prime(p), "{p} should be prime");
        }
        let composites = [0, 1, 4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21, 22];
        for &c in &composites {
            assert!(!is_prime(c), "{c} should not be prime");
        }
    }

    #[test]
    fn test_garner_small() {
        let primes = vec![2, 3, 5, 7];
        for v in [0u64, 1, 42, 100, 209] {
            let res: Vec<u64> = primes.iter().map(|&p| v % p).collect();
            assert_eq!(garner_reconstruct(&res, &primes), v as u128, "failed for v={v}");
        }
    }

    #[test]
    fn test_garner_s6() {
        let primes = vec![2, 3, 5, 7, 11, 13];
        for v in [0u64, 1, 42, 12345, 30029] {
            let res: Vec<u64> = primes.iter().map(|&p| v % p).collect();
            assert_eq!(garner_reconstruct(&res, &primes), v as u128, "failed for v={v}");
        }
    }

    #[test]
    fn test_k_elimination_roundtrip() {
        let vals = [0u64, 1, 35, 42, 76];
        for &v in &vals {
            let m = 7u64;
            let a = 11u64;
            assert_eq!(
                k_reconstruct(v % m, v % a, m, a),
                v as u128,
                "k-reconstruct failed for v={v}"
            );
        }
    }

    #[test]
    fn test_k_elimination_exhaustive() {
        let m = 7u64;
        let a = 11u64;
        for v in 0..(m * a) {
            assert_eq!(k_reconstruct(v % m, v % a, m, a), v as u128);
        }
    }
}
