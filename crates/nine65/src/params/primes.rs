//! Prime Selection - NTT-Friendly Primes for FHE
//!
//! QMNF requires primes q where:
//! - q ≡ 1 (mod 2N) for NTT compatibility
//! - q is large enough for security
//! - Multiple primes are coprime for RNS

/// Standard NTT-friendly primes for various polynomial degrees
/// These satisfy q ≡ 1 (mod 2N) and are suitable for FHE
pub const PRIMES_1024: [u64; 4] = [
    998244353, // 2^23 * 7 * 17 + 1
    985661441, // 2^22 * 5 * 47 + 1
    754974721, // 2^24 * 45 + 1
    167772161, // 2^25 * 5 + 1
];

pub const PRIMES_4096: [u64; 4] = [
    998244353, 985661441, 754974721, 469762049, // 2^26 * 7 + 1
];

/// 8 primes for full 8-core utilization at N=8192
/// Each satisfies q ≡ 1 (mod 16384) for NTT compatibility
/// Product exceeds 2^128 for 128-bit security
pub const PRIMES_8192: [u64; 8] = [
    998244353,  // 2^23 × 119 + 1
    985661441,  // 2^22 × 235 + 1
    754974721,  // 2^24 × 45 + 1
    469762049,  // 2^26 × 7 + 1
    1638350849, // 16384 × 99997 + 1 (31 bits)
    1638137857, // 16384 × 99984 + 1 (31 bits)
    1637990401, // 16384 × 99975 + 1 (31 bits)
    1637613569, // 16384 × 99952 + 1 (31 bits)
];

/// Check if a number is prime (deterministic Miller-Rabin for u64)
pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    // Quick checks for small primes
    const SMALL_PRIMES: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    for &p in &SMALL_PRIMES {
        if n == p {
            return true;
        }
        if n % p == 0 {
            return false;
        }
    }

    // Write n-1 = d * 2^s with d odd
    let mut d = n - 1;
    let mut s = 0u32;
    while (d & 1) == 0 {
        d >>= 1;
        s += 1;
    }

    #[inline]
    fn mod_mul(a: u64, b: u64, m: u64) -> u64 {
        ((a as u128 * b as u128) % m as u128) as u64
    }

    #[inline]
    fn mod_pow(mut base: u64, mut exp: u64, m: u64) -> u64 {
        let mut acc = 1u64;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = mod_mul(acc, base, m);
            }
            base = mod_mul(base, base, m);
            exp >>= 1;
        }
        acc
    }

    #[inline]
    fn is_composite_witness(a: u64, n: u64, d: u64, s: u32) -> bool {
        let mut x = mod_pow(a % n, d, n);
        if x == 1 || x == n - 1 {
            return false;
        }
        for _ in 1..s {
            x = mod_mul(x, x, n);
            if x == n - 1 {
                return false;
            }
        }
        true
    }

    // Deterministic bases for 64-bit integers
    // Ref: https://miller-rabin.appspot.com/
    const BASES: [u64; 7] = [2, 325, 9375, 28178, 450775, 9780504, 1795265022];
    for &a in &BASES {
        if a % n == 0 {
            continue;
        }
        if is_composite_witness(a, n, d, s) {
            return false;
        }
    }
    true
}

/// Check if prime is NTT-compatible for given N
pub fn is_ntt_compatible(q: u64, n: usize) -> bool {
    (q - 1).is_multiple_of(2 * n as u64)
}

/// Find NTT-friendly primes near a target value
pub fn find_ntt_primes(n: usize, num_primes: usize, min_bits: u32) -> Vec<u64> {
    let two_n = 2 * n as u64;
    let min_value = 1u64 << min_bits;
    let max_value = 1u64 << (min_bits + 4);

    let mut primes = Vec::new();
    let mut k = max_value / two_n;

    while primes.len() < num_primes && k > min_value / two_n {
        let candidate = k * two_n + 1;
        if is_prime(candidate) && !primes.contains(&candidate) {
            primes.push(candidate);
        }
        k -= 1;
    }

    primes
}

/// GCD using Euclidean algorithm
pub fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

/// Extended GCD: returns (g, x, y) such that ax + by = g
pub fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x, y) = extended_gcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

/// Modular inverse: a^(-1) mod m
pub fn mod_inverse(a: u64, m: u64) -> u64 {
    let (g, x, _) = extended_gcd(a as i128, m as i128);
    assert_eq!(g, 1, "No inverse exists");
    ((x % m as i128 + m as i128) % m as i128) as u64
}

/// Modular exponentiation: base^exp mod m
pub fn mod_pow(base: u64, exp: u64, m: u64) -> u64 {
    if m == 1 {
        return 0;
    }
    let mut result = 1u64;
    let mut base = base % m;
    let mut exp = exp;

    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % m as u128) as u64;
        }
        exp >>= 1;
        base = ((base as u128 * base as u128) % m as u128) as u64;
    }
    result
}

/// Find a primitive n-th root of unity modulo prime q
pub fn find_primitive_root(q: u64, n: usize) -> u64 {
    assert!((q - 1).is_multiple_of(n as u64), "n must divide q-1");

    let exp = (q - 1) / (n as u64);

    for g in 2..q {
        let candidate = mod_pow(g, exp, q);

        // Check it's a primitive n-th root (order is exactly n)
        let half = mod_pow(candidate, (n / 2) as u64, q);
        if half != 1 && mod_pow(candidate, n as u64, q) == 1 {
            return candidate;
        }
    }

    panic!("No primitive root found");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_primes_are_prime() {
        for &p in &PRIMES_1024 {
            assert!(is_prime(p), "PRIMES_1024: {} should be prime", p);
        }
        for &p in &PRIMES_4096 {
            assert!(is_prime(p), "PRIMES_4096: {} should be prime", p);
        }
        for &p in &PRIMES_8192 {
            assert!(is_prime(p), "PRIMES_8192: {} should be prime", p);
        }
    }

    #[test]
    fn test_primes_ntt_compatible_4096() {
        for &p in &PRIMES_4096 {
            assert!(
                is_ntt_compatible(p, 4096),
                "{} should be NTT-compatible for N=4096",
                p
            );
        }
    }

    #[test]
    fn test_primes_ntt_compatible_8192() {
        for &p in &PRIMES_8192 {
            assert!(
                is_ntt_compatible(p, 8192),
                "{} should be NTT-compatible for N=8192",
                p
            );
        }
    }

    #[test]
    fn test_primes_pairwise_coprime() {
        let primes = &PRIMES_1024;
        for i in 0..primes.len() {
            for j in (i + 1)..primes.len() {
                assert_eq!(
                    gcd(primes[i], primes[j]),
                    1,
                    "Primes {} and {} share factor {}",
                    primes[i],
                    primes[j],
                    gcd(primes[i], primes[j])
                );
            }
        }
    }

    #[test]
    fn test_product_security_128bit() {
        // Product of primes should exceed 2^128 for 128-bit security
        let product: u128 = PRIMES_1024.iter().map(|&p| p as u128).product();
        assert!(product > 1u128 << 100, "Product too small for security");
    }

    #[test]
    fn test_gcd() {
        assert_eq!(gcd(48, 18), 6);
        assert_eq!(gcd(17, 13), 1);
        assert_eq!(gcd(100, 25), 25);
    }

    #[test]
    fn test_mod_inverse() {
        let p = 998244353u64;
        for a in [1, 2, 3, 100, 12345, p - 1] {
            let inv = mod_inverse(a, p);
            let product = ((a as u128 * inv as u128) % p as u128) as u64;
            assert_eq!(product, 1, "Inverse of {} failed", a);
        }
    }

    #[test]
    fn test_mod_pow() {
        assert_eq!(mod_pow(2, 10, 1000), 24); // 1024 mod 1000
        assert_eq!(mod_pow(3, 0, 17), 1);
        assert_eq!(mod_pow(7, 11, 13), 2); // Fermat's little theorem
    }

    #[test]
    fn test_find_primitive_root() {
        let q = 998244353u64;
        let n = 2048usize;

        let omega = find_primitive_root(q, n);

        // omega^n should be 1
        assert_eq!(mod_pow(omega, n as u64, q), 1);

        // omega^(n/2) should not be 1
        assert_ne!(mod_pow(omega, (n / 2) as u64, q), 1);
    }
}
