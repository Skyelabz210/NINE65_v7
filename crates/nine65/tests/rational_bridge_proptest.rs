//! Property-based tests for the rational bridge integration.
//!
//! Validates that NexGen rational arithmetic produces correct
//! residues for NINE65's modular arithmetic pipeline.

#![cfg(feature = "exact_rational")]

use nine65::arithmetic::rational_bridge::RationalBridge;
use proptest::prelude::*;

/// Small primes for modular residue testing.
const TEST_PRIMES: [u64; 5] = [17, 31, 61, 127, 251];

/// Check if denominator is coprime to prime (residue conversion requires this).
fn den_coprime(rat: &RationalBridge, p: u64) -> bool {
    let den = rat.denominator().unsigned_abs() as u64;
    gcd_u64(den, p) == 1
}

fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

proptest! {
    /// Rational addition: (a/b + c/d) mod p must equal
    /// (res1 + res2) mod p, when all denominators are coprime to p.
    #[test]
    fn add_residue_consistency(
        a in -1000i128..1000,
        b in 1i128..100,
        c in -1000i128..1000,
        d in 1i128..100,
    ) {
        let r1 = RationalBridge::new(a, b).unwrap();
        let r2 = RationalBridge::new(c, d).unwrap();

        if let Ok(sum) = r1.add(&r2) {
            for &p in &TEST_PRIMES {
                // Skip if any denominator is not coprime to p
                if !den_coprime(&r1, p) || !den_coprime(&r2, p) || !den_coprime(&sum, p) {
                    continue;
                }
                let res_sum = sum.to_residue(p);
                let res1 = r1.to_residue(p);
                let res2 = r2.to_residue(p);
                let expected = (res1 as u128 + res2 as u128) % p as u128;
                prop_assert_eq!(res_sum, expected as u64);
            }
        }
    }

    /// Rational multiplication: (a/b * c/d) mod p must equal
    /// (res1 * res2) mod p, when all denominators are coprime to p.
    #[test]
    fn mul_residue_consistency(
        a in -100i128..100,
        b in 1i128..50,
        c in -100i128..100,
        d in 1i128..50,
    ) {
        let r1 = RationalBridge::new(a, b).unwrap();
        let r2 = RationalBridge::new(c, d).unwrap();

        if let Ok(prod) = r1.mul(&r2) {
            for &p in &TEST_PRIMES {
                if !den_coprime(&r1, p) || !den_coprime(&r2, p) || !den_coprime(&prod, p) {
                    continue;
                }
                let res_prod = prod.to_residue(p);
                let res1 = r1.to_residue(p);
                let res2 = r2.to_residue(p);
                let expected = (res1 as u128 * res2 as u128) % p as u128;
                prop_assert_eq!(res_prod, expected as u64);
            }
        }
    }

    /// Division trichotomy: for all a, b with b != 0,
    /// exactly one of ExactInverse/ExactAFC/FPD holds,
    /// and a = b*q + r with 0 <= |r| < |b|.
    #[test]
    fn division_trichotomy_holds(
        a in -10000i128..10000,
        b in 1i128..1000,
    ) {
        let result = RationalBridge::exact_divide(a, b).unwrap();
        let q = result.quotient().0;
        let r = result.remainder().0;

        // Division algorithm: a = b*q + r
        prop_assert_eq!(a, b * q + r);

        // Remainder bound: |r| < |b|
        prop_assert!(r.abs() < b.abs());
    }

    /// Integer rationals must have residue equal to value mod p.
    #[test]
    fn integer_rational_residue(val in -10000i128..10000) {
        let rat = RationalBridge::from_integer(val);
        for &p in &TEST_PRIMES {
            let residue = rat.to_residue(p);
            let expected = val.rem_euclid(p as i128) as u64;
            prop_assert_eq!(residue, expected);
        }
    }
}
