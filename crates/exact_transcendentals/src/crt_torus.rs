//! CRT Torus — Configurable Exploration Substrate
//!
//! A CRT torus Z/P_odd x Z/2^k with arbitrary odd-prime sets,
//! dynamic 2-power depth k, and K-Elimination lift/project operations.
//!
//! Zero floating point. All arithmetic exact integer (A1).

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, vec::Vec};
#[cfg(feature = "std")]
use std::vec::Vec;

use core::fmt;

use crate::k_elim::{self, KElimResult};

/// A point on the CRT torus: (r_odd, r_2) where
/// r_odd in Z/P_odd and r_2 in Z/2^k.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TorusPoint {
    pub r_odd: i128,
    pub r_2: i128,
}

impl TorusPoint {
    pub fn new(r_odd: i128, r_2: i128) -> Self {
        TorusPoint { r_odd, r_2 }
    }
}

impl fmt::Display for TorusPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({},{})", self.r_odd, self.r_2)
    }
}

/// Configuration for a CRT torus.
#[derive(Clone, Debug)]
pub struct TorusConfig {
    pub odd_primes: Vec<i128>,
    pub p_odd: i128,
    pub k: u32,
    pub p_two: i128,
    pub total: i128,
    pub inv2_mod_p_odd: i128,
    pub inv_p_odd_mod_p2: i128,
}

impl TorusConfig {
    pub fn new(odd_primes: &[i128], k: u32) -> Self {
        assert!(!odd_primes.is_empty(), "Need at least one odd prime");
        assert!(
            odd_primes.iter().all(|&p| p > 2 && p % 2 == 1),
            "All primes must be odd and > 2"
        );

        let p_odd: i128 = odd_primes.iter().product();
        let p_two: i128 = 1i128 << k;
        let total = p_odd * p_two;

        for i in 0..odd_primes.len() {
            for j in (i + 1)..odd_primes.len() {
                assert_eq!(
                    k_elim::gcd(odd_primes[i], odd_primes[j]),
                    1,
                    "Primes must be pairwise coprime: {} and {}",
                    odd_primes[i],
                    odd_primes[j]
                );
            }
        }

        let inv2_mod_p_odd = k_elim::mod_inv(2, p_odd).expect("2 invertible mod odd product");
        let inv_p_odd_mod_p2 = k_elim::mod_inv(k_elim::modd(p_odd, p_two), p_two)
            .expect("p_odd invertible mod 2^k");

        TorusConfig {
            odd_primes: odd_primes.to_vec(),
            p_odd,
            k,
            p_two,
            total,
            inv2_mod_p_odd,
            inv_p_odd_mod_p2,
        }
    }

    /// Standard (3,5,7) x 2^k torus.
    pub fn standard_357(k: u32) -> Self {
        Self::new(&[3, 5, 7], k)
    }

    /// Safe Basis torus (3,5,7,11,13) x 2^k.
    pub fn safe_basis(k: u32) -> Self {
        Self::new(&[3, 5, 7, 11, 13], k)
    }

    /// S8 torus (3,5,7,11,13,17,19) x 2^k — excludes 2 since the torus
    /// already has a 2-power component.
    pub fn s8(k: u32) -> Self {
        Self::new(&[3, 5, 7, 11, 13, 17, 19], k)
    }

    /// Exact-lane torus (primes > 11) x 2^k.
    pub fn exact_lanes(primes: &[i128], k: u32) -> Self {
        assert!(
            primes.iter().all(|&p| p > 11),
            "Exact lanes require primes > 11"
        );
        Self::new(primes, k)
    }

    /// K-Elimination lift: given (r_odd, r_2), compute winding number
    /// and canonical representative in [0, total).
    pub fn k_elim_lift(&self, pt: TorusPoint) -> KElimResult {
        k_elim::k_eliminate(pt.r_odd, self.p_odd, pt.r_2, self.p_two)
            .expect("k_elim_lift: coprime torus components must succeed")
    }

    /// Project an integer n onto the torus.
    pub fn project(&self, n: i128) -> TorusPoint {
        TorusPoint {
            r_odd: k_elim::modd(n, self.p_odd),
            r_2: k_elim::modd(n, self.p_two),
        }
    }

    /// Decompose r_odd into per-prime residues.
    pub fn decompose_odd(&self, r_odd: i128) -> Vec<(i128, i128)> {
        self.odd_primes
            .iter()
            .map(|&p| (k_elim::modd(r_odd, p), p))
            .collect()
    }

    /// Carry pattern: for canonical lift n, compute floor(n/p) mod p per prime.
    pub fn carry_pattern(&self, n: i128) -> Vec<i128> {
        self.odd_primes.iter().map(|&p| (n / p) % p).collect()
    }

    /// Total state count.
    pub fn state_count(&self) -> i128 {
        self.total
    }

    /// Clone with different k (dynamic-k exploration).
    pub fn with_k(&self, new_k: u32) -> Self {
        Self::new(&self.odd_primes, new_k)
    }
}

impl fmt::Display for TorusConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let primes_str: Vec<_> = self.odd_primes.iter().map(|p| {
            let mut buf = [0u8; 40];
            let s = fmt_i128(*p, &mut buf);
            s.to_owned()
        }).collect();
        write!(
            f,
            "({})[{}] x 2^{} [{}]  total={}",
            primes_str.join("x"),
            self.p_odd,
            self.k,
            self.p_two,
            self.total
        )
    }
}

fn fmt_i128(val: i128, buf: &mut [u8; 40]) -> &str {
    use core::fmt::Write;
    struct BufWriter<'a> {
        buf: &'a mut [u8],
        pos: usize,
    }
    impl<'a> Write for BufWriter<'a> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let bytes = s.as_bytes();
            if self.pos + bytes.len() > self.buf.len() {
                return Err(fmt::Error);
            }
            self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
            self.pos += bytes.len();
            Ok(())
        }
    }
    let mut w = BufWriter { buf, pos: 0 };
    let _ = write!(w, "{}", val);
    let len = w.pos;
    core::str::from_utf8(&buf[..len]).unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_357() {
        let t = TorusConfig::standard_357(4);
        assert_eq!(t.p_odd, 105);
        assert_eq!(t.p_two, 16);
        assert_eq!(t.total, 1680);
        assert_eq!(k_elim::mulmod(t.inv2_mod_p_odd, 2, t.p_odd), 1);
    }

    #[test]
    fn kelim_lift() {
        let t = TorusConfig::standard_357(4);
        let r = t.k_elim_lift(TorusPoint::new(79, 10));
        assert_eq!(r.k, 3);
        assert_eq!(r.value, 394);
    }

    #[test]
    fn project_roundtrip() {
        let t = TorusConfig::standard_357(4);
        let pt = t.project(394);
        assert_eq!(pt.r_odd, 79);
        assert_eq!(pt.r_2, 10);
        let lifted = t.k_elim_lift(pt);
        assert_eq!(lifted.value, 394);
    }

    #[test]
    fn dynamic_k() {
        let t4 = TorusConfig::standard_357(4);
        let t8 = t4.with_k(8);
        assert_eq!(t8.p_odd, 105);
        assert_eq!(t8.p_two, 256);
        assert_eq!(t8.total, 105 * 256);
    }

    #[test]
    fn safe_basis_torus() {
        let t = TorusConfig::safe_basis(6);
        assert_eq!(t.p_odd, 3 * 5 * 7 * 11 * 13);
        assert_eq!(t.p_odd, 15015);
        assert_eq!(t.p_two, 64);
        assert_eq!(t.total, 15015 * 64);
    }

    #[test]
    fn s8_torus() {
        let t = TorusConfig::s8(4);
        assert_eq!(t.p_odd, 3 * 5 * 7 * 11 * 13 * 17 * 19);
        assert_eq!(t.p_odd, 4849845);
        assert_eq!(t.total, 4849845 * 16);
    }

    #[test]
    fn decompose_odd_basic() {
        let t = TorusConfig::standard_357(4);
        let pt = t.project(42);
        let decomp = t.decompose_odd(pt.r_odd);
        assert_eq!(decomp.len(), 3);
        assert_eq!(decomp[0], (42 % 3, 3)); // (0, 3)
        assert_eq!(decomp[1], (42 % 5, 5)); // (2, 5)
        assert_eq!(decomp[2], (42 % 7, 7)); // (0, 7)
    }

    #[test]
    fn project_negative() {
        let t = TorusConfig::standard_357(4);
        let pt = t.project(-1);
        assert_eq!(pt.r_odd, t.p_odd - 1);
        assert_eq!(pt.r_2, t.p_two - 1);
    }
}
