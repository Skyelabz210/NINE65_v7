//! RNS - Residue Number System with Adaptive Multi-Prime Support
//!
//! CRTBigInt parallel coefficient operations enable
//! exact arithmetic on integers larger than any single prime modulus.

// Allow explicit indexing in RNS computations - loop indices are used
// in CRT reconstruction and multi-limb arithmetic, not just array access.
#![allow(clippy::needless_range_loop)]

use super::montgomery::MontgomeryContext;
#[cfg(feature = "ntt_fft")]
use super::ntt_fft::NTTEngineFFT as NTTEngine;
use zeroize::Zeroize;

#[cfg(not(feature = "ntt_fft"))]
use super::ntt::NTTEngine;

use core::cmp::Ordering;

/// Minimal 256-bit unsigned integer for intermediate reconstruction.
///
/// Representation: value = lo + hi * 2^128.
/// Only the operations needed by NINE65's K-Elimination / rescale path are implemented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct U256 {
    pub(crate) lo: u128,
    pub(crate) hi: u128,
}

impl U256 {
    #[inline]
    pub(crate) const fn zero() -> Self {
        Self { lo: 0, hi: 0 }
    }
    #[inline]
    pub(crate) const fn one() -> Self {
        Self { lo: 1, hi: 0 }
    }
    #[inline]
    pub(crate) const fn from_u64(x: u64) -> Self {
        Self {
            lo: x as u128,
            hi: 0,
        }
    }
    #[cfg(test)]
    #[inline]
    pub(crate) const fn from_u128(x: u128) -> Self {
        Self { lo: x, hi: 0 }
    }

    #[inline]
    pub(crate) fn is_zero(self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    #[inline]
    pub(crate) fn cmp(self, other: Self) -> Ordering {
        match self.hi.cmp(&other.hi) {
            Ordering::Equal => self.lo.cmp(&other.lo),
            o => o,
        }
    }

    #[inline]
    pub(crate) fn ge(self, other: Self) -> bool {
        self.cmp(other) != Ordering::Less
    }
    #[inline]
    pub(crate) fn gt(self, other: Self) -> bool {
        self.cmp(other) == Ordering::Greater
    }
    #[inline]
    pub(crate) fn le(self, other: Self) -> bool {
        self.cmp(other) != Ordering::Greater
    }

    #[inline]
    pub(crate) fn overflowing_add(self, other: Self) -> (Self, bool) {
        let (lo, c0) = self.lo.overflowing_add(other.lo);
        let (hi1, c1) = self.hi.overflowing_add(other.hi);
        let (hi, c2) = hi1.overflowing_add(if c0 { 1 } else { 0 });
        (Self { lo, hi }, c1 || c2)
    }

    #[inline]
    pub(crate) fn add(self, other: Self) -> Self {
        self.overflowing_add(other).0
    }

    #[inline]
    pub(crate) fn sub(self, other: Self) -> Self {
        debug_assert!(self.ge(other), "U256 underflow");
        let (lo, b0) = self.lo.overflowing_sub(other.lo);
        let hi = self.hi - other.hi - if b0 { 1 } else { 0 };
        Self { lo, hi }
    }

    #[inline]
    pub(crate) fn shr1(self) -> Self {
        let lo = (self.lo >> 1) | ((self.hi & 1) << 127);
        let hi = self.hi >> 1;
        Self { lo, hi }
    }

    #[inline]
    pub(crate) fn shl1(self) -> Self {
        let hi = (self.hi << 1) | (self.lo >> 127);
        let lo = self.lo << 1;
        Self { lo, hi }
    }

    #[inline]
    pub(crate) fn bitlen(self) -> u32 {
        if self.hi != 0 {
            256 - self.hi.leading_zeros()
        } else if self.lo != 0 {
            128 - self.lo.leading_zeros()
        } else {
            0
        }
    }

    #[inline]
    pub(crate) fn get_bit(self, i: u32) -> u32 {
        if i < 128 {
            ((self.lo >> i) & 1) as u32
        } else {
            ((self.hi >> (i - 128)) & 1) as u32
        }
    }

    #[inline]
    fn wide_mul_256(a: u128, b: u128) -> (u128, u128) {
        let a_lo = a as u64 as u128;
        let a_hi = (a >> 64) as u64 as u128;
        let b_lo = b as u64 as u128;
        let b_hi = (b >> 64) as u64 as u128;

        let lo_lo = a_lo * b_lo;
        let hi_lo = a_hi * b_lo;
        let lo_hi = a_lo * b_hi;
        let hi_hi = a_hi * b_hi;

        let (mid, mid_carry) = hi_lo.overflowing_add(lo_hi);
        let (result_lo, carry1) = lo_lo.overflowing_add(mid << 64);
        let carry2 = mid >> 64;
        // mid_carry means the true mid sum had bit 128 set (value 2^128).
        // In the full product, mid contributes at bit offset 64, so bit 128 of
        // mid lands at bit 192 of the product = bit 64 of result_hi.
        let mid_carry_hi = if mid_carry { 1u128 << 64 } else { 0 };
        let result_hi = hi_hi + carry2 + mid_carry_hi + if carry1 { 1 } else { 0 };

        (result_lo, result_hi)
    }

    /// Multiply by a u64, returning the low 256 bits.
    ///
    /// Exact when the true product fits in 256 bits (which is the case for all
    /// K-Elimination and CRT reconstruction paths in NINE65).  A debug_assert
    /// fires if the product overflows 256 bits.
    #[inline]
    pub(crate) fn mul_u64(self, m: u64) -> Self {
        let b = m as u128;
        let (p0_lo, p0_hi) = Self::wide_mul_256(self.lo, b);
        let (p1_lo, p1_hi) = Self::wide_mul_256(self.hi, b);
        let (hi, carry) = p0_hi.overflowing_add(p1_lo);
        debug_assert!(
            p1_hi == 0 && !carry,
            "U256::mul_u64 overflow: product exceeds 256 bits"
        );
        Self { lo: p0_lo, hi }
    }

    /// Multiply two U256 values and return the low 256 bits.
    #[inline]
    pub(crate) fn mul_low(self, other: Self) -> Self {
        let (p00_lo, p00_hi) = Self::wide_mul_256(self.lo, other.lo);
        let (p01_lo, _) = Self::wide_mul_256(self.lo, other.hi);
        let (p10_lo, _) = Self::wide_mul_256(self.hi, other.lo);
        let (cross, _) = p01_lo.overflowing_add(p10_lo);
        let (hi, _) = p00_hi.overflowing_add(cross);
        Self { lo: p00_lo, hi }
    }

    /// value mod m where m fits in u64 (as used for primes).
    #[inline]
    pub(crate) fn mod_u64(self, m: u64) -> u64 {
        let m128 = m as u128;
        if m128 == 0 {
            return 0;
        }
        // 2^128 mod m = (2^64 mod m)^2 mod m
        let two64 = (1u128 << 64) % m128;
        let two128 = (two64 * two64) % m128;
        let hi_mod = self.hi % m128;
        let lo_mod = self.lo % m128;
        let rem = (hi_mod * two128 + lo_mod) % m128;
        rem as u64
    }

    /// Divide by u64, returning (quotient, remainder).
    pub(crate) fn div_mod_u64(self, d: u64) -> (Self, u64) {
        assert!(d != 0, "division by zero");
        let d128 = d as u128;

        // Work in base 2^64 limbs: [w0, w1, w2, w3] least->most significant.
        let w0 = self.lo as u64;
        let w1 = (self.lo >> 64) as u64;
        let w2 = self.hi as u64;
        let w3 = (self.hi >> 64) as u64;

        let mut rem: u128 = 0;
        // limb 3
        let acc3 = (rem << 64) | (w3 as u128);
        let q3 = (acc3 / d128) as u64;
        rem = acc3 % d128;

        // limb 2
        let acc2 = (rem << 64) | (w2 as u128);
        let q2 = (acc2 / d128) as u64;
        rem = acc2 % d128;

        // limb 1
        let acc1 = (rem << 64) | (w1 as u128);
        let q1 = (acc1 / d128) as u64;
        rem = acc1 % d128;

        // limb 0
        let acc0 = (rem << 64) | (w0 as u128);
        let q0 = (acc0 / d128) as u64;
        rem = acc0 % d128;

        let q_lo = (q0 as u128) | ((q1 as u128) << 64);
        let q_hi = (q2 as u128) | ((q3 as u128) << 64);

        (Self { lo: q_lo, hi: q_hi }, rem as u64)
    }

    /// Remainder of self divided by modulus (modulus != 0).
    /// Uses bitwise long division; 256 steps worst case.
    pub(crate) fn rem_u256(self, modulus: Self) -> Self {
        assert!(!modulus.is_zero(), "mod by zero");
        if self.lt(modulus) {
            return self;
        }
        let mut rem = Self::zero();
        let bl = self.bitlen();
        for i in (0..bl).rev() {
            rem = rem.shl1();
            if self.get_bit(i) == 1 {
                rem.lo |= 1;
            }
            if rem.ge(modulus) {
                rem = rem.sub(modulus);
            }
        }
        rem
    }

    #[inline]
    pub(crate) fn lt(self, other: Self) -> bool {
        self.cmp(other) == Ordering::Less
    }

    /// (a + b) mod m, with a,b < m
    #[inline]
    pub(crate) fn add_mod(self, other: Self, m: Self) -> Self {
        let (sum, _) = self.overflowing_add(other);
        if sum.ge(m) {
            sum.sub(m)
        } else {
            sum
        }
    }

    /// (a - b) mod m, with a,b < m
    #[inline]
    pub(crate) fn sub_mod(self, other: Self, m: Self) -> Self {
        if self.ge(other) {
            self.sub(other)
        } else {
            m.sub(other.sub(self))
        }
    }

    /// Product of a slice of u64s (exact as long as the true product fits in 256 bits).
    pub(crate) fn product_u64s(values: &[u64]) -> Self {
        let mut acc = Self::one();
        for &v in values {
            acc = acc.mul_u64(v);
        }
        acc
    }
}

/// Compute Δ = floor(Q/t) in RNS form without relying on u128-sized Q.
pub(crate) fn compute_delta_rns_overflow_safe(primes: &[u64], t: u64) -> Vec<u64> {
    assert!(t != 0, "Plaintext modulus t must be > 0");
    let q = U256::product_u64s(primes);
    let (delta, _) = q.div_mod_u64(t);
    primes.iter().map(|&p| delta.mod_u64(p)).collect()
}

/// RNS Context for managing multiple prime moduli
pub struct RNSContext {
    /// List of coprime moduli
    pub primes: Vec<u64>,
    /// Product of all primes (as u128, may overflow for many primes)
    pub product: u128,
    /// Montgomery contexts for each prime
    pub mont_contexts: Vec<MontgomeryContext>,
    /// NTT engines for each prime
    pub ntt_engines: Vec<NTTEngine>,
    /// Polynomial degree
    pub n: usize,
    /// Precomputed CRT reconstruction values
    /// For each prime q_i: M_i = (product / q_i), M_i_inv = M_i^(-1) mod q_i
    pub crt_values: Vec<(u128, u64)>,
}

impl RNSContext {
    /// Create a new RNS context from a list of primes
    pub fn new(primes: Vec<u64>, n: usize) -> Self {
        assert!(!primes.is_empty(), "Need at least one prime");
        assert!(n.is_power_of_two(), "N must be power of 2");

        // Verify primes are coprime (all distinct primes are coprime)
        for i in 0..primes.len() {
            for j in (i + 1)..primes.len() {
                assert_ne!(primes[i], primes[j], "Primes must be distinct");
            }
        }

        // Compute product (may overflow for many primes - use checked mul)
        let product = primes
            .iter()
            .try_fold(1u128, |acc, &p| acc.checked_mul(p as u128))
            .unwrap_or(0); // 0 indicates overflow

        // Create Montgomery and NTT contexts
        let mont_contexts: Vec<_> = primes.iter().map(|&p| MontgomeryContext::new(p)).collect();

        let ntt_engines: Vec<_> = primes.iter().map(|&p| NTTEngine::new(p, n)).collect();

        // Precompute CRT values (only if product fits in u128)
        let crt_values: Vec<_> = if product > 0 {
            primes
                .iter()
                .map(|&qi| {
                    let mi = product / qi as u128;
                    let mi_mod_qi = (mi % qi as u128) as u64;
                    let mi_inv = mod_inverse(mi_mod_qi, qi);
                    (mi, mi_inv)
                })
                .collect()
        } else {
            // Product overflow - CRT not usable, set dummy values
            // (to_int will panic if called, but RNS-domain ops still work)
            primes.iter().map(|_| (0u128, 0u64)).collect()
        };

        Self {
            primes,
            product,
            mont_contexts,
            ntt_engines,
            n,
            crt_values,
        }
    }

    /// Get the number of primes
    pub fn num_primes(&self) -> usize {
        self.primes.len()
    }

    /// Convert a small integer to RNS representation
    pub fn from_int(&self, x: u64) -> Vec<u64> {
        self.primes.iter().map(|&q| x % q).collect()
    }

    /// Convert RNS representation back to integer using CRT
    /// Only valid if result < product of primes
    pub fn to_int(&self, rns: &[u64]) -> u128 {
        assert_eq!(rns.len(), self.primes.len());
        assert!(
            self.product > 0,
            "Cannot call to_int when product overflows u128. Use RNS-domain operations instead."
        );

        let mut result = 0u128;
        for i in 0..self.primes.len() {
            let (mi, mi_inv) = self.crt_values[i];
            let term = (rns[i] as u128 * mi_inv as u128) % self.primes[i] as u128;
            let contribution = (term * mi) % self.product;
            result = (result + contribution) % self.product;
        }

        result
    }

    /// Convert RNS representation back to integer using only the first `level` primes
    ///
    /// This is used for level-aware decryption after modulus switching.
    /// The `rns` slice should have exactly `level` elements.
    ///
    /// # Panics
    /// Panics if the partial prime product overflows u128. Callers that may
    /// exceed u128 should use `to_u256_level` or `try_to_int_level` instead.
    pub fn to_int_level(&self, rns: &[u64], level: usize) -> u128 {
        self.try_to_int_level(rns, level)
            .expect("Partial product overflow: use to_u256_level for large-Q configs")
    }

    /// Fallible variant: returns `None` if the partial prime product overflows u128.
    pub fn try_to_int_level(&self, rns: &[u64], level: usize) -> Option<u128> {
        assert!(
            level <= self.primes.len(),
            "Level cannot exceed number of primes"
        );
        assert_eq!(
            rns.len(),
            level,
            "RNS representation must have exactly `level` elements"
        );

        if level == self.primes.len() {
            // If the full product overflows u128 (sentinel value 0), return None.
            if self.product == 0 {
                return None;
            }
            return Some(self.to_int(rns));
        }

        // Compute partial product Q_level = q_0 * q_1 * ... * q_{level-1}
        let partial_primes = &self.primes[..level];
        let partial_product: u128 = partial_primes
            .iter()
            .try_fold(1u128, |acc, &p| acc.checked_mul(p as u128))?;

        // Compute CRT reconstruction for partial primes
        // For each prime q_i: M_i = partial_product / q_i, M_i_inv = M_i^(-1) mod q_i
        let mut result = 0u128;
        for i in 0..level {
            let mi = partial_product / partial_primes[i] as u128;
            let mi_inv = Self::mod_inv(mi % partial_primes[i] as u128, partial_primes[i] as u128);
            let term = (rns[i] as u128 * mi_inv) % partial_primes[i] as u128;
            let contribution = (term * mi) % partial_product;
            result = (result + contribution) % partial_product;
        }

        Some(result)
    }

    /// Reconstruct at a given level into a 256-bit integer (exact if the level product fits in 256 bits).
    ///
    /// This is used for secure_192 / secure_256 paths where the level product exceeds u128.
    pub(crate) fn to_u256_level(&self, rns: &[u64], level: usize) -> U256 {
        assert!(level <= self.primes.len(), "Level exceeds prime count");
        assert!(rns.len() >= level, "RNS length mismatch");

        let primes = &self.primes[..level];

        // Iterative CRT (Garner-style) in full precision (U256).
        // x_0 = r0, m_0 = p0
        let mut x = U256::from_u64(rns[0] % primes[0]);
        let mut m_prod = U256::from_u64(primes[0]);

        for i in 1..level {
            let p = primes[i];
            let x_mod_p = x.mod_u64(p);
            let m_mod_p = m_prod.mod_u64(p);
            let diff = (rns[i] + p - x_mod_p) % p;
            let inv = mod_inverse(m_mod_p, p);
            let t = ((diff as u128) * (inv as u128) % (p as u128)) as u64;

            x = x.add(m_prod.mul_u64(t));
            m_prod = m_prod.mul_u64(p);
        }

        x
    }

    /// Compute modular inverse using extended Euclidean algorithm
    fn mod_inv(a: u128, m: u128) -> u128 {
        let (mut old_r, mut r) = (m as i128, a as i128);
        let (mut old_t, mut t) = (0i128, 1i128);

        while r != 0 {
            let q = old_r / r;
            (old_r, r) = (r, old_r - q * r);
            (old_t, t) = (t, old_t - q * t);
        }

        if old_t < 0 {
            (old_t + m as i128) as u128
        } else {
            old_t as u128
        }
    }

    /// Add two RNS numbers
    pub fn add(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), self.primes.len());
        assert_eq!(b.len(), self.primes.len());

        a.iter()
            .zip(b.iter())
            .zip(self.primes.iter())
            .map(|((&ai, &bi), &qi)| {
                let sum = ai as u128 + bi as u128;
                if sum >= qi as u128 {
                    (sum - qi as u128) as u64
                } else {
                    sum as u64
                }
            })
            .collect()
    }

    /// Subtract two RNS numbers
    pub fn sub(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), self.primes.len());
        assert_eq!(b.len(), self.primes.len());

        a.iter()
            .zip(b.iter())
            .zip(self.primes.iter())
            .map(
                |((&ai, &bi), &qi)| {
                    if ai >= bi {
                        ai - bi
                    } else {
                        qi - bi + ai
                    }
                },
            )
            .collect()
    }

    /// Multiply two RNS numbers
    pub fn mul(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), self.primes.len());
        assert_eq!(b.len(), self.primes.len());

        a.iter()
            .zip(b.iter())
            .zip(self.primes.iter())
            .map(|((&ai, &bi), &qi)| ((ai as u128 * bi as u128) % qi as u128) as u64)
            .collect()
    }

    /// Negate an RNS number
    pub fn neg(&self, a: &[u64]) -> Vec<u64> {
        a.iter()
            .zip(self.primes.iter())
            .map(|(&ai, &qi)| if ai == 0 { 0 } else { qi - ai })
            .collect()
    }
}

/// RNS Polynomial - coefficients stored as parallel limbs
#[derive(Clone, Debug, Zeroize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RNSPolynomial {
    /// Limbs: limbs[i] is the polynomial mod primes[i]
    pub limbs: Vec<Vec<u64>>,
    /// Polynomial degree
    pub n: usize,
}

impl RNSPolynomial {
    /// Create from a single-modulus polynomial
    pub fn from_poly(poly: &[u64], ctx: &RNSContext) -> Self {
        let n = poly.len();
        let limbs = ctx
            .primes
            .iter()
            .map(|&q| poly.iter().map(|&c| c % q).collect())
            .collect();

        Self { limbs, n }
    }

    /// Create a zero polynomial
    pub fn zero(ctx: &RNSContext) -> Self {
        let limbs = vec![vec![0u64; ctx.n]; ctx.num_primes()];
        Self { limbs, n: ctx.n }
    }

    /// Add two RNS polynomials
    pub fn add(&self, other: &Self, ctx: &RNSContext) -> Self {
        assert_eq!(self.n, other.n);

        let limbs = self
            .limbs
            .iter()
            .zip(other.limbs.iter())
            .zip(ctx.primes.iter())
            .map(|((a, b), &q)| {
                a.iter()
                    .zip(b.iter())
                    .map(|(&ai, &bi)| {
                        let sum = ai as u128 + bi as u128;
                        if sum >= q as u128 {
                            (sum - q as u128) as u64
                        } else {
                            sum as u64
                        }
                    })
                    .collect()
            })
            .collect();

        Self { limbs, n: self.n }
    }

    /// Subtract two RNS polynomials
    pub fn sub(&self, other: &Self, ctx: &RNSContext) -> Self {
        assert_eq!(self.n, other.n);

        let limbs = self
            .limbs
            .iter()
            .zip(other.limbs.iter())
            .zip(ctx.primes.iter())
            .map(|((a, b), &q)| {
                a.iter()
                    .zip(b.iter())
                    .map(|(&ai, &bi)| if ai >= bi { ai - bi } else { q - bi + ai })
                    .collect()
            })
            .collect();

        Self { limbs, n: self.n }
    }

    /// Negate RNS polynomial
    pub fn neg(&self, ctx: &RNSContext) -> Self {
        let limbs = self
            .limbs
            .iter()
            .zip(ctx.primes.iter())
            .map(|(a, &q)| {
                a.iter()
                    .map(|&ai| if ai == 0 { 0 } else { q - ai })
                    .collect()
            })
            .collect();

        Self { limbs, n: self.n }
    }

    /// Multiply two RNS polynomials using parallel NTT
    pub fn mul(&self, other: &Self, ctx: &RNSContext) -> Self {
        assert_eq!(self.n, other.n);

        let limbs = self
            .limbs
            .iter()
            .zip(other.limbs.iter())
            .zip(ctx.ntt_engines.iter())
            .map(|((a, b), ntt)| ntt.multiply(a, b))
            .collect();

        Self { limbs, n: self.n }
    }

    /// Drop the last prime (for rescaling)
    pub fn drop_last_prime(&self, ctx: &RNSContext) -> Self {
        assert!(ctx.num_primes() > 1);

        let limbs = self.limbs[..self.limbs.len() - 1].to_vec();
        Self { limbs, n: self.n }
    }
}

/// Modular inverse using extended Euclidean algorithm

/// Reconstruct an integer from CRT residues into U256 using iterative CRT.
///
/// Assumes primes are pairwise coprime and the true value is in [0, Π p_i).
fn crt_reconstruct_u256(residues: &[u64], primes: &[u64]) -> U256 {
    assert!(!primes.is_empty(), "need primes");
    assert!(residues.len() >= primes.len(), "residue length mismatch");

    let mut x = U256::from_u64(residues[0] % primes[0]);
    let mut m_prod = U256::from_u64(primes[0]);

    for i in 1..primes.len() {
        let p = primes[i];
        let x_mod_p = x.mod_u64(p);
        let m_mod_p = m_prod.mod_u64(p);
        let diff = (residues[i] + p - x_mod_p) % p;
        let inv = mod_inverse(m_mod_p, p);
        let t = ((diff as u128) * (inv as u128) % (p as u128)) as u64;

        x = x.add(m_prod.mul_u64(t));
        m_prod = m_prod.mul_u64(p);
    }

    x
}

fn mod_inverse(a: u64, m: u64) -> u64 {
    let mut mn = (m as i128, a as i128);
    let mut xy = (0i128, 1i128);

    while mn.1 != 0 {
        let q = mn.0 / mn.1;
        mn = (mn.1, mn.0 - q * mn.1);
        xy = (xy.1, xy.0 - q * xy.1);
    }

    while xy.0 < 0 {
        xy.0 += m as i128;
    }
    (xy.0 % m as i128) as u64
}

/// Modular inverse for u128
fn mod_inverse_u128(a: u128, m: u128) -> u128 {
    let mut mn = (m as i128, (a % (1u128 << 127)) as i128);
    let mut xy = (0i128, 1i128);

    while mn.1 != 0 {
        let q = mn.0 / mn.1;
        mn = (mn.1, mn.0 - q * mn.1);
        xy = (xy.1, xy.0 - q * xy.1);
    }

    let m_i128 = (m % (1u128 << 127)) as i128;
    while xy.0 < 0 {
        xy.0 += m_i128;
    }
    (xy.0 % m_i128) as u128
}

// ============================================================================
// Dual-RNS Architecture for Bootstrap-Free FHE
// ============================================================================
//
// The key insight from the QMNF papers:
// - Main RNS: 3 primes for computation (M = q0 × q1 × q2)
// - Anchor RNS: 2 additional coprime primes (A = a0 × a1)
// - K-Elimination: Exact division using both systems
//
// After tensor product, coefficient v exists in both systems:
//   v_m = v mod M (stored across main RNS limbs)
//   v_a = v mod A (stored across anchor RNS limbs)
//
// K-Elimination reconstructs v exactly:
//   k = ((v_a - v_m) × M⁻¹) mod A
//   v = v_m + k × M
//
// Then exact division by q_last (the prime being dropped):
//   result = v / q_last  (exact because q_last | v in valid FHE)

/// Dual-RNS Context for Bootstrap-Free FHE with K-Elimination
///
/// Maintains two independent RNS systems that together enable exact
/// reconstruction of values larger than either system's modulus product.
///
/// NOTE: With 5+ anchor primes, anchor_product may not fit in u128.
/// K-Elimination is done per-limb in RNS domain, then k is reconstructed
/// using a subset of 3 primes (sufficient since k < N×Q²/M ≈ 10²¹).
pub struct DualRNSContext {
    /// Main RNS system for FHE computation
    pub main: RNSContext,
    /// Anchor RNS system for K-Elimination
    pub anchor: RNSContext,
    /// Product of main primes (M)
    pub main_product: u128,
    /// Product of anchor primes (A) - may be 0 if > u128::MAX
    pub anchor_product: u128,
    /// M⁻¹ mod A (precomputed) - only valid if anchor_product fits u128
    pub main_inv_anchor: u128,
    /// M⁻¹ mod pi for each anchor prime (for RNS-domain K-Elim)
    pub main_inv_anchor_rns: Vec<u64>,
    /// Polynomial degree
    pub n: usize,
}

impl DualRNSContext {
    /// Create dual-RNS context from main and anchor prime sets
    ///
    /// Requirements:
    /// - All primes must be coprime (distinct NTT-friendly primes satisfy this)
    /// - anchor_product must be large enough to uniquely identify k
    ///
    /// NOTE: If anchor_product exceeds u128::MAX, it's set to 0 and RNS-domain
    /// K-Elimination must be used (via extract_k_rns method).
    pub fn new(main_primes: Vec<u64>, anchor_primes: Vec<u64>, n: usize) -> Self {
        // Verify no overlap between main and anchor
        for &mp in &main_primes {
            for &ap in &anchor_primes {
                assert_ne!(mp, ap, "Main and anchor primes must be disjoint");
            }
        }

        // Verify anchor primes are NTT-compatible with N
        // NTT requires: (p-1) % 2n == 0 (2n-th root of unity exists)
        let two_n = 2 * n as u64;
        for &ap in &anchor_primes {
            assert!(
                (ap - 1) % two_n == 0,
                "Anchor prime {} is not NTT-compatible with N={}: (p-1) % 2n = {} != 0",
                ap,
                n,
                (ap - 1) % two_n
            );
        }

        let main = RNSContext::new(main_primes.clone(), n);
        let anchor = RNSContext::new(anchor_primes.clone(), n);

        let main_product = main.product;

        // Try to compute anchor_product - may overflow for 5+ primes
        let anchor_product = anchor.product; // RNSContext::product handles overflow

        // Compute M⁻¹ mod pi for each anchor prime (always works)
        let main_inv_anchor_rns: Vec<u64> = anchor_primes
            .iter()
            .map(|&pi| {
                let m_mod_pi = (main_product % pi as u128) as u64;
                mod_inverse(m_mod_pi, pi)
            })
            .collect();

        // Compute M⁻¹ mod A only if anchor_product fits in u128
        let main_inv_anchor = if anchor_product > 0 {
            let main_mod_anchor = main_product % anchor_product;
            mod_inverse_u128(main_mod_anchor, anchor_product)
        } else {
            0 // Can't compute, must use RNS-domain K-Elim
        };

        Self {
            main,
            anchor,
            main_product,
            anchor_product,
            main_inv_anchor,
            main_inv_anchor_rns,
            n,
        }
    }

    /// Create optimized dual-RNS for FHE
    ///
    /// Uses the provided main primes and selects appropriate NTT-compatible anchor primes.
    /// Anchor primes must satisfy: (p-1) % 2n == 0 for NTT compatibility.
    ///
    /// For n=1024: anchor primes with (p-1) % 2048 == 0
    /// CRITICAL: All anchor primes must be > max rescaled coefficient (~1.3×10^9)
    pub fn for_fhe(main_primes: &[u64], n: usize) -> Self {
        // Use NTT-compatible anchor primes > 2×10^9
        // These satisfy (p-1) % 2n == 0 for all supported n values
        // 2013265921 = 15 × 2^27 + 1, works for n up to 2^26
        // 2281701377 = 17 × 2^27 + 1, works for n up to 2^26
        // 2483027969 = 37 × 2^26 + 1, works for n up to 2^25
        // IMPORTANT: Need at least 3 primes for k reconstruction in extract_k_rns
        let anchor_primes = vec![2013265921, 2281701377, 2483027969];

        Self::new(main_primes.to_vec(), anchor_primes, n)
    }

    /// Create dual-RNS for coefficient-domain K-Elimination
    ///
    /// CRITICAL: NTT-domain K-Elimination is INVALID because different primes
    /// use different roots of unity, so NTT point i represents different values.
    /// K-Elimination MUST be done in coefficient domain.
    ///
    /// COEFFICIENT-DOMAIN BOUND: After tensor product, coefficients are O(Q²×N)
    /// For 2 main primes (Q ≈ 10^18) and N=1024:
    ///   Q²×N ≈ 10^39
    ///   Need ANCHOR CAPACITY A > Q²×N for correct NTT multiplication
    ///   With 5 anchor primes: A ≈ 1.3×10^44 >> Q²×N ≈ 10^39 ✓
    ///
    /// Note: 5 primes make A > u128::MAX, so we use RNS-domain K-Elimination.
    /// The k value is computed per-limb, then reconstructed using first 3 primes
    /// (product ≈ 6×10^25 >> k_max ≈ 10^21).
    pub fn for_fhe_coeff_domain(main_primes: &[u64], n: usize) -> Self {
        // 5 NTT-compatible anchor primes for Q²×N capacity
        // All satisfy: (p-1) % 2n == 0 for NTT compatibility
        //
        // These are distinct from main primes and from each other
        // CRITICAL: All anchor primes must be > max rescaled coefficient
        // After rescale, coefficients can be ~1.3×10^9, so all primes must be > 2×10^9
        let anchor_primes = vec![
            2013265921, // 15 × 2^27 + 1    (~31 bits)
            2281701377, // 17 × 2^27 + 1    (~31 bits)
            2483027969, // 37 × 2^26 + 1    (~32 bits)
            2885681153, // 43 × 2^26 + 1    (~32 bits)
            3221225473, // 3 × 2^30 + 1     (~32 bits)
        ];
        // A ≈ 1.1 × 10^47 >> Q²×N ≈ 10^39 ✓
        // A does NOT fit in u128, so anchor_product will be 0
        // k reconstruction uses first 3 primes: 2013265921 × 2281701377 × 2483027969
        //   = 1.14×10^28 >> k_max ≈ 10^21 ✓
        //
        // All primes are NTT-compatible: (p-1) % 2048 == 0 for N=1024

        Self::new(main_primes.to_vec(), anchor_primes, n)
    }

    /// DEPRECATED: NTT-domain K-Elimination is mathematically invalid
    ///
    /// NTT uses different roots of unity for different moduli:
    ///   NTT_{p1}(poly)[i] ≠ NTT_{p2}(poly)[i] (different underlying values!)
    ///
    /// K-Elimination requires SAME integer with different residues.
    /// Use `for_fhe_coeff_domain` instead.
    #[deprecated(note = "NTT-domain K-Elimination is invalid. Use for_fhe_coeff_domain")]
    pub fn for_fhe_ntt_domain(main_primes: &[u64], n: usize) -> Self {
        Self::for_fhe_coeff_domain(main_primes, n)
    }

    /// Convert value to dual-RNS representation
    pub fn from_u128(&self, x: u128) -> DualRNSValue {
        // Main limbs: x mod each main prime
        let main_limbs: Vec<u64> = self
            .main
            .primes
            .iter()
            .map(|&p| (x % p as u128) as u64)
            .collect();

        // Anchor limbs: x mod each anchor prime
        let anchor_limbs: Vec<u64> = self
            .anchor
            .primes
            .iter()
            .map(|&p| (x % p as u128) as u64)
            .collect();

        DualRNSValue {
            main_limbs,
            anchor_limbs,
        }
    }

    /// K-Elimination: Extract k value for exact reconstruction
    ///
    /// Given v_main = v mod M and v_anchor = v mod A,
    /// computes k such that v = v_main + k × M
    ///
    /// NOTE: Only works if anchor_product fits in u128. For 5+ primes,
    /// use extract_k_rns instead.
    pub fn extract_k(&self, v_main: u128, v_anchor: u128) -> u128 {
        assert!(
            self.anchor_product > 0,
            "Use extract_k_rns for 5+ anchor primes"
        );

        // k = ((v_anchor - v_main mod A) × M⁻¹) mod A
        let v_main_mod_a = v_main % self.anchor_product;

        let diff = if v_anchor >= v_main_mod_a {
            v_anchor - v_main_mod_a
        } else {
            self.anchor_product - (v_main_mod_a - v_anchor)
        };

        // Multiply diff × M⁻¹ mod A
        mul_mod_u128(diff, self.main_inv_anchor, self.anchor_product)
    }

    /// K-Elimination in RNS domain: Extract k from anchor limbs
    ///
    /// This version works for any number of anchor primes, including 5+
    /// where the full anchor product doesn't fit in u128.
    ///
    /// The k value is computed per-limb in RNS form, then reconstructed
    /// using the first 3 anchor primes (product ≈ 6×10^25 >> k_max ≈ 10^21).
    ///
    /// Returns k such that v = v_main + k × M
    pub fn extract_k_rns(&self, v_main: u128, v_anchor_rns: &[u64]) -> u128 {
        assert_eq!(v_anchor_rns.len(), self.anchor.primes.len());
        assert!(
            self.anchor.primes.len() >= 3,
            "Need at least 3 anchor primes for k reconstruction"
        );

        // Compute k in RNS form: k_rns[i] = ((v_anchor[i] - (v_main mod pi)) × M⁻¹) mod pi
        let k_rns: Vec<u64> = self
            .anchor
            .primes
            .iter()
            .zip(v_anchor_rns.iter())
            .zip(self.main_inv_anchor_rns.iter())
            .map(|((&pi, &v_a_i), &m_inv_i)| {
                let v_m_mod_pi = (v_main % pi as u128) as u64;

                // diff = v_a_i - v_m_mod_pi mod pi
                let diff = if v_a_i >= v_m_mod_pi {
                    v_a_i - v_m_mod_pi
                } else {
                    pi - v_m_mod_pi + v_a_i
                };

                // k_i = diff × M⁻¹ mod pi
                ((diff as u128 * m_inv_i as u128) % pi as u128) as u64
            })
            .collect();

        // Reconstruct k from first 3 primes (product fits u128)
        // Product of first 3 primes: 469762049 × 415236097 × 754974721 ≈ 1.47×10^26
        let p0 = self.anchor.primes[0] as u128;
        let p1 = self.anchor.primes[1] as u128;
        let p2 = self.anchor.primes[2] as u128;

        let product_3 = p0 * p1 * p2;

        // CRT reconstruction for 3 primes
        // m0 = p1*p2, m1 = p0*p2, m2 = p0*p1
        let m0 = p1 * p2;
        let m1 = p0 * p2;
        let m2 = p0 * p1;

        // m0_inv mod p0, m1_inv mod p1, m2_inv mod p2
        let m0_inv = mod_inverse((m0 % p0) as u64, self.anchor.primes[0]) as u128;
        let m1_inv = mod_inverse((m1 % p1) as u64, self.anchor.primes[1]) as u128;
        let m2_inv = mod_inverse((m2 % p2) as u64, self.anchor.primes[2]) as u128;

        // k = sum of (k_i × m_i_inv × m_i) mod product_3
        let term0 = ((k_rns[0] as u128 * m0_inv) % p0) * m0;
        let term1 = ((k_rns[1] as u128 * m1_inv) % p1) * m1;
        let term2 = ((k_rns[2] as u128 * m2_inv) % p2) * m2;

        // Sum and reduce mod product_3
        (term0 % product_3 + term1 % product_3 + term2 % product_3) % product_3
    }

    /// Level-aware K-Elimination extraction for reduced ciphertext levels
    ///
    /// This is the critical fix for depth > 1: after mod_switch, the effective
    /// modulus M_level is smaller than the full M. We must compute M_level⁻¹
    /// dynamically based on which main primes are still active.
    ///
    /// # Arguments
    /// * `v_main` - Value mod M_level (reconstructed from level main primes)
    /// * `v_anchor_rns` - Anchor residues [v mod a_0, v mod a_1, ...]
    /// * `level_main_primes` - The main primes still active at this level
    ///
    /// # Returns
    /// k such that v_exact = v_main + k × M_level

    /// Extract k using a LEVEL-SPECIFIC main modulus product, without materializing the full modulus in u128.
    ///
    /// Returns k as a 256-bit unsigned value in [0, A_k), where A_k is the product of the anchor primes
    /// used for reconstruction.
    pub(crate) fn extract_k_rns_level(
        &self,
        v_main: U256,
        v_anchor_rns: &[u64],
        level_main_primes: &[u64],
    ) -> U256 {
        assert!(
            level_main_primes.len() <= self.main.primes.len(),
            "Level exceeds main prime count"
        );
        assert_eq!(
            v_anchor_rns.len(),
            self.anchor.primes.len(),
            "Anchor RNS length mismatch"
        );

        // Compute M_level = product(level_main_primes) as U256 (fits for current parameter sets).
        let m_level = U256::product_u64s(level_main_primes);

        // Choose how many anchor primes to reconstruct k from.
        // For >=5 main primes, use 5 anchors; for >=4 use 4; else use 3.
        let k_primes = if level_main_primes.len() >= 5 {
            self.anchor.primes.len().min(5)
        } else if level_main_primes.len() >= 4 {
            self.anchor.primes.len().min(4)
        } else {
            self.anchor.primes.len().min(3)
        };
        assert!(
            k_primes >= 3,
            "Need at least 3 anchor primes for k reconstruction"
        );

        // Compute k residues in each anchor modulus: k_i = (v_a - v_m) * (M_level^{-1} mod a_i) mod a_i
        let mut k_rns = vec![0u64; self.anchor.primes.len()];
        for (i, &a_i) in self.anchor.primes.iter().enumerate() {
            let m_level_mod_ai = m_level.mod_u64(a_i);
            let inv = mod_inverse(m_level_mod_ai, a_i);
            let v_m_mod_ai = v_main.mod_u64(a_i);
            let diff = (v_anchor_rns[i] + a_i - v_m_mod_ai) % a_i;
            k_rns[i] = ((diff as u128) * (inv as u128) % (a_i as u128)) as u64;
        }

        // Reconstruct k from the first k_primes anchors via iterative CRT to U256.
        crt_reconstruct_u256(&k_rns[..k_primes], &self.anchor.primes[..k_primes])
    }

    /// K-Elimination: Reconstruct full value from dual-RNS representation
    ///
    /// Returns the unique value v < M×A such that:
    ///   v ≡ v_main (mod M)
    ///   v ≡ v_anchor (mod A)
    pub fn reconstruct(&self, v_main: u128, v_anchor: u128) -> u128 {
        let k = self.extract_k(v_main, v_anchor);
        v_main + k * self.main_product
    }

    /// K-Elimination exact division: compute v / divisor where divisor | v
    ///
    /// This is the KEY operation for FHE rescaling.
    /// After multiplication, we need to divide by q_last exactly.
    pub fn exact_divide(&self, v_main: u128, v_anchor: u128, divisor: u64) -> u128 {
        let v_full = self.reconstruct(v_main, v_anchor);
        v_full / divisor as u128
    }

    /// Exact division with centered representation
    ///
    /// For FHE coefficients, we need signed arithmetic.
    /// If v_full > (M×A)/2, treat as negative.
    pub fn exact_divide_centered(&self, v_main: u128, v_anchor: u128, divisor: u64) -> i128 {
        let v_full = self.reconstruct(v_main, v_anchor);
        let half_capacity = (self.main_product / 2) * (self.anchor_product / 2);

        let signed_v = if v_full > half_capacity {
            -((self.main_product * self.anchor_product - v_full) as i128)
        } else {
            v_full as i128
        };

        signed_v / divisor as i128
    }
}

/// Value in dual-RNS representation
#[derive(Clone, Debug)]
pub struct DualRNSValue {
    pub main_limbs: Vec<u64>,
    pub anchor_limbs: Vec<u64>,
}

/// Dual-RNS Polynomial: coefficients tracked in both RNS systems
///
/// This is the fundamental data structure for Bootstrap-Free FHE.
/// Every coefficient exists in 5 limbs: 3 main + 2 anchor.
#[derive(Clone, Debug, Zeroize)]
pub struct DualRNSPolynomial {
    /// Main RNS limbs: main_limbs[prime_idx][coeff_idx]
    pub main_limbs: Vec<Vec<u64>>,
    /// Anchor RNS limbs: anchor_limbs[prime_idx][coeff_idx]
    pub anchor_limbs: Vec<Vec<u64>>,
    /// Polynomial degree
    pub n: usize,
}

impl DualRNSPolynomial {
    /// Create from coefficient array (converts to dual-RNS form)
    pub fn from_coeffs(coeffs: &[u64], ctx: &DualRNSContext) -> Self {
        let n = coeffs.len();

        let main_limbs: Vec<Vec<u64>> = ctx
            .main
            .primes
            .iter()
            .map(|&p| coeffs.iter().map(|&c| c % p).collect())
            .collect();

        let anchor_limbs: Vec<Vec<u64>> = ctx
            .anchor
            .primes
            .iter()
            .map(|&p| coeffs.iter().map(|&c| c % p).collect())
            .collect();

        Self {
            main_limbs,
            anchor_limbs,
            n,
        }
    }

    /// Create zero polynomial
    pub fn zero(ctx: &DualRNSContext) -> Self {
        let main_limbs = vec![vec![0u64; ctx.n]; ctx.main.num_primes()];
        let anchor_limbs = vec![vec![0u64; ctx.n]; ctx.anchor.num_primes()];
        Self {
            main_limbs,
            anchor_limbs,
            n: ctx.n,
        }
    }

    /// Add two dual-RNS polynomials
    pub fn add(&self, other: &Self, ctx: &DualRNSContext) -> Self {
        assert_eq!(self.n, other.n);

        // Add in main RNS
        let main_limbs: Vec<Vec<u64>> = self
            .main_limbs
            .iter()
            .zip(other.main_limbs.iter())
            .zip(ctx.main.primes.iter())
            .map(|((a, b), &q)| {
                a.iter()
                    .zip(b.iter())
                    .map(|(&ai, &bi)| {
                        let sum = ai as u128 + bi as u128;
                        if sum >= q as u128 {
                            (sum - q as u128) as u64
                        } else {
                            sum as u64
                        }
                    })
                    .collect()
            })
            .collect();

        // Add in anchor RNS
        let anchor_limbs: Vec<Vec<u64>> = self
            .anchor_limbs
            .iter()
            .zip(other.anchor_limbs.iter())
            .zip(ctx.anchor.primes.iter())
            .map(|((a, b), &q)| {
                a.iter()
                    .zip(b.iter())
                    .map(|(&ai, &bi)| {
                        let sum = ai as u128 + bi as u128;
                        if sum >= q as u128 {
                            (sum - q as u128) as u64
                        } else {
                            sum as u64
                        }
                    })
                    .collect()
            })
            .collect();

        Self {
            main_limbs,
            anchor_limbs,
            n: self.n,
        }
    }

    /// Subtract two dual-RNS polynomials
    pub fn sub(&self, other: &Self, ctx: &DualRNSContext) -> Self {
        assert_eq!(self.n, other.n);

        let main_limbs: Vec<Vec<u64>> = self
            .main_limbs
            .iter()
            .zip(other.main_limbs.iter())
            .zip(ctx.main.primes.iter())
            .map(|((a, b), &q)| {
                a.iter()
                    .zip(b.iter())
                    .map(|(&ai, &bi)| if ai >= bi { ai - bi } else { q - bi + ai })
                    .collect()
            })
            .collect();

        let anchor_limbs: Vec<Vec<u64>> = self
            .anchor_limbs
            .iter()
            .zip(other.anchor_limbs.iter())
            .zip(ctx.anchor.primes.iter())
            .map(|((a, b), &q)| {
                a.iter()
                    .zip(b.iter())
                    .map(|(&ai, &bi)| if ai >= bi { ai - bi } else { q - bi + ai })
                    .collect()
            })
            .collect();

        Self {
            main_limbs,
            anchor_limbs,
            n: self.n,
        }
    }

    /// Negate polynomial
    pub fn neg(&self, ctx: &DualRNSContext) -> Self {
        let main_limbs: Vec<Vec<u64>> = self
            .main_limbs
            .iter()
            .zip(ctx.main.primes.iter())
            .map(|(a, &q)| {
                a.iter()
                    .map(|&ai| if ai == 0 { 0 } else { q - ai })
                    .collect()
            })
            .collect();

        let anchor_limbs: Vec<Vec<u64>> = self
            .anchor_limbs
            .iter()
            .zip(ctx.anchor.primes.iter())
            .map(|(a, &q)| {
                a.iter()
                    .map(|&ai| if ai == 0 { 0 } else { q - ai })
                    .collect()
            })
            .collect();

        Self {
            main_limbs,
            anchor_limbs,
            n: self.n,
        }
    }

    /// Multiply two dual-RNS polynomials using parallel NTT
    ///
    /// Multiplication is done independently in each limb (main and anchor)
    pub fn mul(&self, other: &Self, ctx: &DualRNSContext) -> Self {
        assert_eq!(self.n, other.n);

        // Multiply in main RNS using NTT
        let main_limbs: Vec<Vec<u64>> = self
            .main_limbs
            .iter()
            .zip(other.main_limbs.iter())
            .zip(ctx.main.ntt_engines.iter())
            .map(|((a, b), ntt)| ntt.multiply(a, b))
            .collect();

        // Multiply in anchor RNS using NTT
        let anchor_limbs: Vec<Vec<u64>> = self
            .anchor_limbs
            .iter()
            .zip(other.anchor_limbs.iter())
            .zip(ctx.anchor.ntt_engines.iter())
            .map(|((a, b), ntt)| ntt.multiply(a, b))
            .collect();

        Self {
            main_limbs,
            anchor_limbs,
            n: self.n,
        }
    }

    /// K-Elimination rescaling: exact division by q_last
    ///
    /// This is the CRITICAL operation that enables Bootstrap-Free FHE.
    /// After tensor product, divide each coefficient exactly by q_last
    /// and return result in reduced RNS (without q_last).
    ///
    /// Note: For large moduli products, we use modular arithmetic to avoid
    /// overflow. The key insight is that we can compute (v / q_last) mod p
    /// for each output prime p without fully reconstructing v.
    ///
    /// IMPORTANT: The limb for p == q_last is undefined in this fast path
    /// (no modular inverse exists). It is set to 0 and should be dropped
    /// before any full reconstruction.
    pub fn k_elim_rescale(&self, ctx: &DualRNSContext, q_last: u64) -> Self {
        let num_main = ctx.main.num_primes();

        // Result will have same number of limbs (we don't drop primes yet)
        let mut result_main = vec![vec![0u64; self.n]; num_main];
        let mut result_anchor = vec![vec![0u64; self.n]; ctx.anchor.num_primes()];

        // Precompute q_last^{-1} mod p for each output prime p
        let q_last_inv_main: Vec<Option<u64>> = ctx
            .main
            .primes
            .iter()
            .map(|&p| {
                let ql_mod_p = q_last % p;
                if ql_mod_p == 0 {
                    None
                } else {
                    Some(mod_inverse(ql_mod_p, p))
                }
            })
            .collect();

        let q_last_inv_anchor: Vec<Option<u64>> = ctx
            .anchor
            .primes
            .iter()
            .map(|&p| {
                let ql_mod_p = q_last % p;
                if ql_mod_p == 0 {
                    None
                } else {
                    Some(mod_inverse(ql_mod_p, p))
                }
            })
            .collect();

        for coeff_idx in 0..self.n {
            // For each coefficient, we need to compute (v / q_last) mod each prime.
            //
            // Key insight: If v ≡ 0 (mod q_last), then v = q_last × r for some r.
            // We want r mod p for each prime p.
            //
            // Using CRT: r ≡ v × q_last^{-1} (mod p)
            //
            // So we just multiply each residue by q_last^{-1} mod p.

            // For main primes
            for (limb_idx, &p) in ctx.main.primes.iter().enumerate() {
                let v_i = self.main_limbs[limb_idx][coeff_idx];
                // r_i = v_i × q_last^{-1} mod p (skip when p == q_last)
                let result = if let Some(inv) = q_last_inv_main[limb_idx] {
                    ((v_i as u128 * inv as u128) % p as u128) as u64
                } else {
                    0
                };
                result_main[limb_idx][coeff_idx] = result;
            }

            // For anchor primes
            for (limb_idx, &p) in ctx.anchor.primes.iter().enumerate() {
                let v_i = self.anchor_limbs[limb_idx][coeff_idx];
                // r_i = v_i × q_last^{-1} mod p
                let result = if let Some(inv) = q_last_inv_anchor[limb_idx] {
                    ((v_i as u128 * inv as u128) % p as u128) as u64
                } else {
                    0
                };
                result_anchor[limb_idx][coeff_idx] = result;
            }
        }

        Self {
            main_limbs: result_main,
            anchor_limbs: result_anchor,
            n: self.n,
        }
    }

    /// Full K-Elimination rescaling with CRT reconstruction (for small moduli)
    ///
    /// This version reconstructs the full value using CRT, which requires
    /// M × A to fit in u128. Use k_elim_rescale for large moduli.
    #[allow(dead_code)]
    pub fn k_elim_rescale_full(&self, ctx: &DualRNSContext, q_last: u64) -> Self {
        let num_main = ctx.main.num_primes();
        let mut result_main = vec![vec![0u64; self.n]; num_main];
        let mut result_anchor = vec![vec![0u64; self.n]; ctx.anchor.num_primes()];

        for coeff_idx in 0..self.n {
            let main_residues: Vec<u64> =
                self.main_limbs.iter().map(|limb| limb[coeff_idx]).collect();
            let v_main = ctx.main.to_int(&main_residues);

            let anchor_residues: Vec<u64> = self
                .anchor_limbs
                .iter()
                .map(|limb| limb[coeff_idx])
                .collect();
            let v_anchor = ctx.anchor.to_int(&anchor_residues);

            let v_full = ctx.reconstruct(v_main, v_anchor);

            let half_m = ctx.main_product / 2;
            let (is_neg, abs_v) = if v_full > half_m {
                (
                    true,
                    ctx.main_product
                        .saturating_mul(ctx.anchor_product)
                        .saturating_sub(v_full),
                )
            } else {
                (false, v_full)
            };

            let divided = abs_v / q_last as u128;

            let result_val = if is_neg && divided > 0 {
                ctx.main_product.saturating_sub(divided % ctx.main_product)
            } else {
                divided % ctx.main_product
            };

            for (limb_idx, &p) in ctx.main.primes.iter().enumerate() {
                result_main[limb_idx][coeff_idx] = (result_val % p as u128) as u64;
            }

            let result_anchor_val = if is_neg && divided > 0 {
                ctx.anchor_product
                    .saturating_sub(divided % ctx.anchor_product)
            } else {
                divided % ctx.anchor_product
            };
            for (limb_idx, &p) in ctx.anchor.primes.iter().enumerate() {
                result_anchor[limb_idx][coeff_idx] = (result_anchor_val % p as u128) as u64;
            }
        }

        Self {
            main_limbs: result_main,
            anchor_limbs: result_anchor,
            n: self.n,
        }
    }

    /// Convert to standard RNSPolynomial (main limbs only)
    pub fn to_rns_polynomial(&self) -> RNSPolynomial {
        RNSPolynomial {
            limbs: self.main_limbs.clone(),
            n: self.n,
        }
    }

    /// Create from RNSPolynomial by adding anchor limbs
    pub fn from_rns_polynomial(poly: &RNSPolynomial, ctx: &DualRNSContext) -> Self {
        // First reconstruct each coefficient from main RNS
        let mut anchor_limbs = vec![vec![0u64; poly.n]; ctx.anchor.num_primes()];

        for coeff_idx in 0..poly.n {
            let main_residues: Vec<u64> = poly.limbs.iter().map(|limb| limb[coeff_idx]).collect();
            let v_main = ctx.main.to_int(&main_residues);

            // Reduce into anchor limbs
            for (limb_idx, &p) in ctx.anchor.primes.iter().enumerate() {
                anchor_limbs[limb_idx][coeff_idx] = (v_main % p as u128) as u64;
            }
        }

        Self {
            main_limbs: poly.limbs.clone(),
            anchor_limbs,
            n: poly.n,
        }
    }
}

/// Modular multiplication for u128 (double-word multiplication)
fn mul_mod_u128(a: u128, b: u128, m: u128) -> u128 {
    // For values that fit in 64 bits, direct multiplication is safe
    if a < (1u128 << 64) && b < (1u128 << 64) {
        (a * b) % m
    } else {
        // Use peasant multiplication for larger values
        let mut result = 0u128;
        let mut a = a % m;
        let mut b = b;

        while b > 0 {
            if b & 1 == 1 {
                result = result.wrapping_add(a);
                if result >= m {
                    result -= m;
                }
            }
            a = a.wrapping_shl(1);
            if a >= m {
                a -= m;
            }
            b >>= 1;
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // For basic RNS integer tests, we don't need NTT.
    // Create a simpler context that skips NTT for non-polynomial tests.

    #[test]
    fn test_rns_roundtrip() {
        // Use NTT-compatible primes
        let primes = vec![998244353, 985661441];
        let ctx = RNSContext::new(primes, 4);

        for x in [0u64, 1, 100, 1000, 7000] {
            let rns = ctx.from_int(x);
            let back = ctx.to_int(&rns);
            assert_eq!(back, x as u128, "Roundtrip failed for {}", x);
        }
    }

    #[test]
    fn test_rns_add() {
        let primes = vec![998244353, 985661441];
        let ctx = RNSContext::new(primes, 4);

        let a = ctx.from_int(100);
        let b = ctx.from_int(200);
        let sum = ctx.add(&a, &b);
        let result = ctx.to_int(&sum);

        assert_eq!(result, 300);
    }

    #[test]
    fn test_rns_mul() {
        let primes = vec![998244353, 985661441];
        let ctx = RNSContext::new(primes, 4);

        let a = ctx.from_int(12);
        let b = ctx.from_int(34);
        let prod = ctx.mul(&a, &b);
        let result = ctx.to_int(&prod);

        assert_eq!(result, 408);
    }

    #[test]
    fn test_rns_polynomial_add() {
        let primes = vec![998244353, 985661441];
        let ctx = RNSContext::new(primes, 4);

        let a = vec![1, 2, 3, 4];
        let b = vec![5, 6, 7, 8];

        let rns_a = RNSPolynomial::from_poly(&a, &ctx);
        let rns_b = RNSPolynomial::from_poly(&b, &ctx);

        let rns_sum = rns_a.add(&rns_b, &ctx);

        // Check first limb
        assert_eq!(rns_sum.limbs[0], vec![6, 8, 10, 12]);
    }

    #[test]
    fn test_rns_polynomial_mul() {
        let primes = vec![998244353, 985661441];
        let ctx = RNSContext::new(primes, 8);

        // (1 + 2x) * (3 + 4x) = 3 + 10x + 8x^2
        let a = vec![1, 2, 0, 0, 0, 0, 0, 0];
        let b = vec![3, 4, 0, 0, 0, 0, 0, 0];

        let rns_a = RNSPolynomial::from_poly(&a, &ctx);
        let rns_b = RNSPolynomial::from_poly(&b, &ctx);

        let rns_prod = rns_a.mul(&rns_b, &ctx);

        // Check both limbs have correct result
        assert_eq!(rns_prod.limbs[0][0], 3);
        assert_eq!(rns_prod.limbs[0][1], 10);
        assert_eq!(rns_prod.limbs[0][2], 8);

        assert_eq!(rns_prod.limbs[1][0], 3);
        assert_eq!(rns_prod.limbs[1][1], 10);
        assert_eq!(rns_prod.limbs[1][2], 8);
    }

    // ========================================================================
    // Dual-RNS K-Elimination Tests
    // ========================================================================
    //
    // NOTE: Tests use NTT-compatible primes where (p-1) is divisible by 2N.
    // For n=4: need (p-1) % 8 == 0
    // For n=1024: need (p-1) % 2048 == 0

    /// Get NTT-compatible primes for small n (tests)
    /// For n=4, we need (p-1) divisible by 8
    fn small_ntt_primes() -> (Vec<u64>, Vec<u64>) {
        // Main primes: 17, 41 are small primes with (p-1) % 8 == 0
        // 17-1=16, 41-1=40, 73-1=72, 89-1=88, 97-1=96
        let main = vec![17, 41];
        // Anchor primes: 73, 89
        let anchor = vec![73, 89];
        (main, anchor)
    }

    #[test]
    fn test_dual_rns_k_elimination_basic() {
        // Test the K-Elimination formula with NTT-compatible primes
        let (main_primes, anchor_primes) = small_ntt_primes();

        let ctx = DualRNSContext::new(main_primes, anchor_primes, 4);

        println!("K-Elimination test:");
        println!("  Main product M = {}", ctx.main_product);
        println!("  Anchor product A = {}", ctx.anchor_product);
        println!("  M^-1 mod A = {}", ctx.main_inv_anchor);

        // Test value that fits within M (17 × 41 = 697)
        let v: u128 = 500;
        let v_main = v % ctx.main_product;
        let v_anchor = v % ctx.anchor_product;

        println!("  Testing v = {}", v);
        println!("    v mod M = {}", v_main);
        println!("    v mod A = {}", v_anchor);

        // Reconstruct using K-Elimination
        let k = ctx.extract_k(v_main, v_anchor);
        let reconstructed = ctx.reconstruct(v_main, v_anchor);

        println!("    k = {}", k);
        println!("    reconstructed = {}", reconstructed);

        assert_eq!(reconstructed, v, "K-Elimination reconstruction failed!");
    }

    #[test]
    fn test_dual_rns_exact_division() {
        let (main_primes, anchor_primes) = small_ntt_primes();
        let ctx = DualRNSContext::new(main_primes, anchor_primes, 4);

        // Test: 600 / 6 = 100 (values fit within M = 17 × 41 = 697)
        let v: u128 = 600;
        let divisor = 6u64;
        let expected = 100u128;

        let v_main = v % ctx.main_product;
        let v_anchor = v % ctx.anchor_product;

        let result = ctx.exact_divide(v_main, v_anchor, divisor);
        assert_eq!(result, expected, "Exact division failed!");
    }

    #[test]
    fn test_dual_rns_fhe_capacity() {
        // Test with FHE-sized primes (all NTT-compatible for n=1024)
        // These primes satisfy (p-1) % 2048 == 0
        let main_primes = vec![998244353, 985661441, 754974721];
        // Use NTT-compatible anchor primes > 2×10^9
        // All must be larger than rescaled coefficients (~1.3×10^9)
        let anchor_primes = vec![2013265921, 2281701377];

        let ctx = DualRNSContext::new(main_primes, anchor_primes, 1024);

        println!("FHE-sized K-Elimination:");
        println!(
            "  M = {} ({} bits)",
            ctx.main_product,
            128u32.saturating_sub(ctx.main_product.leading_zeros())
        );
        println!(
            "  A = {} ({} bits)",
            ctx.anchor_product,
            128u32.saturating_sub(ctx.anchor_product.leading_zeros())
        );
        println!(
            "  Total capacity = {} + {} = {} bits",
            128u32.saturating_sub(ctx.main_product.leading_zeros()),
            128u32.saturating_sub(ctx.anchor_product.leading_zeros()),
            128u32.saturating_sub(ctx.main_product.leading_zeros())
                + 128u32.saturating_sub(ctx.anchor_product.leading_zeros())
        );

        // Test large value (simulating Δ² after tensor product)
        // Δ ≈ M/t where t = 65537
        // Δ² ≈ M²/t² which is still < M×A for reasonable t
        let delta: u128 = ctx.main_product / 65537;
        let delta_sq = delta.saturating_mul(delta);

        println!(
            "  Δ = M/t = {} ({} bits)",
            delta,
            128u32.saturating_sub(delta.leading_zeros())
        );
        println!(
            "  Δ² = {} ({} bits)",
            delta_sq,
            128u32.saturating_sub(delta_sq.leading_zeros())
        );
        println!(
            "  Δ² < M×A? {}",
            delta_sq < ctx.main_product.saturating_mul(ctx.anchor_product)
        );

        // Create dual-RNS representation of delta_sq
        let drns = ctx.from_u128(delta_sq);
        let v_main = ctx.main.to_int(&drns.main_limbs);
        let v_anchor = ctx.anchor.to_int(&drns.anchor_limbs);

        // Verify reconstruction
        let reconstructed = ctx.reconstruct(v_main, v_anchor);
        assert_eq!(
            reconstructed, delta_sq,
            "Large value reconstruction failed!"
        );
    }

    #[test]
    fn test_dual_rns_polynomial_operations() {
        let (main_primes, anchor_primes) = small_ntt_primes();
        let ctx = DualRNSContext::new(main_primes, anchor_primes, 4);

        // Create polynomials with small coefficients
        let a_coeffs = vec![1, 2, 3, 4];
        let b_coeffs = vec![5, 6, 7, 8];

        let a = DualRNSPolynomial::from_coeffs(&a_coeffs, &ctx);
        let b = DualRNSPolynomial::from_coeffs(&b_coeffs, &ctx);

        // Test addition
        let sum = a.add(&b, &ctx);

        // Verify: reconstruct first coefficient from main
        let c0_main: Vec<u64> = sum.main_limbs.iter().map(|l| l[0]).collect();
        let c0_reconstructed = ctx.main.to_int(&c0_main);
        assert_eq!(
            c0_reconstructed, 6,
            "Polynomial addition coefficient 0 failed"
        );

        // Verify last coefficient
        let c3_main: Vec<u64> = sum.main_limbs.iter().map(|l| l[3]).collect();
        let c3_reconstructed = ctx.main.to_int(&c3_main);
        assert_eq!(
            c3_reconstructed, 12,
            "Polynomial addition coefficient 3 failed"
        );
    }

    #[test]
    fn test_k_elim_rescale() {
        // Test the critical rescaling operation with NTT-compatible primes
        let (main_primes, anchor_primes) = small_ntt_primes();
        let ctx = DualRNSContext::new(main_primes, anchor_primes, 4);

        // Use divisor = 41 (one of the main primes)
        let q_last = 41u64;

        // Coefficients that are multiples of q_last
        let coeffs: Vec<u64> = vec![
            q_last * 1, // 41
            q_last * 2, // 82
            q_last * 3, // 123
            q_last * 4, // 164
        ];

        let poly = DualRNSPolynomial::from_coeffs(&coeffs, &ctx);

        // Rescale by dividing by q_last
        let rescaled = poly.k_elim_rescale(&ctx, q_last);

        // Verify: residues match for all primes except q_last (which is dropped)
        for i in 0..4 {
            let expected = (i + 1) as u64;
            for (limb_idx, &p) in ctx.main.primes.iter().enumerate() {
                let got = rescaled.main_limbs[limb_idx][i];
                if p == q_last {
                    assert_eq!(
                        got, 0,
                        "Rescaling coefficient {} failed: q_last limb should be zero",
                        i
                    );
                } else {
                    assert_eq!(
                        got,
                        expected % p,
                        "Rescaling main coefficient {} failed for p={}: got {} expected {}",
                        i,
                        p,
                        got,
                        expected % p
                    );
                }
            }

            for (limb_idx, &p) in ctx.anchor.primes.iter().enumerate() {
                let got = rescaled.anchor_limbs[limb_idx][i];
                assert_eq!(
                    got,
                    expected % p,
                    "Rescaling anchor coefficient {} failed for p={}: got {} expected {}",
                    i,
                    p,
                    got,
                    expected % p
                );
            }
        }

        println!("K-Elimination rescaling test passed!");
    }

    #[test]
    fn test_dual_rns_fhe_full_chain() {
        // Test with actual FHE primes for n=1024
        let main_primes = vec![998244353, 985661441, 754974721];
        let anchor_primes = vec![2013265921, 2281701377];

        let ctx = DualRNSContext::new(main_primes.clone(), anchor_primes, 1024);

        println!("=== Full Dual-RNS FHE Chain Test ===");
        println!("Main primes: {:?}", main_primes);
        println!(
            "M = {} ({} bits)",
            ctx.main_product,
            128u32.saturating_sub(ctx.main_product.leading_zeros())
        );
        println!(
            "A = {} ({} bits)",
            ctx.anchor_product,
            128u32.saturating_sub(ctx.anchor_product.leading_zeros())
        );

        // Simulate: m = 5 encoded as m * Δ
        let t = 65537u64;
        let m = 5u64;
        let delta = ctx.main_product / t as u128;

        println!(
            "t = {}, Δ = M/t = {} ({} bits)",
            t,
            delta,
            128u32.saturating_sub(delta.leading_zeros())
        );

        // Encode message
        let encoded = delta * m as u128;
        println!(
            "Encoded m = {} × Δ = {} ({} bits)",
            m,
            encoded,
            128u32.saturating_sub(encoded.leading_zeros())
        );

        // Actually, let's just test the k_elim path with a simpler value
        // Simulate tensor product: (m₁ × Δ) × (m₂ × Δ) = m₁m₂ × Δ²
        // After rescale by Δ, should get m₁m₂ × Δ

        // Create a value that is exactly Δ (scaled by 1)
        let v_main = delta % ctx.main_product;
        let v_anchor = delta % ctx.anchor_product;

        let reconstructed = ctx.reconstruct(v_main, v_anchor);
        assert_eq!(reconstructed, delta, "Delta reconstruction failed");

        println!("Δ reconstruction: OK");

        // Test exact division of Δ²/Δ = Δ
        let delta_sq = delta.saturating_mul(delta);
        // Note: M × A would overflow u128, so we can't check directly
        // But we can verify the division works for values within range
        if delta_sq < u128::MAX / 2 {
            // This should give us Δ
            // But we can't divide by Δ directly since Δ is u128
            // In practice, we divide by q_last
            let q_last = main_primes[2]; // 754974721

            // Create a value divisible by q_last
            let test_val = q_last as u128 * 12345;
            let test_main = test_val % ctx.main_product;
            let test_anchor = test_val % ctx.anchor_product;

            let divided = ctx.exact_divide(test_main, test_anchor, q_last);
            assert_eq!(divided, 12345, "q_last division failed");

            println!("Exact division by q_last: OK");
        }

        println!("=== Full chain test PASSED ===");
    }

    // ========================================================================
    // HIGH-002: Edge Case Tests for Gap Analysis
    // ========================================================================

    /// Test 4-prime CRT reconstruction with large k values (up to ~99 bits)
    #[test]
    fn test_4prime_crt_large_k() {
        // 4-prime config: k_max can be ~99 bits, requiring 4 anchor primes (~125 bits capacity)
        let main_primes = vec![998244353u64, 985661441, 754974721, 469762049];

        let ctx = DualRNSContext::for_fhe_coeff_domain(&main_primes, 4096);

        println!("=== 4-Prime CRT Large k Test ===");
        println!("Main primes: {:?}", main_primes);
        println!(
            "Anchor primes: {:?}",
            &ctx.anchor.primes[..4.min(ctx.anchor.primes.len())]
        );

        // Compute M_level = product of main primes (we work mod this truncated to u128 range)
        let m_level: u128 = main_primes
            .iter()
            .fold(1u128, |acc, &p| acc.saturating_mul(p as u128));
        println!(
            "M_level = {} ({} bits)",
            m_level,
            128 - m_level.leading_zeros()
        );

        // Test with k values of increasing size that fit in anchor capacity
        let a4_capacity: u128 = ctx.anchor.primes[..4.min(ctx.anchor.primes.len())]
            .iter()
            .map(|&p| p as u128)
            .product();
        println!(
            "Anchor capacity (4 primes) = {} ({} bits)",
            a4_capacity,
            128 - a4_capacity.leading_zeros()
        );

        let test_k_values: Vec<u128> = vec![
            0,
            1,
            (1u128 << 32) - 1, // 32-bit k
            (1u128 << 60) - 1, // 60-bit k (safe range)
            (1u128 << 80) - 1, // 80-bit k
        ];

        for k_true in test_k_values {
            if k_true >= a4_capacity {
                println!(
                    "  k = {} ({} bits): SKIP (exceeds anchor capacity)",
                    k_true,
                    128 - k_true.leading_zeros()
                );
                continue;
            }

            // Construct v = v_main + k * M, then compute v_anchor_rns
            // For simplicity, use v_main = 0, so v = k * M
            let v_main = U256::zero();
            // v_exact = k * M (may overflow u128, so compute residues directly)

            // Compute v_anchor_rns[i] = (k * M) mod anchor_primes[i]
            // = ((k mod a_i) * (M mod a_i)) mod a_i
            let v_anchor_rns: Vec<u64> = ctx
                .anchor
                .primes
                .iter()
                .map(|&a_i| {
                    let k_mod_ai = (k_true % a_i as u128) as u64;
                    let m_mod_ai = (m_level % a_i as u128) as u64;
                    ((k_mod_ai as u128 * m_mod_ai as u128) % a_i as u128) as u64
                })
                .collect();

            // Use extract_k_rns_level to recover k
            let k_reconstructed = ctx.extract_k_rns_level(v_main, &v_anchor_rns, &main_primes);

            assert_eq!(
                k_reconstructed,
                U256::from_u128(k_true),
                "4-prime CRT failed for k = {} ({} bits)",
                k_true,
                128 - k_true.leading_zeros().max(1)
            );
            println!(
                "  k = {} ({} bits): OK",
                k_true,
                128 - k_true.leading_zeros().max(1)
            );
        }

        println!("=== 4-Prime CRT Large k Test PASSED ===");
    }

    /// Test signed-k boundary behavior at A/2
    #[test]
    fn test_signed_k_boundary() {
        let main_primes = vec![998244353u64, 985661441, 754974721];
        let _anchor_primes = vec![2013265921u64, 2281701377, 2483027969];

        let ctx = DualRNSContext::for_fhe_coeff_domain(&main_primes, 4096);

        // Compute A (product of 3 anchor primes) - this is ~94 bits
        let a_product: u128 = ctx.anchor.primes[..3].iter().map(|&p| p as u128).product();
        let a_half = a_product / 2;

        println!("=== Signed-k Boundary Test ===");
        println!(
            "A (3 anchors) = {} ({} bits)",
            a_product,
            128 - a_product.leading_zeros()
        );
        println!("A/2 = {}", a_half);

        // Test values around A/2 boundary
        let test_cases: Vec<(u128, bool)> = vec![
            (a_half - 100, false), // Below A/2: positive k
            (a_half - 1, false),   // Just below A/2: positive k
            (a_half, true),        // Exactly A/2: could be either (boundary)
            (a_half + 1, true),    // Just above A/2: negative k
            (a_half + 100, true),  // Above A/2: negative k
        ];

        for (k_value, expected_negative) in test_cases {
            if k_value >= a_product {
                continue; // Skip values outside range
            }

            // Check if k is interpreted as negative (k > A/2)
            let is_negative = k_value > a_half;

            // Compute signed magnitude
            let magnitude = if is_negative {
                a_product - k_value // |k_signed| = A - k
            } else {
                k_value
            };

            println!(
                "  k = {}: is_negative = {} (expected {}), magnitude = {}",
                k_value, is_negative, expected_negative, magnitude
            );

            // Verify boundary behavior is consistent
            if k_value != a_half {
                // Skip exact boundary (ambiguous)
                assert_eq!(
                    is_negative, expected_negative,
                    "Signed-k boundary mismatch at k = {}",
                    k_value
                );
            }
        }

        println!("=== Signed-k Boundary Test PASSED ===");
    }

    /// Test anchor capacity validation assertion
    #[test]
    #[should_panic(expected = "Level exceeds main prime count")]
    fn test_anchor_capacity_insufficient() {
        // Create context with only 3 main primes
        let main_primes = vec![998244353u64, 985661441, 754974721]; // 3 main initially
        let anchor_primes = vec![2013265921u64, 2281701377, 2483027969]; // Only 3 anchor

        // Create context with 3 main primes
        let ctx = DualRNSContext::new(main_primes.clone(), anchor_primes, 4096);

        // Now try to extract_k with 4 main primes - should panic because
        // the context was created with only 3 main primes
        let four_main_primes = vec![998244353u64, 985661441, 754974721, 469762049];
        let v_anchor_rns = vec![0u64; ctx.anchor.primes.len()];
        let _ = ctx.extract_k_rns_level(U256::zero(), &v_anchor_rns, &four_main_primes);
    }

    /// Test u128 overflow boundary in 4-prime CRT
    #[test]
    fn test_4prime_crt_near_u128_limit() {
        let main_primes = vec![998244353u64, 985661441, 754974721, 469762049];

        let ctx = DualRNSContext::for_fhe_coeff_domain(&main_primes, 4096);

        // Compute M_level
        let m_level: u128 = main_primes
            .iter()
            .fold(1u128, |acc, &p| acc.saturating_mul(p as u128));

        // 4 anchor primes give ~125 bits capacity
        let a4_product: u128 = ctx.anchor.primes[..4.min(ctx.anchor.primes.len())]
            .iter()
            .map(|&p| p as u128)
            .product();

        println!("=== 4-Prime CRT u128 Boundary Test ===");
        println!(
            "A4 product = {} ({} bits)",
            a4_product,
            128 - a4_product.leading_zeros()
        );
        println!(
            "M_level = {} ({} bits)",
            m_level,
            128 - m_level.leading_zeros()
        );

        // Test k values that fit in anchor capacity
        // Stay well under capacity to avoid edge issues
        let test_k_values: Vec<u128> = vec![
            (1u128 << 90) - 1,  // 90-bit k
            (1u128 << 100) - 1, // 100-bit k (if fits)
            a4_product / 4,     // Quarter of capacity
        ];

        for k_true in test_k_values {
            if k_true >= a4_product {
                println!(
                    "  k ({} bits): SKIP (exceeds anchor capacity)",
                    128 - k_true.leading_zeros()
                );
                continue;
            }

            // Construct v_anchor_rns = (k * M) mod each anchor prime
            let v_main = U256::zero();
            let v_anchor_rns: Vec<u64> = ctx
                .anchor
                .primes
                .iter()
                .map(|&a_i| {
                    let k_mod_ai = (k_true % a_i as u128) as u64;
                    let m_mod_ai = (m_level % a_i as u128) as u64;
                    ((k_mod_ai as u128 * m_mod_ai as u128) % a_i as u128) as u64
                })
                .collect();

            let k_reconstructed = ctx.extract_k_rns_level(v_main, &v_anchor_rns, &main_primes);

            assert_eq!(
                k_reconstructed,
                U256::from_u128(k_true),
                "u128 boundary CRT failed for k = {} ({} bits)",
                k_true,
                128 - k_true.leading_zeros()
            );
            println!("  k ({} bits): OK", 128 - k_true.leading_zeros());
        }

        println!("=== 4-Prime CRT u128 Boundary Test PASSED ===");
    }

    // ========================================================================
    // U256 Arithmetic Correctness Tests
    // ========================================================================

    #[test]
    fn test_wide_mul_256_mid_carry_overflow() {
        // wide_mul_256(u128::MAX, u128::MAX) computes (2^128-1)^2.
        //
        // Correct: (2^128-1)^2 = 2^256 - 2^129 + 1
        //   lo = 1
        //   hi = 2^128 - 2 = u128::MAX - 1
        //
        // Bug: The internal cross-term sum `mid = hi_lo + lo_hi` overflows u128
        // when both inputs have all four 64-bit quarter-words populated (here
        // each quarter is u64::MAX). The lost carry corrupts the result.
        let (lo, hi) = U256::wide_mul_256(u128::MAX, u128::MAX);
        assert_eq!(lo, 1, "lo of (2^128-1)^2 should be 1");
        assert_eq!(
            hi,
            u128::MAX - 1,
            "hi of (2^128-1)^2 should be u128::MAX - 1"
        );
    }

    #[test]
    fn test_wide_mul_256_cross_term_boundary() {
        // A targeted case where hi_lo + lo_hi just barely overflows u128.
        //
        // Choose a = (u64::MAX << 64) | u64::MAX = u128::MAX
        //        b = (1 << 64) | u64::MAX
        //
        // b = 2^64 + (2^64 - 1) = 2^65 - 1
        // a * b = (2^128-1)(2^65-1) = 2^193 - 2^128 - 2^65 + 1
        //
        // Decompose into (lo, hi) where value = lo + hi * 2^128:
        //   Start:    hi = 2^65, lo = 0       (from 2^193)
        //   -2^128:   hi = 2^65 - 1, lo = 0
        //   -2^65:    hi = 2^65 - 2, lo = 2^128 - 2^65  (borrow from hi)
        //   +1:       hi = 2^65 - 2, lo = 2^128 - 2^65 + 1
        let a = u128::MAX;
        let b = (1u128 << 64) | (u64::MAX as u128);
        let (lo, hi) = U256::wide_mul_256(a, b);

        let expected_lo = u128::MAX - (1u128 << 65) + 2; // 2^128 - 2^65 + 1
        let expected_hi = (1u128 << 65) - 2;
        assert_eq!(lo, expected_lo, "lo mismatch for cross-term boundary case");
        assert_eq!(hi, expected_hi, "hi mismatch for cross-term boundary case");
    }

    #[test]
    fn test_mul_low_large_lo_triggers_wide_mul_overflow() {
        // mul_low delegates to wide_mul_256(self.lo, other.lo) when both .hi are 0.
        // This exercises the same mid carry overflow path.
        //
        // (2^128-1)^2 = 2^256 - 2^129 + 1
        // Low 256 bits: U256 { lo: 1, hi: u128::MAX - 1 }
        let a = U256 {
            lo: u128::MAX,
            hi: 0,
        };
        let b = U256 {
            lo: u128::MAX,
            hi: 0,
        };
        let result = a.mul_low(b);
        assert_eq!(
            result,
            U256 {
                lo: 1,
                hi: u128::MAX - 1
            }
        );
    }

    #[test]
    fn test_mul_low_kelim_scale_values() {
        // Simulate extract_digit_dual: k.mul_low(m_product_level) where both
        // k.lo and m_product_level.lo have large upper 64-bit halves.
        //
        // Use the secure_192 scale: M_level ~= 2^150, k can be up to ~2^150.
        // Both .lo fields are full 128-bit values with all quarters populated.
        //
        // Verify correctness by checking (a * b) mod several coprime u64 moduli.
        // If wide_mul_256 is wrong, the residues won't match.
        let a = U256 {
            lo: 0xDEADBEEF_12345678_CAFEBABE_87654321_u128,
            hi: 0,
        };
        let b = U256 {
            lo: 0xFEDCBA98_AABBCCDD_11223344_55667788_u128,
            hi: 0,
        };
        let result = a.mul_low(b);

        // Cross-check: (a.lo * b.lo) mod p should equal result mod p for small primes.
        // This works because when both .hi are 0, mul_low is just wide_mul_256.
        let check_primes: &[u64] = &[998244353, 985661441, 754974721, 469762049];
        for &p in check_primes {
            let a_mod = (a.lo % p as u128) as u64;
            let b_mod = (b.lo % p as u128) as u64;
            let expected = ((a_mod as u128) * (b_mod as u128) % (p as u128)) as u64;
            let got = result.mod_u64(p);
            assert_eq!(
                got, expected,
                "mul_low residue mod {} mismatch: got {}, expected {}",
                p, got, expected
            );
        }
    }

    #[test]
    fn test_product_u64s_secure_256_primes() {
        // Verify product_u64s correctly computes the modulus product for secure_256
        // (7 primes, ~237 bits total). This exercises mul_u64 iteratively.
        let primes: &[u64] = &[
            998244353, 985661441, 754974721, 469762049, 167772161, 595591169, 645922817,
        ];
        let product = U256::product_u64s(primes);

        // Cross-check: product mod each prime should be 0
        for &p in primes {
            assert_eq!(
                product.mod_u64(p),
                0,
                "product_u64s mod prime {} should be 0",
                p
            );
        }

        // Verify bit-length is in expected range (~204 bits for these 7 primes)
        let bl = product.bitlen();
        assert!(
            bl >= 200 && bl <= 210,
            "secure_256 product bit-length {} outside expected range 200..210",
            bl
        );
    }

    #[test]
    fn test_mul_u64_kelim_rescale_scale() {
        // Simulate k_mod_delta * t in k_elim_rescale_dual for secure_192.
        //
        // secure_192 primes: [998244353, 985661441, 754974721, 469762049, 167772161]
        // M_level = product ≈ 2^150
        // delta = M_level / t where t = 65537
        // k_mod_delta < delta ≈ 2^134
        // k_base = k_mod_delta * t ≈ 2^150 (must fit in 256 bits)
        let primes: &[u64] = &[998244353, 985661441, 754974721, 469762049, 167772161];
        let m_level = U256::product_u64s(primes);
        let t: u64 = 65537;
        let (delta, r) = m_level.div_mod_u64(t);

        // Use delta - 1 as a worst-case k_mod_delta (just under the maximum)
        let k_mod_delta = delta.sub(U256::one());

        // k_base = k_mod_delta * t
        let k_base = k_mod_delta.mul_u64(t);

        // Verify: k_base < m_level (since k_mod_delta < delta = floor(M/t))
        assert!(k_base.lt(m_level), "k_base should be < m_level");

        // Verify: k_base + r should approximate m_level
        // k_mod_delta * t + k_mod_delta * r ≈ k_mod_delta * (t + r) but we just check k_base fits
        assert!(k_base.bitlen() <= 256, "k_base should fit in 256 bits");

        // k_rem = k_mod_delta * r
        let k_rem = k_mod_delta.mul_u64(r);
        assert!(k_rem.lt(m_level), "k_rem should be < m_level");
    }

    #[test]
    fn test_try_to_int_level_returns_some_for_valid_configs() {
        use crate::params::secure_configs::SecureConfig;
        let config = SecureConfig::secure_128().into_config();
        let rns = RNSContext::new(config.primes.clone(), config.n);

        // secure_128 has 3 x 30-bit primes, product fits u128
        let level = config.primes.len();
        let residues: Vec<u64> = config.primes.iter().map(|&p| 42 % p).collect();

        for lvl in 1..=level {
            let sub_residues: Vec<u64> = residues[..lvl].to_vec();
            let result = rns.try_to_int_level(&sub_residues, lvl);
            assert!(
                result.is_some(),
                "Level {} should succeed for secure_128",
                lvl
            );
        }
    }

    #[test]
    fn test_try_to_int_level_matches_to_int_level() {
        let primes = vec![998244353u64, 985661441, 754974721];
        let n = 4096;
        let rns = RNSContext::new(primes.clone(), n);

        for level in 1..=3 {
            let residues: Vec<u64> = primes[..level].iter().map(|&p| 42 % p).collect();
            let try_result = rns.try_to_int_level(&residues, level);
            assert!(try_result.is_some());
            let direct_result = rns.to_int_level(&residues, level);
            assert_eq!(
                try_result.unwrap(),
                direct_result,
                "try_to_int_level and to_int_level must agree at level {}",
                level
            );
        }
    }

    /// When the full chain's product overflows u128, try_to_int_level at full level
    /// must return None rather than panicking.
    #[test]
    fn test_try_to_int_level_returns_none_for_overflow_chain() {
        use crate::params::production::PRODUCTION_PRIMES_30BIT;
        // Use all 15 primes — product is ~450 bits, way beyond u128
        let primes: Vec<u64> = PRODUCTION_PRIMES_30BIT.to_vec();
        let n = 8192;
        let rns = RNSContext::new(primes.clone(), n);
        // The RNS context's product should be 0 (overflow sentinel)
        assert_eq!(rns.product, 0, "15x30-bit primes should overflow u128");

        // Residues at full level
        let residues: Vec<u64> = primes.iter().map(|&p| 42 % p).collect();
        let result = rns.try_to_int_level(&residues, primes.len());
        assert!(
            result.is_none(),
            "try_to_int_level at full overflow chain must return None, got {:?}",
            result
        );
    }

    /// Partial levels of a large chain that still fit in u128 should still work.
    #[test]
    fn test_try_to_int_level_partial_overflow_chain_works() {
        use crate::params::production::PRODUCTION_PRIMES_30BIT;
        let primes: Vec<u64> = PRODUCTION_PRIMES_30BIT.to_vec();
        let n = 8192;
        let rns = RNSContext::new(primes.clone(), n);

        // 4 primes × 30 bits = 120 bits — fits in u128
        let level = 4;
        let residues: Vec<u64> = primes[..level].iter().map(|&p| 42 % p).collect();
        let result = rns.try_to_int_level(&residues, level);
        assert!(result.is_some(), "4 primes (120 bits) should fit in u128");
    }
}
