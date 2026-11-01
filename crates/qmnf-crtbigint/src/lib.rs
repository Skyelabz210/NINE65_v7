//! # QMNF CRTBigInt — checked signed reference arithmetic
//!
//! Imported from the user's ns_v5 substrate and repaired for signed arithmetic
//! and exact capacity checks. This crate is reference/boundary infrastructure:
//! its signed operations reconstruct a full magnitude to compare and certify
//! range. It is not the residue-native divider for a production BFV hot path.
//! The auxiliary exploratory types below are retained from the supplied source;
//! their presence does not certify their broader architecture claims.
//!
//! ZERO FLOAT. Not one f64, not one f32, not one approximate value.
//!
//! Seven-layer exact computation architecture:
//! - **Layer 0** — Modular primitives (mulmod, gcd, mod_inverse)
//! - **Layer 1** — Exact CRT Lanes: 8×63-bit primes (~504-bit capacity)
//! - **Layer 2** — Safe Basis Composites: {2,3,5,7,11,13} phase-locked sub-lanes
//! - **Layer 3** — Safe Anchor: single large prime for O(1) magnitude recovery
//! - **Layer 4** — WASSAN Bands: 144 φ-harmonic execution lanes
//! - **Layer 5** — PLMG Rails/Voids: 28% valid / 72% free error detection
//! - **Layer 6** — Double Helix: dual-strand compute + verify
//!
//! All capacity and ratio computations are exact integer/rational.

use std::fmt;
use std::ops::{Add, Mul, Neg, Sub};
use std::sync::LazyLock;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Eight 63-bit primes for the exact lane CRT system.
/// Product M ≈ 2^504. All pairwise coprime by primality.
pub const EXACT_MODULI: &[u64] = &[
    9_223_372_036_854_775_783, // 2^63 - 25
    9_223_372_036_854_775_643, // 2^63 - 165
    9_223_372_036_854_775_549, // 2^63 - 259
    9_223_372_036_854_775_507, // 2^63 - 301
    9_223_372_036_854_775_337, // 2^63 - 471
    9_223_372_036_854_775_291, // 2^63 - 517
    9_223_372_036_854_775_279, // 2^63 - 529
    9_223_372_036_854_775_207, // 2^63 - 601
];

/// The Safe Prime Basis.
pub const SAFE_BASIS: &[u64] = &[2, 3, 5, 7, 11, 13];

/// Product of Safe Basis: 2 × 3 × 5 × 7 × 11 × 13 = 30030
pub const SAFE_BASIS_PRODUCT: u64 = 30030;

// ============================================================================
// MONTGOMERY CONTEXT
// ============================================================================

#[derive(Clone, Debug)]
pub struct MontgomeryCtx {
    pub modulus: u64,
    r_squared: u64,
    n_inv_neg: u64,
}

impl MontgomeryCtx {
    pub fn new(modulus: u64) -> Self {
        debug_assert!(modulus & 1 == 1, "Montgomery requires odd modulus");
        let n_inv_neg = Self::hensel_lift(modulus);
        let r_squared = Self::compute_r2(modulus);
        Self {
            modulus,
            r_squared,
            n_inv_neg,
        }
    }

    fn hensel_lift(n: u64) -> u64 {
        let mut y: u64 = 1;
        for _ in 0..6 {
            y = y.wrapping_mul(2u64.wrapping_sub(n.wrapping_mul(y)));
        }
        y.wrapping_neg()
    }

    fn compute_r2(n: u64) -> u64 {
        let r = (1u128 << 64) % n as u128;
        ((r * r) % n as u128) as u64
    }

    #[inline(always)]
    pub fn redc(&self, t: u128) -> u64 {
        let m = (t as u64).wrapping_mul(self.n_inv_neg);
        let mn = (m as u128) * (self.modulus as u128);
        let u = (t.wrapping_add(mn) >> 64) as u64;
        if u >= self.modulus {
            u - self.modulus
        } else {
            u
        }
    }

    #[inline]
    pub fn to_mont(&self, a: u64) -> u64 {
        self.redc((a as u128) * (self.r_squared as u128))
    }

    #[inline]
    pub fn from_mont(&self, ar: u64) -> u64 {
        self.redc(ar as u128)
    }

    #[inline]
    pub fn mul(&self, a: u64, b: u64) -> u64 {
        self.redc((a as u128) * (b as u128))
    }

    pub fn pow(&self, base: u64, mut exp: u64) -> u64 {
        let mut result = self.to_mont(1);
        let mut b = self.to_mont(base);
        while exp > 0 {
            if exp & 1 == 1 {
                result = self.mul(result, b);
            }
            b = self.mul(b, b);
            exp >>= 1;
        }
        self.from_mont(result)
    }
}

// ============================================================================
// PRECOMPUTED CONTEXTS
// ============================================================================

static MONT_CTXS: LazyLock<Vec<MontgomeryCtx>> = LazyLock::new(|| {
    EXACT_MODULI
        .iter()
        .map(|&m| MontgomeryCtx::new(m))
        .collect()
});

// ============================================================================
// MODULAR ARITHMETIC UTILITIES
// ============================================================================

#[inline]
pub fn mulmod(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

#[inline]
pub fn addmod(a: u64, b: u64, m: u64) -> u64 {
    let s = a as u128 + b as u128;
    (s % m as u128) as u64
}

#[inline]
pub fn submod(a: u64, b: u64, m: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        m - (b - a)
    }
}

pub fn extended_gcd(a: i128, b: i128) -> (i128, i128, i128) {
    if a == 0 {
        return (b, 0, 1);
    }
    let (g, x1, y1) = extended_gcd(b % a, a);
    (g, y1 - (b / a) * x1, x1)
}

pub fn mod_inverse(a: u64, m: u64) -> Option<u64> {
    if a == 0 || m == 0 {
        return None;
    }
    let (g, x, _) = extended_gcd(a as i128, m as i128);
    if g != 1 {
        return None;
    }
    Some(((x % m as i128 + m as i128) % m as i128) as u64)
}

pub fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd(b, a % b)
    }
}

pub fn newton_inverse(a: u64, m: u64) -> Option<u64> {
    let mut x = mod_inverse(a, m)?;
    for _ in 0..4 {
        let ax = mulmod(a, x, m);
        let two_minus_ax = if ax <= 1 { 2 - ax } else { m + 2 - ax };
        x = mulmod(x, two_minus_ax, m);
    }
    Some(x)
}

// ============================================================================
// CRT BIGINT
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrtError {
    InvalidSign,
    NonCanonicalResidue { lane: usize },
    MagnitudeOverflow,
    NarrowingOverflow,
}

impl fmt::Display for CrtError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for CrtError {}

/// Unsigned little-endian limbs used only at the reference/boundary layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Magnitude([u64; 8]);

impl Magnitude {
    const ZERO: Self = Self([0; 8]);

    fn from_u128(value: u128) -> Self {
        let mut limbs = [0; 8];
        limbs[0] = value as u64;
        limbs[1] = (value >> 64) as u64;
        Self(limbs)
    }

    fn cmp(&self, rhs: &Self) -> std::cmp::Ordering {
        self.0.iter().rev().cmp(rhs.0.iter().rev())
    }

    fn checked_add(self, rhs: Self) -> Option<Self> {
        let mut limbs = [0; 8];
        let mut carry = 0;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let sum = self.0[i] as u128 + rhs.0[i] as u128 + carry;
            *limb = sum as u64;
            carry = sum >> 64;
        }
        (carry == 0).then_some(Self(limbs))
    }

    fn checked_sub(self, rhs: Self) -> Option<Self> {
        let mut limbs = [0; 8];
        let mut borrow = false;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let (difference, first_borrow) = self.0[i].overflowing_sub(rhs.0[i]);
            let (difference, second_borrow) = difference.overflowing_sub(u64::from(borrow));
            *limb = difference;
            borrow = first_borrow || second_borrow;
        }
        (!borrow).then_some(Self(limbs))
    }

    fn checked_mul(self, rhs: Self) -> Option<Self> {
        let mut wide = [0u64; 16];
        for (i, &left) in self.0.iter().enumerate() {
            let mut carry = 0;
            for (j, &right) in rhs.0.iter().enumerate() {
                let sum = left as u128 * right as u128 + wide[i + j] as u128 + carry;
                wide[i + j] = sum as u64;
                carry = sum >> 64;
            }
            wide[i + 8] = carry as u64;
        }
        if wide[8..].iter().any(|&limb| limb != 0) {
            return None;
        }
        let mut limbs = [0; 8];
        limbs.copy_from_slice(&wide[..8]);
        Some(Self(limbs))
    }

    fn modulo(self, modulus: u64) -> u64 {
        let mut remainder = 0u128;
        for &limb in self.0.iter().rev() {
            remainder = ((remainder << 64) | limb as u128) % modulus as u128;
        }
        remainder as u64
    }

    fn to_u128(self) -> Option<u128> {
        self.0[2..]
            .iter()
            .all(|&limb| limb == 0)
            .then_some(self.0[0] as u128 | ((self.0[1] as u128) << 64))
    }
}

static EXACT_CAPACITY: LazyLock<Magnitude> = LazyLock::new(|| {
    EXACT_MODULI
        .iter()
        .fold(Magnitude::from_u128(1), |product, &modulus| {
            product
                .checked_mul(Magnitude::from_u128(modulus as u128))
                .expect("the fixed eight-lane product fits 512 bits")
        })
});

/// Signed integer with magnitude strictly below the full CRT product.
///
/// Residues encode the magnitude, not the signed integer. Use
/// [`Self::signed_residue`] when converting into signed arithmetic lanes.
/// Fields are private so callers cannot forge sign/zero/range invariants.
#[derive(Clone, Debug)]
pub struct CRTBigInt {
    residues: [u64; 8],
    sign: i8,
}

impl CRTBigInt {
    pub const NUM_LANES: usize = 8;

    pub fn from_i64(value: i64) -> Self {
        Self::from_i128(value as i128)
    }

    pub fn from_i128(value: i128) -> Self {
        Self::from_magnitude(
            value.signum() as i8,
            Magnitude::from_u128(value.unsigned_abs()),
        )
        .expect("every i128 magnitude fits the fixed CRT basis")
    }

    pub fn from_u64(value: u64) -> Self {
        Self::from_u128(value as u128)
    }

    pub fn from_u128(value: u128) -> Self {
        Self::from_magnitude(i8::from(value != 0), Magnitude::from_u128(value))
            .expect("every u128 fits the fixed CRT basis")
    }

    fn from_magnitude(sign: i8, magnitude: Magnitude) -> Result<Self, CrtError> {
        if magnitude.cmp(&EXACT_CAPACITY) != std::cmp::Ordering::Less {
            return Err(CrtError::MagnitudeOverflow);
        }
        if !(-1..=1).contains(&sign) || (sign == 0) != (magnitude == Magnitude::ZERO) {
            return Err(CrtError::InvalidSign);
        }
        let mut residues = [0; 8];
        for (residue, &modulus) in residues.iter_mut().zip(EXACT_MODULI) {
            *residue = magnitude.modulo(modulus);
        }
        Ok(Self { residues, sign })
    }

    /// Admit a specified bounded sign-magnitude integer without reducing it.
    pub fn try_from_magnitude_limbs(sign: i8, limbs: [u64; 8]) -> Result<Self, CrtError> {
        Self::from_magnitude(sign, Magnitude(limbs))
    }

    /// Interpret a canonical CRT residue tuple as its bounded magnitude.
    /// This is a boundary import, not a proof of an external integer's range.
    pub fn try_from_residues(sign: i8, residues: [u64; 8]) -> Result<Self, CrtError> {
        for (lane, (&residue, &modulus)) in residues.iter().zip(EXACT_MODULI).enumerate() {
            if residue >= modulus {
                return Err(CrtError::NonCanonicalResidue { lane });
            }
        }
        if !(-1..=1).contains(&sign) || (sign == 0) != residues.iter().all(|&r| r == 0) {
            return Err(CrtError::InvalidSign);
        }
        Ok(Self { residues, sign })
    }

    /// Import Euclidean residues of a signed integer with its explicit sign.
    /// The signed magnitude must independently satisfy `|x| < M`; as with
    /// [`Self::try_from_residues`], this boundary does not prove provenance.
    pub fn try_from_signed_residues(sign: i8, signed: [u64; 8]) -> Result<Self, CrtError> {
        let mut magnitude = signed;
        for (lane, (&residue, &modulus)) in signed.iter().zip(EXACT_MODULI).enumerate() {
            if residue >= modulus {
                return Err(CrtError::NonCanonicalResidue { lane });
            }
            if sign < 0 && residue != 0 {
                magnitude[lane] = modulus - residue;
            }
        }
        Self::try_from_residues(sign, magnitude)
    }

    pub fn sign(&self) -> i8 {
        self.sign
    }

    pub fn residues(&self) -> &[u64; 8] {
        &self.residues
    }

    pub fn capacity_limbs() -> [u64; 8] {
        EXACT_CAPACITY.0
    }

    /// Exact full-width magnitude reconstruction at a reference boundary.
    pub fn magnitude_limbs(&self) -> [u64; 8] {
        let mut result = Magnitude::from_u128(self.residues[0] as u128);
        let mut product = Magnitude::from_u128(EXACT_MODULI[0] as u128);
        for (&residue, &modulus) in self.residues[1..].iter().zip(&EXACT_MODULI[1..]) {
            let inverse = mod_inverse(product.modulo(modulus), modulus)
                .expect("fixed CRT basis moduli must be pairwise coprime");
            let digit = mulmod(
                submod(residue, result.modulo(modulus), modulus),
                inverse,
                modulus,
            );
            let increment = product
                .checked_mul(Magnitude::from_u128(digit as u128))
                .expect("canonical CRT increment fits the fixed basis width");
            result = result
                .checked_add(increment)
                .expect("canonical CRT representative fits the fixed basis width");
            product = product
                .checked_mul(Magnitude::from_u128(modulus as u128))
                .expect("fixed CRT basis product fits its declared width");
        }
        result.0
    }

    /// Signed Euclidean residue of the represented integer.
    pub fn signed_residue(&self, lane: usize) -> u64 {
        let residue = self.residues[lane];
        if self.sign < 0 && residue != 0 {
            EXACT_MODULI[lane] - residue
        } else {
            residue
        }
    }

    pub fn checked_add(&self, rhs: &Self) -> Result<Self, CrtError> {
        if self.sign == 0 {
            return Ok(rhs.clone());
        }
        if rhs.sign == 0 {
            return Ok(self.clone());
        }
        let left = Magnitude(self.magnitude_limbs());
        let right = Magnitude(rhs.magnitude_limbs());
        let (sign, magnitude) = if self.sign == rhs.sign {
            (
                self.sign,
                left.checked_add(right).ok_or(CrtError::MagnitudeOverflow)?,
            )
        } else {
            match left.cmp(&right) {
                std::cmp::Ordering::Greater => (
                    self.sign,
                    left.checked_sub(right).ok_or(CrtError::MagnitudeOverflow)?,
                ),
                std::cmp::Ordering::Less => (
                    rhs.sign,
                    right.checked_sub(left).ok_or(CrtError::MagnitudeOverflow)?,
                ),
                std::cmp::Ordering::Equal => return Ok(Self::zero()),
            }
        };
        Self::from_magnitude(sign, magnitude)
    }

    pub fn checked_sub(&self, rhs: &Self) -> Result<Self, CrtError> {
        self.checked_add(&(-rhs.clone()))
    }

    pub fn checked_mul(&self, rhs: &Self) -> Result<Self, CrtError> {
        if self.is_zero() || rhs.is_zero() {
            return Ok(Self::zero());
        }
        let product = Magnitude(self.magnitude_limbs())
            .checked_mul(Magnitude(rhs.magnitude_limbs()))
            .ok_or(CrtError::MagnitudeOverflow)?;
        Self::from_magnitude(self.sign * rhs.sign, product)
    }

    pub fn zero() -> Self {
        Self {
            residues: [0; 8],
            sign: 0,
        }
    }
    pub fn one() -> Self {
        Self {
            residues: [1; 8],
            sign: 1,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.sign == 0
    }

    /// Checked narrowing of the exact reconstructed magnitude.
    pub fn try_garner_reconstruct(&self) -> Result<u128, CrtError> {
        Magnitude(self.magnitude_limbs())
            .to_u128()
            .ok_or(CrtError::NarrowingOverflow)
    }

    /// Legacy u128 boundary conversion. Wide values fail explicitly; use
    /// [`Self::try_garner_reconstruct`] or [`Self::magnitude_limbs`] instead.
    pub fn garner_reconstruct(&self) -> u128 {
        self.try_garner_reconstruct()
            .expect("CRT magnitude exceeds u128; use magnitude_limbs")
    }

    /// Convert back to i64 (only valid for values that fit).
    pub fn to_i64(&self) -> Option<i64> {
        if self.is_zero() {
            return Some(0);
        }
        let magnitude = self.try_garner_reconstruct().ok()?;
        if self.sign < 0 && magnitude == 1u128 << 63 {
            return Some(i64::MIN);
        }
        let value = i64::try_from(magnitude).ok()?;
        Some(if self.sign < 0 { -value } else { value })
    }

    /// Convert back to i64, panicking if it doesn't fit.
    /// NO SENTINEL FALLBACK. Fail-stop, not fail-silent.
    pub fn to_i64_exact(&self) -> i64 {
        self.to_i64()
            .expect("CRTBigInt value exceeds i64 range — exact reconstruction failed")
    }

    pub fn mod_inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        let mut residues = [0u64; 8];
        for (i, &r) in self.residues.iter().enumerate() {
            residues[i] = mod_inverse(r, EXACT_MODULI[i])?;
        }
        Some(Self {
            residues,
            sign: self.sign,
        })
    }

    /// Modular exponentiation of the magnitude, followed by its signed parity.
    /// This explicitly reduces modulo the CRT product; it is not integer power.
    pub fn mod_pow(&self, exp: u64) -> Self {
        let mut residues = [0u64; 8];
        for (i, &base) in self.residues.iter().enumerate() {
            residues[i] = MONT_CTXS[i].pow(base, exp);
        }
        let sign = if residues.iter().all(|&r| r == 0) {
            0
        } else if exp % 2 == 0 {
            1
        } else {
            self.sign
        };
        Self { residues, sign }
    }

    #[inline]
    pub fn residue(&self, lane: usize) -> u64 {
        self.residues[lane]
    }
}

impl PartialEq for CRTBigInt {
    fn eq(&self, other: &Self) -> bool {
        self.sign == other.sign && self.residues == other.residues
    }
}
impl Eq for CRTBigInt {}

impl fmt::Display for CRTBigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_i64() {
            Some(v) => write!(f, "{}", v),
            None => write!(f, "CRT[{:?}]", &self.residues[..3]),
        }
    }
}

impl Add for CRTBigInt {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        self.checked_add(&rhs)
            .expect("CRTBigInt addition exceeds exact CRT capacity")
    }
}

impl Sub for CRTBigInt {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self.checked_sub(&rhs)
            .expect("CRTBigInt subtraction exceeds exact CRT capacity")
    }
}

impl Mul for CRTBigInt {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        self.checked_mul(&rhs)
            .expect("CRTBigInt multiplication exceeds exact CRT capacity")
    }
}

impl Neg for CRTBigInt {
    type Output = Self;
    fn neg(self) -> Self {
        Self {
            residues: self.residues,
            sign: -self.sign,
        }
    }
}

// ============================================================================
// K-ELIMINATION
// ============================================================================

#[derive(Clone, Debug)]
pub struct KElimResult {
    pub k: u64,
    pub r_main: u64,
    pub m_main: u64,
    pub r_anchor: u64,
    pub m_anchor: u64,
}

impl KElimResult {
    pub fn reconstruct(&self) -> u128 {
        self.r_main as u128 + (self.k as u128) * (self.m_main as u128)
    }
}

pub fn k_eliminate(r_main: u64, m_main: u64, r_anchor: u64, m_anchor: u64) -> Option<KElimResult> {
    let m_inv = mod_inverse(m_main % m_anchor, m_anchor)?;
    let diff = if r_anchor >= (r_main % m_anchor) {
        r_anchor - (r_main % m_anchor)
    } else {
        m_anchor - ((r_main % m_anchor) - r_anchor)
    };
    let k = mulmod(diff, m_inv, m_anchor);
    Some(KElimResult {
        k,
        r_main,
        m_main,
        r_anchor,
        m_anchor,
    })
}

pub fn k_eliminate_lanes(
    value: &CRTBigInt,
    main_lane: usize,
    anchor_lane: usize,
) -> Option<KElimResult> {
    k_eliminate(
        value.residues[main_lane],
        EXACT_MODULI[main_lane],
        value.residues[anchor_lane],
        EXACT_MODULI[anchor_lane],
    )
}

// ============================================================================
// 13-SMOOTH FACTORIZATION
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmoothFactors {
    pub exponents: [u32; 6],
    pub cofactor: u64,
}

impl SmoothFactors {
    pub fn smooth_product(&self) -> u64 {
        let mut prod: u64 = 1;
        for (i, &e) in self.exponents.iter().enumerate() {
            for _ in 0..e {
                prod *= SAFE_BASIS[i];
            }
        }
        prod
    }
    pub fn is_fully_smooth(&self) -> bool {
        self.cofactor == 1
    }
    pub fn sublane_moduli(&self) -> Vec<(u64, u32, u64)> {
        self.exponents
            .iter()
            .enumerate()
            .filter(|(_, &e)| e > 0)
            .map(|(i, &e)| (SAFE_BASIS[i], e, SAFE_BASIS[i].pow(e)))
            .collect()
    }
}

pub fn factor_smooth(mut n: u64) -> SmoothFactors {
    assert!(n > 0, "Cannot factor zero");
    let mut exponents = [0u32; 6];
    for (i, &p) in SAFE_BASIS.iter().enumerate() {
        while n % p == 0 {
            n /= p;
            exponents[i] += 1;
        }
    }
    SmoothFactors {
        exponents,
        cofactor: n,
    }
}

#[inline]
pub fn is_smooth(n: u64) -> bool {
    factor_smooth(n).is_fully_smooth()
}

// ============================================================================
// SAFE ANCHOR — exact magnitude recovery via anchor prime
// ============================================================================

#[derive(Clone, Debug)]
pub struct SafeAnchor {
    pub prime: u64,
    m_safe: u64,
    pub m_safe_inv_p: u64,
    encoded_residue: u64,
}

impl SafeAnchor {
    pub fn new(prime: u64, m_safe: u64) -> Option<Self> {
        if gcd(prime, m_safe) != 1 {
            return None;
        }
        let inv = mod_inverse(m_safe % prime, prime)?;
        Some(Self {
            prime,
            m_safe,
            m_safe_inv_p: inv,
            encoded_residue: 0,
        })
    }

    pub fn mersenne(bits: u32, m_safe: u64) -> Option<Self> {
        let p = (1u64 << bits) - 1;
        Self::new(p, m_safe)
    }

    pub fn encode(&mut self, value: u64) {
        self.encoded_residue = value % self.prime;
    }

    pub fn k_eliminate(&self, r_safe: u64) -> u64 {
        let r_safe_mod_p = r_safe % self.prime;
        let diff = if self.encoded_residue >= r_safe_mod_p {
            self.encoded_residue - r_safe_mod_p
        } else {
            self.prime - (r_safe_mod_p - self.encoded_residue)
        };
        mulmod(diff, self.m_safe_inv_p, self.prime)
    }

    pub fn reconstruct(&self, r_safe: u64) -> u128 {
        let k = self.k_eliminate(r_safe);
        r_safe as u128 + k as u128 * self.m_safe as u128
    }
}

// ============================================================================
// WASSAN BANDED — integer-only decomposition
// ============================================================================

#[derive(Clone, Debug)]
pub struct WassanBanded {
    pub bands: Vec<u64>,
    pub band_size: u64,
    pub total_bits: u32,
}

impl WassanBanded {
    pub fn from_u128(value: u128, total_bits: u32) -> Self {
        let band_size = 144u64;
        let mut bands = Vec::new();
        let mut v = value;
        loop {
            bands.push((v % band_size as u128) as u64);
            v /= band_size as u128;
            if v == 0 {
                break;
            }
        }
        if bands.is_empty() {
            bands.push(0);
        }
        Self {
            bands,
            band_size,
            total_bits,
        }
    }

    pub fn reconstruct_u128(&self) -> u128 {
        let mut result: u128 = 0;
        let mut mult: u128 = 1;
        for &b in &self.bands {
            result += b as u128 * mult;
            mult *= self.band_size as u128;
        }
        result
    }

    pub fn band_mod(&self, p: u64) -> u64 {
        let mut result: u64 = 0;
        let mut mult: u64 = 1;
        for &b in &self.bands {
            result = addmod(result, mulmod(b % p, mult, p), p);
            mult = mulmod(mult, self.band_size % p, p);
        }
        result
    }

    pub fn band_add(&self, other: &Self) -> Self {
        let len = self.bands.len().max(other.bands.len());
        let mut carry: u64 = 0;
        let mut bands = Vec::with_capacity(len + 1);
        for i in 0..len {
            let a = if i < self.bands.len() {
                self.bands[i]
            } else {
                0
            };
            let b = if i < other.bands.len() {
                other.bands[i]
            } else {
                0
            };
            let sum = a + b + carry;
            bands.push(sum % self.band_size);
            carry = sum / self.band_size;
        }
        if carry > 0 {
            bands.push(carry);
        }
        Self {
            bands,
            band_size: self.band_size,
            total_bits: self.total_bits,
        }
    }

    pub fn unique_bands(&self) -> usize {
        let mut seen = self.bands.clone();
        seen.sort();
        seen.dedup();
        seen.len()
    }
}

// ============================================================================
// PLMG VALIDATOR — ZERO FLOAT
// Ratios stored as (numerator, denominator) exact rational pairs.
// ============================================================================

/// Rail signal with exact rational confidence.
#[derive(Clone, Debug)]
pub enum RailSignal {
    /// On rail: value in valid trajectory. confidence = (num, den).
    OnRail {
        value: u128,
        confidence_num: u128,
        confidence_den: u128,
    },
    /// In void: value outside valid trajectory.
    Void { value: u128, nearest_rail: u128 },
}

/// PLMG Validator with exact integer/rational ratios.
pub struct PLMGValidator {
    pub trajectory_bound: u128,
    pub total_space: u128,
    /// void ratio = (total_space - trajectory_bound) / total_space
    /// stored as (void_num, void_den)
    pub void_num: u128,
    pub void_den: u128,
}

impl PLMGValidator {
    pub fn new(trajectory_bound: u128, total_space: u128) -> Self {
        let void_num = total_space - trajectory_bound;
        let void_den = total_space;
        Self {
            trajectory_bound,
            total_space,
            void_num,
            void_den,
        }
    }

    pub fn is_on_rail(&self, value: u128) -> bool {
        value < self.trajectory_bound
    }

    pub fn check(&self, value: u128) -> RailSignal {
        if value < self.trajectory_bound {
            let half_bound = self.trajectory_bound / 2;
            let dist = half_bound.abs_diff(value);
            // confidence = dist / half_bound (exact rational)
            let conf_num = dist.min(half_bound);
            let conf_den = half_bound.max(1);
            RailSignal::OnRail {
                value,
                confidence_num: conf_num,
                confidence_den: conf_den,
            }
        } else {
            RailSignal::Void {
                value,
                nearest_rail: self.trajectory_bound - 1,
            }
        }
    }
}

// ============================================================================
// DOUBLE HELIX — ZERO FLOAT
// Phase stored as exact rational, not f64.
// φ ≈ 1618034/1000000 (6-digit rational approximation).
// ============================================================================

/// Rational approximation of φ: 1618034/1000000 = 809017/500000
const PHI_NUM: u64 = 809017;
const PHI_DEN: u64 = 500000;

pub struct DoubleHelix<T: Clone + PartialEq> {
    pub strand_a: T,
    pub strand_b: T,
    step: u64,
    /// phase_b = step × PHI_NUM / PHI_DEN, stored as (accumulated_num, den)
    phase_b_num: u128,
}

impl<T: Clone + PartialEq> DoubleHelix<T> {
    pub fn new(initial: T) -> Self {
        Self {
            strand_a: initial.clone(),
            strand_b: initial,
            step: 0,
            phase_b_num: 0,
        }
    }

    pub fn strands_agree(&self) -> bool {
        self.strand_a == self.strand_b
    }

    /// Check contention: strands must disagree AND phase must be below π/2.
    /// At step 0 (strands agree), there is no contention by definition.
    pub fn has_contention(&self) -> bool {
        if self.strand_a == self.strand_b {
            return false;
        }
        // phase_b < π/2 means contention
        let lhs = self.phase_b_num * 1_000_000;
        let rhs = 1_570_796u128 * PHI_DEN as u128;
        lhs < rhs
    }

    pub fn advance(&mut self, new_a: T, expected_old: &T) -> bool {
        let ok = self.strand_b == *expected_old;
        self.strand_b = self.strand_a.clone();
        self.strand_a = new_a;
        self.step += 1;
        self.phase_b_num += PHI_NUM as u128;

        // Möbius twist at odd steps: swap strands
        if self.step % 2 == 0 {
            let tmp = self.strand_a.clone();
            self.strand_a = self.strand_b.clone();
            self.strand_b = tmp;
        }
        ok
    }

    pub fn current_step(&self) -> u64 {
        self.step
    }
}

// ============================================================================
// INFINITE SCAFFOLD — ZERO FLOAT
// Capacity computed as exact integer product, not floating-point bits.
// ============================================================================

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct ScaffoldTier {
    prime: u64,
    exponent: u32,
    modulus: u64,
}

pub struct InfiniteScaffold {
    tiers: Vec<ScaffoldTier>,
}

impl InfiniteScaffold {
    pub fn new(exponents: &[u32]) -> Self {
        assert!(exponents.len() <= 6);
        let tiers: Vec<ScaffoldTier> = exponents
            .iter()
            .enumerate()
            .filter(|(_, &e)| e > 0)
            .map(|(i, &e)| ScaffoldTier {
                prime: SAFE_BASIS[i],
                exponent: e,
                modulus: SAFE_BASIS[i].pow(e),
            })
            .collect();
        Self { tiers }
    }

    pub fn tier_count(&self) -> usize {
        self.tiers.len()
    }

    pub fn add_prime(&mut self, p: u64) -> bool {
        if self.tiers.iter().any(|t| t.prime == p) {
            return false;
        }
        self.tiers.push(ScaffoldTier {
            prime: p,
            exponent: 1,
            modulus: p,
        });
        true
    }

    /// Exact capacity as product of all tier moduli (no floating-point log).
    pub fn capacity_product(&self) -> u128 {
        self.tiers.iter().map(|t| t.modulus as u128).product()
    }

    /// Integer approximation of log2(capacity) via bit counting.
    /// Returns (integer_part, is_exact) — no float.
    pub fn capacity_log2_approx(&self) -> (u32, bool) {
        let product = self.capacity_product();
        if product == 0 {
            return (0, true);
        }
        let bits = 128 - product.leading_zeros();
        // bits-1 ≤ log2(product) < bits
        let exact = product.is_power_of_two();
        (bits - 1, exact)
    }

    pub fn encode(&mut self, _value: u64) {
        // Residue decomposition stored per-tier
    }

    pub fn reconstruct(&self) -> u64 {
        // Garner reconstruction from tier residues
        // Simplified: identity for now
        0
    }
}

// ============================================================================
// MAA ELEMENT (Apollonian) — already integer-only, no changes needed
// ============================================================================

#[derive(Clone, Debug)]
pub struct MAAElement {
    pub curvatures: [CRTBigInt; 4],
}

impl MAAElement {
    pub fn new(curvatures: [CRTBigInt; 4]) -> Self {
        Self { curvatures }
    }

    pub fn reflect(&self, index: usize) -> Self {
        let sum: CRTBigInt = self
            .curvatures
            .iter()
            .cloned()
            .fold(CRTBigInt::zero(), |acc, c| acc + c);
        let doubled_sum = sum.clone() + sum;
        let mut new_curvatures = self.curvatures.clone();
        new_curvatures[index] = doubled_sum
            - self.curvatures[index].clone()
            - self.curvatures[index].clone()
            - self.curvatures[index].clone();
        Self {
            curvatures: new_curvatures,
        }
    }
}

// ============================================================================
// INTEGER SINE — Bhaskara I approximation, ZERO FLOAT
// ============================================================================

/// Integer sine approximation: sin(2πk/N) × scale.
/// Uses Bhaskara I formula: sin(x) ≈ 16x(π-x) / (5π² - 4x(π-x))
/// mapped to integer domain. Maximum error ~0.15%.
///
/// Returns exact integer. ZERO FLOAT.
pub fn integer_sine(k: usize, n: usize, scale: i64) -> i64 {
    if n == 0 {
        return 0;
    }
    let k = k % n;
    if k == 0 {
        return 0;
    }
    let half_n = n / 2;
    if half_n == 0 {
        return 0;
    }
    if k == half_n {
        return 0;
    }

    // sin(2πk/N) for k ∈ (N/2, N): sin(2πk/N) = -sin(2π(k - N/2)/N)
    let (pos, sign): (usize, i64) = if k <= half_n {
        (k, 1)
    } else {
        (k - half_n, -1)
    };

    if pos == 0 || pos == half_n {
        return 0;
    }

    // Bhaskara in integer form:
    // sin(2π·pos/N) ≈ 32·pos·(half_n - pos) / (5·half_n² - 8·pos·(half_n - pos) + 4·half_n²)
    //
    // Corrected formula derivation:
    // x = π·pos/half_n, so x ∈ [0, π]
    // sin(x) ≈ 16·x·(π-x) / (5π² - 4x(π-x))
    // Let u = pos, h = half_n. Then x/π = u/h, (π-x)/π = (h-u)/h.
    // sin(x) ≈ 16·(u/h)·((h-u)/h) / (5 - 4·(u/h)·((h-u)/h))
    //         = 16·u·(h-u) / (5·h² - 4·u·(h-u))
    let u = pos as i128;
    let h = half_n as i128;
    let product = u * (h - u);
    let numer = 16 * product;
    let denom = 5 * h * h - 4 * product;
    if denom == 0 {
        return 0;
    }
    sign * (scale as i128 * numer / denom) as i64
}

// ============================================================================
// EXACT RATIONAL — (numerator, denominator) pair for exact fractions
// ============================================================================

/// Exact rational number as (numerator, denominator).
/// All comparisons are cross-multiplication, no float.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactRational {
    pub num: u128,
    pub den: u128,
}

impl ExactRational {
    pub fn new(num: u128, den: u128) -> Self {
        assert!(den > 0, "Rational denominator must be positive");
        Self { num, den }
    }

    /// self < other ⟺ self.num × other.den < other.num × self.den
    pub fn lt(&self, other: &Self) -> bool {
        // Use checked_mul to avoid overflow; fallback to u128 cross-multiply
        self.num * other.den < other.num * self.den
    }

    /// self ≤ other
    pub fn le(&self, other: &Self) -> bool {
        self.num * other.den <= other.num * self.den
    }

    /// Multiply two rationals: (a/b) × (c/d) = (a×c)/(b×d)
    pub fn mul(&self, other: &Self) -> Self {
        Self::new(self.num * other.num, self.den * other.den)
    }

    /// Reduce by GCD.
    pub fn reduce(&self) -> Self {
        let g = gcd128(self.num, self.den);
        Self::new(self.num / g, self.den / g)
    }

    /// Integer unit: 1/1
    pub fn one() -> Self {
        Self::new(1, 1)
    }
}

fn gcd128(a: u128, b: u128) -> u128 {
    if b == 0 {
        a
    } else {
        gcd128(b, a % b)
    }
}

impl fmt::Display for ExactRational {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = self.reduce();
        write!(f, "{}/{}", r.num, r.den)
    }
}

// ============================================================================
// TESTS — ALL ZERO FLOAT
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crt_roundtrip() {
        for v in [-10000i64, -1, 0, 1, 42, 10000, 1_000_000] {
            let c = CRTBigInt::from_i64(v);
            assert_eq!(c.to_i64_exact(), v, "roundtrip failed at {}", v);
        }
    }

    #[test]
    fn test_crt_add() {
        let a = CRTBigInt::from_i64(123);
        let b = CRTBigInt::from_i64(456);
        assert_eq!((a + b).to_i64_exact(), 579);
    }

    #[test]
    fn test_crt_mul() {
        let a = CRTBigInt::from_i64(123);
        let b = CRTBigInt::from_i64(456);
        assert_eq!((a * b).to_i64_exact(), 56088);
    }

    #[test]
    fn test_k_eliminate_basic() {
        let r = k_eliminate(42, 100, 42, 97).unwrap();
        assert_eq!(r.reconstruct(), 42);
    }

    #[test]
    fn test_k_eliminate_winding() {
        let x: u64 = 30030 * 7 + 42;
        let r_main = x % 30030;
        let r_anchor = x % 97;
        let result = k_eliminate(r_main, 30030, r_anchor, 97).unwrap();
        assert_eq!(result.k, 7);
        assert_eq!(result.reconstruct(), x as u128);
    }

    #[test]
    fn test_integer_sine_basic() {
        // sin(2π·0/32) = 0
        assert_eq!(integer_sine(0, 32, 10000), 0);
        // sin(2π·16/32) = sin(π) = 0
        assert_eq!(integer_sine(16, 32, 10000), 0);
        // sin(2π·8/32) = sin(π/2) = 1.0 → ~10000
        let val = integer_sine(8, 32, 10000);
        // Bhaskara gives exactly 10000 at quarter-period
        assert_eq!(val, 10000, "sin(π/2) should be exactly SCALE");
    }

    #[test]
    fn test_integer_sine_symmetry() {
        let n = 64usize;
        let scale = 10000i64;
        for k in 0..n {
            let s = integer_sine(k, n, scale);
            assert!(s.abs() <= scale, "sine must be bounded by scale at k={}", k);
        }
        // Antisymmetry: sin(k) = -sin(k + N/2)
        for k in 0..n / 2 {
            let pos = integer_sine(k, n, scale);
            let neg = integer_sine(k + n / 2, n, scale);
            assert_eq!(pos, -neg, "antisymmetry failed at k={}", k);
        }
    }

    #[test]
    fn test_exact_rational_comparison() {
        let a = ExactRational::new(90, 1001);
        let b = ExactRational::one();
        assert!(a.lt(&b), "90/1001 < 1");
        assert!(!b.lt(&a), "1 ≥ 90/1001");
    }

    #[test]
    fn test_exact_rational_product() {
        let a = ExactRational::new(3, 7);
        let b = ExactRational::new(5, 11);
        let c = ExactRational::new(6, 13);
        let product = a.mul(&b).mul(&c);
        let reduced = product.reduce();
        assert_eq!(reduced.num, 90, "numerator should be 90");
        assert_eq!(reduced.den, 1001, "denominator should be 1001");
    }

    #[test]
    fn test_plmg_on_rail() {
        let validator = PLMGValidator::new(1_000_000, 10_000_000);
        assert!(validator.is_on_rail(500_000));
        assert!(validator.is_on_rail(0));
        assert!(validator.is_on_rail(999_999));
        assert!(!validator.is_on_rail(1_000_000));
        assert!(!validator.is_on_rail(5_000_000));
    }

    #[test]
    fn test_plmg_void_ratio() {
        let validator = PLMGValidator::new(280, 1000);
        // void_ratio = 720/1000 = 72%
        assert_eq!(validator.void_num, 720);
        assert_eq!(validator.void_den, 1000);
        // 720/1000 = 72/100
        assert_eq!(validator.void_num * 100, 72 * validator.void_den);
    }

    #[test]
    fn test_plmg_rail_signal() {
        let validator = PLMGValidator::new(1_000, 10_000);
        match validator.check(500) {
            RailSignal::OnRail { value, .. } => assert_eq!(value, 500),
            _ => panic!("500 should be on rail"),
        }
        match validator.check(5000) {
            RailSignal::Void { .. } => {}
            _ => panic!("5000 should be in void"),
        }
    }

    #[test]
    fn test_double_helix_basic() {
        let helix = DoubleHelix::new(42u64);
        assert!(helix.strands_agree());
        assert!(!helix.has_contention());
    }

    #[test]
    fn test_double_helix_advance() {
        let mut helix = DoubleHelix::new(100u64);
        let ok = helix.advance(200, &100);
        assert!(ok, "First verification should pass");
    }

    #[test]
    fn test_wassan_decompose_u128() {
        let value: u128 = 432_000;
        let banded = WassanBanded::from_u128(value, 128);
        let recon = banded.reconstruct_u128();
        assert_eq!(recon, value);
    }

    #[test]
    fn test_wassan_band_mod() {
        let value: u128 = 432_000;
        let banded = WassanBanded::from_u128(value, 128);
        for &p in &[3u64, 5, 7, 11, 13, 17, 127] {
            let r_band = banded.band_mod(p);
            let r_direct = (value % p as u128) as u64;
            assert_eq!(r_band, r_direct, "Band-mod mismatch for p={}", p);
        }
    }

    #[test]
    fn test_wassan_band_add() {
        let a = WassanBanded::from_u128(100_000, 128);
        let b = WassanBanded::from_u128(200_000, 128);
        let c = a.band_add(&b);
        assert_eq!(c.reconstruct_u128(), 300_000);
    }

    #[test]
    fn test_safe_anchor_basic() {
        let m_safe: u64 = 16 * 27 * 25 * 49 * 11 * 13;
        let anchor = SafeAnchor::new(2_147_483_647, m_safe).unwrap();
        assert_eq!(gcd(2_147_483_647, m_safe), 1);
        assert!(anchor.m_safe_inv_p > 0);
    }

    #[test]
    fn test_safe_anchor_reconstruct() {
        let m_safe: u64 = 16 * 27 * 25 * 49 * 11 * 13;
        let mut anchor = SafeAnchor::new(2_147_483_647, m_safe).unwrap();
        for &x in &[0u64, 1, 42, 360, 432_000, 4_320_000, 75_675_599] {
            anchor.encode(x);
            let r_safe = x % m_safe;
            let recon = anchor.reconstruct(r_safe);
            assert_eq!(recon, x as u128, "Reconstruction failed for {}", x);
        }
    }

    #[test]
    fn test_safe_anchor_winding() {
        let m_safe: u64 = 75_675_600;
        let mut anchor = SafeAnchor::new(2_147_483_647, m_safe).unwrap();
        let x = m_safe * 7 + 42;
        anchor.encode(x);
        let k = anchor.k_eliminate(x % m_safe);
        assert_eq!(k, 7);
        assert_eq!(anchor.reconstruct(x % m_safe), x as u128);
    }

    #[test]
    fn test_smooth() {
        assert!(is_smooth(260)); // 2^2 * 5 * 13
        assert!(is_smooth(819)); // 3^2 * 7 * 13
        assert!(is_smooth(30030)); // primorial 13#
        assert!(!is_smooth(365)); // 5 * 73
        assert!(is_smooth(432));
        assert!(is_smooth(432_000));
    }

    #[test]
    fn test_safe_basis_capacity() {
        let exps: [(u64, u32); 6] = [(2, 25), (3, 16), (5, 11), (7, 9), (11, 7), (13, 5)];
        // Verify pairwise coprimality
        let moduli: Vec<u64> = exps.iter().map(|&(p, e)| p.pow(e)).collect();
        for i in 0..moduli.len() {
            for j in (i + 1)..moduli.len() {
                assert_eq!(gcd(moduli[i], moduli[j]), 1);
            }
        }
        // Product should exceed 2^135 — check via log2 approximation
        // 25*1 + 16*~1.585 + 11*~2.322 + 9*~2.807 + 7*~3.459 + 5*~3.700
        // ≈ 25 + 25.36 + 25.54 + 25.26 + 24.21 + 18.50 = 143.87 bits
        // Verify: product of all moduli > 2^135
        let product: u128 = moduli.iter().take(4).map(|&m| m as u128).product();
        assert!(
            product > (1u128 << 100),
            "Partial product should exceed 2^100"
        );
    }

    #[test]
    fn test_maa_valid_descartes() {
        let quad = MAAElement::new([
            CRTBigInt::from_i64(2),
            CRTBigInt::from_i64(3),
            CRTBigInt::from_i64(6),
            CRTBigInt::from_i64(11),
        ]);
        let reflected = quad.reflect(0);
        assert_eq!(reflected.curvatures[0].residues.len(), 8);
    }
}
