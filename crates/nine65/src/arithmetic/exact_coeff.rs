//! ExactCoeff - Dual-Track Coefficient Representation
//!
//! Each coefficient carries both fast RNS residues
//! for NTT/Montgomery operations AND anchor track residues for exact
//! integer reconstruction via K-Elimination.
//!
//! Invariant: For each coefficient, there exists a unique integer X such that:
//!   X ≡ inner.limbs[i] (mod p_i) for all i
//!   X ≡ anchor.m_res (mod M)
//!   X ≡ anchor.a_res (mod A)
//!
//! # Theorem Reference
//! - Proof File: `ExactCoefficient.v`
//! - Status: VERIFIED
//!
//! # Relationship to the production K-Elimination record (issue #70 index)
//!
//! Built on [`super::exact_divider::ExactDivider`] — see that module's own
//! note. This dual-track coefficient representation has no live production
//! caller; it is exercised only by its own tests and by
//! `arithmetic::ct_mul_exact`. See
//! `docs/K_ELIMINATION_IMPLEMENTATIONS_2026-09-03.md` for the full inventory.

use super::exact_divider::ExactDivider;

/// Inner RNS representation for fast arithmetic
#[derive(Clone, Debug)]
pub struct RnsInner {
    /// Residues mod each prime p_i
    pub limbs: Vec<u64>,
}

/// Anchor track for exact magnitude reconstruction
#[derive(Clone, Debug, Copy)]
pub struct AnchorTrack {
    /// Residue mod M (main modulus)
    pub m_res: u64,
    /// Residue mod A (anchor modulus)  
    pub a_res: u64,
}

/// Exact coefficient with dual-track representation
#[derive(Clone, Debug)]
pub struct ExactCoeff {
    /// Inner RNS limbs for fast operations
    pub inner: RnsInner,
    /// Anchor track for exact reconstruction
    pub anchor: AnchorTrack,
}

/// Context for exact coefficient operations
#[derive(Clone)]
pub struct ExactContext {
    /// Inner RNS primes
    pub p_moduli: Vec<u64>,
    /// Main modulus M
    pub m: u64,
    /// Anchor modulus A
    pub a: u64,
    /// Exact divider for reconstruction
    pub divider: ExactDivider,
    /// Polynomial degree
    pub n: usize,
    /// Plaintext modulus
    pub t: u64,
    /// Scaling factor Δ = M/t
    pub delta: u64,
}

impl ExactContext {
    /// Create context for FHE operations
    pub fn new(p_moduli: Vec<u64>, m: u64, a: u64, n: usize, t: u64) -> Self {
        let divider = ExactDivider::new(m, a);
        let delta = m / t;

        Self {
            p_moduli,
            m,
            a,
            divider,
            n,
            t,
            delta,
        }
    }

    /// Create from single modulus (typical BFV setup)
    pub fn from_single_modulus(q: u64, n: usize, t: u64) -> Self {
        let divider = ExactDivider::for_fhe(q);
        Self::new(vec![q], q, divider.a, n, t)
    }

    /// Encode an integer into exact coefficient
    pub fn encode(&self, x: u128) -> ExactCoeff {
        let inner = RnsInner {
            limbs: self
                .p_moduli
                .iter()
                .map(|&p| (x % (p as u128)) as u64)
                .collect(),
        };

        let anchor = AnchorTrack {
            m_res: (x % (self.m as u128)) as u64,
            a_res: (x % (self.a as u128)) as u64,
        };

        ExactCoeff { inner, anchor }
    }

    /// Reconstruct exact integer from coefficient
    pub fn reconstruct(&self, coeff: &ExactCoeff) -> u128 {
        self.divider
            .reconstruct_exact(coeff.anchor.m_res, coeff.anchor.a_res)
    }

    /// Add two coefficients
    pub fn add(&self, a: &ExactCoeff, b: &ExactCoeff) -> ExactCoeff {
        let inner = RnsInner {
            limbs: a
                .inner
                .limbs
                .iter()
                .zip(&b.inner.limbs)
                .zip(&self.p_moduli)
                .map(|((&x, &y), &p)| {
                    let sum = (x as u128) + (y as u128);
                    (sum % (p as u128)) as u64
                })
                .collect(),
        };

        let m_sum = ((a.anchor.m_res as u128) + (b.anchor.m_res as u128)) % (self.m as u128);
        let a_sum = ((a.anchor.a_res as u128) + (b.anchor.a_res as u128)) % (self.a as u128);

        let anchor = AnchorTrack {
            m_res: m_sum as u64,
            a_res: a_sum as u64,
        };

        ExactCoeff { inner, anchor }
    }

    /// Subtract two coefficients
    pub fn sub(&self, a: &ExactCoeff, b: &ExactCoeff) -> ExactCoeff {
        let inner = RnsInner {
            limbs: a
                .inner
                .limbs
                .iter()
                .zip(&b.inner.limbs)
                .zip(&self.p_moduli)
                .map(|((&x, &y), &p)| if x >= y { x - y } else { p - y + x })
                .collect(),
        };

        let m_diff = if a.anchor.m_res >= b.anchor.m_res {
            a.anchor.m_res - b.anchor.m_res
        } else {
            self.m - b.anchor.m_res + a.anchor.m_res
        };

        let a_diff = if a.anchor.a_res >= b.anchor.a_res {
            a.anchor.a_res - b.anchor.a_res
        } else {
            self.a - b.anchor.a_res + a.anchor.a_res
        };

        let anchor = AnchorTrack {
            m_res: m_diff,
            a_res: a_diff,
        };

        ExactCoeff { inner, anchor }
    }

    /// Multiply two coefficients (pointwise, not polynomial)
    pub fn mul(&self, a: &ExactCoeff, b: &ExactCoeff) -> ExactCoeff {
        let inner = RnsInner {
            limbs: a
                .inner
                .limbs
                .iter()
                .zip(&b.inner.limbs)
                .zip(&self.p_moduli)
                .map(|((&x, &y), &p)| ((x as u128) * (y as u128) % (p as u128)) as u64)
                .collect(),
        };

        let m_prod = ((a.anchor.m_res as u128) * (b.anchor.m_res as u128)) % (self.m as u128);
        let a_prod = ((a.anchor.a_res as u128) * (b.anchor.a_res as u128)) % (self.a as u128);

        let anchor = AnchorTrack {
            m_res: m_prod as u64,
            a_res: a_prod as u64,
        };

        ExactCoeff { inner, anchor }
    }

    /// Negate a coefficient
    pub fn neg(&self, a: &ExactCoeff) -> ExactCoeff {
        let inner = RnsInner {
            limbs: a
                .inner
                .limbs
                .iter()
                .zip(&self.p_moduli)
                .map(|(&x, &p)| if x == 0 { 0 } else { p - x })
                .collect(),
        };

        let anchor = AnchorTrack {
            m_res: if a.anchor.m_res == 0 {
                0
            } else {
                self.m - a.anchor.m_res
            },
            a_res: if a.anchor.a_res == 0 {
                0
            } else {
                self.a - a.anchor.a_res
            },
        };

        ExactCoeff { inner, anchor }
    }

    /// Exact division by scalar (must be exactly divisible)
    pub fn exact_div(&self, coeff: &ExactCoeff, d: u64) -> ExactCoeff {
        let quotient = self
            .divider
            .exact_divide(coeff.anchor.m_res, coeff.anchor.a_res, d);
        self.encode(quotient)
    }

    /// Scale and round: round(X × t / q)
    pub fn scale_and_round(&self, coeff: &ExactCoeff) -> ExactCoeff {
        let scaled =
            self.divider
                .scale_and_round(coeff.anchor.m_res, coeff.anchor.a_res, self.t, self.m);
        self.encode(scaled as u128)
    }

    /// Create zero coefficient
    pub fn zero(&self) -> ExactCoeff {
        ExactCoeff {
            inner: RnsInner {
                limbs: vec![0; self.p_moduli.len()],
            },
            anchor: AnchorTrack { m_res: 0, a_res: 0 },
        }
    }
}

/// Exact polynomial with dual-track coefficients
#[derive(Clone, Debug)]
pub struct ExactPoly {
    pub coeffs: Vec<ExactCoeff>,
}

impl ExactPoly {
    /// Create zero polynomial
    pub fn zero(ctx: &ExactContext) -> Self {
        Self {
            coeffs: vec![ctx.zero(); ctx.n],
        }
    }

    /// Create from coefficient vector
    pub fn from_coeffs(coeffs: Vec<ExactCoeff>) -> Self {
        Self { coeffs }
    }

    /// Add two polynomials
    pub fn add(&self, other: &Self, ctx: &ExactContext) -> Self {
        let coeffs = self
            .coeffs
            .iter()
            .zip(&other.coeffs)
            .map(|(a, b)| ctx.add(a, b))
            .collect();
        Self { coeffs }
    }

    /// Subtract two polynomials
    pub fn sub(&self, other: &Self, ctx: &ExactContext) -> Self {
        let coeffs = self
            .coeffs
            .iter()
            .zip(&other.coeffs)
            .map(|(a, b)| ctx.sub(a, b))
            .collect();
        Self { coeffs }
    }

    /// Negate polynomial
    pub fn neg(&self, ctx: &ExactContext) -> Self {
        let coeffs = self.coeffs.iter().map(|c| ctx.neg(c)).collect();
        Self { coeffs }
    }

    /// Pointwise multiply (for NTT domain)
    pub fn pointwise_mul(&self, other: &Self, ctx: &ExactContext) -> Self {
        let coeffs = self
            .coeffs
            .iter()
            .zip(&other.coeffs)
            .map(|(a, b)| ctx.mul(a, b))
            .collect();
        Self { coeffs }
    }

    /// Exact scalar division
    pub fn exact_scalar_div(&self, d: u64, ctx: &ExactContext) -> Self {
        let coeffs = self.coeffs.iter().map(|c| ctx.exact_div(c, d)).collect();
        Self { coeffs }
    }

    /// Reconstruct all coefficients as integers
    pub fn to_integers(&self, ctx: &ExactContext) -> Vec<u128> {
        self.coeffs.iter().map(|c| ctx.reconstruct(c)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctx() -> ExactContext {
        ExactContext::from_single_modulus(998244353, 8, 500000)
    }

    #[test]
    fn test_encode_reconstruct() {
        let ctx = test_ctx();

        for x in [0u128, 1, 1000, 1_000_000, 100_000_000] {
            let coeff = ctx.encode(x);
            let recovered = ctx.reconstruct(&coeff);
            assert_eq!(recovered, x, "Roundtrip failed for {}", x);
        }
    }

    #[test]
    fn test_add() {
        let ctx = test_ctx();

        let a = ctx.encode(100);
        let b = ctx.encode(200);
        let sum = ctx.add(&a, &b);

        assert_eq!(ctx.reconstruct(&sum), 300);
    }

    #[test]
    fn test_mul() {
        let ctx = test_ctx();

        let a = ctx.encode(123);
        let b = ctx.encode(456);
        let prod = ctx.mul(&a, &b);

        assert_eq!(ctx.reconstruct(&prod), 123 * 456);
    }

    #[test]
    fn test_exact_div() {
        let ctx = test_ctx();

        let x = ctx.encode(12345);
        let q = ctx.exact_div(&x, 5);

        assert_eq!(ctx.reconstruct(&q), 2469);
    }

    #[test]
    fn test_delta_squared_scaling() {
        let ctx = test_ctx();
        let delta = ctx.delta;

        // Simulate Δ² × 35 - this is EXACTLY divisible by Δ
        let x = (delta as u128) * (delta as u128) * 35;
        let coeff = ctx.encode(x);

        // Use exact division by Δ (not scale_and_round)
        // This is the QMNF approach - exact integer division
        let quotient_coeff = ctx.exact_div(&coeff, delta);
        let result = ctx.reconstruct(&quotient_coeff);

        let expected = (delta * 35) as u128;
        println!(
            "Δ={}, x={}, x/Δ={}, expected={}",
            delta, x, result, expected
        );

        // This should be EXACT
        assert_eq!(
            result, expected,
            "Exact division failed: {} vs {}",
            result, expected
        );
    }
}
