//! Public preprocessing for the expanded-plaintext BFV refresh construction.
//!
//! This module calculates `a_i = round(t^e * c_i / Q_level) mod t^e`
//! directly from the active main residues. It needs no secret, bootstrap key,
//! or serialized anchor. Its output is a pair of public polynomials, **not** a
//! refreshed ciphertext. The separate expanded evaluator uses its bootstrap
//! key to encrypt the inner product; encrypted digit removal is still missing.
//!
//! A plan checks arithmetic capacity and input shape. It does not certify the
//! input noise, lattice security, or the depth of the missing encrypted circuit.

use crate::arithmetic::canonical_scale_round::{CanonicalScaleRound, CanonicalScaleRoundError};
use crate::arithmetic::rns::U512;
use crate::ops::rns_fhe::DualRNSCiphertext;
use crate::params::FHEConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandedPhase1Error {
    InvalidLevel {
        level: usize,
        available: usize,
    },
    InvalidExponent {
        exponent: u32,
    },
    EmptyPolynomial,
    NoDigitRemovalMargin,
    PlaintextPowerOverflow {
        plaintext: u64,
        exponent: u32,
    },
    CiphertextLevelMismatch {
        got: usize,
        expected: usize,
    },
    PolynomialDegreeMismatch {
        component: &'static str,
        got: usize,
        expected: usize,
    },
    LaneCountMismatch {
        component: &'static str,
        got: usize,
        expected: usize,
    },
    CoefficientCountMismatch {
        component: &'static str,
        lane: usize,
        got: usize,
        expected: usize,
    },
    Arithmetic(CanonicalScaleRoundError),
}

impl From<CanonicalScaleRoundError> for ExpandedPhase1Error {
    fn from(value: CanonicalScaleRoundError) -> Self {
        Self::Arithmetic(value)
    }
}

/// Public component polynomials modulo `plaintext_modulus = t^e`.
///
/// After an encrypted secret inner product, the coefficient-wise target is
/// `round(w / digit_divisor) mod t`. Computing that operation in the clear
/// with a secret is only a test oracle and does not implement refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedPhase1Components {
    pub c0: Vec<u64>,
    pub c1: Vec<u64>,
    pub plaintext_modulus: u64,
    pub digit_divisor: u64,
    pub source_level: usize,
}

/// Parameter-derived input allowance, not a measurement of ciphertext noise.
///
/// The error is measured from the centered BFV encoding `Delta_t*m`, with
/// `|m| <= (t-1)/2`. For ordinary nonnegative encryption of `m > t/2`, its
/// bound must also include the `Q mod t` error from centering the message.
/// An evaluator needs independently justified operation-history evidence
/// before it can use this allowance to admit an input to digit removal.
#[derive(Debug, Clone)]
pub struct ExpandedPhase1NoiseBudget {
    pub max_centered_error: U512,
    pub source_level: usize,
    pub source_encoding_remainder: u64,
    pub secret_hamming_weight_bound: usize,
}

pub struct ExpandedPhase1Plan {
    n: usize,
    level: usize,
    base_plaintext: u64,
    source_modulus: U512,
    digit_divisor: u64,
    scale: CanonicalScaleRound,
}

impl ExpandedPhase1Plan {
    /// Precompute the public scaler for exactly the first `level` work primes.
    /// The current backend supports odd `t^e` below `2^63` and refuses main
    /// chains whose exact rank fallback would exceed its 256-bit capacity.
    pub fn new(
        config: &FHEConfig,
        level: usize,
        exponent: u32,
    ) -> Result<Self, ExpandedPhase1Error> {
        if level == 0 || level > config.primes.len() {
            return Err(ExpandedPhase1Error::InvalidLevel {
                level,
                available: config.primes.len(),
            });
        }
        if exponent < 2 {
            return Err(ExpandedPhase1Error::InvalidExponent { exponent });
        }
        if config.n == 0 {
            return Err(ExpandedPhase1Error::EmptyPolynomial);
        }
        let expanded =
            config
                .t
                .checked_pow(exponent)
                .ok_or(ExpandedPhase1Error::PlaintextPowerOverflow {
                    plaintext: config.t,
                    exponent,
                })?;
        let scale = CanonicalScaleRound::new(&config.primes[..level], expanded)?;
        Ok(Self {
            n: config.n,
            level,
            base_plaintext: config.t,
            source_modulus: U512::product_u64s(&config.primes[..level]),
            digit_divisor: expanded / config.t,
            scale,
        })
    }

    /// Largest integer bound E satisfying the strict digit margin for every
    /// ternary work secret of weight at most N. This uses public metadata only.
    /// It neither reads a ciphertext nor certifies its actual error.
    pub fn input_noise_budget(&self) -> Result<ExpandedPhase1NoiseBudget, ExpandedPhase1Error> {
        let q = self.source_modulus;
        let t = self.base_plaintext;
        let p = self.scale.target();
        let r = q.mod_u64(t);
        // |rho| <= P/Q * (E + r*(t-1)/(2t)) + (N+1)/2 < P/(2t).
        // Clearing denominators gives
        //   2*t*P*E < P*Q - t*Q*(N+1) - P*r*(t-1).
        // All products here are parameter metadata, never coefficients. The
        // source capacity is <=256 bits, t,P<2^63, N fits usize, so U512
        // covers the intermediates without saturation or truncation.
        let capacity = q.mul_u128(p as u128);
        let cost = q
            .mul_u128(t as u128 * (self.n as u128 + 1))
            .add(U512::from_u64(p).mul_u128(r as u128 * (t - 1) as u128));
        let words = |v: U512| (v.d3, v.d2, v.d1, v.d0);
        if words(capacity) <= words(cost) {
            return Err(ExpandedPhase1Error::NoDigitRemovalMargin);
        }
        // Subtract one before integer division to retain the strict margin;
        // successive floor divisions equal division by the product.
        let max_centered_error = capacity
            .sub(cost)
            .sub(U512::from_u64(1))
            .div_u64(t)
            .div_u64(p)
            .div_u64(2);
        Ok(ExpandedPhase1NoiseBudget {
            max_centered_error,
            source_level: self.level,
            source_encoding_remainder: r,
            secret_hamming_weight_bound: self.n,
        })
    }

    /// Prepare both public components using only their active main residues.
    /// Anchors are intentionally not read: no coprime-to-Q state is trusted or
    /// added to the ciphertext's wire representation by this operation.
    pub fn prepare(
        &self,
        ct: &DualRNSCiphertext,
    ) -> Result<ExpandedPhase1Components, ExpandedPhase1Error> {
        if ct.level != self.level {
            return Err(ExpandedPhase1Error::CiphertextLevelMismatch {
                got: ct.level,
                expected: self.level,
            });
        }
        // Validate both components before any coefficient is accessed.
        for (component, poly) in [("c0", &ct.c0), ("c1", &ct.c1)] {
            if poly.n != self.n {
                return Err(ExpandedPhase1Error::PolynomialDegreeMismatch {
                    component,
                    got: poly.n,
                    expected: self.n,
                });
            }
            if poly.main.len() != self.level {
                return Err(ExpandedPhase1Error::LaneCountMismatch {
                    component,
                    got: poly.main.len(),
                    expected: self.level,
                });
            }
            for (lane, coefficients) in poly.main.iter().enumerate() {
                if coefficients.len() != self.n {
                    return Err(ExpandedPhase1Error::CoefficientCountMismatch {
                        component,
                        lane,
                        got: coefficients.len(),
                        expected: self.n,
                    });
                }
            }
        }

        let mut residues = vec![0u64; self.level];
        let mut scale_poly = |main: &[Vec<u64>]| -> Result<Vec<u64>, ExpandedPhase1Error> {
            let mut result = Vec::with_capacity(self.n);
            for coefficient in 0..self.n {
                for (residue, lane) in residues.iter_mut().zip(main) {
                    *residue = lane[coefficient];
                }
                result.push(self.scale.scale_round(&residues)?);
            }
            Ok(result)
        };
        Ok(ExpandedPhase1Components {
            c0: scale_poly(&ct.c0.main)?,
            c1: scale_poly(&ct.c1.main)?,
            plaintext_modulus: self.scale.target(),
            digit_divisor: self.digit_divisor,
            source_level: self.level,
        })
    }
}
