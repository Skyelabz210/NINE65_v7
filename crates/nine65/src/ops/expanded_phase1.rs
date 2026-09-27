//! Public preprocessing for the expanded-plaintext BFV refresh construction.
//!
//! This module calculates `a_i = round(t^e * c_i / Q_level) mod t^e`
//! directly from the active main residues. It needs no secret, bootstrap key,
//! or serialized anchor. Its output is a pair of public polynomials, **not** a
//! refreshed ciphertext. The evaluator still needs an expanded-plaintext
//! bootstrap key, an encrypted inner product, and encrypted digit removal.
//!
//! A plan checks arithmetic capacity and input shape. It does not certify the
//! input noise, lattice security, or the depth of the missing encrypted circuit.

use crate::arithmetic::canonical_scale_round::{CanonicalScaleRound, CanonicalScaleRoundError};
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

pub struct ExpandedPhase1Plan {
    n: usize,
    level: usize,
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
            digit_divisor: expanded / config.t,
            scale,
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
