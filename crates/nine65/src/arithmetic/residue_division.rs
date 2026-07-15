//! Typed contract for bounded quotient projection in DualRNS space.
//!
//! This module defines the proof-carrying boundary required by the CRAM
//! residue-native bootstrap specification. It validates basis, shape, and
//! public range preconditions. A concrete projector must return quotient and
//! remainder residues plus a certificate; it may not fall back to full integer
//! reconstruction.

use crate::errors::{Nine65Error, Nine65Result};
use crate::params::is_prime;

/// Borrowed coherent residue state for one coefficient.
#[derive(Clone, Copy, Debug)]
pub struct ResidueStateRef<'a> {
    pub main: &'a [u64],
    pub anchor: &'a [u64],
}

/// Canonical ordered main and anchor bases.
#[derive(Clone, Copy, Debug)]
pub struct ResidueBasisRef<'a> {
    pub main_moduli: &'a [u64],
    pub anchor_moduli: &'a [u64],
}

/// Public divisor metadata. The exact factor vector is canonical; scalar
/// projection is neither required nor accepted as a substitute.
#[derive(Clone, Copy, Debug)]
pub struct ResidueDivisorRef<'a> {
    pub factors: &'a [u64],
    pub main_residues: &'a [u64],
    pub anchor_residues: &'a [u64],
}

/// One bounded quotient-projection request.
#[derive(Clone, Copy, Debug)]
pub struct ResidueDivisionRequest<'a> {
    pub basis: ResidueBasisRef<'a>,
    pub numerator: ResidueStateRef<'a>,
    pub divisor: ResidueDivisorRef<'a>,
    /// Public strict upper bound: `0 <= quotient < quotient_bound`.
    pub quotient_bound: u64,
}

/// Machine-auditable certificate emitted by a concrete projector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidueDivisionCertificate {
    pub quotient_bound: u64,
    pub main_equations_verified: bool,
    pub anchor_equations_verified: bool,
    pub remainder_in_range: bool,
    pub quotient_unique_in_anchor_basis: bool,
}

impl ResidueDivisionCertificate {
    pub fn is_complete(&self) -> bool {
        self.main_equations_verified
            && self.anchor_equations_verified
            && self.remainder_in_range
            && self.quotient_unique_in_anchor_basis
    }
}

/// Residue-native quotient/remainder result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidueDivisionResult {
    /// Quotient reduced into the requested plaintext/output modulus.
    pub quotient_mod_output: u64,
    /// Exact remainder residues in CLASS-F lanes.
    pub remainder_main: Vec<u64>,
    /// Exact remainder residues in CLASS-R lanes.
    pub remainder_anchor: Vec<u64>,
    pub certificate: ResidueDivisionCertificate,
}

/// Concrete bounded K-Elimination projector interface.
pub trait BoundedResidueDivider {
    fn project_bounded(
        &self,
        request: ResidueDivisionRequest<'_>,
        output_modulus: u64,
    ) -> Nine65Result<ResidueDivisionResult>;
}

/// Validate every non-algorithmic precondition before projection.
pub fn validate_residue_division_request(
    request: ResidueDivisionRequest<'_>,
    output_modulus: u64,
) -> Nine65Result<()> {
    validate_main_family(request.basis.main_moduli)?;
    validate_anchor_family(request.basis.anchor_moduli)?;
    validate_cross_family(
        request.basis.main_moduli,
        request.basis.anchor_moduli,
    )?;

    if output_modulus < 2 {
        return Err(Nine65Error::InvalidParameter {
            message: "output modulus must be at least two".to_string(),
        });
    }
    if request.quotient_bound == 0 {
        return Err(Nine65Error::InvalidParameter {
            message: "quotient bound must be nonzero".to_string(),
        });
    }
    if request.divisor.factors.is_empty() {
        return Err(Nine65Error::InvalidParameter {
            message: "divisor factor vector must not be empty".to_string(),
        });
    }
    if request.divisor.factors.iter().any(|&factor| factor <= 1) {
        return Err(Nine65Error::InvalidParameter {
            message: "every divisor factor must be greater than one".to_string(),
        });
    }

    require_shape(
        "numerator main residues",
        request.numerator.main.len(),
        request.basis.main_moduli.len(),
    )?;
    require_shape(
        "numerator anchor residues",
        request.numerator.anchor.len(),
        request.basis.anchor_moduli.len(),
    )?;
    require_shape(
        "divisor main residues",
        request.divisor.main_residues.len(),
        request.basis.main_moduli.len(),
    )?;
    require_shape(
        "divisor anchor residues",
        request.divisor.anchor_residues.len(),
        request.basis.anchor_moduli.len(),
    )?;

    validate_reduced(
        "numerator main residue",
        request.numerator.main,
        request.basis.main_moduli,
    )?;
    validate_reduced(
        "numerator anchor residue",
        request.numerator.anchor,
        request.basis.anchor_moduli,
    )?;
    validate_reduced(
        "divisor main residue",
        request.divisor.main_residues,
        request.basis.main_moduli,
    )?;
    validate_reduced(
        "divisor anchor residue",
        request.divisor.anchor_residues,
        request.basis.anchor_moduli,
    )?;

    if !anchor_capacity_covers_bound(
        request.basis.anchor_moduli,
        request.quotient_bound,
    ) {
        return Err(Nine65Error::InvalidParameter {
            message: format!(
                "anchor capacity does not cover quotient bound {}",
                request.quotient_bound
            ),
        });
    }

    Ok(())
}

/// Verify that a result preserves lane shape and carries a complete
/// certificate. Equation checking remains the projector's responsibility and
/// must be reflected in the certificate booleans.
pub fn validate_residue_division_result(
    request: ResidueDivisionRequest<'_>,
    output_modulus: u64,
    result: &ResidueDivisionResult,
) -> Nine65Result<()> {
    validate_residue_division_request(request, output_modulus)?;
    if result.quotient_mod_output >= output_modulus {
        return Err(Nine65Error::RangeOverflow {
            x: result.quotient_mod_output as u128,
            bound: output_modulus as u128,
        });
    }
    require_shape(
        "remainder main residues",
        result.remainder_main.len(),
        request.basis.main_moduli.len(),
    )?;
    require_shape(
        "remainder anchor residues",
        result.remainder_anchor.len(),
        request.basis.anchor_moduli.len(),
    )?;
    validate_reduced(
        "remainder main residue",
        &result.remainder_main,
        request.basis.main_moduli,
    )?;
    validate_reduced(
        "remainder anchor residue",
        &result.remainder_anchor,
        request.basis.anchor_moduli,
    )?;
    if result.certificate.quotient_bound != request.quotient_bound {
        return Err(Nine65Error::InvalidParameter {
            message: "result certificate quotient bound does not match request".to_string(),
        });
    }
    if !result.certificate.is_complete() {
        return Err(Nine65Error::InvalidParameter {
            message: "residue-division certificate is incomplete".to_string(),
        });
    }
    Ok(())
}

fn validate_main_family(moduli: &[u64]) -> Nine65Result<()> {
    if moduli.is_empty() {
        return Err(Nine65Error::InvalidParameter {
            message: "CLASS-F main family must not be empty".to_string(),
        });
    }
    for (index, &modulus) in moduli.iter().enumerate() {
        if modulus <= 1 || !is_prime(modulus) {
            return Err(Nine65Error::InvalidParameter {
                message: format!("CLASS-F modulus {modulus} is not prime"),
            });
        }
        for &previous in &moduli[..index] {
            let divisor = gcd_u64(modulus, previous);
            if divisor != 1 {
                return Err(Nine65Error::NotCoprime {
                    m: modulus,
                    a: previous,
                    gcd: divisor,
                });
            }
        }
    }
    Ok(())
}

fn validate_anchor_family(moduli: &[u64]) -> Nine65Result<()> {
    if moduli.is_empty() {
        return Err(Nine65Error::InvalidParameter {
            message: "CLASS-R anchor family must not be empty".to_string(),
        });
    }
    for (index, &modulus) in moduli.iter().enumerate() {
        if modulus <= 1 {
            return Err(Nine65Error::InvalidParameter {
                message: format!("CLASS-R modulus {modulus} must be greater than one"),
            });
        }
        for &previous in &moduli[..index] {
            let divisor = gcd_u64(modulus, previous);
            if divisor != 1 {
                return Err(Nine65Error::NotCoprime {
                    m: modulus,
                    a: previous,
                    gcd: divisor,
                });
            }
        }
    }
    Ok(())
}

fn validate_cross_family(main: &[u64], anchor: &[u64]) -> Nine65Result<()> {
    for &main_modulus in main {
        for &anchor_modulus in anchor {
            let divisor = gcd_u64(main_modulus, anchor_modulus);
            if divisor != 1 {
                return Err(Nine65Error::NotCoprime {
                    m: main_modulus,
                    a: anchor_modulus,
                    gcd: divisor,
                });
            }
        }
    }
    Ok(())
}

fn require_shape(label: &str, actual: usize, expected: usize) -> Nine65Result<()> {
    if actual != expected {
        return Err(Nine65Error::InvalidParameter {
            message: format!("{label} length {actual} does not match basis length {expected}"),
        });
    }
    Ok(())
}

fn validate_reduced(label: &str, residues: &[u64], moduli: &[u64]) -> Nine65Result<()> {
    for (index, (&residue, &modulus)) in residues.iter().zip(moduli).enumerate() {
        if residue >= modulus {
            return Err(Nine65Error::InvalidParameter {
                message: format!(
                    "{label} at lane {index} is {residue}, not reduced modulo {modulus}"
                ),
            });
        }
    }
    Ok(())
}

/// Since the public quotient bound is `u64`, multiplication can stop as soon
/// as the exact anchor product reaches it. Overflow cannot hide insufficiency:
/// a `u128` overflow is possible only after the product already exceeds every
/// `u64` bound.
fn anchor_capacity_covers_bound(anchor_moduli: &[u64], bound: u64) -> bool {
    let target = bound as u128;
    let mut product = 1u128;
    for &modulus in anchor_moduli {
        if product >= target {
            return true;
        }
        match product.checked_mul(modulus as u128) {
            Some(next) => product = next,
            None => return true,
        }
    }
    product >= target
}

fn gcd_u64(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request<'a>(
        main: &'a [u64],
        anchor: &'a [u64],
        numerator_main: &'a [u64],
        numerator_anchor: &'a [u64],
        divisor_main: &'a [u64],
        divisor_anchor: &'a [u64],
        factors: &'a [u64],
        quotient_bound: u64,
    ) -> ResidueDivisionRequest<'a> {
        ResidueDivisionRequest {
            basis: ResidueBasisRef {
                main_moduli: main,
                anchor_moduli: anchor,
            },
            numerator: ResidueStateRef {
                main: numerator_main,
                anchor: numerator_anchor,
            },
            divisor: ResidueDivisorRef {
                factors,
                main_residues: divisor_main,
                anchor_residues: divisor_anchor,
            },
            quotient_bound,
        }
    }

    #[test]
    fn valid_safe_basis_and_shapes_pass() {
        let request = valid_request(
            &[17, 19],
            &[23, 29],
            &[3, 5],
            &[7, 11],
            &[0, 0],
            &[2, 3],
            &[17, 19],
            31,
        );
        assert!(validate_residue_division_request(request, 31).is_ok());
    }

    #[test]
    fn class_f_and_class_r_rules_are_enforced() {
        let composite_main = valid_request(
            &[15, 17], &[23], &[1, 1], &[1], &[0, 0], &[1], &[15, 17], 2,
        );
        assert!(validate_residue_division_request(composite_main, 31).is_err());

        let noncoprime_anchor = valid_request(
            &[17, 19], &[23, 46], &[1, 1], &[1, 1], &[0, 0], &[1, 1], &[17, 19], 2,
        );
        assert!(validate_residue_division_request(noncoprime_anchor, 31).is_err());
    }

    #[test]
    fn shape_and_reduction_errors_fail_closed() {
        let wrong_shape = valid_request(
            &[17, 19], &[23], &[1], &[1], &[0, 0], &[1], &[17, 19], 2,
        );
        assert!(validate_residue_division_request(wrong_shape, 31).is_err());

        let unreduced = valid_request(
            &[17, 19], &[23], &[17, 1], &[1], &[0, 0], &[1], &[17, 19], 2,
        );
        assert!(validate_residue_division_request(unreduced, 31).is_err());
    }

    #[test]
    fn anchor_capacity_must_cover_quotient_bound() {
        let insufficient = valid_request(
            &[17, 19], &[5], &[1, 1], &[1], &[0, 0], &[1], &[17, 19], 6,
        );
        assert!(validate_residue_division_request(insufficient, 31).is_err());

        let sufficient = valid_request(
            &[17, 19], &[5, 7], &[1, 1], &[1, 1], &[0, 0], &[1, 1], &[17, 19], 31,
        );
        assert!(validate_residue_division_request(sufficient, 31).is_ok());
    }

    #[test]
    fn incomplete_certificate_is_rejected() {
        let request = valid_request(
            &[17, 19], &[23, 29], &[3, 5], &[7, 11], &[0, 0], &[2, 3], &[17, 19], 31,
        );
        let result = ResidueDivisionResult {
            quotient_mod_output: 4,
            remainder_main: vec![1, 1],
            remainder_anchor: vec![1, 1],
            certificate: ResidueDivisionCertificate {
                quotient_bound: 31,
                main_equations_verified: true,
                anchor_equations_verified: true,
                remainder_in_range: false,
                quotient_unique_in_anchor_basis: true,
            },
        };
        assert!(validate_residue_division_result(request, 31, &result).is_err());
    }
}