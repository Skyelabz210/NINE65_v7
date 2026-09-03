//! Lift-aware CRAM transduction.
//!
//! `TransductionMap::apply` intentionally names the canonical source value in
//! `[0, M_A)`.  Once the represented integer crosses that source-product
//! boundary, the source residue tray alone cannot distinguish `X` from
//! `X + M_A`.  This module supplies the missing exact term without carrying a
//! scalar winding as payload.
//!
//! If the represented integer is
//!
//! ```text
//! X = g + K*M_A,   0 <= g < M_A,
//! ```
//!
//! then on target lane `b`:
//!
//! ```text
//! X mod b = g mod b + (K mod b)*(M_A mod b) mod b.
//! ```
//!
//! The caller supplies `K mod b` per target lane.  Those residues are intended
//! to be derived on demand from the phase-lock/anchor machinery; this API does
//! not require, store, or reconstruct a scalar `K`.
//!
//! A1/A2: exact integer arithmetic only; no floating point and no
//! mixed-radix/Garner reconstruction is introduced by this module.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

use crate::k_elim::{modd, mulmod};
use crate::transduction::TransductionMap;

/// Typed failure for lift-aware transduction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LiftedTransductionError {
    /// The source residue count does not match the source basis.
    SourceLengthMismatch { expected: usize, actual: usize },
    /// One `K mod b_j` value is required for every target lane.
    LiftLengthMismatch { expected: usize, actual: usize },
    /// Residue modulus must be strictly positive.
    InvalidTargetModulus { index: usize, modulus: i128 },
}

/// Overflow-safe modular addition for normalized positive modulus `m`.
#[inline]
fn addmod(a: i128, b: i128, m: i128) -> i128 {
    debug_assert!(m > 0);
    let a = modd(a, m);
    let b = modd(b, m);
    // Avoid forming a+b when it could overflow i128.
    if a >= m - b {
        a - (m - b)
    } else {
        a + b
    }
}

/// Project a canonical source residue plus a derived lift residue into one
/// target lane.
///
/// This is Universal Projection specialized to the source-product lift:
///
/// ```text
/// X = g + K*M
/// X mod b = g_b + K_b*M_b mod b.
/// ```
///
/// `k_mod_b` is an observable of the phase-locked state, not a stored scalar
/// winding requirement.
pub fn project_with_lift(
    g_mod_b: i128,
    k_mod_b: i128,
    source_product_mod_b: i128,
    target_modulus: i128,
) -> Option<i128> {
    if target_modulus <= 0 {
        return None;
    }
    let lift_term = mulmod(k_mod_b, source_product_mod_b, target_modulus);
    Some(addmod(g_mod_b, lift_term, target_modulus))
}

/// Lift-aware basis transduction.
///
/// First obtains the canonical source representative's target residues using
/// the existing bounded [`TransductionMap`].  It then adds the exact lift
/// contribution independently on every target lane.
///
/// The operation never requires full integer materialization.  `k_mod_targets`
/// must contain `K mod b_j` for each target modulus `b_j`, obtained from the
/// caller's certified phase-lock/anchor mechanism.
pub fn transduct_with_lift(
    basis_a: &[i128],
    basis_b: &[i128],
    source_residues: &[i128],
    k_mod_targets: &[i128],
) -> Result<Vec<i128>, LiftedTransductionError> {
    if source_residues.len() != basis_a.len() {
        return Err(LiftedTransductionError::SourceLengthMismatch {
            expected: basis_a.len(),
            actual: source_residues.len(),
        });
    }
    if k_mod_targets.len() != basis_b.len() {
        return Err(LiftedTransductionError::LiftLengthMismatch {
            expected: basis_b.len(),
            actual: k_mod_targets.len(),
        });
    }
    for (j, &b) in basis_b.iter().enumerate() {
        if b <= 0 {
            return Err(LiftedTransductionError::InvalidTargetModulus {
                index: j,
                modulus: b,
            });
        }
    }

    // `apply` returns g mod b_j for the canonical g in [0,M_A).
    let map = TransductionMap::new(basis_a, basis_b);
    let canonical_targets = map.apply(source_residues);
    let m_a = map.m_a();

    let mut out = Vec::with_capacity(basis_b.len());
    for (j, &b) in basis_b.iter().enumerate() {
        let y = project_with_lift(
            canonical_targets[j],
            k_mod_targets[j],
            modd(m_a, b),
            b,
        )
        .expect("target moduli validated positive above");
        out.push(y);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transduction::{S6_BASIS, S8_BASIS};

    fn residues(x: i128, basis: &[i128]) -> Vec<i128> {
        basis.iter().map(|&m| modd(x, m)).collect()
    }

    #[test]
    fn universal_projection_matches_direct_mod_for_shared_factor_targets() {
        let m = 30_030i128;
        let g = 29i128;
        let k = 17i128;
        let x = g + k * m;
        for b in [1i128, 4, 6, 9, 12, 18, 35, 77, 143, 256] {
            let got = project_with_lift(modd(g, b), modd(k, b), modd(m, b), b).unwrap();
            assert_eq!(got, modd(x, b), "target={b}");
        }
    }

    #[test]
    fn first_s6_wrap_projects_to_correct_s8_extension_lanes() {
        let x = 30_030i128;
        let source = residues(x, &S6_BASIS); // same tray as zero
        assert_eq!(source, residues(0, &S6_BASIS));

        // K=1 is derived by the phase-lock layer.  This test feeds only its
        // target residues, never a scalar winding field into the API.
        let k_mod_targets: Vec<i128> = S8_BASIS.iter().map(|&b| 1 % b).collect();
        let out = transduct_with_lift(&S6_BASIS, &S8_BASIS, &source, &k_mod_targets).unwrap();

        assert_eq!(out[6], 8);  // 30030 mod 17
        assert_eq!(out[7], 10); // 30030 mod 19
        assert_eq!(out, residues(x, &S8_BASIS));
    }

    #[test]
    fn zero_lift_is_identical_to_bounded_transduction() {
        let x = 12_345i128;
        let source = residues(x, &S6_BASIS);
        let zero_k = vec![0i128; S8_BASIS.len()];
        let lifted = transduct_with_lift(&S6_BASIS, &S8_BASIS, &source, &zero_k).unwrap();
        let bounded = TransductionMap::new(&S6_BASIS, &S8_BASIS).apply(&source);
        assert_eq!(lifted, bounded);
    }

    #[test]
    fn bad_lengths_fail_closed() {
        let err = transduct_with_lift(&S6_BASIS, &S8_BASIS, &[0], &[0; 8]).unwrap_err();
        assert!(matches!(err, LiftedTransductionError::SourceLengthMismatch { .. }));

        let source = vec![0i128; S6_BASIS.len()];
        let err = transduct_with_lift(&S6_BASIS, &S8_BASIS, &source, &[0]).unwrap_err();
        assert!(matches!(err, LiftedTransductionError::LiftLengthMismatch { .. }));
    }
}
