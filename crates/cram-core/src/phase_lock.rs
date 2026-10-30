//! Exact 2/11 residue check for a winding-successor sister tray.
//!
//! This checks a declared arithmetic relation. The caller must separately
//! establish that both trays came from the same source and valid epochs, and
//! that their public intervals stay below `main_modulus * 22`.

use crate::gcd;

const ANCHOR: u64 = 22;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseLock22 {
    residue2: u8,
    residue11: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseLockError {
    InvalidResidue2,
    InvalidResidue11,
    InvalidMainModulus,
    NonCoprimeMainModulus,
    InvalidSourceBound,
    SuccessorExceedsCapacity,
    SuccessorMismatch,
}

impl PhaseLock22 {
    pub fn new(residue2: u8, residue11: u8) -> Result<Self, PhaseLockError> {
        if residue2 >= 2 {
            return Err(PhaseLockError::InvalidResidue2);
        }
        if residue11 >= 11 {
            return Err(PhaseLockError::InvalidResidue11);
        }
        Ok(Self {
            residue2,
            residue11,
        })
    }

    /// The unique residue in `[0,22)` matching both logical coordinates.
    pub fn residue22(self) -> u8 {
        let parity = (self.residue2 as i16 - self.residue11 as i16).rem_euclid(2) as u8;
        self.residue11 + 11 * parity
    }

    /// Checks `B ≡ A + M*delta_winding (mod 22)`. The increment is supplied
    /// by the refresh producer; it need not equal the source winding.
    ///
    /// The caller supplies a public upper bound for the source value. This
    /// checks the entire successor interval before using the residue relation.
    /// The producer must establish the bound and source/epoch binding before
    /// this result is used as live authority.
    pub fn verify_residue_successor(
        self,
        successor: Self,
        main_modulus: u64,
        delta_winding: u64,
        source_upper: u64,
    ) -> Result<(), PhaseLockError> {
        if main_modulus < 2 || main_modulus > i64::MAX as u64 {
            return Err(PhaseLockError::InvalidMainModulus);
        }
        if gcd(main_modulus, ANCHOR) != 1 {
            return Err(PhaseLockError::NonCoprimeMainModulus);
        }
        let capacity = main_modulus as u128 * ANCHOR as u128;
        if source_upper as u128 >= capacity {
            return Err(PhaseLockError::InvalidSourceBound);
        }
        let largest_successor = source_upper as u128 + main_modulus as u128 * delta_winding as u128;
        if largest_successor >= capacity {
            return Err(PhaseLockError::SuccessorExceedsCapacity);
        }
        let expected = ((self.residue22() as u64
            + (main_modulus % ANCHOR) * (delta_winding % ANCHOR))
            % ANCHOR) as u8;
        if successor.residue22() != expected {
            return Err(PhaseLockError::SuccessorMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tray(value: u64) -> PhaseLock22 {
        PhaseLock22::new((value % 2) as u8, (value % 11) as u8).unwrap()
    }

    #[test]
    fn crt_pair_covers_every_residue() {
        for value in 0..22 {
            assert_eq!(tray(value).residue22() as u64, value);
        }
        assert_eq!(PhaseLock22::new(2, 0), Err(PhaseLockError::InvalidResidue2));
        assert_eq!(
            PhaseLock22::new(0, 11),
            Err(PhaseLockError::InvalidResidue11)
        );
    }

    #[test]
    fn nonzero_refresh_increment_is_independent_of_source_winding() {
        // M=35 has M mod 22 = 13 and inverse 17. Both values are inside M*22.
        let main_modulus = 35;
        let source = 159;
        assert_eq!(source / main_modulus, 4);
        let delta_winding = 2;
        let successor = source + main_modulus * delta_winding;
        assert_eq!(successor, 229);
        assert_eq!(tray(source).residue22(), 5);
        assert_eq!(tray(successor).residue22(), 9);
        assert_eq!(
            tray(source).verify_residue_successor(
                tray(successor),
                main_modulus,
                delta_winding,
                source
            ),
            Ok(())
        );
        assert_eq!(
            tray(source).verify_residue_successor(
                tray(source),
                main_modulus,
                delta_winding,
                source
            ),
            Err(PhaseLockError::SuccessorMismatch)
        );
        assert_eq!(
            tray(source).verify_residue_successor(
                tray(successor + 1),
                main_modulus,
                delta_winding,
                source
            ),
            Err(PhaseLockError::SuccessorMismatch)
        );
    }

    #[test]
    fn s8_joint_split_reference_and_invalid_inputs() {
        let main_modulus = 440_895; // all S8 payload roles except 2 and 11
        let source = 19 + 4 * main_modulus;
        let successor = source + 4 * main_modulus;
        assert!(successor < main_modulus * 22);
        assert_eq!(tray(source).residue22(), 13);
        assert_eq!(tray(successor).residue22(), 7);
        assert_eq!(
            tray(source).verify_residue_successor(tray(successor), main_modulus, 4, source),
            Ok(())
        );
        assert_eq!(
            tray(source).verify_residue_successor(tray(successor), 11, 4, 1),
            Err(PhaseLockError::NonCoprimeMainModulus)
        );
        assert_eq!(
            tray(source).verify_residue_successor(
                tray(successor),
                main_modulus,
                4,
                22 * main_modulus
            ),
            Err(PhaseLockError::InvalidSourceBound)
        );
        assert_eq!(
            tray(source).verify_residue_successor(
                tray(successor),
                main_modulus,
                4,
                21 * main_modulus
            ),
            Err(PhaseLockError::SuccessorExceedsCapacity)
        );
    }
}
