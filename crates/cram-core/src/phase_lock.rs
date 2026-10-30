//! Exact 2/11 residue check for a winding-successor sister tray.
//!
//! This checks a declared arithmetic relation. The caller must separately
//! establish that both trays came from the same source and valid epochs, and
//! that their public intervals stay below `main_modulus * 22`.

use crate::anchor::recover_winding;
use crate::gcd;

const ANCHOR: u64 = 22;

/// Bounded successor check with 11 outside the payload basis. Root roles are
/// retained; a producer must bind the supplied views and bounds to its source.
#[derive(Clone, Debug)]
pub struct Shadow11Plan {
    payload: crate::BasisFrame,
    modulus: u64,
}

impl Shadow11Plan {
    pub fn new(payload_moduli: Vec<u64>) -> Result<Self, PhaseLockError> {
        let payload = crate::BasisFrame::try_new(payload_moduli)
            .map_err(|_| PhaseLockError::InvalidPayloadBasis)?;
        let mut modulus = 1u64;
        for &lane in payload.moduli() {
            if gcd(lane, 11) != 1 {
                return Err(PhaseLockError::NonCoprimeMainModulus);
            }
            modulus = modulus
                .checked_mul(lane)
                .filter(|&value| value <= i64::MAX as u64)
                .ok_or(PhaseLockError::InvalidMainModulus)?;
        }
        Ok(Self { payload, modulus })
    }

    pub fn s8() -> Self {
        Self::new(vec![2, 3, 5, 7, 13, 17, 19]).expect("fixed S8 shadow split")
    }

    /// Verify unchanged payload views and derive the transient increment as
    /// `(shadow_b-shadow_a) * M^-1 mod 11`. With a producer-established
    /// nonnegative increment bound below 11, this residue uniquely names DeltaK.
    /// This checks arithmetic only, without authenticating caller-supplied views.
    pub fn verify_successor(
        &self,
        payload_a: &[u64],
        shadow_a: u8,
        payload_b: &[u64],
        shadow_b: u8,
        source_upper: u64,
        delta_upper: u8,
    ) -> Result<(), PhaseLockError> {
        if shadow_a >= 11 || shadow_b >= 11 {
            return Err(PhaseLockError::InvalidResidue11);
        }
        if delta_upper >= 11 {
            return Err(PhaseLockError::AmbiguousIncrement);
        }
        let capacity = self.modulus as u128 * 11;
        if source_upper as u128 >= capacity {
            return Err(PhaseLockError::InvalidSourceBound);
        }
        if source_upper as u128 + self.modulus as u128 * delta_upper as u128 >= capacity {
            return Err(PhaseLockError::SuccessorExceedsCapacity);
        }
        if payload_a.len() != self.payload.moduli().len() || payload_b.len() != payload_a.len() {
            return Err(PhaseLockError::InvalidPayloadShape);
        }
        for ((&a, &b), &modulus) in payload_a.iter().zip(payload_b).zip(self.payload.moduli()) {
            if a >= modulus || b >= modulus {
                return Err(PhaseLockError::InvalidPayloadResidue);
            }
            if a != b {
                return Err(PhaseLockError::PayloadChanged);
            }
        }
        // The difference is M*DeltaK: its main residue is zero and its
        // independently supplied shadow residue is the modular difference.
        let difference = (shadow_b as i16 - shadow_a as i16).rem_euclid(11) as u64;
        let winding = recover_winding(0, difference, self.modulus, 11)
            .map_err(|_| PhaseLockError::InvalidMainModulus)?;
        if winding.winding_mod_anchor > delta_upper as u64 {
            return Err(PhaseLockError::IncrementExceedsBound);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseLock22 {
    residue2: u8,
    residue11: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseLockError {
    InvalidPayloadBasis,
    InvalidPayloadShape,
    InvalidPayloadResidue,
    PayloadChanged,
    AmbiguousIncrement,
    IncrementExceedsBound,
    InvalidResidue2,
    InvalidResidue11,
    InvalidMainModulus,
    NonCoprimeMainModulus,
    InvalidSourceBound,
    SuccessorExceedsCapacity,
    SuccessorMismatch,
    RawCarryOutOfRange,
}

/// Exact Euclidean split of a native refresh carry into one shadow-11 sheet
/// digit and its higher epoch quotient. This is an arithmetic primitive for
/// protected state; returning these clear values does not authorize a public
/// evaluator to observe a secret-dependent carry.
pub fn verify_refresh_carry_step(raw_carry_digit: i16) -> Result<(u8, i16), PhaseLockError> {
    if !(-49..=49).contains(&raw_carry_digit) {
        return Err(PhaseLockError::RawCarryOutOfRange);
    }
    let sheet_inc = raw_carry_digit.rem_euclid(11) as u8;
    let epoch_carry = (raw_carry_digit - sheet_inc as i16) / 11;
    debug_assert_eq!(raw_carry_digit, 11 * epoch_carry + sheet_inc as i16);
    Ok((sheet_inc, epoch_carry))
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

    #[test]
    fn all_native_signed_carries_split_exactly_without_mod11_aliasing() {
        for raw in -49i16..=49 {
            let (sheet, epoch) = verify_refresh_carry_step(raw).unwrap();
            assert!(sheet < 11);
            assert!((-5..=4).contains(&epoch));
            assert_eq!(raw, 11 * epoch + sheet as i16);
        }
        assert_eq!(verify_refresh_carry_step(-49), Ok((6, -5)));
        assert_eq!(verify_refresh_carry_step(49), Ok((5, 4)));
        assert_eq!(verify_refresh_carry_step(5), Ok((5, 0)));
        assert_eq!(verify_refresh_carry_step(16), Ok((5, 1)));
        assert_eq!(
            verify_refresh_carry_step(-50),
            Err(PhaseLockError::RawCarryOutOfRange)
        );
        assert_eq!(
            verify_refresh_carry_step(50),
            Err(PhaseLockError::RawCarryOutOfRange)
        );
    }

    #[test]
    fn shadow_elimination_matches_independent_integer_successors() {
        for moduli in [vec![2, 3, 5], vec![7, 13]] {
            let plan = Shadow11Plan::new(moduli.clone()).unwrap();
            let m: u64 = moduli.iter().product();
            for delta in 0..11u8 {
                for source in 0..m * (11 - delta as u64) {
                    let successor = source + m * delta as u64;
                    let a: Vec<_> = moduli.iter().map(|p| source % p).collect();
                    let b: Vec<_> = moduli.iter().map(|p| successor % p).collect();
                    assert_eq!(
                        plan.verify_successor(
                            &a,
                            (source % 11) as u8,
                            &b,
                            (successor % 11) as u8,
                            source,
                            delta
                        ),
                        Ok(())
                    );
                    if delta > 0 {
                        assert_eq!(
                            plan.verify_successor(
                                &a,
                                (source % 11) as u8,
                                &b,
                                (successor % 11) as u8,
                                source,
                                delta - 1
                            ),
                            Err(PhaseLockError::IncrementExceedsBound)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn s8_shadow_elimination_refuses_changed_payload_and_aliases() {
        let plan = Shadow11Plan::s8();
        let m = 881_790u64;
        assert_eq!(plan.modulus, m);
        let source = m + 123;
        let successor = source + 4 * m;
        let a: Vec<_> = plan.payload.moduli().iter().map(|p| source % p).collect();
        let b: Vec<_> = plan
            .payload
            .moduli()
            .iter()
            .map(|p| successor % p)
            .collect();
        let sa = (source % 11) as u8;
        let sb = (successor % 11) as u8;
        assert_eq!(plan.verify_successor(&a, sa, &b, sb, source, 4), Ok(()));
        let mut changed = b.clone();
        changed[0] ^= 1;
        assert_eq!(
            plan.verify_successor(&a, sa, &changed, sb, source, 4),
            Err(PhaseLockError::PayloadChanged)
        );
        assert_eq!(
            plan.verify_successor(&a, sa, &b, sb, source, 3),
            Err(PhaseLockError::IncrementExceedsBound)
        );
        assert_eq!(
            plan.verify_successor(&a, sa, &a, sa, source, 11),
            Err(PhaseLockError::AmbiguousIncrement)
        );
        // The native refresh carry radius is 49; a lone shadow-11 reading
        // cannot uniquely encode that range.
        assert_eq!(
            plan.verify_successor(&a, sa, &a, sa, source, 49),
            Err(PhaseLockError::AmbiguousIncrement)
        );
        assert_eq!(
            plan.verify_successor(&a, sa, &b, sb, 7 * m, 4),
            Err(PhaseLockError::SuccessorExceedsCapacity)
        );
        assert_eq!(
            plan.verify_successor(&a, sa, &b[..6], sb, source, 4),
            Err(PhaseLockError::InvalidPayloadShape)
        );
        assert_eq!(
            plan.verify_successor(&a, sa, &b, 11, source, 4),
            Err(PhaseLockError::InvalidResidue11)
        );
        let mut noncanonical = b.clone();
        noncanonical[0] = 2;
        assert_eq!(
            plan.verify_successor(&a, sa, &noncanonical, sb, source, 4),
            Err(PhaseLockError::InvalidPayloadResidue)
        );
        assert_eq!(
            Shadow11Plan::new(vec![2, 11]).unwrap_err(),
            PhaseLockError::NonCoprimeMainModulus
        );
    }

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
