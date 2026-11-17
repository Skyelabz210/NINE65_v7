use crate::gcd;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorError {
    InvalidModulus,
    ModulusTooLarge,
    NonCanonicalMainResidue,
    NonCanonicalAnchorResidue,
    NonCoprimeModuli,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorWitness {
    pub main_modulus: u64,
    pub anchor_modulus: u64,
    pub main_residue: u64,
    pub anchor_residue: u64,
    pub winding_mod_anchor: u64,
}

impl AnchorWitness {
    pub fn verify(self) -> bool {
        if self.main_modulus < 2
            || self.anchor_modulus < 2
            || self.main_residue >= self.main_modulus
            || self.anchor_residue >= self.anchor_modulus
            || gcd(self.main_modulus, self.anchor_modulus) != 1
        {
            return false;
        }
        let lhs = self.anchor_residue as u128;
        let rhs = (self.main_residue as u128
            + self.winding_mod_anchor as u128 * self.main_modulus as u128)
            % self.anchor_modulus as u128;
        lhs == rhs
    }
}

pub fn recover_winding(
    main_residue: u64,
    anchor_residue: u64,
    main_modulus: u64,
    anchor_modulus: u64,
) -> Result<AnchorWitness, AnchorError> {
    validate_inputs(main_residue, anchor_residue, main_modulus, anchor_modulus)?;

    let inverse = inverse_mod(main_modulus % anchor_modulus, anchor_modulus)?;
    let reduced_main = main_residue % anchor_modulus;
    let difference = if anchor_residue >= reduced_main {
        anchor_residue - reduced_main
    } else {
        anchor_modulus - (reduced_main - anchor_residue)
    };
    let winding_mod_anchor =
        ((difference as u128 * inverse as u128) % anchor_modulus as u128) as u64;

    let witness = AnchorWitness {
        main_modulus,
        anchor_modulus,
        main_residue,
        anchor_residue,
        winding_mod_anchor,
    };
    debug_assert!(witness.verify());
    Ok(witness)
}

pub fn recover_adjacent_winding(
    main_residue: u64,
    anchor_residue: u64,
    main_modulus: u64,
) -> Result<AnchorWitness, AnchorError> {
    let anchor_modulus = main_modulus
        .checked_add(1)
        .ok_or(AnchorError::InvalidModulus)?;
    validate_inputs(main_residue, anchor_residue, main_modulus, anchor_modulus)?;
    let winding_mod_anchor =
        (main_residue % anchor_modulus + anchor_modulus - anchor_residue) % anchor_modulus;
    let witness = AnchorWitness {
        main_modulus,
        anchor_modulus,
        main_residue,
        anchor_residue,
        winding_mod_anchor,
    };
    debug_assert!(witness.verify());
    Ok(witness)
}

fn validate_inputs(
    main_residue: u64,
    anchor_residue: u64,
    main_modulus: u64,
    anchor_modulus: u64,
) -> Result<(), AnchorError> {
    if main_modulus < 2 || anchor_modulus < 2 {
        return Err(AnchorError::InvalidModulus);
    }
    if main_modulus > i64::MAX as u64 || anchor_modulus > i64::MAX as u64 {
        return Err(AnchorError::ModulusTooLarge);
    }
    if main_residue >= main_modulus {
        return Err(AnchorError::NonCanonicalMainResidue);
    }
    if anchor_residue >= anchor_modulus {
        return Err(AnchorError::NonCanonicalAnchorResidue);
    }
    if gcd(main_modulus, anchor_modulus) != 1 {
        return Err(AnchorError::NonCoprimeModuli);
    }
    Ok(())
}

fn inverse_mod(value: u64, modulus: u64) -> Result<u64, AnchorError> {
    let (divisor, coefficient, _) = extended_gcd(value as i128, modulus as i128);
    if divisor != 1 {
        return Err(AnchorError::NonCoprimeModuli);
    }
    Ok(coefficient.rem_euclid(modulus as i128) as u64)
}

fn extended_gcd(left: i128, right: i128) -> (i128, i128, i128) {
    if right == 0 {
        return (left.abs(), left.signum(), 0);
    }
    let quotient = left.div_euclid(right);
    let remainder = left.rem_euclid(right);
    let (divisor, x1, y1) = extended_gcd(right, remainder);
    (divisor, y1, x1 - quotient * y1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhaustive_small_coprime_pairs() {
        let pairs = [(4_u64, 9_u64), (8, 9), (15, 16), (25, 49), (36, 37)];
        for (main, anchor) in pairs {
            for value in 0..main * anchor {
                let witness = recover_winding(value % main, value % anchor, main, anchor)
                    .expect("coprime pair");
                assert_eq!(witness.winding_mod_anchor, value / main);
                assert!(witness.verify());
            }
        }
    }

    #[test]
    fn adjacent_path_matches_general_path() {
        for main in 2_u64..128 {
            let anchor = main + 1;
            for value in 0..main * anchor {
                let general = recover_winding(value % main, value % anchor, main, anchor)
                    .expect("adjacent pair is coprime");
                let adjacent = recover_adjacent_winding(value % main, value % anchor, main)
                    .expect("adjacent pair is valid");
                assert_eq!(general, adjacent);
            }
        }
    }

    #[test]
    fn rejects_non_coprime_pair() {
        assert_eq!(
            recover_winding(1, 1, 6, 9),
            Err(AnchorError::NonCoprimeModuli)
        );
    }
}
