//! Exact scale-and-round of a canonical main-basis coefficient into an odd
//! target modulus. This is the public preprocessing step of expanded BFV
//! Phase 1; it does not evaluate the encrypted digit-removal circuit.
//!
//! For `0 <= X < Q`, put `Z = target*X + floor(Q/2)` and `r = Z mod Q`.
//! Then `Y = floor(Z/Q)` lies in `[0, target]`. The main residues of `r`
//! are the lane-local residues of `Z`. [`MainOnlyBaseExt`] projects those
//! residues to `r mod target` without materializing `r` or `X`:
//!
//! `Y mod target = (floor(Q/2) - r) * Q^{-1} mod target`.
//!
//! A result of zero represents either `Y=0` or `Y=target`, exactly as the
//! BFV component switch requires. The target may be composite (`t^e`).

use super::main_only_base_ext::{MainOnlyBaseExt, MainOnlyBaseExtError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalScaleRoundError {
    EmptyMainBasis,
    InvalidTarget {
        target: u64,
    },
    EvenMainModulus {
        modulus: u64,
    },
    NonCoprimeTarget {
        main: u64,
        target: u64,
    },
    NonCanonicalInput {
        lane: usize,
        residue: u64,
        modulus: u64,
    },
    InputShapeMismatch {
        got: usize,
        expected: usize,
    },
    Projection(MainOnlyBaseExtError),
}

impl From<MainOnlyBaseExtError> for CanonicalScaleRoundError {
    fn from(value: MainOnlyBaseExtError) -> Self {
        Self::Projection(value)
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

// Inputs are below 2^63, so the signed Euclidean intermediates fit i128.
fn inverse_mod(a: u64, modulus: u64) -> u64 {
    let (mut r, mut next_r) = (modulus as i128, a as i128);
    let (mut t, mut next_t) = (0i128, 1i128);
    while next_r != 0 {
        let quotient = r / next_r;
        (r, next_r) = (next_r, r - quotient * next_r);
        (t, next_t) = (next_t, t - quotient * next_t);
    }
    debug_assert_eq!(r, 1);
    t.rem_euclid(modulus as i128) as u64
}

pub struct CanonicalScaleRound {
    main: Vec<u64>,
    target: u64,
    projector: MainOnlyBaseExt,
    half_q_mod_target: u64,
    q_inverse_mod_target: u64,
}

impl CanonicalScaleRound {
    pub fn new(main: &[u64], target: u64) -> Result<Self, CanonicalScaleRoundError> {
        if main.is_empty() {
            return Err(CanonicalScaleRoundError::EmptyMainBasis);
        }
        // Odd target makes `(Q-1)/2 mod target` derivable from `Q mod target`.
        // The upper bound keeps the signed inverse in range and the base
        // extender's `s + target - sub` correction from overflowing u64.
        if target < 3 || target % 2 == 0 || target > i64::MAX as u64 {
            return Err(CanonicalScaleRoundError::InvalidTarget { target });
        }
        for &prime in main {
            if prime % 2 == 0 {
                return Err(CanonicalScaleRoundError::EvenMainModulus { modulus: prime });
            }
            if gcd(prime, target) != 1 {
                return Err(CanonicalScaleRoundError::NonCoprimeTarget {
                    main: prime,
                    target,
                });
            }
        }
        let projector = MainOnlyBaseExt::new(main, &[target])?;
        let q_mod_target = main.iter().fold(1u64, |acc, &prime| {
            ((acc as u128 * (prime % target) as u128) % target as u128) as u64
        });
        let inverse_two = (target + 1) / 2;
        let half_q_mod_target = (((q_mod_target as u128 + target as u128 - 1)
            * inverse_two as u128)
            % target as u128) as u64;

        Ok(Self {
            main: main.to_vec(),
            target,
            projector,
            half_q_mod_target,
            q_inverse_mod_target: inverse_mod(q_mod_target, target),
        })
    }

    pub fn target(&self) -> u64 {
        self.target
    }

    /// Return `round(target*X/Q) mod target` for canonical `X in [0,Q)`.
    pub fn scale_round(&self, x_main: &[u64]) -> Result<u64, CanonicalScaleRoundError> {
        if x_main.len() != self.main.len() {
            return Err(CanonicalScaleRoundError::InputShapeMismatch {
                got: x_main.len(),
                expected: self.main.len(),
            });
        }
        let mut remainder_main = Vec::with_capacity(self.main.len());
        for (lane, (&residue, &prime)) in x_main.iter().zip(&self.main).enumerate() {
            if residue >= prime {
                return Err(CanonicalScaleRoundError::NonCanonicalInput {
                    lane,
                    residue,
                    modulus: prime,
                });
            }
            let half_q_mod_prime = (prime - 1) / 2;
            let z_mod_prime = ((residue as u128 * (self.target % prime) as u128
                + half_q_mod_prime as u128)
                % prime as u128) as u64;
            remainder_main.push(z_mod_prime);
        }
        let mut remainder_target = [0u64; 1];
        self.projector
            .project(&remainder_main, &mut remainder_target)?;
        let difference = (self.half_q_mod_target as u128 + self.target as u128
            - remainder_target[0] as u128)
            % self.target as u128;
        Ok(((difference * self.q_inverse_mod_target as u128) % self.target as u128) as u64)
    }
}
