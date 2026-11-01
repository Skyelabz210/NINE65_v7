//! Exact scale-and-round of a canonical main-basis coefficient into a target
//! modulus coprime to the odd main basis. This is the public preprocessing step of expanded BFV
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
//! [`CanonicalScaleRound::scale_round_unreduced`] distinguishes these
//! endpoints when a subsequent public component calculation needs the integer
//! quotient in `[0,target]`. It compares the public input with `ceil(Q/2)`
//! through the same exact residue projector, without constructing `X`.

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

/// Rounded integer in `[0,target]`, with the upper endpoint preserved.
/// Only the checked scale-and-round operation can construct this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalRoundedCoefficient {
    value: u64,
    target: u64,
}

impl CanonicalRoundedCoefficient {
    /// Integer quotient, including `target` at the upper endpoint.
    pub fn value(self) -> u64 {
        self.value
    }

    pub fn target(self) -> u64 {
        self.target
    }

    /// The modular component value used by a BFV component switch.
    pub fn residue(self) -> u64 {
        if self.is_upper_endpoint() {
            0
        } else {
            self.value
        }
    }

    pub fn is_upper_endpoint(self) -> bool {
        self.value == self.target
    }
}

impl CanonicalScaleRound {
    pub fn new(main: &[u64], target: u64) -> Result<Self, CanonicalScaleRoundError> {
        if main.is_empty() {
            return Err(CanonicalScaleRoundError::EmptyMainBasis);
        }
        // The upper bound keeps the signed inverse in range, and ensures
        // `2*target` fits u64 for deriving floor(Q/2) modulo any target.
        if target < 2 || target > i64::MAX as u64 {
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
        let twice_target = 2 * target;
        let q_mod_twice_target = main.iter().fold(1u64, |acc, &prime| {
            ((acc as u128 * (prime % twice_target) as u128) % twice_target as u128) as u64
        });
        // Q is odd, so Q mod 2t is odd and (Q mod 2t - 1)/2 equals
        // floor(Q/2) mod t. This also works when t itself is even.
        debug_assert_eq!(q_mod_twice_target % 2, 1);
        let half_q_mod_target = (q_mod_twice_target - 1) / 2;
        let q_mod_target = q_mod_twice_target % target;

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

    /// Return `floor((target*X + floor(Q/2))/Q)` in `[0,target]`.
    ///
    /// A zero modular result can mean either endpoint. For `target >= 2`,
    /// `Y=0` implies `X < Q/2`, while `Y=target` implies `X > Q/2`.
    /// The exact public-input half decision therefore resolves the ambiguity.
    /// Main residues are validated before either projector receives them.
    pub fn scale_round_unreduced(
        &self,
        x_main: &[u64],
    ) -> Result<CanonicalRoundedCoefficient, CanonicalScaleRoundError> {
        let mut value = self.scale_round(x_main)?;
        if value == 0 {
            let mut centered = [0u64; 1];
            let (_, upper) = self.projector.project_centered(x_main, &mut centered)?;
            if upper {
                value = self.target;
            }
        }
        Ok(CanonicalRoundedCoefficient {
            value,
            target: self.target,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wide_main_endpoint_rounding_matches_python_integer_vectors() {
        // Independent Python integer oracle: Q=427383473408756350902886276116831015819804673 (149 bits).
        // Source coefficients are supplied only as five canonical residues.
        let main = [
            998_244_353,
            985_661_441,
            754_974_721,
            469_762_049,
            1_224_736_769,
        ];
        let vectors: &[(u64, [u64; 5], u64)] = &[
            (2, [0, 0, 0, 0, 0], 0),
            (2, [1, 1, 1, 1, 1], 0),
            (
                2,
                [499122176, 492830720, 377487360, 234881024, 612368384],
                1,
            ),
            (
                2,
                [499122177, 492830721, 377487361, 234881025, 612368385],
                1,
            ),
            (
                2,
                [748683264, 739246080, 566231040, 352321536, 918552576],
                1,
            ),
            (
                2,
                [748683265, 739246081, 566231041, 352321537, 918552577],
                2,
            ),
            (
                2,
                [998244352, 985661440, 754974720, 469762048, 1224736768],
                2,
            ),
            (16, [0, 0, 0, 0, 0], 0),
            (16, [1, 1, 1, 1, 1], 0),
            (
                16,
                [499122176, 492830720, 377487360, 234881024, 612368384],
                8,
            ),
            (
                16,
                [499122177, 492830721, 377487361, 234881025, 612368385],
                8,
            ),
            (
                16,
                [967049216, 954859520, 731381760, 455081984, 1186463744],
                15,
            ),
            (
                16,
                [967049217, 954859521, 731381761, 455081985, 1186463745],
                16,
            ),
            (
                16,
                [998244352, 985661440, 754974720, 469762048, 1224736768],
                16,
            ),
            (65537, [0, 0, 0, 0, 0], 0),
            (65537, [1, 1, 1, 1, 1], 0),
            (
                65537,
                [499122176, 492830720, 377487360, 234881024, 612368384],
                32768,
            ),
            (
                65537,
                [499122177, 492830721, 377487361, 234881025, 612368385],
                32769,
            ),
            (
                65537,
                [840664101, 410457897, 556689746, 333210148, 357168950],
                65536,
            ),
            (
                65537,
                [840664102, 410457898, 556689747, 333210149, 357168951],
                65537,
            ),
            (
                65537,
                [998244352, 985661440, 754974720, 469762048, 1224736768],
                65537,
            ),
            (1073758208, [0, 0, 0, 0, 0], 0),
            (1073758208, [1, 1, 1, 1, 1], 0),
            (
                1073758208,
                [499122176, 492830720, 377487360, 234881024, 612368384],
                536879104,
            ),
            (
                1073758208,
                [499122177, 492830721, 377487361, 234881025, 612368385],
                536879104,
            ),
            (
                1073758208,
                [630290542, 329461212, 38142137, 76431217, 1020760360],
                1073758207,
            ),
            (
                1073758208,
                [630290543, 329461213, 38142138, 76431218, 1020760361],
                1073758208,
            ),
            (
                1073758208,
                [998244352, 985661440, 754974720, 469762048, 1224736768],
                1073758208,
            ),
            (4611686018427387904, [0, 0, 0, 0, 0], 0),
            (4611686018427387904, [1, 1, 1, 1, 1], 0),
            (
                4611686018427387904,
                [499122176, 492830720, 377487360, 234881024, 612368384],
                2305843009213693952,
            ),
            (
                4611686018427387904,
                [499122177, 492830721, 377487361, 234881025, 612368385],
                2305843009213693952,
            ),
            (
                4611686018427387904,
                [536212096, 526159360, 352169280, 172517632, 724351552],
                4611686018427387903,
            ),
            (
                4611686018427387904,
                [536212097, 526159361, 352169281, 172517633, 724351553],
                4611686018427387904,
            ),
            (
                4611686018427387904,
                [998244352, 985661440, 754974720, 469762048, 1224736768],
                4611686018427387904,
            ),
            (9223372036854775807, [0, 0, 0, 0, 0], 0),
            (9223372036854775807, [1, 1, 1, 1, 1], 0),
            (
                9223372036854775807,
                [499122176, 492830720, 377487360, 234881024, 612368384],
                4611686018427387903,
            ),
            (
                9223372036854775807,
                [499122177, 492830721, 377487361, 234881025, 612368385],
                4611686018427387904,
            ),
            (
                9223372036854775807,
                [764716290, 753398466, 551060066, 318627906, 972032226],
                9223372036854775806,
            ),
            (
                9223372036854775807,
                [764716291, 753398467, 551060067, 318627907, 972032227],
                9223372036854775807,
            ),
            (
                9223372036854775807,
                [998244352, 985661440, 754974720, 469762048, 1224736768],
                9223372036854775807,
            ),
        ];
        for &(target, residues, expected) in vectors {
            let scale = CanonicalScaleRound::new(&main, target).unwrap();
            let rounded = scale.scale_round_unreduced(&residues).unwrap();
            assert_eq!(
                rounded.value(),
                expected,
                "target={target}, residues={residues:?}"
            );
            assert_eq!(rounded.residue(), expected % target);
            assert_eq!(scale.scale_round(&residues).unwrap(), expected % target);
        }
    }

    #[test]
    fn binary_target_is_a_valid_public_rounding_view() {
        let scale = CanonicalScaleRound::new(&[5, 7], 2).unwrap();
        for x in 0..35 {
            assert_eq!(
                scale.scale_round(&[x % 5, x % 7]).unwrap(),
                (2 * x + 17) / 35 % 2
            );
        }
    }

    #[test]
    fn preserving_the_upper_endpoint_keeps_the_public_residual_signed() {
        // Q=35, X=31, p=3, clock size=4: coarse rounds to p while
        // fine rounds to 11. Reducing coarse modulo p too early changes
        // the normalized public residual from -1 to +11.
        let residues = [31 % 5, 31 % 7];
        let coarse = CanonicalScaleRound::new(&[5, 7], 3).unwrap();
        let fine = CanonicalScaleRound::new(&[5, 7], 12).unwrap();
        let a = coarse.scale_round_unreduced(&residues).unwrap();
        let u = fine.scale_round_unreduced(&residues).unwrap();
        assert!(a.is_upper_endpoint());
        assert_eq!(u.value() as i64 - 4 * a.value() as i64, -1);
        assert_eq!(u.residue() as i64 - 4 * a.residue() as i64, 11);
    }

    #[test]
    fn even_target_matches_integer_rounding() {
        let main = [17u64, 13];
        let q = 17 * 13u64;
        let target = 1u64 << 16;
        let scale = CanonicalScaleRound::new(&main, target).unwrap();
        for x in 0..q {
            let residues = main.map(|prime| x % prime);
            let expected =
                ((x as u128 * target as u128 + q as u128 / 2) / q as u128) % target as u128;
            assert_eq!(scale.scale_round(&residues).unwrap(), expected as u64);
        }
    }

    #[test]
    fn endpoint_aware_rounding_matches_exhaustive_integer_oracle() {
        let mut checks = 0usize;
        // Includes single-lane and composite odd lanes. Only coprime bases
        // and targets are admitted; every canonical source is enumerated.
        for main in [&[3u64][..], &[5][..], &[7, 9][..], &[13, 17][..]] {
            let q: u64 = main.iter().product();
            for target in 2..=32u64 {
                if main.iter().any(|&prime| gcd(prime, target) != 1) {
                    continue;
                }
                let scale = CanonicalScaleRound::new(main, target).unwrap();
                for x in 0..q {
                    let residues: Vec<_> = main.iter().map(|&prime| x % prime).collect();
                    let expected = (target as u128 * x as u128 + q as u128 / 2) / q as u128;
                    let rounded = scale.scale_round_unreduced(&residues).unwrap();
                    assert_eq!(rounded.value(), expected as u64);
                    assert_eq!(rounded.target(), target);
                    assert_eq!(rounded.residue(), expected as u64 % target);
                    assert_eq!(rounded.is_upper_endpoint(), expected == target as u128);
                    assert_eq!(scale.scale_round(&residues).unwrap(), rounded.residue());
                    checks += 1;
                }
            }
        }
        assert!(checks > 5000);
    }

    #[test]
    fn checked_rounding_refuses_invalid_parameters_and_inputs() {
        assert!(matches!(
            CanonicalScaleRound::new(&[], 2),
            Err(CanonicalScaleRoundError::EmptyMainBasis)
        ));
        for target in [0, 1, i64::MAX as u64 + 1, u64::MAX] {
            assert!(matches!(
                CanonicalScaleRound::new(&[5, 7], target),
                Err(CanonicalScaleRoundError::InvalidTarget { .. })
            ));
        }
        assert!(matches!(
            CanonicalScaleRound::new(&[4, 7], 3),
            Err(CanonicalScaleRoundError::EvenMainModulus { modulus: 4 })
        ));
        assert!(matches!(
            CanonicalScaleRound::new(&[5, 7], 10),
            Err(CanonicalScaleRoundError::NonCoprimeTarget {
                main: 5,
                target: 10
            })
        ));
        assert!(matches!(
            CanonicalScaleRound::new(&[5, 15], 2),
            Err(CanonicalScaleRoundError::Projection(
                MainOnlyBaseExtError::NonCoprimeMain { .. }
            ))
        ));
        assert!(matches!(
            CanonicalScaleRound::new(&[1], 2),
            Err(CanonicalScaleRoundError::Projection(
                MainOnlyBaseExtError::DegenerateModulus { modulus: 1 }
            ))
        ));
        let scale = CanonicalScaleRound::new(&[5, 7], 2).unwrap();
        for input in [&[][..], &[0][..], &[0, 0, 0][..]] {
            assert!(matches!(
                scale.scale_round(input),
                Err(CanonicalScaleRoundError::InputShapeMismatch { .. })
            ));
            assert!(matches!(
                scale.scale_round_unreduced(input),
                Err(CanonicalScaleRoundError::InputShapeMismatch { .. })
            ));
        }
        for input in [[5, 0], [0, 7], [u64::MAX, 0]] {
            assert!(matches!(
                scale.scale_round(&input),
                Err(CanonicalScaleRoundError::NonCanonicalInput { .. })
            ));
            assert!(matches!(
                scale.scale_round_unreduced(&input),
                Err(CanonicalScaleRoundError::NonCanonicalInput { .. })
            ));
        }
    }
}
