//! Exact coefficientwise RNS scaling between BFV plaintext scales.
//!
//! Given a centered CRT coefficient `x` and plaintext moduli `t_in` and
//! `t_out`, this computes
//!
//! ```text
//! y = floor((t_in * x + floor(t_out / 2)) / t_out)
//! ```
//!
//! directly in the RNS basis. It uses `x mod t_out` as the K-Elimination
//! anchor, then performs exact division modulo every main lane. The centered
//! CRT integer is never materialized.
//!
//! This maps one polynomial component. Applying it separately to `c0` and
//! `c1` does **not** by itself convert a ciphertext: the integer winding in
//! `c0 + c1*s` becomes a plaintext shift after rational scaling. A ciphertext
//! caller must correct that secret-dependent winding in addition to charging
//! coefficient-rounding error.

use super::main_only_base_ext::{MainOnlyBaseExt, MainOnlyBaseExtError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaintextScaleRoundError {
    EmptyMainBasis,
    InvalidPlaintextModulus { modulus: u64 },
    NonCoprimeOutput { main: u64, output: u64 },
    InputShapeMismatch { got: usize, expected: usize },
    NonCanonicalResidue { lane: usize, residue: u64, modulus: u64 },
    Projection(MainOnlyBaseExtError),
}

impl From<MainOnlyBaseExtError> for PlaintextScaleRoundError {
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

fn inverse_mod(a: u64, modulus: u64) -> u64 {
    let (mut r, mut next_r) = (modulus as i128, (a % modulus) as i128);
    let (mut t, mut next_t) = (0i128, 1i128);
    while next_r != 0 {
        let quotient = r / next_r;
        (r, next_r) = (next_r, r - quotient * next_r);
        (t, next_t) = (next_t, t - quotient * next_t);
    }
    debug_assert_eq!(r, 1);
    t.rem_euclid(modulus as i128) as u64
}

/// Precomputed exact scale conversion for one RNS basis.
pub struct RnsComponentScaleRound {
    main: Vec<u64>,
    input: u64,
    output: u64,
    half_output: u64,
    projector: MainOnlyBaseExt,
    output_inverse: Vec<u64>,
}

impl RnsComponentScaleRound {
    /// Build a converter for centered coefficients in `main`.
    ///
    /// The main lanes must be pairwise coprime and below `2^63`. `output`
    /// must be coprime to every main lane so exact division is defined.
    pub fn new(
        main: &[u64],
        input: u64,
        output: u64,
    ) -> Result<Self, PlaintextScaleRoundError> {
        if main.is_empty() {
            return Err(PlaintextScaleRoundError::EmptyMainBasis);
        }
        for modulus in [input, output] {
            if modulus < 2 || modulus > i64::MAX as u64 {
                return Err(PlaintextScaleRoundError::InvalidPlaintextModulus { modulus });
            }
        }
        let mut output_inverse = Vec::with_capacity(main.len());
        for &modulus in main {
            if gcd(modulus, output) != 1 {
                return Err(PlaintextScaleRoundError::NonCoprimeOutput {
                    main: modulus,
                    output,
                });
            }
            output_inverse.push(inverse_mod(output, modulus));
        }
        let projector = MainOnlyBaseExt::new(main, &[output])?;
        Ok(Self {
            main: main.to_vec(),
            input,
            output,
            half_output: output / 2,
            projector,
            output_inverse,
        })
    }

    pub fn input_plaintext(&self) -> u64 {
        self.input
    }

    pub fn output_plaintext(&self) -> u64 {
        self.output
    }

    /// Convert one coefficient using only its canonical main-basis residues.
    pub fn scale_round(&self, input_main: &[u64]) -> Result<Vec<u64>, PlaintextScaleRoundError> {
        if input_main.len() != self.main.len() {
            return Err(PlaintextScaleRoundError::InputShapeMismatch {
                got: input_main.len(),
                expected: self.main.len(),
            });
        }
        for (lane, (&residue, &modulus)) in input_main.iter().zip(&self.main).enumerate() {
            if residue >= modulus {
                return Err(PlaintextScaleRoundError::NonCanonicalResidue {
                    lane,
                    residue,
                    modulus,
                });
            }
        }

        // `centered_residue` is the CRT-centered x modulo output. Therefore
        // this is the exact division remainder of
        // `input*x + floor(output/2)` modulo output.
        let mut centered_residue = [0u64];
        self.projector
            .project_centered(input_main, &mut centered_residue)?;
        let remainder = ((self.input as u128 * centered_residue[0] as u128
            + self.half_output as u128)
            % self.output as u128) as u64;

        Ok(input_main
            .iter()
            .zip(&self.main)
            .zip(&self.output_inverse)
            .map(|((&residue, &modulus), &inverse)| {
                let numerator = (self.input as u128 * residue as u128
                    + self.half_output as u128)
                    % modulus as u128;
                let remainder_mod_main = remainder as u128 % modulus as u128;
                let difference = (numerator + modulus as u128 - remainder_mod_main)
                    % modulus as u128;
                (difference * inverse as u128 % modulus as u128) as u64
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::rns::U512;

    fn product(main: &[u64]) -> U512 {
        U512::product_u64s(main)
    }

    fn greater(a: U512, b: U512) -> bool {
        (a.d3, a.d2, a.d1, a.d0) > (b.d3, b.d2, b.d1, b.d0)
    }

    fn crt_centered(main: &[u64], residues: &[u64]) -> i128 {
        let mut value = U512::zero();
        let mut prefix = U512::from_u64(1);
        for (&residue, &modulus) in residues.iter().zip(main) {
            let delta = (residue as u128 + modulus as u128
                - value.mod_u64(modulus) as u128)
                % modulus as u128;
            let digit = delta * inverse_mod(prefix.mod_u64(modulus), modulus) as u128
                % modulus as u128;
            value = value.add(prefix.mul_u128(digit));
            prefix = prefix.mul_u128(modulus as u128);
        }
        let q = product(main);
        let half = q.sub(U512::from_u64(1)).div_u64(2);
        let magnitude = if greater(value, half) {
            q.sub(value)
        } else {
            value
        };
        // These tests use at most 241-bit products only when the selected
        // coefficient is small. The exhaustive oracle basis stays < 2^14.
        assert_eq!(magnitude.d3, 0);
        assert_eq!(magnitude.d2, 0);
        assert_eq!(magnitude.d1, 0);
        if greater(value, half) {
            -(magnitude.d0 as i128)
        } else {
            magnitude.d0 as i128
        }
    }

    fn oracle(main: &[u64], residues: &[u64], input: u64, output: u64) -> Vec<u64> {
        let x = crt_centered(main, residues);
        let y = (input as i128 * x + (output / 2) as i128).div_euclid(output as i128);
        main.iter()
            .map(|&modulus| y.rem_euclid(modulus as i128) as u64)
            .collect()
    }

    #[test]
    fn adjacent_and_output_scale_conversion_match_every_toy_centered_value() {
        let main = [17, 19, 23];
        let q: u64 = main.iter().product();
        for (input, output) in [(120, 121), (121, 65537)] {
            let scale = RnsComponentScaleRound::new(&main, input, output).unwrap();
            for x in -(q as i64 / 2)..=(q as i64 / 2) {
                let residues: Vec<_> = main
                    .iter()
                    .map(|&modulus| x.rem_euclid(modulus as i64) as u64)
                    .collect();
                assert_eq!(scale.scale_round(&residues).unwrap(), oracle(&main, &residues, input, output));
            }
        }
    }

    #[test]
    fn scale_conversion_is_k_elimination_not_full_crt_reconstruction() {
        let main = [998_244_353, 985_661_441, 754_974_721, 469_762_049,
                    1_811_939_329, 2_113_926_217, 2_130_706_433, 1_107_296_257];
        let scale = RnsComponentScaleRound::new(&main, 120, 121).unwrap();
        for x in [-100i128, -1, 0, 1, 100] {
            let input: Vec<_> = main
                .iter()
                .map(|&modulus| x.rem_euclid(modulus as i128) as u64)
                .collect();
            let expected_value = (120 * x + 60).div_euclid(121);
            let expected: Vec<_> = main
                .iter()
                .map(|&modulus| expected_value.rem_euclid(modulus as i128) as u64)
                .collect();
            assert_eq!(scale.scale_round(&input).unwrap(), expected);
        }
    }

    #[test]
    fn rejects_output_anchor_shared_with_a_main_lane() {
        let result = RnsComponentScaleRound::new(&[17, 19], 120, 17);
        assert!(matches!(
            result,
            Err(PlaintextScaleRoundError::NonCoprimeOutput { main: 17, output: 17 })
        ));
    }
}
