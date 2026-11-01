//! Experimental bounded quotient projection using exact global CRT rank.
//!
//! The coefficient is supplied only as residues, with a trusted public signed
//! interval. This algorithm never assembles its scalar integer value, but its
//! full-width fractional accumulator contains equivalent coefficient
//! information. Reconstruction itself is permitted by the user's clarified
//! policy; this fact alone neither establishes nor refutes independence,
//! reversibility, or the absence of forbidden synthetic emissions. Those
//! properties require a declared input/output domain, an actual inverse,
//! operation traces, and separate source-policy evidence. This kernel is not
//! wired into BFV multiplication, rescaling, or public refresh.
//!
//! Put `P = product(moduli)`, `Y = X - lower`, and assume the caller has
//! established `lower <= X <= upper` with `upper - lower < P`. For the CRT
//! idempotent coefficients `c_i`, `sum(c_i / m_i) = rank + Y/P`. A fractional
//! precision `S = 2^B > lane_count * P` makes the integer part of
//! `sum(floor(S*c_i/m_i))/S` exactly the rank: its downward error is less than
//! `1/P`, and a nonzero `Y/P` is at least `1/P`. When `Y=0`, every `c_i=0`.
//!
//! Exact rank then projects `X` modulo `d*m_i` directly. If `r = X mod d`,
//! `(X mod (d*m_i) - r)/d` is the floor quotient modulo `m_i`, even if `d`
//! and `m_i` share factors. No modular inverse of `d` is required.
//!
//! Interval authenticity is a caller obligation, not a property inferable
//! from aliased residues. The immutable recumbent wrapper establishes it by
//! checked ingress and analytic operation bounds. This low-level routine
//! validates only its structure and capacity; it issues no authenticity or
//! cryptographic certificate. Its global reduction is neither independent
//! lane arithmetic nor a constant-time guarantee.

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RankDivisionError {
    EmptyBasis,
    TooManyLanes,
    InvalidModulus { lane: usize, modulus: u64 },
    NotCoprime { left: u64, right: u64 },
    ZeroDivisor,
    ShapeMismatch { expected: usize, got: usize },
    NonCanonicalResidue { lane: usize, residue: u64 },
    InvalidInterval,
    IntervalAliased,
    ArithmeticInvariant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RankDivisionOutput {
    pub quotient: Vec<u64>,
    pub remainder: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RankResidueDivider {
    moduli: Vec<u64>,
    divisor: u64,
    product: Vec<u64>,
    idempotent_inverses: Vec<u64>,
    fractional_words: usize,
    targets: Vec<ProjectionTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProjectionTarget {
    modulus: u128,
    cofactor_weights: Vec<u128>,
    product_modulus: u128,
}

impl RankResidueDivider {
    pub(crate) fn new(moduli: &[u64], divisor: u64) -> Result<Self, RankDivisionError> {
        if moduli.is_empty() {
            return Err(RankDivisionError::EmptyBasis);
        }
        if moduli.len() > 64 {
            return Err(RankDivisionError::TooManyLanes);
        }
        if divisor == 0 {
            return Err(RankDivisionError::ZeroDivisor);
        }
        for (lane, &modulus) in moduli.iter().enumerate() {
            if modulus < 2 {
                return Err(RankDivisionError::InvalidModulus { lane, modulus });
            }
            for &prior in &moduli[..lane] {
                if gcd(prior, modulus) != 1 {
                    return Err(RankDivisionError::NotCoprime {
                        left: prior,
                        right: modulus,
                    });
                }
            }
        }
        let mut product = vec![1u64];
        for &modulus in moduli {
            multiply_public_product(&mut product, modulus);
        }
        let product_bits = product
            .iter()
            .rposition(|&word| word != 0)
            .map_or(0, |index| {
                index * 64 + (64 - product[index].leading_zeros()) as usize
            });
        let lane_bits = (usize::BITS - moduli.len().leading_zeros()) as usize;
        // Rounding the precision upward preserves the strict S > k*P bound.
        let fractional_words = (product_bits + lane_bits + 1).div_ceil(64);
        let idempotent_inverses = moduli
            .iter()
            .enumerate()
            .map(|(skip, &modulus)| {
                let cofactor = moduli
                    .iter()
                    .enumerate()
                    .filter(|&(i, _)| i != skip)
                    .fold(1u64, |acc, (_, &factor)| {
                        ((acc as u128 * factor as u128) % modulus as u128) as u64
                    });
                inverse(cofactor, modulus).ok_or(RankDivisionError::ArithmeticInvariant)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let targets = std::iter::once(divisor as u128)
            .chain(moduli.iter().map(|&m| divisor as u128 * m as u128))
            .map(|modulus| ProjectionTarget::new(moduli, modulus))
            .collect();
        Ok(Self {
            moduli: moduli.to_vec(),
            divisor,
            product,
            idempotent_inverses,
            fractional_words,
            targets,
        })
    }

    pub(crate) fn divide_floor(
        &self,
        residues: &[u64],
        lower: i128,
        upper: i128,
    ) -> Result<RankDivisionOutput, RankDivisionError> {
        if residues.len() != self.moduli.len() {
            return Err(RankDivisionError::ShapeMismatch {
                expected: self.moduli.len(),
                got: residues.len(),
            });
        }
        if lower > upper {
            return Err(RankDivisionError::InvalidInterval);
        }
        if !self.capacity_covers(lower.abs_diff(upper)) {
            return Err(RankDivisionError::IntervalAliased);
        }
        for (lane, (&residue, &modulus)) in residues.iter().zip(&self.moduli).enumerate() {
            if residue >= modulus {
                return Err(RankDivisionError::NonCanonicalResidue { lane, residue });
            }
        }
        if self.divisor == 1 {
            return Ok(RankDivisionOutput {
                quotient: residues.to_vec(),
                remainder: 0,
            });
        }
        let coefficients: Vec<u64> = residues
            .iter()
            .zip(&self.moduli)
            .zip(&self.idempotent_inverses)
            .map(|((&residue, &modulus), &inverse)| {
                let lower_modulus = signed_mod(lower, modulus as u128);
                let adjusted =
                    (residue as u128 + modulus as u128 - lower_modulus) % modulus as u128;
                ((adjusted * inverse as u128) % modulus as u128) as u64
            })
            .collect();
        let rank = self.rank(&coefficients)?;
        let remainder = self.targets[0].project(&coefficients, rank, lower) as u64;
        let mut quotient = Vec::with_capacity(self.moduli.len());
        for (target, &modulus) in self.targets[1..].iter().zip(&self.moduli) {
            let projected = target.project(&coefficients, rank, lower);
            let difference = projected
                .checked_sub(remainder as u128)
                .ok_or(RankDivisionError::ArithmeticInvariant)?;
            if difference % self.divisor as u128 != 0 {
                return Err(RankDivisionError::ArithmeticInvariant);
            }
            let digit = difference / self.divisor as u128;
            if digit >= modulus as u128 {
                return Err(RankDivisionError::ArithmeticInvariant);
            }
            quotient.push(digit as u64);
        }
        Ok(RankDivisionOutput {
            quotient,
            remainder,
        })
    }

    fn capacity_covers(&self, width: u128) -> bool {
        // This compares public interval width with the public basis product;
        // it does not decode any coefficient.
        if self.product.len() > 2 {
            return true;
        }
        let product =
            self.product[0] as u128 | ((self.product.get(1).copied().unwrap_or(0) as u128) << 64);
        width < product
    }

    fn rank(&self, coefficients: &[u64]) -> Result<u64, RankDivisionError> {
        let words = self.fractional_words;
        let mut sum = vec![0u64; words + 1];
        let mut term = vec![0u64; words];
        for (&coefficient, &modulus) in coefficients.iter().zip(&self.moduli) {
            let mut remainder = coefficient;
            for index in (0..words).rev() {
                let numerator = (remainder as u128) << 64;
                term[index] = (numerator / modulus as u128) as u64;
                remainder = (numerator % modulus as u128) as u64;
            }
            let mut carry = 0u128;
            for index in 0..words {
                let digit = sum[index] as u128 + term[index] as u128 + carry;
                sum[index] = digit as u64;
                carry = digit >> 64;
            }
            sum[words] = sum[words]
                .checked_add(carry as u64)
                .ok_or(RankDivisionError::ArithmeticInvariant)?;
        }
        if sum[words] >= self.moduli.len() as u64 {
            return Err(RankDivisionError::ArithmeticInvariant);
        }
        Ok(sum[words])
    }
}

impl ProjectionTarget {
    fn new(moduli: &[u64], modulus: u128) -> Self {
        let product_modulus = moduli.iter().fold(1 % modulus, |acc, &factor| {
            mul_mod(acc, factor as u128, modulus)
        });
        let cofactor_weights = (0..moduli.len())
            .map(|skip| {
                moduli
                    .iter()
                    .enumerate()
                    .filter(|&(index, _)| index != skip)
                    .fold(1 % modulus, |acc, (_, &factor)| {
                        mul_mod(acc, factor as u128, modulus)
                    })
            })
            .collect();
        Self {
            modulus,
            cofactor_weights,
            product_modulus,
        }
    }

    fn project(&self, coefficients: &[u64], rank: u64, lower: i128) -> u128 {
        let sum = coefficients.iter().zip(&self.cofactor_weights).fold(
            0u128,
            |acc, (&coefficient, &weight)| {
                add_mod(
                    acc,
                    mul_mod(weight, coefficient as u128, self.modulus),
                    self.modulus,
                )
            },
        );
        let correction = mul_mod(self.product_modulus, rank as u128, self.modulus);
        let shifted = sub_mod(sum, correction, self.modulus);
        add_mod(shifted, signed_mod(lower, self.modulus), self.modulus)
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

fn inverse(a: u64, modulus: u64) -> Option<u64> {
    let (mut r, mut next_r) = (modulus as i128, a as i128);
    let (mut t, mut next_t) = (0i128, 1i128);
    while next_r != 0 {
        let quotient = r / next_r;
        (r, next_r) = (next_r, r - quotient * next_r);
        (t, next_t) = (next_t, t - quotient * next_t);
    }
    (r == 1).then(|| t.rem_euclid(modulus as i128) as u64)
}

fn multiply_public_product(limbs: &mut Vec<u64>, factor: u64) {
    let mut carry = 0u128;
    for limb in limbs.iter_mut() {
        let digit = *limb as u128 * factor as u128 + carry;
        *limb = digit as u64;
        carry = digit >> 64;
    }
    if carry != 0 {
        limbs.push(carry as u64);
    }
}

fn signed_mod(value: i128, modulus: u128) -> u128 {
    let magnitude = value.unsigned_abs() % modulus;
    if value < 0 && magnitude != 0 {
        modulus - magnitude
    } else {
        magnitude
    }
}

fn add_mod(a: u128, b: u128, modulus: u128) -> u128 {
    debug_assert!(a < modulus && b < modulus);
    if a >= modulus - b {
        a - (modulus - b)
    } else {
        a + b
    }
}

fn sub_mod(a: u128, b: u128, modulus: u128) -> u128 {
    if a >= b {
        a - b
    } else {
        modulus - (b - a)
    }
}

fn mul_mod(mut a: u128, mut b: u128, modulus: u128) -> u128 {
    if modulus == 1 {
        return 0;
    }
    a %= modulus;
    let mut result = 0u128;
    while b != 0 {
        if b & 1 != 0 {
            result = add_mod(result, a, modulus);
        }
        b >>= 1;
        a = add_mod(a, a, modulus);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn residues(value: i128, moduli: &[u64]) -> Vec<u64> {
        moduli
            .iter()
            .map(|&m| value.rem_euclid(m as i128) as u64)
            .collect()
    }

    fn check(value: i128, lower: i128, upper: i128, moduli: &[u64], divisor: u64) {
        let plan = RankResidueDivider::new(moduli, divisor).unwrap();
        let result = plan
            .divide_floor(&residues(value, moduli), lower, upper)
            .unwrap();
        let quotient = value.div_euclid(divisor as i128);
        assert_eq!(result.quotient, residues(quotient, moduli));
        assert_eq!(result.remainder, value.rem_euclid(divisor as i128) as u64);
    }

    #[test]
    fn shared_factor_divisors_keep_every_quotient_lane() {
        let moduli = [2, 3, 5, 7];
        for divisor in [1, 2, 3, 4, 6, 9, 30, 210, u64::MAX] {
            let plan = RankResidueDivider::new(&moduli, divisor).unwrap();
            for value in -100i128..=100 {
                let result = plan
                    .divide_floor(&residues(value, &moduli), -100, 100)
                    .unwrap();
                let quotient = value.div_euclid(divisor as i128);
                assert_eq!(result.quotient, residues(quotient, &moduli));
                assert_eq!(result.remainder, value.rem_euclid(divisor as i128) as u64);
            }
        }
    }

    #[test]
    fn shifted_signed_intervals_determine_the_lift() {
        check(-1, -9, 9, &[3, 7], 4);
        check(20, 12, 32, &[3, 7], 4);
        check(-22, -32, -12, &[3, 7], 7);
        check(i128::MIN, i128::MIN, i128::MIN + 20, &[3, 7], u64::MAX);
        check(i128::MAX, i128::MAX - 20, i128::MAX, &[3, 7], u64::MAX);
    }

    #[test]
    fn malformed_inputs_and_aliasing_are_refused() {
        assert_eq!(
            RankResidueDivider::new(&[], 2),
            Err(RankDivisionError::EmptyBasis)
        );
        assert_eq!(
            RankResidueDivider::new(&[3, 7], 0),
            Err(RankDivisionError::ZeroDivisor)
        );
        assert!(matches!(
            RankResidueDivider::new(&[3, 9], 2),
            Err(RankDivisionError::NotCoprime { .. })
        ));
        assert!(matches!(
            RankResidueDivider::new(&[1, 7], 2),
            Err(RankDivisionError::InvalidModulus { .. })
        ));
        let plan = RankResidueDivider::new(&[3, 7], 2).unwrap();
        assert_eq!(
            plan.divide_floor(&[0, 0], 0, 21),
            Err(RankDivisionError::IntervalAliased)
        );
        assert_eq!(
            plan.divide_floor(&[0, 0], 1, 0),
            Err(RankDivisionError::InvalidInterval)
        );
        assert!(matches!(
            plan.divide_floor(&[0], 0, 20),
            Err(RankDivisionError::ShapeMismatch { .. })
        ));
        assert!(matches!(
            plan.divide_floor(&[3, 0], 0, 20),
            Err(RankDivisionError::NonCanonicalResidue { .. })
        ));
    }

    #[test]
    fn ten_thousand_signed_inputs_match_independent_integer_division() {
        let moduli = [998_244_353, 985_661_441, 754_974_721, 469_762_049];
        let divisors = [1, 2, 4, 9, 30, 998_244_353, u64::MAX - 1, u64::MAX];
        let plans: Vec<_> = divisors
            .iter()
            .map(|&d| RankResidueDivider::new(&moduli, d).unwrap())
            .collect();
        let bound = 1_000_000_000_000_000_000_000_000_000_000i128;
        let mut state = 0x615a_83c9_2ef4_b761u64;
        let (mut positives, mut negatives) = (0, 0);
        for index in 0..10_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let high = state as u128;
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let magnitude = (((high << 64) | state as u128) % bound as u128) as i128;
            let value = if state >> 63 == 0 {
                positives += 1;
                magnitude
            } else {
                negatives += 1;
                -magnitude
            };
            let plan_index = index % plans.len();
            let result = plans[plan_index]
                .divide_floor(&residues(value, &moduli), -bound, bound)
                .unwrap();
            let divisor = divisors[plan_index] as i128;
            assert_eq!(
                result.quotient,
                residues(value.div_euclid(divisor), &moduli)
            );
            assert_eq!(result.remainder, value.rem_euclid(divisor) as u64);
        }
        assert!(positives > 4_000 && negatives > 4_000);
    }

    #[test]
    fn full_width_targets_and_signed_extrema_match_integer_oracle() {
        let moduli = [u64::MAX, u64::MAX - 2, u64::MAX - 4];
        for divisor in [2, 3, 4, 9, u64::MAX - 1, u64::MAX] {
            for value in [
                i128::MIN,
                i128::MIN + 1,
                -9,
                -1,
                0,
                1,
                9,
                i128::MAX - 1,
                i128::MAX,
            ] {
                check(value, i128::MIN, i128::MAX, &moduli, divisor);
            }
        }
    }

    #[test]
    fn fractional_rank_resolves_points_next_to_integer_boundaries() {
        let moduli = [9_223_372_036_854_775_783u64, 9_223_372_036_854_775_643];
        let product = moduli[0] as i128 * moduli[1] as i128;
        for value in [0, 1, 2, product / 2, product - 2, product - 1] {
            for divisor in [2, 9, moduli[0], u64::MAX] {
                check(value, 0, product - 1, &moduli, divisor);
            }
        }
    }

    #[test]
    fn modular_products_above_signed_u128_boundary_do_not_overflow() {
        let modulus = u64::MAX as u128 * u64::MAX as u128;
        assert!(modulus > i128::MAX as u128);
        assert_eq!(mul_mod(modulus - 1, modulus - 1, modulus), 1);
        assert_eq!(mul_mod(modulus - 1, modulus - 2, modulus), 2);
        assert_eq!(add_mod(modulus - 1, modulus - 1, modulus), modulus - 2);
        assert_eq!(signed_mod(i128::MIN, modulus), modulus - (1u128 << 127));
    }

    #[test]
    fn repeated_shared_factor_divisions_preserve_quotient_anchors() {
        let moduli = [3, 5, 7, 11, 13];
        let mut value = -15_000i128;
        let mut lane_values = residues(value, &moduli);
        for divisor in [3, 5, 4, 7, 9, 11, 13] {
            let plan = RankResidueDivider::new(&moduli, divisor).unwrap();
            let result = plan.divide_floor(&lane_values, -15_000, 0).unwrap();
            value = value.div_euclid(divisor as i128);
            lane_values = result.quotient;
            assert_eq!(lane_values, residues(value, &moduli));
        }
    }
}
