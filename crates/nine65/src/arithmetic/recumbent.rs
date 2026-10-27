//! Immutable, bounded residue state and division by an observed main modulus.
//!
//! This is the first executable FHE-recumbent slice. It manages public
//! coefficient residues; it is not an encrypted secret-dependent carry circuit.
//! Public signed interval metadata currently fits `i128`. It does not cover
//! every secure-256 intermediate. All integer coefficient ingestion happens at
//! [`RecumbentCoefficient::from_coefficient`]; arithmetic and division operate
//! directly on residues and analytically propagated bounds.
//!
//! The explicitly named experimental rank-projection method uses global
//! full-width fractional scratch. It does not meet the strict lane-native
//! contract; only the separately implemented provisioned-lane drop avoids
//! that materialization. Neither path supplies the encrypted phase carry.

pub use crate::arithmetic::rank_residue_divider::RankDivisionError;
use crate::arithmetic::rank_residue_divider::RankResidueDivider;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedInterval {
    lower: i128,
    upper: i128,
}

impl SignedInterval {
    pub fn new(lower: i128, upper: i128) -> Result<Self, RecumbentError> {
        if lower > upper {
            return Err(RecumbentError::InvalidInterval);
        }
        Ok(Self { lower, upper })
    }

    pub fn lower(&self) -> i128 {
        self.lower
    }

    pub fn upper(&self) -> i128 {
        self.upper
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecumbentBasis {
    main: Vec<u64>,
    anchor: Vec<u64>,
    /// One precomputed inverse row for each possible main-modulus drop.
    drop_inverses: Vec<DropInverses>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DropInverses {
    main: Vec<u64>,
    anchor: Vec<u64>,
}

impl RecumbentBasis {
    /// Construct and validate an ordered pairwise-coprime basis. Inverses are
    /// computed once here; subsequent coefficient divisions only read them.
    pub fn new(main: Vec<u64>, anchor: Vec<u64>) -> Result<Self, RecumbentError> {
        if main.is_empty() {
            return Err(RecumbentError::EmptyMainBasis);
        }
        if anchor.is_empty() {
            return Err(RecumbentError::EmptyAnchorBasis);
        }
        let all: Vec<_> = main.iter().chain(&anchor).copied().collect();
        for (index, &modulus) in all.iter().enumerate() {
            if modulus <= 1 {
                return Err(RecumbentError::InvalidModulus);
            }
            if all[..index].iter().any(|&prior| gcd(prior, modulus) != 1) {
                return Err(RecumbentError::NotCoprime);
            }
        }
        let mut drop_inverses = Vec::with_capacity(main.len());
        for (index, &divisor) in main.iter().enumerate() {
            drop_inverses.push(DropInverses {
                main: main
                    .iter()
                    .enumerate()
                    .map(|(j, &modulus)| {
                        if j == index {
                            0
                        } else {
                            inverse(divisor, modulus)
                        }
                    })
                    .collect(),
                anchor: anchor
                    .iter()
                    .map(|&modulus| inverse(divisor, modulus))
                    .collect(),
            });
        }
        Ok(Self {
            main,
            anchor,
            drop_inverses,
        })
    }

    pub fn main_moduli(&self) -> &[u64] {
        &self.main
    }

    pub fn anchor_moduli(&self) -> &[u64] {
        &self.anchor
    }

    /// Inclusive intervals are unique exactly when `upper-lower < P`.
    /// If the checked product exceeds u128, it is necessarily greater than
    /// the width of every supported i128-endpoint interval. No truncated or
    /// saturated product is used as capacity evidence.
    fn admit(&self, interval: &SignedInterval) -> Result<(), RecumbentError> {
        let width = interval.upper.abs_diff(interval.lower);
        let product = self
            .main
            .iter()
            .chain(&self.anchor)
            .try_fold(1u128, |product, &modulus| {
                product.checked_mul(modulus as u128)
            });
        match product {
            Some(product) if width >= product => Err(RecumbentError::IntervalAliased),
            _ => Ok(()),
        }
    }

    fn without_main(&self, index: usize) -> Self {
        let main = without_index(&self.main, index);
        let drop_inverses = self
            .drop_inverses
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != index)
            .map(|(_, row)| DropInverses {
                main: without_index(&row.main, index),
                anchor: row.anchor.clone(),
            })
            .collect();
        Self {
            main,
            anchor: self.anchor.clone(),
            drop_inverses,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrimaryLane {
    residues: Vec<u64>,
}

impl PrimaryLane {
    pub fn residues(&self) -> &[u64] {
        &self.residues
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverflowLane {
    residues: Vec<u64>,
}

impl OverflowLane {
    pub fn residues(&self) -> &[u64] {
        &self.residues
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rounding {
    /// Refuse unless the observed remainder is zero.
    Exact,
    /// Quotient is floor(X/d), including negative X.
    Floor,
    /// Nearest integer, with exact half ties toward positive infinity.
    NearestTiesPositive,
}

/// A residue state whose signed lift is bounded by construction.
///
/// Fields are private, and there is deliberately no raw-residue constructor.
/// A public interval assertion alone does not authenticate an arbitrary
/// incoming DualRNS state. Such ingestion needs a separate provenance adapter
/// before this type can replace live BFV rescale paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecumbentCoefficient {
    basis: RecumbentBasis,
    primary: PrimaryLane,
    overflow: OverflowLane,
    interval: SignedInterval,
    /// Maximum division-event depth along the arithmetic DAG. This is neither
    /// the winding magnitude nor the cumulative number of events in all paths.
    division_events: u64,
    /// Debug-only independent provenance oracle, captured at clear ingress.
    /// This detects implementation mistakes; it is not cryptographic custody.
    #[cfg(debug_assertions)]
    debug_value: i128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DivisionOutput {
    pub coefficient: RecumbentCoefficient,
    pub remainder: i128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecumbentError {
    EmptyMainBasis,
    EmptyAnchorBasis,
    InvalidModulus,
    NotCoprime,
    InvalidInterval,
    ValueOutsideInterval,
    IntervalAliased,
    BoundOverflow,
    BasisMismatch,
    InvalidDropIndex,
    LastMainLane,
    NonExact,
    EventCounterExhausted,
    RankProjection(RankDivisionError),
}

impl RecumbentCoefficient {
    /// Trusted ingestion boundary for a clear coefficient that already exists.
    /// The interval is checked here, then propagated analytically by every
    /// operation. This is not a conversion from an unknown residue tuple.
    pub fn from_coefficient(
        value: i128,
        basis: RecumbentBasis,
        interval: SignedInterval,
    ) -> Result<Self, RecumbentError> {
        if value < interval.lower || value > interval.upper {
            return Err(RecumbentError::ValueOutsideInterval);
        }
        basis.admit(&interval)?;
        let primary = PrimaryLane {
            residues: project(value, &basis.main),
        };
        let overflow = OverflowLane {
            residues: project(value, &basis.anchor),
        };
        let result = Self {
            basis,
            primary,
            overflow,
            interval,
            division_events: 0,
            #[cfg(debug_assertions)]
            debug_value: value,
        };
        result.debug_check();
        Ok(result)
    }

    pub fn primary(&self) -> &PrimaryLane {
        &self.primary
    }

    pub fn overflow(&self) -> &OverflowLane {
        &self.overflow
    }

    pub fn basis(&self) -> &RecumbentBasis {
        &self.basis
    }

    pub fn interval(&self) -> &SignedInterval {
        &self.interval
    }

    pub fn division_event_depth(&self) -> u64 {
        self.division_events
    }

    pub fn add(&self, rhs: &Self) -> Result<Self, RecumbentError> {
        self.check_basis(rhs)?;
        let interval = SignedInterval {
            lower: self
                .interval
                .lower
                .checked_add(rhs.interval.lower)
                .ok_or(RecumbentError::BoundOverflow)?,
            upper: self
                .interval
                .upper
                .checked_add(rhs.interval.upper)
                .ok_or(RecumbentError::BoundOverflow)?,
        };
        self.combine(rhs, interval, ArithmeticOperation::Add)
    }

    pub fn sub(&self, rhs: &Self) -> Result<Self, RecumbentError> {
        self.check_basis(rhs)?;
        let interval = SignedInterval {
            lower: self
                .interval
                .lower
                .checked_sub(rhs.interval.upper)
                .ok_or(RecumbentError::BoundOverflow)?,
            upper: self
                .interval
                .upper
                .checked_sub(rhs.interval.lower)
                .ok_or(RecumbentError::BoundOverflow)?,
        };
        self.combine(rhs, interval, ArithmeticOperation::Sub)
    }

    pub fn mul(&self, rhs: &Self) -> Result<Self, RecumbentError> {
        self.check_basis(rhs)?;
        let mut lower = i128::MAX;
        let mut upper = i128::MIN;
        for x in [self.interval.lower, self.interval.upper] {
            for y in [rhs.interval.lower, rhs.interval.upper] {
                let product = x.checked_mul(y).ok_or(RecumbentError::BoundOverflow)?;
                lower = lower.min(product);
                upper = upper.max(product);
            }
        }
        self.combine(
            rhs,
            SignedInterval { lower, upper },
            ArithmeticOperation::Mul,
        )
    }

    /// Experimental division in the complete unchanged basis, including
    /// divisors sharing factors with its moduli.
    ///
    /// This uses a global exact CRT-rank projection. Although no scalar X is
    /// assembled, the full-width fractional scratch carries equivalent
    /// information. Reconstruction is permitted under the clarified policy;
    /// independence and reversibility still require testing the actual
    /// operation and its declared output domain. This is not a live BFV adapter.
    /// [`Self::drop_main`] is the separate provisioned-lane native path.
    pub fn divide_with_rank_projection(
        &self,
        divisor: u64,
        rounding: Rounding,
    ) -> Result<DivisionOutput, RecumbentError> {
        self.debug_check();
        let division_events = self
            .division_events
            .checked_add(1)
            .ok_or(RecumbentError::EventCounterExhausted)?;
        let moduli: Vec<_> = self
            .basis
            .main
            .iter()
            .chain(&self.basis.anchor)
            .copied()
            .collect();
        let residues: Vec<_> = self
            .primary
            .residues
            .iter()
            .chain(&self.overflow.residues)
            .copied()
            .collect();
        let plan =
            RankResidueDivider::new(&moduli, divisor).map_err(RecumbentError::RankProjection)?;
        let mut projected = plan
            .divide_floor(&residues, self.interval.lower, self.interval.upper)
            .map_err(RecumbentError::RankProjection)?;
        if rounding == Rounding::Exact && projected.remainder != 0 {
            return Err(RecumbentError::NonExact);
        }
        let mut remainder = projected.remainder as i128;
        if rounding == Rounding::NearestTiesPositive
            && (projected.remainder as u128) * 2 >= divisor as u128
        {
            remainder -= divisor as i128;
            for (value, &modulus) in projected.quotient.iter_mut().zip(&moduli) {
                *value = addmod(*value, 1, modulus);
            }
        }
        let interval = SignedInterval {
            lower: quotient_bound(self.interval.lower, divisor, rounding),
            upper: quotient_bound(self.interval.upper, divisor, rounding),
        };
        self.basis.admit(&interval)?;
        let anchor = projected.quotient.split_off(self.basis.main.len());
        let output = DivisionOutput {
            coefficient: Self {
                basis: self.basis.clone(),
                primary: PrimaryLane {
                    residues: projected.quotient,
                },
                overflow: OverflowLane { residues: anchor },
                interval,
                division_events,
                #[cfg(debug_assertions)]
                debug_value: quotient_bound(self.debug_value, divisor, rounding),
            },
            remainder,
        };
        output.coefficient.debug_check();
        Ok(output)
    }

    /// Divide by a main modulus whose remainder is directly observed in its
    /// existing lane, and remove that lane. Every surviving main *and anchor*
    /// residue is `(x_i-remainder) * inverse(d) mod m_i`.
    ///
    /// For nearest rounding the observed remainder is centered first, so the
    /// quotient correction is exact even for negative values. A missing
    /// divisor/remainder lane cannot use this API. It does not implement
    /// arbitrary Delta division or encrypted phase-carry evaluation.
    pub fn drop_main(
        &self,
        index: usize,
        rounding: Rounding,
    ) -> Result<DivisionOutput, RecumbentError> {
        self.debug_check();
        let &divisor = self
            .basis
            .main
            .get(index)
            .ok_or(RecumbentError::InvalidDropIndex)?;
        if self.basis.main.len() == 1 {
            return Err(RecumbentError::LastMainLane);
        }
        let observed = self.primary.residues[index];
        if rounding == Rounding::Exact && observed != 0 {
            return Err(RecumbentError::NonExact);
        }
        let mut remainder = observed as i128;
        if rounding == Rounding::NearestTiesPositive && (observed as u128) * 2 >= divisor as u128 {
            remainder -= divisor as i128;
        }
        let division_events = self
            .division_events
            .checked_add(1)
            .ok_or(RecumbentError::EventCounterExhausted)?;
        let interval = SignedInterval {
            lower: quotient_bound(self.interval.lower, divisor, rounding),
            upper: quotient_bound(self.interval.upper, divisor, rounding),
        };
        let basis = self.basis.without_main(index);
        basis.admit(&interval)?;
        let inverses = &self.basis.drop_inverses[index];
        let mut main = Vec::with_capacity(basis.main.len());
        for (i, (&modulus, &value)) in self
            .basis
            .main
            .iter()
            .zip(&self.primary.residues)
            .enumerate()
        {
            if i != index {
                let residue = remainder.rem_euclid(modulus as i128) as u64;
                main.push(mulmod(
                    submod(value, residue, modulus),
                    inverses.main[i],
                    modulus,
                ));
            }
        }
        let anchor = self
            .basis
            .anchor
            .iter()
            .zip(&self.overflow.residues)
            .zip(&inverses.anchor)
            .map(|((&modulus, &value), &inverse)| {
                let residue = remainder.rem_euclid(modulus as i128) as u64;
                mulmod(submod(value, residue, modulus), inverse, modulus)
            })
            .collect();
        let result = DivisionOutput {
            coefficient: Self {
                basis,
                primary: PrimaryLane { residues: main },
                overflow: OverflowLane { residues: anchor },
                interval,
                division_events,
                #[cfg(debug_assertions)]
                debug_value: quotient_bound(self.debug_value, divisor, rounding),
            },
            remainder,
        };
        result.coefficient.debug_check();
        Ok(result)
    }

    fn check_basis(&self, rhs: &Self) -> Result<(), RecumbentError> {
        self.debug_check();
        rhs.debug_check();
        if self.basis == rhs.basis {
            Ok(())
        } else {
            Err(RecumbentError::BasisMismatch)
        }
    }

    fn combine(
        &self,
        rhs: &Self,
        interval: SignedInterval,
        operation: ArithmeticOperation,
    ) -> Result<Self, RecumbentError> {
        self.basis.admit(&interval)?;
        let combine_lanes = |left: &[u64], right: &[u64], moduli: &[u64]| {
            left.iter()
                .zip(right)
                .zip(moduli)
                .map(|((&x, &y), &modulus)| operation.apply(x, y, modulus))
                .collect()
        };
        #[cfg(debug_assertions)]
        let debug_value = match operation {
            ArithmeticOperation::Add => self.debug_value.checked_add(rhs.debug_value),
            ArithmeticOperation::Sub => self.debug_value.checked_sub(rhs.debug_value),
            ArithmeticOperation::Mul => self.debug_value.checked_mul(rhs.debug_value),
        }
        .ok_or(RecumbentError::BoundOverflow)?;
        let result = Self {
            basis: self.basis.clone(),
            primary: PrimaryLane {
                residues: combine_lanes(
                    &self.primary.residues,
                    &rhs.primary.residues,
                    &self.basis.main,
                ),
            },
            overflow: OverflowLane {
                residues: combine_lanes(
                    &self.overflow.residues,
                    &rhs.overflow.residues,
                    &self.basis.anchor,
                ),
            },
            interval,
            division_events: self.division_events.max(rhs.division_events),
            #[cfg(debug_assertions)]
            debug_value,
        };
        result.debug_check();
        Ok(result)
    }

    /// This oracle never exists in release and is never created by decoding
    /// a residue state. It is propagated independently from already-clear
    /// ingress so debug builds check authentic signed anchor projections.
    fn debug_check(&self) {
        #[cfg(debug_assertions)]
        {
            debug_assert!(self.interval.lower <= self.debug_value);
            debug_assert!(self.debug_value <= self.interval.upper);
            debug_assert_eq!(self.primary.residues.len(), self.basis.main.len());
            debug_assert_eq!(self.overflow.residues.len(), self.basis.anchor.len());
            for (&modulus, &residue) in self.basis.main.iter().zip(&self.primary.residues) {
                debug_assert_eq!(
                    residue,
                    self.debug_value.rem_euclid(modulus as i128) as u64,
                    "main residue provenance mismatch"
                );
            }
            for (&modulus, &residue) in self.basis.anchor.iter().zip(&self.overflow.residues) {
                debug_assert_eq!(
                    residue,
                    self.debug_value.rem_euclid(modulus as i128) as u64,
                    "anchor residue provenance mismatch"
                );
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ArithmeticOperation {
    Add,
    Sub,
    Mul,
}

impl ArithmeticOperation {
    fn apply(self, x: u64, y: u64, modulus: u64) -> u64 {
        match self {
            Self::Add => addmod(x, y, modulus),
            Self::Sub => submod(x, y, modulus),
            Self::Mul => mulmod(x, y, modulus),
        }
    }
}

fn without_index<T: Clone>(values: &[T], index: usize) -> Vec<T> {
    values
        .iter()
        .enumerate()
        .filter(|&(i, _)| i != index)
        .map(|(_, value)| value.clone())
        .collect()
}

fn project(value: i128, moduli: &[u64]) -> Vec<u64> {
    moduli
        .iter()
        .map(|&modulus| value.rem_euclid(modulus as i128) as u64)
        .collect()
}

fn quotient_bound(value: i128, divisor: u64, rounding: Rounding) -> i128 {
    let divisor = divisor as i128;
    let floor = value.div_euclid(divisor);
    if rounding == Rounding::NearestTiesPositive && value.rem_euclid(divisor) * 2 >= divisor {
        floor + 1
    } else {
        floor
    }
}

fn addmod(x: u64, y: u64, modulus: u64) -> u64 {
    ((x as u128 + y as u128) % modulus as u128) as u64
}

fn submod(x: u64, y: u64, modulus: u64) -> u64 {
    ((x as u128 + modulus as u128 - y as u128) % modulus as u128) as u64
}

fn mulmod(x: u64, y: u64, modulus: u64) -> u64 {
    ((x as u128 * y as u128) % modulus as u128) as u64
}

fn gcd(mut x: u64, mut y: u64) -> u64 {
    while y != 0 {
        (x, y) = (y, x % y);
    }
    x
}

/// Construction-only Euclidean inversion, with coefficients kept modulo m so
/// the full u64 modulus range never requires signed extended-GCD products.
fn inverse(value: u64, modulus: u64) -> u64 {
    let (mut r, mut next_r) = (modulus, value % modulus);
    let (mut t, mut next_t) = (0, 1);
    while next_r != 0 {
        let quotient = r / next_r;
        (r, next_r) = (next_r, r % next_r);
        (t, next_t) = (
            next_t,
            submod(t, mulmod(quotient, next_t, modulus), modulus),
        );
    }
    debug_assert_eq!(r, 1);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basis() -> RecumbentBasis {
        RecumbentBasis::new(vec![3, 5, 7], vec![11, 13]).unwrap()
    }

    fn coefficient(value: i128) -> RecumbentCoefficient {
        RecumbentCoefficient::from_coefficient(
            value,
            basis(),
            SignedInterval::new(value, value).unwrap(),
        )
        .unwrap()
    }

    fn assert_residues(state: &RecumbentCoefficient, value: i128) {
        for (&modulus, &residue) in state.basis.main.iter().zip(&state.primary.residues) {
            assert_eq!(residue, value.rem_euclid(modulus as i128) as u64);
        }
        for (&modulus, &residue) in state.basis.anchor.iter().zip(&state.overflow.residues) {
            assert_eq!(residue, value.rem_euclid(modulus as i128) as u64);
        }
        assert!(state.interval.lower <= value && value <= state.interval.upper);
    }

    #[test]
    fn signed_ingress_and_arithmetic_match_scalar_oracle() {
        for x in -18..=18 {
            for y in -18..=18 {
                let lhs = coefficient(x);
                let rhs = coefficient(y);
                assert_residues(&lhs.add(&rhs).unwrap(), x + y);
                assert_residues(&lhs.sub(&rhs).unwrap(), x - y);
                assert_residues(&lhs.mul(&rhs).unwrap(), x * y);
            }
        }
    }

    #[test]
    fn observed_remainder_division_matches_ten_thousand_independent_oracles() {
        let mut random = 0x4e49_4e45_3635_u64;
        for _ in 0..10_000 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let x = (random % 20_001) as i128 - 10_000;
            let index = (random.rotate_left(17) % 3) as usize;
            let input = coefficient(x);
            let divisor = input.basis.main[index] as i128;
            let floor_q = x.div_euclid(divisor);
            let floor_r = x.rem_euclid(divisor);
            let nearest_q = floor_q + i128::from(2 * floor_r >= divisor);

            let floor = input.drop_main(index, Rounding::Floor).unwrap();
            assert_residues(&floor.coefficient, floor_q);
            assert_eq!(x, divisor * floor_q + floor.remainder);
            assert!(floor.remainder >= 0 && floor.remainder < divisor);

            let nearest = input
                .drop_main(index, Rounding::NearestTiesPositive)
                .unwrap();
            assert_residues(&nearest.coefficient, nearest_q);
            assert_eq!(x, divisor * nearest_q + nearest.remainder);
            assert!(2 * nearest.remainder.abs() <= divisor);
            assert_eq!(nearest.coefficient.division_events, 1);

            let exact = input.drop_main(index, Rounding::Exact);
            if floor_r == 0 {
                assert_residues(&exact.unwrap().coefficient, floor_q);
            } else {
                assert_eq!(exact.unwrap_err(), RecumbentError::NonExact);
            }
        }
    }

    #[test]
    fn negative_rounding_and_even_ties_have_declared_semantics() {
        let basis = RecumbentBasis::new(vec![2, 3], vec![5]).unwrap();
        for (x, floor, nearest) in [(-7, -4, -3), (-5, -3, -2), (5, 2, 3)] {
            let state = RecumbentCoefficient::from_coefficient(
                x,
                basis.clone(),
                SignedInterval::new(x, x).unwrap(),
            )
            .unwrap();
            assert_residues(
                &state.drop_main(0, Rounding::Floor).unwrap().coefficient,
                floor,
            );
            assert_residues(
                &state
                    .drop_main(0, Rounding::NearestTiesPositive)
                    .unwrap()
                    .coefficient,
                nearest,
            );
        }
    }

    #[test]
    fn retained_anchor_residues_name_the_signed_quotient() {
        let state = coefficient(-100);
        let output = state.drop_main(1, Rounding::Exact).unwrap();
        assert_residues(&output.coefficient, -20);
        assert_eq!(output.coefficient.overflow.residues, vec![2, 6]);
    }

    #[test]
    fn repeated_division_preserves_signed_value_and_event_depth() {
        let first = coefficient(-630).drop_main(0, Rounding::Exact).unwrap();
        let second = first.coefficient.drop_main(0, Rounding::Exact).unwrap();
        assert_residues(&second.coefficient, -42);
        assert_eq!(second.coefficient.division_events, 2);
        assert_eq!(second.coefficient.basis.main, vec![7]);
        assert_eq!(
            second
                .coefficient
                .drop_main(0, Rounding::Exact)
                .unwrap_err(),
            RecumbentError::LastMainLane
        );
    }

    #[test]
    fn aliasing_intervals_and_unproven_values_are_refused_at_ingress() {
        assert_eq!(
            RecumbentCoefficient::from_coefficient(
                0,
                basis(),
                SignedInterval::new(0, 15_015).unwrap()
            )
            .unwrap_err(),
            RecumbentError::IntervalAliased
        );
        assert_eq!(
            RecumbentCoefficient::from_coefficient(
                15_015,
                basis(),
                SignedInterval::new(0, 10).unwrap()
            )
            .unwrap_err(),
            RecumbentError::ValueOutsideInterval
        );
        assert_eq!(
            SignedInterval::new(1, 0),
            Err(RecumbentError::InvalidInterval)
        );
    }

    #[test]
    fn analytic_bounds_propagate_and_fail_closed_before_capacity_aliases() {
        let state = RecumbentCoefficient::from_coefficient(
            -100,
            basis(),
            SignedInterval::new(-100, 100).unwrap(),
        )
        .unwrap();
        let sum = state.add(&state).unwrap();
        assert_eq!(sum.interval, SignedInterval::new(-200, 200).unwrap());
        assert_eq!(
            state.mul(&state).unwrap_err(),
            RecumbentError::IntervalAliased
        );
    }

    #[test]
    fn invalid_bases_mismatches_and_invalid_drop_are_refused() {
        assert_eq!(
            RecumbentBasis::new(vec![], vec![5]),
            Err(RecumbentError::EmptyMainBasis)
        );
        assert_eq!(
            RecumbentBasis::new(vec![3], vec![]),
            Err(RecumbentError::EmptyAnchorBasis)
        );
        assert_eq!(
            RecumbentBasis::new(vec![1, 3], vec![5]),
            Err(RecumbentError::InvalidModulus)
        );
        assert_eq!(
            RecumbentBasis::new(vec![3, 5], vec![15]),
            Err(RecumbentError::NotCoprime)
        );
        let lhs = coefficient(0);
        let rhs = lhs.drop_main(0, Rounding::Exact).unwrap().coefficient;
        assert_eq!(lhs.add(&rhs).unwrap_err(), RecumbentError::BasisMismatch);
        assert_eq!(
            lhs.drop_main(3, Rounding::Floor).unwrap_err(),
            RecumbentError::InvalidDropIndex
        );
    }

    #[test]
    fn division_event_exhaustion_refuses_without_mutating_input() {
        let mut state = coefficient(105);
        state.division_events = u64::MAX;
        assert_eq!(
            state.drop_main(0, Rounding::Exact).unwrap_err(),
            RecumbentError::EventCounterExhausted
        );
        assert_eq!(state.division_events, u64::MAX);
        assert_residues(&state, 105);
    }

    #[test]
    fn public_bound_overflow_refuses_before_residue_arithmetic() {
        let input = coefficient(i128::MAX);
        assert_eq!(
            input.add(&coefficient(1)).unwrap_err(),
            RecumbentError::BoundOverflow
        );
        assert_eq!(
            input.mul(&coefficient(2)).unwrap_err(),
            RecumbentError::BoundOverflow
        );
    }

    #[test]
    fn inclusive_capacity_boundary_and_rounded_output_capacity_are_checked() {
        let basis = RecumbentBasis::new(vec![3, 5], vec![7]).unwrap();
        let state = RecumbentCoefficient::from_coefficient(
            -52,
            basis,
            SignedInterval::new(-52, 52).unwrap(),
        )
        .unwrap();
        // The input has exactly 105 possible integer lifts; it is unique.
        // Floor division spans [-18,17], whose endpoints alias modulo35.
        assert_eq!(
            state.drop_main(0, Rounding::Floor).unwrap_err(),
            RecumbentError::IntervalAliased
        );
        let rounded = state.drop_main(0, Rounding::NearestTiesPositive).unwrap();
        assert_eq!(
            rounded.coefficient.interval,
            SignedInterval::new(-17, 17).unwrap()
        );
        assert_residues(&rounded.coefficient, -17);
    }

    #[test]
    fn full_u64_moduli_and_full_i128_interval_have_no_sentinel_or_signed_overflow() {
        let basis = RecumbentBasis::new(
            vec![18_446_744_073_709_551_557, 18_446_744_073_709_551_533],
            vec![18_446_744_073_709_551_521],
        )
        .unwrap();
        for value in [i128::MIN, -1, 0, 1, i128::MAX] {
            let input = RecumbentCoefficient::from_coefficient(
                value,
                basis.clone(),
                SignedInterval::new(i128::MIN, i128::MAX).unwrap(),
            )
            .unwrap();
            let d = input.basis.main[0] as i128;
            let q = value.div_euclid(d);
            let output = input.drop_main(0, Rounding::Floor).unwrap();
            assert_residues(&output.coefficient, q);
            assert_eq!(output.remainder, value.rem_euclid(d));
        }
    }

    #[test]
    fn arithmetic_dag_joins_keep_maximum_division_event_depth() {
        let shallow = coefficient(105)
            .drop_main(0, Rounding::Exact)
            .unwrap()
            .coefficient;
        let deep_basis = RecumbentBasis::new(vec![2, 3, 5, 7], vec![11, 13]).unwrap();
        let deep = RecumbentCoefficient::from_coefficient(
            210,
            deep_basis,
            SignedInterval::new(210, 210).unwrap(),
        )
        .unwrap()
        .drop_main(0, Rounding::Exact)
        .unwrap()
        .coefficient
        .drop_main(0, Rounding::Exact)
        .unwrap()
        .coefficient;
        assert_eq!(shallow.division_events, 1);
        assert_eq!(deep.division_events, 2);
        let joined = shallow.add(&deep).unwrap();
        assert_eq!(joined.division_events, 2);
        assert_residues(&joined, 70);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "anchor residue provenance mismatch")]
    fn debug_provenance_oracle_detects_internal_anchor_corruption() {
        let mut state = coefficient(-100);
        state.overflow.residues[0] = 0;
        let _ = state.drop_main(0, Rounding::Floor);
    }

    #[test]
    fn experimental_rank_projection_matches_ten_thousand_broad_interval_oracles() {
        let divisors = [1, 2, 4, 9, 46, 105, 1009, 15_015, u64::MAX];
        let mut random = 0x4352_414d_5241_4e4b_u64;
        for i in 0..10_000 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let x = (random % 2001) as i128 - 1000;
            let d = divisors[i % divisors.len()];
            let input = RecumbentCoefficient::from_coefficient(
                x,
                basis(),
                SignedInterval::new(-1000, 1000).unwrap(),
            )
            .unwrap();
            let floor_q = x.div_euclid(d as i128);
            let floor_r = x.rem_euclid(d as i128);
            let nearest_q = floor_q + i128::from(2 * floor_r >= d as i128);
            let floor = input
                .divide_with_rank_projection(d, Rounding::Floor)
                .unwrap();
            assert_residues(&floor.coefficient, floor_q);
            assert_eq!(floor.coefficient.basis, input.basis);
            assert_eq!(x, d as i128 * floor_q + floor.remainder);
            assert_eq!(floor.coefficient.division_events, 1);
            let nearest = input
                .divide_with_rank_projection(d, Rounding::NearestTiesPositive)
                .unwrap();
            assert_residues(&nearest.coefficient, nearest_q);
            assert_eq!(x, d as i128 * nearest_q + nearest.remainder);
            let exact = input.divide_with_rank_projection(d, Rounding::Exact);
            if floor_r == 0 {
                assert_residues(&exact.unwrap().coefficient, floor_q);
            } else {
                assert_eq!(exact.unwrap_err(), RecumbentError::NonExact);
            }
        }
    }

    #[test]
    fn experimental_projection_retains_shared_factor_anchors_and_division_history() {
        let state = coefficient(-360);
        let first = state
            .divide_with_rank_projection(4, Rounding::Exact)
            .unwrap();
        let second = first
            .coefficient
            .divide_with_rank_projection(9, Rounding::Exact)
            .unwrap();
        assert_residues(&second.coefficient, -10);
        assert_eq!(second.coefficient.basis, state.basis);
        assert_eq!(second.coefficient.division_events, 2);
        assert_eq!(
            state
                .divide_with_rank_projection(0, Rounding::Floor)
                .unwrap_err(),
            RecumbentError::RankProjection(RankDivisionError::ZeroDivisor)
        );
        let mut exhausted = state;
        exhausted.division_events = u64::MAX;
        assert_eq!(
            exhausted
                .divide_with_rank_projection(4, Rounding::Exact)
                .unwrap_err(),
            RecumbentError::EventCounterExhausted
        );
    }
}
