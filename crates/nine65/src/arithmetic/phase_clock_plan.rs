//! Exact public geometry for the encrypted phase-clock carry producer.
//!
//! If `S = R0 + sum(Ri*si) = Q*K + g`, `|g| <= V`, and the ternary secret
//! has at most H nonzero coefficients, quantizing each centered public Ri to
//! a 2N-point clock gives `|2*m*rotation - 4*N*K| <= ceil(4*N*V/Q)+m*(H+1)`.
//! Disjoint antipodal windows define a negacyclic LUT for K modulo m (or its
//! parity sign). This plan validates geometry; V and H still need admitted
//! input-history and key-setup producers. It is not a refresh admission token.

use super::rns::{product_limbs_u64, U512};
use crate::params::{is_prime, FHEConfig};

const MAX_CLOCK_N: usize = 1 << 20;
const MAX_COORDINATE: u64 = 1023;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PhaseClockPlanError {
    SourceDegree,
    SourceLevel,
    SourcePlaintext,
    SourceWeight,
    SourcePrime { lane: usize },
    SourceCapacity,
    ClockDegree,
    Coordinate,
    SourceError,
    Window { twice_window: u64, clock_n: usize },
    ConflictingLookup,
    NonCenteredResidual,
}

/// Immutable source-basis-bound carry-clock geometry and signed lookup.
#[derive(Clone, Debug)]
pub struct PhaseClockPlan {
    source_n: usize,
    source_level: usize,
    source_primes: Vec<u64>,
    source_plaintext: u64,
    source_q: U512,
    source_error: U512,
    source_weight: usize,
    clock_n: usize,
    coordinate: u64,
    twice_window: u64,
    values: Vec<i64>,
}

fn words(value: U512) -> (u128, u128, u128, u128) {
    (value.d3, value.d2, value.d1, value.d0)
}

/// Bounded public quotient search. Every caller proves quotient <= upper and
/// intermediates below 2^300 before entering it; no fixed-width product wraps.
fn floor_bounded(numerator: U512, denominator: U512, upper: u64) -> u64 {
    let (mut lo, mut hi) = (0, upper);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if words(denominator.mul_u128(mid as u128)) <= words(numerator) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

impl PhaseClockPlan {
    pub fn new(
        source: &FHEConfig,
        source_level: usize,
        clock_n: usize,
        coordinate: u64,
        source_error_bound: U512,
        source_weight_bound: usize,
    ) -> Result<Self, PhaseClockPlanError> {
        if source.n < 2 || !source.n.is_power_of_two() || source.n > 65_536 {
            return Err(PhaseClockPlanError::SourceDegree);
        }
        if source_level == 0 || source_level > source.primes.len() {
            return Err(PhaseClockPlanError::SourceLevel);
        }
        if source.t < 3 || source.t % 2 == 0 {
            return Err(PhaseClockPlanError::SourcePlaintext);
        }
        if source_weight_bound > source.n {
            return Err(PhaseClockPlanError::SourceWeight);
        }
        if clock_n < 2 || !clock_n.is_power_of_two() || clock_n > MAX_CLOCK_N {
            return Err(PhaseClockPlanError::ClockDegree);
        }
        if !(coordinate == 2 || (coordinate >= 3 && coordinate % 2 == 1))
            || coordinate > MAX_COORDINATE
        {
            return Err(PhaseClockPlanError::Coordinate);
        }
        let primes = &source.primes[..source_level];
        for (lane, &prime) in primes.iter().enumerate() {
            if prime <= source.t
                || prime % 2 == 0
                || !is_prime(prime)
                || (prime - 1) % (2 * source.n as u64) != 0
                || primes[..lane].contains(&prime)
            {
                return Err(PhaseClockPlanError::SourcePrime { lane });
            }
        }
        // Check the exact product BEFORE U512::product_u64s. The <=256-bit
        // bound leaves over 200 guard bits for every geometry intermediate.
        let limbs = product_limbs_u64(primes);
        if limbs.len() > 4 {
            return Err(PhaseClockPlanError::SourceCapacity);
        }
        let source_q = U512::product_u64s(primes);
        if words(source_error_bound) > words(source_q.div_u64(2)) {
            return Err(PhaseClockPlanError::SourceError);
        }
        let size = (2 * clock_n) as u64;
        let numerator = source_error_bound.mul_u128(2 * size as u128);
        let floor = floor_bounded(numerator, source_q, size);
        let phase = floor + u64::from(words(source_q.mul_u128(floor as u128)) < words(numerator));
        // H<=65536, m<=1023 and 2N<=2^21 prove these u64 operations safe.
        let twice_window = phase + coordinate * (source_weight_bound as u64 + 1);
        if twice_window >= clock_n as u64 {
            return Err(PhaseClockPlanError::Window {
                twice_window,
                clock_n,
            });
        }
        let mut values = vec![None; size as usize];
        // Each rotation has at most one nearest m-chart center. Iterating
        // rotations once avoids an m*2N setup cost for large clock degrees.
        for rotation in 0..size {
            let location = coordinate * rotation;
            let nearest = (location + size / 2) / size;
            let distance = location.abs_diff(nearest * size);
            if 2 * distance > twice_window {
                continue;
            }
            let k = nearest % coordinate;
            let output = if coordinate == 2 {
                if k == 0 {
                    1
                } else {
                    -1
                }
            } else if k > coordinate / 2 {
                k as i64 - coordinate as i64
            } else {
                k as i64
            };
            for (index, value) in [
                (rotation as usize, output),
                (((rotation + clock_n as u64) % size) as usize, -output),
            ] {
                if values[index].is_some_and(|previous| previous != value) {
                    return Err(PhaseClockPlanError::ConflictingLookup);
                }
                values[index] = Some(value);
            }
        }
        Ok(Self {
            source_n: source.n,
            source_level,
            source_primes: primes.to_vec(),
            source_plaintext: source.t,
            source_q,
            source_error: source_error_bound,
            source_weight: source_weight_bound,
            clock_n,
            coordinate,
            twice_window,
            values: values.into_iter().map(|value| value.unwrap_or(0)).collect(),
        })
    }

    pub fn source_n(&self) -> usize {
        self.source_n
    }
    pub fn source_level(&self) -> usize {
        self.source_level
    }
    pub fn source_primes(&self) -> &[u64] {
        &self.source_primes
    }
    pub fn source_plaintext(&self) -> u64 {
        self.source_plaintext
    }
    pub fn source_modulus(&self) -> U512 {
        self.source_q
    }
    pub fn source_error_bound(&self) -> U512 {
        self.source_error
    }
    pub fn source_weight_bound(&self) -> usize {
        self.source_weight
    }
    pub fn clock_n(&self) -> usize {
        self.clock_n
    }
    pub fn coordinate(&self) -> u64 {
        self.coordinate
    }
    pub fn twice_window(&self) -> u64 {
        self.twice_window
    }
    pub fn values(&self) -> &[i64] {
        &self.values
    }

    pub fn lookup(&self, rotation: i64) -> i64 {
        self.values[rotation.rem_euclid((2 * self.clock_n) as i64) as usize]
    }

    /// Round 2N*R/(Q*m) to its nearest integer using exact public residuals.
    /// These signed component residuals are public preprocessing outputs;
    /// this method neither observes nor computes a secret-dependent phase.
    pub fn quantize_public_residual(
        &self,
        negative: bool,
        magnitude: U512,
    ) -> Result<i64, PhaseClockPlanError> {
        if words(magnitude) > words(self.source_q.div_u64(2)) {
            return Err(PhaseClockPlanError::NonCenteredResidual);
        }
        let size = (2 * self.clock_n) as u64;
        let denominator = self.source_q.mul_u128(self.coordinate as u128);
        let numerator = magnitude.mul_u128(size as u128).add(denominator.div_u64(2));
        let rotation = floor_bounded(numerator, denominator, size) as i64;
        Ok(if negative { -rotation } else { rotation })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> FHEConfig {
        FHEConfig {
            n: 4,
            primes: vec![17],
            q: 17,
            t: 3,
            eta: 1,
            security_bits: 0,
            name: "phase-clock geometry fixture",
        }
    }

    #[test]
    fn carry_lut_matches_every_small_signed_trit_tuple() {
        let source = fixture();
        let mut checks = 0;
        for m in [2, 3, 7, 9] {
            let plan = PhaseClockPlan::new(&source, 1, 256, m, U512::from_u64(1), 2).unwrap();
            for r0 in -8i64..=8 {
                for r1 in -8i64..=8 {
                    for r2 in -8i64..=8 {
                        for s1 in -1..=1 {
                            for s2 in -1..=1 {
                                let total = r0 + r1 * s1 + r2 * s2;
                                let k = (total + 8).div_euclid(17);
                                if (total - 17 * k).abs() > 1 {
                                    continue;
                                }
                                // Independent scalar rounding, not the plan's quantizer.
                                let round = |r: i64| {
                                    let a = (512 * r.abs() + (17 * m as i64) / 2) / (17 * m as i64);
                                    if r < 0 {
                                        -a
                                    } else {
                                        a
                                    }
                                };
                                let rotation = round(r0) + round(r1) * s1 + round(r2) * s2;
                                let expected = if m == 2 {
                                    if k.rem_euclid(2) == 0 {
                                        1
                                    } else {
                                        -1
                                    }
                                } else {
                                    k
                                };
                                assert_eq!(
                                    plan.lookup(rotation),
                                    expected,
                                    "m={m}, R={r0},{r1},{r2}, s={s1},{s2}"
                                );
                                checks += 1;
                            }
                        }
                    }
                }
            }
            for rotation in 0..512 {
                assert_eq!(plan.lookup(rotation + 256), -plan.lookup(rotation));
            }
            for residual in -8i64..=8 {
                let actual = plan
                    .quantize_public_residual(residual < 0, U512::from_u64(residual.unsigned_abs()))
                    .unwrap();
                let expected = (512 * residual.unsigned_abs() + (17 * m) / 2) / (17 * m);
                assert_eq!(
                    actual,
                    if residual < 0 {
                        -(expected as i64)
                    } else {
                        expected as i64
                    }
                );
            }
        }
        assert!(checks > 20_000);
    }

    #[test]
    fn native_sparse_window_uses_actual_source_product_and_dense_refuses() {
        let mut source = crate::params::SecureConfig::secure_128().into_config();
        let q = U512::product_u64s(&source.primes[..2]);
        let plan = PhaseClockPlan::new(&source, 2, 16_384, 99, q.div_u64(16), 96).unwrap();
        assert_eq!(plan.twice_window(), 13_699);
        assert_eq!(plan.source_modulus(), q);
        // A poisoned scalar snapshot cannot retag the source period.
        source.q = 1;
        let same = PhaseClockPlan::new(&source, 2, 16_384, 99, q.div_u64(16), 96).unwrap();
        assert_eq!(same.values(), plan.values());
        assert!(matches!(
            PhaseClockPlan::new(&source, 2, 8192, 33, q.div_u64(16), 8192),
            Err(PhaseClockPlanError::Window { .. })
        ));
    }

    #[test]
    fn invalid_metadata_and_full_width_noise_fail_before_lookup_allocation() {
        let mut source = fixture();
        let make = |s: &FHEConfig| PhaseClockPlan::new(s, 1, 256, 3, U512::from_u64(1), 2);
        source.primes = vec![15];
        assert!(matches!(
            make(&source),
            Err(PhaseClockPlanError::SourcePrime { .. })
        ));
        source = fixture();
        assert!(matches!(
            PhaseClockPlan::new(&source, 0, 256, 3, U512::zero(), 2),
            Err(PhaseClockPlanError::SourceLevel)
        ));
        assert!(matches!(
            PhaseClockPlan::new(&source, 1, 256, 4, U512::zero(), 2),
            Err(PhaseClockPlanError::Coordinate)
        ));
        assert!(matches!(
            PhaseClockPlan::new(&source, 1, 256, 3, U512::zero(), 5),
            Err(PhaseClockPlanError::SourceWeight)
        ));
        assert!(matches!(
            PhaseClockPlan::new(
                &source,
                1,
                256,
                3,
                U512 {
                    d0: u128::MAX,
                    d1: u128::MAX,
                    d2: u128::MAX,
                    d3: u128::MAX
                },
                2
            ),
            Err(PhaseClockPlanError::SourceError)
        ));
        let plan = make(&source).unwrap();
        assert_eq!(
            plan.quantize_public_residual(false, U512::from_u64(9)),
            Err(PhaseClockPlanError::NonCenteredResidual)
        );
    }

    #[test]
    fn wide_named_modulus_and_product_capacity_are_exact() {
        let mut source = crate::params::SecureConfig::secure_256().into_config();
        let q = U512::product_u64s(&source.primes);
        assert_ne!(q.d1, 0);
        let plan = PhaseClockPlan::new(&source, source.primes.len(), 16_384, 99, q.div_u64(16), 96)
            .unwrap();
        assert_eq!(plan.twice_window(), 13_699);
        assert_eq!(plan.source_modulus(), q);
        // Near the signed endpoint, rounding uses the wide Q rather than a
        // u128 truncation; its answer is independently floor(N/m+1/2).
        let expected = (2 * 16_384 + 99) / (2 * 99);
        assert_eq!(
            plan.quantize_public_residual(false, q.div_u64(2)).unwrap(),
            expected
        );
        assert_eq!(
            plan.quantize_public_residual(true, q.div_u64(2)).unwrap(),
            -expected
        );
        source.primes = vec![
            998_244_353,
            985_661_441,
            754_974_721,
            469_762_049,
            167_772_161,
            1_811_939_329,
            595_591_169,
            645_922_817,
            2_013_265_921,
        ];
        assert!(matches!(
            PhaseClockPlan::new(&source, source.primes.len(), 16_384, 99, U512::zero(), 96),
            Err(PhaseClockPlanError::SourceCapacity)
        ));
    }
}
