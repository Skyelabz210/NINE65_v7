//! Producer-bound, bounded adjacent-frame queries and public information planning.
//!
//! This is a clear residue runtime, not an encrypted observation producer. The
//! declared ingress accepts an integer once; live state keeps only residues,
//! public interval bounds and local source/frame/epoch authority. Bounds are
//! fixed by a producer's public ingress profile and propagated conservatively.
//! No source integer or winding is retained or reconstructed during execution.
//! Query results are explicit output projections, and temporary winding readouts
//! are discarded with the call. Local sealed types are not remote attestation.

use crate::gcd;
use core::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
/// Default public admission budget for the clear repeated-subtraction route.
pub const DEFAULT_MAX_QUOTIENT_STEPS: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryError {
    InvalidModulus,
    InvalidDivisor,
    InvalidFrame,
    CapacityExceeded,
    InputOutsideProfile,
    ArithmeticOverflow,
    IdentityExhausted,
    FrameMismatch,
    SourceMismatch,
    StaleEpoch,
    DuplicateProducer,
    InvalidCost,
    TooManyCandidates,
    UnavailableObservation,
    WorkBudgetExceeded,
}

fn issue_id() -> Result<u64, QueryError> {
    NEXT_ID
        .fetch_update(AtomicOrdering::Relaxed, AtomicOrdering::Relaxed, |id| {
            id.checked_add(1)
        })
        .map_err(|_| QueryError::IdentityExhausted)
}

/// An integer query with Euclidean unsigned source semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuerySpec {
    LinearResidue {
        coefficient: i64,
        offset: i64,
        modulus: u64,
    },
    FloorQuotient {
        divisor: u64,
        modulus: u64,
        negate: bool,
    },
}

impl QuerySpec {
    fn modulus(self) -> Result<u64, QueryError> {
        let modulus = match self {
            Self::LinearResidue { modulus, .. } => modulus,
            Self::FloorQuotient {
                divisor, modulus, ..
            } => {
                if divisor == 0 {
                    return Err(QueryError::InvalidDivisor);
                }
                modulus
            }
        };
        if modulus == 0 {
            return Err(QueryError::InvalidModulus);
        }
        Ok(modulus)
    }

    /// Least positive period on all integers. A bounded runtime may need less
    /// information because its separate interval certificate selects a lift.
    pub fn period(self) -> Result<u64, QueryError> {
        let modulus = self.modulus()?;
        match self {
            Self::LinearResidue { coefficient, .. } => {
                Ok(modulus / gcd(coefficient.unsigned_abs(), modulus))
            }
            Self::FloorQuotient { divisor, .. } => {
                if modulus == 1 {
                    Ok(1)
                } else {
                    divisor
                        .checked_mul(modulus)
                        .ok_or(QueryError::ArithmeticOverflow)
                }
            }
        }
    }
}

/// Public information requirement only: this does not issue new readings or
/// prove a producer exists. All arithmetic is checked u64 metadata arithmetic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DemandPlan {
    pub observed_period: u64,
    pub required_period: u64,
    pub least_extra_anchor: u64,
}

fn lcm_checked(a: u64, b: u64) -> Result<u64, QueryError> {
    (a / gcd(a, b))
        .checked_mul(b)
        .ok_or(QueryError::ArithmeticOverflow)
}

fn period_of(moduli: &[u64]) -> Result<u64, QueryError> {
    moduli.iter().try_fold(1, |period, &modulus| {
        if modulus == 0 {
            return Err(QueryError::InvalidModulus);
        }
        lcm_checked(period, modulus)
    })
}

/// Factorization-free saturation of exactly the deficient prime supports.
pub fn plan_demands(moduli: &[u64], queries: &[QuerySpec]) -> Result<DemandPlan, QueryError> {
    let observed_period = period_of(moduli)?;
    let required_period = queries
        .iter()
        .try_fold(1, |period, query| lcm_checked(period, query.period()?))?;
    let mut anchor = required_period / gcd(required_period, observed_period);
    loop {
        // Reducing the u128 square before gcd preserves the gcd and cannot
        // overflow: every u64 square fits in u128.
        let square = (anchor as u128 * anchor as u128) % required_period as u128;
        let next = gcd(required_period, square as u64);
        if next == anchor {
            break;
        }
        anchor = next;
    }
    Ok(DemandPlan {
        observed_period,
        required_period,
        least_extra_anchor: anchor,
    })
}

/// A registered *available producer capability*, not an already-issued reading.
/// Names, moduli and costs are public. No source state is accepted by this API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProducerCandidate {
    pub id: u64,
    pub modulus: u64,
    pub cost: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducerSelection {
    pub ids: Vec<u64>,
    pub total_cost: u64,
    pub combined_period: u64,
}

/// Exact public-cost subset planner, with <=16 candidates. Ties use producer
/// count, then sorted IDs. Work is O(n*s) state transitions, not O(1). The
/// complete offered catalog's period and summed cost must fit u64; oversized
/// catalogs are refused before optimization, even if a smaller subset fits.
pub fn select_producers(
    moduli: &[u64],
    queries: &[QuerySpec],
    candidates: &[ProducerCandidate],
) -> Result<ProducerSelection, QueryError> {
    if candidates.len() > 16 {
        return Err(QueryError::TooManyCandidates);
    }
    let plan = plan_demands(moduli, queries)?;
    let mut ordered = candidates.to_vec();
    ordered.sort_by_key(|c| c.id);
    for (i, c) in ordered.iter().enumerate() {
        if c.modulus == 0 {
            return Err(QueryError::InvalidModulus);
        }
        if c.cost == 0 {
            return Err(QueryError::InvalidCost);
        }
        if i > 0 && ordered[i - 1].id == c.id {
            return Err(QueryError::DuplicateProducer);
        }
    }
    ordered
        .iter()
        .try_fold(plan.observed_period, |p, c| lcm_checked(p, c.modulus))?;
    ordered.iter().try_fold(0u64, |cost, c| {
        cost.checked_add(c.cost)
            .ok_or(QueryError::ArithmeticOverflow)
    })?;
    let mut states = BTreeMap::from([(
        gcd(plan.observed_period, plan.required_period),
        (0u64, Vec::<u64>::new()),
    )]);
    for candidate in &ordered {
        for (coverage, (cost, ids)) in states.clone() {
            let next = lcm_checked(coverage, gcd(candidate.modulus, plan.required_period))?;
            let cost = cost
                .checked_add(candidate.cost)
                .ok_or(QueryError::ArithmeticOverflow)?;
            let mut ids = ids;
            ids.push(candidate.id);
            let improves = states
                .get(&next)
                .map(|(old_cost, old_ids)| {
                    (cost, ids.len(), &ids) < (*old_cost, old_ids.len(), old_ids)
                })
                .unwrap_or(true);
            if improves {
                states.insert(next, (cost, ids));
            }
        }
    }
    let (total_cost, ids) = states
        .remove(&plan.required_period)
        .ok_or(QueryError::UnavailableObservation)?;
    let combined_period = ordered
        .iter()
        .filter(|c| ids.contains(&c.id))
        .try_fold(plan.observed_period, |p, c| lcm_checked(p, c.modulus))?;
    Ok(ProducerSelection {
        ids,
        total_cost,
        combined_period,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Binding {
    frame: u64,
    source: u64,
    epoch: u64,
}

/// Opaque live state. Deliberately not Clone and has no raw-residue constructor.
/// Debug prints public metadata only, not residue contents.
pub struct SourceState {
    binding: Binding,
    main_residue: u64,
    anchor_residue: u64,
    upper: u64,
}

impl core::fmt::Debug for SourceState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SourceState")
            .field("binding", &self.binding)
            .field("public_upper", &self.upper)
            .finish_non_exhaustive()
    }
}

impl SourceState {
    pub fn public_upper(&self) -> u64 {
        self.upper
    }
    pub fn epoch(&self) -> u64 {
        self.binding.epoch
    }
}

/// Borrowed producer-issued authority; cannot combine lanes from two states.
pub struct Observation<'a> {
    state: &'a SourceState,
    producer: &'a AdjacentProducer,
}

/// A source-specific plan. Reusing it after a source update is refused even
/// when the new residues happen to equal the old residues.
#[derive(Debug)]
pub struct QueryPlan {
    binding: Binding,
    spec: QuerySpec,
    quotient_step_bound: u64,
}

impl QueryPlan {
    pub fn quotient_step_bound(&self) -> u64 {
        self.quotient_step_bound
    }
}

/// Counts the modular helper calls actually made by a query. Public setup,
/// division/comparison instructions, bit cost and ingress are separate costs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QueryCost {
    pub modular_additions: u128,
    pub modular_subtractions: u128,
    pub modular_multiplications: u128,
    pub winding_readouts: u128,
    pub integer_comparisons: u128,
    pub loop_iterations: u128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryOutput {
    /// The explicitly requested output residue, not persistent source state.
    pub residue: u64,
    pub cost: QueryCost,
}

pub struct AdjacentProducer {
    frame: u64,
    main: u64,
    anchor: u64,
    capacity: u64,
    ingress_upper: u64,
}

impl AdjacentProducer {
    /// The ingress profile must be chosen from public workload requirements.
    /// Every ingress under this producer receives the same bound; no API
    /// shrinks a bound based on the input or subsequently derived magnitude.
    pub fn new(main: u64, ingress_upper: u64) -> Result<Self, QueryError> {
        if main < 2 {
            return Err(QueryError::InvalidFrame);
        }
        let anchor = main.checked_add(1).ok_or(QueryError::ArithmeticOverflow)?;
        let capacity = main
            .checked_mul(anchor)
            .ok_or(QueryError::ArithmeticOverflow)?;
        if ingress_upper >= capacity {
            return Err(QueryError::CapacityExceeded);
        }
        Ok(Self {
            frame: issue_id()?,
            main,
            anchor,
            capacity,
            ingress_upper,
        })
    }

    pub fn frame_36_37(ingress_upper: u64) -> Result<Self, QueryError> {
        Self::new(36, ingress_upper)
    }

    pub fn moduli(&self) -> [u64; 2] {
        [self.main, self.anchor]
    }
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Declared integer ingress. The input is reduced immediately and is never
    /// retained in the resulting state. No interpretation of arbitrary raw
    /// residues or ciphertext components is performed here.
    pub fn ingress(&self, value: u64) -> Result<SourceState, QueryError> {
        if value > self.ingress_upper {
            return Err(QueryError::InputOutsideProfile);
        }
        Ok(SourceState {
            binding: Binding {
                frame: self.frame,
                source: issue_id()?,
                epoch: 0,
            },
            main_residue: value % self.main,
            anchor_residue: value % self.anchor,
            upper: self.ingress_upper,
        })
    }

    pub fn observe<'a>(&'a self, state: &'a SourceState) -> Result<Observation<'a>, QueryError> {
        self.check_frame(state)?;
        Ok(Observation {
            state,
            producer: self,
        })
    }

    fn check_frame(&self, state: &SourceState) -> Result<(), QueryError> {
        if state.binding.frame != self.frame {
            return Err(QueryError::FrameMismatch);
        }
        Ok(())
    }

    pub fn add_assign(
        &self,
        left: &mut SourceState,
        right: &SourceState,
    ) -> Result<(), QueryError> {
        self.update(left, right, false)
    }

    pub fn multiply_assign(
        &self,
        left: &mut SourceState,
        right: &SourceState,
    ) -> Result<(), QueryError> {
        self.update(left, right, true)
    }

    /// Native self-product without cloning a source identity or re-ingress.
    pub fn square_assign(&self, state: &mut SourceState) -> Result<(), QueryError> {
        self.check_frame(state)?;
        let upper = state
            .upper
            .checked_mul(state.upper)
            .ok_or(QueryError::ArithmeticOverflow)?;
        if upper >= self.capacity {
            return Err(QueryError::CapacityExceeded);
        }
        let epoch = state
            .binding
            .epoch
            .checked_add(1)
            .ok_or(QueryError::IdentityExhausted)?;
        state.main_residue =
            (state.main_residue as u128 * state.main_residue as u128 % self.main as u128) as u64;
        state.anchor_residue = (state.anchor_residue as u128 * state.anchor_residue as u128
            % self.anchor as u128) as u64;
        state.upper = upper;
        state.binding.epoch = epoch;
        Ok(())
    }

    fn update(
        &self,
        left: &mut SourceState,
        right: &SourceState,
        multiply: bool,
    ) -> Result<(), QueryError> {
        self.check_frame(left)?;
        self.check_frame(right)?;
        let upper = if multiply {
            left.upper.checked_mul(right.upper)
        } else {
            left.upper.checked_add(right.upper)
        }
        .ok_or(QueryError::ArithmeticOverflow)?;
        if upper >= self.capacity {
            return Err(QueryError::CapacityExceeded);
        }
        let epoch = left
            .binding
            .epoch
            .checked_add(1)
            .ok_or(QueryError::IdentityExhausted)?;
        // All admission checks precede mutation. Each lane sees only its own
        // operand residues; no magnitude query is required by these updates.
        let lane = |a: u64, b: u64, m: u64| -> u64 {
            let raw = if multiply {
                a as u128 * b as u128
            } else {
                a as u128 + b as u128
            };
            (raw % m as u128) as u64
        };
        left.main_residue = lane(left.main_residue, right.main_residue, self.main);
        left.anchor_residue = lane(left.anchor_residue, right.anchor_residue, self.anchor);
        left.upper = upper;
        left.binding.epoch = epoch;
        Ok(())
    }
}

fn add_mod(a: u64, b: u64, m: u64, cost: &mut QueryCost) -> u64 {
    cost.modular_additions += 1;
    ((a as u128 + b as u128) % m as u128) as u64
}

fn sub_mod(a: u64, b: u64, m: u64, cost: &mut QueryCost) -> u64 {
    cost.modular_subtractions += 1;
    ((a as u128 + m as u128 - b as u128) % m as u128) as u64
}

fn mul_mod(a: u64, b: u64, m: u64, cost: &mut QueryCost) -> u64 {
    cost.modular_multiplications += 1;
    ((a as u128 * b as u128) % m as u128) as u64
}

fn winding(main_residue: u64, anchor_residue: u64, anchor: u64, cost: &mut QueryCost) -> u64 {
    cost.winding_readouts += 1;
    sub_mod(main_residue, anchor_residue, anchor, cost)
}

impl Observation<'_> {
    pub fn plan(&self, spec: QuerySpec) -> Result<QueryPlan, QueryError> {
        self.plan_with_budget(spec, DEFAULT_MAX_QUOTIENT_STEPS)
    }

    /// General quotient execution is variable-time repeated subtraction. This
    /// checks its worst-case loop bound from public parameters before execution.
    /// It is not a fixed-schedule encrypted divider or a constant-time promise.
    pub fn plan_with_budget(
        &self,
        spec: QuerySpec,
        max_quotient_steps: u64,
    ) -> Result<QueryPlan, QueryError> {
        let modulus = spec.modulus()?;
        let quotient_step_bound = match spec {
            QuerySpec::FloorQuotient { divisor, .. }
                if modulus != 1 && divisor != self.producer.main =>
            {
                self.state.upper / divisor
            }
            _ => 0,
        };
        if quotient_step_bound > max_quotient_steps {
            return Err(QueryError::WorkBudgetExceeded);
        }
        Ok(QueryPlan {
            binding: self.state.binding,
            spec,
            quotient_step_bound,
        })
    }

    pub fn execute(&self, plan: &QueryPlan) -> Result<QueryOutput, QueryError> {
        if plan.binding.frame != self.state.binding.frame {
            return Err(QueryError::FrameMismatch);
        }
        if plan.binding.source != self.state.binding.source {
            return Err(QueryError::SourceMismatch);
        }
        if plan.binding.epoch != self.state.binding.epoch {
            return Err(QueryError::StaleEpoch);
        }
        let modulus = plan.spec.modulus()?;
        let mut cost = QueryCost::default();
        if modulus == 1 {
            return Ok(QueryOutput { residue: 0, cost });
        }
        let p = self.producer;
        let residue = match plan.spec {
            QuerySpec::LinearResidue {
                coefficient,
                offset,
                ..
            } => {
                let a = (coefficient as i128).rem_euclid(modulus as i128) as u64;
                let c = (offset as i128).rem_euclid(modulus as i128) as u64;
                if a == 0 {
                    c
                } else {
                    let k = winding(
                        self.state.main_residue,
                        self.state.anchor_residue,
                        p.anchor,
                        &mut cost,
                    );
                    let low = mul_mod(a, self.state.main_residue % modulus, modulus, &mut cost);
                    let high_coefficient = mul_mod(a, p.main % modulus, modulus, &mut cost);
                    let high = mul_mod(high_coefficient, k % modulus, modulus, &mut cost);
                    let value = add_mod(low, high, modulus, &mut cost);
                    add_mod(value, c, modulus, &mut cost)
                }
            }
            QuerySpec::FloorQuotient {
                divisor, negate, ..
            } => {
                let q = if divisor > self.state.upper {
                    0
                } else if divisor == p.main {
                    winding(
                        self.state.main_residue,
                        self.state.anchor_residue,
                        p.anchor,
                        &mut cost,
                    ) % modulus
                } else {
                    // Fuel is public, derived solely from the admitted interval.
                    // The remainder stays in two residue lanes throughout.
                    let mut r_main = self.state.main_residue;
                    let mut r_anchor = self.state.anchor_residue;
                    let mut q_mod = 0;
                    let d_main = divisor % p.main;
                    let d_anchor = divisor % p.anchor;
                    let d_high = divisor / p.main;
                    for _ in 0..self.state.upper / divisor {
                        let high = winding(r_main, r_anchor, p.anchor, &mut cost);
                        cost.integer_comparisons += 1;
                        let less = match high.cmp(&d_high) {
                            Ordering::Less => true,
                            Ordering::Greater => false,
                            Ordering::Equal => {
                                cost.integer_comparisons += 1;
                                r_main < d_main
                            }
                        };
                        if less {
                            break;
                        }
                        r_main = sub_mod(r_main, d_main, p.main, &mut cost);
                        r_anchor = sub_mod(r_anchor, d_anchor, p.anchor, &mut cost);
                        q_mod = add_mod(q_mod, 1, modulus, &mut cost);
                        cost.loop_iterations += 1;
                    }
                    q_mod
                };
                if negate {
                    sub_mod(0, q, modulus, &mut cost)
                } else {
                    q
                }
            }
        };
        Ok(QueryOutput { residue, cost })
    }
}
