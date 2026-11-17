use cram_core::query_runtime::{
    plan_demands, select_producers, AdjacentProducer, ProducerCandidate, QueryError, QuerySpec,
    SourceState,
};

fn linear(a: i64, c: i64, modulus: u64) -> QuerySpec {
    QuerySpec::LinearResidue {
        coefficient: a,
        offset: c,
        modulus,
    }
}

fn quotient(divisor: u64, modulus: u64, negate: bool) -> QuerySpec {
    QuerySpec::FloorQuotient {
        divisor,
        modulus,
        negate,
    }
}

fn query(producer: &AdjacentProducer, state: &SourceState, spec: QuerySpec) -> u64 {
    let view = producer.observe(state).unwrap();
    view.execute(&view.plan(spec).unwrap()).unwrap().residue
}

#[test]
fn exhaustive_36_37_ingress_consumers_and_signed_coefficients() {
    let producer = AdjacentProducer::frame_36_37(1331).unwrap();
    for x in 0..1332 {
        let state = producer.ingress(x).unwrap();
        // Every source gets the identical public profile, not a value-tight bound.
        assert_eq!(state.public_upper(), 1331);
        for b in [1, 2, 7, 17, 36, 37, 1332, u64::MAX] {
            for (a, c) in [(1, 0), (-3, 7), (i64::MIN, i64::MAX), (0, -1)] {
                let expected = ((a as i128 * x as i128 + c as i128).rem_euclid(b as i128)) as u64;
                assert_eq!(
                    query(&producer, &state, linear(a, c, b)),
                    expected,
                    "x={x}, b={b}"
                );
            }
            for negate in [false, true] {
                let expected = if negate {
                    -(x as i128 / 36)
                } else {
                    x as i128 / 36
                };
                assert_eq!(
                    query(&producer, &state, quotient(36, b, negate)),
                    expected.rem_euclid(b as i128) as u64
                );
            }
        }
    }
}

#[test]
fn exhaustive_general_division_including_nonunit_divisors() {
    let producer = AdjacentProducer::frame_36_37(1331).unwrap();
    for x in 0..1332 {
        let state = producer.ingress(x).unwrap();
        for d in [1, 2, 3, 6, 9, 12, 36, 37, 74, 1331, 1332, u64::MAX] {
            for b in [1, 7, 19] {
                assert_eq!(query(&producer, &state, quotient(d, b, false)), (x / d) % b);
                assert_eq!(
                    query(&producer, &state, quotient(d, b, true)),
                    (-(x as i128 / d as i128)).rem_euclid(b as i128) as u64
                );
            }
        }
    }
}

#[test]
fn native_add_multiply_and_mixed_sequences_match_independent_oracle() {
    let producer = AdjacentProducer::frame_36_37(35).unwrap();
    for x in 0..=35 {
        for y in 0..=35 {
            let right = producer.ingress(y).unwrap();
            let mut sum = producer.ingress(x).unwrap();
            producer.add_assign(&mut sum, &right).unwrap();
            assert_eq!(sum.public_upper(), 70);
            let mut product = producer.ingress(x).unwrap();
            producer.multiply_assign(&mut product, &right).unwrap();
            assert_eq!(product.public_upper(), 1225);
            for b in [2, 19, 37, 1332] {
                assert_eq!(query(&producer, &sum, linear(1, 0, b)), (x + y) % b);
                assert_eq!(query(&producer, &product, linear(1, 0, b)), (x * y) % b);
            }
            producer.add_assign(&mut product, &right).unwrap();
            assert_eq!(
                query(&producer, &product, quotient(6, 37, false)),
                ((x * y + y) / 6) % 37
            );
            assert_eq!(product.epoch(), 2);
        }
    }
    let small = AdjacentProducer::frame_36_37(3).unwrap();
    for a in 0..=3 {
        for b in 0..=3 {
            for c in 0..=3 {
                let mut state = small.ingress(a).unwrap();
                small
                    .add_assign(&mut state, &small.ingress(b).unwrap())
                    .unwrap();
                small
                    .multiply_assign(&mut state, &small.ingress(c).unwrap())
                    .unwrap();
                assert_eq!(query(&small, &state, linear(1, 0, 1332)), (a + b) * c);
                assert_eq!(state.public_upper(), 18);
            }
        }
    }
}

#[test]
fn source_frame_and_epoch_authority_refuses_replays() {
    let producer = AdjacentProducer::frame_36_37(1).unwrap();
    let mut a = producer.ingress(1).unwrap();
    let b = producer.ingress(1).unwrap();
    let plan = producer
        .observe(&a)
        .unwrap()
        .plan(linear(1, 0, 17))
        .unwrap();
    assert_eq!(
        producer.observe(&b).unwrap().execute(&plan),
        Err(QueryError::SourceMismatch)
    );
    let other = AdjacentProducer::frame_36_37(1).unwrap();
    let other_state = other.ingress(1).unwrap();
    assert!(matches!(
        producer.observe(&other_state),
        Err(QueryError::FrameMismatch)
    ));
    assert_eq!(
        other.observe(&other_state).unwrap().execute(&plan),
        Err(QueryError::FrameMismatch)
    );
    // Residues stay unchanged, but changing the operation epoch invalidates a plan.
    let zero = producer.ingress(0).unwrap();
    producer.add_assign(&mut a, &zero).unwrap();
    assert_eq!(
        producer.observe(&a).unwrap().execute(&plan),
        Err(QueryError::StaleEpoch)
    );
    assert_eq!(query(&producer, &a, linear(1, 0, 17)), 1);
}

#[test]
fn repeated_native_square_preserves_identity_and_public_admission() {
    let producer = AdjacentProducer::frame_36_37(3).unwrap();
    for x in 0..=3 {
        let mut state = producer.ingress(x).unwrap();
        let initial_plan = producer
            .observe(&state)
            .unwrap()
            .plan(linear(1, 0, 19))
            .unwrap();
        producer.square_assign(&mut state).unwrap();
        assert_eq!(state.public_upper(), 9);
        assert_eq!(query(&producer, &state, linear(1, 0, 1332)), x * x);
        assert_eq!(
            producer.observe(&state).unwrap().execute(&initial_plan),
            Err(QueryError::StaleEpoch)
        );
        producer.square_assign(&mut state).unwrap();
        assert_eq!(state.public_upper(), 81);
        assert_eq!(query(&producer, &state, linear(1, 0, 1332)), x * x * x * x);
        assert_eq!(state.epoch(), 2);
        let plan = producer
            .observe(&state)
            .unwrap()
            .plan(linear(1, 0, 19))
            .unwrap();
        assert_eq!(
            producer.square_assign(&mut state),
            Err(QueryError::CapacityExceeded)
        );
        assert_eq!(state.epoch(), 2);
        assert_eq!(
            producer
                .observe(&state)
                .unwrap()
                .execute(&plan)
                .unwrap()
                .residue,
            (x * x * x * x) % 19
        );
    }
    let huge = AdjacentProducer::new(4_294_967_295, u64::MAX / 2).unwrap();
    let mut zero = huge.ingress(0).unwrap();
    assert_eq!(
        huge.square_assign(&mut zero),
        Err(QueryError::ArithmeticOverflow)
    );
    assert_eq!(zero.epoch(), 0);
}

#[test]
fn admission_is_public_conservative_and_failure_is_atomic() {
    assert!(matches!(
        AdjacentProducer::frame_36_37(1332),
        Err(QueryError::CapacityExceeded)
    ));
    let all = AdjacentProducer::frame_36_37(1331).unwrap();
    assert!(matches!(
        all.ingress(1332),
        Err(QueryError::InputOutsideProfile)
    ));
    let mut state = all.ingress(0).unwrap();
    let zero = all.ingress(0).unwrap();
    let plan = all.observe(&state).unwrap().plan(linear(1, 0, 17)).unwrap();
    // Actual 0+0 would fit, but the public profile does not justify all inputs.
    assert_eq!(
        all.add_assign(&mut state, &zero),
        Err(QueryError::CapacityExceeded)
    );
    assert_eq!(
        all.multiply_assign(&mut state, &zero),
        Err(QueryError::CapacityExceeded)
    );
    assert_eq!(state.public_upper(), 1331);
    assert_eq!(state.epoch(), 0);
    assert_eq!(
        all.observe(&state).unwrap().execute(&plan).unwrap().residue,
        0
    );
    let foreign = AdjacentProducer::new(4, 1).unwrap();
    assert_eq!(
        all.add_assign(&mut state, &foreign.ingress(1).unwrap()),
        Err(QueryError::FrameMismatch)
    );
    assert_eq!(state.epoch(), 0);
    assert!(matches!(
        AdjacentProducer::new(1, 0),
        Err(QueryError::InvalidFrame)
    ));
    assert!(matches!(
        AdjacentProducer::new(u64::MAX, 0),
        Err(QueryError::ArithmeticOverflow)
    ));
    assert!(matches!(
        AdjacentProducer::new(1 << 32, 0),
        Err(QueryError::ArithmeticOverflow)
    ));
}

#[test]
fn observed_operation_counts_match_executed_readout_routes() {
    let producer = AdjacentProducer::frame_36_37(1331).unwrap();
    let state = producer.ingress(100).unwrap();
    let view = producer.observe(&state).unwrap();
    let run = |q| view.execute(&view.plan(q).unwrap()).unwrap();
    let k = run(quotient(36, 37, false));
    assert_eq!(k.residue, 2);
    assert_eq!(
        (
            k.cost.winding_readouts,
            k.cost.modular_subtractions,
            k.cost.modular_multiplications
        ),
        (1, 1, 0)
    );
    let target = run(linear(1, 0, 19));
    assert_eq!(
        (
            target.cost.modular_additions,
            target.cost.modular_subtractions,
            target.cost.modular_multiplications
        ),
        (2, 1, 3)
    );
    let general = run(quotient(6, 19, false));
    assert_eq!(general.cost.loop_iterations, 16);
    assert_eq!(general.cost.winding_readouts, 17);
    assert_eq!(general.cost.modular_subtractions, 17 + 2 * 16);
    assert_eq!(general.cost.modular_additions, 16);
    assert_eq!(run(quotient(1332, 19, false)).cost.winding_readouts, 0);
    assert_eq!(run(linear(0, -1, 19)).cost.winding_readouts, 0);
    assert!(view.plan(quotient(0, 19, false)).is_err());
    assert!(view.plan(linear(1, 0, 0)).is_err());
    let large = AdjacentProducer::new(1_000_000, 2_000_000).unwrap();
    let zero = large.ingress(0).unwrap();
    let large_view = large.observe(&zero).unwrap();
    assert!(matches!(
        large_view.plan(quotient(1, 19, false)),
        Err(QueryError::WorkBudgetExceeded)
    ));
    let explicitly_budgeted = large_view
        .plan_with_budget(quotient(1, 19, false), 2_000_000)
        .unwrap();
    assert_eq!(explicitly_budgeted.quotient_step_bound(), 2_000_000);
    assert_eq!(large_view.execute(&explicitly_budgeted).unwrap().residue, 0);
    assert_eq!(
        large_view
            .plan_with_budget(quotient(1_000_000, 19, false), 0)
            .unwrap()
            .quotient_step_bound(),
        0
    );
}

#[test]
fn planner_minimal_anchor_agrees_with_exhaustive_divisibility_oracle() {
    for p in 1..=80 {
        for d in 1..=80 {
            let got = plan_demands(&[p], &[linear(1, 0, d)]).unwrap();
            assert_eq!(got.observed_period, p);
            assert_eq!(got.required_period, d);
            for a in 1..=160 {
                // The oracle checks divisibility directly by scanning multiples.
                let common = (p..=p * a)
                    .step_by(p as usize)
                    .find(|n| n % a == 0)
                    .unwrap();
                if common % d == 0 {
                    assert_eq!(a % got.least_extra_anchor, 0);
                }
            }
            let a = got.least_extra_anchor;
            let common = (p..=p * a)
                .step_by(p as usize)
                .find(|n| n % a == 0)
                .unwrap();
            assert_eq!(common % d, 0);
        }
    }
    assert_eq!(
        plan_demands(&[4, 6, 6], &[linear(1, 0, 18)])
            .unwrap()
            .least_extra_anchor,
        9
    );
    assert_eq!(
        plan_demands(&[12], &[linear(6, 3, 18)])
            .unwrap()
            .least_extra_anchor,
        1
    );
    assert_eq!(plan_demands(&[], &[]).unwrap().observed_period, 1);
}

#[test]
fn planner_periods_match_signed_integer_queries() {
    for d in 1..=8u64 {
        for b in 1..=8u64 {
            let q = quotient(d, b, false);
            let period = q.period().unwrap();
            for p in 1..=64u64 {
                let actual = (-(d as i64)..=d as i64).all(|x| {
                    (x.div_euclid(d as i64)).rem_euclid(b as i64)
                        == ((x + p as i64).div_euclid(d as i64)).rem_euclid(b as i64)
                });
                assert_eq!(actual, p % period == 0);
            }
        }
    }
    assert_eq!(linear(i64::MIN, 0, 1 << 63).period().unwrap(), 1);
    assert_eq!(quotient(u64::MAX, 1, false).period().unwrap(), 1);
    assert_eq!(
        quotient(u64::MAX, 2, false).period(),
        Err(QueryError::ArithmeticOverflow)
    );
    assert_eq!(
        plan_demands(&[u64::MAX, 2], &[]),
        Err(QueryError::ArithmeticOverflow)
    );
    assert_eq!(plan_demands(&[0], &[]), Err(QueryError::InvalidModulus));
    assert_eq!(
        quotient(0, 1, false).period(),
        Err(QueryError::InvalidDivisor)
    );
    assert_eq!(linear(1, 0, 0).period(), Err(QueryError::InvalidModulus));
}

#[test]
fn producer_selection_matches_independent_subset_enumeration() {
    let candidates = [
        ProducerCandidate {
            id: 4,
            modulus: 25,
            cost: 5,
        },
        ProducerCandidate {
            id: 2,
            modulus: 9,
            cost: 2,
        },
        ProducerCandidate {
            id: 1,
            modulus: 4,
            cost: 3,
        },
        ProducerCandidate {
            id: 3,
            modulus: 6,
            cost: 1,
        },
        ProducerCandidate {
            id: 5,
            modulus: 18,
            cost: 4,
        },
        ProducerCandidate {
            id: 6,
            modulus: 7,
            cost: 2,
        },
    ];
    for p in 1..=20u64 {
        for d in 1..=60u64 {
            let mut expected = None;
            for bits in 0..1 << candidates.len() {
                let subset: Vec<_> = candidates
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| bits & (1 << i) != 0)
                    .map(|(_, c)| c)
                    .collect();
                let mut period = p;
                for c in &subset {
                    period = period / cram_core::gcd(period, c.modulus) * c.modulus;
                }
                if period % d == 0 {
                    let mut ids: Vec<_> = subset.iter().map(|c| c.id).collect();
                    ids.sort_unstable();
                    let cost = subset.iter().map(|c| c.cost).sum::<u64>();
                    let option = (cost, ids.len(), ids);
                    if expected.as_ref().map(|old| &option < old).unwrap_or(true) {
                        expected = Some(option);
                    }
                }
            }
            let got = select_producers(&[p], &[linear(1, 0, d)], &candidates);
            match expected {
                Some(expected) => {
                    let got = got.unwrap();
                    assert_eq!((got.total_cost, got.ids.len(), got.ids), expected);
                    assert_eq!(got.combined_period % d, 0);
                }
                None => assert_eq!(got, Err(QueryError::UnavailableObservation)),
            }
        }
    }
}

#[test]
fn catalog_validation_and_missing_observations_are_explicit() {
    let c = ProducerCandidate {
        id: 1,
        modulus: 3,
        cost: 1,
    };
    assert_eq!(
        select_producers(&[12], &[linear(1, 0, 18)], &[c]),
        Err(QueryError::UnavailableObservation)
    );
    assert_eq!(
        select_producers(&[], &[], &[c, c]),
        Err(QueryError::DuplicateProducer)
    );
    assert_eq!(
        select_producers(&[], &[], &[ProducerCandidate { cost: 0, ..c }]),
        Err(QueryError::InvalidCost)
    );
    assert_eq!(
        select_producers(&[], &[], &[ProducerCandidate { modulus: 0, ..c }]),
        Err(QueryError::InvalidModulus)
    );
    assert_eq!(
        select_producers(&[], &[], &[c; 17]),
        Err(QueryError::TooManyCandidates)
    );
    assert_eq!(
        select_producers(
            &[2],
            &[],
            &[ProducerCandidate {
                modulus: u64::MAX,
                ..c
            }]
        ),
        Err(QueryError::ArithmeticOverflow)
    );
    assert_eq!(
        select_producers(
            &[],
            &[],
            &[
                ProducerCandidate {
                    cost: u64::MAX,
                    ..c
                },
                ProducerCandidate { id: 2, ..c }
            ]
        ),
        Err(QueryError::ArithmeticOverflow)
    );
    assert_eq!(select_producers(&[12], &[], &[]).unwrap().total_cost, 0);
}
