#![cfg(feature = "residue-query")]

use nine65::compiler::residue_query::{
    choose_observation_producers, execute_residue_queries, plan_information, AdjacentProducer,
    ProducerCandidate, QueryError, QuerySpec,
};

fn linear(modulus: u64) -> QuerySpec {
    QuerySpec::LinearResidue {
        coefficient: 1,
        offset: 0,
        modulus,
    }
}

#[test]
fn adapter_dispatch_matches_serial_source_queries_in_order() {
    let producer = AdjacentProducer::frame_36_37(35).unwrap();
    let mut state = producer.ingress(31).unwrap();
    producer
        .add_assign(&mut state, &producer.ingress(14).unwrap())
        .unwrap();
    let queries: Vec<_> = (1..=128)
        .map(|i| {
            if i % 2 == 0 {
                QuerySpec::LinearResidue {
                    coefficient: -3,
                    offset: 7,
                    modulus: i + 1,
                }
            } else {
                QuerySpec::FloorQuotient {
                    divisor: i % 36 + 1,
                    modulus: i + 1,
                    negate: false,
                }
            }
        })
        .collect();
    let outputs = execute_residue_queries(&producer, &state, &queries).unwrap();
    let view = producer.observe(&state).unwrap();
    for ((q, actual), i) in queries.iter().zip(&outputs).zip(1..=128) {
        let expected = view.execute(&view.plan(*q).unwrap()).unwrap();
        assert_eq!(*actual, expected);
        let integer_expected = if i % 2 == 0 {
            (-3i128 * 45 + 7).rem_euclid(i as i128 + 1) as u64
        } else {
            (45 / (i % 36 + 1)) % (i + 1)
        };
        assert_eq!(actual.residue, integer_expected);
    }
    assert!(execute_residue_queries(&producer, &state, &[])
        .unwrap()
        .is_empty());
}

#[test]
fn adapter_refuses_invalid_query_and_frame_before_execution() {
    let producer = AdjacentProducer::frame_36_37(100).unwrap();
    let state = producer.ingress(99).unwrap();
    assert_eq!(
        execute_residue_queries(&producer, &state, &[linear(19), linear(0)]),
        Err(QueryError::InvalidModulus)
    );
    let foreign = AdjacentProducer::frame_36_37(100).unwrap();
    assert_eq!(
        execute_residue_queries(&foreign, &state, &[linear(19)]),
        Err(QueryError::FrameMismatch)
    );
    let large = AdjacentProducer::new(1_000_000, 2_000_000).unwrap();
    let zero = large.ingress(0).unwrap();
    assert_eq!(
        execute_residue_queries(
            &large,
            &zero,
            &[
                linear(19),
                QuerySpec::FloorQuotient {
                    divisor: 1,
                    modulus: 19,
                    negate: false
                }
            ]
        ),
        Err(QueryError::WorkBudgetExceeded)
    );
}

#[test]
fn adapter_distinguishes_unrestricted_demand_and_bounded_runtime() {
    let demand = plan_information(&[36, 37], &[linear(19)]).unwrap();
    assert_eq!(demand.least_extra_anchor, 19);
    let selection = choose_observation_producers(
        &[12],
        &[linear(18)],
        &[
            ProducerCandidate {
                id: 1,
                modulus: 3,
                cost: 1,
            },
            ProducerCandidate {
                id: 2,
                modulus: 9,
                cost: 3,
            },
            ProducerCandidate {
                id: 3,
                modulus: 18,
                cost: 5,
            },
        ],
    )
    .unwrap();
    assert_eq!(selection.ids, vec![2]);
    let producer = AdjacentProducer::frame_36_37(1331).unwrap();
    let state = producer.ingress(1331).unwrap();
    // An authentic interval selects this source, so no extra lane is needed.
    assert_eq!(
        execute_residue_queries(&producer, &state, &[linear(19)]).unwrap()[0].residue,
        1331 % 19
    );
}
