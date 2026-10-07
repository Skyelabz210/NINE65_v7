//! Black-box unit-domain checks for the admitted schema API.
//! The small-modulus oracle searches products directly; it does not use EEA.
use exact_transcendentals::cram_machine::Cram;
use exact_transcendentals::cram_ops::{
    lane_validity, parse_schema, schema_validity, CramOp, CramOpError, Schema,
};
use exact_transcendentals::k_elim;

const OPERATORS: [CramOp; 8] = [
    CramOp::Add,
    CramOp::Sub,
    CramOp::Mul,
    CramOp::Div,
    CramOp::Sqr,
    CramOp::Neg,
    CramOp::Inv,
    CramOp::Id,
];

fn oracle_inverse(a: u64, modulus: u64) -> Option<u64> {
    (0..modulus).find(|&inverse| (a as u128 * inverse as u128) % modulus as u128 == 1)
}

fn check_schema_inverse(modulus: u64, expected: u64) {
    let schema = Schema::new(&[CramOp::Inv], &[modulus]).unwrap();
    let actual = schema.apply(&[2], &[0]).unwrap()[0];
    assert_eq!(actual, expected);
    assert_eq!((2 * actual) % modulus, 1);
}

#[test]
fn schema_inverse_mod9_is5() {
    check_schema_inverse(9, 5);
}

#[test]
fn schema_inverse_mod15_is8() {
    check_schema_inverse(15, 8);
}

#[test]
fn owner_t5_schema_inverse_mod15015_is7508() {
    check_schema_inverse(15_015, 7_508);
}

#[test]
fn inverse_units_and_nonunits_match_product_search() {
    for modulus in 3..=64 {
        let schema = Schema::new(&[CramOp::Inv], &[modulus]).unwrap();
        for a in 0..modulus {
            match oracle_inverse(a, modulus) {
                Some(expected) => {
                    assert_eq!(
                        schema.apply(&[a], &[0]).unwrap(),
                        [expected],
                        "Inv({a}) mod {modulus}"
                    );
                }
                None => assert!(
                    schema.apply(&[a], &[0]).is_err(),
                    "nonunit {a} mod {modulus} was accepted"
                ),
            }
        }
    }
}

#[test]
fn division_matches_product_search_on_small_rings() {
    for modulus in 3..=64 {
        let schema = Schema::new(&[CramOp::Div], &[modulus]).unwrap();
        for b in 0..modulus {
            let inverse = oracle_inverse(b, modulus);
            for a in 0..modulus {
                match inverse {
                    Some(inverse) => {
                        let expected = ((a as u128 * inverse as u128) % modulus as u128) as u64;
                        assert_eq!(
                            schema.apply(&[a], &[b]).unwrap(),
                            [expected],
                            "Div({a},{b}) mod {modulus}"
                        );
                    }
                    None => assert!(
                        schema.apply(&[a], &[b]).is_err(),
                        "nonunit divisor {b} mod {modulus} was accepted"
                    ),
                }
            }
        }
    }
}

#[test]
fn noncanonical_inputs_have_canonical_ring_outputs() {
    for modulus in 3..=32 {
        let inputs = [0, 1, modulus, modulus + 1, 2 * modulus + 3, u64::MAX];
        for op in OPERATORS {
            let schema = Schema::new(&[op], &[modulus]).unwrap();
            for a in inputs {
                for b in inputs {
                    let ar = a % modulus;
                    let br = b % modulus;
                    let expected = match op {
                        CramOp::Add => Some((ar + br) % modulus),
                        CramOp::Sub => Some((ar + modulus - br) % modulus),
                        CramOp::Mul => Some(ar * br % modulus),
                        CramOp::Div => {
                            oracle_inverse(br, modulus).map(|inverse| ar * inverse % modulus)
                        }
                        CramOp::Sqr => Some(ar * ar % modulus),
                        CramOp::Neg => Some((modulus - ar) % modulus),
                        CramOp::Inv => oracle_inverse(ar, modulus),
                        CramOp::Id => Some(ar),
                    };
                    match expected {
                        Some(expected) => assert_eq!(
                            schema.apply(&[a], &[b]).unwrap(),
                            [expected],
                            "{op:?}({a},{b}) mod {modulus}"
                        ),
                        None => assert!(schema.apply(&[a], &[b]).is_err()),
                    }
                }
            }
        }
    }
}

#[test]
fn full_width_u64_units_and_products_do_not_overflow() {
    for modulus in [u64::MAX, u64::MAX - 58] {
        let inv = Schema::new(&[CramOp::Inv], &[modulus]).unwrap();
        let expected = (modulus as u128).div_ceil(2) as u64;
        assert_eq!(inv.apply(&[2], &[0]).unwrap(), [expected]);
        let division = Schema::new(&[CramOp::Div], &[modulus]).unwrap();
        let a = u64::MAX;
        let quotient = division.apply(&[a], &[2]).unwrap()[0];
        assert_eq!(
            2 * quotient as u128 % modulus as u128,
            a as u128 % modulus as u128
        );
        let expected_product = (a as u128 * a as u128 % modulus as u128) as u64;
        assert_eq!(CramOp::Mul.apply(a, a, modulus).unwrap(), expected_product);
        assert_eq!(CramOp::Sqr.apply(a, 0, modulus).unwrap(), expected_product);
    }
    let modulus = 1u64 << 63;
    let inverse = CramOp::Inv.apply(3, 0, modulus).unwrap();
    assert_eq!(3 * inverse as u128 % modulus as u128, 1);
    assert!(matches!(
        CramOp::Inv.apply(2, 0, modulus),
        Err(CramOpError::InvNonInvertible { gcd: 2, .. })
    ));
}

#[test]
fn full_width_fibonacci_pair_exercises_a_long_euclidean_chain() {
    let a = 7_540_113_804_746_346_429u64;
    let modulus = 12_200_160_415_121_876_738u64;
    // Independently checked by Python's integer inverse and the product identity.
    let expected = 4_660_046_610_375_530_309u64;
    assert_eq!(a as u128 * expected as u128 % modulus as u128, 1);
    let schema = Schema::new(&[CramOp::Inv], &[modulus]).unwrap();
    assert_eq!(schema.apply(&[a], &[0]).unwrap(), [expected]);
}

#[test]
fn zero_nonunits_and_invalid_moduli_return_typed_errors() {
    assert!(matches!(
        CramOp::Inv.apply(0, 0, 15),
        Err(CramOpError::InvNonInvertible { gcd: 15, .. })
    ));
    assert!(matches!(
        CramOp::Inv.apply(3, 0, 15),
        Err(CramOpError::InvNonInvertible { gcd: 3, .. })
    ));
    assert!(matches!(
        CramOp::Div.apply(2, 15, 15),
        Err(CramOpError::DivByNonInvertible { b: 0, gcd: 15, .. })
    ));
    for op in OPERATORS {
        assert!(matches!(
            op.apply(0, 0, 0),
            Err(CramOpError::InvalidModulus { modulus: 0 })
        ));
    }
}

#[test]
fn modulus1_is_only_a_constant_view() {
    for op in OPERATORS {
        match op {
            CramOp::Inv | CramOp::Div => assert!(matches!(
                op.apply(9, 3, 1),
                Err(CramOpError::InvalidModulus { modulus: 1 })
            )),
            _ => assert_eq!(op.apply(u64::MAX, u64::MAX, 1), Ok(0)),
        }
        assert!(matches!(
            Schema::new(&[op], &[1]),
            Err(CramOpError::InvalidModulus { modulus: 1 })
        ));
    }
}

#[test]
fn schema_shapes_and_unknown_codes_return_errors() {
    assert!(matches!(
        Schema::new(&[], &[]),
        Err(CramOpError::EmptySchema)
    ));
    assert!(matches!(
        Schema::new(&[CramOp::Id], &[]),
        Err(CramOpError::LengthMismatch { .. })
    ));
    assert!(matches!(
        Schema::new(&[CramOp::Id], &[0]),
        Err(CramOpError::InvalidModulus { modulus: 0 })
    ));
    assert!(matches!(
        parse_schema("?", &[15]),
        Err(CramOpError::UnknownOperator { code: '?' })
    ));
    let schema = Schema::new(&[CramOp::Div], &[15]).unwrap();
    assert!(matches!(
        schema.apply(&[], &[2]),
        Err(CramOpError::LengthMismatch { argument: "a", .. })
    ));
    assert!(matches!(
        schema.apply(&[2], &[]),
        Err(CramOpError::LengthMismatch { argument: "b", .. })
    ));
}

#[test]
fn independent_source_schema_guards_remain_enforced() {
    assert!(matches!(
        Schema::new(&[CramOp::Id; 2], &[6, 9]),
        Err(CramOpError::NonCoprimeBasis { gcd: 3, .. })
    ));
    assert!(matches!(
        Schema::new(&[CramOp::Mul, CramOp::Id], &[2, 3]),
        Err(CramOpError::DegreeViolation { rho: 2, .. })
    ));
}

#[test]
fn unit_counts_match_exhaustive_small_ring_search() {
    for modulus in 2..=256 {
        let count = (0..modulus)
            .filter(|&a| oracle_inverse(a, modulus).is_some())
            .count() as u64;
        assert_eq!(lane_validity(modulus), Ok((count, modulus)));
    }
    assert_eq!(lane_validity(15_015), Ok((5_760, 15_015)));
    assert_eq!(lane_validity(1u64 << 63), Ok((1u64 << 62, 1u64 << 63)));
    let modulus = 3u64.pow(40);
    assert_eq!(lane_validity(modulus), Ok((2 * 3u64.pow(39), modulus)));
}

#[test]
fn validity_failures_are_explicit_and_do_not_restrict_lane_execution() {
    for modulus in [0, 1] {
        assert!(matches!(
            lane_validity(modulus),
            Err(CramOpError::InvalidModulus { .. })
        ));
    }
    // Both factors exceed the diagnostic's bounded trial search.
    let modulus = 1_000_003u64 * 1_000_033;
    let schema = Schema::new(&[CramOp::Inv], &[modulus]).unwrap();
    assert!(matches!(
        schema_validity(&schema),
        Err(CramOpError::ValidityFactorizationRequired { .. })
    ));
    let inverse = schema.apply(&[2], &[0]).unwrap()[0];
    assert_eq!(2 * inverse as u128 % modulus as u128, 1);
    let moduli = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59];
    let schema = Schema::new(&[CramOp::Inv; 16], &moduli).unwrap();
    assert!(matches!(
        schema_validity(&schema),
        Err(CramOpError::ArithmeticOverflow {
            operation: "schema validity"
        })
    ));
}

#[test]
fn schema_validity_uses_units_only_for_inverse_operands() {
    let schema = Schema::new(&[CramOp::Inv, CramOp::Div, CramOp::Mul], &[9, 10, 7]).unwrap();
    assert_eq!(schema_validity(&schema), Ok((6 * 4, 9 * 10)));
    let schema = Schema::new(&[CramOp::Add, CramOp::Mul], &[9, 10]).unwrap();
    assert_eq!(schema_validity(&schema), Ok((1, 1)));
    assert_eq!(Cram::new(&[3, 5, 7], 1).validity(), Ok(None));
    assert_eq!(
        Cram::configured("AADIM", 1).unwrap().validity(),
        Ok(Some((60, 77)))
    );
}

#[test]
fn live_machine_propagates_diagnostic_factorization_failure() {
    let modulus = 1_000_003u64 * 1_000_033;
    let machine = Cram::configure(&[modulus], "I", 1).unwrap();
    assert!(matches!(
        machine.validity(),
        Err(CramOpError::ValidityFactorizationRequired { .. })
    ));
}

#[test]
fn heterogeneous_inverse_operator_lanes_roundtrip_as_residues() {
    let schema = Schema::new(&[CramOp::Neg, CramOp::Inv, CramOp::Id], &[9, 10, 7]).unwrap();
    for a in 0..9 {
        for b in [1, 3, 7, 9] {
            // units on the composite inverse lane
            for c in 0..7 {
                let input = [a, b, c];
                let once = schema.apply(&input, &[0; 3]).unwrap();
                let twice = schema.apply(&once, &[0; 3]).unwrap();
                assert_eq!(twice, input);
                assert_eq!(once[1], oracle_inverse(b, 10).unwrap());
            }
        }
    }
}

#[test]
fn heterogeneous_schema_is_lane_local_and_order_equivariant() {
    let ops = [CramOp::Inv, CramOp::Neg, CramOp::Mul, CramOp::Id];
    let moduli = [9, 10, 7, 11];
    let a = [2, 3, 4, 5];
    let b = [0, 0, 6, 0];
    let schema = Schema::new(&ops, &moduli).unwrap();
    let expected = schema.apply(&a, &b).unwrap();
    let order = [2, 0, 3, 1];
    let reorder = |input: &[u64]| order.map(|i| input[i]);
    let permuted = Schema::new(&order.map(|i| ops[i]), &reorder(&moduli)).unwrap();
    assert_eq!(
        permuted.apply(&reorder(&a), &reorder(&b)).unwrap(),
        reorder(&expected)
    );
    let mut changed = a;
    changed[0] = 4;
    let output = schema.apply(&changed, &b).unwrap();
    assert_ne!(output[0], expected[0]);
    assert_eq!(&output[1..], &expected[1..]);
}

#[test]
fn div3_matches_multiplication_on_composite_units_and_refuses_nonunits() {
    for modulus in 3..=64u64 {
        for a in 0..modulus {
            for b in 0..modulus {
                let actual = k_elim::mul_via_div(&[a as i128], &[b as i128], &[modulus as i128]);
                if oracle_inverse(a, modulus).is_some() && oracle_inverse(b, modulus).is_some() {
                    assert_eq!(actual, Some(vec![(a * b % modulus) as i128]));
                } else {
                    assert!(
                        actual.is_none(),
                        "DIV3 accepted nonunit ({a},{b}) mod {modulus}"
                    );
                }
            }
        }
    }
}
