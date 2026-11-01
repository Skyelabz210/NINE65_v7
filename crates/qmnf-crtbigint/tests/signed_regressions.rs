use qmnf_crtbigint::{CRTBigInt, CrtError, EXACT_MODULI};

#[test]
fn mixed_sign_addition_and_zero_subtraction() {
    for (left, right, expected) in [(5, -3, 2), (-5, 3, -2), (-5, -3, -8), (3, -5, -2)] {
        assert_eq!(
            (CRTBigInt::from_i64(left) + CRTBigInt::from_i64(right)).to_i64(),
            Some(expected)
        );
    }
    assert_eq!((CRTBigInt::zero() - CRTBigInt::one()).to_i64(), Some(-1));
}

#[test]
fn signed_small_integer_oracle() {
    for left in -32i64..=32 {
        for right in -32i64..=32 {
            let a = CRTBigInt::from_i64(left);
            let b = CRTBigInt::from_i64(right);
            assert_eq!(
                (a.clone() + b.clone()).to_i64(),
                Some(left + right),
                "{left}+{right}"
            );
            assert_eq!(
                (a.clone() - b.clone()).to_i64(),
                Some(left - right),
                "{left}-{right}"
            );
            assert_eq!((a * b).to_i64(), Some(left * right), "{left}*{right}");
        }
    }
}

#[test]
fn signed_i64_boundaries_round_trip() {
    for value in [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX] {
        assert_eq!(CRTBigInt::from_i64(value).to_i64(), Some(value));
    }
}

#[test]
fn zero_cancellation_and_powers_are_canonical() {
    let zero = CRTBigInt::from_i64(7) + CRTBigInt::from_i64(-7);
    assert_eq!(zero, CRTBigInt::zero());
    assert_eq!(-CRTBigInt::zero(), CRTBigInt::zero());
    assert_eq!(CRTBigInt::zero().mod_pow(2), CRTBigInt::zero());
    assert_eq!(CRTBigInt::zero().mod_pow(0), CRTBigInt::one());
    assert_eq!(CRTBigInt::from_i64(-2).mod_pow(3).to_i64(), Some(-8));
    assert_eq!(CRTBigInt::from_i64(-2).mod_pow(4).to_i64(), Some(16));
}

#[test]
fn negative_values_have_signed_lane_projection() {
    for value in [i64::MIN, -17, -1, 0, 1, 17, i64::MAX] {
        let x = CRTBigInt::from_i64(value);
        for (lane, &modulus) in EXACT_MODULI.iter().enumerate() {
            assert_eq!(
                x.signed_residue(lane),
                (value as i128).rem_euclid(modulus as i128) as u64
            );
        }
        let signed = std::array::from_fn(|lane| x.signed_residue(lane));
        assert_eq!(
            CRTBigInt::try_from_signed_residues(x.sign(), signed).unwrap(),
            x
        );
    }
}

fn power_of_two(bit: usize, sign: i8) -> CRTBigInt {
    let mut limbs = [0; 8];
    limbs[bit / 64] = 1u64 << (bit % 64);
    CRTBigInt::try_from_magnitude_limbs(sign, limbs).unwrap()
}

#[test]
fn wide_reconstruction_and_arithmetic_preserve_all_limbs() {
    let x = power_of_two(128, 1);
    let mut expected = [0; 8];
    expected[2] = 1;
    assert_eq!(x.magnitude_limbs(), expected);
    assert_eq!(x.try_garner_reconstruct(), Err(CrtError::NarrowingOverflow));
    assert_eq!(x.to_i64(), None);
    let square = x.checked_mul(&x).unwrap();
    assert_eq!(square, power_of_two(256, 1));
    assert_eq!((-x.clone()).checked_mul(&x).unwrap(), power_of_two(256, -1));

    let borrowed = x.checked_sub(&CRTBigInt::one()).unwrap();
    assert_eq!(
        borrowed.magnitude_limbs(),
        [u64::MAX, u64::MAX, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(borrowed.try_garner_reconstruct(), Ok(u128::MAX));
    assert_eq!(borrowed.checked_add(&CRTBigInt::one()).unwrap(), x);
    assert_eq!(
        power_of_two(400, 1)
            .checked_mul(&power_of_two(100, -1))
            .unwrap(),
        power_of_two(500, -1)
    );
}

#[test]
#[should_panic(expected = "CRT magnitude exceeds u128")]
fn legacy_narrow_reconstruction_refuses_two_to_the_128() {
    let factor = CRTBigInt::from_u64(1u64 << 32);
    let wide = factor.clone() * factor.clone() * factor.clone() * factor;
    let _ = wide.garner_reconstruct();
}

#[test]
fn full_product_boundary_refuses_aliased_results() {
    let capacity = CRTBigInt::capacity_limbs();
    assert_eq!(
        CRTBigInt::try_from_magnitude_limbs(1, capacity),
        Err(CrtError::MagnitudeOverflow)
    );
    // The product is odd, so its lowest limb is nonzero: subtracting one
    // here requires no borrow through the higher limbs.
    let mut largest = capacity;
    largest[0] -= 1;
    let x = CRTBigInt::try_from_magnitude_limbs(1, largest).unwrap();
    assert_eq!(x.magnitude_limbs(), largest);
    assert_eq!(
        x.checked_add(&CRTBigInt::one()),
        Err(CrtError::MagnitudeOverflow)
    );
    assert_eq!(
        x.checked_mul(&CRTBigInt::from_u64(2)),
        Err(CrtError::MagnitudeOverflow)
    );
    assert_eq!(
        (-x.clone()).checked_sub(&CRTBigInt::one()),
        Err(CrtError::MagnitudeOverflow)
    );
    assert_eq!(x.checked_add(&(-x.clone())).unwrap(), CRTBigInt::zero());
    assert_eq!(
        power_of_two(500, 1).checked_mul(&CRTBigInt::from_u64(16)),
        Err(CrtError::MagnitudeOverflow)
    );
}

#[test]
fn boundary_residue_import_rejects_noncanonical_sign_and_lanes() {
    assert_eq!(
        CRTBigInt::try_from_residues(0, [1; 8]),
        Err(CrtError::InvalidSign)
    );
    assert_eq!(
        CRTBigInt::try_from_residues(-1, [0; 8]),
        Err(CrtError::InvalidSign)
    );
    assert_eq!(
        CRTBigInt::try_from_residues(2, [1; 8]),
        Err(CrtError::InvalidSign)
    );
    let mut residues = [1; 8];
    residues[3] = EXACT_MODULI[3];
    assert_eq!(
        CRTBigInt::try_from_residues(1, residues),
        Err(CrtError::NonCanonicalResidue { lane: 3 })
    );
    let value = CRTBigInt::from_i64(-42);
    assert_eq!(
        CRTBigInt::try_from_residues(value.sign(), *value.residues()).unwrap(),
        value
    );
}

#[test]
fn deterministic_signed_oracle_spans_full_i64_range() {
    let mut state = 0xd1b5_4a32_d192_ed03u64;
    for _ in 0..10_000 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let left = state as i64;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let right = state as i64;
        let a = CRTBigInt::from_i64(left);
        let b = CRTBigInt::from_i64(right);
        for (actual, expected) in [
            (a.checked_add(&b).unwrap(), left as i128 + right as i128),
            (a.checked_sub(&b).unwrap(), left as i128 - right as i128),
            (a.checked_mul(&b).unwrap(), left as i128 * right as i128),
        ] {
            assert_eq!(actual.sign(), expected.signum() as i8);
            assert_eq!(actual.try_garner_reconstruct(), Ok(expected.unsigned_abs()));
            for (lane, &modulus) in EXACT_MODULI.iter().enumerate() {
                assert_eq!(
                    actual.signed_residue(lane),
                    expected.rem_euclid(modulus as i128) as u64
                );
            }
        }
    }
}

#[test]
fn modular_inverse_has_signed_unit_semantics() {
    for value in [-17, -1, 1, 17] {
        let x = CRTBigInt::from_i64(value);
        let inverse = x.mod_inverse().unwrap();
        for (lane, &modulus) in EXACT_MODULI.iter().enumerate() {
            assert_eq!(
                (x.signed_residue(lane) as u128 * inverse.signed_residue(lane) as u128)
                    % modulus as u128,
                1
            );
        }
    }
    assert!(CRTBigInt::zero().mod_inverse().is_none());
    assert!(CRTBigInt::from_u64(EXACT_MODULI[0]).mod_inverse().is_none());
}

fn parse_signed_hex(text: &str) -> CRTBigInt {
    let (sign, digits) = text
        .strip_prefix('-')
        .map_or((1, text), |digits| (-1, digits));
    let mut limbs = [0; 8];
    for (index, chunk) in digits.as_bytes().rchunks(16).enumerate() {
        limbs[index] = u64::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
    }
    CRTBigInt::try_from_magnitude_limbs(sign, limbs).unwrap()
}

#[test]
fn multi_limb_signed_arithmetic_matches_python_integer_vectors() {
    // Generated independently with Python random.Random(0x504), signed
    // 245-bit operands and arbitrary-width integer +, -, *. Products span
    // nearly the full fixed CRT magnitude; there is no Rust reconstruction
    // or shared multiply routine in the expected-value oracle.
    for row in include_str!("wide_oracle_vectors.tsv").lines() {
        let values: Vec<_> = row.split('\t').map(parse_signed_hex).collect();
        assert_eq!(values[0].checked_add(&values[1]).unwrap(), values[2]);
        assert_eq!(values[0].checked_sub(&values[1]).unwrap(), values[3]);
        assert_eq!(values[0].checked_mul(&values[1]).unwrap(), values[4]);
    }
}
