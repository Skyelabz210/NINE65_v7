//! Exact public metadata must not derive arithmetic from legacy overflow sentinels.

use nine65::arithmetic::DualRNSContext;

fn wide_main() -> Vec<u64> {
    // The exact product is 149 bits. All primes support the N=4 chart.
    vec![
        998_244_353,
        985_661_441,
        754_974_721,
        469_762_049,
        1_224_736_769,
    ]
}

#[test]
fn wide_main_product_retains_nonzero_per_anchor_inverses() {
    let ctx = DualRNSContext::new(wide_main(), vec![17, 41, 73], 4);
    assert_eq!(ctx.main_product_checked, None);
    assert_eq!(ctx.main_product_bit_length, 149);
    // Independently calculated from the true prime-factor product.
    assert_eq!(ctx.main_inv_anchor_rns, [10, 17, 46]);
    assert_eq!(ctx.main_inv_anchor_checked, Some(13_916));
    assert_eq!(ctx.main_inv_anchor, 13_916);
}

#[test]
fn scalar_k_extraction_uses_true_wide_main_modulo_narrow_anchor() {
    let mut ctx = DualRNSContext::new(wide_main(), vec![17, 41, 73], 4);
    // Compatibility metadata is deliberately poisoned: arithmetic must use
    // the checked inverse, not this historical scalar snapshot.
    ctx.main_inv_anchor = 0;
    // A=50881, M mod A=43243, v_main=12345. This tuple represents k=25440.
    assert_eq!(ctx.extract_k(12_345, 16_164), 25_440);
}

#[test]
fn scalar_inverse_and_k_extraction_support_full_u128_anchor_product() {
    // A=216000000024588000000908274000010841257 exceeds i128::MAX.
    let ctx = DualRNSContext::new(
        vec![17, 41],
        vec![6_000_000_000_161, 6_000_000_000_233, 6_000_000_000_289],
        4,
    );
    let a = ctx.anchor_product_checked.unwrap();
    assert_eq!(a, 216_000_000_024_588_000_000_908_274_000_010_841_257);
    assert_eq!(ctx.anchor_product_bit_length, 128);
    assert_eq!(
        ctx.main_inv_anchor_checked,
        Some(179_431_850_809_521_451_937_626_815_847_928_661_532)
    );
    assert_eq!(
        ctx.main_inv_anchor,
        179_431_850_809_521_451_937_626_815_847_928_661_532
    );
    // 123+(A-1)*697 is deliberately not materialized: it exceeds u128.
    assert_eq!(ctx.extract_k(123, a - 574), a - 1);
    assert_eq!(ctx.extract_k(123, (a - 451) / 2), (a - 1) / 2);
}

#[test]
fn wide_main_and_full_u128_anchor_compute_inverse_without_a_scalar_main_product() {
    let ctx = DualRNSContext::new(
        wide_main(),
        vec![6_000_000_000_161, 6_000_000_000_233, 6_000_000_000_289],
        4,
    );
    assert_eq!(ctx.main_product_checked, None);
    assert_eq!(ctx.anchor_product_bit_length, 128);
    assert_eq!(
        ctx.main_inv_anchor_checked,
        Some(141_031_589_477_643_036_956_124_841_793_197_169_419)
    );
    assert_eq!(
        ctx.main_inv_anchor_rns,
        [4_963_506_483_272, 5_412_535_833_740, 718_260_346_911]
    );
    assert_eq!(
        ctx.extract_k(123, 202_163_281_854_037_763_355_825_988_515_441_500_392),
        31
    );
}

#[test]
fn one_anchor_has_a_checked_inverse_and_normalizes_scalar_residues() {
    let ctx = DualRNSContext::new(vec![17], vec![41], 4);
    assert_eq!(ctx.main_inv_anchor_checked, Some(29));
    assert_eq!(ctx.main_inv_anchor_rns, [29]);
    // 85=0+5*17, and 85 mod41=3. A noncanonical anchor input is normalized.
    assert_eq!(ctx.extract_k(0, 85), 5);
    assert_eq!(ctx.anchor_capacity_bits(), 6);
    assert_eq!(ctx.anchor3_capacity_bits(), 6);
    assert_eq!(ctx.audit_capacity(10, false).capacity_bits, 10);
}

#[test]
#[should_panic(expected = "Need at least one prime")]
fn empty_anchor_basis_cannot_publish_a_modulo_one_inverse() {
    // Preserve the existing constructor contract rather than inventing
    // inverse metadata for the empty product A=1.
    let _ = DualRNSContext::new(vec![17], vec![], 4);
}

#[test]
fn fhe_setup_retains_exact_metadata_when_both_products_exceed_u128() {
    let ctx = DualRNSContext::for_fhe(&wide_main(), 4);
    assert_eq!(ctx.main_product_checked, None);
    assert_eq!(ctx.anchor_product_checked, None);
    assert_eq!(ctx.main_inv_anchor_checked, None);
    assert_eq!(ctx.main_inv_anchor, 0); // Explicitly unavailable legacy snapshot.
    assert_eq!(
        ctx.main_inv_anchor_rns,
        [
            977_670_438,
            476_311_479,
            1_150_282_766,
            218_717_997,
            1_043_437_771,
            1_966_447_557,
            2_775_206_938,
        ]
    );
    assert_eq!(ctx.anchor_capacity_bits(), 220);
    assert_eq!(ctx.anchor3_capacity_bits(), 94);
    assert_eq!(ctx.audit_capacity(368, false).capacity_bits, 368);
    assert_eq!(ctx.max_intermediate_bits(), 63);
}

#[test]
fn capacities_use_bit_length_of_products_not_sum_of_factor_widths() {
    let ctx = DualRNSContext::new(vec![17, 41], vec![73, 89, 97], 4);
    // A=630209 has 20 bits; summing the three factor widths gives 21.
    assert_eq!(ctx.anchor_capacity_bits(), 20);
    assert_eq!(ctx.anchor3_capacity_bits(), 20);
    assert_eq!(ctx.check_k_proximity(20).capacity_bits, 20);
    assert_eq!(ctx.check_intermediate_proximity(20).capacity_bits, 20);
    // M*A=439255673 has 29 bits, while bitlen(M)+bitlen(A)=30.
    assert_eq!(ctx.audit_capacity(29, false).capacity_bits, 29);
    assert_eq!(ctx.audit_capacity(29, false).utilization_percent, 100);
    // N*max(q)^2=4*41^2=6724 has 13 bits, not 3+2*6=15.
    assert_eq!(ctx.max_intermediate_bits(), 13);
}

#[test]
fn three_anchor_capacity_uses_only_the_exact_prefix_product() {
    let ctx = DualRNSContext::new(vec![17], vec![41, 73, 89, 97], 4);
    assert_eq!(ctx.anchor3_capacity_bits(), 19); // 41*73*89=266377
    assert_eq!(ctx.anchor_capacity_bits(), 25); // 266377*97=25838569
    assert_eq!(ctx.audit_capacity(29, false).capacity_bits, 29);
}
