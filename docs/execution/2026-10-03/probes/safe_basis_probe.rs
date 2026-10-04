//! Source-bound review probe, not a completed production acceptance test.
//! Compile as documented in SAFE_BASIS_REVISION.md; no Cargo dependencies.
#[path = "../../../../crates/exact_transcendentals/src/k_elim.rs"]
mod k_elim;
#[path = "../../../../crates/exact_transcendentals/src/cram_ops.rs"]
mod cram_ops;
#[path = "../../../../crates/exact_transcendentals/src/transduction.rs"]
mod transduction;
#[path = "../../../../crates/exact_transcendentals/src/lifted_transduction.rs"]
mod lifted_transduction;

fn main() {
    use cram_ops::{CramOp, Schema};
    use lifted_transduction::transduct_with_lift_provider;
    use transduction::S8_BASIS;

    // Post-S02 correctness check. The original defect-reproduction probe is
    // preserved in artifacts/execution/2026-10-03-s02/S02/ alongside its
    // pre-mutation source hashes. The Cargo suite checks the real schema too.
    let schema = Schema::new(&[CramOp::Inv], &[15]).unwrap();
    let actual = schema.apply(&[2], &[0]).unwrap()[0];
    let expected = (0..15).find(|v| (2 * v) % 15 == 1).unwrap();
    assert_eq!(expected, 8);
    assert_eq!(actual, expected);
    println!("Composite inverse regression passed: Inv(2) mod15 = {actual}");

    let div3 = k_elim::mul_via_div(&[2], &[4], &[15]).unwrap();
    assert_eq!(div3, vec![8]);
    assert!(k_elim::mul_via_div(&[3], &[4], &[15]).is_none());
    println!("DIV3 composite unit case passed; nonunit refused");

    let m: i128 = S8_BASIS.iter().product();
    let anchor = m + 1;
    let targets = [1, 6, 10, 15, 22, 121, 323];
    let mut checks = 0;
    for x in [0, m - 1, m, m + 1, 2 * m + 7, m * anchor - 1] {
        // x is used only by this oracle to create authentic state and
        // calculate expectations; the callback sees only its two residues.
        let source: Vec<i128> = S8_BASIS.iter().map(|p| x % p).collect();
        let r = x % m;
        let a = x % anchor;
        let provider = |_: usize, b: i128| Ok((r - a).rem_euclid(anchor) % b);
        let output = transduct_with_lift_provider(&S8_BASIS, &targets, &source, &provider).unwrap();
        for (b, value) in targets.iter().zip(output) {
            assert_eq!(value, x % b);
            checks += 1;
        }
    }
    println!("Production lifted projection passed {checks} oracle comparisons, including shared-factor targets and modulus1");
    assert_eq!(m % 11, 0);
    assert_eq!(k_elim::mod_inv(m, 11), None);
    println!("Full S8 product has no inverse mod11; a different source/anchor split is required for that formula");
}
