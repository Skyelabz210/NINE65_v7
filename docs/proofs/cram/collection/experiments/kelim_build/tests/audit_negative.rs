use kelim::*;

#[test]
fn canonical_i128_inputs_can_overflow_intermediate_product() {
    let a = (1i128 << 126) + 1;
    // X=2*(a-2)=i128::MAX-1 is representable. Its canonical residues:
    let expected = a - 2;
    let observed = std::panic::catch_unwind(|| k_elim(0, a - 4, 2, a));
    match observed {
        Err(_) => (), // debug overflow: expected negative control
        Ok(k) => assert_ne!(k, expected), // release wrap: wrong result
    }
}

#[test]
fn supported_pair_cannot_detect_out_of_range_alias() {
    assert_eq!(k_elim(0, 0, 35, 36), 0);
    assert_eq!(1260 / 35, 36); // Same observed pair, quotient differs.
}

#[test]
fn documented_comparison_window_is_necessary() {
    let (x,y,m)=(1000i128,0i128,35i128);
    assert!(rns_less_than((x%m,x%(m+1)),(y%m,y%(m+1)),m));
    assert!(!(x<y)); // outside lower-half domain; expected disagreement
}
