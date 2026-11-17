// Reproduce the uploaded BandInteger representation mismatch without modifying it.
#[path = "../archives/14-Crate-12/band_add.rs"]
mod band;

fn main() {
    let a = band::WASSAN_MODULI[0] as u128 - 1;
    let b = 1;
    let got = band::band_add_checked(
        &band::band_integer_from_u128(a),
        &band::band_integer_from_u128(b),
    ).unwrap();
    let expected = ((a + b) % band::WASSAN_MODULI[1] as u128) as u64;
    println!("source=Crate-12/band_add.rs, a={a}, b={b}, band=1, got={}, expected={expected}", got.bands[1]);
    assert_eq!(got.bands[1], expected + 1);
    assert_ne!(got.bands[1], expected);
    println!("Confirmed: a positional carry corrupts the documented independent-residue encoding.");
}
