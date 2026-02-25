#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use nine65::prelude::*;

#[derive(Arbitrary, Debug)]
struct NTTInput {
    // Polynomial coefficients (will be reduced mod q)
    coeffs: Vec<u64>,
}

// Fuzz NTT/INTT roundtrip
// This verifies that for any polynomial:
// - NTT(INTT(poly)) == poly
// - INTT(NTT(poly)) == poly
// - No panics on edge cases
fuzz_target!(|input: NTTInput| {
    let config = FHEConfig::standard_128_insecure();
    let ntt = NTTEngine::new(config.q, config.n);

    // Take at most n coefficients
    let n = config.n;
    let mut poly: Vec<u64> = input.coeffs
        .iter()
        .take(n)
        .map(|&c| c % config.q)
        .collect();

    // Pad to full size if needed
    poly.resize(n, 0);

    // Test forward-inverse roundtrip
    let ntt_result = ntt.ntt(&poly);
    let recovered = ntt.intt(&ntt_result);

    // Verify roundtrip
    for (i, (&orig, &rec)) in poly.iter().zip(recovered.iter()).enumerate() {
        assert_eq!(
            orig, rec,
            "NTT roundtrip failed at index {}: orig={}, recovered={}",
            i, orig, rec
        );
    }

    // Test inverse-forward roundtrip (start from frequency domain)
    let freq_poly = poly.clone();
    let time_domain = ntt.intt(&freq_poly);
    let recovered_freq = ntt.ntt(&time_domain);

    for (i, (&orig, &rec)) in freq_poly.iter().zip(recovered_freq.iter()).enumerate() {
        assert_eq!(
            orig, rec,
            "INTT-NTT roundtrip failed at index {}: orig={}, recovered={}",
            i, orig, rec
        );
    }
});
