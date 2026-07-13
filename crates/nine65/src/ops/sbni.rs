//! Shadow Butterfly Noise Injection (SBNI).
//!
//! SBNI deterministically derives a bounded rerandomization polynomial from
//! butterfly-side entropy and injects the same signed polynomial into every
//! main and anchor lane. This preserves the DualRNS representation invariant.
//!
//! SBNI is a hardening layer. Constant-time behavior and IND-CPA security remain
//! separate properties that must be established by their dedicated audits and
//! security reductions.

use crate::ops::rns_fhe::DualRNSPoly;
use crate::ring::RingPolynomial;

/// Conservative signed coefficient bound.
pub const SBNI_BOUND: u64 = 20;

#[inline]
fn validate_generation_inputs(q_bfly: &[u64], n: usize, q: u64, num_lanes: usize) {
    assert!(!q_bfly.is_empty(), "SBNI butterfly source must not be empty");
    assert!(n > 0, "SBNI polynomial degree must be nonzero");
    assert!(num_lanes > 0, "SBNI lane count must be nonzero");
    assert!(
        q > 2 * SBNI_BOUND,
        "SBNI modulus must exceed twice the signed injection bound"
    );
}

#[inline]
fn signed_to_mod(value: i64, modulus: u64) -> u64 {
    if value >= 0 {
        value as u64 % modulus
    } else {
        let magnitude = (-value) as u64 % modulus;
        if magnitude == 0 {
            0
        } else {
            modulus - magnitude
        }
    }
}

/// Generate a bounded injection polynomial from butterfly quotients.
///
/// # Panics
///
/// Panics on an empty entropy source, zero degree, zero lane count, or a
/// modulus too small to represent the full signed injection interval. These are
/// construction-time invariant violations rather than data-dependent branches.
pub fn generate_injection_poly(
    q_bfly: &[u64],
    tau: u64,
    n: usize,
    q: u64,
    num_lanes: u8,
) -> RingPolynomial {
    validate_generation_inputs(q_bfly, n, q, num_lanes as usize);

    let mut coeffs = vec![0u64; n];
    for (k, coefficient) in coeffs.iter_mut().enumerate() {
        let lane_id = (k % num_lanes as usize) as u8;
        let gro_nonce = gro_tick(lane_id, tau);
        let xi = blake3_hash_4(lane_id, tau, q_bfly[k % q_bfly.len()], gro_nonce);
        let raw = u64::from_le_bytes(xi[0..8].try_into().expect("fixed BLAKE3 prefix"));
        let signed = (raw % (2 * SBNI_BOUND + 1)) as i64 - SBNI_BOUND as i64;
        *coefficient = signed_to_mod(signed, q);
    }

    RingPolynomial::from_coeffs(coeffs, q)
}

/// Apply one signed injection polynomial to every DualRNS lane.
///
/// The same integer coefficient is reduced independently modulo each main and
/// anchor prime. This keeps the main and anchor tracks phase-consistent for
/// subsequent K-Elimination and avoids any residue-to-number-line conversion.
///
/// # Panics
///
/// Panics when the polynomial shape, modulus vectors, or entropy source are
/// inconsistent. Silent truncation is prohibited because it would break the
/// DualRNS invariant and could reintroduce anchor drift.
pub fn inject_dual_in_place(
    poly: &mut DualRNSPoly,
    q_bfly: &[u64],
    tau: u64,
    main_moduli: &[u64],
    anchor_moduli: &[u64],
) {
    let n = poly.n;
    let total_lanes = main_moduli.len() + anchor_moduli.len();
    validate_generation_inputs(q_bfly, n, 2 * SBNI_BOUND + 1, total_lanes);

    assert_eq!(
        poly.main.len(),
        main_moduli.len(),
        "SBNI main-limb count must match the main modulus count"
    );
    assert_eq!(
        poly.anchor.len(),
        anchor_moduli.len(),
        "SBNI anchor-limb count must match the anchor modulus count"
    );

    for (&modulus, limb) in main_moduli.iter().zip(poly.main.iter()) {
        assert!(
            modulus > 2 * SBNI_BOUND,
            "SBNI main modulus must exceed twice the injection bound"
        );
        assert_eq!(limb.len(), n, "SBNI main limb length must equal poly.n");
    }
    for (&modulus, limb) in anchor_moduli.iter().zip(poly.anchor.iter()) {
        assert!(
            modulus > 2 * SBNI_BOUND,
            "SBNI anchor modulus must exceed twice the injection bound"
        );
        assert_eq!(
            limb.len(),
            n,
            "SBNI anchor limb length must equal poly.n"
        );
    }

    let mut epsilon_coeffs = vec![0i64; n];
    for (k, coefficient) in epsilon_coeffs.iter_mut().enumerate() {
        let lane_id = (k % total_lanes) as u8;
        let gro_nonce = gro_tick(lane_id, tau);
        let xi = blake3_hash_4(lane_id, tau, q_bfly[k % q_bfly.len()], gro_nonce);
        let raw = u64::from_le_bytes(xi[0..8].try_into().expect("fixed BLAKE3 prefix"));
        *coefficient = (raw % (2 * SBNI_BOUND + 1)) as i64 - SBNI_BOUND as i64;
    }

    for (limb, &modulus) in poly.main.iter_mut().zip(main_moduli.iter()) {
        for (coefficient, &epsilon) in limb.iter_mut().zip(epsilon_coeffs.iter()) {
            let e = signed_to_mod(epsilon, modulus);
            *coefficient = ((*coefficient as u128 + e as u128) % modulus as u128) as u64;
        }
    }

    for (limb, &modulus) in poly.anchor.iter_mut().zip(anchor_moduli.iter()) {
        for (coefficient, &epsilon) in limb.iter_mut().zip(epsilon_coeffs.iter()) {
            let e = signed_to_mod(epsilon, modulus);
            *coefficient = ((*coefficient as u128 + e as u128) % modulus as u128) as u64;
        }
    }
}

/// Integer-only phi-spaced nonce per lane.
fn gro_tick(lane_id: u8, tau: u64) -> u64 {
    const PHI_INV_2_64: u64 = 11_400_714_819_323_198_485;
    tau.wrapping_mul(PHI_INV_2_64)
        .wrapping_mul(lane_id as u64 + 1)
}

fn blake3_hash_4(lane: u8, tau: u64, q_bfly: u64, nonce: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[lane]);
    hasher.update(&tau.to_le_bytes());
    hasher.update(&q_bfly.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::ShadowHarvester;
    use crate::ops::rns_fhe::RNSFHEContext;
    use crate::params::SecureConfig;

    #[test]
    fn test_injection_poly_bounded() {
        let n = 1024;
        let q = 998_244_353;
        let q_bfly = vec![12_345u64; n];
        let poly = generate_injection_poly(&q_bfly, 1, n, q, 5);

        for &coefficient in &poly.coeffs {
            let is_small_positive = coefficient <= SBNI_BOUND;
            let is_small_negative = coefficient >= q - SBNI_BOUND;
            assert!(
                is_small_positive || is_small_negative,
                "coefficient {coefficient} exceeds the SBNI bound"
            );
        }
    }

    #[test]
    fn test_injection_preserves_correctness() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::new(&config);
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        let message = 42;
        let mut ciphertext = ctx.encrypt_dual(message, &keys.public_key, &mut rng);
        let q_bfly = vec![1337u64; config.n];

        inject_dual_in_place(
            &mut ciphertext.c0,
            &q_bfly,
            1,
            &config.primes,
            &ctx.dual_rns.anchor.primes,
        );

        assert_eq!(
            ctx.decrypt_dual(&ciphertext, &keys.secret_key),
            message,
            "SBNI corrupted decryption"
        );
    }

    #[test]
    fn test_injection_stochastic_support() {
        let n = 1024;
        let q = 998_244_353;
        let mut counts = vec![0usize; (2 * SBNI_BOUND + 1) as usize];

        for tau in 0..100 {
            let q_bfly = vec![tau; n];
            let poly = generate_injection_poly(&q_bfly, tau, n, q, 5);
            for &coefficient in &poly.coeffs {
                let signed = if coefficient <= SBNI_BOUND {
                    coefficient as i64
                } else {
                    -((q - coefficient) as i64)
                };
                counts[(signed + SBNI_BOUND as i64) as usize] += 1;
            }
        }

        assert_eq!(counts.iter().sum::<usize>(), n * 100);
        assert!(counts.iter().all(|&count| count > 0));
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn empty_butterfly_source_is_rejected() {
        let _ = generate_injection_poly(&[], 0, 16, 97, 1);
    }

    #[test]
    #[should_panic(expected = "main-limb count")]
    fn mismatched_main_shape_is_rejected() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::new(&config);
        let mut rng = ShadowHarvester::with_seed(7);
        let keys = ctx.generate_keys_dual_full(&mut rng);
        let mut ciphertext = ctx.encrypt_dual(1, &keys.public_key, &mut rng);
        let too_few_moduli = &config.primes[..config.primes.len() - 1];
        inject_dual_in_place(
            &mut ciphertext.c0,
            &[1],
            1,
            too_few_moduli,
            &ctx.dual_rns.anchor.primes,
        );
    }

    #[test]
    fn test_blake3_uniformity_integer_only() {
        let samples: u64 = 100_000;
        let bins = 2 * SBNI_BOUND + 1;
        let mut counts = vec![0u64; bins as usize];

        for tau in 0..samples {
            let nonce = gro_tick(0, tau);
            let xi = blake3_hash_4(0, tau, 12_345, nonce);
            let raw = u64::from_le_bytes(xi[0..8].try_into().expect("fixed BLAKE3 prefix"));
            counts[(raw % bins) as usize] += 1;
        }

        // chi_square = sum((count - samples/bins)^2 / (samples/bins)).
        // Avoid rational division by comparing the exactly scaled numerator:
        // sum((bins*count - samples)^2) < 70 * samples * bins.
        let numerator = counts.iter().fold(0u128, |acc, &count| {
            let signed_delta = bins as i128 * count as i128 - samples as i128;
            acc + (signed_delta * signed_delta) as u128
        });
        let upper_bound = 70u128 * samples as u128 * bins as u128;

        assert!(
            numerator < upper_bound,
            "scaled chi-square numerator {numerator} exceeded bound {upper_bound}"
        );
    }
}
