//! RETIRED MECHANISM — Shadow Butterfly Noise Injection (SBNI)
//!
//! **This file is not part of the module tree.** `pub mod sbni;` was removed
//! from `crates/nine65/src/ops/mod.rs`; nothing here compiles into the crate.
//! It is kept on disk as the record of a dropped mechanism, per
//! `docs/RETIRED_MECHANISMS.md` §5 (a silent delete is not acceptable).
//!
//! Dropped per explicit author decision. SBNI was a purely additive masking
//! layer — not a representation transform and not a correctness mechanism. It
//! had exactly one production call site, `mul_dual_public` Step 3.5 in
//! `ops/rns_fhe.rs`, which has been removed.
//!
//! Three reasons the removal is observationally safe:
//!
//! 1. STRUCTURAL. `inject_dual_in_place` only performed
//!    `poly.main[i][k] += e` and `poly.anchor[i][k] += e` with the *same*
//!    integer epsilon in every lane. It added no lane, dropped no lane,
//!    reordered nothing and rescaled nothing, and it touched `c0` only. No
//!    code anywhere read a value it produced.
//!
//! 2. NUMERICAL. Injection ran immediately *before* the K-Elimination rescale
//!    by `Delta = M_level / t` (100+ bits for secure_128), while
//!    `|epsilon| <= SBNI_BOUND = 20`. So `round((v + eps)/Delta)` differed
//!    from `round(v/Delta)` only with probability ~40/2^100. SBNI was already
//!    a no-op on the emitted ciphertext.
//!
//! 3. CRYPTOGRAPHIC. The claimed "zero-marginal-cost butterfly entropy" was
//!    harvested by running an NTT over the hardcoded constant
//!    `vec![123u64; n]` through fixed twiddles, producing an identical shadow
//!    vector on every call. The only varying hash input was `tau`, a monotonic
//!    counter from 0. No secret key, no RNG, no ciphertext-dependent material,
//!    and blake3 unkeyed. Epsilon was therefore a deterministic, publicly
//!    recomputable function of the operation index — an adversary reproduces
//!    it exactly, so it masked nothing.
//!
//! The original module doc claimed SBNI "rerandomizes accumulated
//! deterministic noise drift", provides "timing side-channel immunity" and
//! "strengthens IND-CPA security". None of those were delivered by this
//! implementation. Downstream documents still asserting SBNI as a live
//! security control (README.md, docs/ENTROPY_MODEL.md,
//! docs/SIDE_CHANNEL_THREAT_MODEL.md T5, docs/CLAIM_EVIDENCE_LEDGER.md,
//! docs/CRAM_RLWE_SECURITY_ASSESSMENT_2026-06-03.md §3.2 "Option B") need
//! those claims retired, not merely re-pointed.
//!
//! It was also the crash site: `inject_dual_in_place` indexed `poly.main[i]`
//! while iterating the *full* `config.primes`, which panicked out of bounds
//! once the auto modulus-switch in `mul_dual_public` Step 5 had shortened
//! `poly.main`. Both the injection and that auto-switch are now gone.
//!
//! Five tests retired with this file: `test_injection_poly_bounded`,
//! `test_injection_preserves_correctness`, `test_injection_stochastic`, and
//! the two bare module-scope tests `test_blake3_uniformity` and
//! `test_blake3_serial_correlation` (which sit *outside* the `mod tests`
//! block). All five passed at the time of retirement; they tested the
//! mechanism's own internals and have no replacement, because the mechanism
//! has none.

use crate::ring::RingPolynomial;
use crate::ops::rns_fhe::DualRNSPoly;

/// B = 6σ = 6 * 3.2 ≈ 20 (conservative integer bound)
pub const SBNI_BOUND: u64 = 20;

/// Generate injection polynomial ε from butterfly quotients.
///
/// Mapping: M_B: {0,1}^256 -> [-B, B]
pub fn generate_injection_poly(
    q_bfly: &[u64],       // NTT butterfly Montgomery quotients
    tau: u64,             // computation step counter
    n: usize,             // polynomial degree
    q: u64,               // ciphertext modulus
    num_lanes: u8,        // RNS lane count
) -> RingPolynomial {
    let mut coeffs = vec![0u64; n];
    for k in 0..n {
        let lane_id = (k % num_lanes as usize) as u8;
        let gro_nonce = gro_tick(lane_id, tau);

        // xi_{k,l,tau} = BLAKE3( l || tau || q_bfly[k] || gro_nonce )
        let xi = blake3_hash_4(lane_id, tau, q_bfly[k % q_bfly.len()], gro_nonce);

        // Map 256-bit hash to [-B, B]
        let raw = u64::from_le_bytes(xi[0..8].try_into().unwrap());
        let coeff_signed = (raw % (2 * SBNI_BOUND + 1)) as i64 - SBNI_BOUND as i64;

        // Convert to mod q
        coeffs[k] = if coeff_signed >= 0 {
            coeff_signed as u64 % q
        } else {
            q - ((-coeff_signed) as u64 % q)
        };
    }
    RingPolynomial::from_coeffs(coeffs, q)
}

/// Apply SBNI injection to a DualRNS polynomial: ct_0 += ε(x) mod q
///
/// Injects noise into both main and anchor tracks to preserve K-Elimination invariants.
pub fn inject_dual_in_place(
    poly: &mut DualRNSPoly,
    q_bfly: &[u64],
    tau: u64,
    main_moduli: &[u64],
    anchor_moduli: &[u64],
) {
    let n = poly.n;
    let num_main = main_moduli.len();
    let num_anchor = anchor_moduli.len();

    // We want the SAME noise polynomial injected across all RNS lanes
    // to maintain the property that it represents a single integer polynomial.

    // Use a fixed modulus for the symbolic injection polynomial generation,
    // then reduce it for each lane. We pick a value larger than any B, but
    // the actual values are [-B, B], so any q > 2B works.
    // We'll just generate the signed coefficients once.

    let mut epsilon_coeffs = vec![0i64; n];
    for k in 0..n {
        let lane_id = (k % (num_main + num_anchor)) as u8;
        let gro_nonce = gro_tick(lane_id, tau);
        let xi = blake3_hash_4(lane_id, tau, q_bfly[k % q_bfly.len()], gro_nonce);
        let raw = u64::from_le_bytes(xi[0..8].try_into().unwrap());
        epsilon_coeffs[k] = (raw % (2 * SBNI_BOUND + 1)) as i64 - SBNI_BOUND as i64;
    }

    // Add to main lanes
    for (i, &q) in main_moduli.iter().enumerate() {
        for k in 0..n {
            let e = if epsilon_coeffs[k] >= 0 {
                epsilon_coeffs[k] as u64 % q
            } else {
                q - ((-epsilon_coeffs[k]) as u64 % q)
            };
            poly.main[i][k] = ((poly.main[i][k] as u128 + e as u128) % q as u128) as u64;
        }
    }

    // Add to anchor lanes
    for (i, &a) in anchor_moduli.iter().enumerate() {
        for k in 0..n {
            let e = if epsilon_coeffs[k] >= 0 {
                epsilon_coeffs[k] as u64 % a
            } else {
                a - ((-epsilon_coeffs[k]) as u64 % a)
            };
            poly.anchor[i][k] = ((poly.anchor[i][k] as u128 + e as u128) % a as u128) as u64;
        }
    }
}

/// GRO tick: φ-spaced nonce per lane.
/// GRO_l(tau) = floor( tau * 2^64 / phi^l ) mod 2^64
fn gro_tick(lane_id: u8, tau: u64) -> u64 {
    // 1/phi ≈ 0.618033988749895
    // 2^64 / phi ≈ 11400714819323198485
    const PHI_INV_2_64: u64 = 11400714819323198485;
    tau.wrapping_mul(PHI_INV_2_64).wrapping_mul(lane_id as u64 + 1)
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
    use crate::params::SecureConfig;
    use crate::ops::rns_fhe::RNSFHEContext;
    use crate::entropy::ShadowHarvester;

    #[test]
    fn test_injection_poly_bounded() {
        let n = 1024;
        let q = 998244353;
        let q_bfly = vec![12345u64; n];
        let tau = 1;
        let poly = generate_injection_poly(&q_bfly, tau, n, q, 5);

        for &c in &poly.coeffs {
            // Values should be in [0, B] or [q-B, q-1]
            let is_small_pos = c <= SBNI_BOUND;
            let is_small_neg = c >= q - SBNI_BOUND;
            assert!(is_small_pos || is_small_neg, "Coefficient {} out of bound", c);
        }
    }

    #[test]
    fn test_injection_preserves_correctness() {
        let config = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::new(&config);
        let mut rng = ShadowHarvester::with_seed(42);
        let keys = ctx.generate_keys_dual_full(&mut rng);

        let m = 42;
        let mut ct = ctx.encrypt_dual(m, &keys.public_key, &mut rng);

        let q_bfly = vec![1337u64; config.n];
        inject_dual_in_place(
            &mut ct.c0,
            &q_bfly,
            1,
            &config.primes,
            &ctx.dual_rns.anchor.primes
        );

        let decrypted = ctx.decrypt_dual(&ct, &keys.secret_key);
        assert_eq!(decrypted, m, "SBNI corrupted decryption");
    }

    #[test]
    fn test_injection_stochastic() {
        let n = 1024;
        let q = 998244353;
        let mut counts = vec![0usize; (2 * SBNI_BOUND + 1) as usize];

        for tau in 0..100 {
            let q_bfly = vec![tau; n];
            let poly = generate_injection_poly(&q_bfly, tau, n, q, 5);
            for &c in &poly.coeffs {
                let signed = if c <= SBNI_BOUND {
                    c as i64
                } else {
                    -((q - c) as i64)
                };
                counts[(signed + SBNI_BOUND as i64) as usize] += 1;
            }
        }

        // Basic check for distribution - should not be all zeros
        let total: usize = counts.iter().sum();
        assert_eq!(total, n * 100);
        for &count in &counts {
            assert!(count > 0, "Zero count for some value in SBNI distribution");
        }
    }
}

#[test]
fn test_blake3_uniformity() {
    let n = 100000;
    let q = 998244353;
    let mut counts = std::collections::HashMap::new();
    let q_bfly = vec![12345; 1];

    for tau in 0..n {
        let gro_nonce = gro_tick(0, tau as u64);
        let xi = blake3_hash_4(0, tau as u64, q_bfly[0], gro_nonce);
        let raw = u64::from_le_bytes(xi[0..8].try_into().unwrap());
        let coeff_signed = (raw % (2 * SBNI_BOUND + 1)) as i64 - SBNI_BOUND as i64;
        *counts.entry(coeff_signed).or_insert(0usize) += 1;
    }

    let num_bins = (2 * SBNI_BOUND + 1) as f64;
    let expected = n as f64 / num_bins;
    let mut chi_square = 0.0;

    for i in -(SBNI_BOUND as i64)..=(SBNI_BOUND as i64) {
        let count = *counts.get(&i).unwrap_or(&0) as f64;
        chi_square += (count - expected).powi(2) / expected;
    }

    // Degrees of freedom = num_bins - 1 = 40
    // Chi-square critical value for df=40, p=0.05 is ~55.76
    println!("SBNI BLAKE3 Chi-square: {} (expected < 55.76)", chi_square);
    assert!(chi_square < 70.0, "Chi-square too high: {}", chi_square);
}

#[test]
fn test_blake3_serial_correlation() {
    let n = 100000;
    let mut samples = Vec::with_capacity(n);
    let q_bfly = vec![12345; 1];

    for tau in 0..n {
        let gro_nonce = gro_tick(0, tau as u64);
        let xi = blake3_hash_4(0, tau as u64, q_bfly[0], gro_nonce);
        let raw = u64::from_le_bytes(xi[0..8].try_into().unwrap());
        let coeff_signed = (raw % (2 * SBNI_BOUND + 1)) as i64 - SBNI_BOUND as i64;
        samples.push(coeff_signed as f64);
    }

    let mut sum = 0.0;
    for &s in &samples { sum += s; }
    let mean = sum / n as f64;

    let mut num = 0.0;
    let mut den = 0.0;
    for i in 0..(n-1) {
        num += (samples[i] - mean) * (samples[i+1] - mean);
        den += (samples[i] - mean).powi(2);
    }
    den += (samples[n-1] - mean).powi(2);

    let correlation = num / den;
    println!("SBNI BLAKE3 Serial Correlation: {} (expected < 0.01)", correlation);
    assert!(correlation.abs() < 0.01, "Serial correlation too high: {}", correlation);
}
