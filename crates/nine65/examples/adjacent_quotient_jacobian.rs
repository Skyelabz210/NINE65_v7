//! Research probe for the CRAM p-to-p² hidden quotient carry.
//!
//! The evaluator-style adjacent K-Elimination quotients recover the winding
//! without enumerating ternary support words. The final correction below is
//! intentionally a key-holder oracle control: it supplies one clean
//! high-scale encryption of J, but does not implement the live Safe-Basis
//! producer required for public refresh. Parameters are unadmitted.

use nine65::arithmetic::canonical_scale_round::CanonicalScaleRound;
use nine65::arithmetic::main_only_base_ext::MainOnlyBaseExt;
use nine65::arithmetic::rns::{RNSPolynomial, U512};
use nine65::entropy::ShadowHarvester;
use nine65::ops::rns_fhe::{RNSCiphertext, RNSFHEContext, RNSPublicKey, RNSSecretKey};
use nine65::params::primes::extended_gcd;
use nine65::params::secure_configs::SecureConfig;

const P: u64 = 65_537;
const K_BOUND: i64 = 8_193;
const FULL_BOUND_PJ_FACTOR: u64 = 16_390;
const FULL_BOUND_PJ_TRAY: u64 = FULL_BOUND_PJ_FACTOR * (P + 1);

fn inverse(a: u64, modulus: u64) -> u64 {
    let (gcd, x, _) = extended_gcd(a as i128, modulus as i128);
    assert_eq!(gcd, 1);
    x.rem_euclid(modulus as i128) as u64
}

fn ordinary(ctx: &RNSFHEContext, poly: &RNSPolynomial) -> Vec<Vec<u64>> {
    poly.limbs
        .iter()
        .enumerate()
        .map(|(lane, values)| {
            values
                .iter()
                .map(|&value| ctx.rns.mont_contexts[lane].from_montgomery(value))
                .collect()
        })
        .collect()
}

fn montgomery(ctx: &RNSFHEContext, values: Vec<Vec<u64>>) -> RNSPolynomial {
    RNSPolynomial {
        n: ctx.n,
        limbs: values
            .into_iter()
            .enumerate()
            .map(|(lane, values)| {
                values
                    .into_iter()
                    .map(|value| ctx.rns.mont_contexts[lane].to_montgomery(value))
                    .collect()
            })
            .collect(),
    }
}

/// Exact centered coefficient quotient `(x - (x mod d)_centered) / d`.
/// This is the same component operation as the research K-Elimination lift.
fn centered_component_quotient(
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    divisor: u64,
) -> RNSCiphertext {
    let projector = MainOnlyBaseExt::new(&ctx.config.primes, &[divisor]).unwrap();
    let divide = |poly: &RNSPolynomial| {
        let source = ordinary(ctx, poly);
        let inverses: Vec<_> = ctx
            .config
            .primes
            .iter()
            .map(|&q| inverse(divisor % q, q))
            .collect();
        let mut output = vec![vec![0; ctx.n]; ctx.config.primes.len()];
        for coefficient in 0..ctx.n {
            let residues: Vec<_> = source.iter().map(|lane| lane[coefficient]).collect();
            let mut remainder = [0u64];
            projector
                .project_centered(&residues, &mut remainder)
                .unwrap();
            let centered_remainder = if remainder[0] > divisor / 2 {
                remainder[0] as i128 - divisor as i128
            } else {
                remainder[0] as i128
            };
            for (lane, (&q, &inv)) in ctx.config.primes.iter().zip(&inverses).enumerate() {
                let numerator =
                    (residues[lane] as i128 - centered_remainder).rem_euclid(q as i128) as u128;
                output[lane][coefficient] = (numerator * inv as u128 % q as u128) as u64;
            }
        }
        montgomery(ctx, output)
    };
    RNSCiphertext {
        c0: divide(&ct.c0),
        c1: divide(&ct.c1),
        num_primes: ct.num_primes,
    }
}

fn scale(ctx: &RNSFHEContext, ct: &RNSCiphertext, scalar: u64) -> RNSCiphertext {
    let apply = |poly: &RNSPolynomial| RNSPolynomial {
        n: ctx.n,
        limbs: poly
            .limbs
            .iter()
            .zip(&ctx.config.primes)
            .map(|(values, &q)| {
                values
                    .iter()
                    .map(|&value| (value as u128 * scalar as u128 % q as u128) as u64)
                    .collect()
            })
            .collect(),
    };
    RNSCiphertext {
        c0: apply(&ct.c0),
        c1: apply(&ct.c1),
        num_primes: ct.num_primes,
    }
}

fn centered(value: i128, modulus: u64) -> i128 {
    let residue = value.rem_euclid(modulus as i128);
    if residue > (modulus / 2) as i128 {
        residue - modulus as i128
    } else {
        residue
    }
}

/// Client-side observer used only by this research example.
fn decrypt_coefficients(
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    secret: &RNSSecretKey,
) -> Vec<i128> {
    let c0 = ordinary(ctx, &ct.c0);
    let c1 = ordinary(ctx, &ct.c1);
    let secret = ordinary(ctx, &secret.s);
    let mut phase = vec![vec![0; ctx.n]; ctx.config.primes.len()];
    for lane in 0..ctx.config.primes.len() {
        let product = ctx.ntt_engines[lane].multiply(&c1[lane], &secret[lane]);
        let q = ctx.config.primes[lane];
        for coefficient in 0..ctx.n {
            phase[lane][coefficient] = (c0[lane][coefficient] + product[coefficient]) % q;
        }
    }
    let decoder = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
    (0..ctx.n)
        .map(|coefficient| {
            let residues: Vec<_> = phase.iter().map(|lane| lane[coefficient]).collect();
            decoder.scale_round(&residues).unwrap() as i128
        })
        .collect()
}

fn words(value: U512) -> (u128, u128, u128, u128) {
    (value.d3, value.d2, value.d1, value.d0)
}

fn abs_diff(left: U512, right: U512) -> U512 {
    if words(left) >= words(right) {
        left.sub(right)
    } else {
        right.sub(left)
    }
}

fn bits(value: U512) -> u32 {
    for (limb, offset) in [
        (value.d3, 384),
        (value.d2, 256),
        (value.d1, 128),
        (value.d0, 0),
    ] {
        if limb != 0 {
            return offset + 128 - limb.leading_zeros();
        }
    }
    0
}

fn bit(value: U512, index: u32) -> u64 {
    let limb = match index / 128 {
        0 => value.d0,
        1 => value.d1,
        2 => value.d2,
        3 => value.d3,
        _ => 0,
    };
    ((limb >> (index % 128)) & 1) as u64
}

fn set_bit(value: &mut U512, index: u32) {
    let mask = 1u128 << (index % 128);
    match index / 128 {
        0 => value.d0 |= mask,
        1 => value.d1 |= mask,
        2 => value.d2 |= mask,
        3 => value.d3 |= mask,
        _ => unreachable!("U512 bit index"),
    }
}

fn shl_one(value: U512) -> U512 {
    U512 {
        d0: value.d0 << 1,
        d1: (value.d1 << 1) | (value.d0 >> 127),
        d2: (value.d2 << 1) | (value.d1 >> 127),
        d3: (value.d3 << 1) | (value.d2 >> 127),
    }
}

fn div_mod_u512(numerator: U512, denominator: U512) -> (U512, U512) {
    assert_ne!(words(denominator), (0, 0, 0, 0));
    let mut quotient = U512::zero();
    let mut remainder = U512::zero();
    for index in (0..bits(numerator)).rev() {
        remainder = shl_one(remainder);
        remainder.d0 |= bit(numerator, index) as u128;
        if words(remainder) >= words(denominator) {
            remainder = remainder.sub(denominator);
            set_bit(&mut quotient, index);
        }
    }
    (quotient, remainder)
}

fn client_crt(ctx: &RNSFHEContext, residues: &[u64]) -> U512 {
    let (mut value, mut product) = (U512::zero(), U512::from_u64(1));
    for (&residue, &q) in residues.iter().zip(&ctx.config.primes) {
        let digit = ((residue as u128 + q as u128 - value.mod_u64(q) as u128)
            * inverse(product.mod_u64(q), q) as u128
            % q as u128) as u64;
        value = value.add(product.mul_u128(digit as u128));
        product = product.mul_u128(q as u128);
    }
    value
}

/// Public integer wrap counts for multiplying a ciphertext component by a
/// scalar before reducing its full CRT representative modulo Q.
fn scale_wraps(ctx: &RNSFHEContext, poly: &RNSPolynomial, scalar: u64) -> Vec<u64> {
    let source = ordinary(ctx, poly);
    let q = U512::product_u64s(&ctx.config.primes);
    (0..ctx.n)
        .map(|coefficient| {
            let residues: Vec<_> = source.iter().map(|lane| lane[coefficient]).collect();
            let value = client_crt(ctx, &residues);
            let (mut wrap, scaled_remainder) = div_mod_u512(value.mul_u128(scalar as u128), q);
            // MainOnlyBaseExt divides the centered CRT representative. If the
            // scaled CRT remainder is in Q's upper half, centering y subtracts
            // Q and increments the wrap count. The input representative can
            // also be centered, but that changes the count by exactly scalar.
            if words(scaled_remainder) > words(q.div_u64(2)) {
                wrap = wrap.add(U512::from_u64(1));
            }
            assert_eq!((wrap.d3, wrap.d2, wrap.d1), (0, 0, 0));
            (wrap.d0 as u64) % scalar
        })
        .collect()
}

/// Client-only decoder for arbitrary target moduli, including even trays.
/// `CanonicalScaleRound` deliberately keeps its odd-target contract.
fn decrypt_coefficients_any_t(
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    secret: &RNSSecretKey,
) -> Vec<i128> {
    let c0 = ordinary(ctx, &ct.c0);
    let c1 = ordinary(ctx, &ct.c1);
    let secret = ordinary(ctx, &secret.s);
    let mut phase = vec![vec![0; ctx.n]; ctx.config.primes.len()];
    for lane in 0..ctx.config.primes.len() {
        let product = ctx.ntt_engines[lane].multiply(&c1[lane], &secret[lane]);
        let q = ctx.config.primes[lane];
        for coefficient in 0..ctx.n {
            phase[lane][coefficient] = (c0[lane][coefficient] + product[coefficient]) % q;
        }
    }
    let q = U512::product_u64s(&ctx.config.primes);
    (0..ctx.n)
        .map(|coefficient| {
            let residues: Vec<_> = phase.iter().map(|lane| lane[coefficient]).collect();
            let phase = client_crt(ctx, &residues);
            let numerator = phase.mul_u128(ctx.t as u128).add(q.div_u64(2));
            let (rounded, _) = div_mod_u512(numerator, q);
            assert_eq!((rounded.d3, rounded.d2, rounded.d1), (0, 0, 0));
            centered((rounded.d0 as u64 % ctx.t) as i128, ctx.t)
        })
        .collect()
}

fn phase_error_bound(
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    secret: &RNSSecretKey,
    message: &[i64],
) -> U512 {
    let c0 = ordinary(ctx, &ct.c0);
    let c1 = ordinary(ctx, &ct.c1);
    let secret = ordinary(ctx, &secret.s);
    let mut phases = vec![vec![0; ctx.n]; ctx.config.primes.len()];
    for lane in 0..ctx.config.primes.len() {
        let product = ctx.ntt_engines[lane].multiply(&c1[lane], &secret[lane]);
        let q = ctx.config.primes[lane];
        for coefficient in 0..ctx.n {
            phases[lane][coefficient] = (c0[lane][coefficient] + product[coefficient]) % q;
        }
    }
    let q = U512::product_u64s(&ctx.config.primes);
    let period = q.mul_u128(ctx.t as u128);
    let mut maximum = U512::zero();
    for coefficient in 0..ctx.n {
        let residues: Vec<_> = phases.iter().map(|lane| lane[coefficient]).collect();
        let phase = client_crt(ctx, &residues);
        let encoded = q.mul_u128(message[coefficient].rem_euclid(ctx.t as i64) as u128);
        let error = abs_diff(phase.mul_u128(ctx.t as u128), encoded);
        let error = if words(error) > words(period.div_u64(2)) {
            period.sub(error)
        } else {
            error
        };
        if words(error) > words(maximum) {
            maximum = error;
        }
    }
    maximum
}

fn encode_centered_polynomial(ctx: &RNSFHEContext, values: &[i64]) -> RNSPolynomial {
    let limbs = ctx
        .config
        .primes
        .iter()
        .enumerate()
        .map(|(lane, &q)| {
            values
                .iter()
                .map(|&value| {
                    (value.rem_euclid(ctx.t as i64) as u128 * ctx.delta_rns[lane] as u128
                        % q as u128) as u64
                })
                .collect()
        })
        .collect();
    montgomery(ctx, limbs)
}

/// Exercise the adjacent K-Elimination consumer when the p+1 sister tray is
/// available as a common-target ciphertext. The tray value itself is supplied
/// by a client-side control here; this does not implement the live Safe-Basis
/// producer.
fn run_inverse_residual_control(
    input_ctx: &RNSFHEContext,
    encrypted_k: &RNSCiphertext,
    public_key: &RNSPublicKey,
    secret_key: &RNSSecretKey,
    plaintext: &[i64],
) {
    let m = P + 1;
    let scale_factor = FULL_BOUND_PJ_TRAY;
    let required_t = 2 * scale_factor as u128 * K_BOUND as u128 + 1;
    let min_divisor = required_t.div_ceil(P as u128);
    // Choosing the high target as T=p*s with s == 1 mod (p+1) makes
    // T == -1 mod (p+1), hence (p+1)^-1 mod T is exactly (T+1)/(p+1).
    // The congruence lets the composite modulus be budgeted without making
    // p+1 a factor of the output plaintext modulus.
    let divisor_step = (min_divisor - 1).div_ceil(m as u128);
    let divisor = (divisor_step * m as u128 + 1) as u64;
    let target_t = P * divisor;
    let inverse_m = (target_t + 1) / m;
    assert_eq!(target_t % m, m - 1);
    assert_eq!((m as u128 * inverse_m as u128) % target_t as u128, 1);
    assert!(2 * scale_factor as u128 * (K_BOUND as u128) < target_t as u128);

    let mut high_config = input_ctx.config.clone();
    high_config.t = target_t;
    high_config.name = "UNADMITTED adjacent inverse-residual control";
    let high_ctx = RNSFHEContext::try_new(&high_config).unwrap();
    let lifted = centered_component_quotient(input_ctx, encrypted_k, divisor);
    let lifted_values = decrypt_coefficients(&high_ctx, &lifted, secret_key);

    let mut winding = Vec::with_capacity(input_ctx.n);
    let mut residual = Vec::with_capacity(input_ctx.n);
    let mut max_abs_winding = 0i128;
    for (coefficient, (&lifted_value, &k)) in lifted_values.iter().zip(plaintext).enumerate() {
        let difference = centered(lifted_value - k as i128, target_t);
        assert_eq!(
            difference % P as i128,
            0,
            "p-winding at coefficient {coefficient}"
        );
        let j = difference / P as i128;
        assert!(j.unsigned_abs() <= (input_ctx.n / 2 + 1) as u128);
        // The M-residue is a same-history sister view. Reducing the centered
        // T representative would be invalid because gcd(T,M)=1 and that
        // representative can differ from the lifted integer by a T winding.
        let r = centered(k as i128 - j, m);
        assert!(r.unsigned_abs() <= K_BOUND as u128 + (input_ctx.n / 2 + 1) as u128);
        max_abs_winding = max_abs_winding.max(j.abs());
        winding.push(j as i64);
        residual.push(r as i64);
    }
    let scaled_expected: Vec<i64> = plaintext.iter().map(|&k| k * scale_factor as i64).collect();

    // Adjacent-scale tray: because T+1=M*u, u*Delta_T is within one
    // rounding cell of Delta_M. Reinterpreting u*C under M should expose the
    // same-history residual r without a separate encryption.
    let mut residual_config = input_ctx.config.clone();
    residual_config.t = m;
    residual_config.name = "UNADMITTED adjacent p+1 sister view";
    let residual_ctx = RNSFHEContext::try_new(&residual_config).unwrap();
    let residual_view = scale(&high_ctx, &lifted, inverse_m);
    let residual_view_values =
        decrypt_coefficients_any_t(&residual_ctx, &residual_view, secret_key);
    let residual_view_mismatches = residual_view_values
        .iter()
        .zip(&residual)
        .filter(|(actual, expected)| centered(**actual, m) != **expected as i128)
        .count();

    // The reverse component quotient is deliberately retained as a separate
    // K-Elimination probe: it may reintroduce an M-multiple winding.
    let lifted_residual_view =
        centered_component_quotient(&residual_ctx, &residual_view, inverse_m);
    let lifted_residual_values = decrypt_coefficients(&high_ctx, &lifted_residual_view, secret_key);
    let mut lifted_residual_mismatches = 0usize;
    let mut lifted_residual_nonmultiples = 0usize;
    let mut max_lifted_residual_winding = 0i128;
    for (&actual, &expected) in lifted_residual_values.iter().zip(&residual) {
        let delta = centered(actual - expected as i128, target_t);
        lifted_residual_mismatches += usize::from(delta != 0);
        lifted_residual_nonmultiples += usize::from(delta % m as i128 != 0);
        if delta % m as i128 == 0 {
            max_lifted_residual_winding =
                max_lifted_residual_winding.max((delta / m as i128).abs());
        }
    }

    // Test-only root output: a real Safe-Basis producer must emit this
    // same-history r=C mod(p+1) view at the common T encoding.
    let mut residual_rng = ShadowHarvester::with_seed(0x5245_5349_4455_414c);
    let mut encrypted_residual = high_ctx.encrypt_with_rng(0, public_key, &mut residual_rng);
    encrypted_residual.c0 = encrypted_residual.c0.add(
        &encode_centered_polynomial(&high_ctx, &residual),
        &high_ctx.rns,
    );

    // A second control keeps the sister tray at its own plaintext M. Align
    // both BFV scales to Q, subtract the same-history values, then divide the
    // resulting Q*M*J phase by T*M. This tests whether one M-tray root can
    // feed the common-T correction without first lifting r to T.
    let mut residual_m_rng = ShadowHarvester::with_seed(0x4d5f_524f_4f54_0001);
    let mut encrypted_residual_m =
        residual_ctx.encrypt_with_rng(0, public_key, &mut residual_m_rng);
    encrypted_residual_m.c0 = encrypted_residual_m.c0.add(
        &encode_centered_polynomial(&residual_ctx, &residual),
        &residual_ctx.rns,
    );
    let aligned_numerator = high_ctx.sub(
        &scale(&high_ctx, &lifted, target_t),
        &scale(&residual_ctx, &encrypted_residual_m, m),
    );
    let common_t_j = centered_component_quotient(&high_ctx, &aligned_numerator, target_t * m);
    let common_t_j_values = decrypt_coefficients(&high_ctx, &common_t_j, secret_key);
    let common_t_j_mismatches = common_t_j_values
        .iter()
        .zip(&winding)
        .filter(|(actual, expected)| centered(**actual, target_t) != **expected as i128)
        .count();
    let common_t_corrected = high_ctx.sub(&lifted, &scale(&high_ctx, &common_t_j, P));
    let common_t_corrected_values =
        decrypt_coefficients(&high_ctx, &common_t_corrected, secret_key);
    let common_t_k_mismatches = common_t_corrected_values
        .iter()
        .zip(plaintext)
        .filter(|(actual, expected)| centered(**actual, target_t) != **expected as i128)
        .count();
    let common_t_scaled = scale(&high_ctx, &common_t_corrected, scale_factor);
    let common_t_scaled_values = decrypt_coefficients(&high_ctx, &common_t_scaled, secret_key);
    let common_t_scaled_mismatches = common_t_scaled_values
        .iter()
        .zip(&scaled_expected)
        .filter(|(actual, expected)| centered(**actual, target_t) != **expected as i128)
        .count();
    let common_t_j_error = phase_error_bound(&high_ctx, &common_t_j, secret_key, &winding);
    let common_t_k_error = phase_error_bound(&high_ctx, &common_t_corrected, secret_key, plaintext);
    let common_t_scaled_error =
        phase_error_bound(&high_ctx, &common_t_scaled, secret_key, &scaled_expected);

    let difference = high_ctx.sub(&lifted, &encrypted_residual);
    let encrypted_j = scale(&high_ctx, &difference, inverse_m);
    let j_values = decrypt_coefficients(&high_ctx, &encrypted_j, secret_key);
    let j_mismatches = j_values
        .iter()
        .zip(&winding)
        .filter(|(actual, expected)| centered(**actual, target_t) != **expected as i128)
        .count();

    // Because p=(p+1)-1, C-pJ = r+J. Both forms should agree; the first is
    // the existing consumer equation, while the second exposes the small
    // adjacent Jacobian directly.
    let correction = scale(&high_ctx, &encrypted_j, P);
    let corrected = high_ctx.sub(&lifted, &correction);
    let corrected_values = decrypt_coefficients(&high_ctx, &corrected, secret_key);
    let corrected_mismatches = corrected_values
        .iter()
        .zip(plaintext)
        .filter(|(actual, expected)| centered(**actual, target_t) != **expected as i128)
        .count();
    let sum_form = high_ctx.add(&encrypted_j, &encrypted_residual);
    let sum_values = decrypt_coefficients(&high_ctx, &sum_form, secret_key);
    let sum_mismatches = sum_values
        .iter()
        .zip(plaintext)
        .filter(|(actual, expected)| centered(**actual, target_t) != **expected as i128)
        .count();

    let scaled = scale(&high_ctx, &corrected, scale_factor);
    let scaled_values = decrypt_coefficients(&high_ctx, &scaled, secret_key);
    let scaled_mismatches = scaled_values
        .iter()
        .zip(&scaled_expected)
        .filter(|(actual, expected)| centered(**actual, target_t) != **expected as i128)
        .count();
    let q = U512::product_u64s(&high_config.primes);
    let j_error = phase_error_bound(&high_ctx, &encrypted_j, secret_key, &winding);
    let corrected_error = phase_error_bound(&high_ctx, &corrected, secret_key, plaintext);
    let scaled_error = phase_error_bound(&high_ctx, &scaled, secret_key, &scaled_expected);

    println!(
        "inverse-residual K-Elimination: T=p*s={}, s={}, M=p+1={}, M^-1 mod T={}, inverse bits={}, max |J|={}, adjacent r-view mismatches={}/{}, raw r-to-T mismatches={}/{}, nonmultiples={}, raw winding max={}, J mismatches={}/{}, K correction mismatches={}/{}, r+J mismatches={}/{}, full M_pJ*K mismatches={}/{}, phase-error bits J->K->scaled={}/{}/{}, Q={}, live r-root producer present=false",
        target_t,
        divisor,
        m,
        inverse_m,
        64 - inverse_m.leading_zeros(),
        max_abs_winding,
        residual_view_mismatches,
        input_ctx.n,
        lifted_residual_mismatches,
        input_ctx.n,
        lifted_residual_nonmultiples,
        max_lifted_residual_winding,
        j_mismatches,
        input_ctx.n,
        corrected_mismatches,
        input_ctx.n,
        sum_mismatches,
        input_ctx.n,
        scaled_mismatches,
        input_ctx.n,
        bits(j_error),
        bits(corrected_error),
        bits(scaled_error),
        bits(q),
    );
    println!(
        "M-tray to common-T Jacobian: J mismatches={}/{}, K mismatches={}/{}, full M_pJ*K mismatches={}/{}, phase-error bits J->K->scaled={}/{}/{}, divisor=T*M={}, residual root input is M-encoded=true",
        common_t_j_mismatches,
        input_ctx.n,
        common_t_k_mismatches,
        input_ctx.n,
        common_t_scaled_mismatches,
        input_ctx.n,
        bits(common_t_j_error),
        bits(common_t_k_error),
        bits(common_t_scaled_error),
        target_t * m,
    );
    assert_eq!(j_mismatches, 0);
    assert_eq!(corrected_mismatches, 0);
    assert_eq!(sum_mismatches, 0);
    assert_eq!(scaled_mismatches, 0);
}

fn main() {
    let n = std::env::args()
        .nth(1)
        .map_or(512usize, |arg| arg.parse().expect("degree must be usize"));
    let j_bound = n / 2 + 1;
    let minimum_j_modulus = (2 * j_bound + 1) as u128;
    let minimum_scale_modulus =
        (2 * FULL_BOUND_PJ_TRAY as u128 * K_BOUND as u128).div_ceil((P * P) as u128);
    let minimum_modulus = minimum_j_modulus.max(minimum_scale_modulus);
    // Include p+1 as a phase-locked sister: C=K+pJ is K-J modulo p+1.
    let j_modulus = (P + 1) * minimum_modulus.div_ceil((P + 1) as u128) as u64;
    let high_t = P * P * j_modulus;
    let mut input_config = SecureConfig::secure_128().into_config();
    input_config.n = n;
    input_config.primes = vec![
        9_223_372_036_853_661_697,
        9_223_372_036_853_235_713,
        9_223_372_036_852_744_193,
    ];
    input_config.q = input_config.primes[0];
    input_config.security_bits = 0;
    input_config.name = "UNADMITTED adjacent quotient Jacobian research probe";
    input_config.t = P;
    let input_ctx = RNSFHEContext::try_new(&input_config).unwrap();

    let mut high_config = input_config.clone();
    high_config.t = high_t;
    let high_ctx = RNSFHEContext::try_new(&high_config).unwrap();

    let mut key_rng = ShadowHarvester::with_seed(0x4a41_434f_4249_414e);
    let keys = input_ctx.generate_keys_with_rng(&mut key_rng);
    let mut plaintext: Vec<i64> = (0..input_ctx.n)
        .map(|j| (j * 37 % (2 * K_BOUND as usize + 1)) as i64 - K_BOUND)
        .collect();
    for (index, value) in [-K_BOUND, K_BOUND, -K_BOUND + 1, K_BOUND - 1, -1, 0, 1]
        .into_iter()
        .enumerate()
    {
        if index < plaintext.len() {
            plaintext[index] = value;
        }
    }

    let mut encrypt_rng = ShadowHarvester::with_seed(0x454e_435f_4b00);
    let mut encrypted_k = input_ctx.encrypt_with_rng(0, &keys.public_key, &mut encrypt_rng);
    encrypted_k.c0 = encrypted_k.c0.add(
        &encode_centered_polynomial(&input_ctx, &plaintext),
        &input_ctx.rns,
    );

    // The two quotients use denominator ratio p:(p+1), with the shared
    // factor J_MODULUS preserving the same adjacent-scale Jacobian at
    // HIGH_T = p^2 * J_MODULUS.
    let divisor_p = P * j_modulus;
    let divisor_p1 = (P + 1) * j_modulus;
    let lifted_at_p = centered_component_quotient(&input_ctx, &encrypted_k, divisor_p);
    let lifted_at_p1 = centered_component_quotient(&input_ctx, &encrypted_k, divisor_p1);
    let difference = high_ctx.sub(&lifted_at_p, &lifted_at_p1);
    let lifted_k = decrypt_coefficients(&high_ctx, &lifted_at_p, &keys.secret_key);
    let jacobian_j = decrypt_coefficients(&high_ctx, &difference, &keys.secret_key);

    let mut max_abs_j = 0i128;
    let mut jacobian_mismatches = 0usize;
    let mut clean_j = vec![0i64; input_ctx.n];
    let mut clean_residual = vec![0i64; input_ctx.n];
    let residual_bound = K_BOUND as u64 + j_bound as u64;
    assert!(2 * residual_bound < P + 1);
    for coefficient in 0..input_ctx.n {
        let delta = centered(
            lifted_k[coefficient] - plaintext[coefficient] as i128,
            high_t,
        );
        assert_eq!(
            delta % P as i128,
            0,
            "lift carry at coefficient {coefficient}"
        );
        let j = delta / P as i128;
        max_abs_j = max_abs_j.max(j.abs());
        jacobian_mismatches += usize::from(centered(jacobian_j[coefficient], high_t) != j);
        let r = plaintext[coefficient] as i128 - j;
        assert!(r.unsigned_abs() < (P / 2) as u128);
        assert!(j.unsigned_abs() <= j_bound as u128);
        assert!(j.unsigned_abs() < (j_modulus / 2) as u128);
        assert!(r.unsigned_abs() <= residual_bound as u128);
        // D=J+(K-J)/(p+1), so this public bound puts every D coefficient
        // strictly inside J's nearest-integer cell.
        assert!(2 * r.unsigned_abs() < (P + 1) as u128);
        clean_j[coefficient] = j as i64;
        clean_residual[coefficient] = r as i64;
    }

    // Read the same high-T lift in its adjacent p and p+1 trays:
    // C mod p=K, D mod p=J, and C mod (p+1)=r=K-J. The public residual
    // bound is below p/2, so both tray views have a unique signed lift.
    let c_p = scale(&high_ctx, &lifted_at_p, high_t / P);
    let d_p = scale(&high_ctx, &difference, high_t / P);
    let r_p = input_ctx.sub(&c_p, &d_p);
    let c_p_values = decrypt_coefficients(&input_ctx, &c_p, &keys.secret_key);
    let d_p_values = decrypt_coefficients(&input_ctx, &d_p, &keys.secret_key);
    let r_p_values = decrypt_coefficients(&input_ctx, &r_p, &keys.secret_key);
    let mut p_view_mismatches = 0usize;
    for coefficient in 0..input_ctx.n {
        p_view_mismatches += usize::from(
            centered(c_p_values[coefficient], P) != centered(plaintext[coefficient] as i128, P),
        );
        p_view_mismatches += usize::from(
            centered(d_p_values[coefficient], P) != centered(clean_j[coefficient] as i128, P),
        );
        p_view_mismatches += usize::from(
            centered(r_p_values[coefficient], P) != clean_residual[coefficient] as i128,
        );
    }
    let mut p1_config = high_config.clone();
    p1_config.t = P + 1;
    let p1_ctx = RNSFHEContext::try_new(&p1_config).unwrap();
    let r_p1 = scale(&high_ctx, &lifted_at_p, high_t / (P + 1));
    let r_p1_values = decrypt_coefficients_any_t(&p1_ctx, &r_p1, &keys.secret_key);
    let p1_view_mismatches = (0..input_ctx.n)
        .filter(|&coefficient| r_p1_values[coefficient] != clean_residual[coefficient] as i128)
        .count();
    let adjacent_kelim_mismatches = (0..input_ctx.n)
        .filter(|&coefficient| {
            let k_mod_p = centered(c_p_values[coefficient], P);
            let r_mod_p = r_p1_values[coefficient].rem_euclid(P as i128);
            centered(k_mod_p - r_mod_p, P) != clean_j[coefficient] as i128
        })
        .count();

    // Attempt the actual K-Elimination lift from the p+1 residual sibling to
    // HIGH_T. Its componentwise division may introduce a new quotient
    // winding; retain the all-coefficient count as the next gate diagnostic.
    let raw_residual_lift = centered_component_quotient(&high_ctx, &r_p1, P * P);
    let raw_residual_values = decrypt_coefficients(&high_ctx, &raw_residual_lift, &keys.secret_key);
    let raw_residual_lift_mismatches = (0..input_ctx.n)
        .filter(|&coefficient| {
            centered(raw_residual_values[coefficient], high_t)
                != clean_residual[coefficient] as i128
        })
        .count();
    let adjacent_residual_lift = centered_component_quotient(&high_ctx, &r_p1, P * P + 1);
    let adjacent_residual_values =
        decrypt_coefficients(&high_ctx, &adjacent_residual_lift, &keys.secret_key);
    let adjacent_residual_lift_mismatches = (0..input_ctx.n)
        .filter(|&coefficient| {
            centered(adjacent_residual_values[coefficient], high_t)
                != clean_residual[coefficient] as i128
        })
        .count();
    let mut raw_winding_max = 0i128;
    let mut raw_winding_nonmultiple = 0usize;
    let mut max_second_winding = 0i128;
    let mut clean_second_winding = vec![0i64; input_ctx.n];
    let mut adjacent_winding_max = 0i128;
    let mut adjacent_equals_raw = 0usize;
    for coefficient in 0..input_ctx.n {
        let raw_winding = centered(
            raw_residual_values[coefficient] - clean_residual[coefficient] as i128,
            high_t,
        );
        let adjacent_winding = centered(
            adjacent_residual_values[coefficient] - clean_residual[coefficient] as i128,
            high_t,
        );
        raw_winding_max = raw_winding_max.max(raw_winding.abs());
        adjacent_winding_max = adjacent_winding_max.max(adjacent_winding.abs());
        raw_winding_nonmultiple += usize::from(raw_winding % (P + 1) as i128 != 0);
        if raw_winding % (P + 1) as i128 == 0 {
            let winding = raw_winding / (P + 1) as i128;
            max_second_winding = max_second_winding.max(winding.abs());
            clean_second_winding[coefficient] = winding as i64;
        }
        adjacent_equals_raw += usize::from(raw_winding == adjacent_winding);
    }

    // Check the lift winding against the public wrap cocycle of the p^2
    // scale change. If p^2*x=Q*k+y for each public component coefficient,
    // component division subtracts Q*k/p^2; after high-T decoding this shifts
    // the quotient by (p+1)*sum(k0+k1*s). The carry is therefore J-sum(k0+k1*s)
    // modulo p^2. The evaluator can compute the wrap polynomials; the
    // secret-key convolution below is client-only validation.
    let wrap_c0 = scale_wraps(&high_ctx, &lifted_at_p.c0, P * P);
    let wrap_c1 = scale_wraps(&high_ctx, &lifted_at_p.c1, P * P);
    let q0 = high_config.primes[0];
    let wrap_c1_mod: Vec<_> = wrap_c1.iter().map(|&value| value % q0).collect();
    let secret_coefficients = ordinary(&high_ctx, &keys.secret_key.s)[0]
        .iter()
        .map(|&value| match value {
            0 => 0u64,
            1 => 1u64,
            v if v == q0 - 1 => q0 - 1,
            _ => panic!("secret coefficient is not ternary"),
        })
        .collect::<Vec<_>>();
    let wrapped_phase = high_ctx.ntt_engines[0].multiply(&wrap_c1_mod, &secret_coefficients);
    let mut predicted_winding_mismatches = 0usize;
    let mut max_scale_wrap_value = 0i128;
    for coefficient in 0..input_ctx.n {
        let value = ((wrapped_phase[coefficient] as u128 + wrap_c0[coefficient] as u128)
            % q0 as u128) as u64;
        let centered_value = if value > q0 / 2 {
            value as i128 - q0 as i128
        } else {
            value as i128
        };
        max_scale_wrap_value = max_scale_wrap_value.max(centered_value.abs());
        let mut wrap_carry = centered_value.rem_euclid((P * P) as i128);
        if wrap_carry > (P * P / 2) as i128 {
            wrap_carry -= (P * P) as i128;
        }
        let actual = clean_second_winding[coefficient] as i128;
        predicted_winding_mismatches +=
            usize::from(clean_j[coefficient] as i128 - wrap_carry != actual);
    }

    // The new lift winding is also visible through the same p/p+1 sisters:
    // Y=r+(p+1)Jq gives Y-r=Jq mod p and Y=r mod (p+1).
    let raw_p = scale(&high_ctx, &raw_residual_lift, high_t / P);
    let jq_p = input_ctx.sub(&raw_p, &r_p);
    let jq_p_values = decrypt_coefficients(&input_ctx, &jq_p, &keys.secret_key);
    let jq_p_mismatches = (0..input_ctx.n)
        .filter(|&coefficient| {
            centered(jq_p_values[coefficient], P)
                != centered(clean_second_winding[coefficient] as i128, P)
        })
        .count();
    let raw_p1 = scale(&high_ctx, &raw_residual_lift, high_t / (P + 1));
    let raw_p1_values = decrypt_coefficients_any_t(&p1_ctx, &raw_p1, &keys.secret_key);
    let raw_p1_mismatches = (0..input_ctx.n)
        .filter(|&coefficient| raw_p1_values[coefficient] != clean_residual[coefficient] as i128)
        .count();

    // Oracle control for one further K-Elimination correction step.
    let mut second_winding_rng = ShadowHarvester::with_seed(0x4a51_5749_4e44_494e);
    let mut encrypted_second_winding =
        high_ctx.encrypt_with_rng(0, &keys.public_key, &mut second_winding_rng);
    encrypted_second_winding.c0 = encrypted_second_winding.c0.add(
        &encode_centered_polynomial(&high_ctx, &clean_second_winding),
        &high_ctx.rns,
    );
    let second_winding_correction = scale(&high_ctx, &encrypted_second_winding, P + 1);
    let corrected_residual_lift = high_ctx.sub(&raw_residual_lift, &second_winding_correction);
    let corrected_residual_values =
        decrypt_coefficients(&high_ctx, &corrected_residual_lift, &keys.secret_key);
    let corrected_residual_lift_mismatches = (0..input_ctx.n)
        .filter(|&coefficient| {
            centered(corrected_residual_values[coefficient], high_t)
                != clean_residual[coefficient] as i128
        })
        .count();

    // The Jacobian ciphertext decrypts to J, but its phase still contains
    // (K-J)/(p+1). Multiplication by p amplifies that fractional offset, so
    // this direct correction deliberately measures as a failing control.
    let naive_correction = scale(&high_ctx, &difference, P);
    let naive_output = high_ctx.sub(&lifted_at_p, &naive_correction);
    let naive_plain = decrypt_coefficients(&high_ctx, &naive_output, &keys.secret_key);
    let naive_mismatches = (0..input_ctx.n)
        .filter(|&j| centered(naive_plain[j], high_t) != plaintext[j] as i128)
        .count();

    // Oracle control: the missing live Safe-Basis producer must turn the
    // phase-locked rounded view D into one clean bounded Enc_T(J).
    let mut winding_rng = ShadowHarvester::with_seed(0x5749_4e44_494e_4700);
    let mut encrypted_j = high_ctx.encrypt_with_rng(0, &keys.public_key, &mut winding_rng);
    encrypted_j.c0 = encrypted_j.c0.add(
        &encode_centered_polynomial(&high_ctx, &clean_j),
        &high_ctx.rns,
    );

    // The quotient identity is simply C=K+pJ, so one clean root view is
    // sufficient: subtract p*Enc_T(J). The adjacent D supplies J's nearest
    // integer with margin, while Safe-Basis must materialize its common-T
    // encryption without the key-holder oracle used here.
    let correction = scale(&high_ctx, &encrypted_j, P);
    let corrected = high_ctx.sub(&lifted_at_p, &correction);
    let corrected_plain = decrypt_coefficients(&high_ctx, &corrected, &keys.secret_key);
    let corrected_mismatches = (0..input_ctx.n)
        .filter(|&j| centered(corrected_plain[j], high_t) != plaintext[j] as i128)
        .count();

    // A stale/corrupted root view must not silently produce a valid refresh.
    let mut wrong_j = encrypted_j.clone();
    wrong_j.c0 = wrong_j.c0.add(
        &encode_centered_polynomial(&high_ctx, &vec![1; input_ctx.n]),
        &high_ctx.rns,
    );
    let wrong_correction = scale(&high_ctx, &wrong_j, P);
    let wrong_output = high_ctx.sub(&lifted_at_p, &wrong_correction);
    let wrong_plain = decrypt_coefficients(&high_ctx, &wrong_output, &keys.secret_key);
    let wrong_root_mismatches = (0..input_ctx.n)
        .filter(|&j| centered(wrong_plain[j], high_t) != plaintext[j] as i128)
        .count();

    // Exercise the dependent high correction consumed by the CRAM path.
    let scaled_expected: Vec<i64> = plaintext
        .iter()
        .map(|&k| k * FULL_BOUND_PJ_TRAY as i64)
        .collect();
    assert!(scaled_expected
        .iter()
        .all(|&k| k.unsigned_abs() < high_t / 2));
    let scaled_correction = scale(&high_ctx, &corrected, FULL_BOUND_PJ_TRAY);
    let scaled_plain = decrypt_coefficients(&high_ctx, &scaled_correction, &keys.secret_key);
    let scaled_mismatches = (0..input_ctx.n)
        .filter(|&j| centered(scaled_plain[j], high_t) != scaled_expected[j] as i128)
        .count();
    let q = U512::product_u64s(&high_config.primes);
    let correction_error = phase_error_bound(&high_ctx, &corrected, &keys.secret_key, &plaintext);
    let scaled_error = phase_error_bound(
        &high_ctx,
        &scaled_correction,
        &keys.secret_key,
        &scaled_expected,
    );
    assert!(words(correction_error.mul_u128(2)) < words(q));
    assert!(
        words(scaled_error.mul_u128(2)) < words(q),
        "scaled phase error={} bits, Q={} bits",
        bits(scaled_error),
        bits(q)
    );

    // First-order Richardson/K-Elimination control. If adjacent quotients
    // expose D_m=J+r/m and D_(m+1)=J+r/(m+1), then
    // (m+1)D_(m+1)-mD_m cancels the shared residual fraction exactly.
    let lifted_at_p2 = centered_component_quotient(&input_ctx, &encrypted_k, (P + 2) * j_modulus);
    let second_difference = high_ctx.sub(&lifted_at_p1, &lifted_at_p2);
    let second_difference_values =
        decrypt_coefficients(&high_ctx, &second_difference, &keys.secret_key);
    let second_difference_mismatches = second_difference_values
        .iter()
        .zip(&clean_j)
        .filter(|(actual, expected)| centered(**actual, high_t) != **expected as i128)
        .count();
    let jacobian_cancellation = high_ctx.sub(
        &scale(&high_ctx, &second_difference, P + 2),
        &scale(&high_ctx, &difference, P + 1),
    );
    let jacobian_cancellation_values =
        decrypt_coefficients(&high_ctx, &jacobian_cancellation, &keys.secret_key);
    let jacobian_cancellation_mismatches = jacobian_cancellation_values
        .iter()
        .zip(&clean_j)
        .filter(|(actual, expected)| centered(**actual, high_t) != **expected as i128)
        .count();
    let jacobian_corrected =
        high_ctx.sub(&lifted_at_p, &scale(&high_ctx, &jacobian_cancellation, P));
    let jacobian_corrected_values =
        decrypt_coefficients(&high_ctx, &jacobian_corrected, &keys.secret_key);
    let jacobian_corrected_mismatches = jacobian_corrected_values
        .iter()
        .zip(&plaintext)
        .filter(|(actual, expected)| centered(**actual, high_t) != **expected as i128)
        .count();
    let jacobian_scaled = scale(&high_ctx, &jacobian_corrected, FULL_BOUND_PJ_TRAY);
    let jacobian_scaled_values =
        decrypt_coefficients(&high_ctx, &jacobian_scaled, &keys.secret_key);
    let jacobian_scaled_mismatches = jacobian_scaled_values
        .iter()
        .zip(&scaled_expected)
        .filter(|(actual, expected)| centered(**actual, high_t) != **expected as i128)
        .count();
    let jacobian_error = phase_error_bound(
        &high_ctx,
        &jacobian_cancellation,
        &keys.secret_key,
        &clean_j,
    );
    let jacobian_corrected_error =
        phase_error_bound(&high_ctx, &jacobian_corrected, &keys.secret_key, &plaintext);
    let jacobian_scaled_error = phase_error_bound(
        &high_ctx,
        &jacobian_scaled,
        &keys.secret_key,
        &scaled_expected,
    );

    println!(
        "adjacent Richardson K-Elimination: second difference mismatches={}/{}, Jacobian cancellation J mismatches={}/{}, corrected K mismatches={}/{}, full M_pJ*K mismatches={}/{}, phase-error bits J->K->scaled={}/{}/{}",
        second_difference_mismatches,
        input_ctx.n,
        jacobian_cancellation_mismatches,
        input_ctx.n,
        jacobian_corrected_mismatches,
        input_ctx.n,
        jacobian_scaled_mismatches,
        input_ctx.n,
        bits(jacobian_error),
        bits(jacobian_corrected_error),
        bits(jacobian_scaled_error),
    );

    println!(
        "N={}, public |J| bound={}, |K-J| bound={}, M={}, T=p^2*M={}, K range=[{},{}], max |J|={}; adjacent Jacobian mismatches={}/{}; p/p+1 residue-view mismatches={}/{}; adjacent K-Elimination mismatches={}/{}; raw p+1-to-T lift mismatches={}/{}, winding max={}=(p+1)*{}, nonmultiples={}; scale-wrap cocycle mismatch={}/{}, max |wrap polynomial|={}; p-view Jq mismatches={}/{}, p+1-view residual mismatches={}/{}; Jq-oracle correction mismatches={}/{}; adjacent-divisor mismatches={}/{}, winding max={}, equal to raw={}; naive correction mismatches={}/{}; single-J-root oracle correction mismatches={}/{}; corrupted-root mismatches={}/{}; M_pJ*K mismatches={}/{}; phase-error bits={} -> scaled={}, Q={}",
        input_ctx.n,
        j_bound,
        residual_bound,
        j_modulus,
        high_t,
        plaintext.iter().min().unwrap(),
        plaintext.iter().max().unwrap(),
        max_abs_j,
        jacobian_mismatches,
        input_ctx.n,
        p_view_mismatches + p1_view_mismatches,
        4 * input_ctx.n,
        adjacent_kelim_mismatches,
        input_ctx.n,
        raw_residual_lift_mismatches,
        input_ctx.n,
        raw_winding_max,
        max_second_winding,
        raw_winding_nonmultiple,
        predicted_winding_mismatches,
        input_ctx.n,
        max_scale_wrap_value,
        jq_p_mismatches,
        input_ctx.n,
        raw_p1_mismatches,
        input_ctx.n,
        corrected_residual_lift_mismatches,
        input_ctx.n,
        adjacent_residual_lift_mismatches,
        input_ctx.n,
        adjacent_winding_max,
        adjacent_equals_raw,
        naive_mismatches,
        input_ctx.n,
        corrected_mismatches,
        input_ctx.n,
        wrong_root_mismatches,
        input_ctx.n,
        scaled_mismatches,
        input_ctx.n,
        bits(correction_error),
        bits(scaled_error),
        bits(q),
    );
    assert!(max_abs_j <= j_bound as i128);
    assert_eq!(jacobian_mismatches, 0);
    assert_eq!(p_view_mismatches, 0);
    assert_eq!(p1_view_mismatches, 0);
    assert_eq!(adjacent_kelim_mismatches, 0);
    assert_eq!(raw_winding_nonmultiple, 0);
    assert!(max_second_winding <= j_bound as i128);
    assert_eq!(predicted_winding_mismatches, 0);
    assert_eq!(jq_p_mismatches, 0);
    assert_eq!(raw_p1_mismatches, 0);
    assert_eq!(corrected_residual_lift_mismatches, 0);
    // A coefficient can pass by coincidence (one does at N=16,384); the
    // control must fail broadly, rather than requiring every sample to fail.
    assert!(naive_mismatches > input_ctx.n / 2);
    assert_eq!(corrected_mismatches, 0);
    assert_eq!(wrong_root_mismatches, input_ctx.n);
    assert_eq!(scaled_mismatches, 0);

    run_inverse_residual_control(
        &input_ctx,
        &encrypted_k,
        &keys.public_key,
        &keys.secret_key,
        &plaintext,
    );
}
