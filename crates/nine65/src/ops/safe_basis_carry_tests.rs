//! Aligned sister-frame carry experiment, with a retained-residual check.
//! This is test-only: carry correctness is not a noise-refresh certificate.

use super::evaluate_centered_components;
use super::safe_basis_precharge_tests::{decode_indices, inverse, precharge, signed_secret};
use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
use crate::arithmetic::main_only_base_ext::MainOnlyBaseExt;
use crate::arithmetic::rns::{U256, U512};
use crate::arithmetic::RNSPolynomial;
use crate::entropy::ShadowHarvester;
use crate::keys::bootstrap::{screen_bootstrap_security, validate_bootstrap_primes};
use crate::ops::rns_fhe::{
    DualRNSCiphertext, DualRNSSecretKey, RNSCiphertext, RNSFHEContext, RNSSecretKey,
};
use crate::params::{is_prime, SecureConfig};

const ROOT: [u64; 8] = [2, 3, 5, 7, 11, 13, 17, 19];
// All boot primes exceed every work/coordinate prime. No plaintext-range
// or security check is bypassed to admit the source-prime coordinates.
const BOOT: [u64; 4] = [1811939329, 2113929217, 2130706433, 1107296257];
// Existing screened five-prime tuple from the composition experiments. Its
// product is wider than u128, so the follow-up test exercises the U256 path.
const SQUARE_BOOT: [u64; 5] = [
    1811939329, 2113929217, 2130706433, 1107296257, 1711276033,
];

fn coordinate_error(n: usize, eta: usize, qb: U256, m: u64) -> u128 {
    let remainder = qb.mod_u64(m) as u128;
    eta as u128 * (2 * n as u128 + 1) * n as u128 * (m / 2) as u128
        + (n as u128 + 1) * remainder
        + remainder.div_ceil(2)
}

fn weighted_add(ctx: &RNSFHEContext, dst: &mut RNSCiphertext, src: &RNSCiphertext, weight: u64) {
    for (a, b) in [(&mut dst.c0, &src.c0), (&mut dst.c1, &src.c1)] {
        for (lane, &prime) in ctx.config.primes.iter().enumerate() {
            for (value, &term) in a.limbs[lane].iter_mut().zip(&b.limbs[lane]) {
                *value = ((*value as u128 + weight as u128 * term as u128) % prime as u128) as u64;
            }
        }
    }
}

fn abs_difference(a: U256, b: U256) -> U256 {
    if a.ge(b) {
        a.sub(b)
    } else {
        b.sub(a)
    }
}

fn ceil_ratio(numerator: U256, q: u128, t: u64) -> u128 {
    let (whole, remainder_q) = numerator.div_mod_u256(U256::from_u128(q));
    let (quotient, remainder_t) = whole.div_mod_u64(t);
    assert_eq!(quotient.hi, 0);
    quotient.lo + u128::from(remainder_q != U256::zero() || remainder_t != 0)
}

// Oracles below are outside the evaluator. Use separate positive/negative
// accumulators so native S may occupy all 132 bits without i128 overflow.
fn residual_oracle(ctx: &RNSFHEContext, input: &DualRNSCiphertext) -> [Vec<i128>; 2] {
    let q = ctx.q_product;
    [&input.c0, &input.c1].map(|poly| {
        (0..ctx.n)
            .map(|j| {
                let residues: Vec<_> = ctx
                    .config
                    .primes
                    .iter()
                    .enumerate()
                    .map(|(lane, &p)| {
                        (poly.main[lane][j] as u128 * ctx.t as u128 % p as u128) as u64
                    })
                    .collect();
                let x = ctx.rns.to_u256_level(&residues, residues.len());
                assert_eq!(x.hi, 0);
                if x.lo > q / 2 {
                    x.lo as i128 - q as i128
                } else {
                    x.lo as i128
                }
            })
            .collect()
    })
}

fn carry_oracle(r: &[Vec<i128>; 2], s: &[i8], q: u128, j: usize) -> (i128, i128) {
    let (mut positive, mut negative) = (U256::zero(), U256::zero());
    let mut add = |value: i128| {
        if value >= 0 {
            positive = positive.add(U256::from_u128(value as u128));
        } else {
            negative = negative.add(U256::from_u128(value.unsigned_abs()));
        }
    };
    add(r[0][j]);
    for (i, &value) in r[1].iter().enumerate() {
        let k = (j + s.len() - i) % s.len();
        add(value * s[k] as i128 * if i + k < s.len() { 1 } else { -1 });
    }
    let is_negative = negative.ge(positive);
    let magnitude = abs_difference(positive, negative);
    let (k, _) = magnitude
        .add(U256::from_u128(q / 2))
        .div_mod_u256(U256::from_u128(q));
    assert_eq!(k.hi, 0);
    let multiple = U256::from_u128(q).mul_u64(k.lo as u64);
    let remainder = abs_difference(magnitude, multiple);
    assert_eq!(remainder.hi, 0);
    assert!(remainder.lo <= q / 2);
    let g = remainder.lo as i128 * if magnitude.ge(multiple) { 1 } else { -1 };
    if is_negative {
        (-(k.lo as i128), -g)
    } else {
        (k.lo as i128, g)
    }
}

fn phase_oracle(
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    sk: &DualRNSSecretKey,
    indices: &[usize],
) -> Vec<U256> {
    let phase: Vec<Vec<u64>> = ctx
        .config
        .primes
        .iter()
        .enumerate()
        .map(|(lane, &p)| {
            let mont = &ctx.rns.mont_contexts[lane];
            let c1: Vec<_> = ct.c1.limbs[lane]
                .iter()
                .map(|&x| mont.from_montgomery(x))
                .collect();
            let product = ctx.ntt_engines[lane].multiply(&c1, &sk.s.main[lane]);
            ct.c0.limbs[lane]
                .iter()
                .zip(product)
                .map(|(&a, b)| ((mont.from_montgomery(a) as u128 + b as u128) % p as u128) as u64)
                .collect()
        })
        .collect();
    indices
        .iter()
        .map(|&j| {
            ctx.rns.to_u256_level(
                &phase.iter().map(|lane| lane[j]).collect::<Vec<_>>(),
                phase.len(),
            )
        })
        .collect()
}

fn signed_grid_error(phase: U256, qb: U256, t: u64, decoded: u64) -> i128 {
    let scaled = phase.mul_u64(t);
    let ideal = qb.mul_u64(decoded);
    let period = qb.mul_u64(t);
    let mut negative = ideal.ge(scaled);
    let mut difference = abs_difference(scaled, ideal);
    if difference.ge(period.shr1()) {
        difference = period.sub(difference);
        negative = !negative;
    }
    assert_eq!(difference.hi, 0);
    let value = i128::try_from(difference.lo).unwrap();
    if negative {
        -value
    } else {
        value
    }
}

fn residual_subtracted_error(grid_error: i128, q: u128, g: i128, qb: U256) -> U256 {
    let a = U256::from_u128(grid_error.unsigned_abs()).mul_low(U256::from_u128(q));
    let b = U256::from_u128(g.unsigned_abs()).mul_low(qb);
    if (grid_error < 0) == (g < 0) {
        abs_difference(a, b)
    } else {
        a.add(b)
    }
}

#[test]
fn precharged_aligned_frame_encodes_native_carry_and_retains_input_residual() {
    run_precharged_aligned_frame(&BOOT, &[0, 1, -1], false);
}

#[test]
fn five_prime_full_refresh_supports_one_followup_square() {
    run_precharged_aligned_frame(&SQUARE_BOOT, &[0], true);
}

fn run_precharged_aligned_frame(boot_primes: &[u64], profiles: &[i128], check_square: bool) {
    let config = SecureConfig::secure_128().into_config();
    let work = RNSFHEContext::try_new(&config).unwrap();
    let q = work.q_product;
    let mut boot_config = config.clone();
    boot_config.primes = boot_primes.to_vec();
    boot_config.q = boot_primes[0];
    assert!(boot_primes.iter().all(|&p| is_prime(p)));
    validate_bootstrap_primes(boot_primes, config.n).unwrap();
    assert!(
        screen_bootstrap_security(boot_primes, config.n, 128)
            .unwrap()
            .meets_claim_under_both
    );
    let boot = RNSFHEContext::try_new(&boot_config).unwrap();
    let qb = U256::product_u64s(boot_primes);
    let mut rng = ShadowHarvester::with_seed(0x4341_5252_5951);
    let work_keys = work.generate_keys_dual(&mut rng);
    let boot_keys = boot.generate_keys_dual(&mut rng);
    assert_ne!(
        work_keys.secret_key.s.main[0],
        boot_keys.secret_key.s.main[0]
    );
    let secret = signed_secret(&work_keys.secret_key, config.primes[0]);
    let mut moduli = ROOT.to_vec();
    moduli.extend(&config.primes);
    moduli.push(config.t);
    let projector = MainOnlyBaseExt::new(&config.primes, &moduli).unwrap();
    let mut coordinates = Vec::new();
    let mut weights = Vec::new();
    let mut assembly_error = 0u128;
    for (lane, &m) in moduli.iter().enumerate() {
        assert!(boot_primes.iter().all(|&p| m < p));
        let mut encoding = boot_config.clone();
        encoding.t = m;
        let ctx = RNSFHEContext::try_new(&encoding).unwrap();
        let key = precharge(&ctx, &boot_keys, &secret, &mut rng);
        if lane >= ROOT.len() {
            // M=Q_work*t, represented as factors; no 135-bit scalar M.
            let complement = if m == config.t {
                (q % m as u128) as u64
            } else {
                ((q / m as u128) % m as u128 * (config.t % m) as u128 % m as u128) as u64
            };
            let weight = inverse(complement, m);
            assembly_error += weight as u128 * coordinate_error(config.n, config.eta, qb, m);
            weights.push(weight);
        }
        coordinates.push((ctx, key));
    }
    let boot_delta = qb.div_mod_u64(config.t).0;
    assert!(U256::from_u128(assembly_error).mul_u64(4).lt(boot_delta));
    let indices = [0, 1, config.n / 3, config.n / 2, config.n - 2, config.n - 1];
    let all_indices: Vec<_> = (0..config.n).collect();
    let original = work.encrypt_dual(7, &work_keys.public_key, &mut rng);
    let injected = q / (8 * config.t as u128);
    let mut checked = 0;
    let mut nonzero = 0;
    let mut affine_only_failures = 0;
    let mut square_checks = 0;
    for &offset_sign in profiles {
        let mut input = original.clone();
        let offset = offset_sign * injected as i128;
        for (values, &prime) in input.c0.main.iter_mut().zip(&config.primes) {
            values[0] = (values[0] as i128 + offset.rem_euclid(prime as i128))
                .rem_euclid(prime as i128) as u64;
        }
        assert_eq!(work.decrypt_dual(&input, &work_keys.secret_key), 7);
        // Public parameter/history bound: fresh public-key encryption plus
        // this known additive perturbation. Do not select a noise allowance
        // by decrypting the input or observing its actual residual.
        let fresh_error = config.eta as u128 * (2 * config.n as u128 + 1);
        let source_error_bound = fresh_error + offset.unsigned_abs();
        let public_g_bound = config.t as u128 * source_error_bound
            + (q % config.t as u128) * ((config.t - 1) / 2) as u128;
        assert!(public_g_bound < q / 2);
        let retained_bound = ceil_ratio(
            qb.mul_low(U256::from_u128(public_g_bound)),
            q,
            config.t,
        );
        let total_bound = assembly_error + retained_bound;
        assert!(U256::from_u128(total_bound).mul_u64(2).lt(boot_delta));
        let mut residuals = [
            vec![vec![0; config.n]; moduli.len()],
            vec![vec![0; config.n]; moduli.len()],
        ];
        // Evaluator boundary: no work/boot secret and no decrypted residue.
        for (component, poly) in [&input.c0, &input.c1].iter().enumerate() {
            for j in 0..config.n {
                let main: Vec<_> = config
                    .primes
                    .iter()
                    .enumerate()
                    .map(|(lane, &p)| {
                        (poly.main[lane][j] as u128 * config.t as u128 % p as u128) as u64
                    })
                    .collect();
                let mut views = vec![0; moduli.len()];
                projector.project_centered(&main, &mut views).unwrap();
                for (lane, value) in views.into_iter().enumerate() {
                    residuals[component][lane][j] = value;
                }
            }
        }
        let mut root = Vec::new();
        let mut carry: Option<RNSCiphertext> = None;
        for (lane, (ctx, key)) in coordinates.iter().enumerate() {
            let output =
                evaluate_centered_components(ctx, &residuals[0][lane], &residuals[1][lane], key);
            if lane < ROOT.len() {
                root.push(output);
            } else {
                if carry.is_none() {
                    let mut zero = output.clone();
                    for poly in [&mut zero.c0, &mut zero.c1] {
                        for limb in &mut poly.limbs {
                            limb.fill(0);
                        }
                    }
                    carry = Some(zero);
                }
                weighted_add(
                    &boot,
                    carry.as_mut().unwrap(),
                    &output,
                    weights[lane - ROOT.len()],
                );
            }
        }
        let carry = carry.unwrap();
        assert_eq!(root.len(), 8, "preserve the intact encrypted priming root");
        // End evaluator boundary. Everything below is an independent oracle.
        let r = residual_oracle(&work, &input);
        // Exercise the complete hidden negacyclic sum for all three input
        // residual profiles, not just sampled coefficients.
        let expected_all: Vec<_> = (0..config.n)
            .map(|j| carry_oracle(&r, &secret, q, j))
            .collect();
        assert!(expected_all
            .iter()
            .all(|(_, g)| g.unsigned_abs() <= public_g_bound));
        let decoded_all = decode_indices(
            &boot,
            &carry,
            &boot_keys.secret_key,
            &all_indices,
            total_bound,
        );
        for ((&j, &actual), &(k, _)) in all_indices.iter().zip(&decoded_all).zip(&expected_all) {
            assert_eq!(
                actual as i128,
                k.rem_euclid(config.t as i128),
                "full native carry at j={j}, offset_sign={offset_sign}"
            );
            assert!(k.unsigned_abs() <= (config.n / 2) as u128);
            nonzero += usize::from(k != 0);
        }
        checked += config.n;

        // Feed the complete carry into the affine path using the same
        // precharged old secret. N*(t-8)=1 mod t; unlike the scalar
        // coefficient probe, no coefficient trace is needed here.
        let scaler = CanonicalScaleRound::new(&config.primes, config.t).unwrap();
        let prepared = [&input.c0, &input.c1].map(|poly| {
            (0..config.n)
                .map(|j| {
                    let residues: Vec<_> = poly.main.iter().map(|lane| lane[j]).collect();
                    let scaled = scaler.scale_round(&residues).unwrap();
                    (scaled as u128 * (config.t - 8) as u128 % config.t as u128) as u64
                })
                .collect::<Vec<_>>()
        });
        assert_eq!(config.n as u64 * (config.t - 8) % config.t, 1);
        let source_lane = ROOT.len() + config.primes.len();
        let affine_half = evaluate_centered_components(
            &boot,
            &prepared[0],
            &prepared[1],
            &coordinates[source_lane].1,
        );
        let affine = scale(&boot, &affine_half, config.n as i64);
        let refreshed = boot.add(&affine, &carry);
        let n = config.n as u128;
        let remainder = qb.mod_u64(config.t) as u128;
        let beta = config.eta as u128 * (2 * n + 1);
        let affine_inner_error =
            beta * n * (config.t / 2) as u128 + (n + 1) * remainder + remainder.div_ceil(2);
        // Multiplication by N restores the inverse-N preconditioning and
        // scales the affine error by N. This path has no trace key-switch
        // term, unlike the per-coefficient trace implementation.
        let affine_bound = affine_inner_error * n;
        let refresh_bound = affine_bound + total_bound;
        assert!(U256::from_u128(refresh_bound).mul_u64(2).lt(boot_delta));
        let wrong_j = expected_all
            .iter()
            .position(|(k, _)| *k != 0)
            .expect("fixture must exercise a nonzero hidden carry");
        let affine_only = decode_indices(
            &boot,
            &affine,
            &boot_keys.secret_key,
            &[wrong_j],
            affine_bound,
        );
        assert_ne!(
            affine_only[0],
            u64::from(wrong_j == 0) * 7,
            "affine-only phase must miss the carry at j={wrong_j}"
        );
        affine_only_failures += 1;
        let refreshed_all =
            decode_indices(&boot, &refreshed, &boot_keys.secret_key, &all_indices, refresh_bound);
        for (&j, &actual) in all_indices.iter().zip(&refreshed_all) {
            assert_eq!(
                actual,
                u64::from(j == 0) * 7,
                "full refresh at j={j}, offset_sign={offset_sign}"
            );
        }
        checked += config.n;
        let noise = super::safe_basis_composition_tests::Noise::new(&boot.config);
        let refresh_bound_value = refresh_bound;
        let refresh_bound = U512::from_u128(refresh_bound_value);
        let square_preflight = noise.multiply(refresh_bound, refresh_bound);
        if check_square {
            assert_eq!(offset_sign, 0);
            let square_bound = square_preflight.unwrap();
            assert!(
                (square_bound.d3, square_bound.d2, square_bound.d1, square_bound.d0)
                    < (
                        noise.half().d3,
                        noise.half().d2,
                        noise.half().d1,
                        noise.half().d0
                    )
            );
            let native_boot_secret = RNSSecretKey {
                s: RNSPolynomial {
                    n: boot.n,
                    limbs: boot
                        .rns
                        .mont_contexts
                        .iter()
                        .zip(&boot_keys.secret_key.s.main)
                        .map(|(mont, lane)| {
                            lane.iter().map(|&x| mont.to_montgomery(x)).collect()
                        })
                        .collect(),
                },
            };
            let exact = boot.try_exact_evaluator().unwrap();
            let relin = exact.generate_hybrid_gadget_key_with_rng(&native_boot_secret, &mut rng);
            let square = exact.try_mul_exact(&refreshed, &refreshed, &relin).unwrap();
            let actual = super::safe_basis_composition_tests::decode_at(
                &boot,
                &square,
                &boot_keys.secret_key,
                square_bound,
                0..config.n,
            );
            for (j, &value) in actual.iter().enumerate() {
                assert_eq!(value, u64::from(j == 0) * 49, "follow-up square at j={j}");
            }
            eprintln!(
                "five-prime refresh→square bounds: refresh={refresh_bound_value}; square={square_bound:?}; half-scale={:?}; checked={} coefficients",
                noise.half(),
                config.n
            );
            square_checks += config.n;
        } else {
            assert!(square_preflight.is_err());
        }
        let expected: Vec<_> = indices
            .iter()
            .map(|&j| carry_oracle(&r, &secret, q, j))
            .collect();
        assert!(expected
            .iter()
            .all(|(_, g)| g.unsigned_abs() <= public_g_bound));
        let decoded = decode_indices(&boot, &carry, &boot_keys.secret_key, &indices, total_bound);
        let phases = phase_oracle(&boot, &carry, &boot_keys.secret_key, &indices);
        let new_error_limit = U256::from_u128(q)
            .mul_u64(config.t)
            .mul_low(U256::from_u128(assembly_error));
        for (((&j, &actual), &phase), &(k, g)) in
            indices.iter().zip(&decoded).zip(&phases).zip(&expected)
        {
            assert_eq!(
                actual as i128,
                k.rem_euclid(config.t as i128),
                "carry at j={j}, offset_sign={offset_sign}"
            );
            assert!(k.unsigned_abs() <= (config.n / 2) as u128);
            let grid_error = signed_grid_error(phase, qb, config.t, actual);
            assert!(
                new_error_limit.ge(residual_subtracted_error(grid_error, q, g, qb)),
                "retained-residual law at j={j}"
            );
            if offset_sign != 0 && j == 0 {
                // A real carry ciphertext can retain large OLD noise. This
                // must fail any interpretation of CRT assembly as refresh.
                assert!(grid_error.unsigned_abs() / config.t as u128 > assembly_error * 1000);
            }
            checked += 1;
            nonzero += usize::from(k != 0);
        }
    }
    assert_eq!(checked, profiles.len() * (6 + 2 * config.n));
    assert_eq!(affine_only_failures, profiles.len());
    assert_eq!(square_checks, if check_square { config.n } else { 0 });
    assert!(nonzero > 0);
    eprintln!("aligned frame ({boot_prime_count} boot primes): {checked} encrypted native carry/refresh checks across all {n} coefficients and {profiles} residual profiles; {square_checks} follow-up square coefficients checked; {nonzero} nonzero carries; {affine_only_failures} affine-only negative controls fail; assembly error={assembly_error}; outputs match all-coefficient oracle", n = config.n, boot_prime_count = boot_primes.len(), profiles = profiles.len());
}

fn scale(ctx: &RNSFHEContext, ct: &RNSCiphertext, scalar: i64) -> RNSCiphertext {
    let mut result = ct.clone();
    for poly in [&mut result.c0, &mut result.c1] {
        for (lane, &q) in ctx.config.primes.iter().enumerate() {
            let residue = (scalar as i128).rem_euclid(q as i128) as u128;
            for value in &mut poly.limbs[lane] {
                *value = (*value as u128 * residue % q as u128) as u64;
            }
        }
    }
    result
}

fn local_coefficients(q: i128, r0: i128, r1: i128, t: u64) -> (i64, i64) {
    assert!(r0.abs() <= q / 2 && r1.abs() <= q / 2);
    let nearest = |x: i128| (x + q / 2).div_euclid(q);
    let minus = nearest(r0 - r1);
    let plus = nearest(r0 + r1);
    assert_eq!(nearest(r0), 0);
    let inverse_two = ((t + 1) / 2) as i128;
    let center = |x: i128| {
        let r = x.rem_euclid(t as i128);
        (if r > t as i128 / 2 { r - t as i128 } else { r }) as i64
    };
    (
        center((plus + minus) * inverse_two),
        center((plus - minus) * inverse_two),
    )
}

#[test]
fn precharged_local_ternary_carry_gate_removes_residual_at_native_ring_size() {
    use std::collections::BTreeMap;
    let work = SecureConfig::secure_128().into_config();
    let q = work.primes.iter().map(|&p| p as u128).product::<u128>() as i128;
    let mut config = work.clone();
    config.primes = BOOT.to_vec();
    config.q = BOOT[0];
    validate_bootstrap_primes(&BOOT, config.n).unwrap();
    assert!(
        screen_bootstrap_security(&BOOT, config.n, 128)
            .unwrap()
            .meets_claim_under_both
    );
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x5445_524e_4152_59);
    let keys = ctx.generate_keys_dual(&mut rng);
    let native_secret = RNSSecretKey {
        s: RNSPolynomial {
            n: config.n,
            limbs: ctx
                .rns
                .mont_contexts
                .iter()
                .zip(&keys.secret_key.s.main)
                .map(|(mont, values)| values.iter().map(|&v| mont.to_montgomery(v)).collect())
                .collect(),
        },
    };
    let exact = ctx.try_exact_evaluator().unwrap();
    let arithmetic = exact.plan().certificate();
    let n = config.n as u128;
    let t = config.t as u128;
    let input_bound = config.eta as u128 * (2 * n + 1) + 1;
    let switch_bound = n
        * config.eta as u128
        * ((1u128 << arithmetic.base_bits) - 1)
        * arithmetic.digits_per_lane.iter().sum::<usize>() as u128;
    // Constant-plaintext BFV product bound, including component lift winding,
    // quadratic input noise, coefficient rounding and gadget-switch error.
    let factor = n * t * (n / 2 + 1) + (t - 1) / 2;
    let square_bound = 2 * input_bound * factor
        + (n * t * input_bound * input_bound).div_ceil(ctx.q_product)
        + (n * n + n + 1).div_ceil(2)
        + switch_bound;
    let output_bound = ((t - 1) / 2) * (square_bound + input_bound);
    assert!(output_bound < ctx.q_product / t / 2);
    let relin = exact.generate_hybrid_gadget_key_with_rng(&native_secret, &mut rng);
    let h = q / 2;
    let boundaries = [-h, -h + 1, -1, 0, 1, h - 1, h];
    let positions = [0, 1, ctx.n / 2, ctx.n - 1];
    let mut encrypted_checks = 0;
    let mut boundary_cases = 0;
    for secret in [-1i8, 0, 1] {
        // Key-holder precharge for ONE ternary coefficient, as a constant
        // plaintext. Generalizing to all coefficients has a separate cost.
        let mut scalar_secret = vec![0; ctx.n];
        scalar_secret[0] = secret;
        let encrypted = precharge(&ctx, &keys, &scalar_secret, &mut rng);
        // Evaluator boundary: fresh public evaluation key + encrypted trit.
        // No phase decryption or secret-dependent coefficient selection.
        let square = exact.try_mul_exact(&encrypted, &encrypted, &relin).unwrap();
        let mut cache = BTreeMap::new();
        for &r0 in &boundaries {
            for &r1 in &boundaries {
                let coefficients = local_coefficients(q, r0, r1, config.t);
                let decoded = cache.entry(coefficients).or_insert_with(|| {
                    let a = scale(&ctx, &square, coefficients.0);
                    let b = scale(&ctx, &encrypted, coefficients.1);
                    let output = ctx.add(&a, &b);
                    // Independent oracle starts after the complete gate.
                    encrypted_checks += positions.len();
                    decode_indices(&ctx, &output, &keys.secret_key, &positions, output_bound)
                });
                let expected = (r0 + r1 * secret as i128 + h).div_euclid(q);
                assert_eq!(decoded[0] as i128, expected.rem_euclid(config.t as i128));
                assert!(decoded[1..].iter().all(|&m| m == 0));
                boundary_cases += 1;
            }
        }
        assert_eq!(cache.len(), 5);
    }
    assert_eq!(boundary_cases, 147);
    assert_eq!(encrypted_checks, 60);
    eprintln!("nonlinear local gate: {encrypted_checks} encrypted coefficient checks, {boundary_cases} signed native boundary cases; depth=1; output_error_bound={output_bound}; bound independent of r0/r1 and their retained residual; full secret-sum gate still required");
}
