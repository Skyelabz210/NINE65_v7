//! Research tests only: encrypted plaintext coordinates, never raw coprime
//! RLWE lanes. Key-holder precharge has the work secret; evaluation does not.
//! Decryption and scalar reconstruction below are explicitly test oracles.

use super::evaluate_centered_components;
use crate::arithmetic::main_only_base_ext::MainOnlyBaseExt;
use crate::arithmetic::rns::{U256, U512};
use crate::arithmetic::RNSPolynomial;
use crate::entropy::ShadowHarvester;
use crate::ops::rns_fhe::cram_precharge::CramPrechargedSecret;
use crate::ops::rns_fhe::{
    DualRNSKeySet, DualRNSSecretKey, RNSCiphertext, RNSFHEContext, RNSSecretKey,
};
use crate::params::SecureConfig;

const ROOT: [u64; 8] = [2, 3, 5, 7, 11, 13, 17, 19];
// Preserve all eight root roles while increasing independent range. These
// are plaintext coordinate moduli; NTT still runs on the main Q primes.
const POWER_FRAME: [u64; 8] = [
    131072, 177147, 390625, 117649, 161051, 371293, 83521, 130321,
];

pub(super) fn signed_secret(sk: &DualRNSSecretKey, first_prime: u64) -> Vec<i8> {
    sk.s.main[0]
        .iter()
        .map(|&value| match value {
            0 => 0,
            1 => 1,
            value if value == first_prime - 1 => -1,
            _ => panic!("non-ternary test secret"),
        })
        .collect()
}

// Only the key holder calls this. Every output is a full main-Q ciphertext
// under the SAME independent boot secret, with its own plaintext scale.
pub(super) fn precharge(
    ctx: &RNSFHEContext,
    keys: &DualRNSKeySet,
    s: &[i8],
    rng: &mut ShadowHarvester,
) -> RNSCiphertext {
    let native_secret = RNSSecretKey {
        s: RNSPolynomial {
            n: ctx.n,
            limbs: ctx
                .rns
                .mont_contexts
                .iter()
                .zip(&keys.secret_key.s.main)
                .map(|(mont, lane)| lane.iter().map(|&v| mont.to_montgomery(v)).collect())
                .collect(),
        },
    };
    let precharged = CramPrechargedSecret::generate_with_rng(ctx, s, &native_secret, rng).unwrap();
    assert_eq!(precharged.phase_error_bound(), ctx.config.eta as u64);
    precharged.encrypted_secret().clone()
}

#[test]
fn key_holder_precharge_has_exact_eta_phase_error() {
    let config = SecureConfig::secure_128().into_config();
    let ctx = RNSFHEContext::try_new(&config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x4352_414d_5052_4543);
    let source_keys = ctx.generate_keys_dual(&mut rng);
    let boot_keys = ctx.generate_keys_dual(&mut rng);
    let source = signed_secret(&source_keys.secret_key, config.primes[0]);
    let encrypted = precharge(&ctx, &boot_keys, &source, &mut rng);
    let mut first_lane_error = vec![0i64; config.n];
    for (lane, &prime) in config.primes.iter().enumerate() {
        let mont = &ctx.rns.mont_contexts[lane];
        let c0: Vec<_> = encrypted.c0.limbs[lane]
            .iter()
            .map(|&v| mont.from_montgomery(v))
            .collect();
        let c1: Vec<_> = encrypted.c1.limbs[lane]
            .iter()
            .map(|&v| mont.from_montgomery(v))
            .collect();
        let product = ctx.ntt_engines[lane].multiply(&c1, &boot_keys.secret_key.s.main[lane]);
        for j in 0..config.n {
            let phase = ((c0[j] as u128 + product[j] as u128) % prime as u128) as u64;
            let ideal =
                (source[j] as i128 * ctx.delta_rns[lane] as i128).rem_euclid(prime as i128) as u64;
            let residue = (phase as u128 + prime as u128 - ideal as u128) % prime as u128;
            let error = if residue > prime as u128 / 2 {
                residue as i64 - prime as i64
            } else {
                residue as i64
            };
            assert!(
                error.unsigned_abs() <= config.eta as u64,
                "lane={lane}, j={j}"
            );
            if lane == 0 {
                first_lane_error[j] = error;
            } else {
                assert_eq!(
                    error, first_lane_error[j],
                    "inconsistent error at lane={lane}, j={j}"
                );
            }
        }
    }
}

pub(super) fn decode_indices(
    ctx: &RNSFHEContext,
    ct: &RNSCiphertext,
    sk: &DualRNSSecretKey,
    indices: &[usize],
    error_bound: u128,
) -> Vec<u64> {
    let phases: Vec<Vec<u64>> = ctx
        .config
        .primes
        .iter()
        .enumerate()
        .map(|(lane, &prime)| {
            let mont = &ctx.rns.mont_contexts[lane];
            let c1: Vec<_> = ct.c1.limbs[lane]
                .iter()
                .map(|&v| mont.from_montgomery(v))
                .collect();
            let product = ctx.ntt_engines[lane].multiply(&c1, &sk.s.main[lane]);
            ct.c0.limbs[lane]
                .iter()
                .zip(product)
                .map(|(&v, product)| {
                    ((mont.from_montgomery(v) as u128 + product as u128) % prime as u128) as u64
                })
                .collect()
        })
        .collect();
    let q = U256::product_u64s(&ctx.config.primes);
    indices
        .iter()
        .map(|&j| {
            let residues: Vec<_> = phases.iter().map(|lane| lane[j]).collect();
            let phase = ctx.rns.to_u256_level(&residues, residues.len());
            let (rounded, _) = phase.mul_u64(ctx.t).add(q.shr1()).div_mod_u256(q);
            assert_eq!(rounded.hi, 0);
            let decoded = (rounded.lo % ctx.t as u128) as u64;
            let scaled = phase.mul_u64(ctx.t);
            let ideal = q.mul_u64(decoded);
            let mut distance = if scaled.ge(ideal) {
                scaled.sub(ideal)
            } else {
                ideal.sub(scaled)
            };
            let period = q.mul_u64(ctx.t);
            if distance.ge(period.shr1()) {
                distance = period.sub(distance);
            }
            assert!(
                U256::from_u128(error_bound).mul_u64(ctx.t).ge(distance),
                "exact-grid noise at j={j}, m={}",
                ctx.t
            );
            decoded
        })
        .collect()
}

// Direct schoolbook negacyclic coefficient, independent of the evaluator's
// NTT. Reducing each term first keeps this oracle in a small signed i128.
fn phase_mod(c0: &[u64], c1: &[u64], s: &[i8], j: usize, modulus: u64) -> u64 {
    let n = s.len();
    let mut sum = c0[j] as i128;
    for (i, &value) in c1.iter().enumerate() {
        let k = (j + n - i) % n;
        let sign = if i + k < n { 1 } else { -1 };
        sum += value as i128 * s[k] as i128 * sign;
    }
    sum.rem_euclid(modulus as i128) as u64
}

pub(super) fn inverse(a: u64, m: u64) -> u64 {
    let (mut r, mut next_r) = (m as i128, a as i128);
    let (mut t, mut next_t) = (0i128, 1i128);
    while next_r != 0 {
        let quotient = r / next_r;
        (r, next_r) = (next_r, r - quotient * next_r);
        (t, next_t) = (next_t, t - quotient * next_t);
    }
    assert_eq!(r, 1, "coprime CRT factor");
    t.rem_euclid(m as i128) as u64
}

#[test]
fn precharged_safe_basis_clear_rank_bridge_recovers_every_native_carry() {
    // This follow-up tests the REAL rank/projector kernels, but its inputs
    // are CLEAR residues. Passing it does not make those kernels homomorphic.
    let config = SecureConfig::secure_128().into_config();
    let q = config.primes.iter().map(|&p| p as u128).product::<u128>();
    let product = ROOT.iter().product::<u64>();
    let frame_to_main = MainOnlyBaseExt::new(&POWER_FRAME, &config.primes).unwrap();
    let main_to_safe = MainOnlyBaseExt::new(&config.primes, &[product]).unwrap();
    let root_to_safe = MainOnlyBaseExt::new(&ROOT, &[product]).unwrap();
    let q_inverse = inverse((q % product as u128) as u64, product);
    let before = crate::arithmetic::rns::to_u256_level_calls::get();
    let mut checked = 0;
    for k in -(config.n as i128 / 2)..=config.n as i128 / 2 {
        for g in [-1i128, 0, 1] {
            // These S=kQ+g all satisfy the native signed S bound. Generate
            // their coordinates directly without forming the wide scalar S.
            let frame: Vec<_> = POWER_FRAME
                .iter()
                .map(|&m| {
                    ((k.rem_euclid(m as i128) * (q % m as u128) as i128 + g).rem_euclid(m as i128))
                        as u64
                })
                .collect();
            let root: Vec<_> = frame.iter().zip(ROOT).map(|(&r, p)| r % p).collect();
            let mut main = vec![0; config.primes.len()];
            frame_to_main.project_centered(&frame, &mut main).unwrap();
            let mut g_safe = [0];
            main_to_safe.project_centered(&main, &mut g_safe).unwrap();
            assert_eq!(g_safe[0] as i128, g.rem_euclid(product as i128));
            let mut s_safe = [0];
            root_to_safe.project(&root, &mut s_safe).unwrap();
            let residue = ((s_safe[0] as u128 + product as u128 - g_safe[0] as u128)
                * q_inverse as u128
                % product as u128) as i128;
            let recovered = if residue * 2 >= product as i128 {
                residue - product as i128
            } else {
                residue
            };
            assert_eq!(recovered, k, "clear rank bridge k={k}, g={g}");
            checked += 1;
        }
    }
    assert_eq!(crate::arithmetic::rns::to_u256_level_calls::get(), before);
    assert_eq!(checked, 24579);
    eprintln!("clear rank bridge: {checked} recoveries covering every native carry; encrypted rank is still unimplemented");
}

#[test]
fn precharged_safe_basis_encrypts_native_residual_coordinates() {
    let config = SecureConfig::secure_128().into_config();
    assert_eq!(config.eta, 3);
    let work = RNSFHEContext::try_new(&config).unwrap();
    let mut rng = ShadowHarvester::with_seed(0x5341_4645_5052);
    let work_keys = work.generate_keys_dual(&mut rng);
    let boot_keys = work.generate_keys_dual(&mut rng);
    assert_ne!(work_keys.secret_key.s.main, boot_keys.secret_key.s.main);
    let s = signed_secret(&work_keys.secret_key, config.primes[0]);
    let input = work.encrypt_dual(7, &work_keys.public_key, &mut rng);
    assert_eq!(work.decrypt_dual(&input, &work_keys.secret_key), 7);
    let mut targets = ROOT.to_vec();
    targets.extend(POWER_FRAME);
    let projector = MainOnlyBaseExt::new(&config.primes, &targets).unwrap();
    let mut residuals = [
        vec![vec![0; config.n]; targets.len()],
        vec![vec![0; config.n]; targets.len()],
    ];
    for (component, poly) in [&input.c0, &input.c1].iter().enumerate() {
        for j in 0..config.n {
            // Ri = centered_Q(t*ci). Projection acts only on PUBLIC
            // components, before any secret-dependent multiplication.
            let main: Vec<_> = config
                .primes
                .iter()
                .enumerate()
                .map(|(lane, &prime)| {
                    (poly.main[lane][j] as u128 * config.t as u128 % prime as u128) as u64
                })
                .collect();
            let mut output = vec![0; targets.len()];
            projector.project_centered(&main, &mut output).unwrap();
            for (lane, value) in output.into_iter().enumerate() {
                residuals[component][lane][j] = value;
            }
        }
    }
    let indices: Vec<_> = (0..16).map(|i| i * (config.n - 1) / 15).collect();
    let mut root_outputs = Vec::new();
    let mut root_decoded: Vec<Vec<u64>> = Vec::new();
    let mut combined_error = 0u128;
    let mut checked = 0;
    for (lane, &modulus) in targets.iter().enumerate() {
        let mut encoding = config.clone();
        encoding.t = modulus;
        let ctx = RNSFHEContext::try_new(&encoding).unwrap();
        let q = U512::product_u64s(&config.primes);
        let beta = (2 * config.n as u128 + 1) * config.eta as u128;
        let remainder = q.mod_u64(modulus);
        let error = U512::from_u128(beta * config.n as u128 * (modulus / 2) as u128)
            .add(U512::from_u64(remainder).mul_u128(config.n as u128 + 1))
            .add(U512::from_u64(remainder / 2 + remainder % 2));
        let half_delta = q.div_u64(modulus).div_u64(2);
        assert!(
            (error.d3, error.d2, error.d1, error.d0)
                < (half_delta.d3, half_delta.d2, half_delta.d1, half_delta.d0)
        );
        let key = precharge(&ctx, &boot_keys, &s, &mut rng);
        let output =
            evaluate_centered_components(&ctx, &residuals[0][lane], &residuals[1][lane], &key);
        assert_eq!(output.num_primes, config.primes.len());
        for component in [&output.c0, &output.c1] {
            assert_eq!(component.n, config.n);
            assert_eq!(component.limbs.len(), config.primes.len());
            for (values, &prime) in component.limbs.iter().zip(&config.primes) {
                assert_eq!(values.len(), config.n);
                assert!(values.iter().all(|&v| v < prime));
            }
        }
        assert_eq!((error.d3, error.d2, error.d1), (0, 0, 0));
        let decoded = decode_indices(&ctx, &output, &boot_keys.secret_key, &indices, error.d0);
        for (&j, &actual) in indices.iter().zip(&decoded) {
            assert_eq!(
                actual,
                phase_mod(&residuals[0][lane], &residuals[1][lane], &s, j, modulus),
                "modulus={modulus}, j={j}"
            );
            checked += 1;
        }
        if lane < ROOT.len() {
            let product = ROOT.iter().product::<u64>();
            combined_error += inverse((product / modulus) % modulus, modulus) as u128 * error.d0;
            root_decoded.push(decoded);
            root_outputs.push(output);
        } else {
            for (&actual, &root) in decoded.iter().zip(&root_decoded[lane - ROOT.len()]) {
                assert_eq!(
                    actual % ROOT[lane - ROOT.len()],
                    root,
                    "higher-power/root coherence"
                );
            }
        }
    }
    assert_eq!(checked, 256);

    // CRT assembly into S8's SMALL plaintext range is linear when each
    // coordinate uses the same boot secret. The modulus Q stays unchanged.
    let product = ROOT.iter().product::<u64>();
    let mut combined = root_outputs[0].clone();
    for limb in [&mut combined.c0, &mut combined.c1] {
        for values in &mut limb.limbs {
            values.fill(0);
        }
    }
    for (&modulus, output) in ROOT.iter().zip(&root_outputs) {
        let weight = inverse((product / modulus) % modulus, modulus);
        for (dst, src) in [
            (&mut combined.c0, &output.c0),
            (&mut combined.c1, &output.c1),
        ] {
            for (lane, &prime) in config.primes.iter().enumerate() {
                for (value, &term) in dst.limbs[lane].iter_mut().zip(&src.limbs[lane]) {
                    *value =
                        ((*value as u128 + weight as u128 * term as u128) % prime as u128) as u64;
                }
            }
        }
    }
    let mut combined_config = config.clone();
    combined_config.t = product;
    let combined_ctx = RNSFHEContext::try_new(&combined_config).unwrap();
    assert!(combined_error < combined_ctx.q_product / product as u128 / 2);
    let decoded = decode_indices(
        &combined_ctx,
        &combined,
        &boot_keys.secret_key,
        &indices,
        combined_error,
    );
    for (&j, &actual) in indices.iter().zip(&decoded) {
        let expected = ROOT
            .iter()
            .enumerate()
            .fold(0u128, |acc, (lane, &modulus)| {
                let weight = inverse((product / modulus) % modulus, modulus);
                acc + (product / modulus) as u128
                    * weight as u128
                    * phase_mod(&residuals[0][lane], &residuals[1][lane], &s, j, modulus) as u128
            })
            % product as u128;
        assert_eq!(actual as u128, expected, "CRT assembly at j={j}");
    }
    eprintln!("precharge: {checked} encrypted native phase-coordinate checks, 16 encrypted S8 CRT assemblies, exact-grid noise bounds and 128 root/power coherence checks; all main-Q, independent boot secret; no encrypted carry extraction");
}
