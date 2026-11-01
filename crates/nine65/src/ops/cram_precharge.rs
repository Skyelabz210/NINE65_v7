//! Key-holder precharge for CRAM Safe Basis and dependent plaintext trays.
//!
//! One boot-secret encryption of the source secret's ternary polynomial is
//! generated for each requested plaintext coordinate. The public evaluator
//! can apply a public negacyclic residual polynomial to this ciphertext; the
//! key-holder secrets are never inputs to that evaluator.

use super::{sample_cbd_signed_rng, signed_to_mod, RNSCiphertext, RNSFHEContext, RNSSecretKey};
use crate::arithmetic::RNSPolynomial;
use crate::entropy::{require_secure_rng, FheRng, SecureRng};
use crate::errors::{Nine65Error, Nine65Result};
use crate::ops::rns_galois::validate_ternary_secret;
use zeroize::Zeroizing;

/// A secret-key encryption of the source trits at this coordinate's
/// plaintext scale. `phase_error_bound` is in *unscaled phase units* relative
/// to the centered floor-Delta encoding, before a public residual multiply.
pub struct CramPrechargedSecret {
    encrypted: RNSCiphertext,
    phase_error_bound: u64,
}

impl CramPrechargedSecret {
    pub fn encrypted_secret(&self) -> &RNSCiphertext {
        &self.encrypted
    }

    pub fn phase_error_bound(&self) -> u64 {
        self.phase_error_bound
    }

    /// Use only in key-holder setup, with the full-width boot secret.
    /// A fresh uniform main-Q mask and one bounded signed error polynomial
    /// give `c0+c1*s_boot = Delta*source_trits+e (mod Q)` with `|e|<=eta`.
    pub fn generate_secure(
        ctx: &RNSFHEContext,
        source_trits: &[i8],
        boot_secret: &RNSSecretKey,
    ) -> Nine65Result<Self> {
        Self::generate_with_rng(ctx, source_trits, boot_secret, &mut SecureRng::new())
    }

    pub fn generate_with_rng<R: FheRng>(
        ctx: &RNSFHEContext,
        source_trits: &[i8],
        boot_secret: &RNSSecretKey,
        rng: &mut R,
    ) -> Nine65Result<Self> {
        if source_trits.len() != ctx.n || source_trits.iter().any(|&s| !(-1..=1).contains(&s)) {
            return Err(Nine65Error::KeyGenFailed {
                reason: "CRAM precharge source secret must have N ternary coefficients".into(),
            });
        }
        let plaintext: Zeroizing<Vec<i64>> =
            Zeroizing::new(source_trits.iter().map(|&value| value as i64).collect());
        let encrypted = precharge_centered_polynomial_with_rng(ctx, &plaintext, boot_secret, rng)?;
        Ok(Self {
            encrypted,
            phase_error_bound: ctx.config.eta as u64,
        })
    }
}

/// Key-holder helper for precharging bounded plaintext polynomials such as
/// one-hot selector masks. Unlike `CramPrechargedSecret`, this accepts any
/// centered coefficient in `[-t/2,t/2]`; it does not relax the secret-trit
/// contract of that type. The returned phase satisfies
/// `c0+c1*s_boot = Delta*message+e (mod Q)` with `|e|<=eta`.
pub(crate) fn precharge_centered_polynomial_with_rng<R: FheRng>(
    ctx: &RNSFHEContext,
    message: &[i64],
    boot_secret: &RNSSecretKey,
    rng: &mut R,
) -> Nine65Result<RNSCiphertext> {
    if message.len() != ctx.n
        || message
            .iter()
            .any(|&coefficient| coefficient.unsigned_abs() > ctx.t / 2)
    {
        return Err(Nine65Error::KeyGenFailed {
            reason: "CRAM precharge message must have N centered coefficients".into(),
        });
    }
    validate_ternary_secret(ctx, boot_secret)?;
    // The main mask sampler draws independent uniform residues, so its
    // support is the full CRT product at every width admitted by the context.
    // No U256 reconstruction is used here. Keep the separate signed-error
    // capacity check: wide modulus support does not widen the sampler's eta.
    if ctx.config.eta as u128 > i64::MAX as u128 {
        return Err(Nine65Error::KeyGenFailed {
            reason: "CRAM precharge error exceeds its signed integer capacity".into(),
        });
    }
    require_secure_rng(rng, "precharge_centered_polynomial_with_rng");

    let a = ctx.to_montgomery_form(&ctx.sample_uniform_main_poly(rng));
    let e_signed: Zeroizing<Vec<i64>> = Zeroizing::new(
        (0..ctx.n)
            .map(|_| sample_cbd_signed_rng(rng, ctx.config.eta))
            .collect(),
    );
    let error = ctx.to_montgomery_form(&RNSPolynomial {
        limbs: ctx
            .config
            .primes
            .iter()
            .map(|&q| e_signed.iter().map(|&e| signed_to_mod(e, q)).collect())
            .collect(),
        n: ctx.n,
    });
    let encoded = ctx.to_montgomery_form(&RNSPolynomial {
        limbs: ctx
            .config
            .primes
            .iter()
            .enumerate()
            .map(|(lane, &q)| {
                message
                    .iter()
                    .map(|&value| {
                        (value as i128 * ctx.delta_rns[lane] as i128).rem_euclid(q as i128) as u64
                    })
                    .collect()
            })
            .collect(),
        n: ctx.n,
    });
    let masked_secret = ctx.rns_poly_mul(&a, &boot_secret.s);
    let c0 = encoded.add(&error, &ctx.rns).sub(&masked_secret, &ctx.rns);
    Ok(RNSCiphertext {
        c0,
        c1: a,
        num_primes: ctx.config.primes.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::ShadowHarvester;
    use crate::params::FHEConfig;

    const MAIN: [u64; 13] = [
        998244353,
        985661441,
        754974721,
        469762049,
        576460752301785089,
        576460752301391873,
        576460752300015617,
        576460752298835969,
        576460752298180609,
        576460752293134337,
        576460752291954689,
        576460752290775041,
        575870995836829697,
    ];
    // Independent Python integer oracle: [(prod(MAIN)//t) % q for q in MAIN].
    const DELTA_P: [u64; 13] = [
        468285463,
        616931387,
        669704982,
        363906640,
        247746975743962629,
        457794472042941261,
        323049179085442934,
        418714027063818738,
        194302730034435657,
        565175537144560381,
        271293757464344698,
        106026487451561749,
        271604932806146237,
    ];
    const DELTA_P2: [u64; 13] = [
        962883334,
        606879194,
        616608811,
        422423684,
        138777622351358886,
        39351309024156870,
        313791963726289616,
        379895053863641767,
        130103991485304848,
        343068609128797015,
        236228409254469986,
        96246999070038483,
        499780066758383338,
    ];

    fn context(t: u64) -> RNSFHEContext {
        RNSFHEContext::new(&FHEConfig {
            n: 16,
            primes: MAIN.to_vec(),
            q: MAIN[0],
            t,
            eta: 3,
            security_bits: 0,
            name: "wide CRAM precharge arithmetic fixture",
        })
    }

    fn secret(ctx: &RNSFHEContext) -> (RNSSecretKey, Vec<i64>) {
        let values: Vec<_> = (0..ctx.n).map(|j| (j % 3) as i64 - 1).collect();
        let limbs = MAIN
            .iter()
            .map(|&q| {
                values
                    .iter()
                    .map(|&v| (v as i128).rem_euclid(q as i128) as u64)
                    .collect()
            })
            .collect();
        (
            RNSSecretKey {
                s: ctx.to_montgomery_form(&RNSPolynomial { n: ctx.n, limbs }),
            },
            values,
        )
    }

    fn check_phase(
        ctx: &RNSFHEContext,
        ct: &RNSCiphertext,
        sk: &[i64],
        message: &[i64],
        expected_delta: &[u64; 13],
    ) {
        let mut common_errors = vec![0i64; ctx.n];
        for (lane, &q) in MAIN.iter().enumerate() {
            let mont = &ctx.rns.mont_contexts[lane];
            let c0: Vec<_> = ct.c0.limbs[lane]
                .iter()
                .map(|&v| mont.from_montgomery(v))
                .collect();
            let c1: Vec<_> = ct.c1.limbs[lane]
                .iter()
                .map(|&v| mont.from_montgomery(v))
                .collect();
            // Independent signed schoolbook phase; no evaluator NTT used.
            let mut phase: Vec<i128> = c0.iter().map(|&v| v as i128).collect();
            for (i, &a) in c1.iter().enumerate() {
                for (j, &s) in sk.iter().enumerate() {
                    let product = a as i128 * s as i128;
                    if i + j < ctx.n {
                        phase[i + j] += product;
                    } else {
                        phase[i + j - ctx.n] -= product;
                    }
                }
            }
            for (j, value) in phase.iter().enumerate() {
                let residue = (value - expected_delta[lane] as i128 * message[j] as i128)
                    .rem_euclid(q as i128);
                let error = if residue > q as i128 / 2 {
                    residue - q as i128
                } else {
                    residue
                };
                assert!(
                    error.unsigned_abs() <= ctx.config.eta as u128,
                    "lane {lane}, coefficient {j}"
                );
                if lane == 0 {
                    common_errors[j] = error as i64;
                } else {
                    assert_eq!(
                        error, common_errors[j] as i128,
                        "coherent error in every lane"
                    );
                }
            }
        }
    }

    #[test]
    fn wide_cram_precharge_matches_independent_full_polynomial_phase() {
        for (t, delta) in [(65537, DELTA_P), (65537 * 65537, DELTA_P2)] {
            let ctx = context(t);
            assert_eq!(ctx.config.rns_product_bit_length(), 650);
            let (key, signed_key) = secret(&ctx);
            let mut rng = ShadowHarvester::with_seed(0x4352_414d_6500 + t);
            let trits: Vec<_> = (0..ctx.n).map(|j| (j % 3) as i8 - 1).collect();
            let precharge =
                CramPrechargedSecret::generate_with_rng(&ctx, &trits, &key, &mut rng).unwrap();
            assert_eq!(precharge.phase_error_bound(), 3);
            let message: Vec<_> = trits.iter().map(|&s| s as i64).collect();
            check_phase(
                &ctx,
                precharge.encrypted_secret(),
                &signed_key,
                &message,
                &delta,
            );

            let boundary: Vec<_> = (0..ctx.n)
                .map(|j| match j % 5 {
                    0 => -(t as i64 / 2),
                    1 => t as i64 / 2,
                    2 => -1,
                    3 => 0,
                    _ => 1,
                })
                .collect();
            let ct =
                precharge_centered_polynomial_with_rng(&ctx, &boundary, &key, &mut rng).unwrap();
            check_phase(&ctx, &ct, &signed_key, &boundary, &delta);
        }
    }

    #[test]
    fn wide_cram_precharge_keeps_shape_secret_and_message_refusals() {
        let ctx = context(65537);
        let (mut key, _) = secret(&ctx);
        let mut rng = ShadowHarvester::with_seed(0x4352_414d_0001);
        assert!(CramPrechargedSecret::generate_with_rng(&ctx, &[0; 15], &key, &mut rng).is_err());
        assert!(CramPrechargedSecret::generate_with_rng(&ctx, &[2; 16], &key, &mut rng).is_err());
        assert!(
            precharge_centered_polynomial_with_rng(&ctx, &[32769; 16], &key, &mut rng).is_err()
        );
        key.s.limbs[0][0] = ctx.rns.mont_contexts[0].to_montgomery(2);
        assert!(CramPrechargedSecret::generate_with_rng(&ctx, &[0; 16], &key, &mut rng).is_err());
    }
}
