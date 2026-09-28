//! Fresh, non-circular key material for the expanded BFV inner product.
//!
//! The work secret is encrypted under an independently generated boot secret,
//! with centered `-Delta` encoding for -1. The public key object contains only
//! a main-basis ciphertext; the separate key-holder result retains boot keys
//! for verification and future key switching. Digit-removal/rotation keys are
//! not claimed by this inner-product key type.

use crate::arithmetic::RNSPolynomial;
use crate::entropy::{require_secure_rng, FheRng, SecureRng};
use crate::errors::{Nine65Error, Nine65Result};
use crate::ops::expanded_bootstrap::ExpandedPhaseEvaluator;
use crate::ops::rns_fhe::{DualRNSKeySet, DualRNSSecretKey, RNSCiphertext};
use crate::params::FHEConfig;
use zeroize::Zeroizing;

pub use crate::ops::prime_power_phase::{PrimePowerBootstrapKey, PrimePowerBootstrapKeySet};

pub struct ExpandedBootstrapKey {
    pub(crate) enc_s: RNSCiphertext,
    pub(crate) primes: Vec<u64>,
    pub(crate) n: usize,
    pub(crate) plaintext_modulus: u64,
    pub(crate) base_plaintext: u64,
    pub(crate) exponent: u32,
    pub(crate) eta: usize,
    pub(crate) work_levels: usize,
}

/// Key-holder material. Only `bootstrap_key` is sent to the phase evaluator.
pub struct ExpandedBootstrapKeySet {
    pub bootstrap_key: ExpandedBootstrapKey,
    pub boot_keys: DualRNSKeySet,
}

impl ExpandedBootstrapKey {
    pub fn encrypted_secret(&self) -> &RNSCiphertext {
        &self.enc_s
    }

    pub fn generate_secure(
        work_config: &FHEConfig,
        work_sk: &DualRNSSecretKey,
        evaluator: &ExpandedPhaseEvaluator<'_>,
    ) -> Nine65Result<ExpandedBootstrapKeySet> {
        let mut rng = SecureRng::new();
        Self::generate_with_rng(work_config, work_sk, evaluator, &mut rng)
    }

    /// Generate the boot key pair and Enc_P(s_work), after validating every
    /// work-secret main lane. Malformed keys are refused before consuming RNG.
    pub fn generate_with_rng<R: FheRng>(
        work_config: &FHEConfig,
        work_sk: &DualRNSSecretKey,
        evaluator: &ExpandedPhaseEvaluator<'_>,
        rng: &mut R,
    ) -> Nine65Result<ExpandedBootstrapKeySet> {
        require_secure_rng(rng, "ExpandedBootstrapKey::generate_with_rng");
        let ctx = evaluator.ctx;
        if work_config.n != ctx.n
            || work_config.t != evaluator.base_plaintext
            || work_config.primes.len() < 2
            || work_sk.s.n != work_config.n
            || work_sk.s.main.len() != work_config.primes.len()
            || work_sk
                .s
                .main
                .iter()
                .any(|lane| lane.len() != work_config.n)
        {
            return Err(Nine65Error::KeyGenFailed {
                reason: "expanded bootstrap work-key shape or parameter mismatch".into(),
            });
        }
        if evaluator.certificate().security_screen.binding_bits < work_config.security_bits as u32 {
            return Err(Nine65Error::SecurityLevelNotMet {
                bits: evaluator.certificate().security_screen.binding_bits,
                required: work_config.security_bits as u32,
            });
        }
        if work_config
            .primes
            .iter()
            .any(|&prime| prime < 3 || prime % 2 == 0)
        {
            return Err(Nine65Error::KeyGenFailed {
                reason: "expanded bootstrap work basis must be odd non-degenerate moduli".into(),
            });
        }
        let first = work_config.primes[0];
        let mut signed: Zeroizing<Vec<i8>> = Zeroizing::new(Vec::with_capacity(ctx.n));
        for (coefficient, &value) in work_sk.s.main[0].iter().enumerate() {
            let sign = match value {
                0 => 0,
                1 => 1,
                value if value == first - 1 => -1,
                _ => {
                    return Err(Nine65Error::KeyGenFailed { reason: format!("expanded bootstrap work secret is non-ternary at coefficient {coefficient}") });
                }
            };
            signed.push(sign);
        }
        for (lane, (&prime, coefficients)) in
            work_config.primes.iter().zip(&work_sk.s.main).enumerate()
        {
            for (coefficient, (&value, &sign)) in coefficients.iter().zip(signed.iter()).enumerate()
            {
                let expected = match sign {
                    -1 => prime - 1,
                    0 => 0,
                    _ => 1,
                };
                if value != expected {
                    return Err(Nine65Error::KeyGenFailed { reason: format!("expanded bootstrap work secret has inconsistent main lane {lane}, coefficient {coefficient}") });
                }
            }
        }
        let boot_keys = ctx.generate_keys_dual_with_rng(rng);
        let zero = ctx.encrypt_dual_with_rng(0, &boot_keys.public_key, rng);
        let mut c0 = Vec::with_capacity(ctx.config.primes.len());
        let mut c1 = Vec::with_capacity(ctx.config.primes.len());
        for (lane, &prime) in ctx.config.primes.iter().enumerate() {
            let mont = &ctx.rns.mont_contexts[lane];
            let delta = ctx.delta_rns[lane];
            let encoded: Vec<u64> = zero.c0.main[lane]
                .iter()
                .zip(signed.iter())
                .map(|(&value, &sign)| {
                    let value = match sign {
                        -1 => (value as u128 + prime as u128 - delta as u128) % prime as u128,
                        1 => (value as u128 + delta as u128) % prime as u128,
                        _ => value as u128,
                    };
                    mont.to_montgomery(value as u64)
                })
                .collect();
            c0.push(encoded);
            c1.push(
                zero.c1.main[lane]
                    .iter()
                    .map(|&value| mont.to_montgomery(value))
                    .collect(),
            );
        }
        let enc_s = RNSCiphertext {
            c0: RNSPolynomial {
                limbs: c0,
                n: ctx.n,
            },
            c1: RNSPolynomial {
                limbs: c1,
                n: ctx.n,
            },
            num_primes: ctx.config.primes.len(),
        };
        Ok(ExpandedBootstrapKeySet {
            bootstrap_key: Self {
                enc_s,
                primes: ctx.config.primes.clone(),
                n: ctx.n,
                plaintext_modulus: ctx.t,
                base_plaintext: evaluator.base_plaintext,
                exponent: evaluator.exponent,
                eta: ctx.config.eta,
                work_levels: work_config.primes.len(),
            },
            boot_keys,
        })
    }
}
