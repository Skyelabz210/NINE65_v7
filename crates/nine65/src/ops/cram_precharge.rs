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
        validate_ternary_secret(ctx, boot_secret)?;
        let sum_bits: u32 = ctx
            .config
            .primes
            .iter()
            .map(|&q| 64 - q.leading_zeros())
            .sum();
        if sum_bits > 256 || ctx.config.eta as u128 > i64::MAX as u128 {
            return Err(Nine65Error::KeyGenFailed {
                reason: "CRAM precharge sampler or error exceeds its integer capacity".into(),
            });
        }
        require_secure_rng(rng, "CramPrechargedSecret::generate_with_rng");

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
                    source_trits
                        .iter()
                        .map(|&s| {
                            (s as i128 * ctx.delta_rns[lane] as i128).rem_euclid(q as i128) as u64
                        })
                        .collect()
                })
                .collect(),
            n: ctx.n,
        });
        let masked_secret = ctx.rns_poly_mul(&a, &boot_secret.s);
        let c0 = encoded.add(&error, &ctx.rns).sub(&masked_secret, &ctx.rns);
        Ok(Self {
            encrypted: RNSCiphertext {
                c0,
                c1: a,
                num_primes: ctx.config.primes.len(),
            },
            phase_error_bound: ctx.config.eta as u64,
        })
    }
}
