//! Main-only Galois automorphisms for the native Montgomery ciphertext.
//! No legacy single-modulus key, anchor, or reconstructed coefficient is used.

use crate::arithmetic::RNSPolynomial;
use crate::entropy::FheRng;
use crate::errors::{Nine65Error, Nine65Result};
use crate::ops::rns_fhe::exact_mul::{
    ExactMulEvaluator, ExactTensor3, PreparedHybridGadgetKey, RNSHybridGadgetKey,
};
use crate::ops::rns_fhe::{RNSCiphertext, RNSFHEContext, RNSSecretKey};
use zeroize::Zeroizing;

fn failure(reason: impl Into<String>) -> Nine65Error {
    Nine65Error::BootstrapFailed {
        reason: reason.into(),
    }
}

/// A typed sigma(s) switch key. The underlying gadget is deliberately private:
/// it is not an s^2 relinearization key.
pub struct RNSGaloisKey {
    exponent: u64,
    n: usize,
    primes: Vec<u64>,
    switch: RNSHybridGadgetKey,
}

/// Prepared sigma(s) switch key with private target typing and no raw-key copy.
/// Its transformed rows can be reused across plaintext trays over the same ring.
pub struct PreparedRNSGaloisKey {
    exponent: u64,
    n: usize,
    primes: Vec<u64>,
    switch: PreparedHybridGadgetKey,
}

impl PreparedRNSGaloisKey {
    #[cfg(any(test, feature = "allow_insecure"))]
    pub(crate) fn published_ciphertexts(&self) -> usize {
        self.switch.published_ciphertexts()
    }

    pub fn coefficient_storage_bytes(&self) -> usize {
        self.switch.coefficient_storage_bytes()
    }
}

pub struct RNSGaloisEvaluator<'a> {
    ctx: &'a RNSFHEContext,
    exact: ExactMulEvaluator<'a>,
}

pub(crate) fn validate_main(ctx: &RNSFHEContext, ct: &RNSCiphertext) -> Nine65Result<()> {
    ct.validate(ctx.n, ctx.config.primes.len())?;
    for poly in [&ct.c0, &ct.c1] {
        for (&q, lane) in ctx.config.primes.iter().zip(&poly.limbs) {
            if lane.iter().any(|&v| v >= q) {
                return Err(Nine65Error::InvalidParameter {
                    message: "noncanonical native Galois residue".into(),
                });
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_ternary_secret(ctx: &RNSFHEContext, sk: &RNSSecretKey) -> Nine65Result<()> {
    if sk.s.n != ctx.n
        || sk.s.limbs.len() != ctx.config.primes.len()
        || sk.s.limbs.iter().any(|lane| lane.len() != ctx.n)
        || ctx
            .config
            .primes
            .iter()
            .zip(&sk.s.limbs)
            .any(|(&q, lane)| lane.iter().any(|&v| v >= q))
    {
        return Err(Nine65Error::KeyGenFailed {
            reason: "native Galois secret shape or residue mismatch".into(),
        });
    }
    for j in 0..ctx.n {
        let mut sign = None;
        for (lane, &q) in ctx.config.primes.iter().enumerate() {
            let v = ctx.rns.mont_contexts[lane].from_montgomery(sk.s.limbs[lane][j]);
            let current = match v {
                0 => 0i8,
                1 => 1,
                v if v == q - 1 => -1,
                _ => {
                    return Err(Nine65Error::KeyGenFailed {
                        reason: "native Galois secret is not ternary".into(),
                    })
                }
            };
            if sign.is_some_and(|previous| previous != current) {
                return Err(Nine65Error::KeyGenFailed {
                    reason: "native Galois secret lanes disagree".into(),
                });
            }
            sign = Some(current);
        }
    }
    Ok(())
}

fn sigma(ctx: &RNSFHEContext, poly: &RNSPolynomial, exponent: u64) -> RNSPolynomial {
    let two_n = 2 * ctx.n as u128;
    let limbs = ctx
        .config
        .primes
        .iter()
        .zip(&poly.limbs)
        .map(|(&q, lane)| {
            let mut out = vec![0; ctx.n];
            for (j, &v) in lane.iter().enumerate() {
                let target = (j as u128 * exponent as u128 % two_n) as usize;
                out[target % ctx.n] = if target < ctx.n || v == 0 { v } else { q - v };
            }
            out
        })
        .collect();
    RNSPolynomial { limbs, n: ctx.n }
}

impl<'a> RNSGaloisEvaluator<'a> {
    pub fn new(ctx: &'a RNSFHEContext) -> Nine65Result<Self> {
        if ctx.n < 2
            || !ctx.n.is_power_of_two()
            || ctx.n as u128 * 2 > u64::MAX as u128
            || ctx.n != ctx.config.n
            || ctx.t != ctx.config.t
            || ctx.rns.primes != ctx.config.primes
            || ctx.rns.mont_contexts.len() != ctx.config.primes.len()
            || ctx.ntt_engines.len() != ctx.config.primes.len()
        {
            return Err(failure(
                "native Galois ring must be a supported power of two",
            ));
        }
        let exact = ctx
            .try_exact_evaluator()
            .map_err(|e| failure(format!("native Galois arithmetic capacity: {e:?}")))?;
        Ok(Self { ctx, exact })
    }

    pub fn generate_key_with_rng<R: FheRng>(
        &self,
        sk: &RNSSecretKey,
        exponent: u64,
        rng: &mut R,
    ) -> Nine65Result<RNSGaloisKey> {
        if exponent == 0 || exponent % 2 == 0 || exponent >= 2 * self.ctx.n as u64 {
            return Err(Nine65Error::InvalidParameter {
                message: "Galois exponent must be odd and canonical modulo 2N".into(),
            });
        }
        validate_ternary_secret(self.ctx, sk)?;
        let target = Zeroizing::new(sigma(self.ctx, &sk.s, exponent));
        let switch = self.exact.generate_hybrid_target_key(sk, &target, rng);
        Ok(RNSGaloisKey {
            exponent,
            n: self.ctx.n,
            primes: self.ctx.config.primes.clone(),
            switch,
        })
    }

    pub fn apply(&self, ct: &RNSCiphertext, key: &RNSGaloisKey) -> Nine65Result<RNSCiphertext> {
        if key.n != self.ctx.n || key.primes != self.ctx.config.primes {
            return Err(Nine65Error::BootstrapConfigMismatch {
                reason: "native Galois key basis mismatch".into(),
            });
        }
        validate_main(self.ctx, ct)?;
        self.exact
            .relinearize_tensor(&self.automorphism_tensor(ct, key.exponent), &key.switch)
            .map_err(|e| failure(format!("native Galois switch: {e:?}")))
    }

    /// Validate and transform a Galois key once. The caller may then drop the
    /// raw key; no second key copy is retained in this prepared object.
    pub fn prepare_key(&self, key: &RNSGaloisKey) -> Nine65Result<PreparedRNSGaloisKey> {
        if key.n != self.ctx.n || key.primes != self.ctx.config.primes {
            return Err(Nine65Error::BootstrapConfigMismatch {
                reason: "native Galois key basis mismatch".into(),
            });
        }
        let switch = self
            .exact
            .prepare_hybrid_gadget_key(&key.switch)
            .map_err(|e| failure(format!("native Galois key preparation: {e:?}")))?;
        Ok(PreparedRNSGaloisKey {
            exponent: key.exponent,
            n: key.n,
            primes: key.primes.clone(),
            switch,
        })
    }

    pub fn apply_prepared(
        &self,
        ct: &RNSCiphertext,
        key: &PreparedRNSGaloisKey,
    ) -> Nine65Result<RNSCiphertext> {
        if key.n != self.ctx.n || key.primes != self.ctx.config.primes {
            return Err(Nine65Error::BootstrapConfigMismatch {
                reason: "prepared native Galois key basis mismatch".into(),
            });
        }
        validate_main(self.ctx, ct)?;
        self.exact
            .relinearize_tensor_prepared(&self.automorphism_tensor(ct, key.exponent), &key.switch)
            .map_err(|e| failure(format!("prepared native Galois switch: {e:?}")))
    }

    fn automorphism_tensor(&self, ct: &RNSCiphertext, exponent: u64) -> ExactTensor3 {
        let from_mont = |poly: RNSPolynomial| RNSPolynomial {
            limbs: self
                .ctx
                .rns
                .mont_contexts
                .iter()
                .zip(&poly.limbs)
                .map(|(mont, lane)| lane.iter().map(|&v| mont.from_montgomery(v)).collect())
                .collect(),
            n: self.ctx.n,
        };
        ExactTensor3 {
            e0: from_mont(sigma(self.ctx, &ct.c0, exponent)),
            e1: RNSPolynomial {
                limbs: vec![vec![0; self.ctx.n]; self.ctx.config.primes.len()],
                n: self.ctx.n,
            },
            e2: from_mont(sigma(self.ctx, &ct.c1, exponent)),
            num_primes: self.ctx.config.primes.len(),
        }
    }
}

/// Public monomial multiplication: a signed permutation in every main lane.
pub(crate) fn shift(ctx: &RNSFHEContext, ct: &RNSCiphertext, exponent: usize) -> RNSCiphertext {
    let map = |poly: &RNSPolynomial| RNSPolynomial {
        limbs: ctx
            .config
            .primes
            .iter()
            .zip(&poly.limbs)
            .map(|(&q, lane)| {
                let mut out = vec![0; ctx.n];
                for (j, &v) in lane.iter().enumerate() {
                    let target = (j + exponent) % (2 * ctx.n);
                    out[target % ctx.n] = if target < ctx.n || v == 0 { v } else { q - v };
                }
                out
            })
            .collect(),
        n: ctx.n,
    };
    RNSCiphertext {
        c0: map(&ct.c0),
        c1: map(&ct.c1),
        num_primes: ct.num_primes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::ShadowHarvester;
    use crate::params::FHEConfig;

    #[test]
    fn prepared_galois_is_bit_identical_and_reusable_across_plaintext_trays() {
        let cfg = FHEConfig {
            n: 8,
            primes: vec![998244353, 985661441, 754974721, 469762049],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 80,
            name: "prepared_galois_oracle",
        };
        let ctx = RNSFHEContext::new(&cfg);
        let mut high_cfg = cfg.clone();
        high_cfg.t = 4295098369;
        let high = RNSFHEContext::new(&high_cfg);
        let ev = RNSGaloisEvaluator::new(&ctx).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x6A1015);
        let keys = ctx.generate_keys(&mut rng);
        for exponent in [3, 15] {
            let raw = ev
                .generate_key_with_rng(&keys.secret_key, exponent, &mut rng)
                .unwrap();
            let prepared = ev.prepare_key(&raw).unwrap();
            assert!(prepared.coefficient_storage_bytes() > 0);
            for view in [&ctx, &high] {
                let eval = RNSGaloisEvaluator::new(view).unwrap();
                let ct = view.encrypt(19, &keys.public_key, &mut rng);
                let expected = eval.apply(&ct, &raw).unwrap();
                let actual = eval.apply_prepared(&ct, &prepared).unwrap();
                assert_eq!(actual.c0.limbs, expected.c0.limbs);
                assert_eq!(actual.c1.limbs, expected.c1.limbs);
                assert_eq!(
                    view.try_exact_evaluator()
                        .unwrap()
                        .try_decrypt_exact(&actual, &keys.secret_key)
                        .unwrap(),
                    19
                );
                let mut malformed = ct;
                malformed.c0.limbs[0][0] = cfg.primes[0];
                assert!(eval.apply_prepared(&malformed, &prepared).is_err());
            }
            let mut foreign = cfg.clone();
            foreign.primes.swap(0, 1);
            foreign.q = foreign.primes[0];
            let other = RNSFHEContext::new(&foreign);
            let eval = RNSGaloisEvaluator::new(&other).unwrap();
            assert!(eval.prepare_key(&raw).is_err());
            let ct = ctx.encrypt(19, &keys.public_key, &mut rng);
            assert!(eval.apply_prepared(&ct, &prepared).is_err());
        }
    }
}
