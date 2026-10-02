//! Main-only Galois automorphisms for the native Montgomery ciphertext.
//! No legacy single-modulus key, anchor, or reconstructed coefficient is used.

use crate::arithmetic::RNSPolynomial;
use crate::entropy::FheRng;
use crate::errors::{Nine65Error, Nine65Result};
use crate::ops::rns_fhe::exact_mul::{ExactMulEvaluator, ExactTensor3, RNSHybridGadgetKey};
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
        let tensor = ExactTensor3 {
            e0: from_mont(sigma(self.ctx, &ct.c0, key.exponent)),
            e1: RNSPolynomial {
                limbs: vec![vec![0; self.ctx.n]; self.ctx.config.primes.len()],
                n: self.ctx.n,
            },
            e2: from_mont(sigma(self.ctx, &ct.c1, key.exponent)),
            num_primes: self.ctx.config.primes.len(),
        };
        self.exact
            .relinearize_tensor(&tensor, &key.switch)
            .map_err(|e| failure(format!("native Galois switch: {e:?}")))
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
