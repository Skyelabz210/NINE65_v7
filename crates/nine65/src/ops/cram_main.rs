//! Bounded scalar evaluation on the existing main-Q exact multiply route.
//! Client secret material and public evaluator material are separate. Ciphertext
//! fields and certificates are immutable; raw ciphertexts cannot be wrapped as fresh.

use super::exact_mul::{ExactMulError, RNSHybridGadgetKey, HYBRID_BASE_BITS};
use super::{RNSCiphertext, RNSFHEContext, RNSPublicKey, RNSSecretKey};
use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
use crate::arithmetic::RNSPolynomial;
use crate::entropy::{FheRng, SecureRng};
use crate::noise::certified::{CertifiedNoiseBound, ScalarNoiseModel};
use crate::params::FHEConfig;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[path = "wire_q.rs"]
pub mod wire_q;

#[derive(Debug, thiserror::Error)]
pub enum CramMainError {
    #[error("invalid main-Q parameters: {0}")]
    Parameters(String),
    #[error("ciphertext belongs to another context or key domain")]
    DomainMismatch,
    #[error("plaintext/scalar must be below t")]
    PlaintextRange,
    #[error("{0}")]
    NoiseExhausted(&'static str),
    #[error("exact main-Q arithmetic: {0}")]
    Arithmetic(#[from] ExactMulError),
    #[error("main-Q decoding failed")]
    Decode,
    #[error("OS entropy unavailable")]
    Entropy,
}

struct PublicState {
    ctx: RNSFHEContext,
    public_key: RNSPublicKey,
    noise: ScalarNoiseModel,
    context_id: [u8; 32],
    key_id: [u8; 32],
}

/// Only encryption and admitted operations can construct this value.
/// Cloning preserves its exact history bound and key domain.
///
/// ```compile_fail
/// use nine65::ops::cram_main::CramMainCiphertext;
/// fn reset(ct: &mut CramMainCiphertext) { ct.bound = Default::default(); }
/// ```
#[derive(Clone)]
pub struct CramMainCiphertext {
    raw: RNSCiphertext,
    bound: CertifiedNoiseBound,
    state: Arc<PublicState>,
}

impl CramMainCiphertext {
    pub fn noise_bound(&self) -> &CertifiedNoiseBound {
        &self.bound
    }
    pub fn remaining_millibits(&self) -> i64 {
        self.state.noise.remaining_millibits(&self.bound)
    }

    /// Deterministic |rho| bound for w=t*m+rho (mod t^2), derived from this
    /// ciphertext's immutable operation history and the full ternary key
    /// support. A bounded digit circuit needs radius <= B <= (t-1)/2.
    /// This bound alone does not implement or admit public refresh.
    pub fn prime_square_residual_radius(&self) -> u64 {
        self.state.noise.prime_square_residual_radius(&self.bound)
    }
}

/// Public key and evaluation key only; no decryption secret or noise observation.
pub struct CramMainEvaluator {
    state: Arc<PublicState>,
    relin: RNSHybridGadgetKey,
}

/// Client-owned secret. This is the only main-Q wrapper with a decrypt method.
pub struct CramMainClient {
    state: Arc<PublicState>,
    secret: RNSSecretKey,
}

impl CramMainEvaluator {
    pub fn generate(config: &FHEConfig) -> Result<(CramMainClient, Self), CramMainError> {
        Self::generate_with_rng(config, &mut SecureRng::new())
    }

    pub fn generate_with_rng<R: FheRng>(
        config: &FHEConfig,
        rng: &mut R,
    ) -> Result<(CramMainClient, Self), CramMainError> {
        crate::entropy::require_secure_rng(rng, "CramMainEvaluator::generate_with_rng");
        let digits = config
            .primes
            .iter()
            .map(|q| (64 - q.leading_zeros()).div_ceil(HYBRID_BASE_BITS) as usize)
            .sum();
        let noise = ScalarNoiseModel::new(config, digits, HYBRID_BASE_BITS)
            .map_err(|e| CramMainError::Parameters(e.into()))?;
        noise.fresh().map_err(CramMainError::NoiseExhausted)?;
        super::exact_mul::ExactMulPlan::new(&config.primes, config.n, config.t)?;
        for &q in &config.primes {
            crate::arithmetic::NTTEngine::try_new(q, config.n)
                .map_err(|e| CramMainError::Parameters(e.to_string()))?;
        }
        let ctx =
            RNSFHEContext::try_new(config).map_err(|e| CramMainError::Parameters(e.to_string()))?;
        let exact = ctx.try_exact_evaluator()?;
        let keys = ctx.generate_keys_with_rng(rng);
        let relin = exact.generate_hybrid_gadget_key_with_rng(&keys.secret_key, rng);
        let mut hasher = Sha256::new();
        hasher.update(b"NINE65-main-Q-scalar-v1");
        for value in [
            config.n as u64,
            config.t,
            config.eta as u64,
            config.primes.len() as u64,
        ] {
            hasher.update(value.to_le_bytes());
        }
        for q in &config.primes {
            hasher.update(q.to_le_bytes());
        }
        let mut key_id = [0; 32];
        getrandom::getrandom(&mut key_id).map_err(|_| CramMainError::Entropy)?;
        let state = Arc::new(PublicState {
            ctx,
            public_key: keys.public_key,
            noise,
            context_id: hasher.finalize().into(),
            key_id,
        });
        Ok((
            CramMainClient {
                state: state.clone(),
                secret: keys.secret_key,
            },
            Self { state, relin },
        ))
    }

    pub fn config(&self) -> &FHEConfig {
        &self.state.ctx.config
    }
    pub fn context_id(&self) -> &[u8; 32] {
        &self.state.context_id
    }
    pub fn key_id(&self) -> &[u8; 32] {
        &self.state.key_id
    }
    pub fn fresh_budget_millibits(&self) -> i64 {
        // Generation already admitted this same immutable fresh bound.
        self.state
            .noise
            .remaining_millibits(&self.state.noise.fresh().expect("admitted fresh bound"))
    }

    fn check(&self, ct: &CramMainCiphertext) -> Result<(), CramMainError> {
        if !Arc::ptr_eq(&self.state, &ct.state) {
            return Err(CramMainError::DomainMismatch);
        }
        Ok(())
    }

    fn output(&self, raw: RNSCiphertext, bound: CertifiedNoiseBound) -> CramMainCiphertext {
        CramMainCiphertext {
            raw,
            bound,
            state: self.state.clone(),
        }
    }

    pub fn encrypt(&self, value: u64) -> Result<CramMainCiphertext, CramMainError> {
        self.encrypt_with_rng(value, &mut SecureRng::new())
    }

    pub fn encrypt_with_rng<R: FheRng>(
        &self,
        value: u64,
        rng: &mut R,
    ) -> Result<CramMainCiphertext, CramMainError> {
        if value >= self.state.ctx.t {
            return Err(CramMainError::PlaintextRange);
        }
        let bound = self
            .state
            .noise
            .fresh()
            .map_err(CramMainError::NoiseExhausted)?;
        let raw = self
            .state
            .ctx
            .encrypt_with_rng(value, &self.state.public_key, rng);
        Ok(self.output(raw, bound))
    }

    pub fn add(
        &self,
        a: &CramMainCiphertext,
        b: &CramMainCiphertext,
    ) -> Result<CramMainCiphertext, CramMainError> {
        self.check(a)?;
        self.check(b)?;
        let bound = self
            .state
            .noise
            .add(&a.bound, &b.bound)
            .map_err(CramMainError::NoiseExhausted)?;
        Ok(self.output(self.state.ctx.add(&a.raw, &b.raw), bound))
    }

    pub fn sub(
        &self,
        a: &CramMainCiphertext,
        b: &CramMainCiphertext,
    ) -> Result<CramMainCiphertext, CramMainError> {
        self.check(a)?;
        self.check(b)?;
        let bound = self
            .state
            .noise
            .add(&a.bound, &b.bound)
            .map_err(CramMainError::NoiseExhausted)?;
        Ok(self.output(self.state.ctx.sub(&a.raw, &b.raw), bound))
    }

    pub fn negate(&self, a: &CramMainCiphertext) -> Result<CramMainCiphertext, CramMainError> {
        self.scale_signed(a, -1)
    }

    fn centered_scalar(&self, value: u64) -> Result<i64, CramMainError> {
        let t = self.state.ctx.t;
        if value >= t {
            return Err(CramMainError::PlaintextRange);
        }
        Ok(if value > t / 2 {
            value as i64 - t as i64
        } else {
            value as i64
        })
    }

    fn scale_signed(
        &self,
        a: &CramMainCiphertext,
        scalar: i64,
    ) -> Result<CramMainCiphertext, CramMainError> {
        self.check(a)?;
        let bound = self
            .state
            .noise
            .scalar(&a.bound, scalar)
            .map_err(CramMainError::NoiseExhausted)?;
        let ctx = &self.state.ctx;
        let scalars: Vec<u64> = ctx
            .config
            .primes
            .iter()
            .map(|&q| super::signed_to_mod(scalar, q))
            .collect();
        let raw = RNSCiphertext {
            c0: ctx.scalar_mul_rns_vec(&a.raw.c0, &scalars),
            c1: ctx.scalar_mul_rns_vec(&a.raw.c1, &scalars),
            num_primes: a.raw.num_primes,
        };
        Ok(self.output(raw, bound))
    }

    pub fn mul_plain(
        &self,
        a: &CramMainCiphertext,
        scalar: u64,
    ) -> Result<CramMainCiphertext, CramMainError> {
        self.scale_signed(a, self.centered_scalar(scalar)?)
    }

    pub fn add_plain(
        &self,
        a: &CramMainCiphertext,
        scalar: u64,
    ) -> Result<CramMainCiphertext, CramMainError> {
        self.check(a)?;
        let scalar = self.centered_scalar(scalar)?;
        let bound = self
            .state
            .noise
            .add_plain(&a.bound, scalar)
            .map_err(CramMainError::NoiseExhausted)?;
        let ctx = &self.state.ctx;
        let limbs = ctx
            .config
            .primes
            .iter()
            .zip(&ctx.delta_rns)
            .map(|(&q, &delta)| {
                let mut coefficients = vec![0; ctx.n];
                coefficients[0] =
                    ((super::signed_to_mod(scalar, q) as u128 * delta as u128) % q as u128) as u64;
                coefficients
            })
            .collect();
        let plain = ctx.to_montgomery_form(&RNSPolynomial { limbs, n: ctx.n });
        let mut raw = a.raw.clone();
        raw.c0 = raw.c0.add(&plain, &ctx.rns);
        Ok(self.output(raw, bound))
    }

    pub fn multiply(
        &self,
        a: &CramMainCiphertext,
        b: &CramMainCiphertext,
    ) -> Result<CramMainCiphertext, CramMainError> {
        self.check(a)?;
        self.check(b)?;
        let bound = self
            .state
            .noise
            .multiply(&a.bound, &b.bound)
            .map_err(CramMainError::NoiseExhausted)?;
        let raw =
            self.state
                .ctx
                .try_exact_evaluator()?
                .try_mul_exact(&a.raw, &b.raw, &self.relin)?;
        Ok(self.output(raw, bound))
    }
}

impl CramMainClient {
    pub fn decrypt(&self, ct: &CramMainCiphertext) -> Result<u64, CramMainError> {
        if !Arc::ptr_eq(&self.state, &ct.state) {
            return Err(CramMainError::DomainMismatch);
        }
        let ctx = &self.state.ctx;
        let inner = ctx.convert_from_montgomery_form(
            &ct.raw
                .c0
                .add(&ctx.rns_poly_mul(&ct.raw.c1, &self.secret.s), &ctx.rns),
        );
        let residues: Vec<u64> = inner.limbs.iter().map(|lane| lane[0]).collect();
        CanonicalScaleRound::new(&ctx.config.primes, ctx.t)
            .and_then(|scale| scale.scale_round(&residues))
            .map_err(|_| CramMainError::Decode)
    }
}

#[cfg(test)]
#[path = "cram_main_tests.rs"]
mod tests;
