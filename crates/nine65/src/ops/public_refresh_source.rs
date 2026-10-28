//! Public dense-work to sparse-source conversion for refresh research.
//!
//! Available only with `allow_insecure` (or unit tests). Arithmetic/history
//! certificates do not attest the sparse source's security or enable refresh.
//! Public evaluators contain no secret, decoder or observed-error callback.

use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
use crate::arithmetic::rns::U512;
use crate::arithmetic::RNSPolynomial;
use crate::entropy::{FheRng, SecureRng};
use crate::ops::exact_mul::{
    ExactMulError, ExactMulEvaluator, ExactMulPlan, ExactTensor3, RNSHybridGadgetKey,
    HYBRID_BASE_BITS,
};
use crate::ops::{RNSCiphertext, RNSFHEContext, RNSPublicKey, RNSSecretKey};
use crate::params::FHEConfig;
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[path = "public_refresh_source_plan.rs"]
mod plan;
pub use plan::PublicRefreshSourcePlan;
#[path = "public_refresh_source_kernels.rs"]
mod kernels;
use kernels::{balanced_secret, decode, derive_family_id, digest, encode};
pub(crate) use kernels::{drop_last, embed, ordinary};

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("invalid public refresh source parameters: {0}")]
    Parameters(&'static str),
    #[error("ciphertext belongs to another source/key family")]
    DomainMismatch,
    #[error("expected exactly N plaintext coefficients below t")]
    PlaintextRange,
    #[error("certified phase bound exhausted before source conversion")]
    NoiseExhausted,
    #[error("source switch exceeds the declared allocation limit")]
    ResourceLimit,
    #[error("exact source arithmetic: {0}")]
    Arithmetic(#[from] ExactMulError),
    #[error("source context/key operation: {0}")]
    Native(#[from] crate::errors::Nine65Error),
    #[error("client decode failed")]
    Decode,
}

fn words(v: U512) -> (u128, u128, u128, u128) {
    (v.d3, v.d2, v.d1, v.d0)
}

fn source_residual_radius(bound: U512, q: U512, t: u64, weight: usize) -> u64 {
    let numerator = bound
        .mul_u128(2 * t as u128)
        .add(q.sub(U512::from_u64(1)).mul_u128(weight as u128 + 1));
    let mut lo = 0;
    let mut hi = (t + weight as u64 + 1) / 2 + 1;
    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        if words(q.mul_u128(2 * mid as u128)) <= words(numerator) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

struct Family {
    plan: PublicRefreshSourcePlan,
    work: RNSFHEContext,
    source: RNSFHEContext,
    public_key: RNSPublicKey,
    id: [u8; 32],
}

/// Full-polynomial working ciphertext with immutable producer-issued history.
/// No API wraps caller-provided ciphertexts or bounds as trusted inputs.
///
/// ```compile_fail
/// use nine65::ops::public_refresh_source::SourceWorkCiphertext;
/// fn reset(ct: &mut SourceWorkCiphertext) { ct.bound = Default::default(); }
/// ```
#[derive(Clone)]
pub struct SourceWorkCiphertext {
    raw: RNSCiphertext,
    bound: U512,
    family: Arc<Family>,
    lineage: [u8; 32],
}

impl SourceWorkCiphertext {
    pub fn scaled_error_bound(&self) -> U512 {
        self.bound
    }
    pub fn lineage(&self) -> &[u8; 32] {
        &self.lineage
    }
}

/// Proof record produced alongside the exact immutable source ciphertext.
#[derive(Clone)]
pub struct SourceCertificate {
    input_lineage: [u8; 32],
    lineage: [u8; 32],
    family_id: [u8; 32],
    input_bound: U512,
    drop_bounds: Vec<U512>,
    source_bound: U512,
    source_weight: usize,
    embedding_stride: usize,
    q: U512,
    t: u64,
}

impl SourceCertificate {
    pub fn input_lineage(&self) -> &[u8; 32] {
        &self.input_lineage
    }
    pub fn lineage(&self) -> &[u8; 32] {
        &self.lineage
    }
    pub fn family_id(&self) -> &[u8; 32] {
        &self.family_id
    }
    pub fn input_bound(&self) -> U512 {
        self.input_bound
    }
    pub fn modulus_drop_bounds(&self) -> &[U512] {
        &self.drop_bounds
    }
    pub fn scaled_error_bound(&self) -> U512 {
        self.source_bound
    }
    pub fn source_weight(&self) -> usize {
        self.source_weight
    }
    pub fn embedding_stride(&self) -> usize {
        self.embedding_stride
    }

    /// Exact support radius for public component expansion to plaintext t².
    /// Uses the actual switched history and the key-holder-generated norm.
    pub fn prime_square_residual_radius(&self) -> u64 {
        source_residual_radius(self.source_bound, self.q, self.t, self.source_weight)
    }
}

/// Only `prepare` can issue this source/certificate pair. A borrowed raw view
/// is provided for subsequent public circuit stages; it cannot mutate history.
#[derive(Clone)]
pub struct PreparedRefreshSource {
    raw: RNSCiphertext,
    certificate: SourceCertificate,
    family: Arc<Family>,
}

impl PreparedRefreshSource {
    pub fn ciphertext(&self) -> &RNSCiphertext {
        &self.raw
    }
    pub fn certificate(&self) -> &SourceCertificate {
        &self.certificate
    }
    pub fn source_context(&self) -> &RNSFHEContext {
        &self.family.source
    }
}

/// Key-holder object. Only this type owns the original and sparse secrets.
pub struct PublicRefreshSourceClient {
    family: Arc<Family>,
    work_secret: RNSSecretKey,
    source_secret: RNSSecretKey,
}

/// Public polynomial operations and source preparation; no secrets stored.
pub struct PublicRefreshSourceEvaluator {
    family: Arc<Family>,
    relin: RNSHybridGadgetKey,
    source_switch: RNSHybridGadgetKey,
}

impl PublicRefreshSourcePlan {
    /// Key-holder setup for an explicitly unadmitted research candidate.
    /// The limit concerns the switch's raw coefficient payload, not peak RAM.
    pub fn generate_with_rng<R: FheRng>(
        &self,
        rng: &mut R,
        max_switch_key_bytes: usize,
    ) -> Result<(PublicRefreshSourceClient, PublicRefreshSourceEvaluator), SourceError> {
        if self.switch_key_bytes() > max_switch_key_bytes {
            return Err(SourceError::ResourceLimit);
        }
        crate::entropy::require_secure_rng(rng, "PublicRefreshSourcePlan::generate_with_rng");
        self.work_noise.fresh()?;
        let work = RNSFHEContext::try_new(&self.work)?;
        let source = RNSFHEContext::try_new(&self.source)?;
        let work_keys = work.generate_keys_with_rng(rng);
        let relin = work
            .try_exact_evaluator()?
            .generate_hybrid_gadget_key_with_rng(&work_keys.secret_key, rng);
        let source_secret = balanced_secret(&source, self.source_weight, rng);
        let target = zeroize::Zeroizing::new(embed(
            &work_keys.secret_key.s,
            source.n,
            source.config.primes.len(),
        ));
        let source_switch = ExactMulEvaluator::new_with_gadget_base_bits(&source, self.base_bits)?
            .generate_hybrid_target_key(&source_secret, &target, rng);
        let mut nonce = [0u8; 32];
        for chunk in nonce.chunks_exact_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
        }
        let id = derive_family_id(self, &work_keys.public_key, &source_switch, nonce);
        let family = Arc::new(Family {
            plan: self.clone(),
            work,
            source,
            public_key: work_keys.public_key,
            id,
        });
        Ok((
            PublicRefreshSourceClient {
                family: family.clone(),
                work_secret: work_keys.secret_key,
                source_secret,
            },
            PublicRefreshSourceEvaluator {
                family,
                relin,
                source_switch,
            },
        ))
    }
}

impl PublicRefreshSourceEvaluator {
    pub fn plan(&self) -> &PublicRefreshSourcePlan {
        &self.family.plan
    }

    pub fn encrypt(&self, values: &[u64]) -> Result<SourceWorkCiphertext, SourceError> {
        self.encrypt_with_rng(values, &mut SecureRng::new())
    }

    pub fn encrypt_with_rng<R: FheRng>(
        &self,
        values: &[u64],
        rng: &mut R,
    ) -> Result<SourceWorkCiphertext, SourceError> {
        let ctx = &self.family.work;
        if values.len() != ctx.n || values.iter().any(|&v| v >= ctx.t) {
            return Err(SourceError::PlaintextRange);
        }
        let bound = self.plan().work_noise.fresh()?;
        let mut raw = ctx.encrypt_with_rng(0, &self.family.public_key, rng);
        raw.c0 = raw.c0.add(&encode(ctx, values), &ctx.rns);
        Ok(self.output(raw, bound, b"encrypt", &[]))
    }

    fn check(&self, input: &SourceWorkCiphertext) -> Result<(), SourceError> {
        if !Arc::ptr_eq(&self.family, &input.family) {
            return Err(SourceError::DomainMismatch);
        }
        Ok(())
    }

    fn output(
        &self,
        raw: RNSCiphertext,
        bound: U512,
        operation: &[u8],
        parents: &[[u8; 32]],
    ) -> SourceWorkCiphertext {
        let lineage = digest(&self.family.id, operation, parents, &raw, bound);
        SourceWorkCiphertext {
            raw,
            bound,
            family: self.family.clone(),
            lineage,
        }
    }

    pub fn add(
        &self,
        a: &SourceWorkCiphertext,
        b: &SourceWorkCiphertext,
    ) -> Result<SourceWorkCiphertext, SourceError> {
        self.check(a)?;
        self.check(b)?;
        let bound = self.plan().work_noise.add(a.bound, b.bound)?;
        Ok(self.output(
            self.family.work.add(&a.raw, &b.raw),
            bound,
            b"add",
            &[a.lineage, b.lineage],
        ))
    }

    pub fn multiply(
        &self,
        a: &SourceWorkCiphertext,
        b: &SourceWorkCiphertext,
    ) -> Result<SourceWorkCiphertext, SourceError> {
        self.check(a)?;
        self.check(b)?;
        let bound = self.plan().work_noise.multiply(a.bound, b.bound)?;
        let raw =
            self.family
                .work
                .try_exact_evaluator()?
                .try_mul_exact(&a.raw, &b.raw, &self.relin)?;
        Ok(self.output(raw, bound, b"multiply", &[a.lineage, b.lineage]))
    }

    pub fn prepare(
        &self,
        input: &SourceWorkCiphertext,
    ) -> Result<PreparedRefreshSource, SourceError> {
        self.check(input)?;
        let plan = self.plan();
        let (drop_bounds, source_bound) = plan.bounds(input.bound)?;
        // All bounds pass before ciphertext work. No caller state is mutated.
        let mut raw = input.raw.clone();
        for active in (plan.source.primes.len() + 1..=plan.work.primes.len()).rev() {
            raw = drop_last(&self.family.work, &raw, active);
        }
        let source = &self.family.source;
        raw.c0 = embed(&raw.c0, source.n, source.config.primes.len());
        raw.c1 = embed(&raw.c1, source.n, source.config.primes.len());
        let tensor = ExactTensor3 {
            e0: ordinary(source, &raw.c0),
            e1: RNSPolynomial::zero(&source.rns),
            e2: ordinary(source, &raw.c1),
            num_primes: raw.num_primes,
        };
        let raw = ExactMulEvaluator::new_with_gadget_base_bits(source, plan.base_bits)?
            .relinearize_tensor(&tensor, &self.source_switch)?;
        let lineage = digest(
            &self.family.id,
            b"source",
            &[input.lineage],
            &raw,
            source_bound,
        );
        let certificate = SourceCertificate {
            input_lineage: input.lineage,
            lineage,
            family_id: self.family.id,
            input_bound: input.bound,
            drop_bounds,
            source_bound,
            source_weight: plan.source_weight,
            embedding_stride: source.n / plan.work.n,
            q: U512::product_u64s(&source.config.primes),
            t: source.t,
        };
        Ok(PreparedRefreshSource {
            raw,
            certificate,
            family: self.family.clone(),
        })
    }

    /// Resume working arithmetic only from the sealed return-stage producer.
    /// The original source and the returned proof must name this key family
    /// and the exact immutable source history; no caller bound is accepted.
    pub(crate) fn accept_refresh(
        &self,
        source: &PreparedRefreshSource,
        proof: crate::ops::public_refresh_return::ReturnedWorkProof,
    ) -> Result<SourceWorkCiphertext, SourceError> {
        if !Arc::ptr_eq(&self.family, &source.family)
            || proof.family_id() != &self.family.id
            || proof.source_lineage() != source.certificate.lineage()
        {
            return Err(SourceError::DomainMismatch);
        }
        let (raw, bound) = proof.into_parts();
        self.plan().work_noise.admit(bound)?;
        crate::ops::rns_galois::validate_main(&self.family.work, &raw)?;
        Ok(self.output(raw, bound, b"refresh-return", &[source.certificate.lineage]))
    }
}

impl PublicRefreshSourceClient {
    pub(crate) fn work_context(&self) -> &RNSFHEContext {
        &self.family.work
    }
    pub(crate) fn work_secret_key(&self) -> &RNSSecretKey {
        &self.work_secret
    }
    pub fn family_id(&self) -> &[u8; 32] {
        &self.family.id
    }
    pub fn plan(&self) -> &PublicRefreshSourcePlan {
        &self.family.plan
    }
    pub fn source_context(&self) -> &RNSFHEContext {
        &self.family.source
    }
    /// Key-holder access for generating the next stage's public precharge.
    pub fn source_secret_key(&self) -> &RNSSecretKey {
        &self.source_secret
    }
    pub fn decrypt_work(&self, input: &SourceWorkCiphertext) -> Result<Vec<u64>, SourceError> {
        if !Arc::ptr_eq(&self.family, &input.family) {
            return Err(SourceError::DomainMismatch);
        }
        decode(&self.family.work, &input.raw, &self.work_secret)
    }
    pub fn decrypt_source(&self, input: &PreparedRefreshSource) -> Result<Vec<u64>, SourceError> {
        if !Arc::ptr_eq(&self.family, &input.family) {
            return Err(SourceError::DomainMismatch);
        }
        decode(&self.family.source, &input.raw, &self.source_secret)
    }
}

#[cfg(test)]
#[path = "public_refresh_source_tests.rs"]
mod tests;
