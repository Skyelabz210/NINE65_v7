//! Research-only return from a refreshed embedded polynomial to its original
//! dense work key. The evaluator has public switch material and no secret.

use super::public_refresh_source::{
    drop_last, embed, ordinary, PreparedRefreshSource, PublicRefreshSourceClient,
};
use super::rns_fhe::exact_mul::{ExactMulEvaluator, ExactTensor3, RNSHybridGadgetKey};
use super::rns_galois::{validate_main, validate_ternary_secret};
use super::{RNSCiphertext, RNSFHEContext, RNSSecretKey};
use crate::arithmetic::{rns::U512, wide::U1024, RNSPolynomial};
use crate::entropy::FheRng;
use crate::errors::{Nine65Error, Nine65Result};

#[path = "public_refresh_return_plan.rs"]
mod plan;
pub(crate) use plan::ReturnNoisePlan;

fn refused(reason: impl Into<String>) -> Nine65Error {
    Nine65Error::BootstrapFailed {
        reason: reason.into(),
    }
}

fn checked(value: Option<U1024>) -> Nine65Result<U1024> {
    value.ok_or_else(|| refused("public refresh return bound overflow"))
}

/// Only the checked public return evaluator constructs this capability.
pub(crate) struct ReturnedWorkProof {
    root: std::sync::Arc<super::public_refresh_source::CanonicalPlaintextRoot>,
    raw: RNSCiphertext,
    bound: U512,
    family: [u8; 32],
    source_lineage: [u8; 32],
}

impl ReturnedWorkProof {
    pub(crate) fn root(&self) -> &super::public_refresh_source::CanonicalPlaintextRoot {
        &self.root
    }
    pub(crate) fn family_id(&self) -> &[u8; 32] {
        &self.family
    }
    pub(crate) fn source_lineage(&self) -> &[u8; 32] {
        &self.source_lineage
    }
    pub(crate) fn into_parts(self) -> (RNSCiphertext, U512) {
        (self.raw, self.bound)
    }
}

pub(crate) struct PublicRefreshReturn {
    reduced: RNSFHEContext,
    plan: ReturnNoisePlan,
    switch: RNSHybridGadgetKey,
    family: [u8; 32],
}

impl PublicRefreshReturn {
    pub(crate) fn published_ciphertexts(&self) -> usize {
        self.switch.rlk.iter().map(Vec::len).sum()
    }

    /// Key-holder setup. The public object retains neither input secret.
    pub(crate) fn generate_with_rng<R: FheRng>(
        client: &PublicRefreshSourceClient,
        boot: &RNSFHEContext,
        boot_secret: &RNSSecretKey,
        base_bits: u32,
        rng: &mut R,
    ) -> Nine65Result<Self> {
        let work = client.work_context();
        let plan = ReturnNoisePlan::new(&work.config, &boot.config, base_bits)?;
        validate_ternary_secret(boot, boot_secret)?;
        let mut reduced_config = work.config.clone();
        reduced_config.n = boot.n;
        reduced_config.name = "public refresh return research context";
        let reduced = RNSFHEContext::try_new(&reduced_config)?;
        let destination = RNSSecretKey {
            s: embed(
                &client.work_secret_key().s,
                boot.n,
                work.config.primes.len(),
            ),
        };
        let target = zeroize::Zeroizing::new(RNSPolynomial {
            n: boot.n,
            limbs: boot_secret.s.limbs[..work.config.primes.len()].to_vec(),
        });
        let exact = ExactMulEvaluator::new_with_gadget_base_bits(&reduced, base_bits)
            .map_err(|e| refused(format!("return arithmetic plan: {e:?}")))?;
        let switch = exact.generate_hybrid_target_key(&destination, &target, rng);
        Ok(Self {
            reduced,
            plan,
            switch,
            family: *client.family_id(),
        })
    }

    /// Exact public bound after all drops, key switching and projection.
    pub(crate) fn output_bound(&self, ideal_error: U1024) -> Nine65Result<U512> {
        self.plan.output_bound(ideal_error)
    }

    /// Internal stage boundary: callers must provide the proved embedded
    /// message and ideal error produced by the matching slot-return circuit.
    /// This is deliberately not an externally callable raw import API.
    pub(crate) fn evaluate(
        &self,
        boot: &RNSFHEContext,
        source: &PreparedRefreshSource,
        embedded: &RNSCiphertext,
        ideal_error: U1024,
    ) -> Nine65Result<ReturnedWorkProof> {
        if source.certificate().family_id() != &self.family
            || boot.config.primes != self.plan.boot_primes
            || boot.t != self.reduced.t
            || boot.n != self.reduced.n
        {
            return Err(refused(
                "public return key, source family or context mismatch",
            ));
        }
        validate_main(boot, embedded)?;
        let bound = self.output_bound(ideal_error)?;
        let mut dropped = embedded.clone();
        for active in (self.reduced.config.primes.len() + 1..=self.plan.boot_primes.len()).rev() {
            dropped = drop_last(boot, &dropped, active);
        }
        let zero = RNSPolynomial {
            n: self.reduced.n,
            limbs: vec![vec![0; self.reduced.n]; self.reduced.config.primes.len()],
        };
        let tensor = ExactTensor3 {
            e0: ordinary(&self.reduced, &dropped.c0),
            e1: zero,
            e2: ordinary(&self.reduced, &dropped.c1),
            num_primes: self.reduced.config.primes.len(),
        };
        let switched =
            ExactMulEvaluator::new_with_gadget_base_bits(&self.reduced, self.plan.base_bits)
                .map_err(|e| refused(format!("return evaluator: {e:?}")))?
                .relinearize_tensor(&tensor, &self.switch)
                .map_err(|e| refused(format!("return public key switch: {e:?}")))?;
        let stride = self.reduced.n / self.plan.work_n;
        let project = |poly: RNSPolynomial| RNSPolynomial {
            n: self.plan.work_n,
            limbs: poly
                .limbs
                .iter()
                .map(|lane| lane.iter().copied().step_by(stride).collect())
                .collect(),
        };
        Ok(ReturnedWorkProof {
            root: source.certificate().root_capability(),
            raw: RNSCiphertext {
                c0: project(switched.c0),
                c1: project(switched.c1),
                num_primes: self.reduced.config.primes.len(),
            },
            bound,
            family: self.family,
            source_lineage: *source.certificate().lineage(),
        })
    }
}

#[cfg(test)]
#[path = "public_refresh_return_tests.rs"]
mod tests;
