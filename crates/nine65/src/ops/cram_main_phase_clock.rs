//! Producer-bound ingress from immutable main-Q scalar ciphertexts to the
//! conditional phase-clock kernel. Conversion changes representation only;
//! it cannot reset an error bound, truncate the basis, or invent anchor state.

use super::{CramMainCiphertext, CramMainClient, CramMainEvaluator, PublicState};
use crate::arithmetic::phase_clock_plan::PhaseClockPlan;
use crate::arithmetic::rns::U512;
use crate::entropy::FheRng;
use crate::errors::Nine65Error;
use crate::noise::certified::CertifiedNoiseBound;
use crate::ops::phase_clock_return::PhaseClockReturnedCiphertext;
use crate::ops::public_phase_clock::{
    PublicPhaseClockEvaluator, PublicPhaseClockKey, PublicPhaseClockOutput,
    PublicPhaseClockRefreshKey,
};
use crate::ops::rns_fhe::{DualRNSCiphertext, DualRNSPoly, DualRNSSecretKey, RNSSecretKey};
use crate::params::FHEConfig;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum MainQPhaseClockError {
    #[error("phase-clock source belongs to another key/context domain")]
    DomainMismatch,
    #[error("phase-clock source plan does not match the complete certified main basis")]
    PlanMismatch,
    #[error("producer-issued phase bound exceeds the clock input allowance")]
    InputEnvelope,
    #[error("phase-clock source key is unregistered or belongs to another domain")]
    KeyDomainMismatch,
    #[error("returned phase-clock ciphertext has no admitted source receipt for this domain")]
    UncertifiedReturn,
    #[error("{0}")]
    NoiseExhausted(&'static str),
    #[error("phase-clock arithmetic: {0}")]
    Arithmetic(#[from] Nine65Error),
}

fn words(value: U512) -> (u128, u128, u128, u128) {
    (value.d3, value.d2, value.d1, value.d0)
}

fn bound_value(bound: &CertifiedNoiseBound) -> U512 {
    let [d0, d1, d2, d3] = bound.scaled_error_words();
    U512 { d0, d1, d2, d3 }
}

fn check_plan(state: &PublicState, plan: &PhaseClockPlan) -> Result<(), MainQPhaseClockError> {
    let config = &state.ctx.config;
    // CertifiedNoiseBound is expressed at FULL Q. A prefix cannot inherit
    // that bound or its BFV encoding merely by truncating ciphertext lanes.
    if plan.source_n() != config.n
        || plan.source_plaintext() != config.t
        || plan.source_level() != config.primes.len()
        || plan.source_primes() != config.primes
    {
        return Err(MainQPhaseClockError::PlanMismatch);
    }
    Ok(())
}

/// Only a main-Q evaluator in the ciphertext's actual issuance domain can
/// construct this input. Main coefficients and the exact bound are immutable.
/// The source plaintext remains scalar; this adapter does not establish a
/// history bound for arbitrary polynomial plaintexts or authorize refresh.
pub struct CramMainPhaseClockInput {
    ordinary: DualRNSCiphertext,
    bound: CertifiedNoiseBound,
    state: Arc<PublicState>,
}

impl CramMainPhaseClockInput {
    pub fn source_config(&self) -> &FHEConfig {
        &self.state.ctx.config
    }

    pub fn context_id(&self) -> &[u8; 32] {
        &self.state.context_id
    }

    pub fn key_id(&self) -> &[u8; 32] {
        &self.state.key_id
    }

    pub fn noise_bound(&self) -> &CertifiedNoiseBound {
        &self.bound
    }

    pub fn transduce_coefficient(
        &self,
        clock: &PublicPhaseClockEvaluator<'_>,
        key: &PublicPhaseClockKey,
        coefficient: usize,
    ) -> Result<PublicPhaseClockOutput, MainQPhaseClockError> {
        self.check_clock(clock, key)?;
        let mut output = clock.transduce_coefficient(&self.ordinary, coefficient, key)?;
        output.mark_admitted_source(self.state.context_id, self.state.key_id)?;
        Ok(output)
    }

    pub fn transduce_polynomial(
        &self,
        clock: &PublicPhaseClockEvaluator<'_>,
        key: &PublicPhaseClockKey,
    ) -> Result<PublicPhaseClockOutput, MainQPhaseClockError> {
        self.check_clock(clock, key)?;
        let mut output = clock.transduce_polynomial(&self.ordinary, key)?;
        output.mark_admitted_source(self.state.context_id, self.state.key_id)?;
        Ok(output)
    }

    pub fn refresh(
        &self,
        clock: &PublicPhaseClockEvaluator<'_>,
        key: &PublicPhaseClockRefreshKey,
    ) -> Result<PhaseClockReturnedCiphertext, MainQPhaseClockError> {
        let outer = self.transduce_polynomial(clock, key.clock_key())?;
        Ok(clock.return_to_work(&outer, &self.state.ctx, key)?)
    }

    fn check_clock(
        &self,
        clock: &PublicPhaseClockEvaluator<'_>,
        key: &PublicPhaseClockKey,
    ) -> Result<(), MainQPhaseClockError> {
        let plan = clock.source_plan();
        check_plan(&self.state, plan)?;
        if words(bound_value(&self.bound)) > words(plan.source_error_bound()) {
            return Err(MainQPhaseClockError::InputEnvelope);
        }
        if !key.matches_source_domain(self.context_id(), self.key_id()) {
            return Err(MainQPhaseClockError::KeyDomainMismatch);
        }
        Ok(())
    }
}

impl CramMainEvaluator {
    /// Accept only a sealed public return with this exact source-domain
    /// receipt. No caller-provided raw ciphertext or error assertion can be
    /// used to restart the immutable scalar operation history.
    pub fn admit_phase_clock_return(
        &self,
        returned: &PhaseClockReturnedCiphertext,
    ) -> Result<CramMainCiphertext, MainQPhaseClockError> {
        if returned.admitted_source() != Some((self.state.context_id, self.state.key_id)) {
            return Err(MainQPhaseClockError::UncertifiedReturn);
        }
        crate::ops::rns_galois::validate_main(&self.state.ctx, returned.ciphertext())?;
        let bound = self
            .state
            .noise
            .admit(returned.error_bound())
            .map_err(MainQPhaseClockError::NoiseExhausted)?;
        Ok(self.output(returned.ciphertext().clone(), bound))
    }

    pub fn phase_clock_input(
        &self,
        ct: &CramMainCiphertext,
        plan: &PhaseClockPlan,
    ) -> Result<CramMainPhaseClockInput, MainQPhaseClockError> {
        if !Arc::ptr_eq(&self.state, &ct.state) {
            return Err(MainQPhaseClockError::DomainMismatch);
        }
        check_plan(&self.state, plan)?;
        if words(bound_value(&ct.bound)) > words(plan.source_error_bound()) {
            return Err(MainQPhaseClockError::InputEnvelope);
        }
        let ctx = &self.state.ctx;
        let ordinary = |poly| {
            let mut converted = ctx.convert_from_montgomery_form(poly);
            DualRNSPoly {
                main: std::mem::take(&mut converted.limbs),
                // The phase-clock reads only the certified main basis. No
                // synthetic coprime anchor state is supplied by this adapter.
                anchor: Vec::new(),
                n: ctx.n,
            }
        };
        Ok(CramMainPhaseClockInput {
            ordinary: DualRNSCiphertext {
                c0: ordinary(&ct.raw.c0),
                c1: ordinary(&ct.raw.c1),
                level: ctx.config.primes.len(),
            },
            bound: ct.bound.clone(),
            state: self.state.clone(),
        })
    }
}

impl CramMainClient {
    /// Client-only common setup registers source controls and the return
    /// target under this same immutable key/context domain.
    pub fn generate_phase_clock_refresh_key_with_rng<R: FheRng>(
        &self,
        clock: &PublicPhaseClockEvaluator<'_>,
        boot_secret: &RNSSecretKey,
        rng: &mut R,
    ) -> Result<PublicPhaseClockRefreshKey, MainQPhaseClockError> {
        check_plan(&self.state, clock.source_plan())?;
        let mut key =
            clock.generate_refresh_key_with_rng(&self.state.ctx, &self.secret, boot_secret, rng)?;
        key.bind_source_domain(self.state.context_id, self.state.key_id)?;
        Ok(key)
    }

    /// Client-only registration of this domain's source key. The public
    /// evaluator subsequently receives an opaque source-domain-tagged key;
    /// neither source nor boot secret is an evaluation argument.
    pub fn generate_phase_clock_key_with_rng<R: FheRng>(
        &self,
        clock: &PublicPhaseClockEvaluator<'_>,
        boot_secret: &RNSSecretKey,
        rng: &mut R,
    ) -> Result<PublicPhaseClockKey, MainQPhaseClockError> {
        check_plan(&self.state, clock.source_plan())?;
        let ctx = &self.state.ctx;
        let mut converted = ctx.convert_from_montgomery_form(&self.secret.s);
        let source = DualRNSSecretKey {
            s: DualRNSPoly {
                main: std::mem::take(&mut converted.limbs),
                anchor: Vec::new(),
                n: ctx.n,
            },
        };
        let mut key = clock.generate_key_with_rng(boot_secret, &source, rng)?;
        key.bind_source_domain(self.state.context_id, self.state.key_id);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
    use crate::entropy::ShadowHarvester;
    use crate::ops::RNSFHEContext;
    use crate::params::SecureConfig;

    fn toy() -> FHEConfig {
        let mut config = SecureConfig::secure_128().into_config();
        config.n = 8;
        config.security_bits = 0;
        config.name = "certified_phase_clock_ingress";
        config
    }

    fn plan(config: &FHEConfig) -> PhaseClockPlan {
        PhaseClockPlan::new(
            config,
            config.primes.len(),
            256,
            17,
            U512::product_u64s(&config.primes).div_u64(128),
            config.n,
        )
        .unwrap()
    }

    #[test]
    fn immutable_ingress_rejects_foreign_domain_basis_prefix_and_understated_envelope() {
        let config = toy();
        let mut rng = ShadowHarvester::with_seed(0x494e4752455353);
        let (_, eval) = CramMainEvaluator::generate_with_rng(&config, &mut rng).unwrap();
        let (_, other) = CramMainEvaluator::generate_with_rng(&config, &mut rng).unwrap();
        let ct = eval.encrypt_with_rng(7, &mut rng).unwrap();
        let actual = plan(&config);
        let original = ct.noise_bound().clone();
        let input = eval.phase_clock_input(&ct, &actual).unwrap();
        assert_eq!(input.noise_bound(), &original);
        assert!(matches!(
            other.phase_clock_input(&ct, &actual),
            Err(MainQPhaseClockError::DomainMismatch)
        ));

        let mut reordered = config.clone();
        reordered.primes.swap(0, 1);
        assert!(matches!(
            eval.phase_clock_input(&ct, &plan(&reordered)),
            Err(MainQPhaseClockError::PlanMismatch)
        ));
        let prefix = PhaseClockPlan::new(
            &config,
            config.primes.len() - 1,
            256,
            17,
            U512::from_u64(0),
            config.n,
        )
        .unwrap();
        assert!(matches!(
            eval.phase_clock_input(&ct, &prefix),
            Err(MainQPhaseClockError::PlanMismatch)
        ));
        let zero = PhaseClockPlan::new(
            &config,
            config.primes.len(),
            256,
            17,
            U512::from_u64(0),
            config.n,
        )
        .unwrap();
        assert!(matches!(
            eval.phase_clock_input(&ct, &zero),
            Err(MainQPhaseClockError::InputEnvelope)
        ));
        assert_eq!(ct.noise_bound(), &original);
    }

    #[test]
    fn registered_client_key_transduces_and_foreign_or_untagged_keys_refuse() {
        let config = toy();
        let actual = plan(&config);
        let mut outer = config.clone();
        outer.n = actual.clock_n();
        let ctx = RNSFHEContext::try_new(&outer).unwrap();
        let clock = PublicPhaseClockEvaluator::new(&ctx, &actual).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x444f4d41494e);
        let (client, eval) = CramMainEvaluator::generate_with_rng(&config, &mut rng).unwrap();
        let (foreign, _) = CramMainEvaluator::generate_with_rng(&config, &mut rng).unwrap();
        let boot = ctx.generate_keys(&mut rng);
        let ct = eval.encrypt_with_rng(config.t - 3, &mut rng).unwrap();
        let input = eval.phase_clock_input(&ct, &actual).unwrap();
        let key = client
            .generate_phase_clock_key_with_rng(&clock, &boot.secret_key, &mut rng)
            .unwrap();
        let out = input.transduce_coefficient(&clock, &key, 0).unwrap();
        assert_eq!(
            out.admitted_source,
            Some((*eval.context_id(), *eval.key_id()))
        );
        let raw = clock
            .transduce_coefficient(&input.ordinary, 0, &key)
            .unwrap();
        assert_eq!(raw.admitted_source, None);
        let tight_plan = PhaseClockPlan::new(
            &config,
            config.primes.len(),
            256,
            17,
            U512::zero(),
            config.n,
        )
        .unwrap();
        let tight_clock = PublicPhaseClockEvaluator::new(&ctx, &tight_plan).unwrap();
        assert!(matches!(
            input.transduce_coefficient(&tight_clock, &key, 0),
            Err(MainQPhaseClockError::InputEnvelope)
        ));
        let phase = ctx.convert_from_montgomery_form(&out.ciphertext().c0.add(
            &ctx.rns_poly_mul(&out.ciphertext().c1, &boot.secret_key.s),
            &ctx.rns,
        ));
        let residues: Vec<_> = phase.limbs.iter().map(|lane| lane[0]).collect();
        assert_eq!(
            CanonicalScaleRound::new(&outer.primes, outer.t)
                .unwrap()
                .scale_round(&residues)
                .unwrap(),
            config.t - 3
        );
        let key = foreign
            .generate_phase_clock_key_with_rng(&clock, &boot.secret_key, &mut rng)
            .unwrap();
        assert!(matches!(
            input.transduce_coefficient(&clock, &key, 0),
            Err(MainQPhaseClockError::KeyDomainMismatch)
        ));
        assert!(matches!(
            input.transduce_polynomial(&clock, &key),
            Err(MainQPhaseClockError::KeyDomainMismatch)
        ));
        let mut converted = eval
            .state
            .ctx
            .convert_from_montgomery_form(&client.secret.s);
        let ordinary_secret = DualRNSSecretKey {
            s: DualRNSPoly {
                main: std::mem::take(&mut converted.limbs),
                anchor: Vec::new(),
                n: config.n,
            },
        };
        let untagged = clock
            .generate_key_with_rng(&boot.secret_key, &ordinary_secret, &mut rng)
            .unwrap();
        assert!(matches!(
            input.transduce_coefficient(&clock, &untagged, 0),
            Err(MainQPhaseClockError::KeyDomainMismatch)
        ));
    }

    #[test]
    fn certified_refresh_return_multiply_cycles_preserve_scalar_history_and_domain() {
        let config = toy();
        let actual = plan(&config);
        let mut outer = config.clone();
        outer.n = actual.clock_n();
        let ctx = RNSFHEContext::try_new(&outer).unwrap();
        let clock = PublicPhaseClockEvaluator::new(&ctx, &actual).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x524550454154);
        let (client, eval) = CramMainEvaluator::generate_with_rng(&config, &mut rng).unwrap();
        let (_, foreign) = CramMainEvaluator::generate_with_rng(&config, &mut rng).unwrap();
        let boot = ctx.generate_keys(&mut rng);
        let bundle = client
            .generate_phase_clock_refresh_key_with_rng(&clock, &boot.secret_key, &mut rng)
            .unwrap();
        let mut current = eval.encrypt_with_rng(3, &mut rng).unwrap();
        let mut expected = 3u64;
        // This is actual admitted history; no caller-supplied noise or fresh
        // wrapper is used to enter the public clock.
        for _ in 0..3 {
            current = eval.multiply(&current, &current).unwrap();
            expected = expected * expected % config.t;
        }
        let original = current.clone();
        let original_bound = original.noise_bound().clone();
        let cycles = if cfg!(debug_assertions) { 2 } else { 100 };
        for cycle in 0..cycles {
            let input = eval.phase_clock_input(&current, &actual).unwrap();
            let returned = input.refresh(&clock, &bundle).unwrap();
            if cycle == 0 {
                let again = clock
                    .refresh_returned(&eval.state.ctx, &returned, &bundle)
                    .unwrap();
                let again = eval.admit_phase_clock_return(&again).unwrap();
                assert_eq!(client.decrypt(&again).unwrap(), expected);
            }
            assert!(matches!(
                foreign.admit_phase_clock_return(&returned),
                Err(MainQPhaseClockError::UncertifiedReturn)
            ));
            let refreshed = eval.admit_phase_clock_return(&returned).unwrap();
            assert_eq!(client.decrypt(&refreshed).unwrap(), expected);
            current = eval.multiply(&refreshed, &refreshed).unwrap();
            // Avoid the repeated-square fixed point in this finite field;
            // keep a varying plaintext and admitted operation history.
            let offset = (cycle as u64 * 29 + 11) % config.t;
            current = eval.add_plain(&current, offset).unwrap();
            expected = (expected * expected + offset) % config.t;
            assert_eq!(client.decrypt(&current).unwrap(), expected);
        }
        assert_eq!(original.noise_bound(), &original_bound);

        // Conditional raw transduction does not obtain a history receipt,
        // even when it uses this domain's registered bundle.
        let raw = clock
            .refresh_main_polynomial(&eval.state.ctx, &original.raw, &bundle)
            .unwrap();
        assert_eq!(raw.admitted_source(), None);
        assert!(matches!(
            eval.admit_phase_clock_return(&raw),
            Err(MainQPhaseClockError::UncertifiedReturn)
        ));
        println!(
            "certified_roundtrip_cycles={cycles}; same_precharge=true; source_degree={}",
            config.n
        );
    }

    #[test]
    fn repeated_boot_family_cannot_redirect_an_admitted_return_to_another_client() {
        let config = toy();
        let actual = plan(&config);
        let mut outer = config.clone();
        outer.n = actual.clock_n();
        let ctx = RNSFHEContext::try_new(&outer).unwrap();
        let clock = PublicPhaseClockEvaluator::new(&ctx, &actual).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x444f4d41494e5245);
        let (client, eval) = CramMainEvaluator::generate_with_rng(&config, &mut rng).unwrap();
        let (other, _) = CramMainEvaluator::generate_with_rng(&config, &mut rng).unwrap();
        let boot = ctx.generate_keys(&mut rng);
        // Repeated setup randomness deliberately repeats the family nonce.
        // Source/target issuance domains must still remain distinct.
        let first = client
            .generate_phase_clock_refresh_key_with_rng(
                &clock,
                &boot.secret_key,
                &mut ShadowHarvester::with_seed(71),
            )
            .unwrap();
        let second = other
            .generate_phase_clock_refresh_key_with_rng(
                &clock,
                &boot.secret_key,
                &mut ShadowHarvester::with_seed(71),
            )
            .unwrap();
        assert!(first.clock_key().same_boot_family(second.clock_key()));
        let ct = eval.encrypt_with_rng(7, &mut rng).unwrap();
        let input = eval.phase_clock_input(&ct, &actual).unwrap();
        let admitted = input
            .transduce_polynomial(&clock, first.clock_key())
            .unwrap();
        assert!(clock
            .return_to_work(&admitted, &eval.state.ctx, &second)
            .is_err());
        let returned = clock
            .return_to_work(&admitted, &eval.state.ctx, &first)
            .unwrap();
        assert!(clock
            .refresh_returned(&eval.state.ctx, &returned, &second)
            .is_err());
    }
}
