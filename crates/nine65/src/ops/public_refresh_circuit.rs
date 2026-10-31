//! Executable public refresh research backend, gated by `allow_insecure`.
//!
//! This backend supplies the encrypted carry omitted by legacy Phase 1. Its
//! evaluator never owns a secret. The sparse-source and circular evaluation
//! key security assumptions are not production admitted; successful arithmetic
//! execution does not open the legacy public-refresh security gate.

use super::bounded_digit_circuit::SplitDigitEvaluator;
use super::direct_slot_phase::DirectSlotPhaseKey;
use super::public_refresh_return::{PublicRefreshReturn, ReturnNoisePlan};
use super::public_refresh_slots::{PublicSlotReturn, SlotReturnKeys};
use super::public_refresh_source::{
    PublicRefreshSourceClient, PublicRefreshSourceEvaluator, PublicRefreshSourcePlan,
    SourceWorkCiphertext,
};
use super::{PreparedHybridGadgetKey, RNSFHEContext, RNSSecretKey};
use crate::arithmetic::{rns::U512, wide::U1024, RNSPolynomial};
use crate::entropy::{FheRng, SecureRng};
use crate::errors::{Nine65Error, Nine65Result};
use crate::params::FHEConfig;

#[path = "public_refresh_key_graph.rs"]
pub mod key_graph;

fn refused(reason: impl Into<String>) -> Nine65Error {
    Nine65Error::BootstrapFailed {
        reason: reason.into(),
    }
}

/// Deterministic bounds computed before any key material is allocated.
#[derive(Clone, Debug)]
pub struct PublicRefreshCircuitCertificate {
    pub key_graph: key_graph::KeyGraphCertificate,
    pub ring_degree: usize,
    pub work_degree: usize,
    /// Residual rho support used by G/H, not the quotient K radius.
    pub carry_radius: usize,
    pub phase_value_bound: u64,
    /// Signed integer K support certified from the source norm and rho bound.
    pub signed_carry_radius: u64,
    pub ciphertext_products: usize,
    pub inverse_ciphertext_babies: usize,
    pub inverse_plaintext_diagonals: usize,
    pub inverse_galois_calls: usize,
    pub phase_error_bound: U1024,
    pub carry_error_bound: U1024,
    /// Fused 36/37 lift round-trip, before slot return. No remainder LUTs.
    pub lift_restoration: AdjacentLiftRestorationCertificate,
    pub restored_error_bound: U1024,
    pub returned_scaled_error_bound: U512,
    pub next_square_source_radius: u64,
}

/// Certificate for the specific query affine + (g + 36*kappa - shift).
/// Given same-source views of Y=K+shift, the parenthesis is exactly K.
/// The compiler consumes the already-derived encrypted K directly. This
/// certificate does not provide independent encrypted g, a, or kappa queries.
#[derive(Clone, Debug)]
pub struct AdjacentLiftRestorationCertificate {
    pub shift: u64,
    pub shifted_upper_bound: u64,
    pub capacity: u64,
    pub additional_ciphertext_products: usize,
    pub output_error_bound: U1024,
}

impl AdjacentLiftRestorationCertificate {
    fn new(p: u64, radius: u64, affine: U1024, carry: U1024) -> Nine65Result<Self> {
        let span = radius
            .checked_mul(2)
            .ok_or_else(|| refused("adjacent lift interval overflow"))?;
        if span >= 36 * 37 || span >= p {
            return Err(refused(
                "adjacent lift query lacks a unique signed interval",
            ));
        }
        Ok(Self {
            shift: radius,
            shifted_upper_bound: span,
            capacity: 36 * 37,
            additional_ciphertext_products: 0,
            output_error_bound: affine
                .checked_add(carry)
                .ok_or_else(|| refused("adjacent lift restoration error overflow"))?,
        })
    }

    fn apply(
        &self,
        ctx: &RNSFHEContext,
        affine: &super::RNSCiphertext,
        carry: &super::RNSCiphertext,
    ) -> super::RNSCiphertext {
        // Eliminate the entire round-trip before execution:
        // g+36*((g-a) mod37)=Y, then Y-shift=K in F_p.
        // No ciphertext for either remainder or the shifted Y is allocated.
        ctx.add(affine, carry)
    }
}

/// Immutable arithmetic plan for an explicitly unadmitted research backend.
pub struct PublicRefreshCircuitPlan {
    source: PublicRefreshSourcePlan,
    high: FHEConfig,
    baby: usize,
    radius: usize,
    key_limit: usize,
    certificate: PublicRefreshCircuitCertificate,
}

impl PublicRefreshCircuitPlan {
    /// Native N8192 work / N32768 outer-ring research tuple. It is available
    /// only under `allow_insecure`; it carries no production-security grant.
    pub fn native_research(max_phase_key_bytes: usize) -> Nine65Result<Self> {
        let work = FHEConfig {
            n: 8192,
            primes: vec![998244353, 985661441, 754974721, 469762049],
            q: 998244353,
            t: 65537,
            eta: 3,
            security_bits: 0,
            name: "public refresh native research work tuple",
        };
        let source = PublicRefreshSourcePlan::new(&work, 8192, 2, 96, 3)
            .map_err(|e| refused(e.to_string()))?;
        let high = FHEConfig {
            n: 32768,
            primes: vec![
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
            ],
            q: 998244353,
            t: 65537 * 65537,
            eta: 3,
            security_bits: 0,
            name: "public refresh native research Q650 outer tuple",
        };
        Self::new(source, high, 128, 49, max_phase_key_bytes)
    }
    /// Validate all circuit and return bounds before key generation. The
    /// memory limit here covers the coherent phase-bank coefficient payload.
    pub fn new(
        source: PublicRefreshSourcePlan,
        high: FHEConfig,
        baby: usize,
        radius: usize,
        max_phase_key_bytes: usize,
    ) -> Nine65Result<Self> {
        let source_config = source.source_config();
        if source_config.n.checked_mul(4) != Some(high.n)
            || source_config.t.checked_mul(source_config.t) != Some(high.t)
            || source_config.t != 65537
            || high.n > 32768
        {
            return Err(refused(
                "research refresh needs outer N=4*source N and scale p²",
            ));
        }
        if high.primes.len() < 2
            || high.primes.len() > 16
            || high.eta > u32::MAX as usize
            || high.primes.iter().enumerate().any(|(i, &q)| {
                q >= (1u64 << 63)
                    || !crate::params::is_prime(q)
                    || !crate::params::is_ntt_compatible(q, high.n)
                    || crate::params::gcd(q, high.t) != 1
                    || high.primes[..i].contains(&q)
            })
        {
            return Err(refused(
                "research refresh requires distinct compatible main primes and bounded eta",
            ));
        }
        let digits: usize = high
            .primes
            .iter()
            .map(|q| (64 - q.leading_zeros()).div_ceil(10) as usize)
            .sum();
        let giant_storage = if baby < source_config.n {
            digits + 1
        } else {
            0
        };
        let bytes = high
            .n
            .checked_mul(high.primes.len())
            .and_then(|v| v.checked_mul(16))
            .and_then(|v| v.checked_mul(baby.checked_mul(2)?.checked_add(giant_storage)?))
            .ok_or_else(|| refused("phase-bank allocation size overflow"))?;
        if bytes > max_phase_key_bytes || source.switch_key_bytes() > max_phase_key_bytes {
            return Err(refused(
                "phase or source key exceeds the declared coefficient allocation limit",
            ));
        }
        let high_ctx = RNSFHEContext::try_new(&high)?;
        let mut low_config = high.clone();
        low_config.t = source_config.t;
        let low_ctx = RNSFHEContext::try_new(&low_config)?;
        let phase_error = DirectSlotPhaseKey::phase_error_bound(
            &high_ctx,
            source_config.n,
            source_config.t,
            baby,
        )?;
        let q = U1024::checked_product_u64s(&high.primes)
            .ok_or_else(|| refused("research refresh modulus overflow"))?;
        if q.mod_u64(high.t) != Some(1) {
            return Err(refused("coherent phase precharge requires Q=1 modulo p²"));
        }
        let digit =
            SplitDigitEvaluator::new(&high_ctx, &low_ctx, radius, phase_error, phase_error)?;
        let phase_value_bound = super::public_refresh_source::direct_phase_value_bound(
            source_config.t,
            source.source_weight(),
        );
        let signed_carry_radius = super::public_refresh_source::direct_phase_quotient_radius(
            source_config.t,
            source.source_weight(),
            radius as u64,
        );
        if 2 * phase_value_bound as u128 >= high.t as u128
            || 2 * signed_carry_radius >= source_config.t
        {
            return Err(refused("direct phase lacks a unique signed quotient lift"));
        }
        let slots = PublicSlotReturn::new(&low_ctx, source_config.n)?;
        let carry_error = digit.certificate().output_error;
        let lift_restoration = AdjacentLiftRestorationCertificate::new(
            source_config.t,
            signed_carry_radius,
            phase_error,
            carry_error,
        )?;
        let restored_error = lift_restoration
            .output_error_bound
            .checked_mul_u128(slots.certificate().input_error_factor)
            .and_then(|v| v.checked_add(U1024::from_u128(slots.certificate().added_error)))
            .ok_or_else(|| refused("research refresh error certificate overflow"))?;
        let return_plan = ReturnNoisePlan::new(source.work_config(), &low_config, 3)?;
        if return_plan.switch_key_bytes() > max_phase_key_bytes {
            return Err(refused(
                "return key exceeds the declared coefficient allocation limit",
            ));
        }
        let returned = return_plan.output_bound(restored_error)?;
        let next_square_source_radius = source
            .next_square_source_radius(returned)
            .map_err(|e| refused(e.to_string()))?;
        if next_square_source_radius > radius as u64 {
            return Err(refused(
                "returned bound cannot fund the next square and refresh",
            ));
        }
        let certificate = PublicRefreshCircuitCertificate {
            key_graph: key_graph::KeyGraphCertificate::new(&source, &high, baby),
            ring_degree: high.n,
            work_degree: source.work_config().n,
            carry_radius: radius,
            phase_value_bound,
            signed_carry_radius,
            ciphertext_products: digit.certificate().ciphertext_products,
            inverse_ciphertext_babies: slots.certificate().ciphertext_babies,
            inverse_plaintext_diagonals: slots.certificate().plaintext_diagonals,
            inverse_galois_calls: slots.certificate().galois_calls,
            phase_error_bound: phase_error,
            carry_error_bound: carry_error,
            lift_restoration,
            restored_error_bound: restored_error,
            returned_scaled_error_bound: returned,
            next_square_source_radius,
        };
        Ok(Self {
            source,
            high,
            baby,
            radius,
            key_limit: max_phase_key_bytes,
            certificate,
        })
    }

    pub fn certificate(&self) -> &PublicRefreshCircuitCertificate {
        &self.certificate
    }

    pub fn generate(self) -> Nine65Result<(PublicRefreshSourceClient, PublicRefreshCircuit)> {
        self.generate_with_rng(&mut SecureRng::new())
    }

    /// Key-holder setup. The returned evaluator stores only public keys.
    pub fn generate_with_rng<R: FheRng>(
        self,
        rng: &mut R,
    ) -> Nine65Result<(PublicRefreshSourceClient, PublicRefreshCircuit)> {
        crate::entropy::require_secure_rng(rng, "PublicRefreshCircuitPlan::generate_with_rng");
        let (client, source) = self
            .source
            .generate_with_rng(rng, self.key_limit)
            .map_err(|e| refused(e.to_string()))?;
        let high = RNSFHEContext::try_new(&self.high)?;
        let mut low_config = self.high.clone();
        low_config.t = self.source.source_config().t;
        let low = RNSFHEContext::try_new(&low_config)?;
        let trits = zeroize::Zeroizing::new(rng.ternary_vector(high.n));
        let secret = RNSSecretKey {
            s: RNSPolynomial {
                n: high.n,
                limbs: high
                    .config
                    .primes
                    .iter()
                    .zip(&high.rns.mont_contexts)
                    .map(|(&q, mont)| {
                        trits
                            .iter()
                            .map(|&s| mont.to_montgomery((s as i128).rem_euclid(q as i128) as u64))
                            .collect()
                    })
                    .collect(),
            },
        };
        let phase = DirectSlotPhaseKey::generate_with_rng(
            &client,
            &high,
            &low,
            &secret,
            self.baby,
            self.key_limit,
            rng,
        )?;
        let exact = high
            .try_exact_evaluator()
            .map_err(|e| refused(e.to_string()))?;
        let raw_relin = exact.generate_hybrid_gadget_key_with_rng(&secret, rng);
        let relin = exact
            .prepare_hybrid_gadget_key(&raw_relin)
            .map_err(|e| refused(e.to_string()))?;
        drop(raw_relin);
        let inverse = PublicSlotReturn::new(&low, self.source.source_config().n)?
            .generate_keys(&secret, rng)?;
        let return_key = PublicRefreshReturn::generate_with_rng(&client, &low, &secret, 3, rng)?;
        let [public, work_relin, source_switch] = source.published_ciphertexts();
        let (phase_bank, phase_galois) = phase.published_ciphertexts();
        self.certificate.key_graph.verify_generated_counts([
            public,
            work_relin,
            source_switch,
            phase_bank,
            relin.published_ciphertexts(),
            phase_galois + inverse.published_ciphertexts(),
            return_key.published_ciphertexts(),
        ])?;
        drop(secret);
        let evaluator = PublicRefreshCircuit {
            plan: self,
            high,
            low,
            source,
            phase,
            relin,
            inverse,
            return_key,
            refreshes: 0,
        };
        Ok((client, evaluator))
    }
}

#[cfg(test)]
#[path = "public_refresh_circuit_tests.rs"]
mod tests;

/// Public arithmetic evaluator. Its ciphertext inputs carry immutable
/// producer-issued bounds and history, including after each refresh.
pub struct PublicRefreshCircuit {
    plan: PublicRefreshCircuitPlan,
    high: RNSFHEContext,
    low: RNSFHEContext,
    source: PublicRefreshSourceEvaluator,
    phase: DirectSlotPhaseKey,
    relin: PreparedHybridGadgetKey,
    inverse: SlotReturnKeys,
    return_key: PublicRefreshReturn,
    refreshes: u64,
}

impl PublicRefreshCircuit {
    pub fn certificate(&self) -> &PublicRefreshCircuitCertificate {
        &self.plan.certificate
    }
    pub fn real_refreshes(&self) -> u64 {
        self.refreshes
    }
    pub fn encrypt(&self, coefficients: &[u64]) -> Nine65Result<SourceWorkCiphertext> {
        self.source
            .encrypt(coefficients)
            .map_err(|e| refused(e.to_string()))
    }
    pub fn encrypt_with_rng<R: FheRng>(
        &self,
        coefficients: &[u64],
        rng: &mut R,
    ) -> Nine65Result<SourceWorkCiphertext> {
        self.source
            .encrypt_with_rng(coefficients, rng)
            .map_err(|e| refused(e.to_string()))
    }
    pub fn add(
        &self,
        left: &SourceWorkCiphertext,
        right: &SourceWorkCiphertext,
    ) -> Nine65Result<SourceWorkCiphertext> {
        self.source
            .add(left, right)
            .map_err(|e| refused(e.to_string()))
    }
    pub fn multiply(
        &self,
        left: &SourceWorkCiphertext,
        right: &SourceWorkCiphertext,
    ) -> Nine65Result<SourceWorkCiphertext> {
        self.source
            .multiply(left, right)
            .map_err(|e| refused(e.to_string()))
    }
    pub fn refresh(&mut self, input: &SourceWorkCiphertext) -> Nine65Result<SourceWorkCiphertext> {
        self.refresh_with_progress(input, &mut |_, _, _| {})
    }
    /// Progress reports contain only public stage names and operation counts.
    pub fn refresh_with_progress(
        &mut self,
        input: &SourceWorkCiphertext,
        progress: &mut dyn FnMut(&str, usize, usize),
    ) -> Nine65Result<SourceWorkCiphertext> {
        let source = self
            .source
            .prepare(input)
            .map_err(|e| refused(e.to_string()))?;
        if source.certificate().prime_square_residual_radius() > self.plan.radius as u64 {
            return Err(refused("source history exceeds the planned carry support"));
        }
        let phases = self
            .phase
            .evaluate_with_progress(&source, &self.high, &self.low, progress)?;
        if phases.lineage() != source.certificate().lineage()
            || phases.radius() > self.plan.radius as u64
            || phases.value_bound() != self.plan.certificate.phase_value_bound
            || phases.quotient_radius() > self.plan.certificate.signed_carry_radius
            || phases.error_bound() != self.plan.certificate.phase_error_bound
        {
            return Err(refused(
                "phase output does not match the planned source history",
            ));
        }
        let digit = SplitDigitEvaluator::new(
            &self.high,
            &self.low,
            self.plan.radius,
            phases.error_bound(),
            phases.error_bound(),
        )?;
        let carry = digit.evaluate_prepared_with_progress(
            phases.high(),
            phases.low(),
            &self.relin,
            progress,
        )?;
        let message =
            self.plan
                .certificate
                .lift_restoration
                .apply(&self.low, phases.affine(), &carry);
        let restored = PublicSlotReturn::new(&self.low, self.plan.source.source_config().n)?
            .apply_with_progress(&message, &self.inverse, progress)?;
        let proof = self.return_key.evaluate(
            &self.low,
            &source,
            &restored,
            self.plan.certificate.restored_error_bound,
        )?;
        let output = self
            .source
            .accept_refresh(&source, proof)
            .map_err(|e| refused(e.to_string()))?;
        self.refreshes = self
            .refreshes
            .checked_add(1)
            .ok_or_else(|| refused("refresh counter overflow"))?;
        Ok(output)
    }
}
