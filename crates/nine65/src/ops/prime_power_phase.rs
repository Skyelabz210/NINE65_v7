//! Authentic same-prime phase views and conditional t^2 -> t contraction.
//!
//! Both views are evaluated from the same public components under the same
//! independently generated boot secret. Winding by t^2 is irrelevant to the
//! quotient modulo t. An ordinary Enc_t(r), however, is not a certified
//! canonical lift Enc_{t^2}(r): converting the encoding is still nonlinear.
//!
//! The contraction kernel requires that stronger evidence. A public polynomial
//! producer exists, with arithmetic and noise admission; the current four-prime
//! tuple is refused. Neither evaluator reconstructs a ciphertext coefficient,
//! low digit, or winding.

use crate::arithmetic::rns::U512;
use crate::arithmetic::RNSPolynomial;
use crate::entropy::{FheRng, SecureRng};
use crate::errors::{Nine65Error, Nine65Result};
use crate::keys::expanded_bootstrap::{ExpandedBootstrapKey, ExpandedBootstrapKeySet};
use crate::ops::expanded_bootstrap::{evaluate_centered_components, ExpandedPhaseEvaluator};
use crate::ops::expanded_phase1::{ExpandedPhase1Components, ExpandedPhase1Plan};
use crate::ops::rns_fhe::{DualRNSCiphertext, DualRNSKeySet, RNSCiphertext, RNSFHEContext};
use crate::params::{is_prime, FHEConfig};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[path = "prime_power_digit_lift.rs"]
mod digit_lift;
pub use digit_lift::{
    CanonicalLowDigitLiftCertificate, CanonicalLowDigitLiftEvaluator, CanonicalLowDigitLiftKey,
};

fn words(v: U512) -> (u128, u128, u128, u128) {
    (v.d3, v.d2, v.d1, v.d0)
}

fn phase_failure(reason: impl Into<String>) -> Nine65Error {
    Nine65Error::BootstrapFailed {
        reason: reason.into(),
    }
}

/// Public-input digest bound to the boot-key family and the exact source
/// regime. Only the paired evaluator can construct this provenance tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhaseLineage([u8; 32]);

#[derive(Clone, Debug)]
pub struct PrimePowerPhaseNoiseCertificate {
    /// Error relative to the exact Q/P encoding grid, per coefficient.
    pub high_error_bound: U512,
    /// Error relative to the exact Q/t encoding grid, per coefficient.
    pub low_error_bound: U512,
    /// Exact Q/P grid error of the directly evaluated N^{-1}*x view.
    pub projection_input_error_bound: U512,
    /// Parameter-derived allowance; not evidence of actual work-input noise.
    pub max_centered_work_error: U512,
    pub source_level: usize,
    pub rounding_shift: u64,
}

/// An immutable pair Enc_{t^2}(x), Enc_t(x mod t), where x=(w+h) mod t^2.
/// Both encryptions have the same boot secret and main basis. Neither is a
/// serialized coprime anchor. A directly preconditioned N^{-1}*x view supports
/// coefficient projection. All views share lineage; evaluation has no secret.
pub struct PrimePowerLiftedPhase {
    high: RNSCiphertext,
    low: RNSCiphertext,
    trace_input: RNSCiphertext,
    trace_inverse: i64,
    lineage: PhaseLineage,
    family: [u64; 2],
    primes: Vec<u64>,
    n: usize,
    base: u64,
    noise: PrimePowerPhaseNoiseCertificate,
}

impl PrimePowerLiftedPhase {
    pub fn high_lift(&self) -> &RNSCiphertext {
        &self.high
    }
    pub fn low_view(&self) -> &RNSCiphertext {
        &self.low
    }
    /// Enc_P(N^{-1}*x mod P), evaluated directly from public components.
    /// A Galois trace projects x_j without post-scaling ciphertext noise.
    pub fn coefficient_projection_view(&self) -> &RNSCiphertext {
        &self.trace_input
    }
    pub fn coefficient_projection_inverse(&self) -> i64 {
        self.trace_inverse
    }
    pub fn lineage(&self) -> &PhaseLineage {
        &self.lineage
    }
    pub fn noise_certificate(&self) -> &PrimePowerPhaseNoiseCertificate {
        &self.noise
    }
}

pub struct PrimePowerBootstrapKey {
    high: ExpandedBootstrapKey,
    low: RNSCiphertext,
    source_primes: Vec<u64>,
    family: [u64; 2],
}

/// Only bootstrap_key is published; boot_keys remain with the key holder.
pub struct PrimePowerBootstrapKeySet {
    pub bootstrap_key: PrimePowerBootstrapKey,
    pub boot_keys: DualRNSKeySet,
}

pub struct PrimePowerPhaseEvaluator<'a> {
    high: ExpandedPhaseEvaluator<'a>,
    low: RNSFHEContext,
    work: FHEConfig,
    low_error_bound: U512,
}

impl<'a> PrimePowerPhaseEvaluator<'a> {
    pub fn new(high: &ExpandedPhaseEvaluator<'a>, work: &FHEConfig) -> Nine65Result<Self> {
        if high.exponent != 2
            || work.t != high.base_plaintext
            || work.n != high.ctx.n
            || !is_prime(work.t)
        {
            return Err(Nine65Error::BootstrapConfigMismatch {
                reason:
                    "same-prime phase pair needs prime t, exponent two, and the matching work ring"
                        .into(),
            });
        }
        let high = ExpandedPhaseEvaluator::new(high.ctx, work.t, 2)?;
        let mut config = high.ctx.config.clone();
        config.t = work.t;
        config.name = "prime_power_low_view";
        let low = RNSFHEContext::try_new(&config)?;
        let q = U512::product_u64s(&config.primes);
        let n = config.n as u128;
        let beta = U512::from_u128(2 * n + 1).mul_u128(config.eta as u128);
        let r = q.mod_u64(config.t);
        let low_error_bound = beta
            .mul_u128(n * ((config.t - 1) / 2) as u128)
            .add(U512::from_u64(r).mul_u128(n + 1))
            .add(U512::from_u64(r / 2 + r % 2));
        if words(low_error_bound) >= words(q.div_u64(config.t).div_u64(2)) {
            return Err(phase_failure(
                "same-prime low view lacks worst-case decoding headroom",
            ));
        }
        Ok(Self {
            high,
            low,
            work: work.clone(),
            low_error_bound,
        })
    }

    pub fn low_context(&self) -> &RNSFHEContext {
        &self.low
    }

    pub fn generate_keys_secure(
        &self,
        work_sk: &crate::ops::rns_fhe::DualRNSSecretKey,
    ) -> Nine65Result<PrimePowerBootstrapKeySet> {
        let mut rng = SecureRng::new();
        self.generate_keys_with_rng(work_sk, &mut rng)
    }

    pub fn generate_keys_with_rng<R: FheRng>(
        &self,
        work_sk: &crate::ops::rns_fhe::DualRNSSecretKey,
        rng: &mut R,
    ) -> Nine65Result<PrimePowerBootstrapKeySet> {
        // The existing generator validates every work-secret lane before
        // consuming RNG, screens security, and creates an independent boot
        // secret. The public RLWE key is independent of plaintext modulus.
        let ExpandedBootstrapKeySet {
            bootstrap_key: high,
            boot_keys,
        } = ExpandedBootstrapKey::generate_with_rng(&self.work, work_sk, &self.high, rng)?;
        let zero = self
            .low
            .encrypt_dual_with_rng(0, &boot_keys.public_key, rng);
        let first = self.work.primes[0];
        let signs: Zeroizing<Vec<i8>> = Zeroizing::new(
            work_sk.s.main[0]
                .iter()
                .map(|&v| {
                    if v == 0 {
                        0
                    } else if v == first - 1 {
                        -1
                    } else {
                        1
                    }
                })
                .collect(),
        );
        let mut c0 = Vec::with_capacity(self.low.config.primes.len());
        let mut c1 = Vec::with_capacity(self.low.config.primes.len());
        for (lane, &prime) in self.low.config.primes.iter().enumerate() {
            let mont = &self.low.rns.mont_contexts[lane];
            let delta = self.low.delta_rns[lane];
            c0.push(
                zero.c0.main[lane]
                    .iter()
                    .zip(signs.iter())
                    .map(|(&v, &sign)| {
                        let value = match sign {
                            -1 => (v as u128 + prime as u128 - delta as u128) % prime as u128,
                            1 => (v as u128 + delta as u128) % prime as u128,
                            _ => v as u128,
                        };
                        mont.to_montgomery(value as u64)
                    })
                    .collect(),
            );
            c1.push(
                zero.c1.main[lane]
                    .iter()
                    .map(|&v| mont.to_montgomery(v))
                    .collect(),
            );
        }
        let low = RNSCiphertext {
            c0: RNSPolynomial {
                limbs: c0,
                n: self.low.n,
            },
            c1: RNSPolynomial {
                limbs: c1,
                n: self.low.n,
            },
            num_primes: self.low.config.primes.len(),
        };
        Ok(PrimePowerBootstrapKeySet {
            bootstrap_key: PrimePowerBootstrapKey {
                high,
                low,
                source_primes: self.work.primes.clone(),
                family: [rng.next_u64(), rng.next_u64()],
            },
            boot_keys,
        })
    }

    /// Create the phase views in one call. No API accepts independently supplied
    /// ciphertexts as a same-integer pair, and no incoming anchor is read.
    pub fn evaluate(
        &self,
        ct: &DualRNSCiphertext,
        key: &PrimePowerBootstrapKey,
    ) -> Nine65Result<PrimePowerLiftedPhase> {
        if key.source_primes != self.work.primes {
            return Err(Nine65Error::BootstrapConfigMismatch {
                reason: "phase pair source basis mismatch".into(),
            });
        }
        let plan = ExpandedPhase1Plan::new(&self.work, ct.level, 2)
            .map_err(|e| phase_failure(format!("same-prime preprocessing: {e:?}")))?;
        let budget = plan
            .input_noise_budget()
            .map_err(|e| phase_failure(format!("same-prime input allowance: {e:?}")))?;
        let prepared = plan
            .prepare(ct)
            .map_err(|e| phase_failure(format!("same-prime input: {e:?}")))?;
        let mut digest = Sha256::new();
        digest.update(b"nine65.prime_power_phase.v1");
        for value in key.family {
            digest.update(value.to_le_bytes());
        }
        for value in [self.work.n as u64, ct.level as u64, self.work.t] {
            digest.update(value.to_le_bytes());
        }
        for &prime in &self.work.primes[..ct.level] {
            digest.update(prime.to_le_bytes());
        }
        for &value in prepared.c0.iter().chain(&prepared.c1) {
            digest.update(value.to_le_bytes());
        }
        let lineage = PhaseLineage(digest.finalize().into());
        let t = self.work.t;
        let p = prepared.plaintext_modulus;
        let h = (t - 1) / 2;
        let shifted = ExpandedPhase1Components {
            c0: prepared.c0.iter().map(|&v| (v + h) % p).collect(),
            c1: prepared.c1,
            plaintext_modulus: p,
            digit_divisor: t,
            source_level: ct.level,
        };
        // This also validates the high key's full context regime before the
        // paired low key or its limbs are used.
        let high = self.high.inner_product(&shifted, &key.high)?;
        let low0: Vec<u64> = shifted.c0.iter().map(|&v| v % t).collect();
        let low1: Vec<u64> = shifted.c1.iter().map(|&v| v % t).collect();
        let low = evaluate_centered_components(&self.low, &low0, &low1, &key.low);
        let trace_inverse = digit_lift::centered_inverse(self.work.n, p)?;
        let inverse_residue = (trace_inverse as i128).rem_euclid(p as i128) as u128;
        let trace_components = ExpandedPhase1Components {
            c0: shifted
                .c0
                .iter()
                .map(|&v| (v as u128 * inverse_residue % p as u128) as u64)
                .collect(),
            c1: shifted
                .c1
                .iter()
                .map(|&v| (v as u128 * inverse_residue % p as u128) as u64)
                .collect(),
            plaintext_modulus: p,
            digit_divisor: t,
            source_level: ct.level,
        };
        // Reduce the PUBLIC coefficients before encrypted evaluation. Multiplying the
        // ordinary high ciphertext by this inverse would amplify its noise.
        let trace_input = self.high.inner_product(&trace_components, &key.high)?;
        Ok(PrimePowerLiftedPhase {
            high,
            low,
            trace_input,
            trace_inverse,
            lineage,
            family: key.family,
            primes: self.low.config.primes.clone(),
            n: self.work.n,
            base: t,
            noise: PrimePowerPhaseNoiseCertificate {
                high_error_bound: self.high.certificate().phase_error_bound,
                low_error_bound: self.low_error_bound,
                projection_input_error_bound: self.high.certificate().phase_error_bound,
                max_centered_work_error: budget.max_centered_error,
                source_level: ct.level,
                rounding_shift: h,
            },
        })
    }
}

/// Stronger than the ordinary low view: this ciphertext's plaintext modulo
/// t^2 is the canonical integer r in [0,t), for the bound phase lineage.
/// Fields are private. The public polynomial producer is admitted only after
/// its complete noise plan passes; the current four-prime tuple does not.
/// The separate test-only oracle construction below verifies the kernel.
pub struct CanonicalLowDigitLift {
    encrypted: RNSCiphertext,
    lineage: PhaseLineage,
    family: [u64; 2],
    primes: Vec<u64>,
    n: usize,
    base: u64,
    error_bound: U512,
}

#[derive(Debug, Clone)]
pub struct PrimePowerContractionCertificate {
    pub output_error_bound: U512,
    pub half_delta: U512,
    /// Public scale metadata. Already covered by exact-grid input bounds;
    /// do not charge it again as an independent error term.
    pub floor_scale_difference: u64,
}

pub struct ContractedPrimePowerCiphertext {
    encrypted: RNSCiphertext,
    certificate: PrimePowerContractionCertificate,
}

impl ContractedPrimePowerCiphertext {
    pub fn ciphertext(&self) -> &RNSCiphertext {
        &self.encrypted
    }
    pub fn certificate(&self) -> &PrimePowerContractionCertificate {
        &self.certificate
    }
}

pub struct PrimePowerDigitRemoval<'a> {
    ctx: &'a RNSFHEContext,
    base: u64,
}

impl<'a> PrimePowerDigitRemoval<'a> {
    pub fn new(evaluator: &'a PrimePowerPhaseEvaluator<'_>) -> Self {
        Self {
            ctx: &evaluator.low,
            base: evaluator.work.t,
        }
    }

    /// Subtract a certified canonical low digit in the HIGH encoding. The
    /// remaining plaintext is divisible by t, so interpreting its exact
    /// Q/t^2 grid as a Q/t grid performs the quotient without scalar inversion.
    /// Ordinary Enc_t(r) cannot be substituted for this evidence type.
    pub fn contract(
        &self,
        phase: &PrimePowerLiftedPhase,
        digit: &CanonicalLowDigitLift,
    ) -> Nine65Result<ContractedPrimePowerCiphertext> {
        if phase.lineage != digit.lineage
            || phase.family != digit.family
            || phase.primes != self.ctx.config.primes
            || digit.primes != phase.primes
            || phase.n != self.ctx.n
            || digit.n != phase.n
            || phase.base != self.base
            || digit.base != self.base
        {
            return Err(Nine65Error::BootstrapConfigMismatch {
                reason: "canonical low-digit lift is not bound to this phase lineage and encoding"
                    .into(),
            });
        }
        let q = U512::product_u64s(&self.ctx.config.primes);
        let half_delta = q.div_u64(self.base).div_u64(2);
        // Check each operand first so even an invalid full-width certificate
        // cannot wrap the subsequent U512 addition into an admitted bound.
        if words(phase.noise.high_error_bound) >= words(half_delta)
            || words(digit.error_bound) >= words(half_delta)
        {
            return Err(phase_failure(
                "prime-power contraction lacks certified output headroom",
            ));
        }
        let output_error_bound = phase.noise.high_error_bound.add(digit.error_bound);
        if words(output_error_bound) >= words(half_delta) {
            return Err(phase_failure(
                "prime-power contraction lacks certified output headroom",
            ));
        }
        phase
            .high
            .validate(self.ctx.n, self.ctx.config.primes.len())?;
        digit
            .encrypted
            .validate(self.ctx.n, self.ctx.config.primes.len())?;
        for ct in [&phase.high, &digit.encrypted] {
            for poly in [&ct.c0, &ct.c1] {
                for (&prime, lane) in self.ctx.config.primes.iter().zip(&poly.limbs) {
                    if lane.iter().any(|&v| v >= prime) {
                        return Err(Nine65Error::InvalidParameter {
                            message: "noncanonical prime-power contraction residue".into(),
                        });
                    }
                }
            }
        }
        let encrypted = RNSCiphertext {
            c0: phase.high.c0.sub(&digit.encrypted.c0, &self.ctx.rns),
            c1: phase.high.c1.sub(&digit.encrypted.c1, &self.ctx.rns),
            num_primes: self.ctx.config.primes.len(),
        };
        let floor_scale_difference = q.mod_u64(self.base * self.base) / self.base;
        Ok(ContractedPrimePowerCiphertext {
            encrypted,
            certificate: PrimePowerContractionCertificate {
                output_error_bound,
                half_delta,
                floor_scale_difference,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
    use crate::arithmetic::rns::{crt_reconstruct_u256, U256};
    use crate::entropy::ShadowHarvester;
    use crate::ops::rns_fhe::{DualRNSPoly, DualRNSSecretKey, RNSSecretKey};
    use crate::ops::rns_galois::{shift, RNSGaloisEvaluator};
    use crate::params::SecureConfig;

    fn decode_all(ctx: &RNSFHEContext, ct: &RNSCiphertext, sk: &DualRNSSecretKey) -> Vec<u64> {
        let decoder = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
        let phases: Vec<Vec<u64>> = ctx
            .config
            .primes
            .iter()
            .enumerate()
            .map(|(lane, &prime)| {
                let mont = &ctx.rns.mont_contexts[lane];
                let c1: Vec<u64> = ct.c1.limbs[lane]
                    .iter()
                    .map(|&v| mont.from_montgomery(v))
                    .collect();
                let product = ctx.ntt_engines[lane].multiply(&c1, &sk.s.main[lane]);
                ct.c0.limbs[lane]
                    .iter()
                    .zip(product)
                    .map(|(&v, product)| {
                        ((mont.from_montgomery(v) as u128 + product as u128) % prime as u128) as u64
                    })
                    .collect()
            })
            .collect();
        (0..ctx.n)
            .map(|j| {
                decoder
                    .scale_round(&phases.iter().map(|lane| lane[j]).collect::<Vec<_>>())
                    .unwrap()
            })
            .collect()
    }

    // Replace a ciphertext by the phase-equivalent diagnostic form (phase, 0).
    // It is intentionally not a secure ciphertext; it preserves the exact
    // mod-Q decryption phase while removing the c0/c1 component winding.
    fn phase_only_equivalent(
        ctx: &RNSFHEContext,
        ct: &RNSCiphertext,
        sk: &DualRNSSecretKey,
    ) -> RNSCiphertext {
        let phase_limbs: Vec<Vec<u64>> = ctx
            .config
            .primes
            .iter()
            .enumerate()
            .map(|(lane, &prime)| {
                let mont = &ctx.rns.mont_contexts[lane];
                let c0: Vec<u64> = ct.c0.limbs[lane]
                    .iter()
                    .map(|&value| mont.from_montgomery(value))
                    .collect();
                let c1: Vec<u64> = ct.c1.limbs[lane]
                    .iter()
                    .map(|&value| mont.from_montgomery(value))
                    .collect();
                let c1s = ctx.ntt_engines[lane].multiply(&c1, &sk.s.main[lane]);
                c0.iter()
                    .zip(c1s)
                    .map(|(&left, right)| ((left as u128 + right as u128) % prime as u128) as u64)
                    .collect()
            })
            .collect();
        let phase = RNSPolynomial {
            limbs: phase_limbs,
            n: ctx.n,
        };
        let zero = RNSPolynomial {
            limbs: vec![vec![0; ctx.n]; ctx.config.primes.len()],
            n: ctx.n,
        };
        let to_montgomery = |poly: &RNSPolynomial| RNSPolynomial {
            limbs: poly
                .limbs
                .iter()
                .zip(&ctx.rns.mont_contexts)
                .map(|(limb, mont)| {
                    limb.iter()
                        .map(|&value| mont.to_montgomery(value))
                        .collect()
                })
                .collect(),
            n: ctx.n,
        };
        RNSCiphertext {
            c0: to_montgomery(&phase),
            c1: to_montgomery(&zero),
            num_primes: ctx.config.primes.len(),
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct SignedU256 {
        negative: bool,
        magnitude: U256,
    }

    impl SignedU256 {
        fn zero() -> Self {
            Self {
                negative: false,
                magnitude: U256::zero(),
            }
        }

        fn from_magnitude(negative: bool, magnitude: U256) -> Self {
            Self {
                negative: negative && !magnitude.is_zero(),
                magnitude,
            }
        }

        fn negate(self) -> Self {
            Self::from_magnitude(!self.negative, self.magnitude)
        }

        fn add(self, other: Self) -> Self {
            if self.negative == other.negative {
                let (magnitude, overflow) = self.magnitude.overflowing_add(other.magnitude);
                assert!(!overflow, "diagnostic signed U256 addition overflowed");
                Self::from_magnitude(self.negative, magnitude)
            } else if self.magnitude.ge(other.magnitude) {
                Self::from_magnitude(self.negative, self.magnitude.sub(other.magnitude))
            } else {
                Self::from_magnitude(other.negative, other.magnitude.sub(self.magnitude))
            }
        }

        fn multiply_small(self, factor: u64, negate: bool) -> Self {
            Self::from_magnitude(self.negative ^ negate, self.magnitude.mul_u64(factor))
        }

        fn modulo(self, modulus: U256) -> U256 {
            let remainder = self.magnitude.div_mod_u256(modulus).1;
            if self.negative && !remainder.is_zero() {
                modulus.sub(remainder)
            } else {
                remainder
            }
        }

        fn centered(value: U256, modulus: U256) -> Self {
            let half = modulus.div_mod_u64(2).0;
            if value.gt(half) {
                Self::from_magnitude(true, modulus.sub(value))
            } else {
                Self::from_magnitude(false, value)
            }
        }
    }

    // Test oracle only: these are raw phase residues, not Delta-scaled
    // plaintext encodings or a publicly produced encrypted correction.
    fn raw_phase_addend_for_diagnostic(ctx: &RNSFHEContext, residues: &[U256]) -> RNSCiphertext {
        assert_eq!(residues.len(), ctx.n);
        RNSCiphertext {
            c0: RNSPolynomial {
                limbs: ctx
                    .config
                    .primes
                    .iter()
                    .zip(&ctx.rns.mont_contexts)
                    .map(|(&prime, mont)| {
                        residues
                            .iter()
                            .map(|value| mont.to_montgomery(value.mod_u64(prime)))
                            .collect()
                    })
                    .collect(),
                n: ctx.n,
            },
            c1: RNSPolynomial {
                limbs: vec![vec![0; ctx.n]; ctx.config.primes.len()],
                n: ctx.n,
            },
            num_primes: ctx.config.primes.len(),
        }
    }

    fn scale_ciphertext_for_diagnostic(
        ctx: &RNSFHEContext,
        input: &RNSCiphertext,
        scalar: u128,
    ) -> RNSCiphertext {
        let scale = |poly: &RNSPolynomial| RNSPolynomial {
            limbs: poly
                .limbs
                .iter()
                .zip(&ctx.config.primes)
                .map(|(limb, &prime)| {
                    let factor = scalar % prime as u128;
                    limb.iter()
                        .map(|&value| (value as u128 * factor % prime as u128) as u64)
                        .collect()
                })
                .collect(),
            n: ctx.n,
        };
        RNSCiphertext {
            c0: scale(&input.c0),
            c1: scale(&input.c1),
            num_primes: input.num_primes,
        }
    }

    // Key-holder test fixture only. Encrypt a raw phase target using a fresh
    // full-width uniform mask and a consistent signed CBD error. The target
    // K below is manufactured by the secret oracle, not a public producer.
    fn encrypt_raw_phase_for_diagnostic(
        ctx: &RNSFHEContext,
        target: &RNSCiphertext,
        sk: &DualRNSSecretKey,
        rng: &mut ShadowHarvester,
    ) -> RNSCiphertext {
        assert!(target.c1.limbs.iter().flatten().all(|&value| value == 0));
        let mask = ctx.sample_uniform_main_poly(rng);
        let errors = Zeroizing::new(
            (0..ctx.n)
                .map(|_| {
                    (0..ctx.config.eta)
                        .map(|_| (rng.next_u64() & 1) as i64 - (rng.next_u64() & 1) as i64)
                        .sum::<i64>()
                })
                .collect::<Vec<_>>(),
        );
        let mut c0 = Vec::with_capacity(ctx.config.primes.len());
        let mut c1 = Vec::with_capacity(ctx.config.primes.len());
        for (lane, &prime) in ctx.config.primes.iter().enumerate() {
            let mont = &ctx.rns.mont_contexts[lane];
            let product = ctx.ntt_engines[lane].multiply(&mask.limbs[lane], &sk.s.main[lane]);
            c0.push(
                (0..ctx.n)
                    .map(|j| {
                        let value = mont.from_montgomery(target.c0.limbs[lane][j]);
                        let error = errors[j].rem_euclid(prime as i64) as u64;
                        mont.to_montgomery(
                            ((value as u128 + error as u128 + prime as u128 - product[j] as u128)
                                % prime as u128) as u64,
                        )
                    })
                    .collect(),
            );
            c1.push(
                mask.limbs[lane]
                    .iter()
                    .map(|&v| mont.to_montgomery(v))
                    .collect(),
            );
        }
        RNSCiphertext {
            c0: RNSPolynomial {
                limbs: c0,
                n: ctx.n,
            },
            c1: RNSPolynomial {
                limbs: c1,
                n: ctx.n,
            },
            num_primes: ctx.config.primes.len(),
        }
    }

    // Evaluator-side arithmetic only: no secret, reconstruction, or BFV
    // scale-and-round. Its phase is the raw ring product of its input phases.
    fn raw_ring_tensor_for_diagnostic(
        ctx: &RNSFHEContext,
        left: &RNSCiphertext,
        right: &RNSCiphertext,
    ) -> crate::ops::rns_fhe::exact_mul::ExactTensor3 {
        let mut parts = [Vec::new(), Vec::new(), Vec::new()];
        for (lane, &prime) in ctx.config.primes.iter().enumerate() {
            let mont = &ctx.rns.mont_contexts[lane];
            let standard = |poly: &RNSPolynomial| {
                poly.limbs[lane]
                    .iter()
                    .map(|&v| mont.from_montgomery(v))
                    .collect::<Vec<_>>()
            };
            let (a0, a1) = (standard(&left.c0), standard(&left.c1));
            let (b0, b1) = (standard(&right.c0), standard(&right.c1));
            let ntt = &ctx.ntt_engines[lane];
            parts[0].push(ntt.multiply(&a0, &b0));
            parts[1].push(
                ntt.multiply(&a0, &b1)
                    .iter()
                    .zip(ntt.multiply(&a1, &b0))
                    .map(|(&a, b)| ((a as u128 + b as u128) % prime as u128) as u64)
                    .collect(),
            );
            parts[2].push(ntt.multiply(&a1, &b1));
        }
        let [e0, e1, e2] = parts;
        crate::ops::rns_fhe::exact_mul::ExactTensor3 {
            e0: RNSPolynomial {
                limbs: e0,
                n: ctx.n,
            },
            e1: RNSPolynomial {
                limbs: e1,
                n: ctx.n,
            },
            e2: RNSPolynomial {
                limbs: e2,
                n: ctx.n,
            },
            num_primes: ctx.config.primes.len(),
        }
    }

    // Combine already scaled/rounded tensors before ONE key switch. Scaling
    // separately relinearized ciphertexts would also scale their switch noise.
    fn compensated_tensor_for_diagnostic(
        ctx: &RNSFHEContext,
        cross: &crate::ops::rns_fhe::exact_mul::ExactTensor3,
        square: &crate::ops::rns_fhe::exact_mul::ExactTensor3,
    ) -> crate::ops::rns_fhe::exact_mul::ExactTensor3 {
        let combine = |a: &RNSPolynomial, b: &RNSPolynomial| RNSPolynomial {
            limbs: ctx
                .config
                .primes
                .iter()
                .enumerate()
                .map(|(lane, &prime)| {
                    let q = prime as u128;
                    let left = 2 * ctx.t as u128 % q;
                    let right = (ctx.t as u128 * ctx.t as u128) % q;
                    a.limbs[lane]
                        .iter()
                        .zip(&b.limbs[lane])
                        .map(|(&a, &b)| {
                            ((left * a as u128 % q + q - right * b as u128 % q) % q) as u64
                        })
                        .collect()
                })
                .collect(),
            n: ctx.n,
        };
        crate::ops::rns_fhe::exact_mul::ExactTensor3 {
            e0: combine(&cross.e0, &square.e0),
            e1: combine(&cross.e1, &square.e1),
            e2: combine(&cross.e2, &square.e2),
            num_primes: cross.num_primes,
        }
    }

    // Secret oracle for the integer lift of a NEW ciphertext. Keeping this
    // separate prevents confusing the carry ciphertext's J with the input K.
    fn component_winding_for_diagnostic(
        ctx: &RNSFHEContext,
        input: &RNSCiphertext,
        sk: &DualRNSSecretKey,
    ) -> Vec<i64> {
        let q = U256::product_u64s(&ctx.config.primes);
        let centered_coefficients = |poly: &RNSPolynomial| {
            (0..ctx.n)
                .map(|j| {
                    let residues = poly
                        .limbs
                        .iter()
                        .zip(&ctx.rns.mont_contexts)
                        .map(|(lane, mont)| mont.from_montgomery(lane[j]))
                        .collect::<Vec<_>>();
                    SignedU256::centered(crt_reconstruct_u256(&residues, &ctx.config.primes), q)
                })
                .collect::<Vec<_>>()
        };
        let c0 = centered_coefficients(&input.c0);
        let c1 = centered_coefficients(&input.c1);
        let phase = centered_coefficients(&phase_only_equivalent(ctx, input, sk).c0);
        let prime = ctx.config.primes[0];
        let secret = sk.s.main[0]
            .iter()
            .map(|&value| match value {
                0 => 0i8,
                1 => 1,
                v if v == prime - 1 => -1,
                _ => panic!("diagnostic expected a ternary secret"),
            })
            .collect::<Vec<_>>();
        (0..ctx.n)
            .map(|j| {
                let mut lifted = c0[j];
                for (i, &s) in secret.iter().enumerate() {
                    if s == 0 {
                        continue;
                    }
                    let (source, wrapped) = if j >= i {
                        (j - i, false)
                    } else {
                        (ctx.n + j - i, true)
                    };
                    lifted = lifted.add(c1[source].multiply_small(1, (s < 0) ^ wrapped));
                }
                assert_eq!(lifted.modulo(q), phase[j].modulo(q));
                let difference = lifted.add(phase[j].negate());
                let (quotient, remainder) = difference.magnitude.div_mod_u256(q);
                assert!(remainder.is_zero());
                assert_eq!(quotient.hi, 0);
                assert!(quotient.lo <= ctx.n as u128);
                if difference.negative {
                    -(quotient.lo as i64)
                } else {
                    quotient.lo as i64
                }
            })
            .collect()
    }

    struct WindingSquareDiagnostic {
        winding_bits: u32,
        predicted_winding_bits: u32,
        observed_difference_bits: u32,
        rounding_mismatch_bits: u32,
        rounding_bound: u128,
        mismatch_coefficient: usize,
        winding: Vec<i64>,
        correction: RNSCiphertext,
    }

    /// Quantify the integer-lift winding for an input ciphertext and compare
    /// its predicted `2*t*K*P` contribution against two exact tensor outputs:
    /// the original representation and its phase-only equivalent. The
    /// remaining mismatch is bounded by the independently rounded tensor
    /// components (d0 + d1*s + d2*s^2).
    fn winding_square_difference_diagnostic(
        ctx: &RNSFHEContext,
        input: &RNSCiphertext,
        original_square: &RNSCiphertext,
        phase_only_square: &RNSCiphertext,
        sk: &DualRNSSecretKey,
    ) -> WindingSquareDiagnostic {
        let primes = &ctx.config.primes;
        let q = U256::product_u64s(primes);
        let to_signed_coefficients = |poly: &RNSPolynomial| {
            let standard = poly
                .limbs
                .iter()
                .zip(&ctx.rns.mont_contexts)
                .map(|(limb, mont)| {
                    limb.iter()
                        .map(|&value| mont.from_montgomery(value))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            (0..ctx.n)
                .map(|coefficient| {
                    let residues: Vec<u64> =
                        standard.iter().map(|lane| lane[coefficient]).collect();
                    SignedU256::centered(crt_reconstruct_u256(&residues, primes), q)
                })
                .collect::<Vec<_>>()
        };
        let c0 = to_signed_coefficients(&input.c0);
        let c1 = to_signed_coefficients(&input.c1);

        let phase_residues = |ciphertext: &RNSCiphertext| {
            let mut lanes = vec![vec![0u64; ctx.n]; primes.len()];
            for (lane, &prime) in primes.iter().enumerate() {
                let mont = &ctx.rns.mont_contexts[lane];
                let c0_standard: Vec<u64> = ciphertext.c0.limbs[lane]
                    .iter()
                    .map(|&value| mont.from_montgomery(value))
                    .collect();
                let c1_standard: Vec<u64> = ciphertext.c1.limbs[lane]
                    .iter()
                    .map(|&value| mont.from_montgomery(value))
                    .collect();
                let c1s = ctx.ntt_engines[lane].multiply(&c1_standard, &sk.s.main[lane]);
                for coefficient in 0..ctx.n {
                    lanes[lane][coefficient] = ((c0_standard[coefficient] as u128
                        + c1s[coefficient] as u128)
                        % prime as u128) as u64;
                }
            }
            lanes
        };
        let phase_lanes = phase_residues(input);
        let phase = (0..ctx.n)
            .map(|coefficient| {
                let residues: Vec<u64> = phase_lanes.iter().map(|lane| lane[coefficient]).collect();
                SignedU256::centered(crt_reconstruct_u256(&residues, primes), q)
            })
            .collect::<Vec<_>>();

        // Lift c0 + c1*s over Z, not just modulo Q. Secret coefficients are
        // generated from {-1,0,1}; lane zero makes that contract explicit.
        let secret_prime = primes[0];
        let secret: Vec<i8> = sk.s.main[0]
            .iter()
            .map(|&value| match value {
                0 => 0,
                1 => 1,
                value if value == secret_prime - 1 => -1,
                _ => panic!("diagnostic expected ternary secret coefficients"),
            })
            .collect();
        let mut winding = Vec::with_capacity(ctx.n);
        for coefficient in 0..ctx.n {
            let mut lifted_phase = c0[coefficient];
            for (secret_index, &secret_value) in secret.iter().enumerate() {
                if secret_value == 0 {
                    continue;
                }
                let (source, wrapped) = if coefficient >= secret_index {
                    (coefficient - secret_index, false)
                } else {
                    (ctx.n + coefficient - secret_index, true)
                };
                let negative = (secret_value < 0) ^ wrapped;
                lifted_phase = lifted_phase.add(c1[source].multiply_small(1, negative));
            }

            // Guard that this integer lift is exactly the phase recovered in
            // the RNS decryption path before extracting its Q-winding.
            assert_eq!(lifted_phase.modulo(q), phase[coefficient].modulo(q));
            let difference = lifted_phase.add(phase[coefficient].negate());
            let (quotient, remainder) = difference.magnitude.div_mod_u256(q);
            assert!(
                remainder.is_zero(),
                "phase lift did not differ by a Q multiple"
            );
            assert_eq!(quotient.hi, 0, "diagnostic winding exceeded i64");
            assert!(
                quotient.lo <= ctx.n as u128,
                "diagnostic winding exceeded its ternary bound"
            );
            let magnitude = quotient.lo as i64;
            winding.push(if difference.negative {
                -magnitude
            } else {
                magnitude
            });
        }

        // Negacyclic K*P, with small signed K and exact wide phase P.
        let mut winding_phase = vec![SignedU256::zero(); ctx.n];
        for coefficient in 0..ctx.n {
            for (phase_index, &winding_value) in winding.iter().enumerate() {
                if winding_value == 0 {
                    continue;
                }
                let (target, wrapped) = if coefficient + phase_index < ctx.n {
                    (coefficient + phase_index, false)
                } else {
                    (coefficient + phase_index - ctx.n, true)
                };
                let negate = (winding_value < 0) ^ wrapped;
                winding_phase[target] = winding_phase[target]
                    .add(phase[coefficient].multiply_small(winding_value.unsigned_abs(), negate));
            }
        }
        let winding_term: Vec<U256> = winding_phase
            .iter()
            .map(|value| value.multiply_small(2 * ctx.t, false).modulo(q))
            .collect();

        let original_lanes = phase_residues(original_square);
        let phase_only_lanes = phase_residues(phase_only_square);
        // Each scale-round has absolute error at most 1/2. The original
        // tensor contributes (1 + ||s||_1 + ||s^2||_1)/2, and the phase-only
        // tensor adds 1/2. For ternary s, use ||s||_1 <= N and ||s^2||_1 <= N^2.
        let n = ctx.n as u128;
        let rounding_bound = (n * n + n + 2) / 2;
        let mut max_winding_bits = 0;
        let mut max_difference_bits = 0;
        let mut max_mismatch_bits = 0;
        let mut mismatch_index = 0;
        for coefficient in 0..ctx.n {
            let original: Vec<u64> = original_lanes
                .iter()
                .map(|lane| lane[coefficient])
                .collect();
            let phase_only: Vec<u64> = phase_only_lanes
                .iter()
                .map(|lane| lane[coefficient])
                .collect();
            let difference = crt_reconstruct_u256(&original, primes)
                .sub_mod(crt_reconstruct_u256(&phase_only, primes), q);
            let mismatch = difference.sub_mod(winding_term[coefficient], q);
            let centered_difference = SignedU256::centered(difference, q).magnitude;
            let centered_mismatch = SignedU256::centered(mismatch, q).magnitude;
            assert!(
                centered_mismatch.le(U256::from_u128(rounding_bound)),
                "winding mismatch exceeded component-rounding bound at coefficient {coefficient}"
            );
            let winding_magnitude = SignedU256::centered(winding_term[coefficient], q).magnitude;
            let difference_bits = centered_difference.bitlen();
            let mismatch_bits = centered_mismatch.bitlen();
            max_winding_bits = max_winding_bits.max(winding_magnitude.bitlen());
            if difference_bits > max_difference_bits {
                max_difference_bits = difference_bits;
            }
            if mismatch_bits > max_mismatch_bits {
                max_mismatch_bits = mismatch_bits;
                mismatch_index = coefficient;
            }
        }
        WindingSquareDiagnostic {
            winding_bits: winding
                .iter()
                .map(|value| value.unsigned_abs())
                .max()
                .unwrap_or(0)
                .checked_ilog2()
                .unwrap_or(0)
                + u32::from(winding.iter().any(|value| *value != 0)),
            predicted_winding_bits: max_winding_bits,
            observed_difference_bits: max_difference_bits,
            rounding_mismatch_bits: max_mismatch_bits,
            rounding_bound,
            mismatch_coefficient: mismatch_index,
            winding,
            correction: raw_phase_addend_for_diagnostic(ctx, &winding_term),
        }
    }

    // Test-only measurement of the actual centered phase residual. This is
    // evidence about one sampled key/ciphertext, not a replacement for the
    // public worst-case certificate.
    fn phase_residual_max(ctx: &RNSFHEContext, ct: &RNSCiphertext, sk: &DualRNSSecretKey) -> U256 {
        let decoded = decode_all(ctx, ct, sk);
        phase_residual_max_against(ctx, ct, sk, &decoded)
    }

    fn phase_residual_max_against(
        ctx: &RNSFHEContext,
        ct: &RNSCiphertext,
        sk: &DualRNSSecretKey,
        expected_messages: &[u64],
    ) -> U256 {
        assert_eq!(expected_messages.len(), ctx.n);
        let phases: Vec<Vec<u64>> = ctx
            .config
            .primes
            .iter()
            .enumerate()
            .map(|(lane, &prime)| {
                let mont = &ctx.rns.mont_contexts[lane];
                let c1: Vec<u64> = ct.c1.limbs[lane]
                    .iter()
                    .map(|&v| mont.from_montgomery(v))
                    .collect();
                let product = ctx.ntt_engines[lane].multiply(&c1, &sk.s.main[lane]);
                ct.c0.limbs[lane]
                    .iter()
                    .zip(product)
                    .map(|(&v, product)| {
                        ((mont.from_montgomery(v) as u128 + product as u128) % prime as u128) as u64
                    })
                    .collect()
            })
            .collect();
        let primes = &ctx.config.primes;
        let q_full = U512::product_u64s(primes);
        if q_full.d1 == 0 && q_full.d2 == 0 && q_full.d3 == 0 {
            let q = q_full.d0;
            let crt_u128 = |residues: &[u64]| {
                let (mut value, mut prefix) = (0u128, 1u128);
                for (lane, &prime) in primes.iter().enumerate() {
                    let modulus = prime as u128;
                    let difference = (residues[lane] as u128 + modulus - value % modulus) % modulus;
                    let inverse =
                        crate::arithmetic::rns::mod_inverse((prefix % modulus) as u64, prime)
                            as u128;
                    value += prefix * (difference * inverse % modulus);
                    prefix *= modulus;
                }
                value
            };
            let mut maximum = 0u128;
            for (coefficient, &message) in expected_messages.iter().enumerate() {
                let residual_residues = primes
                    .iter()
                    .enumerate()
                    .map(|(lane, &prime)| {
                        let modulus = prime as u128;
                        let expected = message as u128 * ctx.delta_rns[lane] as u128 % modulus;
                        ((phases[lane][coefficient] as u128 + modulus - expected) % modulus) as u64
                    })
                    .collect::<Vec<_>>();
                let difference = crt_u128(&residual_residues);
                maximum = maximum.max(difference.min(q - difference));
            }
            return U256::from_u128(maximum);
        }
        let q = q_full;
        let q = U256 { lo: q.d0, hi: q.d1 };
        let mut maximum = U256::zero();
        for (coefficient, &message) in expected_messages.iter().enumerate() {
            let residual_residues = primes
                .iter()
                .enumerate()
                .map(|(lane, &prime)| {
                    let modulus = prime as u128;
                    let expected = message as u128 * ctx.delta_rns[lane] as u128 % modulus;
                    ((phases[lane][coefficient] as u128 + modulus - expected) % modulus) as u64
                })
                .collect::<Vec<_>>();
            let difference = crt_reconstruct_u256(&residual_residues, primes);
            let wrapped = q.sub(difference);
            let residual = if difference.le(wrapped) {
                difference
            } else {
                wrapped
            };
            if residual.gt(maximum) {
                maximum = residual;
            }
        }
        maximum
    }

    fn integer_bits(value: U256) -> u32 {
        value.bitlen()
    }

    fn u128_bits(value: u128) -> u32 {
        128 - value.leading_zeros()
    }

    fn as_u512(value: U256) -> U512 {
        U512 {
            d0: value.lo,
            d1: value.hi,
            d2: 0,
            d3: 0,
        }
    }

    fn native_secret(ctx: &RNSFHEContext, sk: &DualRNSSecretKey) -> RNSSecretKey {
        RNSSecretKey {
            s: RNSPolynomial {
                limbs: ctx
                    .rns
                    .mont_contexts
                    .iter()
                    .zip(&sk.s.main)
                    .map(|(mont, lane)| lane.iter().map(|&v| mont.to_montgomery(v)).collect())
                    .collect(),
                n: ctx.n,
            },
        }
    }

    fn tensor_phase(
        ctx: &RNSFHEContext,
        tensor: &crate::ops::rns_fhe::exact_mul::ExactTensor3,
        sk: &DualRNSSecretKey,
    ) -> RNSCiphertext {
        let mut c0_limbs = Vec::with_capacity(ctx.config.primes.len());
        let mut c1_limbs = Vec::with_capacity(ctx.config.primes.len());
        for (lane, &prime) in ctx.config.primes.iter().enumerate() {
            let mont = &ctx.rns.mont_contexts[lane];
            let ntt = &ctx.ntt_engines[lane];
            let s_squared = ntt.multiply(&sk.s.main[lane], &sk.s.main[lane]);
            let e2: Vec<u64> = tensor.e2.limbs[lane]
                .iter()
                .map(|&value| mont.to_montgomery(value))
                .collect();
            let e2_s_squared = ntt.multiply(&e2, &s_squared);
            let c0: Vec<u64> = tensor.e0.limbs[lane]
                .iter()
                .zip(e2_s_squared)
                .map(|(&value, product)| {
                    let value = mont.to_montgomery(value);
                    ((value as u128 + product as u128) % prime as u128) as u64
                })
                .collect();
            c0_limbs.push(c0);
            c1_limbs.push(
                tensor.e1.limbs[lane]
                    .iter()
                    .map(|&value| mont.to_montgomery(value))
                    .collect(),
            );
        }
        RNSCiphertext {
            c0: RNSPolynomial {
                limbs: c0_limbs,
                n: ctx.n,
            },
            c1: RNSPolynomial {
                limbs: c1_limbs,
                n: ctx.n,
            },
            num_primes: ctx.config.primes.len(),
        }
    }

    fn subtract_ciphertexts(
        ctx: &RNSFHEContext,
        left: &RNSCiphertext,
        right: &RNSCiphertext,
    ) -> RNSCiphertext {
        let subtract = |a: &RNSPolynomial, b: &RNSPolynomial| RNSPolynomial {
            limbs: ctx
                .config
                .primes
                .iter()
                .enumerate()
                .map(|(lane, &prime)| {
                    a.limbs[lane]
                        .iter()
                        .zip(&b.limbs[lane])
                        .map(|(&x, &y)| if x >= y { x - y } else { prime - (y - x) })
                        .collect()
                })
                .collect(),
            n: ctx.n,
        };
        RNSCiphertext {
            c0: subtract(&left.c0, &right.c0),
            c1: subtract(&left.c1, &right.c1),
            num_primes: ctx.config.primes.len(),
        }
    }

    fn subtract_plain_constant(
        ctx: &RNSFHEContext,
        ciphertext: &RNSCiphertext,
        constant: u64,
    ) -> RNSCiphertext {
        let mut out = ciphertext.clone();
        for (lane, &prime) in ctx.config.primes.iter().enumerate() {
            let mont = &ctx.rns.mont_contexts[lane];
            let encoded = (ctx.delta_rns[lane] as u128 * constant as u128 % prime as u128) as u64;
            let encoded = mont.to_montgomery(encoded);
            out.c0.limbs[lane][0] = ((out.c0.limbs[lane][0] as u128 + prime as u128
                - encoded as u128)
                % prime as u128) as u64;
        }
        out
    }

    fn add_plain_constant(
        ctx: &RNSFHEContext,
        ciphertext: &RNSCiphertext,
        constant: u64,
    ) -> RNSCiphertext {
        let mut out = ciphertext.clone();
        for (lane, &prime) in ctx.config.primes.iter().enumerate() {
            let mont = &ctx.rns.mont_contexts[lane];
            let encoded = (ctx.delta_rns[lane] as u128 * constant as u128 % prime as u128) as u64;
            let encoded = mont.to_montgomery(encoded);
            out.c0.limbs[lane][0] =
                ((out.c0.limbs[lane][0] as u128 + encoded as u128) % prime as u128) as u64;
        }
        out
    }

    fn trace_projection_coefficient(
        ctx: &RNSFHEContext,
        input: &RNSCiphertext,
        sk: &DualRNSSecretKey,
        coefficient_index: usize,
        rng: &mut ShadowHarvester,
    ) -> RNSCiphertext {
        let native = native_secret(ctx, sk);
        let galois = RNSGaloisEvaluator::new(ctx).unwrap();
        let mut projected = shift(
            ctx,
            input,
            if coefficient_index == 0 {
                0
            } else {
                2 * ctx.n - coefficient_index
            },
        );
        let mut stride = ctx.n;
        while stride > 1 {
            let key = galois
                .generate_key_with_rng(&native, stride as u64 + 1, rng)
                .unwrap();
            let transformed = galois.apply(&projected, &key).unwrap();
            projected = RNSCiphertext {
                c0: projected.c0.add(&transformed.c0, &ctx.rns),
                c1: projected.c1.add(&transformed.c1, &ctx.rns),
                num_primes: projected.num_primes,
            };
            stride /= 2;
        }
        projected
    }

    // This is deliberately only a test oracle. It decrypts the phase to
    // manufacture evidence that a future PUBLIC low-digit lift must produce.
    // It is not exposed by allow_insecure or any other production feature.
    fn oracle_digit(
        high: &RNSFHEContext,
        phase: &PrimePowerLiftedPhase,
        keys: &DualRNSKeySet,
        rng: &mut ShadowHarvester,
    ) -> CanonicalLowDigitLift {
        let low_digits: Vec<u64> = decode_all(high, &phase.high, &keys.secret_key)
            .iter()
            .map(|&x| x % phase.base)
            .collect();
        let zero = high.encrypt_dual_with_rng(0, &keys.public_key, rng);
        let c0 = high
            .config
            .primes
            .iter()
            .enumerate()
            .map(|(lane, &prime)| {
                let mont = &high.rns.mont_contexts[lane];
                zero.c0.main[lane]
                    .iter()
                    .zip(&low_digits)
                    .map(|(&v, &r)| {
                        mont.to_montgomery(
                            ((v as u128 + r as u128 * high.delta_rns[lane] as u128) % prime as u128)
                                as u64,
                        )
                    })
                    .collect()
            })
            .collect();
        let c1 = high
            .rns
            .mont_contexts
            .iter()
            .zip(&zero.c1.main)
            .map(|(mont, lane)| lane.iter().map(|&v| mont.to_montgomery(v)).collect())
            .collect();
        let remainder = U512::product_u64s(&high.config.primes).mod_u64(high.t) as u128;
        let grid_error = (remainder * (phase.base - 1) as u128).div_ceil(high.t as u128);
        CanonicalLowDigitLift {
            encrypted: RNSCiphertext {
                c0: RNSPolynomial {
                    limbs: c0,
                    n: high.n,
                },
                c1: RNSPolynomial {
                    limbs: c1,
                    n: high.n,
                },
                num_primes: high.config.primes.len(),
            },
            lineage: phase.lineage.clone(),
            family: phase.family,
            primes: phase.primes.clone(),
            n: phase.n,
            base: phase.base,
            error_bound: U512::from_u128(
                high.config.eta as u128 * (2 * high.n as u128 + 1) + grid_error,
            ),
        }
    }

    #[test]
    fn contraction_with_oracle_lift_refreshes_boundary_input_and_supports_multiply() {
        let work = SecureConfig::secure_128().into_config();
        let ctx = RNSFHEContext::try_new(&work).unwrap();
        let mut config = work.clone();
        config.t = work.t * work.t;
        if std::env::var_os("NINE65_TRACE_NOISE_DIAGNOSTIC").is_some() {
            config.primes = vec![
                1_811_939_329,
                2_113_929_217,
                2_130_706_433,
                1_107_296_257,
                1_711_276_033,
            ];
            config.q = config.primes[0];
        }
        let boot = RNSFHEContext::try_new(&config).unwrap();
        let high = ExpandedPhaseEvaluator::new(&boot, work.t, 2).unwrap();
        let evaluator = PrimePowerPhaseEvaluator::new(&high, &work).unwrap();
        let remover = PrimePowerDigitRemoval::new(&evaluator);
        let mut rng = ShadowHarvester::with_seed(0x5050_5f43_4f4e_5452);
        let keys = ctx.generate_keys_dual(&mut rng);
        let bootstrap = evaluator
            .generate_keys_with_rng(&keys.secret_key, &mut rng)
            .unwrap();
        let trace_diagnostic = std::env::var_os("NINE65_TRACE_NOISE_DIAGNOSTIC").is_some();
        for message in [0, 1, 7, work.t - 1, 32_769] {
            let input = ctx.encrypt_dual(message, &keys.public_key, &mut rng);
            let phase = evaluator
                .evaluate(&input, &bootstrap.bootstrap_key)
                .unwrap();
            let high_residual =
                phase_residual_max(&boot, phase.high_lift(), &bootstrap.boot_keys.secret_key);
            let projection_residual = phase_residual_max(
                &boot,
                phase.coefficient_projection_view(),
                &bootstrap.boot_keys.secret_key,
            );
            let certificate = phase.noise_certificate();
            eprintln!(
                "sampled phase residual for m={message}: high={} bits, projection-input={} bits; public certificate={} bits",
                integer_bits(high_residual),
                integer_bits(projection_residual),
                u128_bits(certificate.high_error_bound.d0)
            );
            assert!(words(as_u512(high_residual)) < words(certificate.high_error_bound));
            assert!(
                words(as_u512(projection_residual))
                    < words(certificate.projection_input_error_bound)
            );
            if message == 32_769 && trace_diagnostic {
                let traced = trace_projection_coefficient(
                    &boot,
                    phase.coefficient_projection_view(),
                    &bootstrap.boot_keys.secret_key,
                    0,
                    &mut rng,
                );
                let traced_messages = decode_all(&boot, &traced, &bootstrap.boot_keys.secret_key);
                let expected_messages =
                    decode_all(&boot, phase.high_lift(), &bootstrap.boot_keys.secret_key);
                assert_eq!(traced_messages[0], expected_messages[0]);
                assert!(traced_messages[1..].iter().all(|&value| value == 0));
                let h = (work.t - 1) / 2;
                let x = traced_messages[0] as u128;
                let w = (x + boot.t as u128 - h as u128) % boot.t as u128;
                let low_digit = w % work.t as u128;
                let centered_low_digit = if low_digit <= (work.t / 2) as u128 {
                    low_digit as i128
                } else {
                    low_digit as i128 - work.t as i128
                };
                assert!(centered_low_digit.unsigned_abs() <= 17);
                let w_ciphertext = subtract_plain_constant(&boot, &traced, h);
                let p_squared = boot.t as u128;
                let factor_zero = w;
                let factor_one = (w + p_squared - 1) % p_squared;
                let factor_two_value = (w + p_squared - 2) % p_squared;
                let factor_three_value = (w + p_squared - 3) % p_squared;
                let traced_residual =
                    phase_residual_max(&boot, &traced, &bootstrap.boot_keys.secret_key);
                eprintln!(
                    "sampled full-size trace residual={} bits on SQUARE_BOOT; x={x}, shifted w=x-h={w}, centered low digit {centered_low_digit}; formula-only first-product leaf ceiling is about 63 bits",
                    integer_bits(traced_residual),
                );

                let exact = boot.try_exact_evaluator().unwrap();
                let relin = exact.generate_hybrid_gadget_key_with_rng(
                    &native_secret(&boot, &bootstrap.boot_keys.secret_key),
                    &mut rng,
                );
                let high_component = (w as i128 - centered_low_digit as i128) as u128;
                assert!(centered_low_digit >= 0);
                assert!(high_component <= w && high_component < p_squared);
                let low_representative =
                    subtract_plain_constant(&boot, &w_ciphertext, high_component as u64);
                let low_messages =
                    decode_all(&boot, &low_representative, &bootstrap.boot_keys.secret_key);
                assert_eq!(low_messages[0], centered_low_digit as u64);
                assert!(low_messages[1..].iter().all(|&value| value == 0));
                let mut low_input_expected = vec![0; boot.n];
                low_input_expected[0] = centered_low_digit as u64;
                let low_input_residual = phase_residual_max_against(
                    &boot,
                    &low_representative,
                    &bootstrap.boot_keys.secret_key,
                    &low_input_expected,
                );
                assert_eq!(low_input_residual, traced_residual);
                let low_square_tensor = exact
                    .try_mul_no_relin_exact(&low_representative, &low_representative)
                    .unwrap();
                let low_square_phase =
                    tensor_phase(&boot, &low_square_tensor, &bootstrap.boot_keys.secret_key);
                let low_square_messages =
                    decode_all(&boot, &low_square_phase, &bootstrap.boot_keys.secret_key);
                assert_eq!(low_square_messages[0], 1);
                assert!(low_square_messages[1..].iter().all(|&value| value == 0));
                let mut low_square_expected = vec![0; boot.n];
                low_square_expected[0] = 1;
                let low_square_residual = phase_residual_max_against(
                    &boot,
                    &low_square_phase,
                    &bootstrap.boot_keys.secret_key,
                    &low_square_expected,
                );
                eprintln!(
                    "oracle carry-removal control: w={w}, high component={high_component}, same {}-bit input residual; square of low representative 1 is correct with {}-bit residual",
                    integer_bits(low_input_residual),
                    integer_bits(low_square_residual),
                );
                let centered_square_tensor = exact
                    .try_mul_no_relin_centered_tensor_for_diagnostic(
                        &low_representative,
                        &low_representative,
                    )
                    .unwrap();
                let centered_square_phase = tensor_phase(
                    &boot,
                    &centered_square_tensor,
                    &bootstrap.boot_keys.secret_key,
                );
                let centered_square_messages = decode_all(
                    &boot,
                    &centered_square_phase,
                    &bootstrap.boot_keys.secret_key,
                );
                let centered_square_residual = phase_residual_max_against(
                    &boot,
                    &centered_square_phase,
                    &bootstrap.boot_keys.secret_key,
                    &low_square_expected,
                );
                eprintln!(
                    "centered-tensor-wrap control: square of low representative 1 decodes as {}; residual against 1 is {} bits",
                    centered_square_messages[0],
                    integer_bits(centered_square_residual),
                );
                let phase_only = phase_only_equivalent(
                    &boot,
                    &low_representative,
                    &bootstrap.boot_keys.secret_key,
                );
                assert_eq!(
                    phase_residual_max_against(
                        &boot,
                        &phase_only,
                        &bootstrap.boot_keys.secret_key,
                        &low_input_expected,
                    ),
                    low_input_residual,
                );
                let phase_only_tensor = exact
                    .try_mul_no_relin_exact(&phase_only, &phase_only)
                    .unwrap();
                let phase_only_square_phase =
                    tensor_phase(&boot, &phase_only_tensor, &bootstrap.boot_keys.secret_key);
                let phase_only_square_messages = decode_all(
                    &boot,
                    &phase_only_square_phase,
                    &bootstrap.boot_keys.secret_key,
                );
                let phase_only_square_residual = phase_residual_max_against(
                    &boot,
                    &phase_only_square_phase,
                    &bootstrap.boot_keys.secret_key,
                    &low_square_expected,
                );
                eprintln!(
                    "phase-only control: same mod-Q phase and {}-bit input residual; square of 1 decodes as {} with {}-bit residual",
                    integer_bits(low_input_residual),
                    phase_only_square_messages[0],
                    integer_bits(phase_only_square_residual),
                );
                let winding = winding_square_difference_diagnostic(
                    &boot,
                    &low_representative,
                    &low_square_phase,
                    &phase_only_square_phase,
                    &bootstrap.boot_keys.secret_key,
                );
                eprintln!(
                    "integer-lift winding check: max |K|={} bits; predicted 2*t*K*P={} bits; original-vs-phase-only output difference={} bits; component-rounding mismatch={} bits at coefficient {}; deterministic bound={} for N={}",
                    winding.winding_bits,
                    winding.predicted_winding_bits,
                    winding.observed_difference_bits,
                    winding.rounding_mismatch_bits,
                    winding.mismatch_coefficient,
                    winding.rounding_bound,
                    boot.n,
                );

                // Correct the actual relinearized ciphertext's raw phase;
                // keep its c1 component. This isolates cancellation from the
                // insecure component substitution used by (phase, 0).
                let native_low_square = exact
                    .relinearize_tensor(&low_square_tensor, &relin)
                    .unwrap();
                let corrected_low_square =
                    subtract_ciphertexts(&boot, &native_low_square, &winding.correction);
                assert_eq!(corrected_low_square.c1.limbs, native_low_square.c1.limbs);
                assert_eq!(
                    decode_all(
                        &boot,
                        &corrected_low_square,
                        &bootstrap.boot_keys.secret_key
                    ),
                    low_square_expected,
                );
                let corrected_residual = phase_residual_max_against(
                    &boot,
                    &corrected_low_square,
                    &bootstrap.boot_keys.secret_key,
                    &low_square_expected,
                );
                assert!(corrected_residual.lt(low_square_residual));

                // For constant plaintext m=1, Q=t*Delta+r gives the
                // encoded-message part 2*t*K*Delta = -2*r*K (mod Q).
                // This is the carry-only control; full correction also needs
                // the hidden noise term 2*t*K*e.
                let q = U256::product_u64s(&boot.config.primes);
                let remainder = q.div_mod_u64(boot.t).1;
                let message_term: Vec<U256> = winding
                    .winding
                    .iter()
                    .map(|&k| {
                        SignedU256::from_magnitude(
                            k > 0,
                            U256::from_u64(k.unsigned_abs()).mul_u64(2 * remainder),
                        )
                        .modulo(q)
                    })
                    .collect();
                let message_only_correction = raw_phase_addend_for_diagnostic(&boot, &message_term);
                let message_only_square =
                    subtract_ciphertexts(&boot, &native_low_square, &message_only_correction);
                let message_only_residual = phase_residual_max_against(
                    &boot,
                    &message_only_square,
                    &bootstrap.boot_keys.secret_key,
                    &low_square_expected,
                );
                assert!(corrected_residual.lt(message_only_residual));
                eprintln!(
                    "oracle raw-phase cancellation with native c1 preserved: full winding correction leaves {}-bit error; encoded-message/carry-only correction leaves {}-bit error",
                    integer_bits(corrected_residual),
                    integer_bits(message_only_residual),
                );

                let next_square = |label: &str, operand: &RNSCiphertext| {
                    let output = exact.try_mul_exact(operand, operand, &relin).unwrap();
                    let decoded = decode_all(&boot, &output, &bootstrap.boot_keys.secret_key);
                    let correct = decoded == low_square_expected;
                    let residual = phase_residual_max_against(
                        &boot,
                        &output,
                        &bootstrap.boot_keys.secret_key,
                        &low_square_expected,
                    );
                    eprintln!(
                        "winding-correction follow-up {label}: next square correct={correct}; intended error={} bits / half-Delta={} bits",
                        integer_bits(residual),
                        u128_bits(high.certificate().half_delta.d0),
                    );
                    (output, residual, correct)
                };
                let (_, uncorrected_fourth_error, _) =
                    next_square("uncorrected native product", &native_low_square);
                let (_, message_only_fourth_error, _) = next_square(
                    "encoded-message/carry-only correction",
                    &message_only_square,
                );
                let (corrected_fourth, corrected_fourth_error, corrected_fourth_correct) =
                    next_square("full winding correction", &corrected_low_square);
                assert!(corrected_fourth_correct);
                assert!(corrected_fourth_error.lt(uncorrected_fourth_error));
                assert!(corrected_fourth_error.lt(message_only_fourth_error));
                assert!(
                    words(as_u512(corrected_fourth_error)) < words(high.certificate().half_delta)
                );
                // This final control checks whether one oracle cancellation
                // resets the whole chain or only buys the next operation.
                next_square(
                    "one more multiply without another correction",
                    &corrected_fourth,
                );

                // Oracle-provided carry coordinates at two different scales.
                // The circuit closures below receive only ciphertexts and the
                // ordinary relinearization key. Their carry producer is still
                // a key-holder test fixture, with no public admission claim.
                let raw_k_values: Vec<U256> = winding
                    .winding
                    .iter()
                    .map(|&k| {
                        SignedU256::from_magnitude(k < 0, U256::from_u64(k.unsigned_abs()))
                            .modulo(q)
                    })
                    .collect();
                let delta = q.div_mod_u64(boot.t).0;
                let delta_k_values: Vec<U256> = winding
                    .winding
                    .iter()
                    .map(|&k| {
                        SignedU256::from_magnitude(k < 0, delta.mul_u64(k.unsigned_abs())).modulo(q)
                    })
                    .collect();
                let raw_k_clear = raw_phase_addend_for_diagnostic(&boot, &raw_k_values);
                let delta_k_clear = raw_phase_addend_for_diagnostic(&boot, &delta_k_values);
                let mut adapter_rng = ShadowHarvester::with_seed(0x5749_4e44_5f41_4450);
                let raw_k_noisy = encrypt_raw_phase_for_diagnostic(
                    &boot,
                    &raw_k_clear,
                    &bootstrap.boot_keys.secret_key,
                    &mut adapter_rng,
                );
                let delta_k_noisy = encrypt_raw_phase_for_diagnostic(
                    &boot,
                    &delta_k_clear,
                    &bootstrap.boot_keys.secret_key,
                    &mut adapter_rng,
                );
                let expected_k: Vec<u64> = winding
                    .winding
                    .iter()
                    .map(|&k| (k as i128).rem_euclid(boot.t as i128) as u64)
                    .collect();
                assert_eq!(
                    decode_all(&boot, &delta_k_noisy, &bootstrap.boot_keys.secret_key),
                    expected_k
                );
                let adapter_zero = vec![0; boot.n];
                assert_eq!(
                    decode_all(&boot, &raw_k_noisy, &bootstrap.boot_keys.secret_key),
                    adapter_zero
                );
                let raw_k_noise = subtract_ciphertexts(&boot, &raw_k_noisy, &raw_k_clear);
                let carry_noise = phase_residual_max_against(
                    &boot,
                    &raw_k_noise,
                    &bootstrap.boot_keys.secret_key,
                    &adapter_zero,
                );
                assert!(carry_noise.le(U256::from_u64(boot.config.eta as u64)));

                let factor = 2 * boot.t as u128;
                let raw_adapter = |carry: &RNSCiphertext| {
                    let tensor = raw_ring_tensor_for_diagnostic(&boot, &low_representative, carry);
                    let product = exact.relinearize_tensor(&tensor, &relin).unwrap();
                    scale_ciphertext_for_diagnostic(&boot, &product, factor)
                };
                let raw_ideal_correction = raw_adapter(&raw_k_clear);
                let raw_noisy_correction = raw_adapter(&raw_k_noisy);
                let raw_noise_correction = raw_adapter(&raw_k_noise);
                let raw_delta =
                    subtract_ciphertexts(&boot, &raw_noisy_correction, &raw_ideal_correction);
                // Both tensors have exactly the same e2, so the deterministic
                // relinearization error is identical. This is an exact
                // component identity, not merely matching decoded values.
                assert_eq!(raw_delta.c0.limbs, raw_noise_correction.c0.limbs);
                assert_eq!(raw_delta.c1.limbs, raw_noise_correction.c1.limbs);
                let raw_noise_tensor =
                    raw_ring_tensor_for_diagnostic(&boot, &low_representative, &raw_k_noise);
                let raw_noise_phase = scale_ciphertext_for_diagnostic(
                    &boot,
                    &tensor_phase(&boot, &raw_noise_tensor, &bootstrap.boot_keys.secret_key),
                    factor,
                );
                let noise_product_error = phase_residual_max_against(
                    &boot,
                    &raw_noise_phase,
                    &bootstrap.boot_keys.secret_key,
                    &adapter_zero,
                );
                let raw_switch_delta =
                    subtract_ciphertexts(&boot, &raw_noise_correction, &raw_noise_phase);
                let raw_switch_error = phase_residual_max_against(
                    &boot,
                    &raw_switch_delta,
                    &bootstrap.boot_keys.secret_key,
                    &adapter_zero,
                );
                eprintln!(
                    "raw encrypted-carry adapter decomposition: input CBD error={} bits; 2*t*carry_error*P={} bits before relinearization; scaled key-switch delta={} bits",
                    integer_bits(carry_noise), integer_bits(noise_product_error), integer_bits(raw_switch_error),
                );

                let mut unit_error = vec![U256::zero(); boot.n];
                unit_error[0] = U256::from_u64(1);
                let raw_k_unit_error = boot.add(
                    &raw_k_clear,
                    &raw_phase_addend_for_diagnostic(&boot, &unit_error),
                );
                let raw_unit_correction = raw_adapter(&raw_k_unit_error);
                let scaled_ideal_product = exact
                    .try_mul_exact(&low_representative, &delta_k_clear, &relin)
                    .unwrap();
                let scaled_noisy_product = exact
                    .try_mul_exact(&low_representative, &delta_k_noisy, &relin)
                    .unwrap();
                let scaled_ideal_correction =
                    scale_ciphertext_for_diagnostic(&boot, &scaled_ideal_product, factor);
                let scaled_noisy_correction =
                    scale_ciphertext_for_diagnostic(&boot, &scaled_noisy_product, factor);

                // A difference-of-squares control tries cancelling the
                // structured floor-scale bias using the SAME encrypted K:
                // 2*t*Mul(C, Enc(K)) - t^2*Mul(Enc(K), Enc(K)).
                let carry_square_ideal = exact
                    .try_mul_exact(&delta_k_clear, &delta_k_clear, &relin)
                    .unwrap();
                let carry_square_noisy = exact
                    .try_mul_exact(&delta_k_noisy, &delta_k_noisy, &relin)
                    .unwrap();
                let t_squared = boot.t as u128 * boot.t as u128;
                let compensated_ideal = subtract_ciphertexts(
                    &boot,
                    &scaled_ideal_correction,
                    &scale_ciphertext_for_diagnostic(&boot, &carry_square_ideal, t_squared),
                );
                let compensated_noisy = subtract_ciphertexts(
                    &boot,
                    &scaled_noisy_correction,
                    &scale_ciphertext_for_diagnostic(&boot, &carry_square_noisy, t_squared),
                );

                // Matched 2x2 control: same sampled error with/without its
                // mask, and the same mask with/without that exact error.
                // Removing either uses the secret oracle, not public refresh.
                let delta_phase_only =
                    phase_only_equivalent(&boot, &delta_k_noisy, &bootstrap.boot_keys.secret_key);
                let delta_noise_phase =
                    subtract_ciphertexts(&boot, &delta_phase_only, &delta_k_clear);
                let delta_mask_zero_error =
                    subtract_ciphertexts(&boot, &delta_k_noisy, &delta_noise_phase);
                let masked_exact_phase = phase_only_equivalent(
                    &boot,
                    &delta_mask_zero_error,
                    &bootstrap.boot_keys.secret_key,
                );
                assert_eq!(masked_exact_phase.c0.limbs, delta_k_clear.c0.limbs);
                assert_eq!(delta_mask_zero_error.c1.limbs, delta_k_noisy.c1.limbs);
                let delta_noise = phase_residual_max_against(
                    &boot,
                    &delta_noise_phase,
                    &bootstrap.boot_keys.secret_key,
                    &adapter_zero,
                );
                assert!(delta_noise.le(U256::from_u64(boot.config.eta as u64)));

                let mut matched_adapters = Vec::new();
                for (label, carry) in [
                    ("clear / zero error", &delta_k_clear),
                    ("clear / sampled CBD", &delta_phase_only),
                    ("same mask / zero error", &delta_mask_zero_error),
                    ("same mask / sampled CBD", &delta_k_noisy),
                ] {
                    let cross = exact
                        .try_mul_no_relin_exact(&low_representative, carry)
                        .unwrap();
                    let square = exact.try_mul_no_relin_exact(carry, carry).unwrap();
                    let combined = compensated_tensor_for_diagnostic(&boot, &cross, &square);
                    let before_switch =
                        tensor_phase(&boot, &combined, &bootstrap.boot_keys.secret_key);
                    let fused = exact.relinearize_tensor(&combined, &relin).unwrap();
                    let separately_switched = subtract_ciphertexts(
                        &boot,
                        &scale_ciphertext_for_diagnostic(
                            &boot,
                            &exact.relinearize_tensor(&cross, &relin).unwrap(),
                            factor,
                        ),
                        &scale_ciphertext_for_diagnostic(
                            &boot,
                            &exact.relinearize_tensor(&square, &relin).unwrap(),
                            t_squared,
                        ),
                    );
                    for (schedule, result) in
                        [("separate", &separately_switched), ("fused", &fused)]
                    {
                        let switch_delta = subtract_ciphertexts(&boot, result, &before_switch);
                        let switch_error = phase_residual_max_against(
                            &boot,
                            &switch_delta,
                            &bootstrap.boot_keys.secret_key,
                            &adapter_zero,
                        );
                        eprintln!("matched Delta carry {label}, {schedule}: isolated key-switch error={} bits",
                            integer_bits(switch_error));
                    }
                    matched_adapters.push((
                        format!("matched Delta {label}, before switch"),
                        before_switch,
                    ));
                    matched_adapters.push((
                        format!("matched Delta {label}, separate"),
                        separately_switched,
                    ));
                    matched_adapters.push((format!("matched Delta {label}, fused"), fused));
                }

                let assess_adapter = |label: &str,
                                      candidate: &RNSCiphertext,
                                      exact_control: bool| {
                    let difference = subtract_ciphertexts(&boot, candidate, &winding.correction);
                    let producer_error = phase_residual_max_against(
                        &boot,
                        &difference,
                        &bootstrap.boot_keys.secret_key,
                        &adapter_zero,
                    );
                    let output = subtract_ciphertexts(&boot, &native_low_square, candidate);
                    let decoded = decode_all(&boot, &output, &bootstrap.boot_keys.secret_key);
                    let correct = decoded == low_square_expected;
                    let output_error = phase_residual_max_against(
                        &boot,
                        &output,
                        &bootstrap.boot_keys.secret_key,
                        &low_square_expected,
                    );
                    eprintln!(
                        "encrypted-carry adapter {label}: correction-target error={} bits; corrected product error={} bits; product correct={correct}",
                        integer_bits(producer_error), integer_bits(output_error),
                    );
                    if exact_control {
                        assert!(producer_error.is_zero());
                        assert_eq!(output_error, corrected_residual);
                        assert!(correct);
                    }
                    if correct {
                        let (_, _, next_correct) = next_square(label, &output);
                        if exact_control {
                            assert!(next_correct);
                        }
                    } else {
                        eprintln!("encrypted-carry adapter {label}: dependent square skipped because correction already changes the plaintext");
                    }
                };
                for (label, candidate, exact_control) in [
                    (
                        "raw K, zero error (oracle control)",
                        &raw_ideal_correction,
                        true,
                    ),
                    ("raw K, one-unit error", &raw_unit_correction, false),
                    ("raw K, sampled CBD error", &raw_noisy_correction, false),
                    (
                        "Delta K, zero error (oracle control)",
                        &scaled_ideal_correction,
                        false,
                    ),
                    (
                        "Delta K, sampled CBD error",
                        &scaled_noisy_correction,
                        false,
                    ),
                    (
                        "Delta K, compensated zero-error control",
                        &compensated_ideal,
                        false,
                    ),
                    (
                        "Delta K, compensated sampled CBD error",
                        &compensated_noisy,
                        false,
                    ),
                ] {
                    assess_adapter(label, candidate, exact_control);
                }
                for (label, candidate) in &matched_adapters {
                    assess_adapter(label, candidate, false);
                }

                // Second-winding ablation on the actual masked, noisy carry.
                // V=C-t*B has phase P+r*K-t*nu. The extra term in D_comp is
                // 2*t^2*J*V. Its producer below is still a secret oracle.
                let own_j = component_winding_for_diagnostic(
                    &boot,
                    &delta_k_noisy,
                    &bootstrap.boot_keys.secret_key,
                );
                let own_j_values = own_j
                    .iter()
                    .map(|&j| {
                        SignedU256::from_magnitude(j < 0, U256::from_u64(j.unsigned_abs()))
                            .modulo(q)
                    })
                    .collect::<Vec<_>>();
                let raw_j = raw_phase_addend_for_diagnostic(&boot, &own_j_values);
                let v_ciphertext = subtract_ciphertexts(
                    &boot,
                    &low_representative,
                    &scale_ciphertext_for_diagnostic(&boot, &delta_k_noisy, boot.t as u128),
                );
                let cross = exact
                    .try_mul_no_relin_exact(&low_representative, &delta_k_noisy)
                    .unwrap();
                let square = exact
                    .try_mul_no_relin_exact(&delta_k_noisy, &delta_k_noisy)
                    .unwrap();
                let combined = compensated_tensor_for_diagnostic(&boot, &cross, &square);
                let fused = exact.relinearize_tensor(&combined, &relin).unwrap();
                let second_adapter = |carry: &RNSCiphertext| {
                    let tensor = raw_ring_tensor_for_diagnostic(&boot, &v_ciphertext, carry);
                    let product = exact.relinearize_tensor(&tensor, &relin).unwrap();
                    scale_ciphertext_for_diagnostic(&boot, &product, 2 * t_squared)
                };
                let exact_second_term = second_adapter(&raw_j);
                let twice_corrected = subtract_ciphertexts(&boot, &fused, &exact_second_term);
                assess_adapter("two windings, exact raw J oracle", &twice_corrected, false);

                // A single scale-round control: square the same phase V in
                // oracle (V,0) form. This is NOT an evaluator implementation.
                let v_phase =
                    phase_only_equivalent(&boot, &v_ciphertext, &bootstrap.boot_keys.secret_key);
                assert_eq!(
                    decode_all(&boot, &v_phase, &bootstrap.boot_keys.secret_key),
                    low_square_expected
                );
                let single_round = exact.try_mul_exact(&v_phase, &v_phase, &relin).unwrap();
                let corrected_output =
                    subtract_ciphertexts(&boot, &native_low_square, &twice_corrected);
                let rounding_delta = subtract_ciphertexts(&boot, &corrected_output, &single_round);
                let rounding_error = phase_residual_max_against(
                    &boot,
                    &rounding_delta,
                    &bootstrap.boot_keys.secret_key,
                    &adapter_zero,
                );
                let n = boot.n as u128;
                let rounding_bound = (n * n + n + 2) / 2 * (boot.t as u128 + 1).pow(2) + 1;
                let switch_bound = boot.config.eta as u128
                    * n
                    * ((1u128 << 10) - 1)
                    * boot
                        .config
                        .primes
                        .iter()
                        .map(|prime| ((64 - prime.leading_zeros()) as u128).div_ceil(10))
                        .sum::<u128>();
                assert!(rounding_error.le(U256::from_u128(rounding_bound + 2 * switch_bound)));
                let single_error = phase_residual_max_against(
                    &boot,
                    &single_round,
                    &bootstrap.boot_keys.secret_key,
                    &low_square_expected,
                );
                eprintln!("second-winding rounding isolation: |J|={} bits; two-winding output minus single-round phase control={} bits; deterministic rounding+switch bound={} bits; single-round control error={} bits",
                    own_j.iter().map(|j| j.unsigned_abs()).max().unwrap_or(0).checked_ilog2().unwrap_or(0)+1,
                    integer_bits(rounding_error), u128_bits(rounding_bound + 2*switch_bound), integer_bits(single_error));
                let (_, _, single_next_correct) =
                    next_square("single-round V phase oracle", &single_round);
                assert!(single_next_correct);

                let unit_phase = raw_phase_addend_for_diagnostic(&boot, &unit_error);
                let j_one_error = boot.add(&raw_j, &unit_phase);
                let j_noisy = encrypt_raw_phase_for_diagnostic(
                    &boot,
                    &raw_j,
                    &bootstrap.boot_keys.secret_key,
                    &mut adapter_rng,
                );
                for (label, carry) in [
                    ("two windings, raw J one-unit error", &j_one_error),
                    ("two windings, raw J sampled CBD", &j_noisy),
                ] {
                    let second_term = second_adapter(carry);
                    let correction = subtract_ciphertexts(&boot, &fused, &second_term);
                    assess_adapter(label, &correction, false);
                }

                let right = subtract_plain_constant(&boot, &w_ciphertext, 1);
                let first_product_tensor =
                    exact.try_mul_no_relin_exact(&w_ciphertext, &right).unwrap();
                let first_tensor_phase = tensor_phase(
                    &boot,
                    &first_product_tensor,
                    &bootstrap.boot_keys.secret_key,
                );
                let tensor_messages =
                    decode_all(&boot, &first_tensor_phase, &bootstrap.boot_keys.secret_key);
                let expected_first_product = (factor_zero * factor_one % p_squared) as u64;
                assert_eq!(tensor_messages[0], expected_first_product);
                assert!(tensor_messages[1..].iter().all(|&value| value == 0));
                let tensor_residual =
                    phase_residual_max(&boot, &first_tensor_phase, &bootstrap.boot_keys.secret_key);
                let first_product = exact
                    .relinearize_tensor(&first_product_tensor, &relin)
                    .unwrap();
                let switch_delta = subtract_ciphertexts(&boot, &first_product, &first_tensor_phase);
                let zero_messages = vec![0; boot.n];
                let switch_residual = phase_residual_max_against(
                    &boot,
                    &switch_delta,
                    &bootstrap.boot_keys.secret_key,
                    &zero_messages,
                );
                let product_messages =
                    decode_all(&boot, &first_product, &bootstrap.boot_keys.secret_key);
                assert_eq!(
                    product_messages[0],
                    (factor_zero * factor_one % p_squared) as u64
                );
                assert!(product_messages[1..].iter().all(|&value| value == 0));
                let product_residual =
                    phase_residual_max(&boot, &first_product, &bootstrap.boot_keys.secret_key);
                eprintln!(
                    "native first canonical-factor tensor residual={} bits (0x{:032x}{:032x}); relinearized residual={} bits (0x{:032x}{:032x}); isolated relinearization delta={} bits (0x{:032x}{:032x}); product plaintext verified",
                    integer_bits(tensor_residual),
                    tensor_residual.hi,
                    tensor_residual.lo,
                    integer_bits(product_residual),
                    product_residual.hi,
                    product_residual.lo,
                    integer_bits(switch_residual),
                    switch_residual.hi,
                    switch_residual.lo,
                );

                for target_w in [-17i64, -1, 0, 17] {
                    let shift = target_w as i128 - centered_low_digit as i128;
                    let shifted_w = if shift < 0 {
                        subtract_plain_constant(&boot, &w_ciphertext, (-shift) as u64)
                    } else {
                        add_plain_constant(&boot, &w_ciphertext, shift as u64)
                    };
                    let shifted_right = subtract_plain_constant(&boot, &shifted_w, 1);
                    let shifted_tensor = exact
                        .try_mul_no_relin_exact(&shifted_w, &shifted_right)
                        .unwrap();
                    let shifted_phase =
                        tensor_phase(&boot, &shifted_tensor, &bootstrap.boot_keys.secret_key);
                    let shifted_message = (w as i128 + shift).rem_euclid(p_squared as i128) as u64;
                    let mut shifted_input_expected = vec![0; boot.n];
                    shifted_input_expected[0] = shifted_message;
                    let shifted_input_messages =
                        decode_all(&boot, &shifted_w, &bootstrap.boot_keys.secret_key);
                    assert_eq!(shifted_input_messages[0], shifted_message);
                    assert!(shifted_input_messages[1..].iter().all(|&value| value == 0));
                    let shifted_input_residual = phase_residual_max_against(
                        &boot,
                        &shifted_w,
                        &bootstrap.boot_keys.secret_key,
                        &shifted_input_expected,
                    );
                    let expected = ((shifted_message as u128
                        * (shifted_message as u128 + p_squared - 1))
                        % p_squared) as u64;
                    let decoded =
                        decode_all(&boot, &shifted_phase, &bootstrap.boot_keys.secret_key);
                    let plaintext_correct = decoded[0] == expected;
                    let tail_zero = decoded[1..].iter().all(|&value| value == 0);
                    let mut expected_vector = vec![0; boot.n];
                    expected_vector[0] = expected;
                    let residual = phase_residual_max_against(
                        &boot,
                        &shifted_phase,
                        &bootstrap.boot_keys.secret_key,
                        &expected_vector,
                    );

                    let square_tensor = exact
                        .try_mul_no_relin_exact(&shifted_w, &shifted_w)
                        .unwrap();
                    let square_phase =
                        tensor_phase(&boot, &square_tensor, &bootstrap.boot_keys.secret_key);
                    let square_expected =
                        (shifted_message as u128 * shifted_message as u128 % p_squared) as u64;
                    let square_decoded =
                        decode_all(&boot, &square_phase, &bootstrap.boot_keys.secret_key);
                    let square_correct = square_decoded[0] == square_expected
                        && square_decoded[1..].iter().all(|&value| value == 0);
                    let mut expected_square_vector = vec![0; boot.n];
                    expected_square_vector[0] = square_expected;
                    let square_residual = phase_residual_max_against(
                        &boot,
                        &square_phase,
                        &bootstrap.boot_keys.secret_key,
                        &expected_square_vector,
                    );
                    eprintln!(
                        "same traced noise ({}-bit input), support value w={target_w}: factor-product correct={plaintext_correct}/{tail_zero}, expected={expected}, decoded={}, residual={} bits; square correct={square_correct}, expected={square_expected}, decoded={}, residual={} bits",
                        integer_bits(shifted_input_residual),
                        decoded[0],
                        integer_bits(residual),
                        square_decoded[0],
                        integer_bits(square_residual),
                    );
                }

                let factor_two = subtract_plain_constant(&boot, &w_ciphertext, 2);
                let factor_three = subtract_plain_constant(&boot, &w_ciphertext, 3);
                let second_pair = exact
                    .try_mul_exact(&factor_two, &factor_three, &relin)
                    .unwrap();
                let second_pair_messages =
                    decode_all(&boot, &second_pair, &bootstrap.boot_keys.secret_key);
                let expected_second_pair =
                    (factor_two_value * factor_three_value % p_squared) as u64;
                assert_eq!(second_pair_messages[0], expected_second_pair);
                assert!(second_pair_messages[1..].iter().all(|&value| value == 0));
                let depth_two = exact
                    .try_mul_exact(&first_product, &second_pair, &relin)
                    .unwrap();
                let depth_two_messages =
                    decode_all(&boot, &depth_two, &bootstrap.boot_keys.secret_key);
                let expected_depth_two = (factor_zero * factor_one % p_squared * factor_two_value
                    % p_squared
                    * factor_three_value
                    % p_squared) as u64;
                let depth_two_correct = depth_two_messages[0] == expected_depth_two
                    && depth_two_messages[1..].iter().all(|&value| value == 0);
                let mut expected_depth_two_vector = vec![0; boot.n];
                expected_depth_two_vector[0] = expected_depth_two;
                let intended_residual = phase_residual_max_against(
                    &boot,
                    &depth_two,
                    &bootstrap.boot_keys.secret_key,
                    &expected_depth_two_vector,
                );
                let half_delta = high.certificate().half_delta;
                eprintln!(
                    "native balanced four-factor node correct={depth_two_correct}; expected={}, decoded={}, intended residual={} bits / half-Delta={} bits",
                    expected_depth_two,
                    depth_two_messages[0],
                    integer_bits(intended_residual),
                    u128_bits(half_delta.d0)
                );
                if depth_two_correct {
                    eprintln!(
                        "native balanced four-factor node residual={} bits",
                        integer_bits(phase_residual_max(
                            &boot,
                            &depth_two,
                            &bootstrap.boot_keys.secret_key,
                        ))
                    );
                }

                let square = exact
                    .try_mul_exact(&w_ciphertext, &w_ciphertext, &relin)
                    .unwrap();
                let expected_square = (w * w % p_squared) as u64;
                let square_messages = decode_all(&boot, &square, &bootstrap.boot_keys.secret_key);
                let square_correct = square_messages[0] == expected_square
                    && square_messages[1..].iter().all(|&value| value == 0);
                let mut expected_square_vector = vec![0; boot.n];
                expected_square_vector[0] = expected_square;
                let square_residual = phase_residual_max_against(
                    &boot,
                    &square,
                    &bootstrap.boot_keys.secret_key,
                    &expected_square_vector,
                );
                eprintln!(
                    "native power-basis w^2 correct={square_correct}; intended residual={} bits / half-Delta={} bits",
                    integer_bits(square_residual),
                    u128_bits(half_delta.d0)
                );
                if square_correct {
                    let fourth = exact.try_mul_exact(&square, &square, &relin).unwrap();
                    let expected_fourth =
                        (expected_square as u128 * expected_square as u128 % p_squared) as u64;
                    let fourth_messages =
                        decode_all(&boot, &fourth, &bootstrap.boot_keys.secret_key);
                    let fourth_correct = fourth_messages[0] == expected_fourth
                        && fourth_messages[1..].iter().all(|&value| value == 0);
                    let mut expected_fourth_vector = vec![0; boot.n];
                    expected_fourth_vector[0] = expected_fourth;
                    let fourth_residual = phase_residual_max_against(
                        &boot,
                        &fourth,
                        &bootstrap.boot_keys.secret_key,
                        &expected_fourth_vector,
                    );
                    eprintln!(
                        "native power-basis w^4 correct={fourth_correct}; intended residual={} bits / half-Delta={} bits",
                        integer_bits(fourth_residual),
                        u128_bits(half_delta.d0)
                    );
                }
            }
            let digit = oracle_digit(&boot, &phase, &bootstrap.boot_keys, &mut rng);
            let contracted = remover.contract(&phase, &digit).unwrap();
            let decoded = decode_all(
                evaluator.low_context(),
                contracted.ciphertext(),
                &bootstrap.boot_keys.secret_key,
            );
            assert_eq!(decoded[0], message);
            assert!(decoded[1..].iter().all(|&v| v == 0));
            let expected_floor_scale_difference =
                U512::product_u64s(&boot.config.primes).mod_u64(work.t * work.t) / work.t;
            assert_eq!(
                contracted.certificate().floor_scale_difference,
                expected_floor_scale_difference
            );
            assert!(
                words(contracted.certificate().output_error_bound)
                    < words(contracted.certificate().half_delta)
            );

            let mut bad = digit;
            bad.lineage.0[0] ^= 1;
            assert!(matches!(
                remover.contract(&phase, &bad),
                Err(Nine65Error::BootstrapConfigMismatch { .. })
            ));
            bad.lineage = phase.lineage.clone();
            bad.family[0] ^= 1;
            assert!(remover.contract(&phase, &bad).is_err());
            bad.family = phase.family;
            let bound = bad.error_bound;
            bad.error_bound = U512 {
                d0: u128::MAX,
                d1: u128::MAX,
                d2: u128::MAX,
                d3: u128::MAX,
            };
            assert!(matches!(
                remover.contract(&phase, &bad),
                Err(Nine65Error::BootstrapFailed { .. })
            ));
            bad.error_bound = bound;
            bad.encrypted.c0.limbs[0][0] = config.primes[0];
            assert!(matches!(
                remover.contract(&phase, &bad),
                Err(Nine65Error::InvalidParameter { .. })
            ));
        }

        // The source is almost at its admitted digit-margin limit. Without
        // removal, reinterpretation retains its displaced low-digit error.
        let q = work.primes.iter().map(|&v| v as u128).product::<u128>();
        let budget = ExpandedPhase1Plan::new(&work, 4, 2)
            .unwrap()
            .input_noise_budget()
            .unwrap();
        let phase_value = q / work.t as u128 * 7 + budget.max_centered_error.d0;
        let input = DualRNSCiphertext {
            c0: DualRNSPoly {
                main: work
                    .primes
                    .iter()
                    .map(|&p| {
                        let mut lane = vec![0; work.n];
                        lane[0] = (phase_value % p as u128) as u64;
                        lane
                    })
                    .collect(),
                anchor: vec![],
                n: work.n,
            },
            c1: DualRNSPoly {
                main: vec![vec![0; work.n]; 4],
                anchor: vec![],
                n: work.n,
            },
            level: 4,
        };
        let phase = evaluator
            .evaluate(&input, &bootstrap.bootstrap_key)
            .unwrap();
        let digit = oracle_digit(&boot, &phase, &bootstrap.boot_keys, &mut rng);
        let contracted = remover.contract(&phase, &digit).unwrap();
        let low = evaluator.low_context();
        assert_eq!(
            decode_all(
                low,
                contracted.ciphertext(),
                &bootstrap.boot_keys.secret_key
            )[0],
            7
        );
        let native_secret = RNSSecretKey {
            s: RNSPolynomial {
                limbs: low
                    .rns
                    .mont_contexts
                    .iter()
                    .zip(&bootstrap.boot_keys.secret_key.s.main)
                    .map(|(mont, lane)| lane.iter().map(|&v| mont.to_montgomery(v)).collect())
                    .collect(),
                n: low.n,
            },
        };
        let multiply = low.try_exact_evaluator().unwrap();
        let relin = multiply.generate_hybrid_gadget_key_with_rng(&native_secret, &mut rng);
        let squared = multiply
            .try_mul_exact(contracted.ciphertext(), contracted.ciphertext(), &relin)
            .unwrap();
        let decoded = decode_all(low, &squared, &bootstrap.boot_keys.secret_key);
        assert_eq!(decoded[0], 49);
        assert!(decoded[1..].iter().all(|&v| v == 0));
    }
}
