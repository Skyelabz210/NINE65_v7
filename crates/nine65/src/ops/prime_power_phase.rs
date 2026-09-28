//! Authentic same-prime phase views and conditional t^2 -> t contraction.
//!
//! Both views are evaluated from the same public components under the same
//! independently generated boot secret. Winding by t^2 is irrelevant to the
//! quotient modulo t. An ordinary Enc_t(r), however, is not a certified
//! canonical lift Enc_{t^2}(r): converting the encoding is still nonlinear.
//!
//! The contraction kernel requires that stronger evidence. No production
//! constructor for it exists yet. Neither this module nor its arithmetic
//! helper reconstructs a ciphertext coefficient, low digit, or winding.

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
    /// Parameter-derived allowance; not evidence of actual work-input noise.
    pub max_centered_work_error: U512,
    pub source_level: usize,
    pub rounding_shift: u64,
}

/// An immutable pair Enc_{t^2}(x), Enc_t(x mod t), where x=(w+h) mod t^2.
/// Both encryptions have the same boot secret and main basis. Neither is a
/// serialized coprime anchor. The evaluator accepts no secret key.
pub struct PrimePowerLiftedPhase {
    high: RNSCiphertext,
    low: RNSCiphertext,
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

    /// Create both views in one call. No API accepts independently supplied
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
        Ok(PrimePowerLiftedPhase {
            high,
            low,
            lineage,
            family: key.family,
            primes: self.low.config.primes.clone(),
            n: self.work.n,
            base: t,
            noise: PrimePowerPhaseNoiseCertificate {
                high_error_bound: self.high.certificate().phase_error_bound,
                low_error_bound: self.low_error_bound,
                max_centered_work_error: budget.max_centered_error,
                source_level: ct.level,
                rounding_shift: h,
            },
        })
    }
}

/// Stronger than the ordinary low view: this ciphertext's plaintext modulo
/// t^2 is the canonical integer r in [0,t), for the bound phase lineage.
/// Fields and construction are private. No certified production low-digit
/// lift producer exists yet; test-only oracle construction is below.
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
    use crate::entropy::ShadowHarvester;
    use crate::ops::rns_fhe::{DualRNSPoly, DualRNSSecretKey, RNSSecretKey};
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
        let boot = RNSFHEContext::try_new(&config).unwrap();
        let high = ExpandedPhaseEvaluator::new(&boot, work.t, 2).unwrap();
        let evaluator = PrimePowerPhaseEvaluator::new(&high, &work).unwrap();
        let remover = PrimePowerDigitRemoval::new(&evaluator);
        let mut rng = ShadowHarvester::with_seed(0x5050_5f43_4f4e_5452);
        let keys = ctx.generate_keys_dual(&mut rng);
        let bootstrap = evaluator
            .generate_keys_with_rng(&keys.secret_key, &mut rng)
            .unwrap();
        for message in [0, 1, 7, work.t - 1] {
            let input = ctx.encrypt_dual(message, &keys.public_key, &mut rng);
            let phase = evaluator
                .evaluate(&input, &bootstrap.bootstrap_key)
                .unwrap();
            let digit = oracle_digit(&boot, &phase, &bootstrap.boot_keys, &mut rng);
            let contracted = remover.contract(&phase, &digit).unwrap();
            let decoded = decode_all(
                evaluator.low_context(),
                contracted.ciphertext(),
                &bootstrap.boot_keys.secret_key,
            );
            assert_eq!(decoded[0], message);
            assert!(decoded[1..].iter().all(|&v| v == 0));
            assert_eq!(contracted.certificate().floor_scale_difference, 49185);
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
