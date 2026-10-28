//! Main-basis public ring return for an embedded phase-clock polynomial.
//!
//! For boot degree D*N and X=Y^D, select block zero of the decrypted phase
//! and switch each of its D secret blocks under the work secret. No clear
//! secret or plaintext is needed by evaluation. This conditional kernel
//! neither authenticates source history nor admits named-profile refresh.

use crate::arithmetic::rns::{product_limbs_u64, U512};
use crate::arithmetic::RNSPolynomial;
use crate::entropy::FheRng;
use crate::errors::{Nine65Error, Nine65Result};
use crate::ops::exact_mul::{ExactMulEvaluator, ExactTensor3, RNSHybridGadgetKey};
use crate::ops::public_phase_clock::PublicPhaseClockOutput;
use crate::ops::rns_fhe::{RNSCiphertext, RNSFHEContext, RNSSecretKey};
use crate::ops::rns_galois::{shift, validate_main, validate_ternary_secret, RNSGaloisEvaluator};
use zeroize::Zeroizing;

fn failure(reason: impl Into<String>) -> Nine65Error {
    Nine65Error::BootstrapFailed {
        reason: reason.into(),
    }
}

fn words(v: U512) -> (u128, u128, u128, u128) {
    (v.d3, v.d2, v.d1, v.d0)
}

/// Opaque switches from the boot secret's residue classes to the work key.
pub struct PhaseClockReturnKey {
    switches: Vec<RNSHybridGadgetKey>,
    work_n: usize,
    boot_n: usize,
    primes: Vec<u64>,
    t: u64,
    eta: usize,
    boot_family: Option<[u8; 32]>,
    target_source_domain: Option<([u8; 32], [u8; 32])>,
}

impl PhaseClockReturnKey {
    pub(crate) fn bind_boot_family(&mut self, family: [u8; 32]) -> Nine65Result<()> {
        if self.boot_family.is_some() {
            return Err(failure("phase-clock return key family is already bound"));
        }
        self.boot_family = Some(family);
        Ok(())
    }
    pub(crate) fn bind_target_source_domain(
        &mut self,
        context: [u8; 32],
        key: [u8; 32],
    ) -> Nine65Result<()> {
        if self.target_source_domain.is_some() {
            return Err(failure(
                "phase-clock return target source domain is already bound",
            ));
        }
        self.target_source_domain = Some((context, key));
        Ok(())
    }
}

/// A main-only Montgomery ciphertext in the work ring, with a conditional
/// bound in ideal-grid units |t*phase-Q*message|. No DualRNS anchors are forged.
pub struct PhaseClockReturnedCiphertext {
    ciphertext: RNSCiphertext,
    error_bound: U512,
    work_family: Option<[u8; 32]>,
    admitted_source: Option<([u8; 32], [u8; 32])>,
}

impl PhaseClockReturnedCiphertext {
    pub fn ciphertext(&self) -> &RNSCiphertext {
        &self.ciphertext
    }
    pub fn error_bound(&self) -> U512 {
        self.error_bound
    }
    pub(crate) fn matches_work_family(&self, family: [u8; 32]) -> bool {
        self.work_family == Some(family)
    }
    pub(crate) fn admitted_source(&self) -> Option<([u8; 32], [u8; 32])> {
        self.admitted_source
    }
}

pub struct PhaseClockReturnEvaluator<'a> {
    boot: &'a RNSFHEContext,
    work: &'a RNSFHEContext,
    exact: ExactMulEvaluator<'a>,
    ratio: usize,
    switch_error_bound: U512,
}

impl<'a> PhaseClockReturnEvaluator<'a> {
    /// The initial kernel requires identical ordered main bases and plaintext
    /// modulus. Modulus reduction, if needed, must precede this return.
    pub fn new(boot: &'a RNSFHEContext, work: &'a RNSFHEContext) -> Nine65Result<Self> {
        if work.n < 2
            || !work.n.is_power_of_two()
            || work.n > 65_536
            || boot.n < work.n
            || !boot.n.is_power_of_two()
            || boot.n > 1 << 20
            || work.t < 3
            || work.t != boot.t
            || work.config.t != work.t
            || boot.config.t != boot.t
            || work.config.n != work.n
            || boot.config.n != boot.n
            || work.config.primes != boot.config.primes
            || work.rns.primes != work.config.primes
            || boot.rns.primes != boot.config.primes
            || work.ntt_engines.len() != work.config.primes.len()
            || boot.ntt_engines.len() != boot.config.primes.len()
            || work.rns.mont_contexts.len() != work.config.primes.len()
            || boot.rns.mont_contexts.len() != boot.config.primes.len()
        {
            return Err(failure(
                "phase-clock return ring, basis or plaintext mismatch",
            ));
        }
        if work.config.primes.is_empty() || product_limbs_u64(&work.config.primes).len() > 4 {
            return Err(failure(
                "phase-clock return main product exceeds 256-bit capacity",
            ));
        }
        // Validate the native work context and its exact switching contract.
        let _galois = RNSGaloisEvaluator::new(work)?;
        let exact = work
            .try_exact_evaluator()
            .map_err(|e| failure(format!("phase-clock return arithmetic capacity: {e:?}")))?;
        let ratio = boot.n / work.n;
        let cert = exact.plan().certificate();
        let switch_error_bound = U512::from_u128(work.n as u128)
            .mul_u128(work.config.eta as u128)
            .mul_u128((1u128 << cert.base_bits) - 1)
            .mul_u128(cert.digits_per_lane.iter().sum::<usize>() as u128)
            .mul_u128(work.t as u128 * ratio as u128);
        let q = U512::product_u64s(&work.config.primes);
        if words(switch_error_bound) > words(q.div_u64(2)) {
            return Err(failure(
                "phase-clock return lacks worst-case switching headroom",
            ));
        }
        Ok(Self {
            boot,
            work,
            exact,
            ratio,
            switch_error_bound,
        })
    }

    /// Exact coefficient-word storage, excluding allocation/metadata overhead.
    pub fn estimated_key_bytes(&self) -> u128 {
        let c = self.exact.plan().certificate();
        self.ratio as u128
            * 2
            * self.work.n as u128
            * self.work.config.primes.len() as u128
            * c.digits_per_lane.iter().sum::<usize>() as u128
            * 8
    }

    /// Ideal-grid error deposited by all D raw switches, independent of the
    /// input and its secret values. This supports public preflight.
    pub fn switching_error_bound(&self) -> U512 {
        self.switch_error_bound
    }

    pub fn output_error_bound(&self, input_bound: U512) -> Nine65Result<U512> {
        let q = U512::product_u64s(&self.work.config.primes);
        // Validate the full-width bound before multiplication/addition can
        // wrap. Q is odd, so V <= floor(Q/2) is exactly 2V < Q.
        if words(input_bound) > words(q.div_u64(2)) {
            return Err(failure("phase-clock return input lacks headroom"));
        }
        let output_bound = input_bound.add(self.switch_error_bound);
        if words(output_bound) > words(q.div_u64(2)) {
            return Err(failure("phase-clock return output lacks headroom"));
        }
        Ok(output_bound)
    }

    pub fn generate_key_with_rng<R: FheRng>(
        &self,
        work_secret: &RNSSecretKey,
        boot_secret: &RNSSecretKey,
        rng: &mut R,
    ) -> Nine65Result<PhaseClockReturnKey> {
        self.generate_key_with_rng_and_limit(work_secret, boot_secret, rng, 512 * 1024 * 1024)
    }

    /// Secret-dependent setup; evaluation receives only the resulting key.
    pub fn generate_key_with_rng_and_limit<R: FheRng>(
        &self,
        work_secret: &RNSSecretKey,
        boot_secret: &RNSSecretKey,
        rng: &mut R,
        max_polynomial_bytes: u128,
    ) -> Nine65Result<PhaseClockReturnKey> {
        if self.estimated_key_bytes() > max_polynomial_bytes {
            return Err(failure(
                "phase-clock return key exceeds explicit storage limit",
            ));
        }
        validate_ternary_secret(self.work, work_secret)?;
        validate_ternary_secret(self.boot, boot_secret)?;
        let switches = (0..self.ratio)
            .map(|offset| {
                let target = Zeroizing::new(self.block(&boot_secret.s, offset));
                self.exact
                    .generate_hybrid_target_key(work_secret, &target, rng)
            })
            .collect();
        Ok(PhaseClockReturnKey {
            switches,
            work_n: self.work.n,
            boot_n: self.boot.n,
            primes: self.work.config.primes.clone(),
            t: self.work.t,
            eta: self.work.config.eta,
            boot_family: None,
            target_source_domain: None,
        })
    }

    /// Return only an immutable polynomial assembled by the matching clock
    /// producer. The family is bound during common key setup, never inferred
    /// from dimensions or a caller-supplied plaintext/noise assertion.
    pub fn apply(
        &self,
        input: &PublicPhaseClockOutput,
        key: &PhaseClockReturnKey,
    ) -> Nine65Result<PhaseClockReturnedCiphertext> {
        if input.n != self.boot.n
            || input.t != self.boot.t
            || input.primes != self.boot.config.primes
            || input.eta != self.boot.config.eta
            || input.embedded_degree != Some(self.work.n)
            || key.boot_family != Some(input.boot_family)
        {
            return Err(failure("phase-clock return producer domain mismatch"));
        }
        if input.admitted_source.is_some() && input.admitted_source != key.target_source_domain {
            return Err(failure("phase-clock return target source domain mismatch"));
        }
        let mut returned = self.apply_raw(input.ciphertext(), input.error_bound(), key)?;
        returned.work_family = key.boot_family;
        returned.admitted_source = input.admitted_source;
        Ok(returned)
    }

    /// The caller must bind this raw input and bound to an immutable admitted
    /// producer. Public evaluation is intentionally supplied by the typed
    /// phase-clock integration rather than this raw helper.
    pub(crate) fn apply_raw(
        &self,
        input: &RNSCiphertext,
        input_bound: U512,
        key: &PhaseClockReturnKey,
    ) -> Nine65Result<PhaseClockReturnedCiphertext> {
        if key.work_n != self.work.n
            || key.boot_n != self.boot.n
            || key.primes != self.work.config.primes
            || key.t != self.work.t
            || key.eta != self.work.config.eta
            || key.switches.len() != self.ratio
        {
            return Err(failure("phase-clock return key domain mismatch"));
        }
        validate_main(self.boot, input)?;
        let output_bound = self.output_error_bound(input_bound)?;
        let mut output = RNSCiphertext {
            c0: self.block(&input.c0, 0),
            c1: RNSPolynomial::zero(&self.work.rns),
            num_primes: self.work.config.primes.len(),
        };
        for r in 0..self.ratio {
            let component = self.block(&input.c1, r);
            // For X=Y^D, only residues r+(D-r)=D contribute to block0.
            // Their product therefore includes X, including its negacyclic
            // sign at the work-ring boundary. The r=0 term has no X.
            let component = if r == 0 {
                component
            } else {
                shift(
                    self.work,
                    &RNSCiphertext {
                        c0: component,
                        c1: RNSPolynomial::zero(&self.work.rns),
                        num_primes: self.work.config.primes.len(),
                    },
                    1,
                )
                .c0
            };
            let target = if r == 0 { 0 } else { self.ratio - r };
            let ordinary = RNSPolynomial {
                n: self.work.n,
                limbs: component
                    .limbs
                    .iter()
                    .enumerate()
                    .map(|(lane, v)| {
                        v.iter()
                            .map(|&x| self.work.rns.mont_contexts[lane].from_montgomery(x))
                            .collect()
                    })
                    .collect(),
            };
            let switched = self
                .exact
                .relinearize_tensor(
                    &ExactTensor3 {
                        e0: RNSPolynomial::zero(&self.work.rns),
                        e1: RNSPolynomial::zero(&self.work.rns),
                        e2: ordinary,
                        num_primes: self.work.config.primes.len(),
                    },
                    &key.switches[target],
                )
                .map_err(|e| failure(format!("phase-clock return switch: {e:?}")))?;
            output = self.work.add(&output, &switched);
        }
        Ok(PhaseClockReturnedCiphertext {
            ciphertext: output,
            error_bound: output_bound,
            work_family: None,
            admitted_source: None,
        })
    }

    fn block(&self, poly: &RNSPolynomial, offset: usize) -> RNSPolynomial {
        RNSPolynomial {
            n: self.work.n,
            limbs: poly
                .limbs
                .iter()
                .map(|v| v.iter().skip(offset).step_by(self.ratio).copied().collect())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
    use crate::entropy::ShadowHarvester;
    use crate::params::{FHEConfig, SecureConfig};

    fn config(n: usize) -> FHEConfig {
        let mut config = SecureConfig::secure_128().into_config();
        config.n = n;
        config.security_bits = 0;
        config
    }

    fn decode(ctx: &RNSFHEContext, ct: &RNSCiphertext, sk: &RNSSecretKey) -> Vec<u64> {
        let ordinary = |poly: &RNSPolynomial, lane: usize| {
            poly.limbs[lane]
                .iter()
                .map(|&v| ctx.rns.mont_contexts[lane].from_montgomery(v))
                .collect::<Vec<_>>()
        };
        let phase: Vec<Vec<u64>> = ctx
            .config
            .primes
            .iter()
            .enumerate()
            .map(|(i, &q)| {
                ctx.ntt_engines[i]
                    .multiply(&ordinary(&ct.c1, i), &ordinary(&sk.s, i))
                    .iter()
                    .zip(ordinary(&ct.c0, i))
                    .map(|(&a, b)| ((a as u128 + b as u128) % q as u128) as u64)
                    .collect()
            })
            .collect();
        let scaler = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
        (0..ctx.n)
            .map(|j| {
                scaler
                    .scale_round(&phase.iter().map(|lane| lane[j]).collect::<Vec<_>>())
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn independent_dense_boot_key_returns_embedded_polynomial_and_supports_square() {
        let work = RNSFHEContext::try_new(&config(8)).unwrap();
        let boot = RNSFHEContext::try_new(&config(256)).unwrap();
        let evaluator = PhaseClockReturnEvaluator::new(&boot, &work).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x52455455524e3332);
        let work_keys = work.generate_keys(&mut rng);
        let boot_keys = boot.generate_keys(&mut rng);
        let key = evaluator
            .generate_key_with_rng(&work_keys.secret_key, &boot_keys.secret_key, &mut rng)
            .unwrap();
        let message = [1, work.t - 2, 3, 4, work.t - 5, 6, 7, work.t - 8];
        let mut input = boot.encrypt(message[0], &boot_keys.public_key, &mut rng);
        for (j, &value) in message.iter().enumerate().skip(1) {
            input = boot.add(
                &input,
                &shift(
                    &boot,
                    &boot.encrypt(value, &boot_keys.public_key, &mut rng),
                    j * 32,
                ),
            );
        }
        let q = U512::product_u64s(&boot.config.primes);
        let beta = (2 * boot.n + 1) as u128 * boot.config.eta as u128;
        let bound = U512::from_u128(
            boot.t as u128 * beta + q.mod_u64(boot.t) as u128 * (boot.t - 1) as u128,
        )
        .mul_u128(work.n as u128);
        let out = evaluator.apply_raw(&input, bound, &key).unwrap();
        assert_eq!(
            decode(&work, out.ciphertext(), &work_keys.secret_key),
            message
        );
        let exact = work.try_exact_evaluator().unwrap();
        let relin = exact.generate_hybrid_gadget_key_with_rng(&work_keys.secret_key, &mut rng);
        let product = exact
            .try_mul_exact(out.ciphertext(), out.ciphertext(), &relin)
            .unwrap();
        let mut expected = vec![0i128; work.n];
        for (i, &a) in message.iter().enumerate() {
            for (j, &b) in message.iter().enumerate() {
                expected[(i + j) % work.n] += if i + j < work.n {
                    a as i128 * b as i128
                } else {
                    -(a as i128 * b as i128)
                };
            }
        }
        assert_eq!(
            decode(&work, &product, &work_keys.secret_key),
            expected
                .iter()
                .map(|&v| v.rem_euclid(work.t as i128) as u64)
                .collect::<Vec<_>>()
        );
        // Merely extracting block0 while retaining the dense boot key's
        // block0 omits all cross-block products and must fail this fixture.
        let naive = RNSCiphertext {
            c0: evaluator.block(&input.c0, 0),
            c1: evaluator.block(&input.c1, 0),
            num_primes: work.config.primes.len(),
        };
        let naive_secret = RNSSecretKey {
            s: evaluator.block(&boot_keys.secret_key.s, 0),
        };
        assert_ne!(decode(&work, &naive, &naive_secret), message);
    }

    #[test]
    fn return_refuses_wrong_domain_metadata_and_impossible_bounds() {
        let work = RNSFHEContext::try_new(&config(8)).unwrap();
        let boot = RNSFHEContext::try_new(&config(32)).unwrap();
        let evaluator = PhaseClockReturnEvaluator::new(&boot, &work).unwrap();
        let mut rng = ShadowHarvester::with_seed(77);
        let wk = work.generate_keys(&mut rng);
        let bk = boot.generate_keys(&mut rng);
        let key = evaluator
            .generate_key_with_rng(&wk.secret_key, &bk.secret_key, &mut rng)
            .unwrap();
        let input = boot.encrypt(17, &bk.public_key, &mut rng);
        assert!(evaluator
            .apply_raw(
                &input,
                U512 {
                    d0: 0,
                    d1: 0,
                    d2: 0,
                    d3: 1u128 << 127
                },
                &key
            )
            .is_err());
        let mut other_config = config(8);
        other_config.eta += 1;
        let other = RNSFHEContext::try_new(&other_config).unwrap();
        let other = PhaseClockReturnEvaluator::new(&boot, &other).unwrap();
        assert!(other.apply_raw(&input, U512::zero(), &key).is_err());
        let mut short = input;
        short.c1.limbs[0].pop();
        assert!(evaluator.apply_raw(&short, U512::zero(), &key).is_err());
        assert!(evaluator
            .generate_key_with_rng_and_limit(&wk.secret_key, &bk.secret_key, &mut rng, 0)
            .is_err());
        let mut changed = config(8);
        changed.primes.swap(0, 1);
        changed.q = changed.primes[0];
        let changed = RNSFHEContext::try_new(&changed).unwrap();
        assert!(PhaseClockReturnEvaluator::new(&boot, &changed).is_err());
    }

    #[test]
    fn admitted_receipt_cannot_return_to_a_different_registered_work_domain() {
        use crate::arithmetic::phase_clock_plan::PhaseClockPlan;
        use crate::ops::public_phase_clock::PublicPhaseClockEvaluator;
        use crate::ops::rns_fhe::{DualRNSCiphertext, DualRNSPoly, DualRNSSecretKey};
        let wc = config(2);
        let work = RNSFHEContext::try_new(&wc).unwrap();
        let boot = RNSFHEContext::try_new(&config(32)).unwrap();
        let plan = PhaseClockPlan::new(
            &wc,
            wc.primes.len(),
            32,
            5,
            U512::product_u64s(&wc.primes).div_u64(128),
            2,
        )
        .unwrap();
        let clock = PublicPhaseClockEvaluator::new(&boot, &plan).unwrap();
        let returning = PhaseClockReturnEvaluator::new(&boot, &work).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x544152474554444f);
        let a = work.generate_keys(&mut rng);
        let b = work.generate_keys(&mut rng);
        let bk = boot.generate_keys(&mut rng);
        let ordinary = |poly: &RNSPolynomial| DualRNSPoly {
            n: work.n,
            anchor: vec![],
            main: poly
                .limbs
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    v.iter()
                        .map(|&x| work.rns.mont_contexts[i].from_montgomery(x))
                        .collect()
                })
                .collect(),
        };
        let clock_key = clock
            .generate_key_with_rng(
                &bk.secret_key,
                &DualRNSSecretKey {
                    s: ordinary(&a.secret_key.s),
                },
                &mut rng,
            )
            .unwrap();
        let encrypted = work.encrypt(7, &a.public_key, &mut rng);
        let source = DualRNSCiphertext {
            c0: ordinary(&encrypted.c0),
            c1: ordinary(&encrypted.c1),
            level: wc.primes.len(),
        };
        let mut input = clock.transduce_polynomial(&source, &clock_key).unwrap();
        let origin = ([1; 32], [2; 32]);
        input.mark_admitted_source(origin.0, origin.1).unwrap();
        let mut wrong = returning
            .generate_key_with_rng(&b.secret_key, &bk.secret_key, &mut rng)
            .unwrap();
        wrong.bind_boot_family(input.boot_family).unwrap();
        wrong.bind_target_source_domain([3; 32], [4; 32]).unwrap();
        assert!(returning.apply(&input, &wrong).is_err());
        assert!(
            wrong.bind_target_source_domain(origin.0, origin.1).is_err(),
            "registered return target cannot be retagged"
        );
        let mut correct = returning
            .generate_key_with_rng(&a.secret_key, &bk.secret_key, &mut rng)
            .unwrap();
        correct.bind_boot_family(input.boot_family).unwrap();
        correct
            .bind_target_source_domain(origin.0, origin.1)
            .unwrap();
        let out = returning.apply(&input, &correct).unwrap();
        assert_eq!(out.admitted_source(), Some(origin));
        assert!(out.matches_work_family(input.boot_family));
        assert_eq!(decode(&work, out.ciphertext(), &a.secret_key), [7, 0]);
    }
}
