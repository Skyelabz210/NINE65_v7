//! Encrypted phase-clock lookup using opaque ternary selector precharges.
//!
//! This kernel evaluates an anti-periodic LUT of public integer rotations.
//! It does not certify that those rotations describe an admitted work phase,
//! return to the work key, or authorize public refresh. Source-history ingress
//! and the complete carry composition remain separate obligations.

use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
use crate::arithmetic::phase_clock_plan::PhaseClockPlan;
use crate::arithmetic::rns::U512;
use crate::arithmetic::RNSPolynomial;
use crate::entropy::FheRng;
use crate::errors::{Nine65Error, Nine65Result};
use crate::ops::exact_mul::{ExactMulEvaluator, ExactTensor3, RNSHybridGadgetKey};
use crate::ops::rns_fhe::{
    DualRNSCiphertext, DualRNSSecretKey, RNSCiphertext, RNSFHEContext, RNSSecretKey,
};
use crate::ops::rns_galois::{shift, RNSGaloisEvaluator, RNSGaloisKey};
use zeroize::Zeroizing;

fn failure(reason: impl Into<String>) -> Nine65Error {
    Nine65Error::BootstrapFailed {
        reason: reason.into(),
    }
}

fn words(v: U512) -> (u128, u128, u128, u128) {
    (v.d3, v.d2, v.d1, v.d0)
}

struct BitKey {
    constant: RNSHybridGadgetKey,
    secret: RNSHybridGadgetKey,
}
struct TritKey {
    plus: BitKey,
    minus: BitKey,
}

/// Contains encrypted controls and Galois keys, never clear source trits.
pub struct PublicPhaseClockKey {
    controls: Vec<TritKey>,
    trace: Vec<RNSGaloisKey>,
    primes: Vec<u64>,
    n: usize,
    t: u64,
    source_primes: Vec<u64>,
    source_weight_bound: usize,
    eta: usize,
}

/// Main-basis ciphertext under the boot key. Its error bound is in ideal-grid
/// units `|t*phase - Q*message|`, not a refreshed work-ciphertext certificate.
pub struct PublicPhaseClockOutput {
    ciphertext: RNSCiphertext,
    error_bound: U512,
}
impl PublicPhaseClockOutput {
    pub fn ciphertext(&self) -> &RNSCiphertext {
        &self.ciphertext
    }
    pub fn error_bound(&self) -> U512 {
        self.error_bound
    }
}

pub struct PublicPhaseClockEvaluator<'a> {
    ctx: &'a RNSFHEContext,
    plan: &'a PhaseClockPlan,
    exact: ExactMulEvaluator<'a>,
    message: Vec<i64>,
    error_bound: U512,
}

impl<'a> PublicPhaseClockEvaluator<'a> {
    /// Public phase transduction of one coefficient under the independent
    /// boot key. The chart must represent the complete carry. Source-history
    /// admission and work-key return are separate, unimplemented stages.
    pub fn transduce_coefficient(
        &self,
        source: &DualRNSCiphertext,
        coefficient: usize,
        key: &PublicPhaseClockKey,
    ) -> Nine65Result<PublicPhaseClockOutput> {
        if self.ctx.t != self.plan.source_plaintext()
            || self.plan.coordinate() <= self.plan.source_weight_bound() as u64 + 1
        {
            return Err(failure(
                "phase transduction needs matching plaintext and a complete carry chart",
            ));
        }
        let carry = self.evaluate_coefficient(source, coefficient, key)?;
        let scale = CanonicalScaleRound::new(self.plan.source_primes(), self.ctx.t)
            .map_err(|e| failure(format!("phase affine projection: {e:?}")))?;
        let n = self.plan.source_n();
        let coarse = |main: &[Vec<u64>], j: usize| -> Nine65Result<i64> {
            let residues: Vec<_> = main.iter().map(|lane| lane[j]).collect();
            let a = scale
                .scale_round(&residues)
                .map_err(|e| failure(format!("phase affine input: {e:?}")))?;
            Ok(if a > self.ctx.t / 2 {
                a as i64 - self.ctx.t as i64
            } else {
                a as i64
            })
        };
        let a0 = coarse(&source.c0.main, coefficient)?;
        let mut norm = a0.unsigned_abs() as u128;
        let mut affine = self.constant(a0);
        for (l, control) in key.controls.iter().enumerate() {
            let a = coarse(&source.c1.main, (coefficient + n - l) % n)?;
            let a = if l > coefficient { -a } else { a };
            norm += a.unsigned_abs() as u128;
            let message = self.constant(a);
            let plus = self.external_product(&message, &control.plus)?;
            let minus = self.external_product(&message, &control.minus)?;
            affine = self.ctx.add(&affine, &self.ctx.sub(&plus, &minus));
        }
        let q = U512::product_u64s(&self.ctx.config.primes);
        let c = self.exact.plan().certificate();
        let switch = U512::from_u128(self.ctx.n as u128)
            .mul_u128(self.ctx.config.eta as u128)
            .mul_u128((1u128 << c.base_bits) - 1)
            .mul_u128(c.digits_per_lane.iter().sum::<usize>() as u128);
        let bound = carry
            .error_bound
            .add(U512::from_u64(q.mod_u64(self.ctx.t)).mul_u128(norm))
            .add(switch.mul_u128(self.ctx.t as u128 * 4 * n as u128));
        if words(bound.mul_u128(2)) >= words(q) {
            return Err(failure("phase affine correction lacks output headroom"));
        }
        Ok(PublicPhaseClockOutput {
            ciphertext: self.ctx.add(&affine, &carry.ciphertext),
            error_bound: bound,
        })
    }

    fn constant(&self, value: i64) -> RNSCiphertext {
        let mut c0 = RNSPolynomial::zero(&self.ctx.rns);
        for (lane, &q) in self.ctx.config.primes.iter().enumerate() {
            let x = (value as i128 * self.ctx.delta_rns[lane] as i128).rem_euclid(q as i128) as u64;
            c0.limbs[lane][0] = self.ctx.rns.mont_contexts[lane].to_montgomery(x);
        }
        RNSCiphertext {
            c0,
            c1: RNSPolynomial::zero(&self.ctx.rns),
            num_primes: self.ctx.config.primes.len(),
        }
    }

    /// Read a chart LUT from actual public source components, retaining the
    /// canonical upper endpoint in both rounding projections. For a source
    /// satisfying the plan's phase-error bound, this emits the centered carry
    /// modulo its odd chart coordinate. This API does not certify that bound.
    pub fn evaluate_coefficient(
        &self,
        source: &DualRNSCiphertext,
        coefficient: usize,
        key: &PublicPhaseClockKey,
    ) -> Nine65Result<PublicPhaseClockOutput> {
        let n = self.plan.source_n();
        let primes = self.plan.source_primes();
        if self.plan.coordinate() % 2 == 0
            || coefficient >= n
            || source.level != self.plan.source_level()
        {
            return Err(failure(
                "source coefficient clock needs an odd chart and matching active level",
            ));
        }
        for poly in [&source.c0, &source.c1] {
            if poly.n != n
                || poly.main.len() != primes.len()
                || poly
                    .main
                    .iter()
                    .zip(primes)
                    .any(|(lane, &q)| lane.len() != n || lane.iter().any(|&v| v >= q))
            {
                return Err(failure("noncanonical source phase-clock component"));
            }
        }
        let size = (2 * self.ctx.n) as u64;
        let fine_target = self
            .plan
            .source_plaintext()
            .checked_mul(size)
            .ok_or_else(|| failure("phase clock fine projection target overflow"))?;
        let coarse = CanonicalScaleRound::new(primes, self.plan.source_plaintext())
            .map_err(|e| failure(format!("phase clock coarse projection: {e:?}")))?;
        let fine = CanonicalScaleRound::new(primes, fine_target)
            .map_err(|e| failure(format!("phase clock fine projection: {e:?}")))?;
        let project = |main: &[Vec<u64>], j: usize| -> Nine65Result<i64> {
            let residues: Vec<_> = main.iter().map(|lane| lane[j]).collect();
            let a = coarse
                .scale_round_unreduced(&residues)
                .map_err(|e| failure(format!("phase clock coarse input: {e:?}")))?
                .value();
            let u = fine
                .scale_round_unreduced(&residues)
                .map_err(|e| failure(format!("phase clock fine input: {e:?}")))?
                .value();
            // For odd m, round(round(x)/m) = round(x/m). Neither component's
            // endpoint may be reduced modulo its target before subtraction.
            let delta = u as i128 - size as i128 * a as i128;
            i64::try_from(
                (delta + self.plan.coordinate() as i128 / 2)
                    .div_euclid(self.plan.coordinate() as i128),
            )
            .map_err(|_| failure("phase clock public rotation overflow"))
        };
        let initial = project(&source.c0.main, coefficient)?;
        let rotations = (0..n)
            .map(|l| {
                let r = project(&source.c1.main, (coefficient + n - l) % n)?;
                Ok(if l > coefficient { -r } else { r })
            })
            .collect::<Nine65Result<Vec<_>>>()?;
        self.evaluate(initial, &rotations, key)
    }

    pub fn new(ctx: &'a RNSFHEContext, plan: &'a PhaseClockPlan) -> Nine65Result<Self> {
        if ctx.n != plan.clock_n() || ctx.t < 3 || ctx.t > i64::MAX as u64 {
            return Err(failure("phase clock ring or plaintext mismatch"));
        }
        let exact = ctx
            .try_exact_evaluator()
            .map_err(|e| failure(format!("phase clock arithmetic: {e:?}")))?;
        // This validates ring/context consistency before any allocation/keygen.
        let _galois = RNSGaloisEvaluator::new(ctx)?;
        let q = U512::product_u64s(&ctx.config.primes);
        let delta = q.div_u64(ctx.t);
        if ctx.delta_rns.len() != ctx.config.primes.len()
            || ctx
                .delta_rns
                .iter()
                .zip(&ctx.config.primes)
                .any(|(&r, &p)| r != delta.mod_u64(p))
        {
            return Err(failure(
                "phase clock context has inconsistent encoding scale",
            ));
        }
        let inv = crate::keys::bootstrap::mod_inverse_u128(ctx.n as u128, ctx.t as u128)
            .ok_or_else(|| failure("phase clock ring degree is not invertible modulo t"))?
            as u64;
        let centered = |v: i128| -> i64 {
            let r = v.rem_euclid(ctx.t as i128);
            if r > (ctx.t / 2) as i128 {
                (r - ctx.t as i128) as i64
            } else {
                r as i64
            }
        };
        let values = plan.values();
        if values.len() != 2 * ctx.n || (0..ctx.n).any(|i| values[i + ctx.n] != -values[i]) {
            return Err(failure("phase clock LUT is not anti-periodic"));
        }
        let mut message = vec![0; ctx.n];
        message[0] = centered(values[0] as i128 * inv as i128);
        for r in 1..ctx.n {
            message[ctx.n - r] = centered(-(values[r] as i128) * inv as i128);
        }
        let max_message = message.iter().map(|v| v.unsigned_abs()).max().unwrap_or(0);
        let cert = exact.plan().certificate();
        let switch = U512::from_u128(ctx.n as u128)
            .mul_u128(ctx.config.eta as u128)
            .mul_u128((1u128 << cert.base_bits) - 1)
            .mul_u128(cert.digits_per_lane.iter().sum::<usize>() as u128);
        // Two switches per bit external product, two bit CMUXs per trit.
        // CMUX preserves one signed permutation of the old error exactly.
        let initial = U512::from_u64(q.mod_u64(ctx.t)).mul_u128(max_message as u128);
        let clock = initial.add(switch.mul_u128(ctx.t as u128 * 4 * plan.source_n() as u128));
        let error_bound = clock
            .mul_u128(ctx.n as u128)
            .add(switch.mul_u128(ctx.t as u128 * (ctx.n - 1) as u128));
        if words(error_bound.mul_u128(2)) >= words(q) {
            return Err(failure(
                "phase clock lookup lacks worst-case decoding headroom",
            ));
        }
        Ok(Self {
            ctx,
            plan,
            exact,
            message,
            error_bound,
        })
    }

    /// Secret-dependent setup. All active source lanes must encode the SAME
    /// ternary polynomial; its actual weight is checked against the plan.
    /// This emits key-dependent material whose joint security needs separate
    /// review; an arithmetic certificate is not a lattice-security admission.
    pub fn generate_key_with_rng<R: FheRng>(
        &self,
        boot_secret: &RNSSecretKey,
        source: &DualRNSSecretKey,
        rng: &mut R,
    ) -> Nine65Result<PublicPhaseClockKey> {
        self.generate_key_with_rng_and_limit(boot_secret, source, rng, 512 * 1024 * 1024)
    }

    /// Exact polynomial-word storage, excluding allocator/metadata overhead.
    pub fn estimated_key_bytes(&self) -> u128 {
        let c = self.exact.plan().certificate();
        (4 * self.plan.source_n() as u128 + self.ctx.n.trailing_zeros() as u128)
            * 2
            * self.ctx.n as u128
            * self.ctx.config.primes.len() as u128
            * c.digits_per_lane.iter().sum::<usize>() as u128
            * 8
    }

    /// Reject oversized direct precharge before randomness or key allocation.
    /// The default wrapper permits at most 512 MiB of polynomial words.
    pub fn generate_key_with_rng_and_limit<R: FheRng>(
        &self,
        boot_secret: &RNSSecretKey,
        source: &DualRNSSecretKey,
        rng: &mut R,
        max_polynomial_bytes: u128,
    ) -> Nine65Result<PublicPhaseClockKey> {
        if self.estimated_key_bytes() > max_polynomial_bytes {
            return Err(failure(
                "phase clock direct precharge exceeds explicit storage limit",
            ));
        }
        let primes = self.plan.source_primes();
        let n = self.plan.source_n();
        if source.s.n != n
            || source.s.main.len() < primes.len()
            || source
                .s
                .main
                .iter()
                .take(primes.len())
                .any(|lane| lane.len() != n)
        {
            return Err(failure("phase clock source key shape mismatch"));
        }
        let mut trits = Zeroizing::new(Vec::with_capacity(n));
        for j in 0..n {
            let v = source.s.main[0][j];
            let sign = if v == 0 {
                0i8
            } else if v == 1 {
                1
            } else if v == primes[0] - 1 {
                -1
            } else {
                return Err(failure("phase clock source key is not ternary"));
            };
            for (lane, &q) in primes.iter().enumerate() {
                let expected = if sign < 0 { q - 1 } else { sign as u64 };
                if source.s.main[lane][j] != expected {
                    return Err(failure("phase clock source key lanes disagree"));
                }
            }
            trits.push(sign);
        }
        let weight = trits.iter().filter(|&&v| v != 0).count();
        if weight > self.plan.source_weight_bound() {
            return Err(failure("phase clock source key exceeds certified weight"));
        }
        let galois = RNSGaloisEvaluator::new(self.ctx)?;
        // The first trace-key call validates the boot ternary secret before
        // any target-key sampling. All setup randomness uses the FHE RNG gate.
        let trace = (0..self.ctx.n.trailing_zeros())
            .map(|k| galois.generate_key_with_rng(boot_secret, 1 + (self.ctx.n >> k) as u64, rng))
            .collect::<Nine65Result<Vec<_>>>()?;
        let bit = |selected: bool, rng: &mut R| {
            let mut one = Zeroizing::new(RNSPolynomial::zero(&self.ctx.rns));
            if selected {
                for lane in 0..self.ctx.config.primes.len() {
                    one.limbs[lane][0] = self.ctx.rns.mont_contexts[lane].to_montgomery(1);
                }
            }
            let target = Zeroizing::new(if selected {
                boot_secret.s.clone()
            } else {
                RNSPolynomial::zero(&self.ctx.rns)
            });
            BitKey {
                constant: self
                    .exact
                    .generate_hybrid_target_key(boot_secret, &one, rng),
                secret: self
                    .exact
                    .generate_hybrid_target_key(boot_secret, &target, rng),
            }
        };
        let controls = trits
            .iter()
            .map(|&v| TritKey {
                plus: bit(v == 1, rng),
                minus: bit(v == -1, rng),
            })
            .collect();
        Ok(PublicPhaseClockKey {
            controls,
            trace,
            primes: self.ctx.config.primes.clone(),
            n: self.ctx.n,
            t: self.ctx.t,
            source_primes: primes.to_vec(),
            source_weight_bound: self.plan.source_weight_bound(),
            eta: self.ctx.config.eta,
        })
    }

    /// Public evaluation of LUT(initial + sum_j rotations[j]*secret[j]).
    /// Every position, including encrypted zero controls, is processed.
    /// Geometry/lookup correctness does not certify the source noise history.
    pub fn evaluate(
        &self,
        initial: i64,
        rotations: &[i64],
        key: &PublicPhaseClockKey,
    ) -> Nine65Result<PublicPhaseClockOutput> {
        if rotations.len() != self.plan.source_n()
            || key.controls.len() != rotations.len()
            || key.n != self.ctx.n
            || key.t != self.ctx.t
            || key.primes != self.ctx.config.primes
            || key.source_primes != self.plan.source_primes()
            || key.source_weight_bound > self.plan.source_weight_bound()
            || key.eta != self.ctx.config.eta
        {
            return Err(failure("phase clock key/input domain mismatch"));
        }
        let mut c0 = RNSPolynomial::zero(&self.ctx.rns);
        for (lane, &q) in self.ctx.config.primes.iter().enumerate() {
            for (j, &m) in self.message.iter().enumerate() {
                let value =
                    (m as i128 * self.ctx.delta_rns[lane] as i128).rem_euclid(q as i128) as u64;
                c0.limbs[lane][j] = self.ctx.rns.mont_contexts[lane].to_montgomery(value);
            }
        }
        let accumulator = RNSCiphertext {
            c0,
            c1: RNSPolynomial::zero(&self.ctx.rns),
            num_primes: self.ctx.config.primes.len(),
        };
        let rotation = |v: i64| v.rem_euclid((2 * self.ctx.n) as i64) as usize;
        let mut acc = shift(self.ctx, &accumulator, rotation(initial));
        for (&amount, control) in rotations.iter().zip(&key.controls) {
            let amount = rotation(amount);
            acc = self.cmux(&acc, amount, &control.plus)?;
            acc = self.cmux(
                &acc,
                (2 * self.ctx.n - amount) % (2 * self.ctx.n),
                &control.minus,
            )?;
        }
        let galois = RNSGaloisEvaluator::new(self.ctx)?;
        for trace in &key.trace {
            acc = self.ctx.add(&acc, &galois.apply(&acc, trace)?);
        }
        Ok(PublicPhaseClockOutput {
            ciphertext: acc,
            error_bound: self.error_bound,
        })
    }

    fn cmux(&self, ct: &RNSCiphertext, amount: usize, key: &BitKey) -> Nine65Result<RNSCiphertext> {
        let difference = self.ctx.sub(&shift(self.ctx, ct, amount), ct);
        Ok(self.ctx.add(ct, &self.external_product(&difference, key)?))
    }

    fn external_product(&self, ct: &RNSCiphertext, key: &BitKey) -> Nine65Result<RNSCiphertext> {
        let switch = |poly: &RNSPolynomial, target: &RNSHybridGadgetKey| {
            let standard = RNSPolynomial {
                n: self.ctx.n,
                limbs: poly
                    .limbs
                    .iter()
                    .enumerate()
                    .map(|(lane, v)| {
                        v.iter()
                            .map(|&x| self.ctx.rns.mont_contexts[lane].from_montgomery(x))
                            .collect()
                    })
                    .collect(),
            };
            self.exact
                .relinearize_tensor(
                    &ExactTensor3 {
                        e0: RNSPolynomial::zero(&self.ctx.rns),
                        e1: RNSPolynomial::zero(&self.ctx.rns),
                        e2: standard,
                        num_primes: self.ctx.config.primes.len(),
                    },
                    target,
                )
                .map_err(|e| failure(format!("phase clock external product: {e:?}")))
        };
        let product = self.ctx.add(
            &switch(&ct.c0, &key.constant)?,
            &switch(&ct.c1, &key.secret)?,
        );
        Ok(product)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
    use crate::entropy::ShadowHarvester;
    use crate::ops::rns_fhe::DualRNSPoly;
    use crate::params::{FHEConfig, SecureConfig};

    struct NoRng;
    impl FheRng for NoRng {
        fn next_u64(&mut self) -> u64 {
            panic!("invalid setup consumed randomness")
        }
        fn uniform(&mut self, _: u64) -> u64 {
            panic!("invalid setup consumed randomness")
        }
        fn ternary(&mut self) -> i64 {
            panic!("invalid setup consumed randomness")
        }
        fn cbd(&mut self, _: usize) -> i64 {
            panic!("invalid setup consumed randomness")
        }
        fn is_secure(&self) -> bool {
            true
        }
    }

    fn source(config: &FHEConfig, trits: &[i8]) -> DualRNSSecretKey {
        DualRNSSecretKey {
            s: DualRNSPoly {
                n: config.n,
                main: config
                    .primes
                    .iter()
                    .map(|&q| {
                        trits
                            .iter()
                            .map(|&v| if v < 0 { q - 1 } else { v as u64 })
                            .collect()
                    })
                    .collect(),
                anchor: vec![],
            },
        }
    }
    fn config() -> FHEConfig {
        let mut c = SecureConfig::secure_128().into_config();
        c.n = 8;
        c.security_bits = 0;
        c
    }
    fn decode_all(ctx: &RNSFHEContext, out: &RNSCiphertext, sk: &RNSSecretKey) -> Vec<u64> {
        let phase: Vec<Vec<u64>> = ctx
            .config
            .primes
            .iter()
            .enumerate()
            .map(|(i, &q)| {
                let ordinary = |p: &RNSPolynomial| {
                    p.limbs[i]
                        .iter()
                        .map(|&v| ctx.rns.mont_contexts[i].from_montgomery(v))
                        .collect::<Vec<_>>()
                };
                ctx.ntt_engines[i]
                    .multiply(&ordinary(&out.c1), &ordinary(&sk.s))
                    .iter()
                    .zip(ordinary(&out.c0))
                    .map(|(&a, b)| ((a as u128 + b as u128) % q as u128) as u64)
                    .collect()
            })
            .collect();
        let scale = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
        (0..ctx.n)
            .map(|j| {
                let residues: Vec<_> = phase.iter().map(|lane| lane[j]).collect();
                scale.scale_round(&residues).unwrap()
            })
            .collect()
    }

    fn observed_scaled_error(
        ctx: &RNSFHEContext,
        ct: &RNSCiphertext,
        sk: &RNSSecretKey,
        message: &[u64],
    ) -> u128 {
        use crate::arithmetic::rns::{crt_reconstruct_u256, U256};
        let q = U256::product_u64s(&ctx.config.primes);
        let period = q.mul_u64(ctx.t);
        let ordinary = |poly: &RNSPolynomial, i: usize| {
            poly.limbs[i]
                .iter()
                .map(|&v| ctx.rns.mont_contexts[i].from_montgomery(v))
                .collect::<Vec<_>>()
        };
        let phases: Vec<Vec<u64>> = ctx
            .config
            .primes
            .iter()
            .enumerate()
            .map(|(i, &p)| {
                ctx.ntt_engines[i]
                    .multiply(&ordinary(&ct.c1, i), &ordinary(&sk.s, i))
                    .iter()
                    .zip(ordinary(&ct.c0, i))
                    .map(|(&a, b)| ((a as u128 + b as u128) % p as u128) as u64)
                    .collect()
            })
            .collect();
        (0..ctx.n)
            .map(|j| {
                let residues: Vec<_> = phases.iter().map(|lane| lane[j]).collect();
                let scaled = crt_reconstruct_u256(&residues, &ctx.config.primes).mul_u64(ctx.t);
                let ideal = q.mul_u64(message[j]);
                let delta = if scaled.gt(ideal) {
                    scaled.sub(ideal)
                } else {
                    ideal.sub(scaled)
                };
                let other = period.sub(delta);
                let delta = if delta.gt(other) { other } else { delta };
                assert_eq!(delta.hi, 0, "fixture error must fit observer's u128");
                delta.lo
            })
            .max()
            .unwrap()
    }

    #[test]
    fn encrypted_lookup_uses_opaque_signed_controls_and_erases_nonconstant_terms() {
        let source_config = config();
        let q = U512::product_u64s(&source_config.primes);
        let plan = PhaseClockPlan::new(
            &source_config,
            source_config.primes.len(),
            128,
            9,
            q.div_u64(128),
            2,
        )
        .unwrap();
        let mut outer = source_config.clone();
        outer.n = 128;
        let ctx = RNSFHEContext::try_new(&outer).unwrap();
        let evaluator = PublicPhaseClockEvaluator::new(&ctx, &plan).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x5048415345434c4b);
        let boot = ctx.generate_keys(&mut rng);
        let trits = [0, 1, 0, 0, 0, 0, -1, 0];
        let key = evaluator
            .generate_key_with_rng(&boot.secret_key, &source(&source_config, &trits), &mut rng)
            .unwrap();
        // The evaluator receives only integer rotations and encrypted keys.
        // Independent scalar observation is confined to this test observer.
        for (initial, rotations) in [
            (0, [0, 15, 0, 0, 0, 0, -15, 0]),
            (-80, [3, -25, 19, 0, 0, -8, 14, 7]),
            (i64::MIN, [i64::MAX, 0, 0, 1, 0, 0, -35, 0]),
        ] {
            let expected_rotation = (initial as i128
                + rotations
                    .iter()
                    .zip(trits)
                    .map(|(&r, s)| r as i128 * s as i128)
                    .sum::<i128>())
            .rem_euclid(256) as i64;
            let expected = plan.lookup(expected_rotation).rem_euclid(ctx.t as i64) as u64;
            let out = evaluator.evaluate(initial, &rotations, &key).unwrap();
            let got = decode_all(&ctx, out.ciphertext(), &boot.secret_key);
            assert_eq!(got[0], expected);
            assert!(got[1..].iter().all(|&v| v == 0));
            assert!(words(out.error_bound().mul_u128(2)) < words(q));
        }
        // A genuinely nonlinear carry residue: rotation0 reads0, while the
        // encrypted signed controls move the accumulator into a nonzero cell.
        let out = evaluator
            .evaluate(0, &[0, 15, 0, 0, 0, 0, -15, 0], &key)
            .unwrap();
        assert_ne!(
            decode_all(&ctx, out.ciphertext(), &boot.secret_key)[0],
            plan.lookup(0) as u64
        );
    }

    #[test]
    fn malformed_or_understated_source_keys_are_refused_before_rng() {
        let c = config();
        let q = U512::product_u64s(&c.primes);
        let plan = PhaseClockPlan::new(&c, c.primes.len(), 128, 9, q.div_u64(128), 1).unwrap();
        let mut outer = c.clone();
        outer.n = 128;
        let ctx = RNSFHEContext::try_new(&outer).unwrap();
        let evaluator = PublicPhaseClockEvaluator::new(&ctx, &plan).unwrap();
        let mut rng = ShadowHarvester::with_seed(17);
        let boot = ctx.generate_keys(&mut rng);
        let mut bad = source(&c, &[1, -1, 0, 0, 0, 0, 0, 0]);
        let mut rng = NoRng;
        assert!(evaluator
            .generate_key_with_rng(&boot.secret_key, &bad, &mut rng)
            .is_err());
        bad.s.main[1][0] = 0;
        assert!(evaluator
            .generate_key_with_rng(&boot.secret_key, &bad, &mut rng)
            .is_err());
        bad.s.main[0].pop();
        assert!(evaluator
            .generate_key_with_rng(&boot.secret_key, &bad, &mut rng)
            .is_err());
    }

    #[test]
    fn actual_ciphertext_carries_are_read_publicly_in_every_coefficient() {
        use crate::arithmetic::rns::{crt_reconstruct_u256, U256};
        let c = config();
        let q = c.primes.iter().map(|&p| p as u128).product::<u128>();
        let work = RNSFHEContext::try_new(&c).unwrap();
        let plan = PhaseClockPlan::new(
            &c,
            c.primes.len(),
            256,
            17,
            U512::from_u128(q).div_u64(128),
            c.n,
        )
        .unwrap();
        let mut outer = c.clone();
        outer.n = 256;
        let ctx = RNSFHEContext::try_new(&outer).unwrap();
        let evaluator = PublicPhaseClockEvaluator::new(&ctx, &plan).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x4c49564543415252);
        let work_keys = work.generate_keys_dual(&mut rng);
        let boot = ctx.generate_keys(&mut rng);
        let mut input = work.encrypt_dual(c.t - 5, &work_keys.public_key, &mut rng);
        let relin = evaluator
            .exact
            .generate_hybrid_gadget_key_with_rng(&boot.secret_key, &mut rng);
        // Public stress term; source ideal-grid error remains below Q/128.
        // Both main and anchor lanes receive the same integer perturbation.
        let load = q / (512 * c.t as u128);
        for (lanes, primes) in [
            (&mut input.c0.main, &c.primes),
            (&mut input.c0.anchor, &work.dual_rns.anchor.primes),
        ] {
            for (lane, &p) in lanes.iter_mut().zip(primes) {
                for (j, value) in lane.iter_mut().enumerate() {
                    let v = (load % p as u128) as u64;
                    let v = if j % 2 == 0 || v == 0 { v } else { p - v };
                    *value = ((*value as u128 + v as u128) % p as u128) as u64;
                }
            }
        }
        assert_eq!(work.decrypt_dual(&input, &work_keys.secret_key), c.t - 5);
        let key = evaluator
            .generate_key_with_rng(&boot.secret_key, &work_keys.secret_key, &mut rng)
            .unwrap();
        let residual = |main: &[Vec<u64>], j: usize| -> i128 {
            let residues: Vec<_> = main.iter().map(|lane| lane[j]).collect();
            let x = crt_reconstruct_u256(&residues, &c.primes);
            let r = x.mul_u64(c.t).rem_u256(U256::from_u128(q));
            assert_eq!(r.hi, 0);
            if r.lo > q / 2 {
                r.lo as i128 - q as i128
            } else {
                r.lo as i128
            }
        };
        let trits: Vec<i128> = work_keys.secret_key.s.main[0]
            .iter()
            .map(|&x| {
                if x == 0 {
                    0
                } else if x == 1 {
                    1
                } else {
                    -1
                }
            })
            .collect();
        let mut nonzero = 0;
        for j in 0..c.n {
            let mut s = residual(&input.c0.main, j);
            for (l, &trit) in trits.iter().enumerate() {
                let term = residual(&input.c1.main, (j + c.n - l) % c.n) * trit;
                s += if l > j { -term } else { term };
            }
            let carry = (s + q as i128 / 2).div_euclid(q as i128);
            assert!(
                words(U512::from_u128((s - q as i128 * carry).unsigned_abs()))
                    <= words(plan.source_error_bound()),
                "fixture exceeds source phase allowance"
            );
            nonzero += usize::from(carry != 0);
            let out = evaluator.evaluate_coefficient(&input, j, &key).unwrap();
            let got = decode_all(&ctx, out.ciphertext(), &boot.secret_key);
            assert_eq!(
                got[0],
                carry.rem_euclid(c.t as i128) as u64,
                "source coefficient {j}"
            );
            assert!(got[1..].iter().all(|&v| v == 0));
            let fresh = evaluator.transduce_coefficient(&input, j, &key).unwrap();
            let message = decode_all(&ctx, fresh.ciphertext(), &boot.secret_key);
            assert_eq!(message[0], if j == 0 { c.t - 5 } else { 0 });
            assert!(message[1..].iter().all(|&v| v == 0));
            let observed =
                observed_scaled_error(&ctx, fresh.ciphertext(), &boot.secret_key, &message);
            assert!(words(U512::from_u128(observed)) <= words(fresh.error_bound()));
            assert!(
                words(fresh.error_bound()) < words(U512::from_u128(q / 1024)),
                "transduced error bound must be below the injected source error"
            );
            let squared = evaluator
                .exact
                .try_mul_exact(fresh.ciphertext(), fresh.ciphertext(), &relin)
                .unwrap();
            let product = decode_all(&ctx, &squared, &boot.secret_key);
            assert_eq!(product[0], message[0] * message[0] % c.t);
            assert!(product[1..].iter().all(|&v| v == 0));
        }
        assert!(nonzero > 0, "fixture must exercise an actual hidden carry");
        // A same-basis key generated at a different eta cannot borrow this
        // evaluator's smaller deterministic noise certificate.
        let mut other = outer.clone();
        other.eta = 1;
        let other = RNSFHEContext::try_new(&other).unwrap();
        let other_evaluator = PublicPhaseClockEvaluator::new(&other, &plan).unwrap();
        assert!(other_evaluator.evaluate(0, &[0; 8], &key).is_err());
        assert!(evaluator
            .generate_key_with_rng_and_limit(&boot.secret_key, &work_keys.secret_key, &mut rng, 0)
            .is_err());
    }

    #[test]
    fn poisoned_encoding_metadata_is_refused_at_construction() {
        let c = config();
        let q = U512::product_u64s(&c.primes);
        let plan = PhaseClockPlan::new(&c, c.primes.len(), 128, 9, q.div_u64(128), 2).unwrap();
        let mut outer = c;
        outer.n = 128;
        let mut ctx = RNSFHEContext::try_new(&outer).unwrap();
        ctx.delta_rns[0] ^= 1;
        assert!(PublicPhaseClockEvaluator::new(&ctx, &plan).is_err());
        ctx.delta_rns.clear();
        assert!(PublicPhaseClockEvaluator::new(&ctx, &plan).is_err());
    }
}
