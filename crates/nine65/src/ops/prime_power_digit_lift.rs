//! Exact public canonical section, with admission for every arithmetic node.
//!
//! For prime p, F(X)=X+prod_{a=0}^{p-1}(X-a) is x mod p in [0,p)
//! modulo p^2. Wilson's theorem makes F'(a)=0 mod p. This is a genuine
//! encrypted producer, not a clear-digit oracle. It projects coefficients
//! using native Galois keys on a directly preconditioned phase view, then
//! evaluates F on each constant projection.
//! The current 65537/four-prime tuple is refused by the noise certificate.

use super::*;
use crate::ops::rns_fhe::exact_mul::{ExactMulEvaluator, RNSHybridGadgetKey};
use crate::ops::rns_fhe::RNSSecretKey;
use crate::ops::rns_galois::{
    shift, validate_main, validate_ternary_secret, RNSGaloisEvaluator, RNSGaloisKey,
};
use std::collections::BTreeMap;

fn bits(v: U512) -> u32 {
    for (offset, limb) in [(384, v.d3), (256, v.d2), (128, v.d1), (0, v.d0)] {
        if limb != 0 {
            return offset + 128 - limb.leading_zeros();
        }
    }
    0
}

fn pow2(exponent: u32) -> Nine65Result<U512> {
    if exponent >= 512 {
        return Err(phase_failure(
            "canonical-lift public bound exceeds 512-bit capacity",
        ));
    }
    let mut v = U512::zero();
    let limb = match exponent / 128 {
        0 => &mut v.d0,
        1 => &mut v.d1,
        2 => &mut v.d2,
        _ => &mut v.d3,
    };
    *limb = 1u128 << (exponent % 128);
    Ok(v)
}

pub(super) fn centered_inverse(n: usize, p: u64) -> Nine65Result<i64> {
    let (mut r0, mut r1) = (p as i128, (n as u128 % p as u128) as i128);
    let (mut s0, mut s1) = (0i128, 1i128);
    while r1 != 0 {
        let q = r0 / r1;
        (r0, r1) = (r1, r0 - q * r1);
        (s0, s1) = (s1, s0 - q * s1);
    }
    if r0 != 1 {
        return Err(phase_failure(
            "canonical coefficient projection needs invertible N modulo p^2",
        ));
    }
    let inv = s0.rem_euclid(p as i128);
    Ok(if inv > p as i128 / 2 {
        (inv - p as i128) as i64
    } else {
        inv as i64
    })
}

#[derive(Debug, Clone)]
pub struct CanonicalLowDigitLiftCertificate {
    pub polynomial_degree: u64,
    pub multiplicative_depth: u32,
    pub automorphism_count: u128,
    pub ciphertext_multiplication_count: u128,
    pub key_main_word_count: u128,
    pub trace_error_bound: U512,
    /// Diagnostic for tracing an ordinary high view and then normalizing it.
    /// The evaluator uses the directly preconditioned view instead.
    pub unconditioned_projection_error_bound: U512,
    pub projection_error_bound: U512,
    pub coefficient_error_bound: U512,
    pub lifted_error_bound: U512,
    pub half_delta: U512,
}

struct NoisePlan {
    n: u128,
    p: u64,
    q_bits: u32,
    half: U512,
    switch_error: U512,
}

impl NoisePlan {
    fn admit(&self, error: U512, stage: &str) -> Nine65Result<U512> {
        if words(error) >= words(self.half) {
            return Err(phase_failure(format!("canonical low-digit lift {stage} needs {} error bits; high encoding has {} half-Delta bits", bits(error), bits(self.half))));
        }
        Ok(error)
    }

    // For centered component lifts Z=(Q/P)*m+E+Q*K, |K_j|<=N/2+1.
    // Both operands here have CONSTANT plaintext. The other coefficients
    // may still have error and winding. Keep their P*(K_A*E_B+K_B*E_A)
    // terms: treating a ciphertext product as only m_A*E_B+m_B*E_A is unsound.
    fn multiply(&self, a: U512, b: U512) -> Nine65Result<U512> {
        let k = self.n / 2 + 1;
        let np = self
            .n
            .checked_mul(self.p as u128)
            .ok_or_else(|| phase_failure("canonical-lift bound overflow"))?;
        let factor = np
            .checked_mul(k)
            .and_then(|v| v.checked_add((self.p - 1) as u128 / 2))
            .ok_or_else(|| phase_failure("canonical-lift bound overflow"))?;
        let linear = a.add(b).mul_u128(factor);
        // Conservative ceiling of N*P*a*b/Q using public bit lengths.
        // This avoids overflowing a fixed-width numerator before division.
        let numerator_bits = bits(a) + bits(b) + (128 - np.leading_zeros());
        let exponent = numerator_bits.saturating_sub(self.q_bits - 1);
        let quadratic = if a == U512::zero() || b == U512::zero() {
            U512::zero()
        } else {
            pow2(exponent)?
        };
        let rounding = self
            .n
            .checked_mul(self.n)
            .and_then(|v| v.checked_add(self.n + 1))
            .map(|v| v.div_ceil(2))
            .ok_or_else(|| phase_failure("canonical-lift rounding bound overflow"))?;
        self.admit(
            linear
                .add(quadratic)
                .add(U512::from_u128(rounding))
                .add(self.switch_error),
            "polynomial multiply",
        )
    }

    fn product(
        &self,
        count: u64,
        leaf: U512,
        cache: &mut BTreeMap<u64, U512>,
    ) -> Nine65Result<U512> {
        if let Some(&bound) = cache.get(&count) {
            return Ok(bound);
        }
        let bound = if count == 1 {
            self.admit(leaf, "affine factor")?
        } else {
            let left = self.product(count / 2, leaf, cache)?;
            let right = self.product(count - count / 2, leaf, cache)?;
            self.multiply(left, right)?
        };
        cache.insert(count, bound);
        Ok(bound)
    }
}

pub struct CanonicalLowDigitLiftKey {
    family: [u64; 2],
    n: usize,
    p: u64,
    primes: Vec<u64>,
    trace: Vec<RNSGaloisKey>,
    relin: RNSHybridGadgetKey,
}

pub struct CanonicalLowDigitLiftEvaluator<'a> {
    ctx: &'a RNSFHEContext,
    exact: ExactMulEvaluator<'a>,
    base: u64,
    input_bound: U512,
    inverse_n: i64,
    certificate: CanonicalLowDigitLiftCertificate,
}

impl<'a> CanonicalLowDigitLiftEvaluator<'a> {
    pub fn new(evaluator: &'a PrimePowerPhaseEvaluator<'_>) -> Nine65Result<Self> {
        Self::from_context(
            evaluator.high.ctx,
            evaluator.work.t,
            evaluator.high.certificate().phase_error_bound,
        )
    }

    // Private arithmetic constructor. Production comes only from the admitted
    // paired evaluator; toy tests use an explicit insecure small ring here.
    fn from_context(ctx: &'a RNSFHEContext, base: u64, input_bound: U512) -> Nine65Result<Self> {
        if ctx.n < 2
            || !ctx.n.is_power_of_two()
            || !is_prime(base)
            || base.checked_mul(base) != Some(ctx.t)
            || ctx.t > i64::MAX as u64
        {
            return Err(phase_failure(
                "canonical digit lift needs prime p, plaintext p^2, and a power-of-two ring",
            ));
        }
        let exact = ctx
            .try_exact_evaluator()
            .map_err(|e| phase_failure(format!("canonical-lift multiply capacity: {e:?}")))?;
        let arithmetic = exact.plan().certificate();
        let q = U512::product_u64s(&ctx.config.primes);
        let half = q.div_u64(ctx.t).div_u64(2);
        let n = ctx.n as u128;
        let switch_factor = n
            .checked_mul(ctx.config.eta as u128)
            .and_then(|v| v.checked_mul((1u128 << arithmetic.base_bits) - 1))
            .and_then(|v| v.checked_mul(arithmetic.digits_per_lane.iter().sum::<usize>() as u128))
            .ok_or_else(|| phase_failure("canonical-lift switch bound overflow"))?;
        let noise = NoisePlan {
            n,
            p: ctx.t,
            q_bits: bits(q),
            half,
            switch_error: U512::from_u128(switch_factor),
        };
        noise.admit(input_bound, "input")?;
        let trace_error_bound = input_bound
            .mul_u128(n)
            .add(noise.switch_error.mul_u128(n - 1));
        let inverse_n = centered_inverse(ctx.n, ctx.t)?;
        let unconditioned_projection_error_bound =
            trace_error_bound.mul_u128(inverse_n.unsigned_abs() as u128);
        let projection_error_bound = noise.admit(trace_error_bound, "coefficient projection")?;
        let remainder = q.mod_u64(ctx.t) as u128;
        let constant_error = (remainder * (base - 1) as u128).div_ceil(ctx.t as u128);
        let product = noise.product(
            base,
            projection_error_bound.add(U512::from_u128(constant_error)),
            &mut BTreeMap::new(),
        )?;
        let coefficient_error_bound =
            noise.admit(projection_error_bound.add(product), "canonical section")?;
        let lifted_error_bound = noise.admit(
            coefficient_error_bound.mul_u128(n),
            "coefficient reassembly",
        )?;
        let log_n = ctx.n.trailing_zeros();
        let certificate = CanonicalLowDigitLiftCertificate {
            polynomial_degree: base,
            multiplicative_depth: 64 - (base - 1).leading_zeros(),
            automorphism_count: n * log_n as u128,
            ciphertext_multiplication_count: n * (base - 1) as u128,
            key_main_word_count: (log_n as u128 + 1)
                * arithmetic.digits_per_lane.iter().sum::<usize>() as u128
                * 2
                * ctx.config.primes.len() as u128
                * n,
            trace_error_bound,
            unconditioned_projection_error_bound,
            projection_error_bound,
            coefficient_error_bound,
            lifted_error_bound,
            half_delta: half,
        };
        Ok(Self {
            ctx,
            exact,
            base,
            input_bound,
            inverse_n,
            certificate,
        })
    }

    pub fn certificate(&self) -> &CanonicalLowDigitLiftCertificate {
        &self.certificate
    }

    pub fn generate_keys_secure(
        &self,
        keys: &PrimePowerBootstrapKeySet,
    ) -> Nine65Result<CanonicalLowDigitLiftKey> {
        self.generate_keys_with_rng(keys, &mut SecureRng::new())
    }

    pub fn generate_keys_with_rng<R: FheRng>(
        &self,
        keys: &PrimePowerBootstrapKeySet,
        rng: &mut R,
    ) -> Nine65Result<CanonicalLowDigitLiftKey> {
        let key = &keys.bootstrap_key;
        let sk = &keys.boot_keys.secret_key;
        if key.high.n != self.ctx.n
            || key.high.primes != self.ctx.config.primes
            || key.high.plaintext_modulus != self.ctx.t
            || sk.s.n != self.ctx.n
            || sk.s.main.len() != self.ctx.config.primes.len()
            || sk.s.main.iter().any(|lane| lane.len() != self.ctx.n)
            || self
                .ctx
                .config
                .primes
                .iter()
                .zip(&sk.s.main)
                .any(|(&q, lane)| lane.iter().any(|&v| v >= q))
        {
            return Err(Nine65Error::KeyGenFailed {
                reason: "canonical-lift boot key regime mismatch".into(),
            });
        }
        let native = RNSSecretKey {
            s: RNSPolynomial {
                limbs: self
                    .ctx
                    .rns
                    .mont_contexts
                    .iter()
                    .zip(&sk.s.main)
                    .map(|(mont, lane)| lane.iter().map(|&v| mont.to_montgomery(v)).collect())
                    .collect(),
                n: self.ctx.n,
            },
        };
        self.keys_for_secret(&native, key.family, rng)
    }

    fn keys_for_secret<R: FheRng>(
        &self,
        sk: &RNSSecretKey,
        family: [u64; 2],
        rng: &mut R,
    ) -> Nine65Result<CanonicalLowDigitLiftKey> {
        validate_ternary_secret(self.ctx, sk)?;
        let galois = RNSGaloisEvaluator::new(self.ctx)?;
        let mut trace = Vec::new();
        let mut stride = self.ctx.n;
        while stride > 1 {
            trace.push(galois.generate_key_with_rng(sk, stride as u64 + 1, rng)?);
            stride /= 2;
        }
        let relin = self.exact.generate_hybrid_gadget_key_with_rng(sk, rng);
        Ok(CanonicalLowDigitLiftKey {
            family,
            n: self.ctx.n,
            p: self.ctx.t,
            primes: self.ctx.config.primes.clone(),
            trace,
            relin,
        })
    }

    fn add(&self, a: &RNSCiphertext, b: &RNSCiphertext) -> RNSCiphertext {
        RNSCiphertext {
            c0: a.c0.add(&b.c0, &self.ctx.rns),
            c1: a.c1.add(&b.c1, &self.ctx.rns),
            num_primes: a.num_primes,
        }
    }

    fn product(
        &self,
        x: &RNSCiphertext,
        start: u64,
        count: u64,
        key: &CanonicalLowDigitLiftKey,
    ) -> Nine65Result<RNSCiphertext> {
        if count == 1 {
            let mut out = x.clone();
            for (lane, &q) in self.ctx.config.primes.iter().enumerate() {
                let encoded = (self.ctx.delta_rns[lane] as u128 * start as u128 % q as u128) as u64;
                let encoded = self.ctx.rns.mont_contexts[lane].to_montgomery(encoded);
                out.c0.limbs[lane][0] = ((out.c0.limbs[lane][0] as u128 + q as u128
                    - encoded as u128)
                    % q as u128) as u64;
            }
            return Ok(out);
        }
        let left = self.product(x, start, count / 2, key)?;
        let right = self.product(x, start + count / 2, count - count / 2, key)?;
        self.exact
            .try_mul_exact(&left, &right, &key.relin)
            .map_err(|e| phase_failure(format!("canonical section product: {e:?}")))
    }

    /// Derive canonical low digits through public ciphertext arithmetic.
    /// No secret-key argument, decryption, CRT fusion, or clear digit exists.
    pub fn evaluate(
        &self,
        phase: &PrimePowerLiftedPhase,
        key: &CanonicalLowDigitLiftKey,
    ) -> Nine65Result<CanonicalLowDigitLift> {
        if key.family != phase.family
            || key.n != self.ctx.n
            || key.p != self.ctx.t
            || key.primes != self.ctx.config.primes
            || phase.primes != key.primes
            || phase.n != key.n
            || phase.base != self.base
            || phase.trace_inverse != self.inverse_n
            || words(phase.noise.projection_input_error_bound) > words(self.input_bound)
        {
            return Err(Nine65Error::BootstrapConfigMismatch {
                reason: "canonical-lift phase/key lineage or encoding mismatch".into(),
            });
        }
        validate_main(self.ctx, &phase.trace_input)?;
        let galois = RNSGaloisEvaluator::new(self.ctx)?;
        let mut output = RNSCiphertext {
            c0: RNSPolynomial {
                limbs: vec![vec![0; self.ctx.n]; key.primes.len()],
                n: self.ctx.n,
            },
            c1: RNSPolynomial {
                limbs: vec![vec![0; self.ctx.n]; key.primes.len()],
                n: self.ctx.n,
            },
            num_primes: key.primes.len(),
        };
        for j in 0..self.ctx.n {
            let mut coefficient = shift(
                self.ctx,
                &phase.trace_input,
                if j == 0 { 0 } else { 2 * self.ctx.n - j },
            );
            for trace_key in &key.trace {
                let transformed = galois.apply(&coefficient, trace_key)?;
                coefficient = self.add(&coefficient, &transformed);
            }
            let product = self.product(&coefficient, 0, self.base, key)?;
            let digit = self.add(&coefficient, &product);
            output = self.add(&output, &shift(self.ctx, &digit, j));
        }
        Ok(CanonicalLowDigitLift {
            encrypted: output,
            lineage: phase.lineage.clone(),
            family: phase.family,
            primes: phase.primes.clone(),
            n: phase.n,
            base: phase.base,
            error_bound: self.certificate.lifted_error_bound,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
    use crate::entropy::ShadowHarvester;
    use crate::ops::rns_fhe::{RNSKeySet, RNSPublicKey};
    use crate::params::SecureConfig;

    fn inverse(mut a: i128, mut b: i128) -> i128 {
        let modulus = b;
        let (mut x, mut y) = (1i128, 0i128);
        while b != 0 {
            let q = a / b;
            (a, b) = (b, a - q * b);
            (x, y) = (y, x - q * y);
        }
        assert_eq!(a, 1);
        x.rem_euclid(modulus)
    }

    // Independent CRT appears only in this verification oracle, never in
    // the producer. Q fits u128; Q*P fits u128 in the toy noise checks.
    fn phase_oracle(ctx: &RNSFHEContext, ct: &RNSCiphertext, sk: &RNSSecretKey) -> Vec<u128> {
        let residues: Vec<Vec<u64>> = ctx
            .config
            .primes
            .iter()
            .enumerate()
            .map(|(lane, &q)| {
                let mont = &ctx.rns.mont_contexts[lane];
                let c1: Vec<u64> = ct.c1.limbs[lane]
                    .iter()
                    .map(|&v| mont.from_montgomery(v))
                    .collect();
                let s: Vec<u64> = sk.s.limbs[lane]
                    .iter()
                    .map(|&v| mont.from_montgomery(v))
                    .collect();
                let product = ctx.ntt_engines[lane].multiply(&c1, &s);
                ct.c0.limbs[lane]
                    .iter()
                    .zip(product)
                    .map(|(&v, w)| {
                        ((mont.from_montgomery(v) as u128 + w as u128) % q as u128) as u64
                    })
                    .collect()
            })
            .collect();
        (0..ctx.n)
            .map(|j| {
                let (mut x, mut prefix) = (0u128, 1u128);
                for (lane, &q) in ctx.config.primes.iter().enumerate() {
                    let d = (residues[lane][j] as u128 + q as u128 - x % q as u128) % q as u128;
                    let inv = inverse((prefix % q as u128) as i128, q as i128) as u128;
                    x += prefix * (d * inv % q as u128);
                    prefix *= q as u128;
                }
                x
            })
            .collect()
    }

    fn decode_all(ctx: &RNSFHEContext, ct: &RNSCiphertext, sk: &RNSSecretKey) -> Vec<u64> {
        let decoder = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
        phase_oracle(ctx, ct, sk)
            .into_iter()
            .map(|x| {
                decoder
                    .scale_round(
                        &ctx.config
                            .primes
                            .iter()
                            .map(|&q| (x % q as u128) as u64)
                            .collect::<Vec<_>>(),
                    )
                    .unwrap()
            })
            .collect()
    }

    fn encode(
        ctx: &RNSFHEContext,
        message: &[u64],
        pk: &RNSPublicKey,
        rng: &mut ShadowHarvester,
    ) -> RNSCiphertext {
        let mut ct = ctx.encrypt(0, pk, rng);
        for (lane, &q) in ctx.config.primes.iter().enumerate() {
            let mont = &ctx.rns.mont_contexts[lane];
            for (j, &m) in message.iter().enumerate() {
                let signed = if m > ctx.t / 2 {
                    m as i128 - ctx.t as i128
                } else {
                    m as i128
                };
                let encoded = (signed.rem_euclid(q as i128) as u128 * ctx.delta_rns[lane] as u128
                    % q as u128) as u64;
                let encoded = mont.to_montgomery(encoded);
                ct.c0.limbs[lane][j] =
                    ((ct.c0.limbs[lane][j] as u128 + encoded as u128) % q as u128) as u64;
            }
        }
        ct
    }

    fn fixture(
        high: &RNSFHEContext,
        low: &RNSFHEContext,
        x: &[u64],
        keys: &RNSKeySet,
        rng: &mut ShadowHarvester,
    ) -> PrimePowerLiftedPhase {
        let r: Vec<u64> = x.iter().map(|&v| v % low.t).collect();
        let mut hash = Sha256::new();
        hash.update(b"test-only-prime-power-fixture");
        for &v in x {
            hash.update(v.to_le_bytes());
        }
        let bound = U512::from_u128(
            high.config.eta as u128 * (2 * high.n as u128 + 1)
                + (U512::product_u64s(&high.config.primes).mod_u64(high.t) as u128).div_ceil(2),
        );
        let trace_inverse = centered_inverse(high.n, high.t).unwrap();
        let inverse_residue = (trace_inverse as i128).rem_euclid(high.t as i128) as u128;
        let trace_message: Vec<u64> = x
            .iter()
            .map(|&v| (v as u128 * inverse_residue % high.t as u128) as u64)
            .collect();
        PrimePowerLiftedPhase {
            high: encode(high, x, &keys.public_key, rng),
            low: encode(low, &r, &keys.public_key, rng),
            trace_input: encode(high, &trace_message, &keys.public_key, rng),
            trace_inverse,
            lineage: PhaseLineage(hash.finalize().into()),
            family: [17, 31],
            primes: high.config.primes.clone(),
            n: high.n,
            base: low.t,
            noise: PrimePowerPhaseNoiseCertificate {
                high_error_bound: bound,
                low_error_bound: bound,
                projection_input_error_bound: bound,
                max_centered_work_error: U512::zero(),
                source_level: 4,
                rounding_shift: 0,
            },
        }
    }

    #[test]
    fn public_prime_power_lift_polynomial_is_an_exact_canonical_section() {
        for p in [3u64, 5, 17, 31, 101, 257] {
            let modulus = p * p;
            for x in 0..modulus {
                let mut product = 1u128;
                for a in 0..p {
                    product = product * ((x + modulus - a) % modulus) as u128 % modulus as u128;
                }
                assert_eq!(
                    (x as u128 + product) % modulus as u128,
                    (x % p) as u128,
                    "p={p}, x={x}"
                );
            }
        }
        let p = 65537u64;
        let mut factorial = vec![1u64; p as usize];
        for j in 1..p as usize {
            factorial[j] = (factorial[j - 1] as u128 * j as u128 % p as u128) as u64;
        }
        for r in 0..p as usize {
            let mut derivative =
                (factorial[r] as u128 * factorial[p as usize - 1 - r] as u128 % p as u128) as u64;
            if (p as usize - 1 - r) % 2 != 0 {
                derivative = p - derivative;
            }
            assert_eq!(derivative, p - 1);
        }
        assert_eq!(64 - (p - 1).leading_zeros(), 17);
    }

    #[test]
    fn public_prime_power_lift_four_prime_noise_gate_refuses_before_keys() {
        let work = SecureConfig::secure_128().into_config();
        let mut config = work.clone();
        config.t = work.t * work.t;
        let ctx = RNSFHEContext::try_new(&config).unwrap();
        let high = ExpandedPhaseEvaluator::new(&ctx, work.t, 2).unwrap();
        let paired = PrimePowerPhaseEvaluator::new(&high, &work).unwrap();
        match CanonicalLowDigitLiftEvaluator::new(&paired) {
            Err(Nine65Error::BootstrapFailed { reason }) => {
                println!("{reason}");
                assert!(reason.contains("polynomial multiply"));
                assert!(reason.contains("131 error bits"));
                assert!(reason.contains("86 half-Delta bits"));
            }
            _ => panic!("the four-prime polynomial route must not be admitted"),
        }
    }

    #[test]
    fn public_prime_power_lift_encrypted_toy_cases_use_no_digit_oracle() {
        for base in [3u64, 5, 17] {
            let mut config = SecureConfig::secure_128().into_config();
            config.n = 8;
            config.t = base * base;
            config.security_bits = 0;
            config.name = "INSECURE canonical-lift toy";
            let high = RNSFHEContext::try_new(&config).unwrap();
            config.t = base;
            let low = RNSFHEContext::try_new(&config).unwrap();
            let mut rng = ShadowHarvester::with_seed(0x5052_494d_454c_4946 + base);
            let keys = high.generate_keys(&mut rng);
            let sample = fixture(&high, &low, &vec![0; high.n], &keys, &mut rng);
            let evaluator = CanonicalLowDigitLiftEvaluator::from_context(
                &high,
                base,
                sample.noise.high_error_bound,
            )
            .unwrap();
            let lift_key = evaluator
                .keys_for_secret(&keys.secret_key, sample.family, &mut rng)
                .unwrap();
            let certificate = evaluator.certificate();
            println!(
                "toy p={base}, N=8: lift error {} bits / half-Delta {} bits, depth {}",
                bits(certificate.lifted_error_bound),
                bits(certificate.half_delta),
                certificate.multiplicative_depth
            );
            let q = high
                .config
                .primes
                .iter()
                .map(|&q| q as u128)
                .product::<u128>();
            let pq = q * high.t as u128;
            for start in (0..high.t).step_by(high.n) {
                let message: Vec<u64> = (0..high.n).map(|j| (start + j as u64) % high.t).collect();
                let phase = fixture(&high, &low, &message, &keys, &mut rng);
                let lifted = evaluator.evaluate(&phase, &lift_key).unwrap();
                let expected: Vec<u64> = message.iter().map(|&v| v % base).collect();
                assert_eq!(
                    decode_all(&high, &lifted.encrypted, &keys.secret_key),
                    expected
                );
                for (&actual, &r) in phase_oracle(&high, &lifted.encrypted, &keys.secret_key)
                    .iter()
                    .zip(&expected)
                {
                    let difference = (actual * high.t as u128 + pq - q * r as u128) % pq;
                    let distance = difference.min(pq - difference);
                    assert_eq!(
                        (
                            lifted.error_bound.d1,
                            lifted.error_bound.d2,
                            lifted.error_bound.d3
                        ),
                        (0, 0, 0)
                    );
                    assert!(distance <= lifted.error_bound.d0 * high.t as u128);
                }
                let remover = PrimePowerDigitRemoval { ctx: &low, base };
                let contracted = remover.contract(&phase, &lifted).unwrap();
                assert_eq!(
                    decode_all(&low, contracted.ciphertext(), &keys.secret_key),
                    message.iter().map(|&v| v / base).collect::<Vec<_>>()
                );
            }
            let m = 7.min(base - 1);
            let mut message = vec![(base - 1) / 2; high.n];
            message[0] += m * base;
            let phase = fixture(&high, &low, &message, &keys, &mut rng);
            let lifted = evaluator.evaluate(&phase, &lift_key).unwrap();
            let contracted = PrimePowerDigitRemoval { ctx: &low, base }
                .contract(&phase, &lifted)
                .unwrap();
            let squared = low
                .try_exact_evaluator()
                .unwrap()
                .try_mul_exact(
                    contracted.ciphertext(),
                    contracted.ciphertext(),
                    &lift_key.relin,
                )
                .unwrap();
            let decoded = decode_all(&low, &squared, &keys.secret_key);
            assert_eq!(decoded[0], m * m % base);
            assert!(decoded[1..].iter().all(|&v| v == 0));
            let mut bad = phase;
            bad.family[0] ^= 1;
            assert!(matches!(
                evaluator.evaluate(&bad, &lift_key),
                Err(Nine65Error::BootstrapConfigMismatch { .. })
            ));
            bad.family = lift_key.family;
            bad.trace_input.c0.limbs[0][0] = high.config.primes[0];
            assert!(matches!(
                evaluator.evaluate(&bad, &lift_key),
                Err(Nine65Error::InvalidParameter { .. })
            ));
        }
    }

    #[test]
    fn public_prime_power_lift_native_galois_preserves_full_size_phase() {
        let mut config = SecureConfig::secure_128().into_config();
        config.t *= config.t;
        let ctx = RNSFHEContext::try_new(&config).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x524e_535f_4741_4c4f);
        let keys = ctx.generate_keys(&mut rng);
        let galois = RNSGaloisEvaluator::new(&ctx).unwrap();
        let mut message = vec![0; ctx.n];
        message[0] = 7;
        message[1] = ctx.t - 1;
        message[ctx.n - 1] = ctx.t / 2;
        let ct = encode(&ctx, &message, &keys.public_key, &mut rng);
        for exponent in [3u64, ctx.n as u64 + 1, 2 * ctx.n as u64 - 1] {
            let key = galois
                .generate_key_with_rng(&keys.secret_key, exponent, &mut rng)
                .unwrap();
            let transformed = galois.apply(&ct, &key).unwrap();
            let mut expected = vec![0; ctx.n];
            for (j, &v) in message.iter().enumerate() {
                let target = j * exponent as usize % (2 * ctx.n);
                expected[target % ctx.n] = if target < ctx.n || v == 0 {
                    v
                } else {
                    ctx.t - v
                };
            }
            assert_eq!(decode_all(&ctx, &transformed, &keys.secret_key), expected);
        }
        // Precondition the PUBLIC fixture message before encryption; the phase
        // evaluator similarly preconditions its public components. The trace yields
        // a constant encryption of x_j without an inverse-noise multiplier.
        let inverse_n = centered_inverse(ctx.n, ctx.t).unwrap();
        assert_eq!(inverse_n, -524304);
        let inverse_residue = (inverse_n as i128).rem_euclid(ctx.t as i128) as u128;
        let preconditioned: Vec<u64> = message
            .iter()
            .map(|&v| (v as u128 * inverse_residue % ctx.t as u128) as u64)
            .collect();
        let ct = encode(&ctx, &preconditioned, &keys.public_key, &mut rng);
        let j = ctx.n - 1;
        let mut projected = shift(&ctx, &ct, 2 * ctx.n - j);
        let mut stride = ctx.n;
        while stride > 1 {
            let key = galois
                .generate_key_with_rng(&keys.secret_key, stride as u64 + 1, &mut rng)
                .unwrap();
            let transformed = galois.apply(&projected, &key).unwrap();
            projected = RNSCiphertext {
                c0: projected.c0.add(&transformed.c0, &ctx.rns),
                c1: projected.c1.add(&transformed.c1, &ctx.rns),
                num_primes: projected.num_primes,
            };
            stride /= 2;
        }
        let mut expected = vec![0; ctx.n];
        expected[0] = message[j];
        assert_eq!(decode_all(&ctx, &projected, &keys.secret_key), expected);
        for exponent in [0, 2, 2 * ctx.n as u64] {
            assert!(galois
                .generate_key_with_rng(&keys.secret_key, exponent, &mut rng)
                .is_err());
        }
        let mut bad = keys.secret_key.clone();
        bad.s.limbs[0][0] = ctx.rns.mont_contexts[0].to_montgomery(2);
        let mut probe = ShadowHarvester::with_seed(19);
        let mut untouched = ShadowHarvester::with_seed(19);
        assert!(galois.generate_key_with_rng(&bad, 3, &mut probe).is_err());
        assert_eq!(
            FheRng::next_u64(&mut probe),
            FheRng::next_u64(&mut untouched)
        );
    }
}
