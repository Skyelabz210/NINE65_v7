//! Coherent encrypted carry phases in coefficient slots, using public source
//! residues and a key-holder-generated bank. Secrets occur only in key setup.
//!
//! Write p*c_i = Q*a_i + R_i, with R_i centered. The public weights
//! d_i=round(p*R_i/Q) satisfy d0+d1*s=p*K+rho, where the authenticated
//! source certificate bounds every rho. The separate affine view a0+a1*s
//! must be added to the extracted K to recover the original message.
//! Independently of the residual radius, |d0+d1*s| <= (H+1)*floor(p/2)
//! for source norm H. This also certifies the produced integer K's radius.

use crate::arithmetic::canonical_scale_round::CanonicalScaleRound;
use crate::arithmetic::wide::U1024;
use crate::arithmetic::RNSPolynomial;
use crate::entropy::{require_secure_rng, FheRng};
use crate::errors::{Nine65Error, Nine65Result};
use crate::ops::public_refresh_source::{PreparedRefreshSource, PublicRefreshSourceClient};
use crate::ops::rns_fhe::{RNSCiphertext, RNSFHEContext, RNSSecretKey};
use crate::ops::rns_galois::{
    validate_main, validate_ternary_secret, PreparedRNSGaloisKey, RNSGaloisEvaluator,
};
use crate::params::is_prime;
use zeroize::Zeroizing;

fn failure(reason: impl Into<String>) -> Nine65Error {
    Nine65Error::BootstrapFailed {
        reason: reason.into(),
    }
}
fn power(mut a: u64, mut e: u64, q: u64) -> u64 {
    let mut y = 1;
    while e != 0 {
        if e & 1 != 0 {
            y = (y as u128 * a as u128 % q as u128) as u64;
        }
        a = (a as u128 * a as u128 % q as u128) as u64;
        e >>= 1;
    }
    y
}
fn inverse(a: u64, q: u64) -> Nine65Result<u64> {
    let (mut a0, mut a1) = (q as i128, a as i128);
    let (mut b0, mut b1) = (0i128, 1i128);
    while a1 != 0 {
        let k = a0 / a1;
        (a0, a1) = (a1, a0 - k * a1);
        (b0, b1) = (b1, b0 - k * b1);
    }
    if a0 != 1 {
        return Err(failure("slot transform requires a unit"));
    }
    Ok(b0.rem_euclid(q as i128) as u64)
}
fn signed(v: u64, t: u64) -> i64 {
    if v <= t / 2 {
        v as i64
    } else {
        v as i64 - t as i64
    }
}
fn residue(v: i64, q: u64) -> u64 {
    (v as i128).rem_euclid(q as i128) as u64
}

/// Exact plaintext CRT map, in two rows of exponents +5^i and -5^i.
/// Both prime p and its square are supported when 2N divides p-1.
pub(crate) struct SlotEncoding {
    n: usize,
    t: u64,
    root: u64,
    inverse_root: u64,
    inverse_n: u64,
    forward_stages: Vec<u64>,
    inverse_stages: Vec<u64>,
    exponents: Vec<u64>,
}
impl SlotEncoding {
    pub(crate) fn new(n: usize, t: u64) -> Nine65Result<Self> {
        if n < 2 || !n.is_power_of_two() || 2 * n as u128 > u64::MAX as u128 || t > i64::MAX as u64
        {
            return Err(failure("invalid split-slot ring"));
        }
        let p = if is_prime(t) {
            t
        } else {
            let r = t.isqrt();
            if r.checked_mul(r) != Some(t) || !is_prime(r) {
                return Err(failure("slot plaintext must be a prime or its square"));
            }
            r
        };
        if (p - 1) % (2 * n as u64) != 0 {
            return Err(failure(
                "slot plaintext does not split this negacyclic ring",
            ));
        }
        let r = (2..p)
            .map(|a| power(a, (p - 1) / (2 * n as u64), p))
            .find(|&r| power(r, n as u64, p) == p - 1)
            .ok_or_else(|| failure("no primitive plaintext root"))?;
        // Teichmuller lifting preserves the order and reduces to r modulo p.
        let root = if p == t { r } else { power(r, p, t) };
        if power(root, n as u64, t) != t - 1 {
            return Err(failure("invalid lifted plaintext root"));
        }
        let two_n = 2 * n as u64;
        let mut exponents = Vec::with_capacity(n);
        let mut exponent = 1;
        for _ in 0..n / 2 {
            exponents.push(exponent);
            exponent = (exponent as u128 * 5 % two_n as u128) as u64;
        }
        exponents.extend(exponents.clone().into_iter().map(|e| two_n - e));
        let inverse_root = inverse(root, t)?;
        let inverse_n = inverse(n as u64, t)?;
        let omega = (root as u128 * root as u128 % t as u128) as u64;
        let inverse_omega = (inverse_root as u128 * inverse_root as u128 % t as u128) as u64;
        let mut forward_stages = Vec::new();
        let mut inverse_stages = Vec::new();
        let mut width = 2;
        while width <= n {
            forward_stages.push(power(omega, (n / width) as u64, t));
            inverse_stages.push(power(inverse_omega, (n / width) as u64, t));
            width *= 2;
        }
        Ok(Self {
            n,
            t,
            root,
            inverse_root,
            inverse_n,
            forward_stages,
            inverse_stages,
            exponents,
        })
    }
    pub(crate) fn exponents(&self) -> &[u64] {
        &self.exponents
    }
    pub(crate) fn primitive_root(&self) -> u64 {
        self.root
    }
    #[inline]
    fn multiply(&self, a: u64, b: u64) -> u64 {
        if self.t == 65537 {
            // Inputs are canonical. a*b <= 2^32, and 2^16 = -1 mod 65537.
            let product = a * b;
            let difference = (product & 65535) as i64 - (product >> 16) as i64;
            if difference < 0 {
                (difference + 65537) as u64
            } else {
                difference as u64
            }
        } else {
            (a as u128 * b as u128 % self.t as u128) as u64
        }
    }
    fn transform(&self, values: &mut [u64], inverse: bool) {
        let mut j = 0;
        for i in 1..self.n {
            let mut bit = self.n >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j ^= bit;
            if i < j {
                values.swap(i, j);
            }
        }
        let mut width = 2;
        let stages = if inverse {
            &self.inverse_stages
        } else {
            &self.forward_stages
        };
        for &step in stages {
            for start in (0..self.n).step_by(width) {
                let mut factor = 1;
                for offset in 0..width / 2 {
                    let a = values[start + offset];
                    let b = self.multiply(values[start + offset + width / 2], factor);
                    let sum = a + b;
                    values[start + offset] = if sum >= self.t { sum - self.t } else { sum };
                    values[start + offset + width / 2] =
                        if a >= b { a - b } else { a + self.t - b };
                    factor = self.multiply(factor, step);
                }
            }
            width *= 2;
        }
    }
    pub(crate) fn encode_slots(&self, slots: &[u64]) -> Nine65Result<Vec<u64>> {
        if slots.len() != self.n || slots.iter().any(|&x| x >= self.t) {
            return Err(failure("invalid plaintext slots"));
        }
        let mut coefficients = vec![0; self.n];
        for (&value, &e) in slots.iter().zip(&self.exponents) {
            coefficients[((e - 1) / 2) as usize] = value;
        }
        self.transform(&mut coefficients, true);
        let mut factor = self.inverse_n;
        for value in &mut coefficients {
            *value = self.multiply(*value, factor);
            factor = self.multiply(factor, self.inverse_root);
        }
        Ok(coefficients)
    }
    #[cfg(test)]
    pub(crate) fn decode_slots(&self, coefficients: &[u64]) -> Nine65Result<Vec<u64>> {
        if coefficients.len() != self.n || coefficients.iter().any(|&x| x >= self.t) {
            return Err(failure("invalid plaintext coefficients"));
        }
        let mut values = coefficients.to_vec();
        let mut factor = 1;
        for value in &mut values {
            *value = self.multiply(*value, factor);
            factor = self.multiply(factor, self.root);
        }
        self.transform(&mut values, false);
        Ok(self
            .exponents
            .iter()
            .map(|e| values[((e - 1) / 2) as usize])
            .collect())
    }
}

fn zero(ctx: &RNSFHEContext) -> RNSCiphertext {
    let poly = RNSPolynomial {
        limbs: vec![vec![0; ctx.n]; ctx.config.primes.len()],
        n: ctx.n,
    };
    RNSCiphertext {
        c0: poly.clone(),
        c1: poly,
        num_primes: ctx.config.primes.len(),
    }
}
/// A whole public baby sum fits a signed accumulator. Reduce once after the
/// sum, rather than once per bank entry; this is exact modular arithmetic.
fn add_weighted_bank(
    ctx: &RNSFHEContext,
    out: &mut RNSCiphertext,
    bank: &[RNSCiphertext],
    weights: &[i64],
) -> Nine65Result<()> {
    add_weighted_bank_schedule(ctx, out, bank, weights, ctx.n >= 32768)
}
fn add_weighted_bank_schedule(
    ctx: &RNSFHEContext,
    out: &mut RNSCiphertext,
    bank: &[RNSCiphertext],
    weights: &[i64],
    parallel: bool,
) -> Nine65Result<()> {
    if bank.len() != weights.len() {
        return Err(failure("baby weight count mismatch"));
    }
    let total_weight = weights
        .iter()
        .try_fold(0u128, |sum, w| sum.checked_add(w.unsigned_abs() as u128))
        .ok_or_else(|| failure("baby weight norm overflow"))?;
    // Check every public lane before mutating an accumulator or launching work.
    for &q in &ctx.config.primes {
        let bound = total_weight
            .checked_mul((q - 1) as u128)
            .and_then(|v| v.checked_add((q - 1) as u128))
            .ok_or_else(|| failure("baby accumulator bound overflow"))?;
        if bound > i128::MAX as u128 {
            return Err(failure("baby accumulator exceeds signed width"));
        }
    }
    let primes = &ctx.config.primes;
    let accumulate = |component: usize, first_lane: usize, lanes: &mut [Vec<u64>]| {
        for (offset, dst) in lanes.iter_mut().enumerate() {
            let lane = first_lane + offset;
            let q = primes[lane];
            let sources: Vec<_> = bank
                .iter()
                .map(|ct| {
                    if component == 0 {
                        &ct.c0.limbs[lane]
                    } else {
                        &ct.c1.limbs[lane]
                    }
                })
                .collect();
            for (j, value) in dst.iter_mut().enumerate() {
                let mut sum = *value as i128;
                for (source, &weight) in sources.iter().zip(weights) {
                    sum += source[j] as i128 * weight as i128;
                }
                *value = sum.rem_euclid(q as i128) as u64;
            }
        }
    };
    if parallel {
        // Two disjoint lane chunks per component, at most four workers.
        // Every coefficient retains precisely the sequential summation order.
        let chunk_size = ctx.config.primes.len().div_ceil(2).max(1);
        std::thread::scope(|scope| -> Nine65Result<()> {
            let mut workers = Vec::new();
            for (component, limbs) in [&mut out.c0.limbs, &mut out.c1.limbs]
                .into_iter()
                .enumerate()
            {
                for (chunk, values) in limbs.chunks_mut(chunk_size).enumerate() {
                    let accumulate = &accumulate;
                    workers.push(
                        scope.spawn(move || accumulate(component, chunk * chunk_size, values)),
                    );
                }
            }
            for worker in workers {
                worker
                    .join()
                    .map_err(|_| failure("native baby-sum worker failed"))?;
            }
            Ok(())
        })?;
    } else {
        accumulate(0, 0, &mut out.c0.limbs);
        accumulate(1, 0, &mut out.c1.limbs);
    }
    Ok(())
}
fn add_plain(ctx: &RNSFHEContext, out: &mut RNSCiphertext, coefficients: &[u64]) {
    for (lane, &q) in ctx.config.primes.iter().enumerate() {
        let mont = &ctx.rns.mont_contexts[lane];
        for (v, &m) in out.c0.limbs[lane].iter_mut().zip(coefficients) {
            let encoded =
                residue(signed(m, ctx.t), q) as u128 * ctx.delta_rns[lane] as u128 % q as u128;
            *v = ((*v as u128 + mont.to_montgomery(encoded as u64) as u128) % q as u128) as u64;
        }
    }
}
/// Key-holder-only symmetric encryption of a dense centered polynomial.
fn encrypt_polynomial<R: FheRng>(
    ctx: &RNSFHEContext,
    secret: &RNSSecretKey,
    message: &[u64],
    rng: &mut R,
) -> RNSCiphertext {
    let a = ctx.sample_uniform_main_poly(rng);
    let errors = Zeroizing::new(rng.cbd_vector(ctx.n, ctx.config.eta));
    let mut out = zero(ctx);
    for (lane, &q) in ctx.config.primes.iter().enumerate() {
        let mont = &ctx.rns.mont_contexts[lane];
        let key = Zeroizing::new(
            secret.s.limbs[lane]
                .iter()
                .map(|&x| mont.from_montgomery(x))
                .collect::<Vec<_>>(),
        );
        let product = Zeroizing::new(ctx.ntt_engines[lane].multiply(&a.limbs[lane], &key));
        for j in 0..ctx.n {
            let encoded = residue(signed(message[j], ctx.t), q) as u128
                * ctx.delta_rns[lane] as u128
                % q as u128;
            let v = (encoded + residue(errors[j], q) as u128 + q as u128 - product[j] as u128)
                % q as u128;
            out.c0.limbs[lane][j] = mont.to_montgomery(v as u64);
            out.c1.limbs[lane][j] = mont.to_montgomery(a.limbs[lane][j]);
        }
    }
    out
}

/// Shared finite layout: both power-five rows contain [v,-v].
fn repeated_antiperiodic(values: &[i64], modulus: u64) -> Vec<u64> {
    let row: Vec<_> = values
        .iter()
        .copied()
        .chain(values.iter().map(|&v| -v))
        .map(|v| residue(v, modulus))
        .collect();
    row.iter().copied().chain(row.iter().copied()).collect()
}

pub(crate) struct DirectSlotPhaseKey {
    family: [u8; 32],
    source_primes: Vec<u64>,
    source_n: usize,
    outer_primes: Vec<u64>,
    outer_n: usize,
    p: u64,
    eta: usize,
    baby: usize,
    high: Vec<RNSCiphertext>,
    low: Vec<RNSCiphertext>,
    giant: Option<PreparedRNSGaloisKey>,
    error_bound: U1024,
}

/// Output fields are private; only the bound/source-authenticated producer
/// creates this coherent pair. The affine component is part of the contract.
pub(crate) struct DirectSlotPhases {
    high: RNSCiphertext,
    low: RNSCiphertext,
    affine: RNSCiphertext,
    radius: u64,
    value_bound: u64,
    quotient_radius: u64,
    error_bound: U1024,
    lineage: [u8; 32],
}
impl DirectSlotPhases {
    pub(crate) fn high(&self) -> &RNSCiphertext {
        &self.high
    }
    pub(crate) fn low(&self) -> &RNSCiphertext {
        &self.low
    }
    pub(crate) fn affine(&self) -> &RNSCiphertext {
        &self.affine
    }
    pub(crate) fn radius(&self) -> u64 {
        self.radius
    }
    pub(crate) fn value_bound(&self) -> u64 {
        self.value_bound
    }
    pub(crate) fn quotient_radius(&self) -> u64 {
        self.quotient_radius
    }
    pub(crate) fn error_bound(&self) -> U1024 {
        self.error_bound
    }
    pub(crate) fn lineage(&self) -> &[u8; 32] {
        &self.lineage
    }
}

impl DirectSlotPhaseKey {
    pub(crate) fn generate_with_rng<R: FheRng>(
        client: &PublicRefreshSourceClient,
        high: &RNSFHEContext,
        low: &RNSFHEContext,
        outer_secret: &RNSSecretKey,
        baby: usize,
        max_key_bytes: usize,
        rng: &mut R,
    ) -> Nine65Result<Self> {
        let source = client.source_context();
        if low.n != high.n
            || high.n != 4 * source.n
            || low.config.primes != high.config.primes
            || high.t
                != source
                    .t
                    .checked_mul(source.t)
                    .ok_or_else(|| failure("source p square overflow"))?
            || low.t != source.t
            || low.config.eta != high.config.eta
            || baby == 0
            || !baby.is_power_of_two()
            || baby > source.n
            || source.n % baby != 0
        {
            return Err(failure("direct slot key context or baby geometry mismatch"));
        }
        validate_ternary_secret(source, client.source_secret_key())?;
        validate_ternary_secret(high, outer_secret)?;
        let q = U1024::checked_product_u64s(&high.config.primes)
            .ok_or_else(|| failure("direct slot modulus overflow"))?;
        if q.mod_u64(high.t) != Some(1) {
            return Err(failure("direct slot precharge requires Q = 1 mod p²"));
        }
        let high_slots = SlotEncoding::new(high.n, high.t)?;
        let low_slots = SlotEncoding::new(low.n, low.t)?;
        let digits: usize = high
            .config
            .primes
            .iter()
            .map(|q| ((64 - q.leading_zeros()) as usize).div_ceil(10))
            .sum();
        let words_per_ct = 2usize
            .checked_mul(high.n)
            .and_then(|v| v.checked_mul(high.config.primes.len()))
            .ok_or_else(|| failure("direct slot key size overflow"))?;
        let words = words_per_ct
            .checked_mul(2 * baby + if baby < source.n { digits + 1 } else { 0 })
            .and_then(|v| v.checked_mul(8))
            .ok_or_else(|| failure("direct slot key size overflow"))?;
        if words > max_key_bytes {
            return Err(failure(format!(
                "direct slot key needs {words} coefficient bytes"
            )));
        }
        let error_bound = Self::phase_error_bound(high, source.n, source.t, baby)?;
        require_secure_rng(rng, "DirectSlotPhaseKey::generate_with_rng");
        let source_signed = Zeroizing::new(
            client.source_secret_key().s.limbs[0]
                .iter()
                .map(|&v| {
                    signed(
                        source.rns.mont_contexts[0].from_montgomery(v),
                        source.config.primes[0],
                    )
                })
                .collect::<Vec<_>>(),
        );
        if source_signed.iter().map(|v| v.unsigned_abs()).sum::<u64>()
            != client.plan().source_weight() as u64
        {
            return Err(failure("direct phase source norm differs from its plan"));
        }
        let mut bank_high = Vec::with_capacity(baby);
        let mut bank_low = Vec::with_capacity(baby);
        for b in 0..baby {
            let mut shifted = Zeroizing::new(vec![0i64; source.n]);
            for i in 0..source.n {
                let k = (i + 2 * source.n - b) % (2 * source.n);
                shifted[i] = if k < source.n {
                    source_signed[k]
                } else {
                    -source_signed[k - source.n]
                };
            }
            let hs = Zeroizing::new(repeated_antiperiodic(&shifted, high.t));
            let ls = Zeroizing::new(repeated_antiperiodic(&shifted, low.t));
            let hp = Zeroizing::new(high_slots.encode_slots(&hs)?);
            let lp = Zeroizing::new(low_slots.encode_slots(&ls)?);
            bank_high.push(encrypt_polynomial(high, outer_secret, &hp, rng));
            bank_low.push(encrypt_polynomial(low, outer_secret, &lp, rng));
        }
        let groups = source.n / baby;
        let giant = if groups > 1 {
            let exponent = power(5, (high.n / 2 - baby) as u64, 2 * high.n as u64);
            let evaluator = RNSGaloisEvaluator::new(high)?;
            let raw = evaluator.generate_key_with_rng(outer_secret, exponent, rng)?;
            Some(evaluator.prepare_key(&raw)?)
        } else {
            None
        };
        Ok(Self {
            family: *client.family_id(),
            source_primes: source.config.primes.clone(),
            source_n: source.n,
            outer_primes: high.config.primes.clone(),
            outer_n: high.n,
            p: source.t,
            eta: high.config.eta,
            baby,
            high: bank_high,
            low: bank_low,
            giant,
            error_bound,
        })
    }
    /// Parameter-only preflight. This is not source-history admission.
    pub(crate) fn phase_error_bound(
        high: &RNSFHEContext,
        source_n: usize,
        p: u64,
        baby: usize,
    ) -> Nine65Result<U1024> {
        if source_n == 0
            || source_n.checked_mul(4) != Some(high.n)
            || baby == 0
            || !baby.is_power_of_two()
            || baby > source_n
            || source_n % baby != 0
            || p.checked_mul(p) != Some(high.t)
            || high.config.eta > u32::MAX as usize
        {
            return Err(failure("direct phase error geometry mismatch"));
        }
        let q = U1024::checked_product_u64s(&high.config.primes)
            .ok_or_else(|| failure("direct slot modulus overflow"))?;
        if q.mod_u64(high.t) != Some(1) {
            return Err(failure("direct slot precharge requires Q = 1 mod p²"));
        }
        let digits: usize = high
            .config
            .primes
            .iter()
            .map(|q| ((64 - q.leading_zeros()) as usize).div_ceil(10))
            .sum();
        // Ideal Q/t-grid error: symmetric precharge <= eta+1/2, rounded
        // upward; public plaintext addition <=1/2. Horner rotates the
        // accumulated groups without multiplying their noise by weights.
        let fresh = (high.config.eta as u128 + 1) * source_n as u128 * ((p - 1) / 2) as u128;
        let switch = high.n as u128 * high.config.eta as u128 * 1023 * digits as u128;
        let error = fresh
            .checked_add(
                switch
                    .checked_mul((source_n / baby - 1) as u128)
                    .ok_or_else(|| failure("direct phase error overflow"))?,
            )
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| failure("direct phase error overflow"))?;
        let error = U1024::from_u128(error);
        if error >= q.div_mod_u64(high.t).unwrap().0.shr1() {
            return Err(failure("direct slot phase lacks decoding headroom"));
        }
        Ok(error)
    }
    fn inner_product(
        &self,
        ctx: &RNSFHEContext,
        bank: &[RNSCiphertext],
        weights: &[i64],
        constant: &[i64],
        stage: &str,
        progress: &mut dyn FnMut(&str, usize, usize),
    ) -> Nine65Result<RNSCiphertext> {
        let galois = RNSGaloisEvaluator::new(ctx)?;
        let mut out = zero(ctx);
        for group in (0..self.source_n / self.baby).rev() {
            progress(
                stage,
                self.source_n / self.baby - group,
                self.source_n / self.baby,
            );
            if group + 1 < self.source_n / self.baby {
                out = galois.apply_prepared(
                    &out,
                    self.giant
                        .as_ref()
                        .ok_or_else(|| failure("missing giant key"))?,
                )?;
            }
            add_weighted_bank(
                ctx,
                &mut out,
                bank,
                &weights[group * self.baby..(group + 1) * self.baby],
            )?;
        }
        let slots = repeated_antiperiodic(constant, ctx.t);
        let coefficients = SlotEncoding::new(ctx.n, ctx.t)?.encode_slots(&slots)?;
        add_plain(ctx, &mut out, &coefficients);
        Ok(out)
    }
    #[cfg(test)]
    pub(crate) fn evaluate(
        &self,
        source: &PreparedRefreshSource,
        high: &RNSFHEContext,
        low: &RNSFHEContext,
    ) -> Nine65Result<DirectSlotPhases> {
        self.evaluate_with_progress(source, high, low, &mut |_, _, _| {})
    }
    pub(crate) fn evaluate_with_progress(
        &self,
        source: &PreparedRefreshSource,
        high: &RNSFHEContext,
        low: &RNSFHEContext,
        progress: &mut dyn FnMut(&str, usize, usize),
    ) -> Nine65Result<DirectSlotPhases> {
        let source_ctx = source.source_context();
        if *source.certificate().family_id() != self.family
            || source_ctx.n != self.source_n
            || source_ctx.config.primes != self.source_primes
            || source_ctx.t != self.p
            || high.config.primes != self.outer_primes
            || low.config.primes != self.outer_primes
            || high.n != self.outer_n
            || low.n != self.outer_n
            || high.t != self.p * self.p
            || low.t != self.p
            || high.config.eta != self.eta
            || low.config.eta != self.eta
        {
            return Err(failure("direct slot phase source/key/context mismatch"));
        }
        let radius = source.certificate().prime_square_residual_radius();
        if radius * 2 >= self.p {
            return Err(failure("source history has no bounded carry digit margin"));
        }
        validate_main(source_ctx, source.ciphertext())?;
        let projection = CanonicalScaleRound::new(&self.source_primes, self.p)
            .map_err(|e| failure(format!("source residual projection: {e:?}")))?;
        let mut affine = [vec![0i64; self.source_n], vec![0i64; self.source_n]];
        let mut digit = affine.clone();
        let mut residues = vec![0; self.source_primes.len()];
        for (component, polynomial) in [&source.ciphertext().c0, &source.ciphertext().c1]
            .iter()
            .enumerate()
        {
            for j in 0..self.source_n {
                for (lane, r) in residues.iter_mut().enumerate() {
                    *r = source_ctx.rns.mont_contexts[lane]
                        .from_montgomery(polynomial.limbs[lane][j]);
                }
                affine[component][j] = signed(
                    projection
                        .scale_round(&residues)
                        .map_err(|e| failure(format!("source affine projection: {e:?}")))?,
                    self.p,
                );
                for (r, &q) in residues.iter_mut().zip(&self.source_primes) {
                    *r = (*r as u128 * self.p as u128 % q as u128) as u64;
                }
                digit[component][j] = signed(
                    projection
                        .scale_round(&residues)
                        .map_err(|e| failure(format!("source digit projection: {e:?}")))?,
                    self.p,
                );
            }
        }
        Ok(DirectSlotPhases {
            high: self.inner_product(
                high,
                &self.high,
                &digit[1],
                &digit[0],
                "high carry phase",
                progress,
            )?,
            low: self.inner_product(
                low,
                &self.low,
                &digit[1],
                &digit[0],
                "low carry phase",
                progress,
            )?,
            affine: self.inner_product(
                low,
                &self.low,
                &affine[1],
                &affine[0],
                "affine phase",
                progress,
            )?,
            radius,
            value_bound: source.certificate().direct_phase_value_bound(),
            quotient_radius: source.certificate().signed_quotient_radius(),
            error_bound: self.error_bound,
            lineage: *source.certificate().lineage(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slot_encoding_roundtrips_prime_and_square_and_negacyclic_product() {
        for (n, p) in [(8, 17), (16, 97), (128, 257), (128, 65537)] {
            for t in [p, p * p] {
                let encoder = SlotEncoding::new(n, t).unwrap();
                let a: Vec<_> = (0..n).map(|i| (i as u64 * 7 + 3) % t).collect();
                let b: Vec<_> = (0..n).map(|i| (i as u64 * 11 + 5) % t).collect();
                let ea = encoder.encode_slots(&a).unwrap();
                let eb = encoder.encode_slots(&b).unwrap();
                assert_eq!(encoder.decode_slots(&ea).unwrap(), a);
                let mut product = vec![0; n];
                for i in 0..n {
                    for j in 0..n {
                        let value = ea[i] as u128 * eb[j] as u128 % t as u128;
                        let k = (i + j) % n;
                        product[k] = ((product[k] as u128
                            + if i + j < n { value } else { t as u128 - value })
                            % t as u128) as u64;
                    }
                }
                assert_eq!(
                    encoder.decode_slots(&product).unwrap(),
                    a.iter()
                        .zip(&b)
                        .map(|(&x, &y)| (x as u128 * y as u128 % t as u128) as u64)
                        .collect::<Vec<_>>()
                );
            }
        }
        assert!(SlotEncoding::new(32, 17).is_err());
        assert!(SlotEncoding::new(8, 22).is_err());
    }
    #[test]
    fn native_plaintext_fast_transform_matches_direct_root_evaluation() {
        let encoder = SlotEncoding::new(128, 65537).unwrap();
        for a in 0..=65536 {
            for b in [0, 1, 32768, 65535, 65536] {
                assert_eq!(
                    encoder.multiply(a, b),
                    (a as u128 * b as u128 % 65537) as u64
                );
            }
        }
        let coefficients: Vec<_> = (0..128)
            .map(|i| {
                if i % 3 == 0 {
                    65536
                } else {
                    (i * 1771 + 3) % 65537
                }
            })
            .collect();
        let expected: Vec<_> = encoder
            .exponents()
            .iter()
            .map(|&e| {
                let x = power(encoder.primitive_root(), e, 65537);
                coefficients.iter().rev().fold(0u64, |sum, &c| {
                    ((sum as u128 * x as u128 + c as u128) % 65537) as u64
                })
            })
            .collect();
        assert_eq!(encoder.decode_slots(&coefficients).unwrap(), expected);
        assert_eq!(encoder.encode_slots(&expected).unwrap(), coefficients);
        assert!(SlotEncoding::new(usize::MAX / 2 + 1, 65537).is_err());
    }
    #[test]
    fn antiperiodic_baby_horner_is_full_negacyclic_convolution() {
        let n = 8;
        let baby = 2;
        let t = 17;
        let a: Vec<_> = (0..n).map(|i| i as i64 - 3).collect();
        let s = [1, 0, -1, 1, 0, 1, -1, 0];
        let mut out = vec![0i64; 2 * n];
        for g in (0..n / baby).rev() {
            if g + 1 < n / baby {
                out.rotate_right(baby);
            }
            for b in 0..baby {
                for (i, v) in out.iter_mut().enumerate() {
                    let k = (i + 2 * n - b) % (2 * n);
                    *v += a[g * baby + b] * if k < n { s[k] } else { -s[k - n] };
                }
            }
        }
        for i in 0..n {
            let expected = (0..n)
                .map(|j| a[j] * if i >= j { s[i - j] } else { -s[n + i - j] })
                .sum::<i64>();
            assert_eq!(out[i], expected);
            assert_eq!(out[i + n], -expected);
        }
        let slots = repeated_antiperiodic(&out[..n], t);
        assert_eq!(slots.len(), 4 * n);
    }
    #[test]
    fn batched_signed_weights_match_per_term_modular_oracle_on_wide_lanes() {
        use crate::params::SecureConfig;
        let mut cfg = SecureConfig::secure_128().into_config();
        cfg.n = 8;
        cfg.t = 17;
        cfg.security_bits = 0;
        cfg.name = "INSECURE wide-lane accumulator oracle";
        cfg.primes = vec![576460752301785089, 576460752301391873];
        let ctx = RNSFHEContext::try_new(&cfg).unwrap();
        let mut bank = vec![zero(&ctx); 64];
        for (b, ct) in bank.iter_mut().enumerate() {
            for (lane, &q) in ctx.config.primes.iter().enumerate() {
                for j in 0..ctx.n {
                    ct.c0.limbs[lane][j] = q - 1 - (b * ctx.n + j) as u64;
                    ct.c1.limbs[lane][j] = (b * ctx.n + j) as u64;
                }
            }
        }
        let weights: Vec<_> = (0..bank.len())
            .map(|b| if b % 2 == 0 { 32768 } else { -32768 })
            .collect();
        let mut expected = zero(&ctx);
        for (ct, &weight) in bank.iter().zip(&weights) {
            for (lane, &q) in ctx.config.primes.iter().enumerate() {
                for (dst, src) in [
                    (&mut expected.c0.limbs[lane], &ct.c0.limbs[lane]),
                    (&mut expected.c1.limbs[lane], &ct.c1.limbs[lane]),
                ] {
                    for (a, &b) in dst.iter_mut().zip(src) {
                        *a = ((*a as u128 + b as u128 * residue(weight, q) as u128) % q as u128)
                            as u64;
                    }
                }
            }
        }
        let mut actual = zero(&ctx);
        add_weighted_bank(&ctx, &mut actual, &bank, &weights).unwrap();
        assert_eq!(actual.c0.limbs, expected.c0.limbs);
        assert_eq!(actual.c1.limbs, expected.c1.limbs);
        assert!(add_weighted_bank(&ctx, &mut actual, &bank, &vec![i64::MIN; 64]).is_err());
    }
    #[test]
    fn native_weighted_bank_parallel_matches_sequential_reference_exactly() {
        use crate::params::SecureConfig;
        let mut cfg = SecureConfig::secure_128().into_config();
        cfg.n = 32768;
        cfg.t = 65537;
        cfg.security_bits = 0;
        cfg.name = "native-width parallel baby-sum arithmetic oracle";
        cfg.primes = vec![576460752301785089, 576460752301391873];
        let ctx = RNSFHEContext::try_new(&cfg).unwrap();
        let mut bank = vec![zero(&ctx); 16];
        for (b, ct) in bank.iter_mut().enumerate() {
            for (lane, &q) in ctx.config.primes.iter().enumerate() {
                for j in 0..ctx.n {
                    ct.c0.limbs[lane][j] = q - 1 - (b * ctx.n + j) as u64;
                    ct.c1.limbs[lane][j] =
                        ((b as u128 + 3) * (j as u128 + 17) * 177123199 % q as u128) as u64;
                }
            }
        }
        let weights: Vec<_> = (0..bank.len())
            .map(|i| if i % 3 == 0 { -32768 } else { 32768 - i as i64 })
            .collect();
        let mut expected = bank[3].clone();
        let mut actual = expected.clone();
        add_weighted_bank_schedule(&ctx, &mut expected, &bank, &weights, false).unwrap();
        add_weighted_bank(&ctx, &mut actual, &bank, &weights).unwrap();
        assert_eq!(actual.c0.limbs, expected.c0.limbs);
        assert_eq!(actual.c1.limbs, expected.c1.limbs);
    }
    fn observe_slots(
        ctx: &RNSFHEContext,
        ciphertext: &RNSCiphertext,
        sk: &RNSSecretKey,
    ) -> Vec<u64> {
        let mut phase = vec![vec![0; ctx.n]; ctx.config.primes.len()];
        for (lane, &q) in ctx.config.primes.iter().enumerate() {
            let mont = &ctx.rns.mont_contexts[lane];
            let c1: Vec<_> = ciphertext.c1.limbs[lane]
                .iter()
                .map(|&v| mont.from_montgomery(v))
                .collect();
            let secret: Vec<_> = sk.s.limbs[lane]
                .iter()
                .map(|&v| mont.from_montgomery(v))
                .collect();
            let product = ctx.ntt_engines[lane].multiply(&c1, &secret);
            for j in 0..ctx.n {
                phase[lane][j] = ((product[j] as u128
                    + mont.from_montgomery(ciphertext.c0.limbs[lane][j]) as u128)
                    % q as u128) as u64;
            }
        }
        let decoder = CanonicalScaleRound::new(&ctx.config.primes, ctx.t).unwrap();
        let coefficients: Vec<_> = (0..ctx.n)
            .map(|j| {
                decoder
                    .scale_round(&phase.iter().map(|lane| lane[j]).collect::<Vec<_>>())
                    .unwrap()
            })
            .collect();
        SlotEncoding::new(ctx.n, ctx.t)
            .unwrap()
            .decode_slots(&coefficients)
            .unwrap()
    }
    #[test]
    fn coherent_source_phases_extract_all_carries_and_restore_affine_message() {
        use crate::entropy::ShadowHarvester;
        use crate::ops::bounded_digit_circuit::SplitDigitEvaluator;
        use crate::ops::public_refresh_source::PublicRefreshSourcePlan;
        use crate::params::SecureConfig;
        let mut cfg = SecureConfig::secure_128().into_config();
        cfg.n = 8;
        cfg.t = 257;
        cfg.security_bits = 0;
        cfg.name = "INSECURE coherent direct-slot end-to-end arithmetic fixture";
        let plan = PublicRefreshSourcePlan::new(&cfg, 8, 2, 4, 2).unwrap();
        let mut rng = ShadowHarvester::with_seed(0x4453_5048_4153_45);
        let (client, source_eval) = plan.generate_with_rng(&mut rng, 1 << 24).unwrap();
        cfg.n = 32;
        cfg.primes.push(957745601);
        cfg.t = 257 * 257;
        let high = RNSFHEContext::try_new(&cfg).unwrap();
        cfg.t = 257;
        let low = RNSFHEContext::try_new(&cfg).unwrap();
        let keys = high.generate_keys(&mut rng);
        let bank = DirectSlotPhaseKey::generate_with_rng(
            &client,
            &high,
            &low,
            &keys.secret_key,
            2,
            1 << 24,
            &mut rng,
        )
        .unwrap();
        let relin = high
            .try_exact_evaluator()
            .unwrap()
            .generate_hybrid_gadget_key_with_rng(&keys.secret_key, &mut rng);
        let message = [0, 1, 256, 17, 129, 128, 3, 251];
        let input = source_eval.encrypt_with_rng(&message, &mut rng).unwrap();
        let square = source_eval.multiply(&input, &input).unwrap();
        for work in [&input, &square] {
            let expected = client.decrypt_work(work).unwrap();
            let source = source_eval.prepare(work).unwrap();
            let phases = bank.evaluate(&source, &high, &low).unwrap();
            assert_eq!(phases.lineage(), source.certificate().lineage());
            let high_values = observe_slots(&high, phases.high(), &keys.secret_key);
            let low_values = observe_slots(&low, phases.low(), &keys.secret_key);
            for (&a, &b) in high_values.iter().zip(&low_values) {
                assert_eq!(a % 257, b);
                assert!(signed(b, 257).unsigned_abs() <= phases.radius());
                let x = signed(a, 257 * 257);
                let rho = signed(b, 257);
                assert!(x.unsigned_abs() <= phases.value_bound());
                assert_eq!((x - rho) % 257, 0);
                assert!(((x - rho) / 257).unsigned_abs() <= phases.quotient_radius());
            }
            let circuit = SplitDigitEvaluator::new(
                &high,
                &low,
                phases.radius() as usize,
                phases.error_bound(),
                phases.error_bound(),
            )
            .unwrap();
            let carry = circuit
                .evaluate(phases.high(), phases.low(), &relin)
                .unwrap();
            let observed_carry = observe_slots(&low, &carry, &keys.secret_key);
            for ((&x, &rho), &k) in high_values.iter().zip(&low_values).zip(&observed_carry) {
                assert_eq!(
                    signed(k, 257),
                    (signed(x, 257 * 257) - signed(rho, 257)) / 257
                );
                assert!(signed(k, 257).unsigned_abs() <= phases.quotient_radius());
            }
            let corrected = low.add(&carry, phases.affine());
            let result = observe_slots(&low, &corrected, &keys.secret_key);
            assert_eq!(
                result,
                repeated_antiperiodic(
                    &expected.iter().map(|&v| signed(v, 257)).collect::<Vec<_>>(),
                    257
                )
            );
            // Both encrypted carry and affine terms are load-bearing.
            assert_ne!(observe_slots(&low, &carry, &keys.secret_key), result);
            assert_ne!(
                observe_slots(&low, phases.affine(), &keys.secret_key),
                result
            );
        }
        let (other, other_eval) = plan.generate_with_rng(&mut rng, 1 << 24).unwrap();
        let other_input = other_eval.encrypt_with_rng(&message, &mut rng).unwrap();
        let other_source = other_eval.prepare(&other_input).unwrap();
        assert_ne!(client.family_id(), other.family_id());
        assert!(bank.evaluate(&other_source, &high, &low).is_err());
        assert!(DirectSlotPhaseKey::generate_with_rng(
            &client,
            &high,
            &low,
            &keys.secret_key,
            2,
            0,
            &mut rng
        )
        .is_err());
    }
}
