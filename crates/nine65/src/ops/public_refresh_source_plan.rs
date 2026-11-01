use super::*;

/// A deterministic arithmetic plan for dense-work to sparse-source conversion.
/// This research plan does not attest sparse-secret or joint-key security.
#[derive(Clone)]
pub struct PublicRefreshSourcePlan {
    pub(super) work: FHEConfig,
    pub(super) source: FHEConfig,
    pub(super) source_weight: usize,
    pub(super) base_bits: u32,
    pub(super) switch_error: U512,
    pub(super) work_noise: PolynomialNoise,
    switch_key_bytes: usize,
}

impl PublicRefreshSourcePlan {
    pub fn new(
        work: &FHEConfig,
        source_n: usize,
        source_lanes: usize,
        source_weight: usize,
        base_bits: u32,
    ) -> Result<Self, SourceError> {
        if !source_n.is_power_of_two()
            || source_n < work.n
            || source_n > 65536
            || work.n < 2
            || !work.n.is_power_of_two()
            || source_n % work.n != 0
            || source_lanes < 2
            || source_lanes > work.primes.len()
            || source_weight == 0
            || source_weight > source_n
            || source_weight % 2 != 0
            || !(1..=16).contains(&base_bits)
        {
            return Err(SourceError::Parameters(
                "invalid source geometry, weight or gadget base",
            ));
        }
        let work_noise = PolynomialNoise::new(work)?;
        let mut source = work.clone();
        source.n = source_n;
        source.primes.truncate(source_lanes);
        source.security_bits = 0;
        source.name = "RESEARCH sparse public-refresh source (not security admitted)";
        // Validate actual rings and exact arithmetic before allocating keys.
        for config in [work, &source] {
            for &q in &config.primes {
                crate::arithmetic::NTTEngine::try_new(q, config.n)
                    .map_err(|_| SourceError::Parameters("prime does not support the ring"))?;
            }
            ExactMulPlan::new(&config.primes, config.n, config.t)?;
        }
        let digits: usize = source
            .primes
            .iter()
            .map(|q| (64 - q.leading_zeros()).div_ceil(base_bits) as usize)
            .sum();
        let switch_error = U512::from_u128(
            source.t as u128
                * source.n as u128
                * source.eta as u128
                * ((1u128 << base_bits) - 1)
                * digits as u128,
        );
        let switch_key_bytes = digits
            .checked_mul(2)
            .and_then(|n| n.checked_mul(source_lanes))
            .and_then(|n| n.checked_mul(source_n))
            .and_then(|n| n.checked_mul(std::mem::size_of::<u64>()))
            .ok_or(SourceError::Parameters("source key allocation overflow"))?;
        Ok(Self {
            work: work.clone(),
            source,
            source_weight,
            base_bits,
            switch_error,
            work_noise,
            switch_key_bytes,
        })
    }

    pub fn work_config(&self) -> &FHEConfig {
        &self.work
    }
    pub fn source_config(&self) -> &FHEConfig {
        &self.source
    }
    pub fn source_weight(&self) -> usize {
        self.source_weight
    }
    pub fn gadget_base_bits(&self) -> u32 {
        self.base_bits
    }
    pub fn switch_key_bytes(&self) -> usize {
        self.switch_key_bytes
    }

    /// Key-free forecast for a returned bound, one full-polynomial square,
    /// and the next source conversion. This creates no ciphertext proof.
    pub(crate) fn next_square_source_radius(&self, returned: U512) -> Result<u64, SourceError> {
        // Validate before multiplication: numeric forecasts may receive any
        // U512, unlike immutable producer-issued working ciphertext bounds.
        self.work_noise.admit(returned)?;
        let squared = self.work_noise.multiply(returned, returned)?;
        let (_, source_bound) = self.bounds(squared)?;
        Ok(source_residual_radius(
            source_bound,
            U512::product_u64s(&self.source.primes),
            self.source.t,
            self.source_weight,
        ))
    }

    pub(super) fn bounds(&self, incoming: U512) -> Result<(Vec<U512>, U512), SourceError> {
        self.work_noise.admit(incoming)?;
        let mut v = incoming;
        let mut drops = Vec::new();
        for index in (self.source.primes.len()..self.work.primes.len()).rev() {
            let prime = self.work.primes[index];
            // Rounding still occurs under the original DENSE work key.
            v = v
                .add(U512::from_u64(prime - 1))
                .div_u64(prime)
                .add(U512::from_u128(
                    (self.work.t as u128 * (self.work.n + 1) as u128).div_ceil(2),
                ));
            ensure_decode(v, U512::product_u64s(&self.work.primes[..index]))?;
            drops.push(v);
        }
        // Ring embedding inserts zeros and preserves the phase bound. The
        // switch error uses the FULL source ring, not its sparse secret norm.
        v = v.add(self.switch_error);
        ensure_decode(v, U512::product_u64s(&self.source.primes))?;
        Ok((drops, v))
    }
}

#[derive(Clone)]
pub(super) struct PolynomialNoise {
    q: U512,
    n: u128,
    t: u128,
    eta: u128,
    remainder: u128,
    switch: u128,
}

impl PolynomialNoise {
    fn new(config: &FHEConfig) -> Result<Self, SourceError> {
        // With these public limits Q<2^256, every admitted V<Q/2,
        // the multiplication factor is below 2^66, and all fixed deposits
        // fit u128. Consequently no U512 operation below can wrap.
        if config.n > 65536
            || config.t < 3
            || config.t > u32::MAX as u64
            || config.t % 2 == 0
            || config.eta > u32::MAX as usize
            || config.primes.len() < 2
            || config.primes.len() > 8
            || config.primes.iter().any(|&q| q <= config.t || q % 2 == 0)
            || config
                .primes
                .iter()
                .map(|q| 64 - q.leading_zeros())
                .sum::<u32>()
                > 256
        {
            return Err(SourceError::Parameters(
                "unsupported polynomial noise parameters",
            ));
        }
        let q = U512::product_u64s(&config.primes);
        let n = config.n as u128;
        let t = config.t as u128;
        let eta = config.eta as u128;
        let digits: u128 = config
            .primes
            .iter()
            .map(|q| (64 - q.leading_zeros()).div_ceil(HYBRID_BASE_BITS) as u128)
            .sum();
        Ok(Self {
            q,
            n,
            t,
            eta,
            remainder: q.mod_u64(config.t) as u128,
            switch: n * eta * ((1u128 << HYBRID_BASE_BITS) - 1) * digits,
        })
    }

    pub(super) fn admit(&self, value: U512) -> Result<U512, SourceError> {
        ensure_decode(value, self.q)?;
        Ok(value)
    }

    pub(super) fn fresh(&self) -> Result<U512, SourceError> {
        self.admit(U512::from_u128(
            self.t * (2 * self.n + 1) * self.eta + self.remainder * (self.t - 1),
        ))
    }

    pub(super) fn add(&self, a: U512, b: U512) -> Result<U512, SourceError> {
        self.admit(a.add(b))
    }

    pub(super) fn multiply(&self, a: U512, b: U512) -> Result<U512, SourceError> {
        // Units are v=t*(c0+c1*s-Q*k)-Q*m for centered message m.
        // The full-polynomial message l1 bound is N*(t-1)/2.
        // Centered components and 2V<Q also give integer |k|<=N/2+1;
        // retain the t*(k_a*v_b+k_b*v_a) cross terms. Finally,
        // N*Va*Vb/Q <= (N/2)*min(Va,Vb) for admitted operands.
        let factor = self.n * (self.t - 1) / 2 + self.n * self.t * (self.n / 2 + 1);
        let smaller = if words(a) < words(b) { a } else { b };
        let rounding = (self.t * (1 + self.n + self.n * self.n)).div_ceil(2);
        self.admit(
            a.add(b)
                .mul_u128(factor)
                .add(smaller.mul_u128(self.n / 2))
                .add(U512::from_u128(rounding + self.t * self.switch)),
        )
    }
}

pub(super) fn ensure_decode(v: U512, q: U512) -> Result<(), SourceError> {
    // Compare before doubling so even a malformed wide bound cannot wrap.
    if words(v) > words(q.div_u64(2)) {
        return Err(SourceError::NoiseExhausted);
    }
    Ok(())
}
