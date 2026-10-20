//! Deterministic bounds for the scalar main-Q evaluator.
//!
//! The integer unit is `v = t*(c0+c1*s-Q*k)-Q*m`, where `m` is the
//! centered scalar plaintext. Correct decoding follows from `2*||v|| < Q`.
//! No secret-dependent error observation is used. See BOUND_CONTRACT.md.

use crate::arithmetic::rns::U512;
use crate::params::FHEConfig;

fn words(v: U512) -> (u128, u128, u128, u128) {
    (v.d3, v.d2, v.d1, v.d0)
}

fn bits(v: U512) -> u32 {
    for (offset, limb) in [(384, v.d3), (256, v.d2), (128, v.d1), (0, v.d0)] {
        if limb != 0 {
            return offset + 128 - limb.leading_zeros();
        }
    }
    0
}

/// A bound issued only by an admitted producer. Units are t times ideal-scale
/// phase error, not millibits and not error relative to floor(Q/t).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedNoiseBound {
    scaled_error: U512,
}

impl CertifiedNoiseBound {
    /// Exact nonnegative bound, in little-endian 128-bit words.
    pub fn scaled_error_words(&self) -> [u128; 4] {
        let v = self.scaled_error;
        [v.d0, v.d1, v.d2, v.d3]
    }
}

#[derive(Clone)]
pub(crate) struct ScalarNoiseModel {
    q: U512,
    n: u128,
    t: u128,
    eta: u128,
    remainder: u128,
    switch_error: u128,
}

impl ScalarNoiseModel {
    pub(crate) fn new(
        config: &FHEConfig,
        digits: usize,
        base_bits: u32,
    ) -> Result<Self, &'static str> {
        // Public metadata limits prove that every intermediate below fits in
        // 512 bits: admitted bounds <2^256, growth factors <2^100, and deposits
        // <2^160. Reject before any fixed-width product can wrap.
        if config.n < 2
            || !config.n.is_power_of_two()
            || config.n > 65536
            || config.t < 3
            || config.t % 2 == 0
            || config.t > u32::MAX as u64
            || config.eta > u32::MAX as usize
            || digits > u32::MAX as usize
            || base_bits > 16
            || config.primes.is_empty()
            || config.primes.len() > 8
            || config.primes.iter().any(|&q| q <= config.t || q % 2 == 0)
            || config
                .primes
                .iter()
                .map(|q| 64 - q.leading_zeros())
                .sum::<u32>()
                > 256
        {
            return Err("unsupported certified-bound parameters");
        }
        let q = U512::product_u64s(&config.primes);
        let n = config.n as u128;
        let t = config.t as u128;
        let eta = config.eta as u128;
        let switch_error = n * eta * ((1u128 << base_bits) - 1) * digits as u128;
        Ok(Self {
            q,
            n,
            t,
            eta,
            remainder: q.mod_u64(config.t) as u128,
            switch_error,
        })
    }

    fn admit(&self, scaled_error: U512) -> Result<CertifiedNoiseBound, &'static str> {
        if words(scaled_error.mul_u128(2)) >= words(self.q) {
            return Err("certified phase bound exhausted before operation");
        }
        Ok(CertifiedNoiseBound { scaled_error })
    }

    pub(crate) fn fresh(&self) -> Result<CertifiedNoiseBound, &'static str> {
        // pk error*u + e1 + e2*s; u,s ternary. The actual encryptor encodes
        // nonnegative m with Delta=floor(Q/t), hence the rho*(t-1) correction.
        self.admit(U512::from_u128(
            self.t * (2 * self.n + 1) * self.eta + self.remainder * (self.t - 1),
        ))
    }

    pub(crate) fn add(
        &self,
        a: &CertifiedNoiseBound,
        b: &CertifiedNoiseBound,
    ) -> Result<CertifiedNoiseBound, &'static str> {
        self.admit(a.scaled_error.add(b.scaled_error))
    }

    pub(crate) fn scalar(
        &self,
        a: &CertifiedNoiseBound,
        scalar: i64,
    ) -> Result<CertifiedNoiseBound, &'static str> {
        self.admit(a.scaled_error.mul_u128(scalar.unsigned_abs() as u128))
    }

    pub(crate) fn add_plain(
        &self,
        a: &CertifiedNoiseBound,
        scalar: i64,
    ) -> Result<CertifiedNoiseBound, &'static str> {
        self.admit(a.scaled_error.add(U512::from_u128(
            self.remainder * scalar.unsigned_abs() as u128,
        )))
    }

    pub(crate) fn multiply(
        &self,
        a: &CertifiedNoiseBound,
        b: &CertifiedNoiseBound,
    ) -> Result<CertifiedNoiseBound, &'static str> {
        // Centered component lifts give |K| <= N/2+1 whenever 2V<Q.
        // Retain t*(K_a*v_b+K_b*v_a) as well as the plaintext cross terms.
        let factor = (self.t - 1) / 2 + self.n * self.t * (self.n / 2 + 1);
        let linear = a.scaled_error.add(b.scaled_error).mul_u128(factor);
        let smaller = if words(a.scaled_error) < words(b.scaled_error) {
            a.scaled_error
        } else {
            b.scaled_error
        };
        // N*Va*Vb/Q <= (N/2)*min(Va,Vb), since both operands were admitted.
        let quadratic = smaller.mul_u128(self.n / 2);
        let rounding = (self.t * (1 + self.n + self.n * self.n)).div_ceil(2);
        let deposit =
            U512::from_u128(rounding).add(U512::from_u128(self.switch_error).mul_u128(self.t));
        self.admit(linear.add(quadratic).add(deposit))
    }

    pub(crate) fn remaining_millibits(&self, bound: &CertifiedNoiseBound) -> i64 {
        // A conservative display only. Admission compares the exact integers.
        i64::from(bits(self.q).saturating_sub(bits(bound.scaled_error) + 2)) * 1000
    }
}
