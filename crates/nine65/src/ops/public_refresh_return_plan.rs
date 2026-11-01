use super::*;
use crate::ops::exact_mul::ExactMulPlan;
use crate::params::FHEConfig;

/// Key-free arithmetic envelope for the dense-key return stage. This plan
/// computes bounds and allocation size; it is not a ciphertext certificate.
#[derive(Clone)]
pub(crate) struct ReturnNoisePlan {
    pub(super) boot_primes: Vec<u64>,
    pub(super) work_n: usize,
    pub(super) base_bits: u32,
    work_lanes: usize,
    t: u64,
    q: U1024,
    drop_rounding: U1024,
    switch_error: U1024,
    switch_key_bytes: usize,
}

impl ReturnNoisePlan {
    pub(crate) fn new(work: &FHEConfig, boot: &FHEConfig, base_bits: u32) -> Nine65Result<Self> {
        if work.n < 2
            || !work.n.is_power_of_two()
            || !boot.n.is_power_of_two()
            || boot.n < work.n
            || boot.n % work.n != 0
            || boot.t != work.t
            || !(1..=16).contains(&base_bits)
            || work.primes.is_empty()
            || !boot.primes.starts_with(&work.primes)
            || boot.primes.iter().any(|&q| q <= boot.t || q % 2 == 0)
        {
            return Err(refused(
                "return requires a matching work prefix, scale and ring embedding",
            ));
        }
        // The reduced-ring arithmetic certificate supplies the actual radix
        // digits before any context, key or ciphertext allocation.
        let arithmetic =
            ExactMulPlan::new_with_gadget_base_bits(&work.primes, boot.n, work.t, base_bits)
                .map_err(|e| refused(format!("return arithmetic plan: {e:?}")))?;
        let digits: usize = arithmetic.certificate().digits_per_lane.iter().sum();
        let switch_error = [
            work.t,
            boot.n as u64,
            work.eta as u64,
            (1u64 << base_bits) - 1,
            digits as u64,
        ]
        .into_iter()
        .try_fold(U1024::ONE, |bound, factor| {
            checked(bound.checked_mul_u64(factor))
        })?;
        let switch_key_bytes = digits
            .checked_mul(2)
            .and_then(|n| n.checked_mul(work.primes.len()))
            .and_then(|n| n.checked_mul(boot.n))
            .and_then(|n| n.checked_mul(std::mem::size_of::<u64>()))
            .ok_or_else(|| refused("public return key size overflow"))?;
        Ok(Self {
            boot_primes: boot.primes.clone(),
            work_n: work.n,
            base_bits,
            work_lanes: work.primes.len(),
            t: work.t,
            q: checked(U1024::checked_product_u64s(&work.primes))?,
            drop_rounding: U1024::from_u128((work.t as u128 * (boot.n + 1) as u128).div_ceil(2)),
            switch_error,
            switch_key_bytes,
        })
    }

    /// Raw public switch-key coefficient payload; excludes container overhead.
    pub(crate) fn switch_key_bytes(&self) -> usize {
        self.switch_key_bytes
    }

    /// V=p*E after every public drop and the exact-radix key switch. Projection
    /// selects coefficients and does not increase their infinity bound.
    pub(crate) fn output_bound(&self, ideal_error: U1024) -> Nine65Result<U512> {
        let mut scaled = checked(ideal_error.checked_mul_u64(self.t))?;
        for &prime in self.boot_primes[self.work_lanes..].iter().rev() {
            let (quotient, remainder) = scaled
                .div_mod_u64(prime)
                .ok_or_else(|| refused("public return drop modulus is zero"))?;
            scaled = checked(quotient.checked_add(U1024::from_u64(u64::from(remainder != 0))))?;
            scaled = checked(scaled.checked_add(self.drop_rounding))?;
        }
        scaled = checked(scaled.checked_add(self.switch_error))?;
        if scaled > self.q.shr1() || scaled.limbs[8..].iter().any(|&v| v != 0) {
            return Err(refused("public return cannot certify working decryption"));
        }
        let pair = |i| scaled.limbs[i] as u128 | ((scaled.limbs[i + 1] as u128) << 64);
        Ok(U512 {
            d0: pair(0),
            d1: pair(2),
            d2: pair(4),
            d3: pair(6),
        })
    }
}
