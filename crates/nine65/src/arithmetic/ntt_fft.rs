//! NTT FFT - Cooley-Tukey O(N log N) implementation.
//!
//! This is the default NTT engine. The O(N^2) DFT reference implementation
//! in `ntt.rs` can be selected with `--features reference_ntt` for validation.
//! All butterfly addresses and twiddle indices depend only on public parameters.

#![allow(clippy::needless_range_loop)]

use super::montgomery::MontgomeryContext;
use super::persistent_montgomery::PersistentMontgomery;
use crate::errors::{Nine65Error, Nine65Result};
use crate::params::is_prime;

/// FFT-based NTT engine.
#[derive(Clone)]
pub struct NTTEngineFFT {
    pub mont: MontgomeryContext,
    pub pm: PersistentMontgomery,
    pub q: u64,
    pub n: usize,
    log_n: usize,
    pub psi: u64,
    pub omega: u64,
    n_inv_mont: u64,
    twiddles_fwd: Vec<u64>,
    twiddles_inv: Vec<u64>,
    // Only the textbook reference multiply in the tests reads these.
    #[cfg_attr(not(test), allow(dead_code))]
    psi_powers_mont: Vec<u64>,
    #[cfg_attr(not(test), allow(dead_code))]
    psi_inv_powers_mont: Vec<u64>,
    /// `psi^bitrev(k)` in Montgomery form: twiddles for the fused negacyclic
    /// transform (no data bit-reversal, no separate psi twist passes).
    psi_br_mont: Vec<u64>,
    /// `psi^-bitrev(k)` in Montgomery form, for the fused inverse.
    psi_inv_br_mont: Vec<u64>,
    pub psi_inv: u64,
    pub omega_inv: u64,
    pub n_inv: u64,
    pub psi_powers: Vec<u64>,
    pub psi_inv_powers: Vec<u64>,
    pub omega_powers: Vec<u64>,
    pub omega_inv_powers: Vec<u64>,
}

impl NTTEngineFFT {
    /// Construct an NTT engine or panic on invalid public parameters.
    pub fn new(q: u64, n: usize) -> Self {
        Self::try_new(q, n).expect("NTT FFT configuration invalid")
    }

    /// Construct an NTT engine after enforcing the CLASS-F field conditions.
    pub fn try_new(q: u64, n: usize) -> Nine65Result<Self> {
        if q >= (1u64 << 63) {
            return Err(Nine65Error::NTTConfigError {
                message: format!("NTT modulus exceeds the Montgomery range below 2^63: {q}"),
            });
        }
        if !n.is_power_of_two() {
            return Err(Nine65Error::NTTConfigError {
                message: format!("N must be a nonzero power of 2, got {n}"),
            });
        }
        if !is_prime(q) {
            return Err(Nine65Error::NTTConfigError {
                message: format!("CLASS-F NTT modulus must be prime, got {q}"),
            });
        }

        let two_n = n
            .checked_mul(2)
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| Nine65Error::NTTConfigError {
                message: format!("2N does not fit in u64 for N={n}"),
            })?;
        if (q - 1) % two_n != 0 {
            return Err(Nine65Error::NTTConfigError {
                message: format!("q-1 ({}) must be divisible by 2N ({two_n})", q - 1),
            });
        }

        let log_n = n.trailing_zeros() as usize;
        let mont = MontgomeryContext::new(q);
        let pm = PersistentMontgomery::new(q);
        let psi = Self::try_find_primitive_root(q, two_n as usize)?;
        let omega = mod_pow(psi, 2, q);
        let omega_inv = mod_inverse(omega, q);
        let psi_inv = mod_inverse(psi, q);
        let n_inv = mod_inverse(n as u64, q);
        let n_inv_mont = mont.to_montgomery(n_inv);
        let twiddles_fwd = Self::compute_twiddles(&mont, omega, n);
        let twiddles_inv = Self::compute_twiddles(&mont, omega_inv, n);
        // Setup over public values: one iterative pass per table (O(n)),
        // not a square-and-multiply `mod_pow` per entry.
        let psi_pows = power_table(psi, n, q);
        let psi_inv_pows = power_table(psi_inv, n, q);
        let omega_pows = power_table(omega, n, q);
        let omega_inv_pows = power_table(omega_inv, n, q);
        let psi_powers_mont: Vec<u64> = psi_pows.iter().map(|&v| mont.to_montgomery(v)).collect();
        let psi_inv_powers_mont: Vec<u64> = psi_inv_pows
            .iter()
            .map(|&v| mont.to_montgomery(v))
            .collect();
        let psi_br_mont: Vec<u64> = (0..n)
            .map(|k| mont.to_montgomery(psi_pows[Self::bit_reverse(k, log_n)]))
            .collect();
        let psi_inv_br_mont: Vec<u64> = (0..n)
            .map(|k| mont.to_montgomery(psi_inv_pows[Self::bit_reverse(k, log_n)]))
            .collect();

        Ok(Self {
            mont,
            pm,
            q,
            n,
            log_n,
            psi,
            omega,
            n_inv_mont,
            twiddles_fwd,
            twiddles_inv,
            psi_powers_mont,
            psi_inv_powers_mont,
            psi_br_mont,
            psi_inv_br_mont,
            psi_inv,
            omega_inv,
            n_inv,
            psi_powers: psi_pows,
            psi_inv_powers: psi_inv_pows,
            omega_powers: omega_pows,
            omega_inv_powers: omega_inv_pows,
        })
    }

    fn compute_twiddles(mont: &MontgomeryContext, omega: u64, n: usize) -> Vec<u64> {
        let mut twiddles = vec![0_u64; n];
        let mut power = 1_u64;
        for twiddle in &mut twiddles {
            *twiddle = mont.to_montgomery(power);
            power = ((power as u128 * omega as u128) % mont.q as u128) as u64;
        }
        twiddles
    }

    /// Variable-time setup operation over public parameters only.
    fn try_find_primitive_root(q: u64, order: usize) -> Nine65Result<u64> {
        let exponent = (q - 1) / order as u64;
        for generator in 2..q {
            let candidate = mod_pow(generator, exponent, q);
            let half = mod_pow(candidate, (order / 2) as u64, q);
            if half == q - 1 && mod_pow(candidate, order as u64, q) == 1 {
                return Ok(candidate);
            }
        }
        Err(Nine65Error::NTTConfigError {
            message: format!("no primitive root found for q={q}, order={order}"),
        })
    }

    #[inline]
    fn bit_reverse(value: usize, bits: usize) -> usize {
        value.reverse_bits() >> (usize::BITS as usize - bits)
    }

    fn bit_reverse_permute(&self, values: &mut [u64]) {
        for index in 0..self.n {
            let reversed = Self::bit_reverse(index, self.log_n);
            if index < reversed {
                values.swap(index, reversed);
            }
        }
    }

    /// Forward NTT using Cooley-Tukey butterfly (in-place, Montgomery form)
    ///
    /// Control flow, addresses, and twiddle indices are public.
    ///
    /// Complexity: O(N log N) vs O(N²) for DFT
    ///
    /// (This used to take an extra `shadow: &mut Option<Vec<u64>>` parameter
    /// so a caller could capture each twiddle multiply's discarded Montgomery
    /// quotient. Its only feeder was SBNI's entropy harvest; SBNI's removal
    /// left every remaining call passing `&mut None`, so the capture branch
    /// was permanently unreachable. Removed per issue #68 — see
    /// docs/LADDER_REMOVAL.md §6.3 item 4.)
    pub fn ntt_inplace(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.n);
        self.bit_reverse_permute(values);

        let mut width = 1_usize;
        while width < self.n {
            let half = width;
            width *= 2;
            let twiddle_step = self.n / width;

            for block in (0..self.n).step_by(width) {
                let mut twiddle_index = 0_usize;
                for offset in 0..half {
                    let upper_index = block + offset;
                    let lower_index = upper_index + half;
                    let upper = values[upper_index];
                    let product =
                        self.twiddles_fwd[twiddle_index] as u128 * values[lower_index] as u128;
                    let lower = self.mont.montgomery_reduce(product);

                    values[upper_index] = self.mont.montgomery_add(upper, lower);
                    values[lower_index] = self.mont.montgomery_sub(upper, lower);
                    twiddle_index += twiddle_step;
                }
            }
        }
    }

    /// Inverse NTT. Control flow, addresses, and twiddle indices are public.
    pub fn intt_inplace(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.n);
        self.bit_reverse_permute(values);

        let mut width = 1_usize;
        while width < self.n {
            let half = width;
            width *= 2;
            let twiddle_step = self.n / width;

            for block in (0..self.n).step_by(width) {
                let mut twiddle_index = 0_usize;
                for offset in 0..half {
                    let upper_index = block + offset;
                    let lower_index = upper_index + half;
                    let upper = values[upper_index];
                    let lower = self
                        .mont
                        .montgomery_mul(self.twiddles_inv[twiddle_index], values[lower_index]);
                    values[upper_index] = self.mont.montgomery_add(upper, lower);
                    values[lower_index] = self.mont.montgomery_sub(upper, lower);
                    twiddle_index += twiddle_step;
                }
            }
        }

        for value in values {
            *value = self.mont.montgomery_mul(*value, self.n_inv_mont);
        }
    }

    pub fn ntt(&self, values: &[u64]) -> Vec<u64> {
        let mut result = values.to_vec();
        for value in &mut result {
            *value = self.mont.to_montgomery(*value);
        }
        self.ntt_inplace(&mut result);
        for value in &mut result {
            *value = self.mont.from_montgomery(*value);
        }
        result
    }

    pub fn intt(&self, values: &[u64]) -> Vec<u64> {
        let mut result = values.to_vec();
        for value in &mut result {
            *value = self.mont.to_montgomery(*value);
        }
        self.intt_inplace(&mut result);
        for value in &mut result {
            *value = self.mont.from_montgomery(*value);
        }
        result
    }

    pub fn multiply(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        let mut output = Vec::with_capacity(self.n);
        self.multiply_into(left, right, &mut output);
        output
    }

    pub fn multiply_into(&self, left: &[u64], right: &[u64], output: &mut Vec<u64>) {
        debug_assert_eq!(left.len(), self.n);
        debug_assert_eq!(right.len(), self.n);

        output.clear();
        output.reserve(self.n.saturating_sub(output.capacity()));
        output.extend(left.iter().map(|&v| self.mont.to_montgomery(v)));
        let mut right_work: Vec<u64> = right.iter().map(|&v| self.mont.to_montgomery(v)).collect();
        self.negacyclic_product_mont(output, &mut right_work);
        for value in output.iter_mut() {
            *value = self.mont.from_montgomery(*value);
        }
    }

    /// `(sum_i left[i] * right_a[i], sum_i left[i] * right_b[i])` in the
    /// negacyclic ring, plain-domain in and out, bit-identical to summing the
    /// individual [`Self::multiply`] results mod `q`.
    ///
    /// The transform is linear, so each `left[i]` is transformed ONCE (and
    /// shared by both right operands), the products accumulate pointwise in
    /// the transform domain, and only two inverse transforms run at the end:
    /// `3k + 2` transforms for `k` terms instead of `6k` for `2k` separate
    /// products. This is the shape of gadget relinearization
    /// (`sum_i digit_i * rlk0_i`, `sum_i digit_i * rlk1_i`). All addresses and
    /// twiddle indices are public.
    pub fn multiply_sum_pair(
        &self,
        left: &[&[u64]],
        right_a: &[&[u64]],
        right_b: &[&[u64]],
    ) -> (Vec<u64>, Vec<u64>) {
        assert_eq!(left.len(), right_a.len(), "term count mismatch");
        assert_eq!(left.len(), right_b.len(), "term count mismatch");
        let mut acc_a = vec![0_u64; self.n];
        let mut acc_b = vec![0_u64; self.n];
        let mut work_l = Vec::with_capacity(self.n);
        let mut work_r = Vec::with_capacity(self.n);
        for ((l, ra), rb) in left.iter().zip(right_a).zip(right_b) {
            debug_assert_eq!(l.len(), self.n);
            work_l.clear();
            work_l.extend(l.iter().map(|&v| self.mont.to_montgomery(v)));
            self.negacyclic_forward_br(&mut work_l);
            for (right, acc) in [(*ra, &mut acc_a), (*rb, &mut acc_b)] {
                debug_assert_eq!(right.len(), self.n);
                work_r.clear();
                work_r.extend(right.iter().map(|&v| self.mont.to_montgomery(v)));
                self.negacyclic_forward_br(&mut work_r);
                for ((a, &x), &y) in acc.iter_mut().zip(&work_l).zip(&work_r) {
                    *a = self.mont.montgomery_add(*a, self.mont.montgomery_mul(x, y));
                }
            }
        }
        for acc in [&mut acc_a, &mut acc_b] {
            self.negacyclic_inverse_br(acc);
            for value in acc.iter_mut() {
                *value = self.mont.from_montgomery(*value);
            }
        }
        (acc_a, acc_b)
    }

    pub fn multiply_ct(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        self.multiply(left, right)
    }

    pub fn multiply_persistent(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        let mut output = Vec::with_capacity(self.n);
        self.multiply_persistent_into(left, right, &mut output);
        output
    }

    pub fn multiply_persistent_into(&self, left: &[u64], right: &[u64], output: &mut Vec<u64>) {
        debug_assert_eq!(left.len(), self.n);
        debug_assert_eq!(right.len(), self.n);

        output.clear();
        output.reserve(self.n.saturating_sub(output.capacity()));
        output.extend_from_slice(left);
        let mut right_work = right.to_vec();
        self.negacyclic_product_mont(output, &mut right_work);
    }

    /// Negacyclic product of two Montgomery-form polynomials, result left in
    /// `left` (also Montgomery form): fused forward transforms (input in
    /// natural order, output bit-reversed), pointwise product, fused inverse
    /// (input bit-reversed, output natural). The psi twists live inside the
    /// twiddle tables, so there is no data bit-reversal pass and no separate
    /// pre/post-twist loop. All addresses and twiddle indices are public.
    fn negacyclic_product_mont(&self, left: &mut [u64], right: &mut [u64]) {
        self.negacyclic_forward_br(left);
        self.negacyclic_forward_br(right);
        for (l, r) in left.iter_mut().zip(right.iter()) {
            *l = self.mont.montgomery_mul(*l, *r);
        }
        self.negacyclic_inverse_br(left);
    }

    /// Cooley-Tukey negacyclic forward transform (Longa-Naehrig): natural
    /// order in, bit-reversed order out, twiddles `psi^bitrev(k)`.
    fn negacyclic_forward_br(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.n);
        let mut t = self.n;
        let mut m = 1_usize;
        while m < self.n {
            t >>= 1;
            for i in 0..m {
                let twiddle = self.psi_br_mont[m + i];
                let start = 2 * i * t;
                let (low, high) = values[start..start + 2 * t].split_at_mut(t);
                for (u_ref, v_ref) in low.iter_mut().zip(high.iter_mut()) {
                    let u = *u_ref;
                    let v = self.mont.montgomery_mul(*v_ref, twiddle);
                    *u_ref = self.mont.montgomery_add(u, v);
                    *v_ref = self.mont.montgomery_sub(u, v);
                }
            }
            m <<= 1;
        }
    }

    /// Gentleman-Sande negacyclic inverse transform: bit-reversed order in,
    /// natural order out, twiddles `psi^-bitrev(k)`, then the `n^-1` scale.
    fn negacyclic_inverse_br(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.n);
        let mut t = 1_usize;
        let mut m = self.n;
        while m > 1 {
            let half = m >> 1;
            let mut start = 0_usize;
            for i in 0..half {
                let twiddle = self.psi_inv_br_mont[half + i];
                let (low, high) = values[start..start + 2 * t].split_at_mut(t);
                for (u_ref, v_ref) in low.iter_mut().zip(high.iter_mut()) {
                    let u = *u_ref;
                    let v = *v_ref;
                    *u_ref = self.mont.montgomery_add(u, v);
                    *v_ref = self
                        .mont
                        .montgomery_mul(self.mont.montgomery_sub(u, v), twiddle);
                }
                start += 2 * t;
            }
            t <<= 1;
            m = half;
        }
        for value in values.iter_mut() {
            *value = self.mont.montgomery_mul(*value, self.n_inv_mont);
        }
    }

    #[inline]
    pub fn add(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        debug_assert_eq!(left.len(), self.n);
        debug_assert_eq!(right.len(), self.n);
        left.iter()
            .zip(right)
            .map(|(a, b)| self.mont.montgomery_add(*a, *b))
            .collect()
    }

    #[inline]
    pub fn sub(&self, left: &[u64], right: &[u64]) -> Vec<u64> {
        debug_assert_eq!(left.len(), self.n);
        debug_assert_eq!(right.len(), self.n);
        left.iter()
            .zip(right)
            .map(|(a, b)| self.mont.montgomery_sub(*a, *b))
            .collect()
    }

    #[inline]
    pub fn neg(&self, values: &[u64]) -> Vec<u64> {
        values
            .iter()
            .map(|value| self.mont.montgomery_neg(*value))
            .collect()
    }

    #[inline]
    pub fn scalar_mul(&self, values: &[u64], scalar: u64) -> Vec<u64> {
        let scalar_mont = self.mont.to_montgomery(scalar);
        values
            .iter()
            .map(|value| {
                let value_mont = self.mont.to_montgomery(*value);
                self.mont
                    .from_montgomery(self.mont.montgomery_mul(value_mont, scalar_mont))
            })
            .collect()
    }
}

/// `[1, base, base^2, ..., base^(n-1)] mod q`, one multiply per entry.
/// Variable-time setup helper over public values.
fn power_table(base: u64, n: usize, q: u64) -> Vec<u64> {
    let mut table = Vec::with_capacity(n);
    let mut power = 1_u64 % q;
    for _ in 0..n {
        table.push(power);
        power = ((power as u128 * base as u128) % q as u128) as u64;
    }
    table
}

/// Variable-time setup helper over public values.
fn mod_pow(base: u64, exponent: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    let mut result = 1_u64;
    let mut base = base % modulus;
    let mut exponent = exponent;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = ((result as u128 * base as u128) % modulus as u128) as u64;
        }
        exponent >>= 1;
        base = ((base as u128 * base as u128) % modulus as u128) as u64;
    }
    result
}

/// Variable-time setup helper over public values.
fn mod_inverse(value: u64, modulus: u64) -> u64 {
    let mut remainder = (modulus as i128, value as i128);
    let mut coefficient = (0_i128, 1_i128);
    while remainder.1 != 0 {
        let quotient = remainder.0 / remainder.1;
        remainder = (remainder.1, remainder.0 - quotient * remainder.1);
        coefficient = (coefficient.1, coefficient.0 - quotient * coefficient.1);
    }
    while coefficient.0 < 0 {
        coefficient.0 += modulus as i128;
    }
    (coefficient.0 % modulus as i128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIME: u64 = 998_244_353;

    #[test]
    fn ntt_intt_roundtrip() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 8);
        let original = vec![1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(engine.intt(&engine.ntt(&original)), original);
    }

    #[test]
    fn multiply_small() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 8);
        let left = vec![1, 2, 3, 0, 0, 0, 0, 0];
        let right = vec![4, 5, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            engine.multiply(&left, &right),
            vec![4, 13, 22, 15, 0, 0, 0, 0]
        );
    }

    #[test]
    fn negacyclic_wrap() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 4);
        let left = vec![0, 0, 0, 1];
        let right = vec![0, 1, 0, 0];
        assert_eq!(
            engine.multiply(&left, &right),
            vec![TEST_PRIME - 1, 0, 0, 0]
        );
    }

    /// The previous textbook multiply (bit-reversal permutation inside every
    /// transform, separate psi pre/post-twist passes), kept here as the
    /// reference the fused negacyclic path must reproduce exactly.
    fn textbook_multiply_persistent(
        engine: &NTTEngineFFT,
        left: &[u64],
        right: &[u64],
    ) -> Vec<u64> {
        let n = engine.n;
        let mut a: Vec<u64> = (0..n)
            .map(|i| {
                engine
                    .mont
                    .montgomery_mul(left[i], engine.psi_powers_mont[i])
            })
            .collect();
        let mut b: Vec<u64> = (0..n)
            .map(|i| {
                engine
                    .mont
                    .montgomery_mul(right[i], engine.psi_powers_mont[i])
            })
            .collect();
        engine.ntt_inplace(&mut a);
        engine.ntt_inplace(&mut b);
        for i in 0..n {
            a[i] = engine.mont.montgomery_mul(a[i], b[i]);
        }
        engine.intt_inplace(&mut a);
        (0..n)
            .map(|i| {
                engine
                    .mont
                    .montgomery_mul(a[i], engine.psi_inv_powers_mont[i])
            })
            .collect()
    }

    /// Fused negacyclic multiply == textbook multiply, bit for bit, on random,
    /// extreme and sparse inputs, for small rings and the real secure-config
    /// ring sizes and primes; and the plain-domain `multiply_into` agrees too.
    #[test]
    fn fused_negacyclic_multiply_matches_textbook_reference() {
        let mut cases: Vec<(u64, usize)> = vec![
            (TEST_PRIME, 8),
            (TEST_PRIME, 64),
            (TEST_PRIME, 1024),
            (TEST_PRIME, 2),
        ];
        let cfg = crate::params::SecureConfig::secure_128().into_config();
        for &p in &cfg.primes {
            cases.push((p, cfg.n));
        }
        let cfg = crate::params::SecureConfig::secure_256().into_config();
        for &p in cfg.primes.iter().take(2) {
            cases.push((p, cfg.n));
        }
        let mut state = 0xC2B2_AE3D_27D4_EB4Fu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for (q, n) in cases {
            let engine = NTTEngineFFT::new(q, n);
            let shapes: [Box<dyn Fn(&mut dyn FnMut() -> u64) -> Vec<u64>>; 4] = [
                Box::new(move |r| (0..n).map(|_| r() % q).collect()),
                Box::new(move |_| vec![q - 1; n]),
                Box::new(move |_| vec![0; n]),
                Box::new(move |r| {
                    (0..n)
                        .map(|i| if i % 7 == 0 { r() % q } else { 0 })
                        .collect()
                }),
            ];
            for sa in &shapes {
                for sb in &shapes {
                    let a_plain = sa(&mut next);
                    let b_plain = sb(&mut next);
                    let a_mont: Vec<u64> = a_plain
                        .iter()
                        .map(|&v| engine.mont.to_montgomery(v))
                        .collect();
                    let b_mont: Vec<u64> = b_plain
                        .iter()
                        .map(|&v| engine.mont.to_montgomery(v))
                        .collect();
                    let want = textbook_multiply_persistent(&engine, &a_mont, &b_mont);
                    assert_eq!(
                        engine.multiply_persistent(&a_mont, &b_mont),
                        want,
                        "persistent q={q} n={n}"
                    );
                    let want_plain: Vec<u64> = want
                        .iter()
                        .map(|&v| engine.mont.from_montgomery(v))
                        .collect();
                    assert_eq!(
                        engine.multiply(&a_plain, &b_plain),
                        want_plain,
                        "plain q={q} n={n}"
                    );
                }
            }
        }
    }

    /// Direct A/B of the textbook and fused multiply on the real secure_128
    /// ring (n=8192, first main prime). Run with:
    /// `cargo test -p nine65 --lib --release -- --ignored --nocapture ntt_multiply_ab_timing`
    #[test]
    #[ignore = "timing measurement, not a correctness test"]
    fn ntt_multiply_ab_timing() {
        let cfg = crate::params::SecureConfig::secure_128().into_config();
        let engine = NTTEngineFFT::new(cfg.primes[0], cfg.n);
        let q = engine.q;
        let a: Vec<u64> = (0..engine.n as u64).map(|i| (i * 2654435761) % q).collect();
        let b: Vec<u64> = (0..engine.n as u64).map(|i| (i * 40503 + 17) % q).collect();
        let am: Vec<u64> = a.iter().map(|&v| engine.mont.to_montgomery(v)).collect();
        let bm: Vec<u64> = b.iter().map(|&v| engine.mont.to_montgomery(v)).collect();
        let reps = 300;
        let mut best_old = u128::MAX;
        let mut best_new = u128::MAX;
        for _ in 0..7 {
            let t = std::time::Instant::now();
            for _ in 0..reps {
                std::hint::black_box(textbook_multiply_persistent(&engine, &am, &bm));
            }
            best_old = best_old.min(t.elapsed().as_nanos() / reps as u128);
            let t = std::time::Instant::now();
            for _ in 0..reps {
                std::hint::black_box(engine.multiply_persistent(&am, &bm));
            }
            best_new = best_new.min(t.elapsed().as_nanos() / reps as u128);
        }
        println!(
            "textbook {best_old} ns/mult, fused {best_new} ns/mult (n={}, best of 7)",
            engine.n
        );
    }

    /// `multiply_sum_pair` must equal the per-term products summed mod q,
    /// exactly, for several term counts including zero and one.
    #[test]
    fn multiply_sum_pair_matches_summed_products() {
        let cfg = crate::params::SecureConfig::secure_128().into_config();
        let mut cases = vec![(TEST_PRIME, 64usize)];
        cases.push((cfg.primes[0], cfg.n));
        let mut state = 0x1234_5678_9ABC_DEF1u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for (q, n) in cases {
            let engine = NTTEngineFFT::new(q, n);
            for terms in [0usize, 1, 2, 5, 11] {
                let mk = |next: &mut dyn FnMut() -> u64| -> Vec<Vec<u64>> {
                    (0..terms)
                        .map(|_| (0..n).map(|_| next() % q).collect())
                        .collect()
                };
                let l = mk(&mut next);
                let ra = mk(&mut next);
                let rb = mk(&mut next);
                fn refs(v: &[Vec<u64>]) -> Vec<&[u64]> {
                    v.iter().map(|x| x.as_slice()).collect()
                }
                let (got_a, got_b) = engine.multiply_sum_pair(&refs(&l), &refs(&ra), &refs(&rb));
                let mut want_a = vec![0u64; n];
                let mut want_b = vec![0u64; n];
                for t in 0..terms {
                    let pa = engine.multiply(&l[t], &ra[t]);
                    let pb = engine.multiply(&l[t], &rb[t]);
                    for j in 0..n {
                        want_a[j] = ((want_a[j] as u128 + pa[j] as u128) % q as u128) as u64;
                        want_b[j] = ((want_b[j] as u128 + pb[j] as u128) % q as u128) as u64;
                    }
                }
                assert_eq!(got_a, want_a, "A q={q} n={n} terms={terms}");
                assert_eq!(got_b, want_b, "B q={q} n={n} terms={terms}");
            }
        }
    }

    /// The iterative power tables must equal square-and-multiply exactly.
    #[test]
    fn power_table_matches_mod_pow() {
        for &(base, q) in &[(3u64, TEST_PRIME), (TEST_PRIME - 1, TEST_PRIME), (7, 65537)] {
            let table = power_table(base, 300, q);
            for (i, &v) in table.iter().enumerate() {
                assert_eq!(v, mod_pow(base, i as u64, q), "base={base} q={q} i={i}");
            }
        }
    }

    #[test]
    fn multiply_matches_schoolbook() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 8);
        let left: Vec<u64> = (0..8).map(|index| index * 12_345 % TEST_PRIME).collect();
        let right: Vec<u64> = (0..8).map(|index| index * 67_890 % TEST_PRIME).collect();
        let actual = engine.multiply(&left, &right);

        let mut expected = vec![0_i128; 8];
        for left_index in 0..8 {
            for right_index in 0..8 {
                let product = left[left_index] as i128 * right[right_index] as i128;
                let index = left_index + right_index;
                if index < 8 {
                    expected[index] += product;
                } else {
                    expected[index - 8] -= product;
                }
            }
        }
        let expected: Vec<u64> = expected
            .into_iter()
            .map(|value| {
                let modulus = TEST_PRIME as i128;
                (((value % modulus) + modulus) % modulus) as u64
            })
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn class_f_constructor_rejects_composite_modulus() {
        assert!(NTTEngineFFT::try_new(65, 2).is_err());
    }

    #[test]
    fn constructor_rejects_non_power_of_two_degree() {
        assert!(NTTEngineFFT::try_new(TEST_PRIME, 7).is_err());
    }

    #[test]
    fn constructor_rejects_incompatible_prime() {
        assert!(NTTEngineFFT::try_new(17, 32).is_err());
    }

    #[test]
    fn branchless_coefficient_ops_match_integer_reference() {
        let engine = NTTEngineFFT::new(TEST_PRIME, 8);
        let samples = [0, 1, 2, TEST_PRIME / 2, TEST_PRIME - 2, TEST_PRIME - 1];
        for &left in &samples {
            for &right in &samples {
                assert_eq!(
                    engine.add(&[left; 8], &[right; 8])[0],
                    (left + right) % TEST_PRIME
                );
                assert_eq!(
                    engine.sub(&[left; 8], &[right; 8])[0],
                    (left + TEST_PRIME - right) % TEST_PRIME
                );
            }
            let expected_negation = if left == 0 { 0 } else { TEST_PRIME - left };
            assert_eq!(engine.neg(&[left; 8])[0], expected_negation);
        }
    }
}
