//! AVX-512 negacyclic NTT for primes below 2^32 (prototype kernel).
//!
//! Every shipped prime is 28..=32 bits, so a 32-bit Montgomery reduction
//! (`R = 2^32`) runs eight butterflies per 512-bit instruction using
//! `vpmuludq`. Data stays in the PLAIN domain: twiddles are stored as
//! `w * 2^32 mod q`, so `redc(v * w32) = v * w mod q` exactly, with no
//! to/from-Montgomery pass. All shift counts, loop bounds and twiddle indices
//! are public; the only data-dependent step is the branch-free
//! `min_epu64(r, r + q)` correction.
//!
//! Layout and stage order match `NTTEngineFFT::negacyclic_forward_br` /
//! `negacyclic_inverse_br` (Cooley-Tukey forward, Gentleman-Sande inverse,
//! twists merged, bit-reversed spectrum), so the result is bit-identical to
//! the scalar engine in the plain domain.

use core::arch::x86_64::*;

/// True when the running CPU and OS support the AVX-512F kernel.
/// Safe transform entry points also check this themselves.
pub fn available() -> bool {
    std::arch::is_x86_feature_detected!("avx512f")
}

#[derive(Clone, Debug)]
pub struct Ntt32 {
    q: u64,
    n: usize,
    /// `q^-1 mod 2^32`.
    qinv: u64,
    /// `psi^bitrev(k) * 2^32 mod q`.
    psi_br: Vec<u64>,
    /// `psi^-bitrev(k) * 2^32 mod q`.
    psi_inv_br: Vec<u64>,
    /// `n^-1 * 2^32 mod q`.
    n_inv: u64,
}

fn inv_mod_2_32(q: u64) -> u64 {
    // Newton iteration for the 2-adic inverse of an odd number.
    let mut x = q as u32;
    for _ in 0..5 {
        x = x.wrapping_mul(2u32.wrapping_sub((q as u32).wrapping_mul(x)));
    }
    x as u64
}

impl Ntt32 {
    /// Build from PLAIN-domain twiddle tables (`psi^bitrev`, `psi^-bitrev`)
    /// and `n^-1`, all reduced mod `q < 2^32`.
    pub fn new(q: u64, psi_br: &[u64], psi_inv_br: &[u64], n_inv: u64) -> Self {
        assert!(
            q > 2 && q % 2 == 1 && q < (1u64 << 32),
            "q must be odd and below 2^32"
        );
        let n = psi_br.len();
        assert!(n.is_power_of_two() && psi_inv_br.len() == n);
        let to32 = |w: u64| ((w as u128) << 32) % q as u128;
        Self {
            q,
            n,
            qinv: inv_mod_2_32(q),
            psi_br: psi_br.iter().map(|&w| to32(w) as u64).collect(),
            psi_inv_br: psi_inv_br.iter().map(|&w| to32(w) as u64).collect(),
            n_inv: to32(n_inv) as u64,
        }
    }

    #[inline(always)]
    fn redc(&self, x: u64) -> u64 {
        let m = ((x as u32).wrapping_mul(self.qinv as u32)) as u64;
        let r = (x >> 32).wrapping_sub((m * self.q) >> 32);
        r.min(r.wrapping_add(self.q))
    }

    #[inline(always)]
    fn add_mod(&self, a: u64, b: u64) -> u64 {
        let s = a + b;
        s.min(s.wrapping_sub(self.q))
    }

    #[inline(always)]
    fn sub_mod(&self, a: u64, b: u64) -> u64 {
        let d = a.wrapping_sub(b);
        d.min(d.wrapping_add(self.q))
    }

    fn assert_transform_input(&self, a: &[u64]) {
        assert_eq!(
            a.len(),
            self.n,
            "Ntt32 input length must match transform size"
        );
        assert!(
            available(),
            "Ntt32 transforms require runtime AVX-512F support"
        );
    }

    /// Plain coefficients in, plain bit-reversed spectrum out.
    ///
    /// # Panics
    /// Panics before modifying `a` if its length differs from the table size
    /// or runtime AVX-512F support is unavailable, even for small transforms.
    pub fn forward(&self, a: &mut [u64]) {
        self.assert_transform_input(a);
        let mut t = self.n;
        let mut m = 1usize;
        while m < self.n {
            t >>= 1;
            if t >= 8 {
                // SAFETY: this entry point checked AVX-512F and a.len() == n.
                // Power-of-two stages have 2*m*t == n; t >= 8 is a multiple
                // of eight, so all vector loads and stores are in bounds.
                unsafe { self.fwd_stage_avx512(a, t, m) };
            } else {
                for i in 0..m {
                    let w = self.psi_br[m + i];
                    let start = 2 * i * t;
                    for j in start..start + t {
                        let u = a[j];
                        let v = self.redc(a[j + t] * w);
                        a[j] = self.add_mod(u, v);
                        a[j + t] = self.sub_mod(u, v);
                    }
                }
            }
            m <<= 1;
        }
    }

    /// Probe: per-stage nanoseconds of one forward transform.
    ///
    /// # Panics
    /// Panics before modifying `a` if its length differs from the table size
    /// or runtime AVX-512F support is unavailable, even for small transforms.
    pub fn forward_stage_nanos(&self, a: &mut [u64]) -> Vec<(usize, u128)> {
        self.assert_transform_input(a);
        let mut out = Vec::new();
        let mut t = self.n;
        let mut m = 1usize;
        while m < self.n {
            t >>= 1;
            let start = std::time::Instant::now();
            if t >= 8 {
                // SAFETY: this entry point checked AVX-512F and a.len() == n.
                // As in forward, 2*m*t == n and t is a multiple of eight.
                unsafe { self.fwd_stage_avx512(a, t, m) };
            } else {
                for i in 0..m {
                    let w = self.psi_br[m + i];
                    let st = 2 * i * t;
                    for j in st..st + t {
                        let u = a[j];
                        let v = self.redc(a[j + t] * w);
                        a[j] = self.add_mod(u, v);
                        a[j + t] = self.sub_mod(u, v);
                    }
                }
            }
            out.push((t, start.elapsed().as_nanos()));
            m <<= 1;
        }
        out
    }

    /// Plain bit-reversed spectrum in, plain coefficients out (includes `n^-1`).
    ///
    /// # Panics
    /// Panics before modifying `a` if its length differs from the table size
    /// or runtime AVX-512F support is unavailable, even for small transforms.
    pub fn inverse(&self, a: &mut [u64]) {
        self.assert_transform_input(a);
        let mut t = 1usize;
        let mut m = self.n;
        while m > 1 {
            let half = m >> 1;
            if t >= 8 {
                // SAFETY: this entry point checked AVX-512F and a.len() == n.
                // Power-of-two stages have 2*half*t == n; t >= 8 is a
                // multiple of eight, keeping vector loads/stores in bounds.
                unsafe { self.inv_stage_avx512(a, t, half) };
            } else {
                let mut start = 0usize;
                for i in 0..half {
                    let w = self.psi_inv_br[half + i];
                    for j in start..start + t {
                        let u = a[j];
                        let v = a[j + t];
                        a[j] = self.add_mod(u, v);
                        a[j + t] = self.redc(self.sub_mod(u, v) * w);
                    }
                    start += 2 * t;
                }
            }
            t <<= 1;
            m = half;
        }
        for v in a.iter_mut() {
            *v = self.redc(*v * self.n_inv);
        }
    }

    #[target_feature(enable = "avx512f")]
    unsafe fn fwd_stage_avx512(&self, a: &mut [u64], t: usize, m: usize) {
        let qv = _mm512_set1_epi64(self.q as i64);
        let qinv = _mm512_set1_epi64(self.qinv as i64);
        let mask = _mm512_set1_epi64(0xFFFF_FFFF);
        for i in 0..m {
            let w = _mm512_set1_epi64(self.psi_br[m + i] as i64);
            let base = 2 * i * t;
            let mut j = 0;
            while j < t {
                let lo = a.as_mut_ptr().add(base + j) as *mut i64;
                let hi = a.as_mut_ptr().add(base + t + j) as *mut i64;
                let u = _mm512_loadu_si512(lo as *const _);
                let x = _mm512_mul_epu32(_mm512_loadu_si512(hi as *const _), w);
                let mm = _mm512_and_si512(_mm512_mul_epu32(x, qinv), mask);
                let mq = _mm512_mul_epu32(mm, qv);
                let r = _mm512_sub_epi64(_mm512_srli_epi64::<32>(x), _mm512_srli_epi64::<32>(mq));
                let v = _mm512_min_epu64(r, _mm512_add_epi64(r, qv));
                let s = _mm512_add_epi64(u, v);
                let s = _mm512_min_epu64(s, _mm512_sub_epi64(s, qv));
                let d = _mm512_sub_epi64(u, v);
                let d = _mm512_min_epu64(d, _mm512_add_epi64(d, qv));
                _mm512_storeu_si512(lo as *mut _, s);
                _mm512_storeu_si512(hi as *mut _, d);
                j += 8;
            }
        }
    }

    #[target_feature(enable = "avx512f")]
    unsafe fn inv_stage_avx512(&self, a: &mut [u64], t: usize, half: usize) {
        let qv = _mm512_set1_epi64(self.q as i64);
        let qinv = _mm512_set1_epi64(self.qinv as i64);
        let mask = _mm512_set1_epi64(0xFFFF_FFFF);
        let mut start = 0usize;
        for i in 0..half {
            let w = _mm512_set1_epi64(self.psi_inv_br[half + i] as i64);
            let mut j = 0;
            while j < t {
                let lo = a.as_mut_ptr().add(start + j) as *mut i64;
                let hi = a.as_mut_ptr().add(start + t + j) as *mut i64;
                let u = _mm512_loadu_si512(lo as *const _);
                let v = _mm512_loadu_si512(hi as *const _);
                let s = _mm512_add_epi64(u, v);
                let s = _mm512_min_epu64(s, _mm512_sub_epi64(s, qv));
                let d = _mm512_sub_epi64(u, v);
                let d = _mm512_min_epu64(d, _mm512_add_epi64(d, qv));
                let x = _mm512_mul_epu32(d, w);
                let mm = _mm512_and_si512(_mm512_mul_epu32(x, qinv), mask);
                let mq = _mm512_mul_epu32(mm, qv);
                let r = _mm512_sub_epi64(_mm512_srli_epi64::<32>(x), _mm512_srli_epi64::<32>(mq));
                let hi_out = _mm512_min_epu64(r, _mm512_add_epi64(r, qv));
                _mm512_storeu_si512(lo as *mut _, s);
                _mm512_storeu_si512(hi as *mut _, hi_out);
                j += 8;
            }
            start += 2 * t;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn transforms() -> [fn(&Ntt32, &mut [u64]); 3] {
        [Ntt32::forward, Ntt32::inverse, |ntt, a| {
            let _ = ntt.forward_stage_nanos(a);
        }]
    }

    fn assert_rejected_unchanged(
        ntt: &Ntt32,
        len: usize,
        transform: fn(&Ntt32, &mut [u64]),
        message: &str,
    ) {
        let mut a = vec![1; len];
        let before = a.clone();
        let panic = catch_unwind(AssertUnwindSafe(|| transform(ntt, &mut a)))
            .expect_err("invalid transform must panic");
        let text = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .expect("panic must contain an explanatory message");
        assert!(text.contains(message), "unexpected panic: {text}");
        assert_eq!(a, before, "rejection must precede all input writes");
    }

    #[test]
    fn all_entry_points_reject_wrong_lengths_before_execution() {
        // N=16 reaches SIMD; N=1 pins the no-stage edge case on either host.
        for n in [1, 16] {
            let table = vec![1; n];
            let ntt = Ntt32::new(97, &table, &table, 1);
            for transform in transforms() {
                for len in [0, n - 1, n + 1] {
                    assert_rejected_unchanged(&ntt, len, transform, "input length");
                }
            }
        }
    }

    #[test]
    fn all_entry_points_reject_unsupported_hosts_before_execution() {
        if available() {
            eprintln!("AVX-512F available; unsupported-host rejection not exercised");
            return;
        }
        for n in [1, 16] {
            let table = vec![1; n];
            let ntt = Ntt32::new(97, &table, &table, 1);
            for transform in transforms() {
                assert_rejected_unchanged(&ntt, n, transform, "runtime AVX-512F support");
            }
        }
    }
}
