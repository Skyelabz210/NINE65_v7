//! Shenoy-Kumaresan base extension: reads a value's residue in one basis
//! (anchors) from its residues in another (main lanes), without ever
//! reconstructing the value itself.
//!
//! # Status: kernel only, NOT wired into any call site
//!
//! This module was proposed (uploaded `base_ext.rs`/`base_ext.pdf`, both the
//! same source) as a "drop-in replacement for the `to_u256_level(...).mod_u64(a)`
//! site in `canonicalize_dual_anchor`". That claim does not hold as written:
//! `project` needs a per-coefficient residue `r_red` of the value modulo a
//! REDUNDANT lane `m_r` that is coprime to the main basis. Nothing in
//! [`crate::ops::rns_fhe::DualRNSPoly`] carries such a residue — it has only
//! `main` and `anchor` limbs (verified by reading the struct directly). At
//! `canonicalize_dual_anchor`'s call site there is no `r_red` to feed this
//! function without first computing it via the exact `to_u256_level` path
//! this module exists to avoid, which would make it slower, not faster.
//!
//! Using this for real needs the redundant lane threaded through encryption,
//! `dual_poly_add`, `dual_poly_mul`, and the rescale — a materially larger,
//! shipped-format-affecting change, not a one-file merge. That work is not
//! done here. What IS done here: the arithmetic kernel itself, independently
//! differential-tested against `u128` CRT ground truth (see `tests` below) —
//! so if that plumbing is built later, the primitive it calls into is already
//! verified.
//!
//! # The algorithm
//!
//! Given `X`'s residues `r_i = X mod m_i` over main lanes `m_0..m_{k-1}`
//! (`M = prod(m_i)`, `X` canonical in `[0, M)`), and a residue `r_red = X mod m_r`
//! for one further lane `m_r` coprime to every `m_i` with `m_r > k`:
//!
//! ```text
//! X = sum_i c_i * (M/m_i) - t*M,   c_i = r_i * (M/m_i)^-1 mod m_i,   t in [0, k)
//! ```
//!
//! `t` is the CRT overshoot correction (the raw sum before subtracting
//! multiples of `M` lands in `[0, k*M)`, not `[0, M)`) — it is bounded by the
//! number of lanes summed, not by the magnitude of `X`, which is what makes
//! recovering it from a single extra small-modulus residue possible. Once
//! `t` is known, any further modulus `a` (an anchor prime) is read directly:
//! `X mod a = (sum_i c_i*(M/m_i) mod a) - t*(M mod a) mod a`, entirely in
//! `u64`/`u128` — no `U256`, no Garner, no mixed-radix, no floating point.

fn inv_mod(a: u64, m: u64) -> u64 {
    let (mut t, mut newt) = (0i128, 1i128);
    let (mut r, mut newr) = (m as i128, (a % m) as i128);
    while newr != 0 {
        let q = r / newr;
        let tmp = t - q * newt;
        t = newt;
        newt = tmp;
        let tmp = r - q * newr;
        r = newr;
        newr = tmp;
    }
    ((t % m as i128 + m as i128) % m as i128) as u64
}

/// Precomputed constants for one (main basis, anchor basis, redundant lane)
/// triple. Build once per config; `project` is the per-coefficient hot path.
pub struct BaseExt {
    main: Vec<u64>,
    anchors: Vec<u64>,
    xi: Vec<u64>,        // (M/m_i)^-1 mod m_i
    coef: Vec<Vec<u64>>, // [anchor][i] = (M/m_i) mod a
    m_mod: Vec<u64>,     // M mod a
    m_r: u64,
    coef_r: Vec<u64>, // (M/m_i) mod m_r
    m_r_inv: u64,     // (M mod m_r)^-1 mod m_r
}

impl BaseExt {
    /// `m_r` must be coprime to every entry of `main` and strictly greater
    /// than `main.len()` (the structural bound on the overshoot `t`).
    pub fn new(main: &[u64], anchors: &[u64], m_r: u64) -> Self {
        let k = main.len();
        assert!(
            m_r as usize > k,
            "base_ext: redundant lane {m_r} must exceed the main lane count {k}"
        );
        let mut xi = vec![0u64; k];
        for i in 0..k {
            // (M/m_i) mod m_i = product of the other lanes mod m_i
            let mut acc: u128 = 1;
            for (j, &mj) in main.iter().enumerate() {
                if j != i {
                    acc = acc * (mj as u128 % main[i] as u128) % main[i] as u128;
                }
            }
            xi[i] = inv_mod(acc as u64, main[i]);
        }
        let build = |a: u64| -> Vec<u64> {
            (0..k)
                .map(|i| {
                    let mut acc: u128 = 1;
                    for (j, &mj) in main.iter().enumerate() {
                        if j != i {
                            acc = acc * (mj as u128 % a as u128) % a as u128;
                        }
                    }
                    acc as u64
                })
                .collect()
        };
        let coef: Vec<Vec<u64>> = anchors.iter().map(|&a| build(a)).collect();
        let m_mod: Vec<u64> = anchors
            .iter()
            .map(|&a| {
                let mut acc: u128 = 1;
                for &mj in main {
                    acc = acc * (mj as u128 % a as u128) % a as u128;
                }
                acc as u64
            })
            .collect();
        let coef_r = build(m_r);
        let mut mr: u128 = 1;
        for &mj in main {
            mr = mr * (mj as u128 % m_r as u128) % m_r as u128;
        }
        let m_r_inv = inv_mod(mr as u64, m_r);
        BaseExt {
            main: main.to_vec(),
            anchors: anchors.to_vec(),
            xi,
            coef,
            m_mod,
            m_r,
            coef_r,
            m_r_inv,
        }
    }

    /// `r[i] = X mod main[i]` for every main lane, `r_red = X mod m_r`.
    /// Writes `out[j] = X mod anchors[j]` for every anchor lane.
    #[inline]
    pub fn project(&self, r: &[u64], r_red: u64, out: &mut [u64]) {
        let k = self.main.len();
        debug_assert_eq!(r.len(), k);
        debug_assert_eq!(out.len(), self.anchors.len());
        assert!(
            k <= 16,
            "base_ext: fixed-size c[] buffer holds at most 16 lanes"
        );
        let mut c = [0u64; 16];
        for i in 0..k {
            c[i] = ((r[i] as u128 * self.xi[i] as u128) % self.main[i] as u128) as u64;
        }
        // t from the redundant lane
        let mut s_r: u128 = 0;
        for i in 0..k {
            s_r += c[i] as u128 * self.coef_r[i] as u128 % self.m_r as u128;
        }
        let s_r = (s_r % self.m_r as u128) as u64;
        let diff = (s_r + self.m_r - r_red % self.m_r) % self.m_r;
        let t = ((diff as u128 * self.m_r_inv as u128) % self.m_r as u128) as u64;
        for (j, &a) in self.anchors.iter().enumerate() {
            let mut s: u128 = 0;
            for i in 0..k {
                s += c[i] as u128 * self.coef[j][i] as u128 % a as u128;
            }
            let s = (s % a as u128) as u64;
            let sub = ((t as u128 * self.m_mod[j] as u128) % a as u128) as u64;
            out[j] = (s + a - sub) % a;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ground-truth CRT reconstruction, independent of `BaseExt`: fits
    /// comfortably in u128 for every basis these tests use (max product
    /// tested is ~119 bits, `manufactured_m2b_insecure`'s real 4-prime
    /// chain), so this is the oracle, not a second copy of the kernel.
    fn crt_reconstruct_u128(residues: &[u64], moduli: &[u64]) -> u128 {
        let m_prod: u128 = moduli.iter().map(|&m| m as u128).product();
        let mut x: u128 = 0;
        for (&r, &m) in residues.iter().zip(moduli.iter()) {
            let mi = m_prod / m as u128;
            let mi_mod = (mi % m as u128) as u64;
            let inv = inv_mod(mi_mod, m);
            let term = mi * ((r as u128 * inv as u128) % m as u128);
            x = (x + term) % m_prod;
        }
        x
    }

    fn check_basis(main: &[u64], anchors: &[u64], m_r: u64, trials: u64, seed_base: u64) {
        let m_prod: u128 = main.iter().map(|&m| m as u128).product();
        let be = BaseExt::new(main, anchors, m_r);
        let mut state = seed_base ^ 0x9E3779B97F4A7C15;
        let mut next = || {
            // xorshift64*, deterministic, no external RNG dependency
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };

        let mut checked = 0u64;
        let mut mismatches = 0u64;
        for _ in 0..trials {
            // Random X in [0, M): build from two 64-bit draws, reduced mod M.
            let hi = next() as u128;
            let lo = next() as u128;
            let x = ((hi << 64) | lo) % m_prod;

            let r: Vec<u64> = main.iter().map(|&m| (x % m as u128) as u64).collect();
            let r_red = (x % m_r as u128) as u64;
            let expected: Vec<u64> = anchors.iter().map(|&a| (x % a as u128) as u64).collect();

            let mut out = vec![0u64; anchors.len()];
            be.project(&r, r_red, &mut out);
            checked += 1;
            if out != expected {
                mismatches += 1;
                if mismatches <= 3 {
                    println!(
                        "MISMATCH x_bits={} r={:?} r_red={} expected={:?} got={:?}",
                        128 - x.leading_zeros(),
                        r,
                        r_red,
                        expected,
                        out
                    );
                }
            }
            // Independent check: the oracle round-trips too, so a failure
            // here isolates whether the bug is in the oracle or the kernel.
            debug_assert_eq!(crt_reconstruct_u128(&r, main), x, "oracle self-check");
        }
        assert_eq!(
            mismatches, 0,
            "base_ext: {mismatches}/{checked} anchor projections wrong for main={main:?} \
             anchors={anchors:?} m_r={m_r}"
        );
        println!("base_ext: {checked}/{checked} exact for main={main:?} m_r={m_r}");
    }

    #[test]
    fn matches_crt_ground_truth_on_the_real_manufactured_chain() {
        // manufactured_m2b_insecure's actual main lanes and the current
        // 7-anchor canonical set for n<=8192 -- not a synthetic toy basis.
        let main = [65_537u64, 738_208_769, 1_409_307_649, 2_617_285_633];
        let anchors = [
            2_013_265_921u64,
            2_281_701_377,
            2_483_027_969,
            2_885_681_153,
            3_221_225_473,
            3_221_422_081,
            3_222_306_817,
        ];
        // Coprime to every main lane and > k=4; not otherwise special.
        let m_r = 999_999_937u64;
        check_basis(&main, &anchors, m_r, 20_000, 1);
    }

    #[test]
    fn matches_crt_ground_truth_on_a_small_synthetic_basis() {
        // Small primes make the oracle trivially inspectable by hand if this
        // ever regresses, independent of the real chain's specific values.
        let main = [97u64, 101, 103, 107];
        let anchors = [113u64, 127, 131];
        let m_r = 137u64;
        check_basis(&main, &anchors, m_r, 20_000, 2);
    }

    /// Microbenchmark against the REAL shipped path: `crt_reconstruct_u256`
    /// (what `to_u256_level` calls) followed by `U256::mod_u64(a)` per
    /// anchor — exactly what `canonicalize_dual_anchor` does today, minus
    /// only the `RNSFHEContext`/chunking dispatch overhead common to both
    /// sides. The uploaded file's own claim ("48x on the kernel") is a
    /// specific, falsifiable number and is checked here rather than quoted.
    #[test]
    #[ignore] // run explicitly: -- --ignored --nocapture
    fn kernel_speed_vs_shipped_path() {
        use crate::arithmetic::rns::crt_reconstruct_u256;
        use std::time::Instant;

        let main = [65_537u64, 738_208_769, 1_409_307_649, 2_617_285_633];
        let anchors = [
            2_013_265_921u64,
            2_281_701_377,
            2_483_027_969,
            2_885_681_153,
            3_221_225_473,
            3_221_422_081,
            3_222_306_817,
        ];
        let m_r = 999_999_937u64;
        let be = BaseExt::new(&main, &anchors, m_r);
        let m_prod: u128 = main.iter().map(|&m| m as u128).product();

        let n = 200_000usize;
        let mut state = 7u64 ^ 0x9E3779B97F4A7C15;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };
        let cases: Vec<(Vec<u64>, u64)> = (0..n)
            .map(|_| {
                let hi = next() as u128;
                let lo = next() as u128;
                let x = ((hi << 64) | lo) % m_prod;
                let r: Vec<u64> = main.iter().map(|&m| (x % m as u128) as u64).collect();
                let r_red = (x % m_r as u128) as u64;
                (r, r_red)
            })
            .collect();

        let mut out = vec![0u64; anchors.len()];
        let t0 = Instant::now();
        for (r, _) in &cases {
            let v = crt_reconstruct_u256(r, &main);
            for (j, &a) in anchors.iter().enumerate() {
                out[j] = v.mod_u64(a);
            }
        }
        let shipped_ns = t0.elapsed().as_nanos() as f64 / n as f64;
        std::hint::black_box(&out);

        let mut out2 = vec![0u64; anchors.len()];
        let t1 = Instant::now();
        for (r, r_red) in &cases {
            be.project(r, *r_red, &mut out2);
        }
        let base_ext_ns = t1.elapsed().as_nanos() as f64 / n as f64;
        std::hint::black_box(&out2);

        println!(
            "shipped (crt_reconstruct_u256 + mod_u64 x{}): {shipped_ns:.1} ns/coeff   \
             base_ext: {base_ext_ns:.1} ns/coeff   speedup: {:.1}x",
            anchors.len(),
            shipped_ns / base_ext_ns.max(0.001)
        );
    }

    #[test]
    fn refuses_a_redundant_lane_not_exceeding_the_lane_count() {
        let result = std::panic::catch_unwind(|| {
            BaseExt::new(&[3u64, 5, 7, 11], &[13u64, 17], 4);
        });
        assert!(
            result.is_err(),
            "base_ext: m_r=4 does not exceed k=4 and must be rejected, not silently wrong"
        );
    }

    /// Pins the structural bound the module's docs claim: the CRT overshoot
    /// `t` stays in `[0, k)` regardless of how large `X` gets, because it
    /// counts how many `M`-multiples the raw per-lane sum overshoots by, not
    /// `X`'s own magnitude. Recovered here from the internals of `project`
    /// by comparing against the independent oracle's own overshoot.
    #[test]
    fn overshoot_t_stays_below_lane_count_on_the_real_chain() {
        let main = [65_537u64, 738_208_769, 1_409_307_649, 2_617_285_633];
        let k = main.len() as u128;
        let m_prod: u128 = main.iter().map(|&m| m as u128).product();
        let mut state = 3u64 ^ 0x9E3779B97F4A7C15;
        let mut next = || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };
        let xi: Vec<u64> = (0..main.len())
            .map(|i| {
                let mut acc: u128 = 1;
                for (j, &mj) in main.iter().enumerate() {
                    if j != i {
                        acc = acc * (mj as u128 % main[i] as u128) % main[i] as u128;
                    }
                }
                inv_mod(acc as u64, main[i])
            })
            .collect();
        let mut max_t = 0u128;
        for _ in 0..20_000u64 {
            let hi = next() as u128;
            let lo = next() as u128;
            let x = ((hi << 64) | lo) % m_prod;
            let mut raw: u128 = 0;
            for i in 0..main.len() {
                let ri = (x % main[i] as u128) as u64;
                let ci = ((ri as u128 * xi[i] as u128) % main[i] as u128) as u64;
                let mi = m_prod / main[i] as u128;
                raw += ci as u128 * mi;
            }
            let t = (raw - x) / m_prod;
            assert!(t < k, "overshoot t={t} exceeds lane count k={k}");
            max_t = max_t.max(t);
        }
        println!("max observed t = {max_t} (bound: < {k})");
    }
}
