//! Main-only canonical-rank base extension (Track 1, PR #103).
//!
//! Derives every auxiliary residue `X mod a_j` from the mod-`Q` main residues
//! alone — no redundant lane, no anchor, no serialized auxiliary state. This is
//! the D3 (evaluator, derived-transient) primitive from
//! `docs/CRAM_APPLICABILITY_MAP_2026-09-01.md`: auxiliary residues are a
//! deterministic function of the incoming mod-`Q` ciphertext, live inside one
//! kernel call, and are dropped before serialization.
//!
//! Contrast with [`super::base_ext::BaseExt`], whose `project` reads the rank
//! `t` from an externally supplied redundant residue `r_red = X mod m_r`. A
//! mod-`Q` ciphertext does not carry that residue, so `BaseExt` cannot be wired
//! into the evaluator without threading a redundant lane through key
//! generation, encryption, and serialization (which would reintroduce a
//! published coprime-to-`Q` lane — the exact WIRE-Q violation this track
//! forbids). `MainOnlyBaseExt` computes the rank `rho` from the main residues
//! themselves.
//!
//! ## Math (exact, no floating point)
//!
//! For pairwise-coprime main moduli `m_i`, product `M`, `M_i = M / m_i`, and
//! canonical residues `x_i = X mod m_i`:
//!
//! ```text
//! c_i  = x_i * (M_i^{-1} mod m_i) mod m_i    (CRT idempotent coefficient)
//! rho  = floor( sum_i c_i / m_i )            (rank; 0 <= rho < lane_count)
//! X mod a_j = ( sum_i c_i * (M_i mod a_j) - rho * (M mod a_j) ) mod a_j
//! ```
//!
//! **Terminology (WR-1 invariant 4 / finding F4).** `c_i` is the coefficient of
//! the CRT *idempotent* `M_i * (M_i^{-1} mod m_i)`, and the synthesis above is a
//! single parallel sum: no lane reads another lane's partial result, and there
//! is no sequential mixed-radix cascade. It was previously labelled a "Garner
//! coefficient", which is wrong twice over — Garner's algorithm is the
//! sequential mixed-radix walk this deliberately avoids, and that label would
//! trip the WR-1 §F source scanner on a false positive. The formula has not
//! changed; only the name has.
//!
//! `rho` is computed by a certified fixed-point common path with an exact
//! `U256` fallback at integer boundaries. No canonical `X` is ever
//! materialized in the common path; the fallback compares `sum_i c_i * M_i`
//! (a bounded `U256`) against multiples of `M` and is fixed-work.
//!
//! ## Centered projection (WR-1 §A)
//!
//! [`MainOnlyBaseExt::project_centered`] emits the residues of the *centered*
//! lift `Xc` (`Xc = X` in the lower half, `Xc = X - M` in the upper half)
//! rather than of the canonical `X`. WR-1 invariant 5 requires this before a
//! tensor product: the auxiliary base must carry the residues of the same
//! signed integer the main base is a wrapped image of, and the half decision
//! is made against the rank numerator
//!
//! ```text
//! N = sum_i c_i * M_i,   upper half  <=>  N >= rho*M + ceil(M/2)
//! ```
//!
//! without ever forming `X = N - rho*M` as a canonical object.

use super::rns::{U256, U512};

/// Guard-bit precision for the fixed-point rank common path.
const RANK_FRAC_BITS: u32 = 64;

/// Which rank path resolved a projection (test observability; the contract
/// requires both to execute under test).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RankPath {
    /// Fixed-point interval was decisive; no big-integer work.
    CertifiedFixedPoint,
    /// Fixed-point interval met a boundary; resolved by exact `U256` compare.
    ExactFallback,
}

/// Typed failures. Every one is a refused proof obligation, never a
/// best-effort result (contract rule 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MainOnlyBaseExtError {
    /// Two main moduli share a factor: no CRT bijection.
    NonCoprimeMain { m1: u64, m2: u64, gcd: u64 },
    /// A supplied residue was not canonical (`r[i] >= main[i]`).
    NonCanonicalResidue {
        lane: usize,
        residue: u64,
        modulus: u64,
    },
    /// Auxiliary basis was empty.
    EmptyAuxiliaryBasis,
    /// More than the fixed-size accumulator can hold.
    TooManyLanes { lanes: usize, max: usize },
    /// A main modulus was < 2 (not a ring lane).
    DegenerateModulus { modulus: u64 },
    /// WR-1 finding F5. The exact rank fallback accumulates
    /// `N = sum_i c_i * M_i` and walks up to `(k+1) * M` while resolving
    /// `rho`, all in a fixed-width `U256`. `MAX_LANES` is a shape bound, not a
    /// numeric capacity certificate, so the bound is proved here in `U512`
    /// (which cannot itself overflow at these widths) and refused when it does
    /// not hold.
    FallbackAccumulatorOverCapacity {
        lanes: usize,
        /// Bit length of `(k + 1) * M`, which must stay below 256.
        required_bits: u32,
    },
}

const MAX_LANES: usize = 16;

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

fn inv_mod(a: u64, m: u64) -> u64 {
    // Extended Euclid; `a` assumed coprime to `m` (callers hold that proof).
    let (mut t, mut newt): (i128, i128) = (0, 1);
    let (mut r, mut newr): (i128, i128) = (m as i128, (a % m) as i128);
    while newr != 0 {
        let q = r / newr;
        (t, newt) = (newt, t - q * newt);
        (r, newr) = (newr, r - q * newr);
    }
    ((t % m as i128 + m as i128) % m as i128) as u64
}

/// U256 * u64 -> U256 via 4x1 limb schoolbook. Inputs are bounded so the
/// product never exceeds 256 bits (sum_i c_i*M_i < lanes * M).
fn mul_u256_u64(x: U256, m: u64) -> U256 {
    let limbs = [
        x.lo as u64,
        (x.lo >> 64) as u64,
        x.hi as u64,
        (x.hi >> 64) as u64,
    ];
    let mut out = [0u64; 4];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let prod = limbs[i] as u128 * m as u128 + carry;
        out[i] = prod as u64;
        carry = prod >> 64;
    }
    debug_assert_eq!(carry, 0, "mul_u256_u64 overflow past 256 bits");
    U256 {
        lo: (out[0] as u128) | ((out[1] as u128) << 64),
        hi: (out[2] as u128) | ((out[3] as u128) << 64),
    }
}

/// Bit length of a `U512`, most significant limb first.
fn u512_bits(x: U512) -> u32 {
    if x.d3 != 0 {
        return 384 + (128 - x.d3.leading_zeros());
    }
    if x.d2 != 0 {
        return 256 + (128 - x.d2.leading_zeros());
    }
    if x.d1 != 0 {
        return 128 + (128 - x.d1.leading_zeros());
    }
    128 - x.d0.leading_zeros()
}

/// Precomputed constants for one (main basis, auxiliary basis) pair.
/// Build once per config; [`Self::project`] is the per-coefficient hot path.
pub struct MainOnlyBaseExt {
    main: Vec<u64>,
    aux: Vec<u64>,
    /// `(M/m_i)^{-1} mod m_i`.
    xi: Vec<u64>,
    /// `coef[j][i] = (M/m_i) mod aux[j]`.
    coef: Vec<Vec<u64>>,
    /// `m_mod[j] = M mod aux[j]`.
    m_mod: Vec<u64>,
    /// `M_i = M/m_i` as a full-width integer, for the exact fallback.
    mi_u256: Vec<U256>,
    /// `M` as a full-width integer, for the exact fallback.
    m_u256: U256,
    /// `ceil(M/2) = (M+1)/2` (`M` is odd whenever every lane is odd; for an
    /// even `M` this is still the correct upper-half threshold), for the exact
    /// half decision in [`Self::project_centered`].
    half_up_u256: U256,
}

impl MainOnlyBaseExt {
    /// Build the extension. Validates pairwise coprimality of `main` and a
    /// non-empty `aux`. `aux` moduli need only be positive (they are views).
    pub fn new(main: &[u64], aux: &[u64]) -> Result<Self, MainOnlyBaseExtError> {
        let k = main.len();
        if k > MAX_LANES {
            return Err(MainOnlyBaseExtError::TooManyLanes {
                lanes: k,
                max: MAX_LANES,
            });
        }
        if aux.is_empty() {
            return Err(MainOnlyBaseExtError::EmptyAuxiliaryBasis);
        }
        for &m in main {
            if m < 2 {
                return Err(MainOnlyBaseExtError::DegenerateModulus { modulus: m });
            }
        }
        for i in 0..k {
            for j in (i + 1)..k {
                let g = gcd(main[i], main[j]);
                if g != 1 {
                    return Err(MainOnlyBaseExtError::NonCoprimeMain {
                        m1: main[i],
                        m2: main[j],
                        gcd: g,
                    });
                }
            }
        }

        // WR-1 F5: prove the exact-fallback accumulator cannot overflow before
        // any caller can reach it — and before this constructor itself forms
        // any `U256` product. `rank`'s fallback forms `N = sum_i c_i*M_i`
        // (< k*M) and walks `r*M` for `r = 1 ..= k+1`, so the widest `U256`
        // value the fallback ever holds is `(k+1)*M`. `MAX_LANES = 16` is a
        // *shape* bound (16 x 64-bit lanes is 1024 bits) and is not a numeric
        // capacity certificate, which is exactly F5's point.
        //
        // The proof runs in `U512`, so it must first be shown that `U512`
        // itself cannot wrap. `sum_bits` (the sum of the lanes' bit lengths) is
        // an exact upper bound on `bitlen(M)` computed in plain integers, and
        // `M >= 2^(sum_bits - k)` because each lane is at least `2^(bits-1)`.
        // So `sum_bits > 272` already forces `M > 2^256` (k <= 16) and is
        // refused directly; otherwise `(k+1)*M < 2^277` and the `U512`
        // arithmetic below is exact.
        let sum_bits: u32 = main.iter().map(|&p| 64 - p.leading_zeros()).sum();
        if sum_bits > 272 {
            return Err(MainOnlyBaseExtError::FallbackAccumulatorOverCapacity {
                lanes: k,
                required_bits: sum_bits,
            });
        }
        let fallback_peak = U512::product_u64s(main).mul_u128(k as u128 + 1);
        let required_bits = u512_bits(fallback_peak);
        if required_bits > 256 {
            return Err(MainOnlyBaseExtError::FallbackAccumulatorOverCapacity {
                lanes: k,
                required_bits,
            });
        }

        // (M/m_i) mod m_i = product of other lanes mod m_i; invert.
        let xi: Vec<u64> = (0..k)
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
        let coef: Vec<Vec<u64>> = aux.iter().map(|&a| build(a)).collect();
        let m_mod: Vec<u64> = aux
            .iter()
            .map(|&a| U256::product_u64s(main).mod_u64(a))
            .collect();

        let m_u256 = U256::product_u64s(main);
        // `ceil(M/2)` = `(M+1) >> 1` for both parities. `M + 1` cannot wrap
        // because the F5 gate above proved `(k+1)*M < 2^256` with `k >= 1`.
        let half_up_u256 = m_u256.add(U256::one()).shr1();
        let mi_u256: Vec<U256> = (0..k)
            .map(|i| {
                let others: Vec<u64> = main
                    .iter()
                    .enumerate()
                    .filter(|&(j, _)| j != i)
                    .map(|(_, &m)| m)
                    .collect();
                U256::product_u64s(&others)
            })
            .collect();

        Ok(MainOnlyBaseExt {
            main: main.to_vec(),
            aux: aux.to_vec(),
            xi,
            coef,
            m_mod,
            mi_u256,
            m_u256,
            half_up_u256,
        })
    }

    pub fn lane_count(&self) -> usize {
        self.main.len()
    }
    pub fn aux_count(&self) -> usize {
        self.aux.len()
    }

    /// CRT idempotent coefficients `c_i = x_i * (M_i^{-1} mod m_i) mod m_i`.
    ///
    /// Parallel: `c_i` depends only on `x_i`, never on another lane's result.
    /// (Named "Garner coefficients" before WR-1 F4; see the module header.)
    #[inline]
    fn coefficients(&self, r: &[u64]) -> [u64; MAX_LANES] {
        let mut c = [0u64; MAX_LANES];
        for i in 0..self.main.len() {
            c[i] = ((r[i] as u128 * self.xi[i] as u128) % self.main[i] as u128) as u64;
        }
        c
    }

    /// Exact rank `rho = floor(sum_i c_i / m_i)` in `[0, lane_count)`.
    /// Certified fixed-point common path; exact `U256` fallback at boundaries.
    #[inline]
    fn rank(&self, c: &[u64; MAX_LANES]) -> (u64, RankPath) {
        let (rho, _, path) = self.rank_and_half(c, false);
        (rho, path)
    }

    /// Exact rank, and — when `need_half` — the upper-half decision for the
    /// canonical value `X = N - rho*M` in one pass (WR-1 §A).
    ///
    /// Write `S = sum_i c_i / m_i`. Then `S = rho + X/M` exactly, so `rho` is
    /// `floor(S)` and `X` lies in the upper half iff `frac(S) > 1/2`.
    ///
    /// The common path (§A1) uses the same certified fixed-point interval as
    /// [`Self::rank`]: `acc = sum_i floor(c_i * 2^F / m_i)` satisfies
    /// `S * 2^F ∈ [acc, acc + k)`, since each floor loses strictly less than 1.
    /// Writing `acc = rho_lo * 2^F + residual`, the interval decides
    ///
    /// * `rho` when `residual + k <= 2^F` (the window stays in one integer step);
    /// * "upper" when `residual >= 2^(F-1)`, because then
    ///   `frac(S) * 2^F >= residual >= 2^(F-1)` and equality is impossible
    ///   (`frac(S) * 2^F = 2^(F-1)` would mean `2X = M`, which an odd `M`
    ///   forbids and which the exact path below handles for even `M` anyway);
    /// * "lower" when `residual + k <= 2^(F-1)`, because then
    ///   `frac(S) * 2^F < residual + k <= 2^(F-1)`.
    ///
    /// Both decisions must hold to take the common path. Otherwise §A2's exact
    /// fallback forms the bounded parallel idempotent sum `N = sum_i c_i * M_i`
    /// in `U256` (F5-certified at construction) and compares it against
    /// `rho*M` and `rho*M + ceil(M/2)`. `X = N - rho*M` is never materialized
    /// as a canonical coefficient object; only the two comparisons are made.
    #[inline]
    fn rank_and_half(&self, c: &[u64; MAX_LANES], need_half: bool) -> (u64, bool, RankPath) {
        let k = self.main.len();
        // acc = sum_i floor(c_i * 2^F / m_i);  true = sum_i c_i*2^F/m_i.
        // Each floor loses < 1, so true in [acc, acc + k).
        let mut acc: u128 = 0;
        for i in 0..k {
            acc += ((c[i] as u128) << RANK_FRAC_BITS) / self.main[i] as u128;
        }
        let rho_lo = (acc >> RANK_FRAC_BITS) as u64;
        let residual = acc & ((1u128 << RANK_FRAC_BITS) - 1);
        let top = 1u128 << RANK_FRAC_BITS;
        let half = 1u128 << (RANK_FRAC_BITS - 1);
        // Decisive when the whole uncertainty window [acc, acc+k) stays inside
        // one integer step of 2^F: residual + k <= 2^F. This also catches the
        // under-count case (residual wraps near 2^F when frac is tiny).
        let rank_decided = residual + (k as u128) <= top;
        if rank_decided {
            if !need_half {
                return (rho_lo, false, RankPath::CertifiedFixedPoint);
            }
            if residual >= half {
                return (rho_lo, true, RankPath::CertifiedFixedPoint);
            }
            if residual + (k as u128) <= half {
                return (rho_lo, false, RankPath::CertifiedFixedPoint);
            }
        }
        // Exact fallback: N = sum_i c_i * M_i; rho = floor(N / M), N < k*M.
        let mut n = U256::zero();
        for i in 0..k {
            n = n.add(mul_u256_u64(self.mi_u256[i], c[i]));
        }
        let mut rho: u64 = 0;
        let mut rho_mul = U256::zero(); // rho * M, tracked alongside rho
        let mut r_mul = self.m_u256; // 1 * M
        let mut r: u64 = 1;
        while (r as usize) <= k {
            if n.ge(r_mul) {
                rho = r;
                rho_mul = r_mul;
            }
            r_mul = r_mul.add(self.m_u256);
            r += 1;
        }
        // Upper half iff N >= rho*M + ceil(M/2). `rho*M + ceil(M/2) <= k*M`,
        // which the F5 construction gate proved fits `U256`.
        let upper = need_half && n.ge(rho_mul.add(self.half_up_u256));
        (rho, upper, RankPath::ExactFallback)
    }

    /// `r[i] = X mod main[i]` (canonical). Writes `out[j] = X mod aux[j]`.
    /// Returns the rank path taken (for test observability).
    pub fn project(&self, r: &[u64], out: &mut [u64]) -> Result<RankPath, MainOnlyBaseExtError> {
        self.project_inner(r, out, false).map(|(path, _)| path)
    }

    /// Centered projection (WR-1 §A). `r[i] = X mod main[i]` (canonical);
    /// writes `out[j] = Xc mod aux[j]` where `Xc` is the *centered* lift
    ///
    /// ```text
    /// Xc = X          if X <  ceil(M/2)   (lower half)
    /// Xc = X - M      if X >= ceil(M/2)   (upper half)
    /// ```
    ///
    /// Returns the rank path taken and the half decision, both for test
    /// observability (the contract requires each path to execute under test).
    ///
    /// This is the operation WR-1 invariant 5 requires *before* a tensor
    /// product. Base-extending the wrapped mod-`Q` tensor instead would give
    /// the residues of `Xc mod Q`, not of `Xc`, and the pre-reduction integer
    /// tensor coefficient is not recoverable from that.
    pub fn project_centered(
        &self,
        r: &[u64],
        out: &mut [u64],
    ) -> Result<(RankPath, bool), MainOnlyBaseExtError> {
        self.project_inner(r, out, true)
    }

    fn project_inner(
        &self,
        r: &[u64],
        out: &mut [u64],
        centered: bool,
    ) -> Result<(RankPath, bool), MainOnlyBaseExtError> {
        let k = self.main.len();
        assert_eq!(r.len(), k, "residue vector length must match lane count");
        assert_eq!(
            out.len(),
            self.aux.len(),
            "output length must match aux count"
        );
        for i in 0..k {
            if r[i] >= self.main[i] {
                return Err(MainOnlyBaseExtError::NonCanonicalResidue {
                    lane: i,
                    residue: r[i],
                    modulus: self.main[i],
                });
            }
        }
        let c = self.coefficients(r);
        let (rho, upper, path) = self.rank_and_half(&c, centered);
        // In the upper half the centered lift subtracts exactly one `M`, so it
        // is folded into the same `rho * (M mod a_j)` correction the canonical
        // projection already performs: the whole centering costs one increment
        // of the rank correction, per auxiliary lane, and touches nothing else.
        let correction = rho + u64::from(centered && upper);
        for (j, &a) in self.aux.iter().enumerate() {
            let mut s: u128 = 0;
            for i in 0..k {
                s += (c[i] as u128 * self.coef[j][i] as u128) % a as u128;
            }
            let s = (s % a as u128) as u64;
            let sub = ((correction as u128 * self.m_mod[j] as u128) % a as u128) as u64;
            out[j] = (s + a - sub) % a;
        }
        Ok((path, upper))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::rns::U512;

    /// Ground-truth `X mod a` for a `u128`-range `X` (works for main products
    /// up to 128 bits, i.e. the 4-lane production prefix and all small bases).
    fn residues(x: u128, m: &[u64]) -> Vec<u64> {
        m.iter().map(|&mi| (x % mi as u128) as u64).collect()
    }

    /// Real production main-prime prefixes (secure_128_deep / 192 / 256).
    /// 6 lanes ≈ 2^175 — exceeds u128, so ground truth uses `U512`.
    const MAIN_4: [u64; 4] = [998244353, 985661441, 754974721, 469762049];
    const MAIN_5: [u64; 5] = [998244353, 985661441, 754974721, 469762049, 167772161];
    const MAIN_6: [u64; 6] = [
        998244353, 985661441, 754974721, 469762049, 167772161, 595591169,
    ];
    const AUX7: [u64; 7] = [
        2013265921, 2281701377, 2483027969, 2885681153, 3221225473, 3221422081, 3222306817,
    ];

    /// Build a known `X = sum_i d_i * prod(main[0..i])` in `[0, M)` as `U512`
    /// from mixed-radix digits `d_i` (Horner over the main primes, high→low).
    /// Independent of the primitive under test: the oracle owns `X` directly.
    fn build_x_u512(digits: &[u64], main: &[u64]) -> U512 {
        let mut acc = U512::zero();
        for i in (0..main.len()).rev() {
            acc = acc.mul_u128(main[i] as u128).add(U512::from_u64(digits[i]));
        }
        acc
    }

    /// U512 differential oracle over a real production prefix. Small `X` forces
    /// the exact fallback; mid-range forces the certified path. No Python.
    fn oracle_check_u512(main: &[u64], aux: &[u64]) {
        let ext = MainOnlyBaseExt::new(main, aux).unwrap();
        let mut out = vec![0u64; aux.len()];
        let (mut saw_fixed, mut saw_fallback) = (false, false);

        let mut check = |x: &U512| {
            let r: Vec<u64> = main.iter().map(|&m| x.mod_u64(m)).collect();
            let path = ext.project(&r, &mut out).unwrap();
            match path {
                RankPath::CertifiedFixedPoint => {}
                RankPath::ExactFallback => {}
            }
            for (j, &a) in aux.iter().enumerate() {
                assert_eq!(out[j], x.mod_u64(a), "x mod {a} mismatch");
            }
            path
        };

        // Small X (0..64): frac(S) ~ 2^-175, forces the exact fallback.
        for small in 0u64..64 {
            let digits: Vec<u64> = std::iter::once(small)
                .chain(std::iter::repeat(0))
                .take(main.len())
                .collect();
            if check(&build_x_u512(&digits, main)) == RankPath::ExactFallback {
                saw_fallback = true;
            }
        }

        // Pseudo-random mid-range X: exercises the certified common path.
        let mut state: u64 = 0xDEADBEEFCAFEF00D;
        for _ in 0..4000 {
            let digits: Vec<u64> = main
                .iter()
                .map(|&m| {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    state % m
                })
                .collect();
            if check(&build_x_u512(&digits, main)) == RankPath::CertifiedFixedPoint {
                saw_fixed = true;
            }
        }

        assert!(saw_fixed, "certified path never exercised for {main:?}");
        assert!(saw_fallback, "exact fallback never exercised for {main:?}");
    }

    #[test]
    fn production_prefixes_u512_oracle_4_5_6_lanes() {
        oracle_check_u512(&MAIN_4, &AUX7);
        oracle_check_u512(&MAIN_5, &AUX7);
        oracle_check_u512(&MAIN_6, &AUX7);
    }

    #[test]
    fn exhaustive_small_bases_are_exact() {
        for (main, aux) in [
            (vec![3u64, 5, 7], vec![2013265921u64, 11]),
            (vec![5u64, 7, 11, 13], vec![2281701377u64, 8]),
            (vec![3u64, 5, 7, 11], vec![2013265921u64, 2281701377]),
        ] {
            let ext = MainOnlyBaseExt::new(&main, &aux).unwrap();
            let m: u128 = main.iter().map(|&p| p as u128).product();
            let mut out = vec![0u64; aux.len()];
            for x in 0..m {
                let r = residues(x, &main);
                ext.project(&r, &mut out).unwrap();
                for (j, &a) in aux.iter().enumerate() {
                    assert_eq!(out[j], (x % a as u128) as u64, "x={x} a={a}");
                }
            }
        }
    }

    #[test]
    fn production_prefix_random_plus_small_x_and_both_paths() {
        // 4 x ~30-bit NTT primes: M ~ 2^120 fits u128 for ground truth.
        let main = vec![1073750017u64, 1073753089, 1073950721, 1073958913];
        let aux = vec![
            2013265921u64,
            2281701377,
            2483027969,
            2885681153,
            3221225473,
            3221422081,
            3222306817,
        ];
        let ext = MainOnlyBaseExt::new(&main, &aux).unwrap();
        let m: u128 = main.iter().map(|&p| p as u128).product();
        let mut out = vec![0u64; aux.len()];

        let mut saw_fixed = false;
        let mut saw_fallback = false;

        // Small X (0..64): frac(S)=X/M is ~2^-120, forces the exact fallback.
        for x in 0u128..64 {
            let r = residues(x, &main);
            let path = ext.project(&r, &mut out).unwrap();
            if path == RankPath::ExactFallback {
                saw_fallback = true;
            }
            for (j, &a) in aux.iter().enumerate() {
                assert_eq!(out[j], (x % a as u128) as u64, "small x={x} a={a}");
            }
        }

        // Deterministic pseudo-random mid-range X: exercises the common path.
        let mut state: u128 = 0x9E3779B97F4A7C15;
        for _ in 0..5000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let x = state % m;
            let r = residues(x, &main);
            let path = ext.project(&r, &mut out).unwrap();
            if path == RankPath::CertifiedFixedPoint {
                saw_fixed = true;
            }
            for (j, &a) in aux.iter().enumerate() {
                assert_eq!(out[j], (x % a as u128) as u64, "rand x={x} a={a}");
            }
        }

        // Edge values.
        for &x in &[0u128, 1, m / 2 - 1, m / 2, m / 2 + 1, m - 2, m - 1] {
            let r = residues(x, &main);
            ext.project(&r, &mut out).unwrap();
            for (j, &a) in aux.iter().enumerate() {
                assert_eq!(out[j], (x % a as u128) as u64, "edge x={x} a={a}");
            }
        }

        assert!(saw_fixed, "certified fixed-point path never exercised");
        assert!(saw_fallback, "exact fallback path never exercised");
    }

    #[test]
    fn permutation_invariance() {
        let main = vec![1073750017u64, 1073753089, 1073950721, 1073958913];
        let perm = vec![1073950721u64, 1073750017, 1073958913, 1073753089];
        let aux = vec![2013265921u64, 2281701377];
        let a = MainOnlyBaseExt::new(&main, &aux).unwrap();
        let b = MainOnlyBaseExt::new(&perm, &aux).unwrap();
        let m: u128 = main.iter().map(|&p| p as u128).product();
        let x = m / 3 + 12345;
        let mut oa = vec![0u64; 2];
        let mut ob = vec![0u64; 2];
        a.project(&residues(x, &main), &mut oa).unwrap();
        b.project(&residues(x, &perm), &mut ob).unwrap();
        assert_eq!(oa, ob);
    }

    #[test]
    fn typed_rejections() {
        assert!(matches!(
            MainOnlyBaseExt::new(&[6, 9], &[11]),
            Err(MainOnlyBaseExtError::NonCoprimeMain { .. })
        ));
        assert!(matches!(
            MainOnlyBaseExt::new(&[3, 5], &[]),
            Err(MainOnlyBaseExtError::EmptyAuxiliaryBasis)
        ));
        assert!(matches!(
            MainOnlyBaseExt::new(&[1, 5], &[11]),
            Err(MainOnlyBaseExtError::DegenerateModulus { .. })
        ));
        let ext = MainOnlyBaseExt::new(&[3, 5, 7], &[11]).unwrap();
        let mut out = vec![0u64; 1];
        assert!(matches!(
            ext.project(&[3, 0, 0], &mut out), // 3 not canonical mod 3
            Err(MainOnlyBaseExtError::NonCanonicalResidue { .. })
        ));
        assert!(matches!(
            ext.project_centered(&[3, 0, 0], &mut out),
            Err(MainOnlyBaseExtError::NonCanonicalResidue { .. })
        ));
    }

    // ===================================================================
    // WR-1 §A / G2 — centered projection
    // ===================================================================

    /// WR-1 F5. `MAX_LANES = 16` is a shape bound; the numeric capacity of the
    /// exact-fallback `U256` accumulator has to be proved separately, and a
    /// basis that busts it must be refused at construction rather than wrap
    /// silently inside `rank`.
    ///
    /// Non-vacuous by construction: the *accepted* case immediately below it
    /// differs only in lane count, so the refusal cannot be an artifact of some
    /// other validation firing first.
    #[test]
    fn fallback_accumulator_over_capacity_is_refused() {
        // Nine pairwise-coprime ~31/32-bit lanes: M ≈ 2^283, so (k+1)*M is far
        // past 2^256 and `rank`'s fallback could not hold it.
        let too_wide: Vec<u64> = vec![
            2013265921, 2281701377, 2483027969, 2885681153, 3221225473, 3221422081, 3222306817,
            3222372353, 3222568961,
        ];
        match MainOnlyBaseExt::new(&too_wide, &[998244353]) {
            Err(MainOnlyBaseExtError::FallbackAccumulatorOverCapacity {
                lanes,
                required_bits,
            }) => {
                assert_eq!(lanes, 9);
                assert!(
                    required_bits > 256,
                    "refusal must report a genuine shortfall, got {required_bits}"
                );
            }
            Err(other) => panic!("expected FallbackAccumulatorOverCapacity, got {other:?}"),
            Ok(_) => panic!("expected FallbackAccumulatorOverCapacity, got Ok"),
        }
        // Eight of the same lanes (M ≈ 2^251, (k+1)*M ≈ 2^255) are accepted, so
        // the refusal above is the capacity gate and not a lane-count taboo.
        MainOnlyBaseExt::new(&too_wide[..8], &[998244353]).expect("8 lanes must fit U256");
    }

    /// Exhaustive over three small bases: every canonical `X` in `[0, M)` must
    /// project to the residues of its centered lift, and the reported half
    /// decision must match `X >= ceil(M/2)`.
    #[test]
    fn centered_projection_exhaustive_small_bases() {
        for (main, aux) in [
            (vec![3u64, 5, 7], vec![2013265921u64, 11]),
            (vec![5u64, 7, 11, 13], vec![2281701377u64, 8]),
            (vec![3u64, 5, 7, 11], vec![2013265921u64, 2281701377]),
        ] {
            let ext = MainOnlyBaseExt::new(&main, &aux).expect("valid basis");
            let m: i128 = main.iter().map(|&p| p as i128).product();
            let half_up = m.div_euclid(2) + (m % 2);
            let mut out = vec![0u64; aux.len()];
            for x in 0..m {
                let r: Vec<u64> = main.iter().map(|&p| (x % p as i128) as u64).collect();
                let (_, upper) = ext.project_centered(&r, &mut out).expect("canonical");
                let want_upper = x >= half_up;
                assert_eq!(want_upper, upper, "half decision at x={x} M={m}");
                let xc = if want_upper { x - m } else { x };
                for (j, &a) in aux.iter().enumerate() {
                    assert_eq!(
                        out[j] as i128,
                        xc.rem_euclid(a as i128),
                        "centered projection x={x} xc={xc} a={a}"
                    );
                }
            }
        }
    }

    /// Production-basis centered projection against a `U512` ground truth,
    /// including the half boundary `(M-1)/2` / `(M+1)/2` and both endpoints,
    /// with both rank paths required to execute.
    #[test]
    fn centered_projection_production_prefixes_u512_oracle() {
        for main in [&MAIN_4[..], &MAIN_5[..], &MAIN_6[..]] {
            let aux = &AUX7[..];
            let ext = MainOnlyBaseExt::new(main, aux).expect("valid basis");
            let m = U512::product_u64s(main);
            let half_up = m.add(U512::from_u64(1)).div_u64(2); // ceil(M/2)
            let mut out = vec![0u64; aux.len()];
            let (mut saw_fixed, mut saw_fallback) = (false, false);

            // `x` given as U512; check against the centered ground truth.
            let mut check = |x: U512, note: &str| {
                let r: Vec<u64> = main.iter().map(|&p| x.mod_u64(p)).collect();
                let (path, upper) = ext.project_centered(&r, &mut out).expect("canonical");
                // Independent half decision: x >= ceil(M/2).
                let want_upper = !u512_lt(x, half_up);
                assert_eq!(want_upper, upper, "half decision ({note})");
                for (j, &a) in aux.iter().enumerate() {
                    // Xc mod a = (X mod a - [upper] * (M mod a)) mod a.
                    let xa = x.mod_u64(a);
                    let want = if want_upper {
                        ((xa as u128 + a as u128 - m.mod_u64(a) as u128) % a as u128) as u64
                    } else {
                        xa
                    };
                    assert_eq!(out[j], want, "centered residue a={a} ({note})");
                }
                path
            };

            // Structural corners: 0, 1, the two half neighbours, M-2, M-1.
            let one = U512::from_u64(1);
            let corners = [
                (U512::zero(), "0"),
                (one, "1"),
                (half_up.sub(one), "ceil(M/2)-1"),
                (half_up, "ceil(M/2)"),
                (m.sub(U512::from_u64(2)), "M-2"),
                (m.sub(one), "M-1"),
            ];
            for (x, note) in corners {
                match check(x, note) {
                    RankPath::CertifiedFixedPoint => saw_fixed = true,
                    RankPath::ExactFallback => saw_fallback = true,
                }
            }

            // Small X forces the exact fallback (frac(S) ~ 2^-bitlen(M)).
            for small in 0u64..64 {
                if check(U512::from_u64(small), "small") == RankPath::ExactFallback {
                    saw_fallback = true;
                }
            }

            // Deterministic mid-range draws exercise the certified path on both
            // sides of the half boundary.
            let mut state: u64 = 0xA5A5_1234_DEAD_BEEF;
            for _ in 0..3000 {
                let mut acc = U512::zero();
                for &p in main.iter().rev() {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    acc = acc.mul_u128(p as u128).add(U512::from_u64(state % p));
                }
                if check(acc, "random") == RankPath::CertifiedFixedPoint {
                    saw_fixed = true;
                }
            }

            assert!(saw_fixed, "certified path never exercised for {main:?}");
            assert!(saw_fallback, "exact fallback never exercised for {main:?}");
        }
    }

    /// The load-bearing witness the integer oracle
    /// (`scripts/verify_wr1_transient_exact.py::verify_centering_is_load_bearing`)
    /// pins: canonical `M-1` must become centered `-1` in every auxiliary lane,
    /// and the canonical and centered projections must differ there. If they
    /// agreed, centering would be decorative and invariant 5 would be empty.
    #[test]
    fn centered_projection_turns_canonical_m_minus_one_into_minus_one() {
        let main = &MAIN_4[..];
        let aux = &AUX7[..4];
        let ext = MainOnlyBaseExt::new(main, aux).expect("valid basis");
        let m = U512::product_u64s(main);
        let x = m.sub(U512::from_u64(1));
        let r: Vec<u64> = main.iter().map(|&p| x.mod_u64(p)).collect();

        let mut canonical = vec![0u64; aux.len()];
        ext.project(&r, &mut canonical).expect("canonical");
        let mut centered = vec![0u64; aux.len()];
        let (_, upper) = ext.project_centered(&r, &mut centered).expect("canonical");

        assert!(upper, "M-1 must land in the upper half");
        for (j, &a) in aux.iter().enumerate() {
            assert_eq!(centered[j], a - 1, "centered lane {a} must encode -1");
            assert_eq!(canonical[j], x.mod_u64(a), "canonical lane {a}");
            assert_ne!(
                canonical[j], centered[j],
                "canonical and centered lifts must differ on this witness"
            );
        }
    }

    /// Strict less-than on `U512`, most significant limb first (test-local; the
    /// production kernel never compares wide values in this direction).
    fn u512_lt(a: U512, b: U512) -> bool {
        if a.d3 != b.d3 {
            return a.d3 < b.d3;
        }
        if a.d2 != b.d2 {
            return a.d2 < b.d2;
        }
        if a.d1 != b.d1 {
            return a.d1 < b.d1;
        }
        a.d0 < b.d0
    }
}
