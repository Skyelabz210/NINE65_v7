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
//! c_i  = x_i * (M_i^{-1} mod m_i) mod m_i        (Garner coefficient, [0, m_i))
//! rho  = floor( sum_i c_i / m_i )                (rank; 0 <= rho < lane_count)
//! X mod a_j = ( sum_i c_i * (M_i mod a_j) - rho * (M mod a_j) ) mod a_j
//! ```
//!
//! `rho` is computed by a certified fixed-point common path with an exact
//! `U256` fallback at integer boundaries. No canonical `X` is ever
//! materialized in the common path; the fallback compares `sum_i c_i * M_i`
//! (a bounded `U256`) against multiples of `M` and is fixed-work.

use super::rns::U256;

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
        })
    }

    pub fn lane_count(&self) -> usize {
        self.main.len()
    }
    pub fn aux_count(&self) -> usize {
        self.aux.len()
    }

    /// Garner coefficients `c_i = x_i * (M_i^{-1} mod m_i) mod m_i`.
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
        let k = self.main.len();
        // acc = sum_i floor(c_i * 2^F / m_i);  true = sum_i c_i*2^F/m_i.
        // Each floor loses < 1, so true in (acc, acc + k].
        let mut acc: u128 = 0;
        for i in 0..k {
            acc += ((c[i] as u128) << RANK_FRAC_BITS) / self.main[i] as u128;
        }
        let rho_lo = (acc >> RANK_FRAC_BITS) as u64;
        let residual = acc & ((1u128 << RANK_FRAC_BITS) - 1);
        let top = 1u128 << RANK_FRAC_BITS;
        // Decisive when the whole uncertainty window [acc, acc+k) stays inside
        // one integer step of 2^F: residual + k <= 2^F. This also catches the
        // under-count case (residual wraps near 2^F when frac is tiny).
        if residual + (k as u128) <= top {
            return (rho_lo, RankPath::CertifiedFixedPoint);
        }
        // Exact fallback: N = sum_i c_i * M_i; rho = floor(N / M), N < k*M.
        let mut n = U256::zero();
        for i in 0..k {
            n = n.add(mul_u256_u64(self.mi_u256[i], c[i]));
        }
        let mut rho: u64 = 0;
        let mut r_mul = self.m_u256; // 1 * M
        let mut r: u64 = 1;
        while (r as usize) <= k {
            if n.ge(r_mul) {
                rho = r;
            }
            r_mul = r_mul.add(self.m_u256);
            r += 1;
        }
        (rho, RankPath::ExactFallback)
    }

    /// `r[i] = X mod main[i]` (canonical). Writes `out[j] = X mod aux[j]`.
    /// Returns the rank path taken (for test observability).
    pub fn project(&self, r: &[u64], out: &mut [u64]) -> Result<RankPath, MainOnlyBaseExtError> {
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
        let (rho, path) = self.rank(&c);
        for (j, &a) in self.aux.iter().enumerate() {
            let mut s: u128 = 0;
            for i in 0..k {
                s += (c[i] as u128 * self.coef[j][i] as u128) % a as u128;
            }
            let s = (s % a as u128) as u64;
            let sub = ((rho as u128 * self.m_mod[j] as u128) % a as u128) as u64;
            out[j] = ((s + a - sub) % a) as u64;
        }
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ground-truth `X mod a` for a `u128`-range `X` (works for main products
    /// up to 128 bits, i.e. the 4-lane production prefix and all small bases).
    fn residues(x: u128, m: &[u64]) -> Vec<u64> {
        m.iter().map(|&mi| (x % mi as u128) as u64).collect()
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
    }
}
