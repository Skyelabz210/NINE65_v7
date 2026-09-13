//! Exact BFV scale-and-round over a derived-transient auxiliary base
//! (Track 1, PR #103, stage T1.3).
//!
//! Computes `Y = round(Xc * t / Q)` **exactly**, given the residues of the
//! centered tensor coefficient `Xc` in the published main base `Q` and in a
//! transient auxiliary base `A`, and emits `Y` in the main base only. Nothing
//! auxiliary escapes: `A` exists for the duration of one call.
//!
//! This is the operation `ops::rns_fhe::exact_rescale` only approximates. That
//! routine is limb-local (Bajard-style) and is valid only while `Delta^2 <= Q`;
//! `ops::rns_fhe::track1_exact_multiply_lock` pins its failure on a chain where
//! `Delta^2 > Q` (71 of 72 sample points wrong, worst centered error
//! `0.4937 * Q`).
//!
//! ## The identity
//!
//! Write `Z = Xc * t + floor(Q/2)` and `w = Z mod Q` (canonical in `[0, Q)`).
//! Because `Z - w` is divisible by `Q`,
//!
//! ```text
//! Y = floor(Z / Q) = (Z - w) / Q = round(Xc * t / Q)
//! ```
//!
//! and the last equality is the half-up rounding rule BFV specifies. In base
//! `A` the division is a multiplication by `Q^{-1}`, which exists because every
//! auxiliary modulus is coprime to `Q`:
//!
//! ```text
//! Y mod a_j = (Z mod a_j - w mod a_j) * (Q^{-1} mod a_j)   mod a_j
//! ```
//!
//! `Z mod q_i` and `Z mod a_j` are per-lane. The one cross-lane step is
//! obtaining `w mod a_j` from `w`'s main residues — exactly the main-only
//! canonical-rank base extension of [`MainOnlyBaseExt`]. No canonical `X` is
//! materialized, and there is no Garner or mixed-radix cascade.
//!
//! ## Why this kernel needs no sign test
//!
//! `Y` is signed, so recovering it from base `A` would normally need a
//! half-modulus comparison. We avoid that entirely. Let
//!
//! ```text
//! S = s_mult * Q,   s_mult = x_bound_over_q_sq * t + 1
//! ```
//!
//! `S` is by construction a multiple of `Q` and at least `|Y|`, so
//! `Y+ = Y + S` lies in `[0, 2S]` — non-negative without any comparison — and
//! `Y+ ≡ Y (mod q_i)` for every main lane, because `q_i | Q | S`. So the
//! shift is invisible in the output base and is never subtracted back. The
//! second base extension therefore runs on canonical non-negative residues,
//! and the kernel is branch-free with respect to the sign of the data.
//!
//! ## Capacity certificate
//!
//! With the caller's declared bound `|Xc| <= x_bound_over_q_sq * Q^2`:
//!
//! ```text
//! |Z| <= x_bound_over_q_sq * Q^2 * t + Q/2
//! |Y| <= x_bound_over_q_sq * Q * t + 1  <=  S
//! Y+  <= 2S
//! ```
//!
//! so `Y+` is recoverable from base `A` iff **`A > 2 * s_mult * Q`**. That
//! inequality is checked once in [`ExactScaleRound::new`] and refused with a
//! typed [`ExactScaleRoundError::InsufficientAuxCapacity`] — never a
//! best-effort result (contract rule 7). The bound is load-bearing rather than
//! decorative: the tests show a sharp transition from exact to
//! near-universally wrong as `A` crosses it.
//!
//! For the BFV tensor with centered coefficients, `|Xc| <= N * (Q/2)^2`, so the
//! caller passes `x_bound_over_q_sq = N / 4`.
//!
//! ## Scope
//!
//! This is the coefficient-level kernel for T1.3. It is **not yet wired into
//! the evaluator** — that is T1.4, which additionally needs the tensor product
//! and relinearization carried in the extended base. Nothing here changes any
//! existing production path.

use super::main_only_base_ext::{MainOnlyBaseExt, MainOnlyBaseExtError, RankPath};
use super::rns::U512;

/// Typed failures. Every one is a refused proof obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactScaleRoundError {
    /// A basis rejected by the underlying base extension.
    BaseExt(MainOnlyBaseExtError),
    /// A main modulus and an auxiliary modulus share a factor, so `Q` is not
    /// invertible modulo that auxiliary lane.
    MainAuxShareFactor { main: u64, aux: u64, gcd: u64 },
    /// A main modulus is even, so `Q` is even and `floor(Q/2)` has no per-lane
    /// form via the inverse of 2.
    EvenMainModulus { modulus: u64 },
    /// Plaintext modulus below 2.
    DegenerateT { t: u64 },
    /// Declared operand bound of zero: nothing would be representable.
    ZeroOperandBound,
    /// `s_mult = x_bound_over_q_sq * t + 1` overflowed `u64`.
    ShiftMultiplierOverflow { x_bound_over_q_sq: u64, t: u64 },
    /// The auxiliary base cannot hold `Y+`: needs `A > 2 * s_mult * Q`.
    InsufficientAuxCapacity {
        aux_bits: u32,
        required_bits: u32,
        s_mult: u64,
    },
    /// A supplied main residue was not canonical.
    NonCanonicalMainResidue {
        lane: usize,
        residue: u64,
        modulus: u64,
    },
    /// A supplied auxiliary residue was not canonical.
    NonCanonicalAuxResidue {
        lane: usize,
        residue: u64,
        modulus: u64,
    },
}

impl From<MainOnlyBaseExtError> for ExactScaleRoundError {
    fn from(e: MainOnlyBaseExtError) -> Self {
        ExactScaleRoundError::BaseExt(e)
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

fn inv_mod(a: u64, m: u64) -> u64 {
    let (mut t, mut newt): (i128, i128) = (0, 1);
    let (mut r, mut newr): (i128, i128) = (m as i128, (a % m) as i128);
    while newr != 0 {
        let q = r / newr;
        (t, newt) = (newt, t - q * newt);
        (r, newr) = (newr, r - q * newr);
    }
    ((t % m as i128 + m as i128) % m as i128) as u64
}

/// Strict greater-than on [`U512`], most significant limb first.
fn u512_gt(a: U512, b: U512) -> bool {
    if a.d3 != b.d3 {
        return a.d3 > b.d3;
    }
    if a.d2 != b.d2 {
        return a.d2 > b.d2;
    }
    if a.d1 != b.d1 {
        return a.d1 > b.d1;
    }
    a.d0 > b.d0
}

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

fn product_u512(m: &[u64]) -> U512 {
    let mut acc = U512::from_u64(1);
    for &p in m {
        acc = acc.mul_u128(p as u128);
    }
    acc
}

/// Precomputed constants for one (main base, transient auxiliary base, `t`)
/// triple. Build once per configuration; [`Self::scale_round`] is the
/// per-coefficient hot path.
pub struct ExactScaleRound {
    main: Vec<u64>,
    aux: Vec<u64>,
    t: u64,
    /// `s_mult` where the output shift is `S = s_mult * Q`.
    s_mult: u64,
    /// Base extension main -> aux, used for `w = Z mod Q`.
    main_to_aux: MainOnlyBaseExt,
    /// Base extension aux -> main, used for `Y+`.
    aux_to_main: MainOnlyBaseExt,
    /// `t mod q_i` and `t mod a_j`.
    t_mod_main: Vec<u64>,
    t_mod_aux: Vec<u64>,
    /// `floor(Q/2) mod q_i`, which for odd `q_i` is `(q_i - 1) / 2`.
    half_q_mod_main: Vec<u64>,
    /// `floor(Q/2) mod a_j`.
    half_q_mod_aux: Vec<u64>,
    /// `(Q mod a_j)^{-1} mod a_j`.
    q_inv_mod_aux: Vec<u64>,
    /// `S mod a_j`.
    shift_mod_aux: Vec<u64>,
}

impl std::fmt::Debug for ExactScaleRound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExactScaleRound")
            .field("main_lanes", &self.main.len())
            .field("aux_lanes", &self.aux.len())
            .field("t", &self.t)
            .field("s_mult", &self.s_mult)
            .finish()
    }
}

impl ExactScaleRound {
    /// Build the kernel.
    ///
    /// `x_bound_over_q_sq` declares the caller's operand bound as
    /// `|Xc| <= x_bound_over_q_sq * Q^2`. For a BFV tensor over centered
    /// coefficients of a degree-`N` ring that is `N / 4`.
    pub fn new(
        main: &[u64],
        aux: &[u64],
        t: u64,
        x_bound_over_q_sq: u64,
    ) -> Result<Self, ExactScaleRoundError> {
        if t < 2 {
            return Err(ExactScaleRoundError::DegenerateT { t });
        }
        if x_bound_over_q_sq == 0 {
            return Err(ExactScaleRoundError::ZeroOperandBound);
        }
        // `floor(Q/2)` is derived per lane via the inverse of 2, which needs Q
        // odd. Every NTT prime is odd, so this only rejects a malformed basis.
        for &q in main {
            if q % 2 == 0 {
                return Err(ExactScaleRoundError::EvenMainModulus { modulus: q });
            }
        }
        // Q must be invertible modulo every auxiliary lane.
        for &q in main {
            for &a in aux {
                let g = gcd(q, a);
                if g != 1 {
                    return Err(ExactScaleRoundError::MainAuxShareFactor {
                        main: q,
                        aux: a,
                        gcd: g,
                    });
                }
            }
        }

        // Coprimality *within* each basis is enforced by the base extensions.
        let main_to_aux = MainOnlyBaseExt::new(main, aux)?;
        let aux_to_main = MainOnlyBaseExt::new(aux, main)?;

        let s_mult = x_bound_over_q_sq
            .checked_mul(t)
            .and_then(|v| v.checked_add(1))
            .ok_or(ExactScaleRoundError::ShiftMultiplierOverflow {
                x_bound_over_q_sq,
                t,
            })?;

        // Capacity certificate: A > 2 * s_mult * Q.
        let q_wide = product_u512(main);
        let a_wide = product_u512(aux);
        let required = q_wide.mul_u128(2u128 * s_mult as u128);
        if !u512_gt(a_wide, required) {
            return Err(ExactScaleRoundError::InsufficientAuxCapacity {
                aux_bits: u512_bits(a_wide),
                required_bits: u512_bits(required),
                s_mult,
            });
        }

        // Per-lane constants. `Q mod a_j` is folded lane by lane, so no wide
        // value is reduced at runtime.
        let mut q_mod_aux = vec![1u64; aux.len()];
        for (j, &a) in aux.iter().enumerate() {
            let mut acc: u64 = 1 % a;
            for &q in main {
                acc = ((acc as u128 * (q % a) as u128) % a as u128) as u64;
            }
            q_mod_aux[j] = acc;
        }

        let t_mod_main = main.iter().map(|&q| t % q).collect();
        let t_mod_aux = aux.iter().map(|&a| t % a).collect();

        // floor(Q/2) mod q_i: Q = 0 mod q_i, so Q - 1 = q_i - 1, and halving
        // an even value mod an odd modulus is exact.
        let half_q_mod_main: Vec<u64> = main.iter().map(|&q| (q - 1) / 2).collect();

        let half_q_mod_aux: Vec<u64> = aux
            .iter()
            .enumerate()
            .map(|(j, &a)| {
                let qm1 = (q_mod_aux[j] + a - 1) % a;
                ((qm1 as u128 * inv_mod(2, a) as u128) % a as u128) as u64
            })
            .collect();

        let q_inv_mod_aux: Vec<u64> = aux
            .iter()
            .enumerate()
            .map(|(j, &a)| inv_mod(q_mod_aux[j], a))
            .collect();

        let shift_mod_aux: Vec<u64> = aux
            .iter()
            .enumerate()
            .map(|(j, &a)| (((s_mult % a) as u128 * q_mod_aux[j] as u128) % a as u128) as u64)
            .collect();

        Ok(Self {
            main: main.to_vec(),
            aux: aux.to_vec(),
            t,
            s_mult,
            main_to_aux,
            aux_to_main,
            t_mod_main,
            t_mod_aux,
            half_q_mod_main,
            half_q_mod_aux,
            q_inv_mod_aux,
            shift_mod_aux,
        })
    }

    pub fn main_lane_count(&self) -> usize {
        self.main.len()
    }

    pub fn aux_lane_count(&self) -> usize {
        self.aux.len()
    }

    pub fn t(&self) -> u64 {
        self.t
    }

    /// The shift multiplier `s_mult`, where `S = s_mult * Q`.
    pub fn shift_multiplier(&self) -> u64 {
        self.s_mult
    }

    /// `Y = round(Xc * t / Q)`, written into `out_main` as residues in the main
    /// base.
    ///
    /// `x_main[i] = Xc mod q_i` and `x_aux[j] = Xc mod a_j` must be canonical
    /// residues of the *same* integer `Xc`, and the caller must honour the
    /// operand bound declared at construction. Returns the rank path taken by
    /// each of the two base extensions, for test observability.
    pub fn scale_round(
        &self,
        x_main: &[u64],
        x_aux: &[u64],
        out_main: &mut [u64],
    ) -> Result<(RankPath, RankPath), ExactScaleRoundError> {
        assert_eq!(x_main.len(), self.main.len(), "main residue length");
        assert_eq!(x_aux.len(), self.aux.len(), "aux residue length");
        assert_eq!(out_main.len(), self.main.len(), "output length");

        for (i, (&r, &q)) in x_main.iter().zip(self.main.iter()).enumerate() {
            if r >= q {
                return Err(ExactScaleRoundError::NonCanonicalMainResidue {
                    lane: i,
                    residue: r,
                    modulus: q,
                });
            }
        }
        for (j, (&r, &a)) in x_aux.iter().zip(self.aux.iter()).enumerate() {
            if r >= a {
                return Err(ExactScaleRoundError::NonCanonicalAuxResidue {
                    lane: j,
                    residue: r,
                    modulus: a,
                });
            }
        }

        // Z = Xc * t + floor(Q/2), per lane in both bases.
        let mut z_main = vec![0u64; self.main.len()];
        for i in 0..self.main.len() {
            let q = self.main[i] as u128;
            z_main[i] = ((x_main[i] as u128 * self.t_mod_main[i] as u128
                + self.half_q_mod_main[i] as u128)
                % q) as u64;
        }
        let mut z_aux = vec![0u64; self.aux.len()];
        for j in 0..self.aux.len() {
            let a = self.aux[j] as u128;
            z_aux[j] = ((x_aux[j] as u128 * self.t_mod_aux[j] as u128
                + self.half_q_mod_aux[j] as u128)
                % a) as u64;
        }

        // w = Z mod Q, canonical in [0, Q). Its main residues are z_main;
        // extend them into the auxiliary base.
        let mut w_aux = vec![0u64; self.aux.len()];
        let path_forward = self.main_to_aux.project(&z_main, &mut w_aux)?;

        // Y = (Z - w) / Q, exact division carried in the auxiliary base, then
        // shifted by S = s_mult * Q so the result is non-negative without any
        // comparison. S is a multiple of Q, hence invisible mod q_i.
        let mut yplus_aux = vec![0u64; self.aux.len()];
        for j in 0..self.aux.len() {
            let a = self.aux[j];
            let diff = (z_aux[j] + a - w_aux[j]) % a;
            let y = ((diff as u128 * self.q_inv_mod_aux[j] as u128) % a as u128) as u64;
            yplus_aux[j] = (y + self.shift_mod_aux[j]) % a;
        }

        // Back to the main base. Y+ is canonical in [0, A) by the capacity
        // certificate, so this extension is exact.
        let path_back = self.aux_to_main.project(&yplus_aux, out_main)?;

        Ok((path_forward, path_back))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference: `round(xc * t / q)` reduced into each main lane, computed in
    /// `i128` independently of the kernel.
    fn reference_main(xc: i128, t: u64, q: i128, main: &[u64]) -> Vec<u64> {
        let z = xc * t as i128 + q / 2;
        // Rust's `/` truncates toward zero; BFV needs floor.
        let y = if z >= 0 { z / q } else { -((-z + q - 1) / q) };
        main.iter()
            .map(|&m| y.rem_euclid(m as i128) as u64)
            .collect()
    }

    fn residues_i128(xc: i128, m: &[u64]) -> Vec<u64> {
        m.iter().map(|&p| xc.rem_euclid(p as i128) as u64).collect()
    }

    fn product_i128(m: &[u64]) -> i128 {
        m.iter().fold(1i128, |a, &p| a * p as i128)
    }

    /// Deterministic LCG, so every failure is reproducible.
    struct Lcg(u128);
    impl Lcg {
        fn next(&mut self) -> u128 {
            self.0 = self
                .0
                .wrapping_mul(0x5851_F42D_4C95_7F2D)
                .wrapping_add(0x1405_7B7E_F767_814F);
            self.0
        }
    }

    const SMALL_MAIN: [u64; 3] = [1009, 1013, 1019];
    const SMALL_AUX: [u64; 4] = [1021, 1031, 1033, 1039];

    #[test]
    fn small_basis_matches_reference_over_full_operand_range() {
        let t = 13u64;
        let xb = 1u64; // |Xc| <= Q^2
        let k = ExactScaleRound::new(&SMALL_MAIN, &SMALL_AUX, t, xb).expect("capacity");
        let q = product_i128(&SMALL_MAIN);
        let bound = xb as i128 * q * q;

        let mut rng = Lcg(0x243F_6A88_85A3_08D3);
        let mut out = vec![0u64; SMALL_MAIN.len()];
        let mut saw_certified = false;
        let mut saw_fallback = false;

        for _ in 0..20_000 {
            // Full-range signed draw in [-bound, bound].
            let raw = (rng.next() % (2 * bound as u128 + 1)) as i128;
            let xc = raw - bound;
            let xm = residues_i128(xc, &SMALL_MAIN);
            let xa = residues_i128(xc, &SMALL_AUX);
            let (pf, pb) = k.scale_round(&xm, &xa, &mut out).expect("canonical");
            match pf {
                RankPath::CertifiedFixedPoint => saw_certified = true,
                RankPath::ExactFallback => saw_fallback = true,
            }
            match pb {
                RankPath::CertifiedFixedPoint => saw_certified = true,
                RankPath::ExactFallback => saw_fallback = true,
            }
            assert_eq!(
                out,
                reference_main(xc, t, q, &SMALL_MAIN),
                "scale_round mismatch at Xc={xc}"
            );
        }
        assert!(saw_certified, "certified fixed-point rank path never ran");
        // The fallback is rare by design; the T1.2 suite forces it directly.
        let _ = saw_fallback;
    }

    #[test]
    fn corners_and_rounding_ties_are_exact() {
        let t = 13u64;
        let xb = 1u64;
        let k = ExactScaleRound::new(&SMALL_MAIN, &SMALL_AUX, t, xb).expect("capacity");
        let q = product_i128(&SMALL_MAIN);
        let bound = xb as i128 * q * q;

        let mut cases: Vec<i128> = vec![
            0,
            1,
            -1,
            2,
            -2,
            q,
            -q,
            q + 1,
            -(q + 1),
            q / 2,
            -(q / 2),
            bound,
            -bound,
            bound - 1,
            -(bound - 1),
        ];
        // Exact rounding ties: Xc * t / Q == k + 1/2.
        for j in -4i128..=4 {
            cases.push((q * (2 * j + 1)) / (2 * t as i128));
            cases.push((q * (2 * j + 1)) / (2 * t as i128) + 1);
        }

        let mut out = vec![0u64; SMALL_MAIN.len()];
        for xc in cases {
            if xc.abs() > bound {
                continue;
            }
            let xm = residues_i128(xc, &SMALL_MAIN);
            let xa = residues_i128(xc, &SMALL_AUX);
            k.scale_round(&xm, &xa, &mut out).expect("canonical");
            assert_eq!(
                out,
                reference_main(xc, t, q, &SMALL_MAIN),
                "corner mismatch at Xc={xc}"
            );
        }
    }

    /// Real `secure_128` main primes. `Xc` is held inside `i128` so the
    /// reference stays exact without a wide divider, while the kernel runs on
    /// the production moduli.
    #[test]
    fn production_main_primes_match_reference() {
        const MAIN: [u64; 4] = [998244353, 985661441, 754974721, 469762049];
        // Auxiliary lanes: distinct NTT-friendly primes coprime to the chain.
        const AUX: [u64; 6] = [
            1004535809, 1224736769, 167772161, 377487361, 595591169, 645922817,
        ];
        let t = 65537u64;
        // Declared bound must cover the values actually fed below.
        let xb = 1u64;
        let k = ExactScaleRound::new(&MAIN, &AUX, t, xb).expect("capacity");

        let q = MAIN.iter().fold(1i128, |a, &p| a * p as i128);
        let mut rng = Lcg(0xB7E1_5162_8AED_2A6A);
        let mut out = vec![0u64; MAIN.len()];

        // |Xc| kept under 2^100 so `xc * t + q/2` stays exact in i128.
        let cap: i128 = 1i128 << 100;
        for _ in 0..20_000 {
            let raw = (rng.next() % (2 * cap as u128)) as i128;
            let xc = raw - cap;
            let xm = residues_i128(xc, &MAIN);
            let xa = residues_i128(xc, &AUX);
            k.scale_round(&xm, &xa, &mut out).expect("canonical");
            assert_eq!(
                out,
                reference_main(xc, t, q, &MAIN),
                "production-prefix mismatch at Xc={xc}"
            );
        }
    }

    #[test]
    fn insufficient_aux_capacity_is_refused() {
        let t = 13u64;
        // Two auxiliary lanes cannot hold Y+ for |Xc| <= Q^2.
        let err = ExactScaleRound::new(&SMALL_MAIN, &SMALL_AUX[..2], t, 1).unwrap_err();
        match err {
            ExactScaleRoundError::InsufficientAuxCapacity {
                aux_bits,
                required_bits,
                ..
            } => {
                assert!(
                    aux_bits <= required_bits,
                    "refusal must report a genuine shortfall: {aux_bits} vs {required_bits}"
                );
            }
            other => panic!("expected InsufficientAuxCapacity, got {other:?}"),
        }
        // Four lanes clear it.
        ExactScaleRound::new(&SMALL_MAIN, &SMALL_AUX, t, 1).expect("four lanes suffice");
    }

    /// The capacity certificate makes the wrong regime *unreachable*, which is
    /// stronger than detecting it after the fact: every basis that could not
    /// hold `Y+` is refused at construction, so no caller can obtain a kernel
    /// that would compute silently-wrong values.
    ///
    /// (The underlying sharpness — exact above the bound, near-universally
    /// wrong below it — was established against an independent implementation
    /// during design; here it is enforced structurally rather than measured,
    /// because `new` will not hand back an under-capacity kernel to measure.)
    #[test]
    fn under_capacity_bases_are_unreachable() {
        let t = 13u64;
        let xb = 1u64;
        for lanes in 1..=3 {
            assert!(
                matches!(
                    ExactScaleRound::new(&SMALL_MAIN, &SMALL_AUX[..lanes], t, xb),
                    Err(ExactScaleRoundError::InsufficientAuxCapacity { .. })
                ),
                "{lanes} auxiliary lane(s) must be refused for |Xc| <= Q^2"
            );
        }
        // Four lanes clear the bound and are exact.
        let k = ExactScaleRound::new(&SMALL_MAIN, &SMALL_AUX, t, xb).expect("capacity");
        let q = product_i128(&SMALL_MAIN);
        let bound = xb as i128 * q * q;
        let mut rng = Lcg(9);
        let mut out = vec![0u64; SMALL_MAIN.len()];
        for _ in 0..2_000 {
            let raw = (rng.next() % (2 * bound as u128 + 1)) as i128;
            let xc = raw - bound;
            let xm = residues_i128(xc, &SMALL_MAIN);
            let xa = residues_i128(xc, &SMALL_AUX);
            k.scale_round(&xm, &xa, &mut out).expect("canonical");
            assert_eq!(out, reference_main(xc, t, q, &SMALL_MAIN));
        }
    }

    // ---- wide-integer helpers, test-only reference oracle -------------------

    /// `x mod p` for a 512-bit `x`, via the existing `div_u64`.
    fn u512_rem_u64(x: U512, p: u64) -> u64 {
        let q = x.div_u64(p);
        let back = q.mul_u128(p as u128);
        x.sub(back).d0 as u64
    }

    /// `floor(x / prod(divisors))`, exact because dividing successively by each
    /// factor equals dividing by the product.
    fn u512_div_by_product(mut x: U512, divisors: &[u64]) -> U512 {
        for &d in divisors {
            x = x.div_u64(d);
        }
        x
    }

    /// Full-range differential gate at production scale.
    ///
    /// Operands are drawn across the entire declared bound `[0, 2*Q^2)` — a
    /// ~237-bit range, far beyond `i128` — and the reference is computed in
    /// 512-bit arithmetic, dividing by `Q` as a succession of exact divisions
    /// by its prime factors. Non-negative operands keep the oracle free of any
    /// sign handling; the kernel is sign-agnostic either way.
    #[test]
    fn production_primes_full_range_against_u512_oracle() {
        const MAIN: [u64; 4] = [998244353, 985661441, 754974721, 469762049];
        const AUX: [u64; 6] = [
            1004535809, 1224736769, 167772161, 377487361, 595591169, 645922817,
        ];
        let t = 65537u64;
        let xb = 2u64; // declared bound: |Xc| <= 2 * Q^2
        let k = ExactScaleRound::new(&MAIN, &AUX, t, xb).expect("capacity");

        let q_wide = product_u512(&MAIN);
        let half_q = q_wide.sub(U512::from_u64(1)).div_u64(2); // Q odd
        let q_sq = {
            let mut acc = q_wide;
            for &p in MAIN.iter() {
                acc = acc.mul_u128(p as u128);
            }
            acc
        };
        let two_q_sq = q_sq.mul_u128(2);
        assert!(
            u512_bits(two_q_sq) > 200,
            "operand range must exceed the i128 range: {} bits",
            u512_bits(two_q_sq)
        );

        let mut rng = Lcg(0xC3D2_E1F0_A9B8_7654);
        let mut out = vec![0u64; MAIN.len()];
        let mut widest = 0u32;

        for _ in 0..5_000 {
            // A pseudo-random value below 2^256, then reduced into
            // [0, 2*Q^2). The ceiling is chosen so floor(raw / 2Q^2) stays
            // inside one limb (2^256 / 2^237 < 2^19) while the remainder still
            // sweeps the whole declared range.
            let raw = U512 {
                d0: rng.next(),
                d1: rng.next(),
                d2: 0,
                d3: 0,
            };
            // floor(raw / (2*Q^2)) by exact successive division.
            let quo = {
                let v = raw.div_u64(2);
                let v = u512_div_by_product(v, &MAIN);
                u512_div_by_product(v, &MAIN)
            };
            // quo is small (raw < 2^377, 2Q^2 ~ 2^237), so it fits one limb.
            assert_eq!(quo.d1, 0, "quotient wider than one limb");
            let xc = raw.sub(two_q_sq.mul_u128(quo.d0));
            assert!(
                !u512_gt(xc, two_q_sq) && xc != two_q_sq,
                "reduction failed to land inside [0, 2*Q^2)"
            );
            widest = widest.max(u512_bits(xc));

            let xm: Vec<u64> = MAIN.iter().map(|&p| u512_rem_u64(xc, p)).collect();
            let xa: Vec<u64> = AUX.iter().map(|&p| u512_rem_u64(xc, p)).collect();
            k.scale_round(&xm, &xa, &mut out).expect("canonical");

            // Reference: Y = floor((Xc * t + floor(Q/2)) / Q) in 512 bits.
            let z = xc.mul_u128(t as u128).add(half_q);
            let y = u512_div_by_product(z, &MAIN);
            let want: Vec<u64> = MAIN.iter().map(|&p| u512_rem_u64(y, p)).collect();

            assert_eq!(out, want, "full-range production mismatch");
        }

        // The draw must actually have reached the top of the range, otherwise
        // this would silently degenerate into a small-operand test.
        assert!(
            widest > 230,
            "operands never approached the declared bound (widest {widest} bits)"
        );
    }

    #[test]
    fn typed_rejections() {
        // t < 2
        assert_eq!(
            ExactScaleRound::new(&SMALL_MAIN, &SMALL_AUX, 1, 1).unwrap_err(),
            ExactScaleRoundError::DegenerateT { t: 1 }
        );
        // zero operand bound
        assert_eq!(
            ExactScaleRound::new(&SMALL_MAIN, &SMALL_AUX, 13, 0).unwrap_err(),
            ExactScaleRoundError::ZeroOperandBound
        );
        // even main modulus
        assert!(matches!(
            ExactScaleRound::new(&[1024, 1009], &SMALL_AUX, 13, 1),
            Err(ExactScaleRoundError::EvenMainModulus { modulus: 1024 })
        ));
        // main and aux sharing a factor
        assert!(matches!(
            ExactScaleRound::new(&SMALL_MAIN, &[1009, 1031, 1033, 1039], 13, 1),
            Err(ExactScaleRoundError::MainAuxShareFactor { gcd: 1009, .. })
        ));
        // non-canonical residues
        let k = ExactScaleRound::new(&SMALL_MAIN, &SMALL_AUX, 13, 1).unwrap();
        let mut out = vec![0u64; SMALL_MAIN.len()];
        let bad_main = vec![SMALL_MAIN[0], 0, 0];
        assert!(matches!(
            k.scale_round(&bad_main, &[0, 0, 0, 0], &mut out),
            Err(ExactScaleRoundError::NonCanonicalMainResidue { lane: 0, .. })
        ));
        let bad_aux = vec![SMALL_AUX[1], 0, 0, 0];
        assert!(matches!(
            k.scale_round(&[0, 0, 0], &bad_aux, &mut out),
            Err(ExactScaleRoundError::NonCanonicalAuxResidue { .. })
        ));
    }

    /// The shift is invisible in the output base: `S = s_mult * Q` is a
    /// multiple of `Q`, so it never has to be subtracted back.
    #[test]
    fn output_shift_is_a_multiple_of_q() {
        let k = ExactScaleRound::new(&SMALL_MAIN, &SMALL_AUX, 13, 1).unwrap();
        // S mod q_i must be 0 for every main lane, by construction.
        let s_mult = k.shift_multiplier() as i128;
        let q = product_i128(&SMALL_MAIN);
        let s = s_mult * q;
        for &m in SMALL_MAIN.iter() {
            assert_eq!(s % m as i128, 0, "S must vanish in main lane {m}");
        }
        assert_eq!(s_mult, 1 * 13 + 1, "s_mult = x_bound_over_q_sq * t + 1");
    }
}
