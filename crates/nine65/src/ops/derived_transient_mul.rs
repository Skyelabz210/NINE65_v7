//! Derived-transient exact BFV ciphertext multiply (Track 1, PR #103, T1.4).
//!
//! This module is the **evaluator integration** stage of Track 1: it wires
//! [`crate::arithmetic::main_only_base_ext::MainOnlyBaseExt`] and
//! [`crate::arithmetic::exact_scale_round::ExactScaleRound`] into an actual
//! BFV ciphertext x ciphertext multiply, via
//! [`DerivedTransientMulContext::mul_experimental`].
//!
//! ## Status: experimental, additive, non-production
//!
//! Nothing here changes any existing production path. `RNSFHEContext::mul`,
//! `RNSFHEContext::exact_rescale`, `RNSFHEContext::relinearize`,
//! `RNSFHEContext::rns_poly_mul`, `AutoBootstrapEvaluator::mul_auto`, and every
//! other existing entry point are byte-for-byte unchanged and this module is
//! not called from any of them. `mul_experimental` is reachable only by
//! calling it directly.
//!
//! `ops::rns_fhe::track1_exact_multiply_lock` (test-only) separately pins the
//! fact that `RNSFHEContext::mul` gives *wrong* plaintexts on a chain where
//! `Delta^2 > Q`, because `exact_rescale` is only a limb-local (Bajard-style)
//! approximation. That lock test is untouched by this module: it still locks
//! `mul()` itself, which this module does not fix and does not call. This
//! module is a **separate, parallel, correct route** to the same operation,
//! proven correct on the identical chain and operands the lock test uses (see
//! `tests::derived_transient_route_is_exact_where_public_mul_is_wrong` below).
//!
//! ## Why the naive "project the raw residues" reading is wrong
//!
//! A ciphertext coefficient is stored as **canonical** residues in
//! `[0, q_i)` per main lane. BFV's rescale-by-`t/Q` step is only meaningful
//! when applied to the **centered** representative of the tensor-product
//! coefficient (the value bounded by `N * (Q/2)^2` the module doc on
//! [`ExactScaleRound`](crate::arithmetic::exact_scale_round::ExactScaleRound)
//! assumes, matching `x_bound_over_q_sq = N / 4`) — this is exactly the
//! centered-lift convention `RNSFHEContext::decrypt` itself applies to its
//! own reconstructed `inner` value before rounding.
//!
//! Main-track residues (`mod q_i`) do not care which representative you
//! reason about: modular arithmetic is congruence-invariant, so the raw
//! `rns_poly_mul` tensor is correct regardless. The **auxiliary track does
//! care**: an auxiliary prime `a_j` has no divisibility relationship to `Q`,
//! so the canonical ([0, Q)) and centered ((-Q/2, Q/2]) representatives of a
//! ciphertext coefficient project to *different* residues mod `a_j` whenever
//! the canonical value exceeds `Q/2`. Projecting the raw canonical residues
//! into the auxiliary base (skipping this correction) would silently feed
//! the aux-track convolution the wrong integer for roughly half of all
//! coefficients, and `scale_round` would then compute an exact answer to the
//! wrong question.
//!
//! The fix, applied once per input coefficient in [`Self::project_centered`]:
//! reconstruct the coefficient's canonical value (main lanes only — main
//! bases here are 3-6 small NTT primes, so this fits `u128`; see
//! `RNSFHEContext::decompose_rns_poly` and `RNSFHEContext::decrypt` for the
//! same pattern already in production use), compare it against `Q/2`, and
//! when it is in the upper half, subtract `Q mod a_j` from the raw
//! auxiliary projection. This yields the auxiliary residues of the
//! **centered** ciphertext coefficient, matching what the main track already
//! computes congruence-invariantly, so both tracks carry residues of the
//! *same* real integer `Xc` into the tensor product.
//!
//! ## Known follow-up (throughput, not correctness)
//!
//! The auxiliary-track tensor ([`negacyclic_mul_mod`]) is direct O(N^2)
//! schoolbook negacyclic convolution, not NTT: there is no NTT engine wired
//! up for arbitrary auxiliary primes yet, and matching an NTT engine's exact
//! Montgomery/domain convention by hand for a first cut was judged a needless
//! correctness risk. This is a documented next step, not a correctness gap.
//!
//! ## What never leaves this module
//!
//! No auxiliary residue is ever part of the returned [`RNSCiphertext`] — only
//! `e0`/`e1`/`e2`, converted back to Montgomery form and passed through the
//! existing (unmodified) `relinearize`, are returned. Every auxiliary-domain
//! intermediate (`a_c0_1`, `a_c1_1`, `a_c0_2`, `a_c1_2`, `d0_aux`, `d1_aux`,
//! `d2_aux`) is held in a [`Zeroizing`] buffer and is zeroized well before
//! this function returns.

use super::*;
use crate::arithmetic::exact_scale_round::{ExactScaleRound, ExactScaleRoundError};
use crate::arithmetic::main_only_base_ext::{MainOnlyBaseExt, MainOnlyBaseExtError};

/// Typed failures for the derived-transient route. Self-contained: it does
/// not touch `crate::errors::Nine65Error`, exactly like
/// [`ExactScaleRoundError`] does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedTransientMulError {
    /// A basis rejected by the underlying main-only base extension.
    BaseExt(MainOnlyBaseExtError),
    /// A basis or bound rejected by the underlying exact scale-and-round.
    ScaleRound(ExactScaleRoundError),
    /// The main modulus `Q` does not fit in `u128`. The per-coefficient
    /// input-centering step in [`DerivedTransientMulContext::project_centered`]
    /// needs to compare each coefficient's canonical main-base reconstruction
    /// against `Q/2`; that reconstruction is only implemented here for a
    /// main base whose product fits `u128` (3-6 small NTT primes, as used by
    /// every config this stage targets). Wiring the multi-limb comparison for
    /// larger main bases is a documented follow-up, not attempted here.
    MainModulusExceedsU128 { q_bits: usize },
    /// `2 * x_bound_over_q_sq` (the bound this module actually certifies the
    /// shared scale-round kernel for, to cover the d1 cross term -- see
    /// [`DerivedTransientMulContext::new`]) overflowed `u64`.
    OperandBoundOverflow { x_bound_over_q_sq: u64 },
    /// A [`DerivedTransientMulContext`] was applied to an [`RNSFHEContext`]
    /// whose main primes do not match the ones it was built with. Combining
    /// residues certified for one basis with ciphertext data from another
    /// would silently corrupt the centering correction and the rescale --
    /// refused as a typed error rather than left to a `debug_assert!` that
    /// compiles out in `--release` (the build mode this project's own tests
    /// run under).
    MainBasisMismatch,
}

impl From<MainOnlyBaseExtError> for DerivedTransientMulError {
    fn from(e: MainOnlyBaseExtError) -> Self {
        DerivedTransientMulError::BaseExt(e)
    }
}

impl From<ExactScaleRoundError> for DerivedTransientMulError {
    fn from(e: ExactScaleRoundError) -> Self {
        DerivedTransientMulError::ScaleRound(e)
    }
}

/// Negacyclic polynomial multiplication mod a prime `p`: coefficients of
/// `a(X) * b(X) mod (X^N + 1) mod p`, via direct schoolbook convolution.
///
/// For index pairs `(i, j)` with `i + j == k`, the contribution is `+a[i]*b[j]`.
/// For pairs with `i + j == k + N` (wrapping past degree `N-1`), the
/// contribution is `-a[i]*b[j]`, because `X^N == -1` in this ring. The running
/// sum for each output coefficient is accumulated in `i128` (both signs, no
/// intermediate reduction) and reduced mod `p` exactly once at the end, so no
/// partial sum is ever allowed to wrap silently.
fn negacyclic_mul_mod(a: &[u64], b: &[u64], p: u64) -> Vec<u64> {
    let n = a.len();
    assert_eq!(b.len(), n, "negacyclic_mul_mod: length mismatch");
    let p_i = p as i128;
    let mut out = vec![0u64; n];
    for k in 0..n {
        let mut acc: i128 = 0;
        for i in 0..=k {
            acc += a[i] as i128 * b[k - i] as i128;
        }
        for i in (k + 1)..n {
            acc -= a[i] as i128 * b[k - i + n] as i128;
        }
        let reduced = ((acc % p_i) + p_i) % p_i;
        out[k] = reduced as u64;
    }
    out
}

/// Precomputed constants for one (main base, transient auxiliary base, `t`,
/// operand bound) configuration. Build once per configuration;
/// [`Self::mul_experimental`] is the per-call hot path.
pub struct DerivedTransientMulContext {
    main: Vec<u64>,
    aux: Vec<u64>,
    /// Base extension main -> aux, used to project ciphertext coefficients.
    to_aux: MainOnlyBaseExt,
    /// Exact scale-and-round kernel over (main, aux, t, bound).
    scale_round: ExactScaleRound,
    /// `Q mod a_j` for each auxiliary lane, needed to correct a raw canonical
    /// auxiliary projection into a centered one (see module docs).
    q_mod_aux: Vec<u64>,
}

impl std::fmt::Debug for DerivedTransientMulContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedTransientMulContext")
            .field("main_lanes", &self.main.len())
            .field("aux_lanes", &self.aux.len())
            .finish()
    }
}

impl DerivedTransientMulContext {
    /// Build the context. `x_bound_over_q_sq` is the SAME single-tensor-term
    /// bound `ExactScaleRound::new` documents: for a BFV tensor over
    /// centered coefficients of a degree-`N` ring, a single product
    /// `d0 = c0_1*c0_2` or `d2 = c1_1*c1_2` satisfies `|d| <= N * (Q/2)^2`,
    /// i.e. `x_bound_over_q_sq = N / 4` (see
    /// `crate::arithmetic::exact_scale_round`'s module doc, "Capacity
    /// certificate").
    ///
    /// # Why this module doubles the bound internally
    ///
    /// `d1 = c0_1*c1_2 + c1_1*c0_2` (see [`Self::mul_experimental`]) is a
    /// **sum** of two such products, so by the triangle inequality its true
    /// magnitude bound is `2 * N * (Q/2)^2` -- double the single-term one.
    /// All three tensor terms are routed through one shared `scale_round`
    /// kernel below (deliberately: a single kernel with no per-term
    /// dispatch removes an entire class of "routed to the wrong kernel"
    /// bugs), so that kernel must be built for the LARGER of the two true
    /// bounds. This constructor therefore certifies `ExactScaleRound` with
    /// `2 * x_bound_over_q_sq`, not the caller's raw value -- a harmless
    /// over-certification for d0/d2 (they never approach the doubled bound)
    /// and load-bearing for d1 (which routinely does: BFV ciphertext
    /// components look close to uniform over `Z_Q` in normal operation, not
    /// only in adversarial worst cases, so d1 is not a remote corner).
    ///
    /// (This was a real defect in the first implementation of this module,
    /// found by adversarial review: the shared kernel was built directly
    /// from the caller's `x_bound_over_q_sq`, silently undercertifying d1.
    /// It produced a wrong `e1` -- and therefore a corrupted ciphertext,
    /// with `mul_experimental` reporting success -- whenever d1's true
    /// coefficient magnitude exceeded the single-term bound, which the
    /// original decisive test never exercised because its auxiliary base
    /// happened to carry ~60 bits more capacity than either bound required.
    /// See `tests::d1_cross_term_needs_double_the_single_product_bound` for a
    /// direct reproduction of that defect against `ExactScaleRound` alone,
    /// and
    /// `tests::context_construction_requires_doubled_capacity_not_just_the_documented_single_term_bound`
    /// for proof that this constructor's real code path -- not just this
    /// doc comment -- now asks for the doubled bound.)
    pub fn new(
        main: &[u64],
        aux: &[u64],
        t: u64,
        x_bound_over_q_sq: u64,
    ) -> Result<Self, DerivedTransientMulError> {
        let to_aux = MainOnlyBaseExt::new(main, aux)?;
        let doubled_bound = x_bound_over_q_sq
            .checked_mul(2)
            .ok_or(DerivedTransientMulError::OperandBoundOverflow { x_bound_over_q_sq })?;
        let scale_round = ExactScaleRound::new(main, aux, t, doubled_bound)?;

        // Q mod a_j, for the input-centering correction. A direct scalar
        // product reduced lane by lane -- not a Garner/mixed-radix
        // reconstruction of Q itself.
        let q_mod_aux: Vec<u64> = aux
            .iter()
            .map(|&a| {
                let mut acc: u128 = 1 % a as u128;
                for &m in main {
                    acc = (acc * (m as u128 % a as u128)) % a as u128;
                }
                acc as u64
            })
            .collect();

        Ok(Self {
            main: main.to_vec(),
            aux: aux.to_vec(),
            to_aux,
            scale_round,
            q_mod_aux,
        })
    }

    pub fn main_lane_count(&self) -> usize {
        self.main.len()
    }

    pub fn aux_lane_count(&self) -> usize {
        self.aux.len()
    }

    /// Project one plain-domain (standard residues, not Montgomery) ciphertext
    /// polynomial into the auxiliary base, coefficient by coefficient,
    /// correcting each projection from the canonical `[0, Q)` representative
    /// to the centered `(-Q/2, Q/2]` one (see module docs for why this
    /// correction is necessary). Shaped `[aux_lane][coeff_index]`.
    fn project_centered(
        &self,
        ctx: &RNSFHEContext,
        poly: &RNSPolynomial,
    ) -> Result<Zeroizing<Vec<Vec<u64>>>, DerivedTransientMulError> {
        if ctx.q_product == 0 {
            return Err(DerivedTransientMulError::MainModulusExceedsU128 { q_bits: ctx.q_bits });
        }
        // A real Result check, not `debug_assert!` -- the latter compiles
        // out entirely in `--release`, which is how every test command in
        // this project actually runs (see CLAUDE.md's Build & Test
        // Commands). A mismatched basis here would silently combine
        // residues certified for one main-prime chain with ciphertext data
        // from another, corrupting the centering correction with no error.
        if ctx.config.primes != self.main {
            return Err(DerivedTransientMulError::MainBasisMismatch);
        }

        let main_lanes = self.main.len();
        let aux_lanes = self.aux.len();
        let n = poly.n;
        let q_half = ctx.q_product / 2;

        let mut out: Vec<Vec<u64>> = vec![vec![0u64; n]; aux_lanes];
        let mut coeff_main = vec![0u64; main_lanes];
        let mut coeff_aux = vec![0u64; aux_lanes];

        for k in 0..n {
            for lane in 0..main_lanes {
                coeff_main[lane] = poly.limbs[lane][k];
            }
            self.to_aux.project(&coeff_main, &mut coeff_aux)?;

            let canonical = ctx.rns.to_int(&coeff_main);
            if canonical > q_half {
                for j in 0..aux_lanes {
                    let a = self.aux[j];
                    coeff_aux[j] = (coeff_aux[j] + a - self.q_mod_aux[j]) % a;
                }
            }

            for j in 0..aux_lanes {
                out[j][k] = coeff_aux[j];
            }
        }

        Ok(Zeroizing::new(out))
    }

    /// Experimental derived-transient exact BFV ciphertext multiply.
    ///
    /// Computes the same operation as `RNSFHEContext::mul` (tensor product,
    /// exact scale-and-round, relinearize), but replaces the limb-local
    /// (Bajard-style) `exact_rescale` -- which is only an approximation valid
    /// when `Delta^2 <= Q` -- with the exact derived-transient route: the
    /// same tensor product is additionally carried through a transient
    /// auxiliary base wide enough to certify the rescale exactly (see
    /// `ExactScaleRound`'s "Capacity certificate"), and no auxiliary residue
    /// is ever part of the result.
    ///
    /// Not wired into any existing call path. See module docs for scope,
    /// the centering subtlety, and the O(N^2) aux-track follow-up.
    pub fn mul_experimental(
        &self,
        ctx: &RNSFHEContext,
        ct1: &RNSCiphertext,
        ct2: &RNSCiphertext,
        ek: &RNSEvalKey,
    ) -> Result<RNSCiphertext, DerivedTransientMulError> {
        let n = ctx.n;
        let main_lanes = self.main.len();
        let aux_lanes = self.aux.len();

        // (a) Montgomery -> plain standard domain, matching exact_rescale's
        // own first step.
        let p_c0_1 = ctx.convert_from_montgomery_form(&ct1.c0);
        let p_c1_1 = ctx.convert_from_montgomery_form(&ct1.c1);
        let p_c0_2 = ctx.convert_from_montgomery_form(&ct2.c0);
        let p_c1_2 = ctx.convert_from_montgomery_form(&ct2.c1);

        // (b) Project each, coefficient by coefficient, into the auxiliary
        // base, with the canonical -> centered correction.
        let a_c0_1 = self.project_centered(ctx, &p_c0_1)?;
        let a_c1_1 = self.project_centered(ctx, &p_c1_1)?;
        let a_c0_2 = self.project_centered(ctx, &p_c0_2)?;
        let a_c1_2 = self.project_centered(ctx, &p_c1_2)?;

        // (c) Main-track tensor: verbatim from `RNSFHEContext::mul`.
        let d0 = ctx.rns_poly_mul(&ct1.c0, &ct2.c0);
        let c0_1_c1_2 = ctx.rns_poly_mul(&ct1.c0, &ct2.c1);
        let c1_1_c0_2 = ctx.rns_poly_mul(&ct1.c1, &ct2.c0);
        let d1 = c0_1_c1_2.add(&c1_1_c0_2, &ctx.rns);
        let d2 = ctx.rns_poly_mul(&ct1.c1, &ct2.c1);

        // (d) Aux-track tensor: same three-product structure, per aux lane,
        // via direct negacyclic schoolbook convolution.
        let mut d0_aux: Zeroizing<Vec<Vec<u64>>> = Zeroizing::new(vec![vec![0u64; n]; aux_lanes]);
        let mut d1_aux: Zeroizing<Vec<Vec<u64>>> = Zeroizing::new(vec![vec![0u64; n]; aux_lanes]);
        let mut d2_aux: Zeroizing<Vec<Vec<u64>>> = Zeroizing::new(vec![vec![0u64; n]; aux_lanes]);

        for lane in 0..aux_lanes {
            let p = self.aux[lane];

            d0_aux[lane] = negacyclic_mul_mod(&a_c0_1[lane], &a_c0_2[lane], p);

            let t01 = negacyclic_mul_mod(&a_c0_1[lane], &a_c1_2[lane], p);
            let t10 = negacyclic_mul_mod(&a_c1_1[lane], &a_c0_2[lane], p);
            let mut sum = vec![0u64; n];
            for k in 0..n {
                let s = t01[k] as u128 + t10[k] as u128;
                sum[k] = (s % p as u128) as u64;
            }
            d1_aux[lane] = sum;

            d2_aux[lane] = negacyclic_mul_mod(&a_c1_1[lane], &a_c1_2[lane], p);
        }

        // (e) Main tensor -> plain standard domain, matching exact_rescale's
        // own next step, applied to the SAME d0/d1/d2 mul() itself produces.
        let pd0 = ctx.convert_from_montgomery_form(&d0);
        let pd1 = ctx.convert_from_montgomery_form(&d1);
        let pd2 = ctx.convert_from_montgomery_form(&d2);

        // (f) Exact scale-and-round, per coefficient, for each of the three
        // tensor terms.
        let mut e0 = RNSPolynomial {
            limbs: vec![vec![0u64; n]; main_lanes],
            n,
        };
        let mut e1 = RNSPolynomial {
            limbs: vec![vec![0u64; n]; main_lanes],
            n,
        };
        let mut e2 = RNSPolynomial {
            limbs: vec![vec![0u64; n]; main_lanes],
            n,
        };

        let mut x_main = vec![0u64; main_lanes];
        let mut x_aux = vec![0u64; aux_lanes];
        let mut out_main = vec![0u64; main_lanes];

        for k in 0..n {
            for lane in 0..main_lanes {
                x_main[lane] = pd0.limbs[lane][k];
            }
            for lane in 0..aux_lanes {
                x_aux[lane] = d0_aux[lane][k];
            }
            self.scale_round
                .scale_round(&x_main, &x_aux, &mut out_main)?;
            for lane in 0..main_lanes {
                e0.limbs[lane][k] = out_main[lane];
            }

            for lane in 0..main_lanes {
                x_main[lane] = pd1.limbs[lane][k];
            }
            for lane in 0..aux_lanes {
                x_aux[lane] = d1_aux[lane][k];
            }
            self.scale_round
                .scale_round(&x_main, &x_aux, &mut out_main)?;
            for lane in 0..main_lanes {
                e1.limbs[lane][k] = out_main[lane];
            }

            for lane in 0..main_lanes {
                x_main[lane] = pd2.limbs[lane][k];
            }
            for lane in 0..aux_lanes {
                x_aux[lane] = d2_aux[lane][k];
            }
            self.scale_round
                .scale_round(&x_main, &x_aux, &mut out_main)?;
            for lane in 0..main_lanes {
                e2.limbs[lane][k] = out_main[lane];
            }
        }

        // (i) Every auxiliary-domain intermediate is zeroized now, well
        // before returning -- none of it is, or ever becomes, part of the
        // result.
        drop(a_c0_1);
        drop(a_c1_1);
        drop(a_c0_2);
        drop(a_c1_2);
        drop(d0_aux);
        drop(d1_aux);
        drop(d2_aux);

        // (g) Back to Montgomery form, matching exact_rescale's own last
        // step and what `relinearize` expects.
        let e0_mont = ctx.to_montgomery_form(&e0);
        let e1_mont = ctx.to_montgomery_form(&e1);
        let e2_mont = ctx.to_montgomery_form(&e2);

        // (h) Relinearize via the existing, unmodified private method.
        Ok(ctx.relinearize(&e0_mont, &e1_mont, &e2_mont, ek))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic LCG, matching the idiom in
    /// `arithmetic::exact_scale_round`'s own tests, so every failure is
    /// reproducible.
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

    // ---- negacyclic_mul_mod, tested in isolation ---------------------------

    /// Brute-force reference: build the full-degree product over i128
    /// accumulators with no modular reduction, reduce `X^N+1` by hand
    /// (subtract the top half from the bottom half), then reduce mod `p`.
    fn negacyclic_mul_mod_reference(a: &[u64], b: &[u64], p: u64) -> Vec<u64> {
        let n = a.len();
        assert_eq!(b.len(), n);
        // Full (unreduced) convolution, degree up to 2N-2.
        let mut full = vec![0i128; 2 * n - 1];
        for i in 0..n {
            for j in 0..n {
                full[i + j] += a[i] as i128 * b[j] as i128;
            }
        }
        // Reduce X^N + 1: coefficient of X^(N+m) becomes -X^m for m in [0,N-2].
        let mut reduced = vec![0i128; n];
        for deg in 0..(2 * n - 1) {
            let coeff = full[deg];
            if deg < n {
                reduced[deg] += coeff;
            } else {
                reduced[deg - n] -= coeff;
            }
        }
        let p_i = p as i128;
        reduced
            .into_iter()
            .map(|c| (((c % p_i) + p_i) % p_i) as u64)
            .collect()
    }

    fn lcg_vec(rng: &mut Lcg, n: usize, p: u64) -> Vec<u64> {
        (0..n).map(|_| (rng.next() % p as u128) as u64).collect()
    }

    #[test]
    fn negacyclic_mul_mod_matches_brute_force_reference() {
        let cases: [(usize, u64); 4] = [(8, 1009), (16, 1013), (8, 2), (16, 65521)];
        let mut rng = Lcg(0x1234_5678_9ABC_DEF0);
        for (n, p) in cases {
            for _ in 0..20 {
                let a = lcg_vec(&mut rng, n, p);
                let b = lcg_vec(&mut rng, n, p);
                let got = negacyclic_mul_mod(&a, &b, p);
                let want = negacyclic_mul_mod_reference(&a, &b, p);
                assert_eq!(got, want, "mismatch at N={n}, p={p}, a={a:?}, b={b:?}");
            }
        }
    }

    #[test]
    fn negacyclic_mul_mod_corner_inputs() {
        for &(n, p) in &[(8usize, 1009u64), (16, 65521)] {
            let zero = vec![0u64; n];
            let max = vec![p - 1; n];

            let got_zero = negacyclic_mul_mod(&zero, &zero, p);
            assert_eq!(got_zero, negacyclic_mul_mod_reference(&zero, &zero, p));
            assert!(got_zero.iter().all(|&c| c == 0));

            let got_max = negacyclic_mul_mod(&max, &max, p);
            assert_eq!(got_max, negacyclic_mul_mod_reference(&max, &max, p));

            let got_mixed = negacyclic_mul_mod(&zero, &max, p);
            assert_eq!(got_mixed, negacyclic_mul_mod_reference(&zero, &max, p));
            assert!(got_mixed.iter().all(|&c| c == 0));
        }
    }

    // ---- coefficient-level pipeline sanity (no ciphertexts) ---------------

    /// Auxiliary lanes reused for the decisive ciphertext-level test below:
    /// the exact constants already validated for the production main-prime
    /// prefix in `arithmetic::exact_scale_round`'s own production test.
    const AUX: [u64; 6] = [
        1004535809, 1224736769, 167772161, 377487361, 595591169, 645922817,
    ];

    fn residues_i128(xc: i128, m: &[u64]) -> Vec<u64> {
        m.iter().map(|&p| xc.rem_euclid(p as i128) as u64).collect()
    }

    fn product_i128(m: &[u64]) -> i128 {
        m.iter().fold(1i128, |a, &p| a * p as i128)
    }

    /// Independent reference: `round(xc * t / q)` reduced into the main
    /// lanes, computed in i128, mirroring `exact_scale_round`'s own
    /// `reference_main`.
    fn reference_main(xc: i128, t: u64, q: i128, main: &[u64]) -> Vec<u64> {
        let z = xc * t as i128 + q / 2;
        let y = if z >= 0 { z / q } else { -((-z + q - 1) / q) };
        main.iter()
            .map(|&m| y.rem_euclid(m as i128) as u64)
            .collect()
    }

    // Small basis for the direct-coefficient sanity check below: keeps the
    // full operand bound `xb * Q^2` inside i128 so the independent reference
    // (`reference_main`) can stay exact without a wide divider. The decisive
    // proof of the real production chain (with its real, much larger bound)
    // is `derived_transient_route_is_exact_where_public_mul_is_wrong` below,
    // which exercises the identical MAIN/AUX/x_bound_over_q_sq the ciphertext
    // pipeline actually uses.
    const SMALL_MAIN: [u64; 3] = [1009, 1013, 1019];
    const SMALL_AUX: [u64; 4] = [1021, 1031, 1033, 1039];

    #[test]
    fn scale_round_pipeline_matches_reference_on_direct_coefficients() {
        let t = 13u64;
        let xb = 1u64;
        let ctx =
            DerivedTransientMulContext::new(&SMALL_MAIN, &SMALL_AUX, t, xb).expect("capacity");
        let q = product_i128(&SMALL_MAIN);
        let bound = xb as i128 * q * q;

        let mut rng = Lcg(0xABCD_EF01_2345_6789);
        let mut out = vec![0u64; SMALL_MAIN.len()];
        for _ in 0..2_000 {
            let raw = (rng.next() % (2 * bound as u128 + 1)) as i128;
            let xc = raw - bound;
            let xm = residues_i128(xc, &SMALL_MAIN);
            let xa = residues_i128(xc, &SMALL_AUX);
            ctx.scale_round
                .scale_round(&xm, &xa, &mut out)
                .expect("canonical");
            assert_eq!(
                out,
                reference_main(xc, t, q, &SMALL_MAIN),
                "mismatch at Xc={xc}"
            );
        }
    }

    // ---- the d1-capacity defect: reproduced, then proven fixed -------------

    /// A single auxiliary prime with the SMALLEST margin above
    /// `2*(1*13+1)*Q = 29_163_042_244` (`Q = 1009*1013*1019 =
    /// 1_041_537_223`) that is still prime: `29_163_042_253`, only 9 above
    /// the bare minimum for `x_bound_over_q_sq = 1` to construct at all
    /// (confirmed prime by Miller-Rabin, coprime to every `SMALL_MAIN`
    /// factor). Deliberately tight, not merely "less than the doubled
    /// bound's requirement" -- an aux base can have *accidental* margin
    /// past its officially declared bound (the exact phenomenon that let
    /// the original defect hide behind this module's first decisive test,
    /// whose auxiliary base carried ~60 bits more capacity than either
    /// bound required). A base with only single-digit headroom leaves no
    /// room for that: its true break point (where `Y + S` first reaches
    /// this prime) lands at `Xc ~ 1.077 * Q^2` -- safely inside `(Q^2,
    /// 2*Q^2]`, so `Xc = 1.5*Q^2` below is genuinely, not just officially,
    /// beyond what this base can carry at `x_bound_over_q_sq = 1`. It is
    /// also, as required, insufficient for the doubled bound
    /// (`2*(2*13+1)*Q = 56_243_010_042 > 29_163_042_253`).
    const TIGHT_AUX: [u64; 1] = [29_163_042_253];

    /// **Reproduces the exact defect found in adversarial review of this
    /// module's first implementation**, directly against `ExactScaleRound`
    /// (the primitive the bug was in the *use* of, not in itself --
    /// `ExactScaleRound`'s own capacity certificate was and remains sound;
    /// see `arithmetic::exact_scale_round`'s tests). A context certified
    /// only for the single-tensor-term bound (`x_bound_over_q_sq = 1`,
    /// i.e. what `d0`/`d2` need) is silently WRONG -- not refused, not
    /// panicking, just wrong -- on a value squarely inside the doubled
    /// (`d1`-sized) range `Q^2 < |Xc| <= 2*Q^2`. A context certified for the
    /// doubled bound (`x_bound_over_q_sq = 2`) is exact at the identical
    /// input. This is why `DerivedTransientMulContext::new` internally
    /// doubles the caller's bound before building its shared kernel (see
    /// that constructor's doc comment).
    #[test]
    fn d1_cross_term_needs_double_the_single_product_bound() {
        let t = 13u64;
        let q = product_i128(&SMALL_MAIN);

        // Squarely inside (Q^2, 2*Q^2] -- reachable by d1, unreachable by a
        // single product d0/d2.
        let xc: i128 = q * q + (q * q) / 2;
        assert!(
            xc > q * q && xc <= 2 * q * q,
            "test setup: xc must be d1-range, not d0/d2-range"
        );

        let xm = residues_i128(xc, &SMALL_MAIN);
        let xa_tight = residues_i128(xc, &TIGHT_AUX);
        let want = reference_main(xc, t, q, &SMALL_MAIN);

        // Undersized: builds fine (xb=1's capacity requirement is met), but
        // is silently wrong at this input -- the exact "wrong-but-plausible
        // plaintext, no error raised anywhere" failure class Track 1 exists
        // to eliminate. (Verified against the real kernel arithmetic, not
        // just the Y+S >= A criterion, before this constant was chosen: at
        // Xc=1.5*Q^2, Y+S = 34_891_496_970 >= TIGHT_AUX = 29_163_042_253, so
        // the single-lane reconstruction is a genuine, not coincidental,
        // wraparound.)
        let undersized = ExactScaleRound::new(&SMALL_MAIN, &TIGHT_AUX, t, 1)
            .expect("xb=1 (undoubled) must construct: TIGHT_AUX clears 2*S(1) by design");
        let mut out_bad = vec![0u64; SMALL_MAIN.len()];
        undersized
            .scale_round(&xm, &xa_tight, &mut out_bad)
            .expect("scale_round has no runtime bound check -- it returns Ok even when wrong");
        assert_ne!(
            out_bad, want,
            "undersized (xb=1) context was expected to be silently wrong at 1.5*Q^2; \
             if it is now right, TIGHT_AUX no longer demonstrates the defect -- investigate"
        );

        // TIGHT_AUX itself cannot hold the doubled bound -- refused at
        // construction, not silently wrong.
        assert!(
            matches!(
                ExactScaleRound::new(&SMALL_MAIN, &TIGHT_AUX, t, 2),
                Err(ExactScaleRoundError::InsufficientAuxCapacity { .. })
            ),
            "xb=2 (doubled) must be refused on TIGHT_AUX"
        );

        // A genuinely wider aux base, correctly sized for the doubled
        // bound, gets the SAME Xc right -- the fix, not just a refusal.
        let xa_wide = residues_i128(xc, &SMALL_AUX);
        let correctly_sized = ExactScaleRound::new(&SMALL_MAIN, &SMALL_AUX, t, 2)
            .expect("SMALL_AUX has ample margin for the doubled bound");
        let mut out_good = vec![0u64; SMALL_MAIN.len()];
        correctly_sized
            .scale_round(&xm, &xa_wide, &mut out_good)
            .expect("canonical");
        assert_eq!(
            out_good, want,
            "correctly-sized (xb=2) context must be exact at the identical Xc=1.5*Q^2"
        );
    }

    /// **Confirms the actual fix, through the real code path.** With
    /// `TIGHT_AUX` (which accepts `x_bound_over_q_sq = 1` but refuses `= 2`,
    /// per the constant above), `DerivedTransientMulContext::new` must now
    /// REFUSE construction at `x_bound_over_q_sq = 1` -- proving it really
    /// asks `ExactScaleRound` for the doubled bound internally, not just in
    /// its doc comment. Before the fix, this would have constructed
    /// successfully and been silently wrong on real d1-range ciphertext
    /// coefficients, exactly as the previous test reproduces directly.
    #[test]
    fn context_construction_requires_doubled_capacity_not_just_the_documented_single_term_bound() {
        let t = 13u64;
        let err = DerivedTransientMulContext::new(&SMALL_MAIN, &TIGHT_AUX, t, 1)
            .expect_err("must be refused: the aux base has capacity for xb=1 but not the doubled xb=2 this module actually requires");
        match err {
            DerivedTransientMulError::ScaleRound(
                ExactScaleRoundError::InsufficientAuxCapacity { .. },
            ) => {}
            other => panic!("expected ScaleRound(InsufficientAuxCapacity), got {other:?}"),
        }

        // And on the production-scale AUX (which was always generous enough
        // for both the single and doubled bound), construction still
        // succeeds -- the fix does not turn a previously-working
        // configuration into a refusal.
        DerivedTransientMulContext::new(&SMALL_MAIN, &SMALL_AUX, t, 1)
            .expect("SMALL_AUX has ample margin for the doubled bound too");
    }

    /// **Typed error, not a `debug_assert!` that compiles out in
    /// `--release`.** A `DerivedTransientMulContext` built for one main
    /// basis must be refused, not silently miscombined, when applied to an
    /// `RNSFHEContext` over a different one.
    #[test]
    fn mismatched_main_basis_is_a_typed_error_not_a_debug_assert() {
        let config = FHEConfig::light_rns_insecure();
        let ctx = RNSFHEContext::new(&config);

        // Built against a basis that does NOT match ctx.config.primes --
        // deliberately SMALL_MAIN/SMALL_AUX/t=13 scale throughout (matching
        // every other SMALL_MAIN-scale test in this file), NOT ctx's own
        // real t=65537 (SMALL_AUX has nowhere near enough capacity for
        // that plaintext modulus even at xb=1) or its real xb=n/4=256 --
        // both are irrelevant here, since this test only exercises the
        // mismatch-detection path, not a real multiply at ctx's own scale.
        let dt_ctx = DerivedTransientMulContext::new(&SMALL_MAIN, &SMALL_AUX, 13, 1)
            .expect("SMALL_MAIN/SMALL_AUX has capacity at t=13, xb=1");

        let mut rng = ShadowHarvester::with_seed(0x7115_0003);
        let keys = ctx.generate_keys(&mut rng);
        let ct_a = ctx.encrypt(1, &keys.public_key, &mut rng);
        let ct_b = ctx.encrypt(1, &keys.public_key, &mut rng);

        let result = dt_ctx.mul_experimental(&ctx, &ct_a, &ct_b, &keys.eval_key);
        assert!(
            matches!(result, Err(DerivedTransientMulError::MainBasisMismatch)),
            "expected MainBasisMismatch for a context/ctx main-basis mismatch, got {result:?}"
        );
    }

    // ---- the decisive ciphertext-level differential ------------------------

    /// **T1.4 target proof.** On the exact chain and operands
    /// `ops::rns_fhe::track1_exact_multiply_lock` uses to lock `mul()`'s
    /// failure (`FHEConfig::light_rns_insecure()`, `Delta^2 > Q`), the
    /// derived-transient route gives the exact plaintext for every case,
    /// where `mul()` gives the wrong one for all four.
    #[test]
    fn derived_transient_route_is_exact_where_public_mul_is_wrong() {
        let config = FHEConfig::light_rns_insecure();
        let ctx = RNSFHEContext::new(&config);
        assert_eq!(
            ctx.mul_route(),
            MulRoute::KElimDual,
            "sanity: router already knows the single-RNS route is invalid here"
        );

        let main = ctx.config.primes.clone();
        let xb = (ctx.n as u64) / 4;
        let dt_ctx =
            DerivedTransientMulContext::new(&main, &AUX, ctx.t, xb).expect("aux base has capacity");

        let mut rng = ShadowHarvester::with_seed(0x7115_0002);
        let keys = ctx.generate_keys(&mut rng);

        let cases: [(u64, u64); 4] = [(1, 1), (2, 3), (5, 7), (11, 13)];
        for (a, b) in cases {
            let ct_a = ctx.encrypt(a, &keys.public_key, &mut rng);
            let ct_b = ctx.encrypt(b, &keys.public_key, &mut rng);

            // The old lock: public mul() is wrong here.
            let wrong_product = ctx.mul(&ct_a, &ct_b, &keys.eval_key);
            let wrong_got = ctx.decrypt(&wrong_product, &keys.secret_key);
            let want = (a as u128 * b as u128 % ctx.t as u128) as u64;
            assert_ne!(
                wrong_got, want,
                "sanity: mul() was expected to remain wrong for {a}*{b} \
                 (if it now agrees, the T1.1 lock should be re-pointed, not this test)"
            );

            // The new route: exact.
            let product = dt_ctx
                .mul_experimental(&ctx, &ct_a, &ct_b, &keys.eval_key)
                .expect("derived-transient multiply");
            let got = ctx.decrypt(&product, &keys.secret_key);
            assert_eq!(
                got, want,
                "derived-transient route gave wrong plaintext for {a}*{b}: got {got}, want {want}"
            );
        }
    }
}
