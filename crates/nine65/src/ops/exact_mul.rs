//! WR-1 — derived-transient exact evaluator multiply (`docs/work_requests/WR1_EXACT_EVALUATOR_INTEGRATION.md`).
//!
//! Stage T1.4/T1.5 of `docs/TRACK1_D3_EXACT_MULTIPLY_IMPLEMENTATION.md`: the
//! first production caller of [`MainOnlyBaseExt`] and [`ExactScaleRound`].
//!
//! # What this route is
//!
//! An additive, explicitly-routed ciphertext x ciphertext multiply on the
//! **published main base `Q` only**. Inputs and outputs are ordinary
//! [`RNSCiphertext`] values; the auxiliary base `A` is derived from the main
//! residues inside one call, used as D3 scratch, and zeroized before return.
//! No auxiliary lane reaches a ciphertext field, a key, or the wire.
//!
//! It does **not** replace anything. [`RNSFHEContext::mul`] keeps its
//! fail-closed `BajardSingle` route guard (WR-1 invariant 9), the dual-RNS
//! `mul_dual_public` path is untouched, and nothing here is reachable from
//! `mul_auto`.
//!
//! # The flow (WR-1 §C)
//!
//! ```text
//! validate + canonical main residues
//!   -> centered main->A lift of each INPUT coefficient      (§A, invariant 5)
//!   -> negacyclic multiply in every main and A lane
//!   -> tensor d0/d1/d2 carried in BOTH bases
//!   -> ExactScaleRound coefficientwise                      (§C.7)
//!   -> hybrid main-RNS x base-2^10 relinearization of e2    (§D)
//!   -> emit a main-Q-only RNSCiphertext, zeroize A scratch
//! ```
//!
//! ## Why the centered lift comes first (WR-1 F2 / invariant 5)
//!
//! The integer BFV tensor coefficient `Xc` is up to `~N*(Q/2)^2`, far outside
//! `[0, Q)`. Once the tensor has been reduced mod `Q` that magnitude is gone,
//! so base-extending the *wrapped* tensor produces the residues of `Xc mod Q`,
//! not of `Xc`, and [`ExactScaleRound`] would faithfully compute
//! `round((Xc mod Q) * t / Q)` — a wrong plaintext, silently. The auxiliary
//! residues must therefore come from the inputs, before any wrap:
//! `conv(centered lifts)` is an integer identity, and reducing it mod `a_j`
//! commutes with computing it in lane `a_j`.
//!
//! The *representative* matters too, not just the magnitude. If `d_j` is
//! replaced by `d_j + Q*g_j`, then `e_j = round(t*d_j/Q)` moves by `t*g_j`, so
//! the decryption invariant picks up `t*G` mod `Q`. With canonical `[0, Q)`
//! inputs instead of centered ones, `g` is of order `N*Q` and `t*G mod Q` is
//! indistinguishable from noise. Centering keeps `g` at the `O(N)` wraparound
//! the standard BFV analysis already absorbs.
//!
//! # Operand bound: `N/2`, not `N/4` (deviation from WR-1 §B1, recorded)
//!
//! [`ExactScaleRound`] is constructed with `x_bound_over_q_sq = N/2`, one bit
//! above the `N/4` written in WR-1 §B1 and in
//! `scripts/verify_wr1_transient_exact.py`.
//!
//! `N/4` is the correct bound for a **single** negacyclic product: each output
//! coefficient sums exactly `N` terms of magnitude at most `((Q-1)/2)^2`, so
//! `|coeff| < N*Q^2/4`. But `d1 = a.c0*b.c1 + a.c1*b.c0` is the **sum of two**
//! such products, so `|d1 coeff| < N*Q^2/2`, and `N/4` under-declares it by
//! exactly one bit. The owner's oracle does not catch this because it verifies
//! one product, never the `d1` sum.
//!
//! Rounding the two halves of `d1` separately would not fix it —
//! `round(x) + round(y) != round(x+y)` breaks the exact BFV rule this whole
//! track exists to preserve — so the declared bound is raised instead. The
//! cost is one bit of required auxiliary capacity and, as
//! `aux_lane_counts_match_the_integer_oracle` pins, **zero** additional
//! auxiliary lanes for every named production configuration.
//!
//! # No canonical reconstruction (WR-1 §F)
//!
//! Nothing on this route calls `RNSContext::to_int`, `to_u256_level`,
//! `extract_k_rns_level*`, `extract_digit_dual`, `k_elim_rescale_dual*`,
//! `decompose_rns_poly`, `BaseExt::project`, `CompareBit::decide_ct`, or
//! `RNSFHEContext::exact_rescale`, and it constructs no `DualRNSContext`. The
//! only wide-integer work is the bounded `U256` rank/half fallback inside
//! [`MainOnlyBaseExt`], which compares against multiples of `M` and never
//! materializes a coefficient. `scripts/check_wr1_exact_route_denylist.py`
//! enforces this over the whole reachable source set.

use zeroize::{Zeroize, Zeroizing};

use super::{
    sample_cbd_signed_rng, signed_to_mod, MulRoute, RNSCiphertext, RNSFHEContext, RNSSecretKey,
};
use crate::arithmetic::exact_scale_round::{ExactScaleRound, ExactScaleRoundError};
use crate::arithmetic::main_only_base_ext::{MainOnlyBaseExt, MainOnlyBaseExtError, RankPath};
use crate::arithmetic::rns::U512;
use crate::arithmetic::{DualRNSContext, NTTEngine, RNSPolynomial};
use crate::entropy::FheRng;

/// Gadget base exponent for the hybrid relinearization (WR-1 §D).
pub const HYBRID_BASE_BITS: u32 = 10;

// ===========================================================================
// Typed failures (WR-1 invariant 8)
// ===========================================================================

/// Every variant is a refused proof obligation. This route never returns a
/// best-effort quotient, never truncates, and never falls back to an
/// approximate rescale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactMulError {
    /// No prefix of the deterministic NTT-compatible candidate pool reaches the
    /// capacity certificate `A > 2 * s_mult * Q` for this configuration.
    AuxiliaryBasisUnavailable {
        required_bits: u32,
        pool_bits: u32,
        pool_lanes: usize,
    },
    /// A candidate auxiliary lane is not negacyclic-NTT compatible at this `N`.
    AuxiliaryLaneNotNttCompatible { aux: u64, two_n: u64 },
    /// An auxiliary lane shares a factor with a main lane, so `Q` would not be
    /// invertible modulo it.
    MainAuxShareFactor { main: u64, aux: u64, gcd: u64 },
    /// `s_mult = x_bound_over_q_sq * t + 1` does not fit `u64`.
    OperandBoundOverflow { x_bound_over_q_sq: u64, t: u64 },
    /// The auxiliary NTT engine could not be built for this lane.
    AuxiliaryNttUnavailable { aux: u64, n: usize, message: String },
    /// A basis rejected by the main-only base extension.
    BaseExt(MainOnlyBaseExtError),
    /// A basis or residue rejected by the exact scale-and-round kernel.
    ScaleRound(ExactScaleRoundError),
    /// Ciphertext shape does not match the plan.
    CiphertextShape {
        what: &'static str,
        got: usize,
        expected: usize,
    },
    /// A supplied main residue was not canonical for its lane.
    NonCanonicalMainResidue {
        lane: usize,
        coefficient: usize,
        residue: u64,
        modulus: u64,
    },
    /// Hybrid gadget key shape does not match the plan.
    GadgetKeyShape {
        what: &'static str,
        got: usize,
        expected: usize,
    },
    /// Decryption recovered a small value that its main lanes do not agree on.
    /// The scaled plaintext must be a single integer in `[0, t]`; disagreement
    /// means the ciphertext is outside the noise budget (or malformed), and the
    /// route refuses rather than returning whichever lane happened to be read.
    ScaledPlaintextNotSmall {
        lane: usize,
        residue: u64,
        candidate: u64,
    },
}

impl From<MainOnlyBaseExtError> for ExactMulError {
    fn from(e: MainOnlyBaseExtError) -> Self {
        ExactMulError::BaseExt(e)
    }
}

impl From<ExactScaleRoundError> for ExactMulError {
    fn from(e: ExactScaleRoundError) -> Self {
        ExactMulError::ScaleRound(e)
    }
}

impl std::fmt::Display for ExactMulError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ExactMulError {}

// ===========================================================================
// §B — the per-configuration plan
// ===========================================================================

fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
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

/// Certificates the plan proved at construction, exposed so tests and the §H
/// evidence section can print the integers rather than assert on prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactMulCertificate {
    /// `N`.
    pub ring_degree: usize,
    /// Plaintext modulus.
    pub t: u64,
    /// Declared operand bound: `|Xc| <= x_bound_over_q_sq * Q^2`.
    pub x_bound_over_q_sq: u64,
    /// `s_mult = x_bound_over_q_sq * t + 1`; the output shift is `s_mult * Q`.
    pub shift_multiplier: u64,
    /// Exact bit length of `Q`.
    pub q_bits: u32,
    /// Exact bit length of the selected `A`.
    pub aux_bits: u32,
    /// Exact bit length of `2 * s_mult * Q`, the capacity `A` must exceed.
    pub required_bits: u32,
    /// Number of transient auxiliary lanes selected.
    pub aux_lanes: usize,
    /// Gadget base exponent.
    pub base_bits: u32,
    /// Digits per main lane for the hybrid gadget.
    pub digits_per_lane: Vec<usize>,
}

/// Precomputed, immutable per-configuration plan (WR-1 §B).
///
/// Built once per FHE configuration, never per coefficient. Holds no
/// ciphertext state and no secret material.
pub struct ExactMulPlan {
    n: usize,
    t: u64,
    main: Vec<u64>,
    aux: Vec<u64>,
    /// Centered main -> auxiliary projector (§A).
    projector: MainOnlyBaseExt,
    /// Exact BFV scale-and-round over (main, aux) (§C.7).
    scaler: ExactScaleRound,
    /// Negacyclic NTT engine per transient auxiliary lane.
    aux_ntt: Vec<NTTEngine>,
    base_bits: u32,
    digits_per_lane: Vec<usize>,
    certificate: ExactMulCertificate,
}

impl std::fmt::Debug for ExactMulPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExactMulPlan")
            .field("certificate", &self.certificate)
            .finish()
    }
}

impl ExactMulPlan {
    /// Build the plan for one immutable FHE configuration.
    ///
    /// `main` must be the published chain, `n` the ring degree and `t` the
    /// plaintext modulus. The auxiliary basis is selected here (§B1) and every
    /// certificate is proved before the plan exists, so no caller can hold a
    /// plan that would compute a silently-wrong value.
    pub fn new(main: &[u64], n: usize, t: u64) -> Result<Self, ExactMulError> {
        // Operand bound. `N/2` covers `d1` (the sum of two negacyclic
        // products); see the module header for why `N/4` is one bit short.
        let x_bound_over_q_sq = (n as u64) / 2;
        Self::with_operand_bound(main, n, t, x_bound_over_q_sq)
    }

    /// As [`Self::new`], with an explicitly declared operand bound. Exposed so
    /// the differential tests can pin the `N/4`-vs-`N/2` boundary directly.
    pub fn with_operand_bound(
        main: &[u64],
        n: usize,
        t: u64,
        x_bound_over_q_sq: u64,
    ) -> Result<Self, ExactMulError> {
        let s_mult = x_bound_over_q_sq
            .checked_mul(t)
            .and_then(|v| v.checked_add(1))
            .ok_or(ExactMulError::OperandBoundOverflow {
                x_bound_over_q_sq,
                t,
            })?;

        let q_wide = U512::product_u64s(main);
        let required = q_wide.mul_u128(2u128 * s_mult as u128);

        // §B1 candidate pool: the deterministic NTT-compatible catalog, used
        // NUMERICALLY ONLY. No `DualRNSContext` is constructed from it and
        // these primes never touch ciphertext state.
        let pool = DualRNSContext::canonical_anchor_primes_for_n(n);
        let two_n = 2u64 * n as u64;
        for &a in &pool {
            for &q in main {
                let g = gcd_u64(q, a);
                if g != 1 {
                    return Err(ExactMulError::MainAuxShareFactor {
                        main: q,
                        aux: a,
                        gcd: g,
                    });
                }
            }
            if (a - 1) % two_n != 0 {
                return Err(ExactMulError::AuxiliaryLaneNotNttCompatible { aux: a, two_n });
            }
        }

        // Shortest prefix satisfying the capacity certificate A > 2*s_mult*Q.
        let mut selected: Option<usize> = None;
        for lanes in 1..=pool.len() {
            if u512_gt(U512::product_u64s(&pool[..lanes]), required) {
                selected = Some(lanes);
                break;
            }
        }
        let lanes = selected.ok_or_else(|| ExactMulError::AuxiliaryBasisUnavailable {
            required_bits: u512_bits(required),
            pool_bits: u512_bits(U512::product_u64s(&pool)),
            pool_lanes: pool.len(),
        })?;
        let aux = pool[..lanes].to_vec();

        let projector = MainOnlyBaseExt::new(main, &aux)?;
        let scaler = ExactScaleRound::new(main, &aux, t, x_bound_over_q_sq)?;

        let mut aux_ntt = Vec::with_capacity(lanes);
        for &a in &aux {
            let engine =
                NTTEngine::try_new(a, n).map_err(|e| ExactMulError::AuxiliaryNttUnavailable {
                    aux: a,
                    n,
                    message: e.to_string(),
                })?;
            aux_ntt.push(engine);
        }

        // §D gadget shape: enough base-2^b digits to span every main lane.
        let base_bits = HYBRID_BASE_BITS;
        let digits_per_lane: Vec<usize> = main
            .iter()
            .map(|&q| {
                let bits = 64 - q.leading_zeros();
                (bits as usize).div_ceil(base_bits as usize)
            })
            .collect();
        for (i, (&q, &d)) in main.iter().zip(digits_per_lane.iter()).enumerate() {
            // B^d must cover [0, q_i); d*base_bits >= bitlen(q_i) gives that.
            debug_assert!(
                (d as u32) * base_bits >= 64 - q.leading_zeros(),
                "lane {i}: {d} base-2^{base_bits} digits cannot span q={q}"
            );
        }

        let aux_wide = U512::product_u64s(&aux);
        let certificate = ExactMulCertificate {
            ring_degree: n,
            t,
            x_bound_over_q_sq,
            shift_multiplier: s_mult,
            q_bits: u512_bits(q_wide),
            aux_bits: u512_bits(aux_wide),
            required_bits: u512_bits(required),
            aux_lanes: lanes,
            base_bits,
            digits_per_lane: digits_per_lane.clone(),
        };

        Ok(ExactMulPlan {
            n,
            t,
            main: main.to_vec(),
            aux,
            projector,
            scaler,
            aux_ntt,
            base_bits,
            digits_per_lane,
            certificate,
        })
    }

    /// The certificates proved at construction.
    pub fn certificate(&self) -> &ExactMulCertificate {
        &self.certificate
    }

    /// The transient auxiliary basis. Exposed for tests and evidence only —
    /// no ciphertext, key or wire artifact ever carries these lanes.
    pub fn auxiliary_basis(&self) -> &[u64] {
        &self.aux
    }

    /// Published main basis.
    pub fn main_basis(&self) -> &[u64] {
        &self.main
    }

    /// The route this plan implements.
    pub fn route(&self) -> MulRoute {
        MulRoute::DerivedTransientExact
    }
}

// ===========================================================================
// Transient auxiliary scratch (WR-1 §B2)
// ===========================================================================

/// Auxiliary limbs for one polynomial: `limbs[aux_lane][coefficient]`.
///
/// Owned by one operation, never reachable from a ciphertext, key, session or
/// wire DTO, and zeroized on drop. `Zeroizing` is the convention this crate
/// already uses for transient secret-adjacent buffers (see
/// `generate_keys_with_rng`).
type AuxLimbs = Zeroizing<Vec<Vec<u64>>>;

// ===========================================================================
// §D — hybrid main-RNS x base-2^b gadget key
// ===========================================================================

/// Public relinearization key for the exact route (WR-1 §D).
///
/// `rlk[i][j]` encrypts `g_i * B^j * s^2` where `g_i` is the CRT idempotent for
/// main lane `i` and `B = 2^base_bits`. The idempotent is never materialized:
/// its RNS image is `B^j * s^2` in lane `i` and zero elsewhere (§D2).
///
/// Every polynomial carries exactly the main-`Q` lanes — there is no auxiliary
/// field to serialize, and `RNSPolynomial` has no `serde` derive, so the type
/// is structurally WIRE-Q by construction.
#[derive(Clone)]
pub struct RNSHybridGadgetKey {
    /// Gadget base exponent (`B = 2^base_bits`).
    pub base_bits: u32,
    /// Digit count per main lane; `digits_per_lane[i] == rlk[i].len()`.
    pub digits_per_lane: Vec<usize>,
    /// `rlk[lane][digit] = (rlk0, rlk1)`, both in Montgomery form.
    pub rlk: Vec<Vec<(RNSPolynomial, RNSPolynomial)>>,
}

impl std::fmt::Debug for RNSHybridGadgetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RNSHybridGadgetKey")
            .field("base_bits", &self.base_bits)
            .field("digits_per_lane", &self.digits_per_lane)
            .finish()
    }
}

/// Degree-2 exact tensor output (WR-1 §E `try_mul_no_relin_exact`).
///
/// Main-`Q` only, at the plaintext scale — the exact scale-and-round has
/// already been applied to all three components.
#[derive(Clone, Debug)]
pub struct ExactTensor3 {
    pub e0: RNSPolynomial,
    pub e1: RNSPolynomial,
    pub e2: RNSPolynomial,
    pub num_primes: usize,
}

/// Which rank paths a call exercised, for the §A observability requirement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RankPathTally {
    pub certified: usize,
    pub fallback: usize,
}

impl RankPathTally {
    fn note(&mut self, path: RankPath) {
        match path {
            RankPath::CertifiedFixedPoint => self.certified += 1,
            RankPath::ExactFallback => self.fallback += 1,
        }
    }
}

// ===========================================================================
// The evaluator
// ===========================================================================

/// Exact derived-transient evaluator (WR-1 §E).
///
/// Borrows the FHE context and owns one [`ExactMulPlan`]. All auxiliary
/// storage is allocated and zeroized inside individual calls.
pub struct ExactMulEvaluator<'a> {
    ctx: &'a RNSFHEContext,
    plan: ExactMulPlan,
}

impl<'a> ExactMulEvaluator<'a> {
    /// Build an evaluator for `ctx`'s configuration, proving every §B
    /// certificate. Fails closed with a typed error when any of them does not
    /// hold.
    pub fn new(ctx: &'a RNSFHEContext) -> Result<Self, ExactMulError> {
        let plan = ExactMulPlan::new(&ctx.config.primes, ctx.n, ctx.t)?;
        Ok(Self { ctx, plan })
    }

    /// Build an evaluator around an already-proved plan.
    pub fn with_plan(ctx: &'a RNSFHEContext, plan: ExactMulPlan) -> Self {
        Self { ctx, plan }
    }

    pub fn plan(&self) -> &ExactMulPlan {
        &self.plan
    }

    pub fn route(&self) -> MulRoute {
        MulRoute::DerivedTransientExact
    }

    // -----------------------------------------------------------------
    // Shape validation (WR-1 §C.1)
    // -----------------------------------------------------------------

    fn check_ciphertext(&self, ct: &RNSCiphertext) -> Result<(), ExactMulError> {
        let lanes = self.plan.main.len();
        if ct.num_primes != lanes {
            return Err(ExactMulError::CiphertextShape {
                what: "num_primes",
                got: ct.num_primes,
                expected: lanes,
            });
        }
        for poly in [&ct.c0, &ct.c1] {
            if poly.limbs.len() != lanes {
                return Err(ExactMulError::CiphertextShape {
                    what: "limb count",
                    got: poly.limbs.len(),
                    expected: lanes,
                });
            }
            if poly.n != self.plan.n {
                return Err(ExactMulError::CiphertextShape {
                    what: "ring degree",
                    got: poly.n,
                    expected: self.plan.n,
                });
            }
            for limb in &poly.limbs {
                if limb.len() != self.plan.n {
                    return Err(ExactMulError::CiphertextShape {
                        what: "limb length",
                        got: limb.len(),
                        expected: self.plan.n,
                    });
                }
            }
            self.check_canonical(poly)?;
        }
        Ok(())
    }

    /// Canonical-residue contract at the external boundary (§C.1).
    ///
    /// Applied to the **stored Montgomery limbs**, which are themselves
    /// canonical in `[0, q_i)`. Checking the post-`from_montgomery` residues
    /// instead would be vacuous — Montgomery reduction always emits a value
    /// below the modulus, so a malformed input limb would be silently
    /// normalised into a well-formed one and the refusal could never fire.
    fn check_canonical(&self, poly: &RNSPolynomial) -> Result<(), ExactMulError> {
        for (i, (&q, limb)) in self.plan.main.iter().zip(poly.limbs.iter()).enumerate() {
            for (k, &r) in limb.iter().enumerate() {
                if r >= q {
                    return Err(ExactMulError::NonCanonicalMainResidue {
                        lane: i,
                        coefficient: k,
                        residue: r,
                        modulus: q,
                    });
                }
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // §A/§C — centered transient lift
    // -----------------------------------------------------------------

    /// Derive the transient auxiliary limbs of the *centered* lift of every
    /// coefficient of `poly` (standard-domain canonical main residues in).
    fn centered_aux_limbs(
        &self,
        poly: &RNSPolynomial,
        tally: &mut RankPathTally,
    ) -> Result<AuxLimbs, ExactMulError> {
        let n = self.plan.n;
        let lanes = self.plan.main.len();
        let aux_lanes = self.plan.aux.len();
        let mut out: Vec<Vec<u64>> = vec![vec![0u64; n]; aux_lanes];
        let mut residues = vec![0u64; lanes];
        let mut projected = vec![0u64; aux_lanes];
        for k in 0..n {
            for (i, limb) in poly.limbs.iter().enumerate() {
                residues[i] = limb[k];
            }
            let (path, _upper) = self
                .plan
                .projector
                .project_centered(&residues, &mut projected)?;
            tally.note(path);
            for (j, slot) in out.iter_mut().enumerate() {
                slot[k] = projected[j];
            }
        }
        residues.zeroize();
        projected.zeroize();
        Ok(Zeroizing::new(out))
    }

    /// Negacyclic product in every transient auxiliary lane.
    fn aux_mul(&self, a: &AuxLimbs, b: &AuxLimbs) -> AuxLimbs {
        let limbs: Vec<Vec<u64>> = self
            .plan
            .aux_ntt
            .iter()
            .enumerate()
            .map(|(j, engine)| engine.multiply(&a[j], &b[j]))
            .collect();
        Zeroizing::new(limbs)
    }

    /// Lanewise addition in the transient auxiliary base.
    fn aux_add(&self, a: &AuxLimbs, b: &AuxLimbs) -> AuxLimbs {
        let limbs: Vec<Vec<u64>> = self
            .plan
            .aux
            .iter()
            .enumerate()
            .map(|(j, &m)| {
                a[j].iter()
                    .zip(b[j].iter())
                    .map(|(&x, &y)| {
                        let s = x + y;
                        if s >= m {
                            s - m
                        } else {
                            s
                        }
                    })
                    .collect()
            })
            .collect();
        Zeroizing::new(limbs)
    }

    // -----------------------------------------------------------------
    // §C — exact tensor + scale-and-round
    // -----------------------------------------------------------------

    /// Degree-2 exact multiply: tensor, then exact BFV scale-and-round on all
    /// three components. Main-`Q` only on the way in and on the way out.
    pub fn try_mul_no_relin_exact(
        &self,
        a: &RNSCiphertext,
        b: &RNSCiphertext,
    ) -> Result<ExactTensor3, ExactMulError> {
        self.try_mul_no_relin_exact_observed(a, b).map(|(t, _)| t)
    }

    /// As [`Self::try_mul_no_relin_exact`], also returning the rank-path tally
    /// so tests can prove both §A paths execute in the evaluator itself.
    pub fn try_mul_no_relin_exact_observed(
        &self,
        a: &RNSCiphertext,
        b: &RNSCiphertext,
    ) -> Result<(ExactTensor3, RankPathTally), ExactMulError> {
        self.check_ciphertext(a)?;
        self.check_ciphertext(b)?;

        // Standard-domain canonical main residues of the four input
        // components. `check_ciphertext` already refused any non-canonical
        // stored limb, and `from_montgomery` emits residues below the modulus,
        // so these satisfy `MainOnlyBaseExt`'s input contract by construction —
        // and `project_centered` re-checks it and returns a typed error anyway.
        let a0 = self.ctx.convert_from_montgomery_form(&a.c0);
        let a1 = self.ctx.convert_from_montgomery_form(&a.c1);
        let b0 = self.ctx.convert_from_montgomery_form(&b.c0);
        let b1 = self.ctx.convert_from_montgomery_form(&b.c1);

        let mut tally = RankPathTally::default();

        // §C.3-4: centered main -> A lift of each INPUT coefficient, before any
        // multiplication. This is invariant 5; see the module header.
        let a0_aux = self.centered_aux_limbs(&a0, &mut tally)?;
        let a1_aux = self.centered_aux_limbs(&a1, &mut tally)?;
        let b0_aux = self.centered_aux_limbs(&b0, &mut tally)?;
        let b1_aux = self.centered_aux_limbs(&b1, &mut tally)?;

        // §C.5-6: the same degree-2 tensor in both bases, matching negacyclic
        // semantics. The main track reuses the existing persistent-Montgomery
        // NTT path unchanged.
        let d0_main = self.ctx.rns_poly_mul(&a.c0, &b.c0);
        let d1_main = self
            .ctx
            .rns_poly_mul(&a.c0, &b.c1)
            .add(&self.ctx.rns_poly_mul(&a.c1, &b.c0), &self.ctx.rns);
        let d2_main = self.ctx.rns_poly_mul(&a.c1, &b.c1);
        let d0_main = self.ctx.convert_from_montgomery_form(&d0_main);
        let d1_main = self.ctx.convert_from_montgomery_form(&d1_main);
        let d2_main = self.ctx.convert_from_montgomery_form(&d2_main);

        let d0_aux = self.aux_mul(&a0_aux, &b0_aux);
        let d1_aux = self.aux_add(
            &self.aux_mul(&a0_aux, &b1_aux),
            &self.aux_mul(&a1_aux, &b0_aux),
        );
        let d2_aux = self.aux_mul(&a1_aux, &b1_aux);

        // §C.7-8: exact scale-and-round, coefficientwise, emitting main only.
        let e0 = self.scale_round_poly(&d0_main, &d0_aux, &mut tally)?;
        let e1 = self.scale_round_poly(&d1_main, &d1_aux, &mut tally)?;
        let e2 = self.scale_round_poly(&d2_main, &d2_aux, &mut tally)?;

        // §C.9: every transient A buffer is dropped here, zeroized by
        // `Zeroizing`. Nothing auxiliary is in scope past this point.
        Ok((
            ExactTensor3 {
                e0,
                e1,
                e2,
                num_primes: self.plan.main.len(),
            },
            tally,
        ))
    }

    /// Apply [`ExactScaleRound`] to every coefficient of one tensor component.
    /// Returns standard-domain canonical main residues.
    fn scale_round_poly(
        &self,
        main: &RNSPolynomial,
        aux: &AuxLimbs,
        tally: &mut RankPathTally,
    ) -> Result<RNSPolynomial, ExactMulError> {
        let n = self.plan.n;
        let lanes = self.plan.main.len();
        let aux_lanes = self.plan.aux.len();
        let mut limbs: Vec<Vec<u64>> = vec![vec![0u64; n]; lanes];
        let mut x_main = vec![0u64; lanes];
        let mut x_aux = vec![0u64; aux_lanes];
        let mut out = vec![0u64; lanes];
        for k in 0..n {
            for (i, limb) in main.limbs.iter().enumerate() {
                x_main[i] = limb[k];
            }
            for (j, limb) in aux.iter().enumerate() {
                x_aux[j] = limb[k];
            }
            let (forward, back) = self.plan.scaler.scale_round(&x_main, &x_aux, &mut out)?;
            tally.note(forward);
            tally.note(back);
            for (i, slot) in limbs.iter_mut().enumerate() {
                slot[k] = out[i];
            }
        }
        x_aux.zeroize();
        Ok(RNSPolynomial { limbs, n })
    }

    // -----------------------------------------------------------------
    // §D — hybrid relinearization
    // -----------------------------------------------------------------

    /// Generate the hybrid gadget key (WR-1 §D2).
    ///
    /// The message for `(lane i, digit j)` is `g_i * B^j * s^2`, built directly
    /// in RNS form: `B^j * s^2 mod q_i` in lane `i`, zero in every other lane.
    /// `Q/q_i` is never formed and no coefficient is reconstructed.
    pub fn generate_hybrid_gadget_key_with_rng<R: FheRng>(
        &self,
        sk: &RNSSecretKey,
        rng: &mut R,
    ) -> RNSHybridGadgetKey {
        crate::entropy::require_secure_rng(rng, "generate_hybrid_gadget_key_with_rng");
        let ctx = self.ctx;
        let base = 1u64 << self.plan.base_bits;
        let s2 = ctx.rns_poly_mul(&sk.s, &sk.s);

        let mut rlk: Vec<Vec<(RNSPolynomial, RNSPolynomial)>> =
            Vec::with_capacity(self.plan.main.len());
        for (i, &q_i) in self.plan.main.iter().enumerate() {
            let mut per_lane = Vec::with_capacity(self.plan.digits_per_lane[i]);
            let mut power_mod_qi: u64 = 1 % q_i;
            for _ in 0..self.plan.digits_per_lane[i] {
                // §D2: the CRT-idempotent image of `g_i * B^j * s^2`.
                let mut msg_limbs: Vec<Vec<u64>> =
                    vec![vec![0u64; self.plan.n]; self.plan.main.len()];
                for (k, slot) in msg_limbs[i].iter_mut().enumerate() {
                    // `s2` is in Montgomery form; scaling by a plain residue
                    // stays in Montgomery form.
                    *slot = ((s2.limbs[i][k] as u128 * power_mod_qi as u128) % q_i as u128) as u64;
                }
                let msg = RNSPolynomial {
                    limbs: msg_limbs,
                    n: self.plan.n,
                };

                // Full-width uniform `a` over [0, Q) and a signed-CBD error
                // encoded per lane (never one lane's representative reduced
                // into another's modulus).
                let a_rns = ctx.to_montgomery_form(&ctx.sample_uniform_main_poly(rng));
                let e_signed: Zeroizing<Vec<i64>> = Zeroizing::new(
                    (0..self.plan.n)
                        .map(|_| sample_cbd_signed_rng(rng, ctx.config.eta))
                        .collect(),
                );
                let e_limbs: Vec<Vec<u64>> = self
                    .plan
                    .main
                    .iter()
                    .map(|&p| e_signed.iter().map(|&e| signed_to_mod(e, p)).collect())
                    .collect();
                let e_rns = ctx.to_montgomery_form(&RNSPolynomial {
                    limbs: e_limbs,
                    n: self.plan.n,
                });

                let as_rns = ctx.rns_poly_mul(&a_rns, &sk.s);
                let rlk0 = as_rns
                    .add(&e_rns, &ctx.rns)
                    .neg(&ctx.rns)
                    .add(&msg, &ctx.rns);
                per_lane.push((rlk0, a_rns));
                power_mod_qi = ((power_mod_qi as u128 * base as u128) % q_i as u128) as u64;
            }
            rlk.push(per_lane);
        }

        RNSHybridGadgetKey {
            base_bits: self.plan.base_bits,
            digits_per_lane: self.plan.digits_per_lane.clone(),
            rlk,
        }
    }

    fn check_gadget_key(&self, key: &RNSHybridGadgetKey) -> Result<(), ExactMulError> {
        if key.base_bits != self.plan.base_bits {
            return Err(ExactMulError::GadgetKeyShape {
                what: "base_bits",
                got: key.base_bits as usize,
                expected: self.plan.base_bits as usize,
            });
        }
        if key.rlk.len() != self.plan.main.len() {
            return Err(ExactMulError::GadgetKeyShape {
                what: "lane count",
                got: key.rlk.len(),
                expected: self.plan.main.len(),
            });
        }
        if key.digits_per_lane != self.plan.digits_per_lane {
            return Err(ExactMulError::GadgetKeyShape {
                what: "digits_per_lane",
                got: key.digits_per_lane.len(),
                expected: self.plan.digits_per_lane.len(),
            });
        }
        for (i, per_lane) in key.rlk.iter().enumerate() {
            if per_lane.len() != self.plan.digits_per_lane[i] {
                return Err(ExactMulError::GadgetKeyShape {
                    what: "digits in lane",
                    got: per_lane.len(),
                    expected: self.plan.digits_per_lane[i],
                });
            }
            for (rlk0, rlk1) in per_lane {
                for poly in [rlk0, rlk1] {
                    if poly.limbs.len() != self.plan.main.len() {
                        return Err(ExactMulError::GadgetKeyShape {
                            what: "key limb count",
                            got: poly.limbs.len(),
                            expected: self.plan.main.len(),
                        });
                    }
                    if poly.n != self.plan.n {
                        return Err(ExactMulError::GadgetKeyShape {
                            what: "key ring degree",
                            got: poly.n,
                            expected: self.plan.n,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Hybrid relinearization of a degree-2 component (WR-1 §D3/§D4).
    ///
    /// `e2` carries standard-domain canonical main residues. Digits are
    /// extracted lane-locally with shifts and masks on the `u64` residue —
    /// `decompose_rns_poly` is not called and no coefficient is reconstructed.
    /// Returns `(r0, r1)` in Montgomery form with `r0 + r1*s = e2*s^2 + noise`.
    fn hybrid_relinearize(
        &self,
        e2: &RNSPolynomial,
        key: &RNSHybridGadgetKey,
    ) -> Result<(RNSPolynomial, RNSPolynomial), ExactMulError> {
        let ctx = self.ctx;
        let lanes = self.plan.main.len();
        let mask = (1u64 << self.plan.base_bits) - 1;

        let mut r0 = RNSPolynomial::zero(&ctx.rns);
        let mut r1 = RNSPolynomial::zero(&ctx.rns);

        for i in 0..lanes {
            for j in 0..self.plan.digits_per_lane[i] {
                let shift = (j as u32) * self.plan.base_bits;
                // The digit value is < 2^base_bits, so the SAME small integer
                // is a canonical residue in every main lane: broadcast it.
                let digit_limbs: Vec<Vec<u64>> = (0..lanes)
                    .map(|_| e2.limbs[i].iter().map(|&c| (c >> shift) & mask).collect())
                    .collect();
                let digit = ctx.to_montgomery_form(&RNSPolynomial {
                    limbs: digit_limbs,
                    n: self.plan.n,
                });
                let (rlk0, rlk1) = &key.rlk[i][j];
                r0.add_assign_poly(&ctx.rns_poly_mul(&digit, rlk0), &ctx.rns);
                r1.add_assign_poly(&ctx.rns_poly_mul(&digit, rlk1), &ctx.rns);
            }
        }
        Ok((r0, r1))
    }

    // -----------------------------------------------------------------
    // §E — the public exact multiply
    // -----------------------------------------------------------------

    /// Exact public ciphertext x ciphertext multiply (WR-1 §E).
    ///
    /// Emits an ordinary main-`Q` [`RNSCiphertext`], structurally identical to
    /// what [`RNSFHEContext::encrypt`] produces: same lane count, same ring
    /// degree, same Montgomery convention, no extra field.
    pub fn try_mul_exact(
        &self,
        a: &RNSCiphertext,
        b: &RNSCiphertext,
        key: &RNSHybridGadgetKey,
    ) -> Result<RNSCiphertext, ExactMulError> {
        self.check_gadget_key(key)?;
        let tensor = self.try_mul_no_relin_exact(a, b)?;
        self.relinearize_tensor(&tensor, key)
    }

    /// Fold an already-computed exact tensor into a degree-1 ciphertext.
    pub fn relinearize_tensor(
        &self,
        tensor: &ExactTensor3,
        key: &RNSHybridGadgetKey,
    ) -> Result<RNSCiphertext, ExactMulError> {
        self.check_gadget_key(key)?;
        let ctx = self.ctx;
        let (r0, r1) = self.hybrid_relinearize(&tensor.e2, key)?;
        let c0 = ctx.to_montgomery_form(&tensor.e0).add(&r0, &ctx.rns);
        let c1 = ctx.to_montgomery_form(&tensor.e1).add(&r1, &ctx.rns);
        Ok(RNSCiphertext {
            c0,
            c1,
            num_primes: self.plan.main.len(),
        })
    }

    // -----------------------------------------------------------------
    // Decryption for the exact route
    // -----------------------------------------------------------------

    /// Decrypt a main-`Q` ciphertext with the same exact kernel.
    ///
    /// `RNSFHEContext::decrypt` asserts `Q < 2^128` because it reconstructs the
    /// coefficient in `u128`; `secure_192` (146 bits) and `secure_256`
    /// (175 bits) cannot use it at all. This route needs neither the
    /// reconstruction nor the width:
    ///
    /// * `inner = c0 + c1*s` is read as its canonical main residues;
    /// * `Y = round(inner * t / Q)` comes from [`ExactScaleRound`], exactly as
    ///   in the evaluator, with the canonical (non-centered) representative —
    ///   legitimate because `inner_canonical = inner_centered + b*Q` gives
    ///   `Y_canonical = Y_centered + b*t`, which vanishes mod `t`;
    /// * `Y` lies in `[0, t]`, far below every main lane, so it is read
    ///   directly out of lane 0 and **cross-checked against every other lane**.
    ///   Disagreement is a typed refusal, not a best-effort answer.
    ///
    /// Constant-time note: the rank fallback inside [`MainOnlyBaseExt`] is
    /// fixed-work, but *whether* it is taken is data-dependent, so this
    /// function is not constant-time with respect to the decrypted
    /// coefficient. It is a WR-1 verification and evaluation-side entry point;
    /// hardening it is out of this work request's scope and is recorded as
    /// such in the PR.
    pub fn try_decrypt_exact(
        &self,
        ct: &RNSCiphertext,
        sk: &RNSSecretKey,
    ) -> Result<u64, ExactMulError> {
        self.check_ciphertext(ct)?;
        let ctx = self.ctx;
        let inner_mont = ct.c0.add(&ctx.rns_poly_mul(&ct.c1, &sk.s), &ctx.rns);
        let inner = ctx.convert_from_montgomery_form(&inner_mont);

        let lanes = self.plan.main.len();
        let x_main: Vec<u64> = inner.limbs.iter().map(|limb| limb[0]).collect();
        let mut x_aux = vec![0u64; self.plan.aux.len()];
        self.plan.projector.project(&x_main, &mut x_aux)?;
        let mut out = vec![0u64; lanes];
        self.plan.scaler.scale_round(&x_main, &x_aux, &mut out)?;
        x_aux.zeroize();

        // `Y` is in [0, t] and every main lane is far larger, so the canonical
        // residue IS the value. Cross-check all lanes: an inconsistency means
        // the ciphertext is outside the budget, and the route refuses.
        let candidate = out[0];
        for (i, (&r, &q)) in out.iter().zip(self.plan.main.iter()).enumerate() {
            let expected = candidate % q;
            if r != expected {
                return Err(ExactMulError::ScaledPlaintextNotSmall {
                    lane: i,
                    residue: r,
                    candidate,
                });
            }
        }
        if candidate > self.plan.t {
            return Err(ExactMulError::ScaledPlaintextNotSmall {
                lane: 0,
                residue: candidate,
                candidate,
            });
        }
        Ok(candidate % self.plan.t)
    }
}

impl RNSFHEContext {
    /// Build the WR-1 exact derived-transient evaluator for this
    /// configuration, proving every §B certificate up front.
    pub fn try_exact_evaluator(&self) -> Result<ExactMulEvaluator<'_>, ExactMulError> {
        ExactMulEvaluator::new(self)
    }
}

#[cfg(test)]
#[path = "exact_mul_tests.rs"]
mod tests;
