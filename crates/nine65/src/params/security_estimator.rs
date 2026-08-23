//! Lattice Security Estimator (Integer-Only)
//!
//! Proper security estimation based on hybrid lattice attacks against Ring-LWE.
//! Uses BKZ cost models consistent with published attack literature.
//!
//! # Cost Models
//!
//! This module supports two BKZ cost models:
//!
//! ## Core-SVP (Default, Conservative)
//! - Based on classical BKZ analysis
//! - Cost: 2^(0.292·β) operations (292 millibits per β)
//! - Used for conservative security parameter selection
//! - Recommended for initial design and HE Standard compliance
//!
//! ## MATZOV (Aggressive, Realistic)
//! - Based on MATZOV report (2022) analysis of NIST PQC candidates
//! - Cost: 2^(0.265·β) operations (265 millibits per β)
//! - ~10% lower security estimates than Core-SVP (900/1000 factor)
//! - Reflects practical attack optimizations
//! - Recommended for production validation and security margins
//!
//! ## Dual Estimation (Recommended for Production)
//! Use `LatticeSecurityEstimator::dual_estimate()` to validate parameters
//! under BOTH models simultaneously. Production configs should meet claimed
//! security under both CoreSVP (conservative) and MATZOV (realistic).
//!
//! # QMNF Compliance
//! All calculations use integer arithmetic with millibits precision (1000 = 1 bit).
//! No floating-point operations.
//!
//! # Structural modulus screening (additive)
//!
//! `estimate` below is a function of the modulus **width** only. It cannot
//! distinguish a chain of NTT primes from `2^90` from a manufactured
//! `Q = t * D`, because it never sees the modulus. That is fine while every
//! lane is guaranteed to be a large prime by the prime hunt; it stops being
//! fine the moment moduli are manufactured by construction.
//!
//! [`LatticeSecurityEstimator::estimate_with_factorization`] is the additive
//! extension that takes the factorization and is allowed to REFUSE. See the
//! "STRUCTURAL MODULUS SCREEN" section further down this file for the
//! thresholds, what a refusal means, and what it does not mean. Both entry
//! points are engineering screens, never a substitute for an external
//! lattice-estimator run on the concrete parameter set.
//!
//! # References
//! - Albrecht et al. "On the concrete hardness of Learning with Errors" (2015)
//! - HE Standard v1.1 (homomorphicencryption.org)
//! - MATZOV Report on NIST PQC (2022)

/// Security estimation result with detailed breakdown
#[derive(Debug, Clone)]
pub struct SecurityEstimate {
    /// Classical security in bits (BKZ cost)
    pub classical_bits: u32,
    /// Quantum security in bits (Grover speedup on search)
    pub quantum_bits: u32,
    /// Hybrid attack security (meet-in-the-middle + BKZ)
    pub hybrid_bits: u32,
    /// The binding security level (minimum of all attacks)
    pub effective_bits: u32,
    /// BKZ block size required for attack
    pub bkz_block_size: u32,
    /// Estimated BKZ iterations (integer approximation)
    pub bkz_iterations: u64,
    /// Whether this meets claimed security level
    pub meets_claim: bool,
    /// Detailed attack analysis
    pub analysis: String,
}

/// Dual-model security estimate: compares both Core-SVP and MATZOV
#[derive(Debug, Clone)]
pub struct DualSecurityEstimate {
    /// Estimate under Core-SVP model (conservative)
    pub core_svp: SecurityEstimate,
    /// Estimate under MATZOV model (more aggressive)
    pub matzov: SecurityEstimate,
    /// Binding security: minimum across both models
    pub binding_bits: u32,
    /// Whether the claimed security is met under BOTH models
    pub meets_both: bool,
}

/// Lattice security estimator using Core-SVP model
pub struct LatticeSecurityEstimator {
    /// Cost model: "core-svp" or "matzov"
    pub cost_model: CostModel,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CostModel {
    /// Core-SVP model (conservative)
    CoreSVP,
    /// MATZOV model (more aggressive, realistic)
    MATZOV,
}

impl Default for LatticeSecurityEstimator {
    fn default() -> Self {
        Self::new(CostModel::CoreSVP)
    }
}

impl LatticeSecurityEstimator {
    pub fn new(cost_model: CostModel) -> Self {
        Self { cost_model }
    }

    /// Estimate security of Ring-LWE parameters (integer arithmetic)
    ///
    /// Uses the methodology from the Homomorphic Encryption Standard v1.1
    /// which provides security estimates based on the primal uSVP attack.
    ///
    /// # Arguments
    /// * `n` - Ring dimension (power of 2)
    /// * `log_q` - Bits in modulus q
    /// * `secret_distribution` - "ternary", "binary", or "gaussian"
    /// * `claimed_security` - Security level being claimed
    pub fn estimate(
        &self,
        n: usize,
        log_q: u32,
        secret_distribution: SecretDistribution,
        claimed_security: u32,
    ) -> SecurityEstimate {
        // Use HE Standard methodology with integer arithmetic:
        // Security ≈ n * (1 - log(q)/n * α) where α depends on attack model
        //
        // HE Standard Table 3 (128-bit classical security):
        // N=1024 → max log(q) = 27   → ratio = 37.9
        // N=2048 → max log(q) = 54   → ratio = 37.9
        // N=4096 → max log(q) = 109  → ratio = 37.6
        // N=8192 → max log(q) = 218  → ratio = 37.6
        //
        // At HE boundary: security ≈ 3.36 * (n / log(q))
        // Using millibits: base_security_mb = 3360 * n / log_q

        // Ternary secret penalty (vs Gaussian) — used for flat hybrid estimate
        // 850/1000 = 0.85 for ternary, 800/1000 = 0.80 for binary
        let ternary_penalty_per_mille: u32 = match secret_distribution {
            SecretDistribution::Ternary => 850, // ~15% reduction due to MITM
            SecretDistribution::Binary => 800,  // ~20% reduction
            SecretDistribution::Gaussian(_) => 1000,
        };

        // Base security in millibits: 3360 * n / log_q
        // Using 3360 as integer approximation of 3.36 * 1000
        let n_u64 = n as u64;
        let log_q_u64 = log_q as u64;

        // Avoid division by zero
        if log_q_u64 == 0 {
            return SecurityEstimate {
                classical_bits: 0,
                quantum_bits: 0,
                hybrid_bits: 0,
                effective_bits: 0,
                bkz_block_size: 0,
                bkz_iterations: 0,
                meets_claim: false,
                analysis: "Invalid: log_q = 0".to_string(),
            };
        }

        // base_security_mb = 3360 * n / log_q (in millibits)
        let base_security_mb: u64 = (3360 * n_u64) / log_q_u64;

        // Apply cost model adjustment (1000 = 1.0, 900 = 0.9)
        let model_factor_per_mille: u32 = match self.cost_model {
            CostModel::CoreSVP => 1000,
            CostModel::MATZOV => 900, // MATZOV is ~10% more aggressive
        };

        // Classical bits (pure BKZ attack, no secret distribution penalty)
        let classical_bits_mb = (base_security_mb * model_factor_per_mille as u64) / 1000;
        let classical_bits = (classical_bits_mb / 1000) as u32;

        // BKZ block size from classical security (attacker's required block size)
        let beta = ((classical_bits as u64 * 1000) / 292) as u32;

        // BKZ cost using dedicated cost model methods
        let (_bkz_cost_mb, bkz_iterations) = match self.cost_model {
            CostModel::CoreSVP => self.core_svp_cost(beta),
            CostModel::MATZOV => self.matzov_cost(beta),
        };

        // Hybrid security: take the tighter of flat-penalty and detailed MITM analysis
        let hybrid_bits_mb =
            (base_security_mb * ternary_penalty_per_mille as u64 * model_factor_per_mille as u64)
                / 1_000_000;
        let hybrid_bits_flat = (hybrid_bits_mb / 1000) as u32;
        let hybrid_bits_detailed = self.hybrid_attack_cost(n, log_q, beta, secret_distribution);
        let hybrid_bits = hybrid_bits_flat.min(hybrid_bits_detailed);

        // Quantum bits ≈ hybrid * 0.67 (Grover speedup)
        // Using 670/1000 = 0.67
        let quantum_bits = ((hybrid_bits as u64 * 670) / 1000) as u32;

        // Effective security is the binding constraint
        let effective_bits = classical_bits.min(hybrid_bits);

        let meets_claim = effective_bits >= claimed_security;

        // Compute ratio as integer (n * 10 / log_q for one decimal place)
        let ratio_x10 = (n_u64 * 10) / log_q_u64;
        let ratio_int = ratio_x10 / 10;
        let ratio_frac = ratio_x10 % 10;

        let cost_model_name = match self.cost_model {
            CostModel::CoreSVP => "Core-SVP",
            CostModel::MATZOV => "MATZOV",
        };

        let analysis = format!(
            "Ring-LWE n={}, log(q)={}, secret={:?}\n\
             n/log(q) ratio: {}.{}\n\
             Cost model: {} (BKZ-{}, {} iters)\n\
             Classical: {} bits\n\
             Hybrid (ternary): {} bits\n\
             Quantum: {} bits\n\
             Effective: {} bits ({})",
            n,
            log_q,
            secret_distribution,
            ratio_int,
            ratio_frac,
            cost_model_name,
            beta,
            bkz_iterations,
            classical_bits,
            hybrid_bits,
            quantum_bits,
            effective_bits,
            if meets_claim {
                "MEETS CLAIM"
            } else {
                "FAILS CLAIM"
            }
        );

        SecurityEstimate {
            classical_bits,
            quantum_bits,
            hybrid_bits,
            effective_bits,
            bkz_block_size: beta,
            bkz_iterations,
            meets_claim,
            analysis,
        }
    }

    /// Cross-validate parameters under both Core-SVP and MATZOV cost models.
    ///
    /// Returns estimates from both models plus the binding security level
    /// (the minimum of both). A parameter set should meet the claimed security
    /// under BOTH models to be considered production-ready.
    pub fn dual_estimate(
        &self,
        n: usize,
        log_q: u32,
        secret_distribution: SecretDistribution,
        claimed_security: u32,
    ) -> DualSecurityEstimate {
        let core_svp = LatticeSecurityEstimator::new(CostModel::CoreSVP).estimate(
            n,
            log_q,
            secret_distribution,
            claimed_security,
        );
        let matzov = LatticeSecurityEstimator::new(CostModel::MATZOV).estimate(
            n,
            log_q,
            secret_distribution,
            claimed_security,
        );

        let binding_bits = core_svp.effective_bits.min(matzov.effective_bits);
        let meets_both = core_svp.meets_claim && matzov.meets_claim;

        DualSecurityEstimate {
            core_svp,
            matzov,
            binding_bits,
            meets_both,
        }
    }

    /// Convert Hermite factor δ to BKZ block size β (integer approximation)
    ///
    /// Uses lookup table for common values, interpolation for others.
    /// The Hermite factor δ is provided as millionths (1_000_000 = 1.0).
    pub fn delta_to_beta(&self, delta_millionths: u64) -> u32 {
        // delta is provided as millionths (1_000_000 = 1.0)
        // Approximation based on GSA: β ≈ -log(δ) / 0.0085
        // For delta near 1.0, small differences matter

        // Use lookup table for common ranges
        // delta_millionths: 1_000_000 = 1.0, 1_005_000 = 1.005, etc.
        if delta_millionths >= 1_010_000 {
            return 50; // Very insecure
        }
        if delta_millionths >= 1_007_000 {
            return 100;
        }
        if delta_millionths >= 1_005_000 {
            return 200;
        }
        if delta_millionths >= 1_004_000 {
            return 300;
        }
        if delta_millionths >= 1_003_000 {
            return 500;
        }
        if delta_millionths >= 1_002_000 {
            return 1000;
        }
        2000 // Very secure
    }

    /// Core-SVP BKZ cost model (integer)
    /// Cost = 2^(0.292·β + o(β)) for classical
    /// Returns (log_cost_millibits, iterations)
    fn core_svp_cost(&self, beta: u32) -> (u64, u64) {
        // log_cost = 0.292 * beta → log_cost_mb = 292 * beta
        let log_cost_mb = 292 * beta as u64;
        let iterations = 8 * (beta as u64) * (beta as u64);
        (log_cost_mb, iterations)
    }

    /// MATZOV cost model (more aggressive, integer)
    /// Returns (log_cost_millibits, iterations)
    fn matzov_cost(&self, beta: u32) -> (u64, u64) {
        // MATZOV gives about 20% speedup over Core-SVP
        // log_cost = 0.265 * beta → log_cost_mb = 265 * beta
        let log_cost_mb = 265 * beta as u64;
        let iterations = 6 * (beta as u64) * (beta as u64);
        (log_cost_mb, iterations)
    }

    /// Hybrid attack combining BKZ with meet-in-the-middle (integer)
    ///
    /// Computes the optimal split between MITM guessing and BKZ reduction
    /// for structured secret distributions (ternary/binary).
    fn hybrid_attack_cost(
        &self,
        n: usize,
        _log_q: u32,
        beta: u32,
        secret_dist: SecretDistribution,
    ) -> u32 {
        // For ternary secrets, hybrid attack guesses some coordinates
        // and uses BKZ on the remaining lattice

        // Secret entropy per coefficient in millibits
        let _secret_entropy_mb: u32 = match secret_dist {
            SecretDistribution::Ternary => 1585, // log2(3) * 1000 ≈ 1.585
            SecretDistribution::Binary => 1000,
            SecretDistribution::Gaussian(_) => return beta, // No MITM advantage
        };

        // Optimal split: guess g coordinates, BKZ on n-g dimensions
        // Cost = 3^g + BKZ(n-g, log_q)
        let mut best_cost: u64 = u64::MAX;

        for g in 0..=(n / 4) {
            // guess_cost_mb = g * log2(3) * 1000 ≈ g * 1585
            let guess_cost_mb: u64 = (g as u64) * 1585;

            // Reduced dimension
            let reduced_n = n - g;
            if reduced_n < 100 {
                continue;
            }

            // Simplified: assume BKZ cost scales with dimension
            // reduced_beta ≈ beta * reduced_n / n
            let reduced_beta = ((beta as u64) * (reduced_n as u64) / (n as u64)) as u32;

            let (bkz_cost_mb, _) = match self.cost_model {
                CostModel::CoreSVP => self.core_svp_cost(reduced_beta),
                CostModel::MATZOV => self.matzov_cost(reduced_beta),
            };

            // Total cost is max of guess and BKZ (parallel attack)
            let total_cost = guess_cost_mb.max(bkz_cost_mb);

            if total_cost < best_cost {
                best_cost = total_cost;
            }
        }

        // Convert millibits to bits
        (best_cost / 1000).max(1) as u32
    }
}

// =============================================================================
// STRUCTURAL MODULUS SCREEN (additive; `estimate` above is unchanged)
// =============================================================================
//
// `estimate` takes `log_q`, a bare bit count. It therefore scores every 90-bit
// modulus identically at a given `n`: three 30-bit NTT primes, `2^90`, a
// prime-power basis `{8,9,25,49}^k`, and a manufactured `Q = t * D` all return
// the same number. That is recorded as an executable fact in
// `crates/nine65-extreme-tests/tests/full_system_measurement.rs`, MEASUREMENT 6.
//
// The screen below is the part that can SEE the modulus. It takes the
// factorization instead of the width and returns a type that is allowed to say
// *I cannot screen this*. That refusal is the point: a screen that is forced to
// emit a number is what produced the defect above.
//
// # What it does and does not claim
//
// This is an ENGINEERING SCREEN. It is a deterministic integer filter over
// modulus structure. It is not a lattice-security certificate and it is not a
// substitute for running an external lattice estimator (e.g. the Albrecht et
// al. `lattice-estimator`) on the concrete parameter set. Nothing here proves a
// refused parameter set is insecure, and nothing here proves a screened one is
// secure. A `Screened` verdict means only: "every lane has the shape the
// in-tree cost model was calibrated on, and here is that model's number."
//
// # Why refusal, rather than a number, for the non-prime shapes
//
// Two independent reasons, both checkable rather than asserted:
//
// 1. **The model's own output is nonsense on narrow lanes.** `estimate` is
//    `3360 * n / log_q` with no term for the error width. It is monotonically
//    *increasing* as `log_q` shrinks, so a 3-bit lane at `n = 8192` scores
//    ~2.7 million bits. Any number the model emits for a narrow lane is an
//    artefact of the formula, not an estimate.
//
// 2. **The instance's hardness there turns on a quantity this model has no
//    parameter for.** CRT splits RLWE mod `Q = q1 * q2` into components mod
//    `q1` and mod `q2`. Whether the component modulo a narrow lane leaks the
//    secret depends entirely on the error distribution *reduced modulo that
//    lane* — and `estimate` takes no error width at all. For a ternary secret
//    and a lane of 3, `s mod 3` determines `s` exactly; whether that is
//    exploitable is a question about the noise, which this screen cannot see.
//    It refuses rather than guessing.
//
// For prime-power lanes (`p^k`, `k >= 2`) the reason is different again: the
// standard worst-case-to-average-case RLWE reductions are stated for prime
// moduli, the ring `Z_{p^k}[X]/f` carries nilpotents, and the published
// estimator tables this module is calibrated against were validated on chains
// of large primes. That is an *unscreened regime*, reported as such. Note what
// this module does NOT say: it does not claim a power-of-two modulus is broken.
// Deployed lattice schemes (Saber, TFHE-style torus discretisations) use
// power-of-two moduli, so "trivially broken" would be an overclaim. The honest
// output is that the regime is outside this screen's calibration, and that no
// number from this model is meaningful there.
//
// # QMNF compliance
// Integer-only throughout: `u64`/`u128` modular arithmetic, limb-wise big
// multiplication for exact product bit lengths. No `f32`/`f64` anywhere.

/// Minimum bit length of a CRT lane this screen is willing to put a number on.
///
/// **This is an engineering threshold, not a cryptographic derivation.** It is
/// chosen to bracket a specific interval, and the bracket is the whole
/// justification:
///
/// - It must be **above 17 bits**, so that a lane equal to the BFV plaintext
///   modulus `t = 65537` is caught. The manufactured-modulus route
///   (`Q = t * D`, `q = c*t + 1`) makes exactly that lane reachable by
///   construction, which is why this screen exists at all.
/// - It must be low enough to stay inert for every config shipped in
///   `secure_configs.rs`. The narrowest lane in any of them is `754974721`,
///   which is 30 bits. The classification test is the strict `lane_bits <
///   MIN_MODELLED_LANE_BITS`, so a 30-bit lane still screens when the constant
///   is exactly 30: the true inert bound is therefore **`<= 30`**, and the
///   fully inert interval is the closed range `[18, 30]`.
///
/// The constant is pinned at `24`, and
/// `min_modelled_lane_bits_brackets_the_documented_interval` asserts `> 17` and
/// `<= 29` — one bit tighter than the true inert bound of 30, kept deliberately
/// as margin so that a future config introducing a 30-bit lane does not sit
/// exactly on the boundary. Any value in `[18, 30]` screens every in-tree
/// config identically; moving it is a policy decision, and the bracket test
/// pins the reasoning so it cannot drift away from the constant.
pub const MIN_MODELLED_LANE_BITS: u32 = 24;

/// Upper bound on the number of factorization entries this screen will accept.
///
/// The cross-lane coprimality scan is `O(k^2)` in the number of distinct lanes.
/// A real RNS chain has fewer than a dozen lanes; 256 is far past any sane
/// chain and keeps the pairwise scan bounded at 32640 gcds.
pub const MAX_SCREENED_LANES: usize = 256;

/// Upper bound, in 64-bit limbs, on the product this screen will represent
/// exactly (512 limbs = 32768 bits). Beyond this the screen reports the
/// factorization as unreadable rather than truncating a modulus width.
const MAX_PRODUCT_LIMBS: usize = 512;

/// Trial-division ceiling used when a declared lane base turns out composite.
/// Finding *a* small factor is decisive; failing to find one is reported as
/// "structure unknown", never as "no small factor exists".
const TRIAL_DIVISION_CEILING: u64 = 1 << 20;

/// One structural finding about one lane (or one pair of lanes) of a factored
/// modulus.
///
/// Every variant is a statement about the *modulus*, not about an attack cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaneFinding {
    /// `prime^1` with `prime` at least [`MIN_MODELLED_LANE_BITS`] wide. This is
    /// the only lane shape the in-tree cost model was calibrated on.
    PrimeField { prime: u64, bits: u32 },

    /// `2^exponent`. Reported as an unscreened regime: the standard RLWE
    /// reductions are stated for prime moduli and the estimator tables this
    /// module reproduces were validated on prime chains. Not a claim of a break.
    PowerOfTwo { exponent: u32, bits: u32 },

    /// `prime^exponent` with `exponent >= 2` and `prime` odd. `Z_{p^k}[X]/f`
    /// carries nilpotents; unscreened regime.
    PrimePower {
        prime: u64,
        exponent: u32,
        bits: u32,
    },

    /// A lane narrower than [`MIN_MODELLED_LANE_BITS`]. The cost model's output
    /// is an artefact here (it grows without bound as the width shrinks) and
    /// the lane's hardness turns on the error distribution modulo that lane,
    /// which this model has no parameter for.
    ///
    /// `bits` is the exact bit length of `base^exponent`, i.e. the width of the
    /// CRT component itself, not of `base`. When this finding is raised for a
    /// small prime factor discovered inside a composite base, `exponent` is 1
    /// and `bits` is that factor's own width — a lower bound on the true
    /// component, since the rest of the base's factorization is not visible.
    NarrowLane {
        base: u64,
        exponent: u32,
        bits: u32,
    },

    /// The declared base is composite, so the caller's "factorization" is not
    /// one and the true lane structure is not visible to the screen.
    /// `smallest_prime_factor` is `Some` only when trial division below
    /// [`TRIAL_DIVISION_CEILING`] actually found one.
    CompositeBase {
        base: u64,
        smallest_prime_factor: Option<u64>,
    },

    /// Two lanes are not coprime. Reported, never fatal on its own: the CRAM
    /// architecture treats a shared factor as a syndrome regime rather than an
    /// error, so this screen records it and lets the caller decide.
    SharedFactor { lane_a: u64, lane_b: u64, common: u64 },

    /// `base < 2` or `exponent == 0`: not a modulus lane at all.
    DegenerateLane { base: u64, exponent: u32 },

    /// The factorization slice was empty.
    EmptyFactorization,

    /// More entries than [`MAX_SCREENED_LANES`].
    TooManyLanes { count: usize },

    /// The product exceeds [`MAX_PRODUCT_LIMBS`] 64-bit limbs, so its exact bit
    /// length was not computed. The screen refuses rather than truncating.
    ProductTooWide { limb_cap: usize },
}

/// Why the screen declined to emit a number, with every contributing finding
/// kept in its own bucket. Nothing is collapsed to a single "reason", because a
/// modulus can be several kinds of unscreenable at once (each lane of
/// `{8,9,25,49}` is both a prime power and narrower than
/// [`MIN_MODELLED_LANE_BITS`]) and forcing a precedence would discard
/// information the caller needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RefusalReport {
    /// Lanes outside the regime where the standard hardness reductions and the
    /// published estimator tables were validated: prime powers, powers of two,
    /// and bases whose factorization the screen could not read.
    pub outside_regime: Vec<LaneFinding>,
    /// Lanes narrower than [`MIN_MODELLED_LANE_BITS`].
    pub narrow_lane: Vec<LaneFinding>,
    /// The factorization itself could not be read.
    pub malformed: Vec<LaneFinding>,
}

impl RefusalReport {
    /// True when nothing blocks a number being emitted.
    pub fn is_empty(&self) -> bool {
        self.outside_regime.is_empty() && self.narrow_lane.is_empty() && self.malformed.is_empty()
    }
}

/// The verdict of the structural screen.
///
/// [`ScreenVerdict::Refused`] is the reason this type exists: the screen is
/// permitted to decline. A screen that always returns a number is what let a
/// `2^90` modulus and a chain of NTT primes receive the same score.
#[derive(Debug, Clone)]
pub enum ScreenVerdict {
    /// Every lane is a prime field at least [`MIN_MODELLED_LANE_BITS`] wide.
    /// Carries the **binding** estimate: the minimum over the full-width
    /// instance and every individual CRT lane instance.
    Screened(SecurityEstimate),
    /// No number. See [`RefusalReport`].
    Refused(RefusalReport),
}

/// Result of screening a modulus by its factorization.
#[derive(Debug, Clone)]
pub struct FactoredSecurityEstimate {
    /// Screened (with a number) or Refused (without one).
    pub verdict: ScreenVerdict,
    /// Every finding, lane findings in first-appearance order followed by
    /// cross-lane findings.
    ///
    /// The vector exists for both verdicts, but note what a `Screened` verdict
    /// implies: reaching it requires every lane to be a distinct prime with
    /// exponent 1 and width at least [`MIN_MODELLED_LANE_BITS`]. Distinct
    /// primes are pairwise coprime, so the cross-lane scan cannot fire, and
    /// repeated bases merge to exponent >= 2 and force `Refused`. A `Screened`
    /// estimate therefore carries **no** refusal findings and in particular
    /// [`Self::shared_factors`] on it is provably always empty. Findings are
    /// worth reading on `Refused`; on `Screened` they are informational only.
    pub findings: Vec<LaneFinding>,
    /// Exact bit length of the product of all well-formed lanes; 0 when the
    /// product could not be represented.
    pub total_log_q: u32,
    /// Bit length of the widest single lane (`base^exponent`); 0 when none.
    pub widest_lane_bits: u32,
    /// Number of distinct bases after merging repeated entries.
    pub distinct_lane_count: usize,
    /// The claim this was screened against.
    pub claimed_security: u32,
    /// The cost model used.
    pub cost_model: CostModel,
    /// Human-readable report.
    pub analysis: String,
}

impl FactoredSecurityEstimate {
    /// The screened effective security, or `None` when the screen declined.
    ///
    /// `None` is a real answer, not a failure: it means the modulus structure
    /// is outside what this model can speak to.
    pub fn effective_bits(&self) -> Option<u32> {
        match &self.verdict {
            ScreenVerdict::Screened(est) => Some(est.effective_bits),
            ScreenVerdict::Refused(_) => None,
        }
    }

    /// The full binding estimate, or `None` when the screen declined.
    pub fn estimate(&self) -> Option<&SecurityEstimate> {
        match &self.verdict {
            ScreenVerdict::Screened(est) => Some(est),
            ScreenVerdict::Refused(_) => None,
        }
    }

    /// A refusal never meets a claim. This is the whole point: `2^90` cannot
    /// come back as meeting 128 bits, because no number is produced for it.
    pub fn meets_claim(&self) -> bool {
        match &self.verdict {
            ScreenVerdict::Screened(est) => est.meets_claim,
            ScreenVerdict::Refused(_) => false,
        }
    }

    /// True when a number was produced.
    pub fn is_screened(&self) -> bool {
        matches!(self.verdict, ScreenVerdict::Screened(_))
    }

    /// The refusal detail, when the screen declined.
    pub fn refusal(&self) -> Option<&RefusalReport> {
        match &self.verdict {
            ScreenVerdict::Screened(_) => None,
            ScreenVerdict::Refused(report) => Some(report),
        }
    }

    /// True when at least one lane put this modulus outside the regime the
    /// hardness reductions and the published estimators were validated on.
    pub fn is_unscreened_regime(&self) -> bool {
        self.refusal()
            .map(|r| !r.outside_regime.is_empty())
            .unwrap_or(false)
    }

    /// True when at least one lane is narrower than [`MIN_MODELLED_LANE_BITS`].
    pub fn has_narrow_lane(&self) -> bool {
        self.refusal()
            .map(|r| !r.narrow_lane.is_empty())
            .unwrap_or(false)
    }

    /// True when the factorization itself could not be read.
    pub fn is_malformed(&self) -> bool {
        self.refusal()
            .map(|r| !r.malformed.is_empty())
            .unwrap_or(false)
    }

    /// Every non-coprime lane pair the screen noticed. Reported, never fatal.
    pub fn shared_factors(&self) -> Vec<&LaneFinding> {
        self.findings
            .iter()
            .filter(|f| matches!(f, LaneFinding::SharedFactor { .. }))
            .collect()
    }
}

/// Structural screen run under both cost models.
#[derive(Debug, Clone)]
pub struct FactoredDualEstimate {
    /// Core-SVP (conservative).
    pub core_svp: FactoredSecurityEstimate,
    /// MATZOV (aggressive).
    pub matzov: FactoredSecurityEstimate,
    /// Minimum across both models, or `None` if either model declined.
    /// A refusal is structural, so both models always refuse together.
    pub binding_bits: Option<u32>,
    /// Whether the claim is met under both models. Always false on a refusal.
    pub meets_both: bool,
}

impl LatticeSecurityEstimator {
    /// Screen a modulus by its **factorization** rather than by its bit width.
    ///
    /// `factors` is a list of `(base, exponent)` entries whose product is the
    /// ciphertext modulus. Repeated bases are merged (and reported as a shared
    /// factor), so `[(p,1),(p,1)]` is screened as `p^2`.
    ///
    /// Returns [`FactoredSecurityEstimate`], which may decline to produce a
    /// number. See the module section "STRUCTURAL MODULUS SCREEN" for what a
    /// refusal does and does not mean. This is an engineering screen; it is
    /// never a substitute for an external lattice-estimator run on the
    /// concrete parameter set.
    ///
    /// `estimate` is untouched and every existing caller keeps its behaviour.
    pub fn estimate_with_factorization(
        &self,
        n: usize,
        factors: &[(u64, u32)],
        secret_distribution: SecretDistribution,
        claimed_security: u32,
    ) -> FactoredSecurityEstimate {
        let mut findings: Vec<LaneFinding> = Vec::new();
        let mut refusal = RefusalReport::default();

        if factors.is_empty() {
            findings.push(LaneFinding::EmptyFactorization);
            refusal.malformed.push(LaneFinding::EmptyFactorization);
            return Self::refused(
                findings,
                refusal,
                0,
                0,
                0,
                claimed_security,
                self.cost_model,
                n,
            );
        }
        if factors.len() > MAX_SCREENED_LANES {
            let f = LaneFinding::TooManyLanes {
                count: factors.len(),
            };
            findings.push(f.clone());
            refusal.malformed.push(f);
            return Self::refused(
                findings,
                refusal,
                0,
                0,
                0,
                claimed_security,
                self.cost_model,
                n,
            );
        }

        // ---- merge repeated bases, first-appearance order (deterministic) ----
        let mut lanes: Vec<(u64, u32)> = Vec::with_capacity(factors.len());
        let mut duplicate_findings: Vec<LaneFinding> = Vec::new();
        for &(base, exponent) in factors {
            if let Some(slot) = lanes.iter_mut().find(|(b, _)| *b == base) {
                slot.1 = slot.1.saturating_add(exponent);
                duplicate_findings.push(LaneFinding::SharedFactor {
                    lane_a: base,
                    lane_b: base,
                    common: base,
                });
            } else {
                lanes.push((base, exponent));
            }
        }

        // ---- classify each distinct lane -------------------------------------
        // `screenable_lane_bits` collects the widths that may be fed to the
        // cost model, i.e. large prime fields only.
        let mut screenable_lane_bits: Vec<u32> = Vec::with_capacity(lanes.len());
        let mut widest_lane_bits: u32 = 0;

        for &(base, exponent) in &lanes {
            if base < 2 || exponent == 0 {
                let f = LaneFinding::DegenerateLane { base, exponent };
                findings.push(f.clone());
                refusal.malformed.push(f);
                continue;
            }

            let lane_bits = match product_bit_length(&[(base, exponent)]) {
                Some(bits) => bits,
                None => {
                    let f = LaneFinding::ProductTooWide {
                        limb_cap: MAX_PRODUCT_LIMBS,
                    };
                    findings.push(f.clone());
                    refusal.malformed.push(f);
                    continue;
                }
            };
            if lane_bits > widest_lane_bits {
                widest_lane_bits = lane_bits;
            }

            let base_bits = bit_length_u64(base);
            let base_is_prime = is_prime_u64(base);

            // Narrow-lane check first: it is independent of primality, and a
            // narrow lane is unscreenable whatever else it is.
            if lane_bits < MIN_MODELLED_LANE_BITS {
                let f = LaneFinding::NarrowLane {
                    base,
                    exponent,
                    bits: lane_bits,
                };
                findings.push(f.clone());
                refusal.narrow_lane.push(f);
            }

            if base == 2 {
                let f = LaneFinding::PowerOfTwo {
                    exponent,
                    bits: lane_bits,
                };
                findings.push(f.clone());
                refusal.outside_regime.push(f);
                continue;
            }

            if base_is_prime {
                if exponent >= 2 {
                    let f = LaneFinding::PrimePower {
                        prime: base,
                        exponent,
                        bits: lane_bits,
                    };
                    findings.push(f.clone());
                    refusal.outside_regime.push(f);
                    continue;
                }
                // LIVE, not dead: the narrow-lane check above records its
                // finding and falls through without `continue`, so a narrow
                // prime lane with exponent 1 reaches here. This guard is the
                // only thing stopping it from *also* being counted as a
                // screenable `PrimeField`. Removing it makes t = 65537 screen
                // as a real 17-bit lane; see
                // `narrow_prime_lane_is_recorded_narrow_and_never_as_a_screenable_field`.
                if base_bits < MIN_MODELLED_LANE_BITS {
                    continue;
                }
                findings.push(LaneFinding::PrimeField {
                    prime: base,
                    bits: base_bits,
                });
                screenable_lane_bits.push(base_bits);
                continue;
            }

            // Composite declared base: the caller did not hand a factorization.
            let spf = smallest_prime_factor_below_ceiling(base);
            let f = LaneFinding::CompositeBase {
                base,
                smallest_prime_factor: spf,
            };
            findings.push(f.clone());
            refusal.outside_regime.push(f.clone());
            if let Some(factor) = spf {
                if bit_length_u64(factor) < MIN_MODELLED_LANE_BITS {
                    let narrow = LaneFinding::NarrowLane {
                        base: factor,
                        exponent: 1,
                        bits: bit_length_u64(factor),
                    };
                    findings.push(narrow.clone());
                    refusal.narrow_lane.push(narrow);
                }
            }
        }

        // ---- cross-lane coprimality -----------------------------------------
        findings.extend(duplicate_findings);
        for i in 0..lanes.len() {
            for j in (i + 1)..lanes.len() {
                let (a, b) = (lanes[i].0, lanes[j].0);
                if a < 2 || b < 2 {
                    continue;
                }
                let g = gcd_u64(a, b);
                if g > 1 {
                    findings.push(LaneFinding::SharedFactor {
                        lane_a: a,
                        lane_b: b,
                        common: g,
                    });
                }
            }
        }

        // ---- exact total width ----------------------------------------------
        let well_formed: Vec<(u64, u32)> = lanes
            .iter()
            .copied()
            .filter(|&(b, e)| b >= 2 && e >= 1)
            .collect();
        let total_log_q = if well_formed.is_empty() {
            0
        } else {
            match product_bit_length(&well_formed) {
                Some(bits) => bits,
                None => {
                    let f = LaneFinding::ProductTooWide {
                        limb_cap: MAX_PRODUCT_LIMBS,
                    };
                    findings.push(f.clone());
                    refusal.malformed.push(f);
                    0
                }
            }
        };

        let distinct = lanes.len();

        if !refusal.is_empty() {
            return Self::refused(
                findings,
                refusal,
                total_log_q,
                widest_lane_bits,
                distinct,
                claimed_security,
                self.cost_model,
                n,
            );
        }

        // ---- binding numeric result -----------------------------------------
        //
        // The binding result is the MINIMUM over the full-width instance and
        // every individual CRT lane instance. The full-width term is included
        // because it is the instance an adversary is actually handed; the lane
        // terms are included because CRT genuinely splits the problem and an
        // adversary may work any component.
        //
        // Under this cost model (`3360 * n / log_q`, monotonically decreasing
        // in `log_q`) the full-width term always binds, since no lane is wider
        // than the product. That is stated here as an observation, not hidden:
        // the lane terms can only ever TIGHTEN the result, never loosen it, so
        // adding them cannot move an existing config's number. That is exactly
        // the no-regression property `factored_screen_leaves_every_secure_config_unchanged`
        // asserts by execution.
        let mut binding = self.estimate(n, total_log_q, secret_distribution, claimed_security);
        for &lane_bits in &screenable_lane_bits {
            let lane_est = self.estimate(n, lane_bits, secret_distribution, claimed_security);
            if lane_est.effective_bits < binding.effective_bits {
                binding = lane_est;
            }
        }

        let analysis = format!(
            "STRUCTURAL SCREEN (engineering filter, NOT a lattice-estimator run)\n\
             n={}, lanes={}, total log2(Q)={}, widest lane={} bits\n\
             verdict: SCREENED — every lane is a prime field >= {} bits\n\
             binding estimate (min over full width and each CRT lane): {} bits\n\
             {}",
            n,
            distinct,
            total_log_q,
            widest_lane_bits,
            MIN_MODELLED_LANE_BITS,
            binding.effective_bits,
            binding.analysis,
        );

        FactoredSecurityEstimate {
            verdict: ScreenVerdict::Screened(binding),
            findings,
            total_log_q,
            widest_lane_bits,
            distinct_lane_count: distinct,
            claimed_security,
            cost_model: self.cost_model,
            analysis,
        }
    }

    /// Structural screen under both cost models.
    ///
    /// A refusal is a property of the modulus, not of the cost model, so both
    /// models refuse together; `binding_bits` is `None` in that case.
    pub fn dual_estimate_with_factorization(
        &self,
        n: usize,
        factors: &[(u64, u32)],
        secret_distribution: SecretDistribution,
        claimed_security: u32,
    ) -> FactoredDualEstimate {
        let core_svp = LatticeSecurityEstimator::new(CostModel::CoreSVP)
            .estimate_with_factorization(n, factors, secret_distribution, claimed_security);
        let matzov = LatticeSecurityEstimator::new(CostModel::MATZOV)
            .estimate_with_factorization(n, factors, secret_distribution, claimed_security);

        let binding_bits = match (core_svp.effective_bits(), matzov.effective_bits()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            _ => None,
        };
        let meets_both = core_svp.meets_claim() && matzov.meets_claim();

        FactoredDualEstimate {
            core_svp,
            matzov,
            binding_bits,
            meets_both,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn refused(
        findings: Vec<LaneFinding>,
        refusal: RefusalReport,
        total_log_q: u32,
        widest_lane_bits: u32,
        distinct_lane_count: usize,
        claimed_security: u32,
        cost_model: CostModel,
        n: usize,
    ) -> FactoredSecurityEstimate {
        let analysis = format!(
            "STRUCTURAL SCREEN (engineering filter, NOT a lattice-estimator run)\n\
             n={}, lanes={}, total log2(Q)={}, widest lane={} bits\n\
             verdict: REFUSED — NO SECURITY NUMBER IS EMITTED\n\
             outside-regime lanes: {}\n\
             narrow lanes (< {} bits): {}\n\
             malformed entries: {}\n\
             findings: {:?}\n\
             A refusal is not a proof of insecurity. It states that this model's \
             calibration does not cover this modulus structure, so any number it \
             produced would be an artefact of the formula rather than an estimate. \
             Screen the concrete parameter set with an external lattice estimator.",
            n,
            distinct_lane_count,
            total_log_q,
            widest_lane_bits,
            refusal.outside_regime.len(),
            MIN_MODELLED_LANE_BITS,
            refusal.narrow_lane.len(),
            refusal.malformed.len(),
            findings,
        );
        FactoredSecurityEstimate {
            verdict: ScreenVerdict::Refused(refusal),
            findings,
            total_log_q,
            widest_lane_bits,
            distinct_lane_count,
            claimed_security,
            cost_model,
            analysis,
        }
    }
}

// -----------------------------------------------------------------------------
// Integer-only number-theoretic helpers (no f32/f64 anywhere)
// -----------------------------------------------------------------------------

/// Bit length of a `u64` (`bit_length_u64(0) == 0`).
fn bit_length_u64(value: u64) -> u32 {
    if value == 0 {
        0
    } else {
        u64::BITS - value.leading_zeros()
    }
}

/// `a * b mod m` via `u128`. Integer-only.
fn mul_mod_u64(a: u64, b: u64, m: u64) -> u64 {
    (((a as u128) * (b as u128)) % (m as u128)) as u64
}

/// `base^exp mod m` by square-and-multiply. Integer-only.
fn pow_mod_u64(mut base: u64, mut exp: u64, m: u64) -> u64 {
    if m == 1 {
        return 0;
    }
    let mut acc: u64 = 1;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mul_mod_u64(acc, base, m);
        }
        base = mul_mod_u64(base, base, m);
        exp >>= 1;
    }
    acc
}

/// Deterministic Miller-Rabin primality test, exact for the whole `u64` range.
///
/// The witness set `{2, 325, 9375, 28178, 450775, 9780504, 1795265022}` is the
/// standard 7-base set that is deterministic for all `n < 2^64` (Sinclair /
/// Sorenson-Webster). Integer-only.
fn is_prime_u64(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    for small in [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if n % small == 0 {
            return n == small;
        }
    }
    let mut d = n - 1;
    let mut s: u32 = 0;
    while d & 1 == 0 {
        d >>= 1;
        s += 1;
    }
    'witness: for &a in &[2u64, 325, 9375, 28178, 450775, 9780504, 1795265022] {
        let a = a % n;
        if a == 0 {
            continue;
        }
        let mut x = pow_mod_u64(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        for _ in 1..s {
            x = mul_mod_u64(x, x, n);
            if x == n - 1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

/// Smallest prime factor of `n` found by trial division below
/// [`TRIAL_DIVISION_CEILING`], or `None` if none was found in that range.
///
/// `None` means "not found within the budget", never "none exists".
fn smallest_prime_factor_below_ceiling(n: u64) -> Option<u64> {
    if n < 2 {
        return None;
    }
    for small in [2u64, 3, 5] {
        if n % small == 0 {
            return Some(small);
        }
    }
    // mod-30 wheel from 7: gaps 4,2,4,2,4,6,2,6
    const WHEEL: [u64; 8] = [4, 2, 4, 2, 4, 6, 2, 6];
    let mut candidate: u64 = 7;
    let mut index: usize = 0;
    while candidate <= TRIAL_DIVISION_CEILING {
        if candidate > n / candidate {
            break; // candidate^2 > n: no factor below sqrt(n) remains
        }
        if n % candidate == 0 {
            return Some(candidate);
        }
        candidate += WHEEL[index];
        index = (index + 1) % WHEEL.len();
    }
    None
}

/// Binary-free Euclidean gcd. Integer-only.
fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// Exact bit length of `prod(base_i ^ exp_i)` via little-endian `u64` limbs.
///
/// Returns `None` when the product would exceed [`MAX_PRODUCT_LIMBS`] limbs, so
/// a width is never silently truncated. Bases below 2 are skipped (they are
/// reported as degenerate lanes elsewhere); this also keeps the loop bounded,
/// since every accepted multiply adds at least one bit.
fn product_bit_length(factors: &[(u64, u32)]) -> Option<u32> {
    let mut limbs: Vec<u64> = vec![1];
    for &(base, exponent) in factors {
        if base < 2 {
            continue;
        }
        for _ in 0..exponent {
            let mut carry: u128 = 0;
            for limb in limbs.iter_mut() {
                let product = (*limb as u128) * (base as u128) + carry;
                *limb = product as u64;
                carry = product >> 64;
            }
            while carry > 0 {
                if limbs.len() >= MAX_PRODUCT_LIMBS {
                    return None;
                }
                limbs.push(carry as u64);
                carry >>= 64;
            }
        }
    }
    while limbs.len() > 1 && *limbs.last().unwrap_or(&0) == 0 {
        limbs.pop();
    }
    let top = *limbs.last().unwrap_or(&0);
    if limbs.len() == 1 && top <= 1 {
        // Product is 0 or 1: no modulus width to report.
        return Some(0);
    }
    Some((limbs.len() as u32 - 1) * 64 + bit_length_u64(top))
}

/// Secret key distribution type
#[derive(Debug, Clone, Copy)]
pub enum SecretDistribution {
    /// Ternary: {-1, 0, 1}
    Ternary,
    /// Binary: {0, 1}
    Binary,
    /// Discrete Gaussian with given standard deviation (in milliunits, 1000 = 1.0)
    Gaussian(u32),
}

/// HE Standard v1.1 compliant parameter bounds (integer-only)
pub struct HEStandardBounds;

impl HEStandardBounds {
    /// Maximum log(q) for given n to achieve target security
    /// Uses lookup tables - no floating point.
    pub fn max_log_q(n: usize, target_security: u32) -> u32 {
        // From HE Standard v1.1 Table 3
        match (n, target_security) {
            // 128-bit classical security
            (1024, 128) => 27,
            (2048, 128) => 54,
            (4096, 128) => 109,
            (8192, 128) => 218,
            (16384, 128) => 438,
            (32768, 128) => 881,

            // 192-bit classical security
            (1024, 192) => 19,
            (2048, 192) => 37,
            (4096, 192) => 75,
            (8192, 192) => 152,
            (16384, 192) => 305,
            (32768, 192) => 611,

            // 256-bit classical security
            (1024, 256) => 14,
            (2048, 256) => 29,
            (4096, 256) => 58,
            (8192, 256) => 118,
            (16384, 256) => 237,
            (32768, 256) => 476,

            // Interpolate for other values using integer arithmetic
            _ => {
                // Find log2(n) using integer operations
                let log_n = integer_log2(n);

                // Base values at n=1024 (log_n=10)
                let base = match target_security {
                    128 => 27,
                    192 => 19,
                    256 => 14,
                    _ => 20,
                };

                // Scale: each doubling of n roughly doubles max_log_q
                // max_log_q ≈ base * 2^(log_n - 10)
                if log_n >= 10 {
                    base << (log_n - 10)
                } else {
                    base >> (10 - log_n)
                }
            }
        }
    }

    /// Minimum n required for given security level
    pub fn min_n(log_q: u32, target_security: u32) -> usize {
        // Binary search for minimum n
        for n_log in 10..=16 {
            let n = 1usize << n_log;
            let max_q = Self::max_log_q(n, target_security);
            if log_q <= max_q {
                return n;
            }
        }
        1 << 16 // Maximum supported
    }

    /// Check if parameters meet HE Standard
    pub fn is_compliant(n: usize, log_q: u32, target_security: u32) -> bool {
        log_q <= Self::max_log_q(n, target_security)
    }
}

/// Integer log2 (floor) - returns position of highest set bit minus 1
fn integer_log2(n: usize) -> u32 {
    if n == 0 {
        return 0;
    }
    (usize::BITS - 1) - n.leading_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_estimation_integer() {
        let estimator = LatticeSecurityEstimator::default();

        // Test light config (N=1024, log(q)=30)
        // At HE Standard boundary: N=1024 with log(q)=27 gives 128-bit
        // With log(q)=30, we exceed the boundary → lower security
        let est = estimator.estimate(1024, 30, SecretDistribution::Ternary, 80);
        println!("light: {}", est.analysis);
        assert!(
            est.effective_bits < 128,
            "light should have <128 bit security"
        );

        // Test N=4096, log(q)=90
        // HE Standard: N=4096 with log(q)≤109 gives 128-bit
        // With log(q)=90, should be comfortably within bounds
        let est = estimator.estimate(4096, 90, SecretDistribution::Ternary, 128);
        println!("standard: {}", est.analysis);
        assert!(
            est.effective_bits >= 100,
            "N=4096 with log(q)=90 should have >=100 bit security"
        );

        // Test N=8192, log(q)=90
        // HE Standard: N=8192 with log(q)≤218 gives 128-bit
        // With only log(q)=90, should have excellent security
        let est = estimator.estimate(8192, 90, SecretDistribution::Ternary, 128);
        println!("high: {}", est.analysis);
        assert!(
            est.effective_bits >= 200,
            "N=8192 with log(q)=90 should have >=200 bit security"
        );
    }

    #[test]
    fn test_he_standard_bounds() {
        // Verify HE Standard table values
        assert_eq!(HEStandardBounds::max_log_q(1024, 128), 27);
        assert_eq!(HEStandardBounds::max_log_q(2048, 128), 54);
        assert_eq!(HEStandardBounds::max_log_q(4096, 128), 109);

        // Check compliance
        assert!(!HEStandardBounds::is_compliant(1024, 30, 128)); // Exceeds
        assert!(HEStandardBounds::is_compliant(2048, 30, 128)); // OK
        assert!(HEStandardBounds::is_compliant(4096, 90, 128)); // OK
    }

    #[test]
    fn test_min_n_calculation() {
        // 30-bit modulus needs at least N=2048 for 128-bit security
        assert!(HEStandardBounds::min_n(30, 128) >= 2048);

        // 90-bit modulus needs at least N=4096
        assert!(HEStandardBounds::min_n(90, 128) >= 4096);
    }

    #[test]
    fn test_integer_log2() {
        assert_eq!(integer_log2(1), 0);
        assert_eq!(integer_log2(2), 1);
        assert_eq!(integer_log2(4), 2);
        assert_eq!(integer_log2(1024), 10);
        assert_eq!(integer_log2(4096), 12);
        assert_eq!(integer_log2(8192), 13);
    }

    #[test]
    fn test_no_floating_point() {
        // This test verifies the module compiles without std::f64
        // The old version used: use std::f64::consts::PI;
        // Now all operations are integer-only
        let estimator = LatticeSecurityEstimator::new(CostModel::MATZOV);
        let est = estimator.estimate(4096, 100, SecretDistribution::Binary, 128);

        // Results should be reasonable integers
        assert!(est.classical_bits > 0);
        assert!(est.quantum_bits > 0);
        assert!(est.bkz_iterations > 0);
    }

    #[test]
    fn test_dual_estimate_matzov_more_aggressive() {
        // MATZOV should always give lower security than Core-SVP
        let estimator = LatticeSecurityEstimator::default();
        let dual = estimator.dual_estimate(4096, 90, SecretDistribution::Ternary, 128);

        assert!(
            dual.matzov.effective_bits <= dual.core_svp.effective_bits,
            "MATZOV ({}) should be <= Core-SVP ({})",
            dual.matzov.effective_bits,
            dual.core_svp.effective_bits
        );
        assert!(dual.binding_bits > 0, "Binding bits must be positive");
        assert_eq!(
            dual.binding_bits, dual.matzov.effective_bits,
            "Binding bits should equal MATZOV (most aggressive)"
        );
    }

    #[test]
    fn test_dual_estimate_both_models_populated() {
        let estimator = LatticeSecurityEstimator::default();
        let dual = estimator.dual_estimate(8192, 200, SecretDistribution::Ternary, 128);

        // Both estimates should be populated
        assert!(dual.core_svp.classical_bits > 0);
        assert!(dual.matzov.classical_bits > 0);
        assert!(dual.core_svp.bkz_iterations > 0);
        assert!(dual.matzov.bkz_iterations > 0);
    }

    #[test]
    fn test_dual_estimate_meets_claim_under_both() {
        let estimator = LatticeSecurityEstimator::default();

        // N=8192, log(q)=90 should meet 128-bit under both models
        let dual = estimator.dual_estimate(8192, 90, SecretDistribution::Ternary, 128);
        assert!(
            dual.meets_both,
            "N=8192, log(q)=90 should meet 128-bit under both models"
        );

        // N=1024, log(q)=30 should not meet 128-bit under either
        let dual = estimator.dual_estimate(1024, 30, SecretDistribution::Ternary, 128);
        assert!(
            !dual.meets_both,
            "N=1024, log(q)=30 should not meet 128-bit"
        );
    }

    // =========================================================================
    // COMPREHENSIVE MATZOV VALIDATION TESTS
    // =========================================================================

    #[test]
    fn test_matzov_vs_coresvp_10_percent_reduction() {
        // MATZOV should give ~10% lower security than CoreSVP for same params
        let core_svp = LatticeSecurityEstimator::new(CostModel::CoreSVP);
        let matzov = LatticeSecurityEstimator::new(CostModel::MATZOV);

        let test_params = [
            (4096, 90, "secure_128 params"),
            (8192, 150, "secure_192 params"),
            (16384, 177, "secure_256 params"),
            (2048, 54, "HE Standard boundary"),
        ];

        for (n, log_q, desc) in test_params {
            let core_est = core_svp.estimate(n, log_q, SecretDistribution::Ternary, 128);
            let matz_est = matzov.estimate(n, log_q, SecretDistribution::Ternary, 128);

            println!("\n{} (n={}, log_q={}):", desc, n, log_q);
            println!("  CoreSVP: {} bits", core_est.effective_bits);
            println!("  MATZOV:  {} bits", matz_est.effective_bits);

            // MATZOV should be lower (more aggressive)
            assert!(
                matz_est.effective_bits <= core_est.effective_bits,
                "{}: MATZOV should be <= CoreSVP",
                desc
            );

            // Verify ~10% reduction (900/1000 factor)
            let reduction_ratio = if core_est.effective_bits > 0 {
                (matz_est.effective_bits as u64 * 1000) / (core_est.effective_bits as u64)
            } else {
                1000
            };

            println!("  Ratio: {}/1000 (target: 900)", reduction_ratio);

            // Allow variance due to integer rounding and hybrid attack complexity
            // Expected: ~900/1000 (10% reduction), Allow range: 850-950 (5-15%)
            assert!(
                (850..=950).contains(&reduction_ratio),
                "{}: ratio {}/1000 should be near 900 (got {})",
                desc,
                reduction_ratio,
                reduction_ratio
            );
        }
    }

    #[test]
    fn test_matzov_he_standard_boundary_agreement() {
        // Verify both models agree on HE Standard boundary conditions
        let core_svp = LatticeSecurityEstimator::new(CostModel::CoreSVP);
        let matzov = LatticeSecurityEstimator::new(CostModel::MATZOV);

        // HE Standard v1.1 Table 3 boundary cases for 128-bit security
        let boundary_cases = [
            (1024, 27),  // Exactly at boundary
            (2048, 54),  // Exactly at boundary
            (4096, 109), // Exactly at boundary
            (8192, 218), // Exactly at boundary
        ];

        for (n, log_q) in boundary_cases {
            let core_est = core_svp.estimate(n, log_q, SecretDistribution::Ternary, 128);
            let matz_est = matzov.estimate(n, log_q, SecretDistribution::Ternary, 128);

            println!(
                "\nHE Boundary n={}, log_q={}: CoreSVP={} bits, MATZOV={} bits",
                n, log_q, core_est.effective_bits, matz_est.effective_bits
            );

            // At HE Standard boundary, CoreSVP should give ~128 bits
            // (formula is calibrated to HE Standard)
            assert!(
                core_est.effective_bits >= 100 && core_est.effective_bits <= 140,
                "CoreSVP at HE boundary should be near 128 bits, got {}",
                core_est.effective_bits
            );

            // MATZOV should be ~10% lower but still in reasonable range
            assert!(
                matz_est.effective_bits >= 90 && matz_est.effective_bits <= 130,
                "MATZOV at HE boundary should be near 115 bits (90% of 128), got {}",
                matz_est.effective_bits
            );
        }
    }

    #[test]
    fn test_matzov_production_configs_meet_claims() {
        use crate::params::secure_configs::SecureConfig;

        let matzov = LatticeSecurityEstimator::new(CostModel::MATZOV);

        // Test production configs with MATZOV (more realistic attack model)
        // Expected values based on actual measurements (not config names)
        let configs = [
            ("secure_128", SecureConfig::secure_128(), 115), // Measured: 116 bits
            ("secure_192", SecureConfig::secure_192(), 140), // Measured: 143 bits
            ("secure_256", SecureConfig::secure_256(), 230), // 6 primes, log_q=177
        ];

        for (name, sec_config, min_expected_bits) in configs {
            let config = sec_config.into_config();
            let log_q: u32 = config.primes.iter().map(|&p| 64 - p.leading_zeros()).sum();

            let est = matzov.estimate(
                config.n,
                log_q,
                SecretDistribution::Ternary,
                min_expected_bits,
            );

            println!("\n{} with MATZOV:", name);
            println!(
                "  Effective: {} bits (target: >= {})",
                est.effective_bits, min_expected_bits
            );
            println!("{}", est.analysis);

            // MATZOV gives ~10% lower security than CoreSVP
            // Production configs should meet measured security levels
            assert!(
                est.effective_bits >= min_expected_bits,
                "{} should meet {} bits with MATZOV (got {})",
                name,
                min_expected_bits,
                est.effective_bits
            );
        }
    }

    #[test]
    fn test_cost_model_methods_integer_correctness() {
        // Test the cost model methods work correctly with integer arithmetic
        let core_svp = LatticeSecurityEstimator::new(CostModel::CoreSVP);
        let matzov_est = LatticeSecurityEstimator::new(CostModel::MATZOV);

        let test_betas = [100, 200, 300, 500];

        for beta in test_betas {
            let (core_cost_mb, core_iters) = core_svp.core_svp_cost(beta);
            let (matz_cost_mb, matz_iters) = matzov_est.matzov_cost(beta);

            println!("\nBeta={}:", beta);
            println!(
                "  CoreSVP: {} millibits, {} iters",
                core_cost_mb, core_iters
            );
            println!(
                "  MATZOV:  {} millibits, {} iters",
                matz_cost_mb, matz_iters
            );

            // MATZOV should be cheaper (lower cost)
            assert!(
                matz_cost_mb < core_cost_mb,
                "MATZOV cost should be < CoreSVP for beta={}",
                beta
            );

            // CoreSVP: 0.292 * beta → 292 * beta millibits
            assert_eq!(core_cost_mb, 292 * beta as u64);

            // MATZOV: 0.265 * beta → 265 * beta millibits
            assert_eq!(matz_cost_mb, 265 * beta as u64);

            // Iterations: CoreSVP = 8β², MATZOV = 6β²
            assert_eq!(core_iters, 8 * (beta as u64) * (beta as u64));
            assert_eq!(matz_iters, 6 * (beta as u64) * (beta as u64));
        }
    }

    #[test]
    fn test_hybrid_attack_cost_ternary_mitm() {
        // Test hybrid attack cost calculation (ternary secret MITM)
        let core_svp = LatticeSecurityEstimator::new(CostModel::CoreSVP);
        let matzov = LatticeSecurityEstimator::new(CostModel::MATZOV);

        let params = [
            (4096, 90, 300, SecretDistribution::Ternary),
            (8192, 150, 400, SecretDistribution::Ternary),
            (4096, 90, 300, SecretDistribution::Binary),
            (4096, 90, 300, SecretDistribution::Gaussian(3200)),
        ];

        for (n, log_q, beta, secret_dist) in params {
            let core_hybrid = core_svp.hybrid_attack_cost(n, log_q, beta, secret_dist);
            let matz_hybrid = matzov.hybrid_attack_cost(n, log_q, beta, secret_dist);

            println!(
                "\nHybrid attack n={}, log_q={}, beta={}, secret={:?}:",
                n, log_q, beta, secret_dist
            );
            println!("  CoreSVP: {} bits", core_hybrid);
            println!("  MATZOV:  {} bits", matz_hybrid);

            // Results should be reasonable
            assert!(core_hybrid > 0, "CoreSVP hybrid should be > 0");
            assert!(matz_hybrid > 0, "MATZOV hybrid should be > 0");

            // MATZOV should generally be lower or equal (more aggressive)
            assert!(
                matz_hybrid <= core_hybrid,
                "MATZOV hybrid should be <= CoreSVP"
            );

            // For Gaussian distribution, hybrid should equal beta (no MITM advantage)
            if matches!(secret_dist, SecretDistribution::Gaussian(_)) {
                assert_eq!(
                    core_hybrid, beta,
                    "Gaussian should have no hybrid advantage"
                );
                assert_eq!(
                    matz_hybrid, beta,
                    "Gaussian should have no hybrid advantage"
                );
            }
        }
    }

    #[test]
    fn test_delta_to_beta_lookup_ranges() {
        let estimator = LatticeSecurityEstimator::default();

        // Test lookup table ranges
        let test_deltas = [
            (1_002_000, 1000, 2000, "Very secure"),
            (1_003_000, 500, 1000, "Secure"),
            (1_005_000, 200, 300, "Medium"),
            (1_007_000, 100, 200, "Low"),
            (1_010_000, 50, 100, "Very insecure"),
        ];

        for (delta_millionths, min_beta, max_beta, desc) in test_deltas {
            let beta = estimator.delta_to_beta(delta_millionths);
            println!(
                "Delta={} millionths → beta={} ({})",
                delta_millionths, beta, desc
            );

            assert!(
                beta >= min_beta && beta <= max_beta,
                "{}: beta {} should be in [{}, {}]",
                desc,
                beta,
                min_beta,
                max_beta
            );
        }
    }

    #[test]
    fn test_secret_distribution_penalty_ordering() {
        let estimator = LatticeSecurityEstimator::default();

        // Same parameters, different secret distributions
        let n = 4096;
        let log_q = 90;

        let ternary = estimator.estimate(n, log_q, SecretDistribution::Ternary, 128);
        let binary = estimator.estimate(n, log_q, SecretDistribution::Binary, 128);
        let gaussian = estimator.estimate(n, log_q, SecretDistribution::Gaussian(3200), 128);

        println!(
            "\nSecret distribution penalties (n={}, log_q={}):",
            n, log_q
        );
        println!("  Ternary:  {} bits", ternary.effective_bits);
        println!("  Binary:   {} bits", binary.effective_bits);
        println!("  Gaussian: {} bits", gaussian.effective_bits);

        // Gaussian should have highest security (no MITM penalty)
        assert!(
            gaussian.effective_bits >= ternary.effective_bits,
            "Gaussian should be >= ternary"
        );
        assert!(
            gaussian.effective_bits >= binary.effective_bits,
            "Gaussian should be >= binary"
        );

        // Binary should be slightly worse than ternary
        // (800/1000 vs 850/1000 penalty)
        assert!(
            binary.effective_bits <= ternary.effective_bits,
            "Binary should be <= ternary"
        );
    }

    #[test]
    fn test_dual_estimate_production_configs() {
        use crate::params::secure_configs::SecureConfig;

        let estimator = LatticeSecurityEstimator::default();

        // Test dual estimate on production configs
        // Expected values based on actual measurements
        let configs = [
            ("secure_128", SecureConfig::secure_128(), 128, 115), // CoreSVP: 129, MATZOV: 116
            ("secure_192", SecureConfig::secure_192(), 155, 140), // CoreSVP: 159, MATZOV: 143
            ("secure_256", SecureConfig::secure_256(), 260, 230), // 6 primes, log_q=177
        ];

        for (name, sec_config, core_min, matzov_min) in configs {
            let config = sec_config.into_config();
            let log_q: u32 = config.primes.iter().map(|&p| 64 - p.leading_zeros()).sum();

            let dual =
                estimator.dual_estimate(config.n, log_q, SecretDistribution::Ternary, core_min);

            println!("\n{} dual estimate:", name);
            println!(
                "  CoreSVP: {} bits (min: {})",
                dual.core_svp.effective_bits, core_min
            );
            println!(
                "  MATZOV:  {} bits (min: {})",
                dual.matzov.effective_bits, matzov_min
            );
            println!("  Binding: {} bits", dual.binding_bits);

            // Production configs should meet measured security levels
            assert!(
                dual.core_svp.effective_bits >= core_min,
                "{} should meet {} bits under CoreSVP (got {})",
                name,
                core_min,
                dual.core_svp.effective_bits
            );

            assert!(
                dual.matzov.effective_bits >= matzov_min,
                "{} should provide {} bits under MATZOV (got {})",
                name,
                matzov_min,
                dual.matzov.effective_bits
            );

            // Binding bits should equal MATZOV (more aggressive)
            assert_eq!(
                dual.binding_bits, dual.matzov.effective_bits,
                "Binding bits should equal MATZOV"
            );
        }
    }

    // =========================================================================
    // STRUCTURAL MODULUS SCREEN
    //
    // These tests pin the property the width-only screen could not have: the
    // ability to decline. Every assertion below is about a modulus SHAPE, and
    // the no-regression tests assert against the numbers the existing screen
    // produces today so this extension cannot silently move them.
    // =========================================================================

    /// The three 30-bit NTT primes `secure_128` ships.
    const NTT_CHAIN_90_BIT: [(u64, u32); 3] = [(998244353, 1), (985661441, 1), (754974721, 1)];

    #[test]
    fn factored_screen_refuses_power_of_two_2_pow_90_at_n_8192() {
        let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);
        let screened =
            estimator.estimate_with_factorization(8192, &[(2, 90)], SecretDistribution::Ternary, 128);
        println!("\n2^90 @ n=8192:\n{}", screened.analysis);

        // The requirement: 2^90 must NOT come back as meeting 128 bits.
        assert!(
            !screened.meets_claim(),
            "2^90 must not screen as meeting 128 bits"
        );
        // Stronger: no number at all is emitted.
        assert_eq!(
            screened.effective_bits(),
            None,
            "the screen must decline rather than emit a number for 2^90"
        );
        assert!(!screened.is_screened());
        assert!(
            screened.is_unscreened_regime(),
            "a power-of-two lane is an unscreened regime"
        );
        assert!(screened.findings.iter().any(|f| matches!(
            f,
            LaneFinding::PowerOfTwo {
                exponent: 90,
                bits: 91
            }
        )));
        // 2^90 is a WIDE lane (91 bits), so it is not flagged narrow. The
        // refusal is about regime, not about width.
        assert!(!screened.has_narrow_lane());
        assert_eq!(screened.total_log_q, 91);
        assert_eq!(screened.distinct_lane_count, 1);

        // And the recorded defect, restated as an executable contrast: the
        // width-only entry point does emit a number here, and it passes.
        let width_only = estimator.estimate(8192, 90, SecretDistribution::Ternary, 128);
        assert!(
            width_only.meets_claim,
            "documents MEASUREMENT 6: the width-only screen passes a 90-bit 2-power"
        );
        println!(
            "  width-only screen on the same modulus: {} bits, meets128={}",
            width_only.effective_bits, width_only.meets_claim
        );
    }

    #[test]
    fn factored_screen_reproduces_todays_numbers_for_three_30_bit_primes() {
        // No regression: the three-prime 90-bit chain must screen exactly as it
        // does today. These are the numbers `secure_configs.rs` documents for
        // `secure_128` (Core-SVP 259, MATZOV 233).
        let dual = LatticeSecurityEstimator::new(CostModel::CoreSVP)
            .dual_estimate_with_factorization(
                8192,
                &NTT_CHAIN_90_BIT,
                SecretDistribution::Ternary,
                128,
            );
        println!("\n3 x 30-bit NTT primes @ n=8192:\n{}", dual.core_svp.analysis);

        assert!(dual.core_svp.is_screened());
        assert!(dual.matzov.is_screened());
        assert_eq!(dual.core_svp.total_log_q, 90, "exact product bit length");
        assert_eq!(dual.core_svp.widest_lane_bits, 30);
        assert_eq!(dual.core_svp.distinct_lane_count, 3);

        assert_eq!(
            dual.core_svp.effective_bits(),
            Some(259),
            "Core-SVP must stay at today's 259"
        );
        assert_eq!(
            dual.matzov.effective_bits(),
            Some(233),
            "MATZOV must stay at today's 233"
        );
        assert_eq!(dual.binding_bits, Some(233));
        assert!(dual.meets_both);

        // Byte-for-byte agreement with the width-only entry point.
        for model in [CostModel::CoreSVP, CostModel::MATZOV] {
            let estimator = LatticeSecurityEstimator::new(model);
            let width_only = estimator.estimate(8192, 90, SecretDistribution::Ternary, 128);
            let structural = estimator.estimate_with_factorization(
                8192,
                &NTT_CHAIN_90_BIT,
                SecretDistribution::Ternary,
                128,
            );
            assert_eq!(structural.effective_bits(), Some(width_only.effective_bits));
            assert_eq!(structural.meets_claim(), width_only.meets_claim);
        }

        // All three lanes classified as prime fields, nothing else.
        assert_eq!(
            dual.core_svp
                .findings
                .iter()
                .filter(|f| matches!(f, LaneFinding::PrimeField { .. }))
                .count(),
            3
        );
        assert!(dual.core_svp.shared_factors().is_empty());
    }

    #[test]
    fn factored_screen_reports_prime_power_basis_as_unscreened_regime() {
        let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);

        // Wide prime-power lanes: p^2 for two 30-bit primes. The lanes are not
        // narrow, so the ONLY thing wrong with them is the regime.
        let wide = estimator.estimate_with_factorization(
            8192,
            &[(998244353, 2), (985661441, 2)],
            SecretDistribution::Ternary,
            128,
        );
        println!("\nwide prime-power basis:\n{}", wide.analysis);
        assert_eq!(
            wide.effective_bits(),
            None,
            "a prime-power basis must come back unscreened, not as a number"
        );
        assert!(wide.is_unscreened_regime());
        assert!(
            !wide.has_narrow_lane(),
            "these lanes are 60 bits each; the refusal is regime, not width"
        );
        assert!(!wide.meets_claim());
        assert_eq!(wide.refusal().unwrap().outside_regime.len(), 2);
        assert!(wide.findings.iter().any(|f| matches!(
            f,
            LaneFinding::PrimePower {
                prime: 998244353,
                exponent: 2,
                ..
            }
        )));

        // The literal basis from MEASUREMENT 6: {8, 9, 25, 49}^k = 2^3k 3^2k 5^2k 7^2k.
        for k in [1u32, 2, 5] {
            let basis = [(2, 3 * k), (3, 2 * k), (5, 2 * k), (7, 2 * k)];
            let est = estimator.estimate_with_factorization(
                8192,
                &basis,
                SecretDistribution::Ternary,
                128,
            );
            assert_eq!(
                est.effective_bits(),
                None,
                "k={}: prime-power basis must not produce a number",
                k
            );
            assert!(est.is_unscreened_regime(), "k={}", k);
            assert!(!est.meets_claim(), "k={}", k);
            assert_eq!(
                est.refusal().unwrap().outside_regime.len(),
                4,
                "k={}: all four lanes are outside the regime",
                k
            );
            if k == 1 {
                println!("\n{{8,9,25,49}} basis:\n{}", est.analysis);
                // At k=1 every lane is also narrower than the modelled floor,
                // so BOTH refusal buckets are populated. Nothing is collapsed.
                assert!(est.has_narrow_lane());
                assert_eq!(est.refusal().unwrap().narrow_lane.len(), 4);
                assert_eq!(est.total_log_q, 17); // 8*9*25*49 = 88200
            }
        }
    }

    #[test]
    fn factored_screen_leaves_every_secure_config_unchanged() {
        use crate::params::secure_configs::SecureConfig;

        // Guard against this extension silently moving a production number.
        let configs = [
            ("secure_128", SecureConfig::secure_128(), 128u32),
            ("secure_128_deep", SecureConfig::secure_128_deep(), 128),
            ("secure_192", SecureConfig::secure_192(), 192),
            ("secure_256", SecureConfig::secure_256(), 256),
        ];

        for (name, secure_config, claim) in configs {
            let log_q = secure_config.log_q();
            let config = secure_config.into_config();
            let n = config.n;
            let factors: Vec<(u64, u32)> = config.primes.iter().map(|&p| (p, 1)).collect();

            for model in [CostModel::CoreSVP, CostModel::MATZOV] {
                let estimator = LatticeSecurityEstimator::new(model);
                let width_only = estimator.estimate(n, log_q, SecretDistribution::Ternary, claim);
                let structural = estimator.estimate_with_factorization(
                    n,
                    &factors,
                    SecretDistribution::Ternary,
                    claim,
                );

                assert!(
                    structural.is_screened(),
                    "{} must still screen under {:?}: {}",
                    name,
                    model,
                    structural.analysis
                );
                assert_eq!(
                    structural.total_log_q, log_q,
                    "{}: exact product bit length must agree with the config",
                    name
                );
                assert_eq!(
                    structural.effective_bits(),
                    Some(width_only.effective_bits),
                    "{} under {:?}: structural screen moved a production number",
                    name,
                    model
                );
                assert_eq!(
                    structural.meets_claim(),
                    width_only.meets_claim,
                    "{} under {:?}: meets_claim moved",
                    name,
                    model
                );
                assert_eq!(structural.distinct_lane_count, config.primes.len());
                assert!(structural.shared_factors().is_empty(), "{}", name);
            }

            println!(
                "{:<16} n={:<6} log2(Q)={:<4} lanes={} — unchanged",
                name,
                n,
                log_q,
                config.primes.len()
            );
        }
    }

    #[test]
    fn factored_screen_catches_the_plaintext_modulus_lane_of_a_manufactured_q() {
        // Manufacturing Q = t * D is what makes Delta = Q/t = D exact. It also
        // puts a CRT lane equal to t in the modulus. With the in-tree
        // t = 65537 that lane is 17 bits wide, and the width-only screen
        // cannot see it.
        let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);
        let manufactured = [(65537u64, 1u32), (998244353, 1)];
        let screened = estimator.estimate_with_factorization(
            8192,
            &manufactured,
            SecretDistribution::Ternary,
            128,
        );
        println!("\nmanufactured Q = t * D (t=65537):\n{}", screened.analysis);

        assert_eq!(screened.effective_bits(), None);
        assert!(!screened.meets_claim());
        assert!(screened.has_narrow_lane());
        assert!(screened.findings.iter().any(|f| matches!(
            f,
            LaneFinding::NarrowLane {
                base: 65537,
                exponent: 1,
                bits: 17
            }
        )));
        // 65537 is prime and exponent 1, so the lane is a prime FIELD; the only
        // thing wrong with it is that it is narrower than the modelled floor.
        assert!(!screened.is_unscreened_regime());

        // The width-only screen passes the very same modulus.
        let width_only = estimator.estimate(
            8192,
            screened.total_log_q,
            SecretDistribution::Ternary,
            128,
        );
        assert!(
            width_only.meets_claim,
            "the width-only screen sees only {} bits and passes it",
            screened.total_log_q
        );
    }

    #[test]
    fn factored_screen_reports_non_pairwise_coprime_lanes() {
        let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);

        // Same prime twice: merged to p^2 and reported as a shared factor.
        let repeated = estimator.estimate_with_factorization(
            8192,
            &[(998244353, 1), (998244353, 1)],
            SecretDistribution::Ternary,
            128,
        );
        assert_eq!(repeated.distinct_lane_count, 1, "repeated bases merge");
        assert!(!repeated.shared_factors().is_empty());
        assert!(
            repeated.is_unscreened_regime(),
            "p listed twice is p^2, a prime power"
        );
        assert_eq!(repeated.effective_bits(), None);

        // Two distinct composite lanes sharing the factor 3.
        let shared = estimator.estimate_with_factorization(
            8192,
            &[(3 * 998244353, 1), (3 * 985661441, 1)],
            SecretDistribution::Ternary,
            128,
        );
        println!("\nnon-coprime composite lanes:\n{}", shared.analysis);
        assert!(shared
            .shared_factors()
            .iter()
            .any(|f| matches!(f, LaneFinding::SharedFactor { common: 3, .. })));
        assert!(shared.findings.iter().any(|f| matches!(
            f,
            LaneFinding::CompositeBase {
                smallest_prime_factor: Some(3),
                ..
            }
        )));
        assert_eq!(shared.effective_bits(), None);
    }

    #[test]
    fn factored_screen_refuses_a_malformed_factorization() {
        let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);

        let empty =
            estimator.estimate_with_factorization(8192, &[], SecretDistribution::Ternary, 128);
        assert!(empty.is_malformed());
        assert_eq!(empty.effective_bits(), None);
        assert!(!empty.meets_claim());
        assert!(empty.findings.contains(&LaneFinding::EmptyFactorization));

        let unit_base = estimator.estimate_with_factorization(
            8192,
            &[(1, 5), (998244353, 1)],
            SecretDistribution::Ternary,
            128,
        );
        assert!(unit_base.is_malformed());
        assert_eq!(unit_base.effective_bits(), None);
        assert!(unit_base.findings.contains(&LaneFinding::DegenerateLane {
            base: 1,
            exponent: 5
        }));

        let zero_exponent = estimator.estimate_with_factorization(
            8192,
            &[(998244353, 0)],
            SecretDistribution::Ternary,
            128,
        );
        assert!(zero_exponent.is_malformed());
        assert_eq!(zero_exponent.effective_bits(), None);

        let too_many: Vec<(u64, u32)> = (0..(MAX_SCREENED_LANES + 1))
            .map(|_| (998244353u64, 1u32))
            .collect();
        let overflowing = estimator.estimate_with_factorization(
            8192,
            &too_many,
            SecretDistribution::Ternary,
            128,
        );
        assert!(overflowing.is_malformed());
        assert_eq!(overflowing.effective_bits(), None);
    }

    #[test]
    fn min_modelled_lane_bits_brackets_the_documented_interval() {
        use crate::params::secure_configs::SecureConfig;

        // The threshold is an engineering choice; the bracket is its whole
        // justification, so the bracket is asserted rather than described.
        assert!(
            MIN_MODELLED_LANE_BITS > 17,
            "must be above a t = 65537 lane (17 bits) or the manufactured-Q case escapes"
        );
        // The narrowest shipped lane is 754974721 at 30 bits, and the classify
        // test is the strict `lane_bits < MIN_MODELLED_LANE_BITS`, so 30 is
        // itself still inert. 29 is asserted instead of 30 on purpose: one bit
        // of margin so a future 30-bit lane does not land on the boundary.
        assert!(
            MIN_MODELLED_LANE_BITS <= 29,
            "must stay one bit below the narrowest shipped lane (754974721, 30 bits); \
             the true inert bound is 30, and 29 is the deliberate margin"
        );

        for secure_config in [
            SecureConfig::secure_128(),
            SecureConfig::secure_128_deep(),
            SecureConfig::secure_192(),
            SecureConfig::secure_256(),
        ] {
            for &prime in &secure_config.into_config().primes {
                assert!(
                    bit_length_u64(prime) >= MIN_MODELLED_LANE_BITS,
                    "shipped lane {} is {} bits, below the modelled floor {}",
                    prime,
                    bit_length_u64(prime),
                    MIN_MODELLED_LANE_BITS
                );
            }
        }
    }

    /// The narrow-prime guard inside the `base_is_prime` arm is LIVE, not dead.
    ///
    /// An integration review claimed the `base_bits < MIN_MODELLED_LANE_BITS`
    /// check in the `exponent == 1` path was unreachable. It is not: the
    /// narrow-lane check earlier in the loop records its finding and falls
    /// through *without* `continue`, so a narrow prime lane with exponent 1
    /// arrives here and this guard is the only thing stopping it from also
    /// being recorded as a screenable `PrimeField` and having its width pushed
    /// into `screenable_lane_bits`. Deleting it would let `t = 65537` — the
    /// exact lane the manufactured-Q route makes reachable, and the reason
    /// this screen exists — count as a real lane. This test pins that.
    #[test]
    fn narrow_prime_lane_is_recorded_narrow_and_never_as_a_screenable_field() {
        let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);

        // t = 65537 is prime, exponent 1, and 17 bits — below the floor.
        let narrow = estimator.estimate_with_factorization(
            8192,
            &[(65537, 1)],
            SecretDistribution::Ternary,
            128,
        );

        let narrow_findings = narrow
            .findings
            .iter()
            .filter(|f| matches!(f, LaneFinding::NarrowLane { base: 65537, .. }))
            .count();
        assert_eq!(
            narrow_findings, 1,
            "a 17-bit prime lane must be reported as NarrowLane, findings were {:?}",
            narrow.findings
        );

        let prime_field_findings = narrow
            .findings
            .iter()
            .filter(|f| matches!(f, LaneFinding::PrimeField { .. }))
            .count();
        assert_eq!(
            prime_field_findings, 0,
            "the narrow guard must stop a 17-bit prime from also counting as a \
             screenable PrimeField; if this is 1 the guard was deleted as 'dead code'. \
             findings were {:?}",
            narrow.findings
        );

        assert_eq!(
            narrow.effective_bits(),
            None,
            "a chain whose only lane is narrower than the modelled floor must refuse"
        );

        // Control: the same shape one bit-class up screens normally, which is
        // what makes the assertions above about narrowness and not about
        // single-lane chains being rejected wholesale.
        let wide = estimator.estimate_with_factorization(
            8192,
            &[(998244353, 1)],
            SecretDistribution::Ternary,
            128,
        );
        assert_eq!(
            wide.findings
                .iter()
                .filter(|f| matches!(f, LaneFinding::PrimeField { .. }))
                .count(),
            1,
            "a 30-bit prime lane must screen as a PrimeField, findings were {:?}",
            wide.findings
        );
    }

    #[test]
    fn structural_screen_integer_helpers_are_exact() {
        // Deterministic Miller-Rabin over the whole u64 range.
        assert!(is_prime_u64(2));
        assert!(is_prime_u64(65537));
        assert!(is_prime_u64(998244353));
        assert!(is_prime_u64(985661441));
        assert!(is_prime_u64(754974721));
        assert!(is_prime_u64(18_446_744_073_709_551_557)); // largest u64 prime
        assert!(!is_prime_u64(0));
        assert!(!is_prime_u64(1));
        assert!(!is_prime_u64(4_294_967_295));
        // 3215031751 = 151 * 751 * 28351: strong pseudoprime to bases 2,3,5,7.
        assert!(!is_prime_u64(3_215_031_751));

        assert_eq!(gcd_u64(3 * 998244353, 3 * 985661441), 3);
        assert_eq!(gcd_u64(998244353, 985661441), 1);

        assert_eq!(smallest_prime_factor_below_ceiling(3 * 998244353), Some(3));
        assert_eq!(smallest_prime_factor_below_ceiling(88200), Some(2));
        assert_eq!(
            smallest_prime_factor_below_ceiling(998244353),
            None,
            "a prime has no factor below sqrt(n)"
        );

        assert_eq!(bit_length_u64(0), 0);
        assert_eq!(bit_length_u64(1), 1);
        assert_eq!(bit_length_u64(65537), 17);
        assert_eq!(bit_length_u64(998244353), 30);

        // Exact product bit lengths, integer-only limb arithmetic.
        assert_eq!(product_bit_length(&[(2, 90)]), Some(91));
        assert_eq!(product_bit_length(&[(2, 3), (3, 2), (5, 2), (7, 2)]), Some(17)); // 88200
        assert_eq!(product_bit_length(&NTT_CHAIN_90_BIT), Some(90));
        assert_eq!(product_bit_length(&[(65537, 1), (998244353, 1)]), Some(46));
        // Beyond the limb cap the screen declines rather than truncating.
        assert_eq!(product_bit_length(&[(2, 1_000_000)]), None);
    }

    #[test]
    fn factored_screen_separates_the_four_measurement_6_constructions() {
        // MEASUREMENT 6 showed these four 90-bit constructions receiving
        // byte-identical scores. This is the same table through the screen that
        // can see the modulus.
        let estimator = LatticeSecurityEstimator::new(CostModel::CoreSVP);
        let cases: [(&str, Vec<(u64, u32)>); 4] = [
            ("3 x 30-bit NTT primes", NTT_CHAIN_90_BIT.to_vec()),
            ("2^90", vec![(2, 90)]),
            (
                "prime-power basis {8,9,25,49}^6",
                vec![(2, 18), (3, 12), (5, 12), (7, 12)],
            ),
            (
                "manufactured Q = t * D, t = 65537",
                vec![(65537, 1), (998244353, 1)],
            ),
        ];

        println!(
            "\n{:<36} {:>9} {:>12} {:>10}",
            "construction", "log2(Q)", "screened", "meets128"
        );
        let mut screened_count = 0usize;
        for (label, factors) in &cases {
            let result = estimator.estimate_with_factorization(
                8192,
                factors,
                SecretDistribution::Ternary,
                128,
            );
            let shown = match result.effective_bits() {
                Some(bits) => format!("{} bits", bits),
                None => "REFUSED".to_string(),
            };
            println!(
                "{:<36} {:>9} {:>12} {:>10}",
                label,
                result.total_log_q,
                shown,
                result.meets_claim()
            );
            if result.is_screened() {
                screened_count += 1;
            }
        }

        // Exactly one of the four is inside the regime this model covers.
        assert_eq!(
            screened_count, 1,
            "only the prime chain may receive a number"
        );
    }
}
