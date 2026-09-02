//! Manufactured moduli — construction in place of search.
//!
//! Classical RNS-FHE *hunts* for a modulus: it searches the integers for values
//! that are simultaneously prime, NTT-friendly (`q ≡ 1 mod 2N`), pairwise
//! coprime, and coprime to the plaintext modulus `t`. Every one of those
//! conditions is a precondition of *reconstruction* — of rebuilding a single
//! integer out of residues — and not a precondition of residue arithmetic
//! itself. This module takes the other route: it **manufactures** moduli by
//! construction, so the properties that a search would have had to discover are
//! instead read straight off the way the number was built.
//!
//! Three constructions are implemented here, each with the identity it buys:
//!
//! | Construction | Form | Identity obtained by construction |
//! |---|---|---|
//! | [`StarLane`] | `q = c·t + 1` | `q ≡ 1 (mod t)`, and `t⁻¹ mod q = q − c` |
//! | [`AdjacencyAnchor`] | `A = P + 1` | `P ≡ −1 (mod A)`, so `P⁻¹ mod A = P` |
//! | [`ManufacturedChain`] | `Q = t · ∏Dᵢ` | `Δ = Q/t = ∏Dᵢ` **exactly**, no floor |
//!
//! # Why the exact `Δ` matters
//!
//! Textbook BFV sets `Δ = ⌊Q/t⌋` because `t ∤ Q`: the moduli were hunted for
//! primality, `t` was chosen independently, and the quotient is therefore not
//! an integer. Every rounding-error term in a BFV noise analysis descends from
//! that floor. Manufacturing `Q` as `t · D` does not work *around* the rounding
//! term — it removes the premise that creates it. See
//! [`ManufacturedChain::verify_exact_delta`], which recomputes `Q ÷ t` with a
//! remainder and fails closed unless the remainder is zero.
//!
//! # Sign correction against the source white paper
//!
//! "Arbitrary Moduli in RNS-FHE" publishes the adjacency read as
//! `X mod A = (γ + K) mod A`. That is **false as written**: since `A = P + 1`
//! we have `P ≡ −1 (mod A)`, so `K·P ≡ −K` and the correct read is
//! `(γ − K) mod A`. [`adjacency_read`] implements the corrected form, and
//! `tests::published_adjacency_form_is_wrong_and_stays_wrong` is a standing
//! regression guard that measures the published form failing. The same paper's
//! `(P · A) mod P = 1` is identically `0` by construction; the intended true
//! fact is against modulus `A`, and is [`AdjacencyAnchor::p_inverse_mod_a`].
//!
//! # Freedom cuts both ways
//!
//! Manufacturing removes the search, and with it the accidental hygiene that a
//! primality search provided for free. A constructed modulus can be a power of
//! two, can be divisible by 3, can repeat another lane. [`ChainScreen`] is the
//! deliberate refusal surface for exactly that: it **refuses** structurally
//! broken lanes and **flags** (without refusing) a chain whose lanes are not
//! pairwise coprime, because non-coprime lanes are a legitimate syndrome regime
//! in this architecture rather than an error.
//!
//! Everything in this module is integer-only. No floating point appears in any
//! path, including the bit-length accounting, which uses exact 64-bit limbs and
//! bridges to [`U256`] when a value fits in 256 bits.

use crate::arithmetic::rns::U256;
use crate::errors::{Nine65Error, Nine65Result};
use crate::params::primes::gcd;

/// Default smallest prime factor a lane modulus is allowed to have.
///
/// A prime factor `p` of a lane modulus `q` splits off a CRT component `Z/p`
/// that can hold at most `log2(p)` bits. When `p` is tiny that component cannot
/// separate anything useful, so a BFV deployment should raise the bound toward
/// its plaintext modulus `t` via [`ManufacturedChain::screen_with_bound`]. The
/// default is deliberately modest so that the screen refuses only the
/// unambiguously broken cases by default.
///
/// Note the ceiling: the screen trial-divides, so it refuses any bound above
/// [`MAX_SCREEN_BOUND`] (`2^20`) rather than becoming a factoring engine. For
/// `t > 2^20` the bound therefore **cannot** be raised all the way to `t`;
/// `screen_with_bound(t)` returns a typed `InvalidParameter` instead. Screen at
/// `MAX_SCREEN_BOUND` in that case and treat the result as what it is — a
/// small-factor screen, not a proof that every lane factor exceeds `t`.
pub const DEFAULT_MIN_PRIME_FACTOR: u64 = 256;

/// Largest small-factor bound the screen will trial-divide up to.
///
/// The screen finds a lane's smallest divisor by direct trial division, which
/// is `O(bound)` per lane. This cap keeps a caller from turning the screen into
/// an unbounded factoring attempt; [`ManufacturedChain::screen_with_bound`]
/// returns a typed error rather than running past it.
pub const MAX_SCREEN_BOUND: u64 = 1 << 20;

// ═══════════════════════════════════════════════════════════════════
// Exact magnitudes — little-endian 64-bit limbs, no floats anywhere
// ═══════════════════════════════════════════════════════════════════

/// An exact non-negative integer of unbounded width.
///
/// Stored as normalized little-endian 64-bit limbs (always at least one limb;
/// no leading zero limb except for the value zero). This is the accounting type
/// for manufactured moduli, whose products routinely exceed both `u128` and
/// `U256`. Bit lengths are computed from the limbs by leading-zero counts, so
/// no logarithm and no floating-point value is ever formed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactMagnitude {
    limbs: Vec<u64>,
}

impl ExactMagnitude {
    /// The value `1`.
    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }

    /// Build from a single 64-bit value.
    pub fn from_u64(value: u64) -> Self {
        Self { limbs: vec![value] }
    }

    /// Build the exact product of an ordered factor vector.
    ///
    /// The limb vector grows as needed, so there is no saturation and no
    /// fixed product cap.
    pub fn from_factors(factors: &[u64]) -> Self {
        Self {
            limbs: super::exact_product_limbs(factors),
        }
    }

    /// The normalized little-endian limbs of this value.
    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    /// Exact bit length (`0` for the value zero).
    pub fn bit_length(&self) -> u32 {
        super::limbs_bit_length(&self.limbs)
    }

    /// True when this value is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&limb| limb == 0)
    }

    /// Exact value as `u128`, or `None` when it does not fit.
    ///
    /// `None` is a first-class result, not an error: manufactured moduli are
    /// expected to exceed `u128`.
    pub fn try_to_u128(&self) -> Option<u128> {
        if self.limbs.len() > 2 {
            return None;
        }
        let lo = self.limbs.first().copied().unwrap_or(0) as u128;
        let hi = self.limbs.get(1).copied().unwrap_or(0) as u128;
        Some(lo | (hi << 64))
    }

    /// Exact value as [`U256`], or `None` when it exceeds 256 bits.
    ///
    /// This is the bridge to the crate's existing 256-bit reconstruction type
    /// for values that outgrow `u128` but still fit in `U256`.
    pub fn try_to_u256(&self) -> Option<U256> {
        if self.limbs.len() > 4 {
            return None;
        }
        let word = |index: usize| self.limbs.get(index).copied().unwrap_or(0) as u128;
        Some(U256 {
            lo: word(0) | (word(1) << 64),
            hi: word(2) | (word(3) << 64),
        })
    }

    /// Multiply by a 64-bit value, growing the limb vector as needed.
    pub fn mul_u64(&self, multiplier: u64) -> Self {
        let mut limbs = self.limbs.clone();
        let mut carry = 0u128;
        for limb in &mut limbs {
            let product = (*limb as u128) * multiplier as u128 + carry;
            *limb = product as u64;
            carry = product >> 64;
        }
        if carry != 0 {
            limbs.push(carry as u64);
        }
        let mut out = Self { limbs };
        out.normalize();
        out
    }

    /// Divide by a 64-bit value, returning `(quotient, remainder)` exactly.
    ///
    /// Returns [`Nine65Error::ModulusZero`] for a zero divisor rather than
    /// panicking.
    pub fn div_rem_u64(&self, divisor: u64) -> Nine65Result<(Self, u64)> {
        if divisor == 0 {
            return Err(Nine65Error::ModulusZero);
        }
        let mut quotient = vec![0u64; self.limbs.len()];
        let mut remainder = 0u128;
        for index in (0..self.limbs.len()).rev() {
            let numerator = (remainder << 64) | self.limbs[index] as u128;
            quotient[index] = (numerator / divisor as u128) as u64;
            remainder = numerator % divisor as u128;
        }
        let mut out = Self { limbs: quotient };
        out.normalize();
        Ok((out, remainder as u64))
    }

    fn normalize(&mut self) {
        while self.limbs.len() > 1 && self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
        if self.limbs.is_empty() {
            self.limbs.push(0);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// 1. Star family:  q = c*t + 1
// ═══════════════════════════════════════════════════════════════════

/// A star-family lane modulus `q = c·t + 1`.
///
/// Neither `t` nor `c` needs to be prime, and `q` itself is not required to be
/// prime, NTT-friendly, or coprime to anything. Two facts follow purely from
/// the construction and are therefore available without any search:
///
/// * **Message transparency.** `q mod t = 1` for every `c ≥ 1`, `t ≥ 2`.
/// * **Free inverse.** `t⁻¹ mod q = q − c`, because `t·(q − c) = t·q − c·t
///   = t·q − (q − 1) ≡ 1 (mod q)`.
///
/// [`Self::t_inverse_mod_q`] reads that inverse off the construction and never
/// runs the extended Euclidean algorithm. The test
/// `tests::star_family_free_inverse_matches_extended_euclid` checks the read
/// against an independently computed extended-Euclid inverse over prime and
/// composite `t` and prime and composite `c`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StarLane {
    base: u64,
    multiplier: u64,
    modulus: u64,
}

impl StarLane {
    /// Construct `q = c·t + 1`, failing closed on degenerate input or overflow.
    ///
    /// Rejected: `t < 2` (no plaintext space) and `c = 0` (which would give the
    /// degenerate `q = 1`). A product or increment that leaves `u64` returns
    /// [`Nine65Error::Overflow`] rather than wrapping.
    pub fn new(base: u64, multiplier: u64) -> Nine65Result<Self> {
        if base < 2 {
            return Err(Nine65Error::InvalidParameter {
                message: format!("star-family base t must be at least 2, got {base}"),
            });
        }
        if multiplier == 0 {
            return Err(Nine65Error::InvalidParameter {
                message: "star-family multiplier c must be at least 1; c = 0 gives q = 1"
                    .to_string(),
            });
        }
        let product = multiplier.checked_mul(base).ok_or(Nine65Error::Overflow {
            operation: "star_family_lane: c * t exceeds u64",
        })?;
        let modulus = product.checked_add(1).ok_or(Nine65Error::Overflow {
            operation: "star_family_lane: c * t + 1 exceeds u64",
        })?;
        Ok(Self {
            base,
            multiplier,
            modulus,
        })
    }

    /// The lane modulus `q = c·t + 1`.
    pub fn modulus(&self) -> u64 {
        self.modulus
    }

    /// The base `t` the lane was manufactured against.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// The multiplier `c`.
    pub fn multiplier(&self) -> u64 {
        self.multiplier
    }

    /// `q mod t`, which the construction fixes at `1`.
    pub fn base_residue(&self) -> u64 {
        self.modulus % self.base
    }

    /// `t⁻¹ mod q`, read directly off the construction as `q − c`.
    ///
    /// No extended Euclidean algorithm, no modular exponentiation, no inverse
    /// table. `q > c` always holds here (`q = c·t + 1 ≥ 2c + 1`), so the
    /// subtraction cannot underflow.
    pub fn t_inverse_mod_q(&self) -> u64 {
        self.modulus - self.multiplier
    }
}

/// Construct a star-family lane `q = c·t + 1`.
///
/// Thin free-function form of [`StarLane::new`], matching the naming used in
/// the architecture notes.
/// Mint NTT-friendly star Delta-lanes by construction: `D = (two_n·j)·t + 1`
/// for ascending `j`, keeping those that are prime, in range, and absent
/// from `avoid`.
///
/// Every returned lane satisfies, by construction rather than search:
///   * `D ≡ 1 (mod t)`   — star-family message transparency, and the
///     derived inverse `t⁻¹ mod D = D − c` with `c = two_n·j`;
///   * `D ≡ 1 (mod two_n)` — NTT-friendliness for ring dimension
///     `n = two_n/2`.
///
/// Primality is still SCREENED (not constructed): the NTT is Field-Layer —
/// it needs a primitive `two_n`-th root of unity, which the screening
/// guarantees for a prime `D ≡ 1 (mod two_n)`. The identities above are the
/// manufactured part; the primality test is the residual Field-Layer
/// obligation, applied per candidate with `is_prime`.
pub fn manufactured_ntt_delta_lanes(
    t: u64,
    two_n: u64,
    count: usize,
    min_modulus: u64,
    avoid: &[u64],
) -> Nine65Result<Vec<u64>> {
    if t < 2 || two_n < 2 {
        return Err(Nine65Error::InvalidParameter {
            message: format!("manufactured_ntt_delta_lanes: t={t}, two_n={two_n}"),
        });
    }
    let mut lanes = Vec::with_capacity(count);
    let mut j: u64 = 1;
    while lanes.len() < count {
        let c = two_n.checked_mul(j).ok_or(Nine65Error::Overflow {
            operation: "manufactured_ntt_delta_lanes: c = two_n * j",
        })?;
        let d = c
            .checked_mul(t)
            .and_then(|x| x.checked_add(1))
            .ok_or(Nine65Error::Overflow {
                operation: "manufactured_ntt_delta_lanes: D = c*t + 1",
            })?;
        if d < (1u64 << 62)
            && d >= min_modulus
            && crate::params::primes::is_prime(d)
            && !avoid.contains(&d)
            && !lanes.contains(&d)
        {
            debug_assert_eq!(d % t, 1);
            debug_assert_eq!(d % two_n, 1);
            lanes.push(d);
        }
        j += 1;
        if j > 1_000_000 {
            return Err(Nine65Error::InvalidParameter {
                message: "manufactured_ntt_delta_lanes: lane scan exhausted".into(),
            });
        }
    }
    Ok(lanes)
}

pub fn star_family_lane(t: u64, c: u64) -> Nine65Result<StarLane> {
    StarLane::new(t, c)
}

// ═══════════════════════════════════════════════════════════════════
// 2. Adjacency anchor:  A = P + 1
// ═══════════════════════════════════════════════════════════════════

/// An adjacency anchor `A = P + 1`.
///
/// Because `A = P + 1`, we have `P ≡ −1 (mod A)`, and therefore:
///
/// * **Self-inverse.** `P·P ≡ (−1)(−1) ≡ 1 (mod A)`, so `P⁻¹ mod A = P`. This
///   is why an adjacency-anchored basis needs **no inverse bank**: the inverse
///   of the companion modulus is the companion modulus, so there is nothing to
///   precompute, store, or key-schedule. Checked against extended Euclid in
///   `tests::adjacency_self_inverse_matches_extended_euclid`.
/// * **Winding read.** For `X = γ + K·P`, `X ≡ γ − K (mod A)` — note the
///   **minus**. See [`adjacency_read`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdjacencyAnchor {
    partner: u64,
    anchor: u64,
}

impl AdjacencyAnchor {
    /// Construct `A = P + 1`, failing closed on degenerate `P` or `u64` overflow.
    pub fn new(partner: u64) -> Nine65Result<Self> {
        if partner < 2 {
            return Err(Nine65Error::InvalidParameter {
                message: format!("adjacency partner P must be at least 2, got {partner}"),
            });
        }
        let anchor = partner.checked_add(1).ok_or(Nine65Error::Overflow {
            operation: "adjacency_anchor: P + 1 exceeds u64",
        })?;
        Ok(Self { partner, anchor })
    }

    /// The partner modulus `P`.
    pub fn partner(&self) -> u64 {
        self.partner
    }

    /// The anchor modulus `A = P + 1`.
    pub fn anchor(&self) -> u64 {
        self.anchor
    }

    /// `P⁻¹ mod A`, which by construction is `P` itself.
    ///
    /// This is the corrected form of the white paper's `(P · A) mod P = 1`,
    /// which is identically `0` and is checked as such in
    /// `tests::published_anchor_form_is_identically_zero`.
    pub fn p_inverse_mod_a(&self) -> u64 {
        self.partner
    }

    /// `(γ − K) mod A` for this anchor. See [`adjacency_read`].
    pub fn read(&self, gamma: u64, k: u64) -> u64 {
        subtract_mod(gamma, k, self.anchor)
    }
}

/// Construct the adjacency anchor `A = P + 1`.
pub fn adjacency_anchor(p: u64) -> Nine65Result<AdjacencyAnchor> {
    AdjacencyAnchor::new(p)
}

/// The adjacency read: for `X = γ + K·P` with `A = P + 1`, return `X mod A`.
///
/// The value returned is `(γ − K) mod A`. **The sign is the whole point.** The
/// source white paper publishes `(γ + K) mod A`, which is wrong: `P ≡ −1
/// (mod A)` makes `K·P ≡ −K`, not `+K`. Implementing the published form injects
/// a sign error into the winding read, and
/// `tests::published_adjacency_form_is_wrong_and_stays_wrong` measures it
/// failing so the mistake cannot quietly return.
///
/// The subtraction is performed on reduced unsigned residues with an explicit
/// branch that borrows `A` instead of going negative, so it cannot underflow on
/// unsigned types for any input.
pub fn adjacency_read(gamma: u64, k: u64, a: u64) -> Nine65Result<u64> {
    // `AnchorZero` renders as "anchor zero: A must be > 0", which is only an
    // accurate description of A = 0. A = 1 is a nonzero anchor that is still
    // unusable (every residue collapses to 0), so it gets a variant that can
    // say what is actually wrong instead of one that misreports the input.
    if a == 0 {
        return Err(Nine65Error::AnchorZero);
    }
    if a == 1 {
        return Err(Nine65Error::InvalidParameter {
            message: "adjacency anchor A = 1 is degenerate: A must be at least 2, \
                      since every residue modulo 1 is 0"
                .to_string(),
        });
    }
    Ok(subtract_mod(gamma, k, a))
}

/// `(x − y) mod m` on unsigned values, borrow-corrected so it cannot underflow.
#[inline]
fn subtract_mod(x: u64, y: u64, m: u64) -> u64 {
    debug_assert!(m >= 2);
    let x = x % m;
    let y = y % m;
    if x >= y {
        x - y
    } else {
        m - (y - x)
    }
}

// ═══════════════════════════════════════════════════════════════════
// 3. Manufactured chain:  Q = t * prod(D_i)
// ═══════════════════════════════════════════════════════════════════

/// A request for one star-family lane in a manufactured chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneSpec {
    /// The base `t_i` of this lane's star construction.
    pub base: u64,
    /// The multiplier `c_i` of this lane's star construction.
    pub multiplier: u64,
}

impl LaneSpec {
    /// A lane specification `D = c·t + 1`.
    pub fn new(base: u64, multiplier: u64) -> Self {
        Self { base, multiplier }
    }
}

/// A manufactured modulus chain `Q = t · ∏Dᵢ` with every `Dᵢ` a star lane.
///
/// The defining property is that `t` divides `Q` **by construction**, so the
/// BFV scaling factor is exactly `Δ = Q/t = ∏Dᵢ` with no floor and no rounding
/// term. [`Self::verify_exact_delta`] re-derives that by exact long division
/// and fails closed if the remainder is anything but zero.
///
/// This is the **parameter-construction** half of the manufactured-moduli work.
/// The **execution** half is
/// [`crate::arithmetic::unified_rescale::RescaleChain`], which consumes a lane
/// basis of this shape and computes `round(X·t/Q)` on it without ever
/// materialising `Q`. This type answers "is this chain sound and how wide is
/// it"; that one answers "what does the rescale return". See the table on
/// `RescaleChain` for the full split.
#[derive(Clone, Debug)]
pub struct ManufacturedChain {
    plaintext_modulus: u64,
    lanes: Vec<StarLane>,
    delta: ExactMagnitude,
    modulus: ExactMagnitude,
}

impl ManufacturedChain {
    /// The plaintext modulus `t` the chain was manufactured around.
    pub fn plaintext_modulus(&self) -> u64 {
        self.plaintext_modulus
    }

    /// The chain's lanes, exposed so a security screen can inspect the
    /// factorization of `Q` directly instead of trying to recover it.
    pub fn lanes(&self) -> &[StarLane] {
        &self.lanes
    }

    /// The lane moduli `Dᵢ` in order.
    pub fn lane_moduli(&self) -> Vec<u64> {
        self.lanes.iter().map(StarLane::modulus).collect()
    }

    /// The exact scaling factor `Δ = Q/t = ∏Dᵢ`.
    ///
    /// Exact, not floored: see [`Self::verify_exact_delta`].
    pub fn exact_delta(&self) -> &ExactMagnitude {
        &self.delta
    }

    /// The exact ciphertext modulus `Q = t · ∏Dᵢ`.
    pub fn modulus(&self) -> &ExactMagnitude {
        &self.modulus
    }

    /// Exact bit length of `Q`, computed from 64-bit limbs.
    pub fn modulus_bit_length(&self) -> u32 {
        self.modulus.bit_length()
    }

    /// Exact bit length of `Δ`, computed from 64-bit limbs.
    pub fn delta_bit_length(&self) -> u32 {
        self.delta.bit_length()
    }

    /// Re-derive `Δ` by exact long division and confirm no floor was involved.
    ///
    /// Returns [`Nine65Error::InexactDivision`] if `t ∤ Q` and
    /// [`Nine65Error::InvalidParameter`] if the quotient disagrees with `∏Dᵢ`.
    /// Neither can happen for a chain built by [`manufacture_chain`]; the check
    /// exists so that the "no floor" claim is executed rather than asserted.
    pub fn verify_exact_delta(&self) -> Nine65Result<()> {
        let (quotient, remainder) = self.modulus.div_rem_u64(self.plaintext_modulus)?;
        if remainder != 0 {
            // `InexactDivision` can only carry a `u128`, and a manufactured `Q`
            // routinely exceeds that. Report the typed variant only when the
            // value it names is the true `Q`; otherwise fall back to a variant
            // that can state the situation exactly. An error must never name a
            // saturated stand-in as though it were the real modulus.
            return Err(match self.modulus.try_to_u128() {
                Some(value) => Nine65Error::InexactDivision {
                    value,
                    divisor: self.plaintext_modulus,
                },
                None => Nine65Error::InvalidParameter {
                    message: format!(
                        "manufactured chain: t = {} does not divide Q (remainder {}); \
                         Q is {} bits and too wide to report as a u128",
                        self.plaintext_modulus,
                        remainder,
                        self.modulus.bit_length()
                    ),
                },
            });
        }
        if quotient != self.delta {
            return Err(Nine65Error::InvalidParameter {
                message: "manufactured chain: Q/t disagrees with the lane product".to_string(),
            });
        }
        Ok(())
    }

    /// Screen the chain with [`DEFAULT_MIN_PRIME_FACTOR`].
    pub fn screen(&self) -> Nine65Result<ChainScreen> {
        self.screen_with_bound(DEFAULT_MIN_PRIME_FACTOR)
    }

    /// Screen the chain, refusing any lane with a prime factor below `bound`.
    ///
    /// Refusals (structurally broken lanes) and syndrome flags (lanes that are
    /// not pairwise coprime) are reported together in [`ChainScreen`]; this
    /// method itself only errors when the *bound* is unusable.
    pub fn screen_with_bound(&self, bound: u64) -> Nine65Result<ChainScreen> {
        if bound < 2 {
            return Err(Nine65Error::InvalidParameter {
                message: format!("screen bound must be at least 2, got {bound}"),
            });
        }
        if bound > MAX_SCREEN_BOUND {
            return Err(Nine65Error::InvalidParameter {
                message: format!(
                    "screen bound {bound} exceeds MAX_SCREEN_BOUND {MAX_SCREEN_BOUND}; \
                     the screen trial-divides and is not a factoring engine"
                ),
            });
        }

        let mut defects = Vec::new();
        let mut syndromes = Vec::new();

        for (index, lane) in self.lanes.iter().enumerate() {
            let modulus = lane.modulus();
            if modulus < 3 {
                defects.push(LaneDefect::DegenerateLane { index, modulus });
                continue;
            }
            if modulus.is_power_of_two() {
                defects.push(LaneDefect::PowerOfTwo { index, modulus });
            }
            if let Some(factor) = smallest_factor_below(modulus, bound) {
                defects.push(LaneDefect::SmallPrimeFactor {
                    index,
                    modulus,
                    factor,
                    bound,
                });
            }
        }

        for left in 0..self.lanes.len() {
            for right in (left + 1)..self.lanes.len() {
                let a = self.lanes[left].modulus();
                let b = self.lanes[right].modulus();
                let shared = gcd(a, b);
                if shared > 1 {
                    syndromes.push(SyndromeFlag {
                        left,
                        right,
                        left_modulus: a,
                        right_modulus: b,
                        shared_factor: shared,
                    });
                }
            }
        }

        Ok(ChainScreen {
            defects,
            syndromes,
            bound,
        })
    }

    /// Screen and refuse: `Ok` only when no lane defect was found.
    ///
    /// Syndrome flags do **not** cause a refusal — a chain with non-pairwise-
    /// coprime lanes is returned as `Ok` with its flags attached.
    pub fn screen_strict(&self, bound: u64) -> Nine65Result<ChainScreen> {
        let screen = self.screen_with_bound(bound)?;
        if screen.is_refused() {
            return Err(Nine65Error::InvalidParameter {
                message: format!(
                    "manufactured chain refused by screen: {}",
                    screen.refusal_summary()
                ),
            });
        }
        Ok(screen)
    }
}

/// Manufacture a chain `Q = t · ∏Dᵢ` from star-family lane specifications.
///
/// Each `Dᵢ` is built by [`StarLane::new`], so every lane carries its own free
/// `t⁻¹` read and its own message transparency. The chain's `Δ = Q/t` is exact.
///
/// Errors: `t < 2`, an empty lane list, or any lane that fails to construct.
pub fn manufacture_chain(t: u64, lane_specs: &[LaneSpec]) -> Nine65Result<ManufacturedChain> {
    if t < 2 {
        return Err(Nine65Error::InvalidParameter {
            message: format!("plaintext modulus t must be at least 2, got {t}"),
        });
    }
    if lane_specs.is_empty() {
        return Err(Nine65Error::InvalidParameter {
            message: "manufactured chain needs at least one lane".to_string(),
        });
    }

    let mut lanes = Vec::with_capacity(lane_specs.len());
    for spec in lane_specs {
        lanes.push(StarLane::new(spec.base, spec.multiplier)?);
    }

    let lane_moduli: Vec<u64> = lanes.iter().map(StarLane::modulus).collect();
    let delta = ExactMagnitude::from_factors(&lane_moduli);
    let modulus = delta.mul_u64(t);

    Ok(ManufacturedChain {
        plaintext_modulus: t,
        lanes,
        delta,
        modulus,
    })
}

/// Smallest divisor of `value` strictly below `bound`, or `None`.
///
/// The smallest divisor greater than one is necessarily prime, so this is a
/// smallest-prime-factor search without needing a prime table.
fn smallest_factor_below(value: u64, bound: u64) -> Option<u64> {
    let mut candidate = 2u64;
    while candidate < bound {
        if candidate > value / candidate && candidate < value {
            // Past sqrt(value) and value is not itself below the bound yet.
            break;
        }
        if value % candidate == 0 {
            return Some(candidate);
        }
        candidate += 1;
    }
    if value < bound {
        // The lane modulus is itself below the bound: its smallest prime
        // factor is at most itself, so it fails the bound either way.
        return Some(value);
    }
    None
}

// ═══════════════════════════════════════════════════════════════════
// 4. The refusal surface
// ═══════════════════════════════════════════════════════════════════

/// A structural defect in a manufactured lane. Any defect refuses the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneDefect {
    /// The lane modulus is a power of two.
    ///
    /// The star family can produce one — `t = 3, c = 5` gives `q = 16` — and it
    /// is the worst modulus a chain can carry: no odd factor at all, so it
    /// shares the factor `2` with every other even lane and contributes nothing
    /// a residue basis can separate on. `tests::screen_refuses_a_power_of_two_lane`
    /// constructs exactly that lane and checks it is refused.
    PowerOfTwo { index: usize, modulus: u64 },
    /// The lane modulus has a prime factor below the screen bound.
    SmallPrimeFactor {
        index: usize,
        modulus: u64,
        factor: u64,
        bound: u64,
    },
    /// The lane modulus is smaller than 3 and carries no usable residue space.
    DegenerateLane { index: usize, modulus: u64 },
}

/// Two lanes of the chain that share a factor.
///
/// This is a **flag, not a refusal.** Reconstruction-based RNS requires
/// pairwise coprimality because the CRT isomorphism needs it; residue-native
/// execution does not reconstruct, and a shared factor between lanes is a
/// legitimate *syndrome regime* — the shared component becomes a redundancy
/// channel rather than an error. The screen reports it loudly and lets the
/// caller decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyndromeFlag {
    /// Index of the first lane.
    pub left: usize,
    /// Index of the second lane.
    pub right: usize,
    /// Modulus of the first lane.
    pub left_modulus: u64,
    /// Modulus of the second lane.
    pub right_modulus: u64,
    /// The shared factor, `gcd(left_modulus, right_modulus) > 1`.
    pub shared_factor: u64,
}

/// Overall verdict of a chain screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScreenVerdict {
    /// No defects and no shared factors.
    Clean,
    /// No defects, but at least one pair of lanes shares a factor.
    FlaggedSyndrome,
    /// At least one structural lane defect: the chain is refused.
    Refused,
}

/// The result of screening a manufactured chain.
#[derive(Clone, Debug)]
pub struct ChainScreen {
    defects: Vec<LaneDefect>,
    syndromes: Vec<SyndromeFlag>,
    bound: u64,
}

impl ChainScreen {
    /// Structural defects found. Non-empty means the chain is refused.
    pub fn defects(&self) -> &[LaneDefect] {
        &self.defects
    }

    /// Lane pairs sharing a factor. Flagged, never a refusal on its own.
    pub fn syndromes(&self) -> &[SyndromeFlag] {
        &self.syndromes
    }

    /// The small-prime-factor bound this screen ran with.
    pub fn bound(&self) -> u64 {
        self.bound
    }

    /// True when a structural defect was found.
    pub fn is_refused(&self) -> bool {
        !self.defects.is_empty()
    }

    /// The overall verdict.
    pub fn verdict(&self) -> ScreenVerdict {
        if self.is_refused() {
            ScreenVerdict::Refused
        } else if self.syndromes.is_empty() {
            ScreenVerdict::Clean
        } else {
            ScreenVerdict::FlaggedSyndrome
        }
    }

    /// A one-line summary of the refusal reasons (empty string when not refused).
    pub fn refusal_summary(&self) -> String {
        self.defects
            .iter()
            .map(|defect| match defect {
                LaneDefect::PowerOfTwo { index, modulus } => {
                    format!("lane {index} modulus {modulus} is a power of two")
                }
                LaneDefect::SmallPrimeFactor {
                    index,
                    modulus,
                    factor,
                    bound,
                } => format!(
                    "lane {index} modulus {modulus} has prime factor {factor} below bound {bound}"
                ),
                LaneDefect::DegenerateLane { index, modulus } => {
                    format!("lane {index} modulus {modulus} is degenerate (< 3)")
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// A loud, human-readable report of everything the screen found.
    pub fn report_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "chain screen: verdict={:?}, small-factor bound={}",
            self.verdict(),
            self.bound
        ));
        if self.defects.is_empty() {
            lines.push("  REFUSALS: none".to_string());
        } else {
            for defect in &self.defects {
                lines.push(format!("  REFUSE: {defect:?}"));
            }
        }
        if self.syndromes.is_empty() {
            lines.push("  SYNDROME FLAGS: none (lanes are pairwise coprime)".to_string());
        } else {
            for flag in &self.syndromes {
                lines.push(format!(
                    "  FLAG (not a refusal): lanes {} and {} share factor {} \
                     — permitted syndrome regime, verify this is intended",
                    flag.left, flag.right, flag.shared_factor
                ));
            }
        }
        lines
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests — every doc claim above is executed here
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::primes::extended_gcd;

    /// Independent inverse via extended Euclid — deliberately NOT the
    /// construction read, so the construction read is being checked against
    /// something that does not know how the modulus was built.
    fn egcd_inverse(a: u64, m: u64) -> Option<u64> {
        if m < 2 {
            return None;
        }
        let (g, x, _) = extended_gcd(a as i128 % m as i128, m as i128);
        if g != 1 {
            return None;
        }
        Some(((x % m as i128 + m as i128) % m as i128) as u64)
    }

    // Prime AND composite bases; prime AND composite multipliers.
    const BASES: [u64; 8] = [2, 3, 12, 100, 1024, 65537, 65536, 999_983];
    const MULTIPLIERS: [u64; 9] = [1, 2, 3, 7, 100, 1001, 99_991, 1_048_576, 12_345_678];

    // ---------------------------------------------------------------
    // 1. Star family
    // ---------------------------------------------------------------

    #[test]
    fn star_family_free_inverse_matches_extended_euclid() {
        let mut checked = 0usize;
        let mut composite_base = 0usize;
        let mut composite_multiplier = 0usize;

        for &t in &BASES {
            for &c in &MULTIPLIERS {
                let lane = star_family_lane(t, c).expect("lane must construct");
                let q = lane.modulus();

                // Message transparency, by construction.
                assert_eq!(lane.base_residue(), 1, "q={q} t={t}: q mod t must be 1");

                // The load-bearing check: construction read vs independent egcd.
                let independent = egcd_inverse(t, q)
                    .unwrap_or_else(|| panic!("t={t} must be invertible mod q={q}"));
                assert_eq!(
                    lane.t_inverse_mod_q(),
                    independent,
                    "q={q} t={t} c={c}: q-c must equal t^-1 mod q"
                );

                // And it really is an inverse.
                let product = (t as u128 * lane.t_inverse_mod_q() as u128) % q as u128;
                assert_eq!(product, 1, "q={q} t={t}: t * (q-c) must be 1 mod q");

                if !crate::params::primes::is_prime(t) {
                    composite_base += 1;
                }
                if !crate::params::primes::is_prime(c) && c > 1 {
                    composite_multiplier += 1;
                }
                checked += 1;
            }
        }

        assert_eq!(checked, BASES.len() * MULTIPLIERS.len());
        assert!(composite_base > 0, "must cover composite t");
        assert!(composite_multiplier > 0, "must cover composite c");
        println!(
            "star family: {checked} (t,c) pairs verified against extended Euclid \
             ({composite_base} with composite t, {composite_multiplier} with composite c)"
        );
    }

    #[test]
    fn star_family_rejects_degenerate_input() {
        assert!(star_family_lane(1, 5).is_err(), "t < 2 must be rejected");
        assert!(star_family_lane(0, 5).is_err(), "t = 0 must be rejected");
        assert!(
            star_family_lane(65537, 0).is_err(),
            "c = 0 must be rejected"
        );
        assert!(star_family_lane(2, 1).is_ok(), "smallest legal lane");
    }

    #[test]
    fn star_family_rejects_overflow_without_panicking() {
        let err = star_family_lane(u64::MAX, 2).expect_err("c*t must overflow");
        assert!(matches!(err, Nine65Error::Overflow { .. }), "got {err:?}");

        // c*t fits exactly at u64::MAX, but the +1 does not.
        let err = star_family_lane(u64::MAX, 1).expect_err("c*t+1 must overflow");
        assert!(matches!(err, Nine65Error::Overflow { .. }), "got {err:?}");

        // One below: c*t = u64::MAX - 1, so q = u64::MAX is representable.
        let lane = star_family_lane((u64::MAX - 1) / 2, 2).expect("must fit");
        assert_eq!(lane.modulus(), u64::MAX);
        assert_eq!(lane.t_inverse_mod_q(), u64::MAX - 2);
    }

    // ---------------------------------------------------------------
    // 2. Adjacency
    // ---------------------------------------------------------------

    #[test]
    fn adjacency_self_inverse_matches_extended_euclid() {
        let partners: [u64; 8] = [2, 7, 100, 1001, 65536, 998_244_353, (1 << 31) - 1, 1 << 40];
        for &p in &partners {
            let anchor = adjacency_anchor(p).expect("anchor must construct");
            let a = anchor.anchor();
            assert_eq!(a, p + 1);

            let independent =
                egcd_inverse(p, a).unwrap_or_else(|| panic!("P={p} must be invertible mod A={a}"));
            assert_eq!(
                anchor.p_inverse_mod_a(),
                independent,
                "P={p} A={a}: P must be its own inverse mod A"
            );
            assert_eq!(
                (p as u128 * p as u128) % a as u128,
                1,
                "P={p} A={a}: P*P must be 1 mod A"
            );
        }
    }

    #[test]
    fn adjacency_read_matches_exact_projection() {
        let partners: [u64; 5] = [7, 100, 1001, 998_244_353, (1 << 31) - 1];
        let gammas: [u64; 6] = [0, 1, 5, 999, 1_000_003, u32::MAX as u64];
        let ks: [u64; 6] = [0, 1, 2, 37, 1000, 1_234_567];

        let mut checked = 0usize;
        for &p in &partners {
            let anchor = adjacency_anchor(p).expect("anchor");
            let a = anchor.anchor();
            for &gamma in &gammas {
                for &k in &ks {
                    let x = gamma as u128 + (k as u128) * (p as u128);
                    let truth = (x % a as u128) as u64;
                    assert_eq!(
                        anchor.read(gamma, k),
                        truth,
                        "P={p} gamma={gamma} K={k}: adjacency read must equal X mod A"
                    );
                    assert_eq!(adjacency_read(gamma, k, a).expect("valid anchor"), truth);
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, partners.len() * gammas.len() * ks.len());
        println!("adjacency: {checked} (P, gamma, K) triples matched X mod A exactly");
    }

    #[test]
    fn adjacency_read_cannot_underflow_when_k_exceeds_gamma() {
        // gamma = 0, K large: the naive unsigned (gamma - K) would underflow.
        let anchor = adjacency_anchor(1000).expect("anchor");
        let a = anchor.anchor();
        for k in [1u64, 2, 999, 1000, 1001, u64::MAX] {
            let value = anchor.read(0, k);
            assert!(value < a, "read must stay reduced, got {value} for K={k}");
            let expected = ((0u128 + (k as u128) * 1000u128) % a as u128) as u64;
            assert_eq!(value, expected, "K={k}");
        }
    }

    #[test]
    fn published_adjacency_form_is_wrong_and_stays_wrong() {
        // The white paper publishes X mod A = (gamma + K) mod A. Measure it.
        let mut as_written_ok = 0usize;
        let mut corrected_ok = 0usize;
        let mut total = 0usize;

        for &p in &[7u64, 100, 1001, 998_244_353, (1 << 31) - 1] {
            let a = p + 1;
            for &gamma in &[0u64, 1, 5, p - 1] {
                for &k in &[0u64, 1, 2, 37, 1000] {
                    let x = gamma as u128 + (k as u128) * (p as u128);
                    let truth = (x % a as u128) as u64;
                    total += 1;
                    if ((gamma as u128 + k as u128) % a as u128) as u64 == truth {
                        as_written_ok += 1;
                    }
                    if adjacency_read(gamma, k, a).expect("anchor") == truth {
                        corrected_ok += 1;
                    }
                }
            }
        }

        assert_eq!(
            corrected_ok, total,
            "corrected (gamma - K) must always hold"
        );
        assert!(
            as_written_ok < total,
            "published (gamma + K) form must NOT hold in general; if this ever \
             passes, the sign correction has been silently reverted"
        );
        println!(
            "adjacency sign guard: published (gamma+K) held {as_written_ok}/{total}, \
             corrected (gamma-K) held {corrected_ok}/{total}"
        );
    }

    #[test]
    fn published_anchor_form_is_identically_zero() {
        // The paper states (P * A) % P == 1. It is identically 0.
        for &p in &[7u64, 100, 1001, 998_244_353, (1 << 31) - 1] {
            let a = p + 1;
            let published = ((p as u128 * a as u128) % p as u128) as u64;
            assert_eq!(published, 0, "P={p}: (P*A) mod P is 0 by construction");
            let anchor = adjacency_anchor(p).expect("anchor");
            assert_eq!(anchor.p_inverse_mod_a(), p, "the true fact is mod A, not P");
        }
    }

    #[test]
    fn adjacency_rejects_degenerate_and_overflow() {
        assert!(adjacency_anchor(1).is_err(), "P < 2 must be rejected");
        let err = adjacency_anchor(u64::MAX).expect_err("P+1 must overflow");
        assert!(matches!(err, Nine65Error::Overflow { .. }), "got {err:?}");
        // Both degenerate anchors are refused, and each is refused with a
        // variant whose message is true of the input it was given. A = 0 is
        // genuinely a zero anchor; A = 1 is not, so it must not be reported as
        // one.
        let err_one = adjacency_read(0, 0, 1).expect_err("A = 1 must be rejected");
        assert!(
            matches!(err_one, Nine65Error::InvalidParameter { .. }),
            "A = 1 is a nonzero anchor and must not be reported as AnchorZero, got {err_one:?}"
        );
        let err_zero = adjacency_read(0, 0, 0).expect_err("A = 0 must be rejected");
        assert!(
            matches!(err_zero, Nine65Error::AnchorZero),
            "A = 0 is the anchor-zero case, got {err_zero:?}"
        );

        // The smallest usable anchor still works, so the guard rejects exactly
        // the degenerate inputs and nothing beyond them.
        assert_eq!(adjacency_read(1, 0, 2).expect("A = 2 is usable"), 1);
    }

    // ---------------------------------------------------------------
    // 3. Manufactured chain and exact delta
    // ---------------------------------------------------------------

    fn sample_chain() -> ManufacturedChain {
        // Lanes manufactured against t = 65537, all far above the screen bound.
        manufacture_chain(
            65537,
            &[
                LaneSpec::new(65537, 15_000), // D = 983_055_001
                LaneSpec::new(65537, 15_020), // D = 984_365_741
                LaneSpec::new(65537, 15_026), // D = 984_758_963
            ],
        )
        .expect("chain must manufacture")
    }

    #[test]
    fn manufactured_delta_is_exact_with_no_floor() {
        let chain = sample_chain();
        chain.verify_exact_delta().expect("Q/t must be exact");

        let t = chain.plaintext_modulus();
        let (quotient, remainder) = chain
            .modulus()
            .div_rem_u64(t)
            .expect("nonzero plaintext modulus");
        assert_eq!(remainder, 0, "Q mod t must be exactly 0");

        let lane_product = ExactMagnitude::from_factors(&chain.lane_moduli());
        assert_eq!(quotient, lane_product, "Q/t must equal prod(D_i)");
        assert_eq!(chain.exact_delta(), &lane_product);

        // Independent u128 cross-check (this chain fits).
        let q = chain.modulus().try_to_u128().expect("Q fits in u128");
        let d = chain.exact_delta().try_to_u128().expect("delta fits");
        assert_eq!(q % t as u128, 0);
        assert_eq!(q / t as u128, d);
        let direct: u128 = chain
            .lane_moduli()
            .iter()
            .map(|&m| m as u128)
            .product::<u128>();
        assert_eq!(d, direct, "delta must be the plain lane product");
        println!(
            "exact delta: Q={} bits, delta={} bits, remainder=0",
            chain.modulus_bit_length(),
            chain.delta_bit_length()
        );
    }

    #[test]
    fn manufactured_delta_exact_for_composite_plaintext_modulus() {
        // t need not be prime: manufacturing does not care.
        for &t in &[12u64, 100, 1024, 65536] {
            let chain =
                manufacture_chain(t, &[LaneSpec::new(t, 1_000_003), LaneSpec::new(7, 999_983)])
                    .expect("chain");
            chain.verify_exact_delta().expect("Q/t must be exact");
            let (_, remainder) = chain.modulus().div_rem_u64(t).expect("nonzero");
            assert_eq!(remainder, 0, "t={t}: Q mod t must be 0");
        }
    }

    #[test]
    fn chain_bit_length_is_exact_beyond_u128_and_u256() {
        // Six ~62-bit lanes: the product exceeds u128 and then U256.
        let specs: Vec<LaneSpec> = (0..6)
            .map(|i| LaneSpec::new(1 << 31, (1u64 << 31) - 1 - i))
            .collect();
        let chain = manufacture_chain(65537, &specs).expect("chain");
        chain.verify_exact_delta().expect("exact");

        let delta_bits = chain.delta_bit_length();
        let modulus_bits = chain.modulus_bit_length();
        assert!(
            delta_bits > 256,
            "delta should exceed 256 bits, got {delta_bits}"
        );
        assert!(chain.exact_delta().try_to_u128().is_none());
        assert!(chain.exact_delta().try_to_u256().is_none());

        // Q = t * delta, so bit(Q) is bit(delta) + bit(t) - 1 or + bit(t).
        let t_bits = 64 - 65537u64.leading_zeros();
        assert!(
            modulus_bits == delta_bits + t_bits || modulus_bits == delta_bits + t_bits - 1,
            "Q bits {modulus_bits} inconsistent with delta bits {delta_bits} and t bits {t_bits}"
        );

        // Exact limb-level sanity: divide back down and compare.
        let (quotient, remainder) = chain.modulus().div_rem_u64(65537).expect("nonzero");
        assert_eq!(remainder, 0);
        assert_eq!(&quotient, chain.exact_delta());
        println!("wide chain: delta={delta_bits} bits, Q={modulus_bits} bits (exceeds U256)");
    }

    #[test]
    fn exact_magnitude_bridges_to_u256_and_agrees_with_it() {
        // Three ~62-bit lanes: fits in U256, exceeds u128.
        let moduli: Vec<u64> = vec![
            star_family_lane(1 << 31, (1 << 31) - 1)
                .expect("lane")
                .modulus(),
            star_family_lane(1 << 31, (1 << 31) - 3)
                .expect("lane")
                .modulus(),
            star_family_lane(1 << 31, (1 << 31) - 5)
                .expect("lane")
                .modulus(),
        ];
        let magnitude = ExactMagnitude::from_factors(&moduli);
        assert!(magnitude.try_to_u128().is_none(), "should exceed u128");

        let bridged = magnitude.try_to_u256().expect("should fit in U256");
        let native = U256::product_u64s(&moduli);
        assert_eq!(bridged, native, "limb bridge must agree with U256 product");

        // And small values round-trip through both.
        let small = ExactMagnitude::from_factors(&[3, 5, 7]);
        assert_eq!(small.try_to_u128(), Some(105));
        assert_eq!(small.try_to_u256(), Some(U256::from_u64(105)));
        assert_eq!(small.bit_length(), 7);
    }

    #[test]
    fn exact_magnitude_div_rem_fails_closed_on_zero_divisor() {
        let magnitude = ExactMagnitude::from_factors(&[7, 11]);
        assert!(matches!(
            magnitude.div_rem_u64(0),
            Err(Nine65Error::ModulusZero)
        ));
        let (quotient, remainder) = magnitude.div_rem_u64(7).expect("nonzero");
        assert_eq!(quotient, ExactMagnitude::from_u64(11));
        assert_eq!(remainder, 0);
        let (quotient, remainder) = magnitude.div_rem_u64(10).expect("nonzero");
        assert_eq!(quotient, ExactMagnitude::from_u64(7));
        assert_eq!(remainder, 7);
        assert!(!ExactMagnitude::one().is_zero());
        assert_eq!(ExactMagnitude::one().bit_length(), 1);
    }

    #[test]
    fn manufacture_chain_rejects_degenerate_requests() {
        assert!(
            manufacture_chain(1, &[LaneSpec::new(7, 3)]).is_err(),
            "t < 2"
        );
        assert!(manufacture_chain(65537, &[]).is_err(), "empty lane list");
        let err = manufacture_chain(65537, &[LaneSpec::new(u64::MAX, 3)])
            .expect_err("lane must overflow");
        assert!(matches!(err, Nine65Error::Overflow { .. }), "got {err:?}");
    }

    // ---------------------------------------------------------------
    // 4. The refusal surface
    // ---------------------------------------------------------------

    #[test]
    fn screen_accepts_a_clean_chain() {
        let chain = sample_chain();
        let screen = chain.screen().expect("screen runs");
        assert_eq!(
            screen.verdict(),
            ScreenVerdict::Clean,
            "unexpected: {:?}",
            screen.report_lines()
        );
        assert!(!screen.is_refused());
        assert!(screen.syndromes().is_empty());
        assert!(chain.screen_strict(DEFAULT_MIN_PRIME_FACTOR).is_ok());
        for line in screen.report_lines() {
            println!("{line}");
        }
    }

    #[test]
    fn screen_refuses_a_power_of_two_lane() {
        // t = 3, c = 5 gives q = 16 — a legal star lane and a terrible modulus.
        let lane = star_family_lane(3, 5).expect("lane");
        assert_eq!(lane.modulus(), 16);

        let chain = manufacture_chain(65537, &[LaneSpec::new(3, 5)]).expect("chain");
        let screen = chain.screen().expect("screen runs");
        assert_eq!(screen.verdict(), ScreenVerdict::Refused);
        assert!(
            screen.defects().iter().any(|d| matches!(
                d,
                LaneDefect::PowerOfTwo {
                    modulus: 16,
                    index: 0
                }
            )),
            "expected a PowerOfTwo defect, got {:?}",
            screen.defects()
        );
        let err = chain
            .screen_strict(DEFAULT_MIN_PRIME_FACTOR)
            .expect_err("strict screen must refuse");
        assert!(matches!(err, Nine65Error::InvalidParameter { .. }));
        println!("{}", screen.refusal_summary());
    }

    #[test]
    fn screen_refuses_a_lane_with_a_small_prime_factor() {
        // 65537 * 3 + 1 = 196612 = 2^2 * 13 * 3781 -> smallest factor 2.
        let chain = manufacture_chain(65537, &[LaneSpec::new(65537, 3)]).expect("chain");
        let screen = chain.screen().expect("screen runs");
        assert_eq!(screen.verdict(), ScreenVerdict::Refused);
        let small = screen
            .defects()
            .iter()
            .find_map(|d| match d {
                LaneDefect::SmallPrimeFactor { factor, .. } => Some(*factor),
                _ => None,
            })
            .expect("expected a SmallPrimeFactor defect");
        assert_eq!(small, 2);
        assert_eq!(196_612u64 % small, 0);

        // A lane with smallest prime factor 3: 5*3+1 = 16 is p2, use 2*6+1=13.
        // 13 is prime but below the default bound, so it is still refused.
        let tiny = manufacture_chain(65537, &[LaneSpec::new(2, 6)]).expect("chain");
        let screen = tiny.screen().expect("screen runs");
        assert!(screen.is_refused(), "a 13-bit-tiny lane must be refused");
    }

    #[test]
    fn screen_flags_non_pairwise_coprime_lanes_without_refusing() {
        // Two identical lanes: gcd is the lane modulus itself.
        let spec = LaneSpec::new(65537, 15_000);
        let chain = manufacture_chain(65537, &[spec, spec]).expect("chain");
        let screen = chain.screen().expect("screen runs");

        assert_eq!(
            screen.verdict(),
            ScreenVerdict::FlaggedSyndrome,
            "non-coprime lanes must be FLAGGED, not refused: {:?}",
            screen.report_lines()
        );
        assert!(!screen.is_refused(), "shared factors must not refuse");
        assert_eq!(screen.syndromes().len(), 1);
        let flag = screen.syndromes()[0];
        assert_eq!(flag.left, 0);
        assert_eq!(flag.right, 1);
        assert_eq!(flag.shared_factor, flag.left_modulus);

        // Strict screening still accepts it — refusal is for defects only.
        chain
            .screen_strict(DEFAULT_MIN_PRIME_FACTOR)
            .expect("syndrome regime is permitted");

        let report = screen.report_lines().join("\n");
        assert!(report.contains("FLAG (not a refusal)"), "{report}");
        println!("{report}");
    }

    #[test]
    fn screen_bound_is_validated_not_assumed() {
        let chain = sample_chain();
        assert!(chain.screen_with_bound(1).is_err(), "bound < 2 rejected");
        assert!(
            chain.screen_with_bound(MAX_SCREEN_BOUND + 1).is_err(),
            "bound above MAX_SCREEN_BOUND rejected"
        );
        assert!(chain.screen_with_bound(MAX_SCREEN_BOUND).is_ok());
        assert_eq!(
            chain.screen().expect("screen").bound(),
            DEFAULT_MIN_PRIME_FACTOR
        );
    }

    #[test]
    fn raising_the_bound_only_adds_refusals_and_they_are_real() {
        // The sample chain is clean at the default bound of 256.
        let chain = sample_chain();
        let default_screen = chain.screen().expect("screen runs");
        assert_eq!(default_screen.verdict(), ScreenVerdict::Clean);

        // A BFV caller should raise the bound to at least t. Two of the three
        // sample lanes have their smallest prime factor between 256 and 65537
        // (1831 and 4877), so the wider bound refuses what the default passed.
        let wide = chain.screen_with_bound(65537).expect("screen runs");
        assert!(
            wide.defects().len() >= default_screen.defects().len(),
            "raising the bound must never remove a refusal"
        );
        assert!(
            wide.is_refused(),
            "expected the wider bound to refuse: {:?}",
            wide.report_lines()
        );

        let moduli = chain.lane_moduli();
        let mut found = 0usize;
        for defect in wide.defects() {
            if let LaneDefect::SmallPrimeFactor {
                index,
                modulus,
                factor,
                bound,
            } = defect
            {
                assert_eq!(*bound, 65537);
                assert_eq!(*modulus, moduli[*index], "defect must name its lane");
                assert_eq!(modulus % factor, 0, "reported factor must actually divide");
                assert!(
                    *factor >= DEFAULT_MIN_PRIME_FACTOR,
                    "the default bound would already have caught factor {factor}"
                );
                found += 1;
            }
        }
        assert!(
            found >= 2,
            "expected at least two lanes refused at bound 65537"
        );
        for line in wide.report_lines() {
            println!("{line}");
        }
    }

    #[test]
    fn smallest_factor_search_is_correct() {
        assert_eq!(smallest_factor_below(16, 256), Some(2));
        assert_eq!(smallest_factor_below(9, 256), Some(3));
        assert_eq!(smallest_factor_below(15, 256), Some(3));
        assert_eq!(
            smallest_factor_below(13, 256),
            Some(13),
            "value below bound"
        );
        assert_eq!(smallest_factor_below(998_244_353, 256), None, "large prime");
        assert_eq!(
            smallest_factor_below(257 * 263, 256),
            None,
            "no small factor"
        );
        assert_eq!(smallest_factor_below(257 * 263, 258), Some(257));
    }
}
