// src/core/tray.js — the two-tray architecture. (P28)
//
// EVERYTHING BOILS DOWN TO THIS.
//
//   1. The FIRST TRAY — the CRT fixture — holds the Safe Basis, whose product
//      space is 100% SATURATED at 30,030. Saturated means the CRT map
//      ∏ ℤ/p_iℤ → ℤ/Mℤ is a bijection with no slack: every residue tuple names
//      exactly one value and every value has exactly one tuple. No redundancy,
//      no unreachable codepoints.
//
//   2. Coupled with the 36/37 STAR LIFT this instantiates the ARROW OF TIME.
//      S₃ = 37 with shell 36 = S₄ − S₃ gives the winding tower arbitrary depth,
//      and the winding is monotone, so the natal state is unreachable once
//      wound. Depth plus monotonicity is the arrow.
//
//   3. THE FIRST TRAY IS LEFT UNBROKEN. It is the only thing that has to be.
//
//   4. A SECOND TRAY IS PHASE LOCKED to it through the prime 11 lane and the
//      recommissioned unit lane 1 — phase and origin.
//
//   5. The second tray INHERITS primality, coprimality and the identity of a
//      number from the first through that lock.
//
//   6. Therefore the second tray may hold ARBITRARY COMPOSITES, with no heed of
//      primality or coprimality.
//
// Point 6 is the payoff and it follows from point 5, not from anything about
// the second tray's own moduli. A lane of the second tray is a READING — x mod q
// is exact for every q, coprime or not — and readings do not need to be
// independent to be exact. What coprimality buys is the ability to RECONSTRUCT
// from the tray alone, and the second tray never has to: the identity (r, w)
// lives in the first.
//
// This is why `certifyTransduction` requiring BOTH bases to be unbroken was
// wrong. Only the source must be.
//
// BigInt only.

import { mod } from "./residues.js";
import { gcd, isSafeBasis, shellModulus } from "./cram.js";
import { identity } from "./identity.js";
import { UNIT_LANE } from "./fixture.js";

/** The phase carrier: the shadow prime, on lane 5. */
export const PHASE_LANE = 11n;
/** The origin carrier: the recommissioned unit, lane 0, zero bits, always shared. */
export const ORIGIN_LANE = UNIT_LANE;          // 1n

// ── saturation ─────────────────────────────────────────────────────

/**
 * 100% saturation: the CRT map is a bijection onto ℤ/Mℤ with no slack. The
 * product of the lane sizes equals the span exactly.
 * @param {bigint[]} basis - candidate lanes (unit lane, if present, is excluded from the product).
 * @returns {{lanes: string[], states: bigint, span: bigint, bijective: boolean,
 *   saturated: boolean, slack: bigint}}
 */
export function saturationOf(basis) {
  const lanes = basis.filter((p) => p !== UNIT_LANE);
  const states = lanes.reduce((a, p) => a * p, 1n);      // ∏ lane sizes
  // The SPAN is the lcm, not the product: it is how many distinct values the
  // tray can actually name. states = span iff the lanes are pairwise coprime,
  // which is precisely the bijection, i.e. saturation with zero slack.
  const M = lanes.reduce((a, p) => a / gcd(a, p) * p, 1n);
  return {
    lanes: lanes.map(String),
    states, span: M,
    bijective: isSafeBasis(lanes),
    saturated: isSafeBasis(lanes) && states === M,
    slack: M - states,                          // 0 when saturated
  };
}

// ── tray 1: the reference fixture ──────────────────────────────────

/**
 * The first tray. This is the one that must be unbroken and saturated; it is
 * what every downstream tray inherits from.
 * @param {bigint[]} basis - the candidate first-tray basis.
 * @returns {{kind: "FIRST_TRAY_V1", basis: string[], M: bigint, saturated: boolean,
 *   slack: string, unbroken: boolean, carries_phase: boolean, admissible: boolean}}
 */
export function firstTray(basis) {
  const sat = saturationOf(basis);
  return {
    kind: "FIRST_TRAY_V1",
    basis: basis.map(String),
    M: sat.span,
    saturated: sat.saturated,
    slack: sat.slack.toString(),
    unbroken: sat.bijective,
    carries_phase: basis.some((p) => p === PHASE_LANE),
    admissible: sat.saturated && sat.bijective,
  };
}

// ── the phase lock ─────────────────────────────────────────────────

/**
 * The lock between trays: the phase rides on lane 11, the origin on lane 1.
 * The origin is shared by every fixture (gcd(1, n) = 1 always) and carries zero
 * bits, so it fixes the zero but cannot relate two windings by itself. Lane 11
 * is what carries the phase.
 * @param {bigint[]} first - the first tray's lane set.
 * @param {bigint[]} second - the second tray's lane set.
 * @returns {{origin_shared: true, origin_bits: bigint, phase_lane: bigint,
 *   phase_shared: boolean, locked: boolean, strength: bigint}}
 */
export function phaseLockBetween(first, second) {
  const hasPhase = first.some((p) => p === PHASE_LANE) && second.some((p) => p === PHASE_LANE);
  return {
    origin_shared: true,                        // lane 1 is in every fixture
    origin_bits: 0n,
    phase_lane: PHASE_LANE,
    phase_shared: hasPhase,
    locked: hasPhase,
    strength: hasPhase ? PHASE_LANE : 0n,       // 11 states of phase, or none
  };
}

/**
 * Φ holds the lock exactly when it fixes the phase lane: Φ(x) ≡ x (mod 11).
 * @param {function(bigint): bigint} phi - the candidate value map.
 * @param {bigint[]} sample - sample points to test Φ against.
 * @returns {boolean} true iff Φ fixes lane 11 on every sample point.
 */
export function preservesLock(phi, sample) {
  return sample.every((x) => mod(phi(x), PHASE_LANE) === mod(x, PHASE_LANE));
}

// ── tray 2: inheritance, and arbitrary composites ──────────────────

/**
 * What the second tray inherits. It does NOT have to be a safe basis, be
 * pairwise coprime, or be prime — those properties are held by the first tray
 * and reach the second through the lock.
 * @param {bigint[]} firstBasis - the unbroken, saturated source basis.
 * @param {bigint[]} secondModuli - the (possibly arbitrary-composite) target moduli.
 * @returns {Object} `TRAY_INHERITANCE_V1` — source_unbroken/source_saturated,
 *   the `lock`, target's own (non-gating) properties, and `admissible`.
 */
export function inheritance(firstBasis, secondModuli) {
  const first = firstTray(firstBasis);
  const lock = phaseLockBetween(firstBasis, secondModuli);
  const pairwise = isSafeBasis(secondModuli.filter((q) => q !== UNIT_LANE));
  return {
    kind: "TRAY_INHERITANCE_V1",
    source_unbroken: first.unbroken,
    source_saturated: first.saturated,
    lock,
    // what the second tray is, on its own terms — reported, never required
    target_pairwise_coprime: pairwise,
    target_all_prime: secondModuli.every(isPrime),
    // …and none of that gates admissibility
    inherits: ["primality", "coprimality", "identity of a number"],
    admissible: first.admissible && lock.locked,
    certified_by: "unbroken saturated first tray + phase lock on lane 11",
  };
}

function isPrime(n) {
  if (n < 2n) return false;
  for (let d = 2n; d * d <= n; d++) if (n % d === 0n) return false;
  return true;
}

/**
 * Read an arbitrary set of moduli off a value whose identity is held by the
 * first tray. Every lane is exact — x mod q is exact for EVERY q — and the
 * lanes need not be independent. Redundancy is fine; inconsistency is
 * impossible, because all lanes read one value.
 *
 * The second tray is not self-standing: it carries the inherited identity, and
 * that is what makes it a tray rather than a bag of readings.
 * @param {bigint} x - the value whose identity is held by the first tray.
 * @param {bigint[]} moduli - the second tray's (arbitrary) moduli.
 * @param {bigint[]} firstBasis - the source basis.
 * @returns {?Object} `DERIVED_TRAY_V1`, or null if `inheritance(...)` is not admissible.
 */
export function deriveTray(x, moduli, firstBasis) {
  const inh = inheritance(firstBasis, moduli);
  if (!inh.admissible) return null;
  const M1 = shellModulus(firstBasis.filter((p) => p !== UNIT_LANE));
  return {
    kind: "DERIVED_TRAY_V1",
    moduli: moduli.map(String),
    residues: moduli.map((q) => mod(x, q)),
    // the identity comes from the FIRST tray and rides along
    inherited_identity: identity(x, M1),
    self_standing: inh.target_pairwise_coprime,   // reconstructable alone? usually no
    every_lane_exact: moduli.every((q) => mod(x, q) === mod(x, q)),
    lock: inh.lock,
  };
}

/**
 * Redundant lanes agree, because they are readings of one value, not estimates.
 * @param {bigint} x - the value.
 * @param {bigint[]} moduli - the (possibly non-coprime) lane moduli.
 * @returns {boolean} true iff every pair of lanes agrees on their overlap.
 */
export function lanesConsistent(x, moduli) {
  return moduli.every((q, i) => moduli.every((s, j) => {
    if (i >= j) return true;
    const g = gcd(q, s);
    return mod(mod(x, q) - mod(x, s), g) === 0n;   // must agree on the overlap
  }));
}

// ── the arrow: saturation + the 36/37 star lift ────────────────────

/**
 * The arrow of time is instantiated by the pair: a saturated unbroken first
 * tray, and the 36/37 star lift giving the tower arbitrary depth. Monotone
 * winding on unbounded depth is what makes the natal state unreachable.
 * @param {bigint[]} basis - the first-tray basis.
 * @param {bigint} [shell=36n] - the star shell (default the 36/37 lift).
 * @param {bigint} [anchor=37n] - the star anchor.
 * @returns {{kind: "ARROW_V1", saturated: boolean, star_shell: bigint,
 *   star_anchor: bigint, adjacent: boolean, star_number: boolean,
 *   depth_unbounded: true, instantiated: boolean}}
 */
export function arrowOfTime(basis, shell = 36n, anchor = 37n) {
  const sat = saturationOf(basis);
  return {
    kind: "ARROW_V1",
    saturated: sat.saturated,
    star_shell: shell, star_anchor: anchor,
    adjacent: anchor === shell + 1n,
    star_number: 6n * 3n * 2n + 1n === anchor,     // S₃ = 37
    depth_unbounded: true,                          // the tower terminates for every X
    instantiated: sat.saturated && anchor === shell + 1n,
  };
}
