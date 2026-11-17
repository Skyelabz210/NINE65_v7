// src/core/anchor.js — anchor admissibility: the anchor must be INTERNAL. (P17)
//
// CORRECTION OF RECORD — this reverses P14.
// ─────────────────────────────────────────
// P14 called the adjacent anchor A = M + 1 "canonical" and dismissed the gear
// pair 17·19 = 323 as "an RNS move, drawn from inside the basis". That is
// exactly backwards. Drawn from inside the basis is the CRAM move, and it is
// the only admissible one, for a reason stronger than cost:
//
//   THE TRAY DOES NOT DETERMINE AN EXTERNAL ANCHOR.
//
// x and x + M share the entire tray. Their residues modulo A differ by
// M mod A. So x mod A is a function of the tray if and only if A | M. For
// SafeS8, M8 = 9,699,690 and the adjacent modulus 30,031 = 59 · 509 is coprime
// to it: M8 mod 30,031 = 29,708 ≠ 0. The adjacent residue is therefore not
// obtainable from the tray.
//
// AMENDED (P19). Two claims made here originally were too strong and are
// withdrawn:
//
//   · "it cannot be evaluated in residue space at all" — it CAN be reached.
//     Reconstruction is O(1) (K-Elimination plus one multiply-add; see
//     `reconstructAdjacent` in cram.js), so you may rebuild the integer and
//     reduce modulo anything. Reconstruction is not forbidden; A2 retires
//     Garner, not the act of producing the integer.
//
//   · "adjoining lanes violates A3" — A3 was imported from a framework document
//     and was never adopted here. It is not a premise of this codebase.
//
// What survives, and what the objection actually is: I.I.D. Reconstruction
// couples every lane, so an anchor that requires it belongs at a declared
// boundary and not in the hot path. An internal anchor needs no such step:
// 323 is read from lanes 17
// and 19, which are already in the tray, computed independently, and disjoint
// from the six shell lanes. Every lane is still produced by its own reduction
// of x, referencing no other lane. That is what preserves i.i.d., and it is why
// 17 and 19 were promoted into the basis in the first place. The case for an
// internal anchor rests on i.i.d. alone — which is where it started.
//
// ADJACENCY IS STILL AVAILABLE — INTERNALLY.
// ──────────────────────────────────────────
// The one-subtraction collapse is not lost, it just has to be designed in. A
// star pair (6n(n−1), S_n) is adjacent, and both halves can be realised as
// sub-products of one pairwise-coprime basis:
//
//     S_2  basis {4, 3, 13}       shell 12   anchor 13
//     S_3  basis {4, 9, 37}       shell 36   anchor 37     ← the 36/37 star lift
//     S_4  basis {8, 9, 73}       shell 72   anchor 73
//     S_6  basis {4, 9, 5, 181}   shell 180  anchor 181
//
// There the anchor is internal AND adjacent: K ≡ r − s with no multiply, no
// inverse, and no departure from residue space. That is what the star lift is
// for. SafeS8 is simply not such a basis — its internal anchor is 323, and the
// general K-Elimination form with M6⁻¹ ≡ 287 (mod 323) is the correct and
// canonical path there.
//
// THE PARKED LANE (P18)
// ─────────────────────
// There is a further constraint that P17 did not state: a lane cannot be both
// the anchor and part of the shell. The shadow lane 11 is left EMPTY — excluded
// from the shell product — precisely so it can serve as the K-Elimination
// anchor. It is in the basis (so the tray reaches it, satisfying internality)
// but carries no value.
//
// Loading 11 into the shell, as this project had been doing, causes two
// self-inflicted problems:
//
//   1. It forces the anchor elsewhere. With M6 = 30,030 the winding runs to
//      K ≤ 43 over the ecliptic ring, needing the gear pair 323 to cover it.
//      With 11 parked the shell is M = 2·3·5·7·13·17·19 = 881,790 = M8/11, the
//      ring needs only K ≤ 1, and the single lane 11 covers it outright.
//
//   2. It makes the shadow lattice look non-coprime. gcd(11⁶, 30,030) = 11, so
//      the lift needed a divide-by-11 Hensel step — and that was written up as
//      "intentional non-coprimality". It is not intentional and not necessary:
//      gcd(11⁶, 881,790) = 1, so with 11 parked the shadow lift is plain
//      coprime K-Elimination. Same corridor, 881,790 · 11⁶ = 9,699,690 · 11⁵ =
//      1,562,144,774,190, obtained without the workaround.
//
// Widening the parked lane to 11^e is a lane widening, not a basis extension:
// the basis {2,3,5,7,13,17,19, 11⁶} is pairwise coprime, so 11⁶ is tray-
// determined by construction. (11⁶ does NOT divide M8, so it is only reachable
// once the lane is carried at that power — which is what the shadow lattice
// Sh = {11⁶, 13, 17, 19} has always meant.)
//
// BigInt only. No floats, no Date, no ephemeris.

import { mod } from "./residues.js";
import { factorise } from "./ring.js";
import { gcd, inverse, isSafeBasis, shellModulus } from "./cram.js";

/**
 * Does the residue tray over `basis` determine x mod A?
 * Yes iff A | M. Otherwise x and x+M share the tray and differ mod A.
 * @param {bigint[]} basis - the lane moduli.
 * @param {bigint} A - the candidate anchor modulus.
 * @returns {boolean}
 */
export function trayDeterminesAnchor(basis, A) {
  return mod(shellModulus(basis), A) === 0n;
}

/**
 * A witness that an external anchor is undetermined: two values sharing the
 * whole tray whose anchor residues differ. Returns null for internal anchors.
 * @param {bigint[]} basis - the lane moduli.
 * @param {bigint} A - the candidate anchor modulus.
 * @param {bigint} [x=123456n] - the sample value to witness with.
 * @returns {?{x: string, y: string, tray_identical: boolean, anchor_x: string, anchor_y: string, differ_by: string}}
 *   null when A is internal (tray-determined); otherwise the witnessing pair
 *   x, y = x+M and their (differing) anchor residues.
 */
export function undeterminedWitness(basis, A, x = 123456n) {
  const M = shellModulus(basis);
  if (mod(M, A) === 0n) return null;
  const y = x + M;
  return {
    x: x.toString(), y: y.toString(),
    tray_identical: basis.every((p) => mod(x, p) === mod(y, p)),
    anchor_x: mod(x, A).toString(),
    anchor_y: mod(y, A).toString(),
    differ_by: mod(M, A).toString(),
  };
}

/**
 * The lanes of `basis` whose product is A, or null when A is not internal.
 * @param {bigint[]} basis - the lane moduli.
 * @param {bigint} A - the candidate anchor modulus.
 * @returns {?bigint[]} the sub-basis multiplying to A, or null if none does.
 */
export function anchorLanes(basis, A) {
  let rest = A;
  const lanes = [];
  for (const p of basis) {
    if (mod(rest, p) === 0n) { lanes.push(p); rest = rest / p; }
  }
  return rest === 1n ? lanes : null;
}

/**
 * An anchor is internal when it is a sub-product of the fixed basis.
 * @param {bigint[]} basis - the lane moduli.
 * @param {bigint} A - the candidate anchor modulus.
 * @returns {boolean}
 */
export function isInternalAnchor(basis, A) { return anchorLanes(basis, A) !== null; }

/**
 * Which lanes must be read to pin x mod A? For an internal anchor this is
 * exactly its own lane set; for an external one the answer is "all of them,
 * and it is still not determined".
 * @param {bigint[]} basis - the lane moduli.
 * @param {bigint} A - the candidate anchor modulus.
 * @returns {bigint[]} the lanes whose value affects x mod A.
 */
export function laneDependency(basis, A) {
  const M = shellModulus(basis);
  const need = [];
  for (const p of basis) {
    const step = M / p;
    let varies = false;
    for (let k = 1n; k < p; k++) if (mod(step * k, A) !== 0n) { varies = true; break; }
    if (varies) need.push(p);
  }
  return need;
}

/**
 * The i.i.d. verdict for a (shell, anchor) split of one fixed basis.
 *
 * Admissible when: the basis is unbroken, both parts are internal, the two lane
 * sets are disjoint, and the anchor is determined by the tray. Then each lane is
 * still produced by its own reduction and the anchor reads a disjoint subset —
 * no lane depends on another, so i.i.d. survives.
 * @param {bigint[]} basis - the fixed basis both splits are drawn from.
 * @param {bigint[]} shellLanes - the lanes assigned to the shell.
 * @param {bigint[]} anchorLanes_ - the lanes assigned to the anchor.
 * @returns {Object} `ANCHOR_ADMISSIBILITY_V1` — internal/disjoint/tray-determines-anchor/
 *   coprime/adjacent flags, plus `iid_preserved` and `admissible` verdicts and
 *   a `recovery` mechanism label.
 */
export function anchorReport(basis, shellLanes, anchorLanes_) {
  const M = shellModulus(shellLanes);
  const A = shellModulus(anchorLanes_);
  const inBasis = (s) => s.every((p) => basis.some((q) => q === p));
  const disjoint = shellLanes.every((p) => !anchorLanes_.some((q) => q === p));
  const internal = inBasis(shellLanes) && inBasis(anchorLanes_);
  const determined = trayDeterminesAnchor(basis, A);
  return {
    kind: "ANCHOR_ADMISSIBILITY_V1",
    basis: basis.map(String),
    shell: M.toString(),
    anchor: A.toString(),
    shell_lanes: shellLanes.map(String),
    anchor_lanes: anchorLanes_.map(String),
    basis_unbroken: isSafeBasis(basis),
    internal,
    disjoint,
    tray_determines_anchor: determined,
    coprime: gcd(M, A) === 1n,
    adjacent: A === M + 1n,
    iid_preserved: internal && disjoint && determined,
    admissible: isSafeBasis(basis) && internal && disjoint && determined && gcd(M, A) === 1n,
    recovery: A === M + 1n ? "adjacency collapse (K ≡ r − s)" : "general K-Elim (needs M⁻¹ mod A)",
  };
}

// ── star-lift bases: internal AND adjacent ─────────────────────────

/**
 * Prime-power lanes of n — the coarsest pairwise-coprime factorisation.
 * @param {bigint} n - the value to factor.
 * @returns {bigint[]} [p1^e1, p2^e2, ...] for n = p1^e1 * p2^e2 * ...
 */
export function primePowerLanes(n) {
  const out = [];
  for (const [p, e] of factorise(n)) {
    let q = 1n;
    for (let i = 0n; i < e; i++) q = q * p;
    out.push(q);
  }
  return out;
}

/**
 * The safe basis realising the star pair (6n(n−1), S_n) internally, so the
 * adjacency collapse runs without ever leaving residue space.
 * @param {bigint} n - the star index (S_n = 6n(n−1)+1).
 * @returns {?{n: string, basis: bigint[], shell_lanes: bigint[], anchor_lanes: bigint[],
 *   shell: bigint, anchor: bigint, report: Object}} null when the shell would be < 2
 *   (n ≤ 1); otherwise the internal-adjacency configuration and its `anchorReport`.
 */
export function starLiftBasis(n) {
  const A = 6n * n * (n - 1n) + 1n;
  const M = A - 1n;
  if (M < 2n) return null;
  const shellLanes = primePowerLanes(M);
  const anchorLanes_ = primePowerLanes(A);
  const basis = [...shellLanes, ...anchorLanes_];
  return {
    n: n.toString(),
    basis,
    shell_lanes: shellLanes,
    anchor_lanes: anchorLanes_,
    shell: M,
    anchor: A,
    report: anchorReport(basis, shellLanes, anchorLanes_),
  };
}

/**
 * Internal adjacency recovery: K ≡ r − s (mod M+1), admissible only when the
 * anchor is an internal sub-product. Throws otherwise rather than silently
 * performing an operation the tray cannot support.
 * @param {bigint[]} basis - the fixed basis.
 * @param {bigint[]} shellLanes - the shell's lane set.
 * @param {bigint[]} anchorLanes_ - the anchor's lane set.
 * @param {bigint} r - the shell residue.
 * @param {bigint} s - the anchor residue.
 * @returns {bigint} K = (r − s) mod anchor.
 * @throws {Error} "anchor not admissible: ..." if `anchorReport` is not admissible;
 *   "anchor is not adjacent to the shell" if it is admissible but not adjacent (A ≠ M+1).
 */
export function internalAdjacencyRecover(basis, shellLanes, anchorLanes_, r, s) {
  const rep = anchorReport(basis, shellLanes, anchorLanes_);
  if (!rep.admissible) throw new Error("anchor not admissible: " + JSON.stringify(rep));
  if (!rep.adjacent) throw new Error("anchor is not adjacent to the shell");
  return mod(r - s, BigInt(rep.anchor));
}


// ── the parked lane ────────────────────────────────────────────────

/** The shadow lane, parked: in the basis, excluded from the shell. */
export const PARKED_LANE = 11n;

/** Shell lanes of SafeS8 once lane 11 is parked. */
export const SHELL_LANES_PARKED = [2n, 3n, 5n, 7n, 13n, 17n, 19n];
/** ∏ SHELL_LANES_PARKED = M8 / 11 = 881,790. */
export const SHELL_PARKED = 881790n;              // = M8 / 11

/**
 * The parked lane carried at power e. e = 1 is the bare lane.
 * @param {bigint} e - the power to carry lane 11 at.
 * @returns {bigint} 11^e.
 */
export function shadowAnchor(e) {
  let out = 1n;
  for (let i = 0n; i < e; i++) out = out * PARKED_LANE;
  return out;
}

/**
 * Lane occupancy for a basis: which lanes carry value (shell) and which are
 * parked (anchor). A lane may not be both.
 * @param {bigint[]} basis - the full lane set.
 * @param {bigint[]} parked - the sublanes to park as the anchor.
 * @param {bigint} [power=1n] - the power to carry each parked lane at.
 * @returns {Object} `LANE_OCCUPANCY_V1` — shell/anchor moduli, coprimality,
 *   whether the parked lanes are actually in the basis, and `admissible`.
 */
export function parkingReport(basis, parked, power = 1n) {
  const shellLanes = basis.filter((p) => !parked.some((q) => q === p));
  const M = shellModulus(shellLanes);
  const A = parked.reduce((a, p) => {
    let q = 1n; for (let i = 0n; i < power; i++) q = q * p; return a * q;
  }, 1n);
  // A lane can only be PARKED if the tray already carries it. Parking moves a
  // lane out of the shell and onto the anchor; it does not conjure one. A prime
  // outside the basis is an EXTERNAL anchor — coprime or not, the tray cannot
  // read it (trayDeterminesAnchor), so i.i.d. is gone and the split is
  // inadmissible however clean the arithmetic looks. (P22)
  const inBasis = parked.every((p) => basis.some((q) => q === p));
  const external = parked.filter((p) => !basis.some((q) => q === p));
  // Widening an existing lane to p^k is a lane widening, not a basis extension:
  // the lane is still read off the tray, just carried at more precision.
  return {
    kind: "LANE_OCCUPANCY_V1",
    basis: basis.map(String),
    parked: parked.map(String),
    parked_power: power.toString(),
    shell_lanes: shellLanes.map(String),
    shell: M.toString(),
    anchor: A.toString(),
    disjoint: shellLanes.every((p) => !parked.some((q) => q === p)),
    coprime: gcd(M, A) === 1n,
    parked_in_basis: inBasis,
    external_lanes: external.map(String),
    lane_widened: power > 1n,
    corridor: (M * A).toString(),
    admissible: inBasis && gcd(M, A) === 1n && shellLanes.length > 0,
  };
}

/**
 * K-Elimination with the parked lane as anchor. Plain coprime form — no Hensel
 * division, because the shell does not contain the parked prime.
 * @param {bigint} r - shell residue, x mod M.
 * @param {bigint} s - anchor residue, x mod A.
 * @param {bigint} M - the shell modulus.
 * @param {bigint} A - the parked anchor modulus.
 * @returns {bigint} K mod A.
 * @throws {Error} if M is not coprime to A (the anchor prime was not actually parked out of the shell).
 */
export function parkedRecover(r, s, M, A) {
  const mi = inverse(M, A);
  if (mi === null) throw new Error("parked anchor is not coprime to the shell — lane not parked?");
  return mod((s - r) * mi, A);
}

/**
 * The same, driven from the integer.
 * @param {bigint} x - the source integer.
 * @param {bigint} M - the shell modulus.
 * @param {bigint} A - the parked anchor modulus.
 * @returns {bigint} K mod A, as `parkedRecover`.
 */
export function parkedRecoverFrom(x, M, A) {
  return parkedRecover(mod(x, M), mod(x, A), M, A);
}
