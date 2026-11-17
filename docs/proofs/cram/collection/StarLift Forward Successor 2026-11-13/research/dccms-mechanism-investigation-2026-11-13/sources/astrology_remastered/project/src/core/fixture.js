// src/core/fixture.js — star lift, winding tower, and the phase-locked fixture. (P15)
//
// THE STAR FAMILY
// ───────────────
// Star numbers S_n = 6n(n−1) + 1. Since S_n − 1 = 6n(n−1), every star number is
// adjacent to its own shell:
//
//     M = 6n(n−1),   A = S_n = M + 1
//
// so the whole family is adjacency pairs, self-inverse, K ≡ r − s, for free.
// The family is not decorative — it is where this project's anchors already
// came from, and it was never noticed:
//
//     S_1 =   1    the unit lane (recommissioned; see below)
//     S_2 =  13    the boundary witness
//     S_3 =  37    the 36/37 star lift
//     S_4 =  73    the Maya resolution modulus (gcd(260,365)=5 → 365/5 = 73)
//     S_5 = 121    = 11², the shadow prime squared — at n = 5, the shadow lane
//     S_6 = 181    with M = 180, the N-refinement folding period
//
// THE WINDING TOWER — DEPTH
// ─────────────────────────
// Iterating the star lift descends: T_0 = X, T_{d+1} = ⌊T_d / M⌋, terminating
// when T reaches zero. Each level reads its own winding by one subtraction from
// its own (r, s) pair, and NO level's formula references any other level's
// result. That is what separates a tower from a radix: Garner threads an
// accumulator through the digits, so digit i depends on digits 0..i−1; here the
// levels are independent. Depth is unbounded, so the tower supplies arbitrary
// DEPTH.
//
// But a single adjacent anchor certifies a level only while that level's
// winding stays inside the corridor (< M+1). For X = 2¹²⁸−1 over the 36/37 lift
// the tower is 25 levels deep and only the top 2 are corridor-certified. The
// rest need a wider fixture — which is exactly what transduction supplies.
// Tower buys depth; transduction buys precision; neither substitutes for the
// other, and `towerReport` says precisely where the handover happens.
//
// THE UNIT LANE — PHASE LOCK
// ──────────────────────────
// Lane 1 is Z/1, the terminal ring. Recommissioning it is legitimate and it
// does real structural work:
//
//   · gcd(1, n) = 1 for every n, so it is admissible in EVERY fixture and can
//     never collide with an extension;
//   · it leaves M unchanged, so adjoining it is the identity transduction;
//   · every fixture has a unique map onto it, so it is the canonical common
//     quotient — the frame-independent origin two fixtures can both point at;
//   · it makes the bases a monoid under union, with {1} the identity.
//
// What it does NOT do is carry information: Z/1 has one element, so lane 1 is
// exactly 0 bits and cannot by itself relate two windings. The origin comes
// from lane 1; the PHASE comes from a shared informative lane, and the natural
// choice is the shadow anchor 11. A transduction is phase-locked to a lane ℓ
// exactly when Φ(x) ≡ x (mod ℓ) — so the lock is a real constraint on the
// operator, not a label.
//
// INDEXING. In B8 the shadow prime 11 sits on lane 5, one-indexed. Prepending
// the unit as a normal lane would push it to 6. The unit is therefore indexed
// as LANE 0, which keeps 11 on lane 5 in every fixture.
//
// BigInt only. No floats, no Date, no ephemeris.

import { mod } from "./residues.js";
import { gcd, isSafeBasis, shellModulus } from "./cram.js";

// ── the star family ────────────────────────────────────────────────

/**
 * S_n = 6n(n−1) + 1.
 * @param {bigint} n - the star index.
 * @returns {bigint} the nth star number.
 */
export function starNumber(n) { return 6n * n * (n - 1n) + 1n; }

/**
 * The adjacency pair carried by S_n: shell 6n(n−1), anchor S_n.
 * @param {bigint} n - the star index.
 * @returns {{n: string, shell: string, anchor: string, adjacent: true}}
 */
export function starPair(n) {
  const A = starNumber(n);
  return { n: n.toString(), shell: (A - 1n).toString(), anchor: A.toString(), adjacent: true };
}

/**
 * @param {bigint} upTo - the highest star index to include.
 * @returns {Object[]} `starPair(n)` for n = 1..upTo.
 */
export function starFamily(upTo) {
  const out = [];
  for (let n = 1n; n <= upTo; n++) out.push(starPair(n));
  return out;
}

// ── the winding tower ──────────────────────────────────────────────

/**
 * One level of the tower. Reads the level's winding by the adjacency collapse
 * — one subtraction — and reports whether the single anchor certifies it.
 *
 * Nothing here reads any other level. That is the no-accumulator property.
 * @param {bigint} T - the current tower level's value.
 * @param {bigint} M - the star shell modulus.
 * @returns {{value: bigint, digit: bigint, k_mod_anchor: bigint, k_true: bigint,
 *   identity_holds: boolean, certified: boolean, next: bigint}}
 */
export function towerLevel(T, M) {
  const A = M + 1n;
  const r = mod(T, M);
  const s = mod(T, A);
  const kModA = mod(r - s, A);
  const kTrue = T / M;
  return {
    value: T,
    digit: r,
    k_mod_anchor: kModA,
    k_true: kTrue,
    identity_holds: kModA === mod(kTrue, A),
    certified: kTrue < A,          // corridor: one anchor pins K only below M+1
    next: kTrue,
  };
}

/**
 * The full tower, descending until the winding reaches zero.
 * Termination is guaranteed for every finite X because each level divides the
 * magnitude by M ≥ 2.
 * @param {bigint} X - the value to descend.
 * @param {bigint} M - the star shell modulus (M ≥ 2).
 * @returns {Object[]} the tower levels, as `towerLevel` outputs, from X down to zero.
 * @throws {Error} "tower shell must be at least 2" if M < 2.
 */
export function windingTower(X, M) {
  if (M < 2n) throw new Error("tower shell must be at least 2");
  const levels = [];
  let T = X;
  while (T !== 0n) {
    const lv = towerLevel(T, M);
    levels.push(lv);
    T = lv.next;
  }
  return levels;
}

/**
 * BOUNDARY PROJECTION (P20). Horner in base M — this couples every level into a
 * positional composite and is therefore a radix step, exactly like r + K·M. It
 * is exact and it is a useful check that the tower decomposes faithfully, but
 * it is NOT an operation of the tower. The tower's levels stay independent and
 * uncoupled; nothing in the descent forms this.
 * @param {Object[]} levels - a tower from `windingTower`.
 * @param {bigint} M - the star shell modulus.
 * @returns {bigint} the reconstructed original value X.
 */
export function towerRebuild(levels, M) {
  let acc = 0n;
  for (let i = levels.length - 1; i >= 0; i--) acc = acc * M + levels[i].digit;
  return acc;
}

/**
 * Depth/precision report. `handover_depth` is the first level the single
 * adjacent anchor cannot certify — the exact point at which the tower must
 * hand off to a wider fixture via transduction.
 * @param {bigint} X - the value to descend.
 * @param {bigint} M - the star shell modulus.
 * @returns {Object} `STAR_TOWER_V1` — depth, per-level certification counts,
 *   `handover_depth` (first uncertified level, or null if all are certified),
 *   and a boundary-projection self-check.
 */
export function towerReport(X, M) {
  const levels = windingTower(X, M);
  let certified = 0n, handover = null;
  for (let i = 0; i < levels.length; i++) {
    if (levels[i].certified) certified++;
    else if (handover === null) handover = BigInt(i);
  }
  return {
    kind: "STAR_TOWER_V1",
    shell: M.toString(),
    anchor: (M + 1n).toString(),
    value: X.toString(),
    depth: BigInt(levels.length).toString(),
    terminates_at_zero: true,
    identity_holds_every_level: levels.every((l) => l.identity_holds),
    // boundary-projection check only — not a property of the descent
    rebuild_exact_at_boundary: towerRebuild(levels, M) === X,
    certified_levels: certified.toString(),
    handover_depth: handover === null ? null : handover.toString(),
    // the corridor a single fixture would need to certify level 0 outright
    anchor_needed_for_level_0: (X / M + 1n).toString(),
  };
}

/**
 * Level independence, made checkable rather than asserted: recomputing any
 * level from its own value alone reproduces the tower's entry for that level.
 * A Garner cascade cannot pass this — its digit i is a function of digits
 * 0..i−1, so it has no such standalone form.
 * @param {bigint} X - the value to descend.
 * @param {bigint} M - the star shell modulus.
 * @returns {boolean} true iff every level is reproducible from its own value alone.
 */
export function levelsAreIndependent(X, M) {
  const levels = windingTower(X, M);
  for (const lv of levels) {
    const solo = towerLevel(lv.value, M);
    if (solo.digit !== lv.digit || solo.k_mod_anchor !== lv.k_mod_anchor) return false;
  }
  return true;
}

/**
 * Garner's mixed-radix digits, for contrast. The accumulator `acc` threads
 * through every step — this is the positional emission A2 prohibits, and it is
 * the radix that DynCRT was carrying.
 * @param {bigint} X - the value to decompose.
 * @param {bigint[]} basis - the mixed-radix moduli, in digit order.
 * @returns {{digits: bigint[], accumulator_threaded: true}}
 */
export function garnerDigits(X, basis) {
  const digits = [];
  let acc = 0n, radix = 1n;
  for (const p of basis) {
    const d = mod((mod(X, p) - acc) * modInverseOrZero(radix, p), p);
    digits.push(d);
    acc = acc + d * radix;     // ← the accumulator. every later digit depends on it.
    radix = radix * p;
  }
  return { digits, accumulator_threaded: true };
}

function modInverseOrZero(a, m) {
  let old_r = mod(a, m), r = m, old_s = 1n, s = 0n;
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return old_r === 1n ? mod(old_s, m) : 0n;
}

// ── the fixture: unit lane, indexing, phase lock ───────────────────

/** The recommissioned unit. S_1 = 1, terminal ring, indexed as lane 0. */
export const UNIT_LANE = 1n;
/** The unit lane's fixed index within a fixture's lane array. */
export const UNIT_LANE_INDEX = 0n;

/**
 * A CRT fixture: an ordered basis with the unit lane at index 0 and the
 * informative lanes one-indexed after it, so the shadow prime 11 stays on
 * lane 5 no matter what else is adjoined.
 * @param {bigint[]} basis - the informative lanes (unit lane is prepended automatically).
 * @returns {Object} `CRT_FIXTURE_V1` — `{kind, basis, lanes, M, anchor}` where
 *   `lanes` is `[{index, modulus, role}, ...]`.
 * @throws {Error} "fixture basis must be pairwise coprime" if `basis` is not a safe basis.
 */
export function fixture(basis) {
  if (!isSafeBasis(basis)) throw new Error("fixture basis must be pairwise coprime");
  const lanes = [{ index: UNIT_LANE_INDEX, modulus: UNIT_LANE, role: "unit / origin" }];
  for (let i = 0; i < basis.length; i++) {
    lanes.push({ index: BigInt(i + 1), modulus: basis[i], role: "informative" });
  }
  return {
    kind: "CRT_FIXTURE_V1",
    basis: basis.slice(),
    lanes,
    M: shellModulus(basis),
    anchor: shellModulus(basis) + 1n,
  };
}

/**
 * The lane index of a modulus in a fixture, or null.
 * @param {Object} fx - a fixture from `fixture()`.
 * @param {bigint} modulus - the lane modulus to look up.
 * @returns {?bigint} the lane's index, or null if not present.
 */
export function laneOf(fx, modulus) {
  const l = fx.lanes.find((z) => z.modulus === modulus);
  return l ? l.index : null;
}

/**
 * Adjoining the unit lane changes nothing — the identity transduction.
 * @param {bigint[]} basis - the basis to test (before the unit lane is added).
 * @returns {boolean}
 */
export function unitLaneIsIdentity(basis) {
  const a = shellModulus(basis);
  const b = shellModulus([UNIT_LANE, ...basis]);
  return a === b && basis.every((p) => gcd(UNIT_LANE, p) === 1n);
}

/**
 * Z/1 has one element, so the unit lane carries zero bits.
 * @param {bigint} modulus - a lane modulus.
 * @returns {bigint} the number of distinguishable states of that lane (== modulus).
 */
export function laneStates(modulus) { return modulus; }
/**
 * @param {bigint} modulus - a lane modulus.
 * @returns {boolean} true iff the lane carries more than one state (modulus > 1).
 */
export function laneIsInformative(modulus) { return modulus > 1n; }

/**
 * The phase lock between two fixtures: the lanes they share.
 * `origin` is the unit lane, always shared, guaranteeing a common zero;
 * `carriers` are the shared informative lanes, which is where the phase
 * actually lives. `strength` is the number of distinguishable phases.
 * @param {Object} fxA - a fixture from `fixture()`.
 * @param {Object} fxB - a fixture from `fixture()`.
 * @returns {Object} `PHASE_LOCK_V1` — origin fields plus `carriers`
 *   (shared informative lanes), `strength` (product of shared lane sizes),
 *   and `locked`.
 */
export function phaseLock(fxA, fxB) {
  const shared = fxA.basis.filter((p) => fxB.basis.some((q) => q === p));
  const strength = shared.reduce((a, p) => a * p, 1n);
  return {
    kind: "PHASE_LOCK_V1",
    origin: UNIT_LANE.toString(),
    origin_shared: true,                  // Z/1 is terminal: present in every fixture
    origin_states: UNIT_LANE.toString(),  // one state — zero bits
    carriers: shared.map(String),
    carrier_lanes: shared.map((p) => (laneOf(fxA, p) || 0n).toString()),
    strength: strength.toString(),
    locked: shared.length > 0,
  };
}

/**
 * A transduction is phase-locked to lane ℓ exactly when Φ fixes the lane:
 * Φ(x) ≡ x (mod ℓ) for all x. For Φ with integer coefficients this is decided
 * by one period, so the check below is exhaustive for that class — and that
 * assumption is stated rather than hidden.
 * @param {function(bigint): bigint} phi - a value map with integer coefficients.
 * @param {bigint} lane - the lane modulus to check the lock against.
 * @returns {boolean} true iff Φ(x) ≡ x (mod lane) for every x in one period.
 */
export function preservesPhase(phi, lane) {
  if (lane <= 1n) return true;            // the unit lane is fixed by everything
  for (let x = 0n; x < lane; x++) if (mod(phi(x), lane) !== mod(x, lane)) return false;
  return true;
}

/**
 * The Φ that shift a value while holding the lock: x ↦ x + k·ℓ.
 * @param {bigint} lane - the lane to preserve.
 * @param {bigint} k - the shift multiple.
 * @returns {function(bigint): bigint} the shift function.
 */
export function lockedShift(lane, k) { return (x) => x + k * lane; }
