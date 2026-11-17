// src/core/shell-kelim.js — shell winding recovery. (P3, re-based P21)
//
// CANONICAL — the parked split.
// ─────────────────────────────
// Shell {2,3,5,7,13,17,19} = 881,790, anchor the parked lane 11. Both are
// sub-products of the fixed basis and their lane sets are disjoint, so the
// anchor is INTERNAL and tray-determined and i.i.d. survives: every lane is
// still x mod p, referencing no other lane.
//
//     K ≡ (s − r) · M_SHELL⁻¹   (mod 11),      M_SHELL⁻¹ ≡ 7 (mod 11)
//
// Exact while K < 11. Over the ecliptic ring K ≤ 1, so the bare lane covers it
// with an order of magnitude to spare.
//
// The yield is the PAIR (r, K). It is not fused: r lives in the shell lanes,
// K in the parked lane. Forming r + K·M_SHELL is a radix boundary projection
// and lives in cram.js as `projectToInteger`, not here.
//
// LEGACY — the gear split.
// ────────────────────────
// Shell {2,3,5,7,11,13} = 30,030, anchor 17·19 = 323 with the precomputed
// inverse 287. Exact, still PROVEN, still exported. It needs the wider 323
// anchor only because 11 was loaded into the shell, pushing K to 43.
//
// BigInt only.

import {
  M6, GEAR_PRODUCT, M6_INV_MOD_GEAR,
  PARK, SHELL_LANES, M_SHELL, M_SHELL_INV_MOD_PARK,
} from "./basis.js";
import { mod } from "./residues.js";

// ── canonical: parked shell, lane-11 anchor ────────────────────────

/** The canonical internal anchor: the parked lane. */
export const SHELL_ANCHOR = PARK;               // 11

/**
 * r — the shell residue, over {2,3,5,7,13,17,19}.
 * @param {bigint} x - a longitude (BigInt arcseconds) or any integer.
 * @returns {bigint} x mod M_SHELL.
 */
export function parkedShellResidue(x) { return mod(x, M_SHELL); }

/**
 * s — the anchor residue, read straight off the parked lane.
 * @param {bigint} x
 * @returns {bigint} x mod 11.
 */
export function parkResidue(x) { return mod(x, PARK); }

/**
 * K-Elimination on the parked split. Returns K only; the number is the pair
 * (r, K) and nothing here fuses them.
 * @param {bigint} r - shell residue, x mod M_SHELL.
 * @param {bigint} s - parked-lane residue, x mod 11.
 * @returns {bigint} K mod 11.
 */
export function recoverShellWinding(r, s) {
  return mod((s - r) * M_SHELL_INV_MOD_PARK, PARK);
}

/**
 * The same, driven from the integer — for encoding and for tests.
 * @param {bigint} x
 * @returns {bigint} K mod 11, as `recoverShellWinding`.
 */
export function recoverShellWindingFrom(x) {
  return recoverShellWinding(parkedShellResidue(x), parkResidue(x));
}

/**
 * The yield: the identity pair, uncoupled.
 * @param {bigint} x
 * @returns {{r: bigint, K: bigint, shell: bigint, anchor: bigint}}
 */
export function shellIdentity(x) {
  const r = parkedShellResidue(x);
  return { r, K: recoverShellWinding(r, parkResidue(x)), shell: M_SHELL, anchor: PARK };
}

/**
 * @param {bigint} x
 * @returns {bigint} ⌊x / M_SHELL⌋ — the true (non-reduced) winding, for verification.
 */
export function actualShellWinding(x) { return x / M_SHELL; }

// ── the winding is DERIVED, not carried ────────────────────────────
//
// K is not a stored field. It is a FUNCTION OF THE TRAY, recovered on demand by
// K-Elimination on the parked lane. A single elimination at 11 reaches K < 11;
// depth comes from LIFTING the same lane to 11^e and eliminating again. Two
// levels — the double lift — reach K < 121:
//
//     level 1:   K ≡ (s₁ − r)·M⁻¹  (mod 11)      s₁ = x mod 11
//     level 2:   K ≡ (s₂ − r)·M⁻¹  (mod 11²)     s₂ = x mod 11²
//
// Each level yields one base-11 digit of K, and the levels agree because the
// lane is PHASE LOCKED: s₂ ≡ s₁ (mod 11), so lifting never moves the phase it
// was affixed to. Level e is the same single modular subtraction as level 1,
// taken at a higher power of the same prime — not a new lane, not a new basis.
//
// M_SHELL is coprime to 11 (that is what parking the lane buys), so M⁻¹ exists
// mod 11^e for every e and the lift is plain K-Elimination throughout — no
// Hensel division, no divide-by-11 anywhere.

/**
 * 11^e — the parked lane carried at depth e.
 * @param {bigint} levels - the depth e.
 * @returns {bigint} 11^levels.
 */
export function parkPower(levels) {
  let q = 1n;
  for (let i = 0n; i < levels; i++) q = q * PARK;
  return q;
}

/**
 * Derive the winding by an e-fold K-Elimination lift on the parked lane.
 * `levels = 2n` is the double lift. Nothing is carried: r and s are read off
 * the tray, and K falls out of them.
 *
 *   r  = x mod M_SHELL   — from the shell lanes
 *   s  = x mod 11^levels — from the parked lane, carried at that depth
 *
 * Exact while K < 11^levels. Returns the base-11 digits alongside K so the
 * lift is auditable level by level.
 * @param {bigint} r - shell residue, x mod M_SHELL.
 * @param {bigint} s - parked-lane residue, x mod 11^levels.
 * @param {bigint} [levels=2n] - the lift depth (2 = the "double lift").
 * @returns {{K: bigint, digits: bigint[], phases: bigint[], levels: bigint,
 *   depth: bigint, shell: bigint, anchor: bigint, corridor: bigint}}
 * @throws {Error} "the lift needs at least one level" if levels < 1.
 */
export function liftWinding(r, s, levels = 2n) {
  if (levels < 1n) throw new Error("the lift needs at least one level");
  const digits = [];
  const phases = [];
  let K = 0n, pow = 1n;
  for (let i = 0n; i < levels; i++) {
    const prev = pow;
    pow = pow * PARK;                                  // 11^(i+1)
    const sI = mod(s, pow);                            // phase lock: s reduces cleanly
    const inv = inverseModPrimePower(mod(M_SHELL, pow), pow);
    const Ki = mod((sI - r) * inv, pow);
    digits.push((Ki - K) / prev);                      // the new base-11 digit
    phases.push(sI);
    K = Ki;
  }
  return {
    K, digits, phases,
    levels, depth: pow,
    shell: M_SHELL, anchor: pow,
    corridor: M_SHELL * pow,
  };
}

/**
 * The double lift, named — two eliminations, K < 121.
 * @param {bigint} r - shell residue.
 * @param {bigint} s - parked-lane residue mod 121.
 * @returns {Object} `liftWinding(r, s, 2n)` result.
 */
export function doubleLiftWinding(r, s) { return liftWinding(r, s, 2n); }

/**
 * Derive the winding straight from the tray at the given depth. The parked lane
 * is read at 11^levels; every other lane is untouched.
 * @param {bigint} x - the source integer.
 * @param {bigint} [levels=2n] - the lift depth.
 * @returns {Object} `liftWinding(...)` result.
 */
export function windingFromTray(x, levels = 2n) {
  return liftWinding(parkedShellResidue(x), mod(x, parkPower(levels)), levels);
}

/**
 * Inverse mod a prime power, by extended Euclid. Defined because gcd(M,11)=1.
 * @param {bigint} a
 * @param {bigint} m - a prime power modulus.
 * @returns {bigint} a⁻¹ mod m.
 * @throws {Error} "parked lane is not coprime to the shell" if gcd(a, m) ≠ 1.
 */
function inverseModPrimePower(a, m) {
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error("parked lane is not coprime to the shell");
  return mod(old_s, m);
}

/**
 * The register carried by the tray alone. There is no K field — `winding` is a
 * getter-shaped derivation, recomputed from r and s every time it is asked for.
 * @param {bigint} x - the source integer.
 * @param {bigint} [levels=2n] - the parked-lane depth to read s at.
 * @returns {{kind: "PARKED_TRAY_V1", shell_lanes: string[], r: string,
 *   parked_lane: string, parked_depth: string, s: string,
 *   derive: function(): Object, carries_winding: false}}
 */
export function trayRegister(x, levels = 2n) {
  const r = parkedShellResidue(x);
  const s = mod(x, parkPower(levels));
  return {
    kind: "PARKED_TRAY_V1",
    shell_lanes: SHELL_LANES.map(String),
    r: r.toString(),
    parked_lane: PARK.toString(),
    parked_depth: levels.toString(),
    s: s.toString(),
    // K is absent by construction. Derive it:
    derive: () => liftWinding(r, s, levels),
    carries_winding: false,
  };
}

/**
 * Self-check: does the parked-split K-Elimination recovery agree with the
 * directly computed (unbounded) winding?
 * @param {bigint} x
 * @returns {{split: "parked", shell: string, anchor: string, recovered: string, actual: string, ok: boolean}}
 */
export function verifyShellWinding(x) {
  const recovered = recoverShellWindingFrom(x);
  const actual = actualShellWinding(x);
  return {
    split: "parked",
    shell: M_SHELL.toString(),
    anchor: PARK.toString(),
    recovered: recovered.toString(),
    actual: actual.toString(),
    ok: recovered === actual,
  };
}

// ── legacy: gear split, retained and still exact ───────────────────

/** Legacy shell modulus (= M6, 30,030). */
export const LEGACY_SHELL = M6;
/** Legacy anchor modulus (= GEAR_PRODUCT, 323). */
export const LEGACY_ANCHOR = GEAR_PRODUCT;

/** @param {bigint} x @returns {bigint} x mod M6. */
export function shellResidue(x) { return mod(x, M6); }
/** @param {bigint} x @returns {bigint} x mod GEAR_PRODUCT (323). */
export function gearResidue(x) { return mod(x, GEAR_PRODUCT); }

/**
 * K-Elimination on the legacy gear split.
 * @param {bigint} x
 * @returns {bigint} K mod 323.
 */
export function recoverShellWindingFromGear(x) {
  const vM = shellResidue(x);
  const vA = gearResidue(x);
  return mod((vA - vM) * M6_INV_MOD_GEAR, GEAR_PRODUCT);
}

/** @param {bigint} x @returns {bigint} ⌊x / M6⌋. */
export function actualLegacyWinding(x) { return x / M6; }

/**
 * Self-check for the legacy gear-split recovery.
 * @param {bigint} x
 * @returns {{split: "gear (legacy)", shell: string, anchor: string, recovered: string, actual: string, ok: boolean}}
 */
export function verifyLegacyShellWinding(x) {
  const recovered = recoverShellWindingFromGear(x);
  const actual = actualLegacyWinding(x);
  return {
    split: "gear (legacy)",
    shell: M6.toString(),
    anchor: GEAR_PRODUCT.toString(),
    recovered: recovered.toString(),
    actual: actual.toString(),
    ok: recovered === actual,
  };
}
