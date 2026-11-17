// src/core/shadow-spine.js — the shadow spine, correctly separated. (P12)
//
// CORRECTION OF RECORD
// ────────────────────
// The previous version of this file defined "the spine" as {7,11,13,17,19} —
// the Safe-Basis primes that do not divide the ecliptic ring. That set is real,
// but it is the CLOSURE axis. Naming it "shadow" collapsed two independent
// structures into one, which is exactly the failure the visual-class spec
// warned about, committed in the arithmetic rather than the rendering.
//
// TWO AXES, KEPT APART
// ────────────────────
// SHADOW  — a Gaussian/mod-4 property of a prime. p is a shadow prime when it
//           is INERT in Z[i], i.e. p ≡ 3 (mod 4); Fermat's two-square theorem
//           excludes exactly these. In the Safe Basis: {3, 7, 11, 19}, anchored
//           at 11 (δ=1) and escalating at 19 (δ=2). This is what feeds ρ(n).
//
// CLOSURE — a property of a prime relative to the ring R = 1,296,000 = 2⁷·3⁴·5³.
//           p is off-ring when R mod p ≠ 0. In the Safe Basis: {7,11,13,17,19}.
//           This is what decides whether a division of the zodiac tiles exactly.
//
// They cross in a 2×2, and every cell is occupied:
//
//                  │ closes on the ring │ off-ring
//   ───────────────┼────────────────────┼──────────────────────────────
//   shadow (inert) │ 3                  │ 7, 11, 19
//   split/ramified │ 2, 5               │ 13, 17
//
// The upper-left cell is the load-bearing one for traditional astrology: 3 is a
// shadow prime that divides the ring exactly. The TRINE — the most benefic
// classical aspect — sits on an inert Gaussian prime that nonetheless tiles the
// circle with zero remainder. Shadow structure the received apparatus fully
// absorbs. The upper-right cell is shadow structure it cannot absorb; the
// lower-right is boundary and saturation defect, which is not shadow at all.
//
// BigInt only. No floats, no Date, no ephemeris.

import { mod } from "./residues.js";
import { B8 } from "./basis.js";
import { RING, OFF_RING_PRIMES } from "./ring.js";
import {
  SHADOW_SPINE, SHADOW_ANCHOR, SHADOW_ESCALATION, isShadowPrime,
  gaussianClass, role, sumOfTwoSquares,
} from "./safe-basis.js";
import { rho, delta, largestShadowFactor, omega, band } from "./rho.js";

// ── the shadow spine proper ────────────────────────────────────────

export const SPINE = SHADOW_SPINE.map((p) => ({
  prime: p,
  id: p === SHADOW_ANCHOR ? "SH11" : `SH${p.toString()}`,
  role: role(p).role,
  anchor: p === SHADOW_ANCHOR,
  escalation: p === SHADOW_ESCALATION,
  closes_ring: mod(RING, p) === 0n,
  ring_defect: mod(RING, p),
}));

/**
 * The lanes that block exact closure — the closure axis, named as such.
 * @type {{prime: bigint, id: string, role: string, shadow: boolean}[]}
 */
export const OFF_RING_LANES = [
  { prime: 7n, id: "H7", role: "bridge witness", shadow: true },
  { prime: 11n, id: "SH11", role: "shadow anchor", shadow: true },
  { prime: 13n, id: "B13", role: "boundary witness", shadow: false },
  { prime: 17n, id: "G17", role: "saturation extender", shadow: false },
  { prime: 19n, id: "G19", role: "saturation extender", shadow: true },
];

/**
 * The 2×2 cross-classification of the Safe Basis. Every cell is occupied.
 * @returns {{shadow_closing: string[], shadow_off_ring: string[],
 *   nonshadow_closing: string[], nonshadow_off_ring: string[]}} each cell as
 *   an array of stringified basis primes.
 */
export function crossClassify() {
  const cell = (sh, off) => B8.filter((p) =>
    isShadowPrime(p) === sh && (mod(RING, p) !== 0n) === off).map(String);
  return {
    kind: "SHADOW_CLOSURE_CROSS_V1",
    shadow_closing: cell(true, false),      // 3 — absorbed shadow (the trine)
    shadow_off_ring: cell(true, true),      // 7, 11, 19 — irreducible shadow
    nonshadow_closing: cell(false, false),  // 2, 5 — plain ring primes
    nonshadow_off_ring: cell(false, true),  // 13, 17 — boundary / saturation
  };
}

// ── event vocabulary ───────────────────────────────────────────────
// Body/edge classes are unchanged in name — SH-* really was lane 11, the
// Shadow Anchor — but each now declares which axis it reports on, so the
// renderer can never merge a shadow event with a closure event again.

export const EVENT_CLASSES = [
  { id: "R", axis: "none", scope: "both", prime: null, trigger: "no closure on any lane" },
  { id: "SH-body", axis: "shadow", scope: "body", prime: 11n, trigger: "r11 = 0" },
  { id: "SH-edge", axis: "shadow", scope: "edge", prime: 11n, trigger: "shared r11" },
  { id: "H7-body", axis: "shadow", scope: "body", prime: 7n, trigger: "r7 = 0" },
  { id: "H7-edge", axis: "shadow", scope: "edge", prime: 7n, trigger: "shared r7" },
  { id: "G19-body", axis: "shadow", scope: "body", prime: 19n, trigger: "r19 = 0" },
  { id: "B13-zero", axis: "boundary", scope: "body", prime: 13n, trigger: "r13 = 0" },
  { id: "B13-pre", axis: "boundary", scope: "body", prime: 13n, trigger: "r13 = 12" },
  { id: "B13-edge", axis: "boundary", scope: "edge", prime: 13n, trigger: "shared r13" },
  { id: "G-zero", axis: "saturation", scope: "body", prime: 323n, trigger: "r17 = 0 ∧ r19 = 0" },
  { id: "G-pre", axis: "saturation", scope: "body", prime: 323n, trigger: "r17 = 16 ∧ r19 = 18" },
  { id: "G-low", axis: "saturation", scope: "body", prime: 323n, trigger: "r17 ≤ 1 ∧ r19 ≤ 1" },
  { id: "G-edge", axis: "saturation", scope: "edge", prime: 323n, trigger: "shared r17 and r19" },
];

export const CLASS_IDS = EVENT_CLASSES.map((c) => c.id);
/**
 * @param {string} id - an event class id (see `CLASS_IDS`).
 * @returns {Object} the matching `EVENT_CLASSES` entry.
 * @throws {Error} `"unknown event class: ${id}"` if not found.
 */
export function eventClass(id) {
  const c = EVENT_CLASSES.find((z) => z.id === id);
  if (!c) throw new Error(`unknown event class: ${id}`);
  return c;
}
/**
 * @param {string} id - an event class id.
 * @returns {string} its axis ("shadow"|"boundary"|"saturation"|"none").
 */
export function axisOf(id) { return eventClass(id).axis; }

const BODY_CLASSES = EVENT_CLASSES.filter((c) => c.scope !== "edge").map((c) => c.id);
const EDGE_CLASSES = EVENT_CLASSES.filter((c) => c.scope !== "body").map((c) => c.id);
/** @returns {string[]} every event-class id with body scope. */
export function bodyClassVocabulary() { return BODY_CLASSES.slice(); }
/** @returns {string[]} every event-class id with edge scope. */
export function edgeClassVocabulary() { return EDGE_CLASSES.slice(); }

/**
 * The residue tray on the off-ring lanes.
 * @param {bigint} x
 * @returns {Object<string, string>} `{ mod_<p>: "<x mod p>", ... }` for each `OFF_RING_LANES` prime.
 */
export function laneResidues(x) {
  const out = {};
  for (const l of OFF_RING_LANES) out[`mod_${l.prime.toString()}`] = mod(x, l.prime).toString();
  return out;
}

/**
 * The residue tray on the shadow spine — including lane 3, which the ring absorbs.
 * @param {bigint} x
 * @returns {Object<string, string>} `{ mod_<p>: "<x mod p>", ... }` for each `SPINE` prime.
 */
export function shadowResidues(x) {
  const out = {};
  for (const s of SPINE) out[`mod_${s.prime.toString()}`] = mod(x, s.prime).toString();
  return out;
}

/**
 * Body-level events. Order is significant and mirrored exactly by the census
 * classifier in test/shadow-spine.test.js.
 * @param {bigint} x - the ring position (arcseconds) to classify.
 * @param {?string} [label] - an optional body label attached to each event.
 * @returns {Object[]} event records `{eventClass, axis, trigger, scope, body, prime, value, proofStatus}`.
 */
export function bodyEvents(x, label) {
  const r7 = mod(x, 7n), r11 = mod(x, 11n), r13 = mod(x, 13n);
  const r17 = mod(x, 17n), r19 = mod(x, 19n);
  const ev = [];
  const push = (id, value) => {
    const c = eventClass(id);
    ev.push({
      eventClass: id, axis: c.axis, trigger: c.trigger, scope: "body",
      body: label || null,
      prime: c.prime === null ? null : c.prime.toString(),
      value: value === null ? null : value.toString(),
      proofStatus: "computed",
    });
  };
  if (r11 === 0n) push("SH-body", r11);
  if (r13 === 0n) push("B13-zero", r13);
  else if (r13 === 12n) push("B13-pre", r13);
  if (r17 === 0n && r19 === 0n) push("G-zero", mod(x, 323n));
  else if (r17 === 16n && r19 === 18n) push("G-pre", mod(x, 323n));
  else if (r17 <= 1n && r19 <= 1n) push("G-low", mod(x, 323n));
  if (r7 === 0n) push("H7-body", r7);
  if (r19 === 0n) push("G19-body", r19);
  if (ev.length === 0) push("R", null);
  return ev;
}

/**
 * Edge-level events — residue preservation across an aspect edge.
 * @param {bigint} x - first ring position.
 * @param {bigint} y - second ring position.
 * @param {?string} [label] - an optional edge label attached to each event.
 * @returns {Object[]} event records `{eventClass, axis, trigger, scope, edge, prime, value, proofStatus}`.
 */
export function edgeEvents(x, y, label) {
  const ev = [];
  const push = (id, value) => {
    const c = eventClass(id);
    ev.push({
      eventClass: id, axis: c.axis, trigger: c.trigger, scope: "aspect-edge",
      edge: label || null,
      prime: c.prime === null ? null : c.prime.toString(),
      value: value === null ? null : value.toString(),
      proofStatus: "computed",
    });
  };
  if (mod(x, 11n) === mod(y, 11n)) push("SH-edge", mod(x, 11n));
  if (mod(x, 13n) === mod(y, 13n)) push("B13-edge", mod(x, 13n));
  if (mod(x, 17n) === mod(y, 17n) && mod(x, 19n) === mod(y, 19n)) push("G-edge", mod(x, 323n));
  if (mod(x, 7n) === mod(y, 7n)) push("H7-edge", mod(x, 7n));
  if (ev.length === 0) push("R", null);
  return ev;
}

// ── division-level classification, on both axes ────────────────────

/**
 * Why a division of the zodiac fails to close — the CLOSURE axis only.
 * Says nothing about shadow; use divisionShadow for that.
 * @param {bigint} n - the division divisor.
 * @returns {Object} axis:"closure", closes, defect_arcsec, off_ring_lanes,
 *   off_ring_primes, alien_factor (a non-basis prime factor, if any).
 */
export function divisionClosure(n) {
  const carried = OFF_RING_LANES.filter((l) => mod(n, l.prime) === 0n);
  let m = n;
  for (const p of B8) while (mod(m, p) === 0n) m = m / p;
  return {
    axis: "closure",
    divisor: n.toString(),
    closes: mod(RING, n) === 0n,
    defect_arcsec: mod(RING, n).toString(),
    off_ring_lanes: carried.map((l) => l.id),
    off_ring_primes: carried.map((l) => l.prime.toString()),
    alien_factor: m > 1n ? m.toString() : null,
  };
}

/**
 * The SHADOW axis for a division: which inert primes it carries, its q, δ, ω,
 * ρ and stability band. This is the classifier the framework actually defines,
 * and it is independent of whether the division closes.
 * @param {bigint} n - the division divisor.
 * @returns {Object} axis:"shadow", omega, q, delta, rho, band, band_label, anchored, escalated.
 */
export function divisionShadow(n) {
  const q = largestShadowFactor(n);
  const r = rho(n);
  const b = band(r);
  return {
    axis: "shadow",
    divisor: n.toString(),
    omega: omega(n).toString(),
    q: q.toString(),
    delta: delta(n).toString(),
    rho: r.toString(),
    band: b.id,
    band_label: b.label,
    anchored: q === SHADOW_ANCHOR,
    escalated: q >= SHADOW_ESCALATION,
  };
}

/**
 * Both axes at once, kept as separate objects so they cannot be merged.
 * @param {bigint} n - the division divisor.
 * @returns {{divisor: string, closure: Object, shadow: Object}}
 */
export function divisionProfile(n) {
  return { divisor: n.toString(), closure: divisionClosure(n), shadow: divisionShadow(n) };
}

// ── census ─────────────────────────────────────────────────────────

/**
 * Closed-form census of body events over the ring. The exhaustive sweep must
 * reproduce these exactly — arithmetic checking arithmetic, no magic numbers.
 * @returns {Object<string, string>} event-class id → decimal-string count over the full ring.
 */
export function censusClosedForm() {
  const countCongruent = (m, t) => (RING - 1n - mod(t, m)) / m + 1n;
  const gearBoth = (a, b) => {
    let s = 0n;
    while (mod(s, 17n) !== mod(a, 17n) || mod(s, 19n) !== mod(b, 19n)) s++;
    return countCongruent(323n, s);
  };
  return {
    "SH-body": countCongruent(11n, 0n).toString(),
    "B13-zero": countCongruent(13n, 0n).toString(),
    "B13-pre": countCongruent(13n, 12n).toString(),
    "H7-body": countCongruent(7n, 0n).toString(),
    "G19-body": countCongruent(19n, 0n).toString(),
    "G-zero": gearBoth(0n, 0n).toString(),
    "G-pre": gearBoth(16n, 18n).toString(),
  };
}

/**
 * The classical attribution of a ring position. Deliberately independent of
 * everything above: the spine functions never call this, and this never calls
 * them. That separation is what the non-interference certificate checks.
 * @param {bigint} x - the ring position in arcseconds.
 * @param {bigint} offset - a frame offset in arcseconds (e.g. an ayanamsa).
 * @returns {{sign: string, decan: string, dwad: string, degree_in_sign: string, arcsec_in_degree: string}}
 */
export function classicalAttribution(x, offset) {
  const t = mod(x - offset, RING);
  return {
    sign: (t / 108000n).toString(),
    decan: (t / 36000n).toString(),
    dwad: (t / 9000n).toString(),
    degree_in_sign: (mod(t, 108000n) / 3600n).toString(),
    arcsec_in_degree: mod(t, 3600n).toString(),
  };
}

// Re-exported so callers need one import for the shadow story.
export { SHADOW_SPINE, SHADOW_ANCHOR, SHADOW_ESCALATION, isShadowPrime, gaussianClass, sumOfTwoSquares };
export { OFF_RING_PRIMES };
