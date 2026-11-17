// src/core/tower-recover.js — T-COMP-1: winding recovery from an ANCHOR SET. (P26)
//
// SUPERSEDES the anchor-power lift in `transduce` (P24).
//
// P24 grew the corridor by raising a single anchor to a power, (M+1)^depth, and
// certified with a leading-digit heuristic I invented: eliminate at depth and at
// depth+1, and call it good if the top digit came out zero. That was necessary
// but never sufficient, and I said so at the time. It is the wrong mechanism.
//
// The corridor is grown by EXTENDING THE ANCHOR SET, and the theorem gives the
// exact bound rather than a heuristic:
//
//     M = ∏ value_basis,   anchors {A₁..A_t},   L = lcm(Aᵢ),
//     d = gcd(M, L),       R = L / d
//
//     K ≡ ((v_L − r)/d) · (M/d)⁻¹   (mod R),    v_L = X mod L,  r = X mod M
//
// exact for every X with ⌊X/M⌋ < R. Two things make this better than the lift:
//
//   · (M/d) is invertible mod R UNCONDITIONALLY. gcd(M/d, L/d) = 1 always —
//     per prime, one of the two exponents is exhausted by the min — so no
//     coprimality precondition is needed between the shell and the anchor set.
//     The gradient case gcd(M, A) > 1 is not an exception to be routed around;
//     it is the general case with d > 1;
//   · R is COMPUTED, not guessed. K < R is a declared corridor, the same shape
//     as the Lean theorem's `hRange : X < M * A` — not a digit that happened to
//     land on zero.
//
// Reach is unbounded by adding anchors: each coprime anchor multiplies R at one
// pairwise combine, so cost is linear in the anchor count while the corridor
// grows multiplicatively. Raising one anchor to a power is a special case
// ({11, 11², …} ⟹ L = 11^e, d = 1, R = 11^e) and the strictly weaker lever.
//
// BigInt only.

import { mod } from "./residues.js";
import { gcd, inverse } from "./cram.js";

/**
 * lcm of a list.
 * @param {bigint[]} ms
 * @returns {bigint} lcm(ms), or 1n for an empty list.
 */
export function lcmAll(ms) {
  return ms.reduce((a, b) => a / gcd(a, b) * b, 1n);
}

/**
 * CRT over moduli that need NOT be pairwise coprime.
 * @param {bigint[]} residues - x mod moduli[i] for each i.
 * @param {bigint[]} moduli - the (possibly non-coprime) moduli.
 * @returns {?bigint} the unique residue mod lcm(moduli) consistent with every
 *   congruence, or null when they conflict.
 */
export function crtCombine(residues, moduli) {
  let R = mod(residues[0], moduli[0]), Mcur = moduli[0];
  for (let i = 1; i < moduli.length; i++) {
    const m = moduli[i], r = mod(residues[i], m);
    const g = gcd(Mcur, m);
    if (mod(r - R, g) !== 0n) return null;          // inconsistent congruences
    const lcm = Mcur / g * m;
    const step = mod((r - R) / g * inverse(mod(Mcur / g, m / g), m / g), m / g);
    R = mod(R + Mcur * step, lcm);
    Mcur = lcm;
  }
  return R;
}

/**
 * The corridor an anchor set buys: R = lcm(anchors) / gcd(M, lcm(anchors)).
 * @param {bigint} M - the shell modulus.
 * @param {bigint[]} anchors - the anchor moduli.
 * @returns {{L: bigint, d: bigint, R: bigint, span: bigint}} L=lcm(anchors),
 *   d=gcd(M,L), R=L/d (the winding resolution), span=M*R (the total corridor).
 */
export function anchorSetCorridor(M, anchors) {
  const L = lcmAll(anchors);
  const d = gcd(M, L);
  return { L, d, R: L / d, span: M * (L / d) };
}

/**
 * T-COMP-1. Recover the winding K = ⌊X/M⌋ from the shell residue r = X mod M
 * and the anchor residues {X mod Aᵢ}. Exact while K < R.
 *
 * @param {bigint} r - the shell residue, X mod M.
 * @param {bigint[]} anchorResidues - X mod anchors[i] for each i.
 * @param {bigint} M - the shell modulus.
 * @param {bigint[]} anchors - the anchor moduli.
 * @returns {?{K: bigint, R: bigint, L: bigint, d: bigint, corridor: bigint}}
 *   null when the anchor residues are mutually inconsistent, or when
 *   d ∤ (v_L − r) — both of which mean the inputs cannot come from one integer.
 */
export function towerRecover(r, anchorResidues, M, anchors) {
  const L = lcmAll(anchors);
  const d = gcd(M, L);
  const R = L / d;
  const vL = crtCombine(anchorResidues, anchors);
  if (vL === null) return null;

  const diff = mod(vL - r, L);
  if (mod(diff, d) !== 0n) return null;            // not a residue class of one integer

  // gcd(M/d, R) = 1 unconditionally, so this inverse always exists.
  const inv = inverse(mod(M / d, R), R);
  if (inv === null) return null;                   // unreachable; kept as an assertion
  return { K: mod(diff / d * inv, R), R, L, d, corridor: M * R };
}

/**
 * Driven from the integer — for encoding and for tests.
 * @param {bigint} x - the source integer.
 * @param {bigint} M - the shell modulus.
 * @param {bigint[]} anchors - the anchor moduli.
 * @returns {?Object} `towerRecover(...)` result.
 */
export function towerRecoverFrom(x, M, anchors) {
  return towerRecover(mod(x, M), anchors.map((a) => mod(x, a)), M, anchors);
}

/**
 * Extend an anchor set until the corridor covers `need`. Each added anchor is
 * one pairwise combine — linear cost for a multiplicative gain in R.
 * @param {bigint} M - the shell modulus.
 * @param {bigint[]} anchors - the starting anchor set.
 * @param {bigint} need - the target corridor span.
 * @param {bigint[]} candidates - candidate anchors to add, tried in order.
 * @returns {{anchors: bigint[], L: bigint, d: bigint, R: bigint, span: bigint}}
 *   the extended anchor set and its resulting corridor.
 */
export function extendAnchors(M, anchors, need, candidates) {
  const set = [...anchors];
  for (const c of candidates) {
    if (anchorSetCorridor(M, set).span > need) break;
    if (!set.some((a) => a === c)) set.push(c);
  }
  return { anchors: set, ...anchorSetCorridor(M, set) };
}

/**
 * E-DIV-4. The tracked winding and the extracted winding must agree; a
 * disagreement is an implementation fault, not a domain error.
 * @param {bigint} tracked - the winding as independently tracked.
 * @param {bigint} extracted - the winding as recovered by K-Elimination.
 * @returns {{tracked: bigint, extracted: bigint, agree: boolean, fault: ?string}}
 */
export function crossCheckWinding(tracked, extracted) {
  return {
    tracked, extracted,
    agree: tracked === extracted,
    fault: tracked !== extracted ? "E-DIV-4 winding mismatch" : null,
  };
}
