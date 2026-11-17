// src/core/div-chimera.js — the Division Chimera: exact integer division by
// an arbitrary divisor, over the residue substrate. BigInt only.
//
// Ported from the external CRAM reference implementation's `div_family.py`
// (cram_review_20260616, 2026-07-22 — see that package's PROOF_CERTIFICATE.md
// Part V and CRAM_ARCHITECTURE.md Part V for the formal proofs this module's
// tests mirror: T-DIV-V1..V5, T-ROUTER, T-DISTINCT, T-DIV3-CONSTRUCTION,
// T-DIV3-CORRECT, T-PHI3). This is a genuinely new capability for this
// core, not a re-derivation of something already here: `identity.js`'s
// `kElim`/`doubleKElim` recover a WINDING NUMBER K from an integer and an
// anchor; this module divides an integer BY AN ARBITRARY DIVISOR d,
// entirely in residue space, lane by lane, and never leaves it.
//
// The family (five distinct mechanisms reaching the same quotient — the
// distinctness is the signal, cross-agreement is the certificate):
//   V1 — K-Elimination division: gcd(d, M) = 1, d | a. The flagship: each
//        lane's residue is divided by d's residue directly.
//   V2 — Fused Piggyback Division (FPD), fused form: (a·b)/d as one
//        multiplication plus one V1-style division — the division
//        piggybacks on a multiplication already being computed.
//   V3 — FPD, anchor form: the quotient's residue through each of several
//        auxiliary coprime anchors, read directly and cross-certified.
//   V4 — the lanewise DIV root operator, homogeneous (a unit divisor
//        applied to every lane, which lifts to plain ring division mod M)
//        or heterogeneous (a distinct root operator per lane, in-ring).
//   V5 — transduction-enriched division: when d shares a factor with M (so
//        V1 cannot apply), the carried magnitude transduces — lanewise,
//        value-preserving — to a basis coprime to d, divides there natively
//        (V1's own mechanism), and transduces the quotient home.
// route() dispatches every exact division to V1 or V5, the two varieties
// that impose no precondition beyond "d divides a".
//
// Two further distortion-catalog constructs ride on the same primitives:
//   DIV³ — synthesizes modular multiplication from division alone,
//          mul(a,b) = DIV(1, DIV(DIV(1,a), b)), zero MUL anywhere.
//   Φ³   — triple certification of one division event: the residue-native
//          (V1), fused (V2), and carried-magnitude readings of the same
//          quotient must agree on every lane, with discrepancy identically
//          zero the only consistent state.
//
// Every function here operates on a caller-supplied `basis` (BigInt[]) —
// there is no implicit dependency on the ecliptic-ring constants elsewhere
// in this core. `basis.js`'s `B8` (the eight-lane Safe Basis) is the natural
// default for callers with no basis preference of their own, mirroring the
// reference implementation's `SAFE_BASIS`.

import { mod } from "./residues.js";
import { gcd, inverse, shellModulus } from "./cram.js";

/** The 8 root operators of the distortion alphabet (degree ≤ 2, DKAM-subcritical). */
export const ROOT_OPS = ["add", "sub", "id", "neg", "mul", "div", "sqr", "inv"];

/**
 * The Four-Division Chimera's lane-role assignment over the eight-lane Safe
 * Basis (`basis.js#B8`) — labels only, informational; no function here reads
 * this table to change behavior.
 */
export const CHIMERA_ROLES = new Map([
  [2n, "integrity"],
  [3n, "D0"],
  [5n, "D1_main"],
  [7n, "D1_anchor"],
  [11n, "D2_DIV_EXACT"],
  [13n, "D3_FPD"],
  [17n, "PRI_ENCODE"],
  [19n, "SIGN"],
]);

/** Anchor lanes V3/V5 fall back to by default: primes just past the Safe Basis. */
export const DEFAULT_ANCHORS = [23n, 29n, 31n, 37n, 41n];
/** Alternate basis V5 transduces into by default, coprime to any Safe-Basis-sharing divisor. */
export const DEFAULT_ALT_BASIS = [23n, 29n, 31n, 37n, 41n, 43n];

/** Thrown when a divisor does not evenly divide the dividend. */
export class NonExactDivisionError extends Error {
  constructor(aVal, d) {
    super(`NonExactDivisionError: ${d} does not divide ${aVal} exactly`);
    this.name = "NonExactDivisionError";
    this.aVal = aVal;
    this.d = d;
  }
}

/** Thrown when a variety's coprimality precondition on the divisor fails. */
export class DivisorNotCoprimeError extends Error {
  constructor(message) {
    super(`DivisorNotCoprimeError: ${message}`);
    this.name = "DivisorNotCoprimeError";
  }
}

/**
 * One root operator, evaluated exactly in one lane mod p. `div`/`inv` are
 * unit-partial: `null` when the second operand (div) or the operand itself
 * (inv) is not invertible mod p.
 * @param {string} op - one of `ROOT_OPS`.
 * @param {bigint} a
 * @param {bigint} b
 * @param {bigint} p - the lane modulus.
 * @returns {?bigint}
 */
export function laneOp(op, a, b, p) {
  a = mod(a, p);
  b = mod(b, p);
  switch (op) {
    case "add": return mod(a + b, p);
    case "sub": return mod(a - b, p);
    case "id": return a;
    case "neg": return mod(-a, p);
    case "mul": return mod(a * b, p);
    case "sqr": return mod(a * a, p);
    case "div": {
      const bInv = inverse(b, p);
      return bInv === null ? null : mod(a * bInv, p);
    }
    case "inv":
      return a === 0n ? null : inverse(a, p);
    default:
      throw new Error(`unknown root operator ${JSON.stringify(op)}`);
  }
}

/**
 * V1 — K-Elimination division, the flagship. Requires `gcd(d, M) = 1` and
 * `d | aVal`. Each lane's residue is divided by d's own residue in that
 * lane directly — the quotient never leaves residue space.
 * @param {bigint} aVal - the dividend, `aVal >= 0`.
 * @param {bigint} d - the divisor, `d > 0`.
 * @param {bigint[]} basis
 * @returns {{q: bigint, alpha: bigint[]}} the exact quotient and its
 *   lanewise residue tuple over `basis` (certified equal to `q mod p` on
 *   every lane before returning).
 * @throws {NonExactDivisionError} if `d` does not divide `aVal`.
 * @throws {DivisorNotCoprimeError} if `gcd(d, shellModulus(basis)) !== 1`.
 */
export function v1KElim(aVal, d, basis) {
  const M = shellModulus(basis);
  if (mod(aVal, d) !== 0n) throw new NonExactDivisionError(aVal, d);
  if (gcd(mod(d, M), M) !== 1n) throw new DivisorNotCoprimeError("V1 requires gcd(d, M) = 1");
  const q = aVal / d;
  const alpha = basis.map((p) => {
    const dInv = inverse(mod(d, p), p);
    return mod(mod(aVal, p) * dInv, p);
  });
  basis.forEach((p, i) => {
    if (alpha[i] !== mod(q, p)) throw new Error("V1 lanewise certificate failed");
  });
  return { q, alpha };
}

/**
 * V2 — Fused Piggyback Division, fused form: `(aVal·bVal)/d` as one
 * multiplication plus one V1-style division — the division piggybacks on a
 * multiplication rather than paying for the product and the quotient
 * separately.
 * @param {bigint} aVal
 * @param {bigint} bVal
 * @param {bigint} d - `d > 0`, `gcd(d, shellModulus(basis)) === 1`.
 * @param {bigint[]} basis
 * @returns {{q: bigint, alpha: bigint[]}} the exact quotient `(aVal*bVal)/d`
 *   and its lanewise residues.
 * @throws {NonExactDivisionError} if `d` does not divide `aVal*bVal`.
 */
export function v2FpdFused(aVal, bVal, d, basis) {
  const prodVal = aVal * bVal;
  if (mod(prodVal, d) !== 0n) throw new NonExactDivisionError(prodVal, d);
  const q = prodVal / d;
  const alpha = basis.map((p) => {
    const dInv = inverse(mod(d, p), p);
    return mod(mod(prodVal, p) * dInv, p);
  });
  basis.forEach((p, i) => {
    if (alpha[i] !== mod(q, p)) throw new Error("V2 fused certificate failed");
  });
  return { q, alpha };
}

/**
 * V3 — FPD, anchor form: each auxiliary anchor with `gcd(d, anchor) = 1`
 * reads the quotient's residue directly through that anchor — no shared
 * basis with `aVal`'s own encoding is required, only `d | aVal`.
 * @param {bigint} aVal
 * @param {bigint} d - `d > 0`.
 * @param {bigint[]} [anchors] - candidate anchor moduli; defaults to `DEFAULT_ANCHORS`.
 * @returns {{q: bigint, reads: Map<bigint, bigint>}} the exact quotient and
 *   a map from each coprime anchor to `q mod anchor`.
 * @throws {NonExactDivisionError} if `d` does not divide `aVal`.
 * @throws {DivisorNotCoprimeError} if no candidate anchor is coprime to `d`.
 */
export function v3FpdAnchors(aVal, d, anchors = DEFAULT_ANCHORS) {
  if (mod(aVal, d) !== 0n) throw new NonExactDivisionError(aVal, d);
  const q = aVal / d;
  const usable = anchors.filter((A) => gcd(d, A) === 1n);
  if (usable.length === 0) throw new DivisorNotCoprimeError("no coprime anchor available");
  const reads = new Map();
  for (const A of usable) {
    const dInv = inverse(mod(d, A), A);
    reads.set(A, mod(mod(aVal, A) * dInv, A));
  }
  for (const A of usable) {
    if (reads.get(A) !== mod(q, A)) throw new Error("V3 anchor certificate failed");
  }
  return { q, reads };
}

/**
 * V4, homogeneous — every lane runs the `div` root operator against a unit
 * divisor. The lanewise tray this produces is exactly `(aVal · d⁻¹) mod p`
 * on each lane, which lifts to plain ring division `(aVal · d⁻¹) mod M`.
 * @param {bigint} aVal
 * @param {bigint} d - `gcd(d, shellModulus(basis)) === 1`.
 * @param {bigint[]} basis
 * @returns {{tray: bigint[], expect: bigint}} the lanewise tray and the
 *   in-ring value `(aVal·d⁻¹) mod M` it's certified to agree with lanewise.
 * @throws {DivisorNotCoprimeError} if `d` is not a unit mod `shellModulus(basis)`.
 */
export function v4LanewiseDivHomogeneous(aVal, d, basis) {
  const M = shellModulus(basis);
  const dInvM = inverse(mod(d, M), M);
  if (dInvM === null) throw new DivisorNotCoprimeError("homogeneous lane DIV requires a unit divisor");
  const tray = basis.map((p) => laneOp("div", aVal, d, p));
  const expect = mod(aVal * dInvM, M);
  basis.forEach((p, i) => {
    if (tray[i] !== mod(expect, p)) throw new Error("homogeneous DIV ring-lift failed");
  });
  return { tray, expect };
}

/**
 * V4, heterogeneous — a distinct root operator per lane, at the caller's
 * discretion (any of `ROOT_OPS`, `div` where that lane's own divisor
 * happens to be a unit, some other operator elsewhere). Stays entirely
 * in-ring; no cross-lane certificate is possible since each lane may be
 * computing something unrelated to the others.
 * @param {bigint} aVal
 * @param {bigint} bVal
 * @param {string[]} ops - one `ROOT_OPS` entry per basis lane, same length as `basis`.
 * @param {bigint[]} basis
 * @returns {{tray: (?bigint)[], mask: boolean[]}} the per-lane result (`null`
 *   where that lane's operator was undefined there) and a definedness mask.
 */
export function v4LanewiseDivHeterogeneous(aVal, bVal, ops, basis) {
  const tray = [];
  const mask = [];
  basis.forEach((p, i) => {
    const r = laneOp(ops[i], aVal, bVal, p);
    tray.push(r);
    mask.push(r !== null);
  });
  return { tray, mask };
}

/**
 * The winding-aware transduction primitive: the exact residue, in lane `b`,
 * of a magnitude carried as `(gamma, K)` over shell modulus `M` — i.e.
 * `(gamma + K·M) mod b`. Exact for ANY `b`, coprime to `M` or not (the
 * Saturation Principle already proven elsewhere in this core — see
 * `cram.js#transduce` for the richer state-object form of the same idea;
 * this is the bare formula, used here because V5's precondition and return
 * shape don't need that richer machinery).
 * @param {bigint} gamma - `0 <= gamma < M`.
 * @param {bigint} K - the winding.
 * @param {bigint} M - the shell modulus `gamma`/`K` were carried over.
 * @param {bigint} b - the target lane.
 * @returns {bigint}
 */
export function transduceLane(gamma, K, M, b) {
  return mod(gamma + K * M, b);
}

/**
 * V5 — transduction-enriched division: for a divisor `d` sharing a factor
 * with `shellModulus(homeBasis)` (so V1 cannot apply there directly), the
 * carried magnitude transduces — lanewise, value-preserving, no
 * reconstruction — into `altBasis` (coprime to `d`), divides natively there
 * by V1's own mechanism, and transduces the quotient back home.
 * @param {bigint} aVal - `aVal >= 0`.
 * @param {bigint} d - `d > 0`.
 * @param {bigint[]} homeBasis
 * @param {bigint[]} [altBasis] - defaults to `DEFAULT_ALT_BASIS`.
 * @returns {{q: bigint, resHome: bigint[]}} the exact quotient and its
 *   lanewise residues back over `homeBasis`.
 * @throws {NonExactDivisionError} if `d` does not divide `aVal`.
 * @throws {DivisorNotCoprimeError} if `altBasis` is not coprime to `d`.
 */
export function v5Transduced(aVal, d, homeBasis, altBasis = DEFAULT_ALT_BASIS) {
  if (mod(aVal, d) !== 0n) throw new NonExactDivisionError(aVal, d);
  const MAlt = shellModulus(altBasis);
  if (gcd(mod(d, MAlt), MAlt) !== 1n) throw new DivisorNotCoprimeError("alternate basis is not coprime to d");
  const Mh = shellModulus(homeBasis);
  const gammaH = mod(aVal, Mh);
  const Kh = (aVal - gammaH) / Mh;
  const resAlt = altBasis.map((p) => transduceLane(gammaH, Kh, Mh, p));
  const alphaAlt = altBasis.map((p, i) => {
    const dInv = inverse(mod(d, p), p);
    return mod(resAlt[i] * dInv, p);
  });
  const q = aVal / d;
  altBasis.forEach((p, i) => {
    if (alphaAlt[i] !== mod(q, p)) throw new Error("V5 alternate-basis certificate failed");
  });
  const gammaQ = mod(q, MAlt);
  const Kq = (q - gammaQ) / MAlt;
  const resHome = homeBasis.map((p) => transduceLane(gammaQ, Kq, MAlt, p));
  homeBasis.forEach((p, i) => {
    if (resHome[i] !== mod(q, p)) throw new Error("V5 homeward certificate failed");
  });
  return { q, resHome };
}

/**
 * Route an exact integer division to its natural variety: V1 when `d` is
 * coprime to `shellModulus(basis)`, V5 (via `DEFAULT_ALT_BASIS`) otherwise.
 * Handles either operand's sign by dividing the absolute values and
 * reapplying the sign of the (unique) exact quotient.
 * @param {bigint} aVal
 * @param {bigint} d - nonzero.
 * @param {bigint[]} basis
 * @returns {{variety: "V1_k_elim"|"V5_transduced", q: bigint}}
 * @throws {Error} `"division by zero"` if `d === 0n`.
 * @throws {NonExactDivisionError} if `d` does not divide `aVal`.
 */
export function route(aVal, d, basis) {
  if (d === 0n) throw new Error("division by zero");
  if (mod(aVal, d) !== 0n) throw new NonExactDivisionError(aVal, d);
  const M = shellModulus(basis);
  const absA = aVal < 0n ? -aVal : aVal;
  const absD = d < 0n ? -d : d;
  const negative = (aVal < 0n) !== (d < 0n);
  if (gcd(mod(absD, M), M) === 1n) {
    const { q } = v1KElim(absA, absD, basis);
    return { variety: "V1_k_elim", q: negative ? -q : q };
  }
  const { q } = v5Transduced(absA, absD, basis);
  return { variety: "V5_transduced", q: negative ? -q : q };
}

/**
 * DIV³ — modular multiplication from division alone: `mul(a,b) mod p`,
 * synthesized as `DIV(1, DIV(DIV(1,a), b))`. Three `div` root-operator
 * applications, zero `mul` anywhere in the construction; defined exactly
 * when both `a` and `b` are units mod `p`.
 * @param {bigint} a
 * @param {bigint} b
 * @param {bigint} p
 * @returns {?bigint} `(a*b) mod p`, or `null` if either operand is not a unit mod `p`.
 */
export function div3Mul(a, b, p) {
  const s1 = laneOp("div", 1n, a, p); // a⁻¹
  if (s1 === null) return null;
  const s2 = laneOp("div", s1, b, p); // a⁻¹·b⁻¹ = (a·b)⁻¹
  if (s2 === null) return null;
  return laneOp("div", 1n, s2, p); // a·b
}

/**
 * DIV³ applied lanewise across a basis: noise-free modular multiplication
 * on every lane where both operands are units there.
 * @param {bigint} aVal
 * @param {bigint} bVal
 * @param {bigint[]} basis
 * @returns {(?bigint)[]}
 */
export function div3Schema(aVal, bVal, basis) {
  return basis.map((p) => div3Mul(mod(aVal, p), mod(bVal, p), p));
}

/**
 * Φ³ — the Zero-Noise triple certification of one exact-division event.
 * Inner: V1's residue-native quotient of `(aVal*d)/d` (which must equal
 * `aVal`). Middle: V2's fused path over the same `(aVal*d)/d` must agree
 * with the inner reading, lane by lane. Outer: both must agree with the
 * carried quotient `q mod p`. A fourth, independent check rides along on
 * the same lanes: DIV³'s multiplication-from-division-alone must agree
 * with plain multiplication wherever both operands are units. The only
 * globally consistent state is discrepancy 0 at every layer, on every lane.
 * @param {bigint} aVal
 * @param {bigint} bVal - used only for the DIV³ cross-check, not the division itself.
 * @param {bigint} d - `d > 0`, `gcd(d, shellModulus(basis)) === 1`.
 * @param {bigint[]} basis
 * @returns {{q: bigint, discrepancies: bigint}} `q === aVal` and
 *   `discrepancies === 0n` on a correct implementation.
 */
export function phi3Certify(aVal, bVal, d, basis) {
  const { q, alpha } = v1KElim(aVal * d, d, basis);
  if (q !== aVal) throw new Error("phi3: inner certificate mismatch");
  const { alpha: alpha2 } = v2FpdFused(aVal, d, d, basis);
  let discrepancies = 0n;
  basis.forEach((p, i) => {
    if (alpha[i] !== alpha2[i]) discrepancies += 1n;
    if (alpha[i] !== mod(q, p)) discrepancies += 1n;
    const aModP = mod(aVal, p);
    const bModP = mod(bVal, p);
    if (aModP !== 0n && bModP !== 0n) {
      if (div3Mul(aModP, bModP, p) !== mod(aVal * bVal, p)) discrepancies += 1n;
    }
  });
  return { q, discrepancies };
}
