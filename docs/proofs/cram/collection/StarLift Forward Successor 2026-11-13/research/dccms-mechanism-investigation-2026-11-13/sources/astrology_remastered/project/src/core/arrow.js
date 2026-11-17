// src/core/arrow.js — the (r, K) identity and the arrow it carries. (P12)
//
// Carry every integer as its identity
//
//     X = r + K·M          r = X mod M      K = ⌊X / M⌋
//
// r is the PHASE, on the torus Z/M. By itself it is cyclic and reversible and
// has no direction: X and X+M read identically on every lane.
// K is the WINDING, the lift of that phase to the covering line. It is
// unbounded and signed. K IS THE ARROW.
//
// This is the universal cover R → S¹ in discrete form: the torus is the circle,
// K is the fibre coordinate, and K → K+1 is the deck transformation.
//
// SATURATION IS WHAT MAKES THE CLOCK FAITHFUL. Within one lap [0, M) the
// residue tuple over a pairwise-coprime basis is a bijection — M moments, M
// distinct readings — so past and future never alias inside a lap. A
// non-coprime pseudo-basis collides phases and its arrow is ambiguous; the
// module measures that collapse exactly rather than asserting it.
//
// A refinement the arithmetic forces: the tuple is a faithful LABEL, not an
// ORDER. Within a lap the ordering is carried by r as a number, not by the
// tuple compared coordinatewise. So the arrow is the pair (K, r): K orders the
// laps, r orders within a lap.
//
// SHADOW ENTROPY, NOT BOLTZMANN. The right ledger is the fibre multiplicity of
// the step map. H_shadow = 0 ⟺ every fibre is a singleton ⟺ the step is a
// bijection ⟺ reversible. While K is carried the step is a bijection, so the
// arrow is pure orientation with zero entropy production. Irreversibility is
// SYNTHETIC: discard K and L laps collapse onto one phase, fibre size exactly
// L, H_shadow = log₂ L > 0. Entropy in bits is only reported when L is a power
// of two, so the value stays an exact integer — no logarithm is ever taken.
//
// BigInt only. No floats, no Date, no ephemeris.

import { mod } from "./residues.js";
import { B6, M6 } from "./basis.js";

/**
 * Decompose X into its identity (r, K) against a modulus.
 * @param {bigint} x - the integer to decompose.
 * @param {bigint} [m=M6] - the modulus (lap length).
 * @returns {{r: bigint, K: bigint}} r = x mod m (the phase), K = ⌊x/m⌋ (the winding).
 */
export function identity(x, m = M6) {
  const r = mod(x, m);
  const k = (x - r) / m;          // exact floor division, valid for negative x
  return { r, K: k };
}

/**
 * Rebuild X from its identity. reconstruct(identity(x)) === x, always.
 * @param {bigint} r - the phase.
 * @param {bigint} k - the winding.
 * @param {bigint} [m=M6] - the modulus.
 * @returns {bigint} r + k*m.
 */
export function reconstruct(r, k, m = M6) { return r + k * m; }

/**
 * The residue tuple of a phase over a basis — the faithful label.
 * @param {bigint} x - the value to reduce.
 * @param {bigint[]} [basis=B6] - the lane moduli.
 * @returns {bigint[]} the per-lane residues, in basis order.
 */
export function tuple(x, basis = B6) { return basis.map((p) => mod(x, p)); }

/**
 * One forward step, residue-native. Add 1 to every lane; when the phase lands
 * on the all-zeros boundary the winding increments.
 * @param {{r: bigint, K: bigint}} state - the current identity.
 * @param {bigint} [m=M6] - the modulus.
 * @returns {{r: bigint, K: bigint}} the successor identity.
 */
export function stepForward(state, m = M6) {
  const r = mod(state.r + 1n, m);
  return { r, K: state.K + (r === 0n ? 1n : 0n) };
}

/**
 * One backward step. Same boundary, opposite sign: if sitting on all-zeros the
 * winding decrements first, then every lane subtracts 1.
 * @param {{r: bigint, K: bigint}} state - the current identity.
 * @param {bigint} [m=M6] - the modulus.
 * @returns {{r: bigint, K: bigint}} the predecessor identity.
 */
export function stepBackward(state, m = M6) {
  const K = state.K - (state.r === 0n ? 1n : 0n);
  return { r: mod(state.r - 1n, m), K };
}

/**
 * The arrow order on (K, r): K orders the laps, r orders within a lap.
 * This is a total order and it agrees with comparing the reconstructed
 * integers — which is the point.
 * @param {{r: bigint, K: bigint}} a
 * @param {{r: bigint, K: bigint}} b
 * @returns {-1|0|1} -1 if a < b, 0 if equal, 1 if a > b.
 */
export function arrowCompare(a, b) {
  if (a.K !== b.K) return a.K < b.K ? -1 : 1;
  if (a.r !== b.r) return a.r < b.r ? -1 : 1;
  return 0;
}

/**
 * Coordinatewise tuple comparison — deliberately provided so the distinction
 * can be demonstrated rather than described. It does NOT order the lap:
 * x=2 → (0,2,2,2,2,2) sorts below x=1 → (1,1,1,1,1,1).
 * @param {bigint} x
 * @param {bigint} y
 * @param {bigint[]} [basis=B6] - the lane moduli.
 * @returns {-1|0|1} lexicographic comparison of the two residue tuples.
 */
export function tupleCompare(x, y, basis = B6) {
  const a = tuple(x, basis), b = tuple(y, basis);
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return 0;
}

// ── saturation ─────────────────────────────────────────────────────

/**
 * Whether every pair of lanes in `basis` is coprime.
 * @param {bigint[]} basis - candidate lane moduli.
 * @returns {boolean} true iff gcd(basis[i], basis[j]) === 1n for every i≠j.
 */
export function pairwiseCoprime(basis) {
  const g = (a, b) => { while (b) { const t = mod(a, b); a = b; b = t; } return a; };
  for (let i = 0; i < basis.length; i++)
    for (let j = i + 1; j < basis.length; j++)
      if (g(basis[i], basis[j]) !== 1n) return false;
  return true;
}

/**
 * Measure whether a basis gives a faithful clock over a range.
 *
 * A pairwise-coprime basis is a bijection over [0, ∏p): distinct readings equal
 * the range, collisions zero. A pseudo-basis collides: distinct readings drop to
 * lcm(basis) and the collision count is range − lcm. The classic witness
 * {4, 6, 10} over its product 240 has lcm 60 and therefore 180 collisions.
 * @param {bigint[]} basis - candidate lane moduli.
 * @param {?bigint} [range=null] - span to test over; defaults to the basis product.
 * @returns {Object} `SATURATION_V1` report (all numeric fields decimal strings):
 *   product, lcm, range, distinct_readings, collisions, pairwise_coprime, faithful.
 */
export function saturation(basis, range = null) {
  const product = basis.reduce((a, p) => a * p, 1n);
  const g = (a, b) => { while (b) { const t = mod(a, b); a = b; b = t; } return a; };
  let l = 1n;
  for (const p of basis) l = l / g(l, p) * p;
  const span = range === null ? product : range;
  const seen = new Set();
  for (let x = 0n; x < span; x++) seen.add(tuple(x, basis).join(","));
  const distinct = BigInt(seen.size);
  return {
    kind: "SATURATION_V1",
    basis: basis.map(String),
    product: product.toString(),
    lcm: l.toString(),
    range: span.toString(),
    distinct_readings: distinct.toString(),
    collisions: (span - distinct).toString(),
    pairwise_coprime: pairwiseCoprime(basis),
    faithful: distinct === span,
  };
}

// ── shadow entropy ─────────────────────────────────────────────────

/**
 * Fibre multiplicity of a step map over a domain. H_shadow = 0 exactly when
 * every fibre is a singleton. `keyOf` maps a domain point to what the observer
 * retains — carry K and it is injective; discard K and laps collapse.
 * @param {Iterable<*>} domain - the points to classify (e.g. `carriedDomain(...)` output).
 * @param {function(*): *} keyOf - maps a domain point to the retained key (e.g. `keyIdentity` or `keyPhaseOnly`).
 * @returns {{fibres: number, fibre_max: number, bijection: boolean, h_shadow_zero: boolean}}
 */
export function fibreProfile(domain, keyOf) {
  const counts = new Map();
  for (const x of domain) {
    const k = keyOf(x);
    counts.set(k, (counts.get(k) || 0) + 1);
  }
  let max = 0;
  for (const v of counts.values()) if (v > max) max = v;
  return {
    fibres: counts.size,
    fibre_max: max,
    bijection: max === 1,
    h_shadow_zero: max === 1,
  };
}

/**
 * H_shadow in bits, exactly, when the fibre size is a power of two; null
 * otherwise. Reporting an integer exponent keeps this A1-clean — no logarithm
 * is evaluated anywhere.
 * @param {bigint|number} fibreSize - the fibre size to test (coerced to BigInt).
 * @returns {?string} the exponent (as a decimal string) if fibreSize is a
 *   power of two and ≥ 1; null otherwise.
 */
export function shadowEntropyBits(fibreSize) {
  let n = BigInt(fibreSize), bits = 0n;
  if (n < 1n) return null;
  while (mod(n, 2n) === 0n) { n = n / 2n; bits++; }
  return n === 1n ? bits.toString() : null;
}

/**
 * The clean carried successor over `laps` laps: state (r, K) → next state.
 * Its fibre profile is a bijection, so the arrow is pure orientation.
 * @param {bigint} laps - number of laps (K values 0..laps-1) to enumerate.
 * @param {bigint} [m=M6] - the modulus.
 * @returns {{r: bigint, K: bigint}[]} every (r, K) pair over the range, K-major.
 */
export function carriedDomain(laps, m = M6) {
  const out = [];
  for (let k = 0n; k < laps; k++) for (let r = 0n; r < m; r++) out.push({ r, K: k });
  return out;
}

/**
 * The synthetic that breaks it: retain the phase, discard the winding.
 * @param {{r: bigint, K: bigint}} s
 * @returns {string} the phase alone, as a string — collapses distinct laps together.
 */
export function keyPhaseOnly(s) { return s.r.toString(); }
/**
 * The clean key: retain the whole identity.
 * @param {{r: bigint, K: bigint}} s
 * @returns {string} "K:r", injective over the whole domain.
 */
export function keyIdentity(s) { return `${s.K.toString()}:${s.r.toString()}`; }
