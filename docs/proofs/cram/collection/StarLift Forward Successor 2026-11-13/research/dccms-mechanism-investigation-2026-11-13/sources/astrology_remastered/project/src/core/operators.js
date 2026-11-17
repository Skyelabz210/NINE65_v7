// src/core/operators.js — the exact lane-wise operator atlas over S8. (P13)
//
// WHAT AN EXACT LANE OPERATOR IS
// ──────────────────────────────
// A lane operator is a map on Z/p that (a) is a bijection, so the residue tray
// stays a faithful label and the step stays reversible, and (b) fixes 0, so it
// descends to a well-defined map on the CRT torus without special-casing the
// zero tray. The multiplicative maps of that shape are exactly
//
//     x ↦ c · x^e  (mod p),    c ∈ (Z/p)*,    gcd(e, p−1) = 1
//
// x^e permutes the multiplicative group iff e is coprime to p−1 — that is the
// whole constraint, and it is why the per-lane count is φ(p−1) for pure
// monomials and (p−1)·φ(p−1) once a constant twist is allowed. These maps form
// the holomorph of the cyclic group C_{p−1}; the count is a theorem, not a
// tally, and this module verifies it by exhaustive enumeration of function
// tables rather than asserting it.
//
// THE COUNTS
// ──────────
//              p:   2    3    5    7   11   13   17   19
//        φ(p−1):    1    1    2    2    4    4    8    6   →  ∏ = 3,072
//   (p−1)φ(p−1):    1    2    8   12   40   48  128  108   →  ∏ = 5,096,079,360
//         (p−1):    1    2    4    6   10   12   16   18   →  ∏ = 1,658,880 = φ(M)
//
// No lane admits 14 such operators. The counts are not uniform across lanes and
// cannot be: lane 2 has a trivial multiplicative group, so it admits exactly
// one, and lane 3 admits two.
//
// WHAT IS NOT AN OPERATOR OF THIS KIND
// ────────────────────────────────────
// Square root is not a lane operator. It is undefined on non-residues — only
// (p+1)/2 of the p residues are squares — and 2-to-1 where it is defined. No
// per-lane branch rule can repair this: a generic square in Z/M has 2^7 = 128
// square roots, and a fixed branch selects the intended one for a vanishing
// fraction of inputs. `sqrtDiagnostics()` computes both figures exactly.
//
// Frobenius is not an operator of this kind either: on a prime field x^p = x,
// so the Frobenius map is the identity. It becomes non-trivial only over
// F_{p^n} with n > 1, which no lane here is.
//
// BigInt only. No floats, no Date, no ephemeris.

import { mod } from "./residues.js";
import { B8 } from "./basis.js";

// ── small exact helpers ────────────────────────────────────────────

/**
 * Euclidean greatest common divisor.
 * @param {bigint} a
 * @param {bigint} b
 * @returns {bigint} gcd(|a|, |b|), non-negative.
 */
export function gcd(a, b) {
  let x = a < 0n ? -a : a, y = b < 0n ? -b : b;
  while (y) { const t = mod(x, y); x = y; y = t; }
  return x;
}

/**
 * Euler's totient, by direct counting (n is expected small — lane orders here).
 * @param {bigint} n
 * @returns {bigint} |{k in [1,n] : gcd(k,n)=1}|.
 */
export function totient(n) {
  let c = 0n;
  for (let k = 1n; k <= n; k++) if (gcd(k, n) === 1n) c++;
  return c;
}

/**
 * Modular exponentiation by repeated squaring.
 * @param {bigint} base
 * @param {bigint} exp - exponent, ≥ 0.
 * @param {bigint} m - modulus.
 * @returns {bigint} base^exp mod m.
 */
export function powMod(base, exp, m) {
  let r = 1n, b = mod(base, m), e = exp;
  while (e > 0n) {
    if (mod(e, 2n) === 1n) r = mod(r * b, m);
    b = mod(b * b, m);
    e = e / 2n;
  }
  return r;
}

// ── per-lane enumeration ───────────────────────────────────────────

/**
 * Exponents in [1, p−1] that permute the multiplicative group: gcd(e, p−1) = 1.
 * @param {bigint} p - the lane prime.
 * @returns {bigint[]} the admissible exponents.
 */
export function bijectiveExponents(p) {
  const out = [];
  const order = p - 1n;
  for (let e = 1n; e <= order; e++) if (gcd(e, order) === 1n) out.push(e);
  return out;
}

/**
 * The function table of x ↦ c·x^e mod p, as an array of length p.
 * @param {bigint} p - the lane prime.
 * @param {bigint} c - the multiplicative constant.
 * @param {bigint} e - the exponent.
 * @returns {bigint[]} table[x] = c·x^e mod p, for x = 0..p-1.
 */
export function laneTable(p, c, e) {
  const t = [];
  for (let x = 0n; x < p; x++) t.push(mod(c * powMod(x, e, p), p));
  return t;
}

/**
 * Is this table a bijection on Z/p that fixes 0?
 * @param {bigint[]} table - a candidate lane function table.
 * @param {bigint} p - the lane prime.
 * @returns {boolean}
 */
export function isExactLaneOperator(table, p) {
  if (BigInt(table.length) !== p) return false;
  if (table[0] !== 0n) return false;
  const seen = new Set(table.map(String));
  return BigInt(seen.size) === p;
}

/**
 * Every exact lane operator of the form c·x^e, enumerated as distinct function
 * tables. Deduplicated, so the returned count is the true number of distinct
 * maps rather than the number of (c, e) labels.
 * @param {bigint} p - the lane prime.
 * @returns {{c: string, e: string, table: bigint[]}[]} the distinct operators.
 */
export function laneOperators(p) {
  const seen = new Map();
  for (const e of bijectiveExponents(p)) {
    for (let c = 1n; c < p; c++) {
      const t = laneTable(p, c, e);
      const key = t.join(",");
      if (!seen.has(key)) seen.set(key, { c: c.toString(), e: e.toString(), table: t });
    }
  }
  return [...seen.values()];
}

/**
 * Pure monomials only (c = 1): the maps x ↦ x^e. Count is φ(p−1).
 * @param {bigint} p - the lane prime.
 * @returns {{e: string, table: bigint[]}[]}
 */
export function laneMonomials(p) {
  return bijectiveExponents(p).map((e) => ({ e: e.toString(), table: laneTable(p, 1n, e) }));
}

// ── the atlas ──────────────────────────────────────────────────────

/**
 * Per-lane and global operator counts over a basis. Every number is derived by
 * enumeration or by the closed form it is checked against — none is asserted.
 * @param {bigint[]} [basis=B8] - the lanes to profile.
 * @returns {Object} `CRAM_OPERATOR_ATLAS_V1` — per-lane counts (monomials,
 *   twisted, enumerated, units) and basis-wide totals.
 */
export function atlas(basis = B8) {
  const lanes = basis.map((p) => {
    const phiOrder = totient(p - 1n);
    const enumerated = BigInt(laneOperators(p).length);
    return {
      prime: p.toString(),
      order: (p - 1n).toString(),
      monomials: phiOrder.toString(),                    // φ(p−1)
      twisted: ((p - 1n) * phiOrder).toString(),         // (p−1)·φ(p−1)
      twisted_enumerated: enumerated.toString(),
      units: (p - 1n).toString(),
      closed_form_agrees: enumerated === (p - 1n) * phiOrder,
    };
  });
  const prod = (f) => basis.reduce((a, p) => a * f(p), 1n);
  return {
    kind: "CRAM_OPERATOR_ATLAS_V1",
    basis: basis.map(String),
    modulus: prod((p) => p).toString(),
    lanes,
    total_monomial: prod((p) => totient(p - 1n)).toString(),
    total_twisted: prod((p) => (p - 1n) * totient(p - 1n)).toString(),
    total_units: prod((p) => p - 1n).toString(),
  };
}

/**
 * Read a lane table at a BigInt index without leaving BigInt arithmetic.
 * @param {bigint[]} table - a lane function table.
 * @param {bigint} v - the index to read (BigInt, converted internally to compare).
 * @returns {bigint} table[v].
 * @throws {Error} "index outside the lane" if v is not a valid index of `table`.
 */
export function at(table, v) {
  for (let j = 0; j < table.length; j++) if (BigInt(j) === v) return table[j];
  throw new Error("index outside the lane");
}

/**
 * Composition closure check: the exact lane operators form a group under
 * composition (the holomorph of C_{p−1}). Verified by composing every pair and
 * confirming the result is already in the set.
 * @param {bigint} p - the lane prime.
 * @returns {boolean} true iff the operator set is closed under composition.
 */
export function laneClosesUnderComposition(p) {
  const ops = laneOperators(p);
  const keys = new Set(ops.map((o) => o.table.join(",")));
  for (const a of ops) {
    for (const b of ops) {
      const comp = [];
      for (let x = 0n; x < p; x++) comp.push(at(a.table, at(b.table, x)));
      if (!keys.has(comp.join(","))) return false;
    }
  }
  return true;
}

// ── what square root actually is on this basis ─────────────────────

/**
 * Exact diagnostics for the square-root claim, as integer ratios only — no
 * logarithm, no division to a decimal, anywhere.
 *
 *   squares_per_lane      how many of the p residues are squares: (p+1)/2 odd, 2 at p=2
 *   defined_everywhere    |{x ∈ Z/M : x is a square in every lane}|
 *   root_multiplicity     number of square roots a generic square has mod M
 *   branch_hits/branch_of the exact fraction of Y for which a fixed per-lane
 *                         branch rule returns Y itself rather than another root
 * @param {bigint[]} [basis=B8] - the lanes to profile.
 * @returns {Object} `CRAM_SQRT_DIAGNOSTICS_V1` — per-lane square counts plus
 *   basis-wide totality/single-valuedness verdicts. All numeric fields decimal strings.
 */
export function sqrtDiagnostics(basis = B8) {
  const lanes = basis.map((p) => {
    let squares;
    const seen = new Set();
    for (let y = 0n; y < p; y++) seen.add(mod(y * y, p).toString());
    squares = BigInt(seen.size);
    return {
      prime: p.toString(),
      squares: squares.toString(),
      undefined_on: (p - squares).toString(),
      // "pick the smaller root" agrees with the intended y when y ≤ (p−1)/2
      branch_agrees: (p === 2n ? 2n : (p + 1n) / 2n).toString(),
    };
  });
  const M = basis.reduce((a, p) => a * p, 1n);
  const definedEverywhere = lanes.reduce((a, l) => a * BigInt(l.squares), 1n);
  const branchNum = lanes.reduce((a, l) => a * BigInt(l.branch_agrees), 1n);
  const oddLanes = basis.filter((p) => p !== 2n);
  let mult = 1n;
  for (let i = 0; i < oddLanes.length; i++) mult = mult * 2n;
  return {
    kind: "CRAM_SQRT_DIAGNOSTICS_V1",
    modulus: M.toString(),
    lanes,
    defined_everywhere: definedEverywhere.toString(),
    defined_everywhere_of: M.toString(),
    root_multiplicity: mult.toString(),
    branch_hits: branchNum.toString(),
    branch_of: M.toString(),
    is_total: definedEverywhere === M,
    is_single_valued: mult === 1n,
  };
}

/**
 * On a prime field x^p = x, so Frobenius is the identity map. Verified exhaustively.
 * @param {bigint} p - the lane prime.
 * @returns {boolean}
 */
export function frobeniusIsIdentity(p) {
  for (let x = 0n; x < p; x++) if (powMod(x, p, p) !== x) return false;
  return true;
}

/**
 * Keyspace size of "each operator is a secret permutation", in bits, floored.
 * Returned as an integer bit-count so the figure can be compared against a
 * security level without evaluating a logarithm.
 * @param {bigint} count - the number of possibilities.
 * @returns {bigint} ⌊log2(count)⌋.
 */
export function keyspaceBitsFloor(count) {
  let bits = 0n, n = count;
  while (n > 1n) { n = n / 2n; bits++; }
  return bits;
}
