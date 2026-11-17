// src/core/residues.js — pure integer residue helpers. BigInt only. (P3)

/**
 * Non-negative-representative modulus: unlike native BigInt `%`, always
 * returns a value in `[0, m)` (never negative) for `m > 0`.
 * @param {bigint} x - the value to reduce (may be negative).
 * @param {bigint} m - the modulus; must be a positive BigInt.
 * @returns {bigint} `x mod m`, in `[0, m)`.
 */
export function mod(x, m) {
  const r = x % m;
  return r < 0n ? r + m : r;
}

/**
 * The residue tray of `x` over a basis of lanes, in the same order.
 * @param {bigint} x - the value to reduce.
 * @param {bigint[]} basis - the lane moduli, e.g. the Safe Basis S8.
 * @returns {bigint[]} `[x mod basis[0], x mod basis[1], ...]`.
 */
export function residues(x, basis) {
  return basis.map((p) => mod(x, p));
}

/**
 * The residue tray of `x`, as a plain object keyed by lane for display/
 * serialization (each residue stringified, since BigInt is not JSON-safe).
 * @param {bigint} x - the value to reduce.
 * @param {bigint[]} basis - the lane moduli.
 * @returns {Object<string, string>} `{ mod_<p>: "<x mod p>", ... }` for each
 *   lane `p` in `basis`.
 */
export function residueObject(x, basis) {
  const out = {};
  for (const p of basis) {
    out[`mod_${p.toString()}`] = mod(x, p).toString();
  }
  return out;
}
