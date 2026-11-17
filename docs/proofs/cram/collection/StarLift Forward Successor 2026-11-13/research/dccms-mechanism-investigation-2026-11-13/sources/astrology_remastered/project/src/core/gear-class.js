// src/core/gear-class.js — gear-pair classification on (r17, r19). (P3)
// Integer residues only. Spec classes: G-zero, G-pre, G-low, else null.

import { mod } from "./residues.js";

/**
 * Classify a value by its residues on the legacy gear lanes 17 and 19.
 * BigInt arcsecond regime (core layer) — x is typically a longitude in
 * [0, 1296000) but any BigInt is accepted; the function only reduces it.
 * @param {bigint} x - the value to classify (e.g. a longitude in arcseconds).
 * @returns {"G-zero"|"G-pre"|"G-low"|null} "G-zero" when r17=0 ∧ r19=0;
 *   "G-pre" when r17=16 ∧ r19=18 (the residue immediately before G-zero);
 *   "G-low" when r17≤1 ∧ r19≤1; otherwise null (no gear event).
 */
export function gearClass(x) {
  const r17 = mod(x, 17n), r19 = mod(x, 19n);
  if (r17 === 0n && r19 === 0n) return "G-zero";
  if (r17 === 16n && r19 === 18n) return "G-pre";
  if (r17 <= 1n && r19 <= 1n) return "G-low";
  return null;
}
