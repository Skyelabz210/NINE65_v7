// src/core/rho.js — the ρ(n) stability invariant. (P12)
//
//     ρ(n) = ω(n) + δ(n)
//
// ω(n)  number of distinct prime factors.
// q(n)  the largest SHADOW prime dividing n — largest p | n with p ≡ 3 (mod 4),
//       i.e. the largest prime factor that is INERT in Z[i]. Zero if none.
// δ(n)  0 when q ≤ 7 · 1 when q = 11 · 2 when q ≥ 19.
//
// The δ step is not arbitrary: the shadow primes are exactly the primes Fermat's
// two-square theorem excludes, so δ measures the obstruction to representing n
// in the Gaussian integers. 11 is the Shadow Anchor and 19 the escalation — and
// no prime strictly between them is ≡ 3 (mod 4), so the definition has no gap.
//
// Bands:  Stable ρ ≤ 4 · Mild 5–6 · Strong 7–8 · Chaotic ρ ≥ 9.
//
// Reference values this module must reproduce (framework §3.1, §4.2):
//   Tzolk'in 260 → ω 3, q 0,  ρ 3  Stable
//   Haab     365 → ω 2, q 0,  ρ 2  Stable
//   Shell  30030 → ω 6, q 11, ρ 7  Strong
//   Colony 9699690 → ω 8, q 19, ρ 10 Chaotic
//
// BigInt only. No floats, no Date.

import { factorise } from "./ring.js";
import { isShadowPrime } from "./safe-basis.js";

/**
 * ω(n) — the count of distinct prime factors.
 * @param {bigint} n
 * @returns {bigint}
 */
export function omega(n) {
  return BigInt(factorise(n).length);
}

/**
 * q(n) — the largest shadow (inert, p ≡ 3 mod 4) prime factor; 0n when none.
 * @param {bigint} n
 * @returns {bigint}
 */
export function largestShadowFactor(n) {
  let q = 0n;
  for (const [p] of factorise(n)) if (isShadowPrime(p) && p > q) q = p;
  return q;
}

/**
 * δ(n) — the shadow step: 0 for q ≤ 7, 1 at the anchor 11, 2 from 19 up.
 * @param {bigint} n
 * @returns {bigint} 0n, 1n, or 2n.
 */
export function delta(n) {
  const q = largestShadowFactor(n);
  if (q >= 19n) return 2n;
  if (q === 11n) return 1n;
  return 0n;
}

/**
 * ρ(n) = ω(n) + δ(n).
 * @param {bigint} n
 * @returns {bigint}
 */
export function rho(n) {
  return omega(n) + delta(n);
}

export const BANDS = [
  { id: "stable", label: "Stable", min: 0n, max: 4n, note: "clean super-cycles, low spectral entropy" },
  { id: "mild", label: "Mild", min: 5n, max: 6n, note: "beats and quasi-periodicity" },
  { id: "strong", label: "Strong", min: 7n, max: 8n, note: "long recurrence, sensitive to initial conditions" },
  { id: "chaotic", label: "Chaotic", min: 9n, max: null, note: "effectively unpredictable" },
];

/**
 * @param {bigint} r - a ρ value.
 * @returns {Object} the `BANDS` entry containing r.
 * @throws {Error} "ρ outside every band" — structurally unreachable since BANDS is exhaustive.
 */
export function band(r) {
  for (const b of BANDS) if (r >= b.min && (b.max === null || r <= b.max)) return b;
  throw new Error("ρ outside every band");
}

/**
 * Full ρ report for one integer. All numeric fields are decimal strings.
 * @param {bigint} n
 * @returns {Object} factorisation, omega, shadow_factors, q, delta, rho, band, band_label, band_note.
 */
export function rhoReport(n) {
  const f = factorise(n);
  const q = largestShadowFactor(n);
  const w = BigInt(f.length);
  const d = delta(n);
  const r = w + d;
  const b = band(r);
  return {
    n: n.toString(),
    factorisation: f.map(([p, e]) => `${p.toString()}^${e.toString()}`),
    omega: w.toString(),
    shadow_factors: f.map(([p]) => p).filter(isShadowPrime).map(String),
    q: q.toString(),
    delta: d.toString(),
    rho: r.toString(),
    band: b.id,
    band_label: b.label,
    band_note: b.note,
  };
}
