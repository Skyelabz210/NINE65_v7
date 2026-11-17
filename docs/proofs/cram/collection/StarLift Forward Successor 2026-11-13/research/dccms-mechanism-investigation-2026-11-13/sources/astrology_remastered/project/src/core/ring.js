// src/core/ring.js — exact arithmetic of the ecliptic arcsecond ring. BigInt only.
//
// The ring is R = 1,296,000 arcseconds = 360°. Its prime factorisation is
//
//     R = 2^7 · 3^4 · 5^3
//
// so the *only* primes that divide the ring are {2, 3, 5}. Every astrological
// division of the zodiac — 12 signs, 36 decans, 27 nakshatras, 260-day
// Tzolk'in, the nth harmonic — is a request to cut R into n equal integer
// parts. That request closes exactly iff n | R.
//
// Everything below is a statement about integers. No floats, no Date, no
// ephemeris. (P11)

import { mod } from "./residues.js";

export const RING = 1296000n;

/** The primes that divide the ring, with their exponents. R = 2^7·3^4·5^3. */
export const RING_PRIMES = [2n, 3n, 5n];
export const RING_EXPONENTS = [7n, 4n, 3n];

/** radical(R) = 2·3·5 = 30 — the squarefree kernel of the ring. */
export const RING_RADICAL = 30n;

/**
 * The Safe-Basis primes that do NOT divide the ring — the CLOSURE axis.
 *
 * This is NOT the shadow spine. Shadow is a mod-4 / Gaussian property
 * (p ≡ 3 mod 4, inert in Z[i]) and lives in safe-basis.js; the two sets cross
 * rather than coincide. 3 is a shadow prime that divides the ring; 13 and 17
 * are off-ring but split. Naming this set "spine" was the error being
 * corrected — see shadow-spine.js.
 */
export const OFF_RING_PRIMES = [7n, 11n, 13n, 17n, 19n];

/**
 * Exact integer power.
 * @param {bigint} base
 * @param {bigint} exp - exponent, ≥ 0.
 * @returns {bigint} base^exp.
 */
export function ipow(base, exp) {
  let out = 1n;
  for (let i = 0n; i < exp; i++) out = out * base;
  return out;
}

/**
 * Recompute R from its factorisation — a self-check, not an assumption.
 * @returns {bigint} should equal RING (1,296,000).
 */
export function ringFromFactors() {
  let out = 1n;
  for (let i = 0; i < RING_PRIMES.length; i++) {
    out = out * ipow(RING_PRIMES[i], RING_EXPONENTS[i]);
  }
  return out;
}

/**
 * Trial-division factorisation of a positive integer.
 * Exact; used only on the small
 * divisors that astrological traditions actually name (n ≤ a few thousand).
 * @param {bigint} n - a positive integer.
 * @returns {[bigint, bigint][]} [[p, e], ...] with p ascending, n = ∏ p^e.
 * @throws {Error} "factorise expects a positive integer" if n < 1.
 */
export function factorise(n) {
  if (n < 1n) throw new Error("factorise expects a positive integer");
  const out = [];
  let m = n;
  for (let p = 2n; p * p <= m; p++) {
    if (mod(m, p) !== 0n) continue;
    let e = 0n;
    while (mod(m, p) === 0n) { m = m / p; e++; }
    out.push([p, e]);
  }
  if (m > 1n) out.push([m, 1n]);
  return out;
}

/**
 * True iff every prime factor of n lies in {2,3,5}.
 * @param {bigint} n
 * @returns {boolean}
 */
export function isRingSmooth(n) {
  let m = n;
  for (const p of RING_PRIMES) while (mod(m, p) === 0n) m = m / p;
  return m === 1n;
}

/**
 * Does the n-fold division close exactly on the arcsecond ring?
 *
 *     closes(n)  ⟺  n | R  ⟺  n = 2^a·3^b·5^c with a≤7, b≤4, c≤3
 *
 * Ring-smoothness alone is necessary but not sufficient: 2^8 = 256 is smooth
 * yet exceeds the ring's exponent on 2, so it does not divide R.
 * @param {bigint} n - the division divisor (in arcseconds).
 * @returns {boolean} true iff n | R.
 */
export function closes(n) {
  return mod(RING, n) === 0n;
}

/**
 * Step size in arcseconds when the division closes; null when it does not.
 * @param {bigint} n - the division divisor.
 * @returns {?bigint} R/n, or null if `closes(n)` is false.
 */
export function stepArcsec(n) {
  return closes(n) ? RING / n : null;
}

/**
 * The residue defect of a division: R mod n. Zero exactly when the division
 * closes. For a prime p this is the ring's own residue in lane p, which is why
 * the spine primes are precisely the lanes where the ring itself is nonzero.
 * @param {bigint} n
 * @returns {bigint} R mod n.
 */
export function defect(n) {
  return mod(RING, n);
}

/**
 * The prime factors of n that the ring cannot absorb — the reason a division
 * fails to close, named. Empty array ⟺ the division closes (given exponents fit).
 * @param {bigint} n
 * @returns {bigint[]} n's prime factors that do not divide RING.
 */
export function offRingPrimes(n) {
  return factorise(n).map(([p]) => p).filter((p) => mod(RING, p) !== 0n);
}

/**
 * Full exact report on one division of the zodiac.
 * All numeric fields are decimal strings so the report is JSON-safe.
 * @param {bigint} n - the division divisor.
 * @returns {Object} n, closes, step_arcsec, defect_arcsec, ring_smooth,
 *   off_ring_primes, exponent_overflow, factorisation.
 */
export function divisionReport(n) {
  const off = offRingPrimes(n);
  const step = stepArcsec(n);
  const smooth = isRingSmooth(n);
  return {
    n: n.toString(),
    closes: closes(n),
    step_arcsec: step === null ? null : step.toString(),
    defect_arcsec: defect(n).toString(),
    ring_smooth: smooth,
    off_ring_primes: off.map(String),
    // A smooth n that still fails to close overflowed a ring exponent.
    exponent_overflow: smooth && !closes(n),
    factorisation: factorise(n).map(([p, e]) => `${p.toString()}^${e.toString()}`),
  };
}

/**
 * Per-prime defect table for the Safe-basis lanes: R mod p for each p.
 * @param {bigint[]} primes - the lanes to report.
 * @returns {Object<string, string>} `{ mod_<p>: "<R mod p>", ... }`.
 */
export function laneDefects(primes) {
  const out = {};
  for (const p of primes) out[`mod_${p.toString()}`] = mod(RING, p).toString();
  return out;
}

/**
 * Count of x in [0, RING) with x ≡ target (mod m), in closed form.
 * Used to certify swept event censuses against arithmetic rather than against
 * a hardcoded number.
 * @param {bigint} m - the modulus.
 * @param {bigint} target - the target residue class.
 * @returns {bigint} the count, or 0n if the reduced target is ≥ RING.
 */
export function residueClassCount(m, target) {
  const t = mod(target, m);
  if (t >= RING) return 0n;
  return (RING - 1n - t) / m + 1n;
}
